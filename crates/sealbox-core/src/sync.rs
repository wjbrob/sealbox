//! The receive pipeline: IMAP fetch (UID-based, incremental, UIDVALIDITY-aware) → MIME parse
//! → Autocrypt peer update → decrypt / verify → protected headers → gossip import → store.
//! Plus `watch` (IMAP IDLE), and the convergence pass that keeps the stored copy honest when
//! another client has been in the mailbox ([`Engine::reconcile_selected`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use chrono::{DateTime, Utc};
use sealbox_crypto::{
    decrypt_and_verify, effective_date, verify_detached, AutocryptGossip, AutocryptHeader,
    Identity, PublicKey, SignatureStatus,
};
use sealbox_mail::imap::{FetchedMessage, FolderRole, IdleEvent, ImapClient};
use sealbox_mail::mime::{self, MessageKind, PlainBody};

use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::store::{AccountRow, FolderRow, NewAttachment, NewMessage};
use crate::transport::find_sent_folder;
use crate::types::{
    Address, FolderSync, SigState, SignatureSummary, SyncPhase, SyncProgress, SyncReport,
    WatchEvent,
};

/// How many UID ranges one `UID FETCH (FLAGS)` of a reconcile carries. The flags are asked
/// for by *range* (see [`flag_fetch_runs`]), so a fully synced folder is one range and, up to
/// [`RECONCILE_UIDS`] messages, the whole reconcile is one command; this bound only matters
/// for a folder whose stored set is broken up by many messages we hold no copy of, and keeps
/// such a command line to a few kilobytes.
///
/// Fewer commands is the point. GreenMail pays a cost per `FETCH` that grows with the size of
/// the mailbox (≈0.7 s for any `UID FETCH` of a 10,000-message folder, whether it names 1 UID
/// or all of them), so the 500-UID chunks this replaced made a +50 incremental sync of such a
/// folder take 21 extra round trips and 13 s instead of one (G33).
const RECONCILE_RANGES: usize = 256;

/// The most UIDs one reconcile `UID FETCH` covers: a range is split once it spans this many
/// live UIDs. The ranges bound the round trips, this bounds what one of them carries. Without
/// it a fully synced folder of 200,000 messages (Gmail's All Mail) is one `1:200000`, whose
/// 10 MB of `* n FETCH (UID .. FLAGS (..) RFC822.SIZE ..)` lines must all arrive inside one
/// network timeout — on a slow link they do not, and the reconcile would fail on every sync.
/// 16,384 lines are ≈0.9 MB: well inside the 60 s timeout even at 150 kbit/s, and still one
/// command for the folder G33 measures (10,000 stored plus the new mail and the repeated
/// runs' growth, whose sizes count against the bound too). Larger folders pay one round trip
/// per 16,384 messages.
const RECONCILE_UIDS: usize = 16_384;

/// One `UID FETCH` of a reconcile (see [`plan_flag_commands`]).
#[derive(Debug, Default, PartialEq, Eq)]
struct FlagCommand {
    ranges: Vec<(u32, u32)>,
    /// Ask `RFC822.SIZE` too: set only on a command that carries a range of new UIDs.
    with_sizes: bool,
    /// How many live, stored UIDs the command asks flags for (what its answer is held to).
    flag_uids: usize,
}

/// Packs a reconcile into commands of at most `max_ranges` ranges and `max_uids` UIDs each:
/// `runs` (from [`flag_fetch_runs`]) counted by the live UIDs they span, split where one spans
/// more than `max_uids`; then `size_ranges` (new UIDs, all live), split the same way, sharing
/// the last flags command when there is room for them. Only a command that carries a size
/// range asks sizes, so the stored mail's `RFC822.SIZE` is not asked for in bulk.
fn plan_flag_commands(
    runs: &[(u32, u32)],
    live: &BTreeSet<u32>,
    size_ranges: &[(u32, u32)],
    max_ranges: usize,
    max_uids: usize,
) -> Vec<FlagCommand> {
    let max_uids = max_uids.max(1);
    let max_ranges = max_ranges.max(1);
    // (range, UIDs it covers, is a size range)
    let mut pieces: Vec<((u32, u32), usize, bool)> = Vec::new();
    for &(lo, hi) in runs {
        let mut start: Option<u32> = None;
        let mut last = lo;
        let mut n = 0usize;
        for &uid in live.range(lo..=hi) {
            let first = *start.get_or_insert(uid);
            last = uid;
            n += 1;
            if n == max_uids {
                pieces.push(((first, uid), n, false));
                start = None;
                n = 0;
            }
        }
        if let Some(first) = start {
            pieces.push(((first, last), n, false));
        }
    }
    for &(lo, hi) in size_ranges {
        let mut from = u64::from(lo);
        let end = u64::from(hi);
        let step = u64::try_from(max_uids).unwrap_or(u64::MAX);
        while from <= end {
            let to = end.min(from.saturating_add(step - 1));
            let (a, b) = (
                u32::try_from(from).unwrap_or(u32::MAX),
                u32::try_from(to).unwrap_or(u32::MAX),
            );
            let n = usize::try_from(to - from + 1).unwrap_or(usize::MAX);
            pieces.push(((a, b), n, true));
            from = to + 1;
        }
    }
    let mut commands = Vec::new();
    let mut cur = FlagCommand::default();
    let mut cur_uids = 0usize;
    for (range, n, is_size) in pieces {
        if !cur.ranges.is_empty()
            && (cur.ranges.len() >= max_ranges || cur_uids.saturating_add(n) > max_uids)
        {
            commands.push(std::mem::take(&mut cur));
            cur_uids = 0;
        }
        cur.ranges.push(range);
        cur_uids = cur_uids.saturating_add(n);
        if is_size {
            cur.with_sizes = true;
        } else {
            cur.flag_uids += n;
        }
    }
    if !cur.ranges.is_empty() {
        commands.push(cur);
    }
    commands
}

/// What one reconcile did and learned (see `Engine::reconcile_with`).
#[derive(Debug, Default)]
struct Reconciled {
    removed: u32,
    flags_changed: u32,
    /// The folder's `UID SEARCH UID 1:*` answer; `None` when nothing was stored, so nothing
    /// was asked.
    live: Option<BTreeSet<u32>>,
    /// `RFC822.SIZE` of the UIDs the caller asked sizes for, as far as the server answered.
    sizes: HashMap<u32, u32>,
}

/// Ascending UIDs as inclusive runs of consecutive UIDs (`[1, 2, 3, 7]` → `[(1, 3), (7, 7)]`).
fn uid_ranges(uids: &[u32]) -> Vec<(u32, u32)> {
    let mut sorted = uids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out: Vec<(u32, u32)> = Vec::new();
    for u in sorted {
        match out.last_mut() {
            Some((_, hi)) if hi.checked_add(1) == Some(u) => *hi = u,
            _ => out.push((u, u)),
        }
    }
    out
}

/// The stored UIDs that still exist, as a few inclusive ranges to fetch flags for. `live` is
/// the server's own `UID SEARCH UID 1:*` and `stored` a subset of it, both ascending.
///
/// A range runs over every *live* UID that is stored and is broken only by a live UID that is
/// not stored (which we would otherwise ask about for nothing). Gaps left by expunged UIDs do
/// not break it, since the server has nothing there to answer for — so a folder fully synced
/// and since pruned elsewhere is still a single `lo:hi`, as is a first window or a backfill
/// in progress (a contiguous top slice of the live set).
fn flag_fetch_runs(stored: &[u32], live: &BTreeSet<u32>) -> Vec<(u32, u32)> {
    let mut runs = Vec::new();
    let mut want = stored.iter().copied().peekable();
    let mut run: Option<(u32, u32)> = None;
    for &uid in live {
        let Some(&next) = want.peek() else { break };
        if next == uid {
            want.next();
            run = Some(run.map_or((uid, uid), |(lo, _)| (lo, uid)));
        } else if let Some(r) = run.take() {
            runs.push(r);
        }
    }
    runs.extend(run);
    runs
}

/// `UID FETCH` of `uids` that tells a short answer from a broken session. async-imap ends the
/// response stream silently on EOF or a tagged NO, which looks exactly like messages that
/// were expunged meanwhile; storing the watermark past them would lose them for good. So when
/// UIDs are missing the session is checked (`NOOP` fails on a dead connection) and the missing
/// ones are asked for once more; whatever the server still does not return after that is gone
/// or unservable, and is skipped with a warning.
async fn fetch_batch_checked(client: &mut ImapClient, uids: &[u32]) -> Result<Vec<FetchedMessage>> {
    let missing = |got: &[FetchedMessage], want: &[u32]| -> Vec<u32> {
        let have: std::collections::HashSet<u32> = got.iter().map(|m| m.uid).collect();
        want.iter().copied().filter(|u| !have.contains(u)).collect()
    };
    let mut fetched = client.fetch_rfc822_batch(uids).await?;
    let absent = missing(&fetched, uids);
    if absent.is_empty() {
        return Ok(fetched);
    }
    client.noop().await?;
    let again = client.fetch_rfc822_batch(&absent).await?;
    let still = missing(&again, &absent);
    fetched.extend(again);
    if !still.is_empty() {
        client.noop().await?;
        tracing::warn!(
            count = still.len(),
            first = still[0],
            "UID FETCH: message(s) listed by the search were not returned twice; skipped \
             (expunged meanwhile, or the server cannot serve them)"
        );
    }
    fetched.sort_by_key(|m| m.uid);
    Ok(fetched)
}

/// Where a pass reports its stored batches.
pub(crate) type Progress<'a> = &'a mut (dyn FnMut(SyncProgress) + Send);

/// One fetch step of a pass: its phase, whether it reaches the folder's first message, and
/// the folder's size on the server (for [`SyncProgress::total_known`]).
#[derive(Clone, Copy, Debug)]
struct FetchStep {
    phase: SyncPhase,
    reaches_bottom: bool,
    total_known: u32,
}

/// Running counts of one fetch step, for [`SyncProgress`].
#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    planned: u32,
    fetched: u32,
    stored: u32,
}

/// Cut `uids` (already in fetch order) into `UID FETCH` batches of at most `max_count`
/// messages and `max_bytes` bytes by their `RFC822.SIZE` (a UID without a known size counts
/// 0; `max_bytes` 0 = no byte limit). A message bigger than `max_bytes` travels alone.
fn plan_batches(
    uids: &[u32],
    sizes: &HashMap<u32, u32>,
    max_count: usize,
    max_bytes: usize,
) -> Vec<Vec<u32>> {
    let max_count = max_count.max(1);
    let mut out = Vec::new();
    let mut cur: Vec<u32> = Vec::new();
    let mut bytes = 0usize;
    for &u in uids {
        let size = sizes
            .get(&u)
            .map_or(0, |s| usize::try_from(*s).unwrap_or(usize::MAX));
        let full =
            cur.len() >= max_count || (max_bytes > 0 && bytes.saturating_add(size) > max_bytes);
        if !cur.is_empty() && full {
            out.push(std::mem::take(&mut cur));
            bytes = 0;
        }
        cur.push(u);
        bytes = bytes.saturating_add(size);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// What one [`Engine::sync_folder`] pass over a folder does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FolderPass {
    /// Fetch the mail newer than everything stored; for a folder with nothing stored yet,
    /// only its newest `window` UIDs.
    pub new_mail: bool,
    /// Newest-first window of a first sync (0 = the whole folder, oldest first).
    pub window: usize,
    /// Then fetch up to this many older messages below the window's floor, newest first
    /// (0 = none). Never in the pass that fetched the first window: a first sync returns as
    /// soon as the window is stored.
    pub backfill: usize,
    /// Hold the stored copy of the folder up against the server afterwards and converge it
    /// ([`Engine::reconcile_selected`]): drop what has been deleted elsewhere, follow flags
    /// changed elsewhere. Off for a backfill pass, which is about older mail and would pay
    /// for the whole folder's flags once per folder per call for nothing.
    pub reconcile: bool,
}

/// Per-sync cache of key material: our identities, every known signer key, our addresses.
/// It may live long (a `watch` keeps one for hours), so it remembers the store's signer-key
/// generation it was loaded at (`store::KEYS_GENERATION_SCHEMA`, raised by triggers on every
/// write that changes any of this, by whichever sync, UI or process) and reloads when the
/// store's has moved on ([`Engine::fresh_keys`]).
pub(crate) struct SyncContext {
    identities: Vec<Identity>,
    known: Vec<PublicKey>,
    fp_to_addr: BTreeMap<String, String>,
    own_addresses: Vec<String>,
    /// The store's signer-key generation when this was loaded.
    keys_gen: i64,
    /// How often the keys were reloaded after a change (tests).
    pub(crate) key_reloads: u32,
}

impl std::fmt::Debug for SyncContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncContext")
            .field("identities", &self.identities.len())
            .field("known", &self.known.len())
            .finish()
    }
}

/// Outcome of processing one raw message.
#[derive(Debug)]
pub(crate) struct Processed {
    pub message: NewMessage,
    /// Encrypted and successfully decrypted.
    pub decrypted_ok: bool,
    /// Encrypted (or malformed) and not readable.
    pub failed: bool,
    /// The Autocrypt peer table changed (a key change also raises the store's signer-key
    /// generation; a `last_seen` bump does not).
    pub peers_changed: bool,
}

fn to_address(m: &mime::Mailbox) -> Address {
    Address {
        name: m.name.clone(),
        address: m.address.clone(),
    }
}

fn summarize(sigs: &[SignatureStatus], fp_to_addr: &BTreeMap<String, String>) -> SignatureSummary {
    if let Some(SignatureStatus::Bad { fingerprint }) = sigs
        .iter()
        .find(|s| matches!(s, SignatureStatus::Bad { .. }))
    {
        return SignatureSummary {
            status: SigState::Bad,
            fingerprint: Some(fingerprint.clone()),
            signer: fp_to_addr.get(fingerprint).cloned(),
            ..Default::default()
        };
    }
    if let Some(SignatureStatus::Good { fingerprint }) = sigs
        .iter()
        .find(|s| matches!(s, SignatureStatus::Good { .. }))
    {
        return SignatureSummary {
            status: SigState::Good,
            fingerprint: Some(fingerprint.clone()),
            signer: fp_to_addr.get(fingerprint).cloned(),
            ..Default::default()
        };
    }
    if let Some(SignatureStatus::UnknownKey { key_id }) = sigs.first() {
        return SignatureSummary {
            status: SigState::UnknownKey,
            fingerprint: Some(key_id.clone()),
            signer: None,
            ..Default::default()
        };
    }
    SignatureSummary::default()
}

impl Engine {
    pub(crate) fn sync_context(&self, acct: &AccountRow) -> Result<SyncContext> {
        // The generation first: a change while the keys load leaves the context behind,
        // so the next check reloads (never the other way round).
        let keys_gen = self.store().keys_generation()?;
        let identities = self.identities_for(acct)?;
        let (known, fp_to_addr) = self.known_signers()?;
        Ok(SyncContext {
            identities,
            known,
            fp_to_addr,
            own_addresses: self.own_addresses()?,
            keys_gen,
            key_reloads: 0,
        })
    }

    /// Bring a context up to date with the store: when the signer-key generation moved since
    /// it was loaded (a key, peer key, identity or account written by anyone), reload all of
    /// it. One integer read otherwise. Called at the start of every pass (a `watch` round, a
    /// catch-up, a backfill) and right before a decryption / verification needs the keys, so
    /// a run of mail that only bumps `last_seen` (or plain mail, which needs no key) reloads
    /// nothing.
    pub(crate) fn fresh_keys(&self, ctx: &mut SyncContext, acct: &AccountRow) -> Result<()> {
        if self.store().keys_generation()? == ctx.keys_gen {
            return Ok(());
        }
        let reloads = ctx.key_reloads + 1;
        *ctx = self.sync_context(acct)?;
        ctx.key_reloads = reloads;
        Ok(())
    }

    /// Apply the Level 1 peer-state update for a message from `addr`.
    pub(crate) fn update_peer_from_header(
        &self,
        addr: &str,
        header: Option<&AutocryptHeader>,
        effective: DateTime<Utc>,
    ) -> Result<bool> {
        let mut peer = self.peer_state(addr)?;
        let changed = peer.update_from_header(header, effective);
        if changed {
            self.store().save_peer(&peer)?;
        }
        Ok(changed)
    }

    /// Import one gossip header (rule 1 — the address must be a recipient — is the caller's).
    fn update_peer_from_gossip(
        &self,
        gossip: &AutocryptGossip,
        effective: DateTime<Utc>,
    ) -> Result<bool> {
        let mut peer = self.peer_state(&gossip.addr)?;
        let changed = peer.update_from_gossip(gossip, effective);
        if changed {
            self.store().save_peer(&peer)?;
        }
        Ok(changed)
    }

    /// Turn raw RFC 822 bytes into a storable message, updating Autocrypt state on the way.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn process_message(
        &self,
        ctx: &mut SyncContext,
        acct: &AccountRow,
        folder: &FolderRow,
        uid: u32,
        raw: &[u8],
        flags: Vec<String>,
        received_at: DateTime<Utc>,
    ) -> Result<Processed> {
        let received_ts = received_at.timestamp();
        let parsed = match mime::parse(raw) {
            Ok(p) => p,
            Err(e) => {
                return Ok(Processed {
                    message: NewMessage {
                        account_id: acct.id,
                        folder_id: folder.id,
                        uid,
                        message_id: None,
                        from: Address::default(),
                        to: Vec::new(),
                        cc: Vec::new(),
                        subject: Some("(unparseable message)".into()),
                        protected_subject: false,
                        date: None,
                        received_at: received_ts,
                        flags,
                        was_encrypted: false,
                        decrypted: false,
                        was_signed: false,
                        signature: SignatureSummary::default(),
                        signatures_json: "[]".into(),
                        text: None,
                        html: None,
                        in_reply_to: Vec::new(),
                        references: Vec::new(),
                        decrypt_error: Some(format!("unparseable: {e}")),
                        raw: raw.to_vec(),
                        attachments: Vec::new(),
                    },
                    decrypted_ok: false,
                    failed: true,
                    peers_changed: false,
                })
            }
        };
        let h = &parsed.headers;
        let from = h.from.first().map(to_address).unwrap_or_default();
        let effective = effective_date(
            h.date.and_then(|t| DateTime::<Utc>::from_timestamp(t, 0)),
            received_at,
        );
        let from_is_own = ctx
            .own_addresses
            .iter()
            .any(|a| a.eq_ignore_ascii_case(&from.address));
        let mut peers_changed = false;

        // Autocrypt Level 1: exactly one From, not a bounce/report, not ourselves.
        if h.from.len() == 1
            && !from_is_own
            && !h
                .content_type
                .as_deref()
                .is_some_and(|c| c.eq_ignore_ascii_case("multipart/report"))
        {
            let values: Vec<&str> = h.autocrypt.iter().map(String::as_str).collect();
            let header = AutocryptHeader::parse_for_sender(&values, &from.address);
            peers_changed =
                self.update_peer_from_header(&from.address, header.as_ref(), effective)?;
        }

        if !matches!(parsed.kind, MessageKind::Plain(_)) {
            // Decryption / verification below needs the current keys (this message's own
            // Autocrypt key included: saving it raised the generation).
            self.fresh_keys(ctx, acct)?;
        }
        let identities: Vec<&Identity> = ctx.identities.iter().collect();
        let known: Vec<&PublicKey> = ctx.known.iter().collect();

        let mut was_encrypted = false;
        let mut decrypted = false;
        let mut was_signed = false;
        let mut sigs: Vec<SignatureStatus> = Vec::new();
        let mut body = PlainBody::default();
        let mut subject = h.subject.clone();
        let mut protected_subject = false;
        let mut decrypt_error: Option<String> = None;
        let mut gossip_values: Vec<String> = Vec::new();
        let mut inner_recipients: Vec<String> = Vec::new();

        let take_inner = |plaintext: &[u8],
                          body: &mut PlainBody,
                          subject: &mut Option<String>,
                          protected: &mut bool,
                          gossip: &mut Vec<String>,
                          rcpts: &mut Vec<String>,
                          err: &mut Option<String>| {
            match mime::parse_decrypted_inner(plaintext) {
                Ok(inner) => {
                    if inner.headers.present {
                        if let Some(s) = inner.headers.subject.clone() {
                            *subject = Some(s);
                            *protected = true;
                        }
                    }
                    *gossip = inner.headers.autocrypt_gossip.clone();
                    rcpts.extend(
                        inner
                            .headers
                            .to
                            .iter()
                            .chain(inner.headers.cc.iter())
                            .map(|m| m.address.to_ascii_lowercase()),
                    );
                    *body = inner.body;
                }
                Err(e) => {
                    *body = PlainBody {
                        text: Some(String::from_utf8_lossy(plaintext).into_owned()),
                        html: None,
                        attachments: Vec::new(),
                    };
                    *err = Some(format!("inner MIME: {e}"));
                }
            }
        };

        match parsed.kind {
            MessageKind::Plain(b) => body = b,
            MessageKind::PgpMimeEncrypted { ciphertext } => {
                was_encrypted = true;
                match decrypt_and_verify(&ciphertext, &identities, &known) {
                    Ok(dec) => {
                        decrypted = true;
                        sigs = dec.signatures;
                        take_inner(
                            &dec.plaintext,
                            &mut body,
                            &mut subject,
                            &mut protected_subject,
                            &mut gossip_values,
                            &mut inner_recipients,
                            &mut decrypt_error,
                        );
                    }
                    Err(e) => decrypt_error = Some(e.to_string()),
                }
            }
            MessageKind::PgpMimeSigned {
                signed_part,
                signature,
                ..
            } => {
                was_signed = true;
                sigs = match verify_detached(&signed_part, &signature, &known) {
                    Ok(s) => s,
                    Err(e) => vec![SignatureStatus::UnknownKey {
                        key_id: format!("unverifiable: {e}"),
                    }],
                };
                let mut unused_gossip = Vec::new();
                take_inner(
                    &signed_part,
                    &mut body,
                    &mut subject,
                    &mut protected_subject,
                    &mut unused_gossip,
                    &mut inner_recipients,
                    &mut decrypt_error,
                );
            }
            MessageKind::InlinePgp { armored } => {
                if armored.starts_with("-----BEGIN PGP MESSAGE-----") {
                    was_encrypted = true;
                    match decrypt_and_verify(armored.as_bytes(), &identities, &known) {
                        Ok(dec) => {
                            decrypted = true;
                            sigs = dec.signatures;
                            body.text = Some(String::from_utf8_lossy(&dec.plaintext).into_owned());
                        }
                        Err(e) => decrypt_error = Some(e.to_string()),
                    }
                } else {
                    // Clear-signed inline text: shown as-is, not verified (legacy format).
                    body.text = Some(armored);
                }
            }
        }
        was_signed = was_signed || !sigs.is_empty();
        let signature = summarize(&sigs, &ctx.fp_to_addr);
        let signature = self.identity_on_message(acct, folder, uid, h, from_is_own, signature);
        // mail-parser reports the text part as an HTML body too when there is no real HTML.
        if body.html.is_some() && body.html == body.text {
            body.html = None;
        }

        // Autocrypt gossip, only from inside an encrypted payload, only about recipients.
        if decrypted && !gossip_values.is_empty() {
            let mut allowed: Vec<String> =
                h.to.iter()
                    .chain(h.cc.iter())
                    .map(|m| m.address.to_ascii_lowercase())
                    .collect();
            allowed.extend(inner_recipients.iter().cloned());
            for v in &gossip_values {
                let Ok(g) = AutocryptGossip::parse(v) else {
                    continue;
                };
                let addr = g.addr.to_ascii_lowercase();
                if !allowed.contains(&addr) {
                    continue;
                }
                if ctx.own_addresses.contains(&addr) {
                    continue;
                }
                peers_changed |= self.update_peer_from_gossip(&g, effective)?;
            }
        }

        let failed = was_encrypted && !decrypted;
        // Content-ID included: an HTML body's `cid:` images name their part by it.
        let attachments = body
            .attachments
            .into_iter()
            .map(NewAttachment::from)
            .collect();
        let message = NewMessage {
            account_id: acct.id,
            folder_id: folder.id,
            uid,
            message_id: h.message_id.clone(),
            from,
            to: h.to.iter().map(to_address).collect(),
            cc: h.cc.iter().map(to_address).collect(),
            subject,
            protected_subject,
            date: h.date,
            received_at: received_ts,
            flags,
            was_encrypted,
            decrypted,
            was_signed,
            signature,
            signatures_json: serde_json::to_string(&sigs)?,
            text: body.text,
            html: body.html,
            in_reply_to: h.in_reply_to.clone(),
            references: h.references.clone(),
            decrypt_error,
            raw: raw.to_vec(),
            attachments,
        };
        Ok(Processed {
            message,
            decrypted_ok: decrypted,
            failed,
            peers_changed,
        })
    }

    /// One pass over a folder of an open session (see [`FolderPass`]): new mail — for a folder
    /// with nothing stored yet only its newest `pass.window` UIDs, newest batch first — then,
    /// on a later pass, up to `pass.backfill` older messages below the window's floor, newest
    /// first; then the spam / filter and auto-reply passes over everything it stored. The
    /// folder's watermarks (`last_uid`, `floor_uid`, [`FolderRow`]) move after every batch, so
    /// an interrupted pass resumes without gaps or re-fetches.
    pub(crate) async fn sync_folder(
        &self,
        ctx: &mut SyncContext,
        acct: &AccountRow,
        client: &mut ImapClient,
        folder_name: &str,
        pass: FolderPass,
        progress: Progress<'_>,
    ) -> Result<SyncReport> {
        Ok(self
            .sync_folder_counted(ctx, acct, client, folder_name, pass, progress)
            .await?
            .0)
    }

    /// [`Engine::sync_folder`] plus the number of older UIDs its backfill step asked for (what
    /// [`Engine::backfill`] charges against its budget).
    async fn sync_folder_counted(
        &self,
        ctx: &mut SyncContext,
        acct: &AccountRow,
        client: &mut ImapClient,
        folder_name: &str,
        pass: FolderPass,
        progress: Progress<'_>,
    ) -> Result<(SyncReport, usize)> {
        // A long-lived context (watch) may predate keys stored since by anyone.
        self.fresh_keys(ctx, acct)?;
        let mailbox = client.select(folder_name).await?;
        let mut folder = self.store().folder(acct.id, folder_name)?;
        let mut reset = false;
        if folder.uidvalidity != 0 && folder.uidvalidity != mailbox.uidvalidity {
            tracing::warn!(
                folder = folder_name,
                old = folder.uidvalidity,
                new = mailbox.uidvalidity,
                "UIDVALIDITY changed; resyncing folder from scratch"
            );
            self.store().reset_folder(folder.id, mailbox.uidvalidity)?;
            reset = true;
            folder = self.store().folder(acct.id, folder_name)?;
        } else if folder.uidvalidity == 0 {
            self.store()
                .update_folder(folder.id, mailbox.uidvalidity, folder.last_uid)?;
            folder.uidvalidity = mailbox.uidvalidity;
        }
        let mut report = SyncReport {
            account: acct.email.clone(),
            folders: vec![FolderSync {
                name: folder_name.to_string(),
                new: 0,
                uidvalidity_reset: reset,
                ..FolderSync::default()
            }],
            ..SyncReport::default()
        };
        let mut first_window = false;
        let mut older_asked = 0usize;
        // The folder's `UID SEARCH UID 1:*`, asked at most once per pass: by the reconcile when
        // it runs ahead of the new mail (below), else by the backfill, and reused by whichever
        // comes second.
        let mut live_uids: Option<BTreeSet<u32>> = None;
        let mut reconciled = false;
        if pass.new_mail {
            let uids = client.fetch_new_uids(folder.last_uid).await?;
            let fresh = folder.last_uid == 0
                && folder.floor_uid == 0
                && !self.store().folder_has_messages(acct.id, folder.id)?;
            if fresh && pass.window > 0 {
                first_window = true;
                let older = uids.len().saturating_sub(pass.window);
                let newest_first: Vec<u32> = uids[older..].iter().rev().copied().collect();
                report.folders[0].older_pending = Some(u32::try_from(older).unwrap_or(u32::MAX));
                let step = FetchStep {
                    phase: SyncPhase::Initial,
                    reaches_bottom: older == 0,
                    total_known: mailbox.exists,
                };
                self.fetch_and_store(
                    ctx,
                    acct,
                    client,
                    &mut folder,
                    &newest_first,
                    HashMap::new(),
                    step,
                    &mut report,
                    progress,
                )
                .await?;
            } else {
                // An incremental pass reconciles *before* it fetches the new mail, so that the
                // one flags fetch of the stored mail also carries the sizes the new mail's
                // batch plan needs (`RFC822.SIZE` of the new UIDs): one `UID FETCH` instead of
                // two. On a server that pays per command in proportion to the mailbox (G33:
                // GreenMail, ≈0.7 s per FETCH of a 10k folder) that is the difference between
                // an incremental sync costing what it did before the reconcile existed and
                // costing one FETCH more. The new mail itself is not reconciled: it is fetched
                // with its flags a moment later.
                //
                // Its failure must not cost the new mail, though: a reconcile that fails here
                // (a flags fetch that times out on a huge folder over a slow link, the
                // empty-search guard) would otherwise fail every later pass the same way before
                // any new mail is stored. So the error is logged, the new mail is fetched with
                // its own sizes fetch, and the reconcile runs once more at the end of the pass
                // (`!reconciled` below), where its error is the pass's — the order a sync had
                // before the reconcile moved ahead.
                let mut sizes = HashMap::new();
                if pass.reconcile {
                    let size_for: &[u32] = if uids.len() > 1 { &uids } else { &[] };
                    match self
                        .reconcile_with(
                            client,
                            folder.id,
                            folder_name,
                            mailbox.exists,
                            None,
                            size_for,
                        )
                        .await
                    {
                        Ok(r) => {
                            report.folders[0].removed = r.removed;
                            report.folders[0].flags_changed = r.flags_changed;
                            live_uids = r.live;
                            sizes = r.sizes;
                            reconciled = true;
                        }
                        Err(e) => {
                            tracing::warn!(
                                folder = folder_name,
                                error = %e,
                                "reconcile ahead of the new mail failed; fetching the new mail \
                                 first and reconciling after it"
                            );
                            // The new mail goes over a drained (or fresh) session.
                            self.recover_session(acct, client, folder_name, mailbox.uidvalidity)
                                .await?;
                        }
                    }
                }
                let step = FetchStep {
                    phase: SyncPhase::Incremental,
                    reaches_bottom: false,
                    total_known: mailbox.exists,
                };
                self.fetch_and_store(
                    ctx,
                    acct,
                    client,
                    &mut folder,
                    &uids,
                    sizes,
                    step,
                    &mut report,
                    progress,
                )
                .await?;
            }
        }
        // From here on new mail may already be stored, and `last_uid` moved past it: a pass
        // that left on an error now would never show that mail to the spam/filter pass (G25)
        // or the out-of-office replies (G24) — the next pass does not see it as new. So a
        // failure of the backfill step or of the trailing reconcile (on a big folder over a
        // slow link that can be every pass) is held, those passes run over the new mail, and
        // the error is the pass's only after them.
        let mut held: Option<Error> = None;
        if pass.backfill > 0 && !first_window && folder.more_to_backfill() {
            let step_result: Result<()> = async {
                let floor = folder.floor_uid;
                // `1:*`, not `1:floor-1`: async-imap ends a SEARCH silently on EOF or a tagged NO,
                // and an empty answer for a folder that has mail can only be such a failure — an
                // empty `1:floor-1` could also mean "nothing older", which would end the backfill
                // for good. Reused when the reconcile has just asked it (with the same guard).
                let all: BTreeSet<u32> = match live_uids.take() {
                    Some(set) => set,
                    None => {
                        let all = client.uid_search("UID 1:*").await?;
                        if all.is_empty() && mailbox.exists > 0 {
                            return Err(Error::Connection(format!(
                            "UID SEARCH of {folder_name} came back empty with {} message(s) in it",
                            mailbox.exists
                        )));
                        }
                        all.into_iter().collect()
                    }
                };
                let below: Vec<u32> = all.iter().copied().filter(|u| *u < floor).collect();
                live_uids = Some(all);
                let take = below.len().min(pass.backfill);
                let rest = below.len() - take;
                let newest_first: Vec<u32> = below[rest..].iter().rev().copied().collect();
                older_asked = newest_first.len();
                report.folders[0].older_pending = Some(u32::try_from(rest).unwrap_or(u32::MAX));
                let step = FetchStep {
                    phase: SyncPhase::Backfill,
                    reaches_bottom: rest == 0,
                    total_known: mailbox.exists,
                };
                self.fetch_and_store(
                    ctx,
                    acct,
                    client,
                    &mut folder,
                    &newest_first,
                    HashMap::new(),
                    step,
                    &mut report,
                    progress,
                )
                .await
            }
            .await;
            if let Err(e) = step_result {
                held = Some(e);
            }
        }
        if held.is_none() && pass.reconcile && !reconciled {
            match self
                .reconcile_selected(client, folder.id, folder_name, mailbox.exists, live_uids)
                .await
            {
                Ok((removed, flags_changed)) => {
                    report.folders[0].removed = removed;
                    report.folders[0].flags_changed = flags_changed;
                }
                Err(e) => held = Some(e),
            }
        }
        report.folders[0].more_to_backfill = folder.more_to_backfill();
        if !folder.more_to_backfill() {
            report.folders[0].older_pending = Some(0);
        }
        report.new_ids.sort_unstable();
        // The session the failed step leaves may carry an abandoned command's answer; the
        // spam/filter pass moves and flags by UID over it, so it is drained or replaced first.
        // Where that is impossible (no connection, or UIDVALIDITY changed — the UIDs would
        // name other messages) the pass is skipped rather than run on a bad session.
        let session_ok = match &held {
            Some(e) if !report.new_ids.is_empty() => {
                tracing::warn!(
                    folder = folder_name,
                    error = %e,
                    new = report.new_ids.len(),
                    "sync step failed after new mail was stored; filtering it before reporting"
                );
                match self
                    .recover_session(acct, client, folder_name, mailbox.uidvalidity)
                    .await
                {
                    Ok(()) => true,
                    Err(r) => {
                        tracing::warn!(
                            folder = folder_name,
                            error = %r,
                            "no usable session for the spam/filter pass of the new mail"
                        );
                        false
                    }
                }
            }
            _ => true,
        };
        // G25: classify the new messages, move spam, apply filter rules (never fails the sync).
        if session_ok {
            self.spam_after_sync(acct, &folder, client, &report.new_ids)
                .await;
        }
        if let Some(f) = report.folders.first_mut() {
            f.new = report.new;
        }
        // G24: out-of-office replies. Only after the spam/filter pass ran: the responder keeps
        // spam out only because that pass moved it to Junk, and it advances its cursor past
        // every message it looks at, so running it over unfiltered mail would answer spam
        // for good. When skipped here the cursor stays, and a later `run_autoreplies` (or the
        // next pass's evaluation) still reaches this mail.
        if session_ok {
            self.autoreply_after_sync(acct, &report).await;
        }
        match held {
            Some(e) => Err(e),
            None => Ok((report, older_asked)),
        }
    }

    /// Make `client` usable again after a command of it failed (a timeout, typically) with
    /// `folder_name` selected. A command abandoned on a timeout leaves its answer in flight,
    /// and async-imap hands another tag's `FETCH` lines to the next FETCH as its own — stale
    /// flags read as a body answer. NOOP reads through to its own tagged reply, draining them.
    /// If even that fails the session is unusable and is replaced by a fresh one with the
    /// folder selected again; a UIDVALIDITY other than `uidvalidity` there is an error (the
    /// UIDs of this pass would name other messages).
    async fn recover_session(
        &self,
        acct: &AccountRow,
        client: &mut ImapClient,
        folder_name: &str,
        uidvalidity: u32,
    ) -> Result<()> {
        let Err(noop) = client.noop().await else {
            return Ok(());
        };
        tracing::warn!(
            folder = folder_name,
            error = %noop,
            "session unusable after the failed command; reconnecting"
        );
        *client = self.imap_for(acct).await?;
        let again = client.select(folder_name).await?;
        if again.uidvalidity != uidvalidity {
            return Err(Error::Connection(format!(
                "UIDVALIDITY of {folder_name} changed during the sync; \
                 the next sync starts it over"
            )));
        }
        Ok(())
    }

    /// Fetch `uids` (in this order) in batches of at most `fetch_batch` messages and
    /// `fetch_batch_bytes` bytes (sizes asked for first with `RFC822.SIZE`), process and store
    /// them, and move the folder's watermarks after every batch: an incremental step raises
    /// `last_uid`; a first window sets `last_uid` to its top and lowers `floor_uid` batch by
    /// batch, like a backfill step does; `reaches_bottom` (nothing older exists) ends that at 1.
    /// Overlapped: the next batch's `UID FETCH` goes on the wire before the current batch is
    /// processed, so the server prepares it while we parse, decrypt and store (one
    /// connection, one command in flight; the processing yields between messages so the
    /// response is read as it arrives). Reports every stored batch to `progress`.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_and_store(
        &self,
        ctx: &mut SyncContext,
        acct: &AccountRow,
        client: &mut ImapClient,
        folder: &mut FolderRow,
        uids: &[u32],
        mut sizes: HashMap<u32, u32>,
        step: FetchStep,
        report: &mut SyncReport,
        progress: Progress<'_>,
    ) -> Result<()> {
        if uids.is_empty() {
            if step.phase == SyncPhase::Backfill && step.reaches_bottom && folder.more_to_backfill()
            {
                folder.floor_uid = 1;
                self.store().set_folder_marks(
                    folder.id,
                    folder.uidvalidity,
                    folder.last_uid,
                    folder.floor_uid,
                )?;
            }
            return Ok(());
        }
        // One message needs no plan; for more, the sizes bound the bytes of every batch. Sizes
        // the caller already has (the reconcile asks for them alongside the flags) are not
        // asked again; a UID it has none for is (it may also simply be gone).
        if uids.len() > 1 {
            let missing: Vec<u32> = uids
                .iter()
                .copied()
                .filter(|u| !sizes.contains_key(u))
                .collect();
            if !missing.is_empty() {
                sizes.extend(client.fetch_sizes(&missing).await?);
            }
        }
        let plan = plan_batches(
            uids,
            &sizes,
            self.config().fetch_batch,
            self.config().fetch_batch_bytes,
        );
        let mut tally = Tally {
            planned: u32::try_from(uids.len()).unwrap_or(u32::MAX),
            ..Tally::default()
        };
        let mut pending = fetch_batch_checked(client, &plan[0]).await?;
        for (i, chunk) in plan.iter().enumerate() {
            let current = std::mem::take(&mut pending);
            let next = plan.get(i + 1);
            let last = i + 1 == plan.len();
            let (fetched_next, stored) = tokio::join!(
                async {
                    match next {
                        Some(u) => Some(fetch_batch_checked(client, u).await),
                        None => None,
                    }
                },
                self.store_batch(
                    ctx,
                    acct,
                    folder,
                    chunk,
                    current,
                    FetchStep {
                        reaches_bottom: step.reaches_bottom && last,
                        ..step
                    },
                    &mut tally,
                    report,
                    &mut *progress,
                ),
            );
            // The batch just processed is stored (with its marks) before a failed fetch of
            // the next one is reported: progress is never thrown away.
            stored?;
            if let Some(r) = fetched_next {
                pending = r?;
            }
        }
        Ok(())
    }

    /// Process one fetched batch (yielding between messages, see [`Engine::fetch_and_store`]),
    /// store it, move the watermarks past `chunk` (every UID of it is stored now, or gone from
    /// the server) and report it.
    #[allow(clippy::too_many_arguments)]
    async fn store_batch(
        &self,
        ctx: &mut SyncContext,
        acct: &AccountRow,
        folder: &mut FolderRow,
        chunk: &[u32],
        batch: Vec<FetchedMessage>,
        step: FetchStep,
        tally: &mut Tally,
        report: &mut SyncReport,
        progress: Progress<'_>,
    ) -> Result<()> {
        tally.fetched += u32::try_from(batch.len()).unwrap_or(u32::MAX);
        let mut processed = Vec::with_capacity(batch.len());
        for msg in batch {
            let p =
                self.process_message(ctx, acct, folder, msg.uid, &msg.raw, msg.flags, Utc::now())?;
            if p.peers_changed {
                tracing::debug!(uid = msg.uid, "autocrypt peer state updated");
            }
            // One event per processed message: scripts/perf_sync.sh times the pipeline by it.
            tracing::debug!(uid = msg.uid, "message processed");
            processed.push(p);
            tokio::task::yield_now().await;
        }
        let mut marks = folder.clone();
        let lo = chunk.iter().copied().min().unwrap_or(0);
        let hi = chunk.iter().copied().max().unwrap_or(0);
        match step.phase {
            SyncPhase::Incremental => marks.last_uid = marks.last_uid.max(hi),
            SyncPhase::Initial => {
                marks.last_uid = marks.last_uid.max(hi);
                marks.floor_uid = lo;
            }
            SyncPhase::Backfill => marks.floor_uid = lo,
        }
        if step.reaches_bottom && step.phase != SyncPhase::Incremental {
            marks.floor_uid = 1;
        }
        // The batch and its watermarks in one transaction: all stored, or nothing and the
        // marks unchanged (the next sync fetches the batch again).
        let messages: Vec<&NewMessage> = processed.iter().map(|p| &p.message).collect();
        let (ids, local) = {
            let mut store = self.store();
            let ids = store.insert_batch(&messages, &marks)?;
            (ids, store.folder_message_count(acct.id, folder.id)?)
        };
        *folder = marks;
        for (p, id) in processed.iter().zip(ids) {
            if let Some(id) = id {
                tally.stored += 1;
                report.new += 1;
                report.new_ids.push(id);
                if p.decrypted_ok {
                    report.decrypted += 1;
                }
                if p.failed {
                    report.failed += 1;
                }
            }
        }
        progress(SyncProgress {
            account: acct.email.clone(),
            folder: folder.name.clone(),
            phase: step.phase,
            fetched: tally.fetched,
            stored: tally.stored,
            planned: tally.planned,
            total_known: step.total_known,
            local,
            more_to_backfill: folder.more_to_backfill(),
        });
        Ok(())
    }

    /// Flags that describe a session rather than a message, and so must never be compared or
    /// stored: `\Recent` is set for exactly one session per message, so a message fetched on
    /// the sync that first saw it carries it, no later `FETCH FLAGS` reports it, and comparing
    /// it would make every message look changed on every reconcile, for ever.
    fn durable_flags(flags: &[String]) -> Vec<String> {
        let mut out: Vec<String> = flags
            .iter()
            .filter(|f| !f.eq_ignore_ascii_case("\\Recent"))
            .cloned()
            .collect();
        out.sort_unstable();
        out
    }

    /// Converge the stored copy of one *already selected* folder with the server: drop the
    /// messages whose UID is gone, bring flags that changed elsewhere into line. Returns
    /// `(removed, flags_changed)`.
    ///
    /// This is what makes Sealbox usable beside webmail and a phone. Before it, the sync only
    /// ever added: `FLAGS` were read inside the body fetch of *new* UIDs, and nothing removed a
    /// local message whose UID had vanished, so mail deleted elsewhere stayed for ever, mail
    /// read elsewhere stayed bold, and an emptied Trash stayed full.
    ///
    /// **Deletion is driven by `UID SEARCH`, not by the flags fetch**, and that separation is
    /// the whole safety argument. A `UID FETCH (FLAGS)` that answers for none of the UIDs it
    /// was asked about looks, from the reply alone, exactly like "every one of them is gone" —
    /// and that is a perfectly ordinary state of affairs (we hold UID 1; another client
    /// expunged it and appended UID 2, which we have never fetched), so it cannot be rejected
    /// as a protocol failure either. Driving deletions off that reply would mean either losing
    /// mail to a truncated response or refusing a legitimate convergence.
    ///
    /// So the two questions are asked separately, each of the command that can answer it
    /// safely:
    ///
    /// * *which UIDs still exist* — one `UID SEARCH UID 1:*` for the folder, whose own failure
    ///   mode (async-imap ends the stream silently on EOF or a tagged NO) is caught by the
    ///   guard this code shares with [`Engine::sync_folder_counted`]: an empty answer for a
    ///   mailbox the server says holds `exists > 0` messages is an error, and nothing is
    ///   deleted. Stored UIDs the search does not list are gone, by set difference.
    /// * *what the flags are* — `UID FETCH (FLAGS)` over the survivors, as a few UID ranges
    ///   ([`flag_fetch_runs`]; one for an ordinary folder), not a list of them. Its worst
    ///   failure now costs a missed flag update, never a message: a short answer simply leaves
    ///   those messages as they were.
    ///
    /// UIDVALIDITY is not re-checked here: `sync_folder_counted` resets the folder before this
    /// runs, which empties the stored set, so there is nothing of the old incarnation left to
    /// reconcile.
    pub(crate) async fn reconcile_selected(
        &self,
        client: &mut ImapClient,
        folder_id: i64,
        folder_name: &str,
        exists: u32,
        known_live: Option<BTreeSet<u32>>,
    ) -> Result<(u32, u32)> {
        let r = self
            .reconcile_with(client, folder_id, folder_name, exists, known_live, &[])
            .await?;
        Ok((r.removed, r.flags_changed))
    }

    /// [`Engine::reconcile_selected`], which can also bring back the sizes of `size_for` (the
    /// new UIDs an incremental sync is about to fetch) in the same `UID FETCH` as the flags,
    /// and hands back the `UID SEARCH` answer for a backfill to reuse. `size_for` is only ever
    /// asked about, never stored, deleted or flagged here.
    async fn reconcile_with(
        &self,
        client: &mut ImapClient,
        folder_id: i64,
        folder_name: &str,
        exists: u32,
        known_live: Option<BTreeSet<u32>>,
        size_for: &[u32],
    ) -> Result<Reconciled> {
        let stored = self.store().uids_with_ids(folder_id)?;
        if stored.is_empty() {
            return Ok(Reconciled::default());
        }
        // A backfill pass has just run this very search for its own purposes; reusing its
        // answer keeps an ordinary sync at the same number of round trips it always had.
        let live_uids: BTreeSet<u32> = match known_live {
            Some(set) => set,
            None => {
                // `1:*` rather than a set of the stored UIDs: the answer is then also usable as
                // proof that the search works at all, which is what the guard below rests on.
                let found = client.uid_search("UID 1:*").await?;
                if found.is_empty() && exists > 0 {
                    return Err(Error::Connection(format!(
                        "UID SEARCH of {folder_name} came back empty with {exists} message(s) in \
                         it; refusing to treat that as a deletion"
                    )));
                }
                found.into_iter().collect()
            }
        };

        let mut removed = 0u32;
        let mut survivors: Vec<(u32, i64, Vec<String>)> = Vec::with_capacity(stored.len());
        for (uid, id, flags) in stored {
            if live_uids.contains(&uid) {
                survivors.push((uid, id, flags));
            } else {
                self.store().delete_message(id)?;
                removed += 1;
            }
        }

        let mut flags_changed = 0u32;
        let survivor_uids: Vec<u32> = survivors.iter().map(|(uid, _, _)| *uid).collect();
        let by_uid: HashMap<u32, (i64, &Vec<String>)> = survivors
            .iter()
            .map(|(uid, id, flags)| (*uid, (*id, flags)))
            .collect();
        let runs = flag_fetch_runs(&survivor_uids, &live_uids);
        let size_ranges = uid_ranges(size_for);
        let want_size: std::collections::HashSet<u32> = size_for.iter().copied().collect();
        let mut sizes = HashMap::new();
        let commands = plan_flag_commands(
            &runs,
            &live_uids,
            &size_ranges,
            RECONCILE_RANGES,
            RECONCILE_UIDS,
        );
        for command in commands {
            let live = client
                .fetch_flags_ranges(&command.ranges, command.with_sizes)
                .await?;
            let asked = command.flag_uids;
            let mut answered = 0usize;
            for (uid, server_flags, size) in live {
                if want_size.contains(&uid) {
                    if let Some(size) = size {
                        sizes.insert(uid, size);
                    }
                }
                // The ranges hold only stored UIDs (or expunged ones), but the answer is the
                // server's: anything it names that we do not hold is not ours to touch.
                let Some(&(id, stored_flags)) = by_uid.get(&uid) else {
                    continue;
                };
                answered += 1;
                let want = Self::durable_flags(&server_flags);
                if want != Self::durable_flags(stored_flags) {
                    self.store().update_flags(id, &want)?;
                    flags_changed += 1;
                }
            }
            if answered < asked {
                // These UIDs were in the search a moment ago, so a short answer is either a
                // race (expunged since) or a truncated response. Either way the next sync will
                // see it; leaving the flags alone loses nothing.
                tracing::debug!(
                    folder = folder_name,
                    asked,
                    answered,
                    "flags fetch answered for fewer UIDs than it was asked about"
                );
            }
        }
        if removed > 0 || flags_changed > 0 {
            tracing::info!(
                folder = folder_name,
                removed,
                flags_changed,
                "reconciled with the server"
            );
        }
        Ok(Reconciled {
            removed,
            flags_changed,
            live: Some(live_uids),
            sizes,
        })
    }

    /// Converge one folder of one account with the server without fetching any new mail:
    /// [`Engine::reconcile_selected`] with its own connection. Takes the account's mailbox
    /// lock. A sync already does this for the folders it visits; this is for a client that
    /// wants only the convergence (and for the gate).
    pub async fn reconcile_folder(&self, email: &str, folder_name: &str) -> Result<SyncReport> {
        let acct = self.account_row(email)?;
        let _guard = self.account_lock(acct.id).await;
        let mut client = self.imap_for(&acct).await?;
        let mailbox = match client.select(folder_name).await {
            Ok(m) => m,
            Err(e) => {
                let _ = client.logout().await;
                return Err(e.into());
            }
        };
        let mut folder = self.store().folder(acct.id, folder_name)?;
        // A UIDVALIDITY change makes every stored UID meaningless, so reconciling against them
        // would delete the lot *and leave the watermarks pointing into the old incarnation*,
        // where new mail would never be fetched back. A sync handles this before it reaches the
        // reconcile (`sync_folder_counted`); this entry point has to handle it itself.
        let mut dropped_by_reset = 0u32;
        if folder.uidvalidity != 0 && folder.uidvalidity != mailbox.uidvalidity {
            tracing::warn!(
                folder = folder_name,
                old = folder.uidvalidity,
                new = mailbox.uidvalidity,
                "UIDVALIDITY changed; the folder needs a resync, not a reconcile"
            );
            // Counted before the reset, so the report says how much went and not merely that
            // something did.
            dropped_by_reset = self.store().folder_message_count(acct.id, folder.id)?;
            self.store().reset_folder(folder.id, mailbox.uidvalidity)?;
            folder = self.store().folder(acct.id, folder_name)?;
        }
        let out = if dropped_by_reset > 0 {
            Ok((dropped_by_reset, 0)) // reset_folder already dropped the stored copy
        } else {
            self.reconcile_selected(&mut client, folder.id, folder_name, mailbox.exists, None)
                .await
        };
        let _ = client.logout().await;
        let (removed, flags_changed) = out?;
        Ok(SyncReport {
            account: acct.email.clone(),
            folders: vec![FolderSync {
                name: folder_name.to_string(),
                removed,
                flags_changed,
                uidvalidity_reset: dropped_by_reset > 0,
                more_to_backfill: folder.more_to_backfill(),
                ..FolderSync::default()
            }],
            ..SyncReport::default()
        })
    }

    /// The pass [`Engine::sync`] and [`Engine::sync_folder_role`] run on a folder.
    pub(crate) fn sync_pass(&self) -> FolderPass {
        FolderPass {
            new_mail: true,
            window: self.config().sync_window,
            backfill: self.config().backfill_per_sync,
            reconcile: true,
        }
    }

    /// The pass [`Engine::watch`] runs: new mail only (a never-synced INBOX gets its window).
    pub(crate) fn watch_pass(&self) -> FolderPass {
        FolderPass {
            new_mail: true,
            window: self.config().sync_window,
            backfill: 0,
            reconcile: true,
        }
    }

    /// Fetch older mail: up to `max_messages` (`None` = all of it) messages below the window
    /// of every folder of the account that still has some, INBOX first, newest first, with the
    /// spam / filter and auto-reply passes a sync runs. Returns at once when nothing is left.
    /// Progress is saved after every batch, so a later call (or sync) continues where this one
    /// stopped. Takes the account's mailbox lock.
    pub async fn backfill(&self, email: &str, max_messages: Option<usize>) -> Result<SyncReport> {
        self.backfill_with_progress(email, max_messages, |_| {})
            .await
    }

    /// [`Engine::backfill`], calling `on_progress` after every stored batch.
    pub async fn backfill_with_progress<F>(
        &self,
        email: &str,
        max_messages: Option<usize>,
        mut on_progress: F,
    ) -> Result<SyncReport>
    where
        F: FnMut(SyncProgress) + Send,
    {
        let acct = self.account_row(email)?;
        let _guard = self.account_lock(acct.id).await;
        let mut report = SyncReport {
            account: acct.email.clone(),
            ..SyncReport::default()
        };
        let folders: Vec<FolderRow> = self
            .store()
            .folders_of_account(acct.id)?
            .into_iter()
            .filter(FolderRow::more_to_backfill)
            .collect();
        if folders.is_empty() || max_messages == Some(0) {
            return Ok(report);
        }
        let mut ctx = self.sync_context(&acct)?;
        let mut client = self.imap_for(&acct).await?;
        let mut budget = max_messages.unwrap_or(usize::MAX);
        for (k, f) in folders.iter().enumerate() {
            if budget == 0 {
                break;
            }
            let pass = FolderPass {
                new_mail: false,
                window: self.config().sync_window,
                backfill: budget,
                reconcile: false,
            };
            match self
                .sync_folder_counted(
                    &mut ctx,
                    &acct,
                    &mut client,
                    &f.name,
                    pass,
                    &mut on_progress,
                )
                .await
            {
                Ok((r, asked)) => {
                    budget = budget.saturating_sub(asked);
                    report.merge(r);
                }
                // A folder that vanished on the server must not hold up the others; the
                // first one (INBOX) failing means the session is unusable.
                Err(e) if k > 0 => {
                    tracing::warn!(folder = %f.name, "backfill skipped: {e}");
                }
                Err(e) => {
                    let _ = client.logout().await;
                    return Err(e);
                }
            }
        }
        let _ = client.logout().await;
        Ok(report)
    }

    /// Sync one folder of an account by special-use role (the folder the server's `LIST`
    /// mapped to it, else the provider default) on demand — the Trash / Junk / Archive chips.
    /// INBOX syncs run the spam / filter and auto-reply passes exactly like [`Engine::sync`]
    /// does; the Sent folder is not touched. A role the server has no folder for yields an
    /// empty report (`folders` empty). Takes the account's mailbox lock.
    pub async fn sync_folder_role(&self, email: &str, role: FolderRole) -> Result<SyncReport> {
        let acct = self.account_row(email)?;
        let _guard = self.account_lock(acct.id).await;
        let mut ctx = self.sync_context(&acct)?;
        let mut client = self.imap_for(&acct).await?;
        let folder = if role == FolderRole::Inbox {
            Some("INBOX".to_string())
        } else {
            match self
                .resolve_folder_live(&acct, &mut client, role, false)
                .await
            {
                Ok(name) => Some(name),
                Err(Error::InvalidInput(m)) => {
                    tracing::debug!(email = %acct.email, "{m}; nothing to sync");
                    None
                }
                Err(e) => {
                    let _ = client.logout().await;
                    return Err(e);
                }
            }
        };
        let report = match folder {
            Some(name) => {
                let pass = self.sync_pass();
                let report = self
                    .sync_folder(&mut ctx, &acct, &mut client, &name, pass, &mut |_| {})
                    .await;
                if report.is_ok() && role == FolderRole::Drafts {
                    // Saved drafts follow their server copies (drafts_imap.rs); a failure
                    // there does not fail the folder sync.
                    match self.sync_drafts_locked(&acct, &mut client, &name).await {
                        Ok(d) => tracing::info!(
                            email = %acct.email,
                            imported = d.imported,
                            updated = d.updated,
                            uploaded = d.uploaded,
                            "drafts synced with {name}"
                        ),
                        Err(e) => tracing::warn!(email = %acct.email, "draft sync: {e}"),
                    }
                }
                report
            }
            None => Ok(SyncReport {
                account: acct.email.clone(),
                ..SyncReport::default()
            }),
        };
        let _ = client.logout().await;
        report
    }

    /// Sync INBOX (and the Sent folder when the server has one) for one account. Takes the
    /// account's mailbox lock for the whole run. A folder's first sync stores its newest
    /// [`crate::EngineConfig::sync_window`] messages only; later syncs add up to
    /// [`crate::EngineConfig::backfill_per_sync`] older ones after the new mail.
    pub async fn sync(&self, email: &str) -> Result<SyncReport> {
        self.sync_with_progress(email, |_| {}).await
    }

    /// [`Engine::sync`], calling `on_progress` after every stored batch (each one is committed
    /// and listable by then): what a UI uses to show mail while a big first sync runs.
    pub async fn sync_with_progress<F>(&self, email: &str, mut on_progress: F) -> Result<SyncReport>
    where
        F: FnMut(SyncProgress) + Send,
    {
        let acct = self.account_row(email)?;
        let _guard = self.account_lock(acct.id).await;
        let mut ctx = self.sync_context(&acct)?;
        let mut client = self.imap_for(&acct).await?;
        let pass = self.sync_pass();
        let mut report = self
            .sync_folder(
                &mut ctx,
                &acct,
                &mut client,
                "INBOX",
                pass,
                &mut on_progress,
            )
            .await?;
        match client.list_folders().await {
            Ok(folders) => {
                // Remember the special-use mapping (Sent/Trash/Junk/…) for the other paths.
                if let Err(e) = self.remember_folder_roles(&acct, &folders) {
                    tracing::debug!("could not store folder roles: {e}");
                }
                if let Some(sent) = find_sent_folder(&folders) {
                    if !sent.eq_ignore_ascii_case("INBOX") {
                        match self
                            .sync_folder(
                                &mut ctx,
                                &acct,
                                &mut client,
                                &sent,
                                pass,
                                &mut on_progress,
                            )
                            .await
                        {
                            Ok(r) => report.merge(r),
                            Err(e) => {
                                tracing::warn!(folder = %sent, "sent folder sync failed: {e}")
                            }
                        }
                    }
                }
            }
            Err(e) => tracing::warn!("LIST failed: {e}"),
        }
        let _ = client.logout().await;
        Ok(report)
    }

    /// Sync every account; errors are reported per account, not propagated.
    pub async fn sync_all(&self) -> Vec<(String, Result<SyncReport>)> {
        let accounts = self.list_accounts().unwrap_or_default();
        let mut out = Vec::with_capacity(accounts.len());
        for a in accounts {
            let r = self.sync(&a.email).await;
            out.push((a.email, r));
        }
        out
    }

    /// Watch INBOX with IMAP IDLE. After an initial catch-up sync, every server notification
    /// triggers a sync and `on_event(WatchEvent::NewMail)`; `on_event` returns `false` to stop.
    /// `idle_timeout` bounds each IDLE round (servers drop idle sessions after ~30 min).
    ///
    /// Before every IDLE round the watcher looks once more for mail the last sync did not see
    /// (`watch_catch_up`): a message that arrives after a sync's `UID SEARCH` is
    /// announced in-band (during the following FETCH / STORE / MOVE) and never again in IDLE,
    /// so it would otherwise wait for the next new mail. It is synced and reported as
    /// `NewMail` before `Idle`.
    pub async fn watch<F>(&self, email: &str, idle_timeout: Duration, mut on_event: F) -> Result<()>
    where
        F: FnMut(WatchEvent) -> bool,
    {
        let acct = self.account_row(email)?;
        let mut ctx = self.sync_context(&acct)?;
        let mut client = self.imap_for(&acct).await?;
        let idle_timeout = idle_timeout.min(Duration::from_secs(29 * 60));
        // The mailbox lock is held only while syncing, never while IDLE waits, so a manual
        // sync of the same account slots in between IDLE rounds instead of blocking for the
        // whole timeout.
        let initial = {
            let _guard = self.account_lock(acct.id).await;
            let pass = self.watch_pass();
            self.sync_folder(&mut ctx, &acct, &mut client, "INBOX", pass, &mut |_| {})
                .await?
        };
        if initial.changed() && !on_event(WatchEvent::NewMail { report: initial }) {
            let _ = client.logout().await;
            return Ok(());
        }
        if !client.has_capability("IDLE") {
            let _ = client.logout().await;
            return Err(Error::Imap(sealbox_mail::ImapError::IdleUnsupported));
        }
        loop {
            if let Some(report) = self.watch_catch_up(&mut ctx, &acct, &mut client).await? {
                if !on_event(WatchEvent::NewMail { report }) {
                    break;
                }
                continue; // look again: more may have arrived during that sync
            }
            if !on_event(WatchEvent::Idle {
                folder: "INBOX".into(),
            }) {
                break;
            }
            // Gapless: mail announced between the last command and the server's `+` wakes
            // this round instead of waiting out the timeout (sealbox-mail 8725ae6).
            let event = client.idle_wait_gapless(idle_timeout).await?;
            let cont = match event {
                IdleEvent::NewData => {
                    let report = {
                        let _guard = self.account_lock(acct.id).await;
                        let pass = self.watch_pass();
                        self.sync_folder(&mut ctx, &acct, &mut client, "INBOX", pass, &mut |_| {})
                            .await?
                    };
                    on_event(WatchEvent::NewMail { report })
                }
                IdleEvent::Timeout => on_event(WatchEvent::Timeout),
            };
            if !cont {
                break;
            }
        }
        let _ = client.logout().await;
        Ok(())
    }

    /// The check [`Engine::watch`] runs before each IDLE round: one `UID SEARCH` from INBOX's
    /// stored `last_uid` (the query a sync starts with), under the account's mailbox lock so
    /// it cannot read a `last_uid` a concurrent sync is about to move. When it finds anything,
    /// INBOX is synced (same lock) and the report returned; `None` when nothing new arrived,
    /// or when another sync already stored it. Also puts INBOX back as the selected mailbox
    /// should a pass of the last sync have left another one selected — IDLE watches it.
    async fn watch_catch_up(
        &self,
        ctx: &mut SyncContext,
        acct: &AccountRow,
        client: &mut ImapClient,
    ) -> Result<Option<SyncReport>> {
        let _guard = self.account_lock(acct.id).await;
        if !client
            .selected()
            .is_some_and(|m| m.name.eq_ignore_ascii_case("INBOX"))
        {
            client.select("INBOX").await?;
        }
        let folder = self.store().folder(acct.id, "INBOX")?;
        if client.fetch_new_uids(folder.last_uid).await?.is_empty() {
            // No new mail — but an IDLE round is woken by flag changes and expunges too, which
            // is exactly what the reconcile converges. Doing it here rather than only alongside
            // new mail is what makes "deleted in webmail" reach the app while the watcher runs;
            // it costs one `UID SEARCH` and (ordinarily) one `UID FETCH (FLAGS)`, and only on a
            // round the server actually woke.
            let exists = client.selected().map(|m| m.exists).unwrap_or(0);
            let (removed, flags_changed) = self
                .reconcile_selected(client, folder.id, "INBOX", exists, None)
                .await?;
            if removed == 0 && flags_changed == 0 {
                return Ok(None);
            }
            return Ok(Some(SyncReport {
                account: acct.email.clone(),
                folders: vec![FolderSync {
                    name: "INBOX".to_string(),
                    removed,
                    flags_changed,
                    more_to_backfill: folder.more_to_backfill(),
                    ..FolderSync::default()
                }],
                ..SyncReport::default()
            }));
        }
        let report = self
            .sync_folder(ctx, acct, client, "INBOX", self.watch_pass(), &mut |_| {})
            .await?;
        Ok(report.changed().then_some(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use crate::store::NewAccount;
    use crate::types::AuthKind;
    use chrono::TimeZone;
    use sealbox_crypto::{
        encrypt_and_sign_armored, minimal_key_for_autocrypt, PreferEncrypt, Recommendation,
    };
    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::mime::{
        autocrypt_gossip_header_value, autocrypt_header_value, build_pgp_mime_encrypted,
        build_plain, InnerOptions, Mailbox, MessageDraft, OuterHeaders,
    };
    use sealbox_mail::Security;

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    struct Fixture {
        _dir: tempfile::TempDir,
        engine: Engine,
        acct: AccountRow,
        folder: FolderRow,
        alice: Identity,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        let alice = Identity::generate("Alice", "alice@example.org").unwrap();
        let (acct, folder) = {
            let store = engine.store();
            let id = store
                .insert_account(&NewAccount {
                    email: "alice@example.org",
                    display_name: "Alice",
                    imap: &Endpoint::new("127.0.0.1", 143, Security::Plain),
                    smtp: &Endpoint::new("127.0.0.1", 25, Security::Plain),
                    auth_kind: AuthKind::Password,
                    login: "alice",
                    credential: "pw",
                })
                .unwrap();
            store
                .insert_identity(
                    id,
                    &alice.fingerprint(),
                    "alice@example.org",
                    &alice.to_armored_secret(None).unwrap(),
                    &alice.public().to_armored().unwrap(),
                )
                .unwrap();
            let acct = store.account_by_id(id).unwrap().unwrap();
            let folder = store.folder(id, "INBOX").unwrap();
            (acct, folder)
        };
        Fixture {
            _dir: dir,
            engine,
            acct,
            folder,
            alice,
        }
    }

    fn t(day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 1 + day, hour, 0, 0).unwrap()
    }

    fn autocrypt_value(id: &Identity, mutual: bool) -> String {
        let keydata = minimal_key_for_autocrypt(id).unwrap();
        autocrypt_header_value(&id.primary_email().unwrap(), mutual, &B64.encode(&keydata))
    }

    fn plain_from(bob: &Identity, date: DateTime<Utc>, header: Option<String>) -> Vec<u8> {
        let mut d = MessageDraft::new(
            Mailbox::named("Bob", "bob@example.org"),
            vec![Mailbox::new("alice@example.org")],
            "hello",
            "plain body\n",
        );
        d.date = date.timestamp();
        if let Some(h) = header {
            d.extra_headers.push(("Autocrypt".into(), h));
        }
        let _ = bob;
        build_plain(&d).unwrap()
    }

    #[test]
    fn effective_date_rules_drive_peer_state() {
        let f = fixture();
        let bob = Identity::generate("Bob", "bob@example.org").unwrap();
        let mut ctx = f.engine.sync_context(&f.acct).unwrap();

        // 1. A message dated in the future uses the time of receipt as its effective date.
        let raw = plain_from(&bob, t(5, 12), Some(autocrypt_value(&bob, true)));
        let p = f
            .engine
            .process_message(&mut ctx, &f.acct, &f.folder, 1, &raw, vec![], t(2, 0))
            .unwrap();
        assert!(p.peers_changed);
        let peer = f.engine.store().peer("bob@example.org").unwrap().unwrap();
        assert_eq!(peer.autocrypt_timestamp, Some(t(2, 0)));
        assert_eq!(peer.last_seen, Some(t(2, 0)));
        assert_eq!(peer.prefer_encrypt, PreferEncrypt::Mutual);
        assert_eq!(
            f.engine
                .resolve_recipient("bob@example.org", false)
                .unwrap()
                .recommendation,
            Recommendation::Encrypt
        );

        // 2. An older message (Date before autocrypt_timestamp) changes nothing, even if it
        //    carries a different header.
        let raw = plain_from(&bob, t(1, 0), Some(autocrypt_value(&bob, false)));
        let p = f
            .engine
            .process_message(&mut ctx, &f.acct, &f.folder, 2, &raw, vec![], t(3, 0))
            .unwrap();
        assert!(!p.peers_changed);
        let peer = f.engine.store().peer("bob@example.org").unwrap().unwrap();
        assert_eq!(peer.prefer_encrypt, PreferEncrypt::Mutual);
        assert_eq!(peer.autocrypt_timestamp, Some(t(2, 0)));

        // 3. A newer message without a header bumps last_seen only.
        let raw = plain_from(&bob, t(3, 0), None);
        f.engine
            .process_message(&mut ctx, &f.acct, &f.folder, 3, &raw, vec![], t(3, 1))
            .unwrap();
        let peer = f.engine.store().peer("bob@example.org").unwrap().unwrap();
        assert_eq!(peer.last_seen, Some(t(3, 0)));
        assert_eq!(peer.autocrypt_timestamp, Some(t(2, 0)));

        // 4. multipart/report and multi-From messages never update peer state.
        let handmade = |from: &str, ctype: &str, date: DateTime<Utc>| -> Vec<u8> {
            format!(
                "From: {from}\r\nTo: alice@example.org\r\nSubject: x\r\nDate: {}\r\n\
                 Message-ID: <h{}@example.org>\r\nMIME-Version: 1.0\r\n\
                 Content-Type: {ctype}\r\n\r\nbody\r\n",
                date.to_rfc2822(),
                date.timestamp()
            )
            .into_bytes()
        };
        let report = handmade(
            "Bob <bob@example.org>",
            "multipart/report; report-type=delivery-status; boundary=zz",
            t(4, 0),
        );
        f.engine
            .process_message(&mut ctx, &f.acct, &f.folder, 4, &report, vec![], t(4, 1))
            .unwrap();
        let peer = f.engine.store().peer("bob@example.org").unwrap().unwrap();
        assert_eq!(peer.last_seen, Some(t(3, 0)));
        let multi = handmade(
            "Bob <bob@example.org>, Eve <eve@example.org>",
            "text/plain",
            t(4, 0),
        );
        f.engine
            .process_message(&mut ctx, &f.acct, &f.folder, 5, &multi, vec![], t(4, 2))
            .unwrap();
        let peer = f.engine.store().peer("bob@example.org").unwrap().unwrap();
        assert_eq!(peer.last_seen, Some(t(3, 0)));
        // ...while the same hand-made message with a single From does.
        let single = handmade("Bob <bob@example.org>", "text/plain", t(4, 0));
        f.engine
            .process_message(&mut ctx, &f.acct, &f.folder, 6, &single, vec![], t(4, 3))
            .unwrap();
        let peer = f.engine.store().peer("bob@example.org").unwrap().unwrap();
        assert_eq!(peer.last_seen, Some(t(4, 0)));

        // 5. A header whose addr does not match From is ignored (last_seen still moves).
        let other = autocrypt_value(&f.alice, true);
        let raw = plain_from(&bob, t(6, 0), Some(other));
        f.engine
            .process_message(&mut ctx, &f.acct, &f.folder, 7, &raw, vec![], t(6, 1))
            .unwrap();
        let peer = f.engine.store().peer("bob@example.org").unwrap().unwrap();
        assert_eq!(peer.last_seen, Some(t(6, 0)));
        assert_eq!(peer.autocrypt_timestamp, Some(t(2, 0)));

        // Our own address never becomes a peer.
        assert!(f
            .engine
            .store()
            .peer("alice@example.org")
            .unwrap()
            .is_none());
    }

    #[test]
    fn encrypted_message_is_decrypted_verified_and_gossip_imported() {
        let f = fixture();
        let bob = Identity::generate("Bob", "bob@example.org").unwrap();
        let carol = Identity::generate("Carol", "carol@example.org").unwrap();
        let mut ctx = f.engine.sync_context(&f.acct).unwrap();

        // Bob → Alice (+ Carol in Cc), encrypted + signed, protected subject, gossip for Carol.
        let mut d = MessageDraft::new(
            Mailbox::named("Bob", "bob@example.org"),
            vec![Mailbox::new("alice@example.org")],
            "Top secret subject",
            "the secret body\n",
        );
        d.cc = vec![Mailbox::new("carol@example.org")];
        d.date = t(1, 0).timestamp();
        d.attachments.push(sealbox_mail::mime::Attachment::new(
            "x.bin",
            "application/octet-stream",
            vec![9, 8, 7],
        ));
        d.extra_headers
            .push(("Autocrypt".into(), autocrypt_value(&bob, true)));
        let gossip = autocrypt_gossip_header_value(
            "carol@example.org",
            &B64.encode(
                sealbox_crypto::minimal_public_key(&carol.public(), Some("carol@example.org"))
                    .unwrap()
                    .to_bytes()
                    .unwrap(),
            ),
        );
        let inner = sealbox_mail::mime::render_inner_for_encryption(
            &d,
            &InnerOptions {
                gossip_headers: vec![gossip],
                legacy_display: false,
            },
        )
        .unwrap();
        let armored = encrypt_and_sign_armored(
            &inner,
            &[&f.alice.public(), &carol.public(), &bob.public()],
            Some(&bob),
        )
        .unwrap();
        let raw = build_pgp_mime_encrypted(&OuterHeaders::for_protected(&d), &armored).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("Top secret subject"));
        assert!(!String::from_utf8_lossy(&raw).contains("the secret body"));

        let p = f
            .engine
            .process_message(
                &mut ctx,
                &f.acct,
                &f.folder,
                10,
                &raw,
                vec!["\\Seen".into()],
                t(1, 1),
            )
            .unwrap();
        assert!(p.decrypted_ok && !p.failed);
        let m = &p.message;
        assert!(m.was_encrypted && m.decrypted && m.was_signed);
        assert_eq!(m.subject.as_deref(), Some("Top secret subject"));
        assert!(m.protected_subject);
        assert_eq!(
            m.text.as_deref().map(|s| s.replace("\r\n", "\n")),
            Some("the secret body\n".into())
        );
        assert_eq!(m.signature.status, SigState::Good);
        assert_eq!(
            m.signature.fingerprint.as_deref(),
            Some(bob.fingerprint().as_str())
        );
        assert_eq!(m.signature.signer.as_deref(), Some("bob@example.org"));
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.attachments[0].data, vec![9, 8, 7]);

        // Gossip for Carol was imported (she is in Cc), Bob's own key via the header.
        let carol_peer = f.engine.store().peer("carol@example.org").unwrap().unwrap();
        assert_eq!(carol_peer.gossip_timestamp, Some(t(1, 0)));
        assert_eq!(
            carol_peer.gossip_public_key().unwrap().fingerprint(),
            carol.fingerprint()
        );
        let c = f
            .engine
            .resolve_recipient("carol@example.org", false)
            .unwrap();
        assert_eq!(c.recommendation, Recommendation::Discourage);
        assert_eq!(c.source, crate::types::KeySource::Gossip);
        let b = f
            .engine
            .resolve_recipient("bob@example.org", false)
            .unwrap();
        assert_eq!(b.recommendation, Recommendation::Encrypt);

        // Store round trip through the public API.
        let id = f
            .engine
            .store()
            .insert_message(&p.message)
            .unwrap()
            .unwrap();
        let detail = f.engine.get_message(id).unwrap();
        assert_eq!(
            detail.summary.subject.as_deref(),
            Some("Top secret subject")
        );
        assert!(detail.summary.seen);
        assert_eq!(detail.attachments[0].filename, "x.bin");
        let (_, bytes) = f.engine.get_attachment(id, 0).unwrap();
        assert_eq!(bytes, vec![9, 8, 7]);
        let contacts = f.engine.contacts().unwrap();
        assert!(
            contacts
                .iter()
                .any(|c| c.address == "bob@example.org"
                    && c.recommendation == Recommendation::Encrypt)
        );

        // A message we cannot decrypt is stored as failed, with the error.
        let dave = Identity::generate("Dave", "dave@example.org").unwrap();
        let armored = encrypt_and_sign_armored(&inner, &[&dave.public()], Some(&bob)).unwrap();
        let raw = build_pgp_mime_encrypted(&OuterHeaders::for_protected(&d), &armored).unwrap();
        let p = f
            .engine
            .process_message(&mut ctx, &f.acct, &f.folder, 11, &raw, vec![], t(1, 2))
            .unwrap();
        assert!(p.failed && !p.decrypted_ok);
        assert!(p.message.decrypt_error.is_some());
        assert_eq!(p.message.subject.as_deref(), Some("..."));
    }

    /// Bob → Alice, encrypted + signed by `sender`, with `sender`'s Autocrypt header outside.
    fn encrypted_from(f: &Fixture, sender: &Identity, date: DateTime<Utc>) -> Vec<u8> {
        let mut d = MessageDraft::new(
            Mailbox::named("Bob", "bob@example.org"),
            vec![Mailbox::new("alice@example.org")],
            "signed",
            "signed body\n",
        );
        d.date = date.timestamp();
        d.extra_headers
            .push(("Autocrypt".into(), autocrypt_value(sender, true)));
        let inner = sealbox_mail::mime::render_inner_for_encryption(
            &d,
            &InnerOptions {
                gossip_headers: vec![],
                legacy_display: false,
            },
        )
        .unwrap();
        let armored =
            encrypt_and_sign_armored(&inner, &[&f.alice.public(), &sender.public()], Some(sender))
                .unwrap();
        build_pgp_mime_encrypted(&OuterHeaders::for_protected(&d), &armored).unwrap()
    }

    /// The known-signer keys are re-parsed (`refresh_keys`, the debug build's hotspot) only
    /// when a key actually changed, and only once a message needs them: a `last_seen` bump of
    /// a known peer — almost every message — reloads nothing, plain mail never asks.
    #[test]
    fn keys_are_reloaded_only_after_a_key_changed_and_only_when_needed() {
        let f = fixture();
        let bob = Identity::generate("Bob", "bob@example.org").unwrap();
        let mut ctx = f.engine.sync_context(&f.acct).unwrap();
        let received = t(9, 0);
        let mut uid = 100;
        let mut plain_run = |ctx: &mut SyncContext, who: &Identity, day: u32| {
            for h in 0..20 {
                let raw = plain_from(who, t(day, h), Some(autocrypt_value(who, true)));
                uid += 1;
                f.engine
                    .process_message(ctx, &f.acct, &f.folder, uid, &raw, vec![], received)
                    .unwrap();
            }
        };
        plain_run(&mut ctx, &bob, 1);
        assert_eq!(ctx.key_reloads, 0, "plain mail never needs the keys");
        let signed = |ctx: &mut SyncContext, who: &Identity, date, uid| {
            let raw = encrypted_from(&f, who, date);
            let p = f
                .engine
                .process_message(ctx, &f.acct, &f.folder, uid, &raw, vec![], received)
                .unwrap();
            assert!(p.decrypted_ok);
            p.message.signature
        };
        // The first signed message reloads once and verifies with the key learned above.
        let s = signed(&mut ctx, &bob, t(2, 0), 200);
        assert_eq!(s.status, SigState::Good);
        assert_eq!(ctx.key_reloads, 1);
        // Twenty more messages bump last_seen only; the next signed one reloads nothing.
        plain_run(&mut ctx, &bob, 3);
        let s = signed(&mut ctx, &bob, t(4, 0), 201);
        assert_eq!(s.status, SigState::Good);
        assert_eq!(ctx.key_reloads, 1, "no key changed since the last reload");
        // Bob's new key arrives in a newer message: one reload, before it is needed.
        let bob2 = Identity::generate("Bob", "bob@example.org").unwrap();
        plain_run(&mut ctx, &bob2, 5);
        let s = signed(&mut ctx, &bob2, t(6, 0), 202);
        assert_eq!(s.status, SigState::Good);
        assert_eq!(s.fingerprint.as_deref(), Some(bob2.fingerprint().as_str()));
        assert_eq!(ctx.key_reloads, 2);
    }

    /// `multipart/related` (HTML + `image/png` with `Content-ID: <logo@x>`) through the sync's
    /// own processing and the store: the part keeps its Content-ID, so the HTML's `cid:logo@x`
    /// finds it — in plaintext mail and inside an encrypted payload.
    #[test]
    fn an_inline_image_keeps_its_content_id_through_sync_and_store() {
        let f = fixture();
        let mut ctx = f.engine.sync_context(&f.acct).unwrap();
        let related = "From: Shop <shop@example.org>\r\n\
             To: <alice@example.org>\r\n\
             Subject: inline image\r\n\
             Date: Wed, 29 Oct 2026 09:00:00 +0000\r\n\
             Message-ID: <inline-1@example.org>\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/related; boundary=\"rel\"; type=\"text/html\"\r\n\
             \r\n\
             --rel\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             \r\n\
             <p>Hello <img src=\"cid:logo@x\" alt=\"Logo\"></p>\r\n\
             --rel\r\n\
             Content-Type: image/png\r\n\
             Content-Transfer-Encoding: base64\r\n\
             Content-ID: <logo@x>\r\n\
             Content-Disposition: inline; filename=\"logo.png\"\r\n\
             \r\n\
             iVBORw0KGgo=\r\n\
             --rel--\r\n";
        let p = f
            .engine
            .process_message(
                &mut ctx,
                &f.acct,
                &f.folder,
                30,
                related.as_bytes(),
                vec![],
                t(2, 0),
            )
            .unwrap();
        assert_eq!(p.message.attachments.len(), 1);
        assert_eq!(
            p.message.attachments[0].content_id.as_deref(),
            Some("logo@x")
        );
        let id = f
            .engine
            .store()
            .insert_message(&p.message)
            .unwrap()
            .unwrap();
        let d = f.engine.get_message(id).unwrap();
        assert_eq!(d.attachments.len(), 1);
        assert_eq!(d.attachments[0].content_id.as_deref(), Some("logo@x"));
        assert_eq!(d.attachments[0].content_type, "image/png");
        assert_eq!(d.attachments[0].filename, "logo.png");
        assert_eq!(d.inline_part("cid:logo@x").map(|a| a.index), Some(0));
        let (info, bytes) = f.engine.get_attachment(id, 0).unwrap();
        assert_eq!(info.content_id.as_deref(), Some("logo@x"));
        assert_eq!(bytes, b"\x89PNG\r\n\x1a\n".to_vec());
        let html = f
            .engine
            .message_html(id, false)
            .unwrap()
            .expect("html body");
        assert!(
            html.html.contains("<img src=\"cid:logo@x\" alt=\"Logo\">"),
            "{}",
            html.html
        );

        // The same inside an encrypted message (Sealbox's own builder: inline part with a cid).
        let bob = Identity::generate("Bob", "bob@example.org").unwrap();
        let mut d = MessageDraft::new(
            Mailbox::named("Bob", "bob@example.org"),
            vec![Mailbox::new("alice@example.org")],
            "encrypted inline image",
            "text\n",
        );
        d.html_body = Some("<p>Hi <img src=\"cid:pic@bob\" alt=\"Pic\"></p>".into());
        let mut pic = sealbox_mail::mime::Attachment::new("pic.png", "image/png", vec![1, 2, 3]);
        pic.content_id = Some("pic@bob".into());
        d.attachments.push(pic);
        let inner =
            sealbox_mail::mime::render_inner_for_encryption(&d, &InnerOptions::default()).unwrap();
        let armored =
            encrypt_and_sign_armored(&inner, &[&f.alice.public(), &bob.public()], Some(&bob))
                .unwrap();
        let raw = build_pgp_mime_encrypted(&OuterHeaders::for_protected(&d), &armored).unwrap();
        let p = f
            .engine
            .process_message(&mut ctx, &f.acct, &f.folder, 31, &raw, vec![], t(2, 1))
            .unwrap();
        assert!(p.decrypted_ok);
        let id = f
            .engine
            .store()
            .insert_message(&p.message)
            .unwrap()
            .unwrap();
        let d = f.engine.get_message(id).unwrap();
        let part = d.inline_part("cid:pic@bob").expect("the inline part");
        assert_eq!(part.content_id.as_deref(), Some("pic@bob"));
        assert_eq!(
            f.engine.get_attachment(id, part.index).unwrap().1,
            vec![1, 2, 3]
        );
    }

    #[test]
    fn import_and_export_keys() {
        let f = fixture();
        let armored = f.engine.export_public_key("alice@example.org").unwrap();
        assert!(armored.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert_eq!(
            f.engine.my_fingerprint("alice@example.org").unwrap(),
            f.alice.fingerprint()
        );
        let bob = Identity::generate("Bob", "bob@example.org").unwrap();
        let c = f
            .engine
            .import_peer_key("Bob@Example.org", &bob.public().to_armored().unwrap())
            .unwrap();
        assert_eq!(c.address, "bob@example.org");
        assert_eq!(c.fingerprint.as_deref(), Some(bob.fingerprint().as_str()));
        assert_eq!(c.source, crate::types::KeySource::Imported);
        assert_eq!(c.recommendation, Recommendation::Available);
        assert!(f
            .engine
            .import_peer_key("carol@example.org", &bob.public().to_armored().unwrap())
            .is_err());
        let r = f.engine.resolve_recipient("bob@example.org", true).unwrap();
        assert_eq!(r.recommendation, Recommendation::Encrypt);
        assert_eq!(
            f.engine
                .resolve_recipient("alice@example.org", false)
                .unwrap()
                .source,
            crate::types::KeySource::Own
        );
    }
}

/// The per-account mailbox lock (`Engine::account_lock`) as the network paths take it: a
/// sync, a role sync, a move and a spam-feedback move of one account never interleave, and
/// they never wait for another account. Offline: the account's servers are on 127.0.0.1:1, so
/// every call fails fast with a connection error once it is past the lock; while the lock is
/// held by the test the calls must still be pending.
#[cfg(test)]
mod lock_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use chrono::Utc;
    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::imap::FolderRole;
    use sealbox_mail::Security;

    use crate::engine::{Engine, EngineConfig};
    use crate::error::Error;
    use crate::store::NewAccount;
    use crate::types::AuthKind;

    const PENDING: Duration = Duration::from_millis(400);
    const DONE: Duration = Duration::from_secs(10);

    fn engine_with_accounts() -> (tempfile::TempDir, Arc<Engine>, i64, i64) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = EngineConfig {
            network_timeout: Duration::from_secs(3),
            ..EngineConfig::default()
        };
        let engine = Engine::open_with(dir.path(), cfg).unwrap();
        let mut ids = Vec::new();
        for (email, login) in [("a@example.org", "a"), ("b@example.org", "b")] {
            let id = engine
                .store()
                .insert_account(&NewAccount {
                    email,
                    display_name: "",
                    imap: &Endpoint::new("127.0.0.1", 1, Security::Plain),
                    smtp: &Endpoint::new("127.0.0.1", 1, Security::Plain),
                    auth_kind: AuthKind::Password,
                    login,
                    credential: "pw",
                })
                .unwrap();
            let identity = sealbox_crypto::Identity::generate("", email).unwrap();
            engine
                .store()
                .insert_identity(
                    id,
                    &identity.fingerprint(),
                    email,
                    &identity.to_armored_secret(None).unwrap(),
                    &identity.public().to_armored().unwrap(),
                )
                .unwrap();
            ids.push(id);
        }
        (dir, Arc::new(engine), ids[0], ids[1])
    }

    /// Store one plain message in account `a`'s INBOX; returns its local id.
    fn store_message(engine: &Engine, account_id: i64) -> i64 {
        let (acct, folder) = {
            let store = engine.store();
            let acct = store.account_by_id(account_id).unwrap().unwrap();
            let folder = store.folder(account_id, "INBOX").unwrap();
            (acct, folder)
        };
        let raw = b"From: Bob <bob@example.org>\r\nTo: a@example.org\r\nSubject: lock test\r\n\
                    Message-ID: <lock-test@example.org>\r\nDate: Sun, 1 Mar 2026 10:00:00 +0000\r\n\
                    MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nbody\r\n";
        let mut ctx = engine.sync_context(&acct).unwrap();
        let p = engine
            .process_message(&mut ctx, &acct, &folder, 7, raw, vec![], Utc::now())
            .unwrap();
        engine
            .store()
            .insert_message(&p.message)
            .unwrap()
            .expect("inserted")
    }

    /// Run `op` while the test holds account `a`'s lock: it must still be pending after
    /// [`PENDING`], an operation on account `b` must finish meanwhile, and once the lock is
    /// released `op` must finish (with the expected connection failure).
    async fn assert_waits_for_lock<F>(engine: &Arc<Engine>, a: i64, what: &str, op: F)
    where
        F: std::future::Future<Output = Result<(), Error>> + Send + 'static,
    {
        let guard = engine.account_lock(a).await;
        let mut task = tokio::spawn(op);
        assert!(
            tokio::time::timeout(PENDING, &mut task).await.is_err(),
            "{what} ran although the account's mailbox lock was held"
        );
        // Another account is not serialised behind `a`.
        let other = tokio::time::timeout(DONE, engine.sync("b@example.org"))
            .await
            .expect("account b must not wait for account a's lock");
        assert!(other.is_err(), "nothing listens on 127.0.0.1:1");
        drop(guard);
        let res = tokio::time::timeout(DONE, task)
            .await
            .unwrap_or_else(|_| panic!("{what} did not proceed after the lock was released"))
            .unwrap();
        let err = res.expect_err("nothing listens on 127.0.0.1:1");
        assert!(
            err.is_auth_or_connection(),
            "{what}: expected a connection error once past the lock, got {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sync_role_sync_move_and_spam_learn_take_the_account_lock() {
        let (_dir, engine, a, _b) = engine_with_accounts();
        let e = engine.clone();
        assert_waits_for_lock(&engine, a, "sync", async move {
            e.sync("a@example.org").await.map(|_| ())
        })
        .await;
        let e = engine.clone();
        assert_waits_for_lock(&engine, a, "sync_folder_role", async move {
            e.sync_folder_role("a@example.org", FolderRole::Trash)
                .await
                .map(|_| ())
        })
        .await;
        let id = store_message(&engine, a);
        let e = engine.clone();
        assert_waits_for_lock(&engine, a, "move_message", async move {
            e.move_message(id, FolderRole::Trash).await.map(|_| ())
        })
        .await;
        let e = engine.clone();
        assert_waits_for_lock(&engine, a, "delete_message", async move {
            e.delete_message(id).await
        })
        .await;
        let e = engine.clone();
        assert_waits_for_lock(&engine, a, "spam_learn", async move {
            e.spam_learn(id, true).await.map(|_| ())
        })
        .await;
        // The failed network calls left the stored message alone.
        assert_eq!(engine.get_message(id).unwrap().summary.folder, "INBOX");
    }

    #[tokio::test]
    async fn unknown_account_or_message_fails_before_the_lock() {
        let (_dir, engine, a, _b) = engine_with_accounts();
        let _guard = engine.account_lock(a).await;
        // These never reach the lock: a typo'd account or a stale id must not hang the UI.
        assert!(matches!(
            tokio::time::timeout(
                DONE,
                engine.sync_folder_role("nobody@example.org", FolderRole::Junk)
            )
            .await
            .expect("no wait"),
            Err(Error::AccountNotFound(_))
        ));
        assert!(matches!(
            tokio::time::timeout(DONE, engine.move_message(9999, FolderRole::Trash))
                .await
                .expect("no wait"),
            Err(Error::MessageNotFound(9999))
        ));
        assert!(matches!(
            tokio::time::timeout(DONE, engine.sync("nobody@example.org"))
                .await
                .expect("no wait"),
            Err(Error::AccountNotFound(_))
        ));
    }
}

/// `Engine::watch` against a scripted IMAP server on loopback (offline, fast; the style of
/// `sealbox-mail/tests/imap_idle_gapless.rs`). The server plays exactly what the engine sends
/// for a password account: CAPABILITY, LOGIN, SELECT, `UID SEARCH UID n:*` (with RFC 3501's
/// "n:* includes the highest UID" quirk), `UID FETCH … (UID FLAGS BODY.PEEK[])`, IDLE / DONE,
/// LOGOUT. Spam classification is off, so a sync issues nothing else.
#[cfg(test)]
mod watch_tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::Security;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use crate::engine::{Engine, EngineConfig};
    use crate::spam::SpamSettings;
    use crate::store::NewAccount;
    use crate::types::{AuthKind, ListQuery, WatchEvent};

    const EMAIL: &str = "a@example.org";

    fn raw(uid: u32) -> Vec<u8> {
        format!(
            "From: Bob <bob@example.org>\r\nTo: a@example.org\r\nSubject: watch {uid}\r\n\
             Message-ID: <watch-{uid}@example.org>\r\nDate: Sun, 1 Mar 2026 10:0{uid}:00 +0000\r\n\
             MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nmessage {uid}\r\n"
        )
        .into_bytes()
    }

    /// Parse `1`, `1:3`, `1,4:5` (what `sequence_set` produces).
    fn uid_set(set: &str) -> Vec<u32> {
        let mut out = Vec::new();
        for part in set.split(',') {
            match part.split_once(':') {
                Some((a, b)) => {
                    let (a, b) = (a.parse::<u32>().unwrap(), b.parse::<u32>().unwrap());
                    out.extend(a.min(b)..=a.max(b));
                }
                None => out.push(part.parse().unwrap()),
            }
        }
        out
    }

    /// One connection of a minimal IMAP server holding message UID 1. With `stranded`, a
    /// second message lands while the client's first `UID FETCH` runs and is announced only
    /// in-band (`* 2 EXISTS` inside that FETCH response): IDLE later stays silent, as a real
    /// server's would, since it already told the client. Returns the port and the lines the
    /// client sent.
    async fn scripted_imap(stranded: bool) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = sock.into_split();
            let mut lines = BufReader::new(rd).lines();
            let mut seen = Vec::new();
            let mut mailbox: Vec<u32> = vec![1];
            let mut arrival = stranded.then_some(2u32);
            let mut idle_tag: Option<String> = None;
            wr.write_all(b"* OK scripted IMAP ready\r\n").await.unwrap();
            while let Ok(Some(line)) = lines.next_line().await {
                seen.push(line.clone());
                if line.eq_ignore_ascii_case("DONE") {
                    if let Some(tag) = idle_tag.take() {
                        wr.write_all(format!("{tag} OK IDLE terminated\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    continue;
                }
                let mut parts = line.splitn(3, ' ');
                let tag = parts.next().unwrap_or("*").to_owned();
                let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
                let rest = parts.next().unwrap_or("").to_owned();
                let mut reply: Vec<u8> = Vec::new();
                match cmd.as_str() {
                    "CAPABILITY" => reply.extend_from_slice(
                        format!("* CAPABILITY IMAP4rev1 IDLE\r\n{tag} OK done\r\n").as_bytes(),
                    ),
                    "LOGIN" => {
                        reply.extend_from_slice(format!("{tag} OK logged in\r\n").as_bytes())
                    }
                    "SELECT" | "EXAMINE" => reply.extend_from_slice(
                        format!(
                            "* {} EXISTS\r\n* 0 RECENT\r\n* FLAGS (\\Seen)\r\n\
                             * OK [UIDVALIDITY 7] UIDs valid\r\n* OK [UIDNEXT {}] next\r\n\
                             {tag} OK [READ-WRITE] SELECT completed\r\n",
                            mailbox.len(),
                            mailbox.last().copied().unwrap_or(0) + 1
                        )
                        .as_bytes(),
                    ),
                    "UID" => {
                        let mut sub = rest.splitn(2, ' ');
                        let what = sub.next().unwrap_or("").to_ascii_uppercase();
                        let args = sub.next().unwrap_or("");
                        if what == "SEARCH" {
                            // `UID n:*`
                            let from: u32 = args
                                .trim_start_matches("UID ")
                                .trim_end_matches(":*")
                                .parse()
                                .unwrap();
                            let mut hits: Vec<u32> =
                                mailbox.iter().copied().filter(|u| *u >= from).collect();
                            if hits.is_empty() {
                                hits.extend(mailbox.last().copied()); // n:* quirk
                            }
                            let list: Vec<String> = hits.iter().map(u32::to_string).collect();
                            reply.extend_from_slice(
                                format!(
                                    "* SEARCH {}\r\n{tag} OK SEARCH completed\r\n",
                                    list.join(" ")
                                )
                                .as_bytes(),
                            );
                        } else if what == "FETCH" {
                            let set = args.split(' ').next().unwrap_or("");
                            // A flags-only fetch (what a reconcile sends) gets flags only. The
                            // server used to answer every FETCH with a body whatever was asked
                            // for, which made the reconcile's `(UID FLAGS)` look like it worked
                            // while actually being answered by accident.
                            let body_wanted = args.to_ascii_uppercase().contains("BODY");
                            for uid in uid_set(set) {
                                if let Some(seq) = mailbox.iter().position(|u| *u == uid) {
                                    if !body_wanted {
                                        reply.extend_from_slice(
                                            format!("* {} FETCH (UID {uid} FLAGS ())\r\n", seq + 1)
                                                .as_bytes(),
                                        );
                                        continue;
                                    }
                                    let body = raw(uid);
                                    reply.extend_from_slice(
                                        format!(
                                            "* {} FETCH (UID {uid} FLAGS () BODY[] {{{}}}\r\n",
                                            seq + 1,
                                            body.len()
                                        )
                                        .as_bytes(),
                                    );
                                    reply.extend_from_slice(&body);
                                    reply.extend_from_slice(b")\r\n");
                                }
                            }
                            if let Some(uid) = arrival.take() {
                                mailbox.push(uid);
                                reply.extend_from_slice(
                                    format!("* {} EXISTS\r\n", mailbox.len()).as_bytes(),
                                );
                            }
                            reply.extend_from_slice(
                                format!("{tag} OK FETCH completed\r\n").as_bytes(),
                            );
                        } else {
                            reply
                                .extend_from_slice(format!("{tag} BAD unsupported\r\n").as_bytes());
                        }
                    }
                    "IDLE" => {
                        idle_tag = Some(tag);
                        reply.extend_from_slice(b"+ idling\r\n");
                    }
                    "NOOP" => reply.extend_from_slice(format!("{tag} OK NOOP\r\n").as_bytes()),
                    "LOGOUT" => {
                        let _ = wr
                            .write_all(format!("* BYE\r\n{tag} OK LOGOUT completed\r\n").as_bytes())
                            .await;
                        break;
                    }
                    _ => {
                        reply.extend_from_slice(format!("{tag} BAD unknown command\r\n").as_bytes())
                    }
                }
                if wr.write_all(&reply).await.is_err() {
                    break;
                }
            }
            seen
        });
        (port, task)
    }

    fn engine_on(port: u16) -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = EngineConfig {
            network_timeout: Duration::from_secs(5),
            ..EngineConfig::default()
        };
        let engine = Engine::open_with(dir.path(), cfg).unwrap();
        engine
            .store()
            .insert_account(&NewAccount {
                email: EMAIL,
                display_name: "",
                imap: &Endpoint::new("127.0.0.1", port, Security::Plain),
                smtp: &Endpoint::new("127.0.0.1", 1, Security::Plain),
                auth_kind: AuthKind::Password,
                login: "a",
                credential: "pw",
            })
            .unwrap();
        engine
            .set_spam_settings(
                EMAIL,
                SpamSettings {
                    enabled: false,
                    ..SpamSettings::default()
                },
            )
            .unwrap();
        (dir, engine)
    }

    fn stored_subjects(engine: &Engine) -> Vec<String> {
        let mut out: Vec<String> = engine
            .list_messages(ListQuery {
                account: Some(EMAIL.into()),
                ..ListQuery::default()
            })
            .unwrap()
            .into_iter()
            .filter_map(|m| m.subject)
            .collect();
        out.sort();
        out
    }

    fn new_counts(events: &[WatchEvent]) -> Vec<String> {
        events
            .iter()
            .map(|e| match e {
                WatchEvent::NewMail { report } => format!("new:{}", report.new),
                WatchEvent::Idle { .. } => "idle".into(),
                WatchEvent::Timeout => "timeout".into(),
            })
            .collect()
    }

    /// The gap: message 2 arrives after the initial sync's `UID SEARCH` and is announced only
    /// inside the FETCH response. The watcher must fetch it before it goes idle — here the
    /// test stops at the first `Idle` event, so no IDLE command is ever sent.
    #[tokio::test]
    async fn mail_announced_between_the_sync_and_idle_is_fetched_before_idling() {
        let (port, server) = scripted_imap(true).await;
        let (_dir, engine) = engine_on(port);
        let events = Arc::new(Mutex::new(Vec::new()));
        let ev = events.clone();
        tokio::time::timeout(
            Duration::from_secs(20),
            engine.watch(EMAIL, Duration::from_secs(30), move |e| {
                let stop = matches!(e, WatchEvent::Idle { .. });
                ev.lock().unwrap().push(e);
                !stop
            }),
        )
        .await
        .expect("watch returned")
        .expect("watch ok");
        let events = events.lock().unwrap().clone();
        assert_eq!(
            new_counts(&events),
            ["new:1", "new:1", "idle"],
            "initial sync, then the stranded message, then IDLE"
        );
        assert_eq!(stored_subjects(&engine), ["watch 1", "watch 2"]);
        let seen = server.await.unwrap();
        assert!(
            !seen.iter().any(|l| l.contains(" IDLE")),
            "it was fetched without waiting for IDLE: {seen:?}"
        );
        // The exact search sequence, because that is what this test is for. A fresh folder's
        // first new-mail search is itself `UID 1:*` (`fetch_new_uids(0)`), so the two kinds
        // cannot be told apart by their text — the order is the only honest assertion:
        //   1:*  first sync, new mail        1:*  its reconcile
        //   2:*  catch-up before IDLE        2:*  the stranded message's sync
        //   1:*  its reconcile               3:*  catch-up, nothing new
        //   1:*  that round's reconcile
        let searches: Vec<String> = seen
            .iter()
            .filter(|l| l.contains("UID SEARCH"))
            .map(|l| l.split_once("UID SEARCH ").unwrap().1.to_owned())
            .collect();
        assert_eq!(
            searches,
            ["UID 1:*", "UID 1:*", "UID 2:*", "UID 2:*", "UID 1:*", "UID 3:*", "UID 1:*"],
            "{seen:?}"
        );
    }

    /// Nothing stranded: per IDLE round one extra `UID SEARCH` and one flags-only `UID FETCH`
    /// (the reconcile — an IDLE round is woken by expunges and flag changes too, so the
    /// catch-up converges even when no new mail arrived), and otherwise the old sequence:
    /// initial sync, Idle, IDLE until the timeout, Timeout, Idle — one SELECT, one body fetch,
    /// and no extra NewMail, because nothing drifted.
    #[tokio::test]
    async fn without_stranded_mail_each_round_adds_one_search_and_one_reconcile() {
        let (port, server) = scripted_imap(false).await;
        let (_dir, engine) = engine_on(port);
        let events = Arc::new(Mutex::new(Vec::new()));
        let ev = events.clone();
        let mut idles = 0;
        tokio::time::timeout(
            Duration::from_secs(20),
            engine.watch(EMAIL, Duration::from_millis(300), move |e| {
                if matches!(e, WatchEvent::Idle { .. }) {
                    idles += 1;
                }
                ev.lock().unwrap().push(e);
                idles < 2
            }),
        )
        .await
        .expect("watch returned")
        .expect("watch ok");
        let events = events.lock().unwrap().clone();
        assert_eq!(new_counts(&events), ["new:1", "idle", "timeout", "idle"]);
        assert_eq!(stored_subjects(&engine), ["watch 1"]);
        let seen = server.await.unwrap();
        let count = |needle: &str| seen.iter().filter(|l| l.contains(needle)).count();
        assert_eq!(count("SELECT"), 1, "{seen:?}");
        assert_eq!(count("BODY.PEEK[]"), 1, "one body fetch: {seen:?}");
        assert_eq!(count(" IDLE"), 1, "{seen:?}");
        assert_eq!(
            count("UID SEARCH UID 2:*"),
            2,
            "one look before each IDLE round: {seen:?}"
        );
        assert_eq!(
            count("(UID FLAGS)"),
            3,
            "one reconcile after the initial sync and one per catch-up round: {seen:?}"
        );
    }
}

/// The newest-first window and its backfill against a scripted IMAP server on loopback that
/// keeps its mailbox across connections (every engine call opens one) and records every
/// command: which UIDs a first sync fetches and in which order, how later syncs and
/// `Engine::backfill` continue below the window, that an interrupted sync resumes without a
/// gap or a re-fetch, that a UIDVALIDITY change clears the floor, and that `watch` never
/// backfills. Spam classification is off, so a sync issues nothing else.
#[cfg(test)]
mod window_tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::Security;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use crate::engine::{Engine, EngineConfig};
    use crate::spam::SpamSettings;
    use crate::store::NewAccount;
    use crate::types::{AuthKind, ListQuery, SyncPhase, SyncProgress, WatchEvent};

    const EMAIL: &str = "w@example.org";

    /// The server's state, shared by its connections.
    #[derive(Default)]
    struct Mailbox {
        uids: Vec<u32>,
        uidvalidity: u32,
        /// Every command line, per connection.
        log: Vec<Vec<String>>,
        /// Close the connection instead of answering the n-th body `UID FETCH` (counted over
        /// the whole run, 1-based).
        drop_body_fetch: Option<usize>,
        body_fetches: usize,
        /// Answer every `UID SEARCH` with an empty result.
        blind_search: bool,
        /// Flags the server holds for a UID (absent = none). What a reconcile reads.
        flags: std::collections::HashMap<u32, Vec<String>>,
        /// Answer every flags-only `UID FETCH` with no data at all — the protocol failure a
        /// reconcile must not mistake for "every message was deleted".
        blind_flags: bool,
        /// Extra body bytes of some messages (for the byte bound of a batch).
        pad: std::collections::HashMap<u32, usize>,
        /// Messages served instead of `raw(uid)`.
        bodies: std::collections::HashMap<u32, Vec<u8>>,
        /// Stall the flags `UID FETCH`es numbered here (1-based over the run): send the first
        /// FETCH line, then nothing for this long, then the rest — a big folder's flags over
        /// a slow link, past the client's network timeout.
        stall_flags: Vec<usize>,
        stall_for: Duration,
        flags_fetches: usize,
        /// Bump UIDVALIDITY when the n-th flags `UID FETCH` arrives (1-based over the run):
        /// a folder recreated on the server while a pass was running.
        bump_uidvalidity_at_flags: Option<usize>,
    }

    /// The message as this server serves it (`raw` plus its padding).
    fn served(s: &Mailbox, uid: u32) -> Vec<u8> {
        if let Some(b) = s.bodies.get(&uid) {
            return b.clone();
        }
        let mut m = raw(uid);
        if let Some(n) = s.pad.get(&uid) {
            m.truncate(m.len() - 2);
            m.extend(std::iter::repeat_n(b'x', *n));
            m.extend_from_slice(b"\r\n");
        }
        m
    }

    type Shared = Arc<Mutex<Mailbox>>;

    fn raw(uid: u32) -> Vec<u8> {
        let date =
            chrono::DateTime::<chrono::Utc>::from_timestamp(1_772_000_000 + i64::from(uid) * 60, 0)
                .unwrap()
                .to_rfc2822();
        format!(
            "From: Bob <bob@example.org>\r\nTo: w@example.org\r\nSubject: w {uid}\r\n\
             Message-ID: <w-{uid}@example.org>\r\nDate: {date}\r\n\
             MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nmessage {uid}\r\n"
        )
        .into_bytes()
    }

    /// `1`, `1:3`, `4:*`, `1,4:5` against the mailbox's highest UID.
    fn uid_set(set: &str, max: u32) -> Vec<u32> {
        let mut out = Vec::new();
        for part in set.split(',') {
            let num = |s: &str| {
                if s == "*" {
                    max
                } else {
                    s.parse::<u32>().unwrap()
                }
            };
            match part.split_once(':') {
                Some((a, b)) => {
                    let (a, b) = (num(a), num(b));
                    out.extend(a.min(b)..=a.max(b));
                }
                None => out.push(num(part)),
            }
        }
        out
    }

    async fn serve(sock: tokio::net::TcpStream, state: Shared) {
        let (rd, mut wr) = sock.into_split();
        let mut lines = BufReader::new(rd).lines();
        let conn = {
            let mut s = state.lock().unwrap();
            s.log.push(Vec::new());
            s.log.len() - 1
        };
        let mut idle_tag: Option<String> = None;
        if wr.write_all(b"* OK scripted IMAP ready\r\n").await.is_err() {
            return;
        }
        while let Ok(Some(line)) = lines.next_line().await {
            state.lock().unwrap().log[conn].push(line.clone());
            if line.eq_ignore_ascii_case("DONE") {
                if let Some(tag) = idle_tag.take() {
                    let _ = wr
                        .write_all(format!("{tag} OK IDLE terminated\r\n").as_bytes())
                        .await;
                }
                continue;
            }
            let mut parts = line.splitn(3, ' ');
            let tag = parts.next().unwrap_or("*").to_owned();
            let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
            let rest = parts.next().unwrap_or("").to_owned();
            let mut reply: Vec<u8> = Vec::new();
            let mut stall: Option<Duration> = None;
            match cmd.as_str() {
                "CAPABILITY" => reply.extend_from_slice(
                    format!("* CAPABILITY IMAP4rev1 IDLE\r\n{tag} OK done\r\n").as_bytes(),
                ),
                "LOGIN" => reply.extend_from_slice(format!("{tag} OK logged in\r\n").as_bytes()),
                "SELECT" | "EXAMINE" => {
                    let s = state.lock().unwrap();
                    reply.extend_from_slice(
                        format!(
                            "* {} EXISTS\r\n* 0 RECENT\r\n* FLAGS (\\Seen)\r\n\
                             * OK [UIDVALIDITY {}] UIDs valid\r\n* OK [UIDNEXT {}] next\r\n\
                             {tag} OK [READ-WRITE] SELECT completed\r\n",
                            s.uids.len(),
                            s.uidvalidity,
                            s.uids.last().copied().unwrap_or(0) + 1
                        )
                        .as_bytes(),
                    )
                }
                "LIST" => reply.extend_from_slice(
                    format!("* LIST (\\HasNoChildren) \"/\" INBOX\r\n{tag} OK LIST done\r\n")
                        .as_bytes(),
                ),
                "UID" => {
                    let mut sub = rest.splitn(2, ' ');
                    let what = sub.next().unwrap_or("").to_ascii_uppercase();
                    let args = sub.next().unwrap_or("");
                    let mut s = state.lock().unwrap();
                    let max = s.uids.last().copied().unwrap_or(0);
                    if what == "SEARCH" {
                        let set = args.trim_start_matches("UID ");
                        let wanted = uid_set(set, max);
                        let mut hits: Vec<u32> = s
                            .uids
                            .iter()
                            .copied()
                            .filter(|u| wanted.contains(u))
                            .collect();
                        if s.blind_search {
                            hits.clear();
                        } else if hits.is_empty() && set.ends_with(":*") {
                            hits.extend(s.uids.last().copied()); // RFC 3501's n:* quirk
                        }
                        let list: Vec<String> = hits.iter().map(u32::to_string).collect();
                        reply.extend_from_slice(
                            format!(
                                "* SEARCH {}\r\n{tag} OK SEARCH completed\r\n",
                                list.join(" ")
                            )
                            .as_bytes(),
                        );
                    } else if what == "FETCH" {
                        let (set, items) = args.split_once(' ').unwrap_or((args, ""));
                        let items_up = items.to_ascii_uppercase();
                        let body = items_up.contains("BODY");
                        // `(UID FLAGS)` — a reconcile — against `(UID RFC822.SIZE)`, which is
                        // what the sync asks before a batch. Answering flags to a size request
                        // (or the reverse) would let a bug pass, so the server tells them apart.
                        let flags_only = !body && items_up.contains("FLAGS");
                        // A reconcile ahead of new mail asks both at once (`(UID FLAGS
                        // RFC822.SIZE)`): both are answered, as a real server would.
                        let with_size = items_up.contains("RFC822.SIZE");
                        if body {
                            s.body_fetches += 1;
                            if s.drop_body_fetch == Some(s.body_fetches) {
                                return; // the connection breaks mid-sync
                            }
                        }
                        // A blind flags fetch answers `OK` with no FETCH data at all (the tail
                        // below sends the tagged OK), which is what a dead or truncated session
                        // looks like from the client's side.
                        let blind = flags_only && s.blind_flags;
                        if flags_only {
                            s.flags_fetches += 1;
                            if s.stall_flags.contains(&s.flags_fetches) {
                                stall = Some(s.stall_for);
                            }
                            if s.bump_uidvalidity_at_flags == Some(s.flags_fetches) {
                                s.uidvalidity += 1;
                            }
                        }
                        for uid in if blind { Vec::new() } else { uid_set(set, max) } {
                            let Some(seq) = s.uids.iter().position(|u| *u == uid) else {
                                continue;
                            };
                            let msg = served(&s, uid);
                            let flags = s.flags.get(&uid).cloned().unwrap_or_default().join(" ");
                            if body {
                                reply.extend_from_slice(
                                    format!(
                                        "* {} FETCH (UID {uid} FLAGS ({flags}) BODY[] {{{}}}\r\n",
                                        seq + 1,
                                        msg.len()
                                    )
                                    .as_bytes(),
                                );
                                reply.extend_from_slice(&msg);
                                reply.extend_from_slice(b")\r\n");
                            } else if flags_only && with_size {
                                reply.extend_from_slice(
                                    format!(
                                        "* {} FETCH (UID {uid} FLAGS ({flags}) RFC822.SIZE {})\r\n",
                                        seq + 1,
                                        msg.len()
                                    )
                                    .as_bytes(),
                                );
                            } else if flags_only {
                                reply.extend_from_slice(
                                    format!("* {} FETCH (UID {uid} FLAGS ({flags}))\r\n", seq + 1)
                                        .as_bytes(),
                                );
                            } else {
                                reply.extend_from_slice(
                                    format!(
                                        "* {} FETCH (UID {uid} RFC822.SIZE {})\r\n",
                                        seq + 1,
                                        msg.len()
                                    )
                                    .as_bytes(),
                                );
                            }
                        }
                        reply.extend_from_slice(format!("{tag} OK FETCH completed\r\n").as_bytes());
                    } else if what == "STORE" {
                        // `UID STORE 21 +FLAGS.SILENT (\Flagged)` — what a filter rule sends.
                        let mut it = args.splitn(3, ' ');
                        let set = it.next().unwrap_or("");
                        let op = it.next().unwrap_or("").to_ascii_uppercase();
                        let named: Vec<String> = it
                            .next()
                            .unwrap_or("")
                            .trim_matches(|c| c == '(' || c == ')')
                            .split_whitespace()
                            .map(str::to_owned)
                            .collect();
                        for uid in uid_set(set, max) {
                            let held = s.flags.entry(uid).or_default();
                            if op.starts_with('+') {
                                for f in &named {
                                    if !held.contains(f) {
                                        held.push(f.clone());
                                    }
                                }
                            } else if op.starts_with('-') {
                                held.retain(|f| !named.contains(f));
                            } else {
                                *held = named.clone();
                            }
                        }
                        reply.extend_from_slice(format!("{tag} OK STORE completed\r\n").as_bytes());
                    } else {
                        reply.extend_from_slice(format!("{tag} BAD unsupported\r\n").as_bytes());
                    }
                }
                "IDLE" => {
                    idle_tag = Some(tag);
                    reply.extend_from_slice(b"+ idling\r\n");
                }
                "NOOP" => reply.extend_from_slice(format!("{tag} OK NOOP\r\n").as_bytes()),
                "LOGOUT" => {
                    let _ = wr
                        .write_all(format!("* BYE\r\n{tag} OK LOGOUT completed\r\n").as_bytes())
                        .await;
                    return;
                }
                _ => reply.extend_from_slice(format!("{tag} BAD unknown command\r\n").as_bytes()),
            }
            if let Some(pause) = stall {
                let head = reply
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .map_or(0, |i| i + 2);
                if wr.write_all(&reply[..head]).await.is_err() {
                    return;
                }
                tokio::time::sleep(pause).await;
                reply.drain(..head);
            }
            if wr.write_all(&reply).await.is_err() {
                return;
            }
        }
    }

    /// A server holding UIDs `1..=n` (UIDVALIDITY 7) and an engine on it: window 10, backfill
    /// 8 per later sync, 4 messages per `UID FETCH`.
    async fn setup(n: u32) -> (tempfile::TempDir, Engine, Shared) {
        setup_with(n, |_| {}).await
    }

    /// The same body-fetch log as [`body_fetches`] read from an already locked state.
    fn state_of(s: &Mailbox) -> Shared {
        Arc::new(Mutex::new(Mailbox {
            log: s.log.clone(),
            ..Mailbox::default()
        }))
    }

    /// [`setup`] with the engine configuration adjusted by `tune`.
    async fn setup_with(
        n: u32,
        tune: impl FnOnce(&mut EngineConfig),
    ) -> (tempfile::TempDir, Engine, Shared) {
        let state: Shared = Arc::new(Mutex::new(Mailbox {
            uids: (1..=n).collect(),
            uidvalidity: 7,
            ..Mailbox::default()
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let st = state.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(serve(sock, st.clone()));
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = EngineConfig {
            network_timeout: Duration::from_secs(5),
            sync_window: 10,
            backfill_per_sync: 8,
            fetch_batch: 4,
            ..EngineConfig::default()
        };
        tune(&mut cfg);
        let engine = Engine::open_with(dir.path(), cfg).unwrap();
        engine
            .store()
            .insert_account(&NewAccount {
                email: EMAIL,
                display_name: "",
                imap: &Endpoint::new("127.0.0.1", port, Security::Plain),
                smtp: &Endpoint::new("127.0.0.1", 1, Security::Plain),
                auth_kind: AuthKind::Password,
                login: "w",
                credential: "pw",
            })
            .unwrap();
        engine
            .set_spam_settings(
                EMAIL,
                SpamSettings {
                    enabled: false,
                    ..SpamSettings::default()
                },
            )
            .unwrap();
        (dir, engine, state)
    }

    /// Stored UIDs of INBOX, ascending.
    fn stored(engine: &Engine) -> Vec<u32> {
        let mut uids: Vec<u32> = engine
            .list_messages(ListQuery {
                account: Some(EMAIL.into()),
                limit: 10_000,
                ..ListQuery::default()
            })
            .unwrap()
            .into_iter()
            .map(|m| m.uid)
            .collect();
        uids.sort_unstable();
        uids
    }

    /// (last_uid, floor_uid) of INBOX.
    fn marks(engine: &Engine) -> (u32, u32) {
        let store = engine.store();
        let acct = store.account_by_email(EMAIL).unwrap().unwrap();
        let f = store.folder(acct.id, "INBOX").unwrap();
        (f.last_uid, f.floor_uid)
    }

    /// The UID sets of the body `UID FETCH`es of connection `conn` (`None`: all connections).
    fn body_fetches(state: &Shared, conn: Option<usize>) -> Vec<String> {
        let s = state.lock().unwrap();
        s.log
            .iter()
            .enumerate()
            .filter(|(i, _)| conn.is_none_or(|c| c == *i))
            .flat_map(|(_, l)| l.iter())
            .filter(|l| l.contains("UID FETCH") && l.contains("BODY"))
            .map(|l| l.split(' ').nth(3).unwrap_or("").to_owned())
            .collect()
    }

    fn last_conn(state: &Shared) -> usize {
        state.lock().unwrap().log.len() - 1
    }

    fn searches(state: &Shared, conn: usize) -> Vec<String> {
        state.lock().unwrap().log[conn]
            .iter()
            .filter(|l| l.contains("UID SEARCH"))
            .map(|l| l.split(' ').skip(3).collect::<Vec<_>>().join(" "))
            .collect()
    }

    #[tokio::test]
    async fn first_sync_stores_the_newest_window_newest_batch_first() {
        let (_dir, engine, state) = setup(30).await;
        let r = engine.sync(EMAIL).await.unwrap();
        assert_eq!(r.new, 10);
        assert_eq!(stored(&engine), (21..=30).collect::<Vec<_>>());
        assert_eq!(body_fetches(&state, None), ["27:30", "23:26", "21:22"]);
        assert_eq!(marks(&engine), (30, 21));
        let f = &r.folders[0];
        assert!(f.more_to_backfill);
        assert_eq!(f.older_pending, Some(20));
        // The list shows the newest mail first, as it always did.
        let top = engine
            .list_messages(ListQuery {
                account: Some(EMAIL.into()),
                limit: 3,
                ..ListQuery::default()
            })
            .unwrap();
        let subjects: Vec<String> = top.into_iter().filter_map(|m| m.subject).collect();
        assert_eq!(subjects, ["w 30", "w 29", "w 28"]);
        // A mailbox that fits the window is complete after its first sync.
        let (_dir2, small, _) = setup(6).await;
        let r = small.sync(EMAIL).await.unwrap();
        assert_eq!((r.new, r.folders[0].more_to_backfill), (6, false));
        assert_eq!(r.folders[0].older_pending, Some(0));
        assert_eq!(marks(&small), (6, 1));
    }

    #[tokio::test]
    async fn later_syncs_and_backfill_continue_below_the_window_down_to_uid_1() {
        let (_dir, engine, state) = setup(30).await;
        engine.sync(EMAIL).await.unwrap();
        state.lock().unwrap().uids.extend([31, 32]);
        // A later sync: the new mail first (oldest first, as before), then 8 older ones.
        let r = engine.sync(EMAIL).await.unwrap();
        let conn = last_conn(&state);
        assert_eq!(
            body_fetches(&state, Some(conn)),
            ["31:32", "17:20", "13:16"]
        );
        assert_eq!(searches(&state, conn), ["UID 31:*", "UID 1:*"]);
        assert_eq!(r.new, 10);
        assert_eq!(marks(&engine), (32, 13));
        assert_eq!(r.folders[0].older_pending, Some(12));
        // An explicit backfill with a budget, then one without.
        let r = engine.backfill(EMAIL, Some(5)).await.unwrap();
        assert_eq!(r.new, 5);
        assert_eq!(body_fetches(&state, Some(last_conn(&state))), ["9:12", "8"]);
        assert_eq!(marks(&engine), (32, 8));
        let r = engine.backfill(EMAIL, None).await.unwrap();
        assert_eq!(r.new, 7);
        assert_eq!(
            body_fetches(&state, Some(last_conn(&state))),
            ["4:7", "1:3"]
        );
        assert_eq!(marks(&engine), (32, 1));
        assert!(!r.folders[0].more_to_backfill);
        assert_eq!(r.folders[0].older_pending, Some(0));
        // Everything once: 32 stored, and no UID was fetched twice over the whole run.
        assert_eq!(stored(&engine), (1..=32).collect::<Vec<_>>());
        let mut fetched: Vec<u32> = body_fetches(&state, None)
            .iter()
            .flat_map(|s| super::window_tests::uid_set(s, 32))
            .collect();
        fetched.sort_unstable();
        assert_eq!(fetched, (1..=32).collect::<Vec<_>>());
        // Complete: nothing left to backfill, so a sync searches for new mail only and an
        // explicit backfill does not even connect.
        let before = last_conn(&state);
        let r = engine.backfill(EMAIL, None).await.unwrap();
        assert_eq!((r.new, last_conn(&state)), (0, before));
        engine.sync(EMAIL).await.unwrap();
        assert_eq!(
            searches(&state, last_conn(&state)),
            ["UID 33:*", "UID 1:*"],
            "new mail, then the reconcile's own search — with nothing left to backfill there \
             is no `1:*` for it to share"
        );
    }

    #[tokio::test]
    async fn an_interrupted_first_sync_resumes_without_gaps_or_refetches() {
        let (_dir, engine, state) = setup(30).await;
        state.lock().unwrap().drop_body_fetch = Some(2);
        assert!(engine.sync(EMAIL).await.is_err(), "the connection broke");
        // The first batch is stored and the marks say exactly that.
        assert_eq!(stored(&engine), (27..=30).collect::<Vec<_>>());
        assert_eq!(marks(&engine), (30, 27));
        state.lock().unwrap().drop_body_fetch = None;
        let r = engine.sync(EMAIL).await.unwrap();
        assert_eq!(r.new, 8, "no new mail; 8 older ones below the floor");
        assert_eq!(
            body_fetches(&state, Some(last_conn(&state))),
            ["23:26", "19:22"]
        );
        engine.backfill(EMAIL, None).await.unwrap();
        assert_eq!(stored(&engine), (1..=30).collect::<Vec<_>>());
        let mut fetched: Vec<u32> = body_fetches(&state, None)
            .iter()
            .flat_map(|s| uid_set(s, 30))
            .collect();
        fetched.sort_unstable();
        // 23:26 was asked once before the break (never answered), then again.
        let mut expected: Vec<u32> = (1..=30).collect();
        expected.extend(23..=26);
        expected.sort_unstable();
        assert_eq!(fetched, expected);
    }

    #[tokio::test]
    async fn a_uidvalidity_change_clears_the_floor_and_starts_over_with_the_window() {
        let (_dir, engine, state) = setup(30).await;
        engine.sync(EMAIL).await.unwrap();
        engine.sync(EMAIL).await.unwrap(); // backfills 8: floor 13
        assert_eq!(marks(&engine), (30, 13));
        state.lock().unwrap().uidvalidity = 8;
        let r = engine.sync(EMAIL).await.unwrap();
        assert!(r.folders[0].uidvalidity_reset);
        assert_eq!(r.new, 10, "a first sync again: the newest window only");
        assert_eq!(stored(&engine), (21..=30).collect::<Vec<_>>());
        assert_eq!(marks(&engine), (30, 21), "the old floor (13) is gone");
        assert!(r.folders[0].more_to_backfill);
    }

    #[tokio::test]
    async fn watch_fetches_new_mail_only_and_never_backfills() {
        let (_dir, engine, state) = setup(30).await;
        let mut events = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(20),
            engine.watch(EMAIL, Duration::from_millis(200), |e| {
                let stop = matches!(e, WatchEvent::Idle { .. });
                events.push(e);
                !stop
            }),
        )
        .await
        .expect("watch returned")
        .expect("watch ok");
        assert!(matches!(&events[0], WatchEvent::NewMail { report } if report.new == 10));
        assert_eq!(stored(&engine), (21..=30).collect::<Vec<_>>());
        // Nothing below the window is ever fetched. `UID 1:*` appears three times and none of
        // them is a backfill: the first sync's own search, and one per reconcile (the first
        // sync's and the catch-up round's) — a watch pass has no backfill whose search it
        // could share. What matters is the body fetches below, which never go under UID 21.
        let full = searches(&state, 0)
            .iter()
            .filter(|s| s.as_str() == "UID 1:*")
            .count();
        assert_eq!(full, 3, "{:?}", searches(&state, 0));
        assert_eq!(body_fetches(&state, None), ["27:30", "23:26", "21:22"]);
    }

    /// Progress: one event per stored batch, each one already committed (the list shows
    /// `local` messages from inside the callback), for the window, the backfill of a later
    /// sync and an explicit backfill to the end.
    #[tokio::test]
    async fn every_stored_batch_is_reported_and_already_listable() {
        let (_dir, engine, _state) = setup(30).await;
        let mut seen: Vec<(SyncPhase, u32, u32, u32, u32, bool)> = Vec::new();
        let mut listed: Vec<usize> = Vec::new();
        let mut record = |p: SyncProgress| {
            assert_eq!((p.account.as_str(), p.folder.as_str()), (EMAIL, "INBOX"));
            assert_eq!(p.total_known, 30);
            listed.push(stored(&engine).len());
            seen.push((
                p.phase,
                p.fetched,
                p.stored,
                p.planned,
                p.local,
                p.more_to_backfill,
            ));
        };
        engine.sync_with_progress(EMAIL, &mut record).await.unwrap();
        engine.sync_with_progress(EMAIL, &mut record).await.unwrap();
        engine
            .backfill_with_progress(EMAIL, None, &mut record)
            .await
            .unwrap();
        use SyncPhase::{Backfill, Initial};
        assert_eq!(
            seen,
            [
                (Initial, 4, 4, 10, 4, true),
                (Initial, 8, 8, 10, 8, true),
                (Initial, 10, 10, 10, 10, true),
                (Backfill, 4, 4, 8, 14, true),
                (Backfill, 8, 8, 8, 18, true),
                (Backfill, 4, 4, 12, 22, true),
                (Backfill, 8, 8, 12, 26, true),
                (Backfill, 12, 12, 12, 30, false),
            ]
        );
        assert_eq!(listed, [4, 8, 10, 14, 18, 22, 26, 30]);
    }

    #[test]
    fn batches_stop_at_the_count_or_the_bytes_and_big_messages_travel_alone() {
        let sizes: std::collections::HashMap<u32, u32> = [
            (1, 100),
            (2, 100),
            (3, 900),
            (4, 50),
            (5, 50),
            (6, 50),
            (7, 50),
            (8, 5000),
        ]
        .into_iter()
        .collect();
        let uids = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(
            super::plan_batches(&uids, &sizes, 3, 300),
            vec![
                vec![1, 2],
                vec![3],
                vec![4, 5, 6],
                vec![7],
                vec![8],
                vec![9]
            ]
        );
        // The order given is kept (a backfill plans newest first); 0 bytes = count only.
        assert_eq!(
            super::plan_batches(&[9, 8, 7], &sizes, 2, 0),
            vec![vec![9, 8], vec![7]]
        );
        assert!(super::plan_batches(&[], &sizes, 2, 10).is_empty());
    }

    /// The byte bound against the server: every body `UID FETCH` stays under the limit unless
    /// it carries one message, and a batch is only cut when the next message would not fit.
    #[tokio::test]
    async fn every_fetch_stays_under_the_byte_limit() {
        let (_dir, engine, state) = setup_with(30, |c| {
            c.fetch_batch = 10;
            c.fetch_batch_bytes = 1200;
        })
        .await;
        state.lock().unwrap().pad = [(28, 2000), (24, 600), (22, 900)].into_iter().collect();
        engine.sync(EMAIL).await.unwrap();
        assert_eq!(stored(&engine), (21..=30).collect::<Vec<_>>());
        let s = state.lock().unwrap();
        let size = |u: u32| served(&s, u).len();
        let batches: Vec<Vec<u32>> = body_fetches(&state_of(&s), None)
            .iter()
            .map(|set| {
                let mut v = uid_set(set, 30);
                v.reverse();
                v
            })
            .collect();
        assert!(batches.len() > 1, "{batches:?}");
        let order: Vec<u32> = batches.iter().flatten().copied().collect();
        assert_eq!(order, (21..=30).rev().collect::<Vec<_>>(), "newest first");
        for (k, b) in batches.iter().enumerate() {
            let bytes: usize = b.iter().map(|u| size(*u)).sum();
            assert!(b.len() == 1 || bytes <= 1200, "batch {b:?}: {bytes} bytes");
            if let Some(next) = batches.get(k + 1) {
                assert!(bytes + size(next[0]) > 1200, "batch {b:?} was cut early");
            }
        }
        assert!(
            batches.contains(&vec![28]),
            "a message over the limit travels alone"
        );
    }

    /// The overlap: while batch k is processed and stored, the `UID FETCH` of batch k+1 is
    /// already on the wire. Checked from inside the progress callback of batch k, which runs
    /// before `fetch_and_store` can move on — a sequential loop would never send it in time.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_next_fetch_is_on_the_wire_while_a_batch_is_stored() {
        let (_dir, engine, state) = setup(30).await;
        let st = state.clone();
        let mut k = 0usize;
        let mut early = Vec::new();
        engine
            .sync_with_progress(EMAIL, |_| {
                k += 1;
                if k < 3 {
                    let deadline = std::time::Instant::now() + Duration::from_secs(3);
                    let sent = loop {
                        let n = body_fetches(&st, None).len();
                        if n > k || std::time::Instant::now() > deadline {
                            break n;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    };
                    early.push(sent);
                }
            })
            .await
            .unwrap();
        assert_eq!(k, 3, "three batches of the window");
        assert_eq!(
            early,
            [2, 3],
            "FETCH k+1 had reached the server when batch k was stored"
        );
    }

    /// Bob's Autocrypt header value.
    fn bob_autocrypt(bob: &sealbox_crypto::Identity) -> String {
        use base64::Engine as _;
        let keydata = sealbox_crypto::minimal_key_for_autocrypt(bob).unwrap();
        sealbox_mail::mime::autocrypt_header_value(
            "bob@example.org",
            true,
            &base64::engine::general_purpose::STANDARD.encode(&keydata),
        )
    }

    /// A message from Bob to the account, with his Autocrypt header; encrypted to `to` and
    /// signed by Bob when `to` is given, else plain.
    fn from_bob(
        bob: &sealbox_crypto::Identity,
        to: Option<&sealbox_crypto::Identity>,
        subject: &str,
        minute: i64,
    ) -> Vec<u8> {
        use sealbox_mail::mime::{
            build_pgp_mime_encrypted, build_plain, render_inner_for_encryption, InnerOptions,
            Mailbox as MimeBox, MessageDraft, OuterHeaders,
        };
        let mut d = MessageDraft::new(
            MimeBox::named("Bob", "bob@example.org"),
            vec![MimeBox::new(EMAIL)],
            subject,
            "body\n",
        );
        d.date = 1_772_000_000 + minute * 60;
        d.extra_headers
            .push(("Autocrypt".into(), bob_autocrypt(bob)));
        match to {
            None => build_plain(&d).unwrap(),
            Some(rcpt) => {
                let inner = render_inner_for_encryption(
                    &d,
                    &InnerOptions {
                        gossip_headers: vec![],
                        legacy_display: false,
                    },
                )
                .unwrap();
                let armored = sealbox_crypto::encrypt_and_sign_armored(
                    &inner,
                    &[&rcpt.public(), &bob.public()],
                    Some(bob),
                )
                .unwrap();
                build_pgp_mime_encrypted(&OuterHeaders::for_protected(&d), &armored).unwrap()
            }
        }
    }

    /// A long-lived sync context (the app's IDLE watcher, built at start, when no peer was
    /// known) must see a key that ANOTHER sync stored meanwhile: the watcher's next round
    /// verifies Bob's signed mail as Good. (G17 caught the regression: the reload used to be
    /// triggered only by a key change seen through the same context.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_watcher_sees_keys_another_sync_stored_meanwhile() {
        let (_dir, engine, state) = setup(1).await;
        let me = sealbox_crypto::Identity::generate("W", EMAIL).unwrap();
        {
            let store = engine.store();
            let acct = store.account_by_email(EMAIL).unwrap().unwrap();
            store
                .insert_identity(
                    acct.id,
                    &me.fingerprint(),
                    EMAIL,
                    &me.to_armored_secret(None).unwrap(),
                    &me.public().to_armored().unwrap(),
                )
                .unwrap();
        }
        let bob = sealbox_crypto::Identity::generate("Bob", "bob@example.org").unwrap();
        let engine = Arc::new(engine);
        let (tx, rx) = std::sync::mpsc::channel::<&'static str>();
        let e = engine.clone();
        let watcher = tokio::spawn(async move {
            let mut new_mail = 0;
            e.watch(EMAIL, Duration::from_secs(3), move |ev| {
                match ev {
                    WatchEvent::NewMail { .. } => {
                        new_mail += 1;
                        let _ = tx.send("new");
                    }
                    WatchEvent::Idle { .. } => {
                        let _ = tx.send("idle");
                    }
                    WatchEvent::Timeout => {}
                }
                new_mail < 2
            })
            .await
        });
        let wait_for = |what: &str| loop {
            match rx.recv_timeout(Duration::from_secs(20)) {
                Ok(ev) if ev == what => break,
                Ok(_) => continue,
                Err(e) => panic!("waiting for {what}: {e}"),
            }
        };
        wait_for("idle"); // the watcher's context exists (no peers) and IDLE runs for 3 s
        state
            .lock()
            .unwrap()
            .bodies
            .insert(2, from_bob(&bob, None, "hello", 2));
        state.lock().unwrap().uids.push(2);
        engine.sync(EMAIL).await.unwrap(); // another context learns Bob's key
        state
            .lock()
            .unwrap()
            .bodies
            .insert(3, from_bob(&bob, Some(&me), "signed", 3));
        state.lock().unwrap().uids.push(3);
        wait_for("new"); // the watcher's catch-up after its IDLE round
        watcher.await.unwrap().unwrap();
        let signed = engine
            .list_messages(ListQuery {
                account: Some(EMAIL.into()),
                ..ListQuery::default()
            })
            .unwrap()
            .into_iter()
            .find(|m| m.uid == 3)
            .expect("uid 3 stored by the watcher");
        assert!(signed.decrypted, "{signed:?}");
        assert_eq!(
            (
                signed.signature.status,
                signed.signature.fingerprint.as_deref()
            ),
            (
                crate::types::SigState::Good,
                Some(bob.fingerprint().as_str())
            ),
            "the watcher verified with the key the other sync stored"
        );
    }

    /// A search that comes back empty for a folder with mail is a broken session, not "nothing
    /// older": the backfill must fail (and keep its floor), never mark the folder complete.
    #[tokio::test]
    async fn an_empty_search_never_ends_the_backfill() {
        let (_dir, engine, state) = setup(30).await;
        engine.sync(EMAIL).await.unwrap();
        // The server now answers every SEARCH with nothing (as async-imap reports a NO / EOF).
        state.lock().unwrap().blind_search = true;
        assert!(engine.backfill(EMAIL, None).await.is_err());
        assert_eq!(marks(&engine), (30, 21));
        state.lock().unwrap().blind_search = false;
        engine.backfill(EMAIL, None).await.unwrap();
        assert_eq!(marks(&engine), (30, 1));
        assert_eq!(stored(&engine), (1..=30).collect::<Vec<_>>());
    }
    // ----- convergence with the server (Engine::reconcile_selected) --------------------

    /// INBOX's entry in a sync report.
    fn inbox(report: &crate::types::SyncReport) -> &crate::types::FolderSync {
        report
            .folders
            .iter()
            .find(|f| f.name == "INBOX")
            .expect("the report has an INBOX entry")
    }

    /// The flags stored for `uid`, as the UI would read them.
    fn flags_of(engine: &Engine, uid: u32) -> Vec<String> {
        engine
            .list_messages(ListQuery {
                account: Some(EMAIL.into()),
                limit: 10_000,
                ..ListQuery::default()
            })
            .unwrap()
            .into_iter()
            .find(|m| m.uid == uid)
            .map(|m| m.flags)
            .unwrap_or_default()
    }

    fn seen_of(engine: &Engine, uid: u32) -> bool {
        engine
            .list_messages(ListQuery {
                account: Some(EMAIL.into()),
                limit: 10_000,
                ..ListQuery::default()
            })
            .unwrap()
            .into_iter()
            .find(|m| m.uid == uid)
            .map(|m| m.seen)
            .unwrap_or(false)
    }

    /// Every flags-only `UID FETCH` the server was sent, as its UID set.
    fn flag_fetches(state: &Shared) -> Vec<String> {
        let s = state.lock().unwrap();
        s.log
            .iter()
            .flat_map(|l| l.iter())
            .filter(|l| l.contains("(UID FLAGS") && !l.contains("BODY"))
            .map(|l| l.split(' ').nth(3).unwrap_or("").to_owned())
            .collect()
    }

    /// Mail deleted in webmail or on the phone leaves the server, and must leave the local
    /// store on the next sync. Before the reconcile it stayed for ever.
    #[tokio::test]
    async fn a_message_expunged_elsewhere_is_dropped_on_the_next_sync() {
        let (_dir, engine, state) = setup(3).await;
        engine.sync(EMAIL).await.unwrap();
        assert_eq!(stored(&engine), vec![1, 2, 3]);

        state.lock().unwrap().uids.retain(|u| *u != 2);
        let report = engine.sync(EMAIL).await.unwrap();

        assert_eq!(stored(&engine), vec![1, 3], "UID 2 is gone from the server");
        assert_eq!(inbox(&report).removed, 1);
        assert_eq!(inbox(&report).flags_changed, 0);
        // One command for the whole stored set, not one per message — and one range: the gap
        // UID 2 left is bridged, since the server has nothing there to answer for.
        assert_eq!(
            flag_fetches(&state).last().map(String::as_str),
            Some("1:3"),
            "one range over the survivors, not a list of them"
        );
    }

    /// G33: the reconcile's flags are fetched as a few UID ranges, not in 500-UID chunks. Some
    /// servers (GreenMail) pay ≈0.7 s per `FETCH` of a 10,000-message folder whatever it
    /// names, so the chunks made a +50 incremental sync of one take 13 s instead of ~1.
    #[test]
    fn flag_fetch_runs_bridge_expunged_gaps_and_break_only_at_unstored_mail() {
        let live = |v: &[u32]| {
            v.iter()
                .copied()
                .collect::<std::collections::BTreeSet<u32>>()
        };
        // Fully synced, pruned elsewhere (2, 5, 6 expunged): one range.
        assert_eq!(
            super::flag_fetch_runs(&[1, 3, 4, 7, 8], &live(&[1, 3, 4, 7, 8])),
            vec![(1, 8)]
        );
        // A first window / backfill in progress: the stored top slice of the live set.
        assert_eq!(
            super::flag_fetch_runs(&[21, 22, 30], &live(&[1, 2, 20, 21, 22, 30])),
            vec![(21, 30)]
        );
        // A live UID we hold no copy of (a stranded message) splits the range, so it is not
        // asked about for nothing.
        assert_eq!(
            super::flag_fetch_runs(&[1, 2, 4, 5], &live(&[1, 2, 3, 4, 5, 6])),
            vec![(1, 2), (4, 5)]
        );
        assert_eq!(
            super::flag_fetch_runs(&[], &live(&[1, 2])),
            Vec::<(u32, u32)>::new()
        );
        assert_eq!(super::flag_fetch_runs(&[9], &live(&[9])), vec![(9, 9)]);
    }

    /// The whole point of the ranges, end to end: a folder far past the old 500-UID chunk
    /// reconciles in a single flags fetch, and that fetch still finds a change made elsewhere
    /// and drops what was expunged — across an expunged gap inside the range.
    #[tokio::test]
    async fn a_large_folder_reconciles_in_one_flags_fetch() {
        let (_dir, engine, state) = setup_with(1200, |c| {
            c.sync_window = 2000;
            c.fetch_batch = 400;
        })
        .await;
        engine.sync(EMAIL).await.unwrap();
        assert_eq!(stored(&engine).len(), 1200);
        let before = flag_fetches(&state).len();

        {
            let mut s = state.lock().unwrap();
            s.uids.retain(|u| !(600..=610).contains(u));
            s.flags.insert(1100, vec!["\\Seen".into()]);
        }
        let report = engine.sync(EMAIL).await.unwrap();
        let fetches = flag_fetches(&state);
        assert_eq!(
            &fetches[before..],
            &["1:1200".to_string()],
            "one command, one range"
        );
        assert_eq!(inbox(&report).removed, 11);
        assert_eq!(inbox(&report).flags_changed, 1);
        assert!(seen_of(&engine, 1100));
        assert_eq!(stored(&engine).len(), 1189);
    }

    /// G33, the other half: an incremental sync with new mail asks the new mail's sizes in
    /// the reconcile's own flags fetch, so it sends one `UID FETCH` before the bodies, not two
    /// — what it sent before the reconcile existed. The flags of the stored mail are still
    /// followed, what was expunged still goes, and the new mail is stored in byte-bounded
    /// batches planned from those sizes.
    #[tokio::test]
    async fn an_incremental_sync_asks_sizes_and_flags_in_one_fetch() {
        let (_dir, engine, state) = setup_with(20, |c| {
            c.sync_window = 100;
            c.fetch_batch = 100;
            c.fetch_batch_bytes = 3000;
        })
        .await;
        engine.sync(EMAIL).await.unwrap();
        assert_eq!(stored(&engine).len(), 20);
        let mark = state.lock().unwrap().log.len();
        {
            let mut s = state.lock().unwrap();
            s.uids.retain(|u| *u != 7);
            s.flags.insert(3, vec!["\\Seen".into()]);
            s.uids.extend(21..=26);
            for u in 21..=26 {
                s.pad.insert(u, 1000); // ~1.3 kB each: two per 3000-byte batch
            }
        }
        let report = engine.sync(EMAIL).await.unwrap();
        assert_eq!(report.new, 6);
        assert_eq!(inbox(&report).removed, 1);
        assert_eq!(inbox(&report).flags_changed, 1);
        assert!(seen_of(&engine, 3));
        assert_eq!(
            stored(&engine),
            (1..=26).filter(|u| *u != 7).collect::<Vec<u32>>()
        );

        let s = state.lock().unwrap();
        let lines: Vec<&String> = s.log[mark..].iter().flatten().collect();
        let fetches: Vec<&&String> = lines
            .iter()
            .filter(|l| l.contains("UID FETCH") && !l.contains("BODY"))
            .collect();
        assert_eq!(fetches.len(), 1, "one non-body FETCH: {fetches:?}");
        assert!(
            fetches[0].contains("1:20,21:26 (UID FLAGS RFC822.SIZE)"),
            "stored range + new UIDs, flags and sizes together: {fetches:?}"
        );
        let bodies = lines.iter().filter(|l| l.contains("BODY.PEEK[]")).count();
        assert!(
            bodies >= 3,
            "the batches were planned from the sizes (6 padded messages, 3000-byte batches): \
             {bodies} body fetches"
        );
    }

    /// The subject of every stored message by UID — what was actually stored under it.
    fn subjects_by_uid(engine: &Engine) -> Vec<(u32, String)> {
        let mut out: Vec<(u32, String)> = engine
            .list_messages(ListQuery {
                account: Some(EMAIL.into()),
                limit: 10_000,
                ..ListQuery::default()
            })
            .unwrap()
            .into_iter()
            .map(|m| (m.uid, m.subject.unwrap_or_default()))
            .collect();
        out.sort();
        out
    }

    /// A pass whose 20 messages are stored, then six new ones (21..=26) and a flag set
    /// elsewhere on 3, with the next `stalls` flags fetches stalled for `stall_for` (the
    /// network timeout is 1 s).
    async fn stalled_reconcile(
        stalls: usize,
        stall_for: Duration,
    ) -> (tempfile::TempDir, Engine, Shared, usize) {
        let (dir, engine, state) = setup_with(20, |c| {
            c.network_timeout = Duration::from_secs(1);
            c.sync_window = 100;
            c.fetch_batch = 100;
        })
        .await;
        engine.sync(EMAIL).await.unwrap();
        assert_eq!(stored(&engine).len(), 20);
        let mark = state.lock().unwrap().log.len();
        {
            let mut s = state.lock().unwrap();
            s.flags.insert(3, vec!["\\Seen".into()]);
            s.uids.extend(21..=26);
            let next = s.flags_fetches + 1;
            s.stall_flags = (next..next + stalls).collect();
            s.stall_for = stall_for;
        }
        (dir, engine, state, mark)
    }

    /// The reconcile runs ahead of the new mail on an incremental pass. A flags fetch of it
    /// that times out (a huge folder over a slow link) must not keep the new mail out: the
    /// new mail is fetched with its own sizes fetch, the reconcile runs again after it, and
    /// the stale answer of the abandoned command is drained (NOOP) rather than read as the
    /// next command's — every new UID is stored under its own message.
    #[tokio::test]
    async fn a_reconcile_that_times_out_does_not_keep_the_new_mail_out() {
        let (_dir, engine, state, mark) = stalled_reconcile(1, Duration::from_millis(1500)).await;
        let report = engine.sync(EMAIL).await.unwrap();
        assert_eq!(report.new, 6);
        assert_eq!(stored(&engine), (1..=26).collect::<Vec<u32>>());
        for (uid, subject) in subjects_by_uid(&engine) {
            assert_eq!(
                subject,
                format!("w {uid}"),
                "UID {uid} stored the wrong message"
            );
        }
        assert!(
            seen_of(&engine, 3),
            "the reconcile ran again after the new mail"
        );
        assert_eq!(inbox(&report).flags_changed, 1);

        let s = state.lock().unwrap();
        let lines: Vec<&String> = s.log[mark..].iter().flatten().collect();
        let stalled = lines
            .iter()
            .position(|l| l.contains("(UID FLAGS RFC822.SIZE)"))
            .expect("the reconcile asked flags and sizes first");
        assert!(
            lines[stalled + 1].ends_with("NOOP"),
            "the session is drained before it is used again: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.ends_with("(UID RFC822.SIZE)")),
            "the new mail's sizes were asked again on their own: {lines:?}"
        );
    }

    /// Even when every reconcile of the pass times out — and stalls so long that the NOOP
    /// meant to drain it times out too — the new mail is stored first, over a fresh session;
    /// the pass reports the reconcile's error only after that, as it did before the reconcile
    /// moved ahead of the fetch.
    #[tokio::test]
    async fn new_mail_is_stored_even_when_every_reconcile_times_out() {
        let stall = Duration::from_millis(2500);
        let (_dir, engine, state, mark) = stalled_reconcile(2, stall).await;
        let result = engine.sync(EMAIL).await;
        assert!(
            result.is_err(),
            "the trailing reconcile's timeout is reported"
        );
        assert_eq!(stored(&engine), (1..=26).collect::<Vec<u32>>());
        for (uid, subject) in subjects_by_uid(&engine) {
            assert_eq!(
                subject,
                format!("w {uid}"),
                "UID {uid} stored the wrong message"
            );
        }
        let s = state.lock().unwrap();
        let conns = &s.log[mark..];
        assert_eq!(
            conns.len(),
            3,
            "a reconnect after each failed reconcile: {conns:?}"
        );
        assert!(
            conns[1].iter().any(|l| l.contains("BODY.PEEK[]")),
            "the new mail came over the fresh session: {conns:?}"
        );
    }

    /// The new mail a pass stored before its trailing reconcile failed still goes through the
    /// spam/filter pass (G25) of that same pass: the next pass does not see it as new, so it
    /// would otherwise never be filtered. Here every reconcile times out, and a rule stars
    /// mail whose subject contains "w 2": the six new messages (21..=26) are starred, on the
    /// server and locally, over a session that was replaced after the stall; the stored
    /// mail matching the rule (2, 20) is not touched, being not new. The reconcile's error is
    /// still the pass's.
    #[tokio::test]
    async fn new_mail_is_filtered_even_when_the_trailing_reconcile_fails() {
        use sealbox_spam::filters::{FilterAction, FilterField, FilterMatch, FilterOp, FilterRule};
        let (_dir, engine, state, mark) = stalled_reconcile(2, Duration::from_millis(2500)).await;
        engine
            .add_filter_rule(
                EMAIL,
                FilterRule {
                    id: 0,
                    order: 0,
                    enabled: true,
                    name: "star w 2x".into(),
                    matcher: FilterMatch {
                        field: FilterField::Subject,
                        op: FilterOp::Contains,
                        value: "w 2".into(),
                        case_insensitive: true,
                    },
                    action: FilterAction::Star,
                    stop: false,
                },
            )
            .unwrap();
        let result = engine.sync(EMAIL).await;
        assert!(
            result.is_err(),
            "the trailing reconcile's timeout is reported"
        );
        assert_eq!(stored(&engine), (1..=26).collect::<Vec<u32>>());
        let flagged: Vec<u32> = engine
            .list_messages(ListQuery {
                account: Some(EMAIL.into()),
                limit: 10_000,
                ..ListQuery::default()
            })
            .unwrap()
            .into_iter()
            .filter(|m| m.flags.iter().any(|f| f == "\\Flagged"))
            .map(|m| m.uid)
            .collect::<std::collections::BTreeSet<u32>>()
            .into_iter()
            .collect();
        assert_eq!(flagged, (21..=26).collect::<Vec<u32>>(), "starred locally");
        let s = state.lock().unwrap();
        for uid in 21..=26 {
            assert!(
                s.flags
                    .get(&uid)
                    .is_some_and(|f| f.iter().any(|x| x == "\\Flagged")),
                "UID {uid} starred on the server"
            );
        }
        let conns = &s.log[mark..];
        assert_eq!(conns.len(), 3, "{conns:?}");
        assert!(
            conns[2].iter().any(|l| l.contains("UID STORE")),
            "the rule ran over the session opened after the failed reconcile: {conns:?}"
        );
    }

    /// When the session cannot be recovered after the trailing reconcile failed (here the
    /// folder's UIDVALIDITY changed under the pass, so the new UIDs could name other messages)
    /// the spam/filter pass is skipped — and so must the auto-reply be: it relies on that pass
    /// having moved spam out of INBOX, and it moves its cursor past whatever it evaluates, so
    /// answering unfiltered mail could not be taken back. The cursor stays where it was.
    #[tokio::test]
    async fn no_autoreply_over_new_mail_the_spam_pass_could_not_filter() {
        let (_dir, engine, state, _mark) = stalled_reconcile(2, Duration::from_millis(2500)).await;
        engine
            .set_autoreply(
                EMAIL,
                crate::settings::AutoReplySettings {
                    enabled: true,
                    body: "away".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let cursor_before = engine.autoreply_state(EMAIL).unwrap().cursor;
        {
            let mut s = state.lock().unwrap();
            // The stalled flags fetches are the early and the trailing reconcile; the folder
            // is recreated when the trailing one arrives, so recovery finds a new UIDVALIDITY.
            let trailing = *s.stall_flags.last().unwrap();
            s.bump_uidvalidity_at_flags = Some(trailing);
        }
        let result = engine.sync(EMAIL).await;
        assert!(
            result.is_err(),
            "the trailing reconcile's failure is reported"
        );
        assert_eq!(stored(&engine), (1..=26).collect::<Vec<u32>>());
        assert_eq!(
            engine.autoreply_state(EMAIL).unwrap().cursor,
            cursor_before,
            "the responder did not evaluate mail the spam/filter pass skipped"
        );
    }

    /// A reconcile's commands are bounded in UIDs as well as in ranges, so what one command
    /// brings back does not grow with the folder; sizes are asked only where new UIDs are.
    #[test]
    fn reconcile_commands_are_bounded_in_uids_and_ask_sizes_only_for_new_mail() {
        use super::{plan_flag_commands, FlagCommand};
        let live =
            |r: std::ops::RangeInclusive<u32>| r.collect::<std::collections::BTreeSet<u32>>();
        // Fully synced 1..=25 plus new 26..=27, at most 10 UIDs per command.
        let all = live(1..=27);
        let cmds = plan_flag_commands(&[(1, 25)], &all, &[(26, 27)], 256, 10);
        assert_eq!(
            cmds,
            vec![
                FlagCommand {
                    ranges: vec![(1, 10)],
                    with_sizes: false,
                    flag_uids: 10
                },
                FlagCommand {
                    ranges: vec![(11, 20)],
                    with_sizes: false,
                    flag_uids: 10
                },
                FlagCommand {
                    ranges: vec![(21, 25), (26, 27)],
                    with_sizes: true,
                    flag_uids: 5
                },
            ]
        );
        // The count is of live UIDs: an expunged gap inside a range costs nothing.
        let gappy: std::collections::BTreeSet<u32> = (1..=5).chain(1000..=1004).collect();
        assert_eq!(
            plan_flag_commands(&[(1, 1004)], &gappy, &[], 256, 10),
            vec![FlagCommand {
                ranges: vec![(1, 1004)],
                with_sizes: false,
                flag_uids: 10
            }]
        );
        // Many new UIDs are split too, and never share a command beyond the bound.
        let cmds = plan_flag_commands(&[], &live(1..=25), &[(1, 25)], 256, 10);
        assert_eq!(
            cmds.iter().map(|c| c.ranges.clone()).collect::<Vec<_>>(),
            vec![vec![(1, 10)], vec![(11, 20)], vec![(21, 25)]]
        );
        assert!(cmds.iter().all(|c| c.with_sizes && c.flag_uids == 0));
        // The range bound still holds.
        let runs: Vec<(u32, u32)> = (0..5).map(|i| (i * 2 + 1, i * 2 + 1)).collect();
        let cmds = plan_flag_commands(&runs, &live(1..=10), &[], 2, 100);
        assert_eq!(cmds.len(), 3);
        // The folder G33 measures (10,000 stored, +50 new) is still one command at the real
        // bound; a folder ten times that is ten.
        let big = live(1..=10_050);
        let g33 = plan_flag_commands(
            &[(1, 10_000)],
            &big,
            &[(10_001, 10_050)],
            super::RECONCILE_RANGES,
            super::RECONCILE_UIDS,
        );
        assert_eq!(g33.len(), 1);
        assert!(g33[0].with_sizes);
        let huge = live(1..=163_840);
        assert_eq!(
            plan_flag_commands(
                &[(1, 163_840)],
                &huge,
                &[],
                super::RECONCILE_RANGES,
                super::RECONCILE_UIDS
            )
            .len(),
            10
        );
    }

    /// A partly backfilled folder holds only its newest slice. The flags fetch covers that
    /// slice and nothing older — it does not ask about the whole mailbox.
    #[tokio::test]
    async fn a_windowed_folder_fetches_flags_for_its_stored_slice_only() {
        let (_dir, engine, state) = setup_with(30, |c| c.backfill_per_sync = 0).await;
        engine.sync(EMAIL).await.unwrap();
        assert_eq!(stored(&engine), (21..=30).collect::<Vec<u32>>());
        state.lock().unwrap().uids.retain(|u| *u != 25);
        let report = engine.sync(EMAIL).await.unwrap();
        assert_eq!(inbox(&report).removed, 1);
        assert_eq!(
            flag_fetches(&state).last().map(String::as_str),
            Some("21:30")
        );
    }

    /// Mail read elsewhere must stop being bold here — and, just as important, must not be
    /// rewritten on every later sync once it has been followed.
    #[tokio::test]
    async fn flags_set_elsewhere_are_followed_once_and_then_left_alone() {
        let (_dir, engine, state) = setup(3).await;
        engine.sync(EMAIL).await.unwrap();
        assert!(!seen_of(&engine, 2));

        state
            .lock()
            .unwrap()
            .flags
            .insert(2, vec!["\\Seen".into(), "\\Flagged".into()]);
        let report = engine.sync(EMAIL).await.unwrap();
        assert_eq!(inbox(&report).flags_changed, 1);
        assert_eq!(inbox(&report).removed, 0);
        assert!(seen_of(&engine, 2), "read elsewhere, no longer bold here");
        let mut f = flags_of(&engine, 2);
        f.sort();
        assert_eq!(f, vec!["\\Flagged".to_string(), "\\Seen".to_string()]);

        let again = engine.sync(EMAIL).await.unwrap();
        assert_eq!(
            inbox(&again).flags_changed,
            0,
            "converged: nothing left to change"
        );
    }

    /// An emptied folder empties locally. This is the "Trash stays full" case.
    #[tokio::test]
    async fn an_emptied_folder_is_emptied_locally() {
        let (_dir, engine, state) = setup(3).await;
        engine.sync(EMAIL).await.unwrap();
        state.lock().unwrap().uids.clear();

        let report = engine.sync(EMAIL).await.unwrap();
        assert_eq!(stored(&engine), Vec::<u32>::new());
        assert_eq!(inbox(&report).removed, 3);
    }

    /// The dangerous failure mode: an empty `UID SEARCH` for a mailbox the server says holds
    /// three messages. Deletion is driven by the search, so this must be an error and must
    /// delete nothing.
    #[tokio::test]
    async fn an_empty_search_for_a_non_empty_mailbox_deletes_nothing() {
        let (_dir, engine, state) = setup(3).await;
        engine.sync(EMAIL).await.unwrap();
        state.lock().unwrap().blind_search = true;

        let err = engine.sync(EMAIL).await.expect_err("must not be silent");
        assert!(
            matches!(&err, crate::error::Error::Connection(m) if m.contains("refusing")),
            "{err:?}"
        );
        assert_eq!(
            stored(&engine),
            vec![1, 2, 3],
            "a broken answer is not a deletion"
        );
    }

    /// The other half of that separation: a flags fetch that answers for nothing at all costs
    /// a missed flag update and not a single message. Deletion never depends on it, so the
    /// worst a truncated or lying flags answer can do is leave the mail exactly as it was.
    #[tokio::test]
    async fn a_blind_flags_answer_loses_no_mail() {
        let (_dir, engine, state) = setup(3).await;
        engine.sync(EMAIL).await.unwrap();
        {
            let mut s = state.lock().unwrap();
            s.blind_flags = true;
            s.flags.insert(2, vec!["\\Seen".into()]); // a change it will not report
        }

        let report = engine
            .sync(EMAIL)
            .await
            .expect("no error: nothing is at risk");
        assert_eq!(stored(&engine), vec![1, 2, 3], "every message still here");
        assert_eq!(inbox(&report).removed, 0);
        assert_eq!(inbox(&report).flags_changed, 0, "the update was missed");
        assert!(!seen_of(&engine, 2), "and not invented either");

        // It is only missed, not lost: the next honest sync picks it up.
        state.lock().unwrap().blind_flags = false;
        let after = engine.sync(EMAIL).await.unwrap();
        assert_eq!(inbox(&after).flags_changed, 1);
        assert!(seen_of(&engine, 2));
    }

    /// `\Recent` is set for exactly one session per message, so the sync that first fetches a
    /// message sees it and no later `FETCH FLAGS` reports it. Counting that disappearance as a
    /// change would make every message look changed on every sync, for ever.
    ///
    /// The test drops `\Recent` from UID 1 and sets `\Seen` on UID 2 in the same step, so it
    /// cannot pass by reconciling nothing: exactly one of the two must be reported.
    #[tokio::test]
    async fn recent_is_session_state_and_never_counts_as_drift() {
        let (_dir, engine, state) = setup(2).await;
        state
            .lock()
            .unwrap()
            .flags
            .insert(1, vec!["\\Recent".into()]);
        engine.sync(EMAIL).await.unwrap();
        assert!(
            flags_of(&engine, 1)
                .iter()
                .any(|f| f.eq_ignore_ascii_case("\\Recent")),
            "the body fetch stored the session flag, which is what makes this a trap: {:?}",
            flags_of(&engine, 1)
        );

        {
            let mut s = state.lock().unwrap();
            s.flags.remove(&1); // the session ended: no server reports \Recent twice
            s.flags.insert(2, vec!["\\Seen".into()]); // and a real change, at the same time
        }
        let report = engine.sync(EMAIL).await.unwrap();

        assert_eq!(
            inbox(&report).flags_changed,
            1,
            "the real change on UID 2 counts and the vanished \\Recent on UID 1 does not"
        );
        assert!(seen_of(&engine, 2));
        assert_eq!(inbox(&report).removed, 0);
    }

    /// `reconcile_folder` on its own must not reconcile across a UIDVALIDITY change: every
    /// stored UID belongs to the old incarnation, so holding them up against the new one would
    /// delete the lot *and* leave `last_uid` / `floor_uid` pointing into the old numbering,
    /// where the mail would never be fetched back. A sync handles this before it reaches the
    /// reconcile; this entry point has to do it itself.
    #[tokio::test]
    async fn reconcile_folder_resyncs_instead_of_reconciling_across_a_uidvalidity_change() {
        let (_dir, engine, state) = setup(30).await;
        engine.sync(EMAIL).await.unwrap();
        assert_eq!(stored(&engine), (21..=30).collect::<Vec<_>>());
        state.lock().unwrap().uidvalidity = 8;

        let report = engine.reconcile_folder(EMAIL, "INBOX").await.unwrap();
        let f = inbox(&report);
        assert!(f.uidvalidity_reset, "reported as a resync, not as drift");
        assert_eq!(f.removed, 10, "the whole stored copy went, and it says so");
        assert_eq!(stored(&engine), Vec::<u32>::new());
        assert_eq!(
            marks(&engine),
            (0, 0),
            "the watermarks are cleared, so the next sync refetches"
        );

        // And the next sync does refetch, under the new UIDVALIDITY.
        let after = engine.sync(EMAIL).await.unwrap();
        assert_eq!(after.new, 10);
        assert_eq!(stored(&engine), (21..=30).collect::<Vec<_>>());
    }

    /// A backfill is about older mail and runs per folder; paying for the whole folder's flags
    /// each time would buy nothing, so that pass does not reconcile.
    #[tokio::test]
    async fn a_backfill_pass_does_not_reconcile() {
        let (_dir, engine, state) = setup(30).await;
        engine.sync(EMAIL).await.unwrap();
        let before = flag_fetches(&state).len();
        assert!(before > 0, "the sync itself reconciles");

        engine.backfill(EMAIL, Some(8)).await.unwrap();
        assert_eq!(flag_fetches(&state).len(), before, "backfill stayed quiet");
    }
}
