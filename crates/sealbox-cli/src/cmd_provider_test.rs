//! `sealbox provider-test --account A [--json]` — the G21 provider-conformance suite
//! (`docs/PROVIDERS_CONFORMANCE.md`). Runs the checks in order, prints PASS/FAIL/SKIP with
//! timings, and writes secret-free evidence JSON to `.gate/evidence/G21/<provider>-<date>.json`.
//! Exit code 1 when any check failed.

use std::cell::{Cell, RefCell};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use clap::Args;
use sealbox_core::providers::ProviderProfile;
use sealbox_core::sealbox_crypto::{minimal_public_key, AutocryptHeader, PublicKey};
use sealbox_core::sealbox_mail::imap::{
    FolderRole, IdleEvent, ImapClient, SpecialUseSource, AUTH_XOAUTH2,
};
use sealbox_core::sealbox_mail::mime::{parse, PROTECTED_SUBJECT_PLACEHOLDER};
use sealbox_core::sealbox_mail::net_policy;
use sealbox_core::{
    AttachmentData, AuthKind, Draft, Engine, FlagOp, ListQuery, MessageSummary, Security, SendMode,
    SendPolicy,
};

use crate::print_json;

#[derive(Args, Debug)]
pub struct ProviderTestArgs {
    /// The account to test (must already be added)
    #[arg(long)]
    pub account: String,
    /// Also probe the message size limit (sends growing messages until one is rejected)
    #[arg(long)]
    pub probe_size_limit: bool,
    /// Skip the large-attachment round trip
    #[arg(long)]
    pub skip_attachment: bool,
    /// Size of the large attachment in MiB
    #[arg(long, default_value_t = 5)]
    pub attachment_mib: u64,
    /// Seconds to wait for the self-sent message to arrive (via IDLE)
    #[arg(long, default_value_t = 60)]
    pub arrival_timeout: u64,
    /// Keep the test messages (default: moved to Trash at the end)
    #[arg(long)]
    pub keep: bool,
    /// Extra label in the evidence file name: <provider>-<label>-<date>.json
    #[arg(long)]
    pub label: Option<String>,
    /// Where evidence JSON goes (default: $SEALBOX_EVIDENCE_DIR, else .gate/evidence/G21
    /// when run inside the repo, else <profile>/evidence)
    #[arg(long)]
    pub evidence_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum Status {
    Pass,
    Fail,
    Skip,
}

#[derive(Clone, Debug, serde::Serialize)]
struct Check {
    name: &'static str,
    status: Status,
    ms: u128,
    detail: String,
}

/// What a check step reports back.
enum Outcome {
    Pass(String),
    Skip(String),
}

struct Suite {
    checks: Vec<Check>,
    json: bool,
}

impl Suite {
    fn record(&mut self, name: &'static str, status: Status, started: Instant, detail: String) {
        let ms = started.elapsed().as_millis();
        if !self.json {
            let tag = match status {
                Status::Pass => "PASS",
                Status::Fail => "FAIL",
                Status::Skip => "SKIP",
            };
            println!("{tag:<4} {ms:>7} ms  {name:<28} {detail}");
            let _ = std::io::stdout().flush();
        }
        self.checks.push(Check {
            name,
            status,
            ms,
            detail,
        });
    }

    fn finish(&mut self, name: &'static str, started: Instant, r: anyhow::Result<Outcome>) {
        match r {
            Ok(Outcome::Pass(d)) => self.record(name, Status::Pass, started, d),
            Ok(Outcome::Skip(d)) => self.record(name, Status::Skip, started, d),
            Err(e) => self.record(name, Status::Fail, started, format!("{e:#}")),
        }
    }

    fn skip(&mut self, name: &'static str, why: &str) {
        self.record(name, Status::Skip, Instant::now(), why.to_string());
    }

    fn failed(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .count()
    }
}

fn nonce(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{tag}-{nanos}-{}", std::process::id())
}

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed ^ 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// `YYYY-MM-DD` (UTC) without pulling chrono into the CLI.
fn today_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn security_name(s: Security) -> &'static str {
    match s {
        Security::Tls => "tls",
        Security::StartTls => "starttls",
        Security::Plain => "plain",
    }
}

/// The stored row for the message we sent as `mid`, which the server holds at `uid` (when
/// known). The store keys a message on the `Message-ID` it arrived with, and Outlook.com
/// replaces ours on submission (keeping it in `X-Microsoft-Original-Message-ID`), so a row
/// whose Message-ID differs is still ours when it is the server's `uid` in this folder — the
/// UID the search by either header found.
fn find_by_mid(rows: &[MessageSummary], mid: &str, uid: Option<u32>) -> Option<MessageSummary> {
    rows.iter()
        .find(|m| m.message_id.as_deref() == Some(mid))
        .or_else(|| uid.and_then(|uid| rows.iter().find(|m| m.uid == uid)))
        .cloned()
}

async fn list_folder(
    engine: &Engine,
    email: &str,
    folder: &str,
) -> anyhow::Result<Vec<MessageSummary>> {
    Ok(engine.list_messages(ListQuery {
        account: Some(email.to_string()),
        folder: Some(folder.to_string()),
        folder_role: None,
        limit: 500,
    })?)
}

/// Sync `folder` (INBOX through the normal sync, anything else as the Junk folder, the only
/// other place a self-sent message lands), then find the stored row for `mid` / `uid` in it.
async fn sync_and_find_in(
    engine: &Engine,
    email: &str,
    folder: &str,
    mid: &str,
    uid: Option<u32>,
) -> anyhow::Result<Option<MessageSummary>> {
    if folder.eq_ignore_ascii_case("INBOX") {
        engine.sync(email).await?;
    } else {
        engine.sync_folder_role(email, FolderRole::Junk).await?;
    }
    Ok(find_by_mid(
        &list_folder(engine, email, folder).await?,
        mid,
        uid,
    ))
}

/// Where a self-sent message may land: INBOX, then the Junk folder when there is one.
fn arrival_folders(junk: Option<&str>) -> Vec<String> {
    let mut v = vec!["INBOX".to_string()];
    if let Some(j) = junk.filter(|j| !j.eq_ignore_ascii_case("INBOX")) {
        v.push(j.to_string());
    }
    v
}

/// The first of `folders` holding `mid` (by `Message-ID` or the provider's
/// original-Message-ID header), with its UID. Each folder is SELECTed afresh (a new SELECT
/// shows new mail on every server); the last one searched stays selected.
async fn find_mid_in(
    client: &mut ImapClient,
    folders: &[String],
    mid: &str,
) -> anyhow::Result<Option<(String, u32)>> {
    for f in folders {
        client.select(f).await?;
        if let Some(uid) = client.search_message_id(mid).await?.first() {
            return Ok(Some((f.clone(), *uid)));
        }
    }
    Ok(None)
}

/// Poll `folders` until one holds `mid` (re-SELECT + UID SEARCH every 2 s).
async fn poll_for_mid_in(
    client: &mut ImapClient,
    folders: &[String],
    mid: &str,
    timeout: Duration,
) -> anyhow::Result<Option<(String, u32)>> {
    let started = Instant::now();
    loop {
        if let Some(hit) = find_mid_in(client, folders, mid).await? {
            return Ok(Some(hit));
        }
        if started.elapsed() >= timeout {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// The detail for where a message landed: `folder=INBOX`, or the Junk folder made visible.
fn landed_in(folder: &str) -> String {
    if folder.eq_ignore_ascii_case("INBOX") {
        "folder=INBOX".to_string()
    } else {
        format!("folder={folder} (landed in Junk, not INBOX)")
    }
}

/// Poll a raw session until `mid` is in the selected mailbox (NOOP + UID SEARCH).
async fn poll_for_mid(
    client: &mut ImapClient,
    mid: &str,
    timeout: Duration,
) -> anyhow::Result<Option<u32>> {
    let started = Instant::now();
    loop {
        client.noop().await?;
        if let Some(uid) = client.search_message_id(mid).await?.first() {
            return Ok(Some(*uid));
        }
        if started.elapsed() >= timeout {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(700)).await;
    }
}

fn evidence_dir(profile: &Path, args: &ProviderTestArgs) -> PathBuf {
    if let Some(d) = &args.evidence_dir {
        return d.clone();
    }
    if let Some(d) = std::env::var_os("SEALBOX_EVIDENCE_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(d);
    }
    if Path::new(".gate").is_dir() {
        return PathBuf::from(".gate/evidence/G21");
    }
    profile.join("evidence")
}

pub async fn run(profile: &Path, json: bool, args: ProviderTestArgs) -> anyhow::Result<()> {
    let engine = Engine::open(profile)?;
    let email = args.account.trim().to_string();
    let info = engine.account(&email)?;
    // The *stated* provider first (`sealbox account set-provider`), falling back to the host
    // guess. Without this a simulator or a company M365 domain is tested against the wrong
    // profile — a fake on 127.0.0.1 reads as Greenmail, which is why the suite could not be
    // pointed at one at all.
    let profile_: &'static ProviderProfile = engine.provider_profile(&email)?;
    let run_started = Instant::now();
    let tag = nonce("sbx");
    let mut s = Suite {
        checks: Vec::new(),
        json,
    };
    if !json {
        println!(
            "Sealbox provider conformance — {} ({} · imap {}:{} {} · smtp {}:{} {} · auth {:?})",
            email,
            profile_.display_name,
            info.imap.host,
            info.imap.port,
            security_name(info.imap.security),
            info.smtp.host,
            info.smtp.port,
            security_name(info.smtp.security),
            info.auth_kind
        );
    }

    // ---- 1. connect IMAP (TLS verify) ------------------------------------------------
    let t = Instant::now();
    let mut client: Option<ImapClient> = None;
    s.finish(
        "connect_imap",
        t,
        async {
            match engine.imap_session(&email).await {
                Ok(c) => {
                    let tls = match info.imap.security {
                        Security::Tls => {
                            "implicit TLS, certificate verified (webpki roots)".to_string()
                        }
                        Security::StartTls => {
                            "STARTTLS, certificate verified (webpki roots)".to_string()
                        }
                        // Only reachable for hosts the transport policy accepts (R12).
                        Security::Plain => format!(
                            "PLAIN TCP (allowed: {})",
                            net_policy::plain_allowance(&info.imap.host)
                                .map(|a| a.describe())
                                .unwrap_or("?")
                        ),
                    };
                    let d = format!(
                        "{}:{} {} ; auth={}",
                        info.imap.host,
                        info.imap.port,
                        tls,
                        c.auth_mechanism()
                    );
                    client = Some(c);
                    Ok(Outcome::Pass(d))
                }
                Err(e) => Err(anyhow!(e)),
            }
        }
        .await,
    );
    let Some(mut client) = client else {
        return finish(profile, &args, &engine, &info, profile_, s, run_started).await;
    };

    // ---- 2. capabilities --------------------------------------------------------------
    let t = Instant::now();
    let caps = client.capabilities().to_vec();
    let notable: Vec<&str> = [
        "IDLE",
        "MOVE",
        "UIDPLUS",
        "SPECIAL-USE",
        "CONDSTORE",
        "QRESYNC",
    ]
    .into_iter()
    .filter(|c| client.has_capability(c))
    .collect();
    s.finish(
        "capabilities",
        t,
        Ok(Outcome::Pass(format!(
            "{} advertised; notable: {}; pre-auth: {}",
            caps.len(),
            if notable.is_empty() {
                "-".to_string()
            } else {
                notable.join(" ")
            },
            client.preauth_capabilities().join(" ")
        ))),
    );

    // ---- 3. auth method used ----------------------------------------------------------
    // An OAuth account authenticates with XOAUTH2 or not at all: the engine never sends the
    // token as a LOGIN password (a server without AUTH=XOAUTH2 already failed connect_imap
    // with "does not offer OAuth sign-in"), and the token only goes to the provider's hosts.
    let t = Instant::now();
    let imap_mech = client.auth_mechanism();
    s.finish("auth_method", t, async {
        let mut d = format!("imap={imap_mech}");
        match info.auth_kind {
            AuthKind::OAuth => {
                let st = engine.oauth_status(&email)?;
                match &st {
                    Some(st) => {
                        d.push_str(&format!(
                            "; oauth provider={} expires_in={}s refresh_token={} refreshes_so_far={} endpoints_overridden={}",
                            st.provider,
                            st.expires_in_secs.unwrap_or(-1),
                            st.has_refresh_token,
                            st.refresh_count,
                            st.endpoints_overridden
                        ));
                        d.push_str(&format!(
                            "; token pinned to {}{}",
                            net_policy::mail_domains(st.provider).join(" "),
                            if st.dev_hosts_allowed {
                                " + local/private hosts (loopback test IdP)"
                            } else {
                                ""
                            }
                        ));
                    }
                    None => d.push_str("; oauth account without token record (legacy)"),
                }
                if imap_mech != AUTH_XOAUTH2 {
                    Err(anyhow!(
                        "{d}: an OAuth account must authenticate with XOAUTH2 on IMAP, but the \
                         session used `{imap_mech}`"
                    ))
                } else {
                    Ok(Outcome::Pass(d))
                }
            }
            AuthKind::Password => Ok(Outcome::Pass(format!("{d}; password/app-password account"))),
        }
    }.await);

    // ---- 4. list folders + special-use mapping -----------------------------------------
    let t = Instant::now();
    let mut created: Vec<String> = Vec::new();
    let mut junk_folder: Option<String> = None;
    s.finish(
        "special_use_folders",
        t,
        async {
            let su = client.list_special_use().await?;
            let mut missing = Vec::new();
            for role in [
                FolderRole::Sent,
                FolderRole::Trash,
                FolderRole::Junk,
                FolderRole::Drafts,
            ] {
                if su.get(role).is_none() {
                    let want = profile_.folder(role);
                    if client.ensure_folder(&want).await? {
                        created.push(want.clone());
                    } else {
                        missing.push(format!("{role}"));
                    }
                }
            }
            let su = client.list_special_use().await?;
            junk_folder = su.junk.clone();
            let mapped: Vec<String> = su
                .mapped()
                .iter()
                .map(|(r, n)| format!("{r}={n}"))
                .collect();
            let d = format!(
                "source={:?} ; {}{}",
                su.source,
                mapped.join(" "),
                if created.is_empty() {
                    String::new()
                } else {
                    format!(" ; created on first use: {}", created.join(", "))
                }
            );
            if su.sent.is_none() || su.trash.is_none() || su.junk.is_none() {
                Err(anyhow!("{d} ; unresolved roles: {}", missing.join(", ")))
            } else {
                if su.source == SpecialUseSource::None {
                    tracing::warn!("no special-use mapping at all");
                }
                Ok(Outcome::Pass(d))
            }
        }
        .await,
    );

    // ---- 5. SELECT INBOX --------------------------------------------------------------
    let t = Instant::now();
    let mut server_uidvalidity = 0u32;
    s.finish(
        "select_inbox",
        t,
        async {
            let mb = client.select("INBOX").await?;
            server_uidvalidity = mb.uidvalidity;
            if mb.uidvalidity == 0 {
                Err(anyhow!("server reported no UIDVALIDITY"))
            } else {
                Ok(Outcome::Pass(format!(
                    "exists={} uidnext={} uidvalidity={} unseen={:?}",
                    mb.exists, mb.uidnext, mb.uidvalidity, mb.unseen
                )))
            }
        }
        .await,
    );

    // ---- 6. UIDVALIDITY handling ------------------------------------------------------
    let t = Instant::now();
    s.finish("uidvalidity_handling", t, async {
        let before = engine.folder_sync_state(&email, "INBOX")?;
        let report = engine.sync(&email).await?;
        let after = engine
            .folder_sync_state(&email, "INBOX")?
            .ok_or_else(|| anyhow!("no INBOX sync state after sync"))?;
        if after.uidvalidity != server_uidvalidity {
            Err(anyhow!(
                "stored uidvalidity {} != server {}",
                after.uidvalidity,
                server_uidvalidity
            ))
        } else {
            Ok(Outcome::Pass(format!(
                "stored uidvalidity={} last_uid={} (was {:?}); sync: {} new, {} decrypted, resets={}",
                after.uidvalidity,
                after.last_uid,
                before.map(|b| (b.uidvalidity, b.last_uid)),
                report.new,
                report.decrypted,
                report
                    .folders
                    .iter()
                    .filter(|f| f.uidvalidity_reset)
                    .count()
            )))
        }
    }.await);

    // ---- 7 + 8. send encrypted to self, watch it arrive via IDLE ----------------------
    let subject = format!("Sealbox conformance {tag}");
    let body = format!("Encrypted conformance message {tag}\nSecond line.\n");
    let t_send = Instant::now();
    // The send's Message-ID and the moment the send returned it: the arrival window starts
    // there, not with the send (an Outlook.com submission plus its Sent-copy check has taken
    // 61 s, longer than the whole default window).
    let mid_slot: RefCell<Option<(String, Instant)>> = RefCell::new(None);
    let send_done = Cell::new(false);
    let arrival_timeout = Duration::from_secs(args.arrival_timeout.max(5));
    let folders = arrival_folders(junk_folder.as_deref());
    let send_fut = async {
        let r = engine
            .send(
                &email,
                Draft {
                    to: vec![email.clone()],
                    subject: subject.clone(),
                    text: body.clone(),
                    policy: SendPolicy::RequireEncryption,
                    ..Draft::default()
                },
            )
            .await;
        if let Ok(rep) = &r {
            *mid_slot.borrow_mut() = Some((rep.message_id.clone(), Instant::now()));
        }
        send_done.set(true);
        r
    };
    let wait_fut = async {
        let mut wakes = 0u32;
        loop {
            client.noop().await?;
            let known = mid_slot.borrow().clone();
            let slice = match known {
                Some((mid, sent_at)) => {
                    if let Some((folder, uid)) = find_mid_in(&mut client, &folders, &mid).await? {
                        return Ok::<_, anyhow::Error>((folder, uid, wakes, sent_at.elapsed()));
                    }
                    arrival_timeout
                        .checked_sub(sent_at.elapsed())
                        .filter(|r| !r.is_zero())
                        .ok_or_else(|| {
                            anyhow!(
                                "message did not arrive in {} within {arrival_timeout:?} of the \
                                 send returning",
                                folders.join(" or ")
                            )
                        })?
                        .min(Duration::from_secs(10))
                }
                None if send_done.get() => return Err(anyhow!("send failed; nothing to wait for")),
                // Still sending: look again soon after the send returns.
                None => Duration::from_secs(2),
            };
            if client.selected().map(|m| m.name.as_str()) != Some("INBOX") {
                client.select("INBOX").await?;
            }
            if client.has_capability("IDLE") {
                if client.idle_wait_gapless(slice).await? == IdleEvent::NewData {
                    wakes += 1;
                }
            } else {
                tokio::time::sleep(slice.min(Duration::from_secs(2))).await;
            }
        }
    };
    let (send_res, wait_res) = tokio::join!(send_fut, wait_fut);
    let mut send_report = None;
    s.finish(
        "send_encrypted_to_self",
        t_send,
        async {
            match send_res {
                Ok(rep) if rep.mode == SendMode::Encrypted => {
                    let d = format!(
                        "message_id=<{}> sent_copy_appended={} sent_folder={:?}",
                        rep.message_id, rep.sent_copy_appended, rep.sent_folder
                    );
                    send_report = Some(rep);
                    Ok(Outcome::Pass(d))
                }
                Ok(rep) => Err(anyhow!("sent in mode {:?}, expected encrypted", rep.mode)),
                Err(e) => Err(anyhow!(e)),
            }
        }
        .await,
    );
    let t = Instant::now();
    // Where the self-sent message is on the server: (folder, uid).
    let mut arrived: Option<(String, u32)> = None;
    s.finish(
        "arrival_via_idle",
        t,
        async {
            match wait_res {
                Ok((folder, uid, wakes, took)) => {
                    let d = format!(
                        "uid={uid} {} after {} ms of the send returning; IDLE wake-ups={wakes}{}",
                        landed_in(&folder),
                        took.as_millis(),
                        if wakes == 0 && client.has_capability("IDLE") {
                            " (arrived before IDLE started)"
                        } else {
                            ""
                        }
                    );
                    arrived = Some((folder, uid));
                    Ok(Outcome::Pass(d))
                }
                Err(e) => Err(e),
            }
        }
        .await,
    );

    // ---- 9. decrypt it ----------------------------------------------------------------
    let t = Instant::now();
    let mut stored: Option<MessageSummary> = None;
    s.finish(
        "decrypt_received",
        t,
        async {
            match &send_report {
                None => Ok(Outcome::Skip("send failed".into())),
                Some(rep) => {
                    let (folder, uid) = match &arrived {
                        Some((f, u)) => (f.clone(), Some(*u)),
                        None => ("INBOX".to_string(), None),
                    };
                    let m = sync_and_find_in(&engine, &email, &folder, &rep.message_id, uid)
                        .await?
                        .ok_or_else(|| {
                            anyhow!("message not in the local store after syncing {folder}")
                        })?;
                    let detail = engine.get_message(m.id)?;
                    if !(m.was_encrypted && m.decrypted) {
                        Err(anyhow!(
                            "stored message not decrypted: encrypted={} decrypted={} error={:?}",
                            m.was_encrypted,
                            m.decrypted,
                            m.decrypt_error
                        ))
                    } else if detail
                        .text
                        .as_deref()
                        .map(|t| t.replace("\r\n", "\n"))
                        .as_deref()
                        != Some(body.as_str())
                    {
                        Err(anyhow!("decrypted body differs"))
                    } else {
                        let d = format!(
                            "id={} {} signature={:?} subject_protected={}",
                            m.id,
                            landed_in(&folder),
                            m.signature.status,
                            m.protected_subject
                        );
                        stored = Some(m);
                        Ok(Outcome::Pass(d))
                    }
                }
            }
        }
        .await,
    );

    // ---- 10. Sent-copy policy: exactly one copy ---------------------------------------
    let t = Instant::now();
    s.finish(
        "sent_copy_single",
        t,
        async {
            match &send_report {
                None => Ok(Outcome::Skip("send failed".into())),
                Some(rep) => {
                    let folder = match &rep.sent_folder {
                        Some(f) => f.clone(),
                        None => engine.special_folder(&email, FolderRole::Sent)?,
                    };
                    client.select(&folder).await?;
                    // Provider-stored copies may lag a little.
                    let mut copies = client.search_message_id(&rep.message_id).await?.len();
                    let started = Instant::now();
                    while copies == 0 && started.elapsed() < Duration::from_secs(15) {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        client.noop().await?;
                        copies = client.search_message_id(&rep.message_id).await?.len();
                    }
                    let policy = if profile_.smtp_saves_sent {
                        "provider saves on submit (no APPEND)"
                    } else {
                        "client APPENDs"
                    };
                    if copies == 1 {
                        Ok(Outcome::Pass(format!(
                            "folder={folder} copies=1 appended_by_us={} policy: {policy}",
                            rep.sent_copy_appended
                        )))
                    } else {
                        Err(anyhow!(
                            "folder={folder} copies={copies} appended_by_us={} policy: {policy}",
                            rep.sent_copy_appended
                        ))
                    }
                }
            }
        }
        .await,
    );

    // ---- 11. flags set / unset ----------------------------------------------------------
    let t = Instant::now();
    s.finish(
        "flags_set_unset",
        t,
        async {
            match (&stored, &arrived) {
                (Some(m), Some((folder, uid))) => {
                    let uid = *uid;
                    engine
                        .set_flags(m.id, FlagOp::Add, &["\\Flagged".to_string()])
                        .await?;
                    client.select(folder).await?;
                    let f = client.fetch_flags(&[uid]).await?;
                    let has = |f: &[(u32, Vec<String>)]| {
                        f.iter()
                            .any(|(u, fl)| *u == uid && fl.iter().any(|x| x == "\\Flagged"))
                    };
                    if !has(&f) {
                        return_err("\\Flagged not visible on the server after set")?;
                    }
                    engine
                        .set_flags(m.id, FlagOp::Remove, &["\\Flagged".to_string()])
                        .await?;
                    let f = client.fetch_flags(&[uid]).await?;
                    if has(&f) {
                        return_err("\\Flagged still present after remove")?;
                    }
                    Ok(Outcome::Pass(
                        "\\Flagged set and cleared, verified on the server".into(),
                    ))
                }
                _ => Ok(Outcome::Skip("no stored message".into())),
            }
        }
        .await,
    );

    // ---- 12. move to Trash and back ------------------------------------------------------
    let t = Instant::now();
    s.finish(
        "move_to_trash_and_back",
        t,
        async {
            match (&stored, &send_report, arrived.clone()) {
                (Some(m), Some(rep), Some((from, _))) => {
                    let mv = engine.move_message(m.id, FolderRole::Trash).await?;
                    client.select(&mv.to_folder).await?;
                    let in_trash =
                        poll_for_mid(&mut client, &rep.message_id, Duration::from_secs(10))
                            .await?
                            .ok_or_else(|| anyhow!("not found in {} after move", mv.to_folder))?;
                    client.select(&from).await?;
                    if !client.search_message_id(&rep.message_id).await?.is_empty() {
                        return_err(&format!("still present in {from} after the move"))?;
                    }
                    client.select(&mv.to_folder).await?;
                    let back = client.r#move(&[in_trash], "INBOX").await?;
                    client.select("INBOX").await?;
                    let uid = poll_for_mid(&mut client, &rep.message_id, Duration::from_secs(10))
                        .await?
                        .ok_or_else(|| anyhow!("not back in INBOX"))?;
                    arrived = Some(("INBOX".to_string(), uid));
                    // Re-sync so the local store has the message again (new UID).
                    stored = sync_and_find_in(&engine, &email, "INBOX", &rep.message_id, Some(uid))
                        .await?;
                    if stored.is_none() {
                        return_err("message not re-synced into the store after moving back")?;
                    }
                    Ok(Outcome::Pass(format!(
                        "from {from} to {} via {:?}, back to INBOX via {:?}; new uid={uid}",
                        mv.to_folder, mv.method, back
                    )))
                }
                _ => Ok(Outcome::Skip("no stored message".into())),
            }
        }
        .await,
    );

    // ---- 13. spam folder detection --------------------------------------------------------
    let t = Instant::now();
    s.finish(
        "spam_folder_detection",
        t,
        async {
            let su = client.list_special_use().await?;
            let learned = engine.special_folder(&email, FolderRole::Junk)?;
            match su.junk {
                Some(j) => {
                    let st = client.status(&j).await?;
                    Ok(Outcome::Pass(format!(
                        "junk={j} (engine says {learned}) messages={} source={:?}",
                        st.messages, su.source
                    )))
                }
                None => Err(anyhow!(
                    "no Junk/Spam folder found (engine default {learned})"
                )),
            }
        }
        .await,
    );

    // ---- 14. large attachment round trip --------------------------------------------------
    let t = Instant::now();
    let mut attachment_msg: Option<MessageSummary> = None;
    if args.skip_attachment {
        s.skip("large_attachment_roundtrip", "--skip-attachment");
    } else {
        s.finish(
            "large_attachment_roundtrip",
            t,
            async {
                let size = (args.attachment_mib.max(1) * 1024 * 1024) as usize;
                let data = pseudo_random(size, 0xA77A_C4ED);
                let rep = engine
                    .send(
                        &email,
                        Draft {
                            to: vec![email.clone()],
                            subject: format!("Sealbox conformance attachment {tag}"),
                            text: "large attachment\n".into(),
                            attachments: vec![AttachmentData {
                                filename: "blob.bin".into(),
                                content_type: "application/octet-stream".into(),
                                data: data.clone(),
                            }],
                            policy: SendPolicy::RequireEncryption,
                            ..Draft::default()
                        },
                    )
                    .await?;
                let (folder, uid) = poll_for_mid_in(
                    &mut client,
                    &folders,
                    &rep.message_id,
                    Duration::from_secs(180),
                )
                .await?
                .ok_or_else(|| {
                    anyhow!(
                        "attachment message did not arrive in {} within 180 s",
                        folders.join(" or ")
                    )
                })?;
                let m = sync_and_find_in(&engine, &email, &folder, &rep.message_id, Some(uid))
                    .await?
                    .ok_or_else(|| anyhow!("attachment message not in store ({folder})"))?;
                if !(m.was_encrypted && m.decrypted) {
                    return_err("attachment message not decrypted")?;
                }
                let (info_a, bytes) = engine.get_attachment(m.id, 0)?;
                if bytes != data {
                    return_err(&format!(
                        "attachment bytes differ ({} vs {} bytes)",
                        bytes.len(),
                        data.len()
                    ))?;
                }
                let d = format!(
                    "{} MiB {} round-tripped byte-exact in {} ms (raw size {}; {})",
                    args.attachment_mib,
                    info_a.filename,
                    t.elapsed().as_millis(),
                    m.raw_size,
                    landed_in(&folder)
                );
                attachment_msg = Some(m);
                Ok(Outcome::Pass(d))
            }
            .await,
        );
    }

    // ---- 15. connection limit: 3 concurrent sessions ------------------------------------------
    let t = Instant::now();
    s.finish(
        "connection_limit_3",
        t,
        async {
            let (a, b, c) = tokio::join!(
                engine.imap_session(&email),
                engine.imap_session(&email),
                engine.imap_session(&email)
            );
            let results = [a, b, c];
            let ok = results.iter().filter(|r| r.is_ok()).count();
            let errs: Vec<String> = results
                .iter()
                .filter_map(|r| r.as_ref().err().map(|e| e.to_string()))
                .collect();
            for c in results.into_iter().flatten() {
                let _ = c.logout().await;
            }
            // This suite is already holding one session, so the most the provider's own budget
            // leaves for extras is `cap - 1`. Demanding `cap` of them cannot be satisfied on a
            // single-session provider (Yahoo, iCloud) however well the engine behaves, which
            // would have failed the check for a reason that is not about the engine.
            let need = usize::from(profile_.max_connections.saturating_sub(1).min(3));
            let d = format!(
                "{ok}/3 extra sessions opened concurrently (profile cap {}, one already held; {} needed){}",
                profile_.max_connections,
                need,
                if errs.is_empty() {
                    String::new()
                } else {
                    format!("; errors: {}", errs.join(" | "))
                }
            );
            if ok >= need {
                Ok(Outcome::Pass(d))
            } else {
                Err(anyhow!(d))
            }
        }
        .await,
    );

    // ---- 16 + 17. raw fetch: Autocrypt header and protected Subject preserved -------------
    let mut raw_msg: Option<Vec<u8>> = None;
    if let Some((folder, uid)) = &arrived {
        let uid = *uid;
        if client.select(folder).await.is_ok() {
            raw_msg = client.fetch_rfc822(uid).await.ok();
        }
    }
    let t = Instant::now();
    s.finish("autocrypt_header_preserved", t, async {
        match &raw_msg {
            None => Ok(Outcome::Skip("no raw message".into())),
            Some(raw) => {
                let parsed = parse(raw)?;
                let value = parsed
                    .headers
                    .autocrypt
                    .first()
                    .ok_or_else(|| anyhow!("no Autocrypt header in the delivered message"))?;
                let header = AutocryptHeader::parse(value)
                    .map_err(|e| anyhow!("Autocrypt header unparseable after delivery: {e}"))?;
                let fp = engine.my_fingerprint(&email)?;
                let key_fp = header
                    .public_key()
                    .map_err(|e| anyhow!("keydata unusable: {e}"))?
                    .fingerprint();
                let expected = minimal_public_key(
                    &PublicKey::from_armored(&engine.export_public_key(&email)?)?,
                    Some(&email),
                )?
                .to_bytes()?;
                if !header.addr.eq_ignore_ascii_case(&email) {
                    Err(anyhow!("addr={} != {email}", header.addr))
                } else if key_fp != fp {
                    Err(anyhow!("keydata fingerprint {key_fp} != ours {fp}"))
                } else if header.keydata != expected {
                    Err(anyhow!(
                        "keydata bytes changed in transit ({} vs {} bytes)",
                        header.keydata.len(),
                        expected.len()
                    ))
                } else {
                    Ok(Outcome::Pass(format!(
                        "addr ok, keydata byte-exact ({} bytes), fingerprint {fp}, prefer-encrypt={}",
                        header.keydata.len(),
                        format!("{:?}", header.prefer_encrypt).to_lowercase()
                    )))
                }
            }
        }
    }.await);
    let t = Instant::now();
    s.finish(
        "protected_subject_preserved",
        t,
        async {
            match (&raw_msg, &stored) {
                (Some(raw), Some(m)) => {
                    let outer = parse(raw)?.headers.subject;
                    if outer.as_deref() != Some(PROTECTED_SUBJECT_PLACEHOLDER) {
                        Err(anyhow!(
                        "outer Subject is {outer:?}, expected {PROTECTED_SUBJECT_PLACEHOLDER:?}"
                    ))
                    } else if m.subject.as_deref() != Some(subject.as_str()) || !m.protected_subject
                    {
                        Err(anyhow!(
                            "decrypted subject {:?} (protected={}) != {subject:?}",
                            m.subject,
                            m.protected_subject
                        ))
                    } else {
                        Ok(Outcome::Pass(format!(
                        "outer Subject `{PROTECTED_SUBJECT_PLACEHOLDER}`, inner subject restored"
                    )))
                    }
                }
                _ => Ok(Outcome::Skip("no raw/stored message".into())),
            }
        }
        .await,
    );

    // ---- 18. message size limit probe (opt-in) ------------------------------------------
    if !args.probe_size_limit {
        s.skip(
            "message_size_limit_probe",
            "skipped by default (--probe-size-limit)",
        );
    } else {
        let t = Instant::now();
        s.finish(
            "message_size_limit_probe",
            t,
            async {
                let mut accepted = 0u64;
                let mut rejected: Option<(u64, String)> = None;
                for mib in [8u64, 16, 24, 32] {
                    let data = pseudo_random((mib * 1024 * 1024) as usize, mib);
                    let r = engine
                        .send(
                            &email,
                            Draft {
                                to: vec![email.clone()],
                                subject: format!("Sealbox size probe {mib} MiB {tag}"),
                                text: "size probe\n".into(),
                                attachments: vec![AttachmentData {
                                    filename: format!("probe-{mib}.bin"),
                                    content_type: "application/octet-stream".into(),
                                    data,
                                }],
                                policy: SendPolicy::RequireEncryption,
                                ..Draft::default()
                            },
                        )
                        .await;
                    match r {
                        Ok(_) => accepted = mib,
                        Err(e) => {
                            rejected = Some((mib, e.to_string()));
                            break;
                        }
                    }
                }
                Ok(Outcome::Pass(format!(
                    "largest accepted attachment {accepted} MiB{}; documented limit {:?} bytes",
                    match rejected {
                        Some((m, e)) => format!(", {m} MiB rejected: {e}"),
                        None => String::new(),
                    },
                    profile_.max_message_bytes
                )))
            }
            .await,
        );
    }

    // ---- cleanup + 19. clean logout -------------------------------------------------------------
    if !args.keep {
        if let Some(m) = &stored {
            if let Err(e) = engine.delete_message(m.id).await {
                tracing::warn!("cleanup: {e}");
            }
        }
        if let Some(m) = &attachment_msg {
            if let Err(e) = engine.delete_message(m.id).await {
                tracing::warn!("cleanup: {e}");
            }
        }
    }
    let t = Instant::now();
    s.finish(
        "clean_logout",
        t,
        async {
            client
                .logout()
                .await
                .map(|_| Outcome::Pass("LOGOUT acknowledged".into()))
                .map_err(|e| anyhow!(e))
        }
        .await,
    );

    finish(profile, &args, &engine, &info, profile_, s, run_started).await
}

fn return_err(msg: &str) -> anyhow::Result<()> {
    Err(anyhow!("{msg}"))
}

async fn finish(
    profile: &Path,
    args: &ProviderTestArgs,
    engine: &Engine,
    info: &sealbox_core::AccountInfo,
    profile_: &'static ProviderProfile,
    s: Suite,
    run_started: Instant,
) -> anyhow::Result<()> {
    let failed = s.failed();
    let passed = s.checks.iter().filter(|c| c.status == Status::Pass).count();
    let skipped = s.checks.iter().filter(|c| c.status == Status::Skip).count();
    let date = today_utc();
    let oauth = engine.oauth_status(&info.email).ok().flatten();
    let evidence = serde_json::json!({
        "suite": "G21 provider conformance",
        "sealbox_version": env!("CARGO_PKG_VERSION"),
        "date": date,
        "run_at": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        "provider": profile_.id.as_str(),
        "provider_display_name": profile_.display_name,
        "account": info.email,
        "auth_kind": info.auth_kind,
        "login": info.login,
        "imap": {"host": info.imap.host, "port": info.imap.port, "security": security_name(info.imap.security)},
        "smtp": {"host": info.smtp.host, "port": info.smtp.port, "security": security_name(info.smtp.security)},
        "oauth": oauth.map(|o| serde_json::json!({
            "provider": o.provider, "expires_in_secs": o.expires_in_secs,
            "has_refresh_token": o.has_refresh_token, "refresh_count": o.refresh_count,
            "endpoints_overridden": o.endpoints_overridden,
        })),
        "profile": profile_,
        "checks": s.checks,
        "summary": {"pass": passed, "fail": failed, "skip": skipped, "total_ms": run_started.elapsed().as_millis()},
        "result": if failed == 0 { "PASS" } else { "FAIL" },
    });
    let dir = evidence_dir(profile, args);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let file = dir.join(format!(
        "{}{}-{date}.json",
        profile_.id.as_str(),
        args.label
            .as_deref()
            .map(|l| format!("-{l}"))
            .unwrap_or_default()
    ));
    std::fs::write(&file, serde_json::to_vec_pretty(&evidence)?)
        .with_context(|| format!("writing {}", file.display()))?;
    if s.json {
        let mut doc = evidence;
        doc["evidence_file"] = serde_json::Value::String(file.display().to_string());
        print_json(&doc)?;
    } else {
        println!(
            "\n{}: {passed} passed, {failed} failed, {skipped} skipped in {} ms — evidence {}",
            if failed == 0 { "PASS" } else { "FAIL" },
            run_started.elapsed().as_millis(),
            file.display()
        );
    }
    let _ = std::io::stdout().flush();
    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: i64, uid: u32, message_id: Option<&str>) -> MessageSummary {
        serde_json::from_value(serde_json::json!({
            "id": id, "account": "a@x", "folder": "INBOX", "uid": uid,
            "message_id": message_id, "from": {"address": "a@x"}, "to": [],
            "received_at": 0, "flags": [], "seen": false, "was_encrypted": true,
            "decrypted": true, "was_signed": false, "signature": {"status": "none"},
            "protected_subject": false, "attachment_count": 0, "raw_size": 0,
        }))
        .expect("a summary")
    }

    /// Outlook.com rewrites our Message-ID: the stored row carries the provider's, and is
    /// found by the UID the server search (by either header) returned.
    #[test]
    fn a_rewritten_message_id_is_found_by_its_server_uid() {
        let rows = [
            row(1, 10, Some("other@x")),
            row(2, 11, Some("RewrittenByExchange@outlook.com")),
        ];
        let ours = "18e8cdb7.a244@outlook.com";
        assert_eq!(find_by_mid(&rows, ours, Some(11)).map(|m| m.id), Some(2));
        assert_eq!(find_by_mid(&rows, ours, None).map(|m| m.id), None);
        assert_eq!(find_by_mid(&rows, ours, Some(99)).map(|m| m.id), None);
        // An exact Message-ID match wins over the UID (Gmail, GreenMail keep ours).
        assert_eq!(
            find_by_mid(&rows, "other@x", Some(11)).map(|m| m.id),
            Some(1)
        );
    }

    #[test]
    fn arrival_is_watched_in_inbox_then_junk_and_junk_is_visible() {
        assert_eq!(arrival_folders(None), ["INBOX"]);
        assert_eq!(arrival_folders(Some("Junk")), ["INBOX", "Junk"]);
        assert_eq!(arrival_folders(Some("inbox")), ["INBOX"]);
        assert_eq!(landed_in("INBOX"), "folder=INBOX");
        assert_eq!(landed_in("Junk"), "folder=Junk (landed in Junk, not INBOX)");
    }
}
