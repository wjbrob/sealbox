//! The send pipeline: resolve recipients → policy → build (PGP/MIME encrypted+signed, plain,
//! or guest link) → SMTP submit → append to Sent → outbox bookkeeping.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sealbox_crypto::{
    encrypt_and_sign_armored, generate_passphrase, guest_encrypt, minimal_key_for_autocrypt,
    minimal_public_key, PreferEncrypt, PublicKey,
};
use sealbox_mail::mime::{
    autocrypt_gossip_header_value, autocrypt_header_value, build_pgp_mime_encrypted, build_plain,
    render_inner_for_encryption, Attachment, InnerOptions, Mailbox, MessageDraft, OuterHeaders,
};

use crate::directory;
use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::guest;
use crate::policy::{self, ResolvedRecipient};
use crate::providers::profile_of;
use crate::signature::{ComposeOptions, SendExtras};
use crate::store::{AccountRow, NewOutbox};
use crate::types::{
    Draft, GuestLinkInfo, GuestMode, KeySource, RecipientStatus, SendMode, SendReport,
};
use sealbox_mail::imap::FolderRole;

fn parse_mailboxes(list: &[String]) -> Result<Vec<Mailbox>> {
    let mut out = Vec::new();
    for item in list {
        for piece in item.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            let mb = Mailbox::parse(piece)?;
            if !out
                .iter()
                .any(|m: &Mailbox| m.address.eq_ignore_ascii_case(&mb.address))
            {
                out.push(mb);
            }
        }
    }
    Ok(out)
}

/// Reply context derived from `Draft::in_reply_to`.
struct ReplyContext {
    in_reply_to: Option<String>,
    references: Vec<String>,
    reply_to_encrypted: bool,
}

impl Engine {
    fn reply_context(&self, in_reply_to: Option<&str>) -> Result<ReplyContext> {
        let Some(raw) = in_reply_to.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(ReplyContext {
                in_reply_to: None,
                references: Vec::new(),
                reply_to_encrypted: false,
            });
        };
        let store = self.store();
        let row = match raw.parse::<i64>() {
            Ok(id) => Some(store.message(id)?),
            Err(_) => {
                store.message_by_message_id(raw.trim_start_matches('<').trim_end_matches('>'))?
            }
        };
        match row {
            Some(r) => {
                let mid = r
                    .summary
                    .message_id
                    .clone()
                    .unwrap_or_else(|| raw.to_string());
                let mut refs = r.references.clone();
                if !refs.iter().any(|x| x == &mid) {
                    refs.push(mid.clone());
                }
                Ok(ReplyContext {
                    in_reply_to: Some(mid),
                    references: refs,
                    reply_to_encrypted: r.summary.was_encrypted && r.summary.decrypted,
                })
            }
            None => {
                let mid = raw
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_string();
                Ok(ReplyContext {
                    in_reply_to: Some(mid.clone()),
                    references: vec![mid],
                    reply_to_encrypted: false,
                })
            }
        }
    }

    /// Resolve a recipient, consulting the key directory when nothing local is known.
    async fn resolve_for_send(
        &self,
        address: &str,
        reply_to_encrypted: bool,
    ) -> Result<ResolvedRecipient> {
        let mut r = self.resolve_recipient_full(address, reply_to_encrypted)?;
        if r.key.is_none() {
            if let Some(base) = self.directory_url() {
                if let Some(k) = directory::lookup_key(self.http(), &base, address).await {
                    if k.encryption_capable() && self.kt_lookup_ok(address, &k).await {
                        self.store().upsert_key(
                            address,
                            KeySource::Directory,
                            &k.fingerprint(),
                            &k.to_armored()?,
                        )?;
                        r = self.resolve_recipient_full(address, reply_to_encrypted)?;
                    }
                }
            }
        }
        Ok(r)
    }

    /// Send a message from `account_email` according to `draft.policy`. The account
    /// signature is applied per its settings; see [`Engine::send_with`] for quoting and
    /// reply/forward kinds.
    pub async fn send(&self, account_email: &str, draft: Draft) -> Result<SendReport> {
        self.send_with(account_email, draft, ComposeOptions::default())
            .await
    }

    /// The raw pipeline: bodies are taken as given (composition happens in `signature.rs`).
    pub(crate) async fn send_inner(
        &self,
        account_email: &str,
        draft: Draft,
        extras: SendExtras,
    ) -> Result<SendReport> {
        let acct = self.account_row(account_email)?;
        let (_identity_row, identity) = self.identity_for(&acct)?;

        let to = parse_mailboxes(&draft.to)?;
        let cc = parse_mailboxes(&draft.cc)?;
        let bcc = parse_mailboxes(&draft.bcc)?;
        if to.is_empty() && cc.is_empty() && bcc.is_empty() {
            return Err(Error::InvalidInput("no recipients".into()));
        }
        let reply = self.reply_context(draft.in_reply_to.as_deref())?;

        // Resolve every distinct recipient address.
        let mut addresses: Vec<String> = Vec::new();
        for m in to.iter().chain(cc.iter()).chain(bcc.iter()) {
            if !addresses.iter().any(|a| a.eq_ignore_ascii_case(&m.address)) {
                addresses.push(m.address.clone());
            }
        }
        let mut resolved: Vec<ResolvedRecipient> = Vec::with_capacity(addresses.len());
        for a in &addresses {
            resolved.push(self.resolve_for_send(a, reply.reply_to_encrypted).await?);
        }
        let statuses: Vec<RecipientStatus> = resolved.iter().map(|r| r.status.clone()).collect();
        let mode = match policy::decide(draft.policy, &statuses) {
            // Auto-replies only ("encrypted when possible"): never for user mail.
            Err(Error::RecipientsWithoutKeys { .. }) if extras.plaintext_fallback => {
                SendMode::Plaintext
            }
            other => other?,
        };

        // The draft.
        let from = if acct.display_name.is_empty() {
            Mailbox::new(acct.email.clone())
        } else {
            Mailbox::named(acct.display_name.clone(), acct.email.clone())
        };
        let mut md = MessageDraft::new(from, to, draft.subject.clone(), draft.text.clone());
        md.cc = cc;
        md.bcc = bcc;
        md.html_body = draft.html.clone();
        md.attachments = draft
            .attachments
            .iter()
            .map(|a| {
                Attachment::new(
                    a.filename.clone(),
                    if a.content_type.is_empty() {
                        "application/octet-stream".to_string()
                    } else {
                        a.content_type.clone()
                    },
                    a.data.clone(),
                )
            })
            .collect();
        md.in_reply_to = reply.in_reply_to.clone();
        md.references = reply.references.clone();
        let keydata = minimal_key_for_autocrypt(&identity)?;
        md.extra_headers.push((
            "Autocrypt".to_string(),
            autocrypt_header_value(
                &acct.email,
                self.config().prefer_encrypt == PreferEncrypt::Mutual,
                &B64.encode(&keydata),
            ),
        ));
        md.extra_headers.extend(extras.headers); // e.g. Auto-Submitted on auto-replies

        let mut guest_info: Option<GuestLinkInfo> = None;
        let raw: Vec<u8> = match mode {
            SendMode::Encrypted => {
                // Gossip the keys of the other visible recipients (To/Cc, never Bcc, not us).
                let mut gossip_headers = Vec::new();
                for m in md.to.iter().chain(md.cc.iter()) {
                    if m.address.eq_ignore_ascii_case(&acct.email) {
                        continue;
                    }
                    let Some(r) = resolved
                        .iter()
                        .find(|r| r.status.address.eq_ignore_ascii_case(&m.address))
                    else {
                        continue;
                    };
                    if let Some(k) = &r.key {
                        let minimal = minimal_public_key(k, Some(&m.address))?.to_bytes()?;
                        gossip_headers.push(autocrypt_gossip_header_value(
                            &m.address,
                            &B64.encode(&minimal),
                        ));
                    }
                }
                let inner = render_inner_for_encryption(
                    &md,
                    &InnerOptions {
                        gossip_headers,
                        legacy_display: false,
                    },
                )?;
                let own = identity.public();
                let mut keys: Vec<&PublicKey> = Vec::new();
                for r in &resolved {
                    if let Some(k) = &r.key {
                        if !keys.iter().any(|x| x.fingerprint() == k.fingerprint()) {
                            keys.push(k);
                        }
                    }
                }
                if !keys.iter().any(|x| x.fingerprint() == own.fingerprint()) {
                    keys.push(&own);
                }
                let armored = encrypt_and_sign_armored(&inner, &keys, Some(&identity))?;
                build_pgp_mime_encrypted(&OuterHeaders::for_protected(&md), &armored)?
            }
            SendMode::Plaintext => build_plain(&md)?,
            SendMode::GuestLink => {
                let server = self.server_url().ok_or_else(|| {
                    Error::Guest(
                        "no Sealbox server configured (`sealbox server set-url` or \
                         SEALBOX_SERVER_URL); cannot create a guest link"
                            .into(),
                    )
                })?;
                let passphrase = generate_passphrase();
                let date = chrono::DateTime::<chrono::Utc>::from_timestamp(md.date, 0)
                    .map(|d| d.to_rfc2822())
                    .unwrap_or_default();
                let mut guest_plain = format!(
                    "From: {}\nTo: {}\nSubject: {}\nDate: {}\n\n{}",
                    md.from,
                    md.to
                        .iter()
                        .chain(md.cc.iter())
                        .map(|m| m.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    md.subject,
                    date,
                    md.text_body
                );
                if !md.attachments.is_empty() {
                    guest_plain.push_str(&format!(
                        "\n\n[{} attachment(s) were not included in this guest message: {}]\n",
                        md.attachments.len(),
                        md.attachments
                            .iter()
                            .map(|a| a.filename.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                let armored = guest_encrypt(guest_plain.as_bytes(), &passphrase)?;
                let sender_key = identity.public().to_armored()?;
                let guest_mode = draft.guest_mode;
                let envelope = md.envelope_recipients();
                let verify_address = match guest_mode {
                    GuestMode::EmailCode => Some(guest::email_code_recipient(
                        draft.guest_recipient_hint.as_deref(),
                        &envelope,
                    )?),
                    _ => None,
                };
                let up = directory::guest_upload(
                    self.http(),
                    &server,
                    &directory::GuestUploadRequest {
                        ciphertext_armored: &armored,
                        sender_key_armored: Some(&sender_key),
                        expires_in_secs: self.config().guest_expiry_secs,
                        email_code_recipient: verify_address.as_deref(),
                    },
                )
                .await?;
                // G29: only the opted-in modes put the secret in the link (fragment only).
                let link = guest::link_for(guest_mode, &up.url, &passphrase);
                let mut link_draft = md.clone();
                link_draft.attachments.clear();
                link_draft.html_body = None;
                link_draft.text_body = guest::notification_text(
                    guest_mode,
                    &md.from.to_string(),
                    &link,
                    &guest::expiry_text(up.expires_at),
                    verify_address.as_deref(),
                );
                let addrs = |l: &[Mailbox]| l.iter().map(|m| m.to_string()).collect::<Vec<_>>();
                self.record_guest_link(&guest::GuestRecord {
                    message_id: &md.message_id,
                    account_id: acct.id,
                    guest_id: &up.id,
                    bare_url: &up.url,
                    mode: guest_mode,
                    secret: &passphrase,
                    expires_at: up.expires_at,
                    verify_address: verify_address.as_deref(),
                    to: &addrs(&md.to),
                    cc: &addrs(&md.cc),
                    bcc: &addrs(&md.bcc),
                    subject: &md.subject,
                    recipients: &statuses,
                })?;
                guest_info = Some(GuestLinkInfo {
                    url: link,
                    passphrase,
                    mode: guest_mode,
                    expires_at: up.expires_at,
                    secret_in_link: guest_mode.secret_in_link(),
                    recipient_verification: up.recipient_verification,
                });
                build_plain(&link_draft)?
            }
        };

        // Submit.
        let rcpts = md.envelope_recipients();
        let smtp = self.smtp_for(&acct).await?;
        let submitted = smtp.send_raw(&acct.email, &rcpts, &raw).await;
        smtp.shutdown().await;
        let mode_str = match mode {
            SendMode::Encrypted => "encrypted",
            SendMode::Plaintext => "plaintext",
            SendMode::GuestLink => "guest_link",
        };
        if let Err(e) = submitted {
            let _ = self.store().insert_outbox(&NewOutbox {
                account_id: acct.id,
                message_id: &md.message_id,
                recipients: &rcpts,
                subject: &md.subject,
                mode: mode_str,
                state: "failed",
                error: Some(&e.to_string()),
                sent_copy_appended: false,
            });
            return Err(Error::Smtp(e));
        }

        // Sent copy (best effort; the mail is already out). `appended == false` with a folder
        // name means the provider's SMTP stored the copy itself (Gmail, Microsoft 365).
        let (appended, sent_folder) = match self.append_sent(&acct, &raw, &md.message_id).await {
            Ok((appended, name)) => (appended, Some(name)),
            Err(e) => {
                tracing::warn!("could not append the sent copy: {e}");
                (false, None)
            }
        };
        // Best effort too: the mail is out. A failure here (locked database, full disk) must
        // not turn into an error, or the caller would take the group as not delivered and a
        // retry would mail every recipient a second copy (found by the app's partial-send work).
        if let Err(e) = self.store().insert_outbox(&NewOutbox {
            account_id: acct.id,
            message_id: &md.message_id,
            recipients: &rcpts,
            subject: &md.subject,
            mode: mode_str,
            state: "sent",
            error: None,
            sent_copy_appended: appended,
        }) {
            tracing::warn!(
                message_id = %md.message_id,
                "sent, but the outbox row could not be written: {e}"
            );
        }
        Ok(SendReport {
            message_id: md.message_id,
            mode,
            encrypted: mode == SendMode::Encrypted,
            recipients: statuses,
            guest: guest_info,
            sent_copy_appended: appended,
            sent_folder,
        })
    }

    /// Store exactly one copy of `raw` in the account's Sent folder (`\Seen`), creating the
    /// folder when the server has none. Providers whose SMTP already saves a copy (Gmail,
    /// Microsoft 365 — `ProviderProfile::smtp_saves_sent`) are given a few seconds for it to
    /// appear; the copy is looked up by Message-ID on every provider, so a second copy is
    /// never appended. Returns `(appended, folder)`.
    pub(crate) async fn append_sent(
        &self,
        acct: &AccountRow,
        raw: &[u8],
        message_id: &str,
    ) -> Result<(bool, String)> {
        let profile = profile_of(acct);
        let mut client = self.imap_for(acct).await?;
        let name = self
            .resolve_folder_live(acct, &mut client, FolderRole::Sent, true)
            .await?;
        let wait = if profile.smtp_saves_sent {
            std::time::Duration::from_secs(10)
        } else {
            std::time::Duration::ZERO
        };
        let started = std::time::Instant::now();
        loop {
            client.select(&name).await?;
            if !client.search_message_id(message_id).await?.is_empty() {
                tracing::info!(
                    email = %acct.email,
                    folder = %name,
                    provider = %profile.id,
                    "Sent copy already stored by the provider; not appending a second one"
                );
                let _ = client.logout().await;
                return Ok((false, name));
            }
            if started.elapsed() >= wait {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        if profile.smtp_saves_sent {
            tracing::warn!(
                email = %acct.email,
                provider = %profile.id,
                "provider is expected to save Sent copies itself but none appeared; appending"
            );
        }
        client.append(&name, raw, &["\\Seen"]).await?;
        let _ = client.logout().await;
        Ok((true, name))
    }
}
