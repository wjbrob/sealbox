//! Guest links (G29): the notification text for each [`GuestMode`], the link itself, and the
//! local record that lets [`Engine::resend_guest_link`] mail a fresh notification for the same
//! server-side ciphertext. Threat model per mode: `docs/GUEST_LINKS.md`.
//!
//! The local `guest_links` table keeps the secret so the sender can see it again and a resend
//! of a one-click / email-code link can rebuild the fragment. It lives in the profile database
//! next to the Sent copy (which, in those two modes, contains the same link anyway).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rusqlite::{params, OptionalExtension};
use sealbox_crypto::minimal_key_for_autocrypt;
use sealbox_mail::mime::{autocrypt_header_value, build_plain, Mailbox, MessageDraft};

use crate::directory;
use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::store::NewOutbox;
use crate::types::{GuestLinkInfo, GuestMode, RecipientStatus, SendMode, SendReport};

/// Local table: one row per guest message we created. Executed by `Store::open`.
pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS guest_links (
    message_id      TEXT PRIMARY KEY,
    account_id      INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    guest_id        TEXT NOT NULL,
    bare_url        TEXT NOT NULL,
    mode            TEXT NOT NULL,
    secret          TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    verify_address  TEXT,
    to_addrs        TEXT NOT NULL,
    cc_addrs        TEXT NOT NULL,
    bcc_addrs       TEXT NOT NULL,
    subject         TEXT NOT NULL,
    recipients_json TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    resent          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS guest_links_by_guest_id ON guest_links(guest_id);
"#;

impl GuestMode {
    /// Stable string form (database, CLI, JSON): `passphrase`, `one_click`, `email_code`.
    pub fn as_str(self) -> &'static str {
        match self {
            GuestMode::Passphrase => "passphrase",
            GuestMode::OneClick => "one_click",
            GuestMode::EmailCode => "email_code",
        }
    }

    /// Inverse of [`GuestMode::as_str`]; also accepts the CLI spelling (`one-click`).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "passphrase" => Some(GuestMode::Passphrase),
            "one_click" | "oneclick" => Some(GuestMode::OneClick),
            "email_code" | "emailcode" => Some(GuestMode::EmailCode),
            _ => None,
        }
    }

    /// Does the mailed link carry the decryption secret in its `#fragment`?
    pub fn secret_in_link(self) -> bool {
        !matches!(self, GuestMode::Passphrase)
    }
}

/// The link that goes into the notification for `mode`.
pub(crate) fn link_for(mode: GuestMode, bare_url: &str, secret: &str) -> String {
    if mode.secret_in_link() {
        directory::guest_link(bare_url, secret)
    } else {
        bare_url.to_owned()
    }
}

/// The notification body for `mode`. Every claim in it must be true of that mode.
pub(crate) fn notification_text(
    mode: GuestMode,
    from: &str,
    link: &str,
    expires: &str,
    verify_address: Option<&str>,
) -> String {
    match mode {
        GuestMode::Passphrase => format!(
            "{from} sent you an end-to-end encrypted message with Sealbox.\n\n\
             Open it here:\n{link}\n\n\
             To read it you need a passphrase. This e-mail does not contain it: the sender \
             will give it to you another way (in person, by phone or in a chat).\n\n\
             The link expires on {expires}.\n"
        ),
        GuestMode::OneClick => format!(
            "{from} sent you an encrypted message with Sealbox.\n\n\
             Open it here:\n{link}\n\n\
             Important: the key to the message is part of this link. Anyone who has the link \
             (for example anyone who can read this e-mail, or anyone you forward it to) can \
             read the message. It is protected from the Sealbox server and from the network, \
             not from people who can see this e-mail. Do not forward it.\n\n\
             The link expires on {expires}.\n"
        ),
        GuestMode::EmailCode => {
            let addr = verify_address.unwrap_or("your address");
            format!(
                "{from} sent you an encrypted message with Sealbox.\n\n\
                 Open it here:\n{link}\n\n\
                 When you open the link, Sealbox e-mails a one-time code to {addr}. Enter it \
                 to read the message. This protects the message if the link is forwarded or \
                 leaks, but it does not protect it from anyone who can read the {addr} \
                 mailbox, because the code arrives there too.\n\n\
                 The link expires on {expires}.\n"
            )
        }
    }
}

/// RFC 2822 date for the notification, falling back to the raw number.
pub(crate) fn expiry_text(expires_at: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(expires_at, 0)
        .map(|d| d.to_rfc2822())
        .unwrap_or_else(|| expires_at.to_string())
}

/// Pick the address that receives the one-time code: the hint if given, else the only
/// recipient. Errors when it is ambiguous.
pub(crate) fn email_code_recipient(hint: Option<&str>, envelope: &[String]) -> Result<String> {
    if let Some(h) = hint.map(str::trim).filter(|h| !h.is_empty()) {
        if !h.contains('@') {
            return Err(Error::InvalidInput(format!(
                "guest recipient {h:?} is not an e-mail address"
            )));
        }
        return Ok(h.to_owned());
    }
    match envelope {
        [only] => Ok(only.clone()),
        _ => Err(Error::InvalidInput(
            "email-code guest links go to one recipient; send one message per recipient or \
             name the recipient that receives the code (guest_recipient_hint)"
                .into(),
        )),
    }
}

/// Everything recorded about a guest message we sent.
pub(crate) struct GuestRecord<'a> {
    pub message_id: &'a str,
    pub account_id: i64,
    pub guest_id: &'a str,
    pub bare_url: &'a str,
    pub mode: GuestMode,
    pub secret: &'a str,
    pub expires_at: i64,
    pub verify_address: Option<&'a str>,
    pub to: &'a [String],
    pub cc: &'a [String],
    pub bcc: &'a [String],
    pub subject: &'a str,
    pub recipients: &'a [RecipientStatus],
}

struct StoredGuest {
    message_id: String,
    account_id: i64,
    guest_id: String,
    bare_url: String,
    mode: GuestMode,
    secret: String,
    expires_at: i64,
    verify_address: Option<String>,
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    subject: String,
    recipients: Vec<RecipientStatus>,
}

impl Engine {
    pub(crate) fn record_guest_link(&self, r: &GuestRecord<'_>) -> Result<()> {
        let to = serde_json::to_string(r.to)?;
        let cc = serde_json::to_string(r.cc)?;
        let bcc = serde_json::to_string(r.bcc)?;
        let recipients = serde_json::to_string(r.recipients)?;
        let store = self.store();
        // The guest passphrase is wrapped at rest, AAD row id = message_id (G27, vault.rs).
        let secret = store
            .vault()
            .seal_text("guest_links", "secret", r.message_id, r.secret)?;
        store.conn().execute(
            "INSERT OR REPLACE INTO guest_links (message_id, account_id, guest_id, bare_url, mode,
                 secret, expires_at, verify_address, to_addrs, cc_addrs, bcc_addrs, subject,
                 recipients_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                r.message_id,
                r.account_id,
                r.guest_id,
                r.bare_url,
                r.mode.as_str(),
                secret,
                r.expires_at,
                r.verify_address,
                to,
                cc,
                bcc,
                r.subject,
                recipients,
                chrono::Utc::now().timestamp(),
            ],
        )?;
        Ok(())
    }

    fn stored_guest(&self, key: &str) -> Result<StoredGuest> {
        let k = key.trim().trim_start_matches('<').trim_end_matches('>');
        // Accept the Message-ID, the server id, or the whole link.
        let gid = k
            .rsplit_once("/g/")
            .map(|(_, rest)| rest.split('#').next().unwrap_or(rest))
            .unwrap_or(k)
            .to_owned();
        let row = self
            .store()
            .conn()
            .query_row(
                "SELECT message_id, account_id, guest_id, bare_url, mode, secret, expires_at,
                        verify_address, to_addrs, cc_addrs, bcc_addrs, subject, recipients_json
                 FROM guest_links WHERE message_id = ?1 OR guest_id = ?2
                 ORDER BY created_at LIMIT 1",
                params![k, gid],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, rusqlite::types::Value>(5)?,
                        r.get::<_, i64>(6)?,
                        r.get::<_, Option<String>>(7)?,
                        r.get::<_, String>(8)?,
                        r.get::<_, String>(9)?,
                        r.get::<_, String>(10)?,
                        r.get::<_, String>(11)?,
                        r.get::<_, String>(12)?,
                    ))
                },
            )
            .optional()?;
        let Some((mid, acct, guest_id, bare_url, mode, secret, exp, verify, to, cc, bcc, subj, rc)) =
            row
        else {
            return Err(Error::InvalidInput(format!(
                "no guest link {k:?} in this profile"
            )));
        };
        let secret = self
            .store()
            .vault()
            .open_text("guest_links", "secret", &mid, secret)?;
        Ok(StoredGuest {
            message_id: mid,
            account_id: acct,
            guest_id,
            bare_url,
            mode: GuestMode::parse(&mode).unwrap_or_default(),
            secret,
            expires_at: exp,
            verify_address: verify,
            to: serde_json::from_str(&to)?,
            cc: serde_json::from_str(&cc)?,
            bcc: serde_json::from_str(&bcc)?,
            subject: subj,
            recipients: serde_json::from_str(&rc)?,
        })
    }

    /// Mail a new notification for a guest message sent earlier: same server id, same
    /// ciphertext, same secret, same recipients and mode; a new Message-ID. `message_id` is the
    /// `SendReport::message_id` of the original send, or the guest id / link.
    ///
    /// Refused when the message has expired (locally or on the server).
    pub async fn resend_guest_link(&self, message_id: &str) -> Result<SendReport> {
        let g = self.stored_guest(message_id)?;
        if g.expires_at <= chrono::Utc::now().timestamp() {
            return Err(Error::Guest(format!(
                "guest link {} expired on {}; send the message again",
                g.guest_id,
                expiry_text(g.expires_at)
            )));
        }
        let server = self.server_url().ok_or_else(|| {
            Error::Guest(
                "no Sealbox server configured (`sealbox server set-url` or SEALBOX_SERVER_URL); \
                 cannot check the guest link"
                    .into(),
            )
        })?;
        if !directory::guest_alive(self.http(), &server, &g.guest_id).await? {
            return Err(Error::Guest(format!(
                "the server no longer holds guest message {} (expired or deleted)",
                g.guest_id
            )));
        }
        let acct = self
            .store()
            .account_by_id(g.account_id)?
            .ok_or_else(|| Error::AccountNotFound(format!("account #{}", g.account_id)))?;
        let (_, identity) = self.identity_for(&acct)?;

        let from = if acct.display_name.is_empty() {
            Mailbox::new(acct.email.clone())
        } else {
            Mailbox::named(acct.display_name.clone(), acct.email.clone())
        };
        let parse = |list: &[String]| -> Result<Vec<Mailbox>> {
            list.iter()
                .map(|a| Mailbox::parse(a).map_err(Error::from))
                .collect()
        };
        let link = link_for(g.mode, &g.bare_url, &g.secret);
        let text = notification_text(
            g.mode,
            &from.to_string(),
            &link,
            &expiry_text(g.expires_at),
            g.verify_address.as_deref(),
        );
        let mut md = MessageDraft::new(from, parse(&g.to)?, g.subject.clone(), text);
        md.cc = parse(&g.cc)?;
        md.bcc = parse(&g.bcc)?;
        md.references = vec![g.message_id.clone()];
        let keydata = minimal_key_for_autocrypt(&identity)?;
        md.extra_headers.push((
            "Autocrypt".to_string(),
            autocrypt_header_value(
                &acct.email,
                self.config().prefer_encrypt == sealbox_crypto::PreferEncrypt::Mutual,
                &B64.encode(&keydata),
            ),
        ));
        let raw = build_plain(&md)?;

        let rcpts = md.envelope_recipients();
        let smtp = self.smtp_for(&acct).await?;
        let submitted = smtp.send_raw(&acct.email, &rcpts, &raw).await;
        smtp.shutdown().await;
        if let Err(e) = submitted {
            let _ = self.store().insert_outbox(&NewOutbox {
                account_id: acct.id,
                message_id: &md.message_id,
                recipients: &rcpts,
                subject: &md.subject,
                mode: "guest_link",
                state: "failed",
                error: Some(&e.to_string()),
                sent_copy_appended: false,
            });
            return Err(Error::Smtp(e));
        }
        let (appended, sent_folder) = match self.append_sent(&acct, &raw, &md.message_id).await {
            Ok((appended, name)) => (appended, Some(name)),
            Err(e) => {
                tracing::warn!("could not append the sent copy of the resent guest link: {e}");
                (false, None)
            }
        };
        self.store().insert_outbox(&NewOutbox {
            account_id: acct.id,
            message_id: &md.message_id,
            recipients: &rcpts,
            subject: &md.subject,
            mode: "guest_link",
            state: "sent",
            error: None,
            sent_copy_appended: appended,
        })?;
        self.store().conn().execute(
            "UPDATE guest_links SET resent = resent + 1 WHERE message_id = ?1",
            [&g.message_id],
        )?;
        Ok(SendReport {
            message_id: md.message_id,
            mode: SendMode::GuestLink,
            encrypted: false,
            recipients: g.recipients,
            guest: Some(GuestLinkInfo {
                url: link,
                passphrase: g.secret,
                mode: g.mode,
                expires_at: g.expires_at,
                secret_in_link: g.mode.secret_in_link(),
                recipient_verification: g.mode == GuestMode::EmailCode,
            }),
            sent_copy_appended: appended,
            sent_folder,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_mode_mails_no_secret_and_says_so() {
        let secret = "abcd-efgh-ijkl-mnop-qrst";
        let link = link_for(GuestMode::Passphrase, "https://s/g/ID", secret);
        assert_eq!(link, "https://s/g/ID");
        let t = notification_text(GuestMode::Passphrase, "A <a@x>", &link, "soon", None);
        assert!(!t.contains(secret));
        assert!(!t.contains("abcd"));
        assert!(t.contains("This e-mail does not contain it"));
        assert!(t.contains("https://s/g/ID\n"));
    }

    #[test]
    fn one_click_mode_puts_secret_in_fragment_and_warns() {
        let link = link_for(GuestMode::OneClick, "https://s/g/ID", "ab-cd");
        assert_eq!(link, "https://s/g/ID#ab%2Dcd");
        let t = notification_text(GuestMode::OneClick, "A", &link, "soon", None);
        assert!(t.contains(&link));
        assert!(t.contains("Anyone who has the link"));
        assert!(t.contains("can read the message"));
    }

    #[test]
    fn email_code_mode_is_honest_about_the_mailbox() {
        let link = link_for(GuestMode::EmailCode, "https://s/g/ID", "x");
        assert!(link.contains('#'));
        let t = notification_text(GuestMode::EmailCode, "A", &link, "soon", Some("b@y"));
        assert!(t.contains("one-time code to b@y"));
        assert!(t.contains("does not protect it from anyone who can read the b@y"));
    }

    #[test]
    fn mode_strings_roundtrip() {
        for m in [
            GuestMode::Passphrase,
            GuestMode::OneClick,
            GuestMode::EmailCode,
        ] {
            assert_eq!(GuestMode::parse(m.as_str()), Some(m));
        }
        assert_eq!(GuestMode::parse("one-click"), Some(GuestMode::OneClick));
        assert_eq!(GuestMode::parse("email-code"), Some(GuestMode::EmailCode));
        assert_eq!(GuestMode::parse("nope"), None);
        assert_eq!(GuestMode::default(), GuestMode::Passphrase);
    }

    #[test]
    fn email_code_recipient_rules() {
        let one = vec!["b@y".to_string()];
        let two = vec!["b@y".to_string(), "c@z".to_string()];
        assert_eq!(email_code_recipient(None, &one).unwrap(), "b@y");
        assert!(email_code_recipient(None, &two).is_err());
        assert_eq!(email_code_recipient(Some("c@z"), &two).unwrap(), "c@z");
        assert!(email_code_recipient(Some("nope"), &two).is_err());
    }
}
