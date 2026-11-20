//! The fake submission server driven by Sealbox's own `SmtpClient`, including the quirk that
//! only a shared state can demonstrate: when a provider files its own Sent copy, the message
//! really does turn up in the IMAP Sent folder, so "do not APPEND a second one" is testable
//! rather than merely asserted in a table.

use std::time::Duration;

use sealbox_core::providers::ProviderId;
use sealbox_fakeprov::imap::{grant_token, shared};
use sealbox_fakeprov::quirks::{Quirks, SimAuth};
use sealbox_fakeprov::state::Shared;
use sealbox_fakeprov::{imap, smtp};
use sealbox_mail::net_policy::ConnectOptions;
use sealbox_mail::oauth::Provider;
use sealbox_mail::smtp::SmtpClient;
use sealbox_mail::{Auth, BearerScope, Security};

/// Both servers of one provider, sharing a mailbox.
async fn fake(id: ProviderId, tune: impl FnOnce(&mut Quirks)) -> (Shared, u16, u16) {
    let mut q = Quirks::for_provider(id);
    tune(&mut q);
    let state = shared(q);
    let imap_port = imap::start(state.clone()).await.expect("imap");
    let smtp_port = smtp::start(state.clone()).await.expect("smtp");
    (state, imap_port, smtp_port)
}

fn auth_for(state: &Shared) -> Auth {
    let s = state.lock().unwrap();
    match s.quirks.auth.clone() {
        SimAuth::Password(pass) => Auth::Password {
            user: "you@fakeprov.test".into(),
            pass,
        },
        SimAuth::XOAuth2 => Auth::XOAuth2 {
            user: "you@fakeprov.test".into(),
            access_token: "tok-good".into(),
        },
    }
}

fn dev_opts() -> ConnectOptions {
    ConnectOptions::new(Duration::from_secs(10)).with_bearer(Some(BearerScope {
        provider: Provider::Google,
        dev_idp: true,
    }))
}

fn client(state: &Shared, port: u16) -> SmtpClient {
    grant_token(state, "tok-good");
    SmtpClient::connect_with(
        "127.0.0.1",
        port,
        Security::Plain,
        Some(auth_for(state)),
        &dev_opts(),
    )
    .expect("smtp client")
}

fn message(subject: &str, pad: usize) -> Vec<u8> {
    let mut m = format!(
        "From: you@fakeprov.test\r\nTo: them@fakeprov.test\r\nSubject: {subject}\r\n\
         Message-ID: <{subject}@fakeprov.test>\r\n\r\nbody\r\n"
    )
    .into_bytes();
    if pad > 0 {
        m.extend(std::iter::repeat_n(b'x', pad));
        m.extend_from_slice(b"\r\n");
    }
    m
}

#[tokio::test]
async fn the_real_client_authenticates_and_submits() {
    let (state, _imap, smtp_port) = fake(ProviderId::Fastmail, |_| {}).await;
    let c = client(&state, smtp_port);
    let resp = c
        .send_raw(
            "you@fakeprov.test",
            &["them@fakeprov.test".to_string()],
            &message("submitted", 0),
        )
        .await
        .expect("send");
    assert!(resp.code.starts_with('2'), "{resp:?}");

    let s = state.lock().unwrap();
    assert_eq!(s.submitted.len(), 1);
    let (from, rcpt, raw) = &s.submitted[0];
    assert_eq!(from, "you@fakeprov.test");
    assert_eq!(rcpt, &vec!["them@fakeprov.test".to_string()]);
    assert!(
        String::from_utf8_lossy(raw).contains("Subject: submitted"),
        "the body arrived intact"
    );
    assert!(
        !s.smtp_log.iter().flatten().any(|l| l.contains("body")),
        "the submission log must not hold the message itself"
    );
}

/// `smtp_saves_sent` stops being a claim: on Gmail and Outlook the copy is really in Sent
/// afterwards, over IMAP, so a client that also APPENDs would genuinely create a duplicate.
#[tokio::test]
async fn a_provider_that_files_its_own_sent_copy_really_does_file_it() {
    for id in [ProviderId::Gmail, ProviderId::Outlook] {
        let (state, _imap, smtp_port) = fake(id, |_| {}).await;
        let sent_folder = state.lock().unwrap().quirks.sent_folder();
        assert_eq!(state.lock().unwrap().count(&sent_folder), 0);

        let c = client(&state, smtp_port);
        c.send_raw(
            "you@fakeprov.test",
            &["them@fakeprov.test".to_string()],
            &message("filed", 0),
        )
        .await
        .expect("send");

        let s = state.lock().unwrap();
        assert!(
            s.quirks.smtp_saves_sent,
            "{} files its own copy",
            id.as_str()
        );
        assert_eq!(
            s.count(&sent_folder),
            1,
            "{}: submission put it in {sent_folder}",
            id.as_str()
        );
        let msg = &s.folder(&sent_folder).unwrap().messages[0];
        assert!(msg.has_flag("\\Seen"), "a sent copy is not unread");
    }
}

#[tokio::test]
async fn a_provider_that_does_not_file_a_copy_leaves_sent_empty() {
    for id in [ProviderId::Yahoo, ProviderId::Icloud, ProviderId::Fastmail] {
        let (state, _imap, smtp_port) = fake(id, |_| {}).await;
        let sent_folder = state.lock().unwrap().quirks.sent_folder();
        let c = client(&state, smtp_port);
        c.send_raw(
            "you@fakeprov.test",
            &["them@fakeprov.test".to_string()],
            &message("not-filed", 0),
        )
        .await
        .expect("send");
        let s = state.lock().unwrap();
        assert!(!s.quirks.smtp_saves_sent);
        assert_eq!(
            s.count(&sent_folder),
            0,
            "{}: the client has to APPEND its own copy",
            id.as_str()
        );
        assert_eq!(s.submitted.len(), 1, "but it was submitted");
    }
}

/// The size limit, on both paths a real server enforces it: the declared `SIZE=` on
/// `MAIL FROM`, and the bytes that actually arrive.
#[tokio::test]
async fn the_size_limit_is_advertised_and_enforced() {
    // Outlook's documented limit is 20 MB; use a small one so the test is cheap.
    let (state, _imap, smtp_port) =
        fake(ProviderId::Outlook, |q| q.max_message_bytes = Some(2_000)).await;
    let c = client(&state, smtp_port);

    let ok = c
        .send_raw(
            "you@fakeprov.test",
            &["them@fakeprov.test".to_string()],
            &message("small", 100),
        )
        .await
        .expect("under the limit");
    assert!(ok.code.starts_with('2'), "{ok:?}");

    let big = message("big", 5_000);
    let res = c
        .send_raw(
            "you@fakeprov.test",
            &["them@fakeprov.test".to_string()],
            &big,
        )
        .await;
    match res {
        Err(e) => {
            let m = format!("{e}");
            assert!(
                m.contains("552") || m.to_ascii_lowercase().contains("size"),
                "refused for its size: {m}"
            );
        }
        Ok(r) => assert!(
            r.code.starts_with('5'),
            "a message over the limit must be refused: {r:?}"
        ),
    }
    let s = state.lock().unwrap();
    assert_eq!(s.submitted.len(), 1, "only the small one got through");
}

#[tokio::test]
async fn submission_without_authentication_is_refused() {
    let (state, _imap, smtp_port) = fake(ProviderId::Fastmail, |_| {}).await;
    // No credentials at all: an open relay would accept this.
    let c = SmtpClient::connect("127.0.0.1", smtp_port, Security::Plain, None)
        .expect("client without auth");
    let res = c
        .send_raw(
            "you@fakeprov.test",
            &["them@fakeprov.test".to_string()],
            &message("unauthenticated", 0),
        )
        .await;
    let refused = match &res {
        Err(e) => format!("{e}").contains("530") || format!("{e}").to_lowercase().contains("auth"),
        Ok(r) => r.code.starts_with('5'),
    };
    assert!(refused, "submission must require authentication: {res:?}");
    assert!(state.lock().unwrap().submitted.is_empty());
}

#[tokio::test]
async fn an_oauth_only_provider_offers_no_password_mechanism_on_submission() {
    let (state, _imap, smtp_port) = fake(ProviderId::Gmail, |_| {}).await;
    let c = SmtpClient::connect(
        "127.0.0.1",
        smtp_port,
        Security::Plain,
        Some(Auth::Password {
            user: "you@fakeprov.test".into(),
            pass: "hunter2".into(),
        }),
    )
    .expect("client");
    let res = c
        .send_raw(
            "you@fakeprov.test",
            &["them@fakeprov.test".to_string()],
            &message("password-on-gmail", 0),
        )
        .await;
    let refused = match &res {
        Err(_) => true,
        Ok(r) => r.code.starts_with('5'),
    };
    assert!(refused, "Gmail submission is XOAUTH2 only: {res:?}");
    assert!(state.lock().unwrap().submitted.is_empty());
}

/// The alias quirk applies to submission as well as IMAP, which is what makes it so confusing
/// on a real account: the token works for one and not the other depending on the login used.
#[tokio::test]
async fn submission_rejects_xoauth2_under_an_alias_too() {
    let (state, _imap, smtp_port) = fake(ProviderId::Outlook, |q| {
        q.primary_login = Some("primary@fakeprov.test".into())
    })
    .await;
    grant_token(&state, "tok-good");

    let alias = SmtpClient::connect_with(
        "127.0.0.1",
        smtp_port,
        Security::Plain,
        Some(Auth::XOAuth2 {
            user: "alias@fakeprov.test".into(),
            access_token: "tok-good".into(),
        }),
        &dev_opts(),
    )
    .expect("client");
    let res = alias
        .send_raw(
            "alias@fakeprov.test",
            &["them@fakeprov.test".to_string()],
            &message("alias", 0),
        )
        .await;
    assert!(
        res.is_err() || res.as_ref().is_ok_and(|r| r.code.starts_with('5')),
        "{res:?}"
    );

    let primary = SmtpClient::connect_with(
        "127.0.0.1",
        smtp_port,
        Security::Plain,
        Some(Auth::XOAuth2 {
            user: "primary@fakeprov.test".into(),
            access_token: "tok-good".into(),
        }),
        &dev_opts(),
    )
    .expect("client");
    let ok = primary
        .send_raw(
            "primary@fakeprov.test",
            &["them@fakeprov.test".to_string()],
            &message("primary", 0),
        )
        .await
        .expect("the primary address works");
    assert!(ok.code.starts_with('2'), "{ok:?}");
    assert_eq!(state.lock().unwrap().submitted.len(), 1);
}
