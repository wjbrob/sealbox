//! Gate G3 — transport against the local GreenMail server
//! (`testing/mail_up.sh`; SMTP 127.0.0.1:3025, IMAP 127.0.0.1:3143).
//! Run with `cargo test -p sealbox-mail --test gate_g3 -- --ignored`.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sealbox_mail::imap::{FlagOp, IdleEvent, ImapClient};
use sealbox_mail::mime::{build_plain, parse, Mailbox, MessageDraft, MessageKind};
use sealbox_mail::oauth::Provider;
use sealbox_mail::smtp::SmtpClient;
use sealbox_mail::{Auth, BearerScope, ConnectOptions, Security, TransportPolicyError};

const SMTP: (&str, u16) = ("127.0.0.1", 3025);
const IMAP: (&str, u16) = ("127.0.0.1", 3143);

fn unique(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("sealbox-g3-{tag}-{nanos}-{}", std::process::id())
}

async fn imap_login(user: &str, pass: &str) -> ImapClient {
    // GreenMail accepts the bare login; fall back to the full address.
    match ImapClient::connect(
        IMAP.0,
        IMAP.1,
        Security::Plain,
        Auth::Password {
            user: user.into(),
            pass: pass.into(),
        },
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bare login failed ({e}); trying {user}@sealbox.test");
            ImapClient::connect(
                IMAP.0,
                IMAP.1,
                Security::Plain,
                Auth::Password {
                    user: format!("{user}@sealbox.test"),
                    pass: pass.into(),
                },
            )
            .await
            .expect("IMAP login")
        }
    }
}

/// Poll INBOX until a message with `subject` shows up; returns (uid, raw).
async fn wait_for_subject(imap: &mut ImapClient, subject: &str, since_uid: u32) -> (u32, Vec<u8>) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        imap.noop().await.expect("noop");
        let uids = imap.fetch_new_uids(since_uid).await.expect("search");
        for msg in imap.fetch_rfc822_batch(&uids).await.expect("fetch batch") {
            let parsed = parse(&msg.raw).expect("parse fetched");
            if parsed.headers.subject.as_deref() == Some(subject) {
                return (msg.uid, msg.raw);
            }
        }
        assert!(
            Instant::now() < deadline,
            "message {subject:?} never arrived"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn smtp_submit_then_imap_fetch_same_message() {
    let tag = unique("send");
    let subject = format!("G3 {tag}");
    let body =
        format!("Hello Alice,\n\nthis is {tag}.\nSecond paragraph with a dot-line:\n.\nEnd.\n");
    let mut draft = MessageDraft::new(
        Mailbox::named("Bob", "bob@sealbox.test"),
        vec![Mailbox::named("Alice", "alice@sealbox.test")],
        subject.clone(),
        body.clone(),
    );
    draft
        .extra_headers
        .push(("X-Sealbox-Test".into(), tag.clone()));
    let raw = build_plain(&draft).expect("build");

    // Baseline UID so that only new mail is considered.
    let mut imap = imap_login("alice", "alicepw").await;
    let folders = imap.list_folders().await.expect("list");
    assert!(
        folders.iter().any(|f| f.name.eq_ignore_ascii_case("INBOX")),
        "no INBOX in {folders:?}"
    );
    let mb = imap.select("INBOX").await.expect("select");
    assert!(mb.uidvalidity > 0, "GreenMail should report UIDVALIDITY");
    let baseline = mb.uidnext.saturating_sub(1);

    // Authenticated submission as bob (PLAIN/LOGIN).
    let smtp = SmtpClient::connect(
        SMTP.0,
        SMTP.1,
        Security::Plain,
        Some(Auth::Password {
            user: "bob".into(),
            pass: "bobpw".into(),
        }),
    )
    .expect("smtp client");
    let resp = smtp
        .send_raw("bob@sealbox.test", &draft.envelope_recipients(), &raw)
        .await
        .expect("send_raw");
    assert!(resp.code.starts_with('2'), "SMTP reply {resp:?}");
    smtp.shutdown().await;

    let (uid, fetched) = wait_for_subject(&mut imap, &subject, baseline).await;
    assert!(uid > baseline);
    let parsed = parse(&fetched).expect("parse");
    assert_eq!(
        parsed.headers.from,
        vec![Mailbox::named("Bob", "bob@sealbox.test")]
    );
    assert_eq!(
        parsed.headers.message_id.as_deref(),
        Some(draft.message_id.as_str())
    );
    let MessageKind::Plain(plain) = parsed.kind else {
        panic!("expected plain, got {:?}", parsed.kind);
    };
    assert_eq!(
        plain.text.as_deref().map(|t| t.replace("\r\n", "\n")),
        Some(body.clone())
    );

    // Single-message fetch agrees with the batch fetch.
    let single = imap.fetch_rfc822(uid).await.expect("fetch_rfc822");
    assert_eq!(single, fetched);

    // Flags: PEEK must not have set \Seen; set it explicitly and read back.
    let flags = imap.fetch_flags(&[uid]).await.expect("flags");
    assert_eq!(flags.len(), 1);
    assert!(
        !flags[0].1.iter().any(|f| f == "\\Seen"),
        "BODY.PEEK must not mark the message as read: {flags:?}"
    );
    imap.set_flags(&[uid], FlagOp::Add, &["\\Seen", "\\Flagged"])
        .await
        .expect("store");
    let flags = imap.fetch_flags(&[uid]).await.expect("flags");
    assert!(flags[0].1.iter().any(|f| f == "\\Seen"), "{flags:?}");
    assert!(flags[0].1.iter().any(|f| f == "\\Flagged"), "{flags:?}");
    imap.set_flags(&[uid], FlagOp::Remove, &["\\Flagged"])
        .await
        .expect("store");
    let flags = imap.fetch_flags(&[uid]).await.expect("flags");
    assert!(!flags[0].1.iter().any(|f| f == "\\Flagged"), "{flags:?}");

    imap.logout().await.expect("logout");
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn append_with_flags_and_fetch_back() {
    let tag = unique("append");
    let subject = format!("G3 append {tag}");
    let draft = MessageDraft::new(
        Mailbox::new("alice@sealbox.test"),
        vec![Mailbox::new("alice@sealbox.test")],
        subject.clone(),
        format!("appended {tag}\n"),
    );
    let raw = build_plain(&draft).unwrap();

    let mut imap = imap_login("alice", "alicepw").await;
    let mb = imap.select("INBOX").await.unwrap();
    let baseline = mb.uidnext.saturating_sub(1);
    imap.append("INBOX", &raw, &["\\Seen", "\\Draft"])
        .await
        .expect("append");
    let (uid, fetched) = wait_for_subject(&mut imap, &subject, baseline).await;
    assert_eq!(
        parse(&fetched).unwrap().headers.message_id.as_deref(),
        Some(draft.message_id.as_str())
    );
    let flags = imap.fetch_flags(&[uid]).await.unwrap();
    assert!(flags[0].1.iter().any(|f| f == "\\Seen"), "{flags:?}");
    assert!(flags[0].1.iter().any(|f| f == "\\Draft"), "{flags:?}");

    // Mark deleted + expunge so the test mailbox does not grow unbounded.
    imap.set_flags(&[uid], FlagOp::Add, &["\\Deleted"])
        .await
        .unwrap();
    imap.expunge().await.unwrap();
    let remaining = imap.fetch_flags(&[uid]).await.unwrap();
    assert!(
        remaining.is_empty(),
        "expunged message still present: {remaining:?}"
    );
    imap.logout().await.unwrap();
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn idle_wakes_on_new_mail() {
    let tag = unique("idle");
    let subject = format!("G3 idle {tag}");
    let mut imap = imap_login("carol", "carolpw").await;
    assert!(
        imap.has_capability("IDLE"),
        "caps: {:?}",
        imap.capabilities()
    );
    imap.select("INBOX").await.unwrap();

    let sender = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(800)).await;
        let draft = MessageDraft::new(
            Mailbox::new("bob@sealbox.test"),
            vec![Mailbox::new("carol@sealbox.test")],
            subject,
            "wake up\n",
        );
        let smtp = SmtpClient::connect(SMTP.0, SMTP.1, Security::Plain, None).unwrap();
        smtp.send_raw(
            "bob@sealbox.test",
            &draft.envelope_recipients(),
            &build_plain(&draft).unwrap(),
        )
        .await
        .expect("send");
    });

    let started = Instant::now();
    let event = imap.idle_wait(Duration::from_secs(20)).await.expect("idle");
    assert_eq!(
        event,
        IdleEvent::NewData,
        "IDLE should report the new message"
    );
    assert!(started.elapsed() < Duration::from_secs(15));
    sender.await.unwrap();

    // The session is usable again after IDLE/DONE.
    let uids = imap.fetch_new_uids(0).await.unwrap();
    assert!(!uids.is_empty());
    imap.logout().await.unwrap();
}

/// The scope of a token from a loopback mock identity provider (what the G21 local test
/// uses): such a token may go to local hosts like GreenMail (docs/THREAT_MODEL.md R14).
fn dev_token_opts() -> ConnectOptions {
    ConnectOptions::default().with_bearer(Some(BearerScope {
        provider: Provider::Google,
        dev_idp: true,
    }))
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn smtp_xoauth2_against_greenmail() {
    // GreenMail accepts XOAUTH2 when the bearer token equals the user's password,
    // which exercises our XOAUTH2 wiring end to end.
    let smtp = SmtpClient::connect_with(
        SMTP.0,
        SMTP.1,
        Security::Plain,
        Some(Auth::XOAuth2 {
            user: "bob".into(),
            access_token: "bobpw".into(),
        }),
        &dev_token_opts(),
    )
    .unwrap();
    assert!(smtp.test_connection().await.expect("xoauth2 handshake"));
    assert_eq!(smtp.auth_mechanism(), "XOAUTH2");
    let bad = SmtpClient::connect_with(
        SMTP.0,
        SMTP.1,
        Security::Plain,
        Some(Auth::XOAuth2 {
            user: "bob".into(),
            access_token: "wrong-token".into(),
        }),
        &dev_token_opts(),
    )
    .unwrap();
    let err = bad.test_connection().await;
    assert!(
        matches!(&err, Ok(false))
            || matches!(&err, Err(e) if e.to_string().to_lowercase().contains("auth") || e.to_string().contains("535")),
        "wrong token must be rejected, got {err:?}"
    );
    // A token without a scope (provider unknown) is never sent to a non-provider host.
    let err = SmtpClient::connect(
        SMTP.0,
        SMTP.1,
        Security::Plain,
        Some(Auth::XOAuth2 {
            user: "bob".into(),
            access_token: "bobpw".into(),
        }),
    )
    .expect_err("unscoped token to 127.0.0.1");
    assert!(
        matches!(
            err,
            sealbox_mail::SmtpError::Policy(TransportPolicyError::OAuthHostMismatch { .. })
        ),
        "{err:?}"
    );
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn wrong_imap_password_is_an_auth_error() {
    let err = ImapClient::connect(
        IMAP.0,
        IMAP.1,
        Security::Plain,
        Auth::Password {
            user: "alice".into(),
            pass: "nope".into(),
        },
    )
    .await
    .expect_err("login must fail");
    assert!(
        matches!(err, sealbox_mail::ImapError::LoginRejected { .. }),
        "{err:?}"
    );
    assert!(!err.to_string().contains("nope"), "{err}");
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn folders_copy_move_status_and_special_use() {
    use sealbox_mail::imap::{MoveMethod, SpecialUseSource, AUTH_LOGIN};

    let tag = unique("folders");
    let mut imap = imap_login("u30", "u30pw").await;
    assert_eq!(imap.auth_mechanism(), AUTH_LOGIN);
    assert!(
        imap.preauth_capabilities()
            .iter()
            .any(|c| c.eq_ignore_ascii_case("IMAP4rev1")),
        "pre-login CAPABILITY was not collected: {:?}",
        imap.preauth_capabilities()
    );

    // CREATE / ensure / RENAME / STATUS on an empty folder.
    let name = format!("sb-{tag}");
    imap.create_folder(&name).await.expect("CREATE");
    assert!(imap
        .list_folders()
        .await
        .unwrap()
        .iter()
        .any(|f| f.name == name));
    assert!(
        !imap.ensure_folder(&name).await.unwrap(),
        "ensure_folder must not recreate an existing folder"
    );
    let renamed = format!("{name}-r");
    imap.rename_folder(&name, &renamed).await.expect("RENAME");
    let folders = imap.list_folders().await.unwrap();
    assert!(folders.iter().any(|f| f.name == renamed));
    assert!(!folders.iter().any(|f| f.name == name));
    let st = imap.status(&renamed).await.expect("STATUS");
    assert_eq!(st.messages, 0, "{st:?}");
    assert!(st.uidvalidity > 0, "{st:?}");

    // Two messages in INBOX: one is COPYied, one MOVEd (UID MOVE), one more moved
    // through the COPY+EXPUNGE fallback.
    let mut uids = Vec::new();
    let mut mids = Vec::new();
    imap.select("INBOX").await.unwrap();
    for i in 0..3 {
        let subject = format!("G3 folders {tag} {i}");
        let draft = MessageDraft::new(
            Mailbox::new("u30@sealbox.test"),
            vec![Mailbox::new("u30@sealbox.test")],
            subject.clone(),
            format!("message {i}\n"),
        );
        let baseline = imap
            .select("INBOX")
            .await
            .unwrap()
            .uidnext
            .saturating_sub(1);
        imap.append("INBOX", &build_plain(&draft).unwrap(), &["\\Seen"])
            .await
            .unwrap();
        let (uid, _) = wait_for_subject(&mut imap, &subject, baseline).await;
        uids.push(uid);
        mids.push(draft.message_id.clone());
    }
    // search_message_id finds exactly the appended message.
    assert_eq!(
        imap.search_message_id(&mids[0]).await.unwrap(),
        vec![uids[0]]
    );
    assert_eq!(
        imap.search_message_id(&format!("<{}>", mids[1]))
            .await
            .unwrap(),
        vec![uids[1]]
    );
    assert!(imap
        .search_message_id("nonexistent@sealbox.test")
        .await
        .unwrap()
        .is_empty());

    imap.copy(&[uids[0]], &renamed).await.expect("UID COPY");
    let method = imap.r#move(&[uids[1]], &renamed).await.expect("move");
    assert_eq!(
        method,
        MoveMethod::Move,
        "GreenMail advertises MOVE: {:?}",
        imap.capabilities()
    );
    imap.move_via_copy(&[uids[2]], &renamed)
        .await
        .expect("COPY+EXPUNGE fallback");
    // Source: only the copied one is left; the moved ones are gone.
    assert!(!imap.fetch_flags(&[uids[0]]).await.unwrap().is_empty());
    assert!(imap.fetch_flags(&[uids[1]]).await.unwrap().is_empty());
    assert!(imap.fetch_flags(&[uids[2]]).await.unwrap().is_empty());
    // Destination has all three, findable by Message-ID.
    let st = imap.status(&renamed).await.unwrap();
    assert_eq!(st.messages, 3, "{st:?}");
    imap.select(&renamed).await.unwrap();
    for mid in &mids {
        assert_eq!(imap.search_message_id(mid).await.unwrap().len(), 1, "{mid}");
    }

    // Special-use: GreenMail has no SPECIAL-USE, so the mapping is by name.
    let su = imap.list_special_use().await.unwrap();
    assert_eq!(su.inbox, "INBOX");
    imap.ensure_folder("Trash").await.unwrap();
    imap.ensure_folder("Junk").await.unwrap();
    let su = imap.list_special_use().await.unwrap();
    assert_eq!(su.trash.as_deref(), Some("Trash"));
    assert_eq!(su.junk.as_deref(), Some("Junk"));
    assert_eq!(su.source, SpecialUseSource::Heuristic, "{su:?}");

    // Clean up: delete the scratch folder and the copied original.
    imap.select("INBOX").await.unwrap();
    imap.set_flags(&[uids[0]], FlagOp::Add, &["\\Deleted"])
        .await
        .unwrap();
    imap.expunge().await.unwrap();
    imap.delete_folder(&renamed).await.expect("DELETE");
    assert!(!imap
        .list_folders()
        .await
        .unwrap()
        .iter()
        .any(|f| f.name == renamed));
    imap.logout().await.unwrap();
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn imap_xoauth2_is_refused_when_not_advertised() {
    // GreenMail's IMAP advertises no AUTH=XOAUTH2. The token is then not sent at all: no
    // AUTHENTICATE, and never the old "token as LOGIN password" fallback (R14). The bearer
    // equals the mailbox password, so a fallback would have logged in.
    let err = ImapClient::connect_with(
        IMAP.0,
        IMAP.1,
        Security::Plain,
        Auth::XOAuth2 {
            user: "u71".into(),
            access_token: "u71pw".into(),
        },
        &dev_token_opts(),
    )
    .await
    .expect_err("no XOAUTH2 on GreenMail IMAP: must be refused");
    match &err {
        sealbox_mail::ImapError::XOAuth2NotOffered { host } => assert_eq!(host, IMAP.0),
        other => panic!("expected XOAuth2NotOffered, got {other:?}"),
    }
    assert!(
        err.to_string().contains("does not offer OAuth sign-in"),
        "{err}"
    );
    // Without a scope the token does not even reach the server (127.0.0.1 is no provider host).
    let err = ImapClient::connect(
        IMAP.0,
        IMAP.1,
        Security::Plain,
        Auth::XOAuth2 {
            user: "u71".into(),
            access_token: "u71pw".into(),
        },
    )
    .await
    .expect_err("unscoped token to 127.0.0.1");
    assert!(
        matches!(
            err,
            sealbox_mail::ImapError::Policy(TransportPolicyError::OAuthHostMismatch {
                provider: None,
                ..
            })
        ),
        "{err:?}"
    );
    // The same mailbox with its password still logs in (GreenMail itself is untouched).
    let imap = imap_login("u71", "u71pw").await;
    assert_eq!(imap.auth_mechanism(), sealbox_mail::imap::AUTH_LOGIN);
    imap.logout().await.unwrap();
}
