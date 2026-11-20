//! Key-directory publishing end to end through the real `sealbox` binary: GreenMail user u71
//! and an in-process `sealbox-server` on an ephemeral port whose challenge mail goes out
//! through GreenMail SMTP (127.0.0.1:3025, no TLS) — the same path a production server takes,
//! only with a local relay.
//!
//! (a) no server URL: `key publish`, `key directory-status` and `key complete-verification`
//!     refuse with exit 2 and an error naming `sealbox server set-url`; nothing is contacted;
//! (b) `server set-url` stores the URL in the profile (source `settings`); the directory knows
//!     nothing yet (`unpublished`) and completing before publishing is `awaiting_verification`;
//! (c) `key publish` uploads the key and requests the challenge (`token_issued`, `pending`);
//! (d) `key complete-verification` syncs u71's INBOX, follows the challenge link of *this*
//!     server and reports `published` with the matching fingerprint; `key directory-status`
//!     and the engine API (`Engine::directory_status`, what the Flutter bridge calls) agree;
//! (e) publishing again reports the address as already published (no new challenge);
//! (f) `server set-url --clear` drops the URL (source `none`) and publishing refuses again.
//!
//! Run: `testing/mail_up.sh && cargo test -p sealbox-cli --test gate_publish -- --ignored`

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use sealbox_server::config::SmtpTlsMode;
use sealbox_server::mail::{SmtpConfig, SmtpMailSender};
use sealbox_server::{AppState, Limits, StateOptions};
use serde_json::Value;
use tokio::net::TcpListener;

const USER: &str = "u71";
const A: &str = "u71@sealbox.test";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct Server {
    base: String,
    _dir: tempfile::TempDir,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

/// `sealbox-server` in-process on 127.0.0.1:<ephemeral>, fresh SQLite, challenge mails through
/// GreenMail's SMTP port.
async fn start_server() -> Server {
    let dir = tempfile::Builder::new()
        .prefix("sealbox-publish-srv-")
        .tempdir()
        .expect("tempdir");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let mailer = SmtpMailSender::new(&SmtpConfig {
        host: "127.0.0.1".into(),
        port: 3025,
        user: None,
        pass: None,
        from: "Sealbox <noreply@sealbox.test>".into(),
        tls: SmtpTlsMode::None,
    })
    .expect("SMTP mailer");
    let state = AppState::new(StateOptions {
        db_path: dir.path().join("publish.sqlite"),
        public_url: base.clone(),
        static_dir: repo_root().join("web/guest"),
        mailer: Arc::new(mailer),
        trust_proxy: false,
        limits: Limits::default(),
    })
    .expect("server state");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(sealbox_server::serve(listener, state, async move {
        let _ = rx.await;
    }));
    Server {
        base,
        _dir: dir,
        _shutdown: tx,
    }
}

/// Empty u71's INBOX so challenge mails from earlier runs cannot be followed.
async fn purge_inbox(user: &str) {
    let mut imap = imap_login(user).await;
    imap.select("INBOX").await.expect("select");
    let uids = imap.fetch_new_uids(0).await.expect("uids");
    if !uids.is_empty() {
        imap.set_flags(&uids, sealbox_mail::imap::FlagOp::Add, &["\\Deleted"])
            .await
            .expect("flag");
        imap.expunge().await.expect("expunge");
    }
    let _ = imap.logout().await;
}

/// `--json` run that must fail with exit 2 (usage / not configured); returns the error text.
fn refused(p: &Profile, args: &[&str]) -> String {
    let mut full = vec!["--json"];
    full.extend_from_slice(args);
    let r = p.run(&full);
    assert_eq!(
        r.code,
        2,
        "sealbox {} should exit 2:\n{}{}",
        full.join(" "),
        r.stdout,
        r.stderr
    );
    let v = r.json();
    assert_eq!(v["exit_code"], 2, "{v}");
    v["error"].as_str().unwrap_or_default().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn publish_verify_and_status_through_greenmail() {
    let started = Instant::now();
    purge_inbox(USER).await;
    let p = Profile::new("publish-u71");
    p.add_greenmail_account(USER);
    let fpr = p.fingerprint(A);

    // ------------------------------------------------------------ (a) no server configured
    let show = p.json(&["server", "show"]);
    assert_eq!(show["source"], "none", "{show}");
    assert!(show["server_url"].is_null(), "{show}");
    for args in [
        &["key", "publish", "--account", A][..],
        &["key", "directory-status", "--account", A][..],
        &["key", "complete-verification", "--account", A][..],
    ] {
        let err = refused(&p, args);
        assert!(
            err.contains("server set-url"),
            "the refusal must say how to fix it: {err}"
        );
        assert!(err.contains("no Sealbox server configured"), "{err}");
    }
    // The plain-text form carries the same hint on stderr.
    let r = p.run(&["key", "publish", "--account", A]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("sealbox server set-url"), "{}", r.stderr);
    println!("publish (a) no server URL: refused with the set-url hint");

    // ------------------------------------------------------------ (b) set the URL at runtime
    let srv = start_server().await;
    let set = p.json(&["server", "set-url", &format!("{}/", srv.base)]);
    assert_eq!(
        set["server_url"],
        srv.base.as_str(),
        "trailing slash dropped: {set}"
    );
    assert_eq!(set["source"], "settings");
    assert_eq!(set["directory_url"], srv.base.as_str());
    let st = p.json(&["key", "directory-status", "--account", A]);
    assert_eq!(st["state"], "unpublished", "{st}");
    assert_eq!(st["published"], false);
    assert!(st["fingerprint_matches"].is_null(), "{st}");
    assert_eq!(st["server_url"], srv.base.as_str());
    let early = p.json(&["key", "complete-verification", "--account", A]);
    assert_eq!(early["state"], "awaiting_verification", "{early}");
    println!("publish (b) server URL from settings; directory empty");

    // ------------------------------------------------------------ (c) upload + challenge
    let rep = p.json(&["key", "publish", "--account", A]);
    assert_eq!(rep["token_issued"], true, "{rep}");
    assert_eq!(rep["fingerprint"], fpr.as_str(), "{rep}");
    assert_eq!(rep["server_url"], srv.base.as_str());
    assert_eq!(rep["status"][A], "pending", "{rep}");
    println!("publish (c) key {fpr} uploaded, challenge requested");

    // ------------------------------------------------------------ (d) follow the mailed link
    let deadline = Instant::now() + Duration::from_secs(30);
    let done: Value = loop {
        let v = p.json(&["key", "complete-verification", "--account", A]);
        if v["state"] == "published" {
            break v;
        }
        assert_eq!(
            v["state"], "awaiting_verification",
            "only 'not arrived yet' may repeat: {v}"
        );
        assert!(
            Instant::now() < deadline,
            "the challenge mail never reached {A}'s INBOX: {v}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(done["published"], true, "{done}");
    assert_eq!(done["fingerprint_matches"], true, "{done}");
    let st = p.json(&["key", "directory-status", "--account", A]);
    assert_eq!(st["state"], "published", "{st}");
    assert_eq!(st["fingerprint_matches"], true);
    let engine_view = p.engine().directory_status(A).await.expect("engine status");
    assert_eq!(engine_view.state, "published");
    assert_eq!(engine_view.fingerprint_matches, Some(true));
    assert_eq!(engine_view.server_url, srv.base);
    // The challenge itself was ordinary mail in u71's INBOX, from the server's relay.
    let challenge = p.find_by_subject(
        Some(A),
        "INBOX",
        &format!("Verify {A} for your Sealbox key"),
    );
    assert_eq!(
        challenge["from"]["address"], "noreply@sealbox.test",
        "{challenge}"
    );
    let text = p.ok(&["key", "directory-status", "--account", A]);
    assert!(
        text.contains("published: the directory serves this account's key"),
        "{text}"
    );
    println!("publish (d) challenge followed: published, directory_status agrees");

    // ------------------------------------------------------------ (e) idempotent re-publish
    let again = p.json(&["key", "publish", "--account", A]);
    assert_eq!(again["token_issued"], false, "{again}");
    assert_eq!(again["status"][A], "published", "{again}");
    let noop = p.json(&["key", "complete-verification", "--account", A]);
    assert_eq!(noop["state"], "published", "{noop}");
    println!("publish (e) second publish: already published, no new challenge");

    // ------------------------------------------------------------ (f) clear the URL
    let cleared = p.json(&["server", "set-url", "--clear"]);
    assert_eq!(cleared["source"], "none", "{cleared}");
    assert!(cleared["server_url"].is_null());
    let err = refused(&p, &["key", "publish", "--account", A]);
    assert!(err.contains("server set-url"), "{err}");
    // An environment URL is reported as such (and the profile setting would win over it).
    let r = p.run_env(
        &["--json", "server", "show"],
        &[("SEALBOX_SERVER_URL", Some(&srv.base))],
    );
    assert_eq!(r.code, 0, "{}{}", r.stdout, r.stderr);
    assert_eq!(r.json()["source"], "environment");
    let elapsed = started.elapsed();
    println!("publish (f) cleared; whole run {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(60),
        "the publish gate must stay under 60 s"
    );
}
