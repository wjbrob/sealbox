//! The CLI surface behind the Flutter UI wave (special-use folders, spam, filter rules, the
//! runtime server URL), end to end against GreenMail through the real `sealbox` binary, plus
//! the engine's per-account mailbox lock under real IMAP concurrency.
//!
//! * u72 — `folders`, `move --to <role>` (and back), `sync --role`, `list --role`, `server
//!   show | set-url | --clear` (settings vs environment), usage errors exit 2.
//! * u73 — `spam settings show | set | reset`, `spam allow | block [--remove]`, `spam status`,
//!   `spam explain`, `spam learn --spam | --ham` (moves to the junk folder and back);
//!   `filter add | list | enable [--off] | test | rm` including the `filters` / `remove`
//!   aliases.
//! * u75 — an IMAP IDLE watcher and concurrent manual syncs of one account: every message is
//!   stored exactly once, and a manual sync is not held up while the watcher idles.
//!
//! Run: `testing/mail_up.sh && cargo test -p sealbox-cli --test cli_folders_spam_filters -- --ignored`

mod common;

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use sealbox_core::{Draft, ListQuery, SendPolicy, WatchEvent};
use serde_json::Value;

/// Send a plaintext self-mail and wait until it is stored in `account`'s INBOX.
async fn self_mail(p: &Profile, account: &str, subject: &str, body: &str) -> Value {
    let sent = p.json(&[
        "send",
        "--from",
        account,
        "--to",
        account,
        "--subject",
        subject,
        "--body",
        body,
        "--policy",
        "plaintext",
    ]);
    assert_eq!(sent["mode"], "plaintext", "{sent}");
    let arrived = wait_until(Duration::from_secs(30), || async {
        p.sync(account);
        p.list(Some(account), "INBOX")
            .iter()
            .any(|m| m["subject"] == subject)
    })
    .await;
    assert!(arrived, "{subject:?} never reached {account}'s INBOX");
    p.find_by_subject(Some(account), "INBOX", subject)
}

fn ids_with_subject(rows: &[Value], subject: &str) -> Vec<i64> {
    rows.iter()
        .filter(|m| m["subject"] == subject)
        .filter_map(|m| m["id"].as_i64())
        .collect()
}

fn list_role(p: &Profile, account: &str, role: &str) -> Vec<Value> {
    p.json(&[
        "list",
        "--account",
        account,
        "--role",
        role,
        "--limit",
        "200",
    ])
    .as_array()
    .cloned()
    .unwrap_or_default()
}

/// `--json` run expected to fail with `code`; returns the error JSON.
fn fails(p: &Profile, args: &[&str], code: i32) -> Value {
    let mut full = vec!["--json"];
    full.extend_from_slice(args);
    let r = p.run(&full);
    assert_eq!(
        r.code,
        code,
        "sealbox {}:\n{}{}",
        full.join(" "),
        r.stdout,
        r.stderr
    );
    r.json()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn folders_move_role_sync_and_server_url() {
    const A: &str = "u72@sealbox.test";
    let p = Profile::new("folders-u72");
    p.add_greenmail_account("u72");

    // Roles before any sync: every role, all provider defaults (GreenMail profile).
    let roles = p.json(&["folders", "--account", A]);
    let roles = roles.as_array().expect("role list").clone();
    assert_eq!(roles.len(), 8, "{roles:?}");
    let entry = |rs: &[Value], role: &str| -> Value {
        rs.iter()
            .find(|e| e["role"] == role)
            .cloned()
            .unwrap_or_else(|| panic!("no {role} in {rs:?}"))
    };
    assert_eq!(entry(&roles, "trash")["folder"], "Trash");
    assert_eq!(entry(&roles, "junk")["folder"], "Junk");
    assert_eq!(entry(&roles, "inbox")["learned"], false);
    // The text table is aligned (the role column is padded).
    let table = p.ok(&["folders", "--account", A]);
    assert!(
        table.lines().any(|l| l.starts_with("inbox    INBOX")),
        "{table}"
    );

    let subject = format!("folders {}", nonce("u72"));
    let m = self_mail(&p, A, &subject, "move me around").await;
    let id = m["id"].as_i64().expect("id").to_string();
    let roles = p.json(&["folders", "--account", A]);
    assert_eq!(
        entry(roles.as_array().unwrap(), "inbox")["learned"],
        true,
        "{roles}"
    );

    // INBOX → Trash by role.
    let mv = p.json(&["move", &id, "--to", "trash"]);
    assert_eq!(mv["from_folder"], "INBOX", "{mv}");
    assert_eq!(mv["to_folder"], "Trash");
    assert_eq!(mv["method"], "move", "GreenMail advertises MOVE: {mv}");
    assert!(ids_with_subject(&p.list(Some(A), "INBOX"), &subject).is_empty());
    // The local copy is gone until Trash is synced; a role sync brings it back.
    let rep = p.json(&["sync", "--account", A, "--role", "trash"]);
    let rep = &rep[0];
    assert_eq!(rep["folders"][0]["name"], "Trash", "{rep}");
    let in_trash = ids_with_subject(&list_role(&p, A, "trash"), &subject);
    assert_eq!(in_trash.len(), 1, "exactly one copy in Trash");
    let tid = in_trash[0].to_string();
    // Already there: no server round trip, `method` null.
    let same = p.json(&["move", &tid, "--to", "trash"]);
    assert!(same["method"].is_null(), "{same}");
    assert_eq!(same["to_folder"], "Trash");
    let text = p.ok(&["move", &tid, "--to", "trash"]);
    assert!(text.contains("is already in Trash"), "{text}");
    // Back to INBOX; a normal sync stores it there again (once).
    let back = p.json(&["move", &tid, "--to", "inbox"]);
    assert_eq!(
        (back["from_folder"].as_str(), back["to_folder"].as_str()),
        (Some("Trash"), Some("INBOX"))
    );
    p.sync(A);
    assert_eq!(
        ids_with_subject(&p.list(Some(A), "INBOX"), &subject).len(),
        1
    );
    assert!(ids_with_subject(&list_role(&p, A, "trash"), &subject).is_empty());
    let roles = p.json(&["folders", "--account", A]);
    assert_eq!(
        entry(roles.as_array().unwrap(), "trash")["learned"],
        true,
        "{roles}"
    );

    // Usage errors exit 2; a stale id is an ordinary failure.
    let e = fails(&p, &["move", &tid, "--to", "bogus"], 2);
    assert!(
        e["error"].as_str().unwrap().contains("unknown folder role"),
        "{e}"
    );
    fails(&p, &["list", "--account", A, "--role", "nope"], 2);
    fails(&p, &["sync", "--account", A, "--role", "nope"], 2);
    fails(&p, &["move", "999999", "--to", "trash"], 1);
    println!("u72: folders / move / role sync ok");

    // Runtime server URL: settings beat the environment; clearing falls back to it.
    let env_url = "http://127.0.0.1:9";
    let show = p.json(&["server", "show"]);
    assert_eq!(show["source"], "none", "{show}");
    let r = p.run_env(
        &["--json", "server", "show"],
        &[("SEALBOX_SERVER_URL", Some(env_url))],
    );
    assert_eq!(r.json()["source"], "environment");
    assert_eq!(r.json()["server_url"], env_url);
    let set = p.json(&["server", "set-url", "https://keys.sealbox.test/"]);
    assert_eq!(set["server_url"], "https://keys.sealbox.test", "{set}");
    assert_eq!(set["source"], "settings");
    let r = p.run_env(
        &["--json", "server", "show"],
        &[("SEALBOX_SERVER_URL", Some(env_url))],
    );
    assert_eq!(
        r.json()["server_url"],
        "https://keys.sealbox.test",
        "settings win"
    );
    assert_eq!(r.json()["source"], "settings");
    let e = fails(&p, &["server", "set-url", "ftp://keys.sealbox.test"], 2);
    assert!(e["error"].as_str().unwrap().contains("http(s)://"), "{e}");
    let cleared = p.json(&["server", "set-url", "--clear"]);
    assert_eq!(cleared["source"], "none");
    let r = p.run_env(
        &["--json", "server", "show"],
        &[("SEALBOX_SERVER_URL", Some(env_url))],
    );
    assert_eq!(
        r.json()["source"],
        "environment",
        "cleared: the environment applies again"
    );
    println!("u72: server URL settings / environment / clear ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn spam_and_filter_commands() {
    const A: &str = "u73@sealbox.test";
    let p = Profile::new("spam-u73");
    p.add_greenmail_account("u73");
    let subject = format!("[newsletter] issue {}", nonce("u73"));
    let m = self_mail(&p, A, &subject, "This week: encrypted mail for everyone.").await;
    let id = m["id"].as_i64().expect("id");
    let ids = id.to_string();

    // ---- spam settings
    let s = p.json(&["spam", "settings", "show", "--account", A]);
    assert_eq!(s["enabled"], true, "{s}");
    assert_eq!(s["spam_threshold"], 0.9);
    assert_eq!(s["move_to_folder"], "Spam");
    let s = p.json(&[
        "spam",
        "settings",
        "set",
        "--account",
        A,
        "--spam-threshold",
        "0.95",
        "--unsure-threshold",
        "0.6",
    ]);
    assert_eq!(
        (s["spam_threshold"].as_f64(), s["unsure_threshold"].as_f64()),
        (Some(0.95), Some(0.6))
    );
    fails(
        &p,
        &[
            "spam",
            "settings",
            "set",
            "--account",
            A,
            "--unsure-threshold",
            "0.99",
        ],
        2,
    );
    let s = p.json(&["spam", "settings", "reset", "--account", A]);
    assert_eq!(s["spam_threshold"], 0.9, "{s}");

    // ---- allow / block (an entry lives on one list at a time)
    let s = p.json(&["spam", "allow", "Friend.Example", "--account", A]);
    assert_eq!(s["allowlist"], serde_json::json!(["friend.example"]), "{s}");
    let s = p.json(&["spam", "block", "@spam.example", "--account", A]);
    assert_eq!(s["blocklist"], serde_json::json!(["spam.example"]), "{s}");
    let s = p.json(&["spam", "allow", "spam.example", "--account", A]);
    assert!(
        s["blocklist"].as_array().unwrap().is_empty(),
        "moved off the blocklist: {s}"
    );
    assert_eq!(s["allowlist"].as_array().unwrap().len(), 2);
    let s = p.json(&["spam", "allow", "spam.example", "--account", A, "--remove"]);
    assert_eq!(s["allowlist"], serde_json::json!(["friend.example"]), "{s}");

    // ---- status / explain
    let st = p.json(&["spam", "status", "--account", A]);
    let acct = &st["accounts"][0];
    assert_eq!(acct["email"], A, "{st}");
    assert_eq!(acct["filter_rules"], 0);
    assert!(st["model_tokens"].is_u64(), "{st}");
    let ex = p.json(&["spam", "explain", &ids]);
    assert_eq!(ex["id"], id, "{ex}");
    assert_eq!(ex["account"], A);
    assert_eq!(ex["folder"], "INBOX");
    assert_eq!(ex["subject"], subject.as_str());
    assert_eq!(ex["features"]["from_address"], A, "{ex}");
    assert!(
        ["ham", "unsure", "spam"].contains(&ex["verdict"]["label"].as_str().unwrap_or("")),
        "{ex}"
    );
    assert!(ex["filters"]["matched"].as_array().unwrap().is_empty());

    // ---- filter rules: add (both spellings), list, enable, test, remove
    let r1 = p.json(&[
        "filter",
        "add",
        "--account",
        A,
        "--field",
        "subject",
        "--op",
        "contains",
        "--value",
        "[newsletter]",
        "--action",
        "move:Newsletters",
        "--name",
        "newsletters",
    ]);
    let r1_id = r1["id"].as_i64().expect("rule id");
    assert_eq!(r1["action"]["move_to"]["folder"], "Newsletters", "{r1}");
    let r2 = p.json(&[
        "filters",
        "add",
        "--account",
        A,
        "--field",
        "from",
        "--op",
        "domain",
        "--value",
        "sealbox.test",
        "--action",
        "star",
        "--stop",
    ]);
    let r2_id = r2["id"].as_i64().expect("rule id");
    assert!(
        r2["order"].as_i64() > r1["order"].as_i64(),
        "appended after rule 1: {r2}"
    );
    let listed = p.json(&["filter", "list", "--account", A]);
    let listed: Vec<i64> = listed
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["id"].as_i64())
        .collect();
    assert_eq!(listed, vec![r1_id, r2_id]);
    let off = p.json(&[
        "filter",
        "enable",
        &r2_id.to_string(),
        "--account",
        A,
        "--off",
    ]);
    assert_eq!(off["enabled"], false, "{off}");
    let t = p.json(&["filter", "test", &ids, "--account", A]);
    assert_eq!(t["outcome"]["move_to"], "Newsletters", "{t}");
    assert_eq!(t["outcome"]["matched"], serde_json::json!([r1_id]));
    assert_eq!(
        t["outcome"]["star"], false,
        "the disabled rule does not run: {t}"
    );
    assert_eq!(
        t["rules"].as_array().unwrap().len(),
        1,
        "only enabled rules are listed: {t}"
    );
    let on = p.json(&["filters", "enable", &r2_id.to_string(), "--account", A]);
    assert_eq!(on["enabled"], true);
    let t = p.json(&["filters", "test", &ids, "--account", A]);
    assert_eq!(t["outcome"]["star"], true, "{t}");
    let ex = p.json(&["spam", "explain", &ids]);
    assert_eq!(
        ex["filters"]["move_to"], "Newsletters",
        "explain shows the filter outcome: {ex}"
    );
    let rm = p.json(&["filters", "remove", &r2_id.to_string(), "--account", A]);
    assert_eq!(rm["removed"], true, "{rm}");
    // Removing it again: the JSON form reports `removed: false`, the text form fails.
    let again = p.json(&["filter", "rm", &r2_id.to_string(), "--account", A]);
    assert_eq!(again["removed"], false, "{again}");
    assert_eq!(
        p.run(&["filter", "rm", &r2_id.to_string(), "--account", A])
            .code,
        1
    );
    assert_eq!(
        p.json(&["filter", "list", "--account", A])
            .as_array()
            .unwrap()
            .len(),
        1
    );
    fails(
        &p,
        &[
            "filter",
            "add",
            "--account",
            A,
            "--field",
            "subject",
            "--op",
            "regex",
            "--value",
            "(",
            "--action",
            "read",
        ],
        2,
    );
    let st = p.json(&["spam", "status", "--account", A]);
    assert_eq!(st["accounts"][0]["filter_rules"], 1, "{st}");

    // ---- learn: spam moves to the junk folder (the local row follows), ham moves it back
    let l = p.json(&["spam", "learn", &ids, "--spam"]);
    assert_eq!(l["learned"], "spam", "{l}");
    assert_eq!(l["verdict"]["label"], "spam");
    let junk = l["moved_to"]
        .as_str()
        .expect("moved to the junk folder")
        .to_string();
    assert_eq!(
        ids_with_subject(&list_role(&p, A, "junk"), &subject),
        vec![id],
        "row relocated to {junk}"
    );
    let l = p.json(&["spam", "learn", &ids, "--ham"]);
    assert_eq!(l["learned"], "ham", "{l}");
    assert_eq!(l["previously_learned"], "spam");
    assert_eq!(l["moved_to"], "INBOX");
    assert_eq!(
        ids_with_subject(&p.list(Some(A), "INBOX"), &subject),
        vec![id]
    );
    let st = p.json(&["spam", "status"]);
    assert!(st["model_ham_messages"].as_u64().unwrap_or(0) >= 1, "{st}");
    println!("u73: spam settings / allow / block / status / explain / learn and filter rules ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn watch_and_manual_syncs_store_each_message_once() {
    const A: &str = "u75@sealbox.test";
    let p = Profile::new("watch-u75");
    p.add_greenmail_account("u75");
    let engine = Arc::new(p.engine());
    engine.sync(A).await.expect("initial sync");

    // The watcher: long IDLE rounds, so a manual sync that had to wait for an idling watcher
    // would take ~20 s.
    let idle = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let new_mail_events = Arc::new(AtomicU32::new(0));
    let watcher = {
        let (engine, idle, stop, events) = (
            engine.clone(),
            idle.clone(),
            stop.clone(),
            new_mail_events.clone(),
        );
        tokio::spawn(async move {
            engine
                .watch(A, Duration::from_secs(20), move |ev| {
                    match ev {
                        WatchEvent::Idle { .. } => idle.store(true, Ordering::SeqCst),
                        WatchEvent::NewMail { .. } => {
                            events.fetch_add(1, Ordering::SeqCst);
                        }
                        WatchEvent::Timeout => {}
                    }
                    !stop.load(Ordering::SeqCst)
                })
                .await
        })
    };
    assert!(
        wait_until(Duration::from_secs(20), || async {
            idle.load(Ordering::SeqCst)
        })
        .await,
        "the watcher never reached IDLE"
    );

    // A manual sync while the watcher idles must not wait for the IDLE round.
    let t0 = Instant::now();
    engine.sync(A).await.expect("sync during IDLE");
    assert!(
        t0.elapsed() < Duration::from_secs(8),
        "a manual sync waited {:?}: the watcher holds the mailbox lock while idling",
        t0.elapsed()
    );

    // Mail arrives while manual syncs run concurrently with the watcher's own syncs.
    let tag = nonce("race");
    let subjects: Vec<String> = (0..4).map(|i| format!("race {tag} #{i}")).collect();
    for s in &subjects {
        engine
            .send(
                A,
                Draft {
                    to: vec![A.into()],
                    subject: s.clone(),
                    text: "concurrency".into(),
                    policy: SendPolicy::AllowPlaintext,
                    ..Draft::default()
                },
            )
            .await
            .expect("send");
        let syncs: Vec<_> = (0..3)
            .map(|_| {
                let e = engine.clone();
                tokio::spawn(async move { e.sync(A).await.map(|r| r.new) })
            })
            .collect();
        for s in syncs {
            s.await.expect("join").expect("concurrent sync");
        }
    }
    let inbox = |engine: &sealbox_core::Engine| {
        engine
            .list_messages(ListQuery {
                account: Some(A.into()),
                folder: Some("INBOX".into()),
                folder_role: None,
                limit: 500,
            })
            .expect("list")
    };
    let all_there = wait_until(Duration::from_secs(30), || {
        let rows = inbox(&engine);
        let ok = subjects
            .iter()
            .all(|s| rows.iter().any(|m| m.subject.as_deref() == Some(s)));
        async move { ok }
    })
    .await;
    assert!(all_there, "not every message reached the store");
    // Let the watcher's own sync for the last notification run too.
    tokio::time::sleep(Duration::from_secs(2)).await;
    engine.sync(A).await.expect("final sync");
    let rows = inbox(&engine);
    for s in &subjects {
        let n = rows
            .iter()
            .filter(|m| m.subject.as_deref() == Some(s))
            .count();
        assert_eq!(n, 1, "{s:?} stored {n} times");
    }
    assert!(
        new_mail_events.load(Ordering::SeqCst) >= 1,
        "the watcher never woke up for the new mail"
    );

    stop.store(true, Ordering::SeqCst);
    // The loop notices at its next event: the IDLE round ends within its timeout.
    let ended = tokio::time::timeout(Duration::from_secs(30), watcher)
        .await
        .expect("the watcher stopped")
        .expect("join");
    ended.expect("watch ended cleanly");
    println!(
        "u75: watcher + concurrent syncs: {} messages stored once each, {} NewMail event(s)",
        subjects.len(),
        new_mail_events.load(Ordering::SeqCst)
    );
}
