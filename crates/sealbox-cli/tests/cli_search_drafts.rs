//! `sealbox search` and `sealbox draft …` end to end against GreenMail through the real
//! binary (users u73–u75), in one sequential test because both halves share u73.
//!
//! * search — u74 and u75 (one sender profile) mail u73 three plaintext messages; u73's
//!   profile syncs; `search` finds the right one by a body word (exact, prefix, other case),
//!   by the sender's address and by the sender's name; `--account`, `--folder`, `--limit`,
//!   an unknown account; the body word is on no file of the profile (in-memory index).
//! * drafts — u73 saves a draft to u74 with an attachment (default policy: encrypted, since
//!   u74's Autocrypt key came with the mails above), lists, shows and updates it by id; the
//!   subject and body are sealed on disk; `draft send` delivers it — u74 decrypts it with the
//!   attachment — and the draft is gone; a reply draft (`--in-reply-to` the searched message,
//!   `--quote`) arrives with In-Reply-To and the quote; `draft delete`; usage errors exit 2.
//!
//! Run: `testing/mail_up.sh && cargo test -p sealbox-cli --test cli_search_drafts -- --ignored`

mod common;

use std::path::Path;
use std::time::Duration;

use common::*;
use sealbox_mail::imap::FlagOp;
use serde_json::Value;

const R: &str = "u73@sealbox.test";
const A: &str = "u74@sealbox.test";
const B: &str = "u75@sealbox.test";

/// Delete everything in a GreenMail user's INBOX, so the assertions below are exact even
/// though GreenMail keeps its state between runs.
async fn empty_inbox(user: &str) {
    let mut imap = imap_login(user).await;
    imap.select("INBOX").await.expect("select INBOX");
    let uids = imap.fetch_new_uids(0).await.expect("uids");
    if !uids.is_empty() {
        imap.set_flags(&uids, FlagOp::Add, &["\\Deleted"])
            .await
            .expect("flag \\Deleted");
        imap.expunge().await.expect("expunge");
    }
    let _ = imap.logout().await;
}

fn send_plain(p: &Profile, from: &str, subject: &str, body: &str) {
    let v = p.json(&[
        "send",
        "--from",
        from,
        "--to",
        R,
        "--subject",
        subject,
        "--body",
        body,
        "--policy",
        "plaintext",
    ]);
    assert_eq!(v["mode"], "plaintext", "{v}");
}

/// `--json search …` → the hit list.
fn search(p: &Profile, args: &[&str]) -> Vec<Value> {
    let mut full = vec!["search"];
    full.extend_from_slice(args);
    p.json(&full).as_array().cloned().expect("hit array")
}

fn hit_ids(hits: &[Value]) -> Vec<i64> {
    hits.iter().filter_map(|h| h["id"].as_i64()).collect()
}

/// Every byte of every file in the profile directory.
fn profile_bytes(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("profile dir") {
        let p = entry.expect("entry").path();
        if p.is_file() {
            out.extend(std::fs::read(&p).expect("read profile file"));
        }
    }
    out
}

fn on_disk(p: &Profile, needle: &str) -> bool {
    profile_bytes(p.path())
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// Sync `account` in `p` until a message with `subject` is in its INBOX; returns its row.
async fn arrive(p: &Profile, account: &str, subject: &str) -> Value {
    let ok = wait_until(Duration::from_secs(40), || async {
        p.sync(account);
        p.list(Some(account), "INBOX")
            .iter()
            .any(|m| m["subject"] == subject)
    })
    .await;
    assert!(ok, "{subject:?} never reached {account}'s INBOX");
    p.find_by_subject(Some(account), "INBOX", subject)
}

/// `--json` run expected to fail with `code`.
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
async fn search_and_drafts_end_to_end() {
    empty_inbox("u73").await;
    let senders = Profile::new("search-senders-u74-u75");
    senders.add_greenmail_account("u74");
    senders.add_greenmail_account("u75");
    let reader = Profile::new("search-drafts-u73");
    reader.add_greenmail_account("u73");

    // ----- search ------------------------------------------------------------------------
    let tag = nonce("srch");
    let word = format!("zanzibar{}", std::process::id()); // only in m1's body
    let s1 = format!("Quarterly numbers {tag}");
    let s2 = format!("Lunch {tag}");
    let s3 = format!("Trip {tag}");
    send_plain(
        &senders,
        A,
        &s1,
        &format!("Hello U73,\nthe {word} budget is due on Friday.\n{tag}"),
    );
    send_plain(&senders, A, &s2, &format!("Pizza at noon?\n{tag}"));
    send_plain(
        &senders,
        B,
        &s3,
        &format!("Photos from the lighthouse.\n{tag}"),
    );
    let ok = wait_until(Duration::from_secs(40), || async {
        reader.sync(R);
        let rows = reader.list(Some(R), "INBOX");
        [&s1, &s2, &s3]
            .iter()
            .all(|s| rows.iter().any(|m| m["subject"] == s.as_str()))
    })
    .await;
    assert!(ok, "the three mails never all reached u73");
    let m1 = reader.find_by_subject(Some(R), "INBOX", &s1);
    let m3 = reader.find_by_subject(Some(R), "INBOX", &s3);
    let (m1_id, m3_id) = (m1["id"].as_i64().unwrap(), m3["id"].as_i64().unwrap());

    // By a body word: exact, as a prefix, in other case.
    let hits = search(&reader, &[&word]);
    assert_eq!(hit_ids(&hits), vec![m1_id], "{hits:?}");
    let snippet = hits[0]["snippet"].as_str().unwrap();
    assert!(
        snippet.contains(&format!("\u{E000}{word}\u{E001}")),
        "{snippet:?}"
    );
    assert!(hits[0]["rank"].as_f64().unwrap() > 0.0);
    assert_eq!(hits[0]["from"]["address"], A);
    let prefix = word[..word.len() - 2].to_uppercase();
    assert_eq!(hit_ids(&search(&reader, &[&prefix])), vec![m1_id]);
    assert_eq!(hit_ids(&search(&reader, &["BUDGET friday"])), vec![m1_id]);
    // The text output shows the snippet with the match in brackets.
    let text = reader.ok(&["search", &word]);
    assert!(text.contains(&format!("[{word}]")), "{text}");
    assert!(text.contains(&s1), "{text}");
    // By the sender: address (a phrase) and display name.
    assert_eq!(hit_ids(&search(&reader, &[B])), vec![m3_id]);
    assert_eq!(hit_ids(&search(&reader, &["U75"])), vec![m3_id]);
    // Every message of this run; filters and limit.
    assert_eq!(search(&reader, &[&tag]).len(), 3);
    assert_eq!(search(&reader, &[&tag, "--account", R]).len(), 3);
    assert_eq!(search(&reader, &[&tag, "--folder", "inbox"]).len(), 3);
    assert!(search(&reader, &[&tag, "--folder", "Sent"]).is_empty());
    assert_eq!(search(&reader, &[&tag, "--limit", "2"]).len(), 2);
    assert!(search(&reader, &["nothingmatchesthis"]).is_empty());
    assert!(search(&reader, &["--", "-- ..."]).is_empty());
    let err = fails(
        &reader,
        &["search", &tag, "--account", "nobody@sealbox.test"],
        1,
    );
    assert!(err["error"].as_str().unwrap().contains("account not found"));
    // The index never touches the disk: the body word is in no profile file, the plaintext
    // subject (a documented plaintext column) is.
    assert!(!on_disk(&reader, &word), "body word found on disk");
    assert!(
        on_disk(&reader, &s1),
        "control: subjects are plaintext at rest"
    );

    // ----- drafts ------------------------------------------------------------------------
    let files = tempfile::tempdir().expect("tempdir");
    let attachment = temp_file(
        files.path(),
        "notes.txt",
        format!("attachment payload {tag}").as_bytes(),
    );
    let attachment = attachment.to_string_lossy().into_owned();
    let dtag = nonce("draft");
    let subject_v1 = format!("Draft v1 {dtag}");
    let subject_v2 = format!("Draft v2 {dtag}");
    let body = format!("draft body sealed {dtag}");
    let before = reader.json(&["profile", "status"]);
    let saved = reader.json(&[
        "draft",
        "save",
        "--from",
        R,
        "--to",
        A,
        "--subject",
        &subject_v1,
        "--body",
        &body,
        "--attach",
        &attachment,
    ]);
    let id = saved["id"].as_i64().expect("draft id");
    assert_eq!(saved["account"], R);
    assert_eq!(saved["kind"], "new");
    assert_eq!(saved["to"], serde_json::json!([A]));
    assert_eq!(saved["body_text"], body.as_str());
    assert_eq!(saved["attachments"][0]["name"], "notes.txt");
    assert_eq!(saved["attachments"][0]["content_type"], "text/plain");
    let id_s = id.to_string();
    // Listed, shown, updated by id (options not given keep their value).
    let listed = reader.json(&["draft", "list"]);
    assert!(
        listed.as_array().unwrap().iter().any(|d| d["id"] == id),
        "{listed}"
    );
    assert_eq!(
        reader.json(&["draft", "list", "--account", R])[0]["subject"],
        subject_v1.as_str()
    );
    let updated = reader.json(&["draft", "save", "--id", &id_s, "--subject", &subject_v2]);
    assert_eq!(updated["id"], id);
    assert_eq!(updated["subject"], subject_v2.as_str());
    assert_eq!(updated["body_text"], body.as_str(), "body kept");
    assert_eq!(updated["to"], serde_json::json!([A]), "recipients kept");
    let shown = reader.json(&["draft", "show", &id_s]);
    assert_eq!(shown["subject"], subject_v2.as_str());
    assert_eq!(shown["attachments"].as_array().unwrap().len(), 1);
    let text = reader.ok(&["draft", "show", &id_s]);
    assert!(text.contains(&subject_v2) && text.contains(&body), "{text}");
    // Sealed at rest like message bodies; counted by the profile status.
    let after = reader.json(&["profile", "status"]);
    assert_eq!(after["plaintext_rows"], 0, "{after}");
    assert_eq!(
        after["wrapped_rows"].as_u64().unwrap(),
        before["wrapped_rows"].as_u64().unwrap() + 2,
        "{before} → {after}"
    );
    for secret in [&subject_v1, &subject_v2, &body] {
        assert!(!on_disk(&reader, secret), "{secret:?} found on disk");
    }
    assert!(on_disk(&reader, A), "control: recipients are plaintext");

    // Send: encrypted (u74's key came by Autocrypt), the draft is gone, u74 decrypts it.
    let report = reader.json(&["draft", "send", &id_s]);
    assert_eq!(report["mode"], "encrypted", "{report}");
    assert_eq!(report["recipients"][0]["address"], A);
    assert!(reader
        .json(&["draft", "list"])
        .as_array()
        .unwrap()
        .iter()
        .all(|d| d["id"] != id));
    fails(&reader, &["draft", "show", &id_s], 2);
    let got = arrive(&senders, A, &subject_v2).await;
    let detail = senders.json(&[
        "read",
        &got["id"].as_i64().unwrap().to_string(),
        "--no-mark",
    ]);
    assert_eq!(detail["was_encrypted"], true);
    assert_eq!(detail["decrypted"], true);
    assert!(detail["text"].as_str().unwrap().contains(&body), "{detail}");
    assert_eq!(detail["attachments"][0]["filename"], "notes.txt");

    // A reply draft to the searched message, quoted.
    let rtag = nonce("reply");
    let reply_subject = format!("Re: {s1}");
    let reply = reader.json(&[
        "draft",
        "save",
        "--from",
        R,
        "--to",
        A,
        "--subject",
        &reply_subject,
        "--body",
        &format!("Will do. {rtag}"),
        "--in-reply-to",
        &m1_id.to_string(),
        "--quote",
    ]);
    assert_eq!(reply["kind"], "reply");
    assert_eq!(
        reply["in_reply_to"], m1["message_id"],
        "local id → Message-ID"
    );
    assert!(
        reply["id"].as_i64().unwrap() > id,
        "the sent draft's id was reused: {reply}"
    );
    let rid = reply["id"].as_i64().unwrap().to_string();
    let report = reader.json(&["draft", "send", &rid]);
    assert_eq!(report["mode"], "encrypted", "{report}");
    let got = arrive(&senders, A, &reply_subject).await;
    let detail = senders.json(&[
        "read",
        &got["id"].as_i64().unwrap().to_string(),
        "--no-mark",
    ]);
    assert_eq!(detail["in_reply_to"][0], m1["message_id"], "{detail}");
    let text = detail["text"].as_str().unwrap();
    assert!(text.contains(&rtag), "{text}");
    assert!(
        text.contains(&format!("> the {word} budget")),
        "quote: {text}"
    );

    // Delete; deleting twice and usage errors exit 2.
    let doomed = reader.json(&["draft", "save", "--from", R, "--subject", "doomed"]);
    let did = doomed["id"].as_i64().unwrap().to_string();
    let del = reader.json(&["draft", "delete", &did]);
    assert_eq!(del["deleted"], true);
    fails(&reader, &["draft", "delete", &did], 2);
    fails(&reader, &["draft", "save", "--subject", "no account"], 2);
    assert!(reader
        .json(&["draft", "list"])
        .as_array()
        .unwrap()
        .is_empty());
}
