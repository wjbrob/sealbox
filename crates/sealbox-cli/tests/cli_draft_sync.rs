//! Saved drafts on the server (drafts_imap.rs), end to end through the `sealbox` CLI and
//! GreenMail (users u73 → u74; IMAP 127.0.0.1:3143, SMTP :3025, password `uNNpw`):
//!
//! * profile A (u73) saves a draft with a stored attachment: the Drafts folder holds exactly
//!   one message, flagged `\Draft`, whose raw bytes (fetched over IMAP here) contain neither
//!   the subject nor a 64-byte body marker nor the file; saving again keeps exactly one;
//! * profile B — the same account and key (A's profile copied before the draft existed) —
//!   runs `draft sync` and gets the draft, marked `(server)`, the attachment bytes intact;
//! * profile C — the same account, another key — sees the message but cannot read it
//!   (`unreadable`, nothing imported, nothing deleted);
//! * A sends the draft: its server copy is gone, and B's next `draft sync` drops it there.
//!
//! Needs `testing/mail_up.sh`. Run with
//! `cargo test -p sealbox-cli --test cli_draft_sync -- --ignored`. Shares u73/u74 with G27's
//! and G32's e2e tests: do not run them at the same time.

mod common;

use common::{imap_login, nonce, pseudo_random, temp_file, Profile};
use sealbox_mail::imap::FlagOp;

const A: &str = "u73@sealbox.test";
const DRAFTS: &str = "Drafts";

/// Every message in u73's Drafts folder as `(uid, flags, raw)` (an absent folder is empty).
async fn server_drafts() -> Vec<(u32, Vec<String>, Vec<u8>)> {
    let mut imap = imap_login("u73").await;
    if imap.select(DRAFTS).await.is_err() {
        let _ = imap.logout().await;
        return Vec::new();
    }
    let uids = imap.uid_search("ALL").await.expect("search");
    let out = imap
        .fetch_rfc822_batch(&uids)
        .await
        .expect("fetch")
        .into_iter()
        .map(|m| (m.uid, m.flags, m.raw))
        .collect();
    let _ = imap.logout().await;
    out
}

/// Empty u73's Drafts folder (GreenMail keeps state between runs).
async fn empty_drafts() {
    let mut imap = imap_login("u73").await;
    if imap.select(DRAFTS).await.is_ok() {
        let uids = imap.uid_search("ALL").await.expect("search");
        if !uids.is_empty() {
            imap.set_flags(&uids, FlagOp::Add, &["\\Deleted"])
                .await
                .expect("flag");
            imap.expunge().await.expect("expunge");
        }
    }
    let _ = imap.logout().await;
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// `draft sync --account u73 --json` → the one report.
fn sync(p: &Profile) -> serde_json::Value {
    let v = p.json(&["draft", "sync", "--account", A]);
    v.as_array()
        .and_then(|a| a.first())
        .cloned()
        .unwrap_or_else(|| panic!("no sync report: {v}"))
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn drafts_travel_encrypted_to_the_own_key() {
    empty_drafts().await;
    let a = Profile::new("draftsync-a-u73");
    a.add_greenmail_account("u73");
    // B: the same profile (account + key) before any draft existed.
    let mut b = Profile::new("draftsync-b-u73");
    b.passphrase = a.passphrase.clone();
    for e in std::fs::read_dir(a.path()).unwrap().flatten() {
        if e.path().is_file() {
            std::fs::copy(e.path(), b.path().join(e.file_name())).unwrap();
        }
    }
    let src = tempfile::tempdir().unwrap();
    let tag = nonce("draftsync");
    let subject = format!("draft sync subject {tag}");
    let marker = format!("{:x<64}", format!("DRAFTSYNCBODY-{tag}-"));
    assert_eq!(marker.len(), 64);
    let file_marker = format!("{:x<64}", format!("DRAFTSYNCFILE-{tag}-"));
    let mut file = file_marker.as_bytes().to_vec();
    file.extend(pseudo_random(3000, 74));

    // A saves a draft and attaches a stored copy: one server copy, \Draft, nothing readable.
    let id = a.json(&[
        "draft",
        "save",
        "--from",
        A,
        "--to",
        "u74@sealbox.test",
        "--subject",
        &subject,
        "--body",
        &marker,
        "--policy",
        "plaintext",
    ])["id"]
        .as_i64()
        .expect("draft id")
        .to_string();
    let path = temp_file(src.path(), "plan.bin", &file);
    a.ok(&["draft", "attach", &id, path.to_str().unwrap()]);
    let first = server_drafts().await;
    assert_eq!(first.len(), 1, "exactly one server copy");
    let (uid1, flags, raw) = &first[0];
    assert!(flags.iter().any(|f| f == "\\Draft"), "flags {flags:?}");
    for needle in [
        subject.as_bytes(),
        marker.as_bytes(),
        file_marker.as_bytes(),
    ] {
        assert!(
            !contains(raw, needle),
            "{} on the server in the clear",
            String::from_utf8_lossy(needle)
        );
    }
    assert!(contains(raw, b"X-Sealbox-Draft: "));
    assert!(contains(raw, b"multipart/encrypted"));
    // Saving again replaces it: still exactly one, a new UID.
    let body2 = format!("{marker} second version");
    a.ok(&["draft", "save", "--id", &id, "--body", &body2]);
    let second = server_drafts().await;
    assert_eq!(second.len(), 1, "still exactly one server copy");
    assert_ne!(second[0].0, *uid1, "the copy was replaced");
    let shown = a.ok(&["draft", "show", &id]);
    assert!(shown.contains("Server:   on the server"), "{shown}");

    // B (same key): `draft sync` imports it, attachment bytes intact.
    let r = sync(&b);
    assert_eq!(
        (r["imported"].as_u64(), r["unreadable"].as_u64()),
        (Some(1), Some(0)),
        "{r}"
    );
    let listed = b.ok(&["draft", "list"]);
    assert!(
        listed.contains("(server)") && listed.contains(&subject),
        "{listed}"
    );
    let drafts = b.json(&["draft", "list"]);
    let d = &drafts.as_array().expect("list")[0];
    assert_eq!(d["subject"].as_str(), Some(subject.as_str()));
    assert_eq!(d["body_text"].as_str(), Some(body2.as_str()));
    assert_eq!(d["to"][0].as_str(), Some("u74@sealbox.test"));
    let blob = d["attachments"][0]["blob_id"]
        .as_i64()
        .expect("a stored copy");
    assert_eq!(d["attachments"][0]["name"].as_str(), Some("plan.bin"));
    let (_, bytes) = b.engine().get_draft_blob(blob).expect("blob");
    assert_eq!(bytes, file, "attachment bytes intact");
    assert_eq!(
        sync(&b)["imported"].as_u64(),
        Some(0),
        "a second sync imports nothing"
    );

    // C (same account, another key): sees the copy, cannot read it, deletes nothing.
    let c = Profile::new("draftsync-c-u73");
    c.add_greenmail_account("u73");
    let r = sync(&c);
    assert_eq!(
        (r["imported"].as_u64(), r["unreadable"].as_u64()),
        (Some(0), Some(1)),
        "{r}"
    );
    assert_eq!(c.json(&["draft", "list"]).as_array().map(Vec::len), Some(0));
    assert_eq!(server_drafts().await.len(), 1, "C deleted nothing");

    // A sends it: the server copy is gone; B's next sync drops its copy.
    let rep = a.json(&["draft", "send", &id]);
    assert_eq!(rep["mode"], "plaintext", "{rep}");
    assert!(
        server_drafts().await.is_empty(),
        "the sent draft's server copy is gone"
    );
    let r = sync(&b);
    assert_eq!(r["removed_locally"].as_u64(), Some(1), "{r}");
    assert_eq!(b.json(&["draft", "list"]).as_array().map(Vec::len), Some(0));

    // A draft deleted on A goes from the server as well.
    let gone = a.json(&[
        "draft",
        "save",
        "--from",
        A,
        "--subject",
        "discard me",
        "--body",
        "x",
    ])["id"]
        .as_i64()
        .expect("id")
        .to_string();
    assert_eq!(server_drafts().await.len(), 1);
    a.ok(&["draft", "delete", &gone]);
    assert!(
        server_drafts().await.is_empty(),
        "the deleted draft's server copy is gone"
    );
    println!("draft sync: encrypted server copy, replaced on save, imported with the key, unreadable without, removed on send and delete");
}
