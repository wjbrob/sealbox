//! G35 — the mailbox converges with the server (`Engine::reconcile_folder`), end to end
//! against the shared GreenMail (`testing/mail_up.sh`), users **u81** and **u82**.
//!
//! The two tests take a user each because cargo runs them concurrently and each empties its
//! mailbox to start from a known state; sharing one would have them deleting each other's mail.
//!
//! The product's premise is the mailbox you already have, used *alongside* webmail and the
//! phone. Until this landed the sync only ever added: `FLAGS` were read inside the body fetch
//! of new UIDs and nothing removed a local message whose UID had gone, so mail deleted
//! elsewhere stayed for ever, mail read elsewhere stayed bold, and an emptied Trash stayed
//! full. A second IMAP session here plays "elsewhere".
//!
//! Run: `testing/mail_up.sh && cargo test -p sealbox-cli --test cli_reconcile -- --ignored`

mod common;

use common::{imap_login, Profile};
use sealbox_mail::imap::FlagOp;

/// The account each test owns: `(imap login, address)`.
const U81: (&str, &str) = ("u81", "u81@sealbox.test");
const U82: (&str, &str) = ("u82", "u82@sealbox.test");

fn raw(email: &str, subject: &str, n: u32) -> Vec<u8> {
    format!(
        "From: Bob <bob@sealbox.test>\r\nTo: {email}\r\nSubject: {subject}\r\n\
         Message-ID: <{subject}-{n}@sealbox.test>\r\n\
         Date: Mon, 2 Mar 2026 10:0{n}:00 +0000\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain\r\n\r\nmessage {n}\r\n"
    )
    .into_bytes()
}

/// INBOX UIDs as another client sees them, ascending.
async fn server_uids(user: &str) -> Vec<u32> {
    let mut imap = imap_login(user).await;
    imap.select("INBOX").await.expect("select");
    let mut uids = imap.fetch_new_uids(0).await.expect("search");
    let _ = imap.logout().await;
    uids.sort_unstable();
    uids
}

/// Empty the mailbox the way another client would, and seed `subjects` into it.
async fn reset_inbox((user, email): (&str, &str), subjects: &[&str]) {
    let mut imap = imap_login(user).await;
    imap.select("INBOX").await.expect("select");
    let existing = imap.fetch_new_uids(0).await.expect("search");
    if !existing.is_empty() {
        imap.set_flags(&existing, FlagOp::Add, &["\\Deleted"])
            .await
            .expect("mark deleted");
        imap.expunge().await.expect("expunge");
    }
    for (i, s) in subjects.iter().enumerate() {
        imap.append("INBOX", &raw(email, s, i as u32 + 1), &[])
            .await
            .expect("append");
    }
    let _ = imap.logout().await;
}

fn subjects(p: &Profile, email: &str) -> Vec<String> {
    let mut v: Vec<String> = p
        .list(Some(email), "INBOX")
        .into_iter()
        .filter_map(|m| m["subject"].as_str().map(str::to_owned))
        .collect();
    v.sort();
    v
}

fn inbox(report: &serde_json::Value) -> &serde_json::Value {
    report["folders"]
        .as_array()
        .expect("folders array")
        .iter()
        .find(|f| f["name"] == "INBOX")
        .expect("an INBOX entry in the report")
}

fn seen(p: &Profile, email: &str, subject: &str) -> bool {
    p.find_by_subject(Some(email), "INBOX", subject)["seen"]
        .as_bool()
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GreenMail: testing/mail_up.sh"]
async fn the_mailbox_converges_with_what_another_client_did() {
    let tag = common::nonce("rec");
    let (one, two, three) = (
        format!("{tag}-keep"),
        format!("{tag}-delete"),
        format!("{tag}-read"),
    );
    reset_inbox(U81, &[&one, &two, &three]).await;

    let p = Profile::new("reconcile");
    p.add_greenmail_account("u81");
    let first = p.sync("u81@sealbox.test");
    assert_eq!(
        subjects(&p, "u81@sealbox.test"),
        {
            let mut v = vec![one.clone(), two.clone(), three.clone()];
            v.sort();
            v
        },
        "all three stored by the first sync: {first}"
    );
    assert!(
        !seen(&p, "u81@sealbox.test", &three),
        "unread to begin with"
    );

    // --- another client deletes one message and reads another -----------------------------
    let uids = server_uids("u81").await;
    assert_eq!(uids.len(), 3, "three on the server");
    {
        let mut imap = imap_login("u81").await;
        imap.select("INBOX").await.expect("select");
        // uids are ascending and the append order was one, two, three.
        imap.set_flags(&uids[1..2], FlagOp::Add, &["\\Deleted"])
            .await
            .expect("delete the second");
        imap.expunge().await.expect("expunge");
        imap.set_flags(&uids[2..3], FlagOp::Add, &["\\Seen"])
            .await
            .expect("read the third");
        let _ = imap.logout().await;
    }

    let report = p.sync("u81@sealbox.test");
    let f = inbox(&report);
    assert_eq!(
        f["removed"], 1,
        "the expunged message was dropped: {report}"
    );
    assert_eq!(f["flags_changed"], 1, "the read message followed: {report}");
    let mut want = vec![one.clone(), three.clone()];
    want.sort();
    assert_eq!(
        subjects(&p, "u81@sealbox.test"),
        want,
        "the deleted message is gone locally"
    );
    assert!(
        seen(&p, "u81@sealbox.test", &three),
        "read elsewhere, no longer bold here: {report}"
    );

    // --- and it is converged: a further sync changes nothing -------------------------------
    let again = p.sync("u81@sealbox.test");
    let f = inbox(&again);
    assert_eq!(f["removed"], 0, "{again}");
    assert_eq!(f["flags_changed"], 0, "nothing left to do: {again}");

    // --- an emptied mailbox empties locally (the "Trash stays full" case) ------------------
    reset_inbox(U81, &[]).await;
    let emptied = p.sync("u81@sealbox.test");
    assert_eq!(inbox(&emptied)["removed"], 2, "{emptied}");
    assert!(
        subjects(&p, "u81@sealbox.test").is_empty(),
        "nothing stored for an empty mailbox: {:?}",
        subjects(&p, "u81@sealbox.test")
    );
}

/// `sealbox reconcile` on its own: no new mail is fetched, and the convergence still happens.
/// This is the path a client takes when it only wants to catch up with other clients.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GreenMail: testing/mail_up.sh"]
async fn reconcile_alone_converges_without_fetching_new_mail() {
    let tag = common::nonce("rec1");
    let (a, b) = (format!("{tag}-a"), format!("{tag}-b"));
    reset_inbox(U82, &[&a]).await;

    let p = Profile::new("reconcile-only");
    p.add_greenmail_account("u82");
    p.sync("u82@sealbox.test");
    assert_eq!(subjects(&p, "u82@sealbox.test"), vec![a.clone()]);

    // Another client appends one message (new mail) and deletes the one we hold.
    {
        let mut imap = imap_login("u82").await;
        imap.select("INBOX").await.expect("select");
        let uids = imap.fetch_new_uids(0).await.expect("search");
        imap.append("INBOX", &raw(U82.1, &b, 2), &[])
            .await
            .expect("append");
        imap.set_flags(&uids, FlagOp::Add, &["\\Deleted"])
            .await
            .expect("delete");
        imap.expunge().await.expect("expunge");
        let _ = imap.logout().await;
    }

    let out = p.json(&[
        "reconcile",
        "--account",
        "u82@sealbox.test",
        "--folder",
        "INBOX",
    ]);
    let report = out
        .as_array()
        .and_then(|a| a.first().cloned())
        .unwrap_or(out);
    assert_eq!(inbox(&report)["removed"], 1, "{report}");
    assert_eq!(
        inbox(&report)["new"],
        0,
        "reconcile fetches nothing: {report}"
    );
    assert!(
        subjects(&p, "u82@sealbox.test").is_empty(),
        "the deleted message went and the new one was not fetched: {:?}",
        subjects(&p, "u82@sealbox.test")
    );
}
