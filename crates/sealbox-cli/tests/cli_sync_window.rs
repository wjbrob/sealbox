//! `sealbox sync --window N` / `--backfill` and the per-batch progress lines, end to end
//! against the PERFORMANCE GreenMail (`testing/mail_perf_up.sh`: 127.0.0.1:3243, user p03 —
//! docs/PERFORMANCE.md; the shared instance is never seeded): 30 seeded messages
//! (`testing/seed_mailbox.py`, the realistic mix), a first sync of the newest 10, newest
//! first, then the rest backfilled by a later sync; the report says what is still missing and
//! stderr carries one progress event per stored batch.
//!
//! Run: `testing/mail_perf_up.sh && cargo test -p sealbox-cli --test cli_sync_window -- --ignored`

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::Profile;
use serde_json::Value;

const USER: &str = "p03";
const PASSWORD: &str = "p03pw";
const EMAIL: &str = "p03@sealbox.test";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn python(args: &[&str]) -> String {
    let out = Command::new("python3")
        .arg("-I")
        .args(args)
        .current_dir(repo())
        .output()
        .expect("python3");
    assert!(
        out.status.success(),
        "python3 {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn empty_inbox() {
    python(&[
        "testing/gm_expunge.py",
        USER,
        PASSWORD,
        "INBOX",
        "127.0.0.1",
        "3243",
    ]);
}

/// The `sync_progress` events a run printed on stderr.
fn events(stderr: &str) -> Vec<Value> {
    stderr
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["event"] == "sync_progress")
        .collect()
}

#[test]
#[ignore = "needs the perf GreenMail: testing/mail_perf_up.sh"]
fn first_sync_takes_the_newest_window_and_later_syncs_backfill_the_rest() {
    empty_inbox();
    let seeded = python(&[
        "testing/seed_mailbox.py",
        "--user",
        USER,
        "--password",
        PASSWORD,
        "--port",
        "3243",
        "--count",
        "30",
        "--span",
        "30",
    ]);
    assert!(seeded.contains("seeded 30 messages"), "{seeded}");
    let p = Profile::new("syncwindow");
    p.json(&[
        "account",
        "add",
        "--email",
        EMAIL,
        "--name",
        "P03",
        "--password",
        PASSWORD,
        "--imap",
        "127.0.0.1:3243:plain",
        "--smtp",
        "127.0.0.1:3125:plain",
    ]);

    // First sync: the newest 10 only, reported per batch on stderr.
    let r = p.run(&["--json", "sync", "--account", EMAIL, "--window", "10"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let rep = &r.json()[0];
    assert_eq!(rep["new"], 10, "{rep}");
    let inbox = &rep["folders"][0];
    assert_eq!(inbox["name"], "INBOX");
    assert_eq!(inbox["more_to_backfill"], true, "{rep}");
    assert_eq!(inbox["older_pending"], 20, "{rep}");
    let ev = events(&r.stderr);
    assert!(!ev.is_empty(), "no progress events: {}", r.stderr);
    for e in &ev {
        assert_eq!(e["phase"], "initial", "{e}");
        assert_eq!(e["total_known"], 30, "{e}");
        assert!(e["t_ms"].is_u64(), "{e}");
    }
    let last = ev.last().unwrap();
    assert_eq!(
        (last["local"].as_u64(), last["planned"].as_u64()),
        (Some(10), Some(10))
    );
    // The newest mail is what got stored: the seeder's dates ascend with the UIDs.
    let rows = p.list(Some(EMAIL), "INBOX");
    let mut uids: Vec<u64> = rows.iter().filter_map(|m| m["uid"].as_u64()).collect();
    uids.sort_unstable();
    let top = uids.last().copied().unwrap();
    assert_eq!(uids, (top - 9..=top).collect::<Vec<_>>());

    // A later sync backfills (default 1,000 per sync): everything is there afterwards, and
    // --backfill has nothing left to do.
    let r = p.run(&["--json", "sync", "--account", EMAIL, "--backfill"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let rep = &r.json()[0];
    assert_eq!(rep["new"], 20, "{rep}");
    assert_eq!(rep["folders"][0]["more_to_backfill"], false, "{rep}");
    assert_eq!(rep["folders"][0]["older_pending"], 0, "{rep}");
    let ev = events(&r.stderr);
    assert!(ev.iter().all(|e| e["phase"] == "backfill"), "{ev:?}");
    assert_eq!(ev.last().unwrap()["local"], 30);
    assert_eq!(p.list(Some(EMAIL), "INBOX").len(), 30);

    // Human output: the report line; nothing fetched, so no progress lines.
    let r = p.run(&["sync", "--account", EMAIL]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("INBOX +0"), "{}", r.stdout);
    assert!(!r.stdout.contains("backfill"), "{}", r.stdout);
    assert!(!r.stderr.contains("fetched"), "{}", r.stderr);
    empty_inbox();
}
