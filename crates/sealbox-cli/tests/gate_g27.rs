//! Gate G27 — secrets at rest, end to end through the `sealbox` CLI and GreenMail
//! (users u46–u50, IMAP 127.0.0.1:3143 / SMTP :3025 plain, password `uNNpw`):
//!
//! * a passphrase-keyed profile adds an account, receives real plaintext and encrypted mail
//!   with an attachment, and (a) its SQLite files contain no secret key, no password, no
//!   known body/attachment text and not the passphrase — while subjects stay plaintext;
//! * (b) a wrong passphrase fails with `ProfileLocked` (exit 5), prints nothing, writes nothing;
//! * (c) a legacy plaintext profile (written exactly as a pre-G27 build did) migrates on its
//!   first keyed open, and can never be opened unkeyed again;
//! * (d) `profile rewrap` to a new passphrase works and the old one stops working;
//! * (e) draft attachments (threat-model R16, users u73 → u74): `draft attach` keeps a sealed
//!   copy in the store whose bytes are never on disk in the clear — before or after
//!   `draft send` / `draft delete` — and the sent mail carries them intact.
//!
//! Needs `testing/mail_up.sh`. Run with
//! `cargo test -p sealbox-cli --test gate_g27 -- --ignored`.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{nonce, pseudo_random, temp_file, wait_until, Profile, Run, DOMAIN, IMAP, SMTP};

const LOCKED: i32 = 5;

/// Every byte of every file in the profile directory (db, WAL, SHM, salt).
fn profile_bytes(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).expect("read profile dir").flatten() {
        let p = e.path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if p.is_file() && (name.starts_with("sealbox.db") || name.starts_with("profile.")) {
            out.push((name, std::fs::read(&p).expect("read profile file")));
        }
    }
    assert!(
        out.iter().any(|(n, _)| n == "sealbox.db"),
        "no sealbox.db in {}",
        dir.display()
    );
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Files of the profile that contain `needle`.
fn leaks(dir: &Path, needle: &str) -> Vec<String> {
    profile_bytes(dir)
        .into_iter()
        .filter(|(_, b)| contains(b, needle.as_bytes()))
        .map(|(n, _)| n)
        .collect()
}

fn assert_no_leak(p: &Profile, needles: &[&str]) {
    for n in needles {
        let l = leaks(p.path(), n);
        assert!(
            l.is_empty(),
            "[{}] {n:?} found in plaintext in {l:?}",
            p.name
        );
    }
}

fn json_env(p: &Profile, args: &[&str], env: &[(&str, Option<&str>)]) -> serde_json::Value {
    let mut full = vec!["--json"];
    full.extend_from_slice(args);
    let r = p.run_env(&full, env);
    assert_eq!(
        r.code,
        0,
        "sealbox {} failed: {}\n{}",
        full.join(" "),
        r.stdout,
        r.stderr
    );
    r.json()
}

fn status(p: &Profile, env: &[(&str, Option<&str>)]) -> serde_json::Value {
    json_env(p, &["profile", "status"], env)
}

fn add_account_env(p: &Profile, user: &str, env: &[(&str, Option<&str>)]) {
    let email = format!("{user}@{DOMAIN}");
    let pw = format!("{user}pw");
    let v = json_env(
        p,
        &[
            "account",
            "add",
            "--email",
            &email,
            "--name",
            user,
            "--password",
            &pw,
            "--imap",
            IMAP,
            "--smtp",
            SMTP,
        ],
        env,
    );
    assert_eq!(v["email"], email);
}

/// Sync until a message with `subject` is in INBOX; returns its local id.
async fn wait_for(p: &Profile, user: &str, subject: &str, env: &[(&str, Option<&str>)]) -> i64 {
    let email = format!("{user}@{DOMAIN}");
    let found = wait_until(Duration::from_secs(30), || async {
        json_env(p, &["sync", "--account", &email], env);
        json_env(p, &["list", "--account", &email, "--limit", "200"], env)
            .as_array()
            .is_some_and(|a| a.iter().any(|m| m["subject"].as_str() == Some(subject)))
    })
    .await;
    assert!(found, "[{}] {subject:?} never arrived", p.name);
    json_env(p, &["list", "--account", &email, "--limit", "200"], env)
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|m| m["subject"].as_str() == Some(subject))
                .cloned()
        })
        .and_then(|m| m["id"].as_i64())
        .expect("message id")
}

fn locked(r: &Run, secrets: &[&str]) {
    assert_eq!(r.code, LOCKED, "expected ProfileLocked (exit 5): {r:?}");
    assert!(
        r.stdout.contains("profile locked") || r.stderr.contains("profile locked"),
        "{r:?}"
    );
    for s in secrets {
        assert!(
            !r.stdout.contains(s) && !r.stderr.contains(s),
            "{s:?} printed while locked"
        );
    }
}

fn db_bytes(dir: &Path) -> Vec<u8> {
    std::fs::read(dir.join("sealbox.db")).expect("db")
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn passphrase_profile_wraps_locks_and_rewraps() {
    let a = Profile::new("g27a");
    let b = Profile::new("g27b");
    let tag = nonce("g27");
    a.add_greenmail_account("u46");
    b.add_greenmail_account("u47");
    let st = status(&a, &[]);
    assert_eq!(st["source"], "passphrase", "{st}");
    assert_eq!(st["plaintext_rows"], 0, "{st}");
    assert!(st["wrapped_rows"].as_u64().unwrap() >= 2, "{st}");
    assert!(st["kdf"]
        .as_str()
        .unwrap()
        .starts_with("argon2id(m=65536,t=3,p=1)"));

    // A → B plaintext first contact (Autocrypt bootstrap), then B → A encrypted + attachment.
    let fc_subject = format!("g27 first contact {tag}");
    let fc_body = format!("G27FIRSTCONTACT-{tag}-plaintext-body");
    json_env(
        &a,
        &[
            "send",
            "--from",
            "u46@sealbox.test",
            "--to",
            "u47@sealbox.test",
            "--subject",
            &fc_subject,
            "--body",
            &fc_body,
            "--policy",
            "plaintext",
        ],
        &[],
    );
    let fc_id = wait_for(&b, "u47", &fc_subject, &[]).await;
    assert_eq!(
        b.json(&["read", "--no-mark", &fc_id.to_string()])["text"]
            .as_str()
            .unwrap()
            .trim(),
        fc_body
    );

    let subject = format!("g27 subject {tag}");
    let body = format!("G27BODY-{tag}-only-u46-may-read-this");
    let att_marker = format!("G27ATTACHMENT-{tag}");
    let mut blob = att_marker.as_bytes().to_vec();
    blob.extend(pseudo_random(2048, 27));
    blob.extend_from_slice(att_marker.as_bytes());
    let blob_path = temp_file(b.path(), "g27.bin", &blob);
    let r = b.json(&[
        "send",
        "--from",
        "u47@sealbox.test",
        "--to",
        "u46@sealbox.test",
        "--subject",
        &subject,
        "--body",
        &body,
        "--attach",
        blob_path.to_str().unwrap(),
    ]);
    assert_eq!(r["mode"], "encrypted", "{r}");
    std::fs::remove_file(&blob_path).unwrap();
    let id = wait_for(&a, "u46", &subject, &[]).await;
    let read = a.json(&["read", "--no-mark", &id.to_string()]);
    assert_eq!(read["was_encrypted"], true);
    assert_eq!(read["text"].as_str().unwrap().trim(), body);
    let out = a.path().join("..").join(format!("g27-att-{tag}.out"));
    a.ok(&[
        "attachment",
        "save",
        &id.to_string(),
        "0",
        out.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read(&out).unwrap(), blob);
    std::fs::remove_file(&out).unwrap();
    // B syncs its Sent copy too (decrypted body stored for B).
    json_env(&b, &["sync", "--account", "u47@sealbox.test"], &[]);

    // Guest link (G29): the guest passphrase kept in `guest_links.secret` is wrapped too.
    // Needs a sealbox-server; scripts/gate_g27.sh starts one and sets SEALBOX_G27_SERVER.
    let guest = match std::env::var("SEALBOX_G27_SERVER") {
        Ok(server) => {
            let gsubj = format!("g27 guest {tag}");
            let gbody = format!("G27GUESTBODY-{tag}");
            let r = json_env(
                &a,
                &[
                    "send",
                    "--from",
                    "u46@sealbox.test",
                    "--to",
                    "u50@sealbox.test",
                    "--subject",
                    &gsubj,
                    "--body",
                    &gbody,
                    "--policy",
                    "guest",
                ],
                &[("SEALBOX_SERVER_URL", Some(&server))],
            );
            assert_eq!(r["mode"], "guest_link", "{r}");
            let pass = r["guest"]["passphrase"]
                .as_str()
                .expect("passphrase")
                .to_owned();
            let mid = r["message_id"].as_str().expect("message_id").to_owned();
            assert!(pass.len() >= 16, "{r}");
            Some((server, pass, mid, gbody))
        }
        Err(_) => {
            eprintln!(
                "SKIP guest_links check: SEALBOX_G27_SERVER not set (scripts/gate_g27.sh sets it)"
            );
            None
        }
    };
    let guest_needles: Vec<String> = guest
        .as_ref()
        .map(|(_, pass, _, gbody)| vec![pass.clone(), gbody.clone()])
        .unwrap_or_default();

    // (a) the files on disk.
    for n in &guest_needles {
        assert_no_leak(&a, &[n]);
    }
    for p in [&a, &b] {
        assert_no_leak(
            p,
            &[
                &body,
                &fc_body,
                &att_marker,
                "u46pw",
                "u47pw",
                "PRIVATE KEY BLOCK",
                &p.passphrase,
            ],
        );
        let st = status(p, &[]);
        assert_eq!(st["plaintext_rows"], 0, "[{}] {st}", p.name);
    }
    // Positive control: what is documented to stay plaintext is found by the same grep.
    assert!(
        !leaks(a.path(), &subject).is_empty(),
        "grep control: subject should be plaintext"
    );
    assert!(!leaks(a.path(), "u46@sealbox.test").is_empty());

    // (b) wrong passphrase: ProfileLocked, nothing printed, nothing written.
    let before = db_bytes(a.path());
    let wrong = [("SEALBOX_PROFILE_PASSPHRASE", Some("not-the-passphrase"))];
    locked(
        &a.run_env(&["--json", "list", "--limit", "200"], &wrong),
        &[&subject, &body],
    );
    locked(
        &a.run_env(&["read", "--no-mark", &id.to_string()], &wrong),
        &[&subject, &body],
    );
    locked(&a.run_env(&["account", "list"], &wrong), &["u46pw"]);
    locked(&a.run_env(&["--json", "profile", "status"], &wrong), &[]);
    // Unkeyed / keyring sources cannot open it either (never downgrade).
    locked(
        &a.run_env(
            &["list"],
            &[
                ("SEALBOX_PROFILE_KEY", Some("none")),
                ("SEALBOX_ALLOW_PLAINTEXT_PROFILE", Some("1")),
            ],
        ),
        &[&subject],
    );
    locked(
        &a.run_env(
            &["list"],
            &[
                ("SEALBOX_PROFILE_KEY", Some("keyring")),
                ("SEALBOX_NO_KEYRING", Some("1")),
                ("SEALBOX_PROFILE_PASSPHRASE", None),
            ],
        ),
        &[&subject],
    );
    assert_eq!(
        db_bytes(a.path()),
        before,
        "a locked open modified the database"
    );

    // (d) rewrap to a new passphrase.
    let new_pp = format!("rewrapped-{tag}");
    let st = json_env(
        &a,
        &["profile", "rewrap", "--to", "passphrase"],
        &[("SEALBOX_PROFILE_NEW_PASSPHRASE", Some(&new_pp))],
    );
    assert_eq!(st["source"], "passphrase", "{st}");
    assert_eq!(st["plaintext_rows"], 0, "{st}");
    let old = a.run_env(&["--json", "list"], &[]);
    locked(&old, &[&subject]);
    let new_env = [("SEALBOX_PROFILE_PASSPHRASE", Some(new_pp.as_str()))];
    let read = json_env(&a, &["read", "--no-mark", &id.to_string()], &new_env);
    assert_eq!(read["text"].as_str().unwrap().trim(), body);
    // The wrapped IMAP credential still logs in.
    json_env(&a, &["sync", "--account", "u46@sealbox.test"], &new_env);
    // --profile-passphrase-env works as well.
    let r = a.run_env(
        &[
            "--profile-passphrase-env",
            "G27_PP",
            "--json",
            "profile",
            "status",
        ],
        &[
            ("G27_PP", Some(&new_pp)),
            ("SEALBOX_PROFILE_PASSPHRASE", None),
        ],
    );
    assert_eq!(r.code, 0, "{r:?}");
    assert_no_leak(
        &a,
        &[
            &body,
            &fc_body,
            &att_marker,
            "u46pw",
            "PRIVATE KEY BLOCK",
            &new_pp,
        ],
    );
    if let Some((server, pass, mid, _)) = &guest {
        for n in &guest_needles {
            assert_no_leak(&a, &[n]);
        }
        // The rewrapped guest secret still unwraps: a resend reports the same passphrase.
        let r = json_env(
            &a,
            &["guest", "resend", mid],
            &[
                ("SEALBOX_SERVER_URL", Some(server)),
                ("SEALBOX_PROFILE_PASSPHRASE", Some(new_pp.as_str())),
            ],
        );
        assert_eq!(
            r["guest"]["passphrase"].as_str(),
            Some(pass.as_str()),
            "{r}"
        );
        println!("G27 guest_links.secret: wrapped on disk, unwraps after rewrap");
    }
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn legacy_plaintext_profile_migrates_on_first_keyed_open() {
    let legacy_env: [(&str, Option<&str>); 3] = [
        ("SEALBOX_PROFILE_KEY", Some("none")),
        ("SEALBOX_ALLOW_PLAINTEXT_PROFILE", Some("1")),
        ("SEALBOX_PROFILE_PASSPHRASE", None),
    ];
    let c = Profile::new("g27c");
    let d = Profile::new("g27d");
    let tag = nonce("g27legacy");
    // Without the explicit allow flag a plaintext profile is refused outright.
    let r = c.run_env(
        &["account", "list"],
        &[
            ("SEALBOX_PROFILE_KEY", Some("none")),
            ("SEALBOX_ALLOW_PLAINTEXT_PROFILE", None),
        ],
    );
    assert_eq!(r.code, LOCKED, "{r:?}");

    add_account_env(&c, "u48", &legacy_env);
    d.add_greenmail_account("u49");
    let subject = format!("g27 legacy {tag}");
    let body = format!("G27LEGACYBODY-{tag}");
    let att_marker = format!("G27LEGACYATT-{tag}");
    let att_path = temp_file(d.path(), "legacy.txt", att_marker.as_bytes());
    json_env(
        &d,
        &[
            "send",
            "--from",
            "u49@sealbox.test",
            "--to",
            "u48@sealbox.test",
            "--subject",
            &subject,
            "--body",
            &body,
            "--attach",
            att_path.to_str().unwrap(),
            "--policy",
            "plaintext",
        ],
        &[],
    );
    let id = wait_for(&c, "u48", &subject, &legacy_env).await;

    // The fixture really is a plaintext (pre-G27-format) profile.
    let st = status(&c, &legacy_env);
    assert_eq!(st["source"], "none", "{st}");
    assert_eq!(st["wrapped_rows"], 0, "{st}");
    let legacy_plain = st["plaintext_rows"].as_u64().unwrap();
    assert!(legacy_plain >= 5, "{st}");
    assert!(
        st["fallback"].is_string(),
        "plaintext must be reported: {st}"
    );
    for n in [
        body.as_str(),
        "u48pw",
        "PRIVATE KEY BLOCK",
        att_marker.as_str(),
    ] {
        assert!(
            !leaks(c.path(), n).is_empty(),
            "legacy fixture should hold {n:?} in plaintext"
        );
    }

    // First keyed open migrates everything.
    let st = status(&c, &[]);
    assert_eq!(st["source"], "passphrase", "{st}");
    assert_eq!(st["plaintext_rows"], 0, "{st}");
    assert!(st["wrapped_rows"].as_u64().unwrap() >= legacy_plain, "{st}");
    assert_no_leak(
        &c,
        &[
            &body,
            "u48pw",
            "PRIVATE KEY BLOCK",
            &att_marker,
            &c.passphrase,
        ],
    );
    let read = c.json(&["read", "--no-mark", &id.to_string()]);
    assert!(read["text"].as_str().unwrap().contains(&body), "{read}");
    let out = c.path().join("..").join(format!("g27-legacy-{tag}.out"));
    c.ok(&[
        "attachment",
        "save",
        &id.to_string(),
        "0",
        out.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read(&out).unwrap(), att_marker.as_bytes());
    std::fs::remove_file(&out).unwrap();
    json_env(&c, &["sync", "--account", "u48@sealbox.test"], &[]);
    // ... and it is never opened unkeyed again, even with the allow flag.
    locked(&c.run_env(&["list"], &legacy_env), &[&subject]);
    locked(
        &c.run_env(&["list"], &[("SEALBOX_PROFILE_PASSPHRASE", Some("wrong"))]),
        &[&subject],
    );
}

/// (e) Draft attachments are sealed blobs in the store (threat-model R16), through the CLI
/// and GreenMail u73 → u74: `draft attach` stores the file sealed (the original may go),
/// `draft show` lists it as stored, `draft detach` removes one, a wrong passphrase reads
/// nothing, `draft send` delivers the exact bytes and removes draft and copy, `draft delete`
/// removes the copy too — and a 64-byte marker from the file is never on disk in the clear.
#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn draft_attachments_are_sealed_blobs() {
    let s = Profile::new("g27-drafts-u73");
    let r = Profile::new("g27-drafts-u74");
    let src = tempfile::tempdir().expect("source dir");
    let tag = nonce("g27drafts");
    s.add_greenmail_account("u73");
    r.add_greenmail_account("u74");
    let marker = format!("{:x<64}", format!("G27DRAFTBLOB-{tag}-"));
    assert_eq!(marker.len(), 64);
    let mut blob = marker.as_bytes().to_vec();
    blob.extend(pseudo_random(4096, 73));
    blob.extend_from_slice(marker.as_bytes());
    let subject = format!("g27 draft blob {tag}");
    let saved = s.json(&[
        "draft",
        "save",
        "--from",
        "u73@sealbox.test",
        "--to",
        "u74@sealbox.test",
        "--subject",
        &subject,
        "--body",
        "the plan is attached",
        "--policy",
        "plaintext",
    ]);
    let id = saved["id"].as_i64().expect("draft id").to_string();

    // attach: a sealed copy in the store; the original can go.
    let file = temp_file(src.path(), "plan.bin", &blob);
    let d = s.json(&["draft", "attach", &id, file.to_str().unwrap()]);
    let att = &d["attachments"][0];
    assert!(att["blob_id"].as_i64().is_some(), "{d}");
    assert_eq!(att["path"], "", "{d}");
    assert_eq!(att["name"], "plan.bin", "{d}");
    std::fs::remove_file(&file).unwrap();
    let extra_bytes = format!("{marker} extra");
    let extra = temp_file(src.path(), "extra.txt", extra_bytes.as_bytes());
    s.ok(&[
        "draft",
        "attach",
        &id,
        extra.to_str().unwrap(),
        "--name",
        "notes.txt",
    ]);
    std::fs::remove_file(&extra).unwrap();
    let shown = s.ok(&["draft", "show", &id]);
    assert!(
        shown.contains(&format!("[0] plan.bin  (stored, {} bytes)", blob.len())),
        "{shown}"
    );
    assert!(
        shown.contains(&format!(
            "[1] notes.txt  (stored, {} bytes)",
            extra_bytes.len()
        )),
        "{shown}"
    );
    // detach: the second one goes, with its copy; a number out of range is refused.
    let d = s.json(&["draft", "detach", &id, "1"]);
    assert_eq!(d["attachments"].as_array().map(Vec::len), Some(1), "{d}");
    let bad = s.run(&["draft", "detach", &id, "5"]);
    assert_ne!(bad.code, 0, "{bad:?}");
    assert!(bad.stderr.contains("has no attachment 5"), "{bad:?}");

    // On disk: neither file's bytes; nothing under draft-attachments/; names stay plaintext.
    assert_no_leak(&s, &[&marker, "u73pw", &s.passphrase]);
    assert!(!s.path().join("draft-attachments").exists());
    assert!(
        !leaks(s.path(), "plan.bin").is_empty(),
        "grep control: attachment names are plaintext"
    );
    assert_eq!(status(&s, &[])["plaintext_rows"], 0);
    // A wrong passphrase reads nothing.
    locked(
        &s.run_env(
            &["draft", "show", &id],
            &[("SEALBOX_PROFILE_PASSPHRASE", Some("not-the-passphrase"))],
        ),
        &[&subject, &marker],
    );

    // send: the mail carries the exact bytes; the draft and its copy are gone.
    let rep = s.json(&["draft", "send", &id]);
    assert_eq!(rep["mode"], "plaintext", "{rep}");
    assert_eq!(s.json(&["draft", "list"]).as_array().map(Vec::len), Some(0));
    let mid = wait_for(&r, "u74", &subject, &[]).await;
    let out = src.path().join(format!("g27-draft-{tag}.out"));
    r.ok(&[
        "attachment",
        "save",
        &mid.to_string(),
        "0",
        out.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read(&out).unwrap(), blob);
    // The sender's Sent copy is stored (sealed) as well.
    json_env(&s, &["sync", "--account", "u73@sealbox.test"], &[]);
    assert_no_leak(&s, &[&marker]);
    assert_no_leak(&r, &[&marker]);

    // delete: a discarded draft takes its stored copy along.
    let gone = s.json(&[
        "draft",
        "save",
        "--from",
        "u73@sealbox.test",
        "--subject",
        &format!("g27 discarded {tag}"),
        "--body",
        "never sent",
    ]);
    let gone = gone["id"].as_i64().expect("draft id").to_string();
    let again = temp_file(src.path(), "again.bin", &blob);
    s.ok(&["draft", "attach", &gone, again.to_str().unwrap()]);
    std::fs::remove_file(&again).unwrap();
    s.ok(&["draft", "delete", &gone]);
    assert_no_leak(&s, &[&marker]);
    for p in [&s, &r] {
        assert_eq!(status(p, &[])["plaintext_rows"], 0, "[{}]", p.name);
    }
    println!("G27 draft_blobs.data: sealed on disk, sent intact, removed with the draft");
}
