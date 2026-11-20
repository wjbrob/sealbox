//! The alias gotcha, pinned end to end: `account add --oauth` against an Outlook simulator
//! whose mailbox is an **alias**.
//!
//! The day this cost on a real Outlook.com account went into believing the sign-in had failed.
//! It had not: consent was given, the token was issued, and Outlook then refused
//! `AUTHENTICATE XOAUTH2` because the `user=` was an alias of the mailbox rather than its
//! primary address — answering `[AUTHENTICATIONFAILED]`, which is also what a wrong token gets.
//! Re-consenting, re-creating the app registration and re-checking the scopes all "failed" the
//! same way, because none of them was the problem.
//!
//! So this file asserts two things the CLI owes an owner in that position: the run still fails
//! (an alias really cannot sign in, and pretending otherwise would be worse), and the failure
//! says what to try next. The companion unit test for the refusal's shape is
//! `an_xoauth2_refusal_that_will_not_change_its_mind_is_the_alias_shape` in `sealbox-mail`, and
//! the wire-level one is `outlook_rejects_xoauth2_under_an_alias_even_with_a_good_token` in
//! `sealbox-fakeprov`.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use common::Profile;
use sealbox_core::providers::ProviderId;
use sealbox_fakeprov::{ProviderSim, Quirks};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const ALIAS: &str = "alias@fakeprov.test";
const PRIMARY: &str = "primary@fakeprov.test";

/// An Outlook fake that accepts XOAUTH2 only for [`PRIMARY`], serving the mailbox [`ALIAS`].
async fn outlook_with_an_alias() -> ProviderSim {
    let mut quirks = Quirks::for_provider(ProviderId::Outlook);
    quirks.account = ALIAS.to_string();
    quirks.primary_login = Some(PRIMARY.to_string());
    let sim = ProviderSim::start_with(quirks)
        .await
        .expect("start the fake");
    sim.seed_inbox(1);
    sim
}

/// One `account add --oauth microsoft …` run, with the browser played out. Returns
/// (exit code, the JSON event lines, all of stdout, stderr). Both streams are returned
/// because the event stream is one object per line while a failure's `{"error": …}` is
/// pretty-printed over several.
async fn add_oauth(
    sim: &ProviderSim,
    prof: &Profile,
    extra: &[&str],
) -> (i32, Vec<Value>, String, String) {
    let imap = format!("127.0.0.1:{}:plain", sim.imap_port);
    let smtp = format!("127.0.0.1:{}:plain", sim.smtp_port);
    let mut args: Vec<&str> = vec![
        "--json",
        "account",
        "add",
        "--email",
        ALIAS,
        "--name",
        "Alias Tester",
        "--oauth",
        "microsoft",
        "--client-id",
        "sealbox-sim-client",
        "--imap",
        &imap,
        "--smtp",
        &smtp,
        "--provider",
        "outlook",
        "--oauth-timeout",
        "60",
    ];
    args.extend_from_slice(extra);

    let mut cmd = prof.cmd(&args);
    cmd.env("SEALBOX_OAUTH_AUTH_URL", sim.idp.auth_url())
        .env("SEALBOX_OAUTH_TOKEN_URL", sim.idp.token_url())
        .env_remove("GOOGLE_OAUTH_CLIENT_SECRET")
        .env_remove("MICROSOFT_OAUTH_CLIENT_SECRET")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = tokio::process::Command::from(cmd)
        .kill_on_drop(true)
        .spawn()
        .expect("spawn account add --oauth");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();

    // The first event carries the URL to "open"; acting as the browser hands the code back to
    // the CLI's loopback listener. Everything after this point is post-consent.
    let start = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let line = lines
                .next_line()
                .await
                .expect("read stdout")
                .expect("stdout closed before oauth_start");
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if v["event"] == "oauth_start" {
                    return v;
                }
            }
        }
    })
    .await
    .expect("oauth_start");
    let url = start["url"].as_str().expect("url").to_string();
    let (status, headers, _) = http_get(&url).await;
    assert!(status.starts_with("HTTP/1.1 302"), "{status}");
    let (status, _, _) = http_get(&headers["location"]).await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");

    let mut events = vec![start];
    let mut stdout = String::new();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            events.push(v);
        }
        stdout.push_str(&line);
        stdout.push('\n');
    }
    let out = child.wait_with_output().await.expect("wait");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    eprintln!("--- stdout\n{stdout}--- stderr\n{stderr}");
    (out.status.code().unwrap_or(-1), events, stdout, stderr)
}

#[tokio::test]
async fn an_alias_mailbox_fails_and_the_cli_names_the_flag_that_fixes_it() {
    let sim = outlook_with_an_alias().await;
    let prof = Profile::new("oauth-alias");
    let (code, _, stdout, stderr) = add_oauth(&sim, &prof, &[]).await;

    assert_ne!(
        code, 0,
        "an alias cannot sign in; the CLI must not claim it did"
    );
    assert!(
        stdout.to_ascii_uppercase().contains("AUTHENTICATIONFAILED"),
        "the server's own words survive to the caller: {stdout}"
    );

    // The hint: what to try, and the flag to try it with.
    assert!(stderr.contains("--user <primary address>"), "{stderr}");
    assert!(
        stderr.contains("alias") && stderr.contains(ALIAS),
        "the hint names the possibility and the address it is about: {stderr}"
    );
    assert!(
        stderr.contains("token was issued"),
        "the part that did work has to be said, or the owner re-does it: {stderr}"
    );
    // It is a hint, not a claim: the server never told us the primary address, so the CLI must
    // not invent one.
    assert!(
        !stderr.contains(PRIMARY),
        "the CLI cannot know the primary address and must not pretend to: {stderr}"
    );
    // Nothing was half-stored.
    let v = prof.run(&["--json", "account", "list"]).json();
    assert_eq!(v.as_array().map(Vec::len), Some(0), "{v}");
}

#[tokio::test]
async fn the_same_mailbox_and_the_same_token_work_once_the_login_is_the_primary_address() {
    // Which is what makes the hint worth printing: nothing else about the account changes.
    let sim = outlook_with_an_alias().await;
    let prof = Profile::new("oauth-primary");
    let (code, events, _, stderr) = add_oauth(&sim, &prof, &["--user", PRIMARY]).await;

    assert_eq!(code, 0, "stderr:\n{stderr}");
    let added = events
        .iter()
        .find(|v| v["event"] == "account_added")
        .unwrap_or_else(|| panic!("no account_added event: {events:?}"));
    assert_eq!(added["account"]["email"], ALIAS, "{added}");
    assert_eq!(added["account"]["login"], PRIMARY, "{added}");
    assert_eq!(added["account"]["auth_kind"], "o_auth", "{added}");
    assert!(!stderr.contains("hint:"), "nothing to hint at: {stderr}");
}

#[tokio::test]
async fn a_wrong_login_that_is_not_an_alias_gets_the_same_hint_because_the_server_says_the_same() {
    // Honesty about the limit: the refusal for an alias and the refusal for a login that is
    // simply wrong are the same bytes, so the hint fires for both. It is phrased as a
    // possibility to test, which is all the server lets anyone say.
    let sim = outlook_with_an_alias().await;
    let prof = Profile::new("oauth-wrong-login");
    let (code, _, _, stderr) = add_oauth(&sim, &prof, &["--user", "nobody@fakeprov.test"]).await;

    assert_ne!(code, 0);
    assert!(stderr.contains("--user <primary address>"), "{stderr}");
    assert!(
        stderr.contains("`--user nobody@fakeprov.test`"),
        "the hint says which login was refused, so a typo is visible: {stderr}"
    );
}

/// Minimal HTTP GET, playing the browser in the OAuth flow.
async fn http_get(url: &str) -> (String, HashMap<String, String>, String) {
    let rest = url.strip_prefix("http://").expect("http url");
    let idx = rest.find(['/', '?']).unwrap_or(rest.len());
    let (hostport, tail) = rest.split_at(idx);
    let path = match tail.chars().next() {
        None => "/".to_string(),
        Some('?') => format!("/{tail}"),
        _ => tail.to_string(),
    };
    let mut s = TcpStream::connect(hostport).await.expect("connect");
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .expect("write request");
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.expect("read response");
    let text = String::from_utf8_lossy(&out).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut head_lines = head.lines();
    let status = head_lines.next().unwrap_or_default().to_string();
    let headers = head_lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    (status, headers, body.to_string())
}
