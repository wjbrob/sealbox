//! The `sealbox-relay` binary's startup policy (threat-model R9), without docker: on a
//! non-loopback `--bind` it refuses to start unless an API token is set or `--allow-open-relay`
//! is given, and it refuses a malformed IMAP or webhook allow-list. Every refusal happens before
//! a port is bound, so these tests never listen beyond loopback. `bind_policy::decide` has the
//! full decision table as unit tests.

use std::{
    process::{Output, Stdio},
    time::Duration,
};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

const RELAY: &str = env!("CARGO_BIN_EXE_sealbox-relay");

/// A relay command with none of the relay's settings inherited from the environment.
fn relay() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(RELAY);
    for var in [
        "SEALBOX_RELAY_BIND",
        "SEALBOX_RELAY_API_TOKEN",
        "SEALBOX_RELAY_ALLOW_OPEN_RELAY",
        "SEALBOX_RELAY_WEBHOOK_ALLOW_PRIVATE",
        "SEALBOX_RELAY_WEBHOOK_ALLOW_HTTP_PRIVATE",
        "SEALBOX_RELAY_WEBHOOK_ALLOW_HOSTS",
        "SEALBOX_RELAY_IMAP_ALLOW_HOSTS",
        "SEALBOX_RELAY_IMAP_ALLOW_PRIVATE",
        "SEALBOX_RELAY_PARKED_TTL",
        "SEALBOX_RELAY_REGISTER_RATE_LIMIT",
        "SEALBOX_RELAY_MAX_REGISTRATIONS",
        "SEALBOX_RELAY_LOG",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd
}

/// Run to completion (a refusal exits at once); fails the test if it is still running after
/// 20 s, which would mean the relay started.
async fn run_to_exit(mut cmd: tokio::process::Command) -> (Output, String) {
    let out = tokio::time::timeout(Duration::from_secs(20), cmd.output())
        .await
        .expect("the relay should have refused to start, but it is still running")
        .expect("run the relay");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out, text)
}

#[tokio::test]
async fn refuses_an_open_relay_on_a_non_loopback_bind() {
    for bind in ["0.0.0.0:0", "[::]:0"] {
        let mut cmd = relay();
        cmd.args(["--bind", bind]);
        let (out, text) = run_to_exit(cmd).await;
        assert_eq!(
            out.status.code(),
            Some(2),
            "{bind}: started without a token:\n{text}"
        );
        assert!(text.contains("refusing to start"), "{bind}:\n{text}");
        assert!(text.contains("--allow-open-relay"), "{bind}:\n{text}");
        assert!(!text.contains("sealbox-relay listening"), "{bind}:\n{text}");
    }
    // A falsey environment value does not open it, and an empty token counts as none.
    let mut cmd = relay();
    cmd.args(["--bind", "0.0.0.0:0"])
        .env("SEALBOX_RELAY_ALLOW_OPEN_RELAY", "0")
        .env("SEALBOX_RELAY_API_TOKEN", "   ");
    let (out, text) = run_to_exit(cmd).await;
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("refusing to start"), "{text}");
}

#[tokio::test]
async fn refuses_a_malformed_webhook_allow_list_before_binding() {
    let mut cmd = relay();
    cmd.args([
        "--bind",
        "127.0.0.1:0",
        "--webhook-allow-hosts",
        "push.example,*.example.com",
    ]);
    let (out, text) = run_to_exit(cmd).await;
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("--webhook-allow-hosts"), "{text}");
    assert!(!text.contains("sealbox-relay listening"), "{text}");
}

#[tokio::test]
async fn refuses_a_malformed_imap_allow_list_before_binding() {
    for list in ["imap.gmail.com,*.office365.com", "imap.gmail.com:993"] {
        let mut cmd = relay();
        cmd.args(["--bind", "127.0.0.1:0", "--imap-allow-hosts", list]);
        let (out, text) = run_to_exit(cmd).await;
        assert_eq!(out.status.code(), Some(2), "{list}: {text}");
        assert!(text.contains("--imap-allow-hosts"), "{list}: {text}");
        assert!(!text.contains("sealbox-relay listening"), "{list}: {text}");
    }
    // The environment variable is parsed the same way.
    let mut cmd = relay();
    cmd.args(["--bind", "127.0.0.1:0"])
        .env("SEALBOX_RELAY_IMAP_ALLOW_HOSTS", "imaps://imap.gmail.com");
    let (out, text) = run_to_exit(cmd).await;
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("--imap-allow-hosts"), "{text}");
}

#[tokio::test]
async fn refuses_a_malformed_parked_ttl_before_binding() {
    for ttl in ["1 day", "-5", "24H"] {
        let mut cmd = relay();
        cmd.args(["--bind", "127.0.0.1:0", &format!("--parked-ttl={ttl}")]);
        let (out, text) = run_to_exit(cmd).await;
        assert_eq!(out.status.code(), Some(2), "{ttl}: {text}");
        assert!(text.contains("--parked-ttl"), "{ttl}: {text}");
        assert!(!text.contains("sealbox-relay listening"), "{ttl}: {text}");
    }
}

#[tokio::test]
async fn starts_open_on_loopback_with_a_warning_and_stops_on_sigterm() {
    let mut child = relay()
        .args(["--bind", "127.0.0.1:0", "--log-level", "info"])
        .spawn()
        .expect("spawn the relay");
    let pid = child.id().expect("child pid");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let mut head = String::new();
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(line) = stdout.next_line().await.expect("read stdout") {
            head.push_str(&line);
            head.push('\n');
            if line.contains("no API token configured") {
                return;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no loopback warning within 20 s:\n{head}"));
    assert!(head.contains("sealbox-relay listening"), "{head}");
    assert!(head.contains("authenticated=false"), "{head}");
    // The production IMAP and webhook policies are on by default.
    assert!(head.contains("imap_allow_private=false"), "{head}");
    assert!(head.contains("parked_ttl_secs=86400"), "{head}");
    assert!(head.contains("webhook_allow_private=false"), "{head}");
    assert!(!head.contains("OPEN RELAY"), "{head}");

    // SIGTERM to our own child only, identity checked first.
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).expect("child comm");
    assert_eq!(comm.trim(), "sealbox-relay", "pid {pid} is not our relay");
    let killed = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("run kill");
    assert!(killed.success());
    let mut stderr = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut stderr).await;
    }
    let exit = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .expect("the relay did not exit within 20 s of SIGTERM")
        .expect("wait");
    assert!(exit.success(), "{exit:?}\n{head}{stderr}");
}
