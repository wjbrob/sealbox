//! The transport policy (docs/THREAT_MODEL.md R12, R14) at the IMAP client, against scripted
//! servers on loopback (no docker, so these run with every `cargo test`):
//!
//! * an OAuth token is never sent to a server that does not advertise `AUTH=XOAUTH2` — neither
//!   as a `LOGIN` password nor at all (`ImapError::XOAuth2NotOffered`);
//! * when `AUTH=XOAUTH2` is advertised, the token goes through `AUTHENTICATE XOAUTH2` only;
//! * a token for a host outside its provider's domains, and plaintext towards a public host,
//!   are refused before a connection is even opened.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use sealbox_mail::imap::{ImapClient, AUTH_XOAUTH2};
use sealbox_mail::oauth::Provider;
use sealbox_mail::{Auth, BearerScope, ConnectOptions, ImapError, Security, TransportPolicyError};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const TOKEN: &str = "ya29.scripted-token-5b1e";

/// What the scripted server answers to `AUTHENTICATE XOAUTH2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Xoauth2 {
    /// Not advertised (`AUTH=XOAUTH2` missing from CAPABILITY); `AUTHENTICATE` gets `NO`.
    NotOffered,
    /// Advertised; the bearer `TOKEN` is accepted.
    Accept,
    /// Advertised; any token is refused the way Gmail does it (error challenge, then `NO`).
    Reject,
}

/// One-connection IMAP server. Returns the port and every line the client sent.
async fn scripted_server(mode: Xoauth2) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        let Ok((sock, _)) = listener.accept().await else {
            return;
        };
        let (rd, mut wr) = sock.into_split();
        let mut lines = BufReader::new(rd).lines();
        let _ = wr.write_all(b"* OK scripted IMAP ready\r\n").await;
        let caps = match mode {
            Xoauth2::NotOffered => "IMAP4rev1 IDLE UIDPLUS",
            Xoauth2::Accept | Xoauth2::Reject => "IMAP4rev1 IDLE UIDPLUS AUTH=XOAUTH2 AUTH=PLAIN",
        };
        while let Ok(Some(line)) = lines.next_line().await {
            log.lock().unwrap().push(line.clone());
            let mut parts = line.splitn(3, ' ');
            let tag = parts.next().unwrap_or("*").to_owned();
            let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
            let arg = parts.next().unwrap_or("").to_owned();
            let reply = match cmd.as_str() {
                "CAPABILITY" => format!("* CAPABILITY {caps}\r\n{tag} OK CAPABILITY done\r\n"),
                "LOGIN" => format!("{tag} OK LOGIN done\r\n"),
                "AUTHENTICATE"
                    if arg.eq_ignore_ascii_case("XOAUTH2") && mode != Xoauth2::NotOffered =>
                {
                    let _ = wr.write_all(b"+ \r\n").await;
                    let Ok(Some(resp)) = lines.next_line().await else {
                        break;
                    };
                    log.lock().unwrap().push(resp.clone());
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(resp.trim())
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                        .unwrap_or_default();
                    log.lock().unwrap().push(format!("decoded: {decoded}"));
                    let good =
                        decoded == format!("user=u@gmail.com\x01auth=Bearer {TOKEN}\x01\x01");
                    if mode == Xoauth2::Accept && good {
                        format!("{tag} OK AUTHENTICATE done\r\n")
                    } else {
                        // Gmail: base64 JSON error challenge, the client answers empty, then NO.
                        let err = base64::engine::general_purpose::STANDARD
                            .encode(r#"{"status":"400","schemes":"Bearer","scope":"https://mail.google.com/"}"#);
                        let _ = wr.write_all(format!("+ {err}\r\n").as_bytes()).await;
                        let Ok(Some(empty)) = lines.next_line().await else {
                            break;
                        };
                        log.lock().unwrap().push(empty);
                        format!("{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n")
                    }
                }
                "AUTHENTICATE" => format!("{tag} NO unsupported mechanism\r\n"),
                "LOGOUT" => {
                    let _ = wr
                        .write_all(format!("* BYE bye\r\n{tag} OK LOGOUT done\r\n").as_bytes())
                        .await;
                    break;
                }
                _ => format!("{tag} OK done\r\n"),
            };
            if wr.write_all(reply.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    (port, seen)
}

fn token_auth() -> Auth {
    Auth::XOAuth2 {
        user: "u@gmail.com".into(),
        access_token: TOKEN.into(),
    }
}

/// A token from a loopback mock IdP: local hosts (the scripted server) are acceptable.
fn dev_opts() -> ConnectOptions {
    ConnectOptions::new(Duration::from_secs(5)).with_bearer(Some(BearerScope {
        provider: Provider::Google,
        dev_idp: true,
    }))
}

fn wire(seen: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    seen.lock().unwrap().clone()
}

#[tokio::test]
async fn no_xoauth2_advertised_means_no_token_and_no_login_fallback() {
    let (port, seen) = scripted_server(Xoauth2::NotOffered).await;
    let err = ImapClient::connect_with(
        "127.0.0.1",
        port,
        Security::Plain,
        token_auth(),
        &dev_opts(),
    )
    .await
    .expect_err("must refuse");
    match &err {
        ImapError::XOAuth2NotOffered { host } => assert_eq!(host, "127.0.0.1"),
        other => panic!("expected XOAuth2NotOffered, got {other:?}"),
    }
    let text = err.to_string();
    assert!(text.contains("does not offer OAuth sign-in"), "{text}");
    assert!(
        text.contains("never sends an OAuth token as a password"),
        "{text}"
    );
    // Give the server a moment to log anything that might still arrive.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let lines = wire(&seen);
    assert!(
        lines.iter().any(|l| l.ends_with("CAPABILITY")),
        "pre-login CAPABILITY was asked: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| {
            let u = l.to_ascii_uppercase();
            u.contains(" LOGIN ") || u.contains("AUTHENTICATE")
        }),
        "no login of any kind may be attempted: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains(TOKEN)),
        "token on the wire: {lines:?}"
    );
}

#[tokio::test]
async fn advertised_xoauth2_is_used_through_authenticate() {
    let (port, seen) = scripted_server(Xoauth2::Accept).await;
    let client = ImapClient::connect_with(
        "127.0.0.1",
        port,
        Security::Plain,
        token_auth(),
        &dev_opts(),
    )
    .await
    .expect("XOAUTH2 login");
    assert_eq!(client.auth_mechanism(), AUTH_XOAUTH2);
    assert!(client
        .preauth_capabilities()
        .iter()
        .any(|c| c.eq_ignore_ascii_case("AUTH=XOAUTH2")));
    client.logout().await.expect("logout");
    let lines = wire(&seen);
    assert!(
        lines
            .iter()
            .any(|l| l.to_ascii_uppercase().ends_with("AUTHENTICATE XOAUTH2")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l == &format!("decoded: user=u@gmail.com\x01auth=Bearer {TOKEN}\x01\x01")),
        "the SASL initial response carries the bearer: {lines:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|l| l.to_ascii_uppercase().contains(" LOGIN ")),
        "{lines:?}"
    );
}

#[tokio::test]
async fn rejected_xoauth2_is_an_auth_error() {
    let (port, _seen) = scripted_server(Xoauth2::Reject).await;
    let err = ImapClient::connect_with(
        "127.0.0.1",
        port,
        Security::Plain,
        token_auth(),
        &dev_opts(),
    )
    .await
    .expect_err("rejected");
    assert!(
        matches!(
            err,
            ImapError::LoginRejected {
                mechanism: "XOAUTH2",
                ..
            }
        ),
        "{err:?}"
    );
    assert!(!err.to_string().contains(TOKEN), "{err}");
}

/// A listener that records whether anybody connected within `wait`.
async fn watch_for_connections(wait: Duration) -> (u16, tokio::task::JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let task =
        tokio::spawn(async move { tokio::time::timeout(wait, listener.accept()).await.is_ok() });
    (port, task)
}

#[tokio::test]
async fn token_for_a_foreign_host_is_refused_before_connecting() {
    // A real (non-dev) Google token must not go to 127.0.0.1 — nor anywhere outside Google.
    let (port, connected) = watch_for_connections(Duration::from_millis(500)).await;
    let opts = ConnectOptions::new(Duration::from_secs(5))
        .with_bearer(Some(BearerScope::new(Provider::Google)));
    let err = ImapClient::connect_with("127.0.0.1", port, Security::Plain, token_auth(), &opts)
        .await
        .expect_err("mismatch");
    assert!(
        matches!(
            &err,
            ImapError::Policy(TransportPolicyError::OAuthHostMismatch {
                provider: Some(Provider::Google),
                host
            }) if host == "127.0.0.1"
        ),
        "{err:?}"
    );
    assert!(err.to_string().contains("gmail.com"), "{err}");
    assert!(!connected.await.unwrap(), "a connection was opened");

    // The legacy constructor (no scope) refuses local hosts for tokens too.
    let (port, connected) = watch_for_connections(Duration::from_millis(500)).await;
    let err = ImapClient::connect_with_timeout(
        "127.0.0.1",
        port,
        Security::Plain,
        token_auth(),
        Duration::from_secs(5),
    )
    .await
    .expect_err("unscoped");
    assert!(
        matches!(
            err,
            ImapError::Policy(TransportPolicyError::OAuthHostMismatch { provider: None, .. })
        ),
        "{err:?}"
    );
    assert!(!connected.await.unwrap(), "a connection was opened");

    // A Microsoft token for a Google host.
    let ms = ConnectOptions::new(Duration::from_secs(5))
        .with_bearer(Some(BearerScope::new(Provider::Microsoft)));
    let err = ImapClient::connect_with("imap.gmail.com", 993, Security::Tls, token_auth(), &ms)
        .await
        .expect_err("cross-provider");
    assert!(
        matches!(
            err,
            ImapError::Policy(TransportPolicyError::OAuthHostMismatch {
                provider: Some(Provider::Microsoft),
                ..
            })
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn plaintext_to_a_public_host_is_refused_before_connecting() {
    let password = || Auth::Password {
        user: "u".into(),
        pass: "secret".into(),
    };
    for host in ["192.0.2.1", "imap.example.com", "8.8.8.8", "100.64.0.1"] {
        let started = Instant::now();
        let err = ImapClient::connect_with_timeout(
            host,
            143,
            Security::Plain,
            password(),
            Duration::from_secs(3),
        )
        .await
        .expect_err(host);
        assert!(
            matches!(
                &err,
                ImapError::Policy(TransportPolicyError::InsecureTransportRefused { host: h, port: 143 })
                    if h == host
            ),
            "{host}: {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{host}: refused without dialling ({:?})",
            started.elapsed()
        );
        let text = err.to_string();
        assert!(
            text.contains(&format!("SEALBOX_ALLOW_PLAIN_HOSTS={host}")),
            "{text}"
        );
    }
    // Loopback plaintext still works (the scripted server, a password login).
    let (port, _seen) = scripted_server(Xoauth2::NotOffered).await;
    let client = ImapClient::connect_with_timeout(
        "127.0.0.1",
        port,
        Security::Plain,
        password(),
        Duration::from_secs(5),
    )
    .await
    .expect("loopback plaintext is allowed");
    client.logout().await.expect("logout");
}
