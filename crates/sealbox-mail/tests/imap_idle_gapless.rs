//! `ImapClient::idle_wait_gapless` against a scripted IMAP server on loopback (no docker, so
//! these run in G0 with every `cargo test`).
//!
//! The behaviour under test was observed on GreenMail 2.1.3 (2026-10-29): mail that lands
//! between `EXAMINE` and `IDLE` is announced as `* n EXISTS` / `* n RECENT` *before* the `+`
//! continuation. async-imap queues those as unsolicited responses, so plain `idle_wait` does
//! not wake for them; `idle_wait_gapless` must.

use std::time::{Duration, Instant};

use sealbox_mail::imap::{IdleEvent, ImapClient};
use sealbox_mail::{Auth, Security};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

/// What the fake server does when the client sends `IDLE`.
#[derive(Clone, Copy, Debug)]
enum IdleScript {
    /// `* 2 EXISTS` and `* 1 RECENT` before the `+` (mail arrived between two commands).
    AnnounceBeforeContinuation,
    /// `+`, then silence until `DONE`.
    Quiet,
    /// `+`, then `* OK Still here` every 100 ms until `DONE`.
    KeepAlives,
    /// `+`, then `* 3 EXISTS` after 200 ms.
    AnnounceDuringIdle,
}

/// Accept one connection and play a minimal IMAP server. `NOOP` is answered with
/// `* 2 EXISTS`, which leaves a stale entry in the client's unsolicited queue.
/// Returns the port and a handle yielding every line the client sent.
async fn fake_server(script: IdleScript) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.expect("accept");
        let (rd, mut wr) = sock.into_split();
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let writer = tokio::spawn(async move {
            while let Some(s) = rx.recv().await {
                if wr.write_all(s.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        let _ = tx.send("* OK fake IMAP ready\r\n".into());
        let mut lines = BufReader::new(rd).lines();
        let mut seen = Vec::new();
        let mut idle: Option<(String, Option<oneshot::Sender<()>>)> = None;
        while let Ok(Some(line)) = lines.next_line().await {
            seen.push(line.clone());
            if line.eq_ignore_ascii_case("DONE") {
                if let Some((tag, stop)) = idle.take() {
                    drop(stop);
                    let _ = tx.send(format!("{tag} OK IDLE terminated\r\n"));
                }
                continue;
            }
            let mut parts = line.splitn(3, ' ');
            let tag = parts.next().unwrap_or("*").to_owned();
            let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
            let reply = match cmd.as_str() {
                "CAPABILITY" => {
                    format!("* CAPABILITY IMAP4rev1 IDLE\r\n{tag} OK CAPABILITY completed\r\n")
                }
                "LOGIN" => format!("{tag} OK LOGIN completed\r\n"),
                "EXAMINE" | "SELECT" => format!(
                    "* 1 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 7] UIDs valid\r\n\
                     * OK [UIDNEXT 2] Predicted next UID\r\n{tag} OK [READ-ONLY] EXAMINE completed\r\n"
                ),
                "NOOP" => format!("* 2 EXISTS\r\n{tag} OK NOOP completed\r\n"),
                "LOGOUT" => {
                    let _ = tx.send(format!("* BYE logging out\r\n{tag} OK LOGOUT completed\r\n"));
                    break;
                }
                "IDLE" => {
                    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
                    match script {
                        IdleScript::AnnounceBeforeContinuation => {
                            let _ = tx.send("* 2 EXISTS\r\n* 1 RECENT\r\n+ idling\r\n".into());
                        }
                        IdleScript::Quiet => {
                            let _ = tx.send("+ idling\r\n".into());
                        }
                        IdleScript::KeepAlives => {
                            let _ = tx.send("+ idling\r\n".into());
                            let tx = tx.clone();
                            tokio::spawn(async move {
                                loop {
                                    tokio::select! {
                                        _ = &mut stop_rx => break,
                                        _ = tokio::time::sleep(Duration::from_millis(100)) => {
                                            let _ = tx.send("* OK Still here\r\n".into());
                                        }
                                    }
                                }
                            });
                        }
                        IdleScript::AnnounceDuringIdle => {
                            let _ = tx.send("+ idling\r\n".into());
                            let tx = tx.clone();
                            tokio::spawn(async move {
                                tokio::select! {
                                    _ = &mut stop_rx => {}
                                    _ = tokio::time::sleep(Duration::from_millis(200)) => {
                                        let _ = tx.send("* 3 EXISTS\r\n".into());
                                    }
                                }
                            });
                        }
                    }
                    idle = Some((tag, Some(stop_tx)));
                    continue;
                }
                _ => format!("{tag} BAD unknown command\r\n"),
            };
            let _ = tx.send(reply);
        }
        drop(tx);
        let _ = writer.await;
        seen
    });
    (port, task)
}

async fn connect(port: u16) -> ImapClient {
    let mut client = ImapClient::connect_with_timeout(
        "127.0.0.1",
        port,
        Security::Plain,
        Auth::Password {
            user: "u".into(),
            pass: "p".into(),
        },
        Duration::from_secs(5),
    )
    .await
    .expect("connect to the fake server");
    assert!(client.has_capability("IDLE"), "{:?}", client.capabilities());
    client.examine("INBOX").await.expect("examine");
    client
}

#[tokio::test]
async fn mail_announced_while_entering_idle_wakes_at_once() {
    let (port, server) = fake_server(IdleScript::AnnounceBeforeContinuation).await;
    let mut client = connect(port).await;
    let started = Instant::now();
    let event = client
        .idle_wait_gapless(Duration::from_secs(30))
        .await
        .expect("idle");
    assert_eq!(event, IdleEvent::NewData);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    // DONE was sent and the session is usable again.
    client.noop().await.expect("noop after idle");
    client.logout().await.expect("logout");
    let seen = server.await.expect("server");
    assert!(seen.iter().any(|l| l == "DONE"), "{seen:?}");
}

/// Characterisation of the gap `idle_wait_gapless` exists for: plain `idle_wait` does not see
/// what the server announced before the continuation. If an async-imap upgrade makes this
/// fail, the gap is fixed upstream; keep the gapless variant's test and drop this one.
#[tokio::test]
async fn plain_idle_wait_misses_mail_announced_while_entering() {
    let (port, server) = fake_server(IdleScript::AnnounceBeforeContinuation).await;
    let mut client = connect(port).await;
    let event = client
        .idle_wait(Duration::from_millis(400))
        .await
        .expect("idle");
    assert_eq!(event, IdleEvent::Timeout);
    client.logout().await.expect("logout");
    server.await.expect("server");
}

#[tokio::test]
async fn stale_queued_responses_do_not_wake() {
    let (port, server) = fake_server(IdleScript::Quiet).await;
    let mut client = connect(port).await;
    // The NOOP answer (`* 2 EXISTS`) lands in the unsolicited queue: stale by the time we idle.
    client.noop().await.expect("noop");
    let started = Instant::now();
    let event = client
        .idle_wait_gapless(Duration::from_millis(300))
        .await
        .expect("idle");
    assert_eq!(event, IdleEvent::Timeout);
    assert!(started.elapsed() >= Duration::from_millis(250));
    client.logout().await.expect("logout");
    server.await.expect("server");
}

#[tokio::test]
async fn keepalives_cannot_stretch_the_round_past_its_timeout() {
    let (port, server) = fake_server(IdleScript::KeepAlives).await;
    let mut client = connect(port).await;
    let started = Instant::now();
    // Bounded from outside too, so a regression fails instead of hanging the test run.
    let event = tokio::time::timeout(
        Duration::from_secs(5),
        client.idle_wait_gapless(Duration::from_millis(500)),
    )
    .await
    .expect("keep-alives stretched the IDLE round past its timeout")
    .expect("idle");
    let took = started.elapsed();
    assert_eq!(event, IdleEvent::Timeout);
    assert!(
        took >= Duration::from_millis(450) && took < Duration::from_secs(3),
        "{took:?}"
    );
    client.logout().await.expect("logout");
    server.await.expect("server");
}

#[tokio::test]
async fn change_during_idle_wakes() {
    let (port, server) = fake_server(IdleScript::AnnounceDuringIdle).await;
    let mut client = connect(port).await;
    let started = Instant::now();
    let event = client
        .idle_wait_gapless(Duration::from_secs(30))
        .await
        .expect("idle");
    assert_eq!(event, IdleEvent::NewData);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    client.logout().await.expect("logout");
    server.await.expect("server");
}
