//! `ImapClient::fetch_sizes` against a scripted IMAP server on loopback (no docker; runs in
//! G0): the command it sends, the parsed sizes, and UIDs the server does not have.

use std::time::Duration;

use sealbox_mail::imap::ImapClient;
use sealbox_mail::{Auth, Security};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// One connection: UIDs 3, 4, 9 exist with sizes 120, 4096, 7; returns every line sent.
async fn server() -> (u16, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.expect("accept");
        let (rd, mut wr) = sock.into_split();
        let mut lines = BufReader::new(rd).lines();
        let mut seen = Vec::new();
        wr.write_all(b"* OK fake IMAP ready\r\n")
            .await
            .expect("greet");
        while let Ok(Some(line)) = lines.next_line().await {
            seen.push(line.clone());
            let mut parts = line.splitn(3, ' ');
            let tag = parts.next().unwrap_or("*").to_owned();
            let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
            let reply = match cmd.as_str() {
                "CAPABILITY" => format!("* CAPABILITY IMAP4rev1\r\n{tag} OK done\r\n"),
                "LOGIN" => format!("{tag} OK logged in\r\n"),
                "SELECT" => format!(
                    "* 3 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 7] ok\r\n\
                     * OK [UIDNEXT 10] ok\r\n{tag} OK [READ-WRITE] done\r\n"
                ),
                // Out of order on purpose, plus a FLAGS-only line for a UID nobody asked about.
                "UID" => format!(
                    "* 3 FETCH (UID 9 RFC822.SIZE 7)\r\n* 1 FETCH (UID 3 RFC822.SIZE 120)\r\n\
                     * 2 FETCH (UID 4 RFC822.SIZE 4096)\r\n* 2 FETCH (FLAGS (\\Seen))\r\n\
                     {tag} OK FETCH completed\r\n"
                ),
                "LOGOUT" => {
                    let _ = wr
                        .write_all(format!("* BYE\r\n{tag} OK done\r\n").as_bytes())
                        .await;
                    break;
                }
                _ => format!("{tag} BAD unknown\r\n"),
            };
            if wr.write_all(reply.as_bytes()).await.is_err() {
                break;
            }
        }
        seen
    });
    (port, task)
}

#[tokio::test]
async fn fetch_sizes_asks_for_rfc822_size_and_returns_them_by_uid() {
    let (port, task) = server().await;
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
    .expect("connect");
    assert!(
        client.fetch_sizes(&[3]).await.is_err(),
        "no mailbox selected"
    );
    client.select("INBOX").await.expect("select");
    assert!(client.fetch_sizes(&[]).await.expect("empty").is_empty());
    let sizes = client.fetch_sizes(&[3, 4, 5, 9]).await.expect("sizes");
    assert_eq!(
        sizes,
        vec![(3, 120), (4, 4096), (9, 7)],
        "UID 5 does not exist"
    );
    client.logout().await.expect("logout");
    let seen = task.await.expect("server");
    let fetch: Vec<&String> = seen.iter().filter(|l| l.contains("FETCH")).collect();
    assert_eq!(fetch.len(), 1, "{seen:?}");
    assert!(
        fetch[0].ends_with("UID FETCH 3:5,9 (UID RFC822.SIZE)"),
        "{seen:?}"
    );
}
