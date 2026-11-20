//! The fake submission server.
//!
//! Seeded from the scripted SMTP server in `sealbox-mail/src/smtp.rs` and widened to carry the
//! quirks that matter for submission: which AUTH mechanisms are offered, the advertised and
//! enforced `SIZE` limit, and **whether submission files its own copy in Sent** — the quirk
//! behind `smtp_saves_sent`, where a client that also `APPEND`s ends up with two copies of
//! every sent message. Here that is not a claim in a table: the message really does appear in
//! the IMAP Sent folder, because both servers share one [`SimState`](crate::state::SimState).

use base64::Engine as _;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::quirks::SimAuth;
use crate::state::Shared;

/// Start the submission side on an ephemeral loopback port. Returns the port.
pub async fn start(state: Shared) -> std::io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let st = state.clone();
            tokio::spawn(async move {
                serve(sock, st).await;
            });
        }
    });
    Ok(port)
}

async fn serve(sock: TcpStream, state: Shared) {
    let idx = {
        let mut s = state.lock().unwrap();
        s.smtp_log.push(Vec::new());
        s.smtp_log.len() - 1
    };
    let (rd, mut wr) = sock.into_split();
    if wr
        .write_all(b"220 fakeprov.test ESMTP ready\r\n")
        .await
        .is_err()
    {
        return;
    }
    let mut lines = BufReader::new(rd).lines();
    let mut from = String::new();
    let mut rcpt: Vec<String> = Vec::new();
    let mut data: Option<Vec<u8>> = None;
    let mut authed = false;
    let mut auth_user = String::new();
    // Set when AUTH arrived without its payload and the client is sending it next.
    let mut pending_auth: Option<String> = None;

    while let Ok(Some(line)) = lines.next_line().await {
        // Message bodies are not logged: a submission log that holds the mail would be a
        // plaintext copy of it, and these fakes run beside real tests.
        if data.is_none() && pending_auth.is_none() {
            state.lock().unwrap().smtp_log[idx].push(line.clone());
        }

        // Inside DATA until a lone dot.
        if let Some(buf) = data.as_mut() {
            if line == "." {
                let raw = std::mem::take(buf);
                data = None;
                let reply = finish_data(&state, &from, &rcpt, raw);
                from.clear();
                rcpt.clear();
                if wr.write_all(reply.as_bytes()).await.is_err() {
                    break;
                }
            } else {
                // Undo dot-stuffing (RFC 5321 §4.5.2).
                let l = line.strip_prefix('.').unwrap_or(&line);
                buf.extend_from_slice(l.as_bytes());
                buf.extend_from_slice(b"\r\n");
            }
            continue;
        }

        if let Some(mech) = pending_auth.take() {
            let reply = check_auth(&state, &mech, line.trim(), &mut authed, &mut auth_user);
            if wr.write_all(reply.as_bytes()).await.is_err() {
                break;
            }
            continue;
        }

        let up = line.to_ascii_uppercase();
        let reply: String = if up.starts_with("EHLO") {
            let s = state.lock().unwrap();
            let q = &s.quirks;
            let mut ext = vec!["250-fakeprov.test".to_string(), "250-8BITMIME".to_string()];
            let mechs = match (&q.auth, q.no_xoauth2) {
                (SimAuth::XOAuth2, false) => Some("XOAUTH2".to_string()),
                (SimAuth::XOAuth2, true) => None,
                (SimAuth::Password(_), false) => Some("PLAIN LOGIN XOAUTH2".to_string()),
                (SimAuth::Password(_), true) => Some("PLAIN LOGIN".to_string()),
            };
            if let Some(m) = mechs {
                ext.push(format!("250-AUTH {m}"));
            }
            match q.max_message_bytes {
                Some(n) => ext.push(format!("250 SIZE {n}")),
                None => ext.push("250 SIZE 0".to_string()), // 0 = no stated limit
            }
            format!("{}\r\n", ext.join("\r\n"))
        } else if up.starts_with("HELO") {
            "250 fakeprov.test\r\n".to_string()
        } else if up.starts_with("AUTH") {
            let mut it = line.split_whitespace().skip(1);
            let mech = it.next().unwrap_or("").to_ascii_uppercase();
            let payload = it.next().map(str::to_string);
            let offers = {
                let s = state.lock().unwrap();
                let q = &s.quirks;
                match (&q.auth, q.no_xoauth2) {
                    (SimAuth::XOAuth2, false) => mech == "XOAUTH2",
                    (SimAuth::XOAuth2, true) => false,
                    (SimAuth::Password(_), false) => {
                        matches!(mech.as_str(), "PLAIN" | "LOGIN" | "XOAUTH2")
                    }
                    (SimAuth::Password(_), true) => matches!(mech.as_str(), "PLAIN" | "LOGIN"),
                }
            };
            if !offers {
                format!("504 5.5.4 {mech} is not available\r\n")
            } else {
                match payload {
                    Some(p) => check_auth(&state, &mech, &p, &mut authed, &mut auth_user),
                    None => {
                        pending_auth = Some(mech);
                        "334 \r\n".to_string()
                    }
                }
            }
        } else if up.starts_with("MAIL FROM") {
            // Submission always needs authentication; a server that let an unauthenticated
            // client submit would be an open relay.
            if !authed {
                "530 5.7.0 Authentication required\r\n".to_string()
            } else {
                from = angle_addr(&line);
                // Reject a declared SIZE over the limit here, as a real server does, rather
                // than after the client has uploaded the whole message.
                let declared = declared_size(&up);
                let limit = state.lock().unwrap().quirks.max_message_bytes;
                match (declared, limit) {
                    (Some(n), Some(max)) if n > max => {
                        format!("552 5.3.4 Message size {n} exceeds {max} byte limit\r\n")
                    }
                    _ => "250 2.1.0 OK\r\n".to_string(),
                }
            }
        } else if up.starts_with("RCPT TO") {
            if !authed {
                "530 5.7.0 Authentication required\r\n".to_string()
            } else {
                rcpt.push(angle_addr(&line));
                "250 2.1.5 OK\r\n".to_string()
            }
        } else if up.starts_with("DATA") {
            if rcpt.is_empty() {
                "503 5.5.1 RCPT first\r\n".to_string()
            } else {
                data = Some(Vec::new());
                "354 End data with <CR><LF>.<CR><LF>\r\n".to_string()
            }
        } else if up.starts_with("RSET") {
            from.clear();
            rcpt.clear();
            "250 2.0.0 OK\r\n".to_string()
        } else if up.starts_with("NOOP") {
            "250 2.0.0 OK\r\n".to_string()
        } else if up.starts_with("QUIT") {
            let _ = wr.write_all(b"221 2.0.0 bye\r\n").await;
            break;
        } else {
            "500 5.5.2 Command unrecognized\r\n".to_string()
        };
        if wr.write_all(reply.as_bytes()).await.is_err() {
            break;
        }
    }
}

/// Enforce the size limit on what actually arrived, record the submission, and — when the
/// provider does that — file a copy in Sent so it is really there over IMAP.
fn finish_data(state: &Shared, from: &str, rcpt: &[String], raw: Vec<u8>) -> String {
    let mut s = state.lock().unwrap();
    if let Some(max) = s.quirks.max_message_bytes {
        if raw.len() as u64 > max {
            return format!(
                "552 5.3.4 Message size {} exceeds {max} byte limit\r\n",
                raw.len()
            );
        }
    }
    s.submitted
        .push((from.to_string(), rcpt.to_vec(), raw.clone()));
    if s.quirks.smtp_saves_sent {
        let sent = s.quirks.sent_folder();
        s.append(&sent, raw.clone(), vec!["\\Seen".to_string()]);
    }
    // Delivery. A fake provider has no MX, but a conformance run sends to the mailbox's own
    // address and then waits for it to arrive, so submission has to play that part: any
    // recipient that is this mailbox lands in INBOX, unread. Mail to anyone else is accepted
    // and goes nowhere, which is also what a test wants — `submitted` has it either way.
    if rcpt.iter().any(|r| s.quirks.is_own_address(r)) {
        s.append("INBOX", raw, Vec::new());
    }
    "250 2.0.0 Ok: queued as fakeprov-1\r\n".to_string()
}

fn check_auth(
    state: &Shared,
    mech: &str,
    payload: &str,
    authed: &mut bool,
    auth_user: &mut String,
) -> String {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload.as_bytes())
        .unwrap_or_default();
    let decoded = String::from_utf8_lossy(&decoded).into_owned();
    let mut s = state.lock().unwrap();
    match mech {
        "XOAUTH2" => {
            let user = crate::imap::xoauth2_field(&decoded, "user=");
            let token = crate::imap::xoauth2_field(&decoded, "auth=Bearer ");
            if !s.live_tokens.contains(&token) {
                s.rejected_logins
                    .push((user, "unknown or expired bearer (smtp)".into()));
                return "535 5.7.8 Invalid credentials\r\n".to_string();
            }
            if let Some(primary) = s.quirks.primary_login.clone() {
                if !user.eq_ignore_ascii_case(&primary) {
                    s.rejected_logins.push((
                        user,
                        format!(
                            "XOAUTH2 is only accepted for the primary address {primary} (smtp)"
                        ),
                    ));
                    return "535 5.7.8 Invalid credentials\r\n".to_string();
                }
            }
            *authed = true;
            *auth_user = user;
            "235 2.7.0 Authentication successful\r\n".to_string()
        }
        "PLAIN" => {
            let mut f = decoded.split('\0');
            let _ = f.next();
            let user = f.next().unwrap_or("").to_string();
            let pass = f.next().unwrap_or("").to_string();
            match s.quirks.auth.clone() {
                SimAuth::Password(expected) if pass == expected => {
                    *authed = true;
                    *auth_user = user;
                    "235 2.7.0 Authentication successful\r\n".to_string()
                }
                _ => {
                    s.rejected_logins
                        .push((user, "wrong password (smtp)".into()));
                    "535 5.7.8 Invalid credentials\r\n".to_string()
                }
            }
        }
        // LOGIN sends the user and the password in two separate base64 lines; Sealbox prefers
        // PLAIN, so rather than half-implement the exchange this says so.
        other => format!("504 5.5.4 {other} not implemented by this fake\r\n"),
    }
}

/// `MAIL FROM:<a@b> SIZE=123` → `a@b`.
fn angle_addr(line: &str) -> String {
    match (line.find('<'), line.find('>')) {
        (Some(a), Some(b)) if b > a => line[a + 1..b].to_string(),
        _ => line
            .split(':')
            .nth(1)
            .unwrap_or("")
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string(),
    }
}

/// The `SIZE=` parameter of an upper-cased `MAIL FROM`, when the client declared one.
fn declared_size(up: &str) -> Option<u64> {
    up.split_whitespace()
        .find_map(|t| t.strip_prefix("SIZE="))
        .and_then(|n| n.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_addresses_are_read_out_of_either_form() {
        assert_eq!(angle_addr("MAIL FROM:<a@b.test> SIZE=99"), "a@b.test");
        assert_eq!(angle_addr("RCPT TO:<c@d.test>"), "c@d.test");
        assert_eq!(angle_addr("MAIL FROM: a@b.test"), "a@b.test");
        assert_eq!(angle_addr("MAIL FROM:<>"), "");
    }

    #[test]
    fn a_declared_size_is_read_from_the_command() {
        assert_eq!(declared_size("MAIL FROM:<A@B> SIZE=1234"), Some(1234));
        assert_eq!(declared_size("MAIL FROM:<A@B>"), None);
        assert_eq!(declared_size("MAIL FROM:<A@B> SIZE=NOPE"), None);
    }
}
