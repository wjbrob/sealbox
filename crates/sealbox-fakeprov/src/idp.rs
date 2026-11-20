//! The fake OAuth2 identity provider.
//!
//! Lifted out of `crates/sealbox-cli/tests/gate_g21_local.rs`, where it was a private module
//! only one test could use, and given the three knobs that matter for the failures real
//! providers actually produce:
//!
//! * **token TTL** — Google's access tokens last an hour; a short one here makes the engine's
//!   refresh path run inside a test instead of being reasoned about.
//! * **refresh-token rotation** — the issuer replaces the refresh token on every refresh and
//!   invalidates the old one, so a client that keeps the first one is broken after one refresh.
//! * **one `invalid_grant`** — Google expires the refresh token of a project still in *Testing*
//!   after seven days. The owner's own Gmail token will fail this way around 2026-11-24
//!   (`docs/PROVIDERS_CONFORMANCE.md`), so it is worth having a test that produces it on demand
//!   rather than waiting for the calendar.
//!
//! Access tokens it issues are registered with the shared [`SimState`](crate::state::SimState),
//! so the fake IMAP and SMTP servers accept exactly the tokens this IdP minted and nothing
//! else — the three pieces behave as one provider.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sealbox_mail::oauth::pkce_challenge_s256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::state::Shared;

/// What the IdP has been asked to do, for a test to assert on.
#[derive(Default, Debug)]
pub struct IdpState {
    /// code → (code_challenge, redirect_uri, client_id)
    pub codes: HashMap<String, (String, String, String)>,
    /// The refresh token currently valid (rotation invalidates the previous one).
    pub current_refresh: Option<String>,
    pub auth_calls: u32,
    pub code_exchanges: u32,
    pub refresh_calls: u32,
    /// Every refresh token presented, in order — a client that reuses a rotated one shows up
    /// here.
    pub refresh_tokens_seen: Vec<String>,
    pub last_auth_query: HashMap<String, String>,
    /// Access tokens issued, newest last.
    pub issued_access_tokens: Vec<String>,
    /// Protocol errors the IdP rejected, for the test to read back.
    pub errors: Vec<String>,
    /// Set once the scripted `invalid_grant` has been spent.
    pub invalid_grant_spent: bool,
}

pub struct MockIdp {
    pub port: u16,
    pub state: Arc<Mutex<IdpState>>,
}

impl MockIdp {
    pub fn auth_url(&self) -> String {
        format!("http://127.0.0.1:{}/auth", self.port)
    }

    pub fn token_url(&self) -> String {
        format!("http://127.0.0.1:{}/token", self.port)
    }

    /// The access token most recently issued, if any.
    pub fn last_access_token(&self) -> Option<String> {
        self.state
            .lock()
            .unwrap()
            .issued_access_tokens
            .last()
            .cloned()
    }
}

/// Start the IdP. `sim` is the provider's shared state: every access token issued is added to
/// its `live_tokens`, so its IMAP and SMTP servers accept it.
pub async fn start(sim: Shared) -> std::io::Result<MockIdp> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let state = Arc::new(Mutex::new(IdpState::default()));
    let st = state.clone();
    tokio::spawn(async move {
        let mut n = 0u32;
        while let Ok((sock, _)) = listener.accept().await {
            n += 1;
            let st = st.clone();
            let sim = sim.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(sock, st.clone(), sim, n).await {
                    st.lock().unwrap().errors.push(e);
                }
            });
        }
    });
    Ok(MockIdp { port, state })
}

async fn handle(
    mut sock: TcpStream,
    st: Arc<Mutex<IdpState>>,
    sim: Shared,
    n: u32,
) -> Result<(), String> {
    let (request_line, body) = read_request(&mut sock).await?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    match (method.as_str(), path) {
        ("GET", "/auth") => authorize(&mut sock, st, query, n).await,
        ("POST", "/token") => token(&mut sock, st, sim, &String::from_utf8_lossy(&body)).await,
        _ => {
            respond(&mut sock, "404 Not Found", &[], "no").await;
            Err(format!("{method} {path}"))
        }
    }
}

/// `/auth` — checks the request is a correct PKCE authorization request and redirects straight
/// back to the loopback `redirect_uri` with a code, so no browser is needed.
async fn authorize(
    sock: &mut TcpStream,
    st: Arc<Mutex<IdpState>>,
    query: &str,
    n: u32,
) -> Result<(), String> {
    let q = parse_form(query);
    {
        let mut s = st.lock().unwrap();
        s.auth_calls += 1;
        s.last_auth_query = q.clone();
    }
    let missing: Vec<&str> = [
        "response_type",
        "client_id",
        "redirect_uri",
        "code_challenge",
        "code_challenge_method",
        "state",
        "scope",
    ]
    .into_iter()
    .filter(|k| !q.contains_key(*k))
    .collect();
    if !missing.is_empty() {
        respond(
            sock,
            "400 Bad Request",
            &[],
            &format!("missing {}", missing.join(",")),
        )
        .await;
        return Err(format!("/auth missing {missing:?}"));
    }
    if q["response_type"] != "code" || q["code_challenge_method"] != "S256" {
        respond(sock, "400 Bad Request", &[], "bad response_type/method").await;
        return Err("bad response_type/method".into());
    }
    let redirect = q["redirect_uri"].clone();
    if !(redirect.starts_with("http://127.0.0.1:") || redirect.starts_with("http://localhost:")) {
        respond(sock, "400 Bad Request", &[], "redirect_uri not loopback").await;
        return Err(format!("redirect_uri {redirect}"));
    }
    let code = format!("code-{n}-{}", unique());
    st.lock().unwrap().codes.insert(
        code.clone(),
        (
            q["code_challenge"].clone(),
            redirect.clone(),
            q["client_id"].clone(),
        ),
    );
    let location = format!("{redirect}?code={code}&state={}", q["state"]);
    respond(sock, "302 Found", &[("Location", &location)], "").await;
    Ok(())
}

/// `/token` — the authorization-code exchange and the refresh, both honouring the quirks.
async fn token(
    sock: &mut TcpStream,
    st: Arc<Mutex<IdpState>>,
    sim: Shared,
    body: &str,
) -> Result<(), String> {
    let form = parse_form(body);
    let grant = form.get("grant_type").cloned().unwrap_or_default();
    let json_hdr = [("Content-Type", "application/json")];
    let (ttl, rotate, one_invalid_grant) = {
        let s = sim.lock().unwrap();
        (
            s.quirks.token_ttl_secs,
            s.quirks.rotate_refresh_tokens,
            s.quirks.one_invalid_grant,
        )
    };
    match grant.as_str() {
        "authorization_code" => {
            let code = form.get("code").cloned().unwrap_or_default();
            let entry = st.lock().unwrap().codes.remove(&code);
            let Some((challenge, redirect, client_id)) = entry else {
                respond(
                    sock,
                    "400 Bad Request",
                    &json_hdr,
                    r#"{"error":"invalid_grant","error_description":"unknown code"}"#,
                )
                .await;
                return Err(format!("unknown code {code}"));
            };
            let verifier = form.get("code_verifier").cloned().unwrap_or_default();
            if pkce_challenge_s256(&verifier) != challenge {
                respond(
                    sock,
                    "400 Bad Request",
                    &json_hdr,
                    r#"{"error":"invalid_grant","error_description":"pkce mismatch"}"#,
                )
                .await;
                return Err("pkce mismatch".into());
            }
            if form.get("redirect_uri") != Some(&redirect)
                || form.get("client_id") != Some(&client_id)
            {
                respond(
                    sock,
                    "400 Bad Request",
                    &json_hdr,
                    r#"{"error":"invalid_request","error_description":"redirect/client mismatch"}"#,
                )
                .await;
                return Err("redirect/client mismatch".into());
            }
            let rt = "rt-1".to_string();
            let access = format!("at-1-{}", unique());
            {
                let mut s = st.lock().unwrap();
                s.code_exchanges += 1;
                s.current_refresh = Some(rt.clone());
                s.issued_access_tokens.push(access.clone());
            }
            sim.lock().unwrap().live_tokens.push(access.clone());
            respond(
                sock,
                "200 OK",
                &json_hdr,
                &token_json(&access, ttl, Some(&rt)),
            )
            .await;
            Ok(())
        }
        "refresh_token" => {
            let presented = form.get("refresh_token").cloned().unwrap_or_default();
            // The scripted seven-day expiry: one refresh fails with `invalid_grant` and the
            // *next* one works, which is what re-consenting looks like from the client's side.
            let scripted_failure = {
                let mut s = st.lock().unwrap();
                s.refresh_calls += 1;
                s.refresh_tokens_seen.push(presented.clone());
                if one_invalid_grant && !s.invalid_grant_spent {
                    s.invalid_grant_spent = true;
                    true
                } else {
                    false
                }
            };
            if scripted_failure {
                respond(
                    sock,
                    "400 Bad Request",
                    &json_hdr,
                    r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#,
                )
                .await;
                return Ok(()); // a scripted failure, not a protocol error by the client
            }
            let (ok, next) = {
                let mut s = st.lock().unwrap();
                let ok = s.current_refresh.as_deref() == Some(presented.as_str());
                let next = if rotate {
                    format!("rt-{}", s.refresh_calls + 1)
                } else {
                    presented.clone()
                };
                if ok {
                    s.current_refresh = Some(next.clone());
                }
                (ok, next)
            };
            if !ok {
                respond(
                    sock,
                    "400 Bad Request",
                    &json_hdr,
                    r#"{"error":"invalid_grant","error_description":"stale refresh token"}"#,
                )
                .await;
                return Err(format!("stale refresh token {presented}"));
            }
            let access = {
                let mut s = st.lock().unwrap();
                let access = format!("at-{}-{}", s.refresh_calls + 1, unique());
                s.issued_access_tokens.push(access.clone());
                access
            };
            sim.lock().unwrap().live_tokens.push(access.clone());
            respond(
                sock,
                "200 OK",
                &json_hdr,
                &token_json(&access, ttl, Some(&next)),
            )
            .await;
            Ok(())
        }
        other => {
            respond(
                sock,
                "400 Bad Request",
                &json_hdr,
                r#"{"error":"unsupported_grant_type"}"#,
            )
            .await;
            Err(format!("grant {other}"))
        }
    }
}

/// A token response, built by hand so the crate needs no JSON dependency.
fn token_json(access: &str, expires_in: u64, refresh: Option<&str>) -> String {
    let rt = match refresh {
        Some(r) => format!(r#","refresh_token":"{r}""#),
        None => String::new(),
    };
    format!(
        r#"{{"access_token":"{access}","token_type":"Bearer","expires_in":{expires_in}{rt},"scope":"https://mail.google.com/"}}"#
    )
}

/// A short unique suffix without pulling in a random-number crate: the clock in nanoseconds.
fn unique() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{n:x}")
}

pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                match u8::from_str_radix(hex, 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_form(s: &str) -> HashMap<String, String> {
    s.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

async fn read_request(sock: &mut TcpStream) -> Result<(String, Vec<u8>), String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let head_end;
    loop {
        let n = sock.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed before headers".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            head_end = pos + 4;
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err("headers too large".into());
        }
    }
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut content_length = 0usize;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let n = sock.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok((request_line, body))
}

async fn respond(sock: &mut TcpStream, status: &str, extra: &[(&str, &str)], body: &str) {
    let mut h = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n",
        body.len()
    );
    for (k, v) in extra {
        h.push_str(&format!("{k}: {v}\r\n"));
    }
    h.push_str("\r\n");
    let _ = sock.write_all(h.as_bytes()).await;
    let _ = sock.write_all(body.as_bytes()).await;
    let _ = sock.flush().await;
    let _ = sock.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_decode_the_way_an_authorization_request_arrives() {
        let q = parse_form("response_type=code&scope=https%3A%2F%2Fmail.google.com%2F&state=a+b");
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["scope"], "https://mail.google.com/");
        assert_eq!(q["state"], "a b", "+ is a space in a query string");
        assert!(parse_form("").is_empty());
    }

    #[test]
    fn a_token_response_is_well_formed_json_with_and_without_a_refresh_token() {
        let with = token_json("at-1", 3600, Some("rt-1"));
        assert!(with.contains(r#""access_token":"at-1""#));
        assert!(with.contains(r#""expires_in":3600"#));
        assert!(with.contains(r#""refresh_token":"rt-1""#));
        let without = token_json("at-2", 60, None);
        assert!(!without.contains("refresh_token"));
        assert!(without.starts_with('{') && without.ends_with('}'));
    }
}
