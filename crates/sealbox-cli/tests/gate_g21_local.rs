//! Gate G21, local half — the provider-conformance suite against GreenMail (users u26–u29,
//! see docs/GATES.md) and the `account add --oauth` loopback flow end to end against a mock
//! identity provider (the real providers need the human's client ids: `scripts/gate_g21.sh`).
//!
//! GreenMail's IMAP has no `AUTH=XOAUTH2` and Sealbox never sends an OAuth token as a `LOGIN`
//! password (docs/THREAT_MODEL.md R14), so the OAuth account reaches GreenMail's IMAP through
//! [`xoauth2_front`], which plays a provider's XOAUTH2-capable server; SMTP goes to GreenMail
//! directly (its SMTP accepts XOAUTH2). The mock IdP's endpoints are loopback, which is what
//! lets its tokens go to local hosts at all (the test/dev escape hatch of the token pinning).
//!
//! Needs `testing/mail_up.sh`. Run with
//! `cargo test -p sealbox-cli --test gate_g21_local -- --ignored`.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{inbox_raw, nonce, wait_until, Profile, IMAP, SMTP};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// A tiny OAuth2 identity provider: `/auth` redirects straight back to the loopback
/// `redirect_uri` with a code, `/token` exchanges the code (PKCE S256 verified) or a refresh
/// token for an access token that equals the GreenMail password of the test user, so that
/// GreenMail's SMTP XOAUTH2 and the [`xoauth2_front`] accept it.
mod mock_idp {
    use super::*;
    use sealbox_mail::oauth::pkce_challenge_s256;

    #[derive(Default)]
    pub struct State {
        /// code → (code_challenge, redirect_uri, client_id)
        pub codes: HashMap<String, (String, String, String)>,
        pub current_refresh: Option<String>,
        pub auth_calls: u32,
        pub code_exchanges: u32,
        pub refresh_calls: u32,
        pub refresh_tokens_seen: Vec<String>,
        pub last_auth_query: HashMap<String, String>,
        pub errors: Vec<String>,
    }

    pub struct MockIdp {
        pub port: u16,
        pub state: Arc<Mutex<State>>,
    }

    impl MockIdp {
        pub async fn start(secret: &str, first_expires_in: u64) -> MockIdp {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let state = Arc::new(Mutex::new(State::default()));
            let st = state.clone();
            let secret_s = secret.to_string();
            tokio::spawn(async move {
                let mut n = 0u32;
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        break;
                    };
                    n += 1;
                    let st = st.clone();
                    let secret = secret_s.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle(sock, st.clone(), &secret, first_expires_in, n).await
                        {
                            st.lock().unwrap().errors.push(e);
                        }
                    });
                }
            });
            MockIdp { port, state }
        }

        pub fn auth_url(&self) -> String {
            format!("http://127.0.0.1:{}/auth", self.port)
        }

        pub fn token_url(&self) -> String {
            format!("http://127.0.0.1:{}/token", self.port)
        }
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

    async fn read_request(sock: &mut TcpStream) -> Result<(String, String, Vec<u8>), String> {
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
        Ok((request_line, head, body))
    }

    async fn respond(
        sock: &mut TcpStream,
        status: &str,
        extra_headers: &[(&str, &str)],
        body: &str,
    ) {
        let mut h = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n",
            body.len()
        );
        for (k, v) in extra_headers {
            h.push_str(&format!("{k}: {v}\r\n"));
        }
        h.push_str("\r\n");
        let _ = sock.write_all(h.as_bytes()).await;
        let _ = sock.write_all(body.as_bytes()).await;
        let _ = sock.flush().await;
        let _ = sock.shutdown().await;
    }

    async fn handle(
        mut sock: TcpStream,
        st: Arc<Mutex<State>>,
        secret: &str,
        first_expires_in: u64,
        n: u32,
    ) -> Result<(), String> {
        let (request_line, _head, body) = read_request(&mut sock).await?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let target = parts.next().unwrap_or_default().to_string();
        let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
        match (method.as_str(), path) {
            ("GET", "/auth") => {
                let q = parse_form(query);
                st.lock().unwrap().auth_calls += 1;
                st.lock().unwrap().last_auth_query = q.clone();
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
                        &mut sock,
                        "400 Bad Request",
                        &[],
                        &format!("missing {}", missing.join(",")),
                    )
                    .await;
                    return Err(format!("/auth missing {missing:?}"));
                }
                if q["response_type"] != "code" || q["code_challenge_method"] != "S256" {
                    respond(
                        &mut sock,
                        "400 Bad Request",
                        &[],
                        "bad response_type/method",
                    )
                    .await;
                    return Err("bad response_type/method".into());
                }
                let redirect = q["redirect_uri"].clone();
                if !(redirect.starts_with("http://127.0.0.1:")
                    || redirect.starts_with("http://localhost:"))
                {
                    respond(
                        &mut sock,
                        "400 Bad Request",
                        &[],
                        "redirect_uri not loopback",
                    )
                    .await;
                    return Err(format!("redirect_uri {redirect}"));
                }
                let code = format!("code-{n}-{}", nonce("c"));
                st.lock().unwrap().codes.insert(
                    code.clone(),
                    (
                        q["code_challenge"].clone(),
                        redirect.clone(),
                        q["client_id"].clone(),
                    ),
                );
                let location = format!("{redirect}?code={code}&state={}", q["state"]);
                respond(&mut sock, "302 Found", &[("Location", &location)], "").await;
                Ok(())
            }
            ("POST", "/token") => {
                let form = parse_form(&String::from_utf8_lossy(&body));
                let grant = form.get("grant_type").cloned().unwrap_or_default();
                let json_hdr = [("Content-Type", "application/json")];
                match grant.as_str() {
                    "authorization_code" => {
                        let code = form.get("code").cloned().unwrap_or_default();
                        let entry = st.lock().unwrap().codes.remove(&code);
                        let Some((challenge, redirect, client_id)) = entry else {
                            respond(
                                &mut sock,
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
                                &mut sock,
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
                                &mut sock,
                                "400 Bad Request",
                                &json_hdr,
                                r#"{"error":"invalid_request","error_description":"redirect/client mismatch"}"#,
                            )
                            .await;
                            return Err("redirect/client mismatch".into());
                        }
                        let rt = "rt-1".to_string();
                        {
                            let mut s = st.lock().unwrap();
                            s.code_exchanges += 1;
                            s.current_refresh = Some(rt.clone());
                        }
                        let body = serde_json::json!({
                            "access_token": secret,
                            "token_type": "Bearer",
                            "expires_in": first_expires_in,
                            "refresh_token": rt,
                            "scope": "https://mail.google.com/",
                        });
                        respond(&mut sock, "200 OK", &json_hdr, &body.to_string()).await;
                        Ok(())
                    }
                    "refresh_token" => {
                        let presented = form.get("refresh_token").cloned().unwrap_or_default();
                        let (ok, next) = {
                            let mut s = st.lock().unwrap();
                            s.refresh_calls += 1;
                            s.refresh_tokens_seen.push(presented.clone());
                            let ok = s.current_refresh.as_deref() == Some(presented.as_str());
                            let next = format!("rt-{}", s.refresh_calls + 1);
                            if ok {
                                s.current_refresh = Some(next.clone());
                            }
                            (ok, next)
                        };
                        if !ok {
                            respond(
                                &mut sock,
                                "400 Bad Request",
                                &json_hdr,
                                r#"{"error":"invalid_grant","error_description":"stale refresh token"}"#,
                            )
                            .await;
                            return Err(format!("stale refresh token {presented}"));
                        }
                        let body = serde_json::json!({
                            "access_token": secret,
                            "token_type": "Bearer",
                            "expires_in": 3600,
                            "refresh_token": next,
                            "scope": "https://mail.google.com/",
                        });
                        respond(&mut sock, "200 OK", &json_hdr, &body.to_string()).await;
                        Ok(())
                    }
                    other => {
                        respond(
                            &mut sock,
                            "400 Bad Request",
                            &json_hdr,
                            r#"{"error":"unsupported_grant_type"}"#,
                        )
                        .await;
                        Err(format!("grant {other}"))
                    }
                }
            }
            _ => {
                respond(&mut sock, "404 Not Found", &[], "no").await;
                Err(format!("{method} {path}"))
            }
        }
    }
}

/// Test-only stand-in for a provider's XOAUTH2-capable IMAP server, in front of GreenMail
/// (whose IMAP offers no `AUTH=XOAUTH2`). Per connection it relays GreenMail's greeting, adds
/// `AUTH=XOAUTH2` to the pre-login `CAPABILITY`, answers `AUTHENTICATE XOAUTH2` with an empty
/// `+` challenge, checks the SASL framing (`user=…\x01auth=Bearer …\x01\x01`), logs in to
/// GreenMail with `LOGIN user bearer` (the mock IdP's tokens are the mailbox passwords) and,
/// once authenticated, relays bytes unchanged both ways. It counts what the client did, so the
/// test can show that the client used XOAUTH2 and never sent `LOGIN`.
mod xoauth2_front {
    use super::*;
    use tokio::io::AsyncRead;
    use tokio::net::tcp::OwnedWriteHalf;

    #[derive(Debug, Default)]
    pub struct Stats {
        pub sessions: u32,
        pub xoauth2_ok: u32,
        pub xoauth2_failed: u32,
        /// `LOGIN` commands sent by the client: a bearer must never arrive this way.
        pub client_logins: u32,
        pub errors: Vec<String>,
    }

    pub struct Front {
        pub port: u16,
        pub stats: Arc<Mutex<Stats>>,
    }

    impl Front {
        pub async fn start(upstream: (&'static str, u16)) -> Front {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let stats = Arc::new(Mutex::new(Stats::default()));
            let st = stats.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        break;
                    };
                    let st = st.clone();
                    tokio::spawn(async move {
                        st.lock().unwrap().sessions += 1;
                        if let Err(e) = session(sock, upstream, st.clone()).await {
                            st.lock().unwrap().errors.push(e);
                        }
                    });
                }
            });
            Front { port, stats }
        }

        /// `--imap` value pointing at the front.
        pub fn imap_spec(&self) -> String {
            format!("127.0.0.1:{}:plain", self.port)
        }
    }

    fn quote(s: &str) -> String {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }

    /// Standard base64 with padding (enough for SASL responses; no extra dependency).
    fn b64decode(s: &str) -> Option<Vec<u8>> {
        let val = |c: u8| -> Option<u32> {
            Some(match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return None,
            } as u32)
        };
        let bytes = s.trim().as_bytes();
        let (chunks, rest) = bytes.as_chunks::<4>();
        if !rest.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
        for chunk in chunks {
            let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
            if pad > 2 {
                return None;
            }
            let mut n = 0u32;
            for &c in &chunk[..4 - pad] {
                n = (n << 6) | val(c)?;
            }
            n <<= 6 * pad as u32;
            let b = n.to_be_bytes();
            out.extend_from_slice(&b[1..4 - pad]);
        }
        Some(out)
    }

    /// The base64 XOAUTH2 initial response (RFC 7628 style, as Gmail takes it).
    pub fn parse_xoauth2(b64: &str) -> Option<(String, String)> {
        parse_xoauth2_raw(&String::from_utf8(b64decode(b64)?).ok()?)
    }

    /// `user=<u>\x01auth=Bearer <token>\x01\x01`.
    pub fn parse_xoauth2_raw(text: &str) -> Option<(String, String)> {
        let rest = text.strip_prefix("user=")?;
        let (user, rest) = rest.split_once('\x01')?;
        let token = rest
            .strip_prefix("auth=Bearer ")?
            .strip_suffix("\x01\x01")?;
        if user.is_empty() || token.is_empty() || token.contains('\x01') {
            return None;
        }
        Some((user.to_string(), token.to_string()))
    }

    fn io(e: std::io::Error) -> String {
        e.to_string()
    }

    /// Relay upstream lines to the client until the tagged response for `tag`; `true` = OK.
    async fn relay_until_tagged<R: AsyncRead + Unpin>(
        up: &mut BufReader<R>,
        client: &mut OwnedWriteHalf,
        tag: &str,
        add_xoauth2: bool,
    ) -> Result<bool, String> {
        loop {
            let mut line = String::new();
            if up.read_line(&mut line).await.map_err(io)? == 0 {
                return Err(format!("upstream closed before `{tag}` completed"));
            }
            let out = if add_xoauth2 && line.starts_with("* CAPABILITY ") {
                format!("{} AUTH=XOAUTH2\r\n", line.trim_end())
            } else {
                line.clone()
            };
            client.write_all(out.as_bytes()).await.map_err(io)?;
            if let Some(rest) = line.strip_prefix(&format!("{tag} ")) {
                return Ok(rest.to_ascii_uppercase().starts_with("OK"));
            }
        }
    }

    async fn session(
        client: TcpStream,
        upstream: (&str, u16),
        st: Arc<Mutex<Stats>>,
    ) -> Result<(), String> {
        let up = TcpStream::connect(upstream)
            .await
            .map_err(|e| format!("upstream {upstream:?}: {e}"))?;
        let (up_r, mut up_w) = up.into_split();
        let mut up_r = BufReader::new(up_r);
        let (cl_r, mut cl_w) = client.into_split();
        let mut cl_r = BufReader::new(cl_r);
        let mut greeting = String::new();
        up_r.read_line(&mut greeting).await.map_err(io)?;
        cl_w.write_all(greeting.as_bytes()).await.map_err(io)?;
        // Not authenticated yet: interpret commands.
        loop {
            let mut cmd = String::new();
            if cl_r.read_line(&mut cmd).await.map_err(io)? == 0 {
                return Ok(());
            }
            let mut parts = cmd.trim_end().splitn(3, ' ');
            let tag = parts.next().unwrap_or("").to_string();
            let verb = parts.next().unwrap_or("").to_ascii_uppercase();
            let arg = parts.next().unwrap_or("").trim().to_string();
            match verb.as_str() {
                "AUTHENTICATE" if arg.eq_ignore_ascii_case("XOAUTH2") => {
                    cl_w.write_all(b"+ \r\n").await.map_err(io)?;
                    let mut resp = String::new();
                    if cl_r.read_line(&mut resp).await.map_err(io)? == 0 {
                        return Ok(());
                    }
                    let Some((user, token)) = parse_xoauth2(&resp) else {
                        st.lock().unwrap().xoauth2_failed += 1;
                        cl_w.write_all(
                            format!(
                                "{tag} NO [AUTHENTICATIONFAILED] malformed XOAUTH2 response\r\n"
                            )
                            .as_bytes(),
                        )
                        .await
                        .map_err(io)?;
                        continue;
                    };
                    up_w.write_all(
                        format!("{tag} LOGIN {} {}\r\n", quote(&user), quote(&token)).as_bytes(),
                    )
                    .await
                    .map_err(io)?;
                    if relay_until_tagged(&mut up_r, &mut cl_w, &tag, false).await? {
                        st.lock().unwrap().xoauth2_ok += 1;
                        break;
                    }
                    st.lock().unwrap().xoauth2_failed += 1;
                }
                "AUTHENTICATE" => {
                    cl_w.write_all(format!("{tag} NO unsupported mechanism\r\n").as_bytes())
                        .await
                        .map_err(io)?;
                }
                _ => {
                    if verb == "LOGIN" {
                        st.lock().unwrap().client_logins += 1;
                    }
                    up_w.write_all(cmd.as_bytes()).await.map_err(io)?;
                    let ok = relay_until_tagged(&mut up_r, &mut cl_w, &tag, verb == "CAPABILITY")
                        .await?;
                    if verb == "LOGOUT" {
                        return Ok(());
                    }
                    if verb == "LOGIN" && ok {
                        break;
                    }
                }
            }
        }
        // Authenticated: relay unchanged (the BufReaders hand over what they buffered first).
        tokio::select! {
            _ = tokio::io::copy(&mut cl_r, &mut up_w) => {}
            _ = tokio::io::copy(&mut up_r, &mut cl_w) => {}
        }
        Ok(())
    }

    #[test]
    fn sasl_framing() {
        for (user, token) in [("u26", "tok"), ("u26@sealbox.test", "u26pw"), ("a", "bc")] {
            let b64 = sealbox_mail::oauth::xoauth2_sasl(user, token);
            assert_eq!(
                parse_xoauth2(&b64),
                Some((user.to_string(), token.to_string())),
                "{b64}"
            );
        }
        for bad in [
            "user=u\x01auth=tok\x01\x01",
            "user=\x01auth=Bearer t\x01\x01",
            "user=u\x01auth=Bearer t\x01",
            "x",
        ] {
            assert_eq!(parse_xoauth2_raw(bad), None, "{bad:?}");
        }
        assert_eq!(parse_xoauth2("not base64!"), None);
        assert_eq!(b64decode("aGk="), Some(b"hi".to_vec()));
        assert_eq!(b64decode("aGVsbG8="), Some(b"hello".to_vec()));
        assert_eq!(b64decode("YWJj"), Some(b"abc".to_vec()));
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
    }
}

/// Minimal HTTP GET (the "browser"): returns (status line, headers, body).
async fn http_get(url: &str) -> (String, HashMap<String, String>, String) {
    let rest = url.strip_prefix("http://").expect("http url");
    // The loopback redirect URI has no path: `http://127.0.0.1:PORT?code=…`.
    let idx = rest.find(['/', '?']).unwrap_or(rest.len());
    let (hostport, tail) = rest.split_at(idx);
    let path = if tail.is_empty() {
        "/".to_string()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_string()
    };
    let mut s = TcpStream::connect(hostport).await.expect("connect");
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines.next().unwrap_or_default().to_string();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    (status, headers, body.to_string())
}

fn check_status(v: &serde_json::Value, name: &str) -> String {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no check {name} in {v}"))["status"]
        .as_str()
        .unwrap()
        .to_string()
}

fn check_detail(v: &serde_json::Value, name: &str) -> String {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()["detail"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Every check except the opt-in size probe (and the attachment one when skipped) must pass.
fn assert_suite_passed(v: &serde_json::Value, label: &str) {
    assert_eq!(v["result"], "PASS", "{label}: {v}");
    for c in v["checks"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let status = c["status"].as_str().unwrap();
        if name == "message_size_limit_probe" {
            assert_eq!(
                status, "SKIP",
                "{label}: size probe must be skipped by default"
            );
        } else {
            assert_eq!(status, "PASS", "{label}: {name}: {}", c["detail"]);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn conformance_suite_passes_for_a_password_account() {
    let p = Profile::new("g21-pw");
    p.add_greenmail_account("u27");
    let evidence = p.path().join("evidence");
    let v = p.json(&[
        "provider-test",
        "--account",
        "u27@sealbox.test",
        "--evidence-dir",
        evidence.to_str().unwrap(),
        "--attachment-mib",
        "2",
    ]);
    assert_suite_passed(&v, "u27");
    assert_eq!(v["provider"], "greenmail");
    assert_eq!(v["auth_kind"], "password");
    assert!(check_detail(&v, "auth_method").contains("imap=LOGIN"));
    assert!(check_detail(&v, "special_use_folders").contains("sent=Sent"));
    assert!(check_detail(&v, "sent_copy_single").contains("copies=1"));
    assert!(check_detail(&v, "protected_subject_preserved").contains("..."));
    // Evidence file exists, is named <provider>-<date>.json, and carries no secret.
    let file = v["evidence_file"].as_str().unwrap();
    assert!(file.contains("/greenmail-20"), "{file}");
    let text = std::fs::read_to_string(file).unwrap();
    assert!(!text.contains("u27pw"), "password leaked into evidence");
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["result"], "PASS");
    assert_eq!(doc["summary"]["fail"], 0);
    // The human-readable form lists every check with PASS/FAIL/SKIP and a timing.
    let text = p.ok(&[
        "provider-test",
        "--account",
        "u27@sealbox.test",
        "--evidence-dir",
        evidence.to_str().unwrap(),
        "--skip-attachment",
    ]);
    assert!(
        text.contains("PASS") && text.contains(" ms  connect_imap"),
        "{text}"
    );
    assert!(text.contains("SKIP") && text.contains("large_attachment_roundtrip"));
    // The engine learned the special-use mapping from LIST.
    let engine = p.engine();
    let roles = engine.folder_roles("u27@sealbox.test").unwrap();
    assert!(roles
        .iter()
        .any(|(r, n)| *r == sealbox_mail::imap::FolderRole::Trash && n == "Trash"));
    assert_eq!(
        engine
            .special_folder("u27@sealbox.test", sealbox_mail::imap::FolderRole::Junk)
            .unwrap(),
        "Junk"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn delete_moves_to_trash_then_expunges() {
    let p = Profile::new("g21-trash");
    p.add_greenmail_account("u29");
    let tag = nonce("trash");
    let subject = format!("to be deleted {tag}");
    p.json(&[
        "send",
        "--from",
        "u29@sealbox.test",
        "--to",
        "u29@sealbox.test",
        "--subject",
        &subject,
        "--body",
        "bye",
    ]);
    assert!(
        wait_until(Duration::from_secs(20), || async {
            p.sync("u29@sealbox.test");
            p.list(Some("u29@sealbox.test"), "INBOX")
                .iter()
                .any(|m| m["subject"] == subject)
        })
        .await
    );
    let m = p.find_by_subject(Some("u29@sealbox.test"), "INBOX", &subject);
    let id = m["id"].as_i64().unwrap().to_string();
    let mid = m["message_id"].as_str().unwrap().to_string();
    p.json(&["delete", &id]);
    // Gone from INBOX, present in Trash on the server.
    let mut imap = common::imap_login("u29").await;
    imap.select("INBOX").await.unwrap();
    assert!(imap.search_message_id(&mid).await.unwrap().is_empty());
    imap.select("Trash").await.expect("Trash was created");
    assert_eq!(imap.search_message_id(&mid).await.unwrap().len(), 1);
    imap.logout().await.unwrap();
    // Sync Trash into the store (list --folder Trash), delete again → expunged for good.
    let engine = p.engine();
    let mut client = engine.imap_session("u29@sealbox.test").await.unwrap();
    client.select("Trash").await.unwrap();
    let uid = client.search_message_id(&mid).await.unwrap()[0];
    client.logout().await.unwrap();
    // Move it back to INBOX through the engine API, then delete twice.
    engine.sync("u29@sealbox.test").await.unwrap();
    let mut client = engine.imap_session("u29@sealbox.test").await.unwrap();
    client.select("Trash").await.unwrap();
    client.r#move(&[uid], "INBOX").await.unwrap();
    client.logout().await.unwrap();
    engine.sync("u29@sealbox.test").await.unwrap();
    let m = p.find_by_subject(Some("u29@sealbox.test"), "INBOX", &subject);
    let id = m["id"].as_i64().unwrap();
    let rep = engine
        .move_message(id, sealbox_mail::imap::FolderRole::Trash)
        .await
        .unwrap();
    assert_eq!(rep.to_folder, "Trash");
    assert_eq!(
        rep.method,
        Some(sealbox_mail::imap::MoveMethod::Move),
        "GreenMail advertises MOVE"
    );
    assert_eq!(
        engine
            .special_folder("u29@sealbox.test", sealbox_mail::imap::FolderRole::Trash)
            .unwrap(),
        "Trash"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn oauth_add_account_end_to_end_with_mock_idp() {
    // Access tokens issued by the mock equal u26's GreenMail password; first token lives 2 s.
    let idp = mock_idp::MockIdp::start("u26pw", 2).await;
    // GreenMail's IMAP behind the XOAUTH2 front (see the module docs).
    let front = xoauth2_front::Front::start((common::IMAP_HOST, common::IMAP_PORT)).await;
    let front_imap = front.imap_spec();
    let p = Profile::new("g21-oauth");
    let evidence = p.path().join("evidence");

    // 1. `account add --oauth google` binds the loopback port and prints the URL.
    let mut cmd = p.cmd(&[
        "--json",
        "account",
        "add",
        "--email",
        "u26@sealbox.test",
        "--name",
        "OAuth Tester",
        "--oauth",
        "google",
        "--client-id",
        "sealbox-test-client",
        "--imap",
        &front_imap,
        "--smtp",
        SMTP,
        "--oauth-timeout",
        "60",
    ]);
    cmd.env("SEALBOX_OAUTH_AUTH_URL", idp.auth_url())
        .env("SEALBOX_OAUTH_TOKEN_URL", idp.token_url())
        .env_remove("GOOGLE_OAUTH_CLIENT_SECRET")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = tokio::process::Command::from(cmd)
        .kill_on_drop(true)
        .spawn()
        .expect("spawn account add --oauth");
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let start_event = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let line = lines
                .next_line()
                .await
                .unwrap()
                .expect("stdout closed early");
            eprintln!("[u26] {line}");
            if line.trim_start().starts_with('{') {
                let v: serde_json::Value = serde_json::from_str(&line).unwrap();
                if v["event"] == "oauth_start" {
                    break v;
                }
            }
        }
    })
    .await
    .expect("oauth_start event");
    let url = start_event["url"].as_str().unwrap().to_string();
    let port = start_event["loopback_port"].as_u64().unwrap() as u16;
    assert!(port > 0);
    assert_eq!(start_event["endpoints_overridden"], true);
    assert!(url.starts_with(&idp.auth_url()), "{url}");
    let q = mock_idp::parse_form(url.split_once('?').unwrap().1);
    assert_eq!(q["client_id"], "sealbox-test-client");
    assert_eq!(q["redirect_uri"], format!("http://127.0.0.1:{port}"));
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["login_hint"], "u26@sealbox.test");
    assert_eq!(q["access_type"], "offline");
    assert!(q["scope"].contains("https://mail.google.com/"));
    let state = q["state"].clone();

    // 2. Act as the browser: the IdP redirects to the loopback listener with a code.
    let (status, headers, _) = http_get(&url).await;
    assert!(status.starts_with("HTTP/1.1 302"), "{status}");
    let location = headers["location"].clone();
    assert!(
        location.starts_with(&format!("http://127.0.0.1:{port}?code=")),
        "{location}"
    );
    assert!(location.ends_with(&format!("&state={state}")), "{location}");
    let (status, _, body) = http_get(&location).await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(body.contains("Sealbox"), "{body}");

    // 3. The CLI exchanges the code (PKCE checked by the mock), verifies IMAP with
    //    AUTHENTICATE XOAUTH2 (through the front) and SMTP XOAUTH2, stores the account and
    //    prints it.
    let added = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let line = lines
                .next_line()
                .await
                .unwrap()
                .expect("stdout closed early");
            eprintln!("[u26] {line}");
            if line.trim_start().starts_with('{') {
                let v: serde_json::Value = serde_json::from_str(&line).unwrap();
                if v["event"] == "account_added" {
                    break v;
                }
                if v.get("error").is_some() {
                    panic!("account add failed: {v}");
                }
            }
        }
    })
    .await
    .expect("account_added event");
    let status = child.wait().await.unwrap();
    assert!(status.success(), "{status:?}");
    assert_eq!(added["account"]["email"], "u26@sealbox.test");
    assert_eq!(added["account"]["auth_kind"], "o_auth");
    assert_eq!(
        added["account"]["login"], "u26",
        "GreenMail wants the bare login; the full address is tried first"
    );
    assert_eq!(added["oauth"]["has_refresh_token"], true);
    assert_eq!(added["oauth"]["endpoints_overridden"], true);
    assert_eq!(
        added["oauth"]["dev_hosts_allowed"], true,
        "a loopback mock IdP's token may go to local hosts"
    );
    assert_eq!(added["oauth"]["refresh_count"], 0);
    assert!(added["oauth"]["expires_in_secs"].as_i64().unwrap() <= 2);
    {
        let st = idp.state.lock().unwrap();
        assert_eq!(st.auth_calls, 1);
        assert_eq!(st.code_exchanges, 1);
        assert_eq!(st.refresh_calls, 0, "no refresh during add");
        assert!(st.errors.is_empty(), "{:?}", st.errors);
    }

    // 4. Expiry triggers a refresh before the next connection; the rotated refresh token is
    //    persisted and a second sync does not refresh again.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let rep = p.sync("u26@sealbox.test");
    assert_eq!(rep["account"], "u26@sealbox.test");
    assert_eq!(
        idp.state.lock().unwrap().refresh_calls,
        1,
        "expired token must be refreshed"
    );
    let engine = p.engine();
    let st = engine.oauth_status("u26@sealbox.test").unwrap().unwrap();
    assert_eq!(st.refresh_count, 1);
    assert!(st.expires_in_secs.unwrap() > 1000, "{st:?}");
    assert!(st.has_refresh_token);
    p.sync("u26@sealbox.test");
    assert_eq!(
        idp.state.lock().unwrap().refresh_calls,
        1,
        "a fresh token must not be refreshed again"
    );
    // A forced refresh presents the rotated token (rt-2), proving persistence of rotation.
    let st = engine
        .refresh_oauth("u26@sealbox.test", true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(st.refresh_count, 2);
    assert_eq!(
        idp.state.lock().unwrap().refresh_tokens_seen,
        vec!["rt-1".to_string(), "rt-2".to_string()]
    );

    // 5. SMTP XOAUTH2 with the issued token: mail to u28 arrives (u28 has no key → plaintext).
    let tag = nonce("oauth-smtp");
    let before = inbox_raw("u28").await.len();
    let sent = p.json(&[
        "send",
        "--from",
        "u26@sealbox.test",
        "--to",
        "u28@sealbox.test",
        "--subject",
        &format!("xoauth2 smtp {tag}"),
        "--body",
        "sent with a bearer token",
        "--policy",
        "plaintext",
    ]);
    assert_eq!(sent["mode"], "plaintext");
    assert!(
        wait_until(Duration::from_secs(20), || async {
            inbox_raw("u28").await.len() > before
        })
        .await,
        "mail sent via SMTP XOAUTH2 never arrived at u28"
    );
    assert!(inbox_raw("u28")
        .await
        .iter()
        .any(|(_, raw)| String::from_utf8_lossy(raw).contains(&tag)));

    // 6. The conformance suite on the OAuth account.
    let v = p.json(&[
        "provider-test",
        "--account",
        "u26@sealbox.test",
        "--label",
        "oauth",
        "--evidence-dir",
        evidence.to_str().unwrap(),
        "--attachment-mib",
        "1",
    ]);
    assert_suite_passed(&v, "u26 oauth");
    assert_eq!(v["auth_kind"], "o_auth");
    let auth = check_detail(&v, "auth_method");
    assert!(auth.starts_with("imap=XOAUTH2;"), "{auth}");
    assert!(!auth.contains("LOGIN"), "{auth}");
    assert!(auth.contains("oauth provider=google"), "{auth}");
    assert!(
        auth.contains("token pinned to gmail.com googlemail.com google.com + local/private hosts"),
        "{auth}"
    );
    assert!(
        check_detail(&v, "connect_imap").contains("auth=XOAUTH2"),
        "{}",
        check_detail(&v, "connect_imap")
    );
    assert_eq!(v["oauth"]["endpoints_overridden"], true);
    assert!(v["oauth"]["refresh_count"].as_i64().unwrap() >= 2);
    let file = v["evidence_file"].as_str().unwrap();
    assert!(file.contains("/greenmail-oauth-20"), "{file}");
    let text = std::fs::read_to_string(file).unwrap();
    assert!(
        !text.contains("u26pw"),
        "token/password leaked into evidence"
    );
    assert!(!text.contains("rt-"), "refresh token leaked into evidence");
    assert_eq!(check_status(&v, "arrival_via_idle"), "PASS");

    // Every IMAP login of the OAuth account went through AUTHENTICATE XOAUTH2; the bearer
    // never arrived as a LOGIN password (R14).
    {
        let st = front.stats.lock().unwrap();
        eprintln!("[u26] xoauth2 front: {st:?}");
        assert_eq!(st.client_logins, 0, "LOGIN reached the front: {st:?}");
        assert!(st.xoauth2_ok >= 3, "add + sync + provider-test: {st:?}");
        assert!(
            st.xoauth2_failed >= 1,
            "the full-address login candidate is refused by GreenMail first: {st:?}"
        );
    }

    // Without the front GreenMail's IMAP gets no token at all: the account cannot sign in.
    let mut cmd = p.cmd(&[
        "--json",
        "account",
        "add",
        "--email",
        "u72@sealbox.test",
        "--oauth",
        "google",
        "--client-id",
        "sealbox-test-client",
        "--imap",
        IMAP,
        "--smtp",
        SMTP,
        "--oauth-timeout",
        "60",
    ]);
    cmd.env("SEALBOX_OAUTH_AUTH_URL", idp.auth_url())
        .env("SEALBOX_OAUTH_TOKEN_URL", idp.token_url())
        .env_remove("GOOGLE_OAUTH_CLIENT_SECRET")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = tokio::process::Command::from(cmd)
        .kill_on_drop(true)
        .spawn()
        .expect("spawn account add --oauth (no front)");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let start = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let line = lines
                .next_line()
                .await
                .unwrap()
                .expect("stdout closed early");
            if line.trim_start().starts_with('{') {
                let v: serde_json::Value = serde_json::from_str(&line).unwrap();
                if v["event"] == "oauth_start" {
                    break v;
                }
            }
        }
    })
    .await
    .expect("oauth_start event (no front)");
    let (_, headers, _) = http_get(start["url"].as_str().unwrap()).await;
    http_get(&headers["location"]).await;
    // The error document is pretty-printed: read the rest of stdout and parse it whole.
    let mut rest = String::new();
    tokio::time::timeout(
        Duration::from_secs(60),
        lines.into_inner().read_to_string(&mut rest),
    )
    .await
    .expect("account add (no front) finishes")
    .unwrap();
    eprintln!("[u72] {rest}");
    let refused: serde_json::Value =
        serde_json::from_str(&rest[rest.find('{').expect("a JSON document")..]).unwrap();
    assert!(refused.get("error").is_some(), "{refused}");
    let status = child.wait().await.unwrap();
    assert_eq!(status.code(), Some(4), "{refused}");
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("does not offer OAuth sign-in"),
        "{refused}"
    );
    assert!(p
        .run(&["--json", "account", "list"])
        .stdout
        .contains("u26@sealbox.test"));
    assert!(!p
        .run(&["--json", "account", "list"])
        .stdout
        .contains("u72@sealbox.test"));

    // 7. Adding the same address again is refused before any browser round trip.
    let r = p.run(&[
        "account",
        "add",
        "--email",
        "u26@sealbox.test",
        "--oauth",
        "google",
        "--client-id",
        "sealbox-test-client",
    ]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("already exists"), "{}", r.stderr);
    // And a missing client id is a clear error, not a hang.
    let mut cmd = p.cmd(&[
        "account",
        "add",
        "--email",
        "u99@sealbox.test",
        "--oauth",
        "microsoft",
    ]);
    cmd.env_remove("MS_OAUTH_CLIENT_ID");
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("MS_OAUTH_CLIENT_ID"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = Instant::now();
}

/// Outlook.com's SMTP replaces our Message-ID with its own and keeps ours in
/// `X-Microsoft-Original-Message-ID` (G21 Outlook, 2026-11-17). Played here by APPENDing such a
/// message: the lookup by our id finds it, so the provider-test polls see the delivery, and a
/// second copy that still carries our id (the duplicate `append_sent` used to add) is counted
/// with it — `sent_copy_single` then reports `copies=2` instead of a false `copies=1`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn a_message_id_rewritten_by_the_provider_is_found_by_the_original() {
    let tag = nonce("msoid");
    let ours = format!("{tag}@sealbox.test");
    let theirs = format!("PR3P192MB{tag}@outlook.example");
    let rewritten = format!(
        "From: u29@sealbox.test\r\nTo: u29@sealbox.test\r\nSubject: rewritten {tag}\r\n\
         Message-ID: <{theirs}>\r\nX-Microsoft-Original-Message-ID: <{ours}>\r\n\
         Date: Tue, 17 Nov 2026 10:00:00 +0000\r\n\r\nbody\r\n"
    );
    let mut imap = common::imap_login("u29").await;
    imap.append("INBOX", rewritten.as_bytes(), &[])
        .await
        .unwrap();
    imap.select("INBOX").await.unwrap();
    let by_ours = imap.search_message_id(&ours).await.unwrap();
    assert_eq!(by_ours.len(), 1, "found by the original Message-ID");
    assert_eq!(
        imap.search_message_id(&format!("<{theirs}>"))
            .await
            .unwrap(),
        by_ours
    );
    assert!(imap
        .search_message_id(&format!("not-{ours}"))
        .await
        .unwrap()
        .is_empty());

    // Our own copy (Message-ID = ours) next to the provider's: both count.
    let own = format!(
        "From: u29@sealbox.test\r\nTo: u29@sealbox.test\r\nSubject: rewritten {tag}\r\n\
         Message-ID: <{ours}>\r\nDate: Tue, 17 Nov 2026 10:00:00 +0000\r\n\r\nbody\r\n"
    );
    imap.append("INBOX", own.as_bytes(), &["\\Seen"])
        .await
        .unwrap();
    imap.select("INBOX").await.unwrap();
    assert_eq!(imap.search_message_id(&ours).await.unwrap().len(), 2);
    imap.logout().await.unwrap();
}
