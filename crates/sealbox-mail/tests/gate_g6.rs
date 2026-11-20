//! Gate G6 — OAuth2 unit level: XOAUTH2 SASL string, PKCE S256 (RFC 7636
//! Appendix B), authorization URLs for Google and Microsoft, and the loopback
//! redirect listener. The real-account login is a manual step (docs/GATES.md).

use std::collections::HashMap;
use std::time::Duration;

use sealbox_mail::oauth::{
    bind_loopback, pkce_challenge_s256, wait_for_code_on, AuthRequest, Provider, Token,
    GOOGLE_SCOPES, MICROSOFT_SCOPES,
};
use sealbox_mail::oauth::{xoauth2_sasl, xoauth2_sasl_raw};
use sealbox_mail::OAuthError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Google's documented XOAUTH2 example
/// (https://developers.google.com/gmail/imap/xoauth2-protocol#initial_client_response).
const GOOGLE_EXAMPLE_B64: &str = "dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5LnZGOWRmdDRxbVRjMk52YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ==";

#[test]
fn xoauth2_matches_google_documented_example() {
    let user = "someuser@example.com";
    let token = "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg";
    assert_eq!(
        xoauth2_sasl_raw(user, token),
        "user=someuser@example.com\x01auth=Bearer ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg\x01\x01"
    );
    assert_eq!(xoauth2_sasl(user, token), GOOGLE_EXAMPLE_B64);
    // Base64 of the documented bytes starts with "dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5"
    assert!(
        GOOGLE_EXAMPLE_B64.starts_with("dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5")
    );
}

#[test]
fn pkce_s256_matches_rfc7636_appendix_b() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert_eq!(
        pkce_challenge_s256(verifier),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

fn query_map(url: &str) -> (url::Url, HashMap<String, String>) {
    let parsed = url::Url::parse(url).expect("auth url parses");
    let map = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    (parsed, map)
}

#[test]
fn google_auth_url_has_scopes_pkce_and_state() {
    let req = AuthRequest::new(Provider::Google, "test-client-id", "http://127.0.0.1:4321")
        .expect("auth request");
    let (url, q) = query_map(&req.url);
    assert_eq!(url.host_str(), Some("accounts.google.com"));
    assert_eq!(url.path(), "/o/oauth2/v2/auth");
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["client_id"], "test-client-id");
    assert_eq!(q["redirect_uri"], "http://127.0.0.1:4321");
    assert_eq!(q["scope"], GOOGLE_SCOPES.join(" "));
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["code_challenge"], pkce_challenge_s256(&req.pkce_verifier));
    assert_eq!(q["state"], req.state);
    assert_eq!(q["access_type"], "offline");
    assert_eq!(q["prompt"], "consent");
    assert!(req.pkce_verifier.len() >= 43 && req.pkce_verifier.len() <= 128);
    // Fresh randomness every time.
    let again =
        AuthRequest::new(Provider::Google, "test-client-id", "http://127.0.0.1:4321").unwrap();
    assert_ne!(again.state, req.state);
    assert_ne!(again.pkce_verifier, req.pkce_verifier);
}

#[test]
fn microsoft_auth_url_uses_common_tenant_and_mail_scopes() {
    let req = AuthRequest::new(Provider::Microsoft, "ms-client", "http://localhost:4321")
        .expect("auth request");
    let (url, q) = query_map(&req.url);
    assert_eq!(url.host_str(), Some("login.microsoftonline.com"));
    assert_eq!(url.path(), "/common/oauth2/v2.0/authorize");
    let scope = &q["scope"];
    for s in MICROSOFT_SCOPES {
        assert!(
            scope.split(' ').any(|x| x == *s),
            "missing scope {s} in {scope}"
        );
    }
    assert!(scope.contains("https://outlook.office.com/IMAP.AccessAsUser.All"));
    assert!(scope.contains("https://outlook.office.com/SMTP.Send"));
    assert!(scope.contains("offline_access"));
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["code_challenge"], pkce_challenge_s256(&req.pkce_verifier));
    assert_eq!(q["state"], req.state);
    assert!(!q.contains_key("access_type"), "access_type is Google-only");
}

#[test]
fn login_hint_is_forwarded() {
    let req = AuthRequest::with_login_hint(
        Provider::Google,
        "cid",
        "http://127.0.0.1:1",
        Some("alice@gmail.com"),
    )
    .unwrap();
    let (_, q) = query_map(&req.url);
    assert_eq!(q["login_hint"], "alice@gmail.com");
}

#[test]
fn token_expiry_helpers() {
    let t = Token {
        access_token: "a".into(),
        refresh_token: None,
        expires_at: Some(0),
        scopes: vec![],
    };
    assert!(t.is_expired());
    let far = Token {
        expires_at: Some(u64::MAX / 2),
        ..t.clone()
    };
    assert!(!far.is_expired());
    assert!(!far.expires_within(Duration::from_secs(60)));
    let never = Token {
        expires_at: None,
        ..t
    };
    assert!(!never.is_expired());
    // Secrets never leak through Debug.
    assert!(!format!("{never:?}").contains('a') || !format!("{never:?}").contains("\"a\""));
}

async fn hit(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn loopback_listener_returns_code_and_checks_state() {
    let listener = bind_loopback(0).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        wait_for_code_on(listener, Some("st4te"), Duration::from_secs(10)).await
    });
    // A favicon request must not confuse the listener.
    let r = hit(port, "/favicon.ico").await;
    assert!(r.starts_with("HTTP/1.1 404"), "{r}");
    let r = hit(port, "/?code=4%2FabcDEF&state=st4te").await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    assert!(r.contains("Sealbox"));
    let code = task.await.unwrap().unwrap();
    assert_eq!(code.code, "4/abcDEF");
    assert_eq!(code.state.as_deref(), Some("st4te"));
}

#[tokio::test]
async fn loopback_listener_rejects_state_mismatch_and_reports_denial() {
    let listener = bind_loopback(0).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        wait_for_code_on(listener, Some("expected"), Duration::from_secs(10)).await
    });
    let r = hit(port, "/?code=x&state=wrong").await;
    assert!(r.starts_with("HTTP/1.1 400"), "{r}");
    assert!(matches!(
        task.await.unwrap(),
        Err(OAuthError::StateMismatch)
    ));

    let listener = bind_loopback(0).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task =
        tokio::spawn(
            async move { wait_for_code_on(listener, None, Duration::from_secs(10)).await },
        );
    let r = hit(port, "/?error=access_denied&error_description=User+said+no").await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    match task.await.unwrap() {
        Err(OAuthError::Denied(msg)) => {
            assert!(msg.contains("access_denied") && msg.contains("User said no"))
        }
        other => panic!("expected Denied, got {other:?}"),
    }
}

#[tokio::test]
async fn loopback_listener_times_out() {
    let listener = bind_loopback(0).await.unwrap();
    let r = wait_for_code_on(listener, None, Duration::from_millis(200)).await;
    assert!(matches!(r, Err(OAuthError::Listener(_))));
}
