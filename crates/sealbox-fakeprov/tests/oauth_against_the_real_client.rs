//! The fake identity provider driven by `sealbox_mail::oauth`, and the tokens it mints used to
//! log in to the fake IMAP and SMTP servers of the same provider.
//!
//! Three failure modes real providers produce, and all three are reproduced here on demand
//! instead of being waited for:
//!
//! * a rotated refresh token, where keeping the first one breaks the account after one refresh;
//! * a single `invalid_grant`, which is how Google's seven-day Testing-mode expiry arrives;
//! * a short access-token lifetime, which puts the refresh path inside a test.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sealbox_core::providers::ProviderId;
use sealbox_fakeprov::{ProviderSim, Quirks};
use sealbox_mail::imap::ImapClient;
use sealbox_mail::net_policy::ConnectOptions;
use sealbox_mail::oauth::{
    exchange_code_with, pkce_challenge_s256, refresh_with, OAuthEndpoints, Provider,
};
use sealbox_mail::smtp::SmtpClient;
use sealbox_mail::{Auth, BearerScope, Security};

const CLIENT_ID: &str = "fakeprov-client-id";

/// A PKCE verifier and its S256 challenge. `oauth.rs` exposes the challenge function but keeps
/// verifier generation inside its flow, so a fixed verifier stands in — the IdP checks the
/// relationship between the two, which is what matters here.
fn pkce_pair() -> (String, String) {
    let verifier = "fakeprov-verifier-0123456789-0123456789-0123456789".to_string();
    let challenge = pkce_challenge_s256(&verifier);
    (verifier, challenge)
}

fn endpoints(sim: &ProviderSim) -> OAuthEndpoints {
    OAuthEndpoints {
        auth_url: sim.idp.auth_url(),
        token_url: sim.idp.token_url(),
    }
}

fn dev_opts() -> ConnectOptions {
    ConnectOptions::new(Duration::from_secs(10)).with_bearer(Some(BearerScope {
        provider: Provider::Google,
        dev_idp: true,
    }))
}

/// Walk the authorization-code flow against the fake IdP without a browser: ask `/auth` for a
/// code (it redirects straight back), then exchange it.
async fn consent(sim: &ProviderSim) -> sealbox_mail::oauth::Token {
    let (verifier, challenge) = pkce_pair();
    let redirect = "http://127.0.0.1:1/callback";
    let url = format!(
        "{}?response_type=code&client_id={CLIENT_ID}&redirect_uri={}&code_challenge={challenge}\
         &code_challenge_method=S256&state=xyz&scope=https%3A%2F%2Fmail.google.com%2F",
        sim.idp.auth_url(),
        urlencode(redirect),
    );
    let location = get_location(&url)
        .await
        .expect("the IdP redirects with a code");
    let code = location
        .split("code=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .expect("a code in the redirect")
        .to_string();
    exchange_code_with(&endpoints(sim), CLIENT_ID, None, redirect, &code, &verifier)
        .await
        .expect("code exchange")
}

/// One GET, returning the `Location` header of the redirect.
async fn get_location(url: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = hostport.split_once(':')?;
    let mut sock = tokio::net::TcpStream::connect((host, port.parse::<u16>().ok()?))
        .await
        .ok()?;
    sock.write_all(
        format!("GET /{path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .ok()?;
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).await.ok()?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    text.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("location:"))
        .map(|l| l[9..].trim().to_string())
}

/// The `code` parameter of a redirect `Location`.
fn code_from(location: &str) -> String {
    location
        .split("code=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .expect("a code in the redirect")
        .to_string()
}

fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::test]
async fn a_consent_yields_a_token_the_same_providers_imap_and_smtp_accept() {
    let sim = ProviderSim::start(ProviderId::Gmail).await.unwrap();
    sim.seed_inbox(2);
    let token = consent(&sim).await;
    assert!(!token.access_token.is_empty());
    assert_eq!(token.refresh_token.as_deref(), Some("rt-1"));
    assert_eq!(sim.idp.state.lock().unwrap().code_exchanges, 1);

    // The IdP registered the token with the shared state, so IMAP accepts exactly it.
    let mut c = ImapClient::connect_with(
        "127.0.0.1",
        sim.imap_port,
        Security::Plain,
        Auth::XOAuth2 {
            user: "you@fakeprov.test".into(),
            access_token: token.access_token.clone(),
        },
        &dev_opts(),
    )
    .await
    .expect("the minted token works on IMAP");
    assert_eq!(c.select("INBOX").await.unwrap().exists, 2);
    let _ = c.logout().await;

    // And on submission.
    let s = SmtpClient::connect_with(
        "127.0.0.1",
        sim.smtp_port,
        Security::Plain,
        Some(Auth::XOAuth2 {
            user: "you@fakeprov.test".into(),
            access_token: token.access_token.clone(),
        }),
        &dev_opts(),
    )
    .expect("smtp client");
    let resp = s
        .send_raw(
            "you@fakeprov.test",
            &["them@fakeprov.test".to_string()],
            b"From: you@fakeprov.test\r\nTo: them@fakeprov.test\r\nSubject: oauth\r\n\r\nx\r\n",
        )
        .await
        .expect("the same token works on submission");
    assert!(resp.code.starts_with('2'), "{resp:?}");

    // A token this IdP never issued is refused, so the check is not vacuous.
    let err = ImapClient::connect_with(
        "127.0.0.1",
        sim.imap_port,
        Security::Plain,
        Auth::XOAuth2 {
            user: "you@fakeprov.test".into(),
            access_token: "made-up".into(),
        },
        &dev_opts(),
    )
    .await
    .expect_err("an unminted token must fail");
    assert!(
        format!("{err}").to_ascii_uppercase().contains("FAIL"),
        "{err}"
    );
}

#[tokio::test]
async fn a_short_lived_access_token_reports_an_expiry_the_engine_can_act_on() {
    let mut q = Quirks::for_provider(ProviderId::Gmail);
    q.token_ttl_secs = 60;
    let sim = ProviderSim::start_with(q).await.unwrap();
    let token = consent(&sim).await;
    let expires_at = token.expires_at.expect("an expiry was reported");
    let in_secs = expires_at.saturating_sub(now());
    assert!(
        (30..=70).contains(&in_secs),
        "about a minute from now, not an hour: {in_secs}s"
    );
}

#[tokio::test]
async fn a_rotating_provider_invalidates_the_refresh_token_it_replaced() {
    let mut q = Quirks::for_provider(ProviderId::Gmail);
    q.rotate_refresh_tokens = true;
    let sim = ProviderSim::start_with(q).await.unwrap();
    let first = consent(&sim).await;
    let rt1 = first.refresh_token.clone().expect("a refresh token");

    let second = refresh_with(&endpoints(&sim), Provider::Google, CLIENT_ID, None, &rt1)
        .await
        .expect("the first refresh works");
    let rt2 = second.refresh_token.clone().expect("a new refresh token");
    assert_ne!(rt1, rt2, "it was rotated");
    assert_ne!(
        first.access_token, second.access_token,
        "and a fresh access token came with it"
    );

    // Presenting the old one again fails — a client that stored only the first is now broken.
    let err = refresh_with(&endpoints(&sim), Provider::Google, CLIENT_ID, None, &rt1)
        .await
        .expect_err("the replaced refresh token is dead");
    assert!(
        format!("{err}")
            .to_ascii_lowercase()
            .contains("invalid_grant")
            || format!("{err}").to_ascii_lowercase().contains("stale"),
        "{err}"
    );
    // The new one still works.
    refresh_with(&endpoints(&sim), Provider::Google, CLIENT_ID, None, &rt2)
        .await
        .expect("the current refresh token works");
    assert_eq!(sim.idp.state.lock().unwrap().refresh_calls, 3);
}

#[tokio::test]
async fn a_non_rotating_provider_keeps_the_same_refresh_token_working() {
    // The default: the refresh token stays valid, which is what Microsoft does.
    let sim = ProviderSim::start(ProviderId::Outlook).await.unwrap();
    let first = consent(&sim).await;
    let rt = first.refresh_token.clone().unwrap();
    for _ in 0..3 {
        let t = refresh_with(&endpoints(&sim), Provider::Microsoft, CLIENT_ID, None, &rt)
            .await
            .expect("the same refresh token keeps working");
        assert_eq!(t.refresh_token.as_deref(), Some(rt.as_str()));
    }
}

/// Google's seven-day expiry for a project in Testing mode, on demand. The owner's Gmail token
/// is expected to fail exactly this way around 2026-11-24 (`docs/PROVIDERS_CONFORMANCE.md`), and the
/// remedy is to consent again — which is what the second half of this test does.
#[tokio::test]
async fn one_scripted_invalid_grant_is_what_a_testing_mode_expiry_looks_like() {
    let mut q = Quirks::for_provider(ProviderId::Gmail);
    q.one_invalid_grant = true;
    let sim = ProviderSim::start_with(q).await.unwrap();
    let first = consent(&sim).await;
    let rt = first.refresh_token.clone().unwrap();

    let err = refresh_with(&endpoints(&sim), Provider::Google, CLIENT_ID, None, &rt)
        .await
        .expect_err("the scripted expiry");
    let msg = format!("{err}").to_ascii_lowercase();
    assert!(
        msg.contains("invalid_grant"),
        "the error a client has to recognise as 'consent again': {err}"
    );

    // It is spent: the next refresh succeeds, as it would after re-consenting.
    let after = refresh_with(&endpoints(&sim), Provider::Google, CLIENT_ID, None, &rt)
        .await
        .expect("only one failure was scripted");
    assert!(!after.access_token.is_empty());
    assert!(sim.idp.state.lock().unwrap().invalid_grant_spent);
}

#[tokio::test]
async fn the_idp_insists_on_a_correct_pkce_request() {
    let sim = ProviderSim::start(ProviderId::Gmail).await.unwrap();

    // No code_challenge at all.
    let bad = format!(
        "{}?response_type=code&client_id={CLIENT_ID}&redirect_uri={}&state=s&scope=x",
        sim.idp.auth_url(),
        urlencode("http://127.0.0.1:1/callback")
    );
    assert_eq!(
        get_location(&bad).await,
        None,
        "no redirect for a bad request"
    );

    // A non-loopback redirect_uri is refused, which is what stops a code being sent elsewhere.
    let (_, challenge) = pkce_pair();
    let offsite = format!(
        "{}?response_type=code&client_id={CLIENT_ID}&redirect_uri={}&code_challenge={challenge}\
         &code_challenge_method=S256&state=s&scope=x",
        sim.idp.auth_url(),
        urlencode("https://evil.example/callback")
    );
    assert_eq!(get_location(&offsite).await, None);
    let errors = sim.idp.state.lock().unwrap().errors.clone();
    assert!(
        errors.iter().any(|e| e.contains("redirect_uri")),
        "the IdP recorded why: {errors:?}"
    );

    // A good flow still works, so the refusals above are not blanket failure.
    let token = consent(&sim).await;
    assert!(!token.access_token.is_empty());
}

/// PKCE's whole purpose: a code intercepted on the way back is useless without the verifier
/// that produced the challenge.
#[tokio::test]
async fn a_code_cannot_be_exchanged_with_the_wrong_verifier() {
    let sim = ProviderSim::start(ProviderId::Gmail).await.unwrap();
    let (_verifier, challenge) = pkce_pair();
    let redirect = "http://127.0.0.1:1/callback";
    let url = format!(
        "{}?response_type=code&client_id={CLIENT_ID}&redirect_uri={}&code_challenge={challenge}\
         &code_challenge_method=S256&state=s&scope=x",
        sim.idp.auth_url(),
        urlencode(redirect)
    );
    let code = code_from(&get_location(&url).await.unwrap());

    let wrong = "a-different-verifier-that-is-long-enough-0123456789";
    let err = exchange_code_with(&endpoints(&sim), CLIENT_ID, None, redirect, &code, wrong)
        .await
        .expect_err("the challenge does not match this verifier");
    assert!(
        format!("{err}")
            .to_ascii_lowercase()
            .contains("invalid_grant"),
        "{err}"
    );
    assert!(
        sim.idp
            .state
            .lock()
            .unwrap()
            .errors
            .iter()
            .any(|e| e.contains("pkce mismatch")),
        "the IdP said why"
    );
    assert_eq!(
        sim.idp.state.lock().unwrap().code_exchanges,
        0,
        "nothing was issued"
    );
}

#[tokio::test]
async fn a_code_cannot_be_exchanged_twice() {
    let sim = ProviderSim::start(ProviderId::Gmail).await.unwrap();
    let (verifier, challenge) = pkce_pair();
    let redirect = "http://127.0.0.1:1/callback";
    let url = format!(
        "{}?response_type=code&client_id={CLIENT_ID}&redirect_uri={}&code_challenge={challenge}\
         &code_challenge_method=S256&state=s&scope=x",
        sim.idp.auth_url(),
        urlencode(redirect)
    );
    let code = code_from(&get_location(&url).await.unwrap());

    exchange_code_with(
        &endpoints(&sim),
        CLIENT_ID,
        None,
        redirect,
        &code,
        &verifier,
    )
    .await
    .expect("first exchange");
    let err = exchange_code_with(
        &endpoints(&sim),
        CLIENT_ID,
        None,
        redirect,
        &code,
        &verifier,
    )
    .await
    .expect_err("a code is single-use");
    assert!(
        format!("{err}")
            .to_ascii_lowercase()
            .contains("invalid_grant"),
        "{err}"
    );
}
