//! OAuth2 authorization-code + PKCE for Google and Microsoft, the XOAUTH2 SASL
//! string, and a loopback redirect listener for desktop / CLI use.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope,
    TokenResponse, TokenUrl,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::error::OAuthError;

/// Google OAuth2 scope that covers IMAP and SMTP.
pub const GOOGLE_SCOPES: &[&str] = &["https://mail.google.com/"];
/// Microsoft (Entra ID, `common` tenant) scopes for IMAP + SMTP with refresh.
pub const MICROSOFT_SCOPES: &[&str] = &[
    "https://outlook.office.com/IMAP.AccessAsUser.All",
    "https://outlook.office.com/SMTP.Send",
    "offline_access",
    "openid",
    "email",
];

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const MICROSOFT_AUTH_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const MICROSOFT_TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

/// Supported identity providers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Provider {
    Google,
    /// Consumer (outlook.com / hotmail.com) and organisational accounts via the `common` tenant.
    Microsoft,
}

impl Provider {
    pub fn auth_url(self) -> &'static str {
        match self {
            Provider::Google => GOOGLE_AUTH_URL,
            Provider::Microsoft => MICROSOFT_AUTH_URL,
        }
    }

    pub fn token_url(self) -> &'static str {
        match self {
            Provider::Google => GOOGLE_TOKEN_URL,
            Provider::Microsoft => MICROSOFT_TOKEN_URL,
        }
    }

    pub fn scopes(self) -> &'static [&'static str] {
        match self {
            Provider::Google => GOOGLE_SCOPES,
            Provider::Microsoft => MICROSOFT_SCOPES,
        }
    }

    /// Loopback redirect URI accepted by the provider for native apps.
    /// Google wants `http://127.0.0.1:{port}`, Microsoft `http://localhost:{port}`.
    pub fn loopback_redirect_uri(self, port: u16) -> String {
        match self {
            Provider::Google => format!("http://127.0.0.1:{port}"),
            Provider::Microsoft => format!("http://localhost:{port}"),
        }
    }

    /// Stable lower-case name (`google`, `microsoft`).
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Google => "google",
            Provider::Microsoft => "microsoft",
        }
    }

    /// Name for messages (`Google`, `Microsoft`).
    pub fn display_name(self) -> &'static str {
        match self {
            Provider::Google => "Google",
            Provider::Microsoft => "Microsoft",
        }
    }

    /// Parse [`as_str`](Self::as_str) output (also `gmail`, `outlook`, `hotmail`, `m365`).
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "google" | "gmail" | "googlemail" | "workspace" => Provider::Google,
            "microsoft" | "outlook" | "hotmail" | "live" | "m365" | "office365" | "entra" => {
                Provider::Microsoft
            }
            _ => return None,
        })
    }
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Environment variables that redirect every OAuth request to another identity
/// provider — for tests against a mock IdP. Both must be set to take effect.
pub const ENV_AUTH_URL_OVERRIDE: &str = "SEALBOX_OAUTH_AUTH_URL";
pub const ENV_TOKEN_URL_OVERRIDE: &str = "SEALBOX_OAUTH_TOKEN_URL";

/// Authorization + token endpoints. Normally [`OAuthEndpoints::for_provider`];
/// tests point them at a mock IdP (plain `http://` is accepted for loopback
/// hosts only).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OAuthEndpoints {
    pub auth_url: String,
    pub token_url: String,
}

impl OAuthEndpoints {
    /// The provider's real endpoints.
    pub fn for_provider(provider: Provider) -> Self {
        Self {
            auth_url: provider.auth_url().to_owned(),
            token_url: provider.token_url().to_owned(),
        }
    }

    /// The provider's endpoints unless `SEALBOX_OAUTH_AUTH_URL` **and**
    /// `SEALBOX_OAUTH_TOKEN_URL` are set (test override; logged at WARN).
    pub fn from_env(provider: Provider) -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        match (get(ENV_AUTH_URL_OVERRIDE), get(ENV_TOKEN_URL_OVERRIDE)) {
            (Some(auth_url), Some(token_url)) => {
                tracing::warn!(
                    %auth_url,
                    %token_url,
                    "OAuth endpoints overridden by the environment (test mode)"
                );
                Self {
                    auth_url,
                    token_url,
                }
            }
            _ => Self::for_provider(provider),
        }
    }

    /// True when these are not the provider's real endpoints.
    pub fn is_override(&self, provider: Provider) -> bool {
        *self != Self::for_provider(provider)
    }

    /// True when both endpoints are overridden to the loopback interface: a mock identity
    /// provider for tests / development. Tokens from such an IdP may also be presented to
    /// local and private mail hosts (`net_policy::BearerScope::dev_idp`, docs/THREAT_MODEL.md
    /// R14); tokens from the real endpoints never are.
    pub fn is_loopback_mock(&self, provider: Provider) -> bool {
        self.is_override(provider) && self.allows_plain_http()
    }

    fn host_is_loopback(url: &str) -> bool {
        url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .is_some_and(|h| {
                matches!(
                    h.trim_matches(['[', ']']),
                    "127.0.0.1" | "localhost" | "::1"
                )
            })
    }

    /// Plain `http://` is only ever acceptable towards the loopback interface.
    fn allows_plain_http(&self) -> bool {
        Self::host_is_loopback(&self.auth_url) && Self::host_is_loopback(&self.token_url)
    }
}

/// The URL to open in the browser plus the secrets needed to finish the flow.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub url: String,
    /// Keep private; required by [`exchange_code`].
    pub pkce_verifier: String,
    /// CSRF token; compare with the `state` query parameter of the redirect.
    pub state: String,
}

impl std::fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthRequest")
            .field("url", &self.url)
            .field("pkce_verifier", &"<redacted>")
            .field("state", &self.state)
            .finish()
    }
}

impl AuthRequest {
    /// Build the authorization URL with a fresh S256 PKCE challenge and state.
    pub fn new(
        provider: Provider,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<Self, OAuthError> {
        Self::with_login_hint(provider, client_id, redirect_uri, None)
    }

    /// Like [`new`](Self::new) but pre-fills the account chooser with `login_hint`.
    pub fn with_login_hint(
        provider: Provider,
        client_id: &str,
        redirect_uri: &str,
        login_hint: Option<&str>,
    ) -> Result<Self, OAuthError> {
        Self::with_endpoints(
            &OAuthEndpoints::for_provider(provider),
            provider,
            client_id,
            redirect_uri,
            login_hint,
        )
    }

    /// Like [`with_login_hint`](Self::with_login_hint) against explicit endpoints.
    pub fn with_endpoints(
        endpoints: &OAuthEndpoints,
        provider: Provider,
        client_id: &str,
        redirect_uri: &str,
        login_hint: Option<&str>,
    ) -> Result<Self, OAuthError> {
        let client = build_client(endpoints, client_id, None, redirect_uri)?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut req = client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(
                provider
                    .scopes()
                    .iter()
                    .map(|s| Scope::new((*s).to_owned())),
            )
            .set_pkce_challenge(challenge);
        if provider == Provider::Google {
            // Needed to receive a refresh token for a native app.
            req = req
                .add_extra_param("access_type", "offline")
                .add_extra_param("prompt", "consent");
        }
        if let Some(hint) = login_hint {
            req = req.add_extra_param("login_hint", hint);
        }
        let (url, state) = req.url();
        Ok(Self {
            url: url.to_string(),
            pkce_verifier: verifier.secret().to_owned(),
            state: state.secret().to_owned(),
        })
    }
}

/// An access token with optional refresh token and expiry.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix seconds at which `access_token` expires (None if unknown).
    pub expires_at: Option<u64>,
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl Token {
    /// True when the token expires within `skew` from now (or already has).
    pub fn expires_within(&self, skew: Duration) -> bool {
        match self.expires_at {
            Some(t) => now_unix() + skew.as_secs() >= t,
            None => false,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_within(Duration::from_secs(0))
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

type ConfiguredClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

fn build_client(
    endpoints: &OAuthEndpoints,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
) -> Result<ConfiguredClient, OAuthError> {
    if client_id.trim().is_empty() {
        return Err(OAuthError::Config("empty OAuth client id".into()));
    }
    let mut client = BasicClient::new(ClientId::new(client_id.to_owned()))
        .set_auth_uri(
            AuthUrl::new(endpoints.auth_url.clone()).map_err(|e| OAuthError::Url(e.to_string()))?,
        )
        .set_token_uri(
            TokenUrl::new(endpoints.token_url.clone())
                .map_err(|e| OAuthError::Url(e.to_string()))?,
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_uri.to_owned())
                .map_err(|e| OAuthError::Url(e.to_string()))?,
        )
        // Both providers accept client credentials in the request body; this
        // also works for public clients that have no secret at all.
        .set_auth_type(AuthType::RequestBody);
    if let Some(secret) = client_secret.filter(|s| !s.is_empty()) {
        client = client.set_client_secret(ClientSecret::new(secret.to_owned()));
    }
    Ok(client)
}

fn http_client(endpoints: &OAuthEndpoints) -> Result<reqwest::Client, OAuthError> {
    crate::tls::ensure_crypto_provider();
    reqwest::Client::builder()
        // Following redirects opens the client up to SSRF (oauth2 docs).
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        // Plain http only towards a loopback mock IdP; never on the network.
        .https_only(!endpoints.allows_plain_http())
        .build()
        .map_err(|e| OAuthError::Token(e.to_string()))
}

fn to_token<T: TokenResponse>(resp: &T) -> Token {
    Token {
        access_token: resp.access_token().secret().to_owned(),
        refresh_token: resp.refresh_token().map(|r| r.secret().to_owned()),
        expires_at: resp.expires_in().map(|d| now_unix() + d.as_secs()),
        scopes: resp
            .scopes()
            .map(|s| s.iter().map(|x| x.to_string()).collect())
            .unwrap_or_default(),
    }
}

/// Exchange an authorization code for tokens. `client_secret` is required
/// for Google "Desktop app" clients (Google does not treat it as secret) and
/// absent for Microsoft public clients.
pub async fn exchange_code(
    provider: Provider,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    code: &str,
    pkce_verifier: &str,
) -> Result<Token, OAuthError> {
    exchange_code_with(
        &OAuthEndpoints::for_provider(provider),
        client_id,
        client_secret,
        redirect_uri,
        code,
        pkce_verifier,
    )
    .await
}

/// [`exchange_code`] against explicit endpoints.
pub async fn exchange_code_with(
    endpoints: &OAuthEndpoints,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    code: &str,
    pkce_verifier: &str,
) -> Result<Token, OAuthError> {
    let client = build_client(endpoints, client_id, client_secret, redirect_uri)?;
    let http = http_client(endpoints)?;
    let resp = client
        .exchange_code(AuthorizationCode::new(code.to_owned()))
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_owned()))
        .request_async(&http)
        .await
        .map_err(|e| OAuthError::Token(e.to_string()))?;
    Ok(to_token(&resp))
}

/// Refresh an access token. Returns a token whose `refresh_token` falls back
/// to the one passed in when the provider does not rotate it.
pub async fn refresh(
    provider: Provider,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
) -> Result<Token, OAuthError> {
    refresh_with(
        &OAuthEndpoints::for_provider(provider),
        provider,
        client_id,
        client_secret,
        refresh_token,
    )
    .await
}

/// [`refresh`] against explicit endpoints.
pub async fn refresh_with(
    endpoints: &OAuthEndpoints,
    provider: Provider,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
) -> Result<Token, OAuthError> {
    // The redirect URI is not used for refresh but the builder wants one.
    let client = build_client(
        endpoints,
        client_id,
        client_secret,
        &provider.loopback_redirect_uri(0),
    )?;
    let http = http_client(endpoints)?;
    let rt = RefreshToken::new(refresh_token.to_owned());
    let mut req = client.exchange_refresh_token(&rt);
    if provider == Provider::Microsoft {
        req = req.add_scopes(
            provider
                .scopes()
                .iter()
                .map(|s| Scope::new((*s).to_owned())),
        );
    }
    let resp = req
        .request_async(&http)
        .await
        .map_err(|e| OAuthError::Token(e.to_string()))?;
    let mut token = to_token(&resp);
    if token.refresh_token.is_none() {
        token.refresh_token = Some(refresh_token.to_owned());
    }
    Ok(token)
}

/// The raw (un-encoded) XOAUTH2 initial client response:
/// `user=<user>\x01auth=Bearer <token>\x01\x01`.
pub fn xoauth2_sasl_raw(user: &str, access_token: &str) -> String {
    format!("user={user}\x01auth=Bearer {access_token}\x01\x01")
}

/// Base64 XOAUTH2 string as sent on the wire after `AUTHENTICATE XOAUTH2` /
/// `AUTH XOAUTH2`.
pub fn xoauth2_sasl(user: &str, access_token: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(xoauth2_sasl_raw(user, access_token))
}

/// S256 PKCE challenge for a verifier (RFC 7636 §4.2), base64url without padding.
pub fn pkce_challenge_s256(verifier: &str) -> String {
    PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier.to_owned()))
        .as_str()
        .to_owned()
}

/// What the browser delivered to the loopback listener.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthCode {
    pub code: String,
    pub state: Option<String>,
}

impl std::fmt::Debug for AuthCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCode")
            .field("code", &"<redacted>")
            .field("state", &self.state)
            .finish()
    }
}

/// Listen once on `127.0.0.1:port` (0 = ephemeral; see [`bind_loopback`]) for
/// the OAuth redirect, answer the browser with a small HTML page and return
/// the `code`. When `expected_state` is given, a mismatch is an error.
pub async fn wait_for_code(
    port: u16,
    expected_state: Option<&str>,
    timeout: Duration,
) -> Result<AuthCode, OAuthError> {
    let listener = bind_loopback(port).await?;
    wait_for_code_on(listener, expected_state, timeout).await
}

/// Bind the loopback listener up front (so the port is known before the
/// authorization URL is built); then call [`wait_for_code_on`].
pub async fn bind_loopback(port: u16) -> Result<TcpListener, OAuthError> {
    TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| OAuthError::Listener(format!("bind 127.0.0.1:{port}: {e}")))
}

/// Accept one redirect on an already-bound listener.
pub async fn wait_for_code_on(
    listener: TcpListener,
    expected_state: Option<&str>,
    timeout: Duration,
) -> Result<AuthCode, OAuthError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(OAuthError::Listener(
                "timed out waiting for the browser redirect".into(),
            ));
        }
        let (mut sock, _) = tokio::time::timeout(remaining, listener.accept())
            .await
            .map_err(|_| OAuthError::Listener("timed out waiting for the browser redirect".into()))?
            .map_err(|e| OAuthError::Listener(e.to_string()))?;

        let mut buf = Vec::with_capacity(2048);
        let mut chunk = [0u8; 1024];
        let read = async {
            loop {
                let n = sock.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
                    break;
                }
            }
            Ok::<_, std::io::Error>(())
        };
        if tokio::time::timeout(Duration::from_secs(10), read)
            .await
            .is_err()
        {
            continue;
        }
        let request = String::from_utf8_lossy(&buf);
        let Some(first_line) = request.lines().next() else {
            continue;
        };
        let mut parts = first_line.split_whitespace();
        let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
            continue;
        };
        if method != "GET" {
            let _ = respond(&mut sock, 405, "Method not allowed").await;
            continue;
        }
        // Browsers also ask for /favicon.ico; ignore anything without a query.
        let Ok(url) = url::Url::parse(&format!("http://localhost{target}")) else {
            continue;
        };
        let mut code = None;
        let mut state = None;
        let mut error = None;
        let mut error_desc = None;
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                "error" => error = Some(v.into_owned()),
                "error_description" => error_desc = Some(v.into_owned()),
                _ => {}
            }
        }
        if let Some(err) = error {
            let _ = respond(
                &mut sock,
                200,
                "Sign-in was cancelled. You can close this window.",
            )
            .await;
            return Err(OAuthError::Denied(match error_desc {
                Some(d) => format!("{err}: {d}"),
                None => err,
            }));
        }
        let Some(code) = code else {
            let _ = respond(&mut sock, 404, "Not found").await;
            continue;
        };
        if let Some(expected) = expected_state {
            if state.as_deref() != Some(expected) {
                let _ = respond(
                    &mut sock,
                    400,
                    "State mismatch. Please try signing in again.",
                )
                .await;
                return Err(OAuthError::StateMismatch);
            }
        }
        let _ = respond(
            &mut sock,
            200,
            "Sealbox is now connected to your mailbox. You can close this window.",
        )
        .await;
        return Ok(AuthCode { code, state });
    }
}

async fn respond(sock: &mut tokio::net::TcpStream, status: u16, text: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sealbox</title></head>\
         <body style=\"font-family:system-ui;margin:3em\"><h1>Sealbox</h1><p>{text}</p></body></html>"
    );
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(body.as_bytes()).await?;
    sock.flush().await?;
    sock.shutdown().await
}
