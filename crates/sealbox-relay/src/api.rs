//! The registration API (axum): `POST /v1/push/register`, `DELETE /v1/push/register/{id}`,
//! `GET /v1/push/status/{id}`, `GET /v1/health`.
//!
//! Every `/v1/push/*` route requires `Authorization: Bearer <api token>` when a token is
//! configured; `/v1/health` is open. Request bodies are parsed by hand so a malformed body is
//! answered with a shape-only message (serde's type-mismatch text can echo the offending
//! value, which could be a credential pasted into the wrong field). Responses carry
//! `Cache-Control: no-store`.
//!
//! Registration policies (threat-model R9): `security: "plain"` only for a local IMAP host
//! ([`crate::host_class::plain_imap_allowed`]); the IMAP destination through the IMAP guard
//! ([`crate::imap_guard`]: allow-list, public addresses only) before the registration is
//! accepted and again before every connect; webhook URLs through the SSRF guard
//! ([`crate::webhook_guard`]) before the registration is accepted and again at every delivery;
//! at most `register_rate_limit` registrations per client address per minute
//! ([`crate::rate_limit`]). Whether the relay may start without a token is decided by
//! [`crate::bind_policy`] in the binary.

use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use reqwest::Url;
use sealbox_mail::Security;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::{
    error::{ApiError, ApiResult, RelayError},
    host_class,
    imap_guard::{ImapAllowHosts, ImapGuard, ImapPolicy},
    push::{LogTransport, PushTransport},
    rate_limit::{self, ClientKey, Decision, RateLimiter},
    registry::{
        MailboxSpec, NewRegistration, ParkReason, RegistrationState, RegistrationStatus, Registry,
    },
    secret::{Credentials, Secret},
    webhook_guard::{
        AllowHosts, NameResolver, SystemResolver, WebhookGuard, WebhookPolicy, Webhooks,
        RESOLVE_TIMEOUT,
    },
    worker::{self, WorkerConfig},
};

/// Crate version, reported by `GET /v1/health`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Relay-wide settings. The defaults are the production policy; `imap_allow_private` and the
/// `webhook_allow_*` flags are development and test escape hatches.
#[derive(Clone, Debug)]
pub struct Options {
    pub max_registrations: usize,
    /// When set, `/v1/push/*` requires this bearer. Unset = open relay; the binary refuses to
    /// start that way on a non-loopback bind (see [`crate::bind_policy`]).
    pub api_token: Option<Secret>,
    /// Request body limit; a registration is a few hundred bytes.
    pub max_body_bytes: usize,
    /// How long unregister / shutdown waits for a worker before aborting it.
    pub stop_grace: Duration,
    pub worker: WorkerConfig,
    /// Development and tests: let registrations target IMAP servers on loopback, private
    /// (RFC 1918), link-local, unique-local and other non-public addresses (a local GreenMail).
    /// Off: such a destination is refused at registration and before every connect.
    pub imap_allow_private: bool,
    /// When set, the only IMAP hosts accepted (exact names, `.suffix` entries, IP literals).
    pub imap_allow_hosts: Option<ImapAllowHosts>,
    /// Development and tests: let webhooks target loopback, private (RFC 1918), link-local,
    /// unique-local and other non-public addresses. Off: such a destination is refused at
    /// registration and at delivery.
    pub webhook_allow_private: bool,
    /// Development: accept `http://` webhooks to a non-public destination. Has an effect only
    /// together with `webhook_allow_private`; `http` to a public host is always refused.
    pub webhook_allow_http_private: bool,
    /// When set, the only webhook hosts accepted (a name admits its subdomains).
    pub webhook_allow_hosts: Option<AllowHosts>,
    /// `POST /v1/push/register` attempts per client address per `register_rate_window`;
    /// beyond that **429** with `Retry-After`. `0` disables the limit.
    pub register_rate_limit: u32,
    pub register_rate_window: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_registrations: 1000,
            api_token: None,
            max_body_bytes: 64 * 1024,
            stop_grace: Duration::from_secs(5),
            worker: WorkerConfig::default(),
            imap_allow_private: false,
            imap_allow_hosts: None,
            webhook_allow_private: false,
            webhook_allow_http_private: false,
            webhook_allow_hosts: None,
            register_rate_limit: rate_limit::DEFAULT_LIMIT,
            register_rate_window: rate_limit::DEFAULT_WINDOW,
        }
    }
}

impl Options {
    /// The IMAP destination policy these options describe.
    pub fn imap_policy(&self) -> ImapPolicy {
        ImapPolicy {
            allow_private: self.imap_allow_private,
            allow_hosts: self.imap_allow_hosts.clone(),
        }
    }

    /// The webhook destination policy these options describe.
    pub fn webhook_policy(&self) -> WebhookPolicy {
        WebhookPolicy {
            allow_private: self.webhook_allow_private,
            allow_http_private: self.webhook_allow_http_private,
            allow_hosts: self.webhook_allow_hosts.clone(),
        }
    }
}

struct Inner {
    registry: Registry,
    imap: Arc<ImapGuard>,
    webhooks: Webhooks,
    register_limiter: RateLimiter,
    options: Options,
}

/// Shared state: the registry, the IMAP guard, the guarded webhook clients, the rate limiter,
/// the options.
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl AppState {
    /// Fails only if the webhook HTTP clients cannot be built; the relay never falls back to an
    /// unguarded client.
    pub fn new(options: Options) -> Result<Self, RelayError> {
        Self::with_resolver(options, Arc::new(SystemResolver))
    }

    /// Like [`AppState::new`], resolving IMAP and webhook hosts with `resolver` instead of the
    /// system resolver (tests; embedders with their own DNS).
    pub fn with_resolver(
        options: Options,
        resolver: Arc<dyn NameResolver>,
    ) -> Result<Self, RelayError> {
        let imap = Arc::new(ImapGuard::with_resolver(
            options.imap_policy(),
            resolver.clone(),
            RESOLVE_TIMEOUT,
        ));
        let guard =
            WebhookGuard::with_resolver(options.webhook_policy(), resolver, RESOLVE_TIMEOUT);
        let webhooks = Webhooks::new(guard)
            .map_err(|e| RelayError::Setup(format!("webhook HTTP client: {e}")))?;
        let register_limiter = RateLimiter::new(
            options.register_rate_limit,
            options.register_rate_window,
            rate_limit::DEFAULT_MAX_CLIENTS,
        );
        Ok(Self(Arc::new(Inner {
            registry: Registry::new(options.max_registrations),
            imap,
            webhooks,
            register_limiter,
            options,
        })))
    }

    pub fn registry(&self) -> &Registry {
        &self.0.registry
    }

    pub fn options(&self) -> &Options {
        &self.0.options
    }

    /// The IMAP destination guard (registration and every worker connect).
    pub fn imap_guard(&self) -> &Arc<ImapGuard> {
        &self.0.imap
    }

    /// The webhook guard and its clients.
    pub fn webhooks(&self) -> &Webhooks {
        &self.0.webhooks
    }

    /// Cancel every worker and wait (bounded) for each to exit.
    pub async fn shutdown(&self) {
        let regs = self.registry().drain();
        for reg in regs {
            reg.stop(self.options().stop_grace).await;
        }
    }
}

// ---- wire types -------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    imap: ImapSpec,
    username: String,
    #[serde(default)]
    password: Option<Secret>,
    #[serde(default)]
    oauth_token: Option<Secret>,
    #[serde(default)]
    folder: Option<String>,
    transport: TransportSpec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImapSpec {
    host: String,
    port: u16,
    security: SecuritySpec,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SecuritySpec {
    Tls,
    Starttls,
    Plain,
}

impl From<SecuritySpec> for Security {
    fn from(s: SecuritySpec) -> Self {
        match s {
            SecuritySpec::Tls => Security::Tls,
            SecuritySpec::Starttls => Security::StartTls,
            SecuritySpec::Plain => Security::Plain,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum TransportSpec {
    Webhook {
        url: String,
        #[serde(default)]
        bearer: Option<Secret>,
    },
    Log,
}

#[derive(Serialize)]
struct RegisterResponse {
    registration_id: String,
    state: RegistrationState,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    registrations: usize,
    max_registrations: usize,
}

// ---- validation -------------------------------------------------------------------------

const MAX_HOST: usize = 253;
const MAX_USERNAME: usize = 320;
const MAX_FOLDER: usize = 255;
const MAX_URL: usize = 2048;

/// The 400 reason for an `oauth_token` with a host that is not its provider's own mail host
/// (`sealbox-mail` would never present the token there). Names no value.
pub const OAUTH_HOST_REFUSED_AT_REGISTRATION: &str = "oauth_token can only be used with the \
     provider's own IMAP host (Google or Microsoft mail hosts); use a password for this host";

/// The 400 reason for `security: "plain"` towards a host that is not local by its literal form.
pub const PLAIN_IMAP_REFUSED: &str = "imap.security \"plain\" (no TLS) is accepted only for a \
     local IMAP host: a loopback, private (RFC 1918), link-local or unique-local address, \
     localhost, or a name under .test, .local, .localhost, .internal, .lan, .home or .invalid; \
     use \"tls\" or \"starttls\"";

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::BadRequest(msg.into())
}

fn plain_text(field: &str, value: &str, max: usize) -> ApiResult<()> {
    if value.is_empty() {
        return Err(bad(format!("{field} must not be empty")));
    }
    if value.len() > max {
        return Err(bad(format!("{field} is longer than {max} bytes")));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(bad(format!("{field} contains control characters")));
    }
    Ok(())
}

fn parse_json<T: DeserializeOwned>(body: &[u8]) -> ApiResult<T> {
    serde_json::from_slice(body).map_err(|e| {
        let msg = e.to_string();
        // Field names are safe to echo; values (type mismatches, unknown enum variants) are not.
        let shape = ["missing field", "unknown field", "duplicate field"]
            .iter()
            .any(|p| msg.starts_with(p));
        if msg.starts_with("unknown variant") {
            // serde: "unknown variant `<value>`, expected <list> at line L column C". The value
            // came from the client; keep only serde's own suffix (the value precedes it, so the
            // last ", expected " is serde's even if the value contains that text).
            let expected = msg
                .rfind(", expected ")
                .map_or("", |i| &msg[i..])
                .to_owned();
            bad(format!(
                "invalid request body: unknown variant (value not echoed){expected}"
            ))
        } else if shape {
            bad(format!("invalid request body: {msg}"))
        } else if e.is_syntax() || e.is_eof() {
            bad(format!(
                "invalid request body: malformed JSON at line {} column {}",
                e.line(),
                e.column()
            ))
        } else {
            bad(format!(
                "invalid request body: wrong type or value at line {} column {}",
                e.line(),
                e.column()
            ))
        }
    })
}

/// A registration that passed every check that needs no network; the webhook destination
/// (DNS) is checked next, by [`register`].
struct Checked {
    mailbox: MailboxSpec,
    folder: String,
    transport: CheckedTransport,
    extra_secrets: Vec<Secret>,
}

enum CheckedTransport {
    Log,
    Webhook { url: Url, bearer: Option<Secret> },
}

impl RegisterRequest {
    fn validate(self) -> ApiResult<Checked> {
        let host = self.imap.host.trim().to_owned();
        plain_text("imap.host", &host, MAX_HOST)?;
        if host.chars().any(char::is_whitespace) {
            return Err(bad("imap.host contains whitespace"));
        }
        if self.imap.port == 0 {
            return Err(bad("imap.port must be 1..=65535"));
        }
        // Credentials in clear only to a host that is local by its literal form (no DNS).
        if matches!(self.imap.security, SecuritySpec::Plain)
            && !host_class::plain_imap_allowed(&host)
        {
            return Err(bad(PLAIN_IMAP_REFUSED));
        }
        plain_text("username", &self.username, MAX_USERNAME)?;
        // A credential with a control character (CR, LF, NUL, …) can never be sent as an IMAP
        // string or a SASL response: the login would fail the same way on every attempt, so it is
        // refused here (the reason names the field, never the value).
        let credentials = match (self.password, self.oauth_token) {
            (Some(p), None) => {
                if p.is_empty() {
                    return Err(bad("password must not be empty"));
                }
                if p.expose().chars().any(char::is_control) {
                    return Err(bad("password contains control characters"));
                }
                Credentials::Password(p)
            }
            (None, Some(t)) => {
                if t.is_empty() {
                    return Err(bad("oauth_token must not be empty"));
                }
                if t.expose().chars().any(char::is_control) {
                    return Err(bad("oauth_token contains control characters"));
                }
                // `sealbox-mail` presents a bearer only to its provider's own mail hosts
                // (docs/THREAT_MODEL.md R14), so a token for any other host could never log in:
                // refused here instead of parking a worker that never connects.
                if sealbox_mail::net_policy::check_bearer_host(None, &host).is_err() {
                    return Err(bad(OAUTH_HOST_REFUSED_AT_REGISTRATION));
                }
                Credentials::OAuth(t)
            }
            (None, None) => return Err(bad("one of password or oauth_token is required")),
            (Some(_), Some(_)) => return Err(bad("give either password or oauth_token, not both")),
        };
        let folder = self.folder.unwrap_or_else(|| "INBOX".to_owned());
        plain_text("folder", &folder, MAX_FOLDER)?;

        let mut extra_secrets = Vec::new();
        let transport = match self.transport {
            TransportSpec::Log => CheckedTransport::Log,
            TransportSpec::Webhook { url, bearer } => {
                if url.len() > MAX_URL {
                    return Err(bad(format!("transport.url is longer than {MAX_URL} bytes")));
                }
                let parsed = reqwest::Url::parse(url.trim())
                    .map_err(|_| bad("transport.url is not a valid URL"))?;
                if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                    return Err(bad("transport.url must be an http(s) URL with a host"));
                }
                if let Some(b) = &bearer {
                    if b.is_empty() {
                        return Err(bad("transport.bearer must not be empty"));
                    }
                    if HeaderValue::from_str(&format!("Bearer {}", b.expose())).is_err() {
                        return Err(bad("transport.bearer is not a valid header value"));
                    }
                    extra_secrets.push(b.clone());
                }
                CheckedTransport::Webhook {
                    url: parsed,
                    bearer,
                }
            }
        };

        Ok(Checked {
            mailbox: MailboxSpec {
                host,
                port: self.imap.port,
                security: self.imap.security.into(),
                username: self.username,
                credentials,
            },
            folder,
            transport,
            extra_secrets,
        })
    }
}

// ---- handlers ---------------------------------------------------------------------------

async fn register(
    State(state): State<AppState>,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<RegisterResponse>)> {
    let req: RegisterRequest = parse_json(&body)?;
    let checked = req.validate()?;
    // Before anything is stored: the IMAP destination (allow-list, then every address). The
    // worker checks again before every connect and dials only the addresses that passed.
    state
        .imap_guard()
        .check(&checked.mailbox.host)
        .await
        .map_err(|refusal| bad(refusal.to_string()))?;
    let transport: Box<dyn PushTransport> = match checked.transport {
        CheckedTransport::Log => Box::new(LogTransport),
        CheckedTransport::Webhook { url, bearer } => {
            // Before anything is stored: allow-list, scheme, and every resolved address.
            state
                .webhooks()
                .check(&url)
                .await
                .map_err(|refusal| bad(refusal.to_string()))?;
            Box::new(state.webhooks().transport(&url, bearer))
        }
    };
    let spec = NewRegistration {
        mailbox: checked.mailbox,
        folder: checked.folder,
        transport,
        extra_secrets: checked.extra_secrets,
    };
    let reg = state.registry().insert(spec)?;
    reg.attach_task(worker::spawn(
        reg.clone(),
        state.options().worker.clone(),
        state.imap_guard().clone(),
    ));
    tracing::info!(
        registration = reg.id(),
        transport = reg.transport().kind(),
        total = state.registry().len(),
        "registered"
    );
    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            registration_id: reg.id().to_owned(),
            state: reg.state(),
        }),
    ))
}

async fn unregister(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let reg = state.registry().remove(&id)?;
    reg.stop(state.options().stop_grace).await;
    let snap = reg.snapshot();
    tracing::info!(
        registration = reg.id(),
        pushes = snap.pushes,
        // A parked registration removed before its TTL: the category only, no server text.
        parked = snap.parked_reason.map_or("no", ParkReason::as_str),
        total = state.registry().len(),
        "unregistered"
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<RegistrationStatus>> {
    let reg = state.registry().get(&id).ok_or(ApiError::NotFound)?;
    Ok(Json(reg.snapshot()))
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        status: "ok",
        version: VERSION,
        registrations: state.registry().len(),
        max_registrations: state.registry().max_registrations(),
    })
}

// ---- middleware -------------------------------------------------------------------------

/// Constant-time byte comparison (lengths may leak; the token is not derived from them).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn require_api_token(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(expected) = &state.options().api_token {
        let presented = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim);
        match presented {
            Some(t) if ct_eq(t.as_bytes(), expected.expose().as_bytes()) => {}
            _ => return ApiError::Unauthorized.into_response(),
        }
    }
    next.run(req).await
}

/// At most `register_rate_limit` registration attempts per client address per window. Runs
/// after the token check, so only authenticated attempts count; every one of those counts,
/// whatever its outcome. The client address comes from the connection (`ConnectInfo`), never
/// from a header.
async fn limit_registrations(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let key = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(ClientKey::Unknown, |ConnectInfo(peer)| {
            ClientKey::of(peer.ip())
        });
    if let Decision::Limited { retry_after } = state.0.register_limiter.check(key) {
        let retry_after_secs = Decision::retry_after_secs(retry_after);
        // Debug, not info: one line per refused request would let a flood fill the log.
        tracing::debug!(
            retry_after_secs,
            "registration rate limit reached for a client"
        );
        return ApiError::RateLimited { retry_after_secs }.into_response();
    }
    next.run(req).await
}

async fn no_store(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

// ---- router -----------------------------------------------------------------------------

/// Build the router for `state`.
pub fn app(state: AppState) -> Router {
    let max_body = state.options().max_body_bytes;
    let protected = Router::new()
        .route(
            "/v1/push/register",
            post(register).route_layer(middleware::from_fn_with_state(
                state.clone(),
                limit_registrations,
            )),
        )
        .route("/v1/push/register/{id}", delete(unregister))
        .route("/v1/push/status/{id}", get(status))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_token,
        ));
    Router::new()
        .merge(protected)
        .route("/v1/health", get(health))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(middleware::from_fn(no_store))
        .with_state(state)
}

/// Serve `app(state)` on `listener` until `shutdown` resolves (in-flight requests finish).
/// The caller then runs [`AppState::shutdown`] to stop the workers. Each request carries its
/// peer address (`ConnectInfo`) for the registration rate limit.
pub async fn serve<F>(listener: TcpListener, state: AppState, shutdown: F) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhook_guard::Refusal;
    use serde_json::{json, Value};
    use tokio::sync::oneshot;

    struct Relay {
        base: String,
        state: AppState,
        stop: Option<oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
    }

    impl Relay {
        async fn start(options: Options) -> Self {
            Self::start_state(AppState::new(options).expect("state")).await
        }

        async fn start_state(state: AppState) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let base = format!("http://{}", listener.local_addr().expect("addr"));
            let (tx, rx) = oneshot::channel();
            let task = tokio::spawn(serve(listener, state.clone(), async move {
                let _ = rx.await;
            }));
            Self {
                base,
                state,
                stop: Some(tx),
                task,
            }
        }

        async fn finish(mut self) {
            self.state.shutdown().await;
            if let Some(tx) = self.stop.take() {
                let _ = tx.send(());
            }
            let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
        }
    }

    fn closed_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let p = l.local_addr().expect("addr").port();
        drop(l);
        p
    }

    fn register_body(port: u16) -> Value {
        json!({
            "imap": {"host": "127.0.0.1", "port": port, "security": "plain"},
            "username": "u76",
            "password": "pw-secret-abc",
            "transport": {"kind": "log"}
        })
    }

    async fn post(base: &str, token: Option<&str>, body: &Value) -> (StatusCode, Value) {
        let mut req = reqwest::Client::new()
            .post(format!("{base}/v1/push/register"))
            .json(body);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.expect("send");
        let status = resp.status();
        let text = resp.text().await.expect("text");
        let v = serde_json::from_str(&text).unwrap_or(Value::String(text));
        (status, v)
    }

    async fn get(base: &str, token: Option<&str>, path: &str) -> (StatusCode, Value) {
        let mut req = reqwest::Client::new().get(format!("{base}{path}"));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.expect("send");
        let status = resp.status();
        let text = resp.text().await.expect("text");
        let v = serde_json::from_str(&text).unwrap_or(Value::String(text));
        (status, v)
    }

    async fn del(base: &str, token: Option<&str>, id: &str) -> StatusCode {
        let mut req = reqwest::Client::new().delete(format!("{base}/v1/push/register/{id}"));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        req.send().await.expect("send").status()
    }

    /// The API tests' IMAP side is a closed port or a scripted server on loopback, so their
    /// relays set `imap_allow_private` explicitly; the IMAP policy tests below run without it.
    fn fast_worker() -> WorkerConfig {
        WorkerConfig {
            connect_timeout: Duration::from_secs(2),
            backoff_min: Duration::from_millis(50),
            backoff_max: Duration::from_millis(200),
            ..WorkerConfig::default()
        }
    }

    #[tokio::test]
    async fn health_is_open_and_push_routes_require_the_token() {
        let relay = Relay::start(Options {
            api_token: Some(Secret::new("relay-token-123")),
            imap_allow_private: true,
            worker: fast_worker(),
            ..Options::default()
        })
        .await;
        let (st, v) = get(&relay.base, None, "/v1/health").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["status"], "ok");
        assert_eq!(v["registrations"], 0);

        let body = register_body(closed_port());
        let (st, v) = post(&relay.base, None, &body).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{v}");
        assert_eq!(v["error"], "unauthorized");
        let (st, _) = post(&relay.base, Some("relay-token-124"), &body).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let (st, _) = get(&relay.base, None, "/v1/push/status/abc").await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert_eq!(
            del(&relay.base, None, "abc").await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(relay.state.registry().len(), 0);

        let (st, v) = post(&relay.base, Some("relay-token-123"), &body).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        let id = v["registration_id"].as_str().expect("id").to_owned();
        assert_eq!(
            del(&relay.base, Some("relay-token-123"), &id).await,
            StatusCode::NO_CONTENT
        );
        relay.finish().await;
    }

    #[tokio::test]
    async fn register_status_unregister_round_trip_never_leaks_the_password() {
        let relay = Relay::start(Options {
            imap_allow_private: true,
            worker: fast_worker(),
            ..Options::default()
        })
        .await;
        let (st, v) = post(&relay.base, None, &register_body(closed_port())).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        assert_eq!(v["state"], "connecting");
        let id = v["registration_id"].as_str().expect("id").to_owned();
        assert_eq!(id.len(), 32);

        let path = format!("/v1/push/status/{id}");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let body = loop {
            let (st, v) = get(&relay.base, None, &path).await;
            assert_eq!(st, StatusCode::OK, "{v}");
            if v["state"] == "error" {
                break v;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "never reached error: {v}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let text = body.to_string();
        assert!(!text.contains("pw-secret-abc"), "{text}");
        assert_eq!(body["transport"], "log");
        assert_eq!(body["folder"], "INBOX");
        assert_eq!(body["pushes"], 0);
        assert!(body["last_error"].as_str().is_some_and(|e| !e.is_empty()));
        let mut keys: Vec<&str> = body
            .as_object()
            .expect("obj")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "created_at",
                "folder",
                "last_error",
                "last_push_at",
                "parked_reason",
                "pushes",
                "registration_id",
                "state",
                "transport"
            ]
        );

        assert_eq!(del(&relay.base, None, &id).await, StatusCode::NO_CONTENT);
        let (st, _) = get(&relay.base, None, &path).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        assert_eq!(del(&relay.base, None, &id).await, StatusCode::NOT_FOUND);
        relay.finish().await;
    }

    #[tokio::test]
    async fn cap_returns_429_until_a_slot_is_freed() {
        let relay = Relay::start(Options {
            max_registrations: 2,
            imap_allow_private: true,
            worker: fast_worker(),
            ..Options::default()
        })
        .await;
        let body = register_body(closed_port());
        let (st, a) = post(&relay.base, None, &body).await;
        assert_eq!(st, StatusCode::CREATED);
        let (st, _) = post(&relay.base, None, &body).await;
        assert_eq!(st, StatusCode::CREATED);
        let (st, v) = post(&relay.base, None, &body).await;
        assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "{v}");
        assert_eq!(v["error"], "registration limit reached");
        let id = a["registration_id"].as_str().expect("id");
        assert_eq!(del(&relay.base, None, id).await, StatusCode::NO_CONTENT);
        let (st, _) = post(&relay.base, None, &body).await;
        assert_eq!(st, StatusCode::CREATED);
        relay.finish().await;
    }

    #[tokio::test]
    async fn validation_rejects_bad_input_without_echoing_values() {
        let relay = Relay::start(Options::default()).await;
        let port = closed_port();
        let mut cases: Vec<(Value, &str)> = Vec::new();
        let mut b = register_body(port);
        b["imap"]["port"] = json!(0);
        cases.push((b, "port"));
        let mut b = register_body(port);
        b["oauth_token"] = json!("tok");
        cases.push((b, "not both"));
        let mut b = register_body(port);
        b.as_object_mut().expect("obj").remove("password");
        cases.push((b, "password or oauth_token"));
        let mut b = register_body(port);
        b["transport"] = json!({"kind": "webhook", "url": "ftp://x/hook"});
        cases.push((b, "http(s)"));
        let mut b = register_body(port);
        b["transport"] = json!({"kind": "webhook", "url": "http://127.0.0.1:1/h", "bearer": ""});
        cases.push((b, "bearer"));
        let mut b = register_body(port);
        b["subject"] = json!("nope");
        cases.push((b, "unknown field"));
        let mut b = register_body(port);
        b["imap"]["security"] = json!("ssl");
        cases.push((b, "unknown variant"));
        // An unknown variant is a client value: not echoed, but the allowed ones are listed.
        let mut b = register_body(port);
        b["transport"]["kind"] = json!("pw-secret-abc");
        cases.push((b, "expected `webhook` or `log`"));
        let mut b = register_body(port);
        b["folder"] = json!("IN\nBOX");
        cases.push((b, "control"));
        // A credential that can never be sent (CR/LF/NUL) is refused up front instead of
        // failing every login attempt forever; the reason names the field only.
        let mut b = register_body(port);
        b["password"] = json!("pw-secret\r\nabc");
        cases.push((b, "password contains control"));
        let mut b = register_body(port);
        b.as_object_mut().expect("obj").remove("password");
        b["oauth_token"] = json!("ya29.pw-secret\u{0}abc");
        cases.push((b, "oauth_token contains control"));
        // A token for a host that is not its provider's (loopback here) could never log in.
        let mut b = register_body(port);
        b.as_object_mut().expect("obj").remove("password");
        b["oauth_token"] = json!("ya29.pw-secret-token");
        cases.push((b, "provider's own IMAP host"));
        let mut b = register_body(port);
        b["imap"]["host"] = json!("  ");
        cases.push((b, "host"));
        for (body, needle) in cases {
            let (st, v) = post(&relay.base, None, &body).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{body} -> {v}");
            let err = v["error"].as_str().expect("error string");
            assert!(err.contains(needle), "{body} -> {err}");
            assert!(!err.contains("pw-secret"), "{err}");
        }
        // A value pasted into a typed field is not echoed back.
        let mut b = register_body(port);
        b["imap"]["port"] = json!("pw-secret-abc");
        let (st, v) = post(&relay.base, None, &b).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(!v.to_string().contains("pw-secret-abc"), "{v}");

        // Malformed JSON and an oversized body.
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/push/register", relay.base))
            .body("{not json")
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let big = "x".repeat(relay.state.options().max_body_bytes + 1);
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/push/register", relay.base))
            .body(big)
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(relay.state.registry().len(), 0);
        relay.finish().await;
    }

    fn webhook_body(port: u16, url: &str) -> Value {
        let mut b = register_body(port);
        b["transport"] = json!({"kind": "webhook", "url": url, "bearer": "hook-bearer-1"});
        b
    }

    async fn expect_400(base: &str, body: &Value, reason: &str, never: &[&str]) {
        let (st, v) = post(base, None, body).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body} -> {v}");
        let err = v["error"].as_str().expect("error string");
        assert_eq!(err, reason, "{body}");
        let text = v.to_string();
        for n in never {
            assert!(!text.contains(n), "{body}: 400 echoes {n:?}: {text}");
        }
    }

    async fn expect_201_then_delete(base: &str, body: &Value) {
        let (st, v) = post(base, None, body).await;
        assert_eq!(st, StatusCode::CREATED, "{body} -> {v}");
        let id = v["registration_id"].as_str().expect("id");
        assert_eq!(del(base, None, id).await, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn plain_imap_is_refused_for_hosts_that_are_not_local() {
        let relay = Relay::start(Options {
            imap_allow_private: true,
            worker: fast_worker(),
            ..Options::default()
        })
        .await;
        let port = closed_port();
        for host in [
            "imap.gmail.com",
            "outlook.office365.com",
            "8.8.8.8",
            "100.64.0.1",
            "2130706433",
            "mail.example.com.test.evil.net",
        ] {
            let mut b = register_body(port);
            b["imap"]["host"] = json!(host);
            expect_400(&relay.base, &b, PLAIN_IMAP_REFUSED, &[host]).await;
            // The same host with TLS passes validation (not registered here: it would connect).
        }
        // Local by their literal form: accepted (the worker then fails on the closed port).
        for host in ["127.0.0.1", "::1", "localhost"] {
            let mut b = register_body(port);
            b["imap"]["host"] = json!(host);
            expect_201_then_delete(&relay.base, &b).await;
        }
        assert_eq!(relay.state.registry().len(), 0);
        relay.finish().await;
    }

    #[tokio::test]
    async fn webhook_destinations_are_refused_by_default_without_echoing_the_url() {
        let relay = Relay::start(Options {
            imap_allow_private: true,
            worker: fast_worker(),
            ..Options::default()
        })
        .await;
        let port = closed_port();
        let https = Refusal::HttpsRequired.to_string();
        let private = Refusal::NonPublic.to_string();
        for (url, reason) in [
            ("http://127.0.0.1:9/hook?cap=s3cr3t-cap", &https),
            ("http://8.8.8.8/hook?cap=s3cr3t-cap", &https),
            ("https://127.0.0.1:9/hook?cap=s3cr3t-cap", &private),
            (
                "https://169.254.169.254/latest/meta-data/?cap=s3cr3t-cap",
                &private,
            ),
            ("https://[::1]:9/hook?cap=s3cr3t-cap", &private),
            ("https://[fd00::1]/hook?cap=s3cr3t-cap", &private),
            ("https://[::ffff:10.0.0.1]/hook?cap=s3cr3t-cap", &private),
            ("https://0x7f000001/hook?cap=s3cr3t-cap", &private),
            ("https://0.0.0.0:9/hook?cap=s3cr3t-cap", &private),
            // Real resolution (/etc/hosts): a name is checked by what it resolves to.
            ("https://localhost:9/hook?cap=s3cr3t-cap", &private),
        ] {
            let host = Url::parse(url)
                .expect("url")
                .host_str()
                .expect("host")
                .to_owned();
            let never = [
                url,
                "s3cr3t-cap",
                "hook-bearer-1",
                host.as_str(),
                "127.0.0.1",
            ];
            expect_400(&relay.base, &webhook_body(port, url), reason, &never).await;
        }
        assert_eq!(relay.state.registry().len(), 0);
        // A public IP literal over https is accepted (no push is attempted: IMAP never connects).
        expect_201_then_delete(
            &relay.base,
            &webhook_body(port, "https://93.184.216.34/hook"),
        )
        .await;
        relay.finish().await;
    }

    #[tokio::test]
    async fn dev_flags_open_private_destinations_only_as_documented() {
        let port = closed_port();
        let loop_http = webhook_body(port, "http://127.0.0.1:9/hook");
        let loop_https = webhook_body(port, "https://127.0.0.1:9/hook");
        let public_http = webhook_body(port, "http://8.8.8.8/hook");
        let https = Refusal::HttpsRequired.to_string();
        let private = Refusal::NonPublic.to_string();

        let both = Relay::start(Options {
            webhook_allow_private: true,
            webhook_allow_http_private: true,
            imap_allow_private: true,
            worker: fast_worker(),
            ..Options::default()
        })
        .await;
        expect_201_then_delete(&both.base, &loop_http).await;
        expect_201_then_delete(&both.base, &loop_https).await;
        expect_400(&both.base, &public_http, &https, &["8.8.8.8"]).await;
        both.finish().await;

        let private_only = Relay::start(Options {
            webhook_allow_private: true,
            imap_allow_private: true,
            worker: fast_worker(),
            ..Options::default()
        })
        .await;
        expect_400(&private_only.base, &loop_http, &https, &["127.0.0.1"]).await;
        expect_201_then_delete(&private_only.base, &loop_https).await;
        private_only.finish().await;

        let http_only = Relay::start(Options {
            webhook_allow_http_private: true,
            imap_allow_private: true,
            worker: fast_worker(),
            ..Options::default()
        })
        .await;
        expect_400(&http_only.base, &loop_http, &private, &["127.0.0.1"]).await;
        expect_400(&http_only.base, &loop_https, &private, &["127.0.0.1"]).await;
        http_only.finish().await;
    }

    #[tokio::test]
    async fn allow_list_restricts_webhook_hosts() {
        use crate::webhook_guard::test_dns::FakeDns;
        let dns = Arc::new(
            FakeDns::new()
                .answer("push.example", &["93.184.216.34"])
                .answer("eu.push.example", &["93.184.216.35"])
                .answer("lan.push.example", &["192.168.1.9"])
                .answer("other.example", &["93.184.216.36"]),
        );
        let state = AppState::with_resolver(
            Options {
                webhook_allow_hosts: AllowHosts::parse(["push.example"]).expect("valid"),
                imap_allow_private: true,
                worker: fast_worker(),
                ..Options::default()
            },
            dns.clone(),
        )
        .expect("state");
        let relay = Relay::start_state(state).await;
        let port = closed_port();
        let listed = Refusal::NotAllowListed.to_string();
        expect_201_then_delete(&relay.base, &webhook_body(port, "https://push.example/h")).await;
        expect_201_then_delete(
            &relay.base,
            &webhook_body(port, "https://eu.push.example/h"),
        )
        .await;
        for url in [
            "https://other.example/h",
            "https://evilpush.example/h",
            "https://push.example.evil.net/h",
            "https://93.184.216.34/h",
        ] {
            expect_400(
                &relay.base,
                &webhook_body(port, url),
                &listed,
                &["example", "93.184"],
            )
            .await;
        }
        expect_400(
            &relay.base,
            &webhook_body(port, "https://lan.push.example/h"),
            &Refusal::NonPublic.to_string(),
            &["lan.push"],
        )
        .await;
        // Two accepted registrations and one private answer: three lookups, none for the
        // hosts the allow-list refused.
        assert_eq!(dns.lookups(), 3);
        relay.finish().await;
    }

    #[tokio::test]
    async fn registrations_are_rate_limited_per_client_with_retry_after() {
        let relay = Relay::start(Options {
            api_token: Some(Secret::new("tok-rl")),
            register_rate_limit: 3,
            imap_allow_private: true,
            worker: fast_worker(),
            ..Options::default()
        })
        .await;
        let port = closed_port();
        let good = register_body(port);
        let mut invalid = register_body(port);
        invalid["imap"]["port"] = json!(0);
        // Unauthenticated attempts are refused before the limiter and do not count.
        for _ in 0..5 {
            assert_eq!(
                post(&relay.base, None, &good).await.0,
                StatusCode::UNAUTHORIZED
            );
        }
        // Three attempts per window, whatever their outcome.
        let (st, a) = post(&relay.base, Some("tok-rl"), &good).await;
        assert_eq!(st, StatusCode::CREATED, "{a}");
        assert_eq!(
            post(&relay.base, Some("tok-rl"), &invalid).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post(&relay.base, Some("tok-rl"), &good).await.0,
            StatusCode::CREATED
        );
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/push/register", relay.base))
            .bearer_auth("tok-rl")
            .json(&good)
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after: u64 = resp
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .expect("Retry-After in seconds");
        assert!((1..=20).contains(&retry_after), "{retry_after}");
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        let v: Value = resp.json().await.expect("json");
        assert_eq!(
            v["error"],
            "too many registrations from this client address; retry after the Retry-After delay"
        );
        assert_eq!(relay.state.registry().len(), 2);
        // Only registration is limited: status, unregister and health still answer.
        let id = a["registration_id"].as_str().expect("id");
        let (st, _) = get(
            &relay.base,
            Some("tok-rl"),
            &format!("/v1/push/status/{id}"),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(
            del(&relay.base, Some("tok-rl"), id).await,
            StatusCode::NO_CONTENT
        );
        let (st, h) = get(&relay.base, None, "/v1/health").await;
        assert_eq!(st, StatusCode::OK);
        let mut keys: Vec<&str> = h
            .as_object()
            .expect("obj")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["max_registrations", "registrations", "status", "version"]
        );
        relay.finish().await;
    }

    /// Poll `GET status` until `state` is `want`.
    async fn wait_for_state(base: &str, id: &str, want: &str) -> Value {
        let path = format!("/v1/push/status/{id}");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let (st, v) = get(base, None, &path).await;
            assert_eq!(st, StatusCode::OK, "{v}");
            if v["state"] == want {
                return v;
            }
            assert!(std::time::Instant::now() < deadline, "never {want}: {v}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn a_parked_registration_says_why_and_delete_removes_it() {
        use crate::worker::{test_imap, CREDENTIALS_REJECTED};
        let (port, connections) = test_imap::scripted_imap(|_| test_imap::Conn::Reject).await;
        let relay = Relay::start(Options {
            imap_allow_private: true,
            worker: fast_worker(),
            ..Options::default()
        })
        .await;
        let (st, v) = post(&relay.base, None, &register_body(port)).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        let id = v["registration_id"].as_str().expect("id").to_owned();
        let parked = wait_for_state(&relay.base, &id, "parked").await;
        assert_eq!(parked["parked_reason"], "credentials_rejected", "{parked}");
        assert_eq!(parked["last_error"], CREDENTIALS_REJECTED, "{parked}");
        let text = parked.to_string();
        for never in ["pw-secret-abc", "u76", "127.0.0.1", "AUTHENTICATIONFAILED"] {
            assert!(!text.contains(never), "{never}: {text}");
        }
        assert_eq!(connections.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(del(&relay.base, None, &id).await, StatusCode::NO_CONTENT);
        let (st, _) = get(&relay.base, None, &format!("/v1/push/status/{id}")).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        assert_eq!(relay.state.registry().len(), 0);
        relay.finish().await;
    }

    #[tokio::test]
    async fn a_parked_registration_is_evicted_after_the_ttl_and_frees_its_slot() {
        use crate::worker::test_imap;
        let (port, _) = test_imap::scripted_imap(|_| test_imap::Conn::Reject).await;
        let relay = Relay::start(Options {
            max_registrations: 1,
            imap_allow_private: true,
            worker: WorkerConfig {
                parked_ttl: Duration::from_millis(300),
                ..fast_worker()
            },
            ..Options::default()
        })
        .await;
        let (st, v) = post(&relay.base, None, &register_body(port)).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        let id = v["registration_id"].as_str().expect("id").to_owned();
        wait_for_state(&relay.base, &id, "parked").await;
        // The slot is taken while parked …
        let (st, _) = post(&relay.base, None, &register_body(closed_port())).await;
        assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
        // … and free once the TTL has run out: the registration is gone.
        let path = format!("/v1/push/status/{id}");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while get(&relay.base, None, &path).await.0 != StatusCode::NOT_FOUND {
            assert!(std::time::Instant::now() < deadline, "never evicted");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (_, health) = get(&relay.base, None, "/v1/health").await;
        assert_eq!(health["registrations"], 0, "{health}");
        assert_eq!(del(&relay.base, None, &id).await, StatusCode::NOT_FOUND);
        let (st, v) = post(&relay.base, None, &register_body(closed_port())).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        relay.finish().await;
    }

    /// A registration for `host` over TLS (no plain-IMAP rule involved).
    fn imap_body(host: &str, port: u16) -> Value {
        let mut b = register_body(port);
        b["imap"] = json!({"host": host, "port": port, "security": "tls"});
        b
    }

    /// A listener on loopback that only counts the connections it accepts.
    async fn counting_listener() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(sock);
            }
        });
        (port, accepted)
    }

    #[tokio::test]
    async fn imap_destinations_are_refused_by_default_without_echoing_the_host() {
        use crate::imap_guard::ImapRefusal;
        use crate::webhook_guard::test_dns::FakeDns;
        let dns = Arc::new(
            FakeDns::new()
                .answer("metadata.example", &["169.254.169.254"])
                .answer("mixed.example", &["93.184.216.34", "10.0.0.7"])
                .answer("empty.example", &[])
                // Public at registration, loopback for every later lookup (the worker's).
                .answer("rebind.example", &["93.184.216.34"])
                .answer("rebind.example", &["127.0.0.1"]),
        );
        let state = AppState::with_resolver(
            Options {
                worker: fast_worker(),
                ..Options::default()
            },
            dns,
        )
        .expect("state");
        let relay = Relay::start_state(state).await;
        let (port, accepted) = counting_listener().await;
        let port_text = port.to_string();
        let non_public = ImapRefusal::NonPublic.to_string();
        let unresolvable = ImapRefusal::Unresolvable.to_string();
        for (host, reason) in [
            ("127.0.0.1", &non_public),
            ("[::1]", &non_public),
            ("10.0.2.2", &non_public),
            ("169.254.169.254", &non_public),
            ("fd00::1", &non_public),
            ("100.64.0.1", &non_public),
            ("224.0.0.1", &non_public),
            ("0.0.0.0", &non_public),
            ("192.0.2.1", &non_public),
            ("::ffff:10.0.0.1", &non_public),
            ("64:ff9b::a9fe:a9fe", &non_public),
            ("2002:c0a8:0101::1", &non_public),
            ("metadata.example", &non_public),
            ("mixed.example", &non_public),
            ("empty.example", &unresolvable),
            ("nxdomain.example", &unresolvable),
        ] {
            let never = [host, port_text.as_str(), "pw-secret-abc", "u76"];
            expect_400(&relay.base, &imap_body(host, port), reason, &never).await;
        }
        // `plain` to a local literal passes the plain-IMAP rule, then meets the address rule.
        let mut plain_local = register_body(port);
        plain_local["imap"]["host"] = json!("127.0.0.1");
        expect_400(&relay.base, &plain_local, &non_public, &["127.0.0.1"]).await;
        assert_eq!(relay.state.registry().len(), 0);

        // A name that rebinds to loopback after registration: accepted, then refused before
        // the worker's connect, and nothing is ever dialled.
        let (st, v) = post(&relay.base, None, &imap_body("rebind.example", port)).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        let id = v["registration_id"].as_str().expect("id").to_owned();
        let path = format!("/v1/push/status/{id}");
        let refused = format!("IMAP destination refused: {non_public}");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let status = loop {
            let (_, v) = get(&relay.base, None, &path).await;
            if v["last_error"] == refused.as_str() {
                break v;
            }
            assert!(std::time::Instant::now() < deadline, "{v}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(status["state"], "error", "{status}");
        assert!(!status.to_string().contains("rebind.example"), "{status}");
        assert_eq!(
            accepted.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the worker dialled a refused destination"
        );
        assert_eq!(del(&relay.base, None, &id).await, StatusCode::NO_CONTENT);
        relay.finish().await;
    }

    #[tokio::test]
    async fn imap_allow_list_restricts_hosts_before_any_lookup() {
        use crate::imap_guard::ImapRefusal;
        use crate::webhook_guard::test_dns::FakeDns;
        // Accepted names answer public once (registration), then loopback, so their workers are
        // refused before connecting and nothing leaves the host.
        let dns = Arc::new(
            FakeDns::new()
                .answer("imap.example.com", &["93.184.216.34"])
                .answer("imap.example.com", &["127.0.0.1"])
                .answer("eu.example.org", &["93.184.216.35"])
                .answer("eu.example.org", &["127.0.0.1"])
                .answer("lan.example.org", &["192.168.1.9"]),
        );
        let state = AppState::with_resolver(
            Options {
                imap_allow_hosts: ImapAllowHosts::parse(["imap.example.com", ".example.org"])
                    .expect("valid"),
                worker: fast_worker(),
                ..Options::default()
            },
            dns.clone(),
        )
        .expect("state");
        let relay = Relay::start_state(state).await;
        let port = closed_port();
        let listed = ImapRefusal::NotAllowListed.to_string();
        for host in [
            "example.org",
            "evilexample.org",
            "x.imap.example.com",
            "imap.example.com.evil.net",
            "93.184.216.34",
            "127.0.0.1",
        ] {
            expect_400(&relay.base, &imap_body(host, port), &listed, &[host]).await;
        }
        assert_eq!(dns.lookups(), 0, "the allow-list is decided without DNS");
        expect_400(
            &relay.base,
            &imap_body("lan.example.org", port),
            &ImapRefusal::NonPublic.to_string(),
            &["lan.example.org"],
        )
        .await;
        expect_201_then_delete(&relay.base, &imap_body("imap.example.com", port)).await;
        expect_201_then_delete(&relay.base, &imap_body("EU.Example.ORG.", port)).await;
        assert_eq!(relay.state.registry().len(), 0);
        relay.finish().await;
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }
}
