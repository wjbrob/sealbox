//! Router assembly plus the cross-cutting middleware (security headers, tracing).

pub mod backup;
pub mod guest;
pub mod health;
pub mod hosted;
pub mod kt;
pub mod static_files;
pub mod vks;

use axum::{
    extract::{MatchedPath, Request},
    http::{header, HeaderValue},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Router,
};
use tower_http::{
    classify::{ServerErrorsAsFailures, SharedClassifier},
    trace::{DefaultOnResponse, TraceLayer},
};
use tracing::Level;

use crate::{error::AppError, state::AppState};

/// All routes, before the global layers are applied (see [`crate::app`]).
pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(health::root))
        .route("/v1/health", get(health::health))
        // Key directory (VKS-compatible subset)
        .route("/vks/v1/upload", post(vks::upload))
        .route("/vks/v1/request-verify", post(vks::request_verify))
        .route("/vks/v1/verify/{challenge}", get(vks::verify))
        .route("/vks/v1/by-email/{email}", get(vks::by_email))
        .route("/vks/v1/by-fingerprint/{fpr}", get(vks::by_fingerprint))
        // Key-transparency log over the directory (G30)
        .route("/v1/kt/key", get(kt::key))
        .route("/v1/kt/sth", get(kt::sth))
        .route("/v1/kt/proof/by-email/{email}", get(kt::proof_by_email))
        .route("/v1/kt/consistency", get(kt::consistency))
        .route("/v1/kt/entries", get(kt::entries))
        // Guest messages
        .route("/v1/guest", post(guest::create))
        .route("/v1/guest/{id}", get(guest::fetch))
        .route("/v1/guest/{id}/send-code", post(guest::send_code))
        .route("/v1/guest/{id}/verify", post(guest::verify))
        .route("/v1/guest/{id}/reply", post(guest::reply))
        .route("/v1/guest/{id}/replies", get(guest::replies))
        // Client-encrypted backups
        .route("/v1/backup/{fpr}", put(backup::put).get(backup::get))
        // Hosted mailboxes ("Create a new Sealbox address"); 404 unless configured
        .route("/v1/hosted/info", get(hosted::info))
        .route("/v1/hosted/availability", get(hosted::availability))
        .route("/v1/hosted/signup", post(hosted::signup))
        // Static guest viewer
        .route("/g/{id}", get(static_files::viewer_page))
        .nest_service("/static", static_files::static_service(&state))
        .fallback(not_found)
}

async fn not_found() -> Response {
    AppError::NotFound.into_response()
}

/// Content-Security-Policy for everything we serve: scripts and styles only from ourselves,
/// no remote content of any kind, no framing. `'wasm-unsafe-eval'` lets OpenPGP.js instantiate
/// its bundled Argon2 WebAssembly module (RFC 9580 S2K); it does not permit JavaScript `eval`.
/// `require-trusted-types-for 'script'` makes the browser refuse string-to-DOM sinks such as
/// `innerHTML`, which is our guard against ever rendering decrypted text as HTML.
pub const CONTENT_SECURITY_POLICY: &str =
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; \
     style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; \
     base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; \
     require-trusted-types-for 'script'";

/// Adds security headers to every response and `Cache-Control: no-store` to API responses.
pub async fn security_headers(req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let is_api = path.starts_with("/v1/") || path.starts_with("/vks/");
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    if is_api {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

/// The concrete `TraceLayer` type produced by [`trace_layer`].
pub type HttpTraceLayer = TraceLayer<
    SharedClassifier<ServerErrorsAsFailures>,
    fn(&Request) -> tracing::Span,
    tower_http::trace::DefaultOnRequest,
    DefaultOnResponse,
>;

/// Request tracing that logs the *route template* (`/v1/guest/{id}`), never the concrete path,
/// query string or body, so ids, tokens and challenge secrets stay out of the logs.
pub fn trace_layer() -> HttpTraceLayer {
    fn make_span(req: &Request) -> tracing::Span {
        let route = req
            .extensions()
            .get::<MatchedPath>()
            .map(|m| m.as_str().to_owned())
            .unwrap_or_else(|| "<unmatched>".to_owned());
        tracing::info_span!("http", method = %req.method(), route = %route)
    }
    TraceLayer::new_for_http()
        .make_span_with(make_span as fn(&Request) -> tracing::Span)
        .on_response(DefaultOnResponse::new().level(Level::INFO))
}
