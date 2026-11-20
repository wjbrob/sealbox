//! sealbox-server — the small Rust backend of Sealbox (see `docs/ARCHITECTURE.md`, "Server API v1").
//!
//! Three independent services behind one axum router:
//!
//! * **Key directory** (`/vks/v1/*`): a VKS-compatible subset of the keys.openpgp.org API.
//!   Keys are published per e-mail address only after the owner clicks a challenge link that
//!   we mail to that address. Lookups return a key reduced to the verified user ID(s) only.
//! * **Guest messages** (`/v1/guest*`): opaque OpenPGP ciphertext (passphrase/SKESK-encrypted by
//!   the client) stored until it expires, plus encrypted replies from the guest viewer
//!   (`web/guest/`, served at `/g/{id}` and `/static/*`).
//! * **Backups** (`/v1/backup/{fpr}`): client-encrypted blobs; the server verifies a detached
//!   OpenPGP signature to prove possession of the key but can never read the contents.
//!
//! The server never sees plaintext, never logs request bodies, and keeps all secrets
//! (upload tokens, challenge tokens, pickup tokens, backup tokens) hashed at rest.
//!
//! [`app`] builds the router for a given [`AppState`] so tests can run everything in-process on
//! an ephemeral port with an in-memory [`mail::MailSender`].

pub mod config;
pub mod db;
pub mod error;
pub mod hosted;
pub mod kt;
pub mod mail;
pub mod openpgp;
pub mod ratelimit;
pub mod routes;
pub mod state;
pub mod util;

use std::{future::Future, net::SocketAddr};

use axum::{extract::DefaultBodyLimit, Router};
use tokio::net::TcpListener;

pub use state::{AppState, Limits, StateOptions};

/// Crate version, reported by `GET /v1/health`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build the complete router (API + static guest viewer) for `state`.
pub fn app(state: AppState) -> Router {
    let max_body = state.limits().max_body_bytes;
    routes::router(state.clone())
        .layer(DefaultBodyLimit::max(max_body))
        .layer(axum::middleware::from_fn(routes::security_headers))
        .layer(routes::trace_layer())
        .with_state(state)
}

/// Serve `app(state)` on `listener` until `shutdown` resolves (graceful: in-flight requests finish).
///
/// Connection peer addresses are attached so the per-IP rate limiter works; when running behind a
/// reverse proxy set `trust_proxy` in [`StateOptions`] so `X-Forwarded-For` is honoured instead.
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
