//! Error types: [`RelayError`] for the library, [`ApiError`] rendered as `{"error": "..."}`.
//!
//! Messages never contain credentials: the worker scrubs server text with
//! [`crate::secret::scrub`] before an error becomes a stored `last_error`, and HTTP error
//! bodies only ever describe the request shape.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::{imap_guard::ImapRefusal, webhook_guard::Refusal};

/// Why a push could not be delivered.
#[derive(Debug, thiserror::Error)]
pub enum PushError {
    /// The HTTP request itself failed (connect / timeout / TLS). The URL is deliberately not
    /// part of the message: webhook URLs often carry capability tokens.
    #[error("webhook POST failed: {0}")]
    Http(String),
    /// The receiver answered with a non-2xx status.
    #[error("webhook answered HTTP {0}")]
    Status(u16),
    /// The destination failed the webhook policy at delivery time (for example the host now
    /// resolves to a private address): nothing was sent.
    #[error("webhook destination refused: {0}")]
    Refused(Refusal),
    /// A transport that only exists as a payload shape so far (FCM / APNs).
    #[error("push transport {0} is not configured on this relay")]
    NotConfigured(&'static str),
}

/// Library-level error.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("IMAP: {0}")]
    Imap(#[from] sealbox_mail::ImapError),
    /// The IMAP destination failed the relay's IMAP policy when the worker was about to connect
    /// (for example the host now resolves to a private address): no connection was opened.
    #[error("IMAP destination refused: {0}")]
    ImapDestination(ImapRefusal),
    #[error("push: {0}")]
    Push(#[from] PushError),
    #[error("invalid registration: {0}")]
    InvalidRegistration(String),
    #[error("registration limit reached")]
    LimitReached,
    #[error("no such registration")]
    NotFound,
    /// Building the relay failed (for example its HTTP client could not be created).
    #[error("relay setup: {0}")]
    Setup(String),
}

/// HTTP-facing error; converted with [`IntoResponse`].
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("registration limit reached")]
    LimitReached,
    /// Too many registrations from one client address; answered with `Retry-After`.
    #[error("too many registrations from this client address; retry after the Retry-After delay")]
    RateLimited { retry_after_secs: u64 },
}

impl ApiError {
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::LimitReached | ApiError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

impl From<RelayError> for ApiError {
    fn from(e: RelayError) -> Self {
        match e {
            RelayError::InvalidRegistration(m) => ApiError::BadRequest(m),
            RelayError::ImapDestination(refusal) => ApiError::BadRequest(refusal.to_string()),
            RelayError::LimitReached => ApiError::LimitReached,
            RelayError::NotFound => ApiError::NotFound,
            // A registration is accepted before the first IMAP connect, so these cannot
            // surface from a handler; map them defensively without leaking detail.
            RelayError::Imap(_) | RelayError::Push(_) | RelayError::Setup(_) => {
                ApiError::BadRequest("registration rejected".into())
            }
        }
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        tracing::debug!(status = %status, error = %self, "request rejected");
        let message = self.to_string();
        let mut resp = (status, Json(ErrorBody { error: &message })).into_response();
        if let ApiError::RateLimited { retry_after_secs } = self {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
        }
        resp
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
