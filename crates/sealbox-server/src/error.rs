//! One error type for all handlers, rendered as `{"error": "..."}` JSON.
//!
//! Messages never echo request bodies or secrets; 5xx details go to the log only.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::{db::DbError, mail::MailError, openpgp::PgpError};

/// Error returned by handlers; converted to an HTTP response by [`IntoResponse`].
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("too many requests")]
    RateLimited,
    #[error("{0}")]
    Conflict(String),
    #[error("database error")]
    Db(#[from] DbError),
    #[error("mail delivery failed")]
    Mail(#[from] MailError),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl From<PgpError> for AppError {
    fn from(e: PgpError) -> Self {
        AppError::BadRequest(e.to_string())
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

impl AppError {
    /// HTTP status for this error.
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Db(_) | AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Mail(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        match &self {
            AppError::Db(e) => tracing::error!(error = %e, "database error"),
            AppError::Internal(e) => tracing::error!(error = ?e, "internal error"),
            AppError::Mail(e) => tracing::error!(error = %e, "mail error"),
            _ => tracing::debug!(status = %status, error = %self, "request rejected"),
        }
        let message = self.to_string();
        (status, Json(ErrorBody { error: &message })).into_response()
    }
}

/// Handler result alias.
pub type AppResult<T> = Result<T, AppError>;
