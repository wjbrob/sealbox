//! The static guest viewer: `/g/{id}` serves `index.html`, `/static/*` serves the directory.

use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use tower_http::services::ServeDir;

use crate::{error::AppError, state::AppState};

/// `GET /g/{id}` — the viewer page; the page reads the id from its own URL.
pub async fn viewer_page(
    State(state): State<AppState>,
    Path(_id): Path<String>,
) -> Result<Response, AppError> {
    let path = state.static_dir().join("index.html");
    let html = tokio::fs::read(&path).await.map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "guest viewer index.html unreadable");
        AppError::Internal(anyhow::anyhow!("guest viewer not installed"))
    })?;
    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        ],
        html,
    )
        .into_response())
}

/// `ServeDir` for `/static` (precompressed files are not required; files are small).
pub fn static_service(state: &AppState) -> ServeDir {
    ServeDir::new(state.static_dir()).append_index_html_on_directories(false)
}
