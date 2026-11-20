//! `GET /v1/health` and the root banner.

use axum::{extract::State, Json};
use serde::Serialize;

use crate::{state::AppState, VERSION};

#[derive(Serialize)]
pub struct Health {
    pub ok: bool,
    pub version: &'static str,
    pub uptime_secs: u64,
}

/// `GET /v1/health` → `{ "ok": true, "version": "0.1.0", "uptime_secs": 12 }`.
pub async fn health(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        ok: true,
        version: VERSION,
        uptime_secs: state.uptime().as_secs(),
    })
}

/// `GET /` → a one-line banner (there is nothing to browse here).
pub async fn root() -> String {
    format!("sealbox-server {VERSION}\n")
}
