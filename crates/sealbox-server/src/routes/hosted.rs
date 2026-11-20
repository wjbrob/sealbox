//! Hosted-mailbox endpoints (see [`crate::hosted`]).
//!
//! * `GET  /v1/hosted/info`
//! * `GET  /v1/hosted/availability?local_part=NAME`
//! * `POST /v1/hosted/signup` `{local_part, invite_code?, recovery_email?}` → 201
//!
//! All three answer 404 when the server has no hosted domain configured.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;

use crate::{
    error::{AppError, AppResult},
    hosted::{HostedService, SignupRequest},
    state::AppState,
    util::{AppJson, ClientIp},
};

#[derive(Deserialize)]
pub struct AvailabilityQuery {
    pub local_part: String,
}

fn service(state: &AppState) -> AppResult<&HostedService> {
    state.hosted().ok_or(AppError::NotFound)
}

/// `GET /v1/hosted/info`
pub async fn info(State(state): State<AppState>) -> AppResult<Response> {
    let svc = service(&state)?;
    Ok(Json(svc.info()).into_response())
}

/// `GET /v1/hosted/availability?local_part=`
pub async fn availability(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Query(q): Query<AvailabilityQuery>,
) -> AppResult<Response> {
    let svc = service(&state)?;
    if !state.allow("hosted-availability", &ip, svc.config.availability_per_hour) {
        return Err(AppError::RateLimited);
    }
    if q.local_part.len() > 256 {
        return Err(AppError::BadRequest("local_part too long".into()));
    }
    Ok(Json(svc.availability(state.db(), &q.local_part).await?).into_response())
}

/// `POST /v1/hosted/signup`
pub async fn signup(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AppJson(req): AppJson<SignupRequest>,
) -> AppResult<Response> {
    let svc = service(&state)?;
    if !state.allow("hosted-signup", &ip, svc.config.attempts_per_hour) {
        return Err(AppError::RateLimited);
    }
    if req.local_part.len() > 256 {
        return Err(AppError::BadRequest("local_part too long".into()));
    }
    let created = svc.signup(state.db(), &ip, req).await?;
    Ok((StatusCode::CREATED, Json(created)).into_response())
}
