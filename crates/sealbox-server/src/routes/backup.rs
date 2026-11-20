//! Client-encrypted key backups.
//!
//! The blob is encrypted by the client before upload (the server stores and returns bytes it
//! cannot read). Possession of the key is proven with a detached OpenPGP signature over the
//! exact bytes of the body.
//!
//! * `PUT /v1/backup/{fpr}` — body: the blob (any content type). Headers:
//!   * `X-Sealbox-Signature` (required): base64 (any dialect) of the armored *or* binary
//!     detached signature over the body. (Armor has line breaks, which HTTP headers forbid.)
//!   * `X-Sealbox-Key` (first PUT only, optional otherwise): base64 of the armored public key,
//!     used when the key is not in the directory. Its primary fingerprint must equal `{fpr}`.
//!     The key that verified the first PUT is pinned to the slot for all later PUTs.
//!   * `X-Sealbox-Backup-Token` (optional): a client-chosen pickup token (16–128 URL-safe
//!     chars, e.g. derived from the user's recovery code). If absent the server generates one.
//!     Each successful PUT (re)sets the token.
//!
//!   → `{ok, fingerprint, size, backup_token}`
//! * `GET /v1/backup/{fpr}?token=<backup_token>` → the blob (`application/octet-stream`),
//!   401 on a wrong token, 404 when there is no backup.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    db,
    error::{AppError, AppResult},
    openpgp,
    state::AppState,
    util::{self, ClientIp},
};

pub const SIGNATURE_HEADER: &str = "x-sealbox-signature";
pub const KEY_HEADER: &str = "x-sealbox-key";
pub const TOKEN_HEADER: &str = "x-sealbox-backup-token";

#[derive(Serialize)]
pub struct PutResponse {
    pub ok: bool,
    pub fingerprint: String,
    pub size: usize,
    pub backup_token: String,
}

#[derive(Deserialize)]
pub struct GetQuery {
    pub token: String,
}

fn header_b64(headers: &HeaderMap, name: &str) -> AppResult<Option<Vec<u8>>> {
    let Some(v) = headers.get(name) else {
        return Ok(None);
    };
    let s = v
        .to_str()
        .map_err(|_| AppError::BadRequest(format!("{name} is not ASCII")))?;
    util::decode_base64_lenient(s)
        .map(Some)
        .ok_or_else(|| AppError::BadRequest(format!("{name} is not valid base64")))
}

/// `PUT /v1/backup/{fpr}`
pub async fn put(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(fpr): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Json<PutResponse>> {
    if !state.allow("backup-put", &ip, state.limits().backup_put_per_hour) {
        return Err(AppError::RateLimited);
    }
    let fpr = openpgp::normalize_fingerprint(&fpr)
        .ok_or_else(|| AppError::BadRequest("fingerprint must be 40 or 64 hex digits".into()))?;
    if body.is_empty() {
        return Err(AppError::BadRequest("empty backup body".into()));
    }
    let signature = header_b64(&headers, SIGNATURE_HEADER)?
        .ok_or_else(|| AppError::BadRequest(format!("missing {SIGNATURE_HEADER} header")))?;
    let supplied_key = header_b64(&headers, KEY_HEADER)?;
    let chosen_token = match headers.get(TOKEN_HEADER) {
        None => None,
        Some(v) => {
            let t = v
                .to_str()
                .map_err(|_| AppError::BadRequest(format!("{TOKEN_HEADER} is not ASCII")))?;
            if !util::is_token_shaped(t) {
                return Err(AppError::BadRequest(format!(
                    "{TOKEN_HEADER} must be 16..=128 URL-safe characters"
                )));
            }
            Some(t.to_owned())
        }
    };

    // Which key may authorize this slot: the pinned one, else the directory's, else the header's.
    let known = {
        let fpr = fpr.clone();
        state
            .db()
            .call(move |c| match db::backup_key(c, &fpr)? {
                Some(k) => Ok(Some(k)),
                None => db::key_text(c, &fpr),
            })
            .await?
    };
    let keytext = match (known, supplied_key) {
        (Some(k), _) => k,
        (None, Some(raw)) => {
            let text = String::from_utf8(raw).map_err(|_| {
                AppError::BadRequest(format!("{KEY_HEADER} must be an armored key"))
            })?;
            let v = openpgp::parse_and_sanitize(&text)?;
            if v.fingerprint != fpr {
                return Err(AppError::BadRequest(
                    "the key in X-Sealbox-Key does not have this fingerprint".into(),
                ));
            }
            v.armored
        }
        (None, None) => return Err(AppError::BadRequest(
            "no key known for this fingerprint; upload it to the directory or send X-Sealbox-Key"
                .into(),
        )),
    };
    let key = openpgp::parse_armored(&keytext).map_err(|e| AppError::Internal(e.into()))?;
    if openpgp::verify_detached(&key, &signature, &body).is_err() {
        tracing::info!(fpr = %fpr, "backup signature rejected");
        return Err(AppError::Unauthorized);
    }

    let token = chosen_token.unwrap_or_else(|| util::random_token(32));
    let token_hash = util::token_hash(&token);
    let now = util::now();
    let size = body.len();
    {
        let fpr = fpr.clone();
        state
            .db()
            .call(move |c| db::put_backup(c, &fpr, &body, &keytext, &token_hash, now))
            .await?;
    }
    tracing::info!(fpr = %fpr, size, "backup stored");
    Ok(Json(PutResponse {
        ok: true,
        fingerprint: fpr,
        size,
        backup_token: token,
    }))
}

/// `GET /v1/backup/{fpr}?token=`
pub async fn get(
    State(state): State<AppState>,
    Path(fpr): Path<String>,
    Query(q): Query<GetQuery>,
) -> AppResult<Response> {
    let fpr = openpgp::normalize_fingerprint(&fpr).ok_or(AppError::NotFound)?;
    let backup = {
        let fpr = fpr.clone();
        state.db().call(move |c| db::get_backup(c, &fpr)).await?
    }
    .ok_or(AppError::NotFound)?;
    let presented = util::token_hash(&q.token);
    if !util::ct_eq(presented.as_bytes(), backup.token_hash.as_bytes()) {
        return Err(AppError::Unauthorized);
    }
    let updated = HeaderValue::from_str(&backup.updated_at.to_string())
        .map_err(|e| AppError::Internal(e.into()))?;
    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            ),
            (
                header::HeaderName::from_static("x-sealbox-updated-at"),
                updated,
            ),
        ],
        backup.blob,
    )
        .into_response())
}
