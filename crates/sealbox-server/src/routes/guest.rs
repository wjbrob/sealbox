//! Guest messages: ciphertext in, ciphertext out. The server never holds a key or passphrase.
//!
//! * `POST /v1/guest` `{ciphertext_armored, expires_in_secs?, sender_key_armored?,
//!   recipient_email?, require_email_code?}`
//!   → 201 `{id, url, pickup_token, created_at, expires_at, recipient_verification}`
//! * `GET  /v1/guest/{id}[?token=]` → `{id, ciphertext_armored, created_at, expires_at, sender_key_armored, reply_count}`;
//!   401 `{"error":"verification_required"}` when the message is code-gated and no valid token is given
//! * `POST /v1/guest/{id}/send-code` `{email}` → 202 `{status:"sent_if_recipient", expires_in}`
//!   (the same answer whether or not `email` is the recipient; the code goes only to the real one)
//! * `POST /v1/guest/{id}/verify` `{code}` → 200 `{access_token, expires_in}`; 401
//!   `{error:"invalid_code", attempts_left}`; 429 `{error:"locked", retry_after}`; 400 `{error:"no_active_code"}`
//! * `POST /v1/guest/{id}/reply` `{ciphertext_armored}` → 204
//! * `GET  /v1/guest/{id}/replies?token=<pickup_token>` → `{replies:[{id, ciphertext_armored, created_at}]}`
//!
//! The e-mail-code gate (G29) stores a salted hash of the recipient address, a hash of the
//! current code, the failure counter and the lock; the decryption secret stays in the link's
//! fragment, which browsers never send. See `docs/GUEST_LINKS.md`.
//!
//! Timestamps are Unix seconds. Expired messages answer 404 immediately and are purged (with
//! their replies) by the background task.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    db::{self, DbError, GuestGate, GuestMessage},
    error::{AppError, AppResult},
    mail::OutgoingMail,
    openpgp,
    state::AppState,
    util::{self, AppJson, ClientIp},
};

#[derive(Deserialize)]
pub struct CreateRequest {
    pub ciphertext_armored: String,
    #[serde(default)]
    pub expires_in_secs: Option<i64>,
    #[serde(default)]
    pub sender_key_armored: Option<String>,
    /// Address that receives the one-time code (only used with `require_email_code`).
    #[serde(default)]
    pub recipient_email: Option<String>,
    #[serde(default)]
    pub require_email_code: bool,
}

#[derive(Serialize)]
pub struct CreateResponse {
    pub id: String,
    pub url: String,
    pub pickup_token: String,
    pub created_at: i64,
    pub expires_at: i64,
    /// `true` when the ciphertext is served only after e-mail code verification.
    pub recipient_verification: bool,
}

#[derive(Deserialize)]
pub struct FetchQuery {
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Deserialize)]
pub struct SendCodeRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub code: String,
}

#[derive(Serialize)]
pub struct FetchResponse {
    pub id: String,
    pub ciphertext_armored: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub sender_key_armored: Option<String>,
    pub reply_count: i64,
}

#[derive(Deserialize)]
pub struct ReplyRequest {
    pub ciphertext_armored: String,
}

#[derive(Deserialize)]
pub struct RepliesQuery {
    pub token: String,
}

#[derive(Serialize)]
pub struct ReplyItem {
    pub id: i64,
    pub ciphertext_armored: String,
    pub created_at: i64,
}

#[derive(Serialize)]
pub struct RepliesResponse {
    pub id: String,
    pub replies: Vec<ReplyItem>,
}

/// Accept only something that at least looks like an armored OpenPGP message. We do not parse
/// it (the server has no business inspecting it) but refuse to be a generic file host.
fn check_armored_message(s: &str) -> AppResult<String> {
    let t = s.trim();
    if !t.starts_with("-----BEGIN PGP MESSAGE-----") || !t.ends_with("-----END PGP MESSAGE-----") {
        return Err(AppError::BadRequest(
            "ciphertext_armored must be an ASCII-armored OpenPGP message".into(),
        ));
    }
    Ok(format!("{t}\n"))
}

fn valid_id(id: &str) -> bool {
    id.len() == 22
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `POST /v1/guest`
pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AppJson(req): AppJson<CreateRequest>,
) -> AppResult<Response> {
    let limits = state.limits();
    if !state.allow("guest-post", &ip, limits.guest_post_per_hour) {
        return Err(AppError::RateLimited);
    }
    let ciphertext = check_armored_message(&req.ciphertext_armored)?;
    let ttl = match req.expires_in_secs {
        None => limits.default_guest_expiry_secs,
        Some(s) if s < 1 => {
            return Err(AppError::BadRequest("expires_in_secs must be >= 1".into()))
        }
        Some(s) => s.min(limits.max_guest_expiry_secs),
    };
    let sender_key = match req.sender_key_armored.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(k) => {
            if k.len() > limits.max_key_bytes {
                return Err(AppError::PayloadTooLarge);
            }
            Some(openpgp::parse_and_sanitize(k)?.armored)
        }
    };
    let recipient = if req.require_email_code {
        let addr = req
            .recipient_email
            .as_deref()
            .map(normalize_email)
            .filter(|a| plausible_email(a))
            .ok_or_else(|| {
                AppError::BadRequest(
                    "require_email_code needs recipient_email (a valid e-mail address)".into(),
                )
            })?;
        Some(addr)
    } else {
        // Without a gate the address is of no use to us; do not keep it.
        None
    };
    let now = util::now();
    let id = util::random_id();
    let pickup_token = util::random_token(32);
    let recipient_hash = recipient.as_deref().map(|a| recipient_hash(&id, a));
    let gated = recipient_hash.is_some();
    let message = GuestMessage {
        id: id.clone(),
        ciphertext,
        sender_key,
        pickup_token_hash: util::token_hash(&pickup_token),
        created_at: now,
        expires_at: now + ttl,
    };
    let expires_at = message.expires_at;
    state
        .db()
        .call(move |c| db::insert_guest_with_gate(c, &message, recipient_hash.as_deref()))
        .await?;
    tracing::info!(ttl_secs = ttl, gated, "guest message stored");
    let body = CreateResponse {
        url: format!("{}/g/{}", state.public_url(), id),
        id,
        pickup_token,
        created_at: now,
        expires_at,
        recipient_verification: gated,
    };
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

async fn load(state: &AppState, id: &str) -> AppResult<GuestMessage> {
    if !valid_id(id) {
        return Err(AppError::NotFound);
    }
    let now = util::now();
    let id = id.to_owned();
    state
        .db()
        .call(move |c| db::get_guest(c, &id, now))
        .await?
        .ok_or(AppError::NotFound)
}

/// `GET /v1/guest/{id}[?token=]`
pub async fn fetch(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<FetchQuery>,
) -> AppResult<Response> {
    let m = load(&state, &id).await?;
    let now = util::now();
    let allowed = {
        let id = m.id.clone();
        let token_hash = q.token.as_deref().map(util::token_hash);
        state
            .db()
            .call(move |c| -> Result<bool, DbError> {
                if db::get_gate(c, &id)?.is_none() {
                    return Ok(true);
                }
                match token_hash {
                    Some(h) => db::access_token_valid(c, &h, &id, now),
                    None => Ok(false),
                }
            })
            .await?
    };
    if !allowed {
        return Ok(json_error(
            StatusCode::UNAUTHORIZED,
            json!({ "error": "verification_required" }),
        ));
    }
    let reply_count = {
        let id = m.id.clone();
        state.db().call(move |c| db::count_replies(c, &id)).await?
    };
    Ok(Json(FetchResponse {
        id: m.id,
        ciphertext_armored: m.ciphertext,
        created_at: m.created_at,
        expires_at: m.expires_at,
        sender_key_armored: m.sender_key,
        reply_count,
    })
    .into_response())
}

fn json_error(status: StatusCode, body: serde_json::Value) -> Response {
    (status, Json(body)).into_response()
}

fn normalize_email(s: &str) -> String {
    s.trim().to_lowercase()
}

fn plausible_email(s: &str) -> bool {
    s.len() <= 254
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
        && s.split_once('@')
            .is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.contains('@'))
}

/// Salted (per message) SHA-256 of the normalized recipient address. Addresses are guessable,
/// so this keeps the address out of the database and out of dumps, not out of reach of a
/// targeted dictionary attack by someone holding the database.
fn recipient_hash(id: &str, normalized: &str) -> String {
    util::token_hash(&format!("sealbox-guest-recipient-v1\n{id}\n{normalized}"))
}

fn code_hash(id: &str, code: &str) -> String {
    util::token_hash(&format!("sealbox-guest-code-v1\n{id}\n{code}"))
}

fn locked_response(until: i64, now: i64) -> Response {
    json_error(
        StatusCode::TOO_MANY_REQUESTS,
        json!({ "error": "locked", "retry_after": (until - now).max(1) }),
    )
}

/// Clear an elapsed lock (and its failure count). Returns `Some(until)` while still locked.
fn active_lock(g: &mut GuestGate, now: i64) -> Option<i64> {
    match g.locked_until {
        Some(until) if until > now => Some(until),
        Some(_) => {
            g.locked_until = None;
            g.failed_attempts = 0;
            None
        }
        None => None,
    }
}

/// `POST /v1/guest/{id}/send-code` `{email}`
pub async fn send_code(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    AppJson(req): AppJson<SendCodeRequest>,
) -> AppResult<Response> {
    let limits = state.limits().clone();
    if !state.allow(
        "guest-code-ip",
        &ip,
        limits.guest_code_requests_per_ip_per_hour,
    ) {
        return Err(AppError::RateLimited);
    }
    let m = load(&state, &id).await?;
    let email = normalize_email(&req.email);
    if !plausible_email(&email) {
        return Err(AppError::BadRequest(
            "email must be an e-mail address".into(),
        ));
    }
    let now = util::now();
    let gate = {
        let id = m.id.clone();
        state.db().call(move |c| db::get_gate(c, &id)).await?
    };
    let Some(mut gate) = gate else {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            json!({ "error": "not_gated" }),
        ));
    };
    if let Some(until) = active_lock(&mut gate, now) {
        return Ok(locked_response(until, now));
    }
    if !state.allow(
        "guest-code-msg",
        &m.id,
        limits.guest_code_mails_per_message_per_hour,
    ) {
        return Ok(json_error(
            StatusCode::TOO_MANY_REQUESTS,
            json!({ "error": "rate_limited" }),
        ));
    }
    let presented = recipient_hash(&m.id, &email);
    if util::ct_eq(presented.as_bytes(), gate.recipient_hash.as_bytes()) {
        let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000u32));
        gate.code_hash = Some(code_hash(&m.id, &code));
        gate.code_expires_at = Some(now + limits.guest_code_ttl_secs);
        let g = gate.clone();
        state.db().call(move |c| db::update_gate(c, &g)).await?;
        let minutes = (limits.guest_code_ttl_secs / 60).max(1);
        let mail = OutgoingMail {
            to: email,
            subject: "Your Sealbox code".to_owned(),
            body: format!(
                "Your one-time code to open the encrypted message is:\n\n    {code}\n\n\
                 It is valid for {minutes} minutes and works once.\n\n\
                 If you did not just try to open a Sealbox message, someone else may have the \
                 link. Without this code they cannot download the message; do not share it.\n"
            ),
        };
        // Deliver in the background so the answer (and its timing) is the same whether or not
        // the address matched.
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = st.mailer().send(mail).await {
                tracing::error!(error = %e, "guest code mail failed");
            }
        });
        tracing::info!("guest code issued");
    } else {
        tracing::info!("guest code requested for a non-matching address");
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "sent_if_recipient",
            "expires_in": limits.guest_code_ttl_secs,
        })),
    )
        .into_response())
}

enum VerifyOutcome {
    NotGated,
    Locked(i64),
    NoActiveCode,
    Wrong(i64),
    Ok(String),
}

/// `POST /v1/guest/{id}/verify` `{code}`
pub async fn verify(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    AppJson(req): AppJson<VerifyRequest>,
) -> AppResult<Response> {
    let limits = state.limits().clone();
    if !state.allow("guest-verify-ip", &ip, limits.guest_verify_per_ip_per_hour) {
        return Err(AppError::RateLimited);
    }
    let m = load(&state, &id).await?;
    let code: String = req
        .code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AppError::BadRequest("code must be 6 digits".into()));
    }
    let now = util::now();
    let presented = code_hash(&m.id, &code);
    let mid = m.id.clone();
    let outcome = state
        .db()
        .call(move |c| -> Result<VerifyOutcome, DbError> {
            let Some(mut g) = db::get_gate(c, &mid)? else {
                return Ok(VerifyOutcome::NotGated);
            };
            if let Some(until) = active_lock(&mut g, now) {
                return Ok(VerifyOutcome::Locked(until));
            }
            let live = match (&g.code_hash, g.code_expires_at) {
                (Some(h), Some(exp)) if exp > now => Some(h.clone()),
                _ => None,
            };
            let Some(expected) = live else {
                db::update_gate(c, &g)?; // persist a cleared lock
                return Ok(VerifyOutcome::NoActiveCode);
            };
            if util::ct_eq(presented.as_bytes(), expected.as_bytes()) {
                g.code_hash = None;
                g.code_expires_at = None;
                g.failed_attempts = 0;
                db::update_gate(c, &g)?;
                let token = util::random_token(32);
                db::insert_access_token(
                    c,
                    &util::token_hash(&token),
                    &mid,
                    now + limits.guest_access_token_ttl_secs,
                )?;
                return Ok(VerifyOutcome::Ok(token));
            }
            g.failed_attempts += 1;
            if g.failed_attempts >= limits.guest_code_max_attempts {
                // Lock and burn the code: after the lock a fresh code is needed.
                let until = now + limits.guest_code_lock_secs;
                g.locked_until = Some(until);
                g.code_hash = None;
                g.code_expires_at = None;
                db::update_gate(c, &g)?;
                return Ok(VerifyOutcome::Locked(until));
            }
            db::update_gate(c, &g)?;
            Ok(VerifyOutcome::Wrong(
                limits.guest_code_max_attempts - g.failed_attempts,
            ))
        })
        .await?;
    Ok(match outcome {
        VerifyOutcome::NotGated => {
            json_error(StatusCode::BAD_REQUEST, json!({ "error": "not_gated" }))
        }
        VerifyOutcome::Locked(until) => {
            tracing::info!("guest code gate locked");
            locked_response(until, now)
        }
        VerifyOutcome::NoActiveCode => json_error(
            StatusCode::BAD_REQUEST,
            json!({ "error": "no_active_code" }),
        ),
        VerifyOutcome::Wrong(left) => json_error(
            StatusCode::UNAUTHORIZED,
            json!({ "error": "invalid_code", "attempts_left": left }),
        ),
        VerifyOutcome::Ok(token) => {
            tracing::info!("guest code verified");
            Json(json!({
                "access_token": token,
                "expires_in": limits.guest_access_token_ttl_secs,
            }))
            .into_response()
        }
    })
}

/// `POST /v1/guest/{id}/reply`
pub async fn reply(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    AppJson(req): AppJson<ReplyRequest>,
) -> AppResult<StatusCode> {
    if !state.allow("guest-reply", &ip, state.limits().reply_per_hour) {
        return Err(AppError::RateLimited);
    }
    let m = load(&state, &id).await?;
    let ciphertext = check_armored_message(&req.ciphertext_armored)?;
    let max = state.limits().max_replies_per_message;
    let now = util::now();
    let stored = state
        .db()
        .call(move |c| -> Result<bool, DbError> {
            if db::count_replies(c, &m.id)? >= max {
                return Ok(false);
            }
            db::insert_reply(c, &m.id, &ciphertext, now)?;
            Ok(true)
        })
        .await?;
    if !stored {
        return Err(AppError::Conflict(
            "reply limit reached for this message".into(),
        ));
    }
    tracing::info!("guest reply stored");
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/guest/{id}/replies?token=`
pub async fn replies(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<RepliesQuery>,
) -> AppResult<Json<RepliesResponse>> {
    let m = load(&state, &id).await?;
    let presented = util::token_hash(&q.token);
    if !util::ct_eq(presented.as_bytes(), m.pickup_token_hash.as_bytes()) {
        return Err(AppError::Unauthorized);
    }
    let list = {
        let id = m.id.clone();
        state.db().call(move |c| db::list_replies(c, &id)).await?
    };
    Ok(Json(RepliesResponse {
        id: m.id,
        replies: list
            .into_iter()
            .map(|r| ReplyItem {
                id: r.id,
                ciphertext_armored: r.ciphertext,
                created_at: r.created_at,
            })
            .collect(),
    }))
}
