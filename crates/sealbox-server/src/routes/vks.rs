//! Key directory: a VKS-compatible subset of <https://keys.openpgp.org/about/api>.
//!
//! * `POST /vks/v1/upload`          `{keytext}` → `{key_fpr, status:{email: state}, token}`
//! * `POST /vks/v1/request-verify`  `{token, addresses:[..]}` → same shape; mails one challenge per address
//! * `GET  /vks/v1/verify/{challenge}` → publishes that address (link from the mail)
//! * `GET  /vks/v1/by-email/{email}` → armored key reduced to that user ID, 404 unless published
//! * `GET  /vks/v1/by-fingerprint/{fpr}` → armored key reduced to its published user IDs
//!
//! `state` is `"unpublished" | "pending" | "published"`. Fingerprints are upper-case hex.

use std::collections::BTreeMap;

use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    db::{self, EmailStatus},
    error::{AppError, AppResult},
    mail::OutgoingMail,
    openpgp,
    state::AppState,
    util::{self, AppJson, ClientIp},
};

#[derive(Deserialize)]
pub struct UploadRequest {
    pub keytext: String,
}

#[derive(Deserialize)]
pub struct RequestVerifyRequest {
    pub token: String,
    pub addresses: Vec<String>,
}

/// Response of `upload` and `request-verify` (VKS shape).
#[derive(Serialize)]
pub struct UploadResponse {
    pub key_fpr: String,
    pub status: BTreeMap<String, &'static str>,
    pub token: String,
}

const PGP_KEYS_MIME: &str = "application/pgp-keys; charset=utf-8";

/// `POST /vks/v1/upload`
pub async fn upload(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AppJson(req): AppJson<UploadRequest>,
) -> AppResult<Json<UploadResponse>> {
    if !state.allow("vks-upload", &ip, state.limits().upload_per_hour) {
        return Err(AppError::RateLimited);
    }
    if req.keytext.len() > state.limits().max_key_bytes {
        return Err(AppError::PayloadTooLarge);
    }
    // Validate the upload on its own first (400 on anything that is not a usable certificate).
    let verified = openpgp::parse_and_sanitize(&req.keytext)?;
    let now = util::now();
    let token = util::random_token(32);
    let token_hash = util::token_hash(&token);
    let ttl = state.limits().token_ttl_secs;
    let fpr = verified.fingerprint.clone();
    let statuses = {
        let fpr = fpr.clone();
        let keytext = req.keytext;
        state
            .db()
            .call(move |c| -> AppResult<_> {
                // Merge with what we already hold so a stripped re-upload cannot remove
                // user IDs, subkeys or revocations (same policy as keys.openpgp.org).
                let merged = match db::key_text(c, &fpr)? {
                    Some(existing) => {
                        let base = openpgp::parse_armored(&existing).map_err(|e| {
                            AppError::Internal(anyhow::anyhow!("stored key unparsable: {e}"))
                        })?;
                        let fresh = openpgp::parse_armored(&keytext)?;
                        openpgp::sanitize(openpgp::merge(base, fresh)?)?
                    }
                    None => verified,
                };
                db::upsert_key(c, &fpr, &merged.armored, &merged.emails, now)?;
                crate::kt::record_directory_changes(c, now); // G30: dropped addresses
                db::insert_upload_token(c, &token_hash, &fpr, now, now + ttl)?;
                Ok(db::key_statuses(c, &fpr)?)
            })
            .await?
    };
    tracing::info!(fpr = %fpr, addresses = statuses.len(), "key uploaded");
    Ok(Json(UploadResponse {
        key_fpr: fpr,
        status: status_map(&statuses),
        token,
    }))
}

/// `POST /vks/v1/request-verify`
pub async fn request_verify(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AppJson(req): AppJson<RequestVerifyRequest>,
) -> AppResult<Json<UploadResponse>> {
    if !state.allow(
        "vks-request-verify",
        &ip,
        state.limits().request_verify_per_hour,
    ) {
        return Err(AppError::RateLimited);
    }
    if req.addresses.is_empty() || req.addresses.len() > 32 {
        return Err(AppError::BadRequest(
            "addresses must hold 1..=32 entries".into(),
        ));
    }
    let now = util::now();
    let token_hash = util::token_hash(&req.token);
    let fpr = state
        .db()
        .call(move |c| db::upload_token_fpr(c, &token_hash, now))
        .await?
        .ok_or_else(|| AppError::BadRequest("unknown or expired upload token".into()))?;

    let mut wanted: Vec<String> = Vec::new();
    for a in &req.addresses {
        if let Some(e) = openpgp::normalize_email(a) {
            if !wanted.contains(&e) {
                wanted.push(e);
            }
        }
    }
    let statuses = {
        let fpr = fpr.clone();
        state.db().call(move |c| db::key_statuses(c, &fpr)).await?
    };
    let to_challenge: Vec<String> = wanted
        .into_iter()
        .filter(|w| {
            statuses
                .iter()
                .any(|(e, s)| e == w && *s != EmailStatus::Published)
        })
        .collect();
    if to_challenge.is_empty() {
        return Err(AppError::BadRequest(
            "none of the addresses belong to this key or all are already published".into(),
        ));
    }

    let ttl = state.limits().token_ttl_secs;
    for email in to_challenge {
        if !state.allow(
            "vks-challenge-mail",
            &format!("{fpr}:{email}"),
            state.limits().challenge_mails_per_address_per_hour,
        ) {
            tracing::info!(fpr = %fpr, "challenge mail throttled for an address");
            continue;
        }
        let challenge = util::random_token(32);
        let challenge_hash = util::token_hash(&challenge);
        let link = format!("{}/vks/v1/verify/{}", state.public_url(), challenge);
        let mail = OutgoingMail {
            to: email.clone(),
            subject: format!("Verify {email} for your Sealbox key"),
            body: challenge_mail_body(&email, &fpr, &link, state.public_url(), ttl),
        };
        // Record the challenge first so a slow relay cannot leave a sent link that nobody knows.
        {
            let (fpr, email) = (fpr.clone(), email.clone());
            state
                .db()
                .call(move |c| {
                    db::insert_challenge(c, &challenge_hash, &fpr, &email, now, now + ttl)?;
                    db::set_email_status(c, &fpr, &email, EmailStatus::Pending, now)
                })
                .await?;
        }
        state.mailer().send(mail).await?;
        tracing::info!(fpr = %fpr, "challenge mail sent");
    }

    let statuses = {
        let fpr = fpr.clone();
        state.db().call(move |c| db::key_statuses(c, &fpr)).await?
    };
    Ok(Json(UploadResponse {
        key_fpr: fpr,
        status: status_map(&statuses),
        token: req.token,
    }))
}

fn challenge_mail_body(
    email: &str,
    fpr: &str,
    link: &str,
    public_url: &str,
    ttl_secs: i64,
) -> String {
    format!(
        "Hello,\n\n\
         Someone (hopefully you) uploaded an OpenPGP key carrying the address {email}\n\
         to the Sealbox key directory at {public_url}.\n\n\
         Key fingerprint: {fpr}\n\n\
         To publish this address, so that other Sealbox users can find your key, open:\n\n\
         {link}\n\n\
         The link is valid for {hours} hours and can be used once. If you did not request this,\n\
         ignore this message: the address will not be published.\n",
        hours = ttl_secs / 3600
    )
}

/// `GET /vks/v1/verify/{challenge}` — the link from the challenge mail.
pub async fn verify(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(challenge): Path<String>,
) -> AppResult<Response> {
    if !state.allow("vks-verify", &ip, state.limits().verify_attempts_per_hour) {
        return Err(AppError::RateLimited);
    }
    if !util::is_token_shaped(&challenge) {
        return Err(AppError::NotFound);
    }
    let now = util::now();
    let hash = util::token_hash(&challenge);
    let (fpr, email) = state
        .db()
        .call(move |c| {
            db::consume_challenge(c, &hash, now)
                .inspect(|_| crate::kt::record_directory_changes(c, now))
        })
        .await?
        .ok_or(AppError::NotFound)?;
    tracing::info!(fpr = %fpr, "address published");
    let page = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Sealbox — address verified</title>\
         <style>body{{font:16px system-ui,sans-serif;max-width:40em;margin:4em auto;padding:0 1em;color:#1d2a35}}code{{background:#eef3f7;padding:.1em .3em;border-radius:4px}}</style>\
         <h1>Address verified</h1><p><code>{}</code> is now published for the key with fingerprint</p><p><code>{}</code></p>\
         <p>Other Sealbox users can now find this key and send you encrypted mail. You can close this page.</p>",
        html_escape(&email),
        html_escape(&fpr)
    );
    Ok(Html(page).into_response())
}

/// `GET /vks/v1/by-email/{email}`
pub async fn by_email(
    State(state): State<AppState>,
    Path(email): Path<String>,
) -> AppResult<Response> {
    let email = openpgp::normalize_email(&email).ok_or(AppError::NotFound)?;
    let found = {
        let email = email.clone();
        state
            .db()
            .call(move |c| db::published_key_by_email(c, &email))
            .await?
    };
    let (_fpr, keytext) = found.ok_or(AppError::NotFound)?;
    let key = openpgp::parse_armored(&keytext).map_err(|e| AppError::Internal(e.into()))?;
    let armored = openpgp::armored_for_emails(&key, std::slice::from_ref(&email))
        .map_err(|e| AppError::Internal(e.into()))?;
    Ok(pgp_keys_response(armored))
}

/// `GET /vks/v1/by-fingerprint/{fpr}`
pub async fn by_fingerprint(
    State(state): State<AppState>,
    Path(fpr): Path<String>,
) -> AppResult<Response> {
    let fpr = openpgp::normalize_fingerprint(&fpr).ok_or(AppError::NotFound)?;
    let found = state
        .db()
        .call(move |c| db::published_key_by_fpr(c, &fpr))
        .await?;
    let (keytext, emails) = found.ok_or(AppError::NotFound)?;
    let key = openpgp::parse_armored(&keytext).map_err(|e| AppError::Internal(e.into()))?;
    let armored =
        openpgp::armored_for_emails(&key, &emails).map_err(|e| AppError::Internal(e.into()))?;
    Ok(pgp_keys_response(armored))
}

fn pgp_keys_response(armored: String) -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static(PGP_KEYS_MIME),
        )],
        armored,
    )
        .into_response()
}

fn status_map(statuses: &[(String, EmailStatus)]) -> BTreeMap<String, &'static str> {
    statuses
        .iter()
        .map(|(e, s)| (e.clone(), s.as_str()))
        .collect()
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}
