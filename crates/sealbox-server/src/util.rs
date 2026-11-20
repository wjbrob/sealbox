//! Small helpers: clock, random tokens, token hashing, lenient base64, extractors.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{rejection::JsonRejection, ConnectInfo, FromRequest, FromRequestParts, Request},
    http::{request::Parts, StatusCode},
    Json,
};
use base64::{engine::general_purpose, Engine};
use rand::RngCore;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use crate::{error::AppError, state::AppState};

/// Current Unix time in seconds.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `n` random bytes from the OS CSPRNG, URL-safe base64 without padding.
pub fn random_token(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// A 16-byte random identifier (22 URL-safe characters) for guest messages.
pub fn random_id() -> String {
    random_token(16)
}

/// SHA-256 of a token, hex — what we store instead of the token itself.
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Constant-time equality of two byte strings (for token hash comparison).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Decode base64 in any common dialect (standard / URL-safe, padded or not), ignoring whitespace.
pub fn decode_base64_lenient(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let trimmed = cleaned.trim_end_matches('=');
    general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .ok()
}

/// Is `s` a plausible opaque token (what we hand out, or what a client chose for a backup)?
pub fn is_token_shaped(s: &str) -> bool {
    (16..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The client's IP as a string, for rate limiting.
///
/// Uses the TCP peer address; when the state has `trust_proxy` set, the first entry of
/// `X-Forwarded-For` wins. Falls back to `"unknown"` if the router was mounted without
/// connect info (everything still works, the limiter just lumps those clients together).
#[derive(Debug, Clone)]
pub struct ClientIp(pub String);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if state.trust_proxy() {
            if let Some(forwarded) = parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|v| v.trim())
                .filter(|v| !v.is_empty() && v.len() <= 64)
            {
                return Ok(ClientIp(forwarded.to_owned()));
            }
        }
        let ip = parts
            .extensions
            .get::<ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        Ok(ClientIp(ip))
    }
}

/// `Json<T>` whose rejection is our JSON error (400 / 413) instead of axum's plain-text one.
pub struct AppJson<T>(pub T);

impl<T, S> FromRequest<S> for AppJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(AppJson(v)),
            Err(rej) => Err(json_rejection(rej)),
        }
    }
}

fn json_rejection(rej: JsonRejection) -> AppError {
    if rej.status() == StatusCode::PAYLOAD_TOO_LARGE {
        AppError::PayloadTooLarge
    } else {
        AppError::BadRequest(format!("invalid JSON body: {}", rej.body_text()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_url_safe_and_unique() {
        let a = random_token(32);
        let b = random_token(32);
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(is_token_shaped(&a));
        assert!(!is_token_shaped("short"));
        assert!(!is_token_shaped("has space in it 1234"));
    }

    #[test]
    fn lenient_base64_accepts_all_dialects() {
        let data = b"-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\n";
        for engine in [
            general_purpose::STANDARD.encode(data),
            general_purpose::STANDARD_NO_PAD.encode(data),
            general_purpose::URL_SAFE.encode(data),
            general_purpose::URL_SAFE_NO_PAD.encode(data),
        ] {
            assert_eq!(decode_base64_lenient(&engine).as_deref(), Some(&data[..]));
        }
        assert!(decode_base64_lenient("!!!").is_none());
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
