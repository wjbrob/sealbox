//! HTTP clients for the Sealbox server: VKS key lookup and publishing, guest-message
//! upload. All optional: when the URLs are not configured nothing is contacted.

use std::collections::BTreeMap;

use sealbox_crypto::PublicKey;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// `GET {base}/vks/v1/by-email/{email}` → the published key, if any. Network errors and
/// 404s are *not* errors for the caller: the directory is a best-effort source.
pub(crate) async fn lookup_key(
    http: &reqwest::Client,
    base: &str,
    email: &str,
) -> Option<PublicKey> {
    let encoded =
        percent_encoding::utf8_percent_encode(email.trim(), percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    let url = format!("{}/vks/v1/by-email/{encoded}", base.trim_end_matches('/'));
    let resp = match http.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(%url, error = %e, "key directory unreachable");
            return None;
        }
    };
    if !resp.status().is_success() {
        tracing::debug!(%url, status = %resp.status(), "key directory: no key");
        return None;
    }
    let body = resp.text().await.ok()?;
    match PublicKey::from_armored(&body) {
        Ok(k) => Some(k),
        Err(e) => {
            tracing::warn!(%url, error = %e, "key directory returned an unusable key");
            None
        }
    }
}

// ----- VKS publishing (`Engine::publish_key` and friends) ----------------------------------

/// Response of `POST /vks/v1/upload` and `POST /vks/v1/request-verify` (VKS shape).
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct VksUploadResponse {
    pub key_fpr: String,
    /// Address → `unpublished` | `pending` | `published`.
    #[serde(default)]
    pub status: BTreeMap<String, String>,
    pub token: String,
}

fn directory_error(url: &str, status: reqwest::StatusCode, body: &str) -> Error {
    let detail: String = body.chars().take(200).collect();
    if detail.trim().is_empty() {
        Error::Directory(format!("{url} answered {status}"))
    } else {
        Error::Directory(format!("{url} answered {status}: {}", detail.trim()))
    }
}

/// `POST {base}/vks/v1/upload {keytext}` — store (merge) a public key; the response carries
/// the per-address state and an upload token for [`vks_request_verify`].
pub(crate) async fn vks_upload(
    http: &reqwest::Client,
    base: &str,
    keytext: &str,
) -> Result<VksUploadResponse> {
    let url = format!("{}/vks/v1/upload", base.trim_end_matches('/'));
    let resp = http
        .post(&url)
        .json(&serde_json::json!({ "keytext": keytext }))
        .send()
        .await
        .map_err(|e| Error::Directory(format!("{url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(directory_error(&url, status, &body));
    }
    resp.json()
        .await
        .map_err(|e| Error::Directory(format!("{url}: bad JSON: {e}")))
}

/// `POST {base}/vks/v1/request-verify {token, addresses}` — the directory mails one
/// challenge link per address that is not published yet.
pub(crate) async fn vks_request_verify(
    http: &reqwest::Client,
    base: &str,
    token: &str,
    addresses: &[String],
) -> Result<VksUploadResponse> {
    let url = format!("{}/vks/v1/request-verify", base.trim_end_matches('/'));
    let resp = http
        .post(&url)
        .json(&serde_json::json!({ "token": token, "addresses": addresses }))
        .send()
        .await
        .map_err(|e| Error::Directory(format!("{url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(directory_error(&url, status, &body));
    }
    resp.json()
        .await
        .map_err(|e| Error::Directory(format!("{url}: bad JSON: {e}")))
}

/// `GET {base}/vks/v1/by-email/{email}`, strict variant of [`lookup_key`]: `Ok(None)` only
/// for a 404 (nothing published); every other failure is an error, because the caller
/// reports the directory's state to the user instead of silently falling back.
pub(crate) async fn vks_by_email(
    http: &reqwest::Client,
    base: &str,
    email: &str,
) -> Result<Option<PublicKey>> {
    let encoded =
        percent_encoding::utf8_percent_encode(email.trim(), percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    let url = format!("{}/vks/v1/by-email/{encoded}", base.trim_end_matches('/'));
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::Directory(format!("{url}: {e}")))?;
    let status = resp.status();
    match status.as_u16() {
        200 => {
            let body = resp
                .text()
                .await
                .map_err(|e| Error::Directory(format!("{url}: {e}")))?;
            let key = PublicKey::from_armored(&body)
                .map_err(|e| Error::Directory(format!("{url}: unusable key: {e}")))?;
            Ok(Some(key))
        }
        404 => Ok(None),
        _ => {
            let body = resp.text().await.unwrap_or_default();
            Err(directory_error(&url, status, &body))
        }
    }
}

/// What following a challenge link did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerifyLinkOutcome {
    /// The directory published the address.
    Accepted,
    /// The link is unknown, expired or already used (404 / 410).
    Refused,
}

/// `GET` a challenge link from the directory's mail. Only call it with a link that
/// [`verify_links_in`] accepted (same origin as the configured directory).
pub(crate) async fn follow_verify_link(
    http: &reqwest::Client,
    link: &str,
) -> Result<VerifyLinkOutcome> {
    let resp = http
        .get(link)
        .send()
        .await
        .map_err(|e| Error::Directory(format!("{link}: {e}")))?;
    let status = resp.status();
    match status.as_u16() {
        200..=299 => Ok(VerifyLinkOutcome::Accepted),
        404 | 410 => Ok(VerifyLinkOutcome::Refused),
        429 => Err(Error::Directory(format!(
            "{link}: the directory is rate-limiting verification attempts; try again later"
        ))),
        _ => {
            let body = resp.text().await.unwrap_or_default();
            Err(directory_error(link, status, &body))
        }
    }
}

/// Is `s` shaped like the directory's challenge tokens (16–128 of `[A-Za-z0-9_-]`)?
fn token_shaped(s: &str) -> bool {
    (16..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The challenge links in a mail body that belong to the configured directory: every
/// `{origin}/vks/v1/verify/{token}` whose scheme, host and port equal those of
/// `directory_base`. Links to any other origin are ignored, so a mail from a stranger can
/// never make the engine fetch an arbitrary URL. Deduplicated, in order of appearance.
pub(crate) fn verify_links_in(body: &str, directory_base: &str) -> Vec<String> {
    let Ok(base) = reqwest::Url::parse(directory_base.trim()) else {
        return Vec::new();
    };
    let origin = base.origin();
    if !origin.is_tuple() {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    for raw in body.split(|c: char| {
        c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']')
    }) {
        if !raw.contains("/vks/v1/verify/") {
            continue;
        }
        let candidate = raw.trim_end_matches(['.', ',', ';', ':', '!', '?']);
        let Ok(url) = reqwest::Url::parse(candidate) else {
            continue;
        };
        if url.origin() != origin {
            continue;
        }
        let Some(token) = url.path().strip_prefix("/vks/v1/verify/") else {
            continue;
        };
        if !token_shaped(token) || url.query().is_some() || url.fragment().is_some() {
            continue;
        }
        let link = url.to_string();
        if !out.contains(&link) {
            out.push(link);
        }
    }
    out
}

#[derive(Serialize)]
struct GuestCreateRequest<'a> {
    ciphertext_armored: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in_secs: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_key_armored: Option<&'a str>,
    /// Only sent with `require_email_code`: the server keeps a salted hash, never the address.
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient_email: Option<&'a str>,
    require_email_code: bool,
}

#[derive(Deserialize)]
struct GuestCreateResponse {
    url: String,
    expires_at: i64,
    id: String,
    #[serde(default)]
    recipient_verification: bool,
}

/// Result of a guest upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GuestUpload {
    pub id: String,
    /// The bare link (`{public}/g/{id}`), never carrying a secret.
    pub url: String,
    pub expires_at: i64,
    pub recipient_verification: bool,
}

/// What to upload with a guest envelope.
pub(crate) struct GuestUploadRequest<'a> {
    pub ciphertext_armored: &'a str,
    pub sender_key_armored: Option<&'a str>,
    pub expires_in_secs: Option<i64>,
    /// `Some(addr)` = gate the ciphertext behind a one-time code mailed to `addr`.
    pub email_code_recipient: Option<&'a str>,
}

/// `POST {base}/v1/guest` with the guest envelope.
pub(crate) async fn guest_upload(
    http: &reqwest::Client,
    base: &str,
    req: &GuestUploadRequest<'_>,
) -> Result<GuestUpload> {
    let url = format!("{}/v1/guest", base.trim_end_matches('/'));
    let resp = http
        .post(&url)
        .json(&GuestCreateRequest {
            ciphertext_armored: req.ciphertext_armored,
            expires_in_secs: req.expires_in_secs,
            sender_key_armored: req.sender_key_armored,
            recipient_email: req.email_code_recipient,
            require_email_code: req.email_code_recipient.is_some(),
        })
        .send()
        .await
        .map_err(|e| Error::Guest(format!("{url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Guest(format!(
            "{url} answered {status}: {}",
            body.chars().take(200).collect::<String>()
        )));
    }
    let body: GuestCreateResponse = resp
        .json()
        .await
        .map_err(|e| Error::Guest(format!("{url}: bad JSON: {e}")))?;
    if req.email_code_recipient.is_some() && !body.recipient_verification {
        // An older server silently ignored the gate: refuse rather than mail an ungated link
        // whose notification claims a code protects it.
        return Err(Error::Guest(format!(
            "{url} does not support e-mail code verification (upgrade the server)"
        )));
    }
    Ok(GuestUpload {
        id: body.id,
        url: body.url,
        expires_at: body.expires_at,
        recipient_verification: body.recipient_verification,
    })
}

/// Is the guest message `id` still held by the server? `GET {base}/v1/guest/{id}` answers 200,
/// or 401 when it is code-gated; 404 means expired or deleted.
pub(crate) async fn guest_alive(http: &reqwest::Client, base: &str, id: &str) -> Result<bool> {
    let url = format!("{}/v1/guest/{id}", base.trim_end_matches('/'));
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::Guest(format!("{url}: {e}")))?;
    match resp.status().as_u16() {
        200 | 401 => Ok(true),
        404 => Ok(false),
        s => Err(Error::Guest(format!("{url} answered {s}"))),
    }
}

/// `{url}#{secret}` with the secret percent-encoded. Only for the modes that put the secret in
/// the link ([`crate::GuestMode::OneClick`], [`crate::GuestMode::EmailCode`]); the default
/// passphrase mode mails the bare `url`.
pub(crate) fn guest_link(url: &str, passphrase: &str) -> String {
    let frag =
        percent_encoding::utf8_percent_encode(passphrase, percent_encoding::NON_ALPHANUMERIC);
    format!("{url}#{frag}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_links_only_from_the_directory_origin() {
        let base = "http://127.0.0.1:8787/";
        let body = "Hello,\n\nTo publish this address open:\n\n\
                    http://127.0.0.1:8787/vks/v1/verify/abcdefghijklmnopqrstuvwxyz012345.\n\
                    Not ours: https://evil.example/vks/v1/verify/abcdefghijklmnopqrstuvwxyz012345 \
                    nor http://127.0.0.1:9999/vks/v1/verify/abcdefghijklmnopqrstuvwxyz012345 \
                    nor http://127.0.0.1:8787/vks/v1/verify/short \
                    nor http://127.0.0.1:8787/vks/v1/verify/abcdefghijklmnopqrstuvwxyz012345?x=1 \
                    nor http://127.0.0.1:8787/other/abcdefghijklmnopqrstuvwxyz012345\n\
                    <a href=\"http://127.0.0.1:8787/vks/v1/verify/ABCDEFGHIJKLMNOPQRSTUVWXYZ-_6789\">again</a>\n\
                    http://127.0.0.1:8787/vks/v1/verify/abcdefghijklmnopqrstuvwxyz012345";
        assert_eq!(
            verify_links_in(body, base),
            vec![
                "http://127.0.0.1:8787/vks/v1/verify/abcdefghijklmnopqrstuvwxyz012345".to_string(),
                "http://127.0.0.1:8787/vks/v1/verify/ABCDEFGHIJKLMNOPQRSTUVWXYZ-_6789".to_string(),
            ]
        );
        // Scheme is part of the origin: an https directory never follows an http link.
        assert!(verify_links_in(body, "https://127.0.0.1:8787").is_empty());
        assert!(verify_links_in(body, "not a url").is_empty());
        assert!(verify_links_in("", base).is_empty());
    }

    #[test]
    fn link_encodes_fragment() {
        assert_eq!(
            guest_link("https://s/g/abc", "ab-cd ef"),
            "https://s/g/abc#ab%2Dcd%20ef"
        );
    }
}
