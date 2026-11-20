//! Hosted mailboxes — "Create a new Sealbox address".
//!
//! For people without a mailbox they want to use, the Sealbox server can provision a brand-new
//! `name@<hosted domain>` on its own mail host (Stalwart) and hand back the generated password
//! **once**. This module is the client half: it talks to the server's `/v1/hosted/*` endpoints
//! (`hosted_info`, `hosted_availability`, `hosted_signup`) and
//! [`create_hosted_account`] chains the signup into the normal [`Engine::add_account`] path, so
//! a hosted account is stored, keyed and synced exactly like any other account.
//!
//! Every type here is a plain `serde` struct mirroring the server's JSON, so the Flutter
//! onboarding can expose the same option through the bridge.

use std::fmt;

use sealbox_mail::autodiscover::{AuthHint, ConfigSource, Endpoint, ServerConfig, UsernameForm};
use sealbox_mail::Security;
use serde::{Deserialize, Serialize};

use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::types::{AccountInfo, AddAccount, AuthSpec};

/// An IMAP/SMTP endpoint as the server describes it (`security` = `plain|starttls|tls`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedEndpoint {
    pub host: String,
    pub port: u16,
    pub security: String,
}

impl HostedEndpoint {
    /// Convert to the engine's endpoint type.
    pub fn to_endpoint(&self) -> Result<Endpoint> {
        let security = match self.security.trim().to_ascii_lowercase().as_str() {
            "plain" => Security::Plain,
            "starttls" => Security::StartTls,
            "tls" | "ssl" => Security::Tls,
            other => {
                return Err(Error::InvalidInput(format!(
                    "server sent unknown security {other:?} for {}:{}",
                    self.host, self.port
                )))
            }
        };
        Ok(Endpoint::new(self.host.clone(), self.port, security))
    }
}

/// Who may sign up on the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedSignupMode {
    Open,
    Invite,
    Closed,
}

/// Name rules the server enforces (shown in the UI before the user types).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedRequirements {
    pub min_length: usize,
    pub max_length: usize,
    pub pattern: String,
    #[serde(default)]
    pub reserved: Vec<String>,
    #[serde(default)]
    pub reserved_prefixes: Vec<String>,
}

/// `GET /v1/hosted/info`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedInfo {
    pub domain: String,
    pub signups: HostedSignupMode,
    pub invite_required: bool,
    pub requirements: HostedRequirements,
    pub imap: HostedEndpoint,
    pub smtp: HostedEndpoint,
}

/// `GET /v1/hosted/availability?local_part=`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedAvailability {
    /// The normalised (lower-cased) name that was checked.
    pub local_part: String,
    pub email: String,
    pub available: bool,
    /// `too_short | too_long | invalid_characters | invalid_shape | reserved | taken`.
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Body of `POST /v1/hosted/signup`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedSignupRequest {
    pub local_part: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_email: Option<String>,
}

/// `POST /v1/hosted/signup` → the new mailbox. The password is shown here and never again.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedSignup {
    pub email: String,
    pub login: String,
    pub password: String,
    pub domain: String,
    pub imap: HostedEndpoint,
    pub smtp: HostedEndpoint,
    pub created_at: i64,
}

impl fmt::Debug for HostedSignup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostedSignup")
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// Input of [`Engine::create_hosted_account`] (what the onboarding screen collects).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedCreateRequest {
    /// Base URL of the Sealbox server, e.g. `https://sealbox.example`.
    pub server_url: String,
    /// Requested name before the `@`.
    pub local_part: String,
    #[serde(default)]
    pub invite_code: Option<String>,
    /// An address the user already owns, for account recovery (optional).
    #[serde(default)]
    pub recovery_email: Option<String>,
    /// Display name for the new account.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Result of [`Engine::create_hosted_account`]: the stored account plus the one-time password
/// (already stored in the profile like any other account credential; returned so a client can
/// offer to show it once).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedCreated {
    pub account: AccountInfo,
    pub password: String,
}

impl fmt::Debug for HostedCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostedCreated")
            .field("account", &self.account)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
struct ServerError {
    error: String,
}

fn base(server_url: &str) -> Result<String> {
    let s = server_url.trim().trim_end_matches('/');
    if !(s.starts_with("http://") || s.starts_with("https://")) {
        return Err(Error::InvalidInput(format!(
            "server URL must start with http:// or https://, got {server_url:?}"
        )));
    }
    Ok(s.to_owned())
}

/// Map a non-success HTTP answer onto an engine error: 400/409 are the user's input (exit 2),
/// 429 is the server's policy (exit 3), everything else is the connection (exit 4).
async fn failure(what: &str, res: reqwest::Response) -> Error {
    let status = res.status();
    let message = match res.text().await {
        Ok(body) => serde_json::from_str::<ServerError>(&body)
            .map(|e| e.error)
            .unwrap_or_else(|_| body.chars().take(200).collect()),
        Err(e) => e.to_string(),
    };
    match status.as_u16() {
        400 | 409 | 422 => Error::InvalidInput(format!("{what}: {message}")),
        429 => Error::Policy(format!("{what} refused by the server: {message}")),
        404 => Error::Connection(format!(
            "{what}: this server has no hosted mailbox service (HTTP 404)"
        )),
        _ => Error::Connection(format!("{what}: HTTP {status}: {message}")),
    }
}

impl Engine {
    /// `GET {server_url}/v1/hosted/info`.
    pub async fn hosted_info(&self, server_url: &str) -> Result<HostedInfo> {
        let url = format!("{}/v1/hosted/info", base(server_url)?);
        let res = self
            .http()
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Connection(format!("hosted info: {e}")))?;
        if !res.status().is_success() {
            return Err(failure("hosted info", res).await);
        }
        res.json::<HostedInfo>()
            .await
            .map_err(|e| Error::Connection(format!("hosted info: invalid response: {e}")))
    }

    /// `GET {server_url}/v1/hosted/availability?local_part=`.
    pub async fn hosted_availability(
        &self,
        server_url: &str,
        local_part: &str,
    ) -> Result<HostedAvailability> {
        let url = format!("{}/v1/hosted/availability", base(server_url)?);
        let res = self
            .http()
            .get(&url)
            .query(&[("local_part", local_part.trim())])
            .send()
            .await
            .map_err(|e| Error::Connection(format!("hosted availability: {e}")))?;
        if !res.status().is_success() {
            return Err(failure("hosted availability", res).await);
        }
        res.json::<HostedAvailability>()
            .await
            .map_err(|e| Error::Connection(format!("hosted availability: invalid response: {e}")))
    }

    /// `POST {server_url}/v1/hosted/signup` — provisions the mailbox but stores nothing locally.
    /// Prefer [`Engine::create_hosted_account`].
    pub async fn hosted_signup(
        &self,
        server_url: &str,
        req: &HostedSignupRequest,
    ) -> Result<HostedSignup> {
        let url = format!("{}/v1/hosted/signup", base(server_url)?);
        let res = self
            .http()
            .post(&url)
            .json(req)
            .send()
            .await
            .map_err(|e| Error::Connection(format!("hosted signup: {e}")))?;
        if !res.status().is_success() {
            return Err(failure("hosted signup", res).await);
        }
        res.json::<HostedSignup>()
            .await
            .map_err(|e| Error::Connection(format!("hosted signup: invalid response: {e}")))
    }

    /// Create a new hosted address and add it as an account: signup on the server, then the
    /// normal [`Engine::add_account`] with the returned servers (manual configuration, full
    /// address as login) and a freshly generated OpenPGP identity.
    pub async fn create_hosted_account(&self, req: HostedCreateRequest) -> Result<HostedCreated> {
        let local = req.local_part.trim().to_ascii_lowercase();
        if local.is_empty() {
            return Err(Error::InvalidInput("a name is required".into()));
        }
        let signup = self
            .hosted_signup(
                &req.server_url,
                &HostedSignupRequest {
                    local_part: local,
                    invite_code: req
                        .invite_code
                        .as_deref()
                        .map(str::trim)
                        .filter(|c| !c.is_empty())
                        .map(str::to_owned),
                    recovery_email: req
                        .recovery_email
                        .as_deref()
                        .map(str::trim)
                        .filter(|c| !c.is_empty())
                        .map(str::to_owned),
                },
            )
            .await?;
        let servers = ServerConfig {
            imap: signup.imap.to_endpoint()?,
            smtp: signup.smtp.to_endpoint()?,
            auth_hint: AuthHint::Password,
            display_name: format!("Sealbox ({})", signup.domain),
            source: ConfigSource::Guess,
            username: UsernameForm::FullAddress,
        };
        let email = signup.email.clone();
        let account = self
            .add_account(AddAccount {
                email: signup.email,
                display_name: req.display_name,
                auth: AuthSpec::Password {
                    password: signup.password.clone(),
                },
                servers: Some(servers),
                login: Some(signup.login),
            })
            .await
            .map_err(|e| {
                Error::Connection(format!(
                    "hosted mailbox {email} was created on the server but could not be added \
                     to this profile: {e} (its one-time password was not stored; choose a \
                     different name and try again)"
                ))
            })?;
        Ok(HostedCreated {
            account,
            password: signup.password,
        })
    }
}

/// Free-function form of [`Engine::create_hosted_account`] for callers that only have a
/// server URL and a name.
pub async fn create_hosted_account(
    engine: &Engine,
    server_url: &str,
    local_part: &str,
    invite_code: Option<&str>,
) -> Result<HostedCreated> {
    engine
        .create_hosted_account(HostedCreateRequest {
            server_url: server_url.to_owned(),
            local_part: local_part.to_owned(),
            invite_code: invite_code.map(str::to_owned),
            recovery_email: None,
            display_name: None,
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_conversion() {
        let e = HostedEndpoint {
            host: "127.0.0.1".into(),
            port: 1143,
            security: "plain".into(),
        };
        assert_eq!(
            e.to_endpoint().unwrap(),
            Endpoint::new("127.0.0.1", 1143, Security::Plain)
        );
        assert!(HostedEndpoint {
            security: "weird".into(),
            ..e
        }
        .to_endpoint()
        .is_err());
    }

    #[test]
    fn base_url_rules() {
        assert_eq!(base("http://x:1/").unwrap(), "http://x:1");
        assert!(base("x:1").is_err());
    }

    #[test]
    fn signup_json_round_trip_and_redaction() {
        let s: HostedSignup = serde_json::from_str(
            r#"{"email":"a@h","login":"a@h","password":"pw","domain":"h",
                "imap":{"host":"i","port":1,"security":"plain"},
                "smtp":{"host":"s","port":2,"security":"plain"},"created_at":5}"#,
        )
        .unwrap();
        assert_eq!(s.password, "pw");
        assert!(!format!("{s:?}").contains("pw"));
        let req = HostedSignupRequest {
            local_part: "a".into(),
            invite_code: None,
            recovery_email: None,
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"local_part":"a"}"#
        );
    }
}
