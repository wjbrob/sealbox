//! Minimal client for Stalwart's JMAP management API (verified against Stalwart v1.0.0).
//!
//! Registry objects are addressed as `x:<Object>/get|set|query` under the `urn:stalwart:jmap`
//! capability, authenticated with HTTP Basic (an administrator, or the recovery administrator
//! from `STALWART_RECOVERY_ADMIN`). Stalwart serialises its `Map`/`List` types as JSON objects
//! (`{"value": true}` / `{"0": {...}}`), never arrays — mirrored here.
//!
//! Only the three calls the signup flow needs are implemented: find the domain id, check whether
//! a name exists, create an account. `destroy_account` exists for tests and clean-up.

use std::time::Duration;

use serde_json::{json, Value};

/// JMAP endpoint path on the Stalwart base URL.
const JMAP_PATH: &str = "/jmap";

/// Errors talking to Stalwart. Never contains credentials.
#[derive(Debug, thiserror::Error)]
pub enum StalwartError {
    #[error("stalwart http: {0}")]
    Http(String),
    /// Stalwart answered with a JMAP method/set error.
    #[error("stalwart {kind}: {description}")]
    Api { kind: String, description: String },
    #[error("stalwart response: {0}")]
    Shape(String),
}

impl StalwartError {
    /// `true` when Stalwart refused because the name/address already exists.
    pub fn is_already_exists(&self) -> bool {
        matches!(self, StalwartError::Api { kind, .. } if kind == "primaryKeyViolation" || kind == "alreadyExists")
    }
}

/// HTTP client bound to one Stalwart server and one administrator credential.
#[derive(Clone)]
pub struct StalwartClient {
    base: String,
    user: String,
    secret: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for StalwartClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StalwartClient")
            .field("base", &self.base)
            .field("user", &self.user)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl StalwartClient {
    /// `base_url` like `http://127.0.0.1:8084` or `https://mail.example.com` (no trailing slash
    /// needed).
    pub fn new(
        base_url: &str,
        user: &str,
        secret: &str,
        timeout: Duration,
    ) -> Result<Self, StalwartError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("sealbox-server/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| StalwartError::Http(e.to_string()))?;
        Ok(Self {
            base: base_url.trim_end_matches('/').to_owned(),
            user: user.to_owned(),
            secret: secret.to_owned(),
            http,
        })
    }

    /// The configured base URL.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// One method call; returns the method's response arguments.
    pub async fn call(&self, method: &str, args: Value) -> Result<Value, StalwartError> {
        let body = json!({
            "using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
            "methodCalls": [[method, args, "c0"]],
        });
        let res = self
            .http
            .post(format!("{}{JMAP_PATH}", self.base))
            .basic_auth(&self.user, Some(&self.secret))
            .json(&body)
            .send()
            .await
            .map_err(|e| StalwartError::Http(e.to_string()))?;
        let status = res.status();
        let text = res
            .text()
            .await
            .map_err(|e| StalwartError::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(StalwartError::Http(format!(
                "{method}: HTTP {status}: {}",
                truncate(&text, 300)
            )));
        }
        let v: Value = serde_json::from_str(&text)
            .map_err(|e| StalwartError::Shape(format!("{method}: invalid JSON: {e}")))?;
        let resp = v
            .get("methodResponses")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_array)
            .ok_or_else(|| StalwartError::Shape(format!("{method}: no methodResponses")))?;
        let name = resp.first().and_then(Value::as_str).unwrap_or_default();
        let args = resp.get(1).cloned().unwrap_or(Value::Null);
        if name == "error" {
            return Err(StalwartError::Api {
                kind: args
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("error")
                    .to_owned(),
                description: args
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or(method)
                    .to_owned(),
            });
        }
        Ok(args)
    }

    /// Registry id of the domain called `name`, if Stalwart knows it.
    pub async fn domain_id(&self, name: &str) -> Result<Option<String>, StalwartError> {
        let r = self.call("x:Domain/get", json!({ "ids": null })).await?;
        let list = r
            .get("list")
            .and_then(Value::as_array)
            .ok_or_else(|| StalwartError::Shape("x:Domain/get: no list".into()))?;
        Ok(list
            .iter()
            .find(|d| {
                d.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
            })
            .and_then(|d| d.get("id").and_then(Value::as_str))
            .map(str::to_owned))
    }

    /// Does an account with this login name exist (in any domain)?
    pub async fn account_exists(&self, name: &str) -> Result<bool, StalwartError> {
        let r = self
            .call("x:Account/query", json!({ "filter": { "name": name } }))
            .await?;
        let ids = r
            .get("ids")
            .and_then(Value::as_array)
            .ok_or_else(|| StalwartError::Shape("x:Account/query: no ids".into()))?;
        Ok(!ids.is_empty())
    }

    /// Create a user account `name@<domain>` with a password credential; returns its id.
    pub async fn create_account(
        &self,
        name: &str,
        domain_id: &str,
        password: &str,
        description: &str,
    ) -> Result<String, StalwartError> {
        let r = self
            .call(
                "x:Account/set",
                json!({
                    "create": {
                        "n": {
                            "@type": "User",
                            "name": name,
                            "domainId": domain_id,
                            "credentials": { "0": { "@type": "Password", "secret": password } },
                            "roles": { "@type": "User" },
                            "description": description,
                        }
                    }
                }),
            )
            .await?;
        if let Some(err) = r.get("notCreated").and_then(|n| n.get("n")) {
            return Err(StalwartError::Api {
                kind: err
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("notCreated")
                    .to_owned(),
                description: err
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("account not created")
                    .to_owned(),
            });
        }
        r.get("created")
            .and_then(|c| c.get("n"))
            .and_then(|c| c.get("id"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| StalwartError::Shape("x:Account/set: no created id".into()))
    }

    /// Delete an account by id (tests / clean-up).
    pub async fn destroy_account(&self, id: &str) -> Result<(), StalwartError> {
        let r = self
            .call("x:Account/set", json!({ "destroy": [id] }))
            .await?;
        if let Some(err) = r.get("notDestroyed").and_then(|n| n.get(id)) {
            return Err(StalwartError::Api {
                kind: err
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("notDestroyed")
                    .to_owned(),
                description: err
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("account not destroyed")
                    .to_owned(),
            });
        }
        Ok(())
    }
}

fn truncate(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}
