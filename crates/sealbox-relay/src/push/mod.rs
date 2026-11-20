//! Push transports. A push says *that* a mailbox changed and *when* — nothing else.
//!
//! [`PushEvent`] is the complete wire payload: `registration_id`, `event`, `folder`, `sent_at`.
//! No subject, sender, UID, size or message count ever enters this module; the worker does not
//! even fetch them. Transports: [`WebhookTransport`] (HTTP POST, optional bearer),
//! [`LogTransport`] (tracing only) and, as payload shapes without a sender yet, [`mobile`]
//! (FCM / APNs — they need credentials, see `docs/PUSH_RELAY.md`).

pub mod mobile;

use std::{fmt, future::Future, net::IpAddr, pin::Pin, sync::Arc, time::Duration};

use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};

use crate::{
    error::PushError,
    secret::Secret,
    webhook_guard::{self, Scheme, WebhookGuard},
};

/// Boxed future so [`PushTransport`] stays object-safe without an `async-trait` dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What happened. Only one kind exists today; the enum keeps the wire value explicit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    NewMail,
}

/// The content-free push payload. This struct **is** the privacy boundary: add a field here
/// only if it reveals nothing about the mail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushEvent {
    pub registration_id: String,
    pub event: EventKind,
    pub folder: String,
    /// RFC 3339 UTC, millisecond precision.
    pub sent_at: String,
}

impl PushEvent {
    pub fn new_mail(registration_id: &str, folder: &str) -> Self {
        Self {
            registration_id: registration_id.to_owned(),
            event: EventKind::NewMail,
            folder: folder.to_owned(),
            sent_at: crate::now_rfc3339(),
        }
    }
}

/// Delivers a [`PushEvent`]. Implementations must be content-free by construction: they only
/// ever see the event struct.
pub trait PushTransport: Send + Sync + fmt::Debug {
    /// Short name for status output (`"webhook"`, `"log"`).
    fn kind(&self) -> &'static str;

    fn send<'a>(&'a self, event: &'a PushEvent) -> BoxFuture<'a, Result<(), PushError>>;
}

/// `POST url` with the JSON event body and, when configured, `Authorization: Bearer …`.
///
/// Transports built by [`webhook_guard::Webhooks::transport`] are *guarded*: their client
/// resolves names through the webhook policy on every connection, and an IP-literal
/// destination (which no resolver sees) is re-checked here before every send.
pub struct WebhookTransport {
    url: String,
    bearer: Option<Secret>,
    client: reqwest::Client,
    guard: Option<LiteralGuard>,
}

/// The policy re-check for an IP-literal webhook URL.
struct LiteralGuard {
    guard: Arc<WebhookGuard>,
    scheme: Scheme,
    literal: Option<IpAddr>,
}

impl WebhookTransport {
    /// Default per-push timeout; the IDLE loop is blocked for at most this long per burst.
    pub const TIMEOUT: Duration = Duration::from_secs(10);

    /// An unguarded transport: `client` decides where the push goes. The relay's API only
    /// creates guarded ones.
    pub fn new(client: reqwest::Client, url: String, bearer: Option<Secret>) -> Self {
        Self {
            url,
            bearer,
            client,
            guard: None,
        }
    }

    /// Re-check `literal` (the URL's host, when it is an IP address) against `guard`'s policy
    /// before every send. `client` must be the guarded client for `scheme`.
    pub fn guarded(
        mut self,
        guard: Arc<WebhookGuard>,
        scheme: Scheme,
        literal: Option<IpAddr>,
    ) -> Self {
        self.guard = Some(LiteralGuard {
            guard,
            scheme,
            literal,
        });
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn is_guarded(&self) -> bool {
        self.guard.is_some()
    }
}

impl fmt::Debug for WebhookTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookTransport")
            .field("url", &self.url)
            .field("bearer", &self.bearer.as_ref().map(|_| "[redacted]"))
            .field("guarded", &self.guard.is_some())
            .finish()
    }
}

impl PushTransport for WebhookTransport {
    fn kind(&self) -> &'static str {
        "webhook"
    }

    fn send<'a>(&'a self, event: &'a PushEvent) -> BoxFuture<'a, Result<(), PushError>> {
        Box::pin(async move {
            if let Some(LiteralGuard {
                guard,
                scheme,
                literal: Some(ip),
            }) = &self.guard
            {
                guard
                    .policy()
                    .check_addr(*scheme, *ip)
                    .map_err(PushError::Refused)?;
            }
            let mut req = self
                .client
                .post(&self.url)
                .timeout(Self::TIMEOUT)
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .json(event);
            if let Some(b) = &self.bearer {
                let value = HeaderValue::from_str(&format!("Bearer {}", b.expose()))
                    .map_err(|_| PushError::Http("bearer is not a valid header value".into()))?;
                req = req.header(AUTHORIZATION, value);
            }
            let resp = req.send().await.map_err(|e| {
                // A refusal from the guarded resolver travels inside reqwest's error chain.
                match webhook_guard::refusal_in(&e) {
                    Some(refusal) => PushError::Refused(refusal),
                    None => PushError::Http(e.without_url().to_string()),
                }
            })?;
            let status = resp.status();
            if status.is_success() {
                Ok(())
            } else {
                Err(PushError::Status(status.as_u16()))
            }
        })
    }
}

/// Logs the event at `info` and delivers nothing. For development and the unit tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogTransport;

impl PushTransport for LogTransport {
    fn kind(&self) -> &'static str {
        "log"
    }

    fn send<'a>(&'a self, event: &'a PushEvent) -> BoxFuture<'a, Result<(), PushError>> {
        Box::pin(async move {
            tracing::info!(
                registration_id = %event.registration_id,
                folder = %event.folder,
                event = ?event.event,
                sent_at = %event.sent_at,
                "push (log transport)"
            );
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use axum::{extract::State, http::HeaderMap, routing::post, Router};

    /// The wire payload has exactly the four documented keys and no numbers (no UID, no
    /// count, no size can hide in it).
    #[test]
    fn push_event_is_content_free() {
        let ev = PushEvent::new_mail("reg-1", "INBOX");
        let v = serde_json::to_value(&ev).expect("json");
        let obj = v.as_object().expect("object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["event", "folder", "registration_id", "sent_at"]);
        assert_eq!(v["event"], "new_mail");
        assert!(obj.values().all(|x| x.is_string()), "{v}");
        // Round-trips, and unknown keys are rejected so a receiver can validate strictly.
        let back: PushEvent = serde_json::from_value(v.clone()).expect("parse");
        assert_eq!(back, ev);
        let mut extra = v;
        extra["subject"] = serde_json::Value::String("hello".into());
        assert!(serde_json::from_value::<PushEvent>(extra).is_err());
    }

    #[test]
    fn webhook_debug_redacts_bearer() {
        let t = WebhookTransport::new(
            reqwest::Client::new(),
            "http://127.0.0.1:1/hook".into(),
            Some(Secret::new("tok-9f8e7d")),
        );
        let dbg = format!("{t:?}");
        assert!(dbg.contains("http://127.0.0.1:1/hook"));
        assert!(dbg.contains("[redacted]"));
        assert!(!dbg.contains("tok-9f8e7d"), "{dbg}");
    }

    type Received = Arc<Mutex<Vec<(HeaderMap, String)>>>;

    async fn hook(State(rx): State<Received>, headers: HeaderMap, body: String) -> &'static str {
        rx.lock().expect("lock").push((headers, body));
        "ok"
    }

    #[tokio::test]
    async fn webhook_posts_json_with_bearer() {
        let received: Received = Arc::default();
        let app = Router::new()
            .route("/hook", post(hook))
            .with_state(received.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let t = WebhookTransport::new(
            reqwest::Client::new(),
            format!("http://{addr}/hook"),
            Some(Secret::new("bearer-xyz")),
        );
        let ev = PushEvent::new_mail("reg-42", "INBOX");
        t.send(&ev).await.expect("push");

        let got = received.lock().expect("lock");
        assert_eq!(got.len(), 1);
        let (headers, body) = &got[0];
        assert_eq!(
            headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()),
            Some("Bearer bearer-xyz")
        );
        assert_eq!(
            headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let parsed: PushEvent = serde_json::from_str(body).expect("json body");
        assert_eq!(parsed, ev);
        server.abort();
    }

    #[tokio::test]
    async fn webhook_reports_non_2xx_and_connect_errors_without_url() {
        let app = Router::new().route("/hook", post(|| async { axum::http::StatusCode::GONE }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        let t = WebhookTransport::new(
            reqwest::Client::new(),
            format!("http://{addr}/hook?token=cap-secret"),
            None,
        );
        let ev = PushEvent::new_mail("reg-1", "INBOX");
        match t.send(&ev).await {
            Err(PushError::Status(410)) => {}
            other => panic!("expected 410, got {other:?}"),
        }
        server.abort();

        // Closed port: the error text must not include the URL (it may carry a token).
        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = closed.local_addr().expect("addr").port();
        drop(closed);
        let t = WebhookTransport::new(
            reqwest::Client::new(),
            format!("http://127.0.0.1:{port}/hook?token=cap-secret"),
            None,
        );
        let err = t.send(&ev).await.expect_err("connect must fail");
        let text = err.to_string();
        assert!(matches!(err, PushError::Http(_)), "{text}");
        assert!(!text.contains("cap-secret"), "{text}");
    }
}
