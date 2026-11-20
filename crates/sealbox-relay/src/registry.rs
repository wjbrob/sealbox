//! In-memory registrations: who to watch, where to push, and how the worker is doing.
//!
//! A [`Registration`] lives until it is unregistered, or, once parked
//! ([`RegistrationState::Parked`]), until its worker evicts it after the parked TTL; nothing is
//! written to disk. It sits behind an `Arc`, shared between the HTTP layer and its IDLE
//! worker. The worker only ever updates the
//! small `Progress` block; the HTTP layer only ever reads a [`RegistrationStatus`] snapshot,
//! which by construction has no field that could hold a credential or the webhook URL.
//! `Debug` on every type here is redacting.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak},
    time::Duration,
};

use base64::Engine as _;
use rand::RngCore;
use sealbox_mail::Security;
use serde::Serialize;
use tokio::{sync::watch, task::JoinHandle};

use crate::{
    error::RelayError,
    push::PushTransport,
    secret::{scrub, Credentials, Secret},
};

/// Size of the random part of a registration id (24 bytes → 32 url-safe base64 chars).
const ID_BYTES: usize = 24;

/// Where the IDLE session connects and how it authenticates.
#[derive(Clone)]
pub struct MailboxSpec {
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub username: String,
    pub credentials: Credentials,
}

impl fmt::Debug for MailboxSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailboxSpec")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("security", &self.security)
            .field("username", &self.username)
            .field("credentials", &self.credentials)
            .finish()
    }
}

/// Worker lifecycle state as reported by `GET /v1/push/status/{id}`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    /// Connecting / authenticating / taking the baseline (also during reconnect backoff
    /// right after an error has been recorded — see [`RegistrationState::Error`]).
    #[default]
    Connecting,
    /// An IDLE session is up; pushes will be sent for mail arriving from now on.
    Idle,
    /// The last session ended with an error; the worker retries with backoff.
    Error,
    /// The worker gave up for good ([`RegistrationStatus::parked_reason`] says why) and holds
    /// no connection. The registration is evicted after the parked TTL, or earlier by
    /// `DELETE`; only a new registration helps.
    Parked,
    /// Unregistered or the relay is shutting down; no further pushes.
    Stopped,
}

/// Why a registration was parked: a category, never server text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParkReason {
    /// The server rejected the credentials `max_auth_failures` times with no successful login
    /// in between (`last_error` is then [`crate::worker::CREDENTIALS_REJECTED`]).
    CredentialsRejected,
    /// The registration holds an OAuth token but the server offers no `AUTH=XOAUTH2`, so the
    /// token can never be presented: decided on the first connection, before any login
    /// (`last_error` is then [`crate::worker::XOAUTH2_NOT_OFFERED`]). Retrying would only
    /// repeat the capability check, so the registration is parked at once.
    Xoauth2NotOffered,
    /// The registration holds an OAuth token for a host that is not its provider's own mail
    /// host, where `sealbox-mail` never presents a token (`TransportPolicyError::OAuthHostMismatch`,
    /// before any network write; `last_error` is then [`crate::worker::OAUTH_HOST_REFUSED`]).
    /// The API refuses such a registration up front; the worker parks it if the policy decides
    /// so later (the provider table is static today, so this is defence in depth).
    OauthHostRefused,
}

impl ParkReason {
    /// The wire value (`credentials_rejected`, `xoauth2_not_offered`, `oauth_host_refused`),
    /// also used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            ParkReason::CredentialsRejected => "credentials_rejected",
            ParkReason::Xoauth2NotOffered => "xoauth2_not_offered",
            ParkReason::OauthHostRefused => "oauth_host_refused",
        }
    }
}

/// The part of a registration the worker updates.
#[derive(Clone, Debug, Default)]
struct Progress {
    state: RegistrationState,
    parked: Option<ParkReason>,
    last_error: Option<String>,
    pushes: u64,
    last_push_at: Option<String>,
}

/// What the status endpoint returns. Deliberately a separate struct: it has no slot for a
/// credential, a bearer or a URL, so the response cannot leak one by accident.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RegistrationStatus {
    pub registration_id: String,
    pub state: RegistrationState,
    pub folder: String,
    /// Transport kind only (`"webhook"` / `"log"`), never the URL.
    pub transport: &'static str,
    pub created_at: String,
    pub pushes: u64,
    pub last_push_at: Option<String>,
    /// Scrubbed of every secret the registration knows about.
    pub last_error: Option<String>,
    /// Set exactly when `state` is `parked` (or the parked registration is being stopped).
    pub parked_reason: Option<ParkReason>,
}

/// Input to [`Registry::insert`].
pub struct NewRegistration {
    pub mailbox: MailboxSpec,
    pub folder: String,
    pub transport: Box<dyn PushTransport>,
    /// Secrets that are not part of `mailbox` but must still never appear in `last_error`
    /// (the webhook bearer).
    pub extra_secrets: Vec<Secret>,
}

/// One watched mailbox with its worker handle.
pub struct Registration {
    /// The registry this registration lives in, for [`Registration::evict`].
    registry: Weak<Map>,
    id: String,
    mailbox: MailboxSpec,
    folder: String,
    transport: Box<dyn PushTransport>,
    extra_secrets: Vec<Secret>,
    created_at: String,
    progress: Mutex<Progress>,
    cancel: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl fmt::Debug for Registration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = self.progress();
        f.debug_struct("Registration")
            .field("id", &self.id)
            .field("mailbox", &self.mailbox)
            .field("folder", &self.folder)
            // Only the kind: a webhook URL may carry a capability token in its query string.
            .field("transport", &self.transport.kind())
            .field("state", &p.state)
            .field("pushes", &p.pushes)
            .finish()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Registration {
    fn new(registry: Weak<Map>, id: String, spec: NewRegistration) -> Self {
        let (cancel, _) = watch::channel(false);
        Self {
            registry,
            id,
            mailbox: spec.mailbox,
            folder: spec.folder,
            transport: spec.transport,
            extra_secrets: spec.extra_secrets,
            created_at: crate::now_rfc3339(),
            progress: Mutex::new(Progress::default()),
            cancel,
            task: Mutex::new(None),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn mailbox(&self) -> &MailboxSpec {
        &self.mailbox
    }

    pub fn folder(&self) -> &str {
        &self.folder
    }

    pub fn transport(&self) -> &dyn PushTransport {
        self.transport.as_ref()
    }

    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    fn progress(&self) -> MutexGuard<'_, Progress> {
        lock(&self.progress)
    }

    /// Every secret this registration holds, for [`scrub`].
    fn secrets(&self) -> Vec<&str> {
        std::iter::once(self.mailbox.credentials.secret().expose())
            .chain(self.extra_secrets.iter().map(Secret::expose))
            .collect()
    }

    /// Scrub `text` of every secret this registration holds.
    pub fn scrub(&self, text: &str) -> String {
        scrub(text, &self.secrets())
    }

    pub fn state(&self) -> RegistrationState {
        self.progress().state
    }

    pub fn set_state(&self, state: RegistrationState) {
        let mut p = self.progress();
        p.state = state;
        if state == RegistrationState::Idle {
            // A (re)established session supersedes whatever went wrong before.
            p.last_error = None;
        }
    }

    /// Record a session-level failure (scrubbed) and move to [`RegistrationState::Error`].
    /// Returns the scrubbed text so the caller can log exactly what was stored.
    pub fn set_error(&self, text: &str) -> String {
        let clean = self.scrub(text);
        let mut p = self.progress();
        p.state = RegistrationState::Error;
        p.last_error = Some(clean.clone());
        clean
    }

    /// The worker gave up for good: `state: parked` with `reason`, and `message` (fixed relay
    /// text rather than server output, so it is stored as is) as `last_error`. The worker holds
    /// no connection from now on; it evicts the registration after the parked TTL unless it is
    /// unregistered first.
    pub fn park(&self, reason: ParkReason, message: &str) {
        let mut p = self.progress();
        p.state = RegistrationState::Parked;
        p.parked = Some(reason);
        p.last_error = Some(message.to_owned());
    }

    /// Why the registration is parked, if it is.
    pub fn parked(&self) -> Option<ParkReason> {
        self.progress().parked
    }

    /// Remove this registration from its registry and cancel it (the parked TTL ran out).
    /// `false` if it was no longer there (unregistered meanwhile, or the relay shut down).
    pub fn evict(&self) -> bool {
        let Some(map) = self.registry.upgrade() else {
            return false;
        };
        let removed = {
            let mut map = map.write().unwrap_or_else(PoisonError::into_inner);
            match map.get(&self.id) {
                Some(entry) if std::ptr::eq(Arc::as_ptr(entry), self) => map.remove(&self.id),
                _ => None,
            }
        };
        self.cancel();
        removed.is_some()
    }

    /// Record a failed push (scrubbed) without leaving the idle state.
    pub fn note_push_failure(&self, text: &str) -> String {
        let clean = self.scrub(text);
        self.progress().last_error = Some(clean.clone());
        clean
    }

    pub fn record_push(&self) {
        let mut p = self.progress();
        p.pushes += 1;
        p.last_push_at = Some(crate::now_rfc3339());
        p.last_error = None;
    }

    pub fn snapshot(&self) -> RegistrationStatus {
        let p = self.progress().clone();
        RegistrationStatus {
            registration_id: self.id.clone(),
            state: p.state,
            folder: self.folder.clone(),
            transport: self.transport.kind(),
            created_at: self.created_at.clone(),
            pushes: p.pushes,
            last_push_at: p.last_push_at,
            last_error: p.last_error,
            parked_reason: p.parked,
        }
    }

    /// A receiver that resolves (see [`cancelled`]) once [`Registration::cancel`] ran.
    pub fn cancel_signal(&self) -> watch::Receiver<bool> {
        self.cancel.subscribe()
    }

    pub fn is_cancelled(&self) -> bool {
        *self.cancel.borrow()
    }

    /// Ask the worker to stop. Idempotent; returns immediately.
    pub fn cancel(&self) {
        self.cancel.send_replace(true);
    }

    /// Attach the worker task so [`Registration::stop`] can wait for it.
    pub fn attach_task(&self, handle: JoinHandle<()>) {
        if let Some(old) = lock(&self.task).replace(handle) {
            old.abort();
        }
    }

    /// Cancel and wait up to `grace` for the worker to exit, aborting it after that.
    pub async fn stop(&self, grace: Duration) {
        self.cancel();
        let handle = lock(&self.task).take();
        if let Some(mut h) = handle {
            if tokio::time::timeout(grace, &mut h).await.is_err() {
                h.abort();
            }
        }
        self.set_state(RegistrationState::Stopped);
    }
}

/// Resolve once the registration was cancelled (or dropped, which counts as cancelled).
pub async fn cancelled(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|c| *c).await;
}

type Map = RwLock<HashMap<String, Arc<Registration>>>;

/// All live registrations (parked ones included), capped at `max_registrations`.
pub struct Registry {
    inner: Arc<Map>,
    max: usize,
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry")
            .field("registrations", &self.len())
            .field("max", &self.max)
            .finish()
    }
}

impl Registry {
    pub fn new(max_registrations: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            max: max_registrations,
        }
    }

    fn read(&self) -> RwLockReadGuard<'_, HashMap<String, Arc<Registration>>> {
        self.inner.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, HashMap<String, Arc<Registration>>> {
        self.inner.write().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn max_registrations(&self) -> usize {
        self.max
    }

    pub fn len(&self) -> usize {
        self.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A fresh random url-safe id (`[A-Za-z0-9_-]{32}`).
    pub fn new_id() -> String {
        let mut bytes = [0u8; ID_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Store a registration. Does **not** start its worker (see [`crate::worker::spawn`]).
    pub fn insert(&self, spec: NewRegistration) -> Result<Arc<Registration>, RelayError> {
        let mut map = self.write();
        if map.len() >= self.max {
            return Err(RelayError::LimitReached);
        }
        let mut id = Self::new_id();
        while map.contains_key(&id) {
            id = Self::new_id();
        }
        let reg = Arc::new(Registration::new(
            Arc::downgrade(&self.inner),
            id.clone(),
            spec,
        ));
        map.insert(id, reg.clone());
        Ok(reg)
    }

    pub fn get(&self, id: &str) -> Option<Arc<Registration>> {
        self.read().get(id).cloned()
    }

    /// Remove and cancel. The caller may [`Registration::stop`] to wait for the worker.
    pub fn remove(&self, id: &str) -> Result<Arc<Registration>, RelayError> {
        let reg = self.write().remove(id).ok_or(RelayError::NotFound)?;
        reg.cancel();
        Ok(reg)
    }

    pub fn ids(&self) -> Vec<String> {
        self.read().keys().cloned().collect()
    }

    /// Cancel every worker and empty the registry; returns the registrations so the caller
    /// can wait for the workers.
    pub fn drain(&self) -> Vec<Arc<Registration>> {
        let regs: Vec<_> = self.write().drain().map(|(_, r)| r).collect();
        for r in &regs {
            r.cancel();
        }
        regs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::LogTransport;

    fn spec(user: &str, pass: &str) -> NewRegistration {
        NewRegistration {
            mailbox: MailboxSpec {
                host: "127.0.0.1".into(),
                port: 3143,
                security: Security::Plain,
                username: user.into(),
                credentials: Credentials::Password(Secret::new(pass)),
            },
            folder: "INBOX".into(),
            transport: Box::new(LogTransport),
            extra_secrets: vec![Secret::new("hook-bearer-secret")],
        }
    }

    #[test]
    fn ids_are_url_safe_and_unique() {
        let a = Registry::new_id();
        let b = Registry::new_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn cap_is_enforced_and_freed_by_remove() {
        let reg = Registry::new(2);
        let a = reg.insert(spec("u1", "p1")).expect("first");
        let _b = reg.insert(spec("u2", "p2")).expect("second");
        assert!(matches!(
            reg.insert(spec("u3", "p3")),
            Err(RelayError::LimitReached)
        ));
        assert_eq!(reg.len(), 2);
        reg.remove(a.id()).expect("remove");
        assert!(a.is_cancelled());
        assert!(matches!(reg.remove(a.id()), Err(RelayError::NotFound)));
        let _c = reg.insert(spec("u3", "p3")).expect("slot freed");
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn snapshot_and_debug_never_contain_secrets() {
        let reg = Registry::new(1);
        let r = reg.insert(spec("u76", "u76pw-secret")).expect("insert");
        let stored = r.set_error("LOGIN u76 u76pw-secret rejected; bearer hook-bearer-secret");
        assert_eq!(stored, "LOGIN u76 [redacted] rejected; bearer [redacted]");
        let snap = r.snapshot();
        assert_eq!(snap.state, RegistrationState::Error);
        assert_eq!(snap.last_error.as_deref(), Some(stored.as_str()));
        let json = serde_json::to_string(&snap).expect("json");
        assert!(!json.contains("u76pw-secret"), "{json}");
        assert!(!json.contains("hook-bearer-secret"), "{json}");
        assert!(json.contains("\"state\":\"error\""), "{json}");
        let dbg = format!("{r:?} {reg:?}");
        assert!(!dbg.contains("u76pw-secret"), "{dbg}");
        assert!(!dbg.contains("hook-bearer-secret"), "{dbg}");

        r.set_state(RegistrationState::Idle);
        assert_eq!(r.snapshot().last_error, None);
        r.note_push_failure("webhook answered HTTP 500 (hook-bearer-secret)");
        assert_eq!(r.state(), RegistrationState::Idle);
        assert_eq!(
            r.snapshot().last_error.as_deref(),
            Some("webhook answered HTTP 500 ([redacted])")
        );
        r.record_push();
        let snap = r.snapshot();
        assert_eq!(snap.pushes, 1);
        assert!(snap.last_push_at.is_some());
        assert_eq!(snap.last_error, None);
    }

    #[test]
    fn a_parked_registration_reports_its_reason_and_evicts_only_itself() {
        let reg = Registry::new(2);
        let a = reg.insert(spec("u1", "p1")).expect("a");
        let b = reg.insert(spec("u2", "p2")).expect("b");
        a.park(ParkReason::CredentialsRejected, "fixed relay text");
        assert_eq!(a.parked(), Some(ParkReason::CredentialsRejected));
        let json = serde_json::to_value(a.snapshot()).expect("json");
        assert_eq!(json["state"], "parked");
        assert_eq!(json["parked_reason"], "credentials_rejected");
        assert_eq!(json["last_error"], "fixed relay text");
        let other = serde_json::to_value(b.snapshot()).expect("json");
        assert_eq!(other["parked_reason"], serde_json::Value::Null);
        assert_eq!(b.parked(), None);

        assert!(a.evict());
        assert!(a.is_cancelled());
        assert!(reg.get(a.id()).is_none());
        assert!(reg.get(b.id()).is_some(), "only the parked one goes");
        assert!(!a.evict(), "already gone");
        // A registration removed by DELETE is not evicted again; a dropped registry evicts
        // nothing.
        let removed = reg.remove(b.id()).expect("remove");
        assert!(!removed.evict());
        assert!(reg.is_empty());
        let c = reg.insert(spec("u3", "p3")).expect("slot freed");
        drop(reg);
        assert!(!c.evict());
    }

    #[tokio::test]
    async fn stop_waits_for_the_task_then_aborts() {
        let reg = Registry::new(1);
        let r = reg.insert(spec("u1", "p1")).expect("insert");
        let mut rx = r.cancel_signal();
        r.attach_task(tokio::spawn(async move {
            cancelled(&mut rx).await;
        }));
        r.stop(Duration::from_secs(5)).await;
        assert_eq!(r.state(), RegistrationState::Stopped);

        // A task that ignores the signal is aborted after the grace period.
        let r2 = reg.remove(r.id()).expect("remove");
        r2.attach_task(tokio::spawn(std::future::pending::<()>()));
        let started = std::time::Instant::now();
        r2.stop(Duration::from_millis(100)).await;
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(reg.drain().is_empty());
    }
}
