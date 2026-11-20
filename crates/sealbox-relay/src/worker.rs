//! One tokio task per registration: hold an IMAP IDLE session and turn "the mailbox grew"
//! into one content-free push.
//!
//! What the worker reads from the server is exactly the counters a read-only `EXAMINE`
//! returns — `UIDVALIDITY`, `UIDNEXT`, `EXISTS` — captured as a [`Watermark`] when the first
//! session starts (the baseline) and re-read after every IDLE wake-up. New mail means
//! `UIDNEXT` advanced past the last watermark (or `EXISTS` grew, for servers that omit
//! `UIDNEXT`). Nothing is ever `FETCH`ed or `SEARCH`ed, so the relay cannot learn a subject, a
//! sender, a UID list or a size even by accident; and because the baseline is taken at
//! registration, mail that was already in the folder never produces a push.
//!
//! Before every connect, the first one included, the IMAP destination passes the
//! [`ImapGuard`] again (allow-list, every resolved address public) and the session dials only
//! the addresses that passed ([`ImapClient::connect_pinned`]): a host that resolves to a
//! private address by now is refused without a connection, and is retried with backoff like
//! any other failure.
//!
//! Lifecycle: connect → `EXAMINE` → idle (re-issued every ≤ 29 min) → on wake, debounce the
//! burst, re-`EXAMINE`, push if the watermark advanced. IMAP errors drop the session and the
//! worker reconnects with exponential backoff (capped); the watermark survives the reconnect,
//! so mail that arrived while the session was down produces one push as soon as the new
//! session's `EXAMINE` sees it. Cancellation (unregister / shutdown) stops the worker promptly
//! from any of those states.
//!
//! A server that **rejects the credentials** is not retried forever: providers lock accounts
//! that keep failing logins. After [`WorkerConfig::max_auth_failures`] (default 3) rejections
//! with no successful login in between, the worker stops connecting and parks the registration
//! (`state: parked`, `parked_reason: credentials_rejected`, [`CREDENTIALS_REJECTED`] as
//! `last_error`); the client registers again with fresh credentials. A parked registration holds
//! no connection, and its worker evicts it from the registry after
//! [`WorkerConfig::parked_ttl`] (default 24 h) unless it is unregistered first, so parked
//! registrations neither hold their slot nor keep the rejected credentials in memory forever. A rejection is `sealbox-mail`'s typed [`ImapError::LoginRejected`]
//! ([`is_credential_rejection`]). Failures before the login (network, TLS, a busy server's
//! `BYE`) and temporary refusals (`[UNAVAILABLE]`) neither count nor reset that tally and keep
//! the capped exponential backoff; a successful login resets it, even if the session then fails
//! (a missing folder, a dropped IDLE).
//!
//! IDLE rounds use [`ImapClient::idle_wait_gapless`]: a message that lands between an
//! `EXAMINE` and the server's IDLE continuation (for example while a push is being delivered)
//! is announced *before* the `+`, and plain `idle_wait` would sleep through it until the round
//! times out.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use sealbox_mail::{
    imap::{IdleEvent, ImapClient, LoginCode, Mailbox},
    Auth, ConnectOptions, ImapError, TransportPolicyError,
};
use tokio::{sync::watch, task::JoinHandle};

use crate::{
    error::RelayError,
    imap_guard::ImapGuard,
    push::PushEvent,
    registry::{cancelled, ParkReason, Registration, RegistrationState},
    secret::Credentials,
};

/// Servers drop IDLE connections after about 30 minutes (RFC 2177 §3); never idle longer.
pub const MAX_IDLE: Duration = Duration::from_secs(29 * 60);

/// Below this remaining debounce window it is not worth re-entering IDLE.
const MIN_DRAIN: Duration = Duration::from_millis(50);

/// `last_error` of a registration whose worker stopped retrying a rejected login. Fixed text:
/// it names no user, host or server message.
pub const CREDENTIALS_REJECTED: &str =
    "credentials rejected by the server; register again with fresh credentials";

/// `last_error` of a registration parked because its OAuth token can never be presented: the
/// server offers no `AUTH=XOAUTH2`. Fixed text: it names no user, host or server message.
pub const XOAUTH2_NOT_OFFERED: &str = "the server offers no XOAUTH2, so the OAuth token can \
     never be presented; register again with an app password or another host";

/// `last_error` of a registration parked because its OAuth token is for a host that is not
/// its provider's own mail host, where `sealbox-mail` never presents a token. Fixed text.
pub const OAUTH_HOST_REFUSED: &str = "the OAuth token can only be presented to its provider's \
     own mail hosts, never to this one; register again with an app password or the provider's \
     host";

/// Timing knobs; the defaults are what the binary uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerConfig {
    /// TCP connect + TLS + login, and every single IMAP command after that.
    pub connect_timeout: Duration,
    /// One IDLE round; clamped to [`MAX_IDLE`].
    pub idle_timeout: Duration,
    /// After the first wake-up, further notifications within this window are coalesced into
    /// the same re-check (one push per burst).
    pub debounce: Duration,
    /// First reconnect delay after an error; doubles up to `backoff_max`.
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// Credential rejections, with no successful login in between, after which the worker
    /// parks the registration instead of retrying. `0` never parks (not recommended).
    pub max_auth_failures: u32,
    /// How long a parked registration stays visible (`GET status` says `parked`) before its
    /// worker evicts it from the registry, freeing the slot and dropping the credentials.
    /// `--parked-ttl` in the binary.
    pub parked_ttl: Duration,
}

/// Default [`WorkerConfig::parked_ttl`]: a day, so a client that checks in daily still learns
/// why its registration stopped.
pub const DEFAULT_PARKED_TTL: Duration = Duration::from_secs(24 * 60 * 60);

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(25 * 60),
            debounce: Duration::from_secs(1),
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(5 * 60),
            max_auth_failures: 3,
            parked_ttl: DEFAULT_PARKED_TTL,
        }
    }
}

impl WorkerConfig {
    /// `idle_timeout` clamped to [`MAX_IDLE`].
    pub fn effective_idle_timeout(&self) -> Duration {
        self.idle_timeout.min(MAX_IDLE)
    }
}

/// The complete, content-free view of a folder the worker keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watermark {
    pub uidvalidity: u32,
    /// `0` when the server did not report `UIDNEXT`.
    pub uidnext: u32,
    pub exists: u32,
}

impl From<&Mailbox> for Watermark {
    fn from(mb: &Mailbox) -> Self {
        Self {
            uidvalidity: mb.uidvalidity,
            uidnext: mb.uidnext,
            exists: mb.exists,
        }
    }
}

/// Did mail arrive between `prev` and `next`?
///
/// `UIDNEXT` is authoritative when both sides report it: it only ever grows, and it grows
/// exactly when a message is added (an `EXPUNGE` leaves it alone, so a delete can never look
/// like an arrival). Without `UIDNEXT`, a growing `EXISTS` is the best available signal. A
/// `UIDVALIDITY` change means the folder was recreated; the counters are not comparable, so
/// the baseline is simply reset without a push.
pub fn has_new_mail(prev: Watermark, next: Watermark) -> bool {
    if prev.uidvalidity != next.uidvalidity {
        return false;
    }
    if prev.uidnext != 0 && next.uidnext != 0 {
        next.uidnext > prev.uidnext
    } else {
        next.exists > prev.exists
    }
}

/// Next reconnect delay: double, capped.
pub fn next_backoff(current: Duration, cfg: &WorkerConfig) -> Duration {
    current
        .checked_mul(2)
        .unwrap_or(cfg.backoff_max)
        .clamp(cfg.backoff_min, cfg.backoff_max)
}

/// Did the server reject the registration's credentials (as opposed to failing for some other
/// reason)? Exactly an [`ImapError::LoginRejected`] (a `NO` or `BAD` answer to `LOGIN` /
/// `AUTHENTICATE`), except one whose response code marks a temporary failure (RFC 5530
/// `[UNAVAILABLE]`, [`LoginCode::is_temporary`]). A `BYE` greeting ([`ImapError::Auth`]), a
/// server without `AUTH=XOAUTH2` ([`ImapError::XOAuth2NotOffered`]), a timeout or a network
/// error says nothing about the credentials. Decided on `sealbox-mail`'s typed error, never on
/// the server's wording.
pub fn is_credential_rejection(err: &RelayError) -> bool {
    matches!(
        err,
        RelayError::Imap(ImapError::LoginRejected { code, .. })
            if !code.as_ref().is_some_and(LoginCode::is_temporary)
    )
}

/// A failure that no retry can change, decided on `sealbox-mail`'s typed error: the server
/// offers no `AUTH=XOAUTH2` for a registration that only has an OAuth token
/// ([`ImapError::XOAuth2NotOffered`], raised before anything is sent), or the host is not the
/// token's provider's own mail host ([`TransportPolicyError::OAuthHostMismatch`], raised before
/// any network write; the API already refuses such registrations). The worker parks the
/// registration at once with this reason and `last_error` instead of reconnecting forever.
/// Everything else (rejected credentials — counted separately —, `BYE`, timeouts, network
/// errors, a missing IDLE) is left to the retry / rejection logic.
pub fn permanent_failure(err: &RelayError) -> Option<(ParkReason, &'static str)> {
    match err {
        RelayError::Imap(ImapError::XOAuth2NotOffered { .. }) => {
            Some((ParkReason::Xoauth2NotOffered, XOAUTH2_NOT_OFFERED))
        }
        RelayError::Imap(ImapError::Policy(TransportPolicyError::OAuthHostMismatch { .. })) => {
            Some((ParkReason::OauthHostRefused, OAUTH_HOST_REFUSED))
        }
        _ => None,
    }
}

/// Park `reg` with `reason` / `message` and hold the slot without connecting until `DELETE`
/// or shutdown cancels it, or the parked TTL evicts it. `why` is the log line's cause.
async fn park_until_evicted(
    reg: &Registration,
    cfg: &WorkerConfig,
    cancel: &mut watch::Receiver<bool>,
    reason: ParkReason,
    message: &str,
    why: &str,
) {
    reg.park(reason, message);
    tracing::warn!(
        registration = reg.id(),
        reason = reason.as_str(),
        parked_ttl_secs = cfg.parked_ttl.as_secs(),
        "{why}: worker parked, no further attempts (the client must register again)"
    );
    // No connection from here on; wait for DELETE / shutdown or evict.
    tokio::select! {
        _ = cancelled(cancel) => {}
        _ = tokio::time::sleep(cfg.parked_ttl) => {
            if reg.evict() {
                tracing::info!(
                    registration = reg.id(),
                    reason = reason.as_str(),
                    parked_secs = cfg.parked_ttl.as_secs(),
                    "parked registration evicted"
                );
            }
        }
    }
}

/// Start the worker for `reg`; every connect passes `guard` first. The caller attaches the
/// handle with [`Registration::attach_task`] so unregister can wait for it.
pub fn spawn(reg: Arc<Registration>, cfg: WorkerConfig, guard: Arc<ImapGuard>) -> JoinHandle<()> {
    tokio::spawn(run(reg, cfg, guard))
}

/// The worker body: sessions with backoff until cancelled, or until the credentials have been
/// rejected `max_auth_failures` times in a row (then the registration is parked).
pub async fn run(reg: Arc<Registration>, cfg: WorkerConfig, guard: Arc<ImapGuard>) {
    let mut cancel = reg.cancel_signal();
    let mut backoff = cfg.backoff_min;
    // The last counters any session saw; `None` until the first baseline.
    let mut last: Option<Watermark> = None;
    // Credential rejections since the last successful login.
    let mut rejections: u32 = 0;
    while !reg.is_cancelled() {
        reg.set_state(RegistrationState::Connecting);
        match session(
            &reg,
            &cfg,
            &guard,
            &mut cancel,
            &mut backoff,
            &mut last,
            &mut rejections,
        )
        .await
        {
            SessionEnd::Cancelled => break,
            SessionEnd::Failed(err) => {
                if let Some((reason, message)) = permanent_failure(&err) {
                    park_until_evicted(&reg, &cfg, &mut cancel, reason, message, message).await;
                    break;
                }
                if is_credential_rejection(&err) {
                    rejections += 1;
                    if cfg.max_auth_failures > 0 && rejections >= cfg.max_auth_failures {
                        let why = format!("login rejected {rejections} times in a row");
                        park_until_evicted(
                            &reg,
                            &cfg,
                            &mut cancel,
                            ParkReason::CredentialsRejected,
                            CREDENTIALS_REJECTED,
                            &why,
                        )
                        .await;
                        break;
                    }
                }
                // `set_error` scrubs; log only what was stored.
                let stored = reg.set_error(&err.to_string());
                tracing::warn!(
                    registration = reg.id(),
                    retry_in_secs = backoff.as_secs(),
                    "IDLE session ended: {stored}"
                );
                tokio::select! {
                    _ = cancelled(&mut cancel) => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = next_backoff(backoff, &cfg);
            }
        }
    }
    reg.set_state(RegistrationState::Stopped);
    tracing::info!(registration = reg.id(), "worker stopped");
}

enum SessionEnd {
    Cancelled,
    Failed(RelayError),
}

impl From<ImapError> for SessionEnd {
    fn from(e: ImapError) -> Self {
        SessionEnd::Failed(RelayError::Imap(e))
    }
}

fn auth_for(spec: &crate::registry::MailboxSpec) -> Auth {
    match &spec.credentials {
        Credentials::Password(s) => Auth::Password {
            user: spec.username.clone(),
            pass: s.expose().to_owned(),
        },
        Credentials::OAuth(s) => Auth::XOAuth2 {
            user: spec.username.clone(),
            access_token: s.expose().to_owned(),
        },
    }
}

/// One connection: login, `EXAMINE`, idle loop. Returns why it ended. `last` carries the
/// watermark across sessions: the first session's `EXAMINE` is the registration baseline,
/// a later session's first `EXAMINE` is compared against it (mail that arrived while
/// disconnected is pushed once).
async fn session(
    reg: &Registration,
    cfg: &WorkerConfig,
    guard: &ImapGuard,
    cancel: &mut watch::Receiver<bool>,
    backoff: &mut Duration,
    last: &mut Option<Watermark>,
    rejections: &mut u32,
) -> SessionEnd {
    let spec = reg.mailbox();
    let folder = reg.folder();
    // The destination policy again, before every connect: the name may resolve elsewhere by
    // now. The session then dials exactly the addresses that passed.
    let addrs = tokio::select! {
        _ = cancelled(cancel) => return SessionEnd::Cancelled,
        r = guard.check(&spec.host) => match r {
            Ok(addrs) => addrs,
            Err(refusal) => return SessionEnd::Failed(RelayError::ImapDestination(refusal)),
        },
    };
    let opts = ConnectOptions::new(cfg.connect_timeout);
    let connect = ImapClient::connect_pinned(
        &spec.host,
        &addrs,
        spec.port,
        spec.security,
        auth_for(spec),
        &opts,
    );
    let mut client = tokio::select! {
        _ = cancelled(cancel) => return SessionEnd::Cancelled,
        r = connect => match r {
            Ok(c) => c,
            Err(e) => return e.into(),
        },
    };
    // The server accepted the credentials: whatever fails next is not a rejection streak.
    *rejections = 0;
    if !client.has_capability("IDLE") {
        let _ = client.logout().await;
        return ImapError::IdleUnsupported.into();
    }
    // Read-only select: the relay never changes flags, never marks anything \Seen.
    let mut mark = match client.examine(folder).await {
        Ok(mb) => Watermark::from(&mb),
        Err(e) => return e.into(),
    };
    *backoff = cfg.backoff_min;
    reg.set_state(RegistrationState::Idle);
    tracing::info!(registration = reg.id(), folder, "idle session established");
    if let Some(prev) = last.replace(mark) {
        if has_new_mail(prev, mark) {
            // Mail arrived while the previous session was down.
            deliver(reg).await;
        }
    }
    let idle_timeout = cfg.effective_idle_timeout();

    loop {
        let event = tokio::select! {
            _ = cancelled(cancel) => return SessionEnd::Cancelled,
            r = client.idle_wait_gapless(idle_timeout) => match r {
                Ok(ev) => ev,
                Err(e) => return e.into(),
            },
        };
        if event == IdleEvent::NewData {
            if let Err(end) = drain_burst(&mut client, cfg.debounce, cancel).await {
                return end;
            }
        }
        if reg.is_cancelled() {
            let _ = client.logout().await;
            return SessionEnd::Cancelled;
        }
        // Re-read the counters (and, on a timeout, catch anything a quiet server did not
        // announce). Still read-only, still no FETCH.
        let now = match client.examine(folder).await {
            Ok(mb) => Watermark::from(&mb),
            Err(e) => return e.into(),
        };
        if has_new_mail(mark, now) {
            deliver(reg).await;
        }
        mark = now;
        *last = Some(now);
    }
}

/// Keep idling until `window` has passed without a further notification (or expires), so a
/// burst of untagged responses becomes a single re-check.
async fn drain_burst(
    client: &mut ImapClient,
    window: Duration,
    cancel: &mut watch::Receiver<bool>,
) -> Result<(), SessionEnd> {
    let deadline = Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining < MIN_DRAIN {
            return Ok(());
        }
        let event = tokio::select! {
            _ = cancelled(cancel) => return Err(SessionEnd::Cancelled),
            r = client.idle_wait_gapless(remaining) => r.map_err(SessionEnd::from)?,
        };
        if event == IdleEvent::Timeout {
            return Ok(());
        }
    }
}

/// Send the one push. A failure is recorded (scrubbed) and the session keeps idling.
async fn deliver(reg: &Registration) {
    let event = PushEvent::new_mail(reg.id(), reg.folder());
    match reg.transport().send(&event).await {
        Ok(()) => {
            reg.record_push();
            tracing::info!(
                registration = reg.id(),
                transport = reg.transport().kind(),
                "push sent"
            );
        }
        Err(e) => {
            let stored = reg.note_push_failure(&e.to_string());
            tracing::warn!(registration = reg.id(), "push failed: {stored}");
        }
    }
}

/// A scripted IMAP server on loopback for the worker's and the API's tests.
#[cfg(test)]
pub(crate) mod test_imap {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    /// What the scripted IMAP server does on one connection.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Conn {
        /// `NO [AUTHENTICATIONFAILED] …` to `LOGIN`: the credentials are rejected.
        Reject,
        /// `BAD …` to `LOGIN`: also a rejection.
        RejectBad,
        /// `NO [UNAVAILABLE] …` to `LOGIN`: RFC 5530's temporary failure.
        Unavailable,
        /// Exchange Online's code-less `NO User is authenticated but not connected.` to
        /// `LOGIN`: sometimes a burst, often a refusal that never clears (a login that is not
        /// the mailbox, IMAP disabled), so it counts as a rejection.
        NotConnected,
        /// `* BYE …` instead of the greeting (a busy server).
        Bye,
        /// The connection is closed before the greeting (a network failure).
        Drop,
        /// Login and `EXAMINE` succeed; the connection drops when `IDLE` starts.
        AcceptThenDrop,
    }

    /// A scripted IMAP server on loopback (the style of `sealbox-mail`'s
    /// `tests/imap_idle_gapless.rs`): connection `i` (0-based) plays `script(i)`. Returns the
    /// port and the number of connections accepted so far.
    pub(crate) async fn scripted_imap(script: fn(usize) -> Conn) -> (u16, Arc<AtomicUsize>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let behaviour = script(counter.fetch_add(1, Ordering::SeqCst));
                tokio::spawn(async move {
                    let (rd, mut wr) = sock.into_split();
                    match behaviour {
                        Conn::Bye => {
                            let _ = wr
                                .write_all(b"* BYE Too many connections, try later\r\n")
                                .await;
                            return;
                        }
                        Conn::Drop => return,
                        _ => {}
                    }
                    if wr.write_all(b"* OK scripted IMAP ready\r\n").await.is_err() {
                        return;
                    }
                    let mut lines = BufReader::new(rd).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let mut parts = line.splitn(3, ' ');
                        let tag = parts.next().unwrap_or("*").to_owned();
                        let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
                        let reply = match (cmd.as_str(), behaviour) {
                            ("CAPABILITY", _) => format!(
                                "* CAPABILITY IMAP4rev1 IDLE\r\n{tag} OK CAPABILITY completed\r\n"
                            ),
                            ("LOGIN", Conn::Reject) => {
                                format!("{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n")
                            }
                            ("LOGIN", Conn::RejectBad) => {
                                format!("{tag} BAD LOGIN not accepted\r\n")
                            }
                            ("LOGIN", Conn::Unavailable) => {
                                format!("{tag} NO [UNAVAILABLE] Backend down, try later\r\n")
                            }
                            ("LOGIN", Conn::NotConnected) => {
                                format!("{tag} NO User is authenticated but not connected.\r\n")
                            }
                            ("LOGIN", _) => format!("{tag} OK LOGIN completed\r\n"),
                            ("EXAMINE", _) => format!(
                                "* 1 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 7] ok\r\n\
                                 * OK [UIDNEXT 2] ok\r\n{tag} OK [READ-ONLY] EXAMINE done\r\n"
                            ),
                            ("IDLE", _) => return,
                            ("LOGOUT", _) => {
                                let _ = wr
                                    .write_all(format!("* BYE\r\n{tag} OK LOGOUT\r\n").as_bytes())
                                    .await;
                                return;
                            }
                            _ => format!("{tag} OK\r\n"),
                        };
                        if wr.write_all(reply.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (port, accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::test_imap::{scripted_imap, Conn};
    use super::*;
    use crate::{
        imap_guard::{ImapPolicy, ImapRefusal},
        push::LogTransport,
        registry::{MailboxSpec, NewRegistration, Registry},
        secret::Secret,
        webhook_guard::test_dns::FakeDns,
    };
    use sealbox_mail::Security;
    use std::sync::atomic::Ordering;

    fn wm(uidvalidity: u32, uidnext: u32, exists: u32) -> Watermark {
        Watermark {
            uidvalidity,
            uidnext,
            exists,
        }
    }

    #[test]
    fn new_mail_means_uidnext_advanced_within_one_uidvalidity() {
        let base = wm(7, 10, 9);
        assert!(!has_new_mail(base, base));
        assert!(has_new_mail(base, wm(7, 11, 10)));
        // EXPUNGE: EXISTS shrinks, UIDNEXT stays → not new mail.
        assert!(!has_new_mail(base, wm(7, 10, 8)));
        // A delete followed by an arrival: EXISTS unchanged but UIDNEXT moved → new mail.
        assert!(has_new_mail(base, wm(7, 11, 9)));
        // Folder recreated: counters incomparable, no push.
        assert!(!has_new_mail(base, wm(8, 1, 0)));
        assert!(!has_new_mail(base, wm(8, 50, 40)));
        // Servers without UIDNEXT fall back to EXISTS growth.
        assert!(has_new_mail(wm(7, 0, 9), wm(7, 0, 10)));
        assert!(!has_new_mail(wm(7, 0, 9), wm(7, 0, 9)));
        assert!(!has_new_mail(wm(7, 0, 9), wm(7, 0, 3)));
        // UIDNEXT appearing / disappearing mid-session: EXISTS decides.
        assert!(has_new_mail(wm(7, 10, 9), wm(7, 0, 10)));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let cfg = WorkerConfig {
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(300),
            ..WorkerConfig::default()
        };
        let mut d = cfg.backoff_min;
        let mut seen = vec![d];
        for _ in 0..12 {
            d = next_backoff(d, &cfg);
            seen.push(d);
        }
        assert_eq!(seen[1], Duration::from_secs(2));
        assert_eq!(seen[4], Duration::from_secs(16));
        assert!(seen.iter().all(|x| *x <= cfg.backoff_max));
        assert_eq!(*seen.last().expect("non-empty"), cfg.backoff_max);
        assert_eq!(next_backoff(Duration::MAX, &cfg), cfg.backoff_max);
        assert_eq!(next_backoff(Duration::ZERO, &cfg), cfg.backoff_min);
    }

    #[test]
    fn idle_rounds_never_exceed_29_minutes() {
        assert!(WorkerConfig::default().effective_idle_timeout() <= MAX_IDLE);
        let long = WorkerConfig {
            idle_timeout: Duration::from_secs(3600),
            ..WorkerConfig::default()
        };
        assert_eq!(long.effective_idle_timeout(), MAX_IDLE);
    }

    fn quick_retries() -> WorkerConfig {
        WorkerConfig {
            connect_timeout: Duration::from_secs(2),
            backoff_min: Duration::from_millis(20),
            backoff_max: Duration::from_millis(40),
            ..WorkerConfig::default()
        }
    }

    /// An IMAP guard that admits the scripted servers on loopback (and resolves names with
    /// `dns`).
    fn guard_with(allow_private: bool, dns: FakeDns) -> Arc<ImapGuard> {
        let policy = ImapPolicy {
            allow_private,
            ..ImapPolicy::default()
        };
        Arc::new(ImapGuard::with_resolver(
            policy,
            Arc::new(dns),
            Duration::from_millis(300),
        ))
    }

    fn local_guard() -> Arc<ImapGuard> {
        guard_with(true, FakeDns::new())
    }

    /// A registration on the scripted server, its worker running.
    fn start(registry: &Registry, port: u16) -> Arc<Registration> {
        start_at(registry, "127.0.0.1", port, local_guard())
    }

    fn start_at(
        registry: &Registry,
        host: &str,
        port: u16,
        guard: Arc<ImapGuard>,
    ) -> Arc<Registration> {
        start_with(registry, host, port, guard, quick_retries())
    }

    fn start_with(
        registry: &Registry,
        host: &str,
        port: u16,
        guard: Arc<ImapGuard>,
        cfg: WorkerConfig,
    ) -> Arc<Registration> {
        start_as(
            registry,
            host,
            port,
            guard,
            cfg,
            Credentials::Password(Secret::new("pw-scripted-123")),
        )
    }

    fn start_as(
        registry: &Registry,
        host: &str,
        port: u16,
        guard: Arc<ImapGuard>,
        cfg: WorkerConfig,
        credentials: Credentials,
    ) -> Arc<Registration> {
        let reg = registry
            .insert(NewRegistration {
                mailbox: MailboxSpec {
                    host: host.into(),
                    port,
                    security: Security::Plain,
                    username: "u-scripted".into(),
                    credentials,
                },
                folder: "INBOX".into(),
                transport: Box::new(LogTransport),
                extra_secrets: Vec::new(),
            })
            .expect("insert");
        reg.attach_task(spawn(reg.clone(), cfg, guard));
        reg
    }

    async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn parked(reg: &Registration) -> bool {
        parked_as(reg, ParkReason::CredentialsRejected, CREDENTIALS_REJECTED)
    }

    /// Parked with exactly `reason` and the fixed `message` (both or neither).
    fn parked_as(reg: &Registration, reason: ParkReason, message: &str) -> bool {
        let snap = reg.snapshot();
        let parked = snap.state == RegistrationState::Parked;
        assert_eq!(parked, snap.parked_reason == Some(reason), "{snap:?}");
        assert_eq!(
            parked,
            snap.last_error.as_deref() == Some(message),
            "{snap:?}"
        );
        parked
    }

    /// `XOAuth2NotOffered` (the server's CAPABILITY lacks `AUTH=XOAUTH2`, raised by
    /// `sealbox-mail` before the token is sent) is a permanent failure: parked at once with the
    /// fixed text. Rejections, temporary and network failures are not (they keep their own
    /// counting / retry logic). The park-and-hold path itself is exercised end to end by
    /// `an_oauth_token_for_a_non_provider_host_is_parked_at_once` below: a scripted server
    /// cannot play a provider's host over plain IMAP (the transport policy refuses plain to
    /// any non-local host before the capability check).
    #[test]
    fn xoauth2_not_offered_is_a_permanent_failure_and_rejections_are_not() {
        let not_offered = RelayError::Imap(ImapError::XOAuth2NotOffered {
            host: "imap.example.test".into(),
        });
        assert_eq!(
            permanent_failure(&not_offered),
            Some((ParkReason::Xoauth2NotOffered, XOAUTH2_NOT_OFFERED))
        );
        assert!(!is_credential_rejection(&not_offered));
        let mismatch =
            RelayError::Imap(ImapError::Policy(TransportPolicyError::OAuthHostMismatch {
                provider: None,
                host: "imap.example.test".into(),
            }));
        assert_eq!(
            permanent_failure(&mismatch),
            Some((ParkReason::OauthHostRefused, OAUTH_HOST_REFUSED))
        );
        for transient in [
            RelayError::Imap(ImapError::Timeout(Duration::from_secs(1))),
            RelayError::Imap(ImapError::IdleUnsupported),
            RelayError::Imap(ImapError::Auth("* BYE".into())),
            RelayError::Imap(ImapError::LoginRejected {
                host: "imap.example.test".into(),
                mechanism: "LOGIN",
                code: None,
                reply: "NO Invalid credentials".into(),
            }),
        ] {
            assert_eq!(permanent_failure(&transient), None, "{transient}");
        }
        // The wire values the status API shows (serde snake_case == as_str).
        for reason in [
            ParkReason::CredentialsRejected,
            ParkReason::Xoauth2NotOffered,
            ParkReason::OauthHostRefused,
        ] {
            let wire = serde_json::to_string(&reason).expect("json");
            assert_eq!(wire, format!("\"{}\"", reason.as_str()));
        }
        // The fixed texts name no host, user or server message.
        for text in [
            XOAUTH2_NOT_OFFERED,
            OAUTH_HOST_REFUSED,
            CREDENTIALS_REJECTED,
        ] {
            assert!(!text.contains("example"), "{text}");
        }
    }

    /// An OAuth token for a host that is not its provider's (loopback here): `sealbox-mail`
    /// refuses before any network write, and the worker parks the registration at once —
    /// defence in depth behind the API's own refusal of such a registration.
    #[tokio::test]
    async fn an_oauth_token_for_a_non_provider_host_is_parked_at_once() {
        let (port, connections) = scripted_imap(|_| Conn::AcceptThenDrop).await;
        let registry = Registry::new(1);
        let reg = start_as(
            &registry,
            "127.0.0.1",
            port,
            local_guard(),
            quick_retries(),
            Credentials::OAuth(Secret::new("ya29.scripted-token-789")),
        );
        wait_until("parking", || {
            parked_as(&reg, ParkReason::OauthHostRefused, OAUTH_HOST_REFUSED)
        })
        .await;
        let dialled = connections.load(Ordering::SeqCst);
        assert!(dialled <= 1, "{dialled} connections");
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            connections.load(Ordering::SeqCst),
            dialled,
            "the worker kept retrying"
        );
        let text = serde_json::to_string(&reg.snapshot()).expect("json");
        assert!(!text.contains("ya29.scripted-token-789"), "{text}");
        assert!(text.contains("oauth_host_refused"), "{text}");
        reg.stop(Duration::from_secs(5)).await;
        assert_eq!(reg.state(), RegistrationState::Stopped);
    }

    /// The same server with a password logs in normally: the capability check only concerns
    /// an OAuth registration.
    #[tokio::test]
    async fn a_password_registration_ignores_the_missing_xoauth2() {
        let (port, connections) = scripted_imap(|_| Conn::AcceptThenDrop).await;
        let registry = Registry::new(1);
        let reg = start(&registry, port);
        wait_until("a connection", || connections.load(Ordering::SeqCst) >= 1).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_ne!(
            reg.state(),
            RegistrationState::Parked,
            "{:?}",
            reg.snapshot()
        );
        reg.stop(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn rejected_credentials_park_the_registration_after_three_attempts() {
        // NO and BAD to LOGIN both count.
        let (port, connections) = scripted_imap(|i| {
            if i == 1 {
                Conn::RejectBad
            } else {
                Conn::Reject
            }
        })
        .await;
        let registry = Registry::new(1);
        let reg = start(&registry, port);
        wait_until("parking", || parked(&reg)).await;
        let snap = reg.snapshot();
        assert_eq!(snap.state, RegistrationState::Parked);
        assert_eq!(snap.parked_reason, Some(ParkReason::CredentialsRejected));
        assert_eq!(connections.load(Ordering::SeqCst), 3);
        // Ten times the longest backoff later: still parked, not one more login attempt.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            connections.load(Ordering::SeqCst),
            3,
            "the worker kept retrying"
        );
        assert_eq!(reg.snapshot(), snap);
        let text = serde_json::to_string(&snap).expect("json");
        for leak in [
            "pw-scripted-123",
            "u-scripted",
            "127.0.0.1",
            "Invalid credentials",
        ] {
            assert!(!text.contains(leak), "{leak}: {text}");
        }
        // The worker holds no connection and only waits for the parked TTL (24 h here):
        // unregistering is immediate.
        let started = Instant::now();
        reg.stop(Duration::from_secs(5)).await;
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(reg.state(), RegistrationState::Stopped);
    }

    /// Exchange's code-less `User is authenticated but not connected` is also its answer for
    /// failures that never clear (a `user=` that is not the token's mailbox, IMAP disabled for
    /// it, an app not allowed in): repeated, it parks the registration like any rejection
    /// instead of reconnecting forever.
    #[tokio::test]
    async fn a_persistent_not_connected_refusal_parks_the_registration() {
        let (port, connections) = scripted_imap(|_| Conn::NotConnected).await;
        let registry = Registry::new(1);
        let reg = start(&registry, port);
        wait_until("parking", || parked(&reg)).await;
        let snap = reg.snapshot();
        assert_eq!(snap.parked_reason, Some(ParkReason::CredentialsRejected));
        assert_eq!(connections.load(Ordering::SeqCst), 3);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            connections.load(Ordering::SeqCst),
            3,
            "no login while parked"
        );
        reg.stop(Duration::from_secs(5)).await;
    }

    /// A burst of it between successful logins does not park: a successful login resets the
    /// count, so only `max_auth_failures` refusals in a row do.
    #[tokio::test]
    async fn a_not_connected_burst_between_logins_does_not_park() {
        // not-connected ×2, login OK (then the link drops), repeated: never 3 in a row.
        let (port, connections) = scripted_imap(|i| {
            if i % 3 == 2 {
                Conn::AcceptThenDrop
            } else {
                Conn::NotConnected
            }
        })
        .await;
        let registry = Registry::new(1);
        let reg = start(&registry, port);
        wait_until("seven attempts", || connections.load(Ordering::SeqCst) >= 7).await;
        assert!(!parked(&reg), "{:?}", reg.snapshot());
        reg.stop(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn a_parked_registration_is_evicted_after_the_ttl_and_not_before() {
        let (port, connections) = scripted_imap(|_| Conn::Reject).await;
        let registry = Registry::new(1);
        let ttl = Duration::from_millis(400);
        let cfg = WorkerConfig {
            parked_ttl: ttl,
            ..quick_retries()
        };
        let reg = start_with(&registry, "127.0.0.1", port, local_guard(), cfg);
        wait_until("parking", || parked(&reg)).await;
        let parked_at = Instant::now();
        let id = reg.id().to_owned();
        wait_until("eviction", || registry.get(&id).is_none()).await;
        let after = parked_at.elapsed();
        // Polled every 10 ms after parking was seen: eviction came no earlier than the TTL
        // minus that polling slack.
        assert!(
            after >= ttl - Duration::from_millis(30),
            "evicted after {after:?}"
        );
        assert!(registry.is_empty(), "the slot is free");
        assert!(reg.is_cancelled());
        wait_until("the worker to stop", || {
            reg.state() == RegistrationState::Stopped
        })
        .await;
        assert_eq!(
            connections.load(Ordering::SeqCst),
            3,
            "no login while parked"
        );
        // A new registration fits in the freed slot.
        let again = start(&registry, port);
        again.stop(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn temporary_failures_are_retried_without_parking() {
        let (port, connections) = scripted_imap(|i| {
            if i % 2 == 0 {
                Conn::Bye
            } else {
                Conn::Unavailable
            }
        })
        .await;
        let registry = Registry::new(1);
        let reg = start(&registry, port);
        // Three `[UNAVAILABLE]` answers among the first six connections: a worker that counted
        // them would have parked and never open a seventh.
        wait_until("seven attempts", || connections.load(Ordering::SeqCst) >= 7).await;
        assert!(!parked(&reg), "{:?}", reg.snapshot());
        let err = reg.snapshot().last_error.unwrap_or_default();
        assert!(!err.contains("pw-scripted-123"), "{err}");
        reg.stop(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn a_successful_login_resets_the_rejection_count() {
        // reject, reject, login OK (then the link drops), reject × 3 → parked after 6.
        let (port, connections) = scripted_imap(|i| {
            if i == 2 {
                Conn::AcceptThenDrop
            } else {
                Conn::Reject
            }
        })
        .await;
        let registry = Registry::new(1);
        let reg = start(&registry, port);
        wait_until("parking", || parked(&reg)).await;
        assert_eq!(connections.load(Ordering::SeqCst), 6);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(connections.load(Ordering::SeqCst), 6);
        reg.stop(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn other_failures_between_rejections_neither_count_nor_reset() {
        // reject, busy, reject, busy, reject → parked after 5 connections.
        let (port, connections) =
            scripted_imap(|i| if i % 2 == 0 { Conn::Reject } else { Conn::Bye }).await;
        let registry = Registry::new(1);
        let reg = start(&registry, port);
        wait_until("parking", || parked(&reg)).await;
        assert_eq!(connections.load(Ordering::SeqCst), 5);
        reg.stop(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn every_connect_is_checked_again_and_dials_the_checked_address() {
        // `.test` names never resolve through the system resolver, so reaching the scripted
        // server proves the session dialled the address the guard checked. After the link
        // drops, the name no longer resolves: no second connection.
        let (port, connections) = scripted_imap(|_| Conn::AcceptThenDrop).await;
        let dns = FakeDns::new()
            .answer("imap.relay.sealbox.test", &["127.0.0.1"])
            .answer("imap.relay.sealbox.test", &[]);
        let registry = Registry::new(1);
        let reg = start_at(
            &registry,
            "imap.relay.sealbox.test",
            port,
            guard_with(true, dns),
        );
        let refused = format!("IMAP destination refused: {}", ImapRefusal::Unresolvable);
        wait_until("the refused reconnect", || {
            reg.snapshot().last_error.as_deref() == Some(refused.as_str())
        })
        .await;
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        assert!(!parked(&reg));
        reg.stop(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn a_destination_refused_before_connecting_opens_no_connection() {
        // The production policy: the name resolves to loopback, so nothing is dialled; the
        // worker keeps retrying (DNS may change back), it does not park.
        let (port, connections) = scripted_imap(|_| Conn::AcceptThenDrop).await;
        let dns = Arc::new(FakeDns::new().answer("imap.rebound.example", &["127.0.0.1"]));
        let guard = Arc::new(ImapGuard::with_resolver(
            ImapPolicy::default(),
            dns.clone(),
            Duration::from_millis(300),
        ));
        let registry = Registry::new(1);
        let reg = start_at(&registry, "imap.rebound.example", port, guard);
        wait_until("three refused attempts", || dns.lookups() >= 3).await;
        let snap = reg.snapshot();
        assert_eq!(snap.state, RegistrationState::Error);
        assert_eq!(
            snap.last_error.as_deref(),
            Some(format!("IMAP destination refused: {}", ImapRefusal::NonPublic).as_str())
        );
        assert_eq!(connections.load(Ordering::SeqCst), 0, "nothing was dialled");
        assert!(!parked(&reg));
        reg.stop(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn network_errors_between_rejections_neither_count_nor_reset() {
        // reject, dropped, reject, dropped, reject → parked after 5 connections. Counting the
        // drops would park after 3; resetting on them would never park.
        let (port, connections) =
            scripted_imap(|i| if i % 2 == 0 { Conn::Reject } else { Conn::Drop }).await;
        let registry = Registry::new(1);
        let reg = start(&registry, port);
        wait_until("parking", || parked(&reg)).await;
        assert_eq!(connections.load(Ordering::SeqCst), 5);
        reg.stop(Duration::from_secs(5)).await;
    }

    #[test]
    fn only_a_login_rejection_counts_and_not_a_temporary_one() {
        let rejected = |code: Option<LoginCode>| {
            RelayError::Imap(ImapError::LoginRejected {
                host: "imap.example.com".into(),
                mechanism: sealbox_mail::imap::AUTH_LOGIN,
                code,
                reply: "NO whatever the server says".into(),
            })
        };
        for code in [
            None,
            Some(LoginCode::AuthenticationFailed),
            Some(LoginCode::Expired),
            Some(LoginCode::Alert),
            Some(LoginCode::Other("NOPERM".into())),
        ] {
            assert!(is_credential_rejection(&rejected(code.clone())), "{code:?}");
        }
        assert!(!is_credential_rejection(&rejected(Some(
            LoginCode::Unavailable
        ))));
        // Exchange's code-less "not connected" (sometimes a burst, often permanent) counts.
        assert!(is_credential_rejection(&RelayError::Imap(
            ImapError::LoginRejected {
                host: "outlook.office365.com".into(),
                mechanism: sealbox_mail::imap::AUTH_XOAUTH2,
                code: None,
                reply: "NO User is authenticated but not connected.".into(),
            }
        )));
        // Not a login rejection, whatever the text says.
        let not_a_verdict = [
            ImapError::Auth("server refused connection: Too many connections".into()),
            ImapError::Auth("[AUTHENTICATIONFAILED] Invalid credentials".into()),
            ImapError::XOAuth2NotOffered {
                host: "imap.example.com".into(),
            },
            ImapError::IdleUnsupported,
            ImapError::Timeout(Duration::from_secs(1)),
            ImapError::Connect {
                host: "imap.example.com".into(),
                port: 993,
                source: std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
            },
            ImapError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
        ];
        for e in not_a_verdict {
            let text = e.to_string();
            assert!(!is_credential_rejection(&RelayError::Imap(e)), "{text}");
        }
    }

    /// No IMAP server needed: a closed port makes the worker report a (scrubbed) error, back
    /// off, and stop promptly when cancelled.
    #[tokio::test]
    async fn worker_records_scrubbed_error_and_stops_on_cancel() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = closed.local_addr().expect("addr").port();
        drop(closed);

        let registry = Registry::new(1);
        let reg = registry
            .insert(NewRegistration {
                mailbox: MailboxSpec {
                    host: "127.0.0.1".into(),
                    port,
                    security: Security::Plain,
                    username: "u76".into(),
                    credentials: Credentials::Password(Secret::new("pw-secret-xyz")),
                },
                folder: "INBOX".into(),
                transport: Box::new(LogTransport),
                extra_secrets: Vec::new(),
            })
            .expect("insert");
        let cfg = WorkerConfig {
            connect_timeout: Duration::from_secs(2),
            backoff_min: Duration::from_millis(50),
            backoff_max: Duration::from_millis(200),
            ..WorkerConfig::default()
        };
        reg.attach_task(spawn(reg.clone(), cfg, local_guard()));

        let deadline = Instant::now() + Duration::from_secs(5);
        while reg.state() != RegistrationState::Error {
            assert!(Instant::now() < deadline, "state: {:?}", reg.snapshot());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let snap = reg.snapshot();
        let err = snap.last_error.clone().expect("last_error recorded");
        assert!(err.contains("connect"), "{err}");
        assert!(!err.contains("pw-secret-xyz"), "{err}");
        assert_eq!(snap.pushes, 0);

        let started = Instant::now();
        reg.stop(Duration::from_secs(5)).await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "stop was not prompt"
        );
        assert_eq!(reg.state(), RegistrationState::Stopped);
    }
}
