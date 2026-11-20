//! Gate G16 — push relay prototype: IMAP IDLE → content-free push, proven against the local
//! GreenMail server (`testing/mail_up.sh`: IMAP 127.0.0.1:3143, SMTP 127.0.0.1:3025). This gate
//! owns the GreenMail users u76–u80 (password `<user>pw`) and touches no other mailbox.
//!
//! Run: `testing/mail_up.sh && cargo test -p sealbox-relay --test gate_g16 -- --ignored`
//! (add `--nocapture` to see the measured latencies).
//!
//! | test | mailbox | proves |
//! |---|---|---|
//! | `push_arrives_without_content_and_unregister_stops_it` | u76 | the same registration is refused (400, reason without the URL or host) by a relay without the dev IMAP flag or without both dev webhook flags; with them, a real mail produces exactly one webhook push whose body is byte-for-byte `{registration_id, event, folder, sent_at}` — no subject, sender, body, Message-ID, UID or count, no credential, in body or headers; `DELETE` stops pushes and the registration is gone |
//! | `oauth_to_a_non_provider_host_and_control_characters_are_refused` | u77 | registrations that could never log in are refused up front with a 400 naming the field, never the value or host: an OAuth token for a host that is not its provider's (GreenMail on loopback), a password or token with a control character; the parked paths (`xoauth2_not_offered`, `oauth_host_refused`) are unit-tested against a scripted server |
//! | `api_requires_the_token_and_never_echoes_secrets` | u77 | bearer auth on `/v1/push/*`, open health; a rejected IMAP password is tried exactly 3 times (counted at a loopback proxy), then the registration is parked (`state: parked`, `parked_reason: credentials_rejected`, the fixed credentials-rejected `last_error`), no further connection is made, and after the parked TTL (5 s here) it is evicted (404, health 0); unknown fields / wrong types / plain IMAP to a public host → 400 without echoing values |
//! | `relay_binary_runs_as_its_own_process` | u77 | the `sealbox-relay` binary (a separate process, API token from the environment, the three development flags) pushes, then exits 0 on SIGTERM; its log has no secret and no mail content |
//! | `burst_is_debounced` | u78 | three mails in quick succession → 1..=3 pushes, exactly 1 when they land inside the debounce window |
//! | `mail_landing_during_a_push_is_not_missed` | u79 | a mail delivered while the previous push is still in flight gets its own push (the server announces it *before* the IDLE continuation) |
//! | `reconnect_pushes_mail_that_arrived_while_disconnected` | u80 | after a dropped connection the worker reconnects and pushes the mail that arrived during the outage, once; a reconnect without new mail pushes nothing |
//!
//! u77 is shared on purpose: the API test only ever presents a *wrong* password and never
//! sends u77 mail, so it cannot interfere with the process test's pushes.
//!
//! GreenMail (`127.0.0.1:3143`) and the webhook receiver (`http://127.0.0.1:<port>`) are both
//! local, which the production policies refuse: IMAP servers must be public addresses, webhooks
//! https to public addresses. The gate's relays therefore run with the three development flags
//! set explicitly (`imap_allow_private`, `webhook_allow_private`, `webhook_allow_http_private`;
//! the binary gets `--imap-allow-private --webhook-allow-private --webhook-allow-http-private`),
//! and the u76 test proves the same registration is refused without each of them.

use std::{
    collections::BTreeSet,
    process::Stdio,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, Uri},
    Router,
};
use reqwest::StatusCode;
use sealbox_mail::{
    imap::{ImapClient, MailboxStatus},
    mime::{build_plain, Mailbox, MessageDraft},
    smtp::SmtpClient,
    Auth, Security,
};
use sealbox_relay::{
    AppState, ImapRefusal, Options, Refusal, Secret, WorkerConfig, CREDENTIALS_REJECTED,
};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

const IMAP: (&str, u16) = ("127.0.0.1", 3143);
const SMTP: (&str, u16) = ("127.0.0.1", 3025);
const DOMAIN: &str = "sealbox.test";

/// The canonical push body with the two variable values replaced: anything else in a push
/// (a subject, a sender, a UID, a count …) would make the body differ from this.
const PUSH_SKELETON: &str =
    r#"{"registration_id":"<id>","event":"new_mail","folder":"INBOX","sent_at":"<ts>"}"#;

// ---- helpers: identity, mail, mailbox counters -----------------------------------------

/// Unique per call (time + pid + randomness), so concurrent and repeated runs never collide.
fn nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "{nanos:x}p{:x}r{:08x}",
        std::process::id(),
        rand::random::<u32>()
    )
}

fn password(user: &str) -> String {
    format!("{user}pw")
}

fn address(user: &str) -> String {
    format!("{user}@{DOMAIN}")
}

/// A test mail with distinctive content, none of which may ever reach a push.
struct Probe {
    nonce: String,
    sender_name: String,
    draft: MessageDraft,
}

impl Probe {
    fn new(tag: &str, to_user: &str) -> Self {
        let nonce = nonce();
        let sender_name = format!("G16 Sender {nonce}");
        let draft = MessageDraft::new(
            Mailbox::named(&sender_name, format!("g16-{tag}-sender-{nonce}@{DOMAIN}")),
            vec![Mailbox::new(address(to_user))],
            format!("G16 {tag} subject {nonce}"),
            format!("G16 {tag} body text {nonce}: this sentence must never reach a push.\r\n"),
        );
        Self {
            nonce,
            sender_name,
            draft,
        }
    }

    /// Everything about this mail a push must not reveal.
    fn content(&self) -> Vec<String> {
        vec![
            self.nonce.clone(),
            self.draft.subject.clone(),
            self.draft.from.address.clone(),
            self.sender_name.clone(),
            self.draft.text_body.trim().to_owned(),
            self.draft
                .message_id
                .trim_matches(|c| c == '<' || c == '>')
                .to_owned(),
        ]
    }

    async fn send(&self, smtp: &SmtpClient) {
        let raw = build_plain(&self.draft).expect("build the probe mail");
        smtp.send_raw(
            &self.draft.from.address,
            &self.draft.envelope_recipients(),
            &raw,
        )
        .await
        .expect("SMTP submit to GreenMail");
    }
}

fn smtp() -> SmtpClient {
    SmtpClient::connect(SMTP.0, SMTP.1, Security::Plain, None).expect("SMTP client")
}

/// `STATUS INBOX` over a separate IMAP session (the relay's own session is not involved).
async fn counters(user: &str) -> MailboxStatus {
    let mut c = ImapClient::connect(
        IMAP.0,
        IMAP.1,
        Security::Plain,
        Auth::Password {
            user: user.into(),
            pass: password(user),
        },
    )
    .await
    .expect("IMAP login for STATUS");
    let st = c.status("INBOX").await.expect("STATUS INBOX");
    let _ = c.logout().await;
    st
}

/// Wait until GreenMail has stored mail up to `uidnext` (so a "no push" check is meaningful).
async fn wait_delivered(user: &str, uidnext: u32) -> MailboxStatus {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let st = counters(user).await;
        if st.uidnext >= uidnext {
            return st;
        }
        assert!(
            Instant::now() < deadline,
            "GreenMail never stored the mail for {user}: {st:?}, want UIDNEXT ≥ {uidnext}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ---- the webhook receiver --------------------------------------------------------------

/// One request the receiver got.
#[derive(Debug)]
struct Delivery {
    method: Method,
    uri: String,
    headers: HeaderMap,
    body: String,
    at: Instant,
}

#[derive(Clone)]
struct HookState {
    tx: mpsc::UnboundedSender<Delivery>,
    /// When set, the *first* request is recorded immediately but answered only once this
    /// fires (or after 8 s), keeping the relay busy inside its push.
    hold: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
}

async fn record(
    State(st): State<HookState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let _ = st.tx.send(Delivery {
        method,
        uri: uri.to_string(),
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
        at: Instant::now(),
    });
    let hold = st.hold.lock().map(|mut h| h.take()).unwrap_or(None);
    if let Some(release) = hold {
        let _ = tokio::time::timeout(Duration::from_secs(8), release).await;
    }
    StatusCode::NO_CONTENT
}

/// A tiny HTTP server that records every request (any method, any path).
struct Hook {
    url: String,
    path_and_query: String,
    /// Capability token in the URL's query string: must never show up in relay output.
    cap: String,
    bearer: String,
    rx: mpsc::UnboundedReceiver<Delivery>,
    task: JoinHandle<()>,
}

impl Hook {
    async fn start(hold: Option<oneshot::Receiver<()>>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let state = HookState {
            tx,
            hold: Arc::new(Mutex::new(hold)),
        };
        let app = Router::new().fallback(record).with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind hook");
        let addr = listener.local_addr().expect("hook addr");
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let cap = format!("g16-cap-{}", nonce());
        let path_and_query = format!("/hook?cap={cap}");
        Self {
            url: format!("http://{addr}{path_and_query}"),
            path_and_query,
            cap,
            bearer: format!("g16-hook-bearer-{}", nonce()),
            rx,
            task,
        }
    }

    async fn next(&mut self, within: Duration) -> Option<Delivery> {
        tokio::time::timeout(within, self.rx.recv())
            .await
            .ok()
            .flatten()
    }
}

impl Drop for Hook {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Assert `d` is exactly one content-free push for registration `id`; returns the body.
fn assert_content_free(d: &Delivery, id: &str, hook: &Hook, forbidden: &[String]) -> Value {
    assert_eq!(d.method, Method::POST, "{d:?}");
    assert_eq!(
        d.uri, hook.path_and_query,
        "posted to the registered URL: {d:?}"
    );
    let header = |name: &str| d.headers.get(name).and_then(|v| v.to_str().ok());
    let expected_auth = format!("Bearer {}", hook.bearer);
    assert_eq!(header("authorization"), Some(expected_auth.as_str()));
    assert_eq!(header("content-type"), Some("application/json"));

    let v: Value = serde_json::from_str(&d.body).expect("push body is JSON");
    let obj = v.as_object().expect("push body is an object");
    let keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        BTreeSet::from(["event", "folder", "registration_id", "sent_at"]),
        "{v}"
    );
    assert!(
        obj.values().all(Value::is_string),
        "a push carries no numbers (no UID, count or size): {v}"
    );
    assert_eq!(v["registration_id"], id, "{v}");
    assert_eq!(v["event"], "new_mail", "{v}");
    assert_eq!(v["folder"], "INBOX", "{v}");
    let sent_at = v["sent_at"].as_str().expect("sent_at");
    assert!(sent_at.ends_with('Z'), "UTC: {sent_at}");
    let ts = chrono::DateTime::parse_from_rfc3339(sent_at).expect("sent_at is RFC 3339");
    let skew = (chrono::Utc::now() - ts.with_timezone(&chrono::Utc))
        .num_seconds()
        .abs();
    assert!(skew < 60, "sent_at {sent_at} is {skew} s off");

    // Byte level: remove the opaque id and the timestamp and nothing but the fixed skeleton
    // is left — in particular not a single digit, so no UID and no message count.
    let rest = d.body.replacen(id, "<id>", 1).replacen(sent_at, "<ts>", 1);
    assert_eq!(rest, PUSH_SKELETON, "raw push body: {}", d.body);
    assert!(!rest.chars().any(|c| c.is_ascii_digit()), "{rest}");

    for f in forbidden {
        assert!(
            !rest.contains(f.as_str()),
            "push body leaks {f:?}: {}",
            d.body
        );
        // `Authorization` was asserted to be exactly `Bearer <hook bearer>` above.
        for (name, value) in d.headers.iter().filter(|(n, _)| *n != "authorization") {
            let value = String::from_utf8_lossy(value.as_bytes());
            assert!(
                !value.contains(f.as_str()),
                "push header {name} leaks {f:?}: {value}"
            );
        }
    }
    v
}

// ---- the relay under test --------------------------------------------------------------

/// The parked TTL of the u77 relay (production: 24 h).
const PARKED_TTL: Duration = Duration::from_secs(5);

/// Production timing (1 s debounce, 25 min IDLE rounds) with quick reconnects.
fn test_worker() -> WorkerConfig {
    WorkerConfig {
        connect_timeout: Duration::from_secs(10),
        backoff_min: Duration::from_millis(200),
        backoff_max: Duration::from_secs(1),
        ..WorkerConfig::default()
    }
}

/// HTTP client for the relay API.
struct Api {
    base: String,
    token: String,
    http: reqwest::Client,
}

impl Api {
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (StatusCode, String) {
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().await.expect("relay request");
        let status = resp.status();
        (status, resp.text().await.expect("relay response body"))
    }

    async fn call_json(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let (st, text) = self.call(method, path, token, body).await;
        let v = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::String(text))
        };
        (st, v)
    }

    async fn register(&self, body: &Value) -> (StatusCode, Value) {
        self.call_json(
            reqwest::Method::POST,
            "/v1/push/register",
            Some(&self.token),
            Some(body),
        )
        .await
    }

    async fn status(&self, id: &str) -> (StatusCode, Value) {
        self.call_json(
            reqwest::Method::GET,
            &format!("/v1/push/status/{id}"),
            Some(&self.token),
            None,
        )
        .await
    }

    async fn unregister(&self, id: &str) -> StatusCode {
        self.call(
            reqwest::Method::DELETE,
            &format!("/v1/push/register/{id}"),
            Some(&self.token),
            None,
        )
        .await
        .0
    }

    async fn health(&self) -> Value {
        let (st, v) = self
            .call_json(reqwest::Method::GET, "/v1/health", None, None)
            .await;
        assert_eq!(st, StatusCode::OK, "{v}");
        v
    }

    /// Register and return the id (asserting `201` and the initial state).
    async fn register_ok(&self, body: &Value) -> String {
        let (st, v) = self.register(body).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        assert_eq!(v["state"], "connecting", "{v}");
        let id = v["registration_id"]
            .as_str()
            .expect("registration_id")
            .to_owned();
        assert_eq!(id.len(), 32, "{id}");
        id
    }

    /// Poll `GET status` until `state == want`; returns that status.
    async fn wait_for_state(&self, id: &str, want: &str, within: Duration) -> Value {
        let deadline = Instant::now() + within;
        loop {
            let (st, v) = self.status(id).await;
            assert_eq!(st, StatusCode::OK, "{v}");
            if v["state"] == want {
                return v;
            }
            assert!(
                Instant::now() < deadline,
                "registration never reached {want:?} within {within:?}: {v}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

/// The relay library served in-process on an ephemeral port, API token required.
struct Relay {
    api: Api,
    state: AppState,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<std::io::Result<()>>,
}

impl Relay {
    /// The gate's relay: GreenMail is on loopback and the receiver is plain http on loopback,
    /// so the development IMAP flag and both development webhook flags are on (explicitly; the
    /// production defaults refuse both).
    async fn start(worker: WorkerConfig) -> Self {
        Self::start_with(Options {
            imap_allow_private: true,
            webhook_allow_private: true,
            webhook_allow_http_private: true,
            worker,
            ..Options::default()
        })
        .await
    }

    /// A relay with `options` (and a fresh API token).
    async fn start_with(options: Options) -> Self {
        let token = format!("g16-api-token-{}", nonce());
        let state = AppState::new(Options {
            api_token: Some(Secret::new(token.clone())),
            ..options
        })
        .expect("relay state");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
        let base = format!("http://{}", listener.local_addr().expect("relay addr"));
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(sealbox_relay::serve(listener, state.clone(), async move {
            let _ = rx.await;
        }));
        Self {
            api: Api {
                base,
                token,
                http: reqwest::Client::new(),
            },
            state,
            stop: Some(tx),
            task,
        }
    }

    async fn finish(mut self) {
        self.state.shutdown().await;
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), &mut self.task).await;
    }
}

fn registration(user: &str, pass: &str, imap_port: u16, hook: &Hook) -> Value {
    json!({
        "imap": {"host": IMAP.0, "port": imap_port, "security": "plain"},
        "username": user,
        "password": pass,
        "transport": {"kind": "webhook", "url": hook.url, "bearer": hook.bearer},
    })
}

/// Strings that must never appear in a push or a status response for `user`.
fn mailbox_secrets(user: &str, hook: &Hook, api_token: &str) -> Vec<String> {
    vec![
        password(user),
        address(user),
        hook.bearer.clone(),
        hook.cap.clone(),
        api_token.to_owned(),
    ]
}

/// `GET status` must not reveal any of `secrets`; `id` itself is removed before checking
/// (an opaque random id could contain a short username by chance).
fn assert_status_clean(status: &Value, id: &str, secrets: &[String]) {
    let text = status.to_string().replace(id, "<id>");
    for s in secrets {
        assert!(!text.contains(s.as_str()), "status leaks {s:?}: {text}");
    }
}

// ---- G16 tests -------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn push_arrives_without_content_and_unregister_stops_it() {
    let user = "u76";
    let mut hook = Hook::start(None).await;
    let body = registration(user, &password(user), IMAP.1, &hook);

    // Without the development IMAP flag (GreenMail is on loopback), or without both development
    // webhook flags (plain http to loopback), the gate's own registration is refused before
    // anything is stored, and the reason names neither the URL nor the host.
    let hook_port = hook
        .url
        .rsplit_once(':')
        .and_then(|(_, rest)| rest.split('/').next())
        .expect("hook port")
        .to_owned();
    for (label, options, reason) in [
        (
            "production defaults",
            Options::default(),
            ImapRefusal::NonPublic.to_string(),
        ),
        (
            "both webhook flags, no IMAP flag",
            Options {
                webhook_allow_private: true,
                webhook_allow_http_private: true,
                ..Options::default()
            },
            ImapRefusal::NonPublic.to_string(),
        ),
        (
            "IMAP flag, no webhook flags",
            Options {
                imap_allow_private: true,
                ..Options::default()
            },
            Refusal::HttpsRequired.to_string(),
        ),
        (
            "IMAP flag, webhook_allow_private only",
            Options {
                imap_allow_private: true,
                webhook_allow_private: true,
                ..Options::default()
            },
            Refusal::HttpsRequired.to_string(),
        ),
        (
            "IMAP flag, webhook_allow_http_private only",
            Options {
                imap_allow_private: true,
                webhook_allow_http_private: true,
                ..Options::default()
            },
            Refusal::NonPublic.to_string(),
        ),
    ] {
        let strict = Relay::start_with(Options {
            worker: test_worker(),
            ..options
        })
        .await;
        let (st, v) = strict.api.register(&body).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{label}: {v}");
        assert_eq!(v["error"], reason, "{label}: {v}");
        let text = v.to_string();
        for never in [
            hook.url.as_str(),
            hook.path_and_query.as_str(),
            hook.cap.as_str(),
            hook.bearer.as_str(),
            IMAP.0,
            "3143",
            hook_port.as_str(),
        ] {
            assert!(
                !text.contains(never),
                "{label}: 400 echoes {never:?}: {text}"
            );
        }
        assert_eq!(strict.api.health().await["registrations"], 0, "{label}");
        strict.finish().await;
    }

    let relay = Relay::start(test_worker()).await;
    let api = &relay.api;
    let id = api.register_ok(&body).await;
    let idle = api
        .wait_for_state(&id, "idle", Duration::from_secs(20))
        .await;
    assert_eq!(idle["pushes"], 0, "{idle}");
    assert_eq!(idle["transport"], "webhook", "{idle}");
    // Mail already in the folder never pushes: the baseline is taken at registration.
    assert!(
        hook.next(Duration::from_millis(1500)).await.is_none(),
        "push without new mail"
    );

    let before = counters(user).await;
    let probe = Probe::new("push", user);
    let smtp = smtp();
    let sent = Instant::now();
    probe.send(&smtp).await;
    let submitted = sent.elapsed();
    let d = hook
        .next(Duration::from_secs(30))
        .await
        .expect("no push within 30 s of the mail");
    let after = counters(user).await;
    assert!(after.uidnext > before.uidnext, "the mail landed: {after:?}");
    eprintln!(
        "G16 push latency: {:?} from SMTP submit start ({submitted:?} to submit), \
         mailbox now {} messages / UIDNEXT {}",
        d.at.duration_since(sent),
        after.messages,
        after.uidnext
    );

    let mut forbidden = probe.content();
    forbidden.extend(mailbox_secrets(user, &hook, &api.token));
    forbidden.push(user.to_owned());
    assert_content_free(&d, &id, &hook, &forbidden);
    assert!(
        hook.next(Duration::from_secs(3)).await.is_none(),
        "more than one push for one mail"
    );

    let (st, status) = api.status(&id).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(status["state"], "idle", "{status}");
    assert_eq!(status["pushes"], 1, "{status}");
    assert_eq!(status["last_error"], Value::Null, "{status}");
    let last_push = status["last_push_at"].as_str().expect("last_push_at");
    chrono::DateTime::parse_from_rfc3339(last_push).expect("last_push_at is RFC 3339");
    assert_status_clean(&status, &id, &forbidden);

    // Unregister stops it: a mail that demonstrably lands afterwards produces no push.
    assert_eq!(api.unregister(&id).await, StatusCode::NO_CONTENT);
    let probe2 = Probe::new("after-unregister", user);
    let before2 = counters(user).await;
    probe2.send(&smtp).await;
    wait_delivered(user, before2.uidnext + 1).await;
    assert!(
        hook.next(Duration::from_secs(8)).await.is_none(),
        "push after unregister"
    );
    assert_eq!(api.status(&id).await.0, StatusCode::NOT_FOUND);
    assert_eq!(api.unregister(&id).await, StatusCode::NOT_FOUND);
    assert_eq!(api.health().await["registrations"], 0);
    relay.finish().await;
}

/// Registrations that could never log in are refused up front (400 naming the field, never the
/// value) instead of a worker retrying forever: an OAuth token for a host that is not its
/// provider's own mail host (GreenMail on loopback — `sealbox-mail` presents a bearer only to
/// Google's / Microsoft's hosts, THREAT_MODEL R14), and a password or token with a control
/// character (CR/LF/NUL can never be sent as an IMAP string or SASL response). The parked
/// paths behind them (`xoauth2_not_offered`, `oauth_host_refused`) are proven by the worker's
/// unit tests against a scripted server.
#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn oauth_to_a_non_provider_host_and_control_characters_are_refused() {
    let user = "u77"; // shared with the API test on purpose: no mail is ever sent to u77
    let relay = Relay::start(test_worker()).await;
    let api = &relay.api;
    let hook = Hook::start(None).await;
    let cases = [
        (
            "oauth_token",
            format!("ya29.g16-token-{}", nonce()),
            "provider's own IMAP host",
        ),
        (
            "password",
            format!("g16-ctl-{}\r\nx", nonce()),
            "password contains control",
        ),
        (
            "oauth_token",
            format!("ya29.g16-ctl-{}\u{0}x", nonce()),
            "oauth_token contains control",
        ),
    ];
    for (field, value, needle) in &cases {
        let mut bad = registration(user, "unused", IMAP.1, &hook);
        bad.as_object_mut().expect("obj").remove("password");
        bad[*field] = json!(value);
        let (st, v) = api.register(&bad).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{field} -> {v}");
        let err = v["error"].as_str().expect("error string");
        assert!(err.contains(needle), "{field} -> {err}");
        let text = v.to_string();
        assert!(!text.contains("g16-"), "400 echoes the value: {text}");
        assert!(!text.contains(IMAP.0), "400 echoes the host: {text}");
    }
    assert_eq!(api.health().await["registrations"], 0);
    eprintln!(
        "G16 refused up front: {} registrations that could never log in",
        cases.len()
    );
    relay.finish().await;
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn api_requires_the_token_and_never_echoes_secrets() {
    use reqwest::Method as M;
    let user = "u77";
    // A short parked TTL, so the gate also sees a parked registration evict itself.
    let relay = Relay::start(WorkerConfig {
        parked_ttl: PARKED_TTL,
        ..test_worker()
    })
    .await;
    let api = &relay.api;
    let hook = Hook::start(None).await;
    let wrong_password = format!("g16-wrong-password-{}", nonce());
    let body = registration(user, &wrong_password, IMAP.1, &hook);

    // Health is open.
    let health = api.health().await;
    assert_eq!(health["status"], "ok", "{health}");
    assert_eq!(health["registrations"], 0, "{health}");

    // Every push route needs the exact token.
    let unknown = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let wrong_token = format!("{}x", api.token);
    for token in [None, Some(wrong_token.as_str()), Some("")] {
        let (st, v) = api
            .call_json(M::POST, "/v1/push/register", token, Some(&body))
            .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{token:?}: {v}");
        assert_eq!(v["error"], "unauthorized", "{v}");
        let path = format!("/v1/push/status/{unknown}");
        let (st, _) = api.call(M::GET, &path, token, None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{token:?}");
        let path = format!("/v1/push/register/{unknown}");
        let (st, _) = api.call(M::DELETE, &path, token, None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{token:?}");
    }
    // A non-Bearer scheme carrying the right secret is still refused.
    let resp = api
        .http
        .post(format!("{}/v1/push/register", api.base))
        .header("authorization", format!("Basic {}", api.token))
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(api.health().await["registrations"], 0);
    // With the token: unknown ids are 404, not 401.
    assert_eq!(api.status(unknown).await.0, StatusCode::NOT_FOUND);
    assert_eq!(api.unregister(unknown).await, StatusCode::NOT_FOUND);

    // A password GreenMail rejects: accepted by the API (checked asynchronously). Through a
    // loopback proxy that counts IMAP connections: the worker tries exactly three logins, then
    // parks the registration in `error` with the fixed credentials-rejected text, and never
    // connects again (providers lock accounts that keep failing logins).
    let proxy = Proxy::start(IMAP).await;
    let id = api
        .register_ok(&registration(user, &wrong_password, proxy.port, &hook))
        .await;
    let mut secrets = mailbox_secrets(user, &hook, &api.token);
    secrets.push(wrong_password.clone());
    let started = Instant::now();
    let mut retrying_seen = None;
    let parked = loop {
        let (st, v) = api.status(&id).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        assert_status_clean(&v, &id, &secrets);
        let err = v["last_error"].as_str().unwrap_or_default().to_owned();
        if v["state"] == "parked" {
            break v;
        }
        if v["state"] == "error" {
            // An attempt before the third one: sealbox-mail's typed `LoginRejected` with the
            // server's (redacted) answer.
            assert!(err.contains("rejected (LOGIN): NO"), "{err}");
            retrying_seen.get_or_insert(err);
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the rejected login was never parked: {v}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let attempts = proxy.accepted();
    eprintln!(
        "G16 rejected login: parked after {attempts} IMAP connections in {:?}; last_error \
         before parking: {retrying_seen:?}",
        started.elapsed()
    );
    assert_eq!(attempts, 3, "exactly three login attempts");
    let parked_seen = Instant::now();
    assert_eq!(parked["parked_reason"], "credentials_rejected", "{parked}");
    assert_eq!(parked["last_error"], CREDENTIALS_REJECTED, "{parked}");
    assert_eq!(parked["pushes"], 0, "{parked}");
    let text = parked.to_string().replace(&id, "<id>");
    for never in [user, IMAP.0, proxy.port.to_string().as_str()] {
        assert!(
            !text.contains(never),
            "parked status echoes {never:?}: {text}"
        );
    }
    // Three times the longest backoff later (`test_worker`: 1 s): no fourth connection.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        proxy.accepted(),
        3,
        "the worker kept logging in after parking"
    );
    let (_, again) = api.status(&id).await;
    assert_eq!(again["state"], "parked", "{again}");
    assert_eq!(again["parked_reason"], "credentials_rejected", "{again}");
    assert_eq!(again["last_error"], CREDENTIALS_REJECTED, "{again}");
    assert_status_clean(&again, &id, &secrets);
    // The parked TTL runs out: the registration evicts itself (404, slot freed), still
    // without another login.
    let evicted = loop {
        let (st, v) = api.status(&id).await;
        if st == StatusCode::NOT_FOUND {
            break parked_seen.elapsed();
        }
        assert_eq!(v["state"], "parked", "{v}");
        assert!(
            parked_seen.elapsed() < PARKED_TTL + Duration::from_secs(5),
            "the parked registration was never evicted: {v}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    eprintln!("G16 parked registration evicted {evicted:?} after parking (TTL {PARKED_TTL:?})");
    assert!(
        evicted >= PARKED_TTL - Duration::from_millis(100),
        "{evicted:?}"
    );
    assert_eq!(api.health().await["registrations"], 0);
    assert_eq!(api.unregister(&id).await, StatusCode::NOT_FOUND);
    assert_eq!(proxy.accepted(), 3);

    // Unknown fields (top level, nested) and wrong types: 400, values never echoed.
    let leak = format!("g16-must-not-echo-{}", nonce());
    let mut cases: Vec<(Value, &str)> = Vec::new();
    let mut b = body.clone();
    b["subject"] = json!(leak);
    cases.push((b, "unknown field"));
    let mut b = body.clone();
    b["imap"]["tls_insecure"] = json!(leak);
    cases.push((b, "unknown field"));
    let mut b = body.clone();
    b["transport"]["headers"] = json!({ "x": leak });
    cases.push((b, "unknown field"));
    let mut b = body.clone();
    b["imap"]["port"] = json!(leak);
    cases.push((b, "wrong type"));
    let mut b = body.clone();
    b["password"] = json!(12345);
    cases.push((b, "wrong type"));
    let mut b = body.clone();
    b["oauth_token"] = json!(leak);
    cases.push((b, "not both"));
    let mut b = body.clone();
    b["transport"]["kind"] = json!(leak);
    cases.push((b, "unknown variant"));
    // Plain IMAP (credentials in clear) only to a host that is local by its literal form.
    let mut b = body.clone();
    b["imap"]["host"] = json!(format!("imap.{leak}.example.com"));
    cases.push((b, "imap.security \"plain\""));
    for (case, needle) in cases {
        let (st, v) = api.register(&case).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{case} -> {v}");
        let text = v.to_string();
        let err = v["error"].as_str().expect("error string");
        assert!(err.contains(needle), "{case} -> {err}");
        assert!(!text.contains(&leak), "400 echoes the value: {text}");
        assert!(
            !text.contains(&wrong_password),
            "400 echoes the password: {text}"
        );
    }
    assert_eq!(api.health().await["registrations"], 0);
    relay.finish().await;
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn burst_is_debounced() {
    let user = "u78";
    let relay = Relay::start(test_worker()).await;
    let api = &relay.api;
    let mut hook = Hook::start(None).await;
    let id = api
        .register_ok(&registration(user, &password(user), IMAP.1, &hook))
        .await;
    api.wait_for_state(&id, "idle", Duration::from_secs(20))
        .await;

    let probes: Vec<Probe> = (1..=3)
        .map(|i| Probe::new(&format!("burst-{i}"), user))
        .collect();
    let before = counters(user).await;
    let smtp = smtp();
    let started = Instant::now();
    // Concurrent submits (one SMTP connection each): a burst, not three spaced-out mails.
    tokio::join!(
        probes[0].send(&smtp),
        probes[1].send(&smtp),
        probes[2].send(&smtp)
    );
    let spread = started.elapsed();
    let first = hook
        .next(Duration::from_secs(30))
        .await
        .expect("the burst produced no push");
    wait_delivered(user, before.uidnext + 3).await;
    let mut pushes = vec![first];
    while let Some(d) = hook.next(Duration::from_secs(4)).await {
        pushes.push(d);
    }
    let n = pushes.len();
    eprintln!(
        "G16 burst: 3 mails submitted within {spread:?} -> {n} push(es); first push {:?} after \
         the first submit started",
        pushes[0].at.duration_since(started)
    );
    assert!((1..=3).contains(&n), "{n} pushes for 3 mails");
    let mut forbidden: Vec<String> = probes.iter().flat_map(Probe::content).collect();
    forbidden.extend(mailbox_secrets(user, &hook, &api.token));
    for d in &pushes {
        assert_content_free(d, &id, &hook, &forbidden);
    }
    // Debounce: after the first wake-up (which comes no earlier than the first delivery, so no
    // earlier than `started`) the worker keeps idling for `debounce` (1 s, ending at most
    // 50 ms early) and only then re-`EXAMINE`s once. GreenMail stores a message before it
    // answers the SMTP DATA, so if every submit returned within 900 ms of `started`, all
    // three landed before that single re-check: exactly one push.
    if spread < Duration::from_millis(900) {
        assert_eq!(n, 1, "burst within {spread:?} was not debounced");
    }
    let (_, status) = api.status(&id).await;
    assert_eq!(status["pushes"], n as u64, "{status}");
    relay.finish().await;
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn mail_landing_during_a_push_is_not_missed() {
    let user = "u79";
    let relay = Relay::start(test_worker()).await;
    let api = &relay.api;
    let (release, held) = oneshot::channel();
    let mut hook = Hook::start(Some(held)).await;
    let id = api
        .register_ok(&registration(user, &password(user), IMAP.1, &hook))
        .await;
    api.wait_for_state(&id, "idle", Duration::from_secs(20))
        .await;

    let first = Probe::new("inflight-a", user);
    let second = Probe::new("inflight-b", user);
    let before = counters(user).await;
    let smtp = smtp();
    first.send(&smtp).await;
    let d1 = hook
        .next(Duration::from_secs(30))
        .await
        .expect("first push");
    // The relay is now inside its push (our hook has not answered): it is not in IDLE. A mail
    // that lands now is announced by GreenMail *before* the next IDLE continuation.
    second.send(&smtp).await;
    wait_delivered(user, before.uidnext + 2).await;
    let released = Instant::now();
    release.send(()).expect("release the held push");
    let d2 = hook.next(Duration::from_secs(15)).await.expect(
        "no push for the mail that landed while the first push was in flight: the relay \
         slept through the EXISTS sent before the IDLE continuation",
    );
    eprintln!(
        "G16 in-flight race: second push {:?} after the first push was answered",
        d2.at.duration_since(released)
    );
    let mut forbidden: Vec<String> = first.content();
    forbidden.extend(second.content());
    forbidden.extend(mailbox_secrets(user, &hook, &api.token));
    assert_content_free(&d1, &id, &hook, &forbidden);
    assert_content_free(&d2, &id, &hook, &forbidden);
    assert!(
        hook.next(Duration::from_secs(3)).await.is_none(),
        "a third push for two mails"
    );
    let (_, status) = api.status(&id).await;
    assert_eq!(status["pushes"], 2, "{status}");
    assert_eq!(status["state"], "idle", "{status}");
    relay.finish().await;
}

/// A loopback TCP proxy in front of GreenMail's IMAP port that can drop every live
/// connection (`cut`) and refuse new ones (`pause`), to simulate a network outage.
struct Proxy {
    port: u16,
    paused: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
    conns: Arc<Mutex<Vec<JoinHandle<()>>>>,
    task: JoinHandle<()>,
}

impl Proxy {
    async fn start(upstream: (&'static str, u16)) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let port = listener.local_addr().expect("proxy addr").port();
        let paused = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicUsize::new(0));
        let conns: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let task = tokio::spawn({
            let (paused, accepted, conns) = (paused.clone(), accepted.clone(), conns.clone());
            async move {
                while let Ok((mut inbound, _)) = listener.accept().await {
                    if paused.load(Ordering::SeqCst) {
                        drop(inbound);
                        continue;
                    }
                    accepted.fetch_add(1, Ordering::SeqCst);
                    let pipe = tokio::spawn(async move {
                        if let Ok(mut outbound) = TcpStream::connect(upstream).await {
                            let _ =
                                tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                        }
                    });
                    if let Ok(mut c) = conns.lock() {
                        c.push(pipe);
                    }
                }
            }
        });
        Self {
            port,
            paused,
            accepted,
            conns,
            task,
        }
    }

    fn cut(&self) {
        if let Ok(mut c) = self.conns.lock() {
            for pipe in c.drain(..) {
                pipe.abort();
            }
        }
    }

    fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
        self.cut();
    }
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn reconnect_pushes_mail_that_arrived_while_disconnected() {
    let user = "u80";
    let proxy = Proxy::start(IMAP).await;
    let relay = Relay::start(test_worker()).await;
    let api = &relay.api;
    let mut hook = Hook::start(None).await;
    let id = api
        .register_ok(&registration(user, &password(user), proxy.port, &hook))
        .await;
    api.wait_for_state(&id, "idle", Duration::from_secs(20))
        .await;
    let mut secrets = mailbox_secrets(user, &hook, &api.token);

    // Outage: the live IDLE session is dropped and reconnects are refused.
    proxy.set_paused(true);
    proxy.cut();
    let down = api
        .wait_for_state(&id, "error", Duration::from_secs(15))
        .await;
    eprintln!("G16 outage last_error: {}", down["last_error"]);
    assert_status_clean(&down, &id, &secrets);

    // Mail arrives while the relay cannot see the mailbox.
    let probe = Probe::new("outage", user);
    let before = counters(user).await;
    probe.send(&smtp()).await;
    wait_delivered(user, before.uidnext + 1).await;
    assert!(
        hook.next(Duration::from_millis(500)).await.is_none(),
        "push while disconnected?"
    );

    // Back online: the new session's EXAMINE is compared with the last watermark.
    let restored = Instant::now();
    proxy.set_paused(false);
    let d = hook
        .next(Duration::from_secs(15))
        .await
        .expect("no push after reconnecting for the mail that arrived during the outage");
    eprintln!(
        "G16 reconnect: push {:?} after the outage ended",
        d.at.duration_since(restored)
    );
    secrets.extend(probe.content());
    assert_content_free(&d, &id, &hook, &secrets);
    let up = api
        .wait_for_state(&id, "idle", Duration::from_secs(10))
        .await;
    assert_eq!(up["pushes"], 1, "{up}");
    assert_eq!(up["last_error"], Value::Null, "{up}");

    // A reconnect with no new mail pushes nothing.
    let sessions = proxy.accepted();
    proxy.cut();
    let deadline = Instant::now() + Duration::from_secs(15);
    while proxy.accepted() == sessions {
        assert!(Instant::now() < deadline, "the relay never reconnected");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    api.wait_for_state(&id, "idle", Duration::from_secs(10))
        .await;
    assert!(
        hook.next(Duration::from_secs(3)).await.is_none(),
        "a reconnect without new mail produced a push"
    );
    let (_, status) = api.status(&id).await;
    assert_eq!(status["pushes"], 1, "{status}");
    relay.finish().await;
}

/// Read a child pipe to the end on its own task, so a full pipe can never block the relay.
fn drain<R: tokio::io::AsyncRead + Unpin + Send + 'static>(pipe: Option<R>) -> JoinHandle<String> {
    tokio::spawn(async move {
        let mut out = String::new();
        if let Some(mut p) = pipe {
            let _ = p.read_to_string(&mut out).await;
        }
        out
    })
}

#[tokio::test]
#[ignore = "needs the GreenMail docker server (testing/mail_up.sh)"]
async fn relay_binary_runs_as_its_own_process() {
    let user = "u77";
    let token = format!("g16-process-token-{}", nonce());
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_sealbox-relay"))
        // Port 0: the kernel picks a free port and the relay logs it (no reserve-then-bind race).
        .arg("--bind")
        .arg("127.0.0.1:0")
        .arg("--log-level")
        .arg("info")
        // GreenMail and the receiver (plain http) are on loopback: the development flags.
        .arg("--imap-allow-private")
        .arg("--webhook-allow-private")
        .arg("--webhook-allow-http-private")
        // From the environment, so the token is not on the command line (`ps`).
        .env("SEALBOX_RELAY_API_TOKEN", &token)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn the sealbox-relay binary");
    let pid = child.id().expect("child pid");
    let stderr = drain(child.stderr.take());
    let mut stdout = tokio::io::BufReader::new(child.stdout.take().expect("relay stdout")).lines();
    let mut head = String::new();
    let addr = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(line) = stdout.next_line().await.expect("read relay stdout") {
            head.push_str(&line);
            head.push('\n');
            if line.contains("sealbox-relay listening") {
                return line
                    .split_whitespace()
                    .find_map(|w| w.strip_prefix("addr="))
                    .map(str::to_owned);
            }
        }
        None
    })
    .await
    .expect("the relay did not log its listening address within 20 s")
    .unwrap_or_else(|| panic!("no addr= in the relay's startup log:\n{head}"));
    let rest = tokio::spawn(async move {
        let mut out = String::new();
        while let Ok(Some(line)) = stdout.next_line().await {
            out.push_str(&line);
            out.push('\n');
        }
        out
    });
    let api = Api {
        base: format!("http://{addr}"),
        token: token.clone(),
        http: reqwest::Client::new(),
    };
    let health = api.health().await;
    assert_eq!(health["status"], "ok", "{health}");

    let mut hook = Hook::start(None).await;
    let body = registration(user, &password(user), IMAP.1, &hook);
    let (st, _) = api
        .call(
            reqwest::Method::POST,
            "/v1/push/register",
            None,
            Some(&body),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "the env token is enforced");
    let id = api.register_ok(&body).await;
    api.wait_for_state(&id, "idle", Duration::from_secs(20))
        .await;
    let probe = Probe::new("process", user);
    let sent = Instant::now();
    probe.send(&smtp()).await;
    let d = hook
        .next(Duration::from_secs(30))
        .await
        .expect("no push from the relay process");
    eprintln!(
        "G16 process push latency: {:?} from SMTP submit start",
        d.at.duration_since(sent)
    );
    let mut forbidden = probe.content();
    forbidden.extend(mailbox_secrets(user, &hook, &token));
    forbidden.push(user.to_owned());
    assert_content_free(&d, &id, &hook, &forbidden);

    // SIGTERM to our own child, identity checked first (never signal a recycled pid).
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).expect("child comm");
    assert_eq!(comm.trim(), "sealbox-relay", "pid {pid} is not our relay");
    let killed = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("run kill");
    assert!(killed.success());
    let exit = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .expect("the relay did not exit within 20 s of SIGTERM")
        .expect("wait for the relay");
    assert!(exit.success(), "relay exit status: {exit:?}");
    let log = format!(
        "{head}{}{}",
        rest.await.unwrap_or_default(),
        stderr.await.unwrap_or_default()
    );
    for line in [
        "sealbox-relay listening",
        "idle session established",
        "push sent",
        "shutdown requested",
        "worker stopped",
        "sealbox-relay stopped",
    ] {
        assert!(log.contains(line), "relay log lacks {line:?}:\n{log}");
    }
    let log = log.replace(&id, "<id>");
    for f in &forbidden {
        assert!(!log.contains(f.as_str()), "relay log leaks {f:?}:\n{log}");
    }
}
