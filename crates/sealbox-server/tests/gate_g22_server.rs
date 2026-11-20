//! Gate G22 (server half) — hosted mailbox provisioning against an in-process mock of the
//! three Stalwart management calls we use (`x:Domain/get`, `x:Account/query`, `x:Account/set`),
//! covering name validation, reserved names, reservations/conflicts, daily caps, invite codes,
//! the response shape, rollback when Stalwart fails, and 404 when nothing is configured.
//!
//! `real_stalwart_provisions_a_working_mailbox` (ignored) runs the same service against the
//! docker Stalwart from `testing/stalwart_up.sh` and logs in over IMAP with the returned
//! password; `scripts/gate_g22.sh` runs it.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use sealbox_server::{
    hosted::{stalwart::StalwartClient, EndpointInfo, HostedConfig, HostedService, SignupMode},
    mail::MemoryMailSink,
    AppState, Limits, StateOptions,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, sync::oneshot};

const DOMAIN: &str = "hosted.test";
const ADMIN: &str = "admin";
const SECRET: &str = "mock-admin-secret";

// ------------------------------------------------------------------------------------------
// Mock Stalwart
// ------------------------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    /// name -> plaintext secret it was created with
    accounts: HashMap<String, String>,
    /// Fail the next `x:Account/set` create with HTTP 500.
    fail_next_create: bool,
    calls: Vec<String>,
}

type Mock = Arc<Mutex<MockState>>;

async fn mock_jmap(
    State(st): State<Mock>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    let expected = format!("Basic {}", STANDARD.encode(format!("{ADMIN}:{SECRET}")));
    if headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v != expected)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        );
    }
    let using = body["using"].as_array().cloned().unwrap_or_default();
    assert!(
        using.iter().any(|u| u == "urn:stalwart:jmap"),
        "management calls must use urn:stalwart:jmap"
    );
    let call = &body["methodCalls"][0];
    let method = call[0].as_str().unwrap_or_default().to_owned();
    let args = call[1].clone();
    let mut st = st.lock().unwrap();
    st.calls.push(method.clone());
    let resp = match method.as_str() {
        "x:Domain/get" => json!({
            "list": [{"id": "b", "name": DOMAIN, "enable": true}, {"id": "c", "name": "other.test"}],
            "notFound": []
        }),
        "x:Account/query" => {
            let name = args["filter"]["name"].as_str().unwrap_or_default();
            let ids: Vec<String> = if st.accounts.contains_key(name) {
                vec![format!("id-{name}")]
            } else {
                vec![]
            };
            json!({"ids": ids, "position": 0})
        }
        "x:Account/set" => {
            if let Some(create) = args.get("create").and_then(Value::as_object) {
                if st.fail_next_create {
                    st.fail_next_create = false;
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "simulated outage"})),
                    );
                }
                let mut created = serde_json::Map::new();
                let mut not_created = serde_json::Map::new();
                for (cid, obj) in create {
                    assert_eq!(obj["@type"], "User");
                    assert_eq!(obj["domainId"], "b", "must use the hosted domain's id");
                    assert_eq!(obj["roles"]["@type"], "User");
                    assert_eq!(obj["credentials"]["0"]["@type"], "Password");
                    let name = obj["name"].as_str().unwrap().to_owned();
                    let secret = obj["credentials"]["0"]["secret"]
                        .as_str()
                        .unwrap()
                        .to_owned();
                    if st.accounts.contains_key(&name) {
                        not_created.insert(
                            cid.clone(),
                            json!({"type": "primaryKeyViolation", "properties": ["email"]}),
                        );
                    } else {
                        st.accounts.insert(name.clone(), secret);
                        created.insert(cid.clone(), json!({"id": format!("id-{name}")}));
                    }
                }
                let mut r = json!({});
                if !created.is_empty() {
                    r["created"] = Value::Object(created);
                }
                if !not_created.is_empty() {
                    r["notCreated"] = Value::Object(not_created);
                }
                r
            } else if let Some(destroy) = args.get("destroy").and_then(Value::as_array) {
                for id in destroy {
                    let id = id.as_str().unwrap_or_default();
                    let name = id.trim_start_matches("id-").to_owned();
                    st.accounts.remove(&name);
                }
                json!({"destroyed": destroy})
            } else {
                json!({})
            }
        }
        other => {
            return (
                StatusCode::OK,
                Json(
                    json!({"methodResponses": [["error", {"type": "unknownMethod", "description": other}, "c0"]]}),
                ),
            )
        }
    };
    (
        StatusCode::OK,
        Json(json!({"methodResponses": [[method, resp, "c0"]], "sessionState": "s"})),
    )
}

async fn start_mock() -> (String, Mock, oneshot::Sender<()>) {
    let st: Mock = Arc::new(Mutex::new(MockState::default()));
    let app = Router::new()
        .route("/jmap", post(mock_jmap))
        .with_state(st.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    (format!("http://{addr}"), st, tx)
}

// ------------------------------------------------------------------------------------------
// Sealbox server under test
// ------------------------------------------------------------------------------------------

fn hosted_config(signups: SignupMode) -> HostedConfig {
    HostedConfig {
        domain: DOMAIN.into(),
        imap: EndpointInfo {
            host: "imap.hosted.test".into(),
            port: 993,
            security: "tls".into(),
        },
        smtp: EndpointInfo {
            host: "smtp.hosted.test".into(),
            port: 587,
            security: "starttls".into(),
        },
        signups,
        invites: vec!["beta-1".into(), "beta-2".into()],
        per_ip_daily: 50,
        global_daily: 500,
        attempts_per_hour: 1000,
        availability_per_hour: 1000,
        ip_hash_key: "test-key".into(),
        stalwart_timeout: Duration::from_secs(5),
    }
}

struct Srv {
    base: String,
    http: reqwest::Client,
    db_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl Srv {
    async fn start(hosted: Option<(HostedConfig, &str)>) -> Self {
        let dir = tempfile::Builder::new().prefix("g22-").tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let db_path = dir.path().join("srv.sqlite");
        let state = AppState::new(StateOptions {
            db_path: db_path.clone(),
            public_url: base.clone(),
            static_dir: dir.path().to_path_buf(),
            mailer: MemoryMailSink::new(),
            trust_proxy: false,
            limits: Limits::default(),
        })
        .unwrap();
        if let Some((cfg, stalwart_url)) = hosted {
            let client =
                StalwartClient::new(stalwart_url, ADMIN, SECRET, Duration::from_secs(5)).unwrap();
            let svc = HostedService::new(cfg, client);
            svc.ensure_schema(state.db()).await.unwrap();
            assert!(state.set_hosted(svc));
        }
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(sealbox_server::serve(listener, state, async move {
            let _ = rx.await;
        }));
        Self {
            base,
            http: reqwest::Client::new(),
            db_path,
            _dir: dir,
            shutdown: Some(tx),
            task: Some(task),
        }
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        let r = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .unwrap();
        let s = r.status().as_u16();
        (s, r.json().await.unwrap_or(Value::Null))
    }

    async fn signup(&self, body: Value) -> (u16, Value) {
        let r = self
            .http
            .post(format!("{}/v1/hosted/signup", self.base))
            .json(&body)
            .send()
            .await
            .unwrap();
        let s = r.status().as_u16();
        (s, r.json().await.unwrap_or(Value::Null))
    }

    async fn stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
        }
    }
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

// ------------------------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn info_and_availability() {
    let (mock_url, _mock, _m) = start_mock().await;
    let mut srv = Srv::start(Some((hosted_config(SignupMode::Open), &mock_url))).await;

    let (s, info) = srv.get("/v1/hosted/info").await;
    assert_eq!(s, 200, "{info}");
    assert_eq!(info["domain"], DOMAIN);
    assert_eq!(info["signups"], "open");
    assert_eq!(info["invite_required"], false);
    assert_eq!(info["requirements"]["min_length"], 3);
    assert_eq!(info["requirements"]["max_length"], 32);
    assert!(info["requirements"]["reserved"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "postmaster"));
    assert_eq!(info["imap"]["host"], "imap.hosted.test");
    assert_eq!(info["imap"]["port"], 993);
    assert_eq!(info["imap"]["security"], "tls");
    assert_eq!(info["smtp"]["port"], 587);

    let (s, av) = srv.get("/v1/hosted/availability?local_part=Alice").await;
    assert_eq!(s, 200);
    assert_eq!(av["available"], true, "{av}");
    assert_eq!(av["local_part"], "alice");
    assert_eq!(av["email"], "alice@hosted.test");
    assert!(av["reason"].is_null());

    for (name, reason) in [
        ("admin", "reserved"),
        ("sealbox-team", "reserved"),
        ("ab", "too_short"),
        ("a%20b", "invalid_characters"),
        (".alice", "invalid_shape"),
    ] {
        let (s, av) = srv
            .get(&format!("/v1/hosted/availability?local_part={name}"))
            .await;
        assert_eq!(s, 200);
        assert_eq!(av["available"], false, "{name}: {av}");
        assert_eq!(av["reason"], reason, "{name}: {av}");
        assert!(av["message"].as_str().is_some_and(|m| !m.is_empty()));
    }
    let (s, _) = srv.get("/v1/hosted/availability").await;
    assert_eq!(s, 400, "missing local_part is a bad request");
    srv.stop().await;
}

#[tokio::test]
async fn signup_shape_reservation_and_no_plaintext_password_at_rest() {
    let (mock_url, mock, _m) = start_mock().await;
    let mut srv = Srv::start(Some((hosted_config(SignupMode::Open), &mock_url))).await;

    let (s, body) = srv
        .signup(json!({"local_part": "Carol.Test", "recovery_email": "carol@example.org"}))
        .await;
    assert_eq!(s, 201, "{body}");
    assert_eq!(body["email"], "carol.test@hosted.test");
    assert_eq!(body["login"], "carol.test@hosted.test");
    assert_eq!(body["domain"], DOMAIN);
    let pw = body["password"].as_str().unwrap().to_owned();
    assert_eq!(pw.len(), 24);
    assert!(pw.bytes().all(|b| b.is_ascii_alphanumeric()));
    assert_eq!(body["imap"]["host"], "imap.hosted.test");
    assert_eq!(body["imap"]["port"], 993);
    assert_eq!(body["imap"]["security"], "tls");
    assert_eq!(body["smtp"]["host"], "smtp.hosted.test");
    assert_eq!(body["smtp"]["security"], "starttls");
    assert!(body["created_at"].as_i64().unwrap() > 1_700_000_000);
    // Stalwart received exactly that password for exactly that name.
    assert_eq!(
        mock.lock()
            .unwrap()
            .accounts
            .get("carol.test")
            .map(String::as_str),
        Some(pw.as_str())
    );

    // Now taken: availability says so, and a second signup conflicts (409) before Stalwart.
    let (_, av) = srv
        .get("/v1/hosted/availability?local_part=carol.test")
        .await;
    assert_eq!(av["available"], false);
    assert_eq!(av["reason"], "taken");
    let calls_before = mock.lock().unwrap().calls.len();
    let (s, err) = srv.signup(json!({"local_part": "CAROL.TEST"})).await;
    assert_eq!(s, 409, "{err}");
    assert_eq!(
        mock.lock().unwrap().calls.len(),
        calls_before,
        "no Stalwart call on a known conflict"
    );

    // A name that exists on Stalwart but not in our table is also refused (409 from Stalwart).
    mock.lock()
        .unwrap()
        .accounts
        .insert("legacy".into(), "x".into());
    let (s, err) = srv.signup(json!({"local_part": "legacy"})).await;
    assert_eq!(s, 409, "{err}");
    let (_, av) = srv.get("/v1/hosted/availability?local_part=legacy").await;
    assert_eq!(av["available"], false);
    // ... and the failed reservation was released (the name can be retried later).
    let (s, _) = srv.signup(json!({"local_part": "legacy"})).await;
    assert_eq!(s, 409);

    // At rest: only the SHA-256 of the password, never the password; IP stored as a hash.
    srv.stop().await;
    let conn = rusqlite::Connection::open(&srv.db_path).unwrap();
    let (email, hash, ip_hash, rec): (String, String, String, Option<String>) = conn
        .query_row(
            "SELECT email, password_sha256, ip_hash, recovery_email_sha256 FROM hosted_signups WHERE local_part = 'carol.test'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(email, "carol.test@hosted.test");
    assert_eq!(hash, sha256_hex(&pw));
    assert_eq!(ip_hash.len(), 64);
    assert_ne!(ip_hash, "127.0.0.1");
    assert_eq!(
        rec.as_deref(),
        Some(sha256_hex("carol@example.org").as_str())
    );
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM hosted_signups WHERE local_part = 'legacy'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0, "failed provisioning must not leave a reservation");
    drop(conn);
    let raw = std::fs::read(&srv.db_path).unwrap();
    assert!(
        !raw.windows(pw.len()).any(|w| w == pw.as_bytes()),
        "plaintext password found in the database file"
    );
}

#[tokio::test]
async fn validation_rejects_bad_and_reserved_names() {
    let (mock_url, mock, _m) = start_mock().await;
    let mut srv = Srv::start(Some((hosted_config(SignupMode::Open), &mock_url))).await;
    for (name, needle) in [
        ("postmaster", "reserved"),
        ("Root", "reserved"),
        ("sealboxsupport", "reserved"),
        ("ab", "at least 3"),
        ("a b", "may only contain"),
        ("alice@x", "may only contain"),
        ("-alice", "start and end"),
        ("al..ice", "start and end"),
    ] {
        let (s, err) = srv.signup(json!({"local_part": name})).await;
        assert_eq!(s, 400, "{name}: {err}");
        assert!(
            err["error"].as_str().unwrap().contains(needle),
            "{name}: {err}"
        );
    }
    let long = "a".repeat(300);
    let (s, _) = srv.signup(json!({"local_part": long})).await;
    assert_eq!(s, 400);
    let (s, _) = srv.signup(json!({"nope": 1})).await;
    assert_eq!(s, 400, "missing local_part");
    let (s, _) = srv
        .signup(json!({"local_part": "fine", "recovery_email": "not-an-address"}))
        .await;
    assert_eq!(s, 400);
    assert!(
        mock.lock().unwrap().accounts.is_empty(),
        "nothing may reach Stalwart when validation fails"
    );
    srv.stop().await;
}

#[tokio::test]
async fn invite_and_closed_modes() {
    let (mock_url, _mock, _m) = start_mock().await;
    let mut srv = Srv::start(Some((hosted_config(SignupMode::Invite), &mock_url))).await;
    let (_, info) = srv.get("/v1/hosted/info").await;
    assert_eq!(info["signups"], "invite");
    assert_eq!(info["invite_required"], true);
    let (s, err) = srv.signup(json!({"local_part": "dave"})).await;
    assert_eq!(s, 400);
    assert!(err["error"]
        .as_str()
        .unwrap()
        .contains("invite code is required"));
    let (s, err) = srv
        .signup(json!({"local_part": "dave", "invite_code": "wrong"}))
        .await;
    assert_eq!(s, 400);
    assert!(err["error"]
        .as_str()
        .unwrap()
        .contains("invalid invite code"));
    let (s, ok) = srv
        .signup(json!({"local_part": "dave", "invite_code": " beta-2 "}))
        .await;
    assert_eq!(s, 201, "{ok}");
    assert_eq!(ok["email"], "dave@hosted.test");
    srv.stop().await;

    let mut srv = Srv::start(Some((hosted_config(SignupMode::Closed), &mock_url))).await;
    let (s, err) = srv
        .signup(json!({"local_part": "erin", "invite_code": "beta-1"}))
        .await;
    assert_eq!(s, 400);
    assert!(err["error"].as_str().unwrap().contains("closed"));
    let (s, av) = srv.get("/v1/hosted/availability?local_part=erin").await;
    assert_eq!(s, 200, "availability still answers when closed: {av}");
    srv.stop().await;
}

#[tokio::test]
async fn daily_caps_and_attempt_limiter() {
    let (mock_url, _mock, _m) = start_mock().await;
    // Per-IP cap of 2 successful signups per day.
    let mut cfg = hosted_config(SignupMode::Open);
    cfg.per_ip_daily = 2;
    let mut srv = Srv::start(Some((cfg, &mock_url))).await;
    for n in ["cap-one", "cap-two"] {
        let (s, b) = srv.signup(json!({"local_part": n})).await;
        assert_eq!(s, 201, "{b}");
    }
    let (s, err) = srv.signup(json!({"local_part": "cap-three"})).await;
    assert_eq!(s, 429, "{err}");
    srv.stop().await;

    // Global cap of 1.
    let mut cfg = hosted_config(SignupMode::Open);
    cfg.global_daily = 1;
    let mut srv = Srv::start(Some((cfg, &mock_url))).await;
    let (s, _) = srv.signup(json!({"local_part": "glob-one"})).await;
    assert_eq!(s, 201);
    let (s, _) = srv.signup(json!({"local_part": "glob-two"})).await;
    assert_eq!(s, 429);
    srv.stop().await;

    // Attempt limiter: 3 attempts per hour per IP, even invalid ones.
    let mut cfg = hosted_config(SignupMode::Open);
    cfg.attempts_per_hour = 3;
    let mut srv = Srv::start(Some((cfg, &mock_url))).await;
    for _ in 0..3 {
        let (s, _) = srv.signup(json!({"local_part": "ab"})).await;
        assert_eq!(s, 400);
    }
    let (s, _) = srv.signup(json!({"local_part": "ab"})).await;
    assert_eq!(s, 429);
    srv.stop().await;
}

#[tokio::test]
async fn stalwart_outage_releases_the_reservation() {
    let (mock_url, mock, _m) = start_mock().await;
    let mut srv = Srv::start(Some((hosted_config(SignupMode::Open), &mock_url))).await;
    mock.lock().unwrap().fail_next_create = true;
    let (s, err) = srv.signup(json!({"local_part": "frank"})).await;
    assert_eq!(s, 500, "{err}");
    assert!(!err["error"].as_str().unwrap().contains("secret"));
    let (_, av) = srv.get("/v1/hosted/availability?local_part=frank").await;
    assert_eq!(av["available"], true, "reservation must be released: {av}");
    let (s, ok) = srv.signup(json!({"local_part": "frank"})).await;
    assert_eq!(s, 201, "{ok}");
    srv.stop().await;
}

#[tokio::test]
async fn wrong_admin_credential_is_an_internal_error_not_a_leak() {
    let (mock_url, _mock, _m) = start_mock().await;
    let mut cfg = hosted_config(SignupMode::Open);
    cfg.domain = DOMAIN.into();
    // Point the service at the mock with a wrong secret.
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let state = AppState::new(StateOptions {
        db_path: dir.path().join("x.sqlite"),
        public_url: base.clone(),
        static_dir: dir.path().to_path_buf(),
        mailer: MemoryMailSink::new(),
        trust_proxy: false,
        limits: Limits::default(),
    })
    .unwrap();
    let client = StalwartClient::new(&mock_url, ADMIN, "nope", Duration::from_secs(5)).unwrap();
    let svc = HostedService::new(cfg, client);
    svc.ensure_schema(state.db()).await.unwrap();
    state.set_hosted(svc);
    let (tx, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(sealbox_server::serve(listener, state, async move {
        let _ = rx.await;
    }));
    let r = reqwest::Client::new()
        .post(format!("{base}/v1/hosted/signup"))
        .json(&json!({"local_part": "grace"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 500);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error"], "internal error");
    let _ = tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

#[tokio::test]
async fn unconfigured_server_answers_404() {
    let mut srv = Srv::start(None).await;
    for p in [
        "/v1/hosted/info",
        "/v1/hosted/availability?local_part=alice",
    ] {
        let (s, _) = srv.get(p).await;
        assert_eq!(s, 404, "{p}");
    }
    let (s, _) = srv.signup(json!({"local_part": "alice"})).await;
    assert_eq!(s, 404);
    let (s, h) = srv.get("/v1/health").await;
    assert_eq!(s, 200);
    assert_eq!(h["ok"], true);
    srv.stop().await;
}

/// Against the real docker Stalwart (`testing/stalwart_up.sh`): provision, log in over IMAP
/// with the returned password, clean up.
#[tokio::test]
#[ignore = "needs the Stalwart docker server (testing/stalwart_up.sh); run by scripts/gate_g22.sh"]
async fn real_stalwart_provisions_a_working_mailbox() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let url = std::env::var("SEALBOX_G22_STALWART_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8084".into());
    let user = std::env::var("SEALBOX_STALWART_ADMIN_USER").unwrap_or_else(|_| "admin".into());
    let secret = std::env::var("SEALBOX_STALWART_ADMIN_SECRET")
        .unwrap_or_else(|_| "sealbox-stalwart-dev-admin".into());
    let domain =
        std::env::var("SEALBOX_HOSTED_DOMAIN").unwrap_or_else(|_| "hosted.sealbox.test".into());
    let imap = std::env::var("SEALBOX_G22_IMAP").unwrap_or_else(|_| "127.0.0.1:1143".into());

    let mut cfg = hosted_config(SignupMode::Open);
    cfg.domain = domain.clone();
    let client = StalwartClient::new(&url, &user, &secret, Duration::from_secs(20)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::new(StateOptions {
        db_path: dir.path().join("real.sqlite"),
        public_url: "http://127.0.0.1:1".into(),
        static_dir: dir.path().to_path_buf(),
        mailer: MemoryMailSink::new(),
        trust_proxy: false,
        limits: Limits::default(),
    })
    .unwrap();
    let svc = HostedService::new(cfg, client.clone());
    svc.ensure_schema(state.db()).await.unwrap();

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("g22srv-{}", nanos % 1_000_000_000);
    let av = svc.availability(state.db(), &name).await.unwrap();
    assert!(av.available, "{av:?}");
    let created = svc
        .signup(
            state.db(),
            "203.0.113.7",
            sealbox_server::hosted::SignupRequest {
                local_part: name.clone(),
                invite_code: None,
                recovery_email: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(created.email, format!("{name}@{domain}"));
    let av = svc.availability(state.db(), &name).await.unwrap();
    assert!(!av.available && av.reason.as_deref() == Some("taken"));

    // IMAP LOGIN with the one-time password.
    let stream = tokio::net::TcpStream::connect(&imap).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    let mut line = String::new();
    r.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("* OK"), "{line}");
    w.write_all(format!("a LOGIN {} {}\r\n", created.login, created.password).as_bytes())
        .await
        .unwrap();
    line.clear();
    r.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("a OK"), "IMAP login failed: {line}");
    let _ = w.write_all(b"b LOGOUT\r\n").await;

    // Clean up on Stalwart.
    let r = client
        .call("x:Account/query", json!({"filter": {"name": name}}))
        .await
        .unwrap();
    let id = r["ids"][0].as_str().unwrap().to_owned();
    client.destroy_account(&id).await.unwrap();
    assert!(!client.account_exists(&name).await.unwrap());
}
