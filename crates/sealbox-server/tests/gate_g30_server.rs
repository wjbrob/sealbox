//! Gate G30 — server half: the key-transparency log over the key directory.
//!
//! In-process server on 127.0.0.1:0 with a temp SQLite file and the in-memory mail sink.
//! Keys are published through the real VKS flow (upload → challenge mail → verify link); every
//! check of the log is done by the *client* verifier (`sealbox_core::identity::kt`), which
//! shares no code with the server's tree.
//!
//! (a) publish → log entry → STH signature, inclusion and consistency proofs verify;
//! (b) key rotation appears as unpublish + publish, the old key is no longer "included";
//! (c) substitution by the operator: a forked log that swaps a fingerprint (re-signed with the
//!     real log key, so the signature alone looks fine) fails inclusion of the honest leaf,
//!     fails consistency with the head a client saw before, and the audit names the planted
//!     key; a fork that rewrites history and appends fails the RFC 9162 consistency check;
//! (d) a tree head whose root was altered without re-signing fails the signature check;
//! (e) a swapped log key is reported against the client's pin.

use std::{sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::Signer;
use rusqlite::params;
use sealbox_core::identity::kt as client;
use sealbox_core::sealbox_crypto::Identity;
use sealbox_server::{kt, mail::MemoryMailSink, AppState, Limits, StateOptions};
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::oneshot};

struct Srv {
    base: String,
    state: AppState,
    sink: Arc<MemoryMailSink>,
    http: reqwest::Client,
    _dir: tempfile::TempDir,
    stop: Option<oneshot::Sender<()>>,
}

impl Srv {
    async fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let sink = MemoryMailSink::new();
        let state = AppState::new(StateOptions {
            db_path: dir.path().join("g30.sqlite"),
            public_url: base.clone(),
            static_dir: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../web/guest"),
            mailer: sink.clone(),
            trust_proxy: false,
            limits: Limits::default(),
        })
        .expect("state");
        kt::init(state.db()).await.expect("kt init");
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(sealbox_server::serve(listener, state.clone(), async move {
            let _ = rx.await;
        }));
        Self {
            base,
            state,
            sink,
            http: reqwest::Client::new(),
            _dir: dir,
            stop: Some(tx),
        }
    }

    fn url(&self, p: &str) -> String {
        format!("{}{p}", self.base)
    }

    async fn get(&self, p: &str) -> Value {
        let r = self.http.get(self.url(p)).send().await.expect(p);
        assert!(r.status().is_success(), "{p}: {}", r.status());
        r.json().await.expect("json")
    }

    /// Upload `id`'s public key and click the challenge link for `email`.
    async fn publish(&self, id: &Identity, email: &str) {
        let up: Value = self
            .http
            .post(self.url("/vks/v1/upload"))
            .json(&json!({ "keytext": id.public().to_armored().expect("armor") }))
            .send()
            .await
            .expect("upload")
            .json()
            .await
            .expect("json");
        let token = up["token"].as_str().expect("token");
        let r = self
            .http
            .post(self.url("/vks/v1/request-verify"))
            .json(&json!({ "token": token, "addresses": [email] }))
            .send()
            .await
            .expect("request-verify");
        assert_eq!(r.status(), 200);
        let mails = self.sink.take();
        let prefix = self.url("/vks/v1/verify/");
        let link = mails
            .iter()
            .flat_map(|m| m.body.split_whitespace())
            .find(|w| w.starts_with(&prefix))
            .expect("challenge link")
            .to_owned();
        let r = self.http.get(&link).send().await.expect("verify");
        assert_eq!(r.status(), 200);
    }

    async fn audit(
        &self,
        email: &str,
        fp: &str,
        pin: Option<&[u8; 32]>,
        prev: Option<&client::SignedTreeHead>,
    ) -> client::AuditOutcome {
        client::audit(&self.http, &self.base, email, fp, pin, prev).await
    }

    async fn stop(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// What a malicious operator does: rewrite leaf `idx` to name `fingerprint`, then recompute
/// and re-sign every head from that size on with the real log key.
fn fork_log(c: &mut rusqlite::Connection, idx: i64, fingerprint: &str) {
    let (eh, action, time): (String, String, i64) = c
        .query_row(
            "SELECT email_hash, action, time FROM kt_leaves WHERE idx = ?1",
            [idx],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("leaf");
    let entry = kt::Entry {
        action,
        email_hash: eh,
        fingerprint: fingerprint.to_string(),
        time,
    };
    let leaf = entry.leaf_json();
    let lh = kt::merkle::leaf_hash(leaf.as_bytes());
    c.execute(
        "UPDATE kt_leaves SET fingerprint = ?2, leaf = ?3, leaf_hash = ?4 WHERE idx = ?1",
        params![idx, fingerprint, leaf, lh.to_vec()],
    )
    .expect("rewrite");
    resign_heads(c, idx as u64 + 1);
}

fn resign_heads(c: &rusqlite::Connection, from_size: u64) {
    let key = kt::signing_key(c).expect("key");
    let hashes = kt::leaf_hashes(c, None).expect("hashes");
    for size in from_size..=hashes.len() as u64 {
        let root = hex::encode(kt::merkle::root(&hashes[..size as usize]));
        let ts = 1_900_000_000 + size as i64;
        let sig = key.sign(&kt::sth_signing_input(size, &root, ts));
        c.execute(
            "INSERT OR REPLACE INTO kt_heads (tree_size, root_hash, timestamp, signature) VALUES (?1, ?2, ?3, ?4)",
            params![size as i64, root, ts, STANDARD.encode(sig.to_bytes())],
        )
        .expect("head");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_transparency_log_and_substitution_detection() {
    let s = Srv::start().await;
    let alice = Identity::generate("Alice", "alice@sealbox.test").expect("alice");
    let alice_fp = alice.fingerprint();
    let bob = Identity::generate("Bob", "bob@sealbox.test").expect("bob");
    let mallory = Identity::generate("Mallory", "alice@sealbox.test").expect("mallory");

    // Empty log: signed head of size 0, no entry for alice.
    let sth0: client::SignedTreeHead =
        serde_json::from_value(s.get("/v1/kt/sth").await).expect("sth");
    assert_eq!(sth0.tree_size, 0);
    let key: client::KtKey = serde_json::from_value(s.get("/v1/kt/key").await).expect("key");
    assert_eq!(key.algorithm, "ed25519");
    let pin = client::parse_public_key(&key.public_key).expect("32-byte key");
    assert!(client::verify_sth(&sth0, &pin));
    let first = s
        .audit("alice@sealbox.test", &alice_fp, Some(&pin), None)
        .await;
    assert!(first.report.sth_verified && !first.report.own_key_included);
    assert!(first.report.alerts.iter().any(|a| a.contains("no entry")));

    // ---------------------------------------------------------------- (a) publish
    s.publish(&alice, "alice@sealbox.test").await;
    let page = s.get("/v1/kt/entries").await;
    assert_eq!(page["tree_size"], 1);
    let e0 = &page["entries"][0]["entry"];
    assert_eq!(e0["action"], "publish");
    assert_eq!(e0["fingerprint"], alice_fp.as_str());
    assert_eq!(e0["email_hash"], client::email_hash("alice@sealbox.test"));
    assert!(
        !page.to_string().contains("alice@sealbox.test"),
        "the log never carries the address in clear"
    );
    let a1 = s
        .audit("alice@sealbox.test", &alice_fp, Some(&pin), None)
        .await;
    eprintln!("audit after publish: {:?}", a1.report);
    assert!(a1.report.is_clean(), "{:?}", a1.report);
    assert_eq!(a1.report.log_size, 1);
    let sth1 = a1.accepted.clone().expect("accepted head");
    // The served proof checks out field by field with the client verifier.
    let proof1: client::InclusionProof =
        serde_json::from_value(s.get("/v1/kt/proof/by-email/Alice%40sealbox.test").await)
            .expect("proof");
    assert!(client::check_inclusion(&proof1, &sth1));

    s.publish(&bob, "bob@sealbox.test").await;
    let a2 = s
        .audit("alice@sealbox.test", &alice_fp, Some(&pin), Some(&sth1))
        .await;
    assert!(a2.report.is_clean(), "{:?}", a2.report);
    let sth2 = a2.accepted.clone().expect("head 2");
    assert_eq!(sth2.tree_size, 2);
    let cons: client::ConsistencyProof =
        serde_json::from_value(s.get("/v1/kt/consistency?from=1&to=2").await).expect("cons");
    assert!(client::check_consistency(&sth1, &sth2, &cons));
    let b = s
        .audit(
            "bob@sealbox.test",
            &bob.fingerprint(),
            Some(&pin),
            Some(&sth2),
        )
        .await;
    assert!(b.report.is_clean(), "{:?}", b.report);

    // ---------------------------------------------------------------- (b) rotation
    let alice2 = Identity::generate("Alice", "alice@sealbox.test").expect("alice2");
    s.publish(&alice2, "alice@sealbox.test").await;
    let page = s.get("/v1/kt/entries?start=2").await;
    let acts: Vec<(String, String)> = page["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| {
            (
                e["entry"]["action"].as_str().unwrap_or("").to_string(),
                e["entry"]["fingerprint"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    assert_eq!(
        acts,
        vec![
            ("unpublish".to_string(), alice_fp.clone()),
            ("publish".to_string(), alice2.fingerprint())
        ]
    );
    let stale = s
        .audit("alice@sealbox.test", &alice_fp, Some(&pin), Some(&sth2))
        .await;
    assert!(stale.report.consistency_ok && !stale.report.own_key_included);
    let a3 = s
        .audit(
            "alice@sealbox.test",
            &alice2.fingerprint(),
            Some(&pin),
            Some(&sth2),
        )
        .await;
    assert!(a3.report.is_clean(), "{:?}", a3.report);
    let sth4 = a3.accepted.clone().expect("head 4");
    assert_eq!(sth4.tree_size, 4);
    let honest_proof: client::InclusionProof =
        serde_json::from_value(s.get("/v1/kt/proof/by-email/alice@sealbox.test").await)
            .expect("proof");
    assert!(client::check_inclusion(&honest_proof, &sth4));

    // ---------------------------------------------------------------- (c) substitution
    // The operator swaps alice's current key for mallory's in the log and re-signs.
    let mallory_fp = mallory.fingerprint();
    {
        let fp = mallory_fp.clone();
        s.state
            .db()
            .call(move |c| -> Result<(), sealbox_server::db::DbError> {
                fork_log(c, 3, &fp);
                Ok(())
            })
            .await
            .expect("fork");
    }
    let forked: client::SignedTreeHead =
        serde_json::from_value(s.get("/v1/kt/sth").await).expect("sth");
    assert_eq!(forked.tree_size, 4);
    assert!(
        client::verify_sth(&forked, &pin),
        "the operator holds the log key: the forged head is validly signed"
    );
    assert_ne!(forked.root_hash, sth4.root_hash);
    // 1. The honest leaf is not in the forked tree.
    assert!(!client::check_inclusion(&honest_proof, &forked));
    // 2. A client that saw the honest head of the same size detects the fork.
    let c1 = s
        .audit(
            "alice@sealbox.test",
            &alice2.fingerprint(),
            Some(&pin),
            Some(&sth4),
        )
        .await;
    eprintln!(
        "audit of the forked log (client saw size 4): {:?}",
        c1.report
    );
    assert!(c1.report.sth_verified);
    assert!(!c1.report.consistency_ok);
    assert!(!c1.report.own_key_included);
    assert!(c1.accepted.is_none(), "a forked head is never remembered");
    assert!(c1.report.alerts.iter().any(|a| a.contains("fork")));
    // 3. A fresh client (no history) still sees that the log names someone else's key.
    let c2 = s
        .audit(
            "alice@sealbox.test",
            &alice2.fingerprint(),
            Some(&pin),
            None,
        )
        .await;
    assert!(!c2.report.own_key_included);
    assert!(c2
        .report
        .alerts
        .iter()
        .any(|a| a.contains("SUBSTITUTION") && a.contains(&mallory_fp)));
    // 4. A client that saw size 2 and is shown the forked size-4 tree: the consistency proof
    //    holds only for the untouched prefix, so the fork is invisible from size 2 — but the
    //    entry check (3.) still catches it. A rewrite *inside* the seen prefix is caught:
    {
        let fp = mallory_fp.clone();
        s.state
            .db()
            .call(move |c| -> Result<(), sealbox_server::db::DbError> {
                fork_log(c, 0, &fp); // rewrite alice's very first entry (inside size 1 and 2)
                Ok(())
            })
            .await
            .expect("fork 2");
    }
    let c3 = s
        .audit(
            "bob@sealbox.test",
            &bob.fingerprint(),
            Some(&pin),
            Some(&sth2),
        )
        .await;
    eprintln!(
        "audit after a history rewrite (client saw size 2): {:?}",
        c3.report
    );
    assert!(c3.report.sth_verified && !c3.report.consistency_ok);
    assert!(c3.report.alerts.iter().any(|a| a.contains("append-only")));
    let forked2: client::SignedTreeHead =
        serde_json::from_value(s.get("/v1/kt/sth").await).expect("sth");
    let p: client::ConsistencyProof =
        serde_json::from_value(s.get("/v1/kt/consistency?from=2&to=4").await).expect("cons");
    assert!(!client::check_consistency(&sth2, &forked2, &p));

    // ---------------------------------------------------------------- (d) tampered head
    s.state
        .db()
        .call(|c| -> Result<(), sealbox_server::db::DbError> {
            c.execute(
                "UPDATE kt_heads SET root_hash = ?1 WHERE tree_size = 4",
                [hex::encode([0xAB_u8; 32])],
            )?;
            Ok(())
        })
        .await
        .expect("tamper");
    let t = s
        .audit(
            "alice@sealbox.test",
            &alice2.fingerprint(),
            Some(&pin),
            None,
        )
        .await;
    assert!(!t.report.sth_verified && !t.report.own_key_included);
    assert!(t.accepted.is_none());

    // ---------------------------------------------------------------- (e) swapped log key
    s.state
        .db()
        .call(|c| -> Result<(), sealbox_server::db::DbError> {
            c.execute("DELETE FROM kt_signing_key", [])?;
            let _ = kt::signing_key(c)?; // a new key
            resign_heads(c, 0);
            Ok(())
        })
        .await
        .expect("rekey");
    let k = s
        .audit(
            "alice@sealbox.test",
            &alice2.fingerprint(),
            Some(&pin),
            None,
        )
        .await;
    assert!(!k.report.sth_verified);
    assert!(k
        .report
        .alerts
        .iter()
        .any(|a| a.contains("signing key changed")));
    s.stop().await;
}
