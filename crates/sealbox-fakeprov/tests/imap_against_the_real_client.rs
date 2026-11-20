//! The fake IMAP server driven by Sealbox's own `ImapClient`.
//!
//! A fake that only its own unit tests talk to proves nothing: the question is whether the real
//! client can work against it, and whether each quirk shows up as the client behaving
//! differently. So every test here goes over a socket through `sealbox_mail::imap::ImapClient`,
//! the same code that talks to Gmail.

use sealbox_core::providers::ProviderId;
use sealbox_fakeprov::imap::{self, grant_token, shared};
use sealbox_fakeprov::quirks::Quirks;
use sealbox_fakeprov::state::Shared;
use sealbox_mail::imap::{FlagOp, ImapClient};
use sealbox_mail::net_policy::ConnectOptions;
use sealbox_mail::oauth::Provider;
use sealbox_mail::{Auth, BearerScope, Security};
use std::time::Duration;

/// A started fake for one provider, with `n` messages in INBOX.
async fn fake(id: ProviderId, n: u32) -> (Shared, u16) {
    fake_tuned(id, n, |_| {}).await
}

async fn fake_tuned(id: ProviderId, n: u32, tune: impl FnOnce(&mut Quirks)) -> (Shared, u16) {
    let mut q = Quirks::for_provider(id);
    tune(&mut q);
    let state = shared(q);
    if n > 0 {
        state.lock().unwrap().seed("INBOX", n);
    }
    let port = imap::start(state.clone()).await.expect("listener");
    (state, port)
}

/// Log in the way this provider demands.
async fn login(state: &Shared, port: u16) -> ImapClient {
    let auth = {
        let s = state.lock().unwrap();
        match s.quirks.auth.clone() {
            sealbox_fakeprov::quirks::SimAuth::Password(pass) => Auth::Password {
                user: "you@fakeprov.test".into(),
                pass,
            },
            sealbox_fakeprov::quirks::SimAuth::XOAuth2 => Auth::XOAuth2 {
                user: "you@fakeprov.test".into(),
                access_token: "tok-good".into(),
            },
        }
    };
    grant_token(state, "tok-good");
    connect(port, auth).await.expect("login")
}

/// Connect the way the engine does against a loopback test IdP: the bearer's scope says it
/// came from a development identity provider, without which the transport policy refuses to
/// send an XOAUTH2 token to a host it cannot tie to a known provider (threat model R9).
async fn connect(port: u16, auth: Auth) -> Result<ImapClient, sealbox_mail::ImapError> {
    let opts = ConnectOptions::new(Duration::from_secs(10)).with_bearer(Some(BearerScope {
        provider: Provider::Google,
        dev_idp: true,
    }));
    ImapClient::connect_with("127.0.0.1", port, Security::Plain, auth, &opts).await
}

#[tokio::test]
async fn the_real_client_can_log_in_list_and_fetch() {
    let (state, port) = fake(ProviderId::Fastmail, 3).await;
    let mut c = login(&state, port).await;

    let folders = c.list_folders().await.expect("LIST");
    let names: Vec<&str> = folders.iter().map(|f| f.name.as_str()).collect();
    assert!(
        names.contains(&"INBOX") && names.contains(&"Sent"),
        "{names:?}"
    );

    let mb = c.select("INBOX").await.expect("SELECT");
    assert_eq!(mb.exists, 3);
    assert_eq!(mb.uidvalidity, 7);

    assert_eq!(c.fetch_new_uids(0).await.expect("SEARCH"), vec![1, 2, 3]);
    let msgs = c.fetch_rfc822_batch(&[1, 3]).await.expect("FETCH");
    assert_eq!(msgs.len(), 2);
    assert!(
        String::from_utf8_lossy(&msgs[0].raw).contains("Subject: seeded 1"),
        "the fake serves a parseable message"
    );
    let sizes = c.fetch_sizes(&[1, 2, 3]).await.expect("SIZE");
    assert_eq!(sizes.len(), 3);
    assert!(sizes.iter().all(|(_, n)| *n > 50));
    let _ = c.logout().await;
}

#[tokio::test]
async fn special_use_attributes_are_what_a_client_maps_roles_from() {
    // GMX is the case that matters: every folder name is German, so a client that matches on
    // English names finds nothing and must rely on the attributes.
    let (state, port) = fake(ProviderId::Gmx, 0).await;
    let mut c = login(&state, port).await;
    let folders = c.list_folders().await.expect("LIST");

    let junk = folders
        .iter()
        .find(|f| f.has_attribute("\\Junk"))
        .expect("a \\Junk mailbox");
    assert_eq!(junk.name, "Spamverdacht");
    let sent = folders
        .iter()
        .find(|f| f.has_attribute("\\Sent"))
        .expect("a \\Sent mailbox");
    assert_eq!(sent.name, "Gesendet");

    // With SPECIAL-USE off, the same server offers only names — the fallback path.
    let (state2, port2) = fake_tuned(ProviderId::Gmx, 0, |q| q.special_use = false).await;
    let mut c2 = login(&state2, port2).await;
    let plain = c2.list_folders().await.expect("LIST");
    assert!(
        plain.iter().all(|f| !f.has_attribute("\\Junk")),
        "no attributes at all when the server does not advertise SPECIAL-USE"
    );
    assert!(plain.iter().any(|f| f.name == "Spamverdacht"));
    let _ = c.logout().await;
    let _ = c2.logout().await;
}

#[tokio::test]
async fn oauth_only_providers_refuse_a_password_and_accept_a_bearer() {
    let (state, port) = fake(ProviderId::Gmail, 1).await;
    // A password against an OAuth-only provider: refused, and the fake records why.
    let err = connect(
        port,
        Auth::Password {
            user: "you@fakeprov.test".into(),
            pass: "hunter2".into(),
        },
    )
    .await
    .expect_err("basic auth is gone on Gmail");
    assert!(
        format!("{err}")
            .to_ascii_uppercase()
            .contains("AUTHENTICATIONFAILED"),
        "{err}"
    );
    assert!(state
        .lock()
        .unwrap()
        .rejected_logins
        .iter()
        .any(|(_, why)| why.contains("password auth disabled")));

    // An unknown bearer is refused too.
    let err = connect(
        port,
        Auth::XOAuth2 {
            user: "you@fakeprov.test".into(),
            access_token: "not-a-token".into(),
        },
    )
    .await
    .expect_err("unknown bearer");
    assert!(
        format!("{err}").to_ascii_uppercase().contains("FAIL"),
        "{err}"
    );

    // The one the IdP issued works.
    let mut c = login(&state, port).await;
    assert_eq!(c.select("INBOX").await.expect("SELECT").exists, 1);
    let _ = c.logout().await;
}

#[tokio::test]
async fn outlook_rejects_xoauth2_under_an_alias_even_with_a_good_token() {
    // The quirk that cost a day on a real account: the token is valid, the mailbox is the
    // right one, and Outlook still refuses because the login is an alias.
    let (state, port) = fake_tuned(ProviderId::Outlook, 1, |q| {
        q.primary_login = Some("primary@fakeprov.test".into())
    })
    .await;
    grant_token(&state, "tok-good");

    let err = connect(
        port,
        Auth::XOAuth2 {
            user: "alias@fakeprov.test".into(),
            access_token: "tok-good".into(),
        },
    )
    .await
    .expect_err("an alias is refused");
    assert!(
        format!("{err}")
            .to_ascii_uppercase()
            .contains("AUTHENTICATIONFAILED"),
        "{err}"
    );
    assert!(
        state
            .lock()
            .unwrap()
            .rejected_logins
            .iter()
            .any(|(u, why)| u == "alias@fakeprov.test" && why.contains("primary")),
        "the fake says which address it wanted — the hint the CLI can print"
    );

    // The primary address, same token, works.
    let mut c = connect(
        port,
        Auth::XOAuth2 {
            user: "primary@fakeprov.test".into(),
            access_token: "tok-good".into(),
        },
    )
    .await
    .expect("the primary address is accepted");
    assert_eq!(c.select("INBOX").await.unwrap().exists, 1);
    let _ = c.logout().await;
}

#[tokio::test]
async fn flags_set_by_the_client_are_what_a_later_fetch_reports() {
    let (state, port) = fake(ProviderId::Icloud, 2).await;
    let mut c = login(&state, port).await;
    c.select("INBOX").await.unwrap();

    c.set_flags(&[2], FlagOp::Add, &["\\Seen"])
        .await
        .expect("STORE");
    let flags = c.fetch_flags(&[1, 2]).await.expect("FETCH FLAGS");
    let of = |uid: u32| -> Vec<String> {
        flags
            .iter()
            .find(|(u, _)| *u == uid)
            .map(|(_, f)| f.clone())
            .unwrap_or_default()
    };
    assert!(of(2).iter().any(|f| f.eq_ignore_ascii_case("\\Seen")));
    assert!(of(1).is_empty(), "UID 1 was not touched");

    c.set_flags(&[2], FlagOp::Remove, &["\\Seen"])
        .await
        .expect("STORE -");
    let flags = c.fetch_flags(&[2]).await.unwrap();
    assert!(flags[0].1.is_empty(), "removed again: {flags:?}");
    let _ = c.logout().await;
}

#[tokio::test]
async fn a_missing_move_makes_the_client_fall_back_to_copy_and_expunge() {
    let (state, port) = fake_tuned(ProviderId::Zoho, 2, |q| q.has_move = false).await;
    let mut c = login(&state, port).await;
    c.select("INBOX").await.unwrap();
    assert!(!c.has_capability("MOVE"), "the server does not offer it");

    // `ImapClient::move` is the engine's entry point; against a server without RFC 6851 it has
    // to COPY + STORE \Deleted + EXPUNGE and say which route it took.
    let method = c.r#move(&[1], "Trash").await.expect("move by fallback");
    assert!(
        format!("{method:?}").to_ascii_lowercase().contains("copy"),
        "it reported the fallback: {method:?}"
    );
    let s = state.lock().unwrap();
    assert_eq!(s.count("INBOX"), 1, "the message left INBOX");
    assert_eq!(s.count("Trash"), 1, "and arrived in Trash");
    assert!(
        !s.imap_saw("UID MOVE") || s.imap_saw("UID COPY"),
        "{:?}",
        s.imap_commands()
    );
}

#[tokio::test]
async fn gmail_labels_mean_a_copy_leaves_the_message_in_both_folders() {
    let (state, port) = fake(ProviderId::Gmail, 1).await;
    let mut c = login(&state, port).await;
    c.select("INBOX").await.unwrap();

    c.copy(&[1], "[Gmail]/All Mail").await.expect("COPY");
    {
        let s = state.lock().unwrap();
        assert_eq!(s.count("INBOX"), 1, "a label was added, nothing moved");
        assert_eq!(s.count("[Gmail]/All Mail"), 1);
    }

    // And expunging from INBOX only unlabels: the message survives in All Mail. That is the
    // behaviour that makes "delete" on Gmail mean "move to Trash".
    c.set_flags(&[1], FlagOp::Add, &["\\Deleted"])
        .await
        .unwrap();
    c.expunge().await.unwrap();
    let s = state.lock().unwrap();
    assert_eq!(s.count("INBOX"), 0);
    assert_eq!(
        s.count("[Gmail]/All Mail"),
        1,
        "archived, not deleted — the Gmail quirk"
    );
}

#[tokio::test]
async fn the_connection_limit_is_enforced_and_counted() {
    // A server that really refuses a second session. The profile's `max_connections: 1` for
    // Yahoo and iCloud is *our* budget ("keep one IMAP session per account"), not a documented
    // refusal, so the hard limit is stated here rather than taken from the table — otherwise
    // this test would read as evidence about Yahoo, which it is not.
    let (state, port) =
        fake_tuned(ProviderId::Yahoo, 1, |q| q.connection_hard_limit = Some(1)).await;
    let first = login(&state, port).await;

    let second = connect(
        port,
        Auth::Password {
            user: "you@fakeprov.test".into(),
            pass: "yahoo-app-pw".into(),
        },
    )
    .await;
    assert!(second.is_err(), "a second session must be refused");
    assert_eq!(state.lock().unwrap().imap_refused, 1);

    // After the first session closes, a new one is accepted.
    let _ = first.logout().await; // takes ownership, so the socket closes with it
                                  // The server decrements on connection teardown; give the task a turn to run.
    for _ in 0..50 {
        if state.lock().unwrap().imap_open == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let third = login(&state, port).await;
    let _ = third.logout().await;
    assert_eq!(state.lock().unwrap().imap_peak, 1, "never two at once");
}

#[tokio::test]
async fn throttling_is_a_temporary_no_the_client_can_see() {
    let (state, port) = fake_tuned(ProviderId::Gmail, 3, |q| q.throttle_after = Some(4)).await;
    let mut c = login(&state, port).await;
    // SELECT surfaces a tagged NO as an error; UID SEARCH does not (see the test below), so
    // the throttle has to be observed through a command whose failure the client reports.
    let mut refused = None;
    for _ in 0..8 {
        if let Err(e) = c.select("INBOX").await {
            refused = Some(format!("{e}"));
            break;
        }
    }
    let msg = refused.expect("the server started refusing");
    assert!(
        msg.to_ascii_uppercase().contains("THROTTLED"),
        "a temporary failure the client can act on, with the reason: {msg}"
    );
    assert!(state.lock().unwrap().imap_commands().len() > 4);
}

#[tokio::test]
async fn append_stores_what_the_client_sent_byte_for_byte() {
    let (state, port) = fake(ProviderId::Fastmail, 0).await;
    let mut c = login(&state, port).await;
    let raw = b"From: a@fakeprov.test\r\nTo: b@fakeprov.test\r\nSubject: appended\r\n\
                Message-ID: <app-1@fakeprov.test>\r\n\r\nbody line\r\n";
    c.append("Sent", raw, &["\\Seen"]).await.expect("APPEND");

    let s = state.lock().unwrap();
    let mb = s.folder("Sent").expect("Sent");
    assert_eq!(mb.messages.len(), 1);
    assert_eq!(
        String::from_utf8_lossy(&mb.messages[0].raw),
        String::from_utf8_lossy(raw),
        "the literal survived the round trip unchanged"
    );
    assert!(mb.messages[0].has_flag("\\Seen"));
}

#[tokio::test]
async fn a_uidvalidity_bump_is_visible_to_the_client() {
    let (state, port) = fake(ProviderId::Outlook, 2).await;
    let mut c = login(&state, port).await;
    assert_eq!(c.select("INBOX").await.unwrap().uidvalidity, 7);

    let new = state.lock().unwrap().bump_uidvalidity("INBOX");
    assert_eq!(c.select("INBOX").await.unwrap().uidvalidity, new);
    assert_ne!(new, 7);
    let _ = c.logout().await;
}

/// Raw protocol, no client library: send one command and collect the reply.
async fn raw_exchange(port: u16, commands: &[&str]) -> String {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (rd, mut wr) = sock.into_split();
    let mut lines = BufReader::new(rd).lines();
    let mut out = String::new();
    // The greeting.
    if let Ok(Some(l)) = lines.next_line().await {
        out.push_str(&l);
        out.push('\n');
    }
    for cmd in commands {
        wr.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
        // Read until the tagged reply for this command's tag.
        let tag = cmd.split_whitespace().next().unwrap_or("");
        while let Ok(Some(l)) = lines.next_line().await {
            out.push_str(&l);
            out.push('\n');
            if l.starts_with(tag) && !l.starts_with("* ") {
                break;
            }
        }
    }
    out
}

/// The fake answers a command it does not implement with a tagged `BAD` — and **the client
/// cannot tell**, because async-imap ends a SEARCH response stream silently on a tagged NO or
/// BAD and hands back an empty result set.
///
/// That asymmetry is not a flaw in the fake; it is the trap that `sync.rs` already guards for
/// the backfill search and that `Engine::reconcile_selected` was redesigned around in Phase 1:
/// an empty `UID SEARCH` answer cannot be trusted as "nothing matched" without a second
/// opinion. Pinning it here means the fake can be used to exercise that guard, and that nobody
/// later "fixes" the fake into answering `OK` with no results.
#[tokio::test]
async fn an_unimplemented_search_key_is_a_bad_on_the_wire_and_invisible_to_the_client() {
    let (state, port) = fake(ProviderId::Generic, 1).await;

    // On the wire: a tagged BAD that names what was not implemented.
    let reply = raw_exchange(
        port,
        &[
            "A1 LOGIN \"you@fakeprov.test\" \"generic-app-pw\"",
            "A2 SELECT INBOX",
            "A3 UID SEARCH LARGER 100",
        ],
    )
    .await;
    assert!(
        reply.contains("A3 BAD") && reply.to_ascii_uppercase().contains("LARGER"),
        "the server said plainly what it does not implement:\n{reply}"
    );

    // Through the client: an empty result, indistinguishable from "nothing matched".
    let mut c = login(&state, port).await;
    c.select("INBOX").await.unwrap();
    let hits = c
        .uid_search("LARGER 100")
        .await
        .expect("async-imap reports no error for a tagged BAD on SEARCH");
    assert!(
        hits.is_empty(),
        "and the answer looks exactly like an honest empty result: {hits:?}"
    );
    // Which is why a caller must cross-check. The mailbox is not empty:
    assert_eq!(c.select("INBOX").await.unwrap().exists, 1);
    let _ = c.logout().await;
}

/// `IDLE` has to *announce*, not merely accept the command. Without the push the client learns
/// about new mail only when its own wait times out, which would turn the conformance suite's
/// `arrival_via_idle` into a measurement of that timeout — and it would pass, which is worse.
#[tokio::test]
async fn idle_announces_new_mail_rather_than_waiting_for_the_client_to_time_out() {
    let (state, port) = fake(ProviderId::Fastmail, 1).await;
    let mut c = login(&state, port).await;
    c.select("INBOX").await.expect("SELECT");

    // Nothing is happening: the wait ends in a timeout, promptly.
    let started = std::time::Instant::now();
    assert_eq!(
        c.idle_wait(Duration::from_millis(300)).await.expect("idle"),
        sealbox_mail::imap::IdleEvent::Timeout
    );
    assert!(started.elapsed() < Duration::from_secs(3));

    // Mail arrives while the client is parked. It must be told inside the timeout, not at it.
    let st = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        st.lock().unwrap().seed("INBOX", 1);
    });
    let started = std::time::Instant::now();
    let ev = c.idle_wait(Duration::from_secs(10)).await.expect("idle");
    let took = started.elapsed();
    assert_eq!(ev, sealbox_mail::imap::IdleEvent::NewData);
    assert!(
        took < Duration::from_secs(5),
        "told, not timed out: {took:?}"
    );

    // And the client is still usable afterwards: the DONE handshake left no stray bytes.
    assert_eq!(c.uid_search("ALL").await.expect("SEARCH").len(), 2);
}
