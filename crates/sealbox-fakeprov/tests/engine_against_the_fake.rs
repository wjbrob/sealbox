//! The whole engine against a fake provider, through its public API only.
//!
//! This is where Phase 2.1 and 2.2 meet, and the point of both: an account pointed at
//! `127.0.0.1` is `Greenmail` by its host, so before the stored provider id existed there was
//! no way to make the engine treat a simulator as the provider it imitates. With it, the engine
//! resolves GMX's German folder names and Gmail's `[Gmail]/…` names against a fake that serves
//! exactly what `providers.rs` claims each one serves.

use std::time::Duration;

use sealbox_core::providers::ProviderId;
use sealbox_core::{
    AddAccount, AuthHint, AuthSpec, ConfigSource, Draft, Endpoint, Engine, EngineConfig,
    FolderRole, ListQuery, Security, SendPolicy, ServerConfig, UsernameForm,
};
use sealbox_fakeprov::{ProviderSim, Quirks, SimAuth};

const EMAIL: &str = "you@fakeprov.test";

/// An engine with one account pointed at a running fake, with `id` stated as its provider.
async fn engine_on(sim: &ProviderSim) -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = Engine::open_with(
        dir.path(),
        EngineConfig {
            network_timeout: Duration::from_secs(10),
            sync_window: 50,
            // A fixed raw key: tests must never touch (or wait on) the developer's OS keyring.
            profile_key: sealbox_core::ProfileKeySource::Raw(vec![7u8; 32]),
            ..EngineConfig::default()
        },
    )
    .expect("open profile");

    let password = match sim.state.lock().unwrap().quirks.auth.clone() {
        SimAuth::Password(p) => p,
        SimAuth::XOAuth2 => panic!("use a password provider for this test"),
    };
    engine
        .add_account(AddAccount {
            email: EMAIL.to_string(),
            display_name: None,
            auth: AuthSpec::Password { password },
            servers: Some(ServerConfig {
                imap: Endpoint::new("127.0.0.1", sim.imap_port, Security::Plain),
                smtp: Endpoint::new("127.0.0.1", sim.smtp_port, Security::Plain),
                auth_hint: AuthHint::Password,
                display_name: "fakeprov (manual)".into(),
                source: ConfigSource::Manual,
                username: UsernameForm::FullAddress,
            }),
            login: Some(EMAIL.to_string()),
        })
        .await
        .expect("add account against the fake");
    engine
        .set_account_provider(EMAIL, Some(sim.id()))
        .expect("state the provider");
    (dir, engine)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_engine_treats_a_loopback_fake_as_the_provider_it_imitates() {
    let sim = ProviderSim::start(ProviderId::Gmx).await.unwrap();
    let (_dir, engine) = engine_on(&sim).await;

    // By host alone this would be Greenmail; stated, it is GMX.
    assert_eq!(engine.provider_profile(EMAIL).unwrap().id, ProviderId::Gmx);
    assert_eq!(
        engine.special_folder(EMAIL, FolderRole::Junk).unwrap(),
        "Spamverdacht",
        "the German name, from the profile"
    );

    // Clearing it falls back to the host guess, which is wrong — that is the bug 2.1 fixed.
    engine.set_account_provider(EMAIL, None).unwrap();
    assert_eq!(
        engine.provider_profile(EMAIL).unwrap().id,
        ProviderId::Greenmail
    );
    assert_eq!(
        engine.special_folder(EMAIL, FolderRole::Junk).unwrap(),
        "Junk"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sync_against_the_fake_stores_the_mail_and_learns_the_roles_from_its_list() {
    let sim = ProviderSim::start(ProviderId::Gmx).await.unwrap();
    sim.seed_inbox(4);
    let (_dir, engine) = engine_on(&sim).await;

    let report = engine.sync(EMAIL).await.expect("sync");
    assert_eq!(report.new, 4, "{report:?}");
    let stored = engine
        .list_messages(ListQuery {
            account: Some(EMAIL.into()),
            limit: 100,
            ..ListQuery::default()
        })
        .expect("list");
    assert_eq!(stored.len(), 4);
    assert!(stored
        .iter()
        .any(|m| m.subject.as_deref() == Some("seeded 1")));

    // The roles the server's LIST advertised were learned, so they now beat the profile
    // defaults — against a localised provider that is the difference between finding the Junk
    // folder and inventing one.
    let roles = engine.folder_roles(EMAIL).expect("roles");
    let junk = roles
        .iter()
        .find(|(r, _)| *r == FolderRole::Junk)
        .map(|(_, n)| n.as_str());
    assert_eq!(junk, Some("Spamverdacht"), "{roles:?}");
}

/// Phase 1's convergence, now against a simulated provider rather than GreenMail: the fake is
/// the "other client".
#[tokio::test(flavor = "multi_thread")]
async fn the_mailbox_converges_against_a_simulated_provider() {
    let sim = ProviderSim::start(ProviderId::Fastmail).await.unwrap();
    sim.seed_inbox(3);
    let (_dir, engine) = engine_on(&sim).await;
    engine.sync(EMAIL).await.expect("first sync");
    assert_eq!(
        engine
            .list_messages(ListQuery {
                account: Some(EMAIL.into()),
                limit: 100,
                ..ListQuery::default()
            })
            .unwrap()
            .len(),
        3
    );

    // "Elsewhere": UID 2 is expunged and UID 3 is marked read, directly in the fake's state.
    {
        let mut s = sim.state.lock().unwrap();
        s.folder_mut("INBOX").unwrap().get_mut(2).unwrap().flags = vec!["\\Deleted".into()];
        s.expunge("INBOX", None);
        s.folder_mut("INBOX").unwrap().get_mut(3).unwrap().flags = vec!["\\Seen".into()];
    }

    let report = engine.sync(EMAIL).await.expect("second sync");
    let inbox = report
        .folders
        .iter()
        .find(|f| f.name == "INBOX")
        .expect("INBOX");
    assert_eq!(inbox.removed, 1, "{report:?}");
    assert_eq!(inbox.flags_changed, 1, "{report:?}");
    let stored = engine
        .list_messages(ListQuery {
            account: Some(EMAIL.into()),
            limit: 100,
            ..ListQuery::default()
        })
        .unwrap();
    assert_eq!(stored.len(), 2);
    assert!(stored.iter().all(|m| m.uid != 2));
    assert!(
        stored.iter().find(|m| m.uid == 3).is_some_and(|m| m.seen),
        "read elsewhere, no longer unread here"
    );
}

/// **A real risk this simulator surfaced, pinned so it cannot regress unnoticed.**
///
/// The engine avoids a duplicate Sent copy by searching the Sent folder for the message's
/// Message-ID before appending one. async-imap reports a tagged `BAD` on SEARCH as an empty
/// result (see `an_unimplemented_search_key_is_a_bad_on_the_wire_and_invisible_to_the_client`),
/// so against a provider that refuses `SEARCH HEADER` the engine cannot tell "not supported"
/// from "not there yet": it retries for about ten seconds and then appends anyway, leaving the
/// user with two copies of every sent message.
///
/// Every provider in `PROFILES` is believed to support `SEARCH HEADER`, so this is not a live
/// defect — it is a dependency the send path has on a command whose failure it cannot observe.
/// The test records the behaviour as it is today rather than asserting what we would prefer.
#[tokio::test(flavor = "multi_thread")]
async fn a_provider_refusing_header_search_gets_a_duplicate_sent_copy() {
    let mut q = Quirks::for_provider(ProviderId::Outlook);
    q.auth = SimAuth::Password("outlook-app-pw".into());
    q.header_search = false; // the refusal the engine cannot see
    let sent_folder = q.sent_folder();
    let sim = ProviderSim::start_with(q).await.unwrap();
    let (_dir, engine) = engine_on(&sim).await;

    let started = std::time::Instant::now();
    engine
        .send(
            EMAIL,
            Draft {
                to: vec!["them@fakeprov.test".to_string()],
                subject: "dup".into(),
                text: "body".into(),
                policy: SendPolicy::AllowPlaintext,
                ..Draft::default()
            },
        )
        .await
        .expect("the send still succeeds");
    let waited = started.elapsed();

    let s = sim.state.lock().unwrap();
    assert_eq!(s.submitted.len(), 1, "submitted once");
    assert_eq!(
        s.count(&sent_folder),
        2,
        "two copies: submission filed one and the engine appended another"
    );
    assert!(
        s.imap_saw("APPEND"),
        "it appended after failing to find the copy"
    );
    assert!(
        waited > Duration::from_secs(1),
        "and it spent real time retrying first: {waited:?}"
    );
}

/// `smtp_saves_sent` through the engine: against a provider that files its own copy, the engine
/// must not append a second one. The fake is the only place this can be checked without a real
/// Gmail account.
#[tokio::test(flavor = "multi_thread")]
async fn the_engine_does_not_append_a_second_sent_copy_when_submission_files_one() {
    // Outlook files its own copy but authenticates with OAuth, so take its submission quirk
    // and keep password auth, which is the one dimension this test is not about.
    let mut q = Quirks::for_provider(ProviderId::Outlook);
    q.auth = SimAuth::Password("outlook-app-pw".into());
    assert!(q.smtp_saves_sent);
    let sent_folder = q.sent_folder();
    let sim = ProviderSim::start_with(q).await.unwrap();
    let (_dir, engine) = engine_on(&sim).await;

    engine
        .send(
            EMAIL,
            Draft {
                to: vec!["them@fakeprov.test".to_string()],
                subject: "hello".into(),
                text: "body".into(),
                // The recipient has no key here, and encryption is not what this test is
                // about; the Sent-copy behaviour is the same either way.
                policy: SendPolicy::AllowPlaintext,
                ..Draft::default()
            },
        )
        .await
        .expect("send");

    let s = sim.state.lock().unwrap();
    assert_eq!(s.submitted.len(), 1, "submitted once");
    assert_eq!(
        s.count(&sent_folder),
        1,
        "exactly one copy in {sent_folder} — submission filed it and the engine did not add \
         a second"
    );
    assert!(
        !s.imap_saw("APPEND"),
        "the engine must not APPEND against this provider: {:?}",
        s.imap_commands()
    );
}

/// Submission delivers to the mailbox's own address, so a send-to-self comes back.
///
/// A fake provider has no MX. The conformance suite's central move — send an encrypted message
/// to yourself, watch it arrive, decrypt it — needs submission to play that part, and six of
/// the nineteen checks depend on the message existing afterwards. This is that loop through the
/// engine's public API: `send` out over SMTP, `sync` back in over IMAP.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_sent_to_yourself_is_delivered_and_comes_back_over_imap() {
    let mut q = Quirks::for_provider(ProviderId::Fastmail);
    q.auth = SimAuth::Password("fastmail-app-pw".into());
    assert_eq!(
        q.account, EMAIL,
        "the fake serves the address the test uses"
    );
    let sim = ProviderSim::start_with(q).await.unwrap();
    let (_dir, engine) = engine_on(&sim).await;

    let rep = engine
        .send(
            EMAIL,
            Draft {
                to: vec![EMAIL.to_string()],
                subject: "to myself".into(),
                text: "and back again\n".into(),
                policy: SendPolicy::AllowPlaintext,
                ..Draft::default()
            },
        )
        .await
        .expect("send to self");

    assert_eq!(sim.count("INBOX"), 1, "submission delivered it");
    let report = engine.sync(EMAIL).await.expect("sync");
    let inbox = report
        .folders
        .iter()
        .find(|f| f.name == "INBOX")
        .expect("INBOX in the report");
    assert_eq!(inbox.new, 1, "{report:?}");
    let stored = engine
        .list_messages(ListQuery {
            account: Some(EMAIL.into()),
            limit: 100,
            ..ListQuery::default()
        })
        .expect("list");
    assert_eq!(stored.len(), 1, "{stored:?}");
    assert_eq!(stored[0].folder, "INBOX");
    assert_eq!(stored[0].subject.as_deref(), Some("to myself"));
    assert_eq!(
        stored[0].message_id.as_deref(),
        Some(rep.message_id.as_str()),
        "the row is the message we sent, not a lookalike"
    );
    // And the Sent copy is on the server too, appended by the engine because this provider
    // does not file one itself.
    let sent = sim.state.lock().unwrap().quirks.sent_folder();
    assert!(!sim.state.lock().unwrap().quirks.smtp_saves_sent);
    assert_eq!(sim.count(&sent), 1);

    // Mail to anyone else is accepted and goes nowhere: submission has it, the mailbox does not.
    engine
        .send(
            EMAIL,
            Draft {
                to: vec!["someone@elsewhere.test".to_string()],
                subject: "outbound".into(),
                text: "away\n".into(),
                policy: SendPolicy::AllowPlaintext,
                ..Draft::default()
            },
        )
        .await
        .expect("send outbound");
    assert_eq!(sim.count("INBOX"), 1, "not delivered back to us");
    assert_eq!(sim.state.lock().unwrap().submitted.len(), 2);
}
