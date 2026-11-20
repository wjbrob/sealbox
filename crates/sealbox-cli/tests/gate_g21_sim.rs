//! Gate **G21S** — the provider-conformance suite against a simulator, for every provider.
//!
//! G21 proper needs a real mailbox and the owner's consent, so it has only ever run against
//! Gmail. This runs the same nineteen checks — the same `sealbox provider-test` code path, over
//! a socket, as a subprocess — against `sealbox-fakeprov`, once per `ProviderId`. No docker, no
//! non-loopback network.
//!
//! Two things make it worth having:
//!
//! 1. **Expectations are computed from the profile, not written down twice.** The Sent folder
//!    name a check must report, whether a Sent copy is appended or filed by submission, the
//!    connection budget, the Junk folder — each assertion reads `PROFILES`. Edit a profile and
//!    this suite changes with it; get a profile wrong and the engine's behaviour against the
//!    fake changes too, so the two stay in step by construction rather than by diligence.
//! 2. **[`sim_case`] matches exhaustively on `ProviderId`,** so a provider cannot be added to
//!    the table without a case here. That is the compile-time part of the gate.
//!
//! **What a pass here does and does not mean.** It means the engine handles what `providers.rs`
//! *claims* a provider does. It is not evidence about the provider. The fake was built from the
//! same beliefs the engine was, so this suite cannot discover that a belief is wrong — only a
//! real account can, and for Yahoo there will never be one. Evidence written here says
//! "conforms to the simulated <provider> profile" and never "works with <provider>".
//!
//! Run with `cargo test -p sealbox-cli --test gate_g21_sim`.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use common::Profile;
use sealbox_core::providers::{profile, AuthRequirement, ProviderId, ProviderProfile};
use sealbox_fakeprov::quirks::{SimAuth, DEFAULT_ACCOUNT};
use sealbox_fakeprov::{ProviderSim, Quirks};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Why a provider is in this suite, and the expectations that are specific to it rather than
/// derivable from its profile.
struct SimCase {
    /// What this provider is here to demonstrate. Shown on failure, so a reader of a red test
    /// knows what was supposed to be interesting about it.
    why: &'static str,
    /// `(check name, fragment that must appear in its detail)`.
    details: &'static [(&'static str, &'static str)],
}

/// **Exhaustive on purpose.** Adding a `ProviderId` without a case here is a compile error, so
/// a new provider cannot reach users with no conformance evidence at all.
fn sim_case(id: ProviderId) -> SimCase {
    match id {
        ProviderId::Gmail => SimCase {
            why: "labels rather than folders, `[Gmail]/…` names, OAuth-only, and submission \
                  files its own Sent copy — the one provider where an APPEND would duplicate",
            details: &[
                ("auth_method", "oauth provider=google"),
                ("special_use_folders", "junk=[Gmail]/Spam"),
                ("sent_copy_single", "appended_by_us=false"),
            ],
        },
        ProviderId::Outlook => SimCase {
            why: "OAuth via Microsoft, `Sent Items` with a space in the name (which once broke \
                  the fake's own APPEND parser), and submission files its own copy",
            details: &[
                ("auth_method", "oauth provider=microsoft"),
                ("special_use_folders", "sent=Sent Items"),
                ("sent_copy_single", "appended_by_us=false"),
            ],
        },
        ProviderId::Yahoo => SimCase {
            why: "the only Yahoo evidence that will ever exist: app-password only, `Bulk Mail` \
                  as the Junk folder, and a one-session budget",
            details: &[
                ("auth_method", "password/app-password account"),
                ("spam_folder_detection", "junk=Bulk Mail"),
                // Budget 1: holding one session leaves room for no extras, and the check must
                // say so rather than demand one.
                (
                    "connection_limit_3",
                    "profile cap 1, one already held; 0 needed",
                ),
            ],
        },
        ProviderId::Icloud => SimCase {
            why: "app-password only, `Sent Messages` / `Deleted Messages` (neither matches the \
                  English name heuristics), and a one-session budget",
            details: &[
                ("special_use_folders", "sent=Sent Messages"),
                ("move_to_trash_and_back", "to Deleted Messages"),
                (
                    "connection_limit_3",
                    "profile cap 1, one already held; 0 needed",
                ),
            ],
        },
        ProviderId::Fastmail => SimCase {
            why: "app password, plain English folder names, client-appended Sent copy — the \
                  least surprising provider, and so the control",
            details: &[("sent_copy_single", "appended_by_us=true")],
        },
        ProviderId::Zoho => SimCase {
            why: "no Archive folder at all, which exercises the engine's missing-role fallback",
            details: &[(
                "connection_limit_3",
                "profile cap 4, one already held; 3 needed",
            )],
        },
        ProviderId::Gmx => SimCase {
            why: "localised folder names (`Gesendet`, `Gelöscht`, `Spamverdacht`): a client that \
                  matches on English names finds nothing, so this is the special-use test",
            details: &[
                ("special_use_folders", "sent=Gesendet"),
                ("spam_folder_detection", "junk=Spamverdacht"),
                ("move_to_trash_and_back", "to Gelöscht"),
            ],
        },
        ProviderId::Greenmail => SimCase {
            why: "the local test server's own profile, so the simulated and docker halves of \
                  G21 are checked against the same expectations",
            details: &[("auth_method", "password/app-password account")],
        },
        ProviderId::Generic => SimCase {
            why: "the neutral profile an unknown company IMAP server falls back to",
            details: &[("special_use_folders", "sent=Sent")],
        },
    }
}

// ---------------------------------------------------------------------------------------------
// Running the real CLI against a fake
// ---------------------------------------------------------------------------------------------

/// Start a fake of `id` and run the whole conformance suite against it through the CLI.
///
/// The profile comes back with the result because it owns the temporary directory the evidence
/// file was written into: drop it and the evidence is gone before it can be read.
async fn run_suite(id: ProviderId) -> (Profile, Value) {
    let (prof, v, ok) = run_suite_with(id, |_| {}).await;
    assert!(ok, "provider-test exited non-zero: {v}");
    (prof, v)
}

/// As [`run_suite`], with the fake's quirks adjusted first — for asking what happens when a
/// provider does *not* behave the way its profile says.
async fn run_suite_with(id: ProviderId, tune: impl FnOnce(&mut Quirks)) -> (Profile, Value, bool) {
    let p = profile(id);
    let mut quirks = Quirks::for_provider(id);
    tune(&mut quirks);
    let sim = ProviderSim::start_with(quirks)
        .await
        .expect("start the fake");
    // A little mail already in the mailbox, so the first sync is not a no-op and the backfill
    // path runs the way it does on a real account.
    sim.seed_inbox(3);

    let prof = Profile::new(&format!("g21sim-{}", id.as_str()));
    let imap = format!("127.0.0.1:{}:plain", sim.imap_port);
    let smtp = format!("127.0.0.1:{}:plain", sim.smtp_port);

    match p.auth {
        AuthRequirement::OAuth2 => add_oauth_account(&prof, &sim, id, &imap, &smtp).await,
        AuthRequirement::AppPassword | AuthRequirement::Password => {
            let pass = match sim.state.lock().unwrap().quirks.auth.clone() {
                SimAuth::Password(pw) => pw,
                SimAuth::XOAuth2 => unreachable!("a password profile's fake wants a password"),
            };
            let v = prof.json(&[
                "account",
                "add",
                "--email",
                DEFAULT_ACCOUNT,
                "--name",
                "Sim Tester",
                "--password",
                &pass,
                "--imap",
                &imap,
                "--smtp",
                &smtp,
                "--provider",
                id.as_str(),
            ]);
            assert_eq!(v["email"], DEFAULT_ACCOUNT, "{v}");
        }
    }

    // The stated provider is what makes this possible at all: by host, a fake on 127.0.0.1 is
    // Greenmail, so before `account set-provider` existed the suite could not be pointed at one.
    {
        let engine = prof.engine();
        assert_eq!(
            engine.account_provider(DEFAULT_ACCOUNT).expect("provider"),
            Some(id),
            "the account must be tested against {}'s profile, not the host guess",
            id.as_str()
        );
        assert_eq!(
            engine
                .provider_profile(DEFAULT_ACCOUNT)
                .expect("profile")
                .id,
            id
        );
    }

    let evidence = prof.path().join("evidence");
    // `run`, not `json`: a failing check exits 1, and a run that is *supposed* to fail still
    // has to be readable.
    let r = prof.run(&[
        "--json",
        "provider-test",
        "--account",
        DEFAULT_ACCOUNT,
        "--evidence-dir",
        evidence.to_str().unwrap(),
        // 1 MiB keeps the round trip honest (it is a real PGP encrypt, SMTP upload, IMAP fetch
        // and decrypt) without 5 MiB of CPU per provider.
        "--attachment-mib",
        "1",
        "--arrival-timeout",
        "30",
        "--label",
        "sim",
    ]);
    let v = r.json();
    assert_eq!(v["provider"], id.as_str(), "{v}");
    (prof, v, r.code == 0)
}

/// `account add --oauth …` against the fake's own identity provider, playing the browser.
///
/// The same loopback PKCE flow `gate_g21_local` drives, pointed at the simulator's IdP: the
/// access token it issues is one the fake's IMAP and submission accept, so the account reaches
/// the provider the way a real OAuth account does — `AUTHENTICATE XOAUTH2`, never a password.
async fn add_oauth_account(
    prof: &Profile,
    sim: &ProviderSim,
    id: ProviderId,
    imap: &str,
    smtp: &str,
) {
    let oauth_provider = match id {
        ProviderId::Gmail => "google",
        ProviderId::Outlook => "microsoft",
        other => panic!("{} is not an OAuth provider", other.as_str()),
    };
    let mut cmd = prof.cmd(&[
        "--json",
        "account",
        "add",
        "--email",
        DEFAULT_ACCOUNT,
        "--name",
        "Sim Tester",
        "--oauth",
        oauth_provider,
        "--client-id",
        "sealbox-sim-client",
        "--imap",
        imap,
        "--smtp",
        smtp,
        "--provider",
        id.as_str(),
        "--oauth-timeout",
        "60",
    ]);
    cmd.env("SEALBOX_OAUTH_AUTH_URL", sim.idp.auth_url())
        .env("SEALBOX_OAUTH_TOKEN_URL", sim.idp.token_url())
        .env_remove("GOOGLE_OAUTH_CLIENT_SECRET")
        .env_remove("MICROSOFT_OAUTH_CLIENT_SECRET")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = tokio::process::Command::from(cmd)
        .kill_on_drop(true)
        .spawn()
        .expect("spawn account add --oauth");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();

    let start = next_event(&mut lines, "oauth_start").await;
    let url = start["url"].as_str().expect("url").to_string();
    assert_eq!(start["endpoints_overridden"], true, "{start}");

    // Act as the browser: the IdP redirects back to the CLI's loopback listener with a code.
    let (status, headers, _) = http_get(&url).await;
    assert!(status.starts_with("HTTP/1.1 302"), "{status}");
    let (status, _, body) = http_get(&headers["location"]).await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(body.contains("Sealbox"), "{body}");

    let added = next_event(&mut lines, "account_added").await;
    let exit = child.wait().await.expect("wait");
    assert!(exit.success(), "account add --oauth failed: {exit:?}");
    assert_eq!(added["account"]["email"], DEFAULT_ACCOUNT, "{added}");
    assert_eq!(added["account"]["auth_kind"], "o_auth", "{added}");
    assert_eq!(added["oauth"]["has_refresh_token"], true, "{added}");
    assert_eq!(
        added["oauth"]["dev_hosts_allowed"], true,
        "a loopback test IdP's token may reach a local host, and only then: {added}"
    );
}

/// Read the CLI's JSON event stream until the named event, failing loudly on an error event.
async fn next_event<R>(lines: &mut tokio::io::Lines<BufReader<R>>, want: &str) -> Value
where
    R: tokio::io::AsyncRead + Unpin,
{
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let line = lines
                .next_line()
                .await
                .expect("read stdout")
                .expect("stdout closed before the event arrived");
            if !line.trim_start().starts_with('{') {
                continue;
            }
            let v: Value = serde_json::from_str(&line).expect("json line");
            if v["event"] == want {
                return v;
            }
            assert!(v.get("error").is_none(), "account add failed: {v}");
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for the `{want}` event"))
}

/// Minimal HTTP GET, playing the browser in the OAuth flow. Returns (status line, headers,
/// body). `gate_g21_local` has its own copy from before this file existed.
async fn http_get(url: &str) -> (String, HashMap<String, String>, String) {
    let rest = url.strip_prefix("http://").expect("http url");
    let idx = rest.find(['/', '?']).unwrap_or(rest.len());
    let (hostport, tail) = rest.split_at(idx);
    let path = match tail.chars().next() {
        None => "/".to_string(),
        Some('?') => format!("/{tail}"),
        _ => tail.to_string(),
    };
    let mut s = TcpStream::connect(hostport).await.expect("connect");
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .expect("write request");
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.expect("read response");
    let text = String::from_utf8_lossy(&out).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut head_lines = head.lines();
    let status = head_lines.next().unwrap_or_default().to_string();
    let headers = head_lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    (status, headers, body.to_string())
}

// ---------------------------------------------------------------------------------------------
// Expectations, computed from the profile
// ---------------------------------------------------------------------------------------------

/// The nineteen checks, in the order `provider-test` runs them. Pinned here so a check that is
/// quietly dropped fails this suite rather than passing it by absence.
const CHECKS: &[&str] = &[
    "connect_imap",
    "capabilities",
    "auth_method",
    "special_use_folders",
    "select_inbox",
    "uidvalidity_handling",
    "send_encrypted_to_self",
    "arrival_via_idle",
    "decrypt_received",
    "sent_copy_single",
    "flags_set_unset",
    "move_to_trash_and_back",
    "spam_folder_detection",
    "large_attachment_roundtrip",
    "connection_limit_3",
    "autocrypt_header_preserved",
    "protected_subject_preserved",
    "message_size_limit_probe",
    "clean_logout",
];

fn check<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no check `{name}` in {v}"))
}

fn detail(v: &Value, name: &str) -> String {
    check(v, name)["detail"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Assert a check's detail text contains `want`, which is where the provider-specific
/// behaviour actually shows up — a check can pass for the wrong reason, and the detail is the
/// only place that difference is visible.
fn says(v: &Value, name: &str, want: &str, id: ProviderId) {
    let d = detail(v, name);
    assert!(
        d.contains(want),
        "{}: {name} detail should mention `{want}`, said `{d}`",
        id.as_str()
    );
}

/// Everything expected of every provider, derived from its profile.
fn assert_conforms(v: &Value, id: ProviderId) {
    let p: &'static ProviderProfile = profile(id);
    let case = sim_case(id);
    let who = id.as_str();

    // Shape first: the whole suite ran, every check reported, nothing silently missing.
    let names: Vec<&str> = v["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .map(|c| c["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names, CHECKS, "{who}: the suite's checks changed");
    assert_eq!(
        v["result"], "PASS",
        "{who} ({}) should conform to its own simulated profile: {v}",
        case.why
    );
    for c in v["checks"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap_or_default();
        let status = c["status"].as_str().unwrap_or_default();
        // The size probe sends until something is rejected; it stays opt-in everywhere.
        let want = if name == "message_size_limit_probe" {
            "SKIP"
        } else {
            "PASS"
        };
        assert_eq!(
            status, want,
            "{who}: {name} ({}): {}",
            case.why, c["detail"]
        );
    }
    assert_eq!(v["provider_display_name"], p.display_name, "{v}");
    assert_eq!(
        v["auth_kind"],
        match p.auth {
            AuthRequirement::OAuth2 => "o_auth",
            _ => "password",
        }
    );

    // Transport and authentication.
    says(v, "connect_imap", "127.0.0.1:", id);
    says(v, "connect_imap", "PLAIN TCP (allowed: loopback", id);
    let mech = match p.auth {
        AuthRequirement::OAuth2 => "auth=XOAUTH2",
        // The client prefers `LOGIN` when the server offers it; what matters is that it is
        // not XOAUTH2 on an account that has no token.
        _ => "auth=LOGIN",
    };
    says(v, "connect_imap", mech, id);
    says(v, "capabilities", "IDLE MOVE UIDPLUS SPECIAL-USE", id);
    match p.auth {
        AuthRequirement::OAuth2 => {
            says(v, "auth_method", "imap=XOAUTH2", id);
            says(v, "auth_method", "refresh_token=true", id);
            says(v, "auth_method", "(loopback test IdP)", id);
        }
        _ => {
            says(v, "auth_method", "imap=LOGIN", id);
            says(v, "auth_method", "password/app-password account", id);
        }
    }

    // Folders: the names in the profile, resolved from SPECIAL-USE attributes rather than from
    // English-language guesses. This is the check that would fail on GMX if the engine matched
    // on names, and the reason the fake carries the localised ones.
    let f = &p.folders;
    says(v, "special_use_folders", "source=SpecialUse", id);
    for want in [
        format!("sent={}", f.sent),
        format!("trash={}", f.trash),
        format!("junk={}", f.junk),
        format!("drafts={}", f.drafts),
    ] {
        says(v, "special_use_folders", &want, id);
    }
    says(v, "spam_folder_detection", &format!("junk={}", f.junk), id);
    says(v, "spam_folder_detection", "source=SpecialUse", id);
    says(
        v,
        "move_to_trash_and_back",
        &format!("to {} via", f.trash),
        id,
    );

    // The send pipeline: encrypted to self, arriving over IDLE, decrypting, with exactly one
    // Sent copy however this provider files it.
    says(v, "send_encrypted_to_self", "message_id=<", id);
    says(
        v,
        "send_encrypted_to_self",
        &format!("sent_copy_appended={}", !p.smtp_saves_sent),
        id,
    );
    says(v, "arrival_via_idle", "uid=", id);
    says(v, "decrypt_received", "subject_protected=true", id);
    says(
        v,
        "protected_subject_preserved",
        "inner subject restored",
        id,
    );
    says(v, "autocrypt_header_preserved", "keydata byte-exact", id);
    says(v, "sent_copy_single", &format!("folder={}", f.sent), id);
    says(v, "sent_copy_single", "copies=1", id);
    says(
        v,
        "sent_copy_single",
        if p.smtp_saves_sent {
            "provider saves on submit (no APPEND)"
        } else {
            "client APPENDs"
        },
        id,
    );
    says(v, "large_attachment_roundtrip", "1 MiB blob.bin", id);

    // The connection budget, as the profile states it. One session is already held by the
    // suite, so the extras it can ask for are `cap - 1`, capped at 3.
    says(
        v,
        "connection_limit_3",
        &format!(
            "profile cap {}, one already held; {} needed",
            p.max_connections,
            p.max_connections.saturating_sub(1).min(3)
        ),
        id,
    );

    says(v, "message_size_limit_probe", "skipped by default", id);
    says(v, "clean_logout", "LOGOUT acknowledged", id);

    // Finally the provider-specific expectations of its own case.
    for (name, want) in case.details {
        says(v, name, want, id);
    }
}

/// Evidence must name the simulator. A file that reads like a real-account run is the one way
/// this suite could do harm, so the wording is asserted rather than trusted.
fn assert_evidence_is_labelled_as_simulated(v: &Value, id: ProviderId) {
    let file = v["evidence_file"].as_str().expect("evidence_file");
    assert!(
        file.contains(&format!("{}-sim-", id.as_str())),
        "evidence must be labelled `sim`: {file}"
    );
    let on_disk: Value =
        serde_json::from_slice(&std::fs::read(file).expect("read evidence")).expect("parse");
    assert_eq!(on_disk["result"], "PASS");
    assert_eq!(on_disk["account"], DEFAULT_ACCOUNT, "the fake's address");
    assert_eq!(
        on_disk["imap"]["host"], "127.0.0.1",
        "a loopback host is the standing proof that no real mailbox was touched"
    );
}

// ---------------------------------------------------------------------------------------------
// One test per provider, so a failure names the provider it is about
// ---------------------------------------------------------------------------------------------

macro_rules! sim_conformance {
    ($($name:ident => $id:expr),+ $(,)?) => {
        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn $name() {
                let (_profile, v) = run_suite($id).await;
                assert_conforms(&v, $id);
                assert_evidence_is_labelled_as_simulated(&v, $id);
            }
        )+
    };
}

sim_conformance! {
    gmail_conforms_to_its_simulated_profile => ProviderId::Gmail,
    outlook_conforms_to_its_simulated_profile => ProviderId::Outlook,
    yahoo_conforms_to_its_simulated_profile => ProviderId::Yahoo,
    icloud_conforms_to_its_simulated_profile => ProviderId::Icloud,
    fastmail_conforms_to_its_simulated_profile => ProviderId::Fastmail,
    zoho_conforms_to_its_simulated_profile => ProviderId::Zoho,
    gmx_conforms_to_its_simulated_profile => ProviderId::Gmx,
    greenmail_conforms_to_its_simulated_profile => ProviderId::Greenmail,
    generic_conforms_to_its_simulated_profile => ProviderId::Generic,
}

/// Every provider in the table has a test above. The exhaustive `match` in [`sim_case`] makes a
/// missing *case* a compile error; this makes a missing *test* a failure, which the match
/// cannot catch on its own.
#[test]
fn every_profile_has_a_simulated_conformance_test() {
    let source = include_str!("gate_g21_sim.rs");
    for p in sealbox_core::providers::PROFILES {
        let want = format!("=> ProviderId::{:?},", p.id);
        assert!(
            source.contains(&want),
            "{} has no entry in the sim_conformance! list",
            p.id.as_str()
        );
        assert!(
            !sim_case(p.id).why.is_empty(),
            "{} needs a reason for being in the suite",
            p.id.as_str()
        );
    }
}

/// **The suite is not vacuous.** Every provider above passes, which is only meaningful if a
/// provider that misbehaves would fail — so one is made to.
///
/// GMX is the case where it matters most: its folders are `Gesendet`, `Gelöscht` and
/// `Spamverdacht`, so a client that finds them by matching English names finds nothing.
///
/// Withdrawing `SPECIAL-USE` leaves the engine with only the names, and **it does not cope**:
/// the name heuristics know `Gesendet` and `Entwürfe` but not `Gelöscht` or `Spamverdacht`, so
/// Trash and Junk go unresolved and two checks fail. The folders are right there on the server
/// under their German names, and `ensure_folder` cannot create them either because they already
/// exist — so the mailbox has a Junk folder the engine cannot find.
///
/// Every provider in `PROFILES` is believed to advertise `SPECIAL-USE`, so this is not a live
/// defect; it is the fallback path being narrower than the table it falls back for. The test
/// records what happens rather than what one would prefer, which is also what makes the suite
/// above worth anything: a provider that misbehaves fails it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_provider_that_hides_its_special_use_attributes_does_not_quietly_pass() {
    let (_profile, v, ok) = run_suite_with(ProviderId::Gmx, |q| q.special_use = false).await;

    let d = detail(&v, "special_use_folders");
    assert!(
        !d.contains("source=SpecialUse"),
        "the attributes are gone, so the mapping cannot claim to come from them: {d}"
    );
    assert!(
        d.contains("unresolved roles: trash, junk"),
        "the German Trash and Junk names are not in the heuristics: {d}"
    );
    assert_eq!(
        check(&v, "special_use_folders")["status"],
        "FAIL",
        "an unresolved Trash and Junk is a failure, not a shrug: {d}"
    );
    assert!(
        detail(&v, "spam_folder_detection").contains("no Junk/Spam folder found"),
        "and the spam folder is simply lost: {v}"
    );
    // And the run as a whole does not pass: every other provider's does.
    assert!(
        !ok,
        "a GMX that hides its special-use attributes must not pass the suite: {v}"
    );
    assert_eq!(v["result"], "FAIL", "{v}");
}
