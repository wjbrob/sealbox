# Gate matrix — what "finished" means, and what counts as a CONFIRMED RESULT

A gate is **PASS** only when `scripts/gate.sh` ran its command and it exited 0. Results are written
to `.gate/gate_status.json` (local, gitignored). `gate.sh` must stay honest: no gate may be marked
PASS by editing JSON.

## A PASS names a tree (provenance)

Every record `gate.sh` writes carries `commit` and `dirty` alongside `status`, and
`.gate/gate_status.json` carries the run's `head`. Gates that did not run this time are merged
forward **keeping their own older stamp**, and the summary line says so:

```
31/35 gates PASS: G0 G1 …   (34 recorded on an older tree: G0 G1 G2 …)
tree 4bbfbaed3a0c  [DIRTY TREE — describes no commit]
```

This matters because a total without a tree is not a claim about anything. On 2026-10-29,
`8c19bec` — the autosave of a session stopped mid-flight, labelled unverified WIP in its own
commit message — carried a live mutation-test mutant (`return; // MUTATION` at the top of
`MessageBody._markUnshown`). Master kept it for two weeks while the status file still read
green, because nothing recorded which tree the green described. Read a carried-forward row as
"this passed on *that* commit", never as "this passes".

| Gate | Claim | Command (run by gate.sh) | Needs human? |
|---|---|---|---|
| G34 | **tree is gateable** — the run describes a known tree: no mutation/debug marker in source (`// MUTATION`, `XXX-MUTANT`, `DO NOT COMMIT`, comment-anchored and scoped to source paths, because prose legitimately discusses past mutants), HEAD is not an unverified autosave lacking a `Gated: <sha>` trailer, and the working tree is clean. **FAIL** for a marker or an unverified autosave — both make every other PASS meaningless. **NEEDS_HUMAN** for a dirty tree: the run happened and the records carry `dirty=true`, but it describes no commit, so commit or stash and re-run. Runs first and costs under a second | `scripts/gate_tree.sh` | no |
| G0 | workspace builds, fmt + clippy clean, unit tests pass — **and the same for `app/rust`**, the flutter_rust_bridge glue crate, which is a separate cargo workspace (`app/rust/Cargo.toml` carries its own empty `[workspace]`) and so is invisible to `--workspace`. `gate_flutter.sh` did run fmt/clippy/test there, but G9 is `docker=1` and therefore skipped by `--quick`, leaving the bridge crate unchecked on every quick run. Includes `tests/bridge_fingerprint.rs` — see **The bridge surface is pinned** below | `cargo fmt --all --check && cargo clippy --workspace -q --all-targets -- -D warnings && cargo test --workspace -q` then the same three with `--manifest-path app/rust/Cargo.toml`. Both clippy runs are `--all-targets`: without it the workspace's test and example targets were never linted | no |
| G1 | OpenPGP core: keygen, encrypt+sign, decrypt+verify; **interop both directions with gpg, with RNP (the OpenPGP engine inside Thunderbird) and with Sequoia `sq`** (`tests/interop_rnp_sq.rs`, added day 2: each oracle decrypts + verifies a Sealbox message and Sealbox decrypts + verifies theirs; tamper → integrity failure; unknown signer never reported Good; RNP opens our Autocrypt Setup Message with the setup code and we open an RNP-made one; host prerequisite `sudo apt-get install rnp sq`); Autocrypt header round-trip | `cargo test -p sealbox-crypto --test gate_g1 && cargo test -p sealbox-crypto --test interop_rnp_sq -- --ignored` | no |
| G2 | PGP/MIME: build `multipart/encrypted` + `multipart/signed` per RFC 3156, protected Subject, parse back; mail-parser round-trip | `cargo test -p sealbox-mail --test gate_g2` | no |
| G3 | Transport: SMTP submit + IMAP fetch of the same message against local GreenMail (docker) | `testing/mail_up.sh && cargo test -p sealbox-mail --test gate_g3 -- --ignored` | no |
| G4 | **E2E encrypted mail**: Alice→Bob encrypted through GreenMail; Bob decrypts via `sealbox` CLI; Bob replies and Alice decrypts; Autocrypt bootstraps Bob's key from Alice's first mail | `testing/mail_up.sh && cargo test -p sealbox-cli --test gate_g4 -- --ignored` | no |
| G5 | Autodiscover: Gmail/Outlook/Hotmail/Yahoo/iCloud/Fastmail/Zoho/GMX resolved offline from the built-in table; ISPDB + SRV for an unknown domain (network) | `cargo test -p sealbox-mail --test gate_g5` | no |
| G6 | OAuth2: XOAUTH2 SASL string + PKCE flow unit-tested; **real Gmail/Outlook login** (confirmed only against a real account) | `cargo test -p sealbox-mail --test gate_g6` (+ manual real-account run, gate G21) | yes: OAuth client IDs |
| G7 | Server: key upload → email challenge → verified lookup; guest message post/fetch; viewer decrypts in a headless browser | `cargo test -p sealbox-server --test gate_g7` | no |
| G8 | CLI desktop client: `sealbox account add/sync/list/read/send` works end to end against GreenMail | `testing/mail_up.sh && cargo test -p sealbox-cli --test gate_g8 -- --ignored` | no |
| G9 | Flutter: `flutter analyze` + `flutter test` pass; **Linux desktop build succeeds**; FRB bridge call into core (keygen) works | `scripts/gate_flutter.sh` | no |
| G10 | Android debug APK builds | `scripts/gate_android.sh` | no (needs ~6 GB SDK install) |
| G11 | iOS build via CI macOS runner | documented pipeline + a green run | yes: Apple dev account, GitHub repo |
| G12 | **Real world**: encrypted mail from a real Gmail/Outlook account through Sealbox, decrypted by Thunderbird/Proton on the other side (the engine-level half — RNP, Thunderbird's OpenPGP engine, decrypting and verifying Sealbox mail and opening our Setup Message — is machine-proven by G1; the UI + real-provider half is the five-minute recipe in `docs/INTEROP.md`) | manual, evidence in `.gate/reports/` | yes: test accounts |
| G13 | Security: `docs/THREAT_MODEL.md` complete (8 required sections, adversaries A1–A8, no stub markers); libFuzzer harnesses (`fuzz/`, nightly + ASan, built with `cargo fuzz build -O` so debug assertions stay on for every crate except `mail-parser` 0.11, whose `debug_assert!` on a malformed nested `message/rfc822` is a documented waiver — release builds recover) for the untrusted-input parsers — PGP/MIME, OpenPGP message decrypt/verify, Autocrypt header, guest envelope, autoconfig XML — 5 targets × 126 s = **≥ 600 s of fuzzing in total** (parallel by default, ~130 s wall; `SEALBOX_FUZZ_PARALLEL=0` for sequential) with no crash/timeout/leak, seeds replayed by `seedgen --check`; gitleaks 8.30 over the history (minus the review loop's screenshot JSONs, `SEALBOX_GITLEAKS_FULL_HISTORY=1` for everything) **and** the tracked+untracked tree with a path-scoped, reason-annotated allow-list (`.gitleaks.toml`) and a run-time canary that must be detected; `cargo audit` informative (triage in the threat model, R13). Day-2 first pass found and fixed: an rPGP panic on unknown SEIPDv2 AEAD modes (remote crash of the sync loop), unbounded decompressed plaintext, SKESK/Argon2 work amplification, OAuth host confusion in autoconfig (`imap.evilgmail.com` ≠ Gmail) | `scripts/gate_security.sh` (gate timeout 2400 s; cold ASan build ≈ 60 s) | no |
| G14 | PQC hybrid (ML-KEM-768 + X25519) encrypt/decrypt round-trip (rPGP 0.21 ships it behind the `pqc` feature, which stays **off** in the product build until gpg/Thunderbird interoperate; the gate test declares `required-features = ["pqc"]` so G0 still builds without it) | `cargo test -p sealbox-crypto --features pqc --test gate_g14` | no |
| G15 | **Recovery & multi-device**: 12-word recovery phrase → client-encrypted backup to the server; new-device restore returns keys, contacts and settings and decrypts old mail; Autocrypt Setup Message export/import; guest-link resend policy | `testing/mail_up.sh && cargo test -p sealbox-cli --test gate_g15 -- --ignored` | no |
| G16 | Push relay prototype: IMAP IDLE → content-free push (`sealbox-relay`, a separate crate + process holding the IDLE sessions; proven against GreenMail users u76–u80) | `testing/mail_up.sh && cargo test -p sealbox-relay --test gate_g16 -- --ignored` | later: APNs/FCM creds |

### The bridge surface is pinned (part of G0)

`frb_generated.dart` carries a `rustContentHash`, which reads like a pin on the Rust side and is
not one: it does not move when a field of a bridged DTO is renamed, retyped or added. A stale
generated bundle then marshals the old layout against the new library and mis-decodes at run
time — no build error, no test failure, wrong data in the UI.

`app/rust/tests/bridge_fingerprint.rs` pins the shape itself. It parses `app/rust/src/api/*.rs`,
canonicalises every bridged item (each `pub struct`'s fields with their types in declaration
order, each `pub enum`'s variants, every bridged `pub fn` and inherent method signature — 720
lines today), SHA-256s the list and asserts it equals the committed `app/rust/bridge.fingerprint`.
Trait impls are excluded: every `impl From<sc::X> for X` in that tree is internal conversion glue
Dart never sees. It then cross-checks the generated Dart in both directions: a member present in
Rust and absent from `app/lib/src/rust/api/<module>.dart` fails, a bridged type with no Dart
declaration at all fails (`Engine` is allowlisted — it crosses as an opaque handle), and a Dart
class with no Rust counterpart fails. That last pair is what `rustContentHash` cannot do.

When the fingerprint fires legitimately: re-run codegen (`cd app && flutter_rust_bridge_codegen
generate`) and write the computed hash into `app/rust/bridge.fingerprint` in the same commit. The
canonical list is printed by the test and written to `app/rust/target/bridge_api.txt`, so a
failure can be diffed rather than guessed at.

Verified by mutating the tree, four ways (2026-11-17): a field added to `AccountInfo` fails the
fingerprint; the fingerprint then updated without re-running codegen fails the Dart cross-check,
naming `AccountInfo.mutation_probe`; a `class Ghost` appended to the generated Dart fails as an
orphan; a new `pub struct GhostDto` that never reached Dart fails as undeclared.

### G35 — the mailbox converges with the server

| Gate | Claim | Command (run by gate.sh) | Needs human? |
|---|---|---|---|
| G35 | **Mailbox convergence**: a sync no longer only adds. Stored UIDs the server no longer lists are dropped, flags that changed elsewhere are followed, an emptied folder empties locally, `\Recent` is never mistaken for drift, a backfill pass stays quiet, and a broken `UID SEARCH` deletes nothing. Unit tests against the in-process fake IMAP server plus an e2e on GreenMail **u81/u82** where a second IMAP session expunges one message and reads another (`cli_reconcile.rs`); app side `inbox_convergence_test.dart` | `cargo test -p sealbox-core --lib -q reconcile && cargo test -p sealbox-core --lib -q window_tests && testing/mail_up.sh && cargo test -p sealbox-cli --test cli_reconcile -q -- --ignored` | no |

**Why it was the most serious defect in the tree.** `sync.rs` read `FLAGS` only inside the body
fetch of *new* UIDs, and nothing removed a local message whose UID had vanished
(`delete_message` / `update_flags` were called only from user actions and filters). Mail deleted
elsewhere stayed for ever, mail read elsewhere stayed bold, an emptied Trash stayed full — and
the product's premise is the mailbox you already have, used *alongside* webmail and the phone.

**Deletion is driven by `UID SEARCH`, not by the flags fetch.** A `UID FETCH (FLAGS)` that
answers for none of the UIDs it was asked about looks, from the reply alone, exactly like "all of
them are gone" — and that is an ordinary state of affairs (we hold UID 1; another client expunged
it and appended UID 2, which we have never fetched), so it cannot be rejected as a protocol
failure either. The first implementation here coupled the two and the e2e caught it: it refused a
legitimate convergence. So the two questions are now asked separately — *which UIDs exist* of one
`UID SEARCH UID 1:*` (whose empty-answer failure mode is caught by the guard shared with
`sync_folder_counted`: empty for a mailbox the server says holds messages is an error and nothing
is deleted), and *what the flags are* of `UID FETCH (FLAGS)` over the survivors, whose worst
failure now costs a missed flag update rather than a message.

**Cost.** A sync that backfills shares the backfill's `UID SEARCH UID 1:*`, so it adds nothing;
a sync or watch round with nothing to backfill adds one search, plus one flags fetch per 500
stored messages. A `watch` catch-up reconciles even when no new mail arrived, because an IDLE
round is woken by expunges and flag changes too — that is what makes "deleted in webmail" reach
a running app.

### The provider simulator (`crates/sealbox-fakeprov`)

`providers.rs` is a 919-line table of claims about Gmail, Outlook, Yahoo, iCloud, Fastmail, Zoho
and GMX — folder names, whether submission files its own Sent copy, connection limits, label
semantics, size limits, what authentication is accepted — and until now **nothing executed any of
it**. GreenMail cannot stand in: it has no SPECIAL-USE, no XOAUTH2, no labels, no size limit and
no throttling.

`sealbox-fakeprov` runs loopback IMAP, submission and OAuth2 identity servers that imitate one
named provider and share one mailbox, so a quirk is *demonstrated* rather than asserted — a
provider that files its own Sent copy really does have it in the IMAP Sent folder afterwards.
`Quirks::for_provider(id)` takes every default from `PROFILES`, and a test checks that for every
profile in the table, so editing a profile changes the fake and no second copy of our beliefs can
drift. Knobs add the hostile cases: SPECIAL-USE off, `MOVE`/`UIDPLUS` missing, truncated fetches,
throttling, `no_xoauth2`, the Outlook alias rejection, `SEARCH HEADER` refused, short token TTLs,
rotated refresh tokens, and one scripted `invalid_grant`.

Every integration test goes over a socket through Sealbox's own `ImapClient`, `SmtpClient`,
`sealbox_mail::oauth` or the whole `Engine`. That rule earned itself immediately: an `APPEND
"Sent Items" …` bug in the fake passed every unit test and was caught only by the engine
appending to a folder whose name contains a space.

**The honest limit, which governs how results from it may be written up: a simulator encodes our
beliefs.** A run that passes against it proves the engine handles what `providers.rs` claims a
provider does — never that the claim is true. Only a real account can do that, and for Yahoo
there will never be one. Say "conforms to the simulated Yahoo profile", never "works with Yahoo".

### G21S — simulated provider conformance, for every provider

`crates/sealbox-cli/tests/gate_g21_sim.rs` runs the **same nineteen checks** as G21 — the same
`sealbox provider-test` code path, as a subprocess, over a socket — against the simulator, once
per `ProviderId`. No docker, no non-loopback network, ~25 s for all nine.

Two things make it worth having:

- **Expectations are computed from `PROFILES`, not written down a second time.** The Sent folder
  name each check must report, whether the Sent copy is appended or filed by submission, the
  connection budget, the Junk folder: every assertion reads the profile. Edit a profile and the
  suite moves with it.
- **`sim_case()` matches exhaustively on `ProviderId`**, so a provider cannot be added to the
  table without a case here, and a companion test checks each one also has a running test. That
  is the compile-time half of the gate.

It is also checked to be non-vacuous: withdrawing `SPECIAL-USE` from GMX makes the run FAIL, and
the test pins how — see below.

**Two findings it produced on its first run, both pinned as tests:**

1. **The special-use fallback is narrower than the table it falls back for.** With `SPECIAL-USE`
   withdrawn, the engine's name heuristics find GMX's `Gesendet` and `Entwürfe` but not
   `Gelöscht` or `Spamverdacht`, so Trash and Junk go unresolved and two checks fail — the
   folders are on the server under their German names, and `ensure_folder` cannot create them
   because they already exist. Every provider in `PROFILES` is believed to advertise
   `SPECIAL-USE`, so this is a fallback-path gap rather than a live defect.
2. **`connection_limit_3` could not pass on a single-session provider.** It asked for
   `min(cap, 3)` sessions *in addition to* the one it already holds, so on Yahoo and iCloud
   (`max_connections: 1`) it was unsatisfiable however well the engine behaved. Now it asks for
   `min(cap - 1, 3)` and says "one already held" in its detail.

A third thing the suite forced into the open: **`providers.rs`'s `max_connections` is our own
client-side budget, not a server limit.** The notes say "keep one IMAP session per account"; no
provider documents the count at which it refuses. The simulator therefore does not enforce it —
a separate `connection_hard_limit` exists for tests that want a refusal — because enforcing a
budget as a refusal manufactures failures that say nothing about any real server.

**The alias gotcha rides along in the same gate** (`crates/sealbox-cli/tests/cli_oauth_alias.rs`).
Outlook rejects `AUTHENTICATE XOAUTH2` when the `user=` is an *alias* of a mailbox rather than its
primary address, and says only `[AUTHENTICATIONFAILED]` — the same thing a wrong token gets. On a
real account that cost a day, because everything before it had worked: consent given, token
issued, and the CLI's last word was "authentication failed", which reads as if the sign-in were
the problem. The suite pins all three halves of the answer: an alias mailbox still fails (it
really cannot sign in), the CLI prints a hint that names `--user <primary address>` and says the
token *was* issued, and the same mailbox with the same token succeeds once the login is the
primary address. The predicate behind the hint is `ImapError::refused_xoauth2_identity`, which is
deliberately *grounds for a hint, not a diagnosis*: the server never says which address it wanted,
so a login that is simply wrong gets the same hint, and the CLI never invents a primary address it
cannot know. A `[UNAVAILABLE]` refusal — the server asking for a later retry — is excluded, so the
hint cannot send an owner down a blind alley.

**What a G21S pass means.** That the engine handles what we *believe* about a provider. It is not
evidence about the provider: the fake was built from the same beliefs the engine was, so this
suite cannot discover that a belief is wrong. Its evidence files are labelled `-sim-` and carry
`imap.host = 127.0.0.1`, which is the standing proof that no real mailbox was involved. G21
remains the only gate that touches reality.

Gates without a command yet report `NOT_IMPLEMENTED`; that is the daily agent's to-do list.
"Interesting results" worth a celebration even outside this table: a decrypt by a third-party
client we did not target, a measured performance win >10×, a security bug found and fixed.

## Expansion (2026-10-27, owner request): production apps, feedback loops, providers, settings features

| Gate | Claim | Command (run by gate.sh) | Needs human? |
|---|---|---|---|
| G17 | **App ↔ core wiring**: the Flutter app drives real accounts through flutter_rust_bridge → `sealbox-core`; a Linux integration test adds a GreenMail account, syncs, reads a decrypted message, sends an encrypted one, the Sent copy decrypts, reference threading names a conversation after its root, Trash / unread / publish / IDLE arm; **plus `search_drafts_test.dart`** (u66 app, u67/u68 CLI peers): search by body word (incl. one only readable after decryption) and by sender, open a hit; compose → autosaved draft → Drafts chip → resume → send encrypted → the CLI reads it → the draft is gone. The gate empties u01/u02/u66–u68 first (`testing/gm_expunge.py`) and dumps the app + engine state on a timeout | `scripts/gate_g17.sh` | no |
| G18 | **Desktop production + feedback loop**: Linux *release* bundle built and packaged (tar.gz with .desktop + icon; AppImage if tooling present); `scripts/review_desktop.sh` drives every screen under Xvfb, captures PNGs + an HTML contact sheet into `review/desktop/<date>/`, and a 60 s scripted session has no crash or error log | `scripts/gate_g18.sh` | no |
| G19 | **Mobile feedback loop**: headless Android emulator (KVM) boots, the debug APK installs, an on-device integration smoke test passes, `scripts/review_android.sh` captures per-screen PNGs into `review/android/<date>/` | `scripts/gate_g19.sh` | no |
| G20 | **UI/UX test suite**: golden tests for every screen × {phone, desktop} × {light, dark}; accessibility guidelines (text contrast, tap targets, labelled controls) pass; end-to-end flow test onboarding → inbox → compose → send → read; `review/<date>/REVIEW.md` findings from the visual review are tracked to closure | `scripts/gate_g20.sh` | no |
| G21 | **Provider conformance**: `sealbox provider-test --account A` runs login (OAuth or app password), special-use folders, encrypted send-to-self, sync, Sent copy, IDLE, dedupe of provider auto-saved Sent, quirks; OAuth `account add --oauth google\|microsoft` loopback flow with refresh in the engine. PASS requires evidence for **Gmail, Outlook/Hotmail, Yahoo, iCloud** (real accounts in `.gate/providers.local.env`); otherwise the suite reports SKIP and the gate stays open | `scripts/gate_g21.sh` | yes: accounts + OAuth client ids |
| G22 | **Hosted mailbox (optional new address)**: onboarding offers "Create a new Sealbox address"; the backend provisions it on the Stalwart mail server (docker) with abuse controls; the client auto-configures, generates keys, and encrypted send/receive works end to end | `scripts/gate_g22.sh` | production only: domain + DNS |
| G23 | **Signatures**: per-account signature (text + sanitised HTML), applied on compose/reply/forward (above quoted text), editable in settings (UI + CLI) | `cargo test -p sealbox-cli --test gate_g23 -- --ignored` | no |
| G24 | **Holiday / out-of-office auto-reply** (RFC 3834): date range + message, at most one reply per sender per period, suppressed for lists/bounces/auto-submitted/no-reply/own addresses, encrypted when the sender has a key, runs from sync/watch; settings UI + CLI; GreenMail e2e | `cargo test -p sealbox-cli --test gate_g24 -- --ignored` | no |
| G25 | **Spam detection + filtering**: `sealbox-spam` crate (header/auth-results rules + per-user Bayesian classifier with learn-from-feedback + optional DNSBL) and user filter rules (sender/subject/list → move/label/mark); Spam folder; precision ≥ 0.98 and recall ≥ 0.85 on a held-out public corpus; settings UI + CLI | `scripts/gate_g25.sh` | no |
| G26 | **Release engineering**: single version source, release builds (Linux bundle, Android APK + AAB signed with a *test* keystore), CI workflows for Linux/Android/macOS/iOS/Windows, CHANGELOG, privacy policy, log-redaction audit | `scripts/gate_release.sh` | store signing later |
| G27 | **Secrets at rest**: secret keys, tokens and bodies wrapped with a keystore-derived key (desktop keyring / Android Keystore / iOS Keychain), app lock, OAuth refresh inside the engine | `scripts/gate_g27.sh` | no |

### Shared test-mailbox allocation (GreenMail users `uNN`, password `uNNpw`)
| Workstream | Users |
|---|---|
| app wiring + desktop loop (G17/G18/G20) | u01–u05 |
| Android loop + release (G19/G26) | u06–u10 |
| core settings features (G23/G24) | u11–u20 |
| spam + filters (G25) | u21–u25 |
| providers + OAuth (G21) | u26–u30 |
| hosted mailbox (G22, Stalwart) | u31–u35 |
| daily agent scratch | u36–u40 (alice/bob/carol stay for G3/G4/G8) |

### Visual review loop (the agent performs it, every day)
`scripts/review_desktop.sh` and `scripts/review_android.sh` write PNGs + `index.html` under `review/<platform>/<date>/`.
Open the PNGs (the Read tool renders images), write `review/<date>/REVIEW.md` (issue · screen · severity · fix),
fix the top items, re-capture, and only then close the finding. Golden images live in `app/test/goldens/`.

## Second expansion wave (2026-10-27 evening): security fixes and identity

| Gate | Claim | Command (run by gate.sh) | Needs human? |
|---|---|---|---|
| G27 | **Secrets at rest**: secret keys, credentials, OAuth tokens, bodies and attachments wrapped with a key from the OS keyring / Android Keystore / iOS Keychain (passphrase fallback); wrong key ⇒ `ProfileLocked`; existing profiles migrate; app lock in the UI | `scripts/gate_g27.sh` | no |
| G28 | **Browser extension phase**: the crypto + MIME core compiled to WebAssembly round-trips with gpg; MV3 extension builds and lints (Gmail through the documented Gmail API, DOM only for buttons); headless Chromium loads it against a webmail fixture and encrypts/decrypts; Outlook Office.js add-in manifest validates | `scripts/gate_g28.sh` | real Gmail/Outlook: OAuth client of type "Chrome extension" |
| G29 | **Guest-link modes (security fix)**: default notification carries **no secret**; `one-click` puts the secret in the URL fragment only when the sender opted in and the mail says so; `email-code` gates the ciphertext behind a one-time code mailed to the recipient; viewer handles all three; expired link refused; resend works — proven with server + CLI + headless viewer | `scripts/gate_g29.sh` | no |
| G30 | **Identity**: key-change alerts (new key for a known sender flagged on message + contact until acknowledged/verified), verified contacts via fingerprint/QR payload, **key-transparency log** for the directory (signed tree heads, inclusion + consistency proofs verified client-side, substitution detected in a test) | `scripts/gate_g30.sh` | no |

### Mailbox allocation for this wave (GreenMail `uNN`/`uNNpw`, now u01–u80)
| Builder | Users |
|---|---|
| guest-link modes (G29) | u41–u45 |
| secrets at rest (G27) | u46–u50 |
| identity + key transparency (G30) | u51–u55 |
| recovery (G15) | u56–u60 |
| browser extension (G28) | u61–u65 |
| app (UI for all of the above) | u66–u70 |
| daily agent scratch | u71–u80 |

## Third wave (2026-10-29, day 2 continuation): finishing the app for a real mailbox

| Gate | Claim | Command (run by gate.sh) | Needs human? |
|---|---|---|---|
| G31 | **Safe HTML mail**: `sealbox_mail::html::sanitize` (ammonia allow-list, remote images counted/blocked, links http/https/mailto only, no scripts/forms/frames/CSS fetches, iterated to a fixed point, cost clamp on parser depth) passes a 28-vector XSS corpus; an HTML-only mail parses with `text: None, html: Some`; `sealbox read --html` / `--load-images` against GreenMail shows the sanitized part. The fuzz target `html_sanitize` runs in G13; the app's `MessageBody` (blocked-images banner, link confirmation, show-as-text) is covered by G9/G20 goldens + widget tests | `cargo test -p sealbox-mail --lib html && cargo test -p sealbox-mail --lib mime::parse && testing/mail_up.sh && (empty u71/u72 INBOX+Sent with testing/gm_expunge.py) && cargo test -p sealbox-cli --test cli_read_html -- --ignored` | no |
| G32 | **Search + saved drafts**: in-memory FTS5 index (bodies are sealed at rest, nothing plaintext on disk; lazily built, 10k messages searched in ≈130 ms release), `Engine::search`; drafts table with subject/body in `vault::WRAPPED` (rewrap + migration tested), `save/list/get/delete/send_draft`; CLI `search` and `draft …`; e2e on GreenMail u73–u75. **Drafts on the server (2026-10-29)**: each draft has one copy in the account's Drafts role folder, PGP/MIME encrypted and signed to the account's own key only (protected subject, placeholder outside, `\Draft`, `X-Sealbox-Draft: <uuid>`), replaced on every save (APPEND, then delete + expunge the old UID), removed on send / delete; `draft sync` (and a Drafts role sync) imports what the same key saved elsewhere — e2e `cli_draft_sync` on u73–u74: one unreadable-to-the-server copy, still one after a re-save, a second profile with the key imports it with the attachment bytes intact, a profile with another key cannot read it, send removes it. App side (search screen, Drafts chip, compose autosave, Cc) lands with the searchui builder and is covered by G9/G20 + its integration test | `cargo test -p sealbox-core --lib search && cargo test -p sealbox-core --lib drafts && testing/mail_up.sh && cargo test -p sealbox-cli --test cli_search_drafts -- --ignored && cargo test -p sealbox-cli --test cli_draft_sync -- --ignored` | no |
| G33 | **Sync at scale**: against the `mail-perf` GreenMail (compose profile `perf`, 10,000 seeded messages, release CLI) the first sync stores the newest window within 4.5 s (first batch within 2 s — the app shows mail after ~1.2 s instead of after the whole mailbox), the full 10k sync completes within 45 s (phase 1: 276–321 s), incremental and `list` latency bounded; threading by index (`message_refs`), newest-first window + `floor_uid` backfill, 200-message pipelined batches, keys reloaded only when the store's key generation moved, one transaction per batch, stored snippet + list index. Thresholds and the measured table: `docs/PERFORMANCE.md` §G33 | `testing/mail_perf_up.sh && scripts/perf_sync.sh --gate` | no |

G35's mailboxes: **u81** (the full convergence e2e) and **u82** (`sealbox reconcile` on its own) —
one each because cargo runs the two tests concurrently and each empties its mailbox to start from
a known state.

Mailboxes for this wave: htmlmail u71–u72 · searchdrafts u73–u75 · searchui u66–u70 · relay gate u76–u80 · perf: its own `mail-perf` GreenMail (ports 3243/3125, users p01–p03) so the shared instance is never seeded with 10k messages.
Session 14 (2026-10-29): the G27 e2e's sealed-draft-attachment case (`draft_attachments_are_sealed_blobs`) and the draft-sync
work also use **u73–u74**, as G32's e2e does — G27 and G32 must not run concurrently (the runner is sequential; a builder running
one by hand must not overlap the other). G31's inline-image case uses u71–u72 (cidimages).
