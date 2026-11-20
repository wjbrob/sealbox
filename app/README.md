# Sealbox — Flutter client (`app/`)

One Flutter codebase for iOS, Android, Linux, macOS and Windows, talking to the Rust engine
through [flutter_rust_bridge v2](https://cjycode.com/flutter_rust_bridge/). Gate **G9**
(`docs/GATES.md`) is `scripts/gate_flutter.sh`.

## What is real today, what is sample data

| Area | Status |
|---|---|
| Rust bridge (`app/rust`, crate `rust_lib_sealbox_app`) | **Real.** Depends on `sealbox-core` (path dep) and exposes it through flutter_rust_bridge 2.13: an opaque `Engine` (`Engine.open(profileDir)`) with `detectServers`, `addAccount`, `listAccounts`, `removeAccount`, `sync`/`syncAll`, `send`, `listMessages`, `getMessage`, `getAttachment`, `setFlags`, `deleteMessage`, `contacts`, `resolveRecipient`, `exportPublicKey`, `importPeerKey`, `myFingerprint`, and `watch` (IMAP IDLE) as a Dart `Stream`. DTOs mirror `sealbox_core::types` one-to-one (`rust/src/api/engine.rs`). `sealbox_version()`, `greet()`, `generate_identity_preview()` remain the start-up self-check (`[sealbox] bridge OK …`, grepped by G9). |
| Accounts, inbox, threads, read/decrypt, mark-seen, delete, attachments, compose/reply/send, recipient keys, contacts, key export/import | **Real** through `FrbCore` → engine → the account's own IMAP/SMTP servers. Gate **G17** (`scripts/gate_g17.sh`) proves it against GreenMail from the UI. |
| Reference threading | **Real.** Conversations group by the engine's `MessageSummary.thread_id` (References / In-Reply-To through the stored mail, per account): a reply with a changed subject stays in its conversation, two unrelated mails with one subject stay apart. Ids are `t-<base64url('ref\|account\|key')>`; only messages without an engine key (FakeCore samples) group by normalised subject (`threading.dart`). List rows carry `ValueKey('thread-subject-<normalised subject>')` for tests. G17 proves both cases against GreenMail. A conversation whose subject is only the provider's placeholder (`...`, `…`, empty) of mail that could not be decrypted — or was decrypted without a protected subject (`Message.protectedSubject`) — reads **"Encrypted message"** in the secondary colour, italic, in the list row and the thread header (`threading.dart` `conversationTitle` / `subjectUnreadable`; the row key keeps the raw subject; review N1). |
| Folders by role + actions | **Real.** The chips list by special-use role (`listThreadsInRole`; Inbox rows also carry the conversation's Sent replies). Spam / Trash / Archive sync themselves the first time they are opened per account per session (`syncFolder(role)`, progress bar), and say honestly what they show: "Nothing in Spam on the server" (with the folders checked) vs "not synced yet" (+ the error and *Sync now*). Pull-to-refresh and the sync button fetch the current chip's folder. Thread overflow menu: Forward, Archive, Move to Inbox (own mail back to Sent), Mark as spam / Not spam (`spamLearn`), Mark unread, Why is this spam? / Spam check; Delete (= move to Trash, Delete forever inside Trash, both confirmed). List rows: swipe right = archive (restore in Archive/Trash, Not spam in Spam), swipe left = delete (confirmed), long press = the same actions + Mark unread, also as screen-reader custom actions. Every action's snackbar names the destination folder from `MoveResult` / `SpamLearnResult`. The engine drops a moved message locally until its new folder is fetched: the app re-syncs INBOX + Sent after a restore and marks the destination chip stale. G17: delete to Trash → Trash chip; mark unread. |
| Spam & filters (G25) | **Real.** Settings → Mail handling → *Spam* (`/settings/spam?account=`): personal model status (learned counts, words, trust), per-account on/off, the *Possibly spam* / *Spam* thresholds (engine labels, unsure ≤ spam kept), DNS blocklists with "reveals sender IPs and link domains to your DNS resolver", move-to folder, allow / block lists (add, move between, remove). *Filters* (`/settings/filters?account=`): rules in evaluation order, enable switches, drag to reorder (`setFilterRules`), add / edit sheet (field, header name, condition, value, match case, action move / flag / mark read / star, then stop) with the engine's validation errors inline, remove with confirmation, *Test* against a stored message (`testFilterRules`, one row per enabled rule + the combined effect). "Why is this spam?" sheet from a thread (`spamExplain`): label + probability, reasons with weights, SPF / DKIM / DMARC, what the filter rules would do, Mark as spam / Not spam. |
| Key directory (publish) | **Real.** Settings → My key: a state chip from `directoryStatus` with the one action that moves it on — no server (disabled Publish + "Set a server URL first" → Server), not published (**Publish**), waiting for the directory's mail (**Complete verification**, "Send the mail again"), published on `<host>`, another key published (publish this one), verification failed (publish again), unreachable (error + Retry). The engine's status only says what the directory serves, so the app remembers a mailed challenge / refused link per account for the session (`directoryProgressProvider`). G17 publishes through a local `sealbox-server` whose challenge mail goes through GreenMail. |
| Server URL | **Real** (`setServerUrl` / `serverUrlSource`): Settings → Server is editable — the effective URL, then where it comes from ("Source: settings (wins over SEALBOX_SERVER_URL)" / "Source: environment (SEALBOX_SERVER_URL)" / "Source: none — set a URL below"; review N3: the line used to repeat the title), Save, Clear (back to the environment), validation errors inline; a change re-reads capabilities, backup, directory and transparency state. `/settings?section=server` scrolls to it (the guest-link panel's *Open Settings* uses it). |
| Compose preview | **Real** (`composePreview`). Reply / forward go out with `ComposeOptions.reply()` / `.forward(id)`: the engine quotes or adds the forwarded message (and its attachments) itself, so the editor holds only the new text. A collapsible *Preview* under the body (open for replies and forwards) shows exactly what will be sent — signature where the account's settings put it, quote, forwarded block, the attachments that go along — refreshed 400 ms after typing stops and at once on account / reply / forward changes. |
| Profile directory | `--dart-define=SEALBOX_PROFILE=<dir>` or the `SEALBOX_PROFILE` environment variable; otherwise `path_provider`'s application-support dir + `/profile` (`~/.local/share/sealbox_app/profile` on Linux). Same SQLite layout as the CLI, so `sealbox --profile <dir> …` can inspect an app profile (do not run both against one profile at the same time). |
| Provider detection | Built-in table (Dart mirror, instant) → the engine's network discovery (ISPDB → autoconfig → SRV → MX → probes) → manual settings. Manual settings accept `None (plain)` for local test servers. |
| OAuth sign-in | Screen exists; `FrbCore.addAccount` refuses OAuth with a clear message until the client ids exist (`docs/PROVIDERS_CONFORMANCE.md`). App passwords and manual settings work. |
| Guest links | Per-message mode selector (`GuestLinkPanel`): **Passphrase** (default, no secret in the link), **One-click** (secret in the URL fragment — "protects against the server and the network only"), **Email code** (recipient confirms a mailed code). After a send the passphrase is shown **once** with copy/share (`GuestLinkSentDialog`); the engine keeps it in the profile's `guest_links` table for resends, never on the server. **Real since the G29 bridge** (`Draft.guestMode`, `GuestLinkInfo.{mode, secretInLink, recipientVerification}`, `Engine.resendGuestLink`): `FrbCore` passes the mode and sends email-code links one recipient at a time (the code is bound to one address). Modes come from `EngineCapabilities.guestModes`; a mode an engine lacks is shown as "coming soon" and Send stays disabled until an available mode is picked explicitly (never silently weakened). A sent guest-link copy (Sent folder, unencrypted, carries a `…/g/<id>` link) shows **Resend link** (`Engine.resendGuestLink` with its Message-ID). Needs `SEALBOX_SERVER_URL`; without one the panel says "Guest links need a Sealbox server…" with *Open Settings* (L14; the variable name is only logged). |
| App lock + profile key | `lib/src/lock/`: on first launch a random 32-byte profile key is generated once and stored with `flutter_secure_storage` (Android Keystore / iOS Keychain this-device-only / libsecret / Credential Manager), namespaced per profile dir; the user sets a 6–12 digit PIN (PBKDF2-HMAC-SHA256 verifier, escalating lockout after 5 wrong PINs); `local_auth` biometrics where available; auto-lock after N minutes (background or idle; Settings → Security) and "Lock now". `main()` shows the lock before the engine opens and only then takes the key (`AppLockController.takeProfileKey`, Dart copy zeroed). **Hand-off:** `FrbCore.open(dir, profileKey:)` drops the key until the bridge has `Engine::open_with` + `ProfileKeySource::Raw` (G27); Settings says "not yet used by this engine build". Without a reachable keystore (e.g. Xvfb without Secret Service) the PIN verifier lives in `<profile>/applock.json` (0600) and **no** raw key is created. `SEALBOX_APP_LOCK=off` (define or env) skips the lock for scripted runs; integration tests that call `runSealbox` directly run without it. macOS needs a Keychain Sharing entitlement with the team id before secure storage works there (not configured: no signing team yet). |
| Identity (G30) | **Real** (`CoreIdentityOps` → `Engine.{verifyContact, unverifyContact, acknowledgeKeyChange, fingerprintQrPayload, parseFingerprintQr, ktAudit}`; `Contact.{verified, verifiedAt, keyChangedAt, previousFingerprint}`, `SignatureSummary.{keyChanged, signerVerified}`). Amber key-changed banner on a message ([Compare fingerprints] / [Accept new key]) while the contact's change is undecided, "Key changed (accepted)" chip afterwards, "✓ Verified" chip (check icon + "Verified") for a signature by the verified key; ⚠/✓ contact badges (icons: Roboto has neither glyph) and a contact screen (`/settings/contact`); Verify screen (`/settings/verify`) with a scannable `qr_flutter` QR of the own `OPENPGP4FPR:` payload, `mobile_scanner` on Android/iOS (CAMERA permission / `NSCameraUsageDescription`), paste field on desktop, manual entry grouped in fours; mismatch is refused by the engine and explained. Compose warns for recipients with an undecided key change. Settings → Security → key-transparency card: no server / not checked / verified / alert (SUBSTITUTION) / unreachable. **Signer ≠ sender (R4, `docs/THREAT_MODEL.md`):** a good signature whose key belongs to another address than From (`signerMismatch`, `core/signer_mismatch.dart`: the engine's signer address compared lower-cased and trimmed, or a contact verified under another address; not for the key verified for this sender, not between our own addresses) is an amber "signed by X — but sent by Y" chip (wraps, tooltip: the key is not the sender's, + key id), never the green chip; the inbox row keeps its lock badge — a signed-only message then reads "Not encrypted" — and adds an amber glyph (`SignerMismatchGlyph`, `thread-signer-mismatch-<thread id>`). The real loops cannot provoke a key change; the review tours use FakeCore (`SEALBOX_REVIEW=fake`, `fake-*` shots). |
| Recovery (G15) | **Real** (`Engine.{recoveryPhraseCreate, recoveryPhraseValidate, backupToServer(_with), backupStatus, restoreFromServer(_with), setAccountCredential, setupMessageExport, setupMessageImport, serverUrl}`). Settings → Security → *Recovery phrase* (show-once: blurred until tapped, not selectable, no copy, `FLAG_SECURE` on Android outside review runs; confirm words 3/7/11; then `backup_to_server`). *Back up now* asks for the phrase (never stored) or leads to the show-once screen when none was created on this device; reminder banner in Settings and over the inbox while `backup_status.reminder` is set. Onboarding → *Restore from recovery phrase* (`/restore`: email + 12 words validated as typed + server, documented error strings, then the mailbox credential via `set_account_credential`; on "no backup found" it offers the mailbox lookup with the password). *Transfer to another device* (`/settings/transfer`): setup-message export with the 36-digit code in nine blocks, and import. |
| QR code in Settings | Real: `OPENPGP4FPR:<fingerprint>` from the engine, scannable, plus *Copy code*. |
| Live updates (IMAP IDLE) | Wired (`CoreApi.watch` → `Stream<MailEvent>`), a Settings toggle, **off by default** (it keeps one more IMAP connection per account open). The engine serialises syncs per account (its mailbox lock, unit-tested in `sealbox-core`), so a watcher-triggered sync and a manual fetch queue instead of overlapping. |
| `FakeCore` | Kept as the deterministic test double (widget tests, goldens); no production code path uses it any more. Besides the inbox sample and the Spam scam it parks two review samples in a user folder "Review samples" of the second account that only "All mail" lists: an undecryptable mail with subject `...` (N1) and Bob's mail signed with another address's key (R4); the fake review tour ends on both (`fake-thread-undecryptable`, `fake-thread-signer-mismatch`). |

## Prerequisites

- Flutter SDK stable 3.47.8 (Dart 3.13.7) on `PATH` (the scripts default to `$HOME/flutter`; override with `FLUTTER_ROOT`)
- Rust 1.93 via `source ~/.cargo/env` (cargokit needs `rustup` on `PATH` during `flutter build`)
- Linux desktop deps: clang, cmake, ninja, pkg-config, libgtk-3-dev, liblzma-dev; `xvfb` for the gate's smoke run;
  `imagemagick`, `xdotool` and `x11-utils` (xdpyinfo) for `scripts/review_desktop.sh`
- Bridge codegen (only to regenerate bindings): `cargo install flutter_rust_bridge_codegen` — **2.13.0**, must equal the
  `flutter_rust_bridge` version in `pubspec.yaml` *and* in `rust/Cargo.toml`.

`flutter doctor` will flag the Android toolchain as missing; that is expected until G10.

## Run on Linux desktop

```bash
cd app
flutter pub get
flutter run -d linux                                            # real engine; onboarding first when the profile has no account
SEALBOX_PROFILE=/tmp/sb-demo flutter run -d linux               # a throw-away profile
testing/mail_up.sh   # then add u05@sealbox.test with manual servers 127.0.0.1:3143 / 3025, security "None (plain)", user u05, password u05pw
```

The first build compiles the Rust crate (sealbox-core and its dependency tree) through cargokit;
later builds are incremental. Output: `build/linux/x64/debug/bundle/sealbox_app`.
Release bundle + tarball: `scripts/package_linux.sh --build` → `dist/sealbox-linux-x64-<version>.tar.gz`.
Visual review loop: `scripts/review_desktop.sh` → `review/desktop/<date>/` (PNG per screen state + `index.html`).

Tests and lints: `flutter analyze && flutter test`. Everything at once: `../scripts/gate_flutter.sh`.

## Layout

```
app/
├── lib/
│   ├── main.dart                     RustLib.init(), bridge self-check, ProviderScope, start route
│   └── src/
│       ├── app.dart                  MaterialApp.router + Material 3 theme
│       ├── router.dart               go_router: /onboarding, /inbox, /inbox/t/:id, /compose, /settings
│       ├── core/
│       │   ├── core_api.dart         CoreApi (base seam) + CoreMailOps (engine ops) + CoreApiOps extension defaults
│       │   ├── models.dart           plain Dart models (Account, MailThread, Message, ContactKey, SyncOutcome, …)
│       │   ├── threading.dart        conversation grouping by the engine's References key (subject fallback), html→text
│       │   ├── fake_core.dart        FakeCore — in-memory, deterministic sample data (widget tests, goldens)
│       │   ├── frb_core.dart         FrbCore — the real engine through the generated bridge (Engine.open(profileDir))
│       │   ├── review_tour.dart      the scripted screen tour behind scripts/review_desktop.sh (SEALBOX_REVIEW=fresh|seeded)
│       │   └── core_providers.dart   Riverpod providers: coreApiProvider (injection point), sync controller, theme, live updates
│       ├── providers/provider_table.dart   Dart mirror of the built-in provider table (docs/PROVIDERS.md)
│       ├── policy/encryption_policy.dart   per-recipient policy: key ⇒ encrypted · no key ⇒ guest link · plaintext only after confirm
│       ├── features/
│       │   ├── onboarding/           email → detecting → detected (IMAP/SMTP/auth) → OAuth | app password | manual → done
│       │   ├── inbox/                HomeShell (rail ≥ 840 px, bottom bar below), list by folder role with swipe actions, thread view + menu (thread_actions.dart)
│       │   ├── compose/              recipient pills (🔒 / 🔗 / ⚠️), policy banner, guest-link passphrase, confirm dialog, preview
│       │   ├── spam/                 spam settings, filter rules + editor + dry run, "Why is this spam?" sheet
│       │   ├── identity/             key-changed banner/chips/badges, contact + verify screens, QR, scanner, KT card
│       │   ├── recovery/             recovery phrase (show once), backup dialog/reminder, restore, transfer (setup message)
│       │   └── settings/             accounts, my key (real QR, directory publish), security, mail handling, backup, server (editable), engine info
│       ├── widgets/lock_badge.dart   encrypted / signed / plaintext badge
│       └── rust/                     GENERATED by flutter_rust_bridge_codegen — do not edit
├── rust/                             the bridge crate (own [workspace]; built by cargokit, not by the root workspace)
│   └── src/api/engine.rs             the engine API exposed to Dart (opaque Engine + DTOs); sealbox.rs = self-check calls
├── integration_test/
│   └── core_wiring_test.dart         G17: the real flow against GreenMail, driven through the UI (scripts/gate_g17.sh)
├── rust_builder/                     cargokit Flutter plugin that builds rust/ for every platform
├── flutter_rust_bridge.yaml          codegen config (rust_input: crate::api → lib/src/rust)
└── test/                             unit tests (policy, provider table) + widget tests (onboarding, inbox, compose, settings) + goldens
```

State: Riverpod 3 (`Notifier`s for onboarding and compose, `FutureProvider`s over `CoreApi`).
Navigation: go_router 18. Widgets never import the generated bridge code; only `FrbCore` does.

## Regenerating the bridge

Edit `app/rust/src/api/*.rs`, then from `app/`:

```bash
flutter_rust_bridge_codegen generate      # rewrites rust/src/frb_generated.rs and lib/src/rust/**
cd rust && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
```

Commit the generated files together with the Rust change; the gate builds them. Plain `pub fn`s
run on FRB's worker pool (Dart sees a `Future`); `#[frb(sync)]` for trivial getters; `Result<T>`
surfaces as a thrown `AnyhowException` in Dart. Keep the three `flutter_rust_bridge` versions equal
(codegen binary, pub dependency, crate dependency) or `RustLib.init()` refuses to start.

When running `cargo` by hand on this crate use a private target dir (the repo's `target/` is shared
with the workspace): `CARGO_TARGET_DIR=../../target/app-rust cargo test`.

## How `sealbox-core` is integrated

1. **Dependency.** `app/rust/Cargo.toml` has `sealbox-core = { path = "../../crates/sealbox-core" }`
   (rusqlite bundled, rustls, no system libraries) and keeps the empty `[workspace]` table because
   cargokit builds the crate standalone for every platform (Linux now, Android through cargo-ndk, iOS later).
2. **API surface** (`rust/src/api/engine.rs`). `#[frb(opaque)] pub struct Engine { inner: Arc<sealbox_core::Engine> }`;
   `async fn`s (network: detect, add account, sync, send, flags, delete, watch) run on FRB's tokio
   runtime, plain `fn`s (SQLite reads, key export/import) on FRB's worker pool. Every bridge type
   mirrors `sealbox_core::types` one-to-one with `From` conversions; the only deviation is that enums
   carrying data (`AuthHint`, `AuthSpec`, `WatchEvent`) are flattened into `kind` + optional fields so
   the Dart side needs no `freezed`/`build_runner`. Errors cross as `AnyhowException` with the
   engine's message. `watch` takes an FRB `StreamSink<WatchEvent>`; the engine's callback returns
   `false` once Dart cancelled, so the IDLE loop ends at its next event (≤ the IDLE timeout).
3. **Dart side.** `FrbCore` maps DTOs to `models.dart`; conversations are grouped client-side by
   the engine's `thread_id` (`threading.dart`). `CoreApi` kept its original members; the engine-only operations sit on
   `CoreMailOps` and reach screens through the `CoreApiOps` extension, so any `CoreApi` double (e.g.
   `test/support/golden_core.dart`) keeps compiling and gets inert defaults.
4. **Profile + secrets.** `main.dart` resolves the profile dir (`SEALBOX_PROFILE` define/env, else
   `path_provider`), `Engine.open` creates it `0700`; passwords go straight from the text field into
   `AddAccount.auth` and are never logged. Keystore wrapping is G27.
5. **Regenerate** after editing `rust/src/api/*.rs`: `flutter_rust_bridge_codegen generate`, then
   `CARGO_TARGET_DIR=../../target/agent-app cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test` in `rust/`.

### API gaps found while wiring (for `sealbox-core`)

Closed on day 2 (the engine + bridge now have them, and the app uses them): runtime server URL
(`set_server_url` / `server_url_source`), the per-account sync lock (so IDLE and a manual fetch
queue), threading fields on the summary (`thread_id`, `in_reply_to`, `references`), folders by
role (`folder_roles`, `sync_folder_role`, `move_message`, `ListQuery.folder_role`), compose
options and preview (`send_with`, `compose_preview`, `signature_preview`), spam and filter rules,
and key publishing (`publish_key`, `directory_status`, `complete_directory_verification`).
Attachments are sent from the compose screen's file picker.

Still open:

- `MessageSummary` has no "sent as guest link" flag: the app recognises a sent guest copy by its `…/g/<id>` link.
- No way to cancel a running `watch` other than closing the sink; cancellation is only noticed at the next
  IDLE event. A `CancellationToken`/`AbortHandle` on `watch` would make the Settings toggle immediate.
- `AccountInfo` has no "provider display name" — the app derives it from its own provider table or the IMAP host.
- `directory_status` only reports what the directory serves (`published` / `other_key` / `unpublished`);
  "challenge mailed, not verified yet" exists only as the answer of `complete_directory_verification`.
  The app keeps that per account for the session; a persisted "pending since" in the engine would
  survive a restart.
- `move_message` drops the local copy until the destination folder is synced (the message comes back
  under a new id): the app re-syncs INBOX + Sent after a restore and marks Spam / Trash / Archive stale
  so their next open syncs. Relocating the row locally (as `spam_learn` does) would avoid the gap.
- `Message.isSent` means "not in INBOX" (a scam in Spam counts as sent); the UI decides "ours" by the
  account addresses instead.

### Settings UI — what landed, what is left

Day 1: on top of the engine's `settings`/`signature`/`autoreply` APIs, bridge DTOs
(`SignatureSettings`, `AutoReplySettings`, `AutoReplyLogEntry`) + `get/set_signature`,
`get/set_auto_reply`, `auto_reply_log` on `Engine`, and two per-account editors
(`features/settings/signature_screen.dart`, `autoreply_screen.dart`: enabled/text/HTML/placement/
include-on with preview; enabled/dates/subject template/body/once-per-sender/encrypt-when-possible/
known-contacts-only + the sent-replies log). The signature is applied by the engine on send.

Day 2: the section is **Mail handling** (per account: Signature, Out of office, Spam, Filters;
`features/spam/`), My key shows the key-directory state (`features/settings/directory_publish.dart`),
Server is editable (`server_section.dart`), and My key + Security share an account picker
(`account_picker.dart`) when the profile has several accounts. Review items closed in code (the
lead closes them by screenshot): D1 "this device", D5 no ` (os error N)` in `friendlyError()`, D6/B1
the subject heads the first message card (two lines) and the app bar says the folder, D7 "signed by
<address>" with the key id in the tooltip, B3 account subtitle one item per line on ≤ 600 dp.

TODO:

- [x] compose: signature and quote by the engine (`ComposeOptions.reply()` / `.forward(id)`), shown in a Preview;
- [x] **Spam & filters**: Spam folder with mark as spam / not spam, "Why is this spam?", Spam and Filters screens;
- [x] folder chips by special-use role, first-open sync, move to Trash / Spam / Archive / Inbox, mark unread;
- [x] lead review L3: "Publish to directory" (live state, publish, complete verification);
- [ ] lead review L4: thread status row as one chip row (lock · signed-by · folder);
- [ ] lead review L5: disable "Connect" until a plausible app password is typed, 16/16 counter for Gmail;
- [ ] lead review L6/L7: hero icon from `packaging/linux/sealbox.svg`, neutral key icon on the Google button;
- [ ] live updates: the engine has its per-account sync lock now; decide whether IDLE defaults to on
      (one more connection per account) and prove it on a phone;
- [ ] Android: `android.permission.INTERNET` in `app/android/app/src/main/AndroidManifest.xml` (owned by
      the Android loop) before the real engine can connect from a device.
- [ ] identity: the camera scanner (`mobile_scanner`) has never seen a real QR — the review AVD has no
      camera; scan a printed `OPENPGP4FPR:` code on a phone once. The key-change banner is only ever
      captured on FakeCore (the loops cannot rotate a GreenMail peer's key; a CLI `key rotate` would let G17 do it);
- [x] identity/recovery: an account picker (shared with My key) for multi-account profiles;
- [ ] transfer import: pick the setup message from the inbox instead of typing its id / Message-ID;
- [ ] iOS has no screenshot blocking for the recovery phrase (only detection); desktop neither;
- [x] Settings → Server is editable at run time (`set_server_url`);
- [ ] folders: Drafts and Starred have roles but no chip; a folder tree for user folders (filter targets);
- [ ] spam: the Spam folder of a real provider (Gmail `[Gmail]/Spam`, Outlook `Junk Email`) only seen on
      GreenMail so far (where it does not exist: the honest "nothing on the server" state);
- [ ] docs/RECOVERY.md still quotes the old reminder ("…with this phone"); the app now says "this device" (D1).
- [x] review N1: "Encrypted message" (italic, secondary) for the placeholder subject of mail nobody here can read
      (list row + thread header; the thread app bar names the folder since D6/B1);
- [ ] N1 follow-up: the filter dry-run picker and the "Why is this spam?" sheet still print such a subject as `...`;
- [x] review N2: the seeded tour's `settings-publish` shot scrolls up to the Key-directory panel (`revealInList`
      searches a lazy list from the top; it only paged downwards before);
- [x] review N3: the Server card's second line is the URL's source, not a repeat of the title;
- [x] review C1: the review loops stop piling up seeded mail — `scripts/review_android.sh` seeds u06 only into an
      empty INBOX (GreenMail REST API to look, IMAP expunge of the loop's own user when something else is there;
      `manifest.json` → `smoke_test.seed_inbox` before / after), `scripts/review_desktop.sh` empties u03/u04
      INBOX + Sent before it seeds (its profiles get fresh keys every run, so leftovers were undecryptable);
- [x] R4 (threat model): signer ≠ sender is an amber warning, never the green "signed by" chip; the CLI's `read`
      output still lacks the comparison (crates, not the app).

## Known issues

- The repository root `.gitignore` lists `app/rust_builder/`, but that directory *is* the cargokit
  plugin the build needs (it is meant to be committed; the FRB template ships it). Un-ignore it
  before the first clone-and-build elsewhere.
- On this host `fs.inotify.max_user_instances` (128) is exhausted by other processes, so the Dart
  analysis server cannot create file watchers and `flutter analyze` prints "Server error(s)"
  even after "No issues found!". The gate accepts exactly that case and nothing else.
