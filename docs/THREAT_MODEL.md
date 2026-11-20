# Sealbox threat model

Version 1 · 2026-10-29 · gate G13 (`scripts/gate_security.sh` checks this file: required sections,
adversaries A1–A8, no unfinished markers). Living document: a change to an untrusted-input parser, a
trust boundary or a mitigation listed here updates this file in the same commit. Design context:
`docs/ARCHITECTURE.md`; detail per area: `docs/SECRETS_AT_REST.md` (G27), `docs/GUEST_LINKS.md` (G29),
`docs/IDENTITY.md` (G30), `docs/RECOVERY.md` (G15), `docs/HOSTED_MAILBOX.md` (G22).

## 1. Scope & assets

**In scope:** the clients (Flutter app over `sealbox-core` / `-crypto` / `-mail` / `-spam`, the `sealbox`
CLI, the browser extension + Outlook add-in in `extension/`), the backend `sealbox-server` (key
directory + key-transparency log, guest messages, backups, hosted-mailbox provisioning, the static guest
viewer `web/guest/`), the push-relay prototype `sealbox-relay`, and the repository itself as far as
secrets and dependencies go. **Not in scope:** the mail providers' own security, the Stalwart server
software, the OS / browser / Flutter engine, and OpenPGP.js internals (vendored, pinned).

| Asset | Where it lives | Goal |
|---|---|---|
| Message plaintext: bodies, attachments, protected Subject | endpoints only; on the wire and at the provider as OpenPGP ciphertext; local store wrapped (G27) | confidentiality and integrity against everyone but sender and recipients |
| Secret keys | local store `identities.secret_armored` (wrapped, G27); extension `storage.local` (Argon2id + XChaCha20-Poly1305); client-encrypted server backup (G15); Autocrypt Setup Message | never leave the device unencrypted |
| Mail credentials: app passwords, OAuth access / refresh tokens, client secrets | local store (wrapped, G27); relay memory while registered (G16) | confidentiality; never logged |
| Human secrets: 12-word recovery phrase, 36-digit setup code, guest passphrases | the user (paper); guest passphrases also in `guest_links.secret` (wrapped) | never sent to the server |
| Key bindings (which key speaks for which address) | Autocrypt peer state, `identity_keys`, directory + KT log | no undetected substitution |
| Metadata: who, when, how much, subjects of the local list | provider headers, local plaintext columns (`SECRETS_AT_REST.md` "What stays plaintext"), server request logs | minimised, **not** hidden in v1 |
| Server state: KT signing key, guest ciphertext and gate state, backups, hosted signups | server SQLite | integrity and availability; never plaintext |
| Availability of the receive pipeline | every device | one hostile message must not crash, stall or exhaust a client |

Non-negotiables (kept from v0): no plaintext ever reaches the server; a downgrade to plaintext needs an
explicit per-message user action; signature results are shown, never implied; integrity protection
(MDC/AEAD) is mandatory and a failed decryption shows nothing of the plaintext.

## 2. Trust boundaries

```
 ┌───────────────────────── user's device (trusted while unlocked) ───────────────────────────┐
 │ Flutter app / CLI ─FRB─ sealbox-core ─ sealbox-crypto (rPGP) · sealbox-mail · sealbox-spam │
 │ local store: SQLite, sensitive columns wrapped (G27); key: OS keyring/Keystore/Keychain    │
 └──┬───────────────────────────┬────────────────────────────────┬────────────────────────────┘
 B1 │ IMAP / SMTP over TLS    B2 │ HTTPS + JSON                 B5 │ HTTPS: autoconfig, OAuth IdP
    ▼                           ▼                                 ▼
 mail provider (A1)        sealbox-server (A3; directory+KT A6)   ISPDB / autoconfig.<domain> /
 Gmail · Outlook · Yahoo · key directory + KT log · guest         Google · Microsoft
 iCloud · IMAP · hosted    ciphertext · backups · hosted signup
 Stalwart                  · serves the guest viewer
    ▲      ▲                    │ B4 HTTPS: viewer JS + ciphertext (secret stays in the #fragment)
    │      │ B3 IMAP IDLE with  ▼
    │      │ the user's creds  guest recipient's browser: web/guest + OpenPGP.js (A7 may be the reader)
    │   sealbox-relay (A8) ── content-free push ──▶ webhook / FCM / APNs
 any sender on the Internet (A5)
 B6: browser extension — the Gmail page (content script) ↔ extension origin (wasm crypto, keys)
```

| Boundary | What crosses it | What Sealbox relies on |
|---|---|---|
| B1 device ↔ provider | ciphertext mail, plaintext headers, credentials (password / XOAUTH2 token) | TLS with Mozilla roots (`sealbox-mail::tls::client_config`); the provider sees metadata and ciphertext only |
| B2 device ↔ server | public keys, guest ciphertext, backup blobs, KT proofs, hosted signup | TLS; the server is *not* trusted with confidentiality (A3), only for availability |
| B3 relay ↔ provider | the user's IMAP credentials (relay memory), IDLE notifications | the relay operator (A8) is trusted with credentials; never with content |
| B4 server ↔ guest browser | viewer code, ciphertext, the sender key for replies | TLS + CSP; the decryption secret never leaves the browser; the viewer code itself comes from the server (residual R5) |
| B5 device ↔ discovery / IdP | autoconfig XML, OAuth codes and tokens | HTTPS only, size cap, PKCE S256 + state |
| B6 page ↔ extension origin | message ids, encrypted raw mail via the Gmail API | the Gmail page cannot read the extension's iframes or storage |

## 3. Adversaries

| | Adversary | Can | Must not be able to |
|---|---|---|---|
| **A1** | mail provider, or anyone with mailbox access (compromised account, forwarding rule, shared device) | read, store, delete, inject and modify every message and header in the mailbox | read encrypted bodies, attachments or the protected Subject; make tampering go unnoticed; recover a guest passphrase or setup code from the mail alone |
| **A2** | network attacker | observe and modify traffic on any network path | read or alter anything inside TLS; downgrade the E2E layer |
| **A3** | Sealbox server operator, or whoever compromises the server | read and rewrite the server database, serve any HTTP response | read plaintext, secret keys, backups or guest passphrases; substitute a published key unnoticed by an auditing client |
| **A4** | lost or stolen device (locked, or briefly unlocked) | read the disk, the profile file and its backups | get secret keys, credentials or bodies without the profile key (G27) |
| **A5** | malicious sender: anyone on the Internet who can deliver mail to the user and encrypt to the user's public key | send arbitrary MIME, Autocrypt headers and OpenPGP packets, forge From | crash, stall or exhaust the client (DoS), execute code, exfiltrate other plaintext (EFAIL), plant a key silently, fake a good signature |
| **A6** | key-directory / KT operator presenting a **split view** | show different users different logs or keys | do so without leaving evidence a client can check (inclusion / consistency proofs) |
| **A7** | malicious guest-link recipient (or whoever holds the link) | open the message they were sent, reply, request codes, replay requests | read other guest messages, brute-force the email code, attack the sender's client through a reply |
| **A8** | compromised push relay | read its memory (credentials of registered mailboxes), send arbitrary pushes | learn message content from the relay protocol; pushes carry no content by design |

## 4. Attack surface

Every untrusted input, the code that parses it first, and how it is tested. "Fuzzed" means a G13
libFuzzer target feeds that exact function (see §7).

| Component | Untrusted input (from) | Entry point / parser | Fuzzed |
|---|---|---|---|
| receive pipeline (`sealbox-core::sync::process_message`) | raw RFC 5322 message from IMAP (A1, A5) | `sealbox_mail::mime::parse` → mail-parser 0.11.9 + our `classify`, `split_multipart`, `split_entity` | `mime_parse` |
| | `Autocrypt:` / `Autocrypt-Gossip:` values (A5) | `AutocryptHeader::parse_for_sender`, `AutocryptGossip::parse` → `PublicKey::from_bytes` (rPGP key parser + binding verification) | `autocrypt_header` |
| | PGP/MIME and inline PGP ciphertext (A5, A1) | `sealbox_crypto::decrypt_and_verify`: rPGP message parser, PKESK/SEIPD v1+v2, zlib/zip/bzip2, one-pass signatures, verification | `pgp_decrypt` (raw + wrapped packet streams), `mime_parse` |
| | `multipart/signed` part + detached signature (A5) | `sealbox_crypto::verify_detached` | `pgp_decrypt` mode 3, `mime_parse` |
| | decrypted inner entity: protected headers, gossip (A5 — anyone can encrypt to us) | `mime::parse_decrypted_inner` | `mime_parse` |
| | Autocrypt Setup Message (A5 can send one; the user must type the code) | `setup_message_open` → `guest_decrypt` → `Identity::from_armored_secret` | `guest_decrypt` mode 3, `autocrypt_header` (secret-key import) |
| | IMAP protocol responses (A1, A2 without TLS) | async-imap / imap-proto | no (R10) |
| | SMTP replies | lettre | no (R10) |
| account setup | autoconfig XML from ISPDB, `autoconfig.<domain>`, `.well-known` (domain owner, A3-like) | `sealbox_mail::autodiscover::parse_autoconfig_xml` (quick-xml 0.42), HTTPS only, ≤ 256 KiB | `autodiscover_xml` |
| | DNS SRV / MX answers | hickory-resolver, `table::provider_for_mx` | no |
| | OAuth redirect query, token responses (IdP, local loopback) | `sealbox_mail::oauth`, oauth2 crate | no; unit-tested (G6) |
| key directory client | `GET /vks/v1/by-email` response (A3/A6) | `PublicKey::from_armored` (same parser as Autocrypt keydata) | yes, through `autocrypt_header` |
| | KT tree heads and proofs (A6) | `sealbox_core::identity::kt` verifier | no; RFC 6962 vectors (G30) |
| restore | backup blob (A3) | XChaCha20-Poly1305 open, then deflate + JSON (`sealbox-core::recovery`) | no — authenticated before parsing |
| guest replies | reply ciphertext posted by A7, fetched by the sender | `decrypt_and_verify`, shown as text | yes (`pgp_decrypt`) |
| sealbox-server | JSON bodies (≤ 25 MiB), key uploads (≤ 1 MiB), backup signatures, hosted signup input, KT queries (A5, A7, anyone) | serde, `sealbox-server::openpgp` (rPGP), `hosted::validate` | no (R10); same rPGP parsers as the client |
| guest viewer | `#fragment` secret, server JSON, ciphertext (A3, A7) | OpenPGP.js 6.3.2 | no (third party) |
| extension | raw mail from the Gmail API (A5) | the same Rust MIME + crypto code compiled to wasm | at the source level (`mime_parse`, `pgp_decrypt`) |
| sealbox-relay | registration JSON (hand-parsed), IMAP responses | `sealbox-relay::api`, async-imap | no (R10) |

## 5. Threats & mitigations

Status: **M** mitigated · **P** partial (see §6) · **A** accepted.

| # | Threat (adversary) | Mitigation — where it is implemented / proven | |
|---|---|---|---|
| T1 | Read mail bodies at the provider (A1) | OpenPGP encrypt + sign: AES-256 SEIPDv1 (MDC), SEIPDv2/OCB when every recipient supports it (`sealbox-crypto::message::encrypt_and_sign_with`); protected Subject `...` outside (`sealbox-mail::mime::render_inner_for_encryption`); Sent copy encrypted to self — G1, G2, G4, G8 | M (metadata: R1) |
| T2 | Silent downgrade to plaintext (A1, A5) | `sealbox-core::policy::decide`: `Auto` / `RequireEncryption` refuse with `RecipientsWithoutKeys`; plaintext only under the explicit `AllowPlaintext`; guest link instead for key-less recipients — policy unit tests, G4, G8 | M |
| T3 | EFAIL / malleability: exfiltrate plaintext through crafted ciphertext or HTML (A5, A1) | legacy SED refused before any key use (`message::check_outer_layer` → `MissingIntegrityProtection`, G1 g1h); MDC / AEAD failure is fatal and nothing is returned before the end of the message was read (`message::read_limited`); only the encrypted sub-part of a `multipart/mixed` wrapper is decrypted, never concatenated with attacker parts (`mime::parse::classify`); no HTML engine: the app shows the text part, or a tag-stripped text of the HTML (`app/lib/src/core/frb_core.dart::_bodyOf`, `threading.dart::htmlToText`, `thread_screen.dart` `SelectableText`); guest viewer writes plaintext with `textContent` under a CSP with Trusted Types and no remote content (`sealbox-server::routes::CONTENT_SECURITY_POLICY`, `web/guest/viewer.js`); extension HTML parts under a no-network CSP (R8, mitigated) | M |
| T4 | Crash, hang or exhaust the client with one hostile message (A5, A1) | G13 fuzzing of every parser above (§7). Fixed from it: SEIPDv2 with an unknown AEAD mode refused before rPGP panics (`message::check_container_config`, F1); plaintext capped at 256 MiB (`MAX_PLAINTEXT_BYTES`, `Error::TooLarge`, F2); password-packet work budget for guest envelopes / setup messages (`guest::check_s2k_budget`, F3); an unparseable message is stored as "(unparseable message)" instead of failing the sync (`sync.rs`) | P (R10, R11) |
| T5 | Plant a key for an address: forged From + Autocrypt, gossip, directory (A5, A1, A3) | Autocrypt Level 1: exactly one valid header whose `addr` is the single From, never for our own address or `multipart/report` (`sync.rs`, `AutocryptHeader::parse_for_sender`); gossip only from inside a decrypted payload and only about To/Cc/protected recipients (`sync.rs`); key-change alerts with continuity sources, verified contacts by fingerprint / QR (`sealbox-core::identity`, G30) | P (TOFU: R3) |
| T6 | Forge or misrepresent a signature (A5) | rPGP verification per signature, statuses Good / Bad / UnknownKey, never inferred (`message::read_and_verify`, `detached::verify_detached`); "verified" only for exactly the key the user verified (G30); a good signature by another address's key is an amber "signed by X — but sent by Y" warning in the app (`app/lib/src/core/signer_mismatch.dart`) | M (CLI output: R4) |
| T7 | Intercept or alter IMAP / SMTP / HTTPS (A2) | rustls with the Mozilla roots only (`sealbox-mail::tls`), autoconfig HTTPS-only, ≤ 256 KiB, ≤ 3 redirects (`autodiscover::ispdb::fetch`); OAuth plain `http` only to loopback (`sealbox-mail::oauth`); the E2E layer does not depend on TLS; `plain` IMAP/SMTP only to loopback / private / special-use-name hosts (`sealbox-mail::net_policy`, R12) | L (plaintext to a private LAN host remains possible by choice; R12) |
| T8 | Steal secrets from a lost device (A4) | G27: XChaCha20-Poly1305 per column with row-bound AAD, key in the OS keyring / Keystore / Keychain or Argon2id passphrase, KCV, app lock (`sealbox-core::vault`, `store`) | M (metadata, unlocked malware: R1, out of scope) |
| T9 | Server learns plaintext, keys or passphrases (A3) | the server stores public keys, guest ciphertext, client-encrypted backups only; the guest secret stays on the device or in the URL fragment (G29, `routes/guest.rs`); backups are XChaCha20-Poly1305 under an Argon2id key from the 12-word phrase, the server keeps a hash of the pickup token (G15, `RECOVERY.md`) | P (viewer code and reply key come from the server: R5) |
| T10 | Directory serves a substituted key, or a split view (A6) | append-only RFC 6962 log, signed tree heads, inclusion and consistency proofs checked client-side with a pinned log key, substitution reported as `SUBSTITUTION:` (`identity::kt`, `sealbox-server::kt`, G30); `SEALBOX_KT_VERIFY_LOOKUPS=1` uses a directory key only after a passing audit | P (R6) |
| T11 | Guest secret exposed via the recipient's mailbox (A1) or a leaked link | default mode: the notification has no secret; one-click is opt-in and says so; email-code releases ciphertext only after a one-time code (G29, `GUEST_LINKS.md`) | M per mode as documented |
| T12 | Guessing the email code / flooding (A7) | 6 random digits, 10 min, 5 attempts then a 15 min lock, hashed + constant-time compare; ≤ 5 code mails per message per hour, ≤ 20 requests and ≤ 60 verifies per IP per hour (`state.rs` `Limits`, `routes/guest.rs`) | A (≈1.4 % over 30 days, `GUEST_LINKS.md`) |
| T13 | Malicious reply attacks the sender (A7) | replies are OpenPGP ciphertext to the sender key, ≤ 100 per message, 120/h per IP; the sender parses them with the fuzzed `decrypt_and_verify` and shows text | M |
| T14 | Overwrite or fetch someone's backup (A5, A3) | PUT needs a detached signature by the slot's key, the first verifying key is pinned; GET needs the token (stored hashed); the blob is AEAD (`routes/backup.rs`, G15) | P (rollback: R7) |
| T15 | Relay leaks content or credentials (A8) | pushes carry registration id, kind, folder, time only; the worker never `FETCH`es; credentials memory-only behind a redacting, non-`Serialize` `Secret` (`sealbox-relay::{worker,push,secret}`, G16) | P (R9) |
| T16 | Secrets committed to the repository (insider, tooling) | gitleaks over the full history and the tree with path-scoped allow-lists for documented test material only (G13, `.gitleaks.toml`); local secrets are git-ignored (`.gate/providers.local.env`, `.gate/profiles/`, `*.key`, `*.pem`) | M (clean 2026-10-29) |
| T17 | Vulnerable dependency (supply chain) | locked versions (`Cargo.lock`), fuzzing at the product's versions (`fuzz/Cargo.lock` seeded from it), `cargo audit` in G13, OpenPGP.js pinned by SHA-256 (`web/guest/VENDOR.md`) | P (R13) |
| T18 | Secrets in logs (A4, support channels, local malware) | redacting `Debug` for credentials (`sealbox-mail::Auth`, relay `Secret`), server traces carry route templates only (`routes::trace_layer`), G26 static log-redaction audit of our own log statements | M (R2 — F6 fixed) |
| T19 | Abuse of hosted signups (anyone) | invite mode by default, per-IP and global daily caps, attempt limits, reserved names, keyed IP hashes, password stored hashed (`sealbox-server::hosted`, G22) | M |
| T20 | Hostile autoconfig steers setup to an attacker host (domain owner, A3-like) | HTTPS-only fetches with the Mozilla roots; built-in table and ISPDB first (G5); the OAuth provider is inferred from the IMAP host on a domain boundary only, so `imap.evilgmail.com` gets no "Sign in with Google" (`ispdb::oauth_provider_for_host`, fixed in G13 work, F5); an OAuth token is only ever presented to its provider's own mail hosts and only through XOAUTH2, checked before any network write, so a steered account gets no token (`sealbox-mail::net_policy::check_bearer_host`, `ImapError::XOAuth2NotOffered`, R14); an answer that needs `plain` towards a public host is refused (`autodiscover::discover_with` → `net_policy::check_server_config`, R12) | P (R14: the password of a password account) |

## 6. Residual risks and out of scope

Known gaps, honestly. Owner in brackets when it is another workstream.

* **R1 Metadata.** From, To, Date, sizes and timing are visible to A1 and A2; the local store keeps
  addresses and (protected) subjects in plaintext so lists and SQL work (`SECRETS_AT_REST.md`).
* **R2 Credentials in the system log on Android / iOS / macOS (finding F6) — fixed in code.** `init_app` now installs the console logger at `Warn` (`app/rust/src/api/sealbox.rs`); the history below is kept for context. The app calls
  `flutter_rust_bridge::setup_default_user_utils()` (`app/rust/src/api/sealbox.rs`), which installs
  `android_logger` / `os_log` at **Trace** level in every build (FRB 2.13). async-imap logs its traffic
  through the `log` crate at trace level, so the IMAP `LOGIN` command (password), the XOAUTH2 string
  (access token) and raw fetched mail reach logcat. Evidence: the committed review captures
  from the 2026-10-27 Android review run contained `LOGIN "u06" "u06pw"` (a GreenMail test
  credential). G26's audit checks only our own log statements. Fix for the app owner: replace the call
  by `setup_backtrace()` + `setup_log_to_console(LevelFilter::Warn)` (or cap `log::set_max_level`),
  and add a logcat grep for `LOGIN` / `AUTHENTICATE` to the Android loop. [app / G26]
* **R3 Trust on first use.** The first key seen for an address wins (Autocrypt is opportunistic); an
  attacker who reaches the user first with a forged From and their own key is only caught by later
  key-change alerts or by verifying the fingerprint (G30).
* **R4 Signer ≠ sender — mitigated in the app (2026-10-29).** A good signature whose key belongs to
  another address than `From` (the engine's `SignatureSummary.signer`, compared lower-cased and
  trimmed, or a contact the user verified under another address) is an amber "signed by X — but sent
  by Y" chip whose tooltip says the key is not the sender's, never the green "signed by" chip; the
  inbox row keeps its lock badge (a signed-only message reads "Not encrypted") and adds an amber
  glyph (`app/lib/src/core/signer_mismatch.dart`, `thread_screen.dart`, `inbox_list_pane.dart`;
  `app/test/signer_mismatch_test.dart`, goldens `thread_signer_mismatch_*`). Left: the CLI's `read`
  output still prints "good signature by <fingerprint> (<address>)" without the comparison. [CLI]
* **R5 The server delivers the guest viewer.** `web/guest/` is served by the same server that stores
  the ciphertext, so A3 could ship a viewer that leaks the passphrase or plaintext; the viewer also
  encrypts replies to `sender_key_armored` exactly as the server returns it (`viewer-core.mjs`
  `encryptReply`), so A3 could substitute the reply key. CSP and Trusted Types stop injection, not the
  operator. Possible later steps: bind the sender fingerprint inside the encrypted guest payload,
  publish and pin the viewer hash.
* **R6 Key transparency without gossip.** A split view (A6) is only detectable once clients compare
  tree heads (witnesses / STH gossip — not built); `SEALBOX_KT_VERIFY_LOOKUPS` is off by default; leaves
  carry an unsalted SHA-256 of the address, so presence in the log can be confirmed by guessing
  (`IDENTITY.md`).
* **R7 Backup rollback.** A3 can serve an older backup blob whose token still matches (`RECOVERY.md`).
* **R8 Extension HTML parts.** An HTML-only decrypted message is rendered with `srcdoc` in a
  `sandbox=""` iframe (`extension/chrome/src/reader.js`); scripts are off. **Mitigated (2026-10-29):**
  the extension-page CSP (`manifest.json`) is now `default-src 'self'; img-src 'self' data:;
  style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src https:; object-src 'none'; media-src 'none';
  form-action 'none'; base-uri 'none'` (srcdoc frames inherit it; inline styles stay allowed so HTML mail
  keeps its look — CSS cannot fetch anything under `img-src`/`font-src`/`default-src`), and the part is wrapped by `html-part.js::htmlDocument`
  in its own document CSP (`default-src 'none'; img-src data:; style-src 'unsafe-inline'`) that
  does not depend on that inheritance. Verified in headless Chromium by the G28 fixture e2e
  (`test/fixture/e2e.mjs` "HTML part in the reader frame"): a remote image in the part is never
  fetched (a local pixel server sees 0 requests) through both the wrapped and a bare document,
  while text and inline styles still render. Residual: link clicks inside the frame navigate the
  sandboxed frame itself (no popup, no top navigation) — a user action, not an automatic fetch.
  [extension / G28]
* **R9 The relay holds live mailbox credentials** of every registered user (A8 can read, send and
  delete mail; plaintext mail is exposed). **Partially mitigated (2026-10-29)**: the API token is
  mandatory off loopback (`sealbox-relay::bind_policy`, `main.rs`: no start without `--allow-open-relay`);
  webhook URLs must be https to public addresses, optionally allow-listed, and are re-resolved, re-checked
  and pinned at every delivery against DNS rebinding (`webhook_guard`, `push`); IMAP destinations must
  resolve to public addresses only (the same address table; v4-mapped / NAT64 / 6to4 judged by the inner
  v4), optionally allow-listed (`--imap-allow-hosts`: exact hosts and `.suffix` entries), checked at
  registration and again before every (re)connect, which dials only the checked addresses (`imap_guard`,
  `api`, `worker`; `sealbox-mail::imap::ImapClient::connect_pinned`); `plain` IMAP only to hosts that are
  local by their literal form (`host_class`, `api`); three rejected logins park the registration, decided on
  the typed `sealbox-mail::ImapError::LoginRejected` rather than server text (`[UNAVAILABLE]`, a `BYE` greeting
  and network errors do not count; its message has the credential redacted in every form), and a parked
  registration is evicted after `--parked-ttl` (24 h) or on `DELETE` (`worker`, `registry`); a
  registration whose failure no retry can change is parked at once instead of reconnecting forever —
  an OAuth token against a server without `AUTH=XOAUTH2` (`ImapError::XOAuth2NotOffered`,
  `parked_reason: xoauth2_not_offered`, `worker::permanent_failure`; an `OAuthHostMismatch` parks as
  `oauth_host_refused`) — and the API refuses at registration what could never log in: a token for a
  host that is not its provider's own, a password or token with a control character (`api`); 30
  registrations per client address per minute (`rate_limit`). Still open: the credentials themselves (A8);
  without `--imap-allow-hosts` any public IMAP host and any port stay client-chosen (a blind TCP probe from
  the relay's address); one shared API token; a one-bit DNS oracle in the 400 reasons; and the development
  flags (`--imap-allow-private`, `--webhook-allow-private`, `--webhook-allow-http-private`) re-open what they
  name (`docs/PUSH_RELAY.md`, "Exposure policies"). [relay / G16]
* **R10 Parsers not fuzzed by G13:** IMAP responses (async-imap / imap-proto), SMTP replies (lettre),
  DNS (hickory), OAuth responses, server request bodies, the relay API, OpenPGP.js in the viewer.
  Next candidates: an imap-proto response target and a server JSON target.
* **R11 mail-parser debug assertions (finding F4).** mail-parser 0.11.9 (last 0.11 release) hits
  `debug_assert!(false, "Invalid part ID …")` on malformed nested `message/rfc822` parts: a 105-byte
  message panics every **debug** build (developer CLI, debug app builds); release builds compile it out
  and the parser recovers. The fuzz build waives this crate's debug assertions only (`fuzz/Cargo.toml`).
  Remedy: report upstream; mail-parser 1.0 is an API rewrite.
* **R12 Manual plaintext transport — mitigated 2026-10-29.** `plain` (no TLS) is refused with
  `TransportPolicyError::InsecureTransportRefused` unless the host is loopback (`127/8`, `::1`,
  `localhost`, `*.localhost`), private (`10/8` incl. the Android emulator's `10.0.2.2`, `172.16/12`,
  `192.168/16`, `fc00::/7`), link-local (`169.254/16`, `fe80::/10`), a name under `.test`, `.local`,
  `.internal`, `.lan`, `.home`, `.invalid`, or listed exactly in `SEALBOX_ALLOW_PLAIN_HOSTS=h1,h2`
  (read once per process). Decided from the literal host string, never by DNS. One rule
  (`sealbox-mail::net_policy::check_transport`), applied before any network write by
  `ImapClient::connect_with`, `SmtpClient::connect_with` (every IMAP/SMTP connection, the relay's
  too), `autodiscover::discover_with`, and at the add-account boundary (`Engine::add_account`,
  `detect_servers`, `add_oauth_account`, `OAuthStart::preflight`, `account add --dry-run`); the CLI
  exits 4. Tests: `net_policy` unit tests, `sealbox-mail/tests/transport_policy.rs`, the `ispdb`
  autoconfig test, `sealbox-core` `add_account_refuses_plaintext_to_a_public_host_before_connecting`;
  G3/G4/G8/G21 still pass against GreenMail on `127.0.0.1`. What remains: plaintext towards a
  private address is still allowed (an attacker on the same LAN who also controls the autoconfig
  answer, or the user's typing, can read it), and a special-use name is trusted by its spelling —
  how the system resolver completes it (search domains) is not checked. [core / CLI]
* **R13 Dependency advisories (cargo audit 2026-10-29, informative):** RUSTSEC-2023-0071 `rsa` 0.9.10
  (Marvin timing; only relevant if a user imports an RSA secret key — Sealbox generates Curve25519 keys;
  no fixed release exists), RUSTSEC-2026-0387 `crypto-bigint` 0.5.5 (timing; used for NIST-curve
  operations on peers' public data), RUSTSEC-2025-0144 `ml-dsa` 0.0.4 (timing in signing; only behind
  the `pqc` feature, which is off in the product and never signs with ML-DSA); warnings: unmaintained
  `zbus_names` / `zvariant` (Linux keyring), `adler`, `derivative`, unsound `anyhow` 1.0.75
  `downcast_mut` and a yanked `futures-util` in `app/rust/Cargo.lock`. All need upstream releases
  (rPGP / RustCrypto) or a lockfile bump by the owning workstream.
* **R14 Setup trusts the user's domain — mitigated 2026-10-29 for OAuth tokens.** An XOAUTH2 token
  is only presented to its provider's mail hosts, on a domain boundary: Google → `gmail.com`,
  `googlemail.com`, `google.com`; Microsoft → `office365.com`, `outlook.com`, `live.com`,
  `hotmail.com`, `microsoft.com`; anything else is `TransportPolicyError::OAuthHostMismatch` before a
  connection is opened (`sealbox-mail::net_policy::check_bearer_host`, called by
  `ImapClient::connect_with` / `SmtpClient::connect_with`; the engine passes the token's
  `BearerScope` from its `oauth_tokens` row, `sealbox-core::oauth` / `transport`; a token whose
  provider is unknown only goes to Google or Microsoft hosts). A server that does not advertise
  `AUTH=XOAUTH2` before login gets no token at all — the old "token as `LOGIN` password" fallback is
  gone (`ImapError::XOAuth2NotOffered`); SMTP offers the token through lettre's `XOAUTH2` only.
  Test/dev escape hatch: a token from a mock identity provider whose authorization and token
  endpoints are both loopback (`SEALBOX_OAUTH_AUTH_URL` / `SEALBOX_OAUTH_TOKEN_URL`,
  `OAuthEndpoints::is_loopback_mock`) may also go to local/private hosts; tokens from the real
  endpoints never can. Tests: `net_policy` unit tests, `sealbox-mail/tests/transport_policy.rs`
  (scripted servers: no AUTH=XOAUTH2 → nothing sent; XOAUTH2 via AUTHENTICATE; refusal before
  connecting), the `smtp` unit test `xoauth2_token_never_goes_through_plain_or_login`, `sealbox-core`
  `tokens_are_pinned_to_their_provider_hosts`, G3 `imap_xoauth2_is_refused_when_not_advertised`,
  G21 local (the OAuth account reaches GreenMail through a test-only XOAUTH2 front and never sends
  `LOGIN`; without the front it is refused). Still open: whoever controls `autoconfig.<domain>` for
  the user's own domain controls the discovered servers for a password account and receives the
  password typed for them (inherent to autodiscovery; TLS with the Mozilla roots and R12 limit it to
  a host with a valid certificate).
* **R15 Other CPU amplification.** Messages can carry many PKESK packets (each matching one costs an
  X25519 operation) or many signature packets for a known issuer; bounded by message size, not by count.
* **R16 Draft attachment files — mitigated 2026-10-29.** A file attached to a saved draft is no
  longer copied to the profile as a plain file: the engine keeps it as a **sealed blob** in the store
  (table `draft_blobs`, `data` sealed like `attachments.data`, AAD `draft_blobs:data:<id>`, in
  `vault::WRAPPED`, so migration, rewrap and the status count cover it; only drafts of the account
  that stored it may reference it), and the app hands compose a `blob:<id>` handle
  (`FrbCore.keepDraftAttachment` → `put_draft_blob`). The blob is deleted with its draft when the
  draft is sent or deleted (a failed send keeps both), and `sweep_draft_blobs` removes blobs no draft
  references once ten minutes old, run at start-up for every account. File name, type and size stay
  plaintext like a message attachment's. Tests: `sealbox-core` `drafts::tests` (a 64-byte marker is
  in no profile file before or after `send_draft` / `delete_draft`, migration, rewrap, AAD row
  binding, wrong key → `ProfileLocked`, the sweep), G27 e2e `draft_attachments_are_sealed_blobs`
  (CLI `draft attach` / `detach`, u73 → u74), `app/test/frb_core_draft_blobs_test.dart`, and G17
  `search_drafts_test.dart` (no profile file holds the attached bytes). **Residual:** plain copies
  made by builds before this change stay under `<profile>/draft-attachments/` while a saved draft
  still names them (read and released as before; the start-up sweep deletes them once orphaned, and
  sending or discarding the draft deletes them); the CLI's `draft save --attach` still references the
  user's own file by path (nothing copied). Related: a second `send_draft` of a draft being sent fails
  at once (`Error::DraftBeingSent`), per engine process. [app / drafts, 2026-10-29]

* **R17 Draft copies on the server (session 14).** A saved draft is also stored in the account's Drafts
  folder as a PGP/MIME message encrypted and signed to the user's own key only (subject protected,
  no recipients in any outer header; blobs inside, file references stay on the device), so the provider
  (A3) and anyone with mailbox access cannot read it — but they can see that drafts exist, how many,
  their sizes, `Date` = the draft's `updated_at`, the `X-Sealbox-Draft` uuid that links the versions of
  one draft, and the count of file references (`X-Sealbox-Draft-Files`). A device without the key sees an
  unreadable message. Another client may list these copies as odd `...` drafts (`docs/ARCHITECTURE.md`,
  "Drafts on the server"). Whoever can write to the mailbox can also delete a server copy (an unedited
  local draft then disappears at the next sync, like any mail they could delete) and can re-append an
  old, validly signed copy. **Mitigated 2026-10-29 (draftsui):** the tombstone of a draft deleted or sent
  here — or removed here because its copy vanished — is kept for `TOMBSTONE_DAYS` (90; `draft_sync.deleted_at`),
  so a re-appended copy of that uuid is deleted again by the next sync instead of imported (unit test
  `tombstones_of_drafts_never_on_the_server_go_without_a_connection`). Residual: a copy replayed more than
  90 days later, or into a device that never knew the draft, is imported as a draft again (a resurrection,
  not a forgery — only the own key signs). The app's Drafts role sync stores these copies as messages
  but never lists or indexes them (`draft_copies`: header + the account's Drafts role folder, so a mail
  carrying the header elsewhere cannot hide itself). [engine / drafts_imap, 2026-10-29]

**Out of scope for v1:** hiding metadata and traffic analysis; malware or a compromised OS on an
unlocked endpoint; a recipient who forwards or screenshots what they decrypted; post-quantum
confidentiality in the product build (G14 proves the hybrid, off until peers interoperate); physical
side channels; the providers' and Stalwart's own security; denial of service by the provider or the
network (they can always drop mail).

## 7. Security testing

### What G13 proves (`scripts/gate_security.sh`, logs in `target/gate_security/`)

1. **This document** has every required section, describes A1–A8 and holds no unfinished markers.
2. **Fuzz build:** `cargo +nightly fuzz build -O` with AddressSanitizer; debug assertions and overflow
   checks on for every crate through `fuzz/Cargo.toml`'s profile (cargo-fuzz would otherwise force
   them through RUSTFLAGS), except mail-parser's debug assertions (R11). Cold build ≈ 60 s on the
   20-thread build box. `fuzz/Cargo.lock` was seeded from the product's `Cargo.lock`: every product
   dependency is fuzzed at the shipped version.
3. **Seeds are alive:** `fuzz/seedgen -- --check` replays every committed seed through the harness's own
   fixtures and wrapped containers and fails unless it reaches the path its name promises (decrypts,
   verifies Good / UnknownKey, parses, imports the setup-message key). 81 seeds today.
4. **Fuzzing:** five targets × 125 s (`SEALBOX_FUZZ_SECS`; the gate refuses to pass below 600 s in
   total), `-timeout=10 -rss_limit_mb=2560`, LeakSanitizer on; FAIL on any crash, sanitizer report, leak,
   OOM, timeout, or new file in `fuzz/artifacts/`.

   | Target | Real code under test | Modes / oracles | Seeds |
   |---|---|---|---|
   | `mime_parse` | `mime::parse`, then per kind `decrypt_and_verify` / `verify_detached` / `parse_decrypted_inner` + gossip, as `sync::process_message` does; the RFC 2046 splitter on its own | — | 16: builder-made plain, HTML + attachments, PGP/MIME encrypted (v4, v6, gateway-wrapped), signed, inline PGP, protected-header inner entity, hand-written QP / RFC 2047 / nested / bounce / LF-only / unterminated |
   | `pgp_decrypt` | `decrypt_and_verify`, `verify_detached` | raw messages; payload as the decrypted packet stream inside a valid PKESK v3 + SEIPDv1 or v6 PKESK + SEIPDv2/OCB; detached signatures | 28: product and rPGP-made messages (signed, unsigned, compressed, anonymous recipient, partial lengths, not-for-us), inner streams (literal, signed ×1/×2, unknown signer, zlib / zip / bzip2, text mode, partial lengths, 1 MiB amplification), detached signatures |
   | `autocrypt_header` | both Autocrypt parsers, gossip, `PublicKey::from_bytes`, `Identity::from_secret_bytes`, `minimal_public_key`, encryption to the accepted key | render → parse must round-trip; the derived minimal key must parse again | 11 |
   | `guest_decrypt` | `guest_decrypt_bytes`, `setup_message_open` | raw envelopes (both production profiles), payload wrapped in SKESKv4 + SEIPDv1 / SKESKv6 + SEIPDv2, setup-message text | 14 |
   | `autodiscover_xml` | `parse_autoconfig_xml` | — | 12: eight real Mozilla ISPDB documents (gmail.com, outlook.com, yahoo.com, gmx.net, web.de, zoho.com, aol.com, posteo.de) + hand-written edge cases |

   The fuzz identities in `fuzz/seeds/keys/` are TEST keys (`fuzz-*@sealbox.test`), public on purpose.
5. **gitleaks** (default rules + `.gitleaks.toml`), redacted: a canary generated at run time must be
   found (config loads, rules live); then the full history of every ref, and the working tree as git
   sees it (tracked + untracked-not-ignored). The history pass skips two generated report names
   (`review/android/**/{smoke_report,manifest}.json`: PNG screenshots as JSON integer arrays, ~40 MB
   per commit, about 1 GB of history) because `git log -p` alone needs about 8 minutes for them; with
   the default rules both scans gave identical findings (2026-10-29), and their current versions are in
   the tree pass. `SEALBOX_GITLEAKS_FULL_HISTORY=1` includes them.
6. **cargo audit** of `Cargo.lock`, `app/rust/Cargo.lock`, `extension/wasm/Cargo.lock`,
   `fuzz/Cargo.lock`: informative; triage in R13.

### Findings of the G13 work (2026-10-29)

| | Finding | Found by | Resolution |
|---|---|---|---|
| F1 | rPGP 0.21 panics on a SEIPDv2 container with an unknown AEAD mode (`aead.nonce_size() - 8` underflow / out-of-range slice in release); remotely triggerable through `decrypt_and_verify` (also against the default v4 identity via a v6 PKESK) and `guest_decrypt_bytes` | fuzzer (`guest_decrypt`, < 90 s) | fixed in `sealbox-crypto::message::check_container_config`; regression tests in `message.rs` and `guest.rs`; report upstream to rPGP |
| F2 | unbounded plaintext: rPGP's `as_data_vec` follows compressed data without limit — one small mail could abort the client on every sync | review while writing the harness | fixed: `read_limited`, `MAX_PLAINTEXT_BYTES` (256 MiB), `Error::TooLarge`; tests |
| F3 | password-derivation amplification: rPGP tries every SKESK packet, each up to Argon2 2 GiB × 32 passes | review while writing the harness | fixed: `guest::check_s2k_budget` (≤ 4 packets, Argon2 ≤ 2^18 KiB, ≤ 256 MiB of work); tests |
| F4 | mail-parser debug assertion on malformed nested `message/rfc822` | fuzzer (`mime_parse`, < 90 s) | R11: debug builds only; waived for this crate in the fuzz build; report upstream |
| F5 | OAuth provider inferred from the autoconfig host by bare suffix (`evilgmail.com` → Google) | attack-surface mapping | fixed: domain-boundary match in `autodiscover::ispdb`; tests |
| F6 | IMAP credentials and traffic in logcat / os_log (FRB default Trace logger) | gitleaks history scan of the review captures | fixed — `setup_log_to_console(Warn)` |

### What the other gates prove

| Gate | Security property it demonstrates |
|---|---|
| G1 | OpenPGP core interoperates with gpg, RNP and Sequoia both ways; tampered ciphertext and legacy SED are refused |
| G2 | PGP/MIME (RFC 3156) and protected headers build and parse |
| G4 / G8 | end-to-end encrypted mail through a real IMAP/SMTP server; Autocrypt bootstrap |
| G5 / G6 | autodiscover from the built-in table / ISPDB / SRV; XOAUTH2 and PKCE vectors |
| G7 | key directory email-verified publishing, guest messages, backups, viewer decrypts in a headless browser |
| G14 | PQC hybrid ML-KEM-768 + X25519 round trip and draft vectors (feature off in the product) |
| G15 | recovery phrase → client-encrypted backup → restore; Autocrypt Setup Message |
| G16 | relay pushes carry no content |
| G22 | hosted signups respect policy and caps against a real Stalwart |
| G26 | release builds, static log-redaction audit |
| G27 | secrets at rest: no key, password, body or attachment bytes on disk; wrong key reads and writes nothing |
| G28 | the wasm build of the same crypto + MIME code round-trips with gpg; MV3 extension builds and lints |
| G29 | guest links: no secret in the default link; one-click opt-in; email-code gate; expiry; resend |
| G30 | key-change alerts, verified contacts, KT proofs verified client-side, substitution detected |

Current pass/fail status lives in `.gate/gate_status.json` (written by `scripts/gate.sh` only).

## 8. Disclosure

* **Reporting.** Report suspected vulnerabilities privately, never in a public issue, chat or mailing
  list: use GitHub private vulnerability reporting as described in `SECURITY.md`. A dedicated
  security address with an OpenPGP key (also served as `/.well-known/security.txt` by the server)
  is an open release item for the operator.
* **What helps:** affected component and version (`VERSION`, git revision), a minimal reproducer
  (for parser bugs: the input bytes, ideally as a fuzz artifact), impact as you see it, and whether
  it is public.
* **Our side (default timelines, the operator may tighten them):** acknowledgement within 3 working
  days, an assessment within 10, a fix or mitigation for anything rated high within 30 days, and
  coordinated public disclosure once the fix ships or after 90 days at the latest, whichever comes
  first; earlier if the issue is already exploited. Reporters are credited unless they ask otherwise.
* **Every fix** lands with a regression test next to the affected code (parser bugs also as a fuzz
  seed) and an update of §5 / §6 / §7 here, and is listed in `CHANGELOG.md` at the next release.
* **Dependencies.** Bugs in third-party code (rPGP, mail-parser, quick-xml, OpenPGP.js, …) are worked
  around in Sealbox first (as for F1) and reported to the upstream project privately under its own
  security policy.
* **Good-faith research** is welcome within these limits: only your own accounts, a local GreenMail /
  Stalwart, or a server you run; no denial-of-service against shared infrastructure, no access to
  other people's mail or data, no social engineering.

## 9. Change log

* 2026-10-29 — v1 (gate G13): complete model replacing the v0 sketch (assets, A1–A5 there); adds A6–A8,
  trust boundaries, the attack-surface map, threats × mitigations, residual risks R1–R15, the G13 test
  description, findings F1–F6 and the disclosure policy.
