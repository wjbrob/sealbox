# Sealbox — guide for coding agents and contributors

Sealbox is a cross-platform end-to-end-encrypted email client: a Rust core, a Flutter UI
(Linux and Android today), and a small Rust backend. It adds encryption to accounts people
already have (Gmail, Outlook, iCloud, any IMAP) with **no MX-record changes**: OpenPGP/Autocrypt
to capable recipients, a passphrase-protected "guest link" for everyone else.
Design: `docs/ARCHITECTURE.md`. What counts as a confirmed result: `docs/GATES.md`.
Human contributors: see `CONTRIBUTING.md` first.

## Where things are
| Path | Purpose |
|---|---|
| `crates/sealbox-crypto` | OpenPGP (rPGP), Autocrypt, guest envelope, key material |
| `crates/sealbox-mail` | MIME (PGP/MIME), IMAP, SMTP, XOAUTH2, provider autodiscover, OAuth2 PKCE |
| `crates/sealbox-core` | the engine: accounts, local store, sync + send pipelines, API for the UI |
| `crates/sealbox-cli` | `sealbox` CLI — the e2e harness and a desktop client |
| `crates/sealbox-server` | axum backend: key directory, guest messages, encrypted backups, KT log |
| `crates/sealbox-relay` | push relay (IMAP IDLE → content-free push) |
| `crates/sealbox-spam` | spam classifier (rules + Bayes + feedback) and filter engine |
| `crates/sealbox-fakeprov` | provider simulator (IMAP/SMTP/OAuth) for conformance tests |
| `app/` | Flutter app, bridged to the core with flutter_rust_bridge (`app/rust`, its own cargo workspace) |
| `web/guest/` | static guest viewer (decrypts in the browser; the server never sees plaintext) |
| `extension/` | MV3 browser extension (wasm core) |
| `testing/` | GreenMail + Stalwart docker compose and e2e helpers |
| `scripts/gate.sh` | the test gate; writes `.gate/gate_status.json` (local, gitignored) |

## Toolchain
Rust stable (MSRV 1.85), Flutter 3.47.8, Docker (for e2e gates), `gpg`, `rnp` and `sq` (interop
oracles), Android SDK + NDK 27.0.12077973 + `cargo-ndk` for Android. `scripts/env.sh` puts the
toolchain on `PATH`; override `FLUTTER_ROOT` / `ANDROID_HOME` as needed.

## Rules
1. **Never commit secrets** (tokens, OAuth client secrets, app passwords, private keys). Throw-away
   test keys under `testing/` with obvious names are fine. Real-account config lives in `.gate/`.
2. Use an isolated `GNUPGHOME` (under `target/`) for gpg interop tests — never the user's own.
3. Docker: only `docker compose -p sealbox -f testing/docker-compose.yml …`; never stop containers
   you did not start.
4. Never send email to real addresses other than those you configured in `TEST_ACCOUNTS`
   (`.gate/config.local.env`). The local GreenMail domain `sealbox.test` is always fine.
5. Honesty: a gate is PASS only when `scripts/gate.sh` observed it pass. No mocked results written
   up as results. If something is unverified, say so in the PR.
6. Don't change another crate's public API without updating all callers and the gate in one commit.
7. A mutation-test edit must be restored in the same step; `scripts/gate_tree.sh` (G34) fails on
   `// MUTATION` markers.

## Conventions
- Rust 2021, `cargo fmt`, `cargo clippy --all-targets -D warnings` clean before commit. Errors via
  `thiserror` in libs, `anyhow` in binaries. Async with tokio. No `unwrap()` outside tests.
- Every feature lands with a test. Cross-crate behaviour lands with an e2e under
  `crates/sealbox-cli/tests` or `testing/`.
- Interop before invention: OpenPGP (RFC 9580 profile), Autocrypt Level 1, PGP/MIME (RFC 3156),
  protected headers. Our own formats only where no standard exists (the guest link).
- Commits carry a DCO `Signed-off-by:` line (`git commit -s`).
