# Changelog

All notable changes to Sealbox are documented in this file. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The single version source is `VERSION`
(`scripts/version.sh`); `scripts/gate_release.sh` (gate G26) refuses to pass until the
current version has its own `## [X.Y.Z]` section here.

## [Unreleased]

## [0.1.0] - 2026-11-20

First public source release. Pre-alpha: not yet security-audited, not for real secrets.

### Added
- **Crypto** (`sealbox-crypto`, rPGP): identities, encrypt+sign / decrypt+verify, Autocrypt
  Level 1 with gossip and the Setup Message, guest-link envelope, integrity required; interop
  in both directions with GnuPG, RNP (Thunderbird's engine) and Sequoia `sq` (gate G1);
  post-quantum hybrid behind the `pqc` feature (off by default, G14).
- **Mail** (`sealbox-mail`): PGP/MIME with protected headers; IMAP (TLS, IDLE, UID sync,
  special-use folders, MOVE/COPY/APPEND); SMTP (PLAIN/LOGIN/XOAUTH2); provider autodiscover;
  OAuth2 PKCE; HTML sanitiser that blocks remote content by default.
- **Engine and CLI** (`sealbox-core`, `sealbox-cli`): accounts, sync with mailbox convergence,
  threading, send with per-recipient encryption policy, drafts (sealed locally and synced
  encrypted to the Drafts folder), search over a non-persistent index, signatures,
  auto-reply, spam classification and filters, recovery phrase and encrypted backups, key
  directory and key-transparency checks, guest links, provider conformance test.
- **Local store encrypted at rest**: message bodies, raw MIME, drafts and attachments sealed with a
  profile key held in the OS keyring or derived from a passphrase.
- **Server** (`sealbox-server`): key directory with email challenge, guest-message store,
  signed client-encrypted backups, key-transparency log, hosted-mailbox provisioning.
- **Push relay** (`sealbox-relay`): one IMAP IDLE session per registration, content-free push,
  SSRF and destination policy (not yet wired into the app).
- **Flutter app** (`app/`, Linux and Android): onboarding, inbox, thread view with safe HTML,
  compose with per-recipient status and guest links, settings for keys, recovery, spam, filters,
  app lock and live updates.
- **Browser extension** (`extension/`): MV3 wasm core for Gmail and Outlook web (prototype).
- **Guest viewer** (`web/guest/`): decrypts guest links in the browser; the server never sees
  plaintext.
- **Quality gates** (`scripts/gate.sh`, `docs/GATES.md`): 37 gates covering unit and e2e tests
  against GreenMail and Stalwart, interop, fuzzing (six libFuzzer targets), gitleaks, goldens and
  accessibility checks, performance at 10k messages, and a provider simulator.
