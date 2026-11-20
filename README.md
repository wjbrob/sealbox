# Sealbox

**Private email, without changing your email address.**

Sealbox is a free, open-source, end-to-end-encrypted email client for the accounts you already
have: Gmail, Outlook/Hotmail, iCloud, Fastmail or any IMAP provider. You don't change MX records
or move to a new address.

> **Status: pre-alpha.** Sealbox has not had an independent security audit yet. Don't rely on it
> for sensitive communication until a release says otherwise. Linux and Android are the supported
> platforms today; iOS and macOS come later.

## How it works

1. **Connect your existing account.** Sealbox finds your IMAP/SMTP settings automatically and
   signs in with OAuth2 or an app password.
2. **Write mail as usual.** Every message to a recipient with a key is encrypted and signed with
   OpenPGP: [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580), PGP/MIME with protected subject
   lines, and Autocrypt Level 1 key exchange. It works with Thunderbird, GnuPG, Delta Chat,
   Proton (via OpenPGP) and other OpenPGP users.
3. **Reach anyone.** Recipients without a key get a passphrase-protected **guest link**. They read
   it in the browser, which decrypts locally; the server never sees plaintext.
4. **The interface always shows the encryption status** for each recipient before you send.

### Features
- Encrypt and sign, decrypt and verify, with automatic key discovery (Autocrypt, a key directory
  with email verification) and key-change alerts backed by a **key-transparency log**.
- Mail is stored **encrypted at rest** on the device. Search uses an in-memory index, so no
  plaintext index is written to disk.
- Multi-device and recovery: a 12-word recovery phrase, client-encrypted backups, and transfer to
  another device using the Autocrypt Setup Message.
- Safe HTML mail: remote images are blocked by default, and links show the real URL before you
  open them.
- Local spam filtering with explainable rules and per-user learning, filters, signatures,
  auto-reply, and drafts synced *encrypted* to your provider's Drafts folder.
- Self-hostable backend under AGPL: key directory, guest links, backups and push relay.

## Repository layout

| Path | What |
|---|---|
| `crates/sealbox-crypto` | OpenPGP (rPGP), Autocrypt, guest envelope |
| `crates/sealbox-mail` | PGP/MIME, IMAP, SMTP, OAuth2, autodiscover, HTML sanitiser |
| `crates/sealbox-core` | The engine: accounts, encrypted store, sync and send pipelines |
| `crates/sealbox-cli` | `sealbox` command-line client |
| `crates/sealbox-server` | Backend: key directory, guest messages, backups, transparency log (AGPL) |
| `crates/sealbox-relay` | Push relay: IMAP IDLE to content-free push notifications (AGPL) |
| `crates/sealbox-spam` | Spam classifier and filter engine |
| `app/` | Flutter app (Linux, Android), bridged to the core with flutter_rust_bridge |
| `web/guest/` | Static guest-link viewer |
| `extension/` | Browser extension for Gmail and Outlook on the web (prototype) |
| `docs/` | Architecture, threat model, gates, provider notes |

## Building

Prerequisites: Rust stable (1.85+), Flutter 3.47.8, and Docker for the end-to-end tests. The
interop tests also need `gpg`, `rnp` and `sq`.

```sh
cargo test --workspace                    # Rust unit tests
cargo run -p sealbox-cli -- --help        # the CLI
cd app && flutter pub get && flutter run -d linux
scripts/gate.sh --quick                   # the fast quality gates (docs/GATES.md)
```

Android: install the Android SDK, NDK 27.0.12077973 and `cargo-ndk`, then run
`cd app && flutter build apk`. See `docs/RELEASE.md` for release builds.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Quality gates](docs/GATES.md)
- [Provider notes](docs/PROVIDERS.md)
- [Guest links](docs/GUEST_LINKS.md)
- [Recovery](docs/RECOVERY.md)
- [Self-hosting the push relay](docs/PUSH_RELAY.md)

## Your data stays yours

Your keys are generated and kept on your devices. The backend stores only public keys,
client-encrypted guest messages and client-encrypted backups. All of it can be self-hosted, and you
can export everything as standard OpenPGP. If this project ever stopped, your mail would still be
ordinary encrypted email, readable by any OpenPGP client.

## Contributing and security

- Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md); commits need a DCO sign-off.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Please don't open
  public issues for them.
- Community standards: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Name and logo use:
  [TRADEMARKS.md](TRADEMARKS.md).

## License

- **Clients and libraries** (app, CLI, core, crypto, mail, spam, extension, guest viewer):
  [GPL-3.0-or-later](LICENSE).
- **Server, push relay and provider simulator** (`crates/sealbox-server`, `crates/sealbox-relay`,
  `crates/sealbox-fakeprov`): [AGPL-3.0-or-later](LICENSES/AGPL-3.0-or-later.txt).

Third-party components keep their own licences. See `web/guest/VENDOR.md` (OpenPGP.js, LGPL-3.0),
`extension/wasm/vendor/` and `app/rust_builder/cargokit/`.
