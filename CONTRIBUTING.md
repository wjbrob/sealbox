# Contributing to Sealbox

Thanks for your interest. You can help by reporting bugs, improving docs, adding provider support,
writing interop tests or reviewing the cryptography. All of it is welcome.

## Ground rules

- **Security issues go to [SECURITY.md](SECURITY.md)**, never to a public issue.
- Be kind; see the [Code of Conduct](CODE_OF_CONDUCT.md).
- Discuss large changes in an issue first, so nobody's work is wasted.

## Developer Certificate of Origin (DCO)

Sealbox uses the [Developer Certificate of Origin](https://developercertificate.org/) instead of
a CLA. Sign off every commit:

```sh
git commit -s -m "mail: handle UIDVALIDITY change during reconcile"
```

The sign-off certifies that you wrote the change, or otherwise have the right to submit it, under
the project's licences: GPL-3.0-or-later for the clients, AGPL-3.0-or-later for the server, relay
and simulator. Commits without a `Signed-off-by:` line can't be merged.

## Development setup

See the [README](README.md#building) for prerequisites. In short:

```sh
cargo test --workspace
scripts/gate.sh --quick                   # fast gates: build, fmt, clippy, unit tests, interop
testing/mail_up.sh && scripts/gate.sh     # full run, including the docker-based e2e gates
```

`docs/GATES.md` lists every gate and what its PASS means. A gate counts as passing only when
`scripts/gate.sh` observed it pass.

## Pull requests

- Keep each PR focused on one change. Use the commit subject style `area: what changed`, for
  example `sync: …`, `app: …` or `crypto: …`.
- Rust: run `cargo fmt` and `cargo clippy --all-targets -- -D warnings` until both are clean. Use
  `thiserror` in libraries and `anyhow` in binaries, and no `unwrap()` outside tests.
- Flutter: run `flutter analyze` and `flutter test`, and update goldens deliberately
  (`flutter test --update-goldens`), explaining why in the PR.
- **Every behaviour change comes with a test.** Cross-crate behaviour comes with an end-to-end test
  under `crates/sealbox-cli/tests` or `testing/`.
- **Interop before invention.** Follow RFC 9580, Autocrypt, RFC 3156 and the protected-headers
  draft. Only invent a format when no standard covers the need.
- If you change a bridged type in `app/rust/src/api`, re-run flutter_rust_bridge codegen and update
  `app/rust/bridge.fingerprint`.
- Never commit secrets or real account data. Real-provider configuration belongs in the
  gitignored `.gate/` directory.

## Good first contributions

Look for issues labelled `good first issue` or `help wanted`. Provider quirks (`docs/PROVIDERS.md`),
translations and documentation are good places to start.
