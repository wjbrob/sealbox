# Releasing Sealbox

Gate **G26** (`scripts/gate_release.sh`) is the mechanical definition of "releasable". This page
is the human procedure around it: versioning, cutting a release, what the artifacts are, how store
signing works, and which steps only a human with the right accounts can do.

## 1. Versioning — one source

| File | Holds | Written by |
|---|---|---|
| `VERSION` | `X.Y.Z` (semver, optional `-pre`) | you, via `scripts/version.sh set` / `bump` |
| `app/pubspec.yaml` | `version: X.Y.Z+BUILD` — BUILD is the Android `versionCode` and iOS `CFBundleVersion`; it must strictly increase for every store upload | `scripts/version.sh` |
| `Cargo.toml` | `[workspace.package] version = "X.Y.Z"` — every crate inherits it (`version.workspace = true`) | `scripts/version.sh` |
| `docs/PRIVACY_POLICY.md` | `**Applies to:** Sealbox X.Y.Z` | `scripts/version.sh` |
| `CHANGELOG.md` | a `## [X.Y.Z] - YYYY-MM-DD` section per release ([Keep a Changelog](https://keepachangelog.com)) | you |

```bash
scripts/version.sh             # 0.1.0+1
scripts/version.sh check       # exit 1 on any mismatch (gate_release.sh runs this first)
scripts/version.sh sync        # re-derive the three files from VERSION (keeps BUILD)
scripts/version.sh set 0.2.0   # new version, BUILD = previous + 1
scripts/version.sh bump patch  # 0.2.0 → 0.2.1
```

`app/rust/Cargo.toml` (the flutter_rust_bridge glue crate, built by cargokit outside the workspace)
keeps its own `version`; it is not shipped as a crate and is left alone.

## 2. Cutting a release

1. `scripts/version.sh set X.Y.Z` — then move the `## [Unreleased]` notes in `CHANGELOG.md` into a
   new `## [X.Y.Z] - <date>` section and keep an empty `[Unreleased]`.
2. Make sure the tree is green: `scripts/gate.sh` (full) or at least
   `scripts/gate.sh --only G0,G9,G10,G26`. G26 alone: `scripts/gate_release.sh`. It
   - checks version consistency and that `CHANGELOG.md` / `docs/PRIVACY_POLICY.md` name `X.Y.Z`;
   - runs the **log-redaction audit** (section 5) over Rust and Dart sources;
   - builds the **Linux release bundle** (`scripts/package_linux.sh` when present — gate G18's
     packager — otherwise `flutter build linux --release` tarred by the gate);
   - builds the **signed release APK and AAB** (TEST keystore unless you point
     `SEALBOX_KEY_PROPERTIES` at a real one), and verifies the signatures with `apksigner verify`
     (APK) and `jarsigner -verify` + `keytool -printcert` (AAB), checking the signer certificate;
   - parses every workflow under `.github/workflows/` (and runs `actionlint` if installed);
   - writes everything to `dist/` with a `SHA256SUMS` file.
3. Commit (`release: vX.Y.Z`) and tag: `git tag -a vX.Y.Z -m "Sealbox X.Y.Z"`.
4. Push the tag once a remote exists (`git remote add origin …`; CLAUDE.md rule 5): the `v*` tag
   triggers `.github/workflows/ci.yml`, which builds Linux, Android, macOS, iOS (no codesign) and
   Windows and uploads each as a workflow artifact; the `release-gate` job re-runs
   `scripts/gate_release.sh` on a clean runner and uploads `dist/`.
5. Upload to the stores (section 4) — by a human.

### Artifacts (`dist/`)

| File | Produced by | Notes |
|---|---|---|
| `sealbox-X.Y.Z+B-linux-x64.tar.gz` | `flutter build linux --release` (or `scripts/package_linux.sh`) | unpack, run `sealbox-X.Y.Z/sealbox_app` |
| `sealbox-X.Y.Z+B-android.apk` | `flutter build apk --release` | signed; universal (arm64-v8a, armeabi-v7a, x86_64); sideload-able |
| `sealbox-X.Y.Z+B-android.aab` | `flutter build appbundle --release` | signed; what Google Play takes |
| `SHA256SUMS` | the gate | `sha256sum -c SHA256SUMS` |

Verify a signature by hand:
```bash
$ANDROID_HOME/build-tools/35.0.0/apksigner verify --print-certs dist/sealbox-*-android.apk
jarsigner -verify dist/sealbox-*-android.aab && keytool -printcert -jarfile dist/sealbox-*-android.aab
```

## 3. Debug vs release signing on Android

`app/android/app/build.gradle.kts` resolves a key-properties file in this order:
`$SEALBOX_KEY_PROPERTIES` (a path) → `app/android/key.properties` (git-ignored) → none.
With none, `--release` builds are signed with the **debug** key (they install, they must never
ship). Debug builds (`flutter build apk --debug`, gate G10, the emulator loop) never read it.

The committed **TEST keystore** `testing/keys/sealbox-test.jks` (alias/passwords `sealbox-test`,
see `testing/keys/README.md`) exists so that the gate and CI can prove the signing path works. It
is public. Nothing signed with it may reach a user or a store.

## 4. Store signing — what only a human can do

### Google Play
1. Create a Play developer account (one-off fee) and the app entry. **The application id
   `dev.sealbox.sealbox_app` becomes permanent at the first upload** — decide the final product
   name/id first.
2. Generate the *upload key* outside the repository, e.g.
   `keytool -genkeypair -v -keystore ~/secure/sealbox-upload.jks -alias upload -keyalg RSA -keysize 4096 -validity 10000`,
   and a `key.properties` next to it. Never commit either; back them up offline.
3. Enrol in **Play App Signing** (Google holds the app signing key, you keep the upload key).
4. Build with `SEALBOX_KEY_PROPERTIES=~/secure/key.properties scripts/gate_release.sh`, upload the
   `.aab`. In CI, store the keystore as a base64 secret (`SEALBOX_KEYSTORE_BASE64`) plus the
   properties as `SEALBOX_KEY_PROPERTIES_CONTENT`; the Android job decodes them when present.
5. Play Console forms: Data safety (use section 3 of `docs/PRIVACY_POLICY.md`), content rating,
   privacy-policy URL (the policy must be hosted somewhere public).

### Apple (iOS + macOS)
1. Apple Developer Program membership; bundle identifiers for iOS and macOS; an App Store Connect
   record. iOS cannot be built on this Linux box — the `apple` CI job (macOS runner) builds
   `flutter build ios --no-codesign` and `flutter build macos` today (gate G11 = a green run).
2. Signing: Xcode automatic signing with the team id, or `fastlane match` with a private certificates
   repo. Store the App Store Connect API key as CI secrets when automating TestFlight uploads.
3. macOS outside the App Store needs Developer ID signing + notarization (`xcrun notarytool`).
4. App privacy "nutrition labels" from `docs/PRIVACY_POLICY.md`; export-compliance answer: the app
   uses standard encryption (OpenPGP) — usually the "exempt" self-classification, confirm with counsel.

### Windows / Linux
- Windows: `flutter build windows --release` (CI job). A code-signing certificate (or MSIX +
  Microsoft Store) avoids SmartScreen warnings — optional for now.
- Linux: the tarball; AppImage/Flatpak later (G18). Sign tarballs with a project OpenPGP release key
  and publish the fingerprint.

### Also needed from the human
GitHub remote + Actions enabled (nothing is pushed until `origin` exists) · OAuth client ids for
Google/Microsoft (`docs/PROVIDERS_CONFORMANCE.md`) · the real product name · a domain and hosting for the
backend plus the retention numbers in the privacy policy · legal review of the privacy policy ·
store listing assets (icons, screenshots: `review/android/<date>/` is a good source).

## 5. Log-redaction policy

Sealbox must never write passwords, app passwords, OAuth tokens, client secrets, passphrases,
private keys or message plaintext to any log, console or crash output. `scripts/gate_release.sh`
enforces this with a static audit: it extracts every logging/printing statement in
`crates/**`, `app/rust/src/**` and `app/lib/**` (Rust `println!/eprintln!/dbg!/trace!/debug!/info!/warn!/error!`
including `tracing::`/`log::` paths; Dart `print/debugPrint/log/stdout.write/stderr.write/logger.*`),
and fails when such a statement formats a value whose identifier looks secret-bearing
(`password`, `passwd`, `passphrase`, `secret`, `token`, `access_token`, `refresh_token`, `client_secret`,
`private_key`, `secret_key`, `body`, `plaintext`, `cleartext`, `credential`, `authorization`, `bearer`).
Static words inside the format string, lengths/counts (`body.len()`, `.is_empty()`) and fingerprints
are fine. Test code (`tests/`, `app/test*/`, `#[cfg(test)]` tails) is excluded.

Legitimate exceptions go in `scripts/redaction_allowlist.txt`, one per line, as
`<path prefix>::<regex over the statement text>` with a comment saying why. Prefer fixing the log
line over allow-listing it.

## Export compliance (why we stay on standard cryptography)
Sealbox uses only standard, published algorithms (OpenPGP per RFC 9580: Ed25519/X25519, AES-256, SHA-256;
Argon2id; XChaCha20-Poly1305 for local storage). That keeps the apps inside the mass-market / standard-
algorithm self-classification lanes: Apple's export-compliance questionnaire ("uses encryption" → "standard
algorithms only" → usually exempt from the CCATS/ERN paperwork required for *proprietary* cryptography) and
Google Play's equivalent declaration. Keep it that way: a proprietary algorithm would trigger additional
documentation under US EAR and the French import declaration. Innovate in key management, identity and the
recipient experience, never in the primitives.
