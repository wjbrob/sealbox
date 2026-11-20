# Sealbox browser extension and Outlook add-in (gate G28)

End-to-end encryption inside the webmail people already use, built on the same Rust crypto
and MIME code as the app (`sealbox-crypto` + `sealbox-mail::mime`) compiled to WebAssembly.

```
extension/
  wasm/                 Rust → wasm32-unknown-unknown (own [workspace]); wasm-bindgen JS API + TS types
    src/lib.rs          the JS API (below)
    test/roundtrip.mjs  Node: wasm ↔ gpg both directions, PGP/MIME build→parse, key wrapping
    vendor/mail-builder crates.io mail-builder 2.0.0 + a cfg(wasm32) clock patch (SEALBOX_PATCH.md)
  chrome/               MV3 extension for Chrome and Firefox
    static/             manifest.json, options/compose/reader pages, CSS
    src/background.js   service worker: OAuth (launchWebAuthFlow + PKCE) + the Gmail REST API
    src/content.js      Gmail content script — places a button and a panel, nothing else
    src/gmail-selectors.js  THE ONLY Gmail DOM knowledge (see "Selectors policy")
    src/options.js | compose.js | reader.js   extension pages; the wasm runs here
  outlook-addin/        Office.js add-in: manifest.xml + taskpane (same wasm)
  test/fixture/         gmail.html (fixture DOM), mock-google.mjs (OAuth + Gmail API mock), e2e.mjs
  build.mjs             esbuild → dist/chrome, dist/firefox, dist/outlook-addin
```

## Architecture

```
 mail.google.com tab                         extension origin (chrome-extension://…)
 ┌──────────────────────────────┐            ┌──────────────────────────────────────────┐
 │ content.js                   │  "is id X  │ background.js (service worker)           │
 │  • "Sealbox" button after    │  PGP/MIME?"│  • launchWebAuthFlow + PKCE S256         │
 │    div[gh="cm"]              ├──────────► │  • Gmail REST API (fetch, Bearer token)  │
 │  • "Decrypt with Sealbox"    │            │  • never sees keys or plaintext          │
 │    bar on API-confirmed      │            └──────────────▲───────────────────────────┘
 │    PGP/MIME messages         │                           │ raw RFC 5322 (base64url)
 │  • <iframe> of compose.html /│            ┌──────────────┴───────────────────────────┐
 │    reader.html (extension    │  embeds    │ compose.html / reader.html / options.html│
 │    origin: the page cannot   ├──────────► │  sealbox_wasm (rPGP + PGP/MIME)          │
 │    read into it)             │            │  keys: storage.local (wrapped),          │
 └──────────────────────────────┘            │        storage.session (unlocked)        │
                                             └──────────────────────────────────────────┘
```

* **Send**: compose panel → `encryptDraft` (protected headers, outer Subject `...`, Autocrypt
  header, encrypt to recipients + self, sign) → `users.messages.send` with the raw message.
* **Read**: content script asks the worker whether a message is `multipart/encrypted`
  (`users.messages.get?format=metadata&metadataHeaders=Content-Type`); if so it places the bar;
  the reader panel fetches `users.messages.get?format=raw`, learns the sender's Autocrypt key,
  and runs `decryptMessage`. Text is rendered as text; an HTML part goes into a `sandbox=""` iframe.
* **Keys**: generated or imported in the options page; stored in `chrome.storage.local` only as
  `wrapSecret` output (Argon2id 64 MiB / t=3 / p=1 → XChaCha20-Poly1305, in wasm). The unlocked
  key lives in `chrome.storage.session` (memory-only, not exposed to content scripts).
  The worker keeps the access token in session storage and persists only the refresh token.
* **Recipients without a key**: compose refuses to send (nothing goes out in plaintext). The
  guest-link fallback of the app is not in the extension yet.

## Documented-API rule (owner's rule — do not cross)

* Gmail **only** through the Gmail REST API: `users.getProfile`, `users.messages.get`
  (`format=raw` / `format=metadata`), `users.messages.list`, `users.messages.send` (raw), with
  OAuth from `chrome.identity.launchWebAuthFlow` + PKCE. No scraping of message content, no
  posting through the page, no undocumented endpoints, no Gmail Apps Script add-on (that runs
  on Google's servers — not end to end).
* Outlook **only** through Office.js: `item.body.getAsync/setAsync`, `getAllInternetHeadersAsync`,
  `getAttachmentContentAsync`, `item.to/cc.getAsync`, `internetHeaders.setAsync` (Mailbox 1.8).
* The fixture e2e enforces the Gmail half: it fails if the extension makes any request outside
  that endpoint list.

## Selectors policy

All Gmail DOM selectors live in `chrome/src/gmail-selectors.js` with a version note
(`GMAIL_SELECTORS_VERSION = '2026-10'`). They are used **only** to place the compose button
(`div[gh="cm"]`) and the decrypt bar (`div[data-legacy-message-id]`, before `div.a3s`); the one
value read from the DOM is the message id attribute, which is the API message id. If Gmail
changes its markup the buttons disappear — the extension never falls back to scraping. CI checks
them against `test/fixture/gmail.html`, which mimics exactly these hooks and nothing more; it
does not prove they still match live Gmail.

## JS API (wasm, `wasm/pkg-web/sealbox_wasm.d.ts`)

| function | does |
|---|---|
| `generateIdentity(name, email)` | v4 Ed25519 + Curve25519 key (gpg-compatible) → `IdentityInfo` incl. unlocked `secretArmored` |
| `importIdentity(armoredSecret, passphrase?)` | import (optionally protected) secret key |
| `exportPublicKey(armoredSecret)` / `inspectPublicKey(armoredPublic)` | public key / fingerprint, uids |
| `encryptAndSign(plain, recipientsArmored[], signerSecret?)` | armored OpenPGP message |
| `decryptAndVerify(message, secretsArmored[], knownKeysArmored[])` | `{plaintext, text, signatures, signedByKnownKey}` |
| `finalizeDraft(draft)` | fill Message-ID / Date (JS clock) |
| `renderInnerForEncryption(draft)` | the protected-headers MIME entity to encrypt |
| `buildPgpMimeEncrypted(draft, ciphertext)` | RFC 3156 `multipart/encrypted` raw message |
| `encryptDraft(draft, recipients[], signer?)` | the three above in one call |
| `parseMessage(rawRfc822)` / `parseDecryptedInner(raw)` | classify + headers / protected headers + body |
| `decryptMessage(raw, secrets[], known[])` | parse → decrypt → inner, PGP/MIME or inline |
| `autocryptHeader(addr, publicArmored, mutual?)` | `Autocrypt:` value (minimal key, fold-safe) |
| `parseAutocryptHeaders(values[], fromAddr?)` | Level 1 parsing, `forSender` |
| `wrapSecret(text, passphrase)` / `unwrapSecret(json, passphrase)` | key-store wrapping |

## Building and testing

`scripts/gate_g28.sh` does everything (and is what counts). By hand:

```bash
source ~/.cargo/env
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.118 --locked     # = the pin in wasm/Cargo.toml
(cd extension/wasm && cargo build --release --target wasm32-unknown-unknown)
wasm-bindgen --target web    --out-dir extension/wasm/pkg-web  target/wasm32-unknown-unknown/release/sealbox_wasm.wasm
wasm-bindgen --target nodejs --out-dir extension/wasm/pkg-node target/wasm32-unknown-unknown/release/sealbox_wasm.wasm
echo '{"type":"commonjs"}' > extension/wasm/pkg-node/package.json
cd extension && npm ci && node build.mjs && npm run lint && npm run validate:outlook
```

(`target/` above is wherever `CARGO_TARGET_DIR` points; the gate uses the repo's `target/`.)

## Loading unpacked

* **Chrome / Edge / Brave**: `chrome://extensions` → Developer mode → *Load unpacked* →
  `extension/dist/chrome`. Open the options (toolbar icon), copy the shown redirect URI into your
  Google OAuth client, paste the client id, *Connect Google*, then create or import a key.
* **Firefox**: `about:debugging#/runtime/this-firefox` → *Load Temporary Add-on* →
  `extension/dist/firefox/manifest.json` (or `npx web-ext run --source-dir dist/firefox`).
* **Outlook**: serve `extension/dist/outlook-addin` over HTTPS at `https://localhost:3000`
  (or edit the URLs in `manifest.xml`) and sideload the manifest (Outlook → *Get Add-ins* →
  *My add-ins* → *Add a custom add-in*). Compose produces **inline PGP** in the body — Office.js
  cannot construct a `multipart/encrypted` MIME tree; reading handles PGP/MIME (the
  `encrypted.asc` attachment via `getAttachmentContentAsync`) and inline PGP.

## What G28 proves, and what it does not

Proven by the gate: the wasm core interoperates with gpg in both directions and builds/parses
PGP/MIME; the extension builds and lints clean; the Office manifest validates (Microsoft's online
validator — needs network); headless Chromium loads the unpacked extension against the fixture,
does the OAuth+PKCE flow against a mock IdP, decrypts a gpg-made PGP/MIME message served by a
Gmail-API mock, and sends a PGP/MIME message the mock receives and gpg decrypts.

**Not** proven: anything against real Gmail or Outlook (live DOM, Google's OAuth client types,
API quotas, very large messages — only the JSON `messages.send` body is used, not the media-upload
endpoint), the Firefox build at runtime (lint only), and the Outlook taskpane at runtime
(manifest validation only). Real-account checks are manual.
