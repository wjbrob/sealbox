# Vendored third-party code — `web/guest/vendor/`

The guest viewer has no build step and loads no remote content (the server's CSP forbids it),
so the OpenPGP implementation is vendored here and served from `/static/vendor/`.

| File | What | Version | SHA-256 |
|---|---|---|---|
| `openpgp.min.js` | OpenPGP.js browser bundle (UMD, defines `window.openpgp`) — loaded by `index.html` | 6.3.2 (released 2026-09-24) | `e19bf4f04f34f24caded3ff3f3643099538b2674a0a94221e2faca75ac3e4aa1` |
| `openpgp.node.min.mjs` | OpenPGP.js Node build (`dist/node/openpgp.min.mjs`) — **tests only**, never served | 6.3.2 | `4ccebb735be5fc2efb47d2f1fdce0d622db555aeeea4b24857d80e842118123d` |
| `LICENSE-openpgpjs.txt` | LGPL-3.0-or-later licence text of OpenPGP.js | — | `e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118` |

Source: <https://cdn.jsdelivr.net/npm/openpgp@6.3.2/dist/openpgp.min.js>,
<https://cdn.jsdelivr.net/npm/openpgp@6.3.2/dist/node/openpgp.min.mjs>,
<https://cdn.jsdelivr.net/npm/openpgp@6.3.2/LICENSE> (npm package `openpgp`, same bytes as
<https://github.com/openpgpjs/openpgpjs/releases/tag/v6.3.2>). Licence: LGPL-3.0+; we ship it
unmodified as a separate file, which satisfies the LGPL for a web page.

## Verifying / updating

```sh
cd web/guest/vendor
sha256sum -c <<'SUMS'
e19bf4f04f34f24caded3ff3f3643099538b2674a0a94221e2faca75ac3e4aa1  openpgp.min.js
4ccebb735be5fc2efb47d2f1fdce0d622db555aeeea4b24857d80e842118123d  openpgp.node.min.mjs
SUMS

# upgrade: pick a release that is at least a couple of weeks old, then
V=6.3.2
curl -fsSLO https://cdn.jsdelivr.net/npm/openpgp@$V/dist/openpgp.min.js
curl -fsSL  https://cdn.jsdelivr.net/npm/openpgp@$V/dist/node/openpgp.min.mjs -o openpgp.node.min.mjs
sha256sum openpgp.min.js openpgp.node.min.mjs   # update the table above
node --test ../test/viewer.test.mjs             # gpg interop must still pass
```

## Notes for the CSP

OpenPGP.js 6 implements the RFC 9580 Argon2 string-to-key function with a bundled WebAssembly
module, which needs `script-src 'wasm-unsafe-eval'` (allowed by the server; it does not permit
JavaScript `eval`). Everything else runs under `script-src 'self'` with Trusted Types enforced.
The Node test loads the *browser* bundle through `vm.runInThisContext`, so the exact bytes the
browser executes are the bytes exercised against `gpg`.
