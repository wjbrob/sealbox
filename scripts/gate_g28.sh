#!/usr/bin/env bash
# Gate G28 — browser-extension phase (docs/GATES.md, extension/README.md).
#   1. native defaults unchanged: cargo test -p sealbox-crypto -p sealbox-mail; sealbox-mail
#      also checks with --no-default-features (pure MIME, what the wasm build uses)
#   2. wasm core: extension/wasm → wasm32-unknown-unknown (release) → wasm-bindgen (web + nodejs)
#   3. Node interop: wasm ↔ /usr/bin/gpg both directions + PGP/MIME build→parse round trip
#      (isolated GNUPGHOME under the target dir)
#   4. MV3 extension builds (esbuild) and `web-ext lint` is clean (warnings are errors)
#   5. Outlook add-in manifest validates (office-addin-manifest; uses Microsoft's online
#      validation service, so this step needs network)
#   6. fixture e2e: headless Chromium loads the unpacked extension against a Gmail-like
#      fixture page + a mock of the Gmail/OAuth endpoints; encrypt → mock receives PGP/MIME gpg
#      decrypts; gpg PGP/MIME served by the mock decrypts in the panel. A FIXTURE, not Gmail.
# Exit 0 only if every step passes.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
. scripts/env.sh
ROOT="$PWD"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"  # shared with the other gates; scratch goes to target/g28-*
WB_VERSION=0.2.118 # must equal the wasm-bindgen pin in extension/wasm/Cargo.toml
BROWSER="${SEALBOX_CHROMIUM:-/usr/bin/chromium}"
step() { echo; echo "### G28 $*"; }
fail() { echo "G28 FAIL: $*" >&2; exit 1; }

step "0/6 toolchain"
rustup target list --installed | grep -qx wasm32-unknown-unknown || rustup target add wasm32-unknown-unknown || fail "rustup target add wasm32-unknown-unknown"
if [ "$(wasm-bindgen --version 2>/dev/null | awk '{print $2}')" != "$WB_VERSION" ]; then
  cargo install wasm-bindgen-cli --version "$WB_VERSION" --locked || fail "install wasm-bindgen-cli $WB_VERSION"
fi
command -v gpg >/dev/null || fail "gpg not installed"
[ -x "$BROWSER" ] || fail "no Chromium at $BROWSER (set SEALBOX_CHROMIUM)"
if [ ! -d extension/node_modules ]; then
  (cd extension && npm ci --no-audit --no-fund) || fail "npm ci in extension/"
fi
echo "G28 tools: $(wasm-bindgen --version), node $(node --version), $(gpg --version | head -1), $("$BROWSER" --version)"

step "1/6 native sealbox-crypto + sealbox-mail (defaults identical)"
LOG="$(mktemp)"
cargo test -p sealbox-crypto -p sealbox-mail -q 2>&1 | tee "$LOG" | grep -E "^test result|FAILED|panicked" || true
if grep -q "FAILED\|panicked\|error\[" "$LOG" || ! grep -q "^test result: ok" "$LOG"; then rm -f "$LOG"; fail "cargo test -p sealbox-crypto -p sealbox-mail"; fi
rm -f "$LOG"
cargo check -q -p sealbox-mail --no-default-features || fail "sealbox-mail --no-default-features"
echo "G28 native: crypto+mail tests ok; sealbox-mail builds without 'net'"

step "2/6 wasm core build"
(cd extension/wasm && cargo build -q --release --target wasm32-unknown-unknown) || fail "wasm build"
WASM="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/sealbox_wasm.wasm"
rm -rf extension/wasm/pkg-web extension/wasm/pkg-node
wasm-bindgen --target web --out-dir extension/wasm/pkg-web "$WASM" || fail "wasm-bindgen web"
wasm-bindgen --target nodejs --out-dir extension/wasm/pkg-node "$WASM" || fail "wasm-bindgen nodejs"
echo '{"type":"commonjs"}' > extension/wasm/pkg-node/package.json
grep -q "export function encryptAndSign" extension/wasm/pkg-web/sealbox_wasm.d.ts || fail "TS types missing encryptAndSign"
echo "G28 wasm: $(stat -c %s extension/wasm/pkg-web/sealbox_wasm_bg.wasm) bytes ($(gzip -9c extension/wasm/pkg-web/sealbox_wasm_bg.wasm | wc -c) gzipped), $(grep -c '^export function' extension/wasm/pkg-web/sealbox_wasm.d.ts) exported functions"

step "3/6 Node: wasm <-> gpg round trip + PGP/MIME"
node extension/wasm/test/roundtrip.mjs extension/wasm/pkg-node "$CARGO_TARGET_DIR/g28-wasm" || fail "wasm/gpg round trip"

step "4/6 extension build + web-ext lint"
(cd extension && node build.mjs) || fail "extension build"
(cd extension && npx web-ext lint --source-dir dist/firefox --self-hosted --warnings-as-errors --output json > "$CARGO_TARGET_DIR/g28-lint.json" 2>/dev/null)
LINT_RC=$?
node -e 'const s=require(process.argv[1]).summary;console.log(`G28 web-ext lint: errors ${s.errors}, warnings ${s.warnings}, notices ${s.notices}`);process.exit(s.errors+s.warnings+s.notices?1:0)' "$CARGO_TARGET_DIR/g28-lint.json" || fail "web-ext lint not clean"
[ "$LINT_RC" = 0 ] || fail "web-ext lint exit $LINT_RC"

step "5/6 Outlook add-in manifest"
(cd extension && npx office-addin-manifest validate outlook-addin/manifest.xml > "$CARGO_TARGET_DIR/g28-office.log" 2>&1) || { tail -20 "$CARGO_TARGET_DIR/g28-office.log"; fail "office-addin-manifest validate"; }
grep -q "The manifest is valid." "$CARGO_TARGET_DIR/g28-office.log" || fail "office manifest not reported valid"
echo "G28 office-addin-manifest: The manifest is valid."

step "6/6 fixture e2e (headless Chromium + unpacked extension + Gmail API mock)"
(cd extension && node test/fixture/e2e.mjs --dist dist/chrome --wasm-node wasm/pkg-node --scratch "$CARGO_TARGET_DIR/g28-e2e" --browser "$BROWSER") || fail "fixture e2e"

echo
echo "G28 PASS"
