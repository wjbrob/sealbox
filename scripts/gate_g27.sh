#!/usr/bin/env bash
# Gate G27 — secrets at rest (docs/GATES.md, docs/SECRETS_AT_REST.md).
#   1. unit tests: envelope round trip, AAD binding (swapped rows/columns fail), tamper,
#      nonce uniqueness, HKDF/Argon2id/KCV, keyring headless fallback, legacy migration,
#      rewrap, wrong key -> ProfileLocked, wrapped store columns (sealbox-core, whole crate:
#      every unit test of the engine runs against a keyed store)
#   2. mobile builds keep the OS keyring out of the dependency graph (Android/iOS)
#   3. GreenMail end-to-end + a local sealbox-server (cargo test -p sealbox-cli --test gate_g27
#      -- --ignored, u46-u50 + u73-u74; SEALBOX_G27_SERVER enables the guest_links.secret check):
#      passphrase profile + real mail -> no key/password/body/attachment bytes on disk;
#      wrong passphrase -> ProfileLocked, nothing read or written; legacy plaintext profile
#      migrates on first keyed open; rewrap passphrase -> new works, old fails; draft
#      attachments are sealed blobs (`draft attach`), never on disk in the clear, sent intact
#   4. G4 and G8 still pass (their harness opens every profile with a passphrase, so they
#      run on the wrapped store)
# Optional: SEALBOX_TEST_REAL_KEYRING=1 adds a real OS-keyring round trip (writes and deletes
# one entry `sealbox/sealbox-unit-test-<pid>` in the session keyring).
# Exit 0 only if every step passes.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
. scripts/env.sh
step() { echo; echo "### G27 $*"; }
fail() { echo "G27 FAIL: $*" >&2; exit 1; }

step "1/4 unit tests (sealbox-core: vault, store, and every engine test on a keyed store)"
UNIT_LOG="$(mktemp)"
cargo test -p sealbox-core -q 2>&1 | tee "$UNIT_LOG" | grep -E "^test result|FAILED|panicked" || true
grep -q "FAILED\|panicked\|error\[" "$UNIT_LOG" && { rm -f "$UNIT_LOG"; fail "sealbox-core unit tests"; }
grep -q "^test result: ok" "$UNIT_LOG" || { rm -f "$UNIT_LOG"; fail "sealbox-core unit tests did not run"; }
UNIT="$(grep -E '^test result: ok' "$UNIT_LOG" | head -1)"
rm -f "$UNIT_LOG"
cargo test -p sealbox-core -q -- vault:: store::tests 2>&1 | grep -E "^test result: ok. [1-9]" \
  || fail "vault/store unit tests"
if [ "${SEALBOX_TEST_REAL_KEYRING:-0}" = "1" ]; then
  SEALBOX_TEST_REAL_KEYRING=1 cargo test -p sealbox-core -q -- real_keyring 2>&1 | grep -E "^test result: ok. 1 passed" \
    || fail "real OS keyring round trip"
  echo "G27 real keyring round trip: ok"
fi

step "2/4 mobile dependency graph has no OS keyring"
for t in aarch64-linux-android aarch64-apple-ios; do
  n="$(cargo tree -q --target "$t" -p sealbox-core -e normal 2>/dev/null | grep -cE 'keyring|zbus|security-framework' || true)"
  [ "$n" = "0" ] || fail "$t pulls keyring crates ($n)"
  echo "$t: keyring-free"
done

step "3/4 GreenMail end-to-end (u46-u50, drafts u73-u74) + a sealbox-server for the guest-link secret"
testing/mail_up.sh || fail "GreenMail not reachable"
cargo build -q -p sealbox-server -p sealbox-cli || fail "build"
TD="${CARGO_TARGET_DIR:-target}"
LOGDIR="$TD/gate_g27"; mkdir -p "$LOGDIR"
SERVER_PID=""
stop_server() {
  # Only the PID this script started, identity-checked.
  if [ -n "$SERVER_PID" ] && [ "$(ps -o comm= -p "$SERVER_PID" 2>/dev/null)" = "sealbox-server" ]; then
    kill "$SERVER_PID" 2>/dev/null
    for _ in $(seq 1 50); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.1; done
  fi
  SERVER_PID=""
}
trap stop_server EXIT
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
rm -f "$LOGDIR"/server.sqlite*
SEALBOX_BIND="127.0.0.1:$PORT" SEALBOX_DB="$LOGDIR/server.sqlite" SEALBOX_STATIC_DIR="$PWD/web/guest" \
SEALBOX_PUBLIC_URL="http://127.0.0.1:$PORT" SEALBOX_SMTP_HOST=127.0.0.1 SEALBOX_SMTP_PORT=3025 \
SEALBOX_SMTP_TLS=none SEALBOX_SMTP_FROM="Sealbox <noreply@sealbox.test>" \
  "$TD/debug/sealbox-server" > "$LOGDIR/server.log" 2>&1 &
SERVER_PID=$!
up=0
for _ in $(seq 1 60); do
  curl -fsS --max-time 2 "http://127.0.0.1:$PORT/v1/health" >/dev/null 2>&1 && { up=1; break; }
  sleep 0.25
done
[ "$up" = 1 ] || { tail -20 "$LOGDIR/server.log"; fail "sealbox-server did not start"; }
SEALBOX_G27_SERVER="http://127.0.0.1:$PORT" cargo test -p sealbox-cli --test gate_g27 -q -- --ignored --nocapture \
  > "$LOGDIR/e2e.log" 2>&1
rc=$?
stop_server
if [ $rc -ne 0 ] || ! grep -q "test result: ok. 3 passed" "$LOGDIR/e2e.log"; then
  grep -E "panicked|assert" -A6 "$LOGDIR/e2e.log" | head -40 >&2; fail "gate_g27 e2e (log: $LOGDIR/e2e.log)"
fi
grep -q "G27 guest_links.secret: wrapped on disk, unwraps after rewrap" "$LOGDIR/e2e.log" \
  || fail "guest_links check did not run"
grep -q "G27 draft_blobs.data: sealed on disk, sent intact, removed with the draft" "$LOGDIR/e2e.log" \
  || fail "draft attachment check did not run"
grep -E "^test result: ok. 3 passed|^G27 guest_links|^G27 draft_blobs" "$LOGDIR/e2e.log"

step "4/4 G4 + G8 on passphrase-wrapped profiles"
for g in g4 g8; do
  LOG="$(mktemp)"
  cargo test -p sealbox-cli --test "gate_$g" -q -- --ignored >"$LOG" 2>&1
  rc=$?
  if [ $rc -ne 0 ] || ! grep -qE "^test result: ok" "$LOG"; then
    grep -E "panicked|assert|FAILED" -A6 "$LOG" | head -40 >&2
    rm -f "$LOG"; fail "$g with wrapped profiles"
  fi
  echo "$g: $(grep -E '^test result: ok' "$LOG" | head -1)"
  rm -f "$LOG"
done

echo
echo "G27 PASS — unit: $UNIT; e2e gate_g27 3/3 (incl. guest_links.secret, draft blobs); G4+G8 green on wrapped profiles"
exit 0
