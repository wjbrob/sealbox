#!/usr/bin/env bash
# scripts/gate_g29.sh — gate G29 (docs/GATES.md): guest-link modes (security fix).
#
#   PASS  ⇔  every step exits 0:
#     1. testing/mail_up.sh                         GreenMail (users u41–u45 for this gate)
#     2. cargo build sealbox-server + sealbox-cli
#     3. core unit tests for the guest notification texts / links / modes
#     4. node --test web/guest/test/viewer.test.mjs (viewer core: gpg interop + mode flows,
#        secret never in a request)
#     5. cargo test -p sealbox-server --test gate_g29_server  (in-memory mail sink: gate, codes,
#        lock, tokens, rate limit, hashes only at rest; headless viewer in all three modes)
#     6. cargo test -p sealbox-server --test gate_g7   (G7 stays green)
#     7. sealbox-server on an ephemeral port, fresh SQLite, code mail through GreenMail SMTP,
#        15-minute lock shortened to 3 s; then
#        cargo test -p sealbox-cli --test gate_g29 -- --ignored   (a)–(f) from docs/GATES.md
#
# Never kills anything it did not start; the server PID is identity-checked with `ps -o comm=`.
# Logs: $CARGO_TARGET_DIR/gate_g29/.
set -u -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck disable=SC1090
source "$HOME/.cargo/env" 2>/dev/null || true
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LOGDIR="$CARGO_TARGET_DIR/gate_g29"
mkdir -p "$LOGDIR"
LOCK_SECS=3

FAILED=0
SERVER_PID=""
say() { printf '\n=== %s\n' "$*"; }
step() {  # step <name> <cmd...>
  local name="$1"; shift
  say "$name"
  if "$@" > "$LOGDIR/$name.log" 2>&1; then
    echo "ok: $name"
    grep -E '^test result:|^# (pass|fail) ' "$LOGDIR/$name.log" | sed 's/^/    /' || true
  else
    echo "FAIL: $name (see $LOGDIR/$name.log)"; tail -60 "$LOGDIR/$name.log"; FAILED=1
  fi
}
stop_server() {
  if [ -n "$SERVER_PID" ] && [ "$(ps -o comm= -p "$SERVER_PID" 2>/dev/null)" = "sealbox-server" ]; then
    kill "$SERVER_PID" 2>/dev/null
    for _ in $(seq 1 50); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.1; done
    kill -9 "$SERVER_PID" 2>/dev/null || true
  fi
  SERVER_PID=""
}
trap stop_server EXIT

step mail_up testing/mail_up.sh
step build cargo build -q -p sealbox-server -p sealbox-cli
[ "$FAILED" = 0 ] || exit 1

step core_guest_unit cargo test -q -p sealbox-core --lib guest
step viewer_node node --test web/guest/test/viewer.test.mjs
step server_g29 cargo test -q -p sealbox-server --test gate_g29_server
step server_g7 cargo test -q -p sealbox-server --test gate_g7

say "sealbox-server (ephemeral port, SMTP → GreenMail, lock ${LOCK_SECS}s)"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
rm -f "$LOGDIR"/server.sqlite*
SEALBOX_BIND="127.0.0.1:$PORT" SEALBOX_DB="$LOGDIR/server.sqlite" SEALBOX_STATIC_DIR="$ROOT/web/guest" \
SEALBOX_PUBLIC_URL="http://127.0.0.1:$PORT" \
SEALBOX_SMTP_HOST=127.0.0.1 SEALBOX_SMTP_PORT=3025 SEALBOX_SMTP_TLS=none \
SEALBOX_SMTP_FROM="Sealbox <noreply@sealbox.test>" SEALBOX_GUEST_CODE_LOCK_SECS="$LOCK_SECS" \
SEALBOX_PURGE_INTERVAL_SECS=5 RUST_LOG=info \
  "$CARGO_TARGET_DIR/debug/sealbox-server" > "$LOGDIR/server.log" 2>&1 &
SERVER_PID=$!
SERVER_URL="http://127.0.0.1:$PORT"
up=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 2 "$SERVER_URL/v1/health" >/dev/null 2>&1; then up=1; break; fi
  sleep 0.25
done
if [ "$up" = 1 ]; then
  echo "ok: server at $SERVER_URL (pid $SERVER_PID)"
  SEALBOX_G29_SERVER="$SERVER_URL" SEALBOX_G29_DB="$LOGDIR/server.sqlite" SEALBOX_G29_LOCK_SECS="$LOCK_SECS" \
    step cli_e2e cargo test -q -p sealbox-cli --test gate_g29 -- --ignored --nocapture
else
  echo "FAIL: server did not start"; tail -40 "$LOGDIR/server.log"; FAILED=1
fi
stop_server

# The server log must not carry secrets either (route templates only).
if grep -qE '/g/[A-Za-z0-9_-]{22}#|token=' "$LOGDIR/server.log"; then
  echo "FAIL: server log contains a link fragment or token"; FAILED=1
fi

if [ "$FAILED" = 0 ]; then echo; echo "G29 PASS"; exit 0; fi
echo; echo "G29 FAIL"; exit 1
