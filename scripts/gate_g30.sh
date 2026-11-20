#!/usr/bin/env bash
# scripts/gate_g30.sh — gate G30 (docs/GATES.md): identity — key-change alerts, verified
# contacts, key-transparency log. Design: docs/IDENTITY.md.
#
#   PASS  ⇔  every step exits 0:
#     1. testing/mail_up.sh                         GreenMail (users u51–u55 for this gate)
#     2. cargo build sealbox-server + sealbox-cli
#     3. core unit tests: Merkle verifier (RFC 6962 vectors, every size 1..33, odd sizes),
#        STH signatures, canonical leaves, QR payloads, key-change/ack/verify pipeline
#     4. server unit tests: tree + proofs (vectors, sizes 1..40), signed heads, directory diff
#     5. cargo test -p sealbox-server --test gate_g30_server  (publish → entry → proofs verify
#        with the client verifier; forked log swapping a fingerprint detected; tampered head;
#        swapped log key)
#     6. cargo test -p sealbox-server --test gate_g7   (G7 stays green)
#     7. sealbox-server on an ephemeral port, fresh SQLite, challenge mail through GreenMail
#        SMTP; then cargo test -p sealbox-cli --test gate_g30 -- --ignored   (a)–(g)
#
# Never kills anything it did not start; the server PID is identity-checked with `ps -o comm=`.
# Logs: $CARGO_TARGET_DIR/gate_g30/.
set -u -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck disable=SC1090
source "$HOME/.cargo/env" 2>/dev/null || true
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LOGDIR="$CARGO_TARGET_DIR/gate_g30"
mkdir -p "$LOGDIR"

FAILED=0
SERVER_PID=""
say() { printf '\n=== %s\n' "$*"; }
step() {  # step <name> <cmd...>
  local name="$1"; shift
  say "$name"
  if "$@" > "$LOGDIR/$name.log" 2>&1; then
    echo "ok: $name"
    grep -E '^test result:' "$LOGDIR/$name.log" | sed 's/^/    /' || true
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

command -v sqlite3 >/dev/null || { echo "FAIL: sqlite3 not installed (needed to tamper the server DB in step 7)"; exit 1; }

step mail_up testing/mail_up.sh
step build cargo build -q -p sealbox-server -p sealbox-cli
[ "$FAILED" = 0 ] || exit 1

step core_identity_unit cargo test -q -p sealbox-core --lib identity::
step server_kt_unit cargo test -q -p sealbox-server --lib kt::
step server_g30 cargo test -q -p sealbox-server --test gate_g30_server -- --nocapture
step server_g7 cargo test -q -p sealbox-server --test gate_g7

say "sealbox-server (ephemeral port, SMTP → GreenMail)"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
rm -f "$LOGDIR"/server.sqlite*
SEALBOX_BIND="127.0.0.1:$PORT" SEALBOX_DB="$LOGDIR/server.sqlite" SEALBOX_STATIC_DIR="$ROOT/web/guest" \
SEALBOX_PUBLIC_URL="http://127.0.0.1:$PORT" \
SEALBOX_SMTP_HOST=127.0.0.1 SEALBOX_SMTP_PORT=3025 SEALBOX_SMTP_TLS=none \
SEALBOX_SMTP_FROM="Sealbox <noreply@sealbox.test>" RUST_LOG=info \
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
  SEALBOX_G30_SERVER="$SERVER_URL" SEALBOX_G30_DB="$LOGDIR/server.sqlite" \
    step cli_e2e cargo test -q -p sealbox-cli --test gate_g30 -- --ignored --nocapture
else
  echo "FAIL: server did not start"; tail -40 "$LOGDIR/server.log"; FAILED=1
fi
stop_server

if [ "$FAILED" = 0 ]; then echo; echo "G30 PASS"; exit 0; fi
echo; echo "G30 FAIL"; exit 1
