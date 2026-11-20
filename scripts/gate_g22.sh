#!/usr/bin/env bash
# scripts/gate_g22.sh — gate G22 (docs/GATES.md): hosted mailbox ("Create a new Sealbox address").
#
#   PASS  ⇔  every step exits 0:
#     1. testing/stalwart_up.sh                 Stalwart v1.0.0 in docker, bootstrapped, dev listeners up
#     2. cargo build  sealbox-server + sealbox-cli
#     3. cargo test -p sealbox-server --test gate_g22_server       (mocked Stalwart: validation,
#        reservations, caps, invites, shape, rollback)  + the ignored real-Stalwart case
#     4. sealbox-server on an ephemeral port, configured for the local Stalwart
#        (invite mode, per-IP cap 2, fresh database)
#     5. cargo test -p sealbox-cli --test gate_g22 -- --ignored    two hosted accounts via the CLI
#        (unique names per run), encrypted mail between them through Stalwart, sync + decrypt,
#        raw server bytes carry no plaintext, reserved name refused, signup over the cap refused,
#        availability endpoint works
#
# Never kills anything it did not start; the server PID is identity-checked with `ps -o comm=`.
# Logs: target/gate_g22/ (under $CARGO_TARGET_DIR when set).
set -u -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck disable=SC1090
source "$HOME/.cargo/env" 2>/dev/null || true
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LOGDIR="$CARGO_TARGET_DIR/gate_g22"
mkdir -p "$LOGDIR"

STALWART_HTTP="${STALWART_HTTP:-http://127.0.0.1:8084}"
STALWART_ADMIN_USER="${STALWART_ADMIN_USER:-admin}"
STALWART_ADMIN_SECRET="${STALWART_ADMIN_SECRET:-sealbox-stalwart-dev-admin}"
HOSTED_DOMAIN="${SEALBOX_HOSTED_DOMAIN:-hosted.sealbox.test}"
INVITE="g22-invite-$$"

FAILED=0
SERVER_PID=""
say() { printf '\n=== %s\n' "$*"; }
step() {  # step <name> <cmd...>
  local name="$1"; shift
  say "$name"
  if "$@" > "$LOGDIR/$name.log" 2>&1; then
    echo "ok: $name"
  else
    echo "FAIL: $name (see $LOGDIR/$name.log)"; tail -40 "$LOGDIR/$name.log"; FAILED=1
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

step stalwart_up testing/stalwart_up.sh
[ "$FAILED" = 0 ] || exit 1

step build cargo build -q -p sealbox-server -p sealbox-cli
[ "$FAILED" = 0 ] || exit 1

step server_mock_tests cargo test -q -p sealbox-server --test gate_g22_server
SEALBOX_G22_STALWART_URL="$STALWART_HTTP" SEALBOX_STALWART_ADMIN_USER="$STALWART_ADMIN_USER" \
SEALBOX_STALWART_ADMIN_SECRET="$STALWART_ADMIN_SECRET" SEALBOX_HOSTED_DOMAIN="$HOSTED_DOMAIN" \
  step server_real_stalwart cargo test -q -p sealbox-server --test gate_g22_server -- --ignored

say "sealbox-server (ephemeral port, invite mode, per-IP cap 2)"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
rm -f "$LOGDIR"/server.sqlite*
SEALBOX_BIND="127.0.0.1:$PORT" SEALBOX_DB="$LOGDIR/server.sqlite" SEALBOX_STATIC_DIR="$ROOT/web/guest" \
SEALBOX_HOSTED_DOMAIN="$HOSTED_DOMAIN" SEALBOX_STALWART_URL="$STALWART_HTTP" \
SEALBOX_STALWART_ADMIN_USER="$STALWART_ADMIN_USER" SEALBOX_STALWART_ADMIN_SECRET="$STALWART_ADMIN_SECRET" \
SEALBOX_HOSTED_IMAP_HOST=127.0.0.1 SEALBOX_HOSTED_IMAP_PORT=1143 SEALBOX_HOSTED_IMAP_SECURITY=plain \
SEALBOX_HOSTED_SMTP_HOST=127.0.0.1 SEALBOX_HOSTED_SMTP_PORT=1587 SEALBOX_HOSTED_SMTP_SECURITY=plain \
SEALBOX_HOSTED_SIGNUPS=invite SEALBOX_HOSTED_INVITES="$INVITE" SEALBOX_HOSTED_PER_IP_DAILY=2 \
SEALBOX_HOSTED_GLOBAL_DAILY=100 SEALBOX_HOSTED_IP_HASH_KEY="g22-$$" RUST_LOG=info \
  "$CARGO_TARGET_DIR/debug/sealbox-server" > "$LOGDIR/server.log" 2>&1 &
SERVER_PID=$!
SERVER_URL="http://127.0.0.1:$PORT"
for _ in $(seq 1 60); do
  curl -fsS --max-time 2 "$SERVER_URL/v1/health" >/dev/null 2>&1 && break
  sleep 0.25
done
if ! curl -fsS --max-time 2 "$SERVER_URL/v1/health" >/dev/null 2>&1; then
  echo "FAIL: sealbox-server did not come up"; tail -20 "$LOGDIR/server.log"; exit 1
fi
echo "server pid $SERVER_PID ($(ps -o comm= -p "$SERVER_PID")) at $SERVER_URL"

SEALBOX_G22_SERVER_URL="$SERVER_URL" SEALBOX_G22_INVITE="$INVITE" SEALBOX_G22_DOMAIN="$HOSTED_DOMAIN" \
SEALBOX_G22_IMAP=127.0.0.1:1143 \
  step cli_e2e cargo test -q -p sealbox-cli --test gate_g22 -- --ignored --nocapture

stop_server
# The server must never log a mailbox password (handlers log e-mail + outcome only).
if grep -qE 'password=|"password"' "$LOGDIR/server.log"; then
  echo "FAIL: server log mentions a password"; FAILED=1
fi

say "summary"
if [ "$FAILED" = 0 ]; then echo "G22 PASS"; exit 0; else echo "G22 FAIL"; exit 1; fi
