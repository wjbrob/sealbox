#!/usr/bin/env bash
# scripts/gate_g17.sh — gate G17 (docs/GATES.md): app ↔ core wiring.
#
#   PASS ⇔ app/integration_test/core_wiring_test.dart passes on the Linux desktop build
#   under a private Xvfb, against the local GreenMail (testing/mail_up.sh), with the real
#   `sealbox` CLI playing the peer (u02) and the app driving u01 through its own UI:
#   onboarding (manual servers) → sync → plaintext + encrypted mail with the right badges →
#   decrypted body + verified signature → encrypted reply from the compose screen → the CLI
#   decrypts it → the Sent copy is readable in the app → reference threading (In-Reply-To with
#   a changed subject joins, same subject without references stays apart) → delete to Trash
#   and the Trash chip's first-open sync → mark unread → Settings → Server → publish the key
#   to a local sealbox-server (challenge mail through GreenMail) → the IDLE watch stream arms.
#   Then search_drafts_test.dart (u66 app, u67/u68 CLI peers): search by body word (incl. a
#   decrypted one) and by sender, "No results", open a hit; compose → autosaved draft → Drafts
#   chip → resume → send encrypted → the CLI reads it → the draft is gone.
#
# Logs: target/gate_g17/. Never kills anything it did not start (PIDs identity-checked).
set -u -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
. scripts/env.sh
export CI=true
LOGDIR="$ROOT/target/gate_g17"
RUN="$LOGDIR/run-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN"
say() { printf '\n=== %s\n' "$*"; }
fail() { echo "GATE G17: FAIL — $*"; exit 1; }

# Seven agents share this checkout: a `flutter build|test -d linux` already running in app/
# (another session's gate) uses the same CMake build dir, so wait for it instead of colliding.
wait_for_build_dir() {
  local waited=0
  while ps -eo args 2>/dev/null | grep -v grep | grep -qE "ninja -C $ROOT/app/build/linux|tool_backend.sh linux-x64|flutter_tools.*flutter_test_listener"; do
    [ $waited -eq 0 ] && echo "another Flutter Linux build is running in app/ — waiting for it (up to 20 min)"
    sleep 10; waited=$((waited + 10))
    [ $waited -ge 1200 ] && { echo "gave up waiting for the build dir"; return 1; }
  done
  return 0
}

say "Sealbox gate G17 — app ↔ core wiring ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
for t in flutter cargo Xvfb docker; do
  command -v "$t" >/dev/null 2>&1 || fail "missing tool: $t"
done

say "[mail] GreenMail"
testing/mail_up.sh || fail "GreenMail not reachable"
# The app's profile (and key) is fresh every run, so whatever earlier runs left in u01/u02
# is unreadable noise that only slows the first sync and pads the list (120 conversations
# by 2026-10-29). Empty both users' INBOX and Sent over IMAP first (testing/gm_expunge.py).
say "[mail] empty u01/u02 + u66–u68 INBOX + Sent + Drafts (earlier runs' mail and draft copies)"
for u in u01 u02 u66 u67 u68; do
  for f in INBOX Sent Drafts; do
    if n="$(python3 -I testing/gm_expunge.py "$u" "${u}pw" "$f" 2>>"$RUN/expunge.log")"; then
      echo "emptied $u@sealbox.test/$f ($n message(s) from earlier runs)"
    else
      echo "warning: could not empty $u@sealbox.test/$f (log $RUN/expunge.log); earlier runs' mail stays"
    fi
  done
done

say "[cli] cargo build -p sealbox-cli -p sealbox-server"
CLI_TARGET="${SEALBOX_CLI_TARGET_DIR:-$ROOT/target}"
if ! CARGO_TARGET_DIR="$CLI_TARGET" cargo build -q -p sealbox-cli -p sealbox-server >"$RUN/cargo.log" 2>&1; then
  tail -n 30 "$RUN/cargo.log"; fail "CLI/server build failed (log: $RUN/cargo.log)"
fi
CLI="$CLI_TARGET/debug/sealbox"
[ -x "$CLI" ] || fail "CLI binary missing at $CLI"
echo "cli: $CLI ($("$CLI" --version 2>/dev/null | head -n1 || echo '?'))"
SERVER_BIN="$CLI_TARGET/debug/sealbox-server"
[ -x "$SERVER_BIN" ] || fail "server binary missing at $SERVER_BIN"

APP_PROFILE="$RUN/profile-u01"
PEER_PROFILE="$RUN/profile-u02"
# Second test (search + saved drafts): the app is u66, the CLI peers u67/u68 share one profile.
APP_PROFILE2="$RUN/profile-u66"
PEER_PROFILE2="$RUN/profile-u67-u68"
mkdir -p "$APP_PROFILE" "$PEER_PROFILE" "$APP_PROFILE2" "$PEER_PROFILE2"
chmod 700 "$APP_PROFILE" "$PEER_PROFILE" "$APP_PROFILE2" "$PEER_PROFILE2"

say "[x] private Xvfb"
XDISP_FILE="$RUN/xdisplay"; : > "$XDISP_FILE"
Xvfb -displayfd 3 -screen 0 1280x800x24 -nolisten tcp -noreset 3>"$XDISP_FILE" >"$RUN/xvfb.log" 2>&1 &
XPID=$!
n=""
for _ in $(seq 1 100); do n="$(tr -dc '0-9' < "$XDISP_FILE")"; [ -n "$n" ] && break; sleep 0.1; done
[ -n "$n" ] && [ "$(ps -o comm= -p "$XPID" 2>/dev/null)" = "Xvfb" ] || fail "Xvfb did not start (log: $RUN/xvfb.log)"
echo "Xvfb on :$n (pid $XPID)"
SERVER_PID=""
cleanup() {
  if [ "$(ps -o comm= -p "$XPID" 2>/dev/null)" = "Xvfb" ]; then kill "$XPID" 2>/dev/null; wait "$XPID" 2>/dev/null; fi
  if [ -n "$SERVER_PID" ] && [ "$(ps -o comm= -p "$SERVER_PID" 2>/dev/null)" = "sealbox-server" ]; then
    kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null
  fi
}
trap cleanup EXIT

# The key directory the app publishes to (as scripts/gate_g30.sh runs it): an ephemeral port,
# a fresh SQLite under $RUN, challenge mail through GreenMail's SMTP to u01's INBOX.
say "[server] sealbox-server (ephemeral port, SMTP → GreenMail)"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
SEALBOX_BIND="127.0.0.1:$PORT" SEALBOX_DB="$RUN/server.sqlite" SEALBOX_STATIC_DIR="$ROOT/web/guest" \
SEALBOX_PUBLIC_URL="http://127.0.0.1:$PORT" \
SEALBOX_SMTP_HOST=127.0.0.1 SEALBOX_SMTP_PORT=3025 SEALBOX_SMTP_TLS=none \
SEALBOX_SMTP_FROM="Sealbox <noreply@sealbox.test>" RUST_LOG=info \
  "$SERVER_BIN" >"$RUN/server.log" 2>&1 &
SERVER_PID=$!
SERVER_URL="http://127.0.0.1:$PORT"
up=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 2 "$SERVER_URL/v1/health" >/dev/null 2>&1; then up=1; break; fi
  sleep 0.25
done
[ "$up" = 1 ] || { tail -n 30 "$RUN/server.log"; fail "sealbox-server did not start (log: $RUN/server.log)"; }
echo "server: $SERVER_URL (pid $SERVER_PID)"

wait_for_build_dir || fail "build dir busy"
# run_itest NAME APP_PROFILE PEER_PROFILE — one Flutter integration test on the debug Linux build.
run_itest() {
  local name="$1" app_profile="$2" peer_profile="$3" log="$RUN/flutter_test_$1.log" rc=0
  say "[flutter] integration test $name (debug Linux build + run)"
  (
    cd app && DISPLAY=":$n" SEALBOX_LOG=warn flutter test "integration_test/$name.dart" -d linux --no-pub \
      --dart-define=SEALBOX_PROFILE="$app_profile" \
      --dart-define=SEALBOX_CLI="$CLI" \
      --dart-define=SEALBOX_PEER_PROFILE="$peer_profile" \
      --dart-define=SEALBOX_TEST_SERVER="$SERVER_URL"
  ) >"$log" 2>&1 || rc=$?
  grep -v 'Too many open files' "$log" | tail -n 40 | sed 's/^/    | /'
  if [ $rc -eq 0 ] && grep -q 'All tests passed' "$log"; then
    RESULTS+=("  PASS  $name (log: $log)"); return 0
  fi
  RESULTS+=("  FAIL  $name (exit $rc; log: $log)"); return 1
}
RESULTS=(); ok=1
run_itest core_wiring_test "$APP_PROFILE" "$PEER_PROFILE" || ok=0
# The second test only runs when the first passed (same build, same server; a broken bridge
# would fail both for one reason).
if [ $ok = 1 ]; then run_itest search_drafts_test "$APP_PROFILE2" "$PEER_PROFILE2" || ok=0; fi

say "Summary"
printf '%s\n' "${RESULTS[@]}"
if [ $ok = 1 ]; then
  # Secrets stay out of the tree: the profiles hold test keys + GreenMail passwords.
  rm -rf "$APP_PROFILE" "$PEER_PROFILE" "$APP_PROFILE2" "$PEER_PROFILE2" "$RUN"/server.sqlite*
  echo "GATE G17: PASS"
  exit 0
fi
echo "GATE G17: FAIL"
exit 1
