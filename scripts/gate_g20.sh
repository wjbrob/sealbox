#!/usr/bin/env bash
# scripts/gate_g20.sh — gate G20 (docs/GATES.md): the UI/UX test suite.
#
#   PASS  ⇔  every step below exits 0:
#     flutter pub get · flutter analyze (inotify tolerance copied from gate_flutter.sh)
#     flutter test test/golden_*_test.dart test/a11y_test.dart
#         goldens: every screen × {phone 390×844@3x, desktop 1280×800@1x} × {light, dark},
#                  compared pixel-exact against app/test/goldens/*.png
#         a11y:    textContrast / androidTapTarget / iOSTapTarget / labeledTapTarget per
#                  screen and theme, plus lock-badge and recipient-pill semantics; an
#                  assertion skipped for a recorded finding prints SKIP FINDING-n and
#                  still fails the test if the defect has gone (see test/a11y_test.dart)
#     flutter test -d linux integration_test/ux_flow_test.dart under Xvfb
#         onboarding → inbox → encrypted thread → reply → send → receipt → settings,
#         at 1280×720 and in a 480×900 (phone-layout) window; PNG per step under
#         review/ux-flow/<date>/ (override with SEALBOX_FLOW_SHOTS_DIR)
#   and prints the counts: goldens compared, a11y assertions (passed / skipped), flow steps.
#
# Non-interactive by construction. Logs: target/gate_g20/. Never kills anything it did not
# start; PIDs are identity-checked with `ps -o comm=` first. Docs: docs/UX_TESTING.md.

set -u -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/app"
FLUTTER_HOME="${FLUTTER_ROOT:-$HOME/flutter}"
export PATH="$FLUTTER_HOME/bin:$HOME/.cargo/bin:$PATH"
export CI=true                       # flutter tool: no interactive prompts / spinners
LOGDIR="$ROOT/target/gate_g20"
mkdir -p "$LOGDIR"
SHOTS_DIR="${SEALBOX_FLOW_SHOTS_DIR:-$ROOT/review/ux-flow/$(date -u +%Y-%m-%d)}"

RESULTS=()
FAILED=0
GOLDENS_COMPARED=0
GOLDEN_FILES=0
A11Y_PASS=0
A11Y_SKIP=0
FLOW_STEPS=0
FLOW_VARIANTS=0

say() { printf '\n=== %s\n' "$*"; }

# step NAME CMD... — runs CMD, logs to $LOGDIR/NAME.log, records PASS/FAIL.
step() {
  local name="$1"; shift
  local log="$LOGDIR/${name//[^A-Za-z0-9_.-]/_}.log"
  say "[$name] $*"
  local rc
  if "$@" >"$log" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  if [ $rc -eq 0 ]; then
    echo "    PASS"
    RESULTS+=("PASS  $name")
  else
    echo "    FAIL (exit $rc) — log: $log"
    grep -v 'Too many open files' "$log" | tail -n 40 | sed 's/^/    | /'
    RESULTS+=("FAIL  $name")
    FAILED=1
  fi
  return $rc
}

fl() { (cd "$APP" && flutter "$@"); }

preflight() {
  local missing=0
  for t in flutter dart; do
    if ! command -v "$t" >/dev/null 2>&1; then echo "missing tool: $t"; missing=1; fi
  done
  [ $missing -eq 0 ] || return 1
  flutter config --no-analytics --enable-linux-desktop >/dev/null 2>&1 || return 1
  echo "flutter : $(flutter --version 2>/dev/null | head -n 1)"
  if command -v Xvfb >/dev/null 2>&1; then
    echo "Xvfb    : $(command -v Xvfb)"
  else
    echo "Xvfb    : not installed (the flow test needs it or a DISPLAY): sudo apt-get install -y xvfb"
  fi
  for t in cargo rustup cmake ninja clang pkg-config; do
    command -v "$t" >/dev/null 2>&1 || echo "note    : $t not on PATH — the Linux build for the flow test may fail"
  done
  GOLDEN_FILES=$(find "$APP/test/goldens" -name '*.png' 2>/dev/null | wc -l)
  echo "goldens : $GOLDEN_FILES PNG files under app/test/goldens/"
  [ "$GOLDEN_FILES" -gt 0 ] || { echo "no goldens committed — run: cd app && flutter test --update-goldens test/golden_*_test.dart"; return 1; }
}

# Copied from scripts/gate_flutter.sh (keep identical): `flutter analyze` exits 1 on "server
# errors" even when the analysis itself finished with "No issues found!". On this host the
# only such error is the analysis server failing to create inotify file watchers (EMFILE:
# fs.inotify.max_user_instances exhausted by other processes). Watchers are irrelevant to
# a one-shot analysis, so accept exactly that case — and only when the analyzer reports no
# issues. Anything else fails.
run_analyze() {
  local out rc
  out="$(cd "$APP" && flutter analyze --no-pub 2>&1)"; rc=$?
  printf '%s\n' "$out" | grep -v 'Too many open files'
  [ $rc -eq 0 ] && return 0
  local server_errors emfile
  server_errors=$(printf '%s\n' "$out" | grep -c '^Error from the analysis server')
  emfile=$(printf '%s\n' "$out" | grep -c '^Error from the analysis server.*Too many open files')
  local inuse limit
  inuse=$(find /proc/[0-9]*/fd -lname 'anon_inode:inotify' -user "$USER" 2>/dev/null | wc -l)
  limit=$(cat /proc/sys/fs/inotify/max_user_instances 2>/dev/null || echo 0)
  if printf '%s\n' "$out" | grep -q 'No issues found!' && printf '%s\n' "$out" | grep -q 'Server error(s) occurred' \
     && [ "$server_errors" -eq 0 ] && [ "$limit" -gt 0 ] && [ $((inuse + 4)) -ge "$limit" ]; then
    echo "NOTE: analyzer finished with 'No issues found!' but reported server errors while inotify" \
         "instances are exhausted ($inuse of $limit in use by $USER); treating as environmental." \
         "Raise fs.inotify.max_user_instances to fix the host."
    return 0
  fi
  if printf '%s\n' "$out" | grep -q 'No issues found!' \
     && [ "$server_errors" -gt 0 ] && [ "$server_errors" -eq "$emfile" ]; then
    echo "NOTE: analyzer finished with 'No issues found!'; ignoring $emfile analysis-server" \
         "file-watcher EMFILE errors (inotify instances in use:" \
         "$(find /proc/[0-9]*/fd -lname 'anon_inode:inotify' -user "$USER" 2>/dev/null | wc -l)" \
         "of $(cat /proc/sys/fs/inotify/max_user_instances 2>/dev/null || echo '?'))."
    return 0
  fi
  return $rc
}

# Goldens + accessibility in one `flutter test` run; counts come from the marker lines the
# tests print (GOLDEN_COMPARED <name>, A11Y_ASSERT <id> PASS|SKIP FINDING-n).
run_widget_suite() {
  local log="$LOGDIR/widget_suite.log"
  local files=()
  for f in "$APP"/test/golden_*_test.dart "$APP"/test/a11y_test.dart; do
    [ -f "$f" ] && files+=("${f#"$APP"/}")
  done
  [ ${#files[@]} -gt 0 ] || { echo "no test/golden_*_test.dart or test/a11y_test.dart"; return 1; }
  echo "files: ${files[*]}"
  local rc
  (cd "$APP" && flutter test --no-pub --reporter expanded "${files[@]}") >"$log" 2>&1
  rc=$?
  grep -v 'Too many open files' "$log" | grep -E '^[0-9:]+ \+[0-9]+' | tail -n 1
  GOLDENS_COMPARED=$(grep -o 'GOLDEN_COMPARED [a-z0-9_]*' "$log" | sort -u | wc -l)
  A11Y_PASS=$(grep -o 'A11Y_ASSERT [A-Za-z0-9_/]* PASS' "$log" | sort -u | wc -l)
  A11Y_SKIP=$(grep -o 'A11Y_ASSERT [A-Za-z0-9_/]* SKIP FINDING-[0-9]*' "$log" | sort -u | wc -l)
  echo "goldens compared: $GOLDENS_COMPARED (files on disk: $GOLDEN_FILES)"
  echo "a11y assertions : $A11Y_PASS passed, $A11Y_SKIP skipped for recorded findings"
  if [ "$A11Y_SKIP" -gt 0 ]; then
    grep -o 'A11Y_ASSERT [A-Za-z0-9_/]* SKIP FINDING-[0-9]*' "$log" | sort -u | sed 's/^/    /'
  fi
  if [ $rc -ne 0 ]; then
    grep -v 'Too many open files' "$log" | grep -E 'Golden|failures/|Expected|Actual|Which|FAIL|Error|Exception|fail' | head -n 30
    return $rc
  fi
  if [ "$GOLDENS_COMPARED" -ne "$GOLDEN_FILES" ]; then
    echo "WARNING: $GOLDEN_FILES golden PNGs on disk but $GOLDENS_COMPARED compared — stale or missing goldens?"
    echo "  on disk but not compared:"
    comm -23 <(find "$APP/test/goldens" -name '*.png' -printf '%f\n' | sed 's/\.png$//' | sort) \
             <(grep -o 'GOLDEN_COMPARED [a-z0-9_]*' "$log" | awk '{print $2}' | sort -u) | sed 's/^/    /'
    return 1
  fi
  grep -q 'All tests passed!' "$log"
}

# The end-to-end flow on the Linux desktop embedder. Starts a private Xvfb when no DISPLAY
# is usable (same approach as gate_flutter.sh's smoke run) and tears down only what it started.
run_flow() {
  local log="$LOGDIR/flow.log" xlog="$LOGDIR/flow_xvfb.log"
  local display="" xpid=""
  if command -v Xvfb >/dev/null 2>&1; then
    local n=90
    while [ -e "/tmp/.X$n-lock" ] && [ $n -lt 250 ]; do n=$((n + 1)); done
    Xvfb ":$n" -screen 0 1280x1024x24 -nolisten tcp >"$xlog" 2>&1 &
    xpid=$!
    for _ in $(seq 1 50); do [ -e "/tmp/.X$n-lock" ] && break; sleep 0.1; done
    display=":$n"
    echo "Xvfb on $display (pid $xpid)"
  elif [ -n "${DISPLAY:-}" ]; then
    echo "Xvfb not installed; using DISPLAY=$DISPLAY"
    display="$DISPLAY"
  else
    echo "Xvfb is not installed and no DISPLAY is set: sudo apt-get install -y xvfb"
    return 1
  fi

  mkdir -p "$SHOTS_DIR"
  echo "step screenshots → $SHOTS_DIR"
  local rc
  (cd "$APP" && DISPLAY="$display" SEALBOX_FLOW_SHOTS_DIR="$SHOTS_DIR" \
     flutter test --no-pub -d linux --reporter expanded integration_test/ux_flow_test.dart) >"$log" 2>&1
  rc=$?

  if [ -n "$xpid" ] && [ "$(ps -o comm= -p "$xpid" 2>/dev/null)" = "Xvfb" ]; then
    kill "$xpid" 2>/dev/null; wait "$xpid" 2>/dev/null
  fi

  FLOW_STEPS=$(grep -o 'FLOW_STEP [a-z]* [0-9]*:' "$log" | sort -u | wc -l)
  FLOW_VARIANTS=$(grep -o 'FLOW_DONE [a-z]*' "$log" | sort -u | wc -l)
  grep -o 'FLOW_STEP [a-z]* [0-9]*: .*' "$log" | sed 's/^/    /'
  echo "flow steps: $FLOW_STEPS across $FLOW_VARIANTS window variants"
  if [ $rc -ne 0 ]; then
    grep -v 'Too many open files' "$log" | grep -E 'Error|Exception|FAIL|timed out|Expected|Actual|Which' | head -n 30
    return $rc
  fi
  [ "$FLOW_VARIANTS" -eq 2 ] || { echo "expected 2 completed variants (desktop, narrow), got $FLOW_VARIANTS"; return 1; }
  grep -q 'All tests passed!' "$log"
}

say "Sealbox gate G20 — UI/UX test suite ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
step "preflight"              preflight
if [ $FAILED -eq 0 ]; then
  step "flutter pub get"      fl pub get
  step "flutter analyze"      run_analyze
  step "goldens + a11y"       run_widget_suite
  step "ux flow (Xvfb)"       run_flow
fi

say "Summary"
printf '  %s\n' "${RESULTS[@]}"
echo "  goldens compared : $GOLDENS_COMPARED (PNG files: $GOLDEN_FILES)"
echo "  a11y assertions  : $A11Y_PASS passed, $A11Y_SKIP skipped for recorded findings (review/ux-findings-*.md)"
echo "  flow steps       : $FLOW_STEPS ($FLOW_VARIANTS variants; screenshots: $SHOTS_DIR)"
if [ $FAILED -eq 0 ]; then
  echo "GATE G20: PASS"
  exit 0
fi
echo "GATE G20: FAIL"
exit 1
