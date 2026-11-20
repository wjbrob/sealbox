#!/usr/bin/env bash
# scripts/gate_flutter.sh — gate G9 (docs/GATES.md): the Flutter client.
#
#   PASS  ⇔  every step below exits 0:
#     rust glue crate (app/rust): cargo fmt --check, clippy -D warnings, cargo test
#     flutter pub get · flutter analyze · flutter test · flutter build linux --debug
#     smoke run: the built Linux binary stays up for $SMOKE_SECONDS under Xvfb AND prints the
#       "[sealbox] bridge OK" line, i.e. a real OpenPGP key was generated in Rust and its
#       fingerprint crossed the flutter_rust_bridge boundary.
#
# Non-interactive by construction (no prompts, analytics off). Logs: target/gate_flutter/.
# Never kills anything it did not start; PIDs are identity-checked with `ps -o comm=` first.

set -u -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/app"
FLUTTER_HOME="${FLUTTER_ROOT:-$HOME/flutter}"
export PATH="$FLUTTER_HOME/bin:$HOME/.cargo/bin:$PATH"
export CI=true                       # flutter tool: no interactive prompts / spinners
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/app-rust}"   # for app/rust's own cargo steps
LOGDIR="$ROOT/target/gate_flutter"
SMOKE_SECONDS="${SMOKE_SECONDS:-5}"
mkdir -p "$LOGDIR"

RESULTS=()
FAILED=0

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
rs() { (cd "$APP/rust" && "$@"); }

preflight() {
  local missing=0
  for t in flutter dart cargo rustup cmake ninja clang pkg-config; do
    if ! command -v "$t" >/dev/null 2>&1; then echo "missing tool: $t"; missing=1; fi
  done
  [ $missing -eq 0 ] || return 1
  flutter config --no-analytics --enable-linux-desktop >/dev/null 2>&1 || return 1
  echo "flutter : $(flutter --version 2>/dev/null | head -n 1)"
  echo "dart    : $(dart --version 2>&1)"
  echo "cargo   : $(cargo --version)"
  if command -v flutter_rust_bridge_codegen >/dev/null 2>&1; then
    echo "frb     : $(flutter_rust_bridge_codegen --version)"
  else
    echo "frb     : codegen not installed (only needed to regenerate bindings)"
  fi
  echo "pub dep : $(grep -E '^\s*flutter_rust_bridge:' "$APP/pubspec.yaml" | tr -d ' ')"
  echo "crate   : $(grep -E '^flutter_rust_bridge' "$APP/rust/Cargo.toml")"
}

# `flutter analyze` exits 1 on "server errors" even when the analysis itself finished with
# "No issues found!". On this host the only such error is the analysis server failing to
# create inotify file watchers (EMFILE: fs.inotify.max_user_instances exhausted by other
# processes). Watchers are irrelevant to a one-shot analysis, so accept exactly that case —
# and only when the analyzer reports no issues. Anything else fails.
run_analyze() {
  local out rc
  out="$(cd "$APP" && flutter analyze --no-pub 2>&1)"; rc=$?
  printf '%s\n' "$out" | grep -v 'Too many open files'
  [ $rc -eq 0 ] && return 0
  local server_errors emfile
  server_errors=$(printf '%s\n' "$out" | grep -c '^Error from the analysis server')
  emfile=$(printf '%s\n' "$out" | grep -c '^Error from the analysis server.*Too many open files')
  # Environmental check: when the analyzer printed no detail lines, treat "Server error(s)" as the
  # known inotify exhaustion only if the per-user instance budget really is (nearly) spent.
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

# Launch the built binary for $SMOKE_SECONDS on an X server and require both that it is still
# running and that the Rust-bridge self-check line was printed.
run_smoke() {
  local bin="$APP/build/linux/x64/debug/bundle/sealbox_app"
  [ -x "$bin" ] || { echo "binary missing: $bin"; return 1; }
  local applog="$LOGDIR/smoke_app.log" xlog="$LOGDIR/smoke_xvfb.log"
  local display="" xpid=""
  if command -v Xvfb >/dev/null 2>&1; then
    local n=90
    while [ -e "/tmp/.X$n-lock" ] && [ $n -lt 250 ]; do n=$((n + 1)); done
    Xvfb ":$n" -screen 0 1280x800x24 -nolisten tcp >"$xlog" 2>&1 &
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

  DISPLAY="$display" "$bin" >"$applog" 2>&1 &
  local apid=$!
  sleep "$SMOKE_SECONDS"
  local alive=0 bridge=0
  [ "$(ps -o comm= -p "$apid" 2>/dev/null)" = "sealbox_app" ] && alive=1
  grep -q '^\[sealbox\] bridge OK' "$applog" && bridge=1

  # Tear down only what we started, after confirming identity.
  if [ $alive -eq 1 ]; then kill "$apid" 2>/dev/null; wait "$apid" 2>/dev/null; fi
  if [ -n "$xpid" ] && [ "$(ps -o comm= -p "$xpid" 2>/dev/null)" = "Xvfb" ]; then
    kill "$xpid" 2>/dev/null; wait "$xpid" 2>/dev/null
  fi

  echo "--- app output:"
  cat "$applog"
  echo "---"
  if [ $alive -eq 1 ] && [ $bridge -eq 1 ]; then
    echo "app stayed up for ${SMOKE_SECONDS}s and the Rust bridge self-check (real OpenPGP keygen) printed"
    return 0
  fi
  [ $alive -eq 0 ] && echo "FAIL: the app exited within ${SMOKE_SECONDS}s"
  [ $bridge -eq 0 ] && echo "FAIL: no '[sealbox] bridge OK' line in the app output"
  return 1
}

say "Sealbox gate G9 — Flutter client ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
step "preflight"              preflight
if [ $FAILED -eq 0 ]; then
  step "rust fmt"             rs cargo fmt --check
  step "rust clippy"          rs cargo clippy --all-targets -q -- -D warnings
  step "rust test"            rs cargo test -q
  step "flutter pub get"      fl pub get
  step "flutter analyze"      run_analyze
  step "flutter test"         fl test --no-pub
  step "flutter build linux"  fl build linux --debug --no-pub
  if [ $FAILED -eq 0 ]; then
    step "linux smoke run"    run_smoke
  else
    RESULTS+=("SKIP  linux smoke run (build or tests failed)")
  fi
fi

say "Summary"
printf '  %s\n' "${RESULTS[@]}"
if [ $FAILED -eq 0 ]; then
  echo "GATE G9: PASS"
  exit 0
fi
echo "GATE G9: FAIL"
exit 1
