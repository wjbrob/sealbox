#!/usr/bin/env bash
# scripts/gate_g18.sh — gate G18 (docs/GATES.md): desktop production + feedback loop.
#
#   PASS ⇔ all of:
#     1. `flutter build linux --release` succeeds and the bundle contains the Rust engine library;
#     2. scripts/package_linux.sh produces dist/sealbox-linux-x64-<version>.tar.gz containing the
#        launcher, sealbox.desktop, the icon and the bundle (AppImage is a bonus, never required);
#     3. scripts/review_desktop.sh --release --soak 60 captures ≥ 12 distinct screens into
#        review/desktop/<date>/ with index.html + manifest.json, the seeded tour completes, the
#        seeded session ran ≥ 60 s, and the app logs contain zero [ERROR]/exception lines.
# Logs: target/gate_g18/. Nothing it started survives it.
set -u -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
. scripts/env.sh
export CI=true
LOGDIR="$ROOT/target/gate_g18"; mkdir -p "$LOGDIR"
MIN_SCREENS="${MIN_SCREENS:-12}"
SOAK="${SOAK_SECONDS:-60}"
RESULTS=(); FAILED=0
say() { printf '\n=== %s\n' "$*"; }

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
step() {
  local name="$1"; shift
  local log="$LOGDIR/${name//[^A-Za-z0-9_.-]/_}.log"
  say "[$name] $*"
  local rc=0
  "$@" >"$log" 2>&1 || rc=$?
  if [ $rc -eq 0 ]; then echo "    PASS"; RESULTS+=("PASS  $name"); else
    echo "    FAIL (exit $rc) — log: $log"; grep -v 'Too many open files' "$log" | tail -n 30 | sed 's/^/    | /'
    RESULTS+=("FAIL  $name"); FAILED=1
  fi
  return $rc
}

VERSION="$(sed -n 's/^version:[[:space:]]*\([^+[:space:]]*\).*/\1/p' app/pubspec.yaml | head -n1)"
TARBALL="dist/sealbox-linux-x64-$VERSION.tar.gz"
DAY="$(date +%Y-%m-%d)"
OUT="review/desktop/$DAY"

build_release() { (cd app && flutter build linux --release --no-pub) && [ -f app/build/linux/x64/release/bundle/lib/librust_lib_sealbox_app.so ]; }
check_tarball() {
  [ -s "$TARBALL" ] || { echo "missing $TARBALL"; return 1; }
  local listing; listing="$(tar -tzf "$TARBALL")" || return 1
  for f in sealbox sealbox.desktop sealbox.png sealbox.svg bundle/sealbox_app bundle/lib/librust_lib_sealbox_app.so; do
    grep -q "/$f\$" <<<"$listing" || { echo "tarball lacks $f"; return 1; }
  done
  echo "tarball ok: $(du -h "$TARBALL" | cut -f1), $(wc -l <<<"$listing") entries"
  ls -la dist/*.AppImage 2>/dev/null || echo "(no AppImage — optional)"
}
check_review() {
  python3 - "$OUT" "$MIN_SCREENS" "$SOAK" <<'PY'
import json, sys, os
out, min_screens, soak = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
m = json.load(open(os.path.join(out, "manifest.json")))
pngs = [f for f in os.listdir(out) if f.endswith(".png")]
ok = True
def check(cond, msg):
    global ok
    print(("ok   " if cond else "FAIL ") + msg)
    ok = ok and cond
check(m["distinct_screens"] >= min_screens, f"{m['distinct_screens']} distinct screens (≥ {min_screens})")
check(len(pngs) >= min_screens, f"{len(pngs)} PNG files")
check(os.path.exists(os.path.join(out, "index.html")), "index.html present")
s = m.get("sessions", {})
check(s.get("fresh", {}).get("tour_completed", False), "fresh tour completed")
check(s.get("seeded", {}).get("tour_completed", False), "seeded tour completed")
check(s.get("seeded", {}).get("seconds", 0) >= soak, f"seeded session {s.get('seeded', {}).get('seconds', 0)} s (≥ {soak} s)")
check(m["error_lines"] == 0, f"{m['error_lines']} error/exception lines in app logs")
if m["error_lines"]:
    print(open(os.path.join(out, "errors.txt")).read()[:2000])
sys.exit(0 if ok else 1)
PY
}

say "Sealbox gate G18 — desktop production + feedback loop ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
wait_for_build_dir || { echo "GATE G18: FAIL — build dir busy"; exit 1; }
step "flutter build linux --release" build_release
if [ $FAILED -eq 0 ]; then
  step "package_linux"  scripts/package_linux.sh
  step "tarball check"  check_tarball
  step "review_desktop" scripts/review_desktop.sh --release --soak "$SOAK" --out "$OUT"
  step "review check"   check_review
fi

say "Summary"
printf '  %s\n' "${RESULTS[@]}"
if [ $FAILED -eq 0 ]; then echo "GATE G18: PASS"; exit 0; fi
echo "GATE G18: FAIL"; exit 1
