#!/usr/bin/env bash
# scripts/gate_g19.sh — gate G19 (docs/GATES.md): the mobile feedback loop.
#
#   PASS ⇔ scripts/review_android.sh ran to completion AND its manifest.json shows
#     1. the headless emulator booted in ≤ 300 s (a reused, already-booted emulator counts as 0 s)
#     2. the debug APK was built and installed
#     3. the on-device smoke test passed (app launches, first screen renders, navigation to
#        inbox / compose / settings works — asserted inside integration_test/android_smoke_test.dart)
#     4. ≥ 6 screenshots were captured into review/android/<date>/
#     5. logcat holds no fatal exception / native crash for dev.sealbox.sealbox_app
#
# Non-interactive; never kills anything it did not start (the loop script owns the emulator).
# Knobs pass through: KEEP_EMULATOR=1, SKIP_BUILD=1, REVIEW_DATE=YYYY-MM-DD.
set -u -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
DATE="${REVIEW_DATE:-$(date -u +%F)}"
export REVIEW_DATE="$DATE" BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"
MIN_SHOTS="${MIN_SHOTS:-6}"

printf '\n=== Sealbox gate G19 — mobile feedback loop (%s)\n' "$(date -u +%FT%TZ)"
scripts/review_android.sh
LOOP_RC=$?

MANIFEST="review/android/$DATE/manifest.json"
printf '\n=== G19 checks (%s)\n' "$MANIFEST"
if [ ! -f "$MANIFEST" ]; then
  echo "  FAIL  manifest.json missing (review_android.sh exit $LOOP_RC)"
  echo "GATE G19: FAIL"; exit 1
fi
MIN_SHOTS="$MIN_SHOTS" LOOP_RC="$LOOP_RC" python3 - "$MANIFEST" <<'PY'
import json, os, sys
m = json.load(open(sys.argv[1]))
min_shots = int(os.environ["MIN_SHOTS"]); loop_rc = int(os.environ["LOOP_RC"])
emu, apk, launch, smoke, log = m["emulator"], m["apk"], m["launch"], m["smoke_test"], m["logcat"]
boot_ok = emu["boot_seconds"] >= 0 and emu["boot_seconds"] <= emu.get("boot_timeout_seconds", 300)
checks = [
    (f"emulator boot ≤ {emu.get('boot_timeout_seconds', 300)} s", boot_ok,
     f"{emu['boot_seconds']} s" + ("" if emu["started_by_this_run"] else " (reused running emulator)")),
    ("APK built + installed", apk["built"] and apk["installed"], f"{apk['app']['bytes']} bytes"),
    ("app launches (first screen + Rust bridge line)", launch["ok"], f"bridge line seen: {launch['bridge_line_seen']}, am TotalTime {launch['am_total_time_ms']} ms"),
    ("on-device smoke test (inbox / compose / settings navigation)", smoke["passed"],
     f"exit {smoke['exit_code']}, mode {(smoke.get('report') or {}).get('mode', '?')}, "
     f"steps ok {sum(1 for s in ((smoke.get('report') or {}).get('steps') or []) if s.get('ok'))}/{len((smoke.get('report') or {}).get('steps') or [])}"),
    (f"≥ {min_shots} screenshots", m["screenshot_count"] >= min_shots, ", ".join(s["file"] for s in m["screens"])),
    ("no fatal exception in logcat for our package", log["fatal_exceptions_our_package"] == 0,
     f"fatal {log['fatal_exceptions_our_package']}, unhandled Dart exceptions {log['dart_unhandled_exceptions']} (informational), {log['lines']} lines"),
    ("no credentials or IMAP/SMTP protocol traces in logcat", log.get("credential_lines", 0) == 0,
     f"{log.get('credential_lines', 0)} line(s)" + (f" at {log.get('credential_line_numbers')}" if log.get("credential_lines", 0) else "")),
    ("review_android.sh exit 0", loop_rc == 0, f"exit {loop_rc}"),
]
failed = 0
for name, ok, detail in checks:
    print(f"  {'PASS' if ok else 'FAIL'}  {name} — {detail}")
    failed += 0 if ok else 1
print(f"\nreview set: review/android/{m['date']}/index.html")
print("GATE G19: PASS" if failed == 0 else f"GATE G19: FAIL ({failed} check(s))")
sys.exit(0 if failed == 0 else 1)
PY
