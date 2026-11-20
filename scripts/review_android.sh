#!/usr/bin/env bash
# scripts/review_android.sh — the Android visual feedback loop (gate G19, docs/GATES.md).
#
# What it does, in order:
#   1. makes sure the emulator package, the API-35 x86_64 system image and the AVD
#      `sealbox_api35` (pixel_6 profile) exist — installs/creates them when missing;
#   2. reuses a running `sealbox_api35` emulator, else boots one headless
#      (-no-window -no-audio -no-boot-anim -gpu swiftshader_indirect -accel on -no-snapshot)
#      and waits for sys.boot_completed (≤ $BOOT_TIMEOUT s);
#   3. builds the x86_64 debug APK (real app) and the smoke-test APK
#      (entrypoint integration_test/android_smoke_test.dart) with `flutter build apk --debug`;
#   4. installs + launches the real app, waits for the "[sealbox] bridge OK" line and takes a
#      device screencap (00-device-launch.png);
#   5. runs the on-device smoke test through `flutter drive` — the test walks launch → inbox →
#      thread → compose → settings → onboarding and ships one Flutter screenshot per screen to
#      the host (test_driver/integration_test.dart → NN-<screen>.png);
#   6. dumps logcat, counts fatal exceptions / native crashes of our package, and writes
#      review/android/<YYYY-MM-DD>/{NN-<screen>.png, index.html, manifest.json, logcat.txt,
#      smoke_report.json};
#   7. shuts down ONLY the emulator it started (PID identity-checked with `ps -o comm=`).
#
# Idempotent and re-runnable; a re-run on the same day replaces that day's PNGs (REVIEW.md is kept).
# Exit 0 ⇔ build, install, launch and the smoke test all succeeded. The quantitative thresholds
# (boot time, ≥ 6 screenshots, 0 fatals) are enforced by scripts/gate_g19.sh from manifest.json.
#
# Environment knobs:
#   REVIEW_DATE=YYYY-MM-DD  output day (default: today, UTC)      KEEP_EMULATOR=1  leave the emulator up
#   BOOT_TIMEOUT=300        seconds to wait for boot               DRIVE_TIMEOUT=600  seconds per flutter drive attempt (1 retry)
#   SKIP_BUILD=1            reuse target/review_android/*.apk      EMULATOR_PORT=5584 console port (auto-bumped if busy)
#   AVD_NAME=sealbox_api35
set -u -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
. scripts/env.sh
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
: "${ANDROID_HOME:?ANDROID_HOME is not set — install the SDK at ~/android-sdk (scripts/env.sh exports it)}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
# The SDK's adb must win over /usr/bin/adb (a version mismatch makes the two restart each other's server).
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
export CI=true

AVD="${AVD_NAME:-sealbox_api35}"
SYSIMG="system-images;android-35;google_apis;x86_64"
PKG="dev.sealbox.sealbox_app"
ACTIVITY="$PKG/.MainActivity"
DATE="${REVIEW_DATE:-$(date -u +%F)}"
OUT="$ROOT/review/android/$DATE"
WORK="$ROOT/target/review_android"
LOGS="$WORK/logs"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"
DRIVE_TIMEOUT="${DRIVE_TIMEOUT:-600}"
KEEP_EMULATOR="${KEEP_EMULATOR:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
PORT="${EMULATOR_PORT:-5584}"
APK_DEBUG="$WORK/app-debug-x64.apk"
APK_SMOKE="$WORK/app-smoke-x64.apk"
mkdir -p "$OUT" "$LOGS"

SERIAL=""; EMU_PID=""; STARTED=0; BOOT_SECONDS=-1
BUILD_OK=0; INSTALL_OK=0; LAUNCH_OK=0; BRIDGE_OK=0; LAUNCH_MS=-1; DRIVE_RC=-1; DRIVE_OK=0
RESULTS=(); OVERALL=0
RUN_AT="$(date -u +%FT%TZ)"

say()  { printf '\n=== %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
ok()   { RESULTS+=("PASS  $1"); echo "    PASS  $1"; }
bad()  { RESULTS+=("FAIL  $1"); echo "    FAIL  $1"; OVERALL=1; }
adbs() { adb -s "$SERIAL" "$@"; }
prop() { adbs shell getprop "$1" 2>/dev/null | tr -d '\r'; }

# The emulator launcher execs qemu in place, so the PID we started reports comm "qemu-system-x86".
emu_alive() {
  [ -n "$EMU_PID" ] && kill -0 "$EMU_PID" 2>/dev/null \
    && [[ "$(ps -o comm= -p "$EMU_PID" 2>/dev/null)" =~ ^(qemu-system|emulator) ]]
}

cleanup() {
  local rc=$?
  trap - EXIT
  [ -n "$SERIAL" ] && adbs shell am force-stop "$PKG" >/dev/null 2>&1
  if [ "$STARTED" = 1 ] && [ "$KEEP_EMULATOR" != 1 ]; then
    say "shutting down the emulator this run started ($SERIAL, pid $EMU_PID)"
    adbs emu kill >/dev/null 2>&1
    for _ in $(seq 1 30); do emu_alive || break; sleep 1; done
    if emu_alive; then note "still up after 30 s: SIGTERM"; kill "$EMU_PID" 2>/dev/null; for _ in $(seq 1 10); do emu_alive || break; sleep 1; done; fi
    if emu_alive; then note "SIGKILL"; kill -9 "$EMU_PID" 2>/dev/null; fi
    wait "$EMU_PID" 2>/dev/null
    note "emulator stopped"
  elif [ "$STARTED" = 1 ]; then
    note "KEEP_EMULATOR=1: leaving $SERIAL (pid $EMU_PID) running"
  fi
  exit "$rc"
}
trap cleanup EXIT

say "Sealbox Android review loop — $DATE ($RUN_AT) → $OUT"

# ---------------------------------------------------------------- 1. SDK pieces + AVD
say "[sdk] emulator, system image, AVD $AVD"
for t in flutter sdkmanager avdmanager python3 unzip; do
  command -v "$t" >/dev/null 2>&1 || { bad "tool missing: $t"; exit 1; }
done
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then bad "/dev/kvm not accessible (add the user to the kvm group)"; exit 1; fi
if [ ! -x "$ANDROID_HOME/emulator/emulator" ] || [ ! -f "$ANDROID_HOME/system-images/android-35/google_apis/x86_64/system.img" ]; then
  note "installing emulator + $SYSIMG (one-time, ~1.5 GB)"
  yes 2>/dev/null | sdkmanager --install "emulator" "$SYSIMG" >"$LOGS/sdkmanager.log" 2>&1 \
    || { tail -n 20 "$LOGS/sdkmanager.log"; bad "sdkmanager install"; exit 1; }
fi
AVD_HOME="${ANDROID_AVD_HOME:-$HOME/.android/avd}"
if [ ! -d "$AVD_HOME/$AVD.avd" ]; then
  note "creating AVD $AVD (pixel_6, $SYSIMG)"
  echo no | avdmanager create avd -n "$AVD" -k "$SYSIMG" -d pixel_6 >"$LOGS/avdmanager.log" 2>&1 \
    || { tail -n 20 "$LOGS/avdmanager.log"; bad "avdmanager create avd"; exit 1; }
fi
cfg="$AVD_HOME/$AVD.avd/config.ini"
set_ini() { if grep -q "^$1=" "$cfg" 2>/dev/null; then sed -i "s|^$1=.*|$1=$2|" "$cfg"; else echo "$1=$2" >>"$cfg"; fi; }
set_ini hw.keyboard yes
set_ini hw.gpu.enabled yes
set_ini hw.gpu.mode swiftshader_indirect
ok "sdk + AVD ready ($AVD_HOME/$AVD.avd)"

# ---------------------------------------------------------------- 2. emulator
say "[emulator] reuse or boot (timeout ${BOOT_TIMEOUT}s)"
adb start-server >/dev/null 2>&1
find_running() {
  local s name
  for s in $(adb devices 2>/dev/null | awk '$2=="device" && $1 ~ /^emulator-/ {print $1}'); do
    name="$(adb -s "$s" emu avd name 2>/dev/null | head -n 1 | tr -d '\r')"
    if [ "$name" = "$AVD" ]; then echo "$s"; return 0; fi
  done
  return 1
}
port_free() { local l; l="$(ss -ltn 2>/dev/null | awk '{print $4}')"; ! grep -qE "[:.]$1\$" <<<"$l"; }
if SERIAL="$(find_running)"; then
  BOOT_SECONDS=0
  note "reusing the running $AVD at $SERIAL"
  ok "emulator reused ($SERIAL)"
else
  while ! port_free "$PORT" || ! port_free $((PORT + 1)); do
    PORT=$((PORT + 2)); [ "$PORT" -le 5680 ] || { bad "no free emulator console port in 5584..5680"; exit 1; }
  done
  SERIAL="emulator-$PORT"
  t0=$(date +%s)
  emulator -avd "$AVD" -port "$PORT" -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect \
    -accel on -no-snapshot -no-metrics -camera-back none -camera-front none \
    >"$LOGS/emulator.log" 2>&1 &
  EMU_PID=$!; STARTED=1
  sleep 1
  note "started pid $EMU_PID (comm: $(ps -o comm= -p "$EMU_PID" 2>/dev/null || echo gone)) as $SERIAL"
  booted=0; deadline=$((t0 + BOOT_TIMEOUT))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! emu_alive; then tail -n 25 "$LOGS/emulator.log"; bad "emulator exited during boot"; exit 1; fi
    if [ "$(adbs get-state 2>/dev/null | tr -d '\r')" = "device" ] && [ "$(prop sys.boot_completed)" = "1" ]; then
      booted=1; break
    fi
    sleep 2
  done
  BOOT_SECONDS=$(( $(date +%s) - t0 ))
  if [ "$booted" = 1 ]; then ok "emulator booted in ${BOOT_SECONDS}s ($SERIAL, pid $EMU_PID)"
  else tail -n 25 "$LOGS/emulator.log"; bad "emulator not booted after ${BOOT_SECONDS}s"; exit 1; fi
fi
# Deterministic device: no animations, screen on + unlocked, big logcat ring, clean slate.
for k in window_animation_scale transition_animation_scale animator_duration_scale; do adbs shell settings put global "$k" 0 >/dev/null 2>&1; done
adbs shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1
adbs shell wm dismiss-keyguard >/dev/null 2>&1
adbs logcat -G 16M >/dev/null 2>&1
adbs logcat -c >/dev/null 2>&1
note "android $(prop ro.build.version.release) (API $(prop ro.build.version.sdk)), abi $(prop ro.product.cpu.abi), $(adbs shell wm size 2>/dev/null | tr -d '\r')"

# ---------------------------------------------------------------- 3. build
fl() { (cd "$ROOT/app" && flutter "$@"); }
check_abi() { local listing; listing="$(unzip -l "$1" 2>/dev/null)" && grep -qE 'lib/x86_64/librust_lib_sealbox_app\.so' <<<"$listing"; }
if [ "$SKIP_BUILD" = 1 ]; then
  say "[build] SKIP_BUILD=1 — reusing $APK_DEBUG and $APK_SMOKE"
  if [ -s "$APK_DEBUG" ] && [ -s "$APK_SMOKE" ]; then BUILD_OK=1; ok "prebuilt APKs present"; else bad "SKIP_BUILD=1 but APKs missing"; exit 1; fi
else
  say "[build] flutter build apk --debug --target-platform android-x64 (app, then the smoke entrypoint)"
  fl pub get >"$LOGS/pub_get.log" 2>&1 || { tail -n 20 "$LOGS/pub_get.log"; bad "flutter pub get"; exit 1; }
  built="$ROOT/app/build/app/outputs/flutter-apk/app-debug.apk"
  if fl build apk --debug --no-pub --target-platform android-x64 >"$LOGS/build_app.log" 2>&1 \
     && [ -s "$built" ] && check_abi "$built" && cp "$built" "$APK_DEBUG"; then
    note "app APK: $(stat -c %s "$APK_DEBUG") bytes"
  else
    grep -v 'Too many open files' "$LOGS/build_app.log" | tail -n 30 | sed 's/^/    | /'; bad "build app APK"; exit 1
  fi
  if fl build apk --debug --no-pub --target-platform android-x64 --target integration_test/android_smoke_test.dart \
       >"$LOGS/build_smoke.log" 2>&1 && [ -s "$built" ] && check_abi "$built" && cp "$built" "$APK_SMOKE"; then
    note "smoke APK: $(stat -c %s "$APK_SMOKE") bytes"
    BUILD_OK=1; ok "both APKs built (x86_64 Rust bridge inside)"
  else
    grep -v 'Too many open files' "$LOGS/build_smoke.log" | tail -n 30 | sed 's/^/    | /'; bad "build smoke APK"; exit 1
  fi
fi

# ---------------------------------------------------------------- 4. install + launch the real app
say "[launch] install $APK_DEBUG, start $ACTIVITY, screencap"
find "$OUT" -maxdepth 1 -name '*.png' -delete 2>/dev/null
if adbs install -r -t "$APK_DEBUG" >"$LOGS/install.log" 2>&1 && grep -q Success "$LOGS/install.log"; then
  INSTALL_OK=1; ok "APK installed ($(adbs shell pm path "$PKG" | tr -d '\r'))"
  adbs shell pm clear "$PKG" >/dev/null 2>&1 && note "app data cleared → every run starts with a fresh profile (onboarding first)"
else
  cat "$LOGS/install.log" | sed 's/^/    | /'; bad "adb install"; exit 1
fi
adbs logcat -c >/dev/null 2>&1
adbs shell am start -W -n "$ACTIVITY" >"$LOGS/am_start.log" 2>&1
LAUNCH_MS="$(grep -E '^TotalTime' "$LOGS/am_start.log" | awk '{print $2}' | tr -d '\r')"; LAUNCH_MS="${LAUNCH_MS:--1}"
for _ in $(seq 1 40); do
  if grep -q '\[sealbox\] bridge OK' <<<"$(adbs logcat -d 2>/dev/null)"; then BRIDGE_OK=1; break; fi
  sleep 1
done
sleep 3
adbs exec-out screencap -p >"$OUT/00-device-launch.png" 2>/dev/null
resumed="$(adbs shell dumpsys activity activities 2>/dev/null | grep -E 'ResumedActivity|mResumedActivity' | head -n 1 | tr -d '\r')"
if [ -s "$OUT/00-device-launch.png" ] && { [ "$BRIDGE_OK" = 1 ] || [[ "$resumed" == *"$PKG"* ]]; }; then
  LAUNCH_OK=1; ok "app launched (am TotalTime ${LAUNCH_MS} ms, bridge line: $([ "$BRIDGE_OK" = 1 ] && echo yes || echo no)); 00-device-launch.png"
else
  adbs logcat -d 2>/dev/null | grep -E "$PKG|flutter|AndroidRuntime" | tail -n 20 | sed 's/^/    | /'
  bad "app did not come up (bridge line: $BRIDGE_OK, resumed: ${resumed:-none})"
fi
adbs shell am force-stop "$PKG" >/dev/null 2>&1

# ---------------------------------------------------------------- 4b. seed mail for u06 (GreenMail users u06–u10 belong to this loop)
# GreenMail keeps u06's mailbox between runs, so seeding on every run piled up one pair per run
# (review/android/2026-10-29 C1). Seed only into an EMPTY INBOX: an INBOX holding exactly this
# run's two mails is kept as it is; anything else (yesterday's pair, the pile from before this
# fix) is expunged over IMAP first, so the inbox shots always show the same two rows. GreenMail's
# REST API lists one user's mail but purges only all mailboxes at once (POST /api/mail/purge —
# never call it: every other workstream's users live on the same GreenMail).
SEEDED=0; SEED_BEFORE=-1; SEED_AFTER=-1; SEED_EXPUNGED=0
SEED_USER="u06@sealbox.test"
SEED_SUBJECTS=("Welcome to the Android review loop ($DATE)" "Re: screenshots for REVIEW.md")
GM_API="${GREENMAIL_API:-http://127.0.0.1:3080}"
# gm_inbox USER — the subjects in USER's INBOX, one line per message (GET /api/user/USER/messages/INBOX);
# exit status 1 when the API does not answer for USER.
gm_inbox() {
  curl -fsS --max-time 10 "$GM_API/api/user/$1/messages/INBOX" 2>/dev/null | python3 -I -c '
import json, sys
try:
    msgs = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
if not isinstance(msgs, list):
    sys.exit(1)
for m in msgs:
    print(" ".join(str(m.get("subject") or "(no subject)").split()))
'
}
# gm_expunge LOGIN PASSWORD FOLDER — delete every message in FOLDER of that GreenMail user over IMAP
# (the local test server, 127.0.0.1:3143 plain); prints how many there were. Only this loop's own users.
gm_expunge() {
  python3 -I - "$@" <<'PY'
import imaplib, sys
login, password, folder = sys.argv[1:4]
imap = imaplib.IMAP4("127.0.0.1", 3143)
imap.login(login, password)
typ, data = imap.select(folder)
n = int(data[0]) if typ == "OK" and data and data[0] else 0
if n:
    imap.store("1:*", "+FLAGS.SILENT", "(\\Deleted)")
    imap.expunge()
if typ == "OK":
    imap.close()
imap.logout()
print(n)
PY
}
SEALBOX_BIN="${SEALBOX_BIN:-}"
for c in "$ROOT/target/release/sealbox" "$ROOT/target/debug/sealbox"; do [ -z "$SEALBOX_BIN" ] && [ -x "$c" ] && SEALBOX_BIN="$c"; done
if [ -n "$SEALBOX_BIN" ] && ! port_free 3143; then
  say "[seed] plaintext mail u07 → u06 through GreenMail so the inbox/thread shots have content ($SEALBOX_BIN)"
  : >"$LOGS/seed.log"
  if ! inbox="$(gm_inbox "$SEED_USER")"; then
    note "GreenMail's REST API ($GM_API) did not list $SEED_USER's INBOX: not seeding (cannot tell whether it is empty)"
  else
    SEED_BEFORE=$(printf '%s\n' "$inbox" | grep -c .)
    want="$(printf '%s\n' "${SEED_SUBJECTS[@]}" | sort)"
    have="$(printf '%s\n' "$inbox" | sed '/^$/d' | sort)"
    if [ "$SEED_BEFORE" -gt 0 ] && [ "$have" = "$want" ]; then
      note "$SEED_USER's INBOX already holds exactly this run's two mails: nothing seeded"
    else
      if [ "$SEED_BEFORE" -gt 0 ]; then
        SEED_EXPUNGED="$(gm_expunge "${SEED_USER%%@*}" "${SEED_USER%%@*}pw" INBOX 2>>"$LOGS/seed.log")" || SEED_EXPUNGED=0
        note "expunged $SEED_EXPUNGED of $SEED_BEFORE message(s) left in $SEED_USER's INBOX by earlier runs"
      fi
      prof="$WORK/profile-u07"; mkdir -p "$prof"
      "$SEALBOX_BIN" --profile "$prof" account add --email u07@sealbox.test --password u07pw \
          --imap 127.0.0.1:3143:plain --smtp 127.0.0.1:3025:plain >>"$LOGS/seed.log" 2>&1 \
        || note "u07 account add: $(tail -n 1 "$LOGS/seed.log") (already present from an earlier run?)"
      for subj in "${SEED_SUBJECTS[@]}"; do
        if "$SEALBOX_BIN" --profile "$prof" send --from u07@sealbox.test --to "$SEED_USER" --subject "$subj" \
             --body "Seeded by scripts/review_android.sh so the inbox and thread screenshots have content. Nothing in here is secret." \
             --policy plaintext >>"$LOGS/seed.log" 2>&1; then SEEDED=$((SEEDED + 1)); fi
      done
    fi
    for _ in $(seq 1 20); do   # delivery is quick, but let the count settle
      SEED_AFTER=$(gm_inbox "$SEED_USER" | grep -c .)
      [ "$SEED_AFTER" -ge 2 ] && break
      sleep 0.5
    done
    note "$SEED_USER INBOX: $SEED_BEFORE message(s) before, $SEED_AFTER after (expunged $SEED_EXPUNGED, seeded $SEEDED)"
  fi
else
  say "[seed] skipped (no sealbox CLI under target/ or GreenMail not listening on 127.0.0.1:3143)"
fi

# ---------------------------------------------------------------- 5. on-device smoke test
say "[drive] flutter drive (smoke test, timeout ${DRIVE_TIMEOUT}s) → $OUT"
rm -f "$OUT/smoke_report.json"
# Keep the launch-phase logcat, then start the drive from a clean buffer (the tool reads the VM
# Service URI from logcat). A fixed, pre-checked host port replaces `adb forward tcp:0`.
adbs logcat -d -v threadtime >"$LOGS/logcat_launch.txt" 2>/dev/null
adbs logcat -c >/dev/null 2>&1
HOST_VM_PORT="${HOST_VM_PORT:-47600}"
while ! port_free "$HOST_VM_PORT"; do HOST_VM_PORT=$((HOST_VM_PORT + 1)); done
# flutter drive stops AND uninstalls the app when the test ends; --keep-app-running leaves the smoke
# APK and its profile (u06@sealbox.test, synced mail) on the device for the dark-mode capture below.
DRIVE_HELP="$(cd "$ROOT/app" && flutter drive --help 2>/dev/null)"
KEEP_FLAG=""; grep -q -- '--keep-app-running' <<<"$DRIVE_HELP" && KEEP_FLAG="--keep-app-running"
run_drive() {
  ( cd "$ROOT/app" && SEALBOX_SHOTS_DIR="$OUT" timeout --foreground "$1" \
      flutter drive --no-pub -d "$SERIAL" --host-vmservice-port "$HOST_VM_PORT" $KEEP_FLAG \
        --use-application-binary="$APK_SMOKE" \
        --driver=test_driver/integration_test.dart --target=integration_test/android_smoke_test.dart \
    ) >"$LOGS/drive.log" 2>&1
}
run_drive "$DRIVE_TIMEOUT"; DRIVE_RC=$?
if [ "$DRIVE_RC" -ne 0 ] && ! grep -q 'All tests passed' "$LOGS/drive.log" \
   && grep -q 'attempting to connect to the VM Service' "$LOGS/drive.log"; then
  note "flutter drive never reached the app's VM Service (exit $DRIVE_RC, host port $HOST_VM_PORT) — retrying once"
  cp "$LOGS/drive.log" "$LOGS/drive_attempt1.log"
  adbs shell am force-stop "$PKG" >/dev/null 2>&1
  adbs forward --remove "tcp:$HOST_VM_PORT" >/dev/null 2>&1
  HOST_VM_PORT=$((HOST_VM_PORT + 1)); while ! port_free "$HOST_VM_PORT"; do HOST_VM_PORT=$((HOST_VM_PORT + 1)); done
  adbs logcat -c >/dev/null 2>&1
  run_drive "$DRIVE_TIMEOUT"; DRIVE_RC=$?
fi
grep -E '^\[smoke\]|^\[driver\]|All tests passed|Some tests failed|Failure|Exception' "$LOGS/drive.log" | grep -v 'Too many open files' | head -n 60 | sed 's/^/    | /'
if [ "$DRIVE_RC" -eq 0 ] && grep -q 'All tests passed' "$LOGS/drive.log"; then
  DRIVE_OK=1; ok "smoke test passed"
else
  [ "$DRIVE_RC" -eq 124 ] && note "flutter drive timed out after ${DRIVE_TIMEOUT}s"
  bad "smoke test failed (exit $DRIVE_RC) — $LOGS/drive.log"
fi
adbs shell am force-stop "$PKG" >/dev/null 2>&1

# ---------------------------------------------------------------- 5b. dark theme: one device screencap of the real app in night mode
say "[dark] system night mode → real app → 90-device-dark.png"
# The drive may have uninstalled the app (no --keep-app-running) — put the real debug APK back; an
# install over the kept smoke APK preserves /data, so the inbox with the added account comes up.
adbs shell am force-stop "$PKG" >/dev/null 2>&1
adbs install -r -t "$APK_DEBUG" >"$LOGS/install_dark.log" 2>&1 || note "re-install for the dark capture failed: $(tail -n 1 "$LOGS/install_dark.log")"
if adbs shell cmd uimode night yes >/dev/null 2>&1; then
  sleep 3                                  # the mode switch re-creates system UI; let it settle first
  in_front() { [[ "$(adbs shell dumpsys activity activities 2>/dev/null | grep -E 'ResumedActivity' | head -n 1)" == *"$PKG"* ]]; }
  for attempt in 1 2 3; do
    adbs shell am start -W -n "$ACTIVITY" >"$LOGS/am_start_dark.log" 2>&1
    sleep 7
    in_front && break
    note "app not in the foreground after start #$attempt — retrying"
  done
  # The real app opens on its lock screen (the smoke run set the PIN): keep that as 90-, then
  # unlock with the smoke PIN (the PIN field has focus and submits on Enter) and capture the
  # dark inbox as 91-.
  adbs exec-out screencap -p >"$OUT/90-device-dark.png" 2>/dev/null
  if [ -s "$OUT/90-device-dark.png" ] && in_front; then ok "dark-mode screencap captured (app in the foreground)"
  else note "dark-mode screencap: app not in the foreground (not fatal)"; rm -f "$OUT/90-device-dark.png"; fi
  if in_front; then
    adbs shell input text "${SMOKE_PIN:-135790}" >/dev/null 2>&1
    adbs shell input keyevent KEYCODE_ENTER >/dev/null 2>&1
    sleep 8                                # unlock → engine open (raw profile key) → inbox
    sleep 1
    adbs exec-out screencap -p >"$OUT/91-device-dark-unlocked.png" 2>/dev/null
    if [ -s "$OUT/91-device-dark-unlocked.png" ] && in_front; then ok "dark-mode screencap after unlock captured"
    else note "dark-mode screencap after unlock: app not in the foreground (not fatal)"; rm -f "$OUT/91-device-dark-unlocked.png"; fi
  fi
  adbs shell am force-stop "$PKG" >/dev/null 2>&1
  adbs shell cmd uimode night no >/dev/null 2>&1
else
  note "cmd uimode not available — skipped"
fi

# ---------------------------------------------------------------- 6. logcat, manifest, contact sheet
say "[report] logcat + manifest.json + index.html"
{ cat "$LOGS/logcat_launch.txt" 2>/dev/null; adbs logcat -d -v threadtime 2>/dev/null; } >"$OUT/logcat.txt"
cp "$LOGS/drive.log" "$OUT/drive.log" 2>/dev/null
FLUTTER_VERSION="$(flutter --version 2>/dev/null | head -n 1)"
GIT_REV="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
export OUT DATE RUN_AT AVD SERIAL BOOT_SECONDS STARTED EMU_PID PKG APK_DEBUG APK_SMOKE BUILD_OK INSTALL_OK \
       LAUNCH_OK BRIDGE_OK LAUNCH_MS DRIVE_RC DRIVE_OK FLUTTER_VERSION GIT_REV BOOT_TIMEOUT SEEDED \
       SEED_USER SEED_BEFORE SEED_AFTER SEED_EXPUNGED
python3 - <<'PY'
import hashlib, html, json, os, re, struct
out = os.environ["OUT"]; pkg = os.environ["PKG"]
def png_size(path):
    with open(path, "rb") as f:
        head = f.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n": return None
    w, h = struct.unpack(">II", head[16:24]); return [w, h]
def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()
screens = []
for name in sorted(os.listdir(out)):
    if not re.match(r"^\d\d-.*\.png$", name): continue
    p = os.path.join(out, name)
    screens.append({"file": name, "screen": name[3:-4], "bytes": os.path.getsize(p), "size": png_size(p), "sha256": sha(p),
                    "source": "adb screencap (device, with system UI)" if name.startswith(("00-", "90-", "91-")) else "flutter takeScreenshot"})
# fatal exceptions / native crashes of our package, plus (informational) unhandled Dart exceptions
log_path = os.path.join(out, "logcat.txt")
lines = open(log_path, errors="replace").read().splitlines() if os.path.exists(log_path) else []
fatal, dart_unhandled, fatal_excerpts = 0, 0, []
for i, l in enumerate(lines):
    if "FATAL EXCEPTION" in l:
        block = "\n".join(lines[i:i + 8])
        if pkg in block:
            fatal += 1; fatal_excerpts.append(block)
    elif (">>> " + pkg + " <<<") in l:            # native tombstone header (libc Fatal signal)
        fatal += 1; fatal_excerpts.append("\n".join(lines[max(0, i - 2):i + 6]))
    elif "E/flutter" in l or ("E flutter" in l):
        if "Unhandled Exception" in l: dart_unhandled += 1
report_path = os.path.join(out, "smoke_report.json")
try: report = json.load(open(report_path))
except Exception: report = None
# The driver's report embeds every screenshot as a JSON byte array (~40 MB per run; the PNGs
# are already on disk next to it). Keep names/results only, so the committed report and the
# manifest stay small and the daily autosave stops growing the history by ~80 MB per run.
if isinstance(report, dict) and isinstance(report.get("screenshots"), list):
    slim = []
    for shot in report["screenshots"]:
        if isinstance(shot, dict):
            shot = {k: v for k, v in shot.items() if k != "bytes"}
        slim.append(shot)
    report["screenshots"] = slim
    try: json.dump(report, open(report_path, "w"), indent=1)
    except Exception: pass
# Credentials / protocol traces must never reach logcat (G13 review R2: the bridge's default
# logger ran at Trace and async-imap logged the IMAP LOGIN line). Count, never copy, the lines.
# Shapes seen in the 2026-10-27 leak: `V async_imap::imap_stream: encode: ... Ok("LOGIN \"u06\" \"u06pw\"")`
# (escaped quotes) plus the classic forms. Any async-imap protocol-trace line counts: those lines carry
# the whole IMAP conversation, credentials and raw mail included.
cred_re = re.compile(r'async_imap::imap_stream|\bLOGIN \\?"|\bAUTHENTICATE (PLAIN|LOGIN|XOAUTH2)\b|Authorization: Bearer|auth=Bearer|user=[^ ]+\x01auth=|pw\\?"', re.I)
cred_lines = [i + 1 for i, l in enumerate(lines) if cred_re.search(l)]
def env_int(k):
    try: return int(os.environ.get(k, "-1"))
    except ValueError: return -1
def apk(path):
    return {"path": os.path.relpath(path, os.path.dirname(os.path.dirname(out))) if os.path.exists(path) else path,
            "bytes": os.path.getsize(path) if os.path.exists(path) else 0}
manifest = {
    "platform": "android", "date": os.environ["DATE"], "run_at": os.environ["RUN_AT"], "git_rev": os.environ["GIT_REV"],
    "flutter": os.environ["FLUTTER_VERSION"], "package": pkg,
    "emulator": {"avd": os.environ["AVD"], "serial": os.environ["SERIAL"], "started_by_this_run": os.environ["STARTED"] == "1",
                 "boot_seconds": env_int("BOOT_SECONDS"), "boot_timeout_seconds": env_int("BOOT_TIMEOUT"),
                 "headless_flags": "-no-window -no-audio -no-boot-anim -gpu swiftshader_indirect -accel on -no-snapshot"},
    "apk": {"app": apk(os.environ["APK_DEBUG"]), "smoke": apk(os.environ["APK_SMOKE"]), "built": os.environ["BUILD_OK"] == "1",
            "installed": os.environ["INSTALL_OK"] == "1"},
    "launch": {"ok": os.environ["LAUNCH_OK"] == "1", "bridge_line_seen": os.environ["BRIDGE_OK"] == "1", "am_total_time_ms": env_int("LAUNCH_MS")},
    "smoke_test": {"passed": os.environ["DRIVE_OK"] == "1", "exit_code": env_int("DRIVE_RC"), "report": report, "log": "drive.log",
                   "seeded_mail_for_u06": env_int("SEEDED"),
                   # C1: the seeded user's INBOX before / after seeding (-1: not checked) and what was expunged.
                   "seed_inbox": {"user": os.environ.get("SEED_USER", ""), "before": env_int("SEED_BEFORE"),
                                  "after": env_int("SEED_AFTER"), "expunged": env_int("SEED_EXPUNGED")}},
    "screens": screens, "screenshot_count": len(screens),
    "logcat": {"file": "logcat.txt", "lines": len(lines), "fatal_exceptions_our_package": fatal,
               "dart_unhandled_exceptions": dart_unhandled, "fatal_excerpts": fatal_excerpts[:5],
               "credential_lines": len(cred_lines), "credential_line_numbers": cred_lines[:20]},
}
json.dump(manifest, open(os.path.join(out, "manifest.json"), "w"), indent=1)
e = html.escape
rows = "".join(
    f'<figure><a href="{e(s["file"])}"><img src="{e(s["file"])}" loading="lazy" alt="{e(s["screen"])}"></a>'
    f'<figcaption><b>{e(s["file"][:2])}</b> {e(s["screen"])}<br><small>{s["size"][0] if s["size"] else "?"}×{s["size"][1] if s["size"] else "?"} · '
    f'{s["bytes"] // 1024} KB · {e(s["source"])}</small></figcaption></figure>' for s in screens)
steps = ""
if report and isinstance(report.get("steps"), list):
    steps = "<h2>Smoke-test steps</h2><table><tr><th>step</th><th>result</th><th>ms</th><th>error</th></tr>" + "".join(
        f'<tr class="{"ok" if st.get("ok") else "bad"}"><td>{e(str(st.get("step")))}</td><td>{"ok" if st.get("ok") else "FAIL"}</td>'
        f'<td>{e(str(st.get("ms", "")))}</td><td>{e(str(st.get("error", "")))}</td></tr>' for st in report["steps"]) + "</table>"
m = manifest
summary = [("date", m["date"]), ("run at", m["run_at"]), ("git", m["git_rev"]), ("emulator", f'{m["emulator"]["avd"]} @ {m["emulator"]["serial"]}'),
           ("boot", f'{m["emulator"]["boot_seconds"]} s' + (" (reused)" if not m["emulator"]["started_by_this_run"] else "")),
           ("app APK", f'{m["apk"]["app"]["bytes"] // 1024} KB, installed: {m["apk"]["installed"]}'),
           ("launch", f'ok={m["launch"]["ok"]}, bridge line={m["launch"]["bridge_line_seen"]}, am TotalTime {m["launch"]["am_total_time_ms"]} ms'),
           ("smoke test", "PASS" if m["smoke_test"]["passed"] else f'FAIL (exit {m["smoke_test"]["exit_code"]})'),
           ("mode", (report or {}).get("mode", "?")), ("screenshots", str(len(screens))),
           ("logcat", f'{m["logcat"]["lines"]} lines · fatal (our package): {fatal} · unhandled Dart exceptions: {dart_unhandled}')]
page = f"""<!doctype html><meta charset="utf-8"><title>Sealbox Android review {e(m["date"])}</title>
<style>body{{font:14px/1.4 system-ui,sans-serif;margin:24px;background:#fafaf8;color:#222}}h1{{margin:0 0 8px}}
table{{border-collapse:collapse;margin:8px 0 20px}}td,th{{border:1px solid #ddd;padding:4px 8px;text-align:left;vertical-align:top}}
tr.bad td{{background:#fde7e7}}.grid{{display:flex;flex-wrap:wrap;gap:16px}}figure{{margin:0;width:270px}}
figure img{{width:270px;border:1px solid #ccc;border-radius:12px;background:#000}}figcaption{{font-size:13px;margin-top:4px}}
.pass{{color:#0a7}}.fail{{color:#c22}}</style>
<h1>Sealbox — Android review set <span class="{"pass" if m["smoke_test"]["passed"] else "fail"}">{e(m["date"])}</span></h1>
<p>Headless <code>{e(m["emulator"]["avd"])}</code> (Pixel 6 profile, Android {e("API 35")}), captured by <code>scripts/review_android.sh</code>.
Findings go to <a href="REVIEW.md">REVIEW.md</a>; raw data: <a href="manifest.json">manifest.json</a>, <a href="logcat.txt">logcat.txt</a>, <a href="drive.log">drive.log</a>.</p>
<table>{"".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in summary)}</table>
<div class="grid">{rows}</div>{steps}
{"<h2>Fatal exceptions</h2><pre>" + e(chr(10).join(fatal_excerpts[:5])) + "</pre>" if fatal_excerpts else ""}
"""
open(os.path.join(out, "index.html"), "w").write(page)
print(f"    screenshots: {len(screens)}  fatal(our package): {fatal}  dart unhandled: {dart_unhandled}  logcat lines: {len(lines)}  credential/protocol-trace lines: {len(cred_lines)}")
for s in screens: print(f"      {s['file']}  {s['size'][0] if s['size'] else '?'}x{s['size'][1] if s['size'] else '?'}  {s['bytes']//1024} KB")
PY
ok "wrote $OUT/{manifest.json,index.html,logcat.txt}"

# ---------------------------------------------------------------- 7. summary
say "Summary ($(( $(date +%s) - $(date -d "$RUN_AT" +%s) ))s total)"
printf '  %s\n' "${RESULTS[@]}"
echo "  boot: ${BOOT_SECONDS}s  apk: $(stat -c %s "$APK_DEBUG" 2>/dev/null || echo 0) bytes  launch: $LAUNCH_OK  smoke: $DRIVE_OK  out: review/android/$DATE"
[ "$OVERALL" -eq 0 ] && [ "$BUILD_OK" = 1 ] && [ "$INSTALL_OK" = 1 ] && [ "$LAUNCH_OK" = 1 ] && [ "$DRIVE_OK" = 1 ]
