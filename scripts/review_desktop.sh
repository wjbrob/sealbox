#!/usr/bin/env bash
# scripts/review_desktop.sh — the desktop visual feedback loop (docs/GATES.md, G18).
#
# Launches the Linux app under a private Xvfb twice — once on an EMPTY profile (onboarding
# states, empty inbox) and once on a profile SEEDED with real GreenMail mail (u03 ↔ u04:
# plaintext, encrypted, signed, attachment, a Sent copy) — with SEALBOX_REVIEW=fresh|seeded (+ fake: FakeCore states),
# which runs the in-app scripted tour (lib/src/core/review_tour.dart). The tour prints one
# `[review] screen=NN-name` line per settled state; this script captures a PNG for each,
# resizes the window to 480×900 when the tour asks (`[review] resize=WxH`) and writes
#   review/desktop/<YYYY-MM-DD>/NN-<screen>.png, index.html (contact sheet), manifest.json,
#   app-fresh.log, app-seeded.log, errors.txt
# Nothing it started survives it (app + Xvfb PIDs are identity-checked before kill).
#
# Usage: scripts/review_desktop.sh [--release|--debug] [--out DIR] [--soak SECS] [--keep-profiles]
#   --release/--debug  which bundle to run (default: release if built, else debug; builds debug if neither)
#   --soak SECS        keep the seeded session alive at least SECS seconds after the tour (gate: 60)
set -u -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
. scripts/env.sh
export CI=true

MODE=""; OUT=""; SOAK=0; KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --release) MODE=release;; --debug) MODE=debug;;
    --out) OUT="$2"; shift;; --soak) SOAK="$2"; shift;; --keep-profiles) KEEP=1;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac; shift
done
DAY="$(date +%Y-%m-%d)"
OUT="${OUT:-$ROOT/review/desktop/$DAY}"
WORK="$ROOT/target/review_desktop/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${OUT:?}" "${WORK:?}"
say() { printf '\n=== %s\n' "$*"; }
die() { echo "review_desktop: $*" >&2; exit 1; }

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

for t in Xvfb xdpyinfo import xdotool docker cargo flutter python3; do
  command -v "$t" >/dev/null 2>&1 || die "missing tool: $t (sudo -n apt-get install -y xvfb imagemagick xdotool)"
done

# --- binary -----------------------------------------------------------------------------
if [ -z "$MODE" ]; then
  if [ -x app/build/linux/x64/release/bundle/sealbox_app ]; then MODE=release; else MODE=debug; fi
fi
BIN="$ROOT/app/build/linux/x64/$MODE/bundle/sealbox_app"
wait_for_build_dir || die "build dir busy"
if [ ! -x "$BIN" ]; then
  say "[build] flutter build linux --$MODE"
  (cd app && flutter build linux "--$MODE" --no-pub) || die "build failed"
fi
echo "binary: $BIN"

# --- GreenMail + CLI for seeding ------------------------------------------------------------
say "[seed] GreenMail + sealbox CLI"
testing/mail_up.sh || die "GreenMail not reachable"
CLI_TARGET="${SEALBOX_CLI_TARGET_DIR:-$ROOT/target}"
CARGO_TARGET_DIR="$CLI_TARGET" cargo build -q -p sealbox-cli >"$WORK/cargo.log" 2>&1 || { tail -n 20 "$WORK/cargo.log"; die "CLI build failed"; }
CLI="$CLI_TARGET/debug/sealbox"
IMAP="127.0.0.1:3143:plain"; SMTP="127.0.0.1:3025:plain"
U03="$WORK/profile-u03"; U04="$WORK/profile-u04"; FRESH="$WORK/profile-fresh"
mkdir -p "$U03" "$U04" "$FRESH"; chmod 700 "$U03" "$U04" "$FRESH"
cli() { SEALBOX_LOG=warn "$CLI" "$@"; }
NONCE="$(date +%s)"
# Every run seeds fresh profiles with fresh keys, so whatever an earlier run left in u03 / u04 is
# mail this run cannot read: the seeded inbox piled up undecryptable "..." rows, a "Lunch
# Thursday?" per run and setup messages (the accumulation of review/android/2026-10-29 C1). Empty
# both users' INBOX and Sent first, so the seeded session shows exactly this run's mail (u01–u05
# belong to the app wiring + desktop loop, docs/GATES.md; G17 uses u01/u02). GreenMail's REST API
# purges only all mailboxes at once — never call it — so this goes over IMAP, one user at a time.
# gm_expunge LOGIN PASSWORD FOLDER — delete every message in FOLDER (prints how many there were).
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
for u in u03 u04; do
  for f in INBOX Sent; do
    if n="$(gm_expunge "$u" "${u}pw" "$f" 2>>"$WORK/expunge.log")"; then
      echo "emptied $u@sealbox.test/$f ($n message(s) from earlier runs)"
    else
      echo "warning: could not empty $u@sealbox.test/$f (log $WORK/expunge.log); earlier runs' mail stays"
    fi
  done
done
{
  cli --profile "$U03" account add --email u03@sealbox.test --password u03pw --imap "$IMAP" --smtp "$SMTP" --name "Maya Okafor"
  cli --profile "$U04" account add --email u04@sealbox.test --password u04pw --imap "$IMAP" --smtp "$SMTP" --name "Bob Nakamura"
  cli --profile "$U03" key export --address u03@sealbox.test --file "$WORK/u03.asc"
  cli --profile "$U04" key export --address u04@sealbox.test --file "$WORK/u04.asc"
  cli --profile "$U04" key import --address u03@sealbox.test --file "$WORK/u03.asc"
  cli --profile "$U03" key import --address u04@sealbox.test --file "$WORK/u04.asc"
  # first contact (plaintext, carries Autocrypt), then encrypted mail, one with an attachment
  cli --profile "$U04" send --from u04@sealbox.test --to u03@sealbox.test --policy plaintext \
      --subject "Lunch Thursday? ($NONCE)" --body "The Lebanese place near the station, 12:30? Let me know if Thursday does not work."
  cli --profile "$U04" send --from u04@sealbox.test --to u03@sealbox.test --policy auto \
      --subject "Q4 budget — final numbers" --body "Maya,

Attached are the final Q4 numbers. Headcount stays flat, the vendor line drops 8% after the renegotiation.

Please do not forward this outside the finance group.

— Bob"
  printf 'quarter,headcount,vendor\nQ4,42,-8%%\n' > "$WORK/q4-numbers.csv"
  cli --profile "$U04" send --from u04@sealbox.test --to u03@sealbox.test --policy auto \
      --subject "Re: keys for the Thunderbird interop test" --attach "$WORK/q4-numbers.csv" \
      --body "Decrypted fine in Thunderbird 128 — the protected Subject showed up correctly and the Autocrypt header imported your key on first contact. CSV attached."
  # an outgoing encrypted mail so the Sent folder has a copy
  cli --profile "$U03" send --from u03@sealbox.test --to u04@sealbox.test --policy auto \
      --subject "Contract draft" --body "Bob — the draft is behind the guest link; the passphrase is the one I gave you on the phone."
  cli --profile "$U03" sync
} >"$WORK/seed.log" 2>&1 || { tail -n 20 "$WORK/seed.log"; die "seeding failed (log: $WORK/seed.log)"; }
echo "seeded u03 profile (log $WORK/seed.log)"

# --- Xvfb -----------------------------------------------------------------------------------
say "[x] private Xvfb"
# Xvfb chooses a free display itself (-displayfd) — picking a number by probing lock files races
# with the other sessions' Xvfb on this box; -noreset keeps the server up between app launches.
XDISP_FILE="$WORK/xdisplay"; : > "$XDISP_FILE"
Xvfb -displayfd 3 -screen 0 1280x1000x24 -nolisten tcp -noreset 3>"$XDISP_FILE" >"$WORK/xvfb.log" 2>&1 &
XPID=$!
n=""
for _ in $(seq 1 100); do n="$(tr -dc '0-9' < "$XDISP_FILE")"; [ -n "$n" ] && break; sleep 0.1; done
[ -n "$n" ] && [ "$(ps -o comm= -p "$XPID" 2>/dev/null)" = "Xvfb" ] || die "Xvfb did not start (log: $WORK/xvfb.log)"
export DISPLAY=":$n"
echo "Xvfb on $DISPLAY (pid $XPID)"
display_alive() { xdpyinfo -display "$DISPLAY" >/dev/null 2>&1; }
APID=""
cleanup() {
  if [ -n "$APID" ] && [ "$(ps -o comm= -p "$APID" 2>/dev/null)" = "sealbox_app" ]; then kill "$APID" 2>/dev/null; wait "$APID" 2>/dev/null; fi
  if [ "$(ps -o comm= -p "$XPID" 2>/dev/null)" = "Xvfb" ]; then kill "$XPID" 2>/dev/null; wait "$XPID" 2>/dev/null; fi
  # The profiles hold test keys and GreenMail passwords: never leave them around.
  if [ $KEEP -eq 0 ]; then rm -rf "${U03:?}" "${U04:?}" "${FRESH:?}"; fi
}
trap cleanup EXIT

# --- one session: run the app with a tour, capture per marker --------------------------------
MANIFEST_ROWS="$WORK/rows.jsonl"; : > "$MANIFEST_ROWS"
ACK_DIR="$WORK/ack"; mkdir -p "$ACK_DIR"
SHOTS=0
window_id() { xdotool search --onlyvisible --name '^Sealbox$' 2>/dev/null | head -n1; }
capture() {  # capture NAME
  local name="$1" file="$OUT/$1.png" wid
  wid="$(window_id)"
  if [ -n "$wid" ]; then
    import -display "$DISPLAY" -window "$wid" "$file" 2>/dev/null || import -display "$DISPLAY" -window root "$file"
  else
    import -display "$DISPLAY" -window root "$file"
  fi
  touch "$ACK_DIR/$name.ack"   # the tour holds the frame until this exists
  local geo; geo="$(identify -format '%wx%h' "$file" 2>/dev/null || echo '?')"
  printf '{"file":"%s.png","screen":"%s","session":"%s","size":"%s","captured_at":"%s"}\n' \
    "$name" "${name#*-}" "$SESSION" "$geo" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$MANIFEST_ROWS"
  SHOTS=$((SHOTS + 1))
  echo "  shot $name ($geo)"
}
session() {
  SESSION="$1"; local profile="$2" min_secs="$3" log="$OUT/app-$1.log"
  say "[session $SESSION] $BIN"
  : > "$log"
  display_alive || { echo "display $DISPLAY is gone (Xvfb pid $XPID: $(ps -o comm= -p "$XPID" 2>/dev/null || echo dead))"; return 1; }
  # Numbering continues across sessions (SEALBOX_REVIEW_START); each capture is acknowledged
  # through SEALBOX_REVIEW_ACK_DIR so the tour never outruns `import`.
  SEALBOX_PROFILE="$profile" SEALBOX_REVIEW="$SESSION" SEALBOX_REVIEW_START="$SHOTS" \
    SEALBOX_REVIEW_ACK_DIR="$ACK_DIR" SEALBOX_LOG=warn "$BIN" >"$log" 2>&1 &
  APID=$!
  local t0 seen=0 done=0 line wid
  t0=$(date +%s)
  # wait for the window
  for _ in $(seq 1 300); do wid="$(window_id)"; [ -n "$wid" ] && break; sleep 0.2; done
  [ -n "$wid" ] || { echo "no Sealbox window appeared (log: $log)"; return 1; }
  xdotool windowmove "$wid" 0 0 2>/dev/null; xdotool windowsize "$wid" 1280 800 2>/dev/null
  # follow the log; the tour prints markers
  local deadline=$(( t0 + 600 ))
  while [ "$(date +%s)" -lt $deadline ]; do
    if [ "$(ps -o comm= -p "$APID" 2>/dev/null)" != "sealbox_app" ]; then echo "app exited early (log: $log)"; return 1; fi
    local total; total=$(grep -c '^\[review\] ' "$log" || true)
    if [ "$total" -gt "$seen" ]; then
      line="$(grep '^\[review\] ' "$log" | sed -n "$((seen + 1))p")"
      seen=$((seen + 1))
      case "$line" in
        *"screen="*) sleep 0.35; capture "${line#*screen=}";;
        *"resize="*) local wh="${line#*resize=}"; wid="$(window_id)"; [ -n "$wid" ] && xdotool windowsize "$wid" "${wh%x*}" "${wh#*x}"; echo "  resize $wh";;
        *"done"*) done=1;;
        *"error"*) echo "  tour error: $line";;
      esac
      continue
    fi
    if [ $done -eq 1 ] && [ $(( $(date +%s) - t0 )) -ge "$min_secs" ]; then break; fi
    sleep 0.2
  done
  local secs=$(( $(date +%s) - t0 ))
  echo "  session $SESSION: $secs s, tour done=$done"
  echo "$SESSION $secs $done" >> "$WORK/sessions.txt"
  if [ "$(ps -o comm= -p "$APID" 2>/dev/null)" = "sealbox_app" ]; then kill "$APID" 2>/dev/null; wait "$APID" 2>/dev/null; fi
  APID=""
  [ $done -eq 1 ]
}

# Start the day's set afresh (only the PNGs; REVIEW.md and logs of earlier runs are kept).
find "${OUT:?}" -maxdepth 1 -name '*.png' -type f -delete
session fresh "$FRESH" 0 || echo "fresh session incomplete"
session seeded "$U03" "$SOAK" || echo "seeded session incomplete"
# States the real engine cannot be made to show on demand (a correspondent's key changing, a
# key-transparency alert) on FakeCore's sample mailbox; every shot is named fake-*.
session fake "$WORK/profile-fake" 0 || echo "fake session incomplete"

# --- error scan, manifest, contact sheet --------------------------------------------------------
say "[report] $OUT"
grep -hE '\[ERROR\]|Exception|Unhandled|panicked|EXCEPTION CAUGHT|^Error' "$OUT"/app-*.log > "$OUT/errors.txt" || true
ERRORS=$(wc -l < "$OUT/errors.txt" | tr -d ' ')
python3 - "$OUT" "$MANIFEST_ROWS" "$WORK/sessions.txt" "$ERRORS" "$MODE" "$DAY" <<'PY'
import json, sys, os, html
out, rows, sessions, errors, mode, day = sys.argv[1:7]
shots = [json.loads(l) for l in open(rows) if l.strip()]
sess = {}
if os.path.exists(sessions):
    for l in open(sessions):
        name, secs, done = l.split()
        sess[name] = {"seconds": int(secs), "tour_completed": done == "1"}
manifest = {"date": day, "mode": mode, "screens": len(shots), "distinct_screens": len({s["screen"] for s in shots}),
            "error_lines": int(errors), "sessions": sess, "shots": shots}
json.dump(manifest, open(os.path.join(out, "manifest.json"), "w"), indent=1)
cards = "\n".join(
    f'<figure><a href="{s["file"]}"><img src="{s["file"]}" loading="lazy"></a>'
    f'<figcaption><b>{html.escape(s["file"][:-4])}</b><br><small>{s["session"]} · {s["size"]}</small></figcaption></figure>'
    for s in shots)
open(os.path.join(out, "index.html"), "w").write(f"""<!doctype html><meta charset="utf-8"><title>Sealbox desktop review {day}</title>
<style>body{{font:14px system-ui;margin:24px;background:#f6f7f8;color:#222}}h1{{font-size:20px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:18px}}
figure{{margin:0;background:#fff;border:1px solid #ddd;border-radius:8px;padding:8px}}img{{width:100%;height:auto;border:1px solid #eee;background:#000}}
figcaption{{padding:6px 2px}}.meta{{color:#555}}</style>
<h1>Sealbox desktop review — {day} ({mode} build)</h1>
<p class="meta">{len(shots)} screenshots, {manifest["distinct_screens"]} distinct screens · error lines in app logs: {errors} ·
sessions: {", ".join(f"{k} {v['seconds']}s{'' if v['tour_completed'] else ' (incomplete)'}" for k,v in sess.items())} ·
<a href="manifest.json">manifest.json</a> · <a href="errors.txt">errors.txt</a> · <a href="REVIEW.md">REVIEW.md</a></p>
<div class="grid">{cards}</div>""")
print(f"screens: {len(shots)} ({manifest['distinct_screens']} distinct) · error lines: {errors} · {out}/index.html")
PY
