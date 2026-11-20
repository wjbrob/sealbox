#!/usr/bin/env bash
# scripts/perf_sync.sh — how Sealbox behaves on a real-sized mailbox (docs/PERFORMANCE.md).
#
# Measures, against the PERFORMANCE GreenMail only (testing/mail_perf_up.sh: 127.0.0.1:3243 /
# 3125, users p01..p03 — never the shared `mail` service the gates use):
#   (a) first sync of SMALL (1k) messages on a fresh profile, then — after seeding +LARGE−SMALL
#       (9k) more — the first sync of LARGE (10k) on another fresh profile: wall time
#       (/usr/bin/time -v), peak RSS, messages/s, SQLite file size;
#   (b) incremental syncs on the LARGE profile: 0 new, then +NEW (50) new;
#   (c) `sealbox list --limit 50` latency (LIST_RUNS runs) on the SMALL, LARGE and an empty profile;
#   (d) the Linux desktop app's cold start to the first captured frame showing the inbox list
#       (release bundle under a private Xvfb, profile via SEALBOX_PROFILE), unless --no-app.
# Plus the per-message cost from the engine's own debug events (`message processed uid=N`, one
# per processed message) joined with the seeder's manifest: by kind and by position (growth with
# the number of stored messages).
#
# Since phase 2 (docs/PERFORMANCE.md) a folder's first `sync` stores only its newest window (500);
# "first sync" here is therefore measured twice: `sync` (the window: what a user sees first) and
# `sync --backfill` (the whole mailbox, comparable with phase 1's first sync).
#
# --gate is G33 (docs/GATES.md): a release build, the LARGE mailbox, four scenarios with
# thresholds and one verdict line `G33 PASS` / `G33 FAIL (...)`; see gate_run below.
#
# Every profile is a copy of one template (account added, key generated, never synced), so the
# PGP/MIME share of the corpus — encrypted by gpg to that key — decrypts in every scenario.
# Syncs mutate the server only by moving spam; each run checks the INBOX count before a sync.
#
# Usage: scripts/perf_sync.sh [--release] [--user p01] [--small 1000] [--large 10000] [--new 50]
#                             [--list-runs 7] [--no-app] [--app-runs 3] [--samples N]
#                             [--sample-interval 4] [--app-first-sync SECS] [--keep]
#                             [--out DIR]
#        scripts/perf_sync.sh --gate [--user p02]          # G33; exit 0 = PASS
#   --no-restart  keep the running perf GreenMail (only empty the user's folders) instead of
#               restarting it and warming it up first (the default; restarting discards every perf
#               mailbox, so do not run two perf_sync.sh or the cli_sync_window test at once)
#   --release   build/measure an optimised CLI (CARGO_TARGET_DIR=target/perf-release, the product's
#               release profile + line tables so --samples can name frames); default: the debug
#               CLI in target/ exactly as the gates build it (`cargo build -q -p sealbox-cli`)
#   --samples N after the measured runs, re-sync a fresh copy of the LARGE mailbox while taking up
#               to N gdb stack samples, one every --sample-interval s (each attach pauses the
#               process ~1 s, so that run is not timed; spread them over the whole sync)
#   --app-first-sync SECS  also start the app on a FRESH profile against the LARGE mailbox and keep
#               SECS s of frames: what a user sees while the first sync runs inside the app
#   --keep      keep profiles + gnupg home under target/perf/ (default: deleted; logs are kept)
# Results: $OUT (default .gate/evidence/perf/<date>/<mode>-<UTC stamp>/): env.txt, results.tsv,
# summary.txt, per-step *.time (/usr/bin/time -v), *.out, *.err (debug events), seed-*.log, app/.
set -u -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
. scripts/env.sh

MODE=debug; PUSER=""; SMALL=1000; LARGE=10000; NEW=50; LIST_RUNS=7; APP=1; APP_RUNS=3
SAMPLES=0; SAMPLE_IV=4; KEEP=0; OUT=""; APP_FS=0; GATE=0; RESTART=1
while [ $# -gt 0 ]; do
  case "$1" in
    --release) MODE=release;; --debug) MODE=debug;;
    --user) PUSER="$2"; shift;; --small) SMALL="$2"; shift;; --large) LARGE="$2"; shift;;
    --new) NEW="$2"; shift;; --list-runs) LIST_RUNS="$2"; shift;; --no-app) APP=0;;
    --app-runs) APP_RUNS="$2"; shift;; --samples) SAMPLES="$2"; shift;; --keep) KEEP=1;;
    --sample-interval) SAMPLE_IV="$2"; shift;;
    --app-first-sync) APP_FS="$2"; shift;;
    --out) OUT="$2"; shift;;
    --gate) GATE=1;;
    --no-restart) RESTART=0;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac; shift
done
# The gate runs on p02 by default so it never collides with a measurement on p01 (p03: the
# cli_sync_window e2e test).
if [ $GATE -eq 1 ]; then MODE=release; APP=0; SAMPLES=0; PUSER="${PUSER:-p02}"; fi
PUSER="${PUSER:-p01}"
case "$PUSER" in p01|p02|p03) ;; *) echo "--user must be p01, p02 or p03 (the perf GreenMail users)" >&2; exit 2;; esac
[ "$LARGE" -gt "$SMALL" ] || { echo "--large must exceed --small" >&2; exit 2; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$ROOT/.gate/evidence/perf/$(date +%Y-%m-%d)/$([ $GATE -eq 1 ] && echo gate || echo "$MODE")-$STAMP}"
WORK="$ROOT/target/perf/run-$STAMP"
mkdir -p "${OUT:?}" "${WORK:?}"
chmod 700 "$WORK"
export PERF_PASSWORD="${PUSER}pw"           # test password of the perf GreenMail user
EMAIL="$PUSER@sealbox.test"
IMAP_HOST=127.0.0.1; IMAP_PORT=3243
say() { printf '\n=== %s\n' "$*" | tee -a "$OUT/summary.txt"; }
note() { echo "$*" | tee -a "$OUT/summary.txt"; }
die() { note "perf_sync: $*"; exit 1; }
now() { date +%s.%N; }
for t in docker python3 gpg sqlite3 cargo; do command -v "$t" >/dev/null || die "missing tool: $t"; done
[ -x /usr/bin/time ] || die "missing /usr/bin/time (sudo -n apt-get install -y time)"

XPID=""; APID=""
cleanup() {
  if [ -n "$APID" ] && [ "$(ps -o comm= -p "$APID" 2>/dev/null)" = "sealbox_app" ]; then kill "$APID" 2>/dev/null; wait "$APID" 2>/dev/null; fi
  if [ -n "$XPID" ] && [ "$(ps -o comm= -p "$XPID" 2>/dev/null)" = "Xvfb" ]; then kill "$XPID" 2>/dev/null; wait "$XPID" 2>/dev/null; fi
  [ -d "$WORK/gnupg" ] && gpgconf --homedir "$WORK/gnupg" --kill all >/dev/null 2>&1
  if [ $KEEP -eq 0 ]; then
    # Every scenario profile is a copy of the template and shares its OS-keyring entry
    # (sealbox/profile-<hash>, kept in the profile meta): rewrapping the template to `none`
    # deletes that entry, so a run leaves nothing in the user's login keyring.
    if [ -n "${BIN:-}" ] && [ -f "$WORK/tpl/sealbox.db" ]; then
      SEALBOX_ALLOW_PLAINTEXT_PROFILE=1 NO_COLOR=1 SEALBOX_LOG=warn "$BIN" --profile "$WORK/tpl" \
          profile rewrap --to none >/dev/null 2>&1 || echo "perf_sync: could not remove the template's keyring entry" >&2
    fi
    rm -rf "${WORK:?}"
  fi
}
trap cleanup EXIT

# --- build -----------------------------------------------------------------------------------------
say "[build] $MODE CLI"
build() {
  if [ "$MODE" = release ]; then
    CARGO_TARGET_DIR="$ROOT/target/perf-release" CARGO_PROFILE_RELEASE_STRIP=none \
      CARGO_PROFILE_RELEASE_DEBUG=line-tables-only cargo build --release -q -p sealbox-cli
  else
    cargo build -q -p sealbox-cli
  fi
}
built=0
for attempt in 1 2 3 4; do
  if build >"$OUT/build.log" 2>&1; then built=1; break; fi
  note "build attempt $attempt failed (other builders edit the crates concurrently); retrying in 90 s"
  tail -n 5 "$OUT/build.log" | tee -a "$OUT/summary.txt"
  sleep 90
done
[ $built -eq 1 ] || die "CLI build failed 4 times (log $OUT/build.log)"
if [ "$MODE" = release ]; then SRC_BIN="$ROOT/target/perf-release/release/sealbox"; else SRC_BIN="$ROOT/target/debug/sealbox"; fi
# A private copy: another builder's `cargo build` may replace target/*/sealbox mid-run.
cp "$SRC_BIN" "$WORK/sealbox" || die "no binary at $SRC_BIN"
BIN="$WORK/sealbox"
{
  echo "date:        $(date -Is)"
  echo "mode:        $MODE ($( [ "$MODE" = release ] && echo 'release profile: thin LTO, codegen-units=1, + line tables' || echo 'dev profile, as the gates build it'))"
  echo "binary:      $SRC_BIN  sha256 $(sha256sum "$BIN" | cut -c1-16)  $(stat -c %s "$BIN") bytes"
  echo "commit:      $(git rev-parse HEAD) ($(git log -1 --format=%cI))"
  echo "dirty crates (other builders' work in progress at build time):"
  git status --porcelain crates/ | sed 's/^/  /'
  echo "host:        $(hostname) $(uname -r)"
  echo "cpu:         $(lscpu | sed -n 's/^Model name: *//p') ($(nproc) threads)"
  echo "ram:         $(free -g | awk '/^Mem:/{print $2" GB total, "$7" GB available"}')"
  echo "disk /:      $(df -h / | awk 'NR==2{print $2" size, "$4" free"}') ($(lsblk -no MODEL "$(df / | awk 'NR==2{print $1}' | sed 's/p[0-9]*$//')" 2>/dev/null | head -1))"
  echo "load:        $(cut -d' ' -f1-3 /proc/loadavg)"
  echo "rustc:       $(rustc --version)"
  echo "greenmail:   $(docker image inspect greenmail/standalone:2.1.3 --format '{{.Id}}' 2>/dev/null | cut -c1-19) (sealbox-mail-perf)"
  echo "python:      $(python3 --version 2>&1); gpg $(gpg --version | head -1 | awk '{print $3}')"
  echo "user:        $EMAIL on $IMAP_HOST:$IMAP_PORT; small=$SMALL large=$LARGE new=$NEW"
} > "$OUT/env.txt"
cat "$OUT/env.txt" | tee -a "$OUT/summary.txt"

# --- GreenMail (perf) ------------------------------------------------------------------------------
say "[greenmail] perf instance"
# STATUS, not SELECT: a probe must not leave a selected-folder session behind (see below).
inbox_count() { python3 -I - "$PUSER" "$PERF_PASSWORD" <<'PY'
import imaplib, re, sys
m = imaplib.IMAP4("127.0.0.1", 3243); m.login(sys.argv[1], sys.argv[2])
t, d = m.status("INBOX", "(MESSAGES)")
print(int(re.search(rb"MESSAGES (\d+)", d[0]).group(1)) if t == "OK" else -1); m.logout()
PY
}
# GreenMail 2.1.3's cost per UID FETCH at 10k messages is CPU-bound in the server and bimodal
# (docs/PERFORMANCE.md, phase 2): ~0.45 s, or ~1.7 s for the FIRST folder fetched after the JVM
# started (observed 6/6 times, independent of load, SELECT vs EXAMINE, seeding pattern, PGP content,
# expunge, JIT warm-up or core type). So by default the server is restarted and a throwaway folder
# (Warmup, 1000 messages) is fetched first; server_probe records what the measured syncs see.
server_probe() {  # server_probe NAME — median ms of three 200-message UID FETCHes on INBOX
  local ms
  ms="$(python3 -I - "$PUSER" "$PERF_PASSWORD" <<'PY'
import imaplib, statistics, sys, time
m = imaplib.IMAP4("127.0.0.1", 3243); m.login(sys.argv[1], sys.argv[2]); m.select("INBOX", readonly=True)
t, d = m.uid("SEARCH", None, "UID 1:*"); uids = [int(x) for x in d[0].split()]
per = []
for k in range(3):
    s = uids[k * 200:(k + 1) * 200] or uids[:1]
    if not s: break
    t0 = time.monotonic(); m.uid("FETCH", f"{s[0]}:{s[-1]}", "(UID FLAGS BODY.PEEK[])"); per.append(time.monotonic() - t0)
m.logout(); print(int(1000 * statistics.median(per)) if per else 0)
PY
)"
  note "server probe before $1: a 200-message UID FETCH takes ${ms} ms (median of 3)" >&2
  echo "$1 $ms" >> "$OUT/server_probe.txt"
  echo "${ms:-0}"
}
fresh_server() {  # restart the perf GreenMail (discards its mailboxes) and warm it up
  testing/mail_perf_down.sh >/dev/null 2>&1 || true
  testing/mail_perf_up.sh | tee -a "$OUT/summary.txt" || return 1
  python3 -I - "$PUSER" "$PERF_PASSWORD" <<'PY' || return 1
import imaplib, sys, time
# GreenMail greets on IMAP before it has provisioned its users, so a LOGIN straight after a
# restart can fail with "Invalid login/password" (seen 2/2 under load, 2026-11-17): retry ~20 s.
for attempt in range(40):
    m = imaplib.IMAP4("127.0.0.1", 3243)
    try:
        m.login(sys.argv[1], sys.argv[2])
        break
    except imaplib.IMAP4.error:
        m.shutdown()
        if attempt == 39:
            raise
        time.sleep(0.5)
m.create("Warmup"); m.logout()
PY
  python3 -I testing/seed_mailbox.py --user "$PUSER" --password "$PERF_PASSWORD" --host "$IMAP_HOST" \
      --port "$IMAP_PORT" --folder Warmup --count 1000 >/dev/null 2>&1 || return 1
  python3 -I - "$PUSER" "$PERF_PASSWORD" <<'PY' || return 1
import imaplib, sys
m = imaplib.IMAP4("127.0.0.1", 3243); m.login(sys.argv[1], sys.argv[2]); m.select("Warmup", readonly=True)
for k in range(3):
    m.uid("FETCH", f"{1 + 200 * k}:{200 * (k + 1)}", "(UID FLAGS BODY.PEEK[])")
m.logout()
PY
  note "perf server restarted; Warmup folder (1000 messages) fetched first"
}
if [ $RESTART -eq 1 ]; then
  fresh_server || die "perf GreenMail did not come back"
else
  testing/mail_perf_up.sh | tee -a "$OUT/summary.txt" || die "perf GreenMail not reachable"
  for f in INBOX Spam Junk; do
    n="$(python3 -I testing/gm_expunge.py "$PUSER" "$PERF_PASSWORD" "$f" "$IMAP_HOST" "$IMAP_PORT" 2>/dev/null || echo '?')"
    note "emptied $EMAIL/$f on the perf server ($n message(s) from earlier runs)"
  done
fi

# --- template profile ----------------------------------------------------------------------------------
say "[profile] template (account + key, never synced)"
cli() { NO_COLOR=1 SEALBOX_LOG=warn "$BIN" "$@"; }
TPL="$WORK/tpl"; mkdir -m 700 "$TPL"
add_template() {
  cli --profile "$TPL" account add --email "$EMAIL" --password-env PERF_PASSWORD \
      --imap "$IMAP_HOST:$IMAP_PORT:plain" --smtp "$IMAP_HOST:3125:plain" --name "Perf User" \
      >"$OUT/account-add.out" 2>&1
}
add_template_again() { :; }  # the template's account outlives a server restart (same host/port/user)
if ! add_template; then
  # No OS keyring in this session (e.g. a cron run without a Secret Service): measure a plaintext
  # profile instead (sealing costs ~1 % of a sync) and say so.
  [ $GATE -eq 1 ] || { cat "$OUT/account-add.out"; die "account add failed"; }
  note "keyring unavailable ($(tail -n 1 "$OUT/account-add.out")); this run uses a plaintext profile"
  export SEALBOX_PROFILE_KEY=none SEALBOX_ALLOW_PLAINTEXT_PROFILE=1
  rm -rf "${TPL:?}"; mkdir -m 700 "$TPL"
  add_template || { cat "$OUT/account-add.out"; die "account add failed"; }
fi
cli --profile "$TPL" key export --address "$EMAIL" --file "$WORK/key.asc" >/dev/null 2>&1 || die "key export failed"
cat "$OUT/account-add.out" | tee -a "$OUT/summary.txt"
fresh_profile() { rm -rf "${1:?}"; cp -a "$TPL" "$1"; }

seed() {  # seed NAME OFFSET COUNT
  local name="$1" off="$2" cnt="$3"
  note "seeding $cnt message(s) at offset $off into $EMAIL/INBOX"
  python3 -I testing/seed_mailbox.py --user "$PUSER" --password "$PERF_PASSWORD" --host "$IMAP_HOST" \
      --port "$IMAP_PORT" --count "$cnt" --offset "$off" --span "$LARGE" \
      --pgp-recipient-key "$WORK/key.asc" --gnupg-home "$WORK/gnupg" \
      $([ $GATE -eq 1 ] || echo --manifest "$OUT/manifest.jsonl") >"$OUT/seed-$name.log" 2>&1 \
      || { cat "$OUT/seed-$name.log"; die "seeding failed"; }
  cat "$OUT/seed-$name.log" | tee -a "$OUT/summary.txt"
}

# --- timed steps ------------------------------------------------------------------------------------------
LOGSPEC="warn,sealbox_core::sync=debug"   # one debug event per processed message, nothing chattier
[ $GATE -eq 1 ] && LOGSPEC=warn             # the gate keeps its artifacts small
timed() {  # timed NAME PROFILE ARGS... — /usr/bin/time -v, stdout/stderr/time per step
  local name="$1" prof="$2"; shift 2
  local t0 t1 rc l0 l1
  l0="$(cut -d' ' -f1 /proc/loadavg)"
  t0="$(now)"
  NO_COLOR=1 SEALBOX_LOG="$LOGSPEC" /usr/bin/time -v -o "$OUT/$name.time" "$BIN" --profile "$prof" "$@" \
      >"$OUT/$name.out" 2>"$OUT/$name.err"
  rc=$?
  t1="$(now)"
  l1="$(cut -d' ' -f1 /proc/loadavg)"
  # The box is shared (other builders compile and test): the 1-min load average brackets each step.
  echo "$name $t0 $t1 $rc $l0 $l1" >> "$OUT/steps.txt"
  local wall rss
  wall="$(python3 -c "print(f'{$t1-$t0:.2f}')")"
  rss="$(sed -n 's/.*Maximum resident set size (kbytes): //p' "$OUT/$name.time")"
  note "$name: rc=$rc wall=${wall}s maxrss=${rss}kB load ${l0}->${l1}  $(head -c 300 "$OUT/$name.out" | tr '\n' ' ')"
  [ $rc -eq 0 ] || { tail -n 5 "$OUT/$name.err"; return 1; }
}
db_stats() {  # db_stats NAME PROFILE
  local db="$2/sealbox.db"
  {
    echo "files (bytes): db=$(stat -c %s "$db" 2>/dev/null || echo 0) wal=$(stat -c %s "$db-wal" 2>/dev/null || echo 0) shm=$(stat -c %s "$db-shm" 2>/dev/null || echo 0)"
    echo "profile dir: $(du -sb "$2" | cut -f1) bytes"
    sqlite3 -readonly "$db" "SELECT 'messages', count(*), sum(raw_size), sum(was_encrypted), sum(decrypted) FROM messages;
      SELECT 'attachments', count(*), sum(size) FROM attachments;
      SELECT 'spam_label', coalesce(spam_label,'(none)'), count(*) FROM messages GROUP BY 2;
      SELECT 'peers', count(*) FROM peers;
      SELECT 'folders', name, uidvalidity, last_uid, floor_uid FROM folders;
      PRAGMA page_size; PRAGMA page_count; PRAGMA freelist_count;" 2>&1
    sqlite3 -readonly "$db" "SELECT 'dbstat', name, sum(pgsize) FROM dbstat GROUP BY name ORDER BY 3 DESC LIMIT 12;" 2>&1
  } > "$OUT/$1.db.txt"
  note "$1 db: $(head -1 "$OUT/$1.db.txt"); $(grep '^messages|' "$OUT/$1.db.txt")"
}
list_latency() {  # list_latency NAME PROFILE RUNS
  local name="$1" prof="$2" runs="$3" i
  : > "$OUT/$name.tsv"
  local s0 s1
  for i in $(seq 1 "$runs"); do
    s0="$EPOCHREALTIME"
    NO_COLOR=1 SEALBOX_LOG=warn /usr/bin/time -f "%M" -o "$OUT/$name.$i.time" "$BIN" --profile "$prof" \
        list --limit 50 >"$OUT/$name.out" 2>"$OUT/$name.err" || { tail -3 "$OUT/$name.err"; return 1; }
    s1="$EPOCHREALTIME"
    echo "$i $(python3 -c "print(f'{$s1 - $s0:.4f}')") $(cat "$OUT/$name.$i.time")" >> "$OUT/$name.tsv"
    rm -f "$OUT/$name.$i.time"
  done
  local stats lines
  stats="$(python3 -c '
import statistics, sys
rows = [l.split() for l in open(sys.argv[1]) if l.strip()]
s = sorted(float(r[1]) for r in rows); m = [int(r[2]) for r in rows]
print(f"median {statistics.median(s):.4f} s  min {s[0]:.4f}  max {s[-1]:.4f}  maxrss {max(m)} kB")
' "$OUT/$name.tsv")"
  lines="$(wc -l < "$OUT/$name.out")"
  note "$name ($runs runs): $stats ($lines output lines)"
}
expect_inbox() {  # expect_inbox N — the server INBOX must hold exactly N before a measured sync
  local have; have="$(inbox_count)"
  note "server INBOX holds $have (expected $1)"
  [ "$have" = "$1" ] || note "WARNING: INBOX count differs from the seeded count (spam moved by an earlier sync?)"
}

# --- G33: the sync-at-scale gate (--gate) ---------------------------------------------------------------
# One pass, release build, LARGE (10k) seeded messages incl. the PGP/MIME share, logs at warn (the
# artifacts stay small: no manifest, no per-message events). Asserts what the phase-2 work promises
# (docs/PERFORMANCE.md) and prints one verdict line `G33 PASS` / `G33 FAIL (...)`:
#   g1  `sync` on a fresh profile stores the newest window (500): wall time, and the first stored batch
#       (the first mail a user sees) from the progress events;
#   g2  `sync --backfill` on a fresh profile stores all LARGE messages: wall time, peak RSS (memory is
#       bounded by the batch limits);
#   g3  +NEW new messages on the g2 profile: incremental `sync` wall time;
#   g4  `list --limit 50` on the g2 profile: median of LIST_RUNS runs.
# Thresholds: the after-numbers of 2026-10-29 (docs/PERFORMANCE.md "Phase 2"; 3 gate runs + 1
# perf run, perf server at 410-428 ms per 200-message UID FETCH) with >= 30 % headroom over the
# worst run. Phase-1 values (before) in brackets.
G33_WINDOW_S=4.5       # g1 wall: measured 2.27-2.94 s            [no window: 276-321 s until any mail]
G33_FIRST_BATCH_S=2.0  # g1 first stored batch: 1.16-1.22 s        [the newest mail was stored last]
G33_FULL_S=45.0        # g2 wall: 28.95-32.61 s                    [276-321 s]
G33_FULL_RSS_MB=120    # g2 peak RSS: 81-85 MB (200 msgs / 8 MiB per batch, two in memory) [28 MB]
G33_INCR_S=2.0         # g3 wall: 1.13-1.25 s                      [2.60-3.22 s]
G33_LIST_S=0.08        # g4 median: 0.012-0.041 s                  [0.12 s]
G33_SERVER_MS=1000     # the perf server's own cost per 200-message UID FETCH, above which it is restarted
gate_run() {
  local fails=() v
  say "[gate] G33 sync at scale: $LARGE messages on $EMAIL, release CLI"
  local probe attempt
  for attempt in 1 2 3; do
    seed large 0 "$LARGE"
    probe="$(server_probe g1_first_window)"
    # The perf server's pathological state (~1.7 s per command, see fresh_server) measures
    # GreenMail, not Sealbox: start it again (at most twice) rather than gate on it.
    [ "${probe:-0}" -le "$G33_SERVER_MS" ] && break
    if [ $attempt -lt 3 ]; then
      note "perf server in its slow state (${probe} ms per UID FETCH > ${G33_SERVER_MS}); restarting it"
      fresh_server || { note "G33 FAIL (perf GreenMail did not come back)"; return 1; }
      add_template_again
    fi
  done
  [ "${probe:-0}" -le "$G33_SERVER_MS" ] || fails+=("perf server stayed slow: ${probe} ms per 200-message UID FETCH")
  [ "$(inbox_count)" = "$LARGE" ] || fails+=("server INBOX holds $(inbox_count), not $LARGE")
  # g1: the newest window of a first sync.
  fresh_profile "$WORK/W"
  timed g1_first_window "$WORK/W" --json sync || fails+=("g1 sync failed")
  v="$(python3 -I - "$OUT" "$LARGE" <<'PY'
import json, os, sys
out, large = sys.argv[1], int(sys.argv[2])
rep = json.load(open(os.path.join(out, "g1_first_window.out")))[0]
ev = [json.loads(l) for l in open(os.path.join(out, "g1_first_window.err")) if l.startswith('{"')]
ev = [e for e in ev if e.get("event") == "sync_progress" and e.get("folder") == "INBOX"]
want = min(500, large)
ok = rep["new"] == want and bool(ev) and ev[-1]["local"] == want and all(e["phase"] == "initial" for e in ev)
first = ev[0]["t_ms"] / 1000 if ev else -1
print(f"{int(ok)} {first:.3f} {rep['new']} {rep['folders'][0].get('older_pending')} {len(ev)}")
PY
)"
  read -r g1_ok g1_first g1_new g1_older g1_events <<<"$v"
  note "g1: stored $g1_new (older pending $g1_older) in $g1_events batch(es); first batch stored at ${g1_first} s"
  [ "${g1_ok:-0}" = 1 ] || fails+=("g1 did not store exactly the newest window")
  # g2: the whole mailbox.
  fresh_profile "$WORK/F"
  timed g2_full_sync "$WORK/F" --json sync --backfill || fails+=("g2 sync --backfill failed")
  local g2_n g2_more
  g2_n="$(sqlite3 -readonly "$WORK/F/sealbox.db" 'SELECT count(*) FROM messages' 2>/dev/null || echo 0)"
  g2_more="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["folders"][0]["more_to_backfill"])' "$OUT/g2_full_sync.out" 2>/dev/null || echo '?')"
  note "g2: $g2_n messages stored, more_to_backfill=$g2_more"
  db_stats g2_full_sync "$WORK/F"
  [ "$g2_n" = "$LARGE" ] && [ "$g2_more" = "False" ] || fails+=("g2 stored $g2_n of $LARGE (more_to_backfill=$g2_more)")
  # g3: new mail on the complete profile.
  seed new "$LARGE" "$NEW"
  expect_inbox "$((LARGE + NEW))"
  timed g3_incremental "$WORK/F" --json sync || fails+=("g3 sync failed")
  local g3_new
  g3_new="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["new"])' "$OUT/g3_incremental.out" 2>/dev/null || echo '?')"
  note "g3: $g3_new new"
  [ "$g3_new" = "$NEW" ] || fails+=("g3 stored $g3_new new, not $NEW")
  # g4: list latency on the full profile.
  list_latency g4_list "$WORK/F" "$LIST_RUNS"
  local rows; rows="$(wc -l < "$OUT/g4_list.out")"
  [ "$rows" -ge 50 ] || fails+=("g4 list printed $rows lines, expected >= 50")
  # Verdict.
  local w1 w2 w3 l4 rss
  w1="$(awk '$1=="g1_first_window"{printf "%.2f", $3-$2}' "$OUT/steps.txt")"
  w2="$(awk '$1=="g2_full_sync"{printf "%.2f", $3-$2}' "$OUT/steps.txt")"
  w3="$(awk '$1=="g3_incremental"{printf "%.2f", $3-$2}' "$OUT/steps.txt")"
  l4="$(python3 -I -c 'import statistics,sys; print(f"{statistics.median(float(l.split()[1]) for l in open(sys.argv[1]) if l.strip()):.4f}")' "$OUT/g4_list.tsv")"
  rss="$(sed -n 's/.*Maximum resident set size (kbytes): //p' "$OUT/g2_full_sync.time" | awk '{printf "%.0f", $1/1024}')"
  check() {  # check LABEL VALUE MAX
    if python3 -I -c "import sys; sys.exit(0 if float('$2') <= float('$3') else 1)" 2>/dev/null; then
      note "  ok   $1 = $2 (max $3)"
    else
      note "  FAIL $1 = $2 (max $3)"; fails+=("$1 $2 > $3")
    fi
  }
  say "[gate] thresholds"
  check "g1 first window, wall s" "${w1:-999}" "$G33_WINDOW_S"
  check "g1 first stored batch, s" "${g1_first:-999}" "$G33_FIRST_BATCH_S"
  check "g2 full sync, wall s" "${w2:-999}" "$G33_FULL_S"
  check "g2 full sync, peak RSS MB" "${rss:-999999}" "$G33_FULL_RSS_MB"
  check "g3 +$NEW incremental, wall s" "${w3:-999}" "$G33_INCR_S"
  check "g4 list --limit 50, median s" "${l4:-999}" "$G33_LIST_S"
  printf 'metric\tvalue\tmax\ng1_window_s\t%s\t%s\ng1_first_batch_s\t%s\t%s\ng2_full_s\t%s\t%s\ng2_rss_mb\t%s\t%s\ng3_incremental_s\t%s\t%s\ng4_list_s\t%s\t%s\n' \
    "$w1" "$G33_WINDOW_S" "$g1_first" "$G33_FIRST_BATCH_S" "$w2" "$G33_FULL_S" "$rss" "$G33_FULL_RSS_MB" \
    "$w3" "$G33_INCR_S" "$l4" "$G33_LIST_S" > "$OUT/results.tsv"
  printf 'server_ms_per_fetch200\t%s\t%s\n' "$probe" "$G33_SERVER_MS" >> "$OUT/results.tsv"
  for f in INBOX Spam Junk Warmup; do python3 -I testing/gm_expunge.py "$PUSER" "$PERF_PASSWORD" "$f" "$IMAP_HOST" "$IMAP_PORT" >/dev/null 2>&1; done
  if [ ${#fails[@]} -eq 0 ]; then
    note "G33 PASS (window ${w1}s, first batch ${g1_first}s, full ${w2}s / ${rss} MB, +$NEW ${w3}s, list ${l4}s; server ${probe} ms per FETCH; $OUT)"
    return 0
  fi
  local IFS=';'
  note "G33 FAIL (${fails[*]}; $OUT)"
  return 1
}
if [ $GATE -eq 1 ]; then
  gate_run; exit $?
fi

# --- (d) desktop app cold start ---------------------------------------------------------------------------
APP_READY=0
ensure_app() {  # copy the release bundle + start a private Xvfb once; 0 when the app can be measured
  [ $APP -eq 1 ] || return 1
  [ $APP_READY -eq 1 ] && return 0
  [ $APP_READY -eq 2 ] && return 1
  APP_READY=2
  local bundle="$ROOT/app/build/linux/x64/release/bundle"
  if ! [ -x "$bundle/sealbox_app" ] || ! command -v Xvfb >/dev/null || ! command -v import >/dev/null || ! command -v xdotool >/dev/null; then
    note "  no release bundle / Xvfb / import / xdotool: app cold start not measured"; return 1
  fi
  cp -a "$bundle" "$WORK/bundle"   # a concurrent `flutter build` may rewrite the bundle
  APPBIN="$WORK/bundle/sealbox_app"
  note "bundle: $bundle (built $(stat -c %y "$bundle/lib/librust_lib_sealbox_app.so" | cut -c1-19); its engine is whatever app/rust was built from then)"
  local xf="$WORK/xdisplay" n=""
  : > "$xf"
  Xvfb -displayfd 3 -screen 0 1280x1000x24 -nolisten tcp -noreset 3>"$xf" >"$WORK/xvfb.log" 2>&1 &
  XPID=$!
  for _ in $(seq 1 100); do n="$(tr -dc '0-9' < "$xf")"; [ -n "$n" ] && break; sleep 0.1; done
  if [ -z "$n" ] || [ "$(ps -o comm= -p "$XPID" 2>/dev/null)" != "Xvfb" ]; then note "  Xvfb did not start; app cold start not measured"; return 1; fi
  export DISPLAY=":$n"
  APP_READY=1
}
app_cold_start() {  # app_cold_start NAME PROFILE [SECS] — frames for SECS (45) s; prints the timeline
  local name="$1" prof="$2" secs="${3:-45}" dir="$OUT/app/$1"
  mkdir -p "$dir"
  local log="$dir/app.log" t0 i=0 wid="" t_win="" t_bridge="" t f ms
  ms() { date +%s%3N; }
  t0="$(ms)"
  SEALBOX_PROFILE="$prof" SEALBOX_APP_LOCK=off SEALBOX_LOG=warn NO_COLOR=1 "$APPBIN" >"$log" 2>&1 &
  APID=$!
  : > "$dir/frames.tsv"
  # Capture the screen as fast as `import` allows for SECS s; each frame is stamped with the
  # time (ms since launch) at which its capture started.
  while :; do
    t="$(ms)"
    [ $((t - t0)) -lt $((secs * 1000)) ] || break
    [ "$(ps -o comm= -p "$APID" 2>/dev/null)" = "sealbox_app" ] || { note "  app exited early (log $log)"; break; }
    [ -z "$t_bridge" ] && grep -q "bridge OK" "$log" 2>/dev/null && t_bridge=$((t - t0))
    if [ -z "$wid" ]; then
      wid="$(xdotool search --onlyvisible --name '^Sealbox$' 2>/dev/null | head -n1)"
      [ -n "$wid" ] && { t_win=$(( $(ms) - t0 )); xdotool windowmove "$wid" 0 0 2>/dev/null; xdotool windowsize "$wid" 1280 800 2>/dev/null; }
    fi
    i=$((i + 1))
    f="$(printf 'f%03d.png' "$i")"
    import -display "$DISPLAY" -window root -crop 1280x800+0+0 -resize 50% "$dir/$f" 2>/dev/null || continue
    echo "$f $((t - t0))" >> "$dir/frames.tsv"
  done
  if [ "$(ps -o comm= -p "$APID" 2>/dev/null)" = "sealbox_app" ]; then kill "$APID" 2>/dev/null; wait "$APID" 2>/dev/null; fi
  APID=""
  # Drop consecutive duplicate frames (md5 of the pixels), keep the first of each run.
  python3 - "$dir" <<'PY'
import hashlib, os, subprocess, sys
d = sys.argv[1]; prev = None; keep = []
for line in open(os.path.join(d, "frames.tsv")):
    f, t = line.split()
    p = os.path.join(d, f)
    h = hashlib.md5(subprocess.run(["convert", p, "rgb:-"], capture_output=True).stdout).hexdigest()
    if h == prev:
        os.remove(p); continue
    prev = h; keep.append(f"{f} {t}")
open(os.path.join(d, "distinct.tsv"), "w").write("\n".join(keep) + "\n")
PY
  # The inbox list is "shown" in the first frame whose list pane (180x200 px at +45+100 of the
  # half-size capture) has a grey-level standard deviation > 0.08: rows of text and avatars give
  # ~0.13, the empty pane with the loading spinner < 0.03 (calibrated on the 2026-10-29 frames,
  # every decision is checkable in distinct.tsv / the kept PNGs).
  local inbox_ms="" prev_f="" inbox_f="" last_f="" f2 t2 sd
  : > "$dir/distinct_std.tsv"
  while read -r f2 t2; do
    sd="$(convert "$dir/$f2" -crop 180x200+45+100 -colorspace gray -format '%[fx:standard_deviation]' info: 2>/dev/null)"
    echo "$f2 $t2 $sd" >> "$dir/distinct_std.tsv"
    if [ -z "$inbox_ms" ] && python3 -c "import sys; sys.exit(0 if float('${sd:-0}') > 0.08 else 1)"; then
      inbox_ms="$t2"; inbox_f="$f2"
    fi
    [ -z "$inbox_ms" ] && prev_f="$f2"
    last_f="$f2"
  done < "$dir/distinct.tsv"
  # Also keep the first distinct frame at or after every 15 s mark (long captures: --app-first-sync).
  local marks
  marks="$(awk 'BEGIN{m=15000} {while ($2 >= m) {print $1; m += 15000}}' "$dir/distinct.tsv" | sort -u | tr '\n' ' ')"
  for f2 in "$dir"/f*.png; do
    case " $prev_f $inbox_f $last_f $marks " in *" $(basename "$f2") "*) ;; *) rm -f "$f2";; esac
  done
  echo "ms since launch: bridge_line=${t_bridge:--} window_mapped=${t_win:--} inbox_list_frame=${inbox_ms:-not seen} (${inbox_f:--}; previous frame ${prev_f:--}) frames=$i" > "$dir/timeline.txt"
  note "  $name: $(cat "$dir/timeline.txt"); distinct frames: $(wc -l < "$dir/distinct.tsv") (see $dir/distinct.tsv)"
}

# (a) first sync, SMALL
say "[a] first sync of $SMALL"
seed small 0 "$SMALL"
expect_inbox "$SMALL"
fresh_profile "$WORK/A"
timed a1_first_sync_small "$WORK/A" sync --backfill || die "sync failed"
db_stats a1_first_sync_small "$WORK/A"
# Overhead check of the debug events: the same sync with SEALBOX_LOG=warn.
fresh_profile "$WORK/A2"
LOGSPEC=warn timed a1w_first_sync_small_warnlog "$WORK/A2" sync --backfill || die "sync failed"
rm -rf "${WORK:?}/A2"

# (c) list latency on SMALL and on an empty profile
say "[c] list --limit 50 latency"
fresh_profile "$WORK/E"
list_latency c0_list_empty "$WORK/E" "$LIST_RUNS"
list_latency c1_list_small "$WORK/A" "$LIST_RUNS"
if ensure_app; then
  say "[d] desktop app cold start on the $SMALL profile (release bundle, private Xvfb)"
  app_cold_start d_small_run1 "$WORK/A"
fi

# (a) first sync, LARGE
say "[a] first sync of $LARGE (seed +$((LARGE - SMALL)))"
seed large "$SMALL" "$((LARGE - SMALL))"
expect_inbox "$LARGE"
# The window first (what a user sees first; --json: the per-batch progress events land in .err),
# then the whole mailbox on another fresh profile.
server_probe a2w_first_window_large >/dev/null
fresh_profile "$WORK/BW"
timed a2w_first_window_large "$WORK/BW" --json sync || die "sync failed"
rm -rf "${WORK:?}/BW"
server_probe a2_first_sync_large >/dev/null
fresh_profile "$WORK/B"
timed a2_first_sync_large "$WORK/B" sync --backfill || die "sync failed"
db_stats a2_first_sync_large "$WORK/B"

# (b) incremental
say "[b] incremental syncs on the $LARGE profile"
timed b0_incremental_0 "$WORK/B" sync || die "sync failed"
seed new "$LARGE" "$NEW"
expect_inbox "$((LARGE + NEW))"
timed b1_incremental_new "$WORK/B" sync || die "sync failed"
db_stats b1_incremental_new "$WORK/B"
list_latency c2_list_large "$WORK/B" "$LIST_RUNS"
# Where a list call's time goes: syscalls of one run (pread64 = SQLite pages read from the OS).
strace -f -c -o "$OUT/c2_list_large.strace.txt" "$BIN" --profile "$WORK/B" list --limit 50 >/dev/null 2>&1 || true
note "c2_list_large under strace -c: $(awk '$NF=="pread64"{print $4" pread64 calls"}' "$OUT/c2_list_large.strace.txt")"

# (e) the server's own cost: the same IMAP commands the engine sends, without Sealbox
say "[e] server baseline: raw IMAP SELECT / UID SEARCH / UID FETCH (UID FLAGS BODY.PEEK[]) in batches"
python3 -I - "$IMAP_HOST" "$IMAP_PORT" "$PUSER" "$PERF_PASSWORD" "50,200,1000" <<'PY' 2>&1 | tee "$OUT/e_server_baseline.txt" | tee -a "$OUT/summary.txt"
"""Raw IMAP baseline (no Sealbox): the same SELECT / UID SEARCH / UID FETCH (UID FLAGS BODY.PEEK[])
commands the engine sends, timed per command; literals are skipped by length."""
import socket, statistics, sys, time
host, port, user, pw, sizes = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
QA = getattr(socket, "TCP_QUICKACK", None)


class Conn:
    """Minimal IMAP reader: recv() into a buffer, skip literals by length, stop at the tagged line.
    TCP_QUICKACK is re-armed after every recv so the client never sits on a delayed ACK."""
    def __init__(self):
        self.s = socket.create_connection((host, port))
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b""; self.n = 0
        self._line()

    def _fill(self):
        chunk = self.s.recv(1 << 20)
        if QA is not None:
            self.s.setsockopt(socket.IPPROTO_TCP, QA, 1)
        if not chunk:
            raise EOFError
        self.buf += chunk

    def _line(self):
        while True:
            i = self.buf.find(b"\r\n")
            if i >= 0:
                line, self.buf = self.buf[:i + 2], self.buf[i + 2:]
                return line
            self._fill()

    def _skip(self, n):
        while len(self.buf) < n:
            self._fill()
        self.buf = self.buf[n:]

    def cmd(self, c):
        self.n += 1
        tag = b"R%05d" % self.n
        self.s.sendall(tag + b" " + c.encode() + b"\r\n")
        nbytes, untagged = 0, []
        while True:
            line = self._line()
            nbytes += len(line)
            if line.endswith(b"}\r\n") and b"{" in line:
                k = int(line[line.rindex(b"{") + 1:-3]); self._skip(k); nbytes += k
                continue
            if line.startswith(tag + b" "):
                if not line.startswith(tag + b" OK"):
                    raise RuntimeError(line)
                return nbytes, untagged
            if line.startswith(b"* SEARCH") or (line.startswith(b"* ") and b"EXISTS" in line):
                untagged.append(line)


c = Conn()
c.cmd(f'LOGIN "{user}" "{pw}"')
t = time.monotonic(); _, u = c.cmd("SELECT INBOX"); t_sel = time.monotonic() - t
exists = next((int(l.split()[1]) for l in u if b"EXISTS" in l), 0)
t = time.monotonic(); _, u = c.cmd("UID SEARCH UID 1:*"); t_search = time.monotonic() - t
uids = sorted(int(x) for l in u for x in l.split()[2:])
print(f"server baseline ({host}:{port} {user}): {exists} messages; SELECT {t_sel*1000:.0f} ms, "
      f"UID SEARCH UID 1:* {t_search*1000:.0f} ms ({len(uids)} uids)")
for size in (int(s) for s in sizes.split(",")):
    per, total_bytes = [], 0
    for k in range(0, len(uids), size):
        chunk = uids[k:k + size]
        time.sleep(0.1)  # untimed: the engine processes a batch between FETCHes; back-to-back
        # commands hit a ~40 ms delayed-ACK stall on loopback that the engine does not see
        t = time.monotonic()
        nb, _ = c.cmd(f"UID FETCH {chunk[0]}:{chunk[-1]} (UID FLAGS BODY.PEEK[])")
        per.append(time.monotonic() - t)
        total_bytes += nb
    el = sum(per)  # server time only (the pauses are excluded)
    print(f"  UID FETCH batch {size:5d}: {len(per)} commands, {el:7.2f} s total, {len(uids)/el:7.1f} msg/s, "
          f"{total_bytes/1e6/el:6.1f} MB/s, per command median {statistics.median(per)*1000:7.1f} ms "
          f"(first {per[0]*1000:.0f}, last {per[-1]*1000:.0f})")
time.sleep(0.1)
t = time.monotonic(); nb, _ = c.cmd("UID FETCH 1:* (UID FLAGS)"); el = time.monotonic() - t
print(f"  UID FETCH 1:* (UID FLAGS) (flag resync): {el*1000:.0f} ms, {nb/1e6:.2f} MB")
c.cmd("LOGOUT")
PY
if ensure_app; then
  say "[d] desktop app cold start on the $LARGE profile ($APP_RUNS runs)"
  for r in $(seq 1 "$APP_RUNS"); do app_cold_start "d_large_run$r" "$WORK/B"; done
  note "  which frame first shows the inbox list is decided by looking at distinct.tsv (docs/PERFORMANCE.md)"
fi
if [ "$APP_FS" -gt 0 ] && ensure_app; then
  say "[d2] the app during a first sync of the $((LARGE + NEW)) mailbox (fresh profile, $APP_FS s of frames)"
  fresh_profile "$WORK/F"
  app_cold_start d2_first_sync_in_app "$WORK/F" "$APP_FS"
  note "  messages stored by the app's sync when it was stopped: $(sqlite3 -readonly "$WORK/F/sealbox.db" 'select count(*) from messages' 2>/dev/null)"
fi

# --- per-message analysis (debug events x manifest) --------------------------------------------------
say "[analysis] per-message cost from the engine's debug events"
python3 - "$OUT" <<'PY' | tee -a "$OUT/summary.txt"
import datetime, json, os, re, statistics, sys
out = sys.argv[1]
man = {}
for l in open(os.path.join(out, "manifest.jsonl")):
    d = json.loads(l)
    if d.get("uid") is not None:
        man[d["uid"]] = d
steps = {l.split()[0]: (float(l.split()[1]), float(l.split()[2])) for l in open(os.path.join(out, "steps.txt"))}
rx = re.compile(r"^(\S+Z)\s+DEBUG sealbox_core::sync: message processed uid=(\d+)")
def q(v, p):
    v = sorted(v); return v[min(len(v) - 1, int(p * len(v)))]
rows = []
for step in ("a1_first_sync_small", "a2_first_sync_large", "b1_incremental_new"):
    ev = []
    for line in open(os.path.join(out, step + ".err"), errors="replace"):
        m = rx.match(line)
        if m:
            ev.append((datetime.datetime.fromisoformat(m.group(1).replace("Z", "+00:00")).timestamp(), int(m.group(2))))
    if len(ev) < 3:
        print(f"{step}: {len(ev)} events, skipped"); continue
    t0, t1 = steps[step]
    # Since phase 2 a first sync runs newest batch first (UIDs ascend inside a batch, jump down
    # between batches): a pair of consecutive events whose UIDs are not adjacent is a batch
    # boundary (the previous batch stored in one transaction, the next FETCH waited for beyond
    # the overlap); position = messages already processed in this run.
    per, by_kind, by_pos, boundary = [], {}, {}, []
    for k, ((ta, ua), (tb, ub)) in enumerate(zip(ev, ev[1:])):
        ms = (tb - ta) * 1000
        if ub - ua != 1:
            boundary.append(ms)
            continue
        if ub not in man:
            continue
        per.append(ms)
        by_kind.setdefault(man[ub]["kind"], []).append(ms)
        if man[ub]["kind"] in ("text", "alternative"):
            by_pos.setdefault((k + 1) // 1000, []).append(ms)
    if not per:
        print(f"{step}: no adjacent events, skipped"); continue
    n = len(ev)
    uids = [u for _, u in ev]
    print(f"{step}: {len(ev)} events over uids {min(uids)}..{max(uids)}")
    print(f"  phases: start->first message {ev[0][0]-t0:6.2f} s | fetch+process {ev[-1][0]-ev[0][0]:8.2f} s "
          f"({n/max(ev[-1][0]-ev[0][0], 1e-9):.1f} msg/s) | last message->exit {t1-ev[-1][0]:7.2f} s (store, spam pass, LIST, Sent, logout)")
    print(f"  per message (ms): median {statistics.median(per):.2f}  p90 {q(per,.9):.2f}  p99 {q(per,.99):.2f}  mean {statistics.mean(per):.2f}")
    for k, v in sorted(by_kind.items()):
        print(f"    {k:12s} n={len(v):5d}  median {statistics.median(v):8.2f} ms")
    if boundary:
        print(f"    batch boundaries (store a batch + wait for the next UID FETCH beyond the overlap): "
              f"n={len(boundary)} median {statistics.median(boundary):.1f} ms (sum {sum(boundary)/1000:.1f} s)")
    if len(by_pos) > 1:
        print("    text/alternative median by position (thousands of messages already processed this run): " +
              "  ".join(f"{p}k:{statistics.median(v):.1f}" for p, v in sorted(by_pos.items())))
    rows.append((step, len(ev), ev[-1][0]-ev[0][0], t1-ev[-1][0], statistics.median(per)))
with open(os.path.join(out, "per_message.tsv"), "w") as f:
    f.write("step\tevents\tfetch_process_s\ttail_s\tmedian_ms\n")
    for r in rows:
        f.write("\t".join(str(x) for x in r) + "\n")
PY

# --- optional stack samples -----------------------------------------------------------------------------
if [ "$SAMPLES" -gt 0 ]; then
  say "[samples] $SAMPLES gdb stack samples of a fresh first sync of the $LARGE mailbox (not timed)"
  fresh_profile "$WORK/S"
  mkdir -p "$OUT/samples"
  NO_COLOR=1 SEALBOX_LOG=warn "$BIN" --profile "$WORK/S" sync --backfill >"$OUT/samples/sync.out" 2>"$OUT/samples/sync.err" &
  SPID=$!
  sleep 0.5
  k=0
  while [ "$(ps -o comm= -p "$SPID" 2>/dev/null)" = "sealbox" ] && [ $k -lt "$SAMPLES" ]; do
    k=$((k + 1))
    gdb -p "$SPID" -batch -ex "set pagination off" -ex "thread apply all bt" >"$OUT/samples/s$(printf %04d $k).txt" 2>/dev/null
    sleep "$SAMPLE_IV"
  done
  wait "$SPID" 2>/dev/null   # let the sync finish before the profile is cleaned up
  python3 - "$OUT/samples" <<'PY' | tee "$OUT/samples/stages.txt" | tee -a "$OUT/summary.txt"
"""stages.py SAMPLES_DIR — classify gdb stack samples of a `sealbox sync` into pipeline stages.
Works for debug (full paths) and release + line tables (short names) builds. Each sample is put
in ONE bucket: the most specific engine stage on the sync thread's stack (priority order below);
a sample whose sync thread is parked in block_on with no engine frame on any thread is
"waiting on the IMAP server" (the CLI runs one task, so parked = the socket has nothing yet)."""
import collections, glob, os, re, sys

STAGES = [  # (bucket, any of these frame names on the sync thread's stack)
    ("refresh_keys: re-parse + re-verify every known public key", {"known_signers", "refresh_keys"}),
    ("decrypt + verify (rPGP)", {"decrypt_and_verify", "verify_detached"}),
    ("threading: threads_referencing (instr scan of every row)", {"threads_referencing"}),
    ("threading: threads_of_message (scan via messages_thread)", {"threads_of_message"}),
    ("threading: other (UPDATE merges)", {"thread_id_for"}),
    ("insert_message: seal + INSERT + commit", {"insert_message"}),
    ("identity bookkeeping (identity_observe)", {"identity_observe", "identity_on_message"}),
    ("autocrypt peer read/write", {"update_peer_from_header", "update_peer_from_gossip", "peer_state", "save_peer"}),
    ("spam pass after the fetch (load row + raw, features, UPDATE)", {"spam_after_sync", "spam_after_sync_inner"}),
    ("MIME parse (mail-parser)", {"parse", "parse_decrypted_inner"}),
    ("update_folder (watermark)", {"update_folder"}),
    ("IMAP client (FETCH response parsing, TLS-less socket reads)", {"fetch_rfc822_batch", "fetch_new_uids"}),
    ("sync_context / open", {"sync_context", "open", "open_with"}),
]
ENGINE_HINT = re.compile(r"sealbox_core|sealbox_mail|sealbox_crypto|sqlite3|pgp::|mail_parser|async_imap|"
                         r"\bthread_id_for\b|\binsert_message\b|\bprocess_message\b|\bknown_signers\b")


def frames(thread_text):
    out = []
    for m in re.finditer(r"^#\d+\s+(?:0x[0-9a-f]+ in )?(.+?) \((.*?)\)(?: at (\S+))?\s*$", thread_text, re.M):
        name = m.group(1)
        while True:  # strip generic arguments
            n2 = re.sub(r"<[^<>]*>", "", name)
            if n2 == name:
                break
            name = n2
        name = re.sub(r"::\{[^}]*\}", "", name).split("::")[-1]
        out.append((name, m.group(3) or ""))
    return out


def classify(path):
    txt = open(path, errors="replace").read()
    threads = re.split(r"\n(?=Thread \d+ )", txt)
    # The CLI polls the sync future on the main thread (tokio block_on).
    main = [t for t in threads if t.startswith("Thread 1 ")] or threads[:1]
    t = main[0] if main else ""
    fr = frames(t)
    names = {n for n, _ in fr}
    files = " ".join(f for _, f in fr)
    for bucket, keys in STAGES:
        if names & keys:
            if bucket.startswith("MIME") and "sealbox-mail/src/mime" not in files and "mail-parser" not in files:
                continue
            return bucket, fr
    if any(n == "park" for n, _ in fr[:20]) and not any(ENGINE_HINT.search(x) for x in threads if not x.startswith("Thread 1 ")):
        return "waiting on the IMAP server (process idle)", fr
    if "process_message" in names:
        return "process_message: other", fr
    if any("sqlite3" in n for n, _ in fr):
        return "sqlite: other", fr
    return "other", fr


d = sys.argv[1]
files = sorted(glob.glob(os.path.join(d, "s[0-9]*.txt")))
counts = collections.Counter(); sqlite_any = 0; overflow = 0
for f in files:
    b, fr = classify(f)
    counts[b] += 1
    sqlite_any += any(n.startswith("sqlite3") or n in ("pread64", "accessPayload") for n, _ in fr)
    overflow += any(n in ("getOverflowPage", "accessPayload") for n, _ in fr)
n = len(files)
print(f"{n} stack samples, one bucket each (share of samples ~ share of wall time):")
for b, c in counts.most_common():
    print(f"  {c:4d}  {100 * c / max(n, 1):5.1f} %  {b}")
print(f"  inclusive: inside SQLite {100 * sqlite_any / max(n, 1):.1f} % of samples; "
      f"reading overflow pages (accessPayload/getOverflowPage) {100 * overflow / max(n, 1):.1f} %")
PY
  # Keep the evidence small: every sample collapsed to one line of sync-thread frames
  # (flamegraph "collapsed" format), plus the first three raw backtraces.
  python3 - "$OUT/samples" "$OUT/samples/collapsed.txt" <<'PY'
"""collapse.py SAMPLES_DIR OUT — one line per gdb sample: the main thread's frames (the CLI polls the
sync future on it, inside block_on), outermost first, joined by ';' with a count of 1 — the
flamegraph 'collapsed' format. Runtime/generic frames are dropped, names shortened."""
import glob, os, re, sys
d, out = sys.argv[1], sys.argv[2]
lines = []
for f in sorted(glob.glob(os.path.join(d, "s[0-9]*.txt"))):
    txt = open(f, errors="replace").read()
    main = [t for t in re.split(r"\n(?=Thread \d+ )", txt) if t.startswith("Thread 1 ")]
    if not main:
        continue
    names = []
    for m in re.finditer(r"^#\d+\s+(?:0x[0-9a-f]+ in )?(.+?) \(", main[0], re.M):
        n = m.group(1)
        while True:
            n2 = re.sub(r"<[^<>]*>", "", n)
            if n2 == n:
                break
            n = n2
        n = re.sub(r"::\{[^}]*\}", "", n).split("::")[-1]
        if n in ("", "??") or n.startswith(("{closure", "{async_fn", "call_once", "poll", "with_budget",
                                             "budget", "enter_runtime", "try_with", "with_current",
                                             "catch_unwind", "do_call", "__rust", "lang_start")) or n.endswith(","):
            continue
        names.append(n[:80])
    lines.append(";".join(reversed(names)) + " 1")
open(out, "w").write("\n".join(lines) + "\n")
print(f"{len(lines)} samples collapsed -> {out} ({os.path.getsize(out)} bytes)")
PY
  find "$OUT/samples" -name 's[0-9]*.txt' ! -name 's000[123].txt' -delete
fi

# --- results table --------------------------------------------------------------------------------------------
say "[results] $OUT/results.tsv"
python3 - "$OUT" "$SMALL" "$LARGE" "$NEW" <<'PY' | tee -a "$OUT/summary.txt"
import os, re, sys
out, small, large, new = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
def tv(step, key):
    p = os.path.join(out, step + ".time")
    if not os.path.exists(p): return None
    m = re.search(re.escape(key) + r": (.+)", open(p).read())
    return m.group(1).strip() if m else None
def wall(step):
    for l in open(os.path.join(out, "steps.txt")):
        f = l.split()
        if f[0] == step: return float(f[2]) - float(f[1])
def dbbytes(step):
    p = os.path.join(out, step + ".db.txt")
    if not os.path.exists(p): return None
    m = re.search(r"db=(\d+) wal=(\d+)", open(p).read())
    return int(m.group(1)) + int(m.group(2)) if m else None
rows = [("a1_first_sync_small", f"first sync {small} (sync --backfill)", small),
        ("a1w_first_sync_small_warnlog", f"first sync {small} (sync --backfill, SEALBOX_LOG=warn)", small),
        ("a2w_first_window_large", f"first window of {large} (sync)", min(500, large)),
        ("a2_first_sync_large", f"first sync {large} (sync --backfill)", large),
        ("b0_incremental_0", "incremental, 0 new", 0),
        ("b1_incremental_new", f"incremental, {new} new", new)]
lines = ["step\tscenario\twall_s\tuser_s\tsys_s\tmaxrss_MB\tmsgs_per_s\tdb_MB\tload_1min"]
loads = {l.split()[0]: "->".join(l.split()[4:6]) for l in open(os.path.join(out, "steps.txt")) if len(l.split()) >= 6}
for step, label, n in rows:
    w = wall(step)
    if w is None: continue
    rss = tv(step, "Maximum resident set size (kbytes)")
    db = dbbytes(step)
    lines.append("\t".join([step, label, f"{w:.2f}", tv(step, "User time (seconds)") or "-",
                            tv(step, "System time (seconds)") or "-",
                            f"{int(rss)/1024:.0f}" if rss else "-",
                            f"{n / w:.1f}" if n else "-", f"{db/1e6:.1f}" if db else "-", loads.get(step, "-")]))
open(os.path.join(out, "results.tsv"), "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
PY
# Leave the perf mailbox empty (the seeds are the bulk of GreenMail's heap); logs + numbers stay.
if [ $KEEP -eq 0 ]; then
  for f in INBOX Spam Junk Warmup; do python3 -I testing/gm_expunge.py "$PUSER" "$PERF_PASSWORD" "$f" "$IMAP_HOST" "$IMAP_PORT" >/dev/null 2>&1; done
fi
note "done: $OUT"
