#!/usr/bin/env bash
# Gate G13 — security (docs/GATES.md row G13; what each step proves: docs/THREAT_MODEL.md §7).
#
#   (a) docs/THREAT_MODEL.md is complete: every required "## " section is present (REQUIRED_SECTIONS
#       below; a leading "N. " is ignored), adversaries A1–A8 are all there, and no stub marker
#       (TODO, TBD, FIXME, "to be completed", "stub") is left.
#   (b) libFuzzer build: `cargo +nightly fuzz build -O` — AddressSanitizer (cargo-fuzz's default),
#       debug assertions + overflow checks ON for every crate via fuzz/Cargo.toml's profile (one
#       documented exception: mail-parser's debug_assert!s, see there), cached in fuzz/target.
#       Then `fuzz/seedgen -- --check` proves every committed seed still reaches the path it was
#       made for (decrypts, verifies, parses), so (c) never runs over dead seeds.
#   (c) libFuzzer run: every target for SEALBOX_FUZZ_SECS seconds (default 125, i.e. 750 s in
#       total; the gate refuses to pass with less than 600 s), -timeout=10 -rss_limit_mb=2560;
#       LeakSanitizer is on (libFuzzer + ASan default). Working corpora fuzz/corpus/<t> persist
#       between runs; a corpus above SEALBOX_FUZZ_CMIN_AT units (default 20000) is minimised with
#       `cargo fuzz cmin` first (not counted as fuzzing time; a failed cmin only leaves the corpus
#       as it was). FAIL on any non-zero libFuzzer exit (crash, sanitizer report, leak, OOM,
#       timeout) and on any new file under fuzz/artifacts/. The targets run concurrently, one
#       process each (SEALBOX_FUZZ_PARALLEL=0: one after the other); every target gets its full time.
#   (d) gitleaks with .gitleaks.toml (default rules + path-scoped allow-lists for documented test
#       material) and --redact: first a canary (a synthetic AWS-style key generated at run time)
#       must be found, which proves the config loads and the default rules are live; then the full
#       history of every ref, and the working tree as git sees it: tracked + untracked-but-not-
#       ignored files, hard-linked into target/gate_security/tree, so build output and the
#       deliberately git-ignored local secret files (e.g. .gate/providers.local.env) are not
#       "the tree" and are never read. The history pass skips exactly two generated report names
#       (review/android/**/smoke_report.json, manifest.json: PNG screenshots serialised as JSON
#       integer arrays, ~40 MB per commit; `git log -p` alone spends ~8 min diffing them and grows
#       with every autosave). No rule can match integer arrays, their current versions are in the
#       tree pass, and with the default rules the excluded and the full history scans gave the
#       same findings (2026-10-29). SEALBOX_GITLEAKS_FULL_HISTORY=1 scans them as well.
#   (e) cargo audit of Cargo.lock, app/rust/Cargo.lock, extension/wasm/Cargo.lock and
#       fuzz/Cargo.lock — informative: advisories are printed and never fail the gate; with
#       SEALBOX_AUDIT_REQUIRED=1 the gate fails if the tool itself cannot run.
#
# Exit 0 with "GATE G13: PASS" only if (a)–(d) pass, else "GATE G13: FAIL — <reasons>", exit 1.
# Logs: target/gate_security/ (summary.txt, fuzz_<target>.log, gitleaks-*.json/log, cargo-audit-*).
# Env: SEALBOX_FUZZ_SECS, SEALBOX_FUZZ_PARALLEL, SEALBOX_FUZZ_CMIN_AT, SEALBOX_AUDIT_REQUIRED,
#      SEALBOX_GITLEAKS_FULL_HISTORY, SEALBOX_GATE_LOCK_WAIT, GITLEAKS (binary path).
# Every long-running child runs under its own `timeout` (gate.sh's `timeout --foreground` does
# not reach children), so nothing outlives the gate; no process is ever killed by name.
set -u -o pipefail
cd "$(dirname "$0")/.." || exit 2
[ -f scripts/env.sh ] && . scripts/env.sh
ROOT="$PWD"
LOG="target/gate_security"
mkdir -p "$LOG"
# One G13 run at a time: concurrent runs would share fuzz/corpus, fuzz/artifacts and these logs.
# A second run waits (SEALBOX_GATE_LOCK_WAIT seconds, default 1800) instead of interleaving.
exec 9> "$LOG/.lock"
if ! flock -w "${SEALBOX_GATE_LOCK_WAIT:-1800}" 9; then
  echo "GATE G13: FAIL — another scripts/gate_security.sh run still holds $LOG/.lock"
  exit 1
fi
SUMMARY="$LOG/summary.txt"
: > "$SUMMARY"
T0=$(date +%s)
FAILS=()
TARGETS=(mime_parse pgp_decrypt autocrypt_header guest_decrypt autodiscover_xml html_sanitize)

say() { echo "$*" | tee -a "$SUMMARY"; }
step() { echo | tee -a "$SUMMARY"; say "### G13 $*"; }
bad() { FAILS+=("$*"); say "G13 FAIL: $*"; }
since() { echo $(( $(date +%s) - $1 )); }
finish() {
  echo | tee -a "$SUMMARY"
  say "wall-clock: $(since "$T0") s"
  if [ ${#FAILS[@]} -eq 0 ]; then
    say "GATE G13: PASS"
    exit 0
  fi
  local IFS=';'
  say "GATE G13: FAIL — ${FAILS[*]}"
  exit 1
}
say "G13 security gate — $(date -Is) — $(git rev-parse --short HEAD 2>/dev/null)"

# ---------------------------------------------------------------------------------------------
step "(a) threat model: docs/THREAT_MODEL.md"
TM=docs/THREAT_MODEL.md
REQUIRED_SECTIONS=(
  "Scope & assets"
  "Trust boundaries"
  "Adversaries"
  "Attack surface"
  "Threats & mitigations"
  "Residual risks"
  "Security testing"
  "Disclosure"
)
if [ ! -f "$TM" ]; then
  bad "$TM is missing"
else
  HEADINGS="$(sed -nE 's/^## +([0-9]+\.[[:space:]]+)?//p' "$TM")"
  for s in "${REQUIRED_SECTIONS[@]}"; do
    if printf '%s\n' "$HEADINGS" | awk -v s="$s" 'index($0, s) == 1 { f = 1 } END { exit !f }'; then
      say "  section ok: $s"
    else
      bad "threat model lacks the section \"## $s\""
    fi
  done
  for a in 1 2 3 4 5 6 7 8; do
    grep -qE "\bA$a\b" "$TM" || bad "threat model does not describe adversary A$a"
  done
  STUBS="$(grep -nE '\b(TODO|TBD|FIXME)\b' "$TM"; grep -niE 'to be completed|\bstubs?\b' "$TM")"
  if [ -n "$STUBS" ]; then
    bad "stub markers left in $TM: $(printf '%s' "$STUBS" | head -3 | tr '\n' ' ')"
  else
    say "  no stub markers; $(wc -l < "$TM") lines"
  fi
fi

# ---------------------------------------------------------------------------------------------
step "(b) fuzz build (cargo +nightly fuzz build -O, AddressSanitizer) + seed check"
BUILD_OK=1
t=$(date +%s)
if timeout -k 30 1500 cargo +nightly fuzz build -O --fuzz-dir fuzz > "$LOG/fuzz_build.log" 2>&1; then
  say "  fuzz build ok ($(since "$t") s; $(grep -c '^ *Compiling' "$LOG/fuzz_build.log") crates compiled)"
else
  bad "fuzz build failed (see $LOG/fuzz_build.log)"
  BUILD_OK=0
fi
HOST="$(rustc +nightly -vV 2>/dev/null | sed -n 's/^host: //p')"
BIN_DIR="fuzz/target/${HOST:-x86_64-unknown-linux-gnu}/release"
if [ "$BUILD_OK" = 1 ]; then
  for tg in "${TARGETS[@]}"; do
    [ -x "$BIN_DIR/$tg" ] || { bad "fuzz target $tg was not built"; BUILD_OK=0; }
  done
fi
t=$(date +%s)
if timeout -k 30 900 cargo run -q --manifest-path fuzz/seedgen/Cargo.toml --release \
     --target-dir target/fuzz-seedgen -- --check > "$LOG/seed_check.log" 2>&1; then
  say "  $(tail -1 "$LOG/seed_check.log") ($(since "$t") s)"
else
  bad "seed check failed: $(grep -m1 -E '^Error|seed ' "$LOG/seed_check.log") (see $LOG/seed_check.log)"
fi

# ---------------------------------------------------------------------------------------------
SECS="${SEALBOX_FUZZ_SECS:-125}"
PARALLEL="${SEALBOX_FUZZ_PARALLEL:-1}"
step "(c) fuzz run: ${#TARGETS[@]} targets × ${SECS} s ($([ "$PARALLEL" = 0 ] && echo sequential || echo concurrent)), -timeout=10 -rss_limit_mb=2560"
case "$SECS" in ''|*[!0-9]*) SECS=0 ;; esac
PLANNED=$(( SECS * ${#TARGETS[@]} ))
if [ "$PLANNED" -lt 600 ]; then
  bad "SEALBOX_FUZZ_SECS=${SEALBOX_FUZZ_SECS:-} gives ${PLANNED} s of fuzzing; G13 requires >= 600 s in total"
elif [ "$BUILD_OK" != 1 ]; then
  bad "fuzz run skipped: no build"
else
  mkdir -p fuzz/artifacts fuzz/corpus
  find fuzz/artifacts -type f | sort > "$LOG/artifacts.before"
  CMIN_AT="${SEALBOX_FUZZ_CMIN_AT:-20000}"
  case "$CMIN_AT" in ''|*[!0-9]*) CMIN_AT=20000 ;; esac
  run_target() {
    local tg="$1" s n
    mkdir -p "fuzz/corpus/$tg" "fuzz/artifacts/$tg"
    rm -f "$LOG/fuzz_$tg.cmin"
    n=$(find "fuzz/corpus/$tg" -type f | wc -l)
    if [ "$n" -gt "$CMIN_AT" ]; then
      s=$(date +%s)
      if timeout -k 30 900 cargo +nightly fuzz cmin -O --fuzz-dir fuzz "$tg" "fuzz/corpus/$tg" -- \
           -timeout=10 -rss_limit_mb=2560 > "$LOG/fuzz_cmin_$tg.log" 2>&1; then
        echo "corpus minimised $n -> $(find "fuzz/corpus/$tg" -type f | wc -l) units ($(since "$s") s)" \
          > "$LOG/fuzz_$tg.cmin"
      else
        echo "corpus minimisation failed (see $LOG/fuzz_cmin_$tg.log); fuzzing the full corpus" \
          > "$LOG/fuzz_$tg.cmin"
      fi
    fi
    s=$(date +%s)
    timeout -k 30 $(( SECS + 900 )) cargo +nightly fuzz run -O --fuzz-dir fuzz "$tg" \
      "fuzz/corpus/$tg" "fuzz/seeds/$tg" -- \
      -max_total_time="$SECS" -timeout=10 -rss_limit_mb=2560 -print_final_stats=1 \
      > "$LOG/fuzz_$tg.log" 2>&1
    echo "$? $(since "$s")" > "$LOG/fuzz_$tg.rc"
  }
  t=$(date +%s)
  if [ "$PARALLEL" = 0 ]; then
    for tg in "${TARGETS[@]}"; do run_target "$tg"; done
  else
    PIDS=()
    for tg in "${TARGETS[@]}"; do run_target "$tg" & PIDS+=($!); done
    for p in "${PIDS[@]}"; do wait "$p"; done
  fi
  TOTAL=0
  for tg in "${TARGETS[@]}"; do
    read -r rc wall < "$LOG/fuzz_$tg.rc" || { rc=99; wall=0; }
    done_line="$(grep -E '^Done [0-9]+ runs in [0-9]+ second' "$LOG/fuzz_$tg.log" | tail -1)"
    runs="$(printf '%s' "$done_line" | sed -nE 's/^Done ([0-9]+) runs.*/\1/p')"
    fsecs="$(printf '%s' "$done_line" | sed -nE 's/.* in ([0-9]+) second.*/\1/p')"
    corpus="$(find "fuzz/corpus/$tg" -type f | wc -l)"
    rss="$(sed -nE 's/^stat::peak_rss_mb: *([0-9]+).*/\1/p' "$LOG/fuzz_$tg.log" | tail -1)"
    TOTAL=$(( TOTAL + ${fsecs:-0} ))
    [ -f "$LOG/fuzz_$tg.cmin" ] && say "  $tg: $(cat "$LOG/fuzz_$tg.cmin")"
    if [ "$rc" = 0 ] && [ -n "$done_line" ]; then
      say "  $tg: ${runs} execs in ${fsecs} s, corpus ${corpus} units, peak RSS ${rss:-?} MB — clean"
    else
      why="$(grep -m1 -E 'SUMMARY: |ERROR: libFuzzer|panicked at|==ERROR' "$LOG/fuzz_$tg.log")"
      bad "fuzz target $tg: exit $rc after ${wall} s: ${why:-no libFuzzer summary} (see $LOG/fuzz_$tg.log)"
    fi
  done
  say "  total fuzzing time: ${TOTAL} s (wall $(since "$t") s)"
  [ "$TOTAL" -ge 600 ] || bad "only ${TOTAL} s of fuzzing measured; G13 requires >= 600 s"
  find fuzz/artifacts -type f | sort > "$LOG/artifacts.after"
  NEW="$(comm -13 "$LOG/artifacts.before" "$LOG/artifacts.after")"
  if [ -n "$NEW" ]; then
    bad "new fuzz artifacts: $(printf '%s' "$NEW" | tr '\n' ' ')"
  else
    say "  no new files under fuzz/artifacts/"
  fi
fi

# ---------------------------------------------------------------------------------------------
step "(d) gitleaks: full history + working tree (.gitleaks.toml, --redact)"
GL="${GITLEAKS:-}"
[ -z "$GL" ] && [ -x target/tools/gitleaks ] && GL="$ROOT/target/tools/gitleaks"
[ -z "$GL" ] && GL="$(command -v gitleaks || true)"
count_findings() { # report.json -> "N" and a redacted per-file summary into the log
  python3 - "$1" <<'PY'
import collections, json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("ERR"); sys.exit()
print(len(d))
for (rule, path), n in sorted(collections.Counter((f["RuleID"], f["File"]) for f in d).items()):
    print(f"    {n:3d} × {rule:24s} {path}", file=sys.stderr)
PY
}
if [ -z "$GL" ] || [ ! -x "$GL" ]; then
  bad "gitleaks not found (target/tools/gitleaks, \$GITLEAKS or PATH)"
elif [ ! -f .gitleaks.toml ]; then
  bad ".gitleaks.toml is missing"
else
  case "$GL" in /*) ;; *) GL="$ROOT/$GL" ;; esac
  say "  $("$GL" version 2>/dev/null | head -1 | sed 's/^/gitleaks /'); $(git rev-list --all --count) commits"

  # canary: built at run time so the literal never sits in the repository
  CANARY="$LOG/canary"
  rm -rf "$CANARY" && mkdir -p "$CANARY"
  printf 'aws_access_key_id = AKIA%s\n' \
    "$(head -c 64 /dev/urandom | base32 | tr -dc 'A-Z2-7' | head -c 16)" > "$CANARY/canary.txt"
  ( cd "$CANARY" && "$GL" dir --no-banner --redact --config "$ROOT/.gitleaks.toml" \
      -f json -r "$ROOT/$LOG/gitleaks-canary.json" . ) > "$LOG/gitleaks-canary.log" 2>&1
  rc=$?
  n="$(count_findings "$LOG/gitleaks-canary.json" 2>/dev/null)"
  rm -rf "$CANARY"
  if [ "$rc" = 1 ] && [ "$n" = 1 ]; then
    say "  canary detected (config loads, default rules active)"
  else
    bad "gitleaks did not detect the canary secret (exit $rc, $n findings): config or rules broken"
  fi

  HISTORY_OPTS="--full-history --all"
  if [ "${SEALBOX_GITLEAKS_FULL_HISTORY:-0}" != 1 ]; then
    HISTORY_OPTS="$HISTORY_OPTS -- . :(exclude,glob)review/android/**/smoke_report.json"
    HISTORY_OPTS="$HISTORY_OPTS :(exclude,glob)review/android/**/manifest.json"
  fi
  t=$(date +%s)
  timeout -k 30 1500 "$GL" git --no-banner --redact --config .gitleaks.toml --log-opts="$HISTORY_OPTS" \
    -f json -r "$LOG/gitleaks-history.json" . > "$LOG/gitleaks-history.log" 2>&1
  rc=$?
  n="$(count_findings "$LOG/gitleaks-history.json" 2>>"$LOG/gitleaks-history.log")"
  if [ "$rc" = 0 ] && [ "$n" = 0 ]; then
    say "  history: no leaks ($(grep -o 'scanned ~[0-9]* bytes[^)]*)' "$LOG/gitleaks-history.log" | head -1); $(since "$t") s)"
  elif [ "$rc" = 1 ] && [ "$n" != ERR ]; then
    bad "gitleaks: $n finding(s) in the history (redacted list: $LOG/gitleaks-history.log)"
  else
    bad "gitleaks history scan did not complete (exit $rc, see $LOG/gitleaks-history.log)"
  fi

  t=$(date +%s)
  TREE="$LOG/tree"
  rm -rf "$TREE" && mkdir -p "$TREE"
  # tracked + untracked-not-ignored; skip index entries deleted in the working tree
  git ls-files -z -co --exclude-standard \
    | while IFS= read -r -d '' f; do [ -f "$f" ] && printf '%s\0' "$f"; done \
    | xargs -0 -r cp -l --parents -t "$TREE" 2> "$LOG/tree_stage.err" \
    || { : > "$LOG/tree_stage.err"; rm -rf "$TREE" && mkdir -p "$TREE"; \
         git ls-files -z -co --exclude-standard \
           | while IFS= read -r -d '' f; do [ -f "$f" ] && printf '%s\0' "$f"; done \
           | xargs -0 -r cp --parents -t "$TREE"; }
  FILES="$(find "$TREE" -type f | wc -l)"
  ( cd "$TREE" && timeout -k 30 600 "$GL" dir --no-banner --redact --config "$ROOT/.gitleaks.toml" \
      -f json -r "$ROOT/$LOG/gitleaks-tree.json" . ) > "$LOG/gitleaks-tree.log" 2>&1
  rc=$?
  n="$(count_findings "$LOG/gitleaks-tree.json" 2>>"$LOG/gitleaks-tree.log")"
  if [ "$rc" = 0 ] && [ "$n" = 0 ]; then
    say "  tree: no leaks in $FILES files ($(since "$t") s)"
  elif [ "$rc" = 1 ] && [ "$n" != ERR ]; then
    bad "gitleaks: $n finding(s) in the working tree (redacted list: $LOG/gitleaks-tree.log)"
  else
    bad "gitleaks tree scan did not complete (exit $rc, see $LOG/gitleaks-tree.log)"
  fi
  rm -rf "$TREE"
fi

# ---------------------------------------------------------------------------------------------
step "(e) cargo audit (informative)"
if cargo audit --version > /dev/null 2>&1; then
  FETCH=""
  AUDITED=0
  for L in Cargo.lock app/rust/Cargo.lock extension/wasm/Cargo.lock fuzz/Cargo.lock; do
    [ -f "$L" ] || continue
    out="$LOG/cargo-audit-$(printf '%s' "$L" | tr '/' '_').json"
    timeout -k 10 300 cargo audit $FETCH --json -f "$L" > "$out" 2> "$out.err"
    if ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))["vulnerabilities"]' "$out" 2>/dev/null \
       && [ -z "$FETCH" ]; then
      say "  advisory DB fetch failed, retrying with the local copy (--no-fetch)"
      FETCH="--no-fetch"
      timeout -k 10 300 cargo audit --no-fetch --json -f "$L" > "$out" 2> "$out.err"
    fi
    FETCH="--no-fetch" # fetched once is enough
    if summary="$(python3 - "$out" "$L" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
v = d["vulnerabilities"]
w = d.get("warnings", {})
ids = ", ".join(f'{x["advisory"]["id"]} {x["package"]["name"]} {x["package"]["version"]}' for x in v["list"])
ws = ", ".join(f"{len(x)} {k}" for k, x in w.items() if x) or "none"
print(f'  {sys.argv[2]}: {d["lockfile"]["dependency-count"]} deps, {v["count"]} advisories'
      + (f" ({ids})" if ids else "") + f"; warnings: {ws}")
PY
)"; then
      say "$summary"
      AUDITED=$(( AUDITED + 1 ))
    else
      say "  $L: cargo audit did not produce a report (see $out.err)"
    fi
  done
  if [ "$AUDITED" = 0 ] && [ "${SEALBOX_AUDIT_REQUIRED:-0}" = 1 ]; then
    bad "cargo audit could not run (SEALBOX_AUDIT_REQUIRED=1)"
  fi
  say "  (informative: advisories never fail G13; triage in docs/THREAT_MODEL.md §6, R13)"
elif [ "${SEALBOX_AUDIT_REQUIRED:-0}" = 1 ]; then
  bad "cargo audit is not installed (SEALBOX_AUDIT_REQUIRED=1)"
else
  say "  cargo audit not installed — informative step skipped"
fi

finish
