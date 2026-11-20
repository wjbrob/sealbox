#!/usr/bin/env bash
# scripts/gate_g21.sh — gate G21 (docs/GATES.md): provider conformance.
#
#   Step 1 (always, must PASS): the local half against GreenMail —
#       testing/mail_up.sh && cargo test -p sealbox-cli --test gate_g21_local -- --ignored
#     = `sealbox provider-test` on a password account (u27) and on an OAuth account (u26) whose
#       tokens come from a mock identity provider (loopback PKCE flow end to end, token expiry →
#       refresh, SMTP XOAUTH2), plus delete-to-Trash on u29.
#   Step 2 (the real providers): reads .gate/providers.local.env (format documented in
#       testing/providers.local.env.example), makes sure every configured account exists in the gate
#       profile (.gate/profiles/g21 — gitignored; app passwords are added non-interactively, OAuth
#       accounts need one interactive consent, see below), runs the suite for each and writes
#       evidence to .gate/evidence/G21/<provider>-<date>.json (no secrets). The results table in
#       docs/PROVIDERS_CONFORMANCE.md is refreshed (addresses masked).
#
#   Exit 0  local PASS and Gmail, Outlook/Hotmail, Yahoo and iCloud all have PASS evidence from today.
#   Exit 3  NEEDS_HUMAN: local PASS, but accounts / app passwords / OAuth consent are missing or
#           rejected; the script prints exactly what the human has to provide.
#   Exit 1  a real failure: the local suite failed, or a configured account's suite FAILED.
#
# Non-interactive by construction (never opens a browser; never prompts). Logs: target/gate_g21/.

set -u -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
export PATH="$HOME/.cargo/bin:$PATH"
# shellcheck disable=SC1091
[ -f scripts/env.sh ] && . scripts/env.sh >/dev/null 2>&1

DATE="$(date -u +%F)"
LOGDIR="$ROOT/target/gate_g21"
EVIDENCE="${SEALBOX_EVIDENCE_DIR:-$ROOT/.gate/evidence/G21}"
PROFILE="${SEALBOX_G21_PROFILE:-$ROOT/.gate/profiles/g21}"
DOC="$ROOT/docs/PROVIDERS_CONFORMANCE.md"
REQUIRED=(gmail outlook yahoo icloud)
mkdir -p "$LOGDIR" "$EVIDENCE"

say() { printf '%s\n' "$*"; }
hr()  { say "------------------------------------------------------------------------------"; }

# ---------------------------------------------------------------------------------------------
# Step 1: local half.
# ---------------------------------------------------------------------------------------------
hr; say "G21 step 1/2 — local conformance against GreenMail + mock OAuth IdP"; hr
if ! testing/mail_up.sh; then
  say "FAIL: GreenMail did not come up (docker)"; exit 1
fi
if ! cargo test -p sealbox-cli --test gate_g21_local -q -- --ignored --test-threads=3 \
     > "$LOGDIR/local.log" 2>&1; then
  tail -60 "$LOGDIR/local.log"
  say "FAIL: gate_g21_local did not pass (log: $LOGDIR/local.log)"; exit 1
fi
grep -E "^test result" "$LOGDIR/local.log" | tail -1
say "local half: PASS"

if ! cargo build -q -p sealbox-cli; then say "FAIL: sealbox CLI does not build"; exit 1; fi
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
BIN="$TARGET_DIR/debug/sealbox"
[ -x "$BIN" ] || { say "FAIL: $BIN missing"; exit 1; }
sb() { "$BIN" --profile "$PROFILE" "$@"; }

# ---------------------------------------------------------------------------------------------
# Step 2: real providers.
# ---------------------------------------------------------------------------------------------
hr; say "G21 step 2/2 — real providers (.gate/providers.local.env)"; hr
set -a
# shellcheck disable=SC1091
[ -f .gate/config.env ] && . .gate/config.env
# shellcheck disable=SC1091
[ -f .gate/config.local.env ] && . .gate/config.local.env
# shellcheck disable=SC1091
[ -f .gate/providers.local.env ] && . .gate/providers.local.env
set +a

declare -A STATUS   # provider -> PASS | FAIL | NEEDS_HUMAN
declare -A REASON   # provider -> text for the human
declare -A ACCOUNT  # provider -> masked address
NEEDS=()            # lines the human must act on

mask() { local e="$1"; printf '%s***@%s' "${e:0:1}" "${e#*@}"; }
need() { # provider, masked account, instruction
  STATUS["$1"]="NEEDS_HUMAN"; REASON["$1"]="$3"; NEEDS+=("[$1] $3")
}

if [ -z "${PROVIDER_ACCOUNTS:-}" ]; then
  say "no PROVIDER_ACCOUNTS configured."
  NEEDS+=("create .gate/providers.local.env from testing/providers.local.env.example with one entry each for gmail, outlook, yahoo and icloud")
else
  IFS=',' read -r -a ENTRIES <<<"$PROVIDER_ACCOUNTS"
  for entry in "${ENTRIES[@]}"; do
    entry="${entry// /}"; [ -z "$entry" ] && continue
    IFS=':' read -r provider email auth <<<"$entry"
    provider="$(printf '%s' "$provider" | tr 'A-Z' 'a-z')"
    case "$provider" in hotmail|live|microsoft|m365) provider=outlook;; google) provider=gmail;; aol) provider=yahoo;; esac
    masked="$(mask "$email")"
    ACCOUNT["$provider"]="$masked"
    say ""; say "== $provider  $masked  ($auth)"

    # Does the gate profile already hold the account?
    have=0
    if sb --json account list 2>/dev/null | python3 -c '
import json,sys
want=sys.argv[1].lower()
try: rows=json.load(sys.stdin)
except Exception: rows=[]
sys.exit(0 if any(r.get("email","").lower()==want for r in rows) else 1)' "$email"; then have=1; fi

    if [ "$have" = 0 ]; then
      case "$auth" in
        password_env=*)
          var="${auth#password_env=}"
          if [ -z "${!var:-}" ]; then
            need "$provider" "$masked" "set $var=<app password for $masked> in .gate/providers.local.env ($provider app-password how-to: docs/PROVIDERS_CONFORMANCE.md)"
            continue
          fi
          if ! sb account add --email "$email" --password-env "$var" > "$LOGDIR/$provider-add.log" 2>&1; then
            rc=$?
            if [ "$rc" = 4 ]; then
              need "$provider" "$masked" "login rejected for $masked: regenerate the app password and update $var (details: $LOGDIR/$provider-add.log)"
            else
              STATUS["$provider"]="FAIL"; REASON["$provider"]="account add failed (exit $rc): $(tail -1 "$LOGDIR/$provider-add.log")"
            fi
            continue
          fi
          ;;
        oauth)
          case "$provider" in
            gmail)   idp=google;    idvar=GOOGLE_OAUTH_CLIENT_ID;;
            outlook) idp=microsoft; idvar=MS_OAUTH_CLIENT_ID;;
            *)       STATUS["$provider"]="FAIL"; REASON["$provider"]="oauth is only supported for gmail/outlook"; continue;;
          esac
          if [ -z "${!idvar:-}" ]; then
            need "$provider" "$masked" "set $idvar in .gate/config.local.env (console clicks: docs/PROVIDERS_CONFORMANCE.md §OAuth consent), then run the one-time consent below"
          fi
          need "$provider" "$masked" "one-time interactive consent (opens a browser, ~2 min): set -a; . .gate/config.local.env; set +a; $BIN --profile $PROFILE account add --email $email --oauth $idp --open-browser"
          continue
          ;;
        *)
          STATUS["$provider"]="FAIL"; REASON["$provider"]="unknown auth spec '$auth' (expected password_env=VAR or oauth)"
          continue
          ;;
      esac
    fi

    # Run the suite.
    out="$LOGDIR/$provider.json"
    if sb --json provider-test --account "$email" --evidence-dir "$EVIDENCE" > "$out" 2> "$LOGDIR/$provider.err"; then
      STATUS["$provider"]="PASS"; REASON["$provider"]="evidence $EVIDENCE/$provider-$DATE.json"
      python3 - "$out" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
for c in d["checks"]:
    print(f'  {c["status"]:<4} {c["ms"]:>7} ms  {c["name"]:<28} {c["detail"][:110]}')
PY
    else
      rc=$?
      err="$(cat "$LOGDIR/$provider.err" "$out" 2>/dev/null | tr '\n' ' ' | tail -c 400)"
      if [ "$rc" = 4 ] || printf '%s' "$err" | grep -qiE "invalid_grant|consent|AUTHENTICATIONFAILED|authentication failed|re-run .sealbox account add"; then
        need "$provider" "$masked" "credentials no longer accepted for $masked ($err). Password accounts: update the app password and run: $BIN --profile $PROFILE account remove --email $email, then re-run this gate. OAuth: $BIN --profile $PROFILE account remove --email $email && $BIN --profile $PROFILE account add --email $email --oauth <google|microsoft> --open-browser"
      else
        STATUS["$provider"]="FAIL"
        failed="$(python3 -c '
import json,sys
try:
    d=json.load(open(sys.argv[1])); print(", ".join(c["name"]+": "+c["detail"][:160] for c in d["checks"] if c["status"]=="FAIL"))
except Exception as e: print("no evidence: "+str(e))' "$out")"
        REASON["$provider"]="suite FAILED (exit $rc): ${failed:-$err}"
      fi
    fi
  done
fi

# Today's PASS evidence also counts for providers not run in this invocation (e.g. the human
# ran the suite interactively right after consenting).
for p in "${REQUIRED[@]}"; do
  if [ -z "${STATUS[$p]:-}" ] && [ -f "$EVIDENCE/$p-$DATE.json" ] && \
     python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("result")=="PASS" else 1)' "$EVIDENCE/$p-$DATE.json"; then
    STATUS["$p"]="PASS"; REASON["$p"]="evidence $EVIDENCE/$p-$DATE.json (earlier today)"
  fi
  if [ -z "${STATUS[$p]:-}" ]; then
    need "$p" "-" "no account configured for $p: add '$p:<address>:password_env=VAR' or '$p:<address>:oauth' to PROVIDER_ACCOUNTS in .gate/providers.local.env"
  fi
done

# ---------------------------------------------------------------------------------------------
# Results table in the doc (addresses masked, no secrets), summary, exit code.
# ---------------------------------------------------------------------------------------------
python3 - "$DOC" "$DATE" "$EVIDENCE" <<'PY'
import json, os, sys, glob
doc, date, evidence = sys.argv[1:4]
rows = []
for f in sorted(glob.glob(os.path.join(evidence, "*.json"))):
    try:
        d = json.load(open(f))
    except Exception:
        continue
    acct = d.get("account", "")
    masked = (acct[:1] + "***@" + acct.split("@", 1)[1]) if "@" in acct else "-"
    s = d.get("summary", {})
    rows.append((d.get("date", ""), d.get("provider", ""), masked, d.get("auth_kind", ""), d.get("result", ""),
                 f'{s.get("pass",0)}/{s.get("fail",0)}/{s.get("skip",0)}', os.path.relpath(f, os.path.dirname(os.path.dirname(doc)))))
rows.sort(key=lambda r: (r[0], r[1]), reverse=True)
table = ["| date | provider | account | auth | result | pass/fail/skip | evidence |", "|---|---|---|---|---|---|---|"]
table += [f"| {a} | {b} | {c} | {d} | {e} | {f} | `{g}` |" for a, b, c, d, e, f, g in rows[:40]] or ["| – | – | – | – | no runs yet | – | – |"]
start, end = "<!-- G21-RESULTS-START -->", "<!-- G21-RESULTS-END -->"
try:
    text = open(doc).read()
except FileNotFoundError:
    sys.exit(0)
if start in text and end in text:
    head, rest = text.split(start, 1)
    _, tail = rest.split(end, 1)
    text = head + start + "\n" + "\n".join(table) + "\n" + end + tail
    open(doc, "w").write(text)
PY

hr; say "G21 summary ($DATE)"; hr
EXIT=0
for p in "${REQUIRED[@]}"; do
  st="${STATUS[$p]:-NEEDS_HUMAN}"
  printf '%-8s %-12s %s  %s\n' "$p" "$st" "${ACCOUNT[$p]:--}" "${REASON[$p]:-}"
  case "$st" in FAIL) EXIT=1;; NEEDS_HUMAN) [ "$EXIT" = 0 ] && EXIT=3;; esac
done
for p in "${!STATUS[@]}"; do
  case " ${REQUIRED[*]} " in *" $p "*) ;; *) printf '%-8s %-12s %s  %s\n' "$p" "${STATUS[$p]}" "${ACCOUNT[$p]:--}" "${REASON[$p]:-}"; [ "${STATUS[$p]}" = FAIL ] && EXIT=1;; esac
done
if [ "${#NEEDS[@]}" -gt 0 ]; then
  hr; say "NEEDS_HUMAN — exactly what to provide:"
  for n in "${NEEDS[@]}"; do say "  * $n"; done
  say "  (5-minute procedure incl. the Google Cloud / Entra console clicks: docs/PROVIDERS_CONFORMANCE.md)"
fi
case "$EXIT" in
  0) say "G21: PASS (local + gmail/outlook/yahoo/icloud evidence for $DATE)";;
  3) say "G21: NEEDS_HUMAN (local half passed; real-provider evidence incomplete)";;
  *) say "G21: FAIL";;
esac
exit "$EXIT"
