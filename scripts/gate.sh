#!/usr/bin/env bash
# Sealbox gate runner — the ONLY source of truth for gate status (docs/GATES.md).
# Usage: scripts/gate.sh [--quick] [--only G1,G4] [--quiet]
# Gate command exit codes: 0 PASS · 3 NEEDS_HUMAN (blocked on credentials/accounts the human must provide;
#   the suite itself ran) · anything else FAIL · 124 TIMEOUT.
#   --quick  skips gates that need docker / long builds (G3 G4 G8 G9 G10 G15 G16)
# Writes .gate/gate_status.json and per-gate logs in .gate/gate_logs/ (local, gitignored).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
. scripts/env.sh
QUICK=0; ONLY=""; QUIET=0
while [ $# -gt 0 ]; do case "$1" in --quick) QUICK=1;; --only) ONLY="$2"; shift;; --quiet) QUIET=1;; *) echo "unknown arg $1" >&2; exit 2;; esac; shift; done
mkdir -p .gate/gate_logs
STATUS_JSON=.gate/gate_status.json
RUN_AT="$(date -Is)"
# Provenance: every result recorded by THIS run is stamped with the tree it describes. Gates
# carried forward from an earlier run keep their own older stamp, so a reader can tell the
# difference — "31/34 PASS" on no particular tree is how a mutant survived two weeks (G34).
HEAD_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
# Excludes .gate/ for the same reason G34 does: this script writes .gate/gate_logs/*.log and
# the status JSON as it goes, so counting those would mark every run dirty and the flag would
# stop meaning anything. Dirty here means the *source* the gates ran against was uncommitted.
HEAD_DIRTY=false
[ -z "$(git status --porcelain -- . ':!.gate' 2>/dev/null)" ] || HEAD_DIRTY=true

# id | claim | kind:target | command | timeout_s | docker?
# kind:target decides NOT_IMPLEMENTED: file:<path> must exist, script:<path> must be executable, manual:- never auto-passes.
GATES=(
"G34|tree is gateable: no mutation markers, HEAD not an unverified autosave, tree clean|script:scripts/gate_tree.sh|scripts/gate_tree.sh --self-test && scripts/gate_tree.sh|60|0"
"G0|workspace and the app bridge crate build, fmt + clippy clean, unit tests pass|file:Cargo.toml|cargo fmt --all --check && cargo clippy --workspace -q --all-targets -- -D warnings && cargo test --workspace -q && cargo fmt --manifest-path app/rust/Cargo.toml --all --check && cargo clippy --manifest-path app/rust/Cargo.toml --all-targets -q -- -D warnings && cargo test --manifest-path app/rust/Cargo.toml -q|3000|0"
"G1|OpenPGP core + interop both directions with gpg, RNP (Thunderbird's engine) and Sequoia + Autocrypt|file:crates/sealbox-crypto/tests/gate_g1.rs|cargo test -p sealbox-crypto --test gate_g1 -q && cargo test -p sealbox-crypto --test interop_rnp_sq -q -- --ignored|900|0"
"G2|PGP/MIME build+parse, protected headers|file:crates/sealbox-mail/tests/gate_g2.rs|cargo test -p sealbox-mail --test gate_g2 -q|900|0"
"G3|SMTP submit + IMAP fetch against GreenMail|file:crates/sealbox-mail/tests/gate_g3.rs|testing/mail_up.sh && cargo test -p sealbox-mail --test gate_g3 -q -- --ignored|900|1"
"G4|E2E encrypted mail Alice→Bob→Alice through GreenMail via sealbox CLI, Autocrypt bootstrap|file:crates/sealbox-cli/tests/gate_g4.rs|testing/mail_up.sh && cargo test -p sealbox-cli --test gate_g4 -q -- --ignored|1200|1"
"G5|Autodiscover: offline table + ISPDB + SRV|file:crates/sealbox-mail/tests/gate_g5.rs|cargo test -p sealbox-mail --test gate_g5 -q|600|0"
"G6|OAuth2 PKCE + XOAUTH2 unit vectors (real login is manual: gate G21)|file:crates/sealbox-mail/tests/gate_g6.rs|cargo test -p sealbox-mail --test gate_g6 -q|600|0"
"G7|Server: key directory verify flow, guest messages, backups, viewer decrypts|file:crates/sealbox-server/tests/gate_g7.rs|cargo test -p sealbox-server --test gate_g7 -q|900|0"
"G8|CLI desktop client e2e against GreenMail|file:crates/sealbox-cli/tests/gate_g8.rs|testing/mail_up.sh && cargo test -p sealbox-cli --test gate_g8 -q -- --ignored|1200|1"
"G9|Flutter analyze+test+Linux desktop build+launch, FRB bridge into Rust|script:scripts/gate_flutter.sh|scripts/gate_flutter.sh|2400|1"
"G10|Android debug APK builds|script:scripts/gate_android.sh|scripts/gate_android.sh|2400|1"
"G11|iOS build on CI macOS runner (human-gated)|manual:-|false|1|0"
"G12|Real-world encrypted mail via real Gmail/Outlook decrypted by Thunderbird/Proton (human-gated)|manual:-|false|1|0"
"G13|Security: fuzz targets clean, gitleaks clean, threat model complete|script:scripts/gate_security.sh|scripts/gate_security.sh|2400|0"
"G14|PQC hybrid round-trip (ML-KEM-768+X25519; rPGP pqc feature, off in the product build)|file:crates/sealbox-crypto/tests/gate_g14.rs|cargo test -p sealbox-crypto --features pqc --test gate_g14 -q|900|0"
"G15|Multi-device: encrypted backup + restore, Autocrypt Setup Message|file:crates/sealbox-cli/tests/gate_g15.rs|testing/mail_up.sh && cargo test -p sealbox-cli --test gate_g15 -q -- --ignored|1200|1"
"G16|Push relay prototype: IMAP IDLE → content-free push (GreenMail)|file:crates/sealbox-relay/tests/gate_g16.rs|testing/mail_up.sh && cargo test -p sealbox-relay --test gate_g16 -q -- --ignored|900|1"
"G17|App ↔ core wiring: Flutter drives real accounts via FRB (GreenMail integration test)|script:scripts/gate_g17.sh|scripts/gate_g17.sh|2400|1"
"G18|Desktop production: release bundle + packaged, screenshot review loop, 60 s crash-free session|script:scripts/gate_g18.sh|scripts/gate_g18.sh|2400|1"
"G19|Mobile loop: headless Android emulator, on-device smoke test, screenshots|script:scripts/gate_g19.sh|scripts/gate_g19.sh|3000|1"
"G20|UI/UX suite: goldens × sizes × themes, a11y guidelines, e2e flow|script:scripts/gate_g20.sh|scripts/gate_g20.sh|2400|1"
"G21S|Simulated provider conformance: the 19 G21 checks run against a loopback simulator for every ProviderId, each result and detail text asserted against expectations computed from PROFILES; no docker, no real mailbox. Evidence of what the engine does with our beliefs about a provider, never evidence about the provider. Includes the alias gotcha: an OAuth sign-in whose mailbox is an alias fails, and the CLI names the flag that fixes it|file:crates/sealbox-cli/tests/gate_g21_sim.rs|cargo test -p sealbox-fakeprov -q && cargo test -p sealbox-cli --test gate_g21_sim -q && cargo test -p sealbox-cli --test cli_oauth_alias -q|900|0"
"G21|Provider conformance: Gmail/Outlook/Yahoo/iCloud evidence + OAuth add-account|script:scripts/gate_g21.sh|scripts/gate_g21.sh|1800|0"
"G22|Hosted mailbox: provision on Stalwart via backend, encrypted e2e|script:scripts/gate_g22.sh|scripts/gate_g22.sh|1800|1"
"G23|Signatures per account, applied on compose/reply, settings UI+CLI|file:crates/sealbox-cli/tests/gate_g23.rs|testing/mail_up.sh && cargo test -p sealbox-cli --test gate_g23 -q -- --ignored|1200|1"
"G24|Holiday auto-reply (RFC 3834) once per sender, suppression rules, encrypted when possible|file:crates/sealbox-cli/tests/gate_g24.rs|testing/mail_up.sh && cargo test -p sealbox-cli --test gate_g24 -q -- --ignored|1200|1"
"G25|Spam + filters: rules + Bayes + feedback, corpus precision/recall, filter rules|script:scripts/gate_g25.sh|scripts/gate_g25.sh|1800|1"
"G26|Release engineering: release builds, CI workflows, changelog, privacy policy, redaction audit|script:scripts/gate_release.sh|scripts/gate_release.sh|2400|1"
"G27|Secrets at rest wrapped by keystore key, app lock, OAuth refresh in engine|script:scripts/gate_g27.sh|scripts/gate_g27.sh|1800|0"
"G28|Browser extension: wasm core round-trips with gpg, MV3 extension builds+lints, fixture e2e in headless Chromium, Office add-in manifest valid|script:scripts/gate_g28.sh|scripts/gate_g28.sh|2400|0"
"G29|Guest-link modes: no secret in the default link, one-click opt-in, email-code gate, viewer handles all, resend|script:scripts/gate_g29.sh|scripts/gate_g29.sh|1800|1"
"G30|Identity: key-change alerts, verified contacts, key-transparency log with client-verified proofs|script:scripts/gate_g30.sh|scripts/gate_g30.sh|1800|1"
"G31|Safe HTML mail: sanitizer XSS corpus + fixed point + cost clamp, HTML-only mail parsed right, CLI read --html against GreenMail|file:crates/sealbox-cli/tests/cli_read_html.rs|cargo test -p sealbox-mail --lib -q html && cargo test -p sealbox-mail --lib -q mime::parse && testing/mail_up.sh && for u in u71 u72; do for f in INBOX Sent; do python3 -I testing/gm_expunge.py \$u \${u}pw \$f >/dev/null; done; done && cargo test -p sealbox-cli --test cli_read_html -q -- --ignored|1200|1"
"G32|Search + saved drafts: in-memory FTS5 over sealed bodies, drafts sealed at rest (rewrap/migration), CLI search + draft e2e|file:crates/sealbox-cli/tests/cli_search_drafts.rs|cargo test -p sealbox-core --lib -q search && cargo test -p sealbox-core --lib -q drafts && testing/mail_up.sh && cargo test -p sealbox-cli --test cli_search_drafts -q -- --ignored && cargo test -p sealbox-cli --test cli_draft_sync -q -- --ignored|1500|1"
"G35|Mailbox convergence: mail deleted or read elsewhere converges here — stored UIDs the server no longer lists are dropped, flags that changed elsewhere are followed, an emptied folder empties locally, and a broken UID SEARCH deletes nothing|file:crates/sealbox-cli/tests/cli_reconcile.rs|cargo test -p sealbox-core --lib -q reconcile && cargo test -p sealbox-core --lib -q window_tests && testing/mail_up.sh && cargo test -p sealbox-cli --test cli_reconcile -q -- --ignored|900|1"
"G33|Sync at scale: 10k-message mailbox on the perf GreenMail — newest mail stored within budget, full first sync, incremental and list latency bounded (release CLI; scripts/perf_sync.sh --gate)|script:scripts/perf_sync.sh|testing/mail_perf_up.sh && scripts/perf_sync.sh --gate|3000|1"
)

declare -A ST SEC
printf '%-4s %-16s %5s  %s\n' GATE STATUS SECS CLAIM
for row in "${GATES[@]}"; do
  IFS='|' read -r id claim kind cmd tmo dock <<<"$row"
  ktype="${kind%%:*}"; ktarget="${kind#*:}"
  if [ -n "$ONLY" ] && ! grep -qw "$id" <<<"${ONLY//,/ }"; then continue; fi
  log=".gate/gate_logs/$id.log"
  status=""; secs=0
  case "$ktype" in
    manual) status="MANUAL";;
    file)   [ -f "$ktarget" ] || status="NOT_IMPLEMENTED";;
    script) [ -x "$ktarget" ] || status="NOT_IMPLEMENTED";;
  esac
  if [ -z "$status" ] && [ "$QUICK" = 1 ] && [ "$dock" = 1 ]; then status="SKIPPED_QUICK"; fi
  if [ -z "$status" ]; then
    t0=$(date +%s)
    { echo "# $id  $RUN_AT"; echo "# $cmd"; } > "$log"
    if timeout --foreground "$tmo" bash -o pipefail -c "$cmd" >> "$log" 2>&1; then status="PASS"; else
      rc=$?; status="FAIL"; [ $rc -eq 124 ] && status="TIMEOUT"; [ $rc -eq 3 ] && status="NEEDS_HUMAN"; fi
    secs=$(( $(date +%s) - t0 ))
  fi
  ST[$id]="$status"; SEC[$id]="$secs"
  [ "$QUIET" = 1 ] || printf '%-4s %-16s %5s  %s\n' "$id" "$status" "$secs" "$claim"
done

# Write status JSON (merge with previous for gates not run this time).
python3 - "$STATUS_JSON" "$RUN_AT" "$(printf '%s\n' "${GATES[@]}")" "$(for k in "${!ST[@]}"; do echo "$k=${ST[$k]}=${SEC[$k]}"; done)" "$HEAD_SHA" "$HEAD_DIRTY" <<'PY'
import json, sys, os
status_path, run_at, gates_blob, results_blob, head_sha, head_dirty = sys.argv[1:7]
head_dirty = head_dirty == "true"
claims = {r.split('|')[0]: r.split('|')[1] for r in gates_blob.splitlines() if r}
prev = {}
if os.path.exists(status_path):
    try: prev = json.load(open(status_path)).get("gates", {})
    except Exception: prev = {}
gates = dict(prev)
for line in results_blob.splitlines():
    if not line: continue
    gid, st, secs = line.split('=')
    gates[gid] = {"status": st, "seconds": int(secs), "claim": claims.get(gid, ""), "run_at": run_at,
                  "commit": head_sha, "dirty": head_dirty, "log": f".gate/gate_logs/{gid}.log"}
# G21S sorts right after G21: a gate id is a number with an optional letter suffix.
def gate_key(g):
    digits = "".join(c for c in g[1:] if c.isdigit())
    return (int(digits) if digits else 0, g[1:].lstrip("0123456789"))
order = sorted(gates, key=gate_key)
json.dump({"run_at": run_at, "head": head_sha, "dirty": head_dirty,
           "gates": {g: gates[g] for g in order}}, open(status_path, "w"), indent=1)
passed = [g for g in order if gates[g]["status"] == "PASS"]
# A gate whose record names a different commit describes a different tree. Say which, every
# time: a summary that hides it is the thing that let an unverified autosave read as green.
stale = [g for g in order if gates[g].get("commit", "unknown") != head_sha]
note = f"   ({len(stale)} recorded on an older tree: {' '.join(stale)})" if stale else ""
dirty_note = "  [DIRTY TREE — describes no commit]" if head_dirty else ""
print(f"\n{len(passed)}/{len(order)} gates PASS: {' '.join(passed) or '-'}{note}")
print(f"tree {head_sha[:12]}{dirty_note}   (status → {status_path})")
PY
# exit 0 if every gate that RAN passed, else 1
for k in "${!ST[@]}"; do case "${ST[$k]}" in FAIL|TIMEOUT) exit 1;; esac; done
exit 0
