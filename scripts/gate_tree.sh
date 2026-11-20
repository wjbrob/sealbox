#!/usr/bin/env bash
# G34 — "tree is gateable": can the results of this gate run be attributed to a known tree?
#
# Why this gate exists. On 2026-10-29 commit 8c19bec (the autosave of a session stopped
# mid-flight, honestly labelled unverified WIP in its own message) carried a live
# mutation-test mutant — `return; // MUTATION` at the top of MessageBody._markUnshown — and
# master kept it for two weeks. Two gates had the tests that would kill it, and the gate run
# still reported green overall, because nothing tied "31/34 PASS" to a particular tree.
#
# Verdicts:
#   FAIL (1)          a mutation/debug marker is in the tree, or HEAD is an unverified autosave.
#                     These make every other gate's PASS meaningless; fix before trusting a run.
#   NEEDS_HUMAN (3)   the working tree is dirty. The run still happened and the per-gate records
#                     carry dirty=true, but the result describes no commit. Commit or stash.
#   PASS (0)          HEAD is a clean, marker-free tree; a PASS this run means something.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

fail=0

# 1. Mutation and "do not commit" markers.
#    (patterns defined first so --self-test can exercise them)
#    Anchored to a comment opener and scoped to source paths on purpose. Prose legitimately
#    discusses mutants — review findings describe the 8c19bec one at length, and a past
#    celebration message shouts about "MUTATION-XSS" — so a bare word match reports those
#    every run, and a gate that cries wolf is a gate people learn to ignore.
markers='(//|#|/\*|<!--|--)[[:space:]]*(MUTATION|XXX-MUTANT|DO NOT COMMIT)\b'
autosave_re='^autosave before daily run |^daily .* s[0-9]+ autosave\b|^wip[: ]'

# --self-test: the two patterns above against the strings that actually matter. Each case here
# is a mistake this gate made while being written; three in one sitting, all the same shape —
# matching prose that *talks about* a problem as though it were the problem.
if [ "${1:-}" = "--self-test" ]; then
  st=0
  check() { # check <expect FLAG|ok> <pattern> <string> <label>
    if printf '%s' "$3" | grep -qiE "$2"; then got=FLAG; else got=ok; fi
    if [ "$got" = "$1" ]; then printf '  ok   %-5s %s\n' "$got" "$4"
    else printf '  FAIL want=%s got=%s  %s\n' "$1" "$got" "$4"; st=1; fi
  }
  echo "marker pattern:"
  check FLAG "$markers" '    return; // MUTATION' 'the real 8c19bec mutant'
  check FLAG "$markers" '# DO NOT COMMIT' 'shell do-not-commit marker'
  check FLAG "$markers" '<!-- XXX-MUTANT -->' 'html mutant marker'
  check ok   "$markers" 'NON-FIXED-POINT MUTATION-XSS SHAPE' 'prose in a celebration message'
  check ok   "$markers" '| N4 | broken by a mutation-test mutant in 8c19bec' 'a review finding'
  echo "autosave-subject pattern:"
  check FLAG "$autosave_re" 'daily 2026-10-28 s14 autosave (stopped by owner)' 'the mutant commit itself'
  check FLAG "$autosave_re" 'daily 2026-10-28 s13 autosave' 'a plain driver autosave'
  check FLAG "$autosave_re" 'autosave before daily run 22' "the driver's other format"
  check FLAG "$autosave_re" 'wip: half-done sync work' 'an explicit wip subject'
  check ok   "$autosave_re" "gate: G34's autosave check reads the subject" 'a commit about autosaves'
  check ok   "$autosave_re" 'app: saved drafts — autosave, Drafts chip, resume' 'the autosave feature (5058ad9)'
  [ $st = 0 ] && echo "self-test: all cases behave" || echo "self-test: FAILED"
  exit $st
fi

if out=$(git grep -nE "$markers" -- \
        crates app extension web fuzz scripts testing \
        ':!scripts/gate_tree.sh' ':!*/pkg-node/*' ':!*/pkg-web/*' ':!*/vendor/*' 2>/dev/null) \
        && [ -n "$out" ]; then
  echo "FAIL: mutation/debug markers are in the tree —"
  echo "$out"
  echo "A mutant in the tree means every test that should kill it is lying. Remove it."
  fail=1
fi

# 2. An unverified autosave must not be the tree a gate run describes, unless it says which
#    gated tree it was taken from (trailer `Gated: <sha>`).
#
#    Match the autosave subjects automated tooling emits (and an explicit `wip:`) rather than the
#    word "autosave" anywhere. Twice while writing this gate a looser pattern flagged a commit
#    for *talking about* an autosave — including this gate's own two commits — and history also
#    holds 5058ad9 "app: saved drafts — autosave, Drafts chip, …", a real feature commit. The
#    word is not the problem; a tree nobody verified is.
subject=$(git log -1 --pretty=%s 2>/dev/null || echo "")
if printf '%s' "$subject" | grep -qiE "$autosave_re" \
   && ! git log -1 --pretty=%B 2>/dev/null | grep -qE '^Gated: [0-9a-f]{7,40}$'; then
  echo "FAIL: HEAD is an unverified autosave with no 'Gated: <sha>' trailer —"
  git log -1 --oneline
  fail=1
fi

[ "$fail" = 0 ] || exit 1

# 3. A dirty tree is not a lie, just unattributable. Say so and stop short of PASS.
#    `.gate/` is excluded because it is the harness's own bookkeeping — gate.sh opens
#    .gate/gate_logs/G34.log before running this script, so counting it would mean the act of
#    running the gate always fails the gate. What has to be attributable is the source.
if [ -n "$(git status --porcelain -- . ':!.gate' 2>/dev/null)" ]; then
  echo "NEEDS_HUMAN: the working tree is dirty, so this run describes no commit."
  git status --short -- . ':!.gate' | head -20
  echo "Commit or stash, then re-run. (Per-gate records still carry dirty=true.)"
  exit 3
fi

echo "PASS: $(git rev-parse --short HEAD) is clean and marker-free."
exit 0
