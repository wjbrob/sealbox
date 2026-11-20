#!/usr/bin/env bash
# Gate G25 — spam detection + filtering (docs/GATES.md).
#   1. public corpus present (testing/corpus/fetch_corpus.sh, cached under testing/corpus/.cache/)
#   2. unit tests of sealbox-spam and the core spam/filter modules
#   3. `sealbox spam eval` on the held-out 30 % (seed 42): precision >= 0.98 and recall >= 0.85
#   4. GreenMail end-to-end (cargo test -p sealbox-cli --test gate_g25 -- --ignored, users u21–u25)
# Exit 0 only if every step passes. Prints the evaluation numbers.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
. scripts/env.sh
CORPUS=testing/corpus/.cache/corpus
MIN_PRECISION="${G25_MIN_PRECISION:-0.98}"
MIN_RECALL="${G25_MIN_RECALL:-0.85}"
step() { echo; echo "### G25 $*"; }
fail() { echo "G25 FAIL: $*" >&2; exit 1; }

step "1/4 corpus (SpamAssassin public corpus, cached)"
testing/corpus/fetch_corpus.sh || fail "corpus download / verification failed"

step "2/4 unit tests (sealbox-spam, sealbox-core spam + filters)"
cargo test -p sealbox-spam -q || fail "sealbox-spam unit tests"
cargo test -p sealbox-core -q -- spam filters || fail "sealbox-core spam/filter unit tests"

step "3/4 held-out evaluation (70/30 split, seed 42; targets precision >= $MIN_PRECISION, recall >= $MIN_RECALL)"
EVAL_LOG="$(mktemp)"
if cargo run -q -p sealbox-cli -- spam eval --corpus "$CORPUS" --seed 42 --train-fraction 0.7 \
     --min-precision "$MIN_PRECISION" --min-recall "$MIN_RECALL" --list 5 | tee "$EVAL_LOG"; then
  :
else
  cat "$EVAL_LOG"; rm -f "$EVAL_LOG"; fail "evaluation below target"
fi
NUMBERS="$(grep -E '^precision=' "$EVAL_LOG" | head -1)"
rm -f "$EVAL_LOG"
echo "G25 eval: $NUMBERS"

step "4/4 GreenMail end-to-end (u21–u25)"
testing/mail_up.sh || fail "GreenMail not reachable"
cargo test -p sealbox-cli --test gate_g25 -q -- --ignored || fail "e2e"

echo
echo "G25 PASS — $NUMBERS"
exit 0
