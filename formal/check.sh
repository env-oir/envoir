#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Gate the DMTAP formal models against EXPECTED.txt.
#
# run.sh RUNS the models and prints their output, but every invocation is
# `|| true`, so it exits 0 whether every property holds or one silently broke.
# That is the difference between a proof being *executed* and a proof being
# *enforced* — and an unenforced proof degrades into a claim in a README the
# moment the model or the spec moves underneath it.
#
# This script re-runs the models, extracts every RESULT line, and compares the
# verdicts to EXPECTED.txt. Any deviation in EITHER direction is a failure:
#   - a security query turning false is a regression;
#   - a non-vacuity control turning true means the model can no longer reach the
#     states it reasons about, so its "proofs" have gone vacuous while still
#     reporting success. See EXPECTED.txt for why that is the worse case.
#
# Usage:  ./check.sh          # run models, then gate
#         ./check.sh <log>    # gate an existing run.sh log without re-running
# Exit:   0 all verdicts as expected; 1 otherwise.
# ---------------------------------------------------------------------------
set -uo pipefail
cd "$(dirname "$0")"

EXPECTED="EXPECTED.txt"
[ -f "$EXPECTED" ] || { echo "missing $EXPECTED"; exit 1; }

if [ "$#" -ge 1 ]; then
  LOG="$1"
  echo "gating existing log: $LOG"
else
  LOG="$(mktemp -t proverif-check)"
  echo "running models (this takes a few minutes) ..."
  ./run.sh >"$LOG" 2>&1
fi

# Attribute each RESULT line to the model whose banner most recently preceded it.
ACTUAL="$(awk '/^== proverif/{m=$3} /^RESULT/{sub(/^RESULT /,""); print m"\t"$0}' "$LOG")"

fail=0
checked=0
while IFS= read -r line; do
  case "$line" in ''|\#*) continue ;; esac
  model=$(printf '%s' "$line" | awk '{print $1}')
  want=$(printf '%s' "$line"  | awk '{print $2}')
  # The query text is everything after the first two fields; it may contain
  # spaces, parens and "==>" so it is matched as a fixed substring, never a regex.
  query=$(printf '%s' "$line" | sed -E 's/^[^ ]+ +[^ ]+ +//')

  got=$(printf '%s\n' "$ACTUAL" \
        | grep -F "$model	" \
        | grep -F "$query" \
        | sed -E 's/.* is (true|false)\.?$/\1/' \
        | head -1)

  checked=$((checked + 1))
  if [ -z "$got" ]; then
    echo "MISSING  $model :: $query"
    echo "         no RESULT line matched — the query was renamed, removed, or the model failed to run"
    fail=1
  elif [ "$got" != "$want" ]; then
    echo "MISMATCH $model :: $query"
    echo "         expected $want, got $got"
    [ "$want" = "false" ] && echo "         NOTE: this is a non-vacuity control. Turning true means the model no longer reaches the state it reasons about — its other proofs may now be vacuous."
    fail=1
  fi
done < "$EXPECTED"

echo "----------------------------------------------------------------------"
if [ "$fail" -eq 0 ]; then
  echo "formal: all $checked expected verdicts hold"
else
  echo "formal: DEVIATION — see above ($checked verdicts checked)"
fi
exit "$fail"
