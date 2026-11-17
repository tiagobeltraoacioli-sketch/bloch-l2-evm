#!/bin/bash
# Step runner for the dry-run scripts (agent 385). Sourced inside a dry-run container.
# step ID EXPECT COMMAND...  runs COMMAND with bash -c, logs it and its output, and compares the exit code with
# EXPECT: "0" (must succeed), "nz" (must fail: a refusal the procedure relies on) or "any" (recorded only).
# Every step appends one JSON line to $DRYRUN_OUT/steps.jsonl; the full output goes to $DRYRUN_OUT/log.txt.
DRYRUN_OUT=${DRYRUN_OUT:-/dryrun/out}
mkdir -p "$DRYRUN_OUT"
PASS=0 FAIL=0
step() {
  local id=$1 expect=$2; shift 2
  local cmd="$*" out rc verdict
  {
    echo
    echo "=== [$id] expect=$expect $(date -u +%FT%TZ)"
    echo "\$ $cmd"
  } >> "$DRYRUN_OUT/log.txt"
  out=$(bash -c "$cmd" 2>&1); rc=$?
  printf '%s\n' "$out" >> "$DRYRUN_OUT/log.txt"
  echo "--- rc=$rc" >> "$DRYRUN_OUT/log.txt"
  case $expect in
    0) [ $rc = 0 ] && verdict=PASS || verdict=FAIL;;
    nz) [ $rc != 0 ] && verdict=PASS || verdict=FAIL;;
    *) verdict=INFO;;
  esac
  [ $verdict = PASS ] && PASS=$((PASS+1))
  [ $verdict = FAIL ] && FAIL=$((FAIL+1))
  python3 -c 'import json,sys; print(json.dumps({"id":sys.argv[1],"expect":sys.argv[2],"rc":int(sys.argv[3]),"verdict":sys.argv[4],"cmd":sys.argv[5],"tail":sys.argv[6][-600:]}))' \
    "$id" "$expect" "$rc" "$verdict" "$cmd" "$out" >> "$DRYRUN_OUT/steps.jsonl"
  echo "[$verdict] $id (rc=$rc)"
}
# expect_out ID PATTERN COMMAND...: the command must exit 0 AND its output must match the extended regex PATTERN.
expect_out() {
  local id=$1 pat=$2; shift 2
  step "$id" 0 "set -o pipefail; ( $* ) 2>&1 | tee /dev/stderr | grep -qE -- '$pat'"
}
summary() {
  echo "dry-run summary: PASS=$PASS FAIL=$FAIL" | tee -a "$DRYRUN_OUT/log.txt"
  echo "{\"summary\":{\"pass\":$PASS,\"fail\":$FAIL}}" >> "$DRYRUN_OUT/steps.jsonl"
}
