# shellcheck shell=bash
# Shared step runner + assertion helpers for the proof / reliability harnesses
# (scripts/final_serverless_proof.sh, scripts/reliability_matrix_20.sh).
#
# Why this file exists — two bash rules that made earlier harness runs false-green:
#
#   1. `( set -e; a; b; c ) && step_ok || step_fail` does NOT run a/b under
#      errexit. Bash ignores `set -e` for every command inside the left operand
#      of an &&/|| list, an if/while condition, or a `!` pipeline — even when
#      `set -e` is re-issued inside the subshell or function. Only the status of
#      the LAST command counted, so every earlier grep assertion was a no-op.
#   2. errexit never fires on a `!`-negated command, so a mid-body
#      `! grep -q secret log` asserted nothing.
#
# Rules for callers:
#   * run each step body (a shell function) with run_isolated, called as a plain
#     statement — never from if / while / && / || / ! (that re-creates rule 1);
#   * write assertions with must_grep / must_not_grep / fail_assert. They `exit 1`
#     explicitly, so they hold even if errexit is lost again later.
#   * call proof_harness_selftest once at start-up: it proves both rules are
#     handled on this bash before any result is recorded.
#
# Exit-status contract of run_isolated: ISOLATED_RC is 0 (pass), PROOF_RC_SKIP
# (77: the body deliberately skipped), PROOF_RC_SUBSTITUTE (78: the body passed
# on a software substitute) or 1. EVERY other status is folded into 1. Status
# numbers like 2 are not reserved: a clap usage error, a grep I/O error or a
# nested script's `exit 2` used to read as SKIP and hid real failures.
#
# Bash 3.2 compatible (macOS /bin/bash).

PROOF_RC_SKIP=77
PROOF_RC_SUBSTITUTE=78

fail_assert() {
  echo "ASSERTION FAILED: $*" >&2
  exit 1
}

# must_grep [grep options...] PATTERN FILE...
must_grep() {
  local rc=0
  grep -q "$@" || rc=$?
  if [[ $rc -ne 0 ]]; then
    fail_assert "expected a match (grep rc=$rc): grep $*"
  fi
}

# must_not_grep [grep options...] PATTERN FILE...
# A missing/unreadable file is a failure, not a vacuous pass.
must_not_grep() {
  local rc=0
  grep -q "$@" || rc=$?
  case "$rc" in
    1) ;;
    0) fail_assert "unexpected match: grep $*" ;;
    *) fail_assert "grep error rc=$rc (missing file?): grep $*" ;;
  esac
}

# Kill background jobs a step body left behind (bridge / receiver daemons),
# whether it passed or failed half-way.
_isolated_reap() {
  local p
  for p in $(jobs -p); do
    kill "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}

# EXIT trap of the run_isolated subshell: reap daemons, then fold the status
# down to {0, PROOF_RC_SKIP, PROOF_RC_SUBSTITUTE, 1}. Kept in an EXIT trap (not
# an `||` after the call) so the body itself still runs under real errexit.
_isolated_exit() {
  local rc=$?
  _isolated_reap
  case "$rc" in
    0 | "$PROOF_RC_SKIP" | "$PROOF_RC_SUBSTITUTE") exit "$rc" ;;
    *) exit 1 ;;
  esac
}

# run_isolated FN LOGFILE [ARGS...]
# Runs shell function FN in a subshell with errexit, nounset and pipefail really
# in effect; stdout+stderr go to LOGFILE. Sets ISOLATED_RC to FN's exit status
# (normalised, see the contract at the top) and always returns 0. MUST be
# called as a plain statement (see rule 1 above).
run_isolated() {
  local fn="$1" out="$2" had_e=0
  shift 2
  case "$-" in *e*) had_e=1 ;; esac
  set +e
  (
    set -euo pipefail
    trap _isolated_exit EXIT
    "$fn" "$@"
  ) >"$out" 2>&1
  ISOLATED_RC=$?
  if [[ $had_e -eq 1 ]]; then set -e; fi
  return 0
}

# --- self-test ---------------------------------------------------------------
# Each body's LAST command succeeds; an earlier assertion fails. The historical
# `( ... ) && ok || fail` pattern reported all of these as PASS.
_selftest_early_false() { false; echo "unreachable"; true; }
_selftest_early_grep() { grep -q 'needle' "$PROOF_SELFTEST_DIR/hay"; true; }
_selftest_negated_grep() { must_not_grep 'needle' "$PROOF_SELFTEST_DIR/needle"; true; }
_selftest_missing_file() { must_not_grep 'x' "$PROOF_SELFTEST_DIR/does-not-exist"; true; }
_selftest_pipefail() { false | cat; true; }
# A tool's own exit 2 / 10 (clap usage error, grep I/O error, nested `exit 2`)
# must read as FAIL, not as SKIP / SUBSTITUTE.
_selftest_exit2() { bash -c 'exit 2'; true; }
_selftest_return2() { return 2; }
_selftest_return10() { return 10; }
_selftest_skip() { return "$PROOF_RC_SKIP"; }
_selftest_subst() { return "$PROOF_RC_SUBSTITUTE"; }
_selftest_pass() {
  must_grep 'needle' "$PROOF_SELFTEST_DIR/needle"
  must_not_grep 'needle' "$PROOF_SELFTEST_DIR/hay"
}

# proof_harness_selftest — exits 97 unless every broken body above is RED (status
# exactly 1), the SKIP/SUBSTITUTE sentinels survive, and the good body is GREEN.
proof_harness_selftest() {
  local fn
  PROOF_SELFTEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/proof-selftest.XXXXXX")"
  echo "hay only" >"$PROOF_SELFTEST_DIR/hay"
  echo "needle" >"$PROOF_SELFTEST_DIR/needle"
  for fn in _selftest_early_false _selftest_early_grep _selftest_negated_grep \
    _selftest_missing_file _selftest_pipefail _selftest_exit2 _selftest_return2 \
    _selftest_return10; do
    run_isolated "$fn" "$PROOF_SELFTEST_DIR/$fn.log"
    if [[ $ISOLATED_RC -ne 1 ]]; then
      echo "HARNESS SELF-TEST FAILED: $fn gave status $ISOLATED_RC, expected 1 (FAIL)" >&2
      rm -rf "$PROOF_SELFTEST_DIR"
      exit 97
    fi
  done
  run_isolated _selftest_skip "$PROOF_SELFTEST_DIR/skip.log"
  if [[ $ISOLATED_RC -ne $PROOF_RC_SKIP ]]; then
    echo "HARNESS SELF-TEST FAILED: skip sentinel came back as $ISOLATED_RC" >&2
    rm -rf "$PROOF_SELFTEST_DIR"
    exit 97
  fi
  run_isolated _selftest_subst "$PROOF_SELFTEST_DIR/subst.log"
  if [[ $ISOLATED_RC -ne $PROOF_RC_SUBSTITUTE ]]; then
    echo "HARNESS SELF-TEST FAILED: substitute sentinel came back as $ISOLATED_RC" >&2
    rm -rf "$PROOF_SELFTEST_DIR"
    exit 97
  fi
  run_isolated _selftest_pass "$PROOF_SELFTEST_DIR/pass.log"
  if [[ $ISOLATED_RC -ne 0 ]]; then
    echo "HARNESS SELF-TEST FAILED: passing body reported red" >&2
    cat "$PROOF_SELFTEST_DIR/pass.log" >&2 || true
    rm -rf "$PROOF_SELFTEST_DIR"
    exit 97
  fi
  rm -rf "$PROOF_SELFTEST_DIR"
  echo "harness self-test OK (errexit + negative assertions enforced)"
}
