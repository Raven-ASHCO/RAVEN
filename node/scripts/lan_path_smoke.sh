#!/usr/bin/env bash
# Simulates the flagged iOS→raven-node LAN path using raven-node itself:
#  1) unsafe-interim seal (lab demo cipher, debug only) — full DELIVERED + ACK
#  2) fail-closed: `--body-mode atsam` must be REFUSED with ATSAM_SESSION_REQUIRED
#     (no persisted authenticated session) and nothing may be delivered.
# Safe: ephemeral /tmp identities only. No secrets.
#
# Every check below fails the script: negative checks use explicit
# `if grep ...; then exit 1; fi` (errexit never fires on `! cmd`), and no
# assertion runs inside a function called from `if` (errexit is off there).
set -euo pipefail
# Debug/lab file keystore (refused in Release): ephemeral identities must not
# land in the OS keystore, and a headless Linux host has none.
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR="${RAVEN_ALLOW_EPHEMERAL_DATA_DIR:-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../../scripts/lib/harness_util.sh
source "$ROOT/../scripts/lib/harness_util.sh"
BIN="$ROOT/target/debug"
NODE="$BIN/raven-node"
# mktemp: 0700 and never pre-existing (a predictable name can be pre-created or
# symlinked by another user).
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/raven-lan-smoke-XXXXXX")"
mkdir -p "$WORKDIR/a" "$WORKDIR/b"
cleanup() {
  local p
  for p in $(jobs -p); do kill "$p" 2>/dev/null || true; done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

source "${HOME}/.cargo/env" 2>/dev/null || true
# Always (re)build with the lab feature: a prior default-feature build (e.g.
# internet_indexed_two_node.sh) leaves a binary that refuses unsafe-interim.
echo "Building raven-node (unsafe-demo-crypto, debug)..."
(cd "$ROOT" && cargo build -p raven-node --features raven-node/unsafe-demo-crypto -q)

echo "=== LAN path smoke (interim + fail-closed atsam) workdir=$WORKDIR ==="
"$NODE" init --data-dir "$WORKDIR/a" | tee "$WORKDIR/a.out"
"$NODE" init --data-dir "$WORKDIR/b" | tee "$WORKDIR/b.out"
A_PUB=$(grep '^pub_hex=' "$WORKDIR/a.out" | cut -d= -f2)
B_PUB=$(grep '^pub_hex=' "$WORKDIR/b.out" | cut -d= -f2)

run_mode() {
  local mode=$1
  local expect=$2
  rm -f "$WORKDIR/b.listen"
  "$NODE" run \
    --data-dir "$WORKDIR/b" \
    --listen "127.0.0.1:0" \
    --peer-pub-hex "$A_PUB" \
    --write-addr "$WORKDIR/b.listen" \
    --exit-after-recv 1 \
    --timeout-secs 15 \
    >"$WORKDIR/b.log" 2>&1 &
  local BPID=$!
  # Non-empty file (written create+truncate then write), daemon alive, 15 s
  # budget for a cold debug build; fails explicitly and dumps b.log.
  raven_wait_file "$WORKDIR/b.listen" "$BPID" 15 "$WORKDIR/b.log"
  local B_LISTEN
  B_LISTEN=$(cat "$WORKDIR/b.listen")
  printf '%s\n' "lan-smoke-$mode" | "$NODE" run \
    --data-dir "$WORKDIR/a" \
    --listen "127.0.0.1:0" \
    --peer "$B_LISTEN" \
    --peer-pub-hex "$B_PUB" \
    --send-stdin \
    --body-mode "$mode" \
    --exit-after-ack \
    --timeout-secs 15 \
    >"$WORKDIR/a.log" 2>&1
  wait "$BPID" || true
  grep -q 'ACK delivered' "$WORKDIR/a.log"
  grep -q "$expect" "$WORKDIR/b.log"
  echo "mode=$mode OK"
}

run_mode_failclosed() {
  rm -f "$WORKDIR/b.listen"
  "$NODE" run \
    --data-dir "$WORKDIR/b" \
    --listen "127.0.0.1:0" \
    --peer-pub-hex "$A_PUB" \
    --write-addr "$WORKDIR/b.listen" \
    --exit-after-recv 1 \
    --timeout-secs 8 \
    >"$WORKDIR/bf.log" 2>&1 &
  local BPID=$!
  raven_wait_file "$WORKDIR/b.listen" "$BPID" 8 "$WORKDIR/bf.log"
  local B_LISTEN
  B_LISTEN=$(cat "$WORKDIR/b.listen")
  local RC=0
  "$NODE" run \
    --data-dir "$WORKDIR/a" \
    --listen "127.0.0.1:0" \
    --peer "$B_LISTEN" \
    --peer-pub-hex "$B_PUB" \
    --send-stdin \
    --body-mode atsam \
    --exit-after-ack \
    --timeout-secs 8 \
    >"$WORKDIR/af.log" 2>&1 <<<"must-not-send" || RC=$?
  wait "$BPID" || true
  if [[ "$RC" -eq 0 ]]; then
    echo "FAIL: production body-mode unexpectedly originated (rc=0)" >&2
    cat "$WORKDIR/af.log" >&2 || true
    exit 1
  fi
  # The refusal must be the ATSAM gate, not an unrelated crash/timeout.
  if ! grep -q 'ATSAM_SESSION_REQUIRED' "$WORKDIR/af.log"; then
    echo "FAIL: sender failed (rc=$RC) without ATSAM_SESSION_REQUIRED" >&2
    cat "$WORKDIR/af.log" >&2 || true
    exit 1
  fi
  if grep -q 'ACK delivered' "$WORKDIR/af.log" || grep -q 'DELIVERED' "$WORKDIR/bf.log"; then
    echo "FAIL: refused send still produced a delivery/ACK" >&2
    exit 1
  fi
  echo "mode=failclosed OK (ATSAM_SESSION_REQUIRED enforced, rc=$RC)"
}

run_mode unsafe-interim 'DELIVERED bytes='

# Fail-closed proof: production body-mode must REFUSE origination without a
# persisted authenticated ATSAM session. Called as a plain statement so errexit
# stays in force inside the function.
run_mode_failclosed

echo "=== LAN PATH SMOKE PASSED ==="
