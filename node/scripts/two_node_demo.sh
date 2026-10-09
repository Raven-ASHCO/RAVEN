#!/usr/bin/env bash
# Safe local two-node DM reliability loop for RAVEN.
# Uses ONLY local temp dirs and ephemeral keys — no secrets committed.
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
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/raven-demo-XXXXXX")"
mkdir -p "$WORKDIR/a" "$WORKDIR/b"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

# Always (re)build with the lab feature: a prior default-feature build (e.g.
# internet_indexed_two_node.sh) leaves a binary that refuses unsafe-interim.
echo "Building raven-node (unsafe-demo-crypto, debug)..."
(cd "$ROOT" && cargo build -p raven-node --features raven-node/unsafe-demo-crypto -q)

echo "=== RAVEN two-node demo workdir=$WORKDIR ==="

"$NODE" init --data-dir "$WORKDIR/a" | tee "$WORKDIR/a.out"
"$NODE" init --data-dir "$WORKDIR/b" | tee "$WORKDIR/b.out"
A_PUB=$(grep '^pub_hex=' "$WORKDIR/a.out" | cut -d= -f2)
B_PUB=$(grep '^pub_hex=' "$WORKDIR/b.out" | cut -d= -f2)
echo "A $(grep '^address=' "$WORKDIR/a.out")"
echo "B $(grep '^address=' "$WORKDIR/b.out")"

run_once() {
  local round=$1
  local msg="hello-round-$round"
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
  # budget for a cold debug build; dumps b.log instead of a bare `cat` error.
  raven_wait_file "$WORKDIR/b.listen" "$BPID" 15 "$WORKDIR/b.log"
  local B_LISTEN
  B_LISTEN=$(cat "$WORKDIR/b.listen")
  printf '%s\n' "$msg" | "$NODE" run \
    --data-dir "$WORKDIR/a" \
    --listen "127.0.0.1:0" \
    --peer "$B_LISTEN" \
    --peer-pub-hex "$B_PUB" \
    --send-stdin --body-mode unsafe-interim \
    --exit-after-ack \
    --timeout-secs 15 \
    >"$WORKDIR/a.log" 2>&1
  wait "$BPID" || true
  grep -q 'ACK delivered' "$WORKDIR/a.log"
  grep -q 'DELIVERED bytes=' "$WORKDIR/b.log"
  echo "round $round OK"
}

echo "=== 3 consecutive happy-path rounds ==="
for r in 1 2 3; do
  run_once "$r"
done

echo "=== restart persistence (re-init dirs keep identity; new send) ==="
run_once 4

echo "=== ALL DEMO CHECKS PASSED (4/4 rounds) ==="
