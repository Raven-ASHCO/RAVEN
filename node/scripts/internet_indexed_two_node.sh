#!/usr/bin/env bash
# Positive lab smoke: indexed PairInit + sealed ACK over InternetTransport (RIH1).
#
# Manager Decision A (binding): lab-only, localhost Internet carrier, labeled
# localhost-only. Production PairInit/ATSAM/prekey/indexed flags stay false.
#
# CLAIM (exact):
#   PASS = lab localhost InternetTransport indexed two-node delivery (RIH1 hello
#   + framed PairInit/message + sealed ACK) on 127.0.0.1 with debug
#   RAVEN_LAB_TEST_A=1. localhost-only. dial≠WAN. Not public-Internet,
#   not multi-NAT, not WAN Proven. multi-NAT stays BLOCKED_HARDWARE.
#   INTERNET_DIRECT_PRODUCTION_ENABLED=false. Global PRODUCTION_ENABLED
#   tripwires stay false. Legacy raven-node run remains fail-closed
#   (internet_dial_smoke.sh). Named-pipe ≠ WAN.
#
# Does not use unsafe-demo-crypto. Does not bind 0.0.0.0.
set -euo pipefail
set +m

export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
# Lab unlock only (debug). Production InternetTransport slice gate stays false.
export RAVEN_LAB_TEST_A=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../../scripts/lib/harness_util.sh
source "$ROOT/../scripts/lib/harness_util.sh"
BIN="$ROOT/target/debug"
ASH="$BIN/ash"
NODE="$BIN/raven-node"
# mktemp: 0700 and never pre-existing (a predictable name can be pre-created or
# symlinked by another user).
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/raven-inet-indexed-XXXXXX")"
A="$WORKDIR/a"
B="$WORKDIR/b"
# Listeners bind port 0 and the harness reads the bound address back from the
# node log, so a busy fixed port can never fail the run. A_PORT/B_PORT/C_PORT
# stay as optional overrides (default 0 = OS-assigned).
A_PORT="${A_PORT:-0}"
B_PORT="${B_PORT:-0}"
A_PID=""
B_PID=""
C_PID=""

fail() {
  echo "INTERNET_INDEXED_TWO_NODE_FAIL: $*" >&2
  echo "CLAIM: fail is lab localhost InternetTransport — still not WAN / multi-NAT Proven" >&2
  exit 1
}

cleanup() {
  if [[ -n "${A_PID}" ]]; then kill "${A_PID}" 2>/dev/null || true; fi
  if [[ -n "${B_PID}" ]]; then kill "${B_PID}" 2>/dev/null || true; fi
  if [[ -n "${C_PID}" ]]; then kill "${C_PID}" 2>/dev/null || true; fi
  sleep 0.2
  if [[ -n "${A_PID}" ]]; then kill -9 "${A_PID}" 2>/dev/null || true; fi
  if [[ -n "${B_PID}" ]]; then kill -9 "${B_PID}" 2>/dev/null || true; fi
  if [[ -n "${C_PID}" ]]; then kill -9 "${C_PID}" 2>/dev/null || true; fi
  wait 2>/dev/null || true
  if [[ "${RAVEN_KEEP_INET:-}" == "1" ]]; then
    echo "keeping $WORKDIR" >&2
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

source "${HOME}/.cargo/env" 2>/dev/null || true
echo "=== building ash + raven-node (no unsafe-demo-crypto) ==="
(cd "$ROOT" && cargo build -p raven-node -p ash -q --offline 2>/dev/null \
  || cargo build -p raven-node -p ash -q)

mkdir -p "$A" "$B"

echo "=== init + prekey publish ==="
"$ASH" --data-dir "$A" init | tee "$WORKDIR/a.init"
"$ASH" --data-dir "$B" init | tee "$WORKDIR/b.init"
A_ADDR=$(grep '^address=' "$WORKDIR/a.init" | cut -d= -f2)
B_ADDR=$(grep '^address=' "$WORKDIR/b.init" | cut -d= -f2)
A_PUB=$(grep '^pub_hex=' "$WORKDIR/a.init" | cut -d= -f2)
B_PUB=$(grep '^pub_hex=' "$WORKDIR/b.init" | cut -d= -f2)
A_FP=$(grep '^fingerprint=' "$WORKDIR/a.init" | cut -d= -f2)
B_FP=$(grep '^fingerprint=' "$WORKDIR/b.init" | cut -d= -f2)
test -n "$A_ADDR" && test -n "$B_ADDR" && test -n "$A_PUB" && test -n "$B_PUB"
test -n "$A_FP" && test -n "$B_FP"

"$ASH" --data-dir "$A" prekey publish
"$ASH" --data-dir "$B" prekey publish

echo "=== start two raven-node service processes (127.0.0.1 internet listen; localhost-only) ==="
"$NODE" service --data-dir "$A" \
  --lan-listen "127.0.0.1:0" --ble-listen "127.0.0.1:0" \
  --internet-listen "127.0.0.1:${A_PORT}" \
  >"$WORKDIR/a.node.log" 2>&1 &
A_PID=$!
"$NODE" service --data-dir "$B" \
  --lan-listen "127.0.0.1:0" --ble-listen "127.0.0.1:0" \
  --internet-listen "127.0.0.1:${B_PORT}" \
  >"$WORKDIR/b.node.log" 2>&1 &
B_PID=$!

for _ in $(seq 1 150); do
  if raven_ipc_up "$ASH" "$A" && raven_ipc_up "$ASH" "$B" \
    && grep -q "internet_direct: listen" "$WORKDIR/a.node.log" \
    && grep -q "internet_direct: listen" "$WORKDIR/b.node.log"; then
    break
  fi
  if grep -Eqi 'internet_direct failed|INTERNET_DIRECT_HOLD|service identity preflight failed' \
    "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" 2>/dev/null; then
    cat "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
    fail "internet_direct bind/preflight failed"
  fi
  sleep 0.1
done
if ! raven_ipc_up "$ASH" "$A" || ! raven_ipc_up "$ASH" "$B"; then
  cat "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  fail "daemons did not answer IPC (ash ipc-ping)"
fi
"$ASH" --data-dir "$A" ipc-ping >/dev/null
"$ASH" --data-dir "$B" ipc-ping >/dev/null
if ! grep -q "internet_direct: listen" "$WORKDIR/a.node.log" \
  || ! grep -q "internet_direct: listen" "$WORKDIR/b.node.log"; then
  cat "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  fail "internet_direct did not bind"
fi
if ! grep -q "dial≠WAN" "$WORKDIR/a.node.log" || ! grep -q "dial≠WAN" "$WORKDIR/b.node.log"; then
  fail "missing dial≠WAN listen claim marker"
fi
A_INET="$(raven_listen_addr "$WORKDIR/a.node.log" internet_direct)"
B_INET="$(raven_listen_addr "$WORKDIR/b.node.log" internet_direct)"
if [[ -z "$A_INET" || -z "$B_INET" ]]; then
  cat "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  fail "could not read the bound internet_direct address from the node logs"
fi
echo "A_INET=$A_INET B_INET=$B_INET"

echo "=== contact add (trust only; send uses --carrier internet --peer) ==="
# Internet delivery is for verified contacts only (fingerprint pinned with
# --verify-fp): the sender refuses to dial an unpinned one and the Internet
# listener treats an unpinned dialer like a stranger.
"$ASH" --data-dir "$A" contact add \
  --address "$B_ADDR" --pub-hex "$B_PUB" --petname "Bob" --tag bob --verify-fp "$B_FP"
"$ASH" --data-dir "$B" contact add \
  --address "$A_ADDR" --pub-hex "$A_PUB" --petname "Alice" --tag alice --verify-fp "$A_FP"

echo "=== ash send --carrier internet (localhost indexed; not WAN) ==="
set +e
printf '%s\n' "hello over internet transport" | raven_timeout 90 "$ASH" --data-dir "$A" send \
  --peer "$B_INET" --peer-pub-hex "$B_PUB" --carrier internet \
  >"$WORKDIR/a.send.out" 2>"$WORKDIR/a.send.err"
SEND_RC=$?
set -e
if [[ "$SEND_RC" -ne 0 ]]; then
  cat "$WORKDIR/a.send.out" "$WORKDIR/a.send.err" "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  fail "send failed rc=$SEND_RC"
fi
if ! grep -qi 'status.*delivered' "$WORKDIR/a.send.out"; then
  cat "$WORKDIR/a.send.out" "$WORKDIR/a.send.err" "$WORKDIR/b.node.log" >&2 || true
  fail "sender did not report delivered"
fi
if ! grep -q 'carrier=internet_dial' "$WORKDIR/a.send.out"; then
  cat "$WORKDIR/a.send.out" >&2 || true
  fail "sender did not log internet_dial carrier"
fi

echo "=== receiver inbox (localhost-only) ==="
"$ASH" --data-dir "$B" inbox | tee "$WORKDIR/b.inbox.out"
if ! grep -q 'hello over internet transport' "$WORKDIR/b.inbox.out"; then
  cat "$WORKDIR/b.inbox.out" "$WORKDIR/b.node.log" >&2 || true
  fail "inbox missing plaintext"
fi
echo "INTERNET_INDEXED_LOOPBACK_PASS: 127.0.0.1 indexed delivery (not WAN)"

echo "=== stranger PairInit refused (node C → B internet, no contact on B) ==="
C="$WORKDIR/c"
C_PORT="${C_PORT:-0}"
mkdir -p "$C"
"$ASH" --data-dir "$C" init | tee "$WORKDIR/c.init"
C_ADDR=$(grep '^address=' "$WORKDIR/c.init" | cut -d= -f2)
C_PUB=$(grep '^pub_hex=' "$WORKDIR/c.init" | cut -d= -f2)
test -n "$C_ADDR" && test -n "$C_PUB"
"$ASH" --data-dir "$C" prekey publish
"$NODE" service --data-dir "$C" \
  --lan-listen "127.0.0.1:0" --ble-listen "127.0.0.1:0" \
  --internet-listen "127.0.0.1:${C_PORT}" \
  >"$WORKDIR/c.node.log" 2>&1 &
C_PID=$!
for _ in $(seq 1 80); do
  if raven_ipc_up "$ASH" "$C" && grep -q "internet_direct: listen" "$WORKDIR/c.node.log"; then
    break
  fi
  sleep 0.1
done
if ! raven_ipc_up "$ASH" "$C"; then
  cat "$WORKDIR/c.node.log" >&2 || true
  fail "stranger daemon did not answer IPC (ash ipc-ping)"
fi
# C has verified B (so C's own send dials); B has never heard of C.
"$ASH" --data-dir "$C" contact add \
  --address "$B_ADDR" --pub-hex "$B_PUB" --petname "Bob" --tag bob --verify-fp "$B_FP"
# B must be up and listening when the probe arrives; otherwise a failed send
# could only mean "connection refused", not "B refused the stranger".
if ! kill -0 "$B_PID" 2>/dev/null; then
  cat "$WORKDIR/b.node.log" >&2 || true
  fail "B daemon exited before the stranger probe"
fi
set +e
printf '%s\n' "stranger probe" | raven_timeout 90 "$ASH" --data-dir "$C" send \
  --peer "$B_INET" --peer-pub-hex "$B_PUB" --carrier internet \
  >"$WORKDIR/c.send.out" 2>"$WORKDIR/c.send.err"
C_SEND_RC=$?
set -e
if [[ "$C_SEND_RC" -eq 0 ]]; then
  cat "$WORKDIR/c.send.out" "$WORKDIR/c.send.err" "$WORKDIR/b.node.log" >&2 || true
  fail "stranger send unexpectedly succeeded"
fi
if grep -qi 'delivered' "$WORKDIR/c.send.out" 2>/dev/null; then
  fail "stranger send reported delivered"
fi
# The refusal must be B's own diagnostic (internet_direct logs the dispatch
# error "pair init refused: peer is not a local contact" on stderr ->
# b.node.log). C's generic send error text is not evidence: it also matches
# connection refused / bind failures where B never evaluated the stranger.
REFUSED=0
for _ in $(seq 1 30); do
  if grep -Eqi 'pair init refused|not a local contact' "$WORKDIR/b.node.log"; then
    REFUSED=1
    break
  fi
  sleep 0.1
done
if [[ "$REFUSED" -ne 1 ]]; then
  cat "$WORKDIR/c.send.out" "$WORKDIR/c.send.err" "$WORKDIR/b.node.log" >&2 || true
  fail "expected B to log the stranger PairInit refusal (pair init refused / not a local contact)"
fi
if ! kill -0 "$B_PID" 2>/dev/null; then
  cat "$WORKDIR/b.node.log" >&2 || true
  fail "B daemon died while refusing the stranger probe"
fi

echo "INTERNET_INDEXED_TWO_NODE_PASS: localhost/lab indexed delivery over InternetTransport (RIH1)"
echo "CLAIM: dial≠WAN — 127.0.0.1 indexed two-node is NOT public-Internet / multi-NAT / WAN Proven"
echo "CLAIM: multi-NAT stays BLOCKED_HARDWARE — this smoke does not claim it"
echo "CLAIM: named-pipe ≠ WAN; INTERNET_DIRECT_PRODUCTION_ENABLED=false"
echo "CLAIM: internet_dial_smoke.sh remains the fail-closed gate for legacy raven-node run"
echo "=== INTERNET INDEXED TWO-NODE PASSED ==="
