#!/usr/bin/env bash
# Raven Bridge V1 — A–B–C local demo (mock BLE over TCP).
# Topology: A (LAN only) → B (bridge LAN+mock_ble) → C (BLE only).
# Opaque RavenEnvelopeV1 preserved; B never decrypts; ACK only from C.
# Safe: ephemeral dirs only. No secrets. No GitHub.
# Lab body path uses unsafe-demo-crypto (debug only). Always rebuild so a prior
# default-feature `cargo build -p raven-node` cannot leave a binary that refuses
# --body-mode unsafe-interim.
# Software mock_ble / store-carry only — not Byzantine, not flood-proof.
set -euo pipefail

# Headless CI / Linux agents: Secret Service is absent. Debug locked-file is
# refused in Release and does not change production fail-closed identity.
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR="${RAVEN_ALLOW_EPHEMERAL_DATA_DIR:-1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug"
NODE="$BIN/raven-node"
ASH="$BIN/ash"
WORKDIR="${TMPDIR:-/tmp}/raven-bridge-abc-$$"
mkdir -p "$WORKDIR/a" "$WORKDIR/b" "$WORKDIR/c"
cleanup() {
  [[ -n "${BPID:-}" ]] && kill "$BPID" 2>/dev/null || true
  [[ -n "${CPID:-}" ]] && kill "$CPID" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

source "${HOME}/.cargo/env" 2>/dev/null || true
echo "=== building raven-node + ash with unsafe-demo-crypto (debug) ==="
(cd "$ROOT" && cargo build -p raven-node -p ash --features raven-node/unsafe-demo-crypto -q)
[[ -x "$NODE" || -x "${NODE}.exe" ]]
[[ -x "$ASH" || -x "${ASH}.exe" ]]
if [[ ! -x "$NODE" && -x "${NODE}.exe" ]]; then NODE="${NODE}.exe"; fi
if [[ ! -x "$ASH" && -x "${ASH}.exe" ]]; then ASH="${ASH}.exe"; fi

echo "=== Bridge A-B-C workdir=$WORKDIR ==="
"$NODE" init --data-dir "$WORKDIR/a" | tee "$WORKDIR/a.out"
"$NODE" init --data-dir "$WORKDIR/b" | tee "$WORKDIR/b.out"
"$NODE" init --data-dir "$WORKDIR/c" | tee "$WORKDIR/c.out"
A_PUB=$(grep '^pub_hex=' "$WORKDIR/a.out" | cut -d= -f2)
B_PUB=$(grep '^pub_hex=' "$WORKDIR/b.out" | cut -d= -f2)
C_PUB=$(grep '^pub_hex=' "$WORKDIR/c.out" | cut -d= -f2)
echo "A pub (public only) ok"
echo "B pub (public only) ok"
echo "C pub (public only) ok"
# Ensure bridge policy on for B
"$ASH" --data-dir "$WORKDIR/b" node bridge on
"$ASH" --data-dir "$WORKDIR/b" node store on
"$ASH" --data-dir "$WORKDIR/b" status | tee "$WORKDIR/ash_status.txt"
grep -q 'bridge' "$WORKDIR/ash_status.txt"

run_happy() {
  local round=$1
  rm -f "$WORKDIR/b.lan" "$WORKDIR/b.ble"
  "$NODE" bridge \
    --data-dir "$WORKDIR/b" \
    --lan-listen "127.0.0.1:0" \
    --ble-listen "127.0.0.1:0" \
    --write-lan-addr "$WORKDIR/b.lan" \
    --write-ble-addr "$WORKDIR/b.ble" \
    --write-status "$WORKDIR/b.status.json" \
    --timeout-secs 40 \
    >"$WORKDIR/b.log" 2>&1 &
  BPID=$!
  for _ in $(seq 1 80); do
    [[ -f "$WORKDIR/b.lan" && -f "$WORKDIR/b.ble" ]] && break
    sleep 0.05
  done
  local B_LAN B_BLE
  B_LAN=$(cat "$WORKDIR/b.lan")
  B_BLE=$(cat "$WORKDIR/b.ble")

  # C: BLE-only mock — dial B ble, wait for 1 message, ACK as recipient
  "$NODE" run \
    --data-dir "$WORKDIR/c" \
    --listen "127.0.0.1:0" \
    --peer "$B_BLE" \
    --peer-pub-hex "$A_PUB" \
    --origin-pub-hex "$A_PUB" \
    --exit-after-recv 1 \
    --timeout-secs 35 \
    >"$WORKDIR/c.log" 2>&1 &
  CPID=$!
  sleep 0.3

  # A: Internet/LAN only — seal to C, dial B lan, wait for C's ACK via B
  printf '%s\n' "bridge-abc-round-$round" | "$NODE" run \
    --data-dir "$WORKDIR/a" \
    --listen "127.0.0.1:0" \
    --peer "$B_LAN" \
    --peer-pub-hex "$B_PUB" \
    --seal-to-pub-hex "$C_PUB" \
    --ack-pub-hex "$C_PUB" \
    --send-stdin --body-mode unsafe-interim \
    --exit-after-ack \
    --timeout-secs 35 \
    >"$WORKDIR/a.log" 2>&1

  wait "$CPID" || true
  kill "$BPID" 2>/dev/null || true
  wait "$BPID" 2>/dev/null || true
  BPID=""
  CPID=""

  grep -q 'ACK delivered' "$WORKDIR/a.log"
  grep -q 'DELIVERED bytes=' "$WORKDIR/c.log"
  grep -q 'BRIDGE forward' "$WORKDIR/b.log"
  # Same message_id on A send and C deliver path
  local MID
  MID=$(grep 'ENVELOPE_FP mid=' "$WORKDIR/a.log" | head -1 | sed -n 's/.*mid=\([0-9a-f]*\).*/\1/p')
  [[ -n "$MID" ]]
  grep -q "$MID" "$WORKDIR/b.log"
  echo "round $round OK mid=${MID:0:8}…"
}

echo "=== 3 consecutive A→B→C happy-path rounds ==="
for r in 1 2 3; do
  run_happy "$r"
done

echo "=== store-carry: C joins after A sends ==="
rm -f "$WORKDIR/b.lan" "$WORKDIR/b.ble"
"$NODE" bridge \
  --data-dir "$WORKDIR/b" \
  --lan-listen "127.0.0.1:0" \
  --ble-listen "127.0.0.1:0" \
  --write-lan-addr "$WORKDIR/b.lan" \
  --write-ble-addr "$WORKDIR/b.ble" \
  --timeout-secs 45 \
  >"$WORKDIR/b_scf.log" 2>&1 &
BPID=$!
for _ in $(seq 1 80); do
  [[ -f "$WORKDIR/b.lan" && -f "$WORKDIR/b.ble" ]] && break
  sleep 0.05
done
B_LAN=$(cat "$WORKDIR/b.lan")
B_BLE=$(cat "$WORKDIR/b.ble")

# A sends while C offline — B should queue (no ble peer yet)
printf '%s\n' "store-carry-msg" | "$NODE" run \
  --data-dir "$WORKDIR/a" \
  --listen "127.0.0.1:0" \
  --peer "$B_LAN" \
  --peer-pub-hex "$B_PUB" \
  --seal-to-pub-hex "$C_PUB" \
  --ack-pub-hex "$C_PUB" \
  --send-stdin --body-mode unsafe-interim \
  --exit-after-ack \
  --timeout-secs 40 \
  >"$WORKDIR/a_scf.log" 2>&1 &
APID=$!
sleep 0.8
# Now C appears on mock BLE
"$NODE" run \
  --data-dir "$WORKDIR/c" \
  --listen "127.0.0.1:0" \
  --peer "$B_BLE" \
  --peer-pub-hex "$A_PUB" \
  --origin-pub-hex "$A_PUB" \
  --exit-after-recv 1 \
  --timeout-secs 35 \
  >"$WORKDIR/c_scf.log" 2>&1 &
CPID=$!
wait "$APID" || true
wait "$CPID" || true
kill "$BPID" 2>/dev/null || true
wait "$BPID" 2>/dev/null || true
BPID=""
CPID=""
grep -q 'ACK delivered' "$WORKDIR/a_scf.log"
grep -q 'DELIVERED bytes=' "$WORKDIR/c_scf.log"
echo "store-carry OK"

echo "=== reverse C→B→A (BLE→LAN message; A dials B first) ==="
rm -f "$WORKDIR/b.lan" "$WORKDIR/b.ble"
"$NODE" bridge \
  --data-dir "$WORKDIR/b" \
  --lan-listen "127.0.0.1:0" \
  --ble-listen "127.0.0.1:0" \
  --write-lan-addr "$WORKDIR/b.lan" \
  --write-ble-addr "$WORKDIR/b.ble" \
  --timeout-secs 40 \
  >"$WORKDIR/b_rev.log" 2>&1 &
BPID=$!
for _ in $(seq 1 80); do
  [[ -f "$WORKDIR/b.lan" && -f "$WORKDIR/b.ble" ]] && break
  sleep 0.05
done
B_LAN=$(cat "$WORKDIR/b.lan")
B_BLE=$(cat "$WORKDIR/b.ble")

# A holds LAN session on B (receives bridged body from C)
"$NODE" run \
  --data-dir "$WORKDIR/a" \
  --listen "127.0.0.1:0" \
  --peer "$B_LAN" \
  --peer-pub-hex "$C_PUB" \
  --origin-pub-hex "$C_PUB" \
  --exit-after-recv 1 \
  --timeout-secs 35 \
  >"$WORKDIR/a_rev.log" 2>&1 &
APID=$!
sleep 0.4
printf '%s\n' "reverse-c-to-a" | "$NODE" run \
  --data-dir "$WORKDIR/c" \
  --listen "127.0.0.1:0" \
  --peer "$B_BLE" \
  --peer-pub-hex "$B_PUB" \
  --seal-to-pub-hex "$A_PUB" \
  --ack-pub-hex "$A_PUB" \
  --send-stdin --body-mode unsafe-interim \
  --exit-after-ack \
  --timeout-secs 35 \
  >"$WORKDIR/c_rev.log" 2>&1
wait "$APID" || true
kill "$BPID" 2>/dev/null || true
wait "$BPID" 2>/dev/null || true
BPID=""
APID=""
grep -q 'DELIVERED' "$WORKDIR/a_rev.log"
grep -q 'BRIDGE forward' "$WORKDIR/b_rev.log"
grep -q 'ACK delivered' "$WORKDIR/c_rev.log"
echo "reverse path OK (software mock_ble)"

echo "=== ash status still safe ==="
"$ASH" --data-dir "$WORKDIR/b" status | tee "$WORKDIR/ash_status2.txt"
grep -q 'forward_q' "$WORKDIR/ash_status2.txt"
! grep -qiE 'seed|private.key|plaintext' "$WORKDIR/ash_status2.txt"

echo "=== ALL BRIDGE A-B-C CHECKS PASSED ==="
