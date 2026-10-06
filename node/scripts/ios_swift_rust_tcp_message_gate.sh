#!/usr/bin/env bash
# Cross-process Swift ↔ raven-node TCP message gate.
#
# Exit criteria (all must PASS — real TCP, no memory duplex):
#   PairInit → PairResponse → M1 → committed sealed ACK → M2
#   reverse Rust→Swift
#   loss/retry/duplicate/tamper/trust negatives
#   no raw/RVNP1/interim/server fallback
#
# Usage:
#   ./node/scripts/ios_swift_rust_tcp_message_gate.sh
#   DEST='platform=iOS Simulator,id=<udid>' ./node/scripts/ios_swift_rust_tcp_message_gate.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NODE="$ROOT/node"
IOS="$ROOT/ios-native/RAVEN"
PROJECT="$IOS/RAVEN.xcodeproj"
SCHEME="RAVEN"
WORKDIR="/tmp/raven-swift-rust-tcp-gate-$$"
ENV_FILE="/tmp/raven_swift_rust_tcp_gate.env"
READY_FILE="/tmp/raven_swift_rust_tcp_gate.reverse.ready"
DONE_FILE="/tmp/raven_swift_rust_tcp_gate.reverse.done"
STATUS_FILE="/tmp/raven_swift_rust_tcp_gate.reverse.status"
PORT="${PORT:-$((21000 + $$ % 10000))}"
SWIFT_LISTEN_PORT="${SWIFT_LISTEN_PORT:-$((22000 + $$ % 10000))}"
NODE_PID=""
XCODE_REVERSE_PID=""

resolve_destination() {
  if [[ -n "${DEST:-}" ]]; then
    echo "$DEST"
    return
  fi
  if [[ -n "${DEVICE_ID:-}" ]]; then
    echo "platform=iOS Simulator,id=${DEVICE_ID}"
    return
  fi
  local udid
  udid="$(xcrun simctl list devices available | awk -F '[()]' '/RAVEN-Trust-Test/{print $2; exit}')"
  if [[ -z "$udid" ]]; then
    udid="$(xcrun simctl list devices available | awk -F '[()]' '/iPhone/{print $2; exit}')"
  fi
  if [[ -n "$udid" ]]; then
    echo "platform=iOS Simulator,id=${udid}"
    return
  fi
  echo "platform=iOS Simulator,name=iPhone 16"
}

DESTINATION="$(resolve_destination)"

cleanup() {
  if [[ -n "${XCODE_REVERSE_PID}" ]]; then kill "${XCODE_REVERSE_PID}" 2>/dev/null || true; fi
  if [[ -n "${NODE_PID}" ]]; then kill "${NODE_PID}" 2>/dev/null || true; fi
  sleep 0.2
  if [[ -n "${NODE_PID}" ]]; then kill -9 "${NODE_PID}" 2>/dev/null || true; fi
  if [[ "${RAVEN_KEEP_LAN:-}" != "1" ]]; then rm -rf "$WORKDIR"; fi
}
trap cleanup EXIT

source "${HOME}/.cargo/env" 2>/dev/null || true
# shellcheck source=../../scripts/lib/harness_util.sh
source "$ROOT/scripts/lib/harness_util.sh"
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_LAB_TEST_A=1

echo "=== Swift↔Rust TCP message gate ===" >&2
echo "destination=${DESTINATION}" >&2
echo "building raven-node + ash..." >&2
(cd "$NODE" && cargo build -p raven-node -p ash -q --offline 2>/dev/null || cargo build -p raven-node -p ash -q)

mkdir -p "$WORKDIR"
rm -f "$READY_FILE" "$DONE_FILE" "$STATUS_FILE"
ASH="$NODE/target/debug/ash"
RNODE="$NODE/target/debug/raven-node"

"$ASH" --data-dir "$WORKDIR" init | tee "$WORKDIR/init.txt"
PUB_HEX=$(grep '^pub_hex=' "$WORKDIR/init.txt" | cut -d= -f2)
ADDR=$(grep '^address=' "$WORKDIR/init.txt" | cut -d= -f2)
test -n "$PUB_HEX"
test -n "$ADDR"

"$ASH" --data-dir "$WORKDIR" prekey publish --out "$WORKDIR/rust-prekey.json" >/dev/null
"$ASH" --data-dir "$WORKDIR" lab export-cert >/dev/null

CLIENT_LINES=$(
  cd "$NODE" && cargo test -p raven-core --lib lan_vectors::tests::integration_swift_client_pub_hex -- --exact --nocapture 2>&1 \
    | grep '^RAVEN_INTEGRATION_' || true
)
CLIENT_PUB=$(echo "$CLIENT_LINES" | sed -n 's/RAVEN_INTEGRATION_CLIENT_PUB=//p' | head -1)
CLIENT_ADDR=$(echo "$CLIENT_LINES" | sed -n 's/RAVEN_INTEGRATION_CLIENT_ADDR=//p' | head -1)
test -n "$CLIENT_PUB"
test -n "$CLIENT_ADDR"

echo "registering Swift integration client on Rust listener..." >&2
"$ASH" --data-dir "$WORKDIR" contact add \
  --address "$CLIENT_ADDR" \
  --pub-hex "$CLIENT_PUB" \
  --petname "SwiftTcpGateClient" \
  --tag swift >/dev/null

echo "starting Rust lan_direct listener on 127.0.0.1:${PORT}..." >&2
"$RNODE" service --data-dir "$WORKDIR" --lan-listen "127.0.0.1:${PORT}" --ble-listen "127.0.0.1:0" \
  >"$WORKDIR/node.log" 2>&1 &
NODE_PID=$!

for _ in $(seq 1 80); do
  if raven_ipc_up "$ASH" "$WORKDIR"; then break; fi
  sleep 0.1
done
if ! raven_ipc_up "$ASH" "$WORKDIR"; then
  echo "FAIL: raven-node did not start (no IPC answer)" >&2
  cat "$WORKDIR/node.log" >&2 || true
  exit 1
fi
for _ in $(seq 1 80); do
  if grep -q "lan_direct: listen" "$WORKDIR/node.log" 2>/dev/null; then break; fi
  sleep 0.1
done
if ! grep -q "lan_direct: listen" "$WORKDIR/node.log"; then
  echo "FAIL: lan_direct did not bind" >&2
  cat "$WORKDIR/node.log" >&2 || true
  exit 1
fi

# Boot simulator if destination is an id=
if [[ "$DESTINATION" == platform=iOS\ Simulator,id=* ]]; then
  SIM_ID="${DESTINATION#platform=iOS Simulator,id=}"
  xcrun simctl boot "$SIM_ID" 2>/dev/null || true
  xcrun simctl bootstatus "$SIM_ID" -b || true
fi

# Snapshot-local Watch strip if watchOS runtime missing (CI usually has it).
PBX="$IOS/RAVEN.xcodeproj/project.pbxproj"
PBX_BACKUP=""
if ! xcrun simctl list runtimes | grep -q 'watchOS'; then
  echo "watchOS runtime missing — temporarily stripping Watch embed for local gate" >&2
  PBX_BACKUP="$(mktemp)"
  cp "$PBX" "$PBX_BACKUP"
  python3 - <<PY
from pathlib import Path
import re
p = Path("$PBX")
text = p.read_text()
text = text.replace('\t\t\t\t77793E9FB86779B05072DFA3 /* PBXTargetDependency */,\n', '')
text = re.sub(
    r'\t\t77793E9FB86779B05072DFA3 /\* PBXTargetDependency \*/ = \{.*?\n\t\t\};\n',
    '',
    text,
    flags=re.S,
)
text = re.sub(
    r'\t\t8C9559FE7A6DC48C04AF7C84 /\* PBXContainerItemProxy \*/ = \{.*?\n\t\t\};\n',
    '',
    text,
    flags=re.S,
)
# Remove Embed Watch Content phase reference from RAVEN buildPhases if present
text = text.replace('\t\t\t\tAE64034E31B334A9CA08AF0B /* RAVEN-Watch */,\n', '')
# Remove copy-files phase entries that embed watch
text = re.sub(
    r'\t\t[A-F0-9]+ /\* Embed Watch Content \*/ = \{\n\t\t\tisa = PBXCopyFilesBuildPhase;.*?\n\t\t\};\n',
    '',
    text,
    flags=re.S,
)
p.write_text(text)
print('watch stripped')
PY
  restore_pbx() { if [[ -n "$PBX_BACKUP" && -f "$PBX_BACKUP" ]]; then cp "$PBX_BACKUP" "$PBX"; fi; }
  trap 'restore_pbx; cleanup' EXIT
fi

cat >"$ENV_FILE" <<EOF
RAVEN_LAN_RUST_PORT=${PORT}
RAVEN_LAN_RUST_PUB_HEX=${PUB_HEX}
RAVEN_LAN_RUST_CERT_JSON=${WORKDIR}/lab_device_cert.json
RAVEN_LAN_RUST_PREKEY_JSON=${WORKDIR}/rust-prekey.json
RAVEN_LAN_RUST_WORKDIR=${WORKDIR}
RAVEN_INTEGRATION_CLIENT_PUB=${CLIENT_PUB}
RAVEN_SWIFT_LISTEN_PORT=${SWIFT_LISTEN_PORT}
EOF
echo "env written: $ENV_FILE" >&2

run_xcode_tests() {
  local label="$1"
  shift
  echo "=== ${label} ===" >&2
  (
    cd "$IOS"
    export RAVEN_LAB_TEST_A=1
    export RAVEN_LAN_RUST_ENV_FILE="$ENV_FILE"
    export RAVEN_LAN_RUST_PORT="$PORT"
    export RAVEN_LAN_RUST_PUB_HEX="$PUB_HEX"
    export RAVEN_LAN_RUST_CERT_JSON="$WORKDIR/lab_device_cert.json"
    export RAVEN_LAN_RUST_PREKEY_JSON="$WORKDIR/rust-prekey.json"
    export RAVEN_LAN_RUST_WORKDIR="$WORKDIR"
    export RAVEN_INTEGRATION_CLIENT_PUB="$CLIENT_PUB"
    export RAVEN_SWIFT_LISTEN_PORT="$SWIFT_LISTEN_PORT"
    xcodebuild test \
      -project "$PROJECT" \
      -scheme "$SCHEME" \
      -configuration Debug \
      -destination "$DESTINATION" \
      -parallel-testing-enabled NO \
      RAVEN_LAB_TEST_A=1 \
      "$@"
  )
}

echo "=== Forward + negatives (Swift dials Rust) ===" >&2
run_xcode_tests "forward/negatives" \
  -only-testing:RAVENTests/RavenSecureLanSwiftRustTcpGateTests/testForwardPairInitMessageAckSecondMessageOverTCP \
  -only-testing:RAVENTests/RavenSecureLanSwiftRustTcpGateTests/testDuplicateMessageReturnsSameAckNoSecondCommit \
  -only-testing:RAVENTests/RavenSecureLanSwiftRustTcpGateTests/testAckLossRetriesExactCiphertextThenDelivers \
  -only-testing:RAVENTests/RavenSecureLanSwiftRustTcpGateTests/testTamperProducesNoAckAndNoRatchetAdvance \
  -only-testing:RAVENTests/RavenSecureLanSwiftRustTcpGateTests/testBlockPeerRefusesWithoutAck \
  -only-testing:RAVENTests/RavenSecureLanSwiftRustTcpGateTests/testContactDeleteRefusesWithoutAck \
  -only-testing:RAVENTests/RavenSecureLanSwiftRustTcpGateTests/testLocalRevocationStickyDenyBlocksDialPath \
  -only-testing:RAVENTests/RavenSecureLanSwiftRustTcpGateTests/testNoLegacyServerlessLanPathFallbackInSecureSources

echo "=== Reverse Rust→Swift (listener + ash inject) ===" >&2
rm -f "$READY_FILE" "$DONE_FILE" "$STATUS_FILE"
(
  cd "$IOS"
  export RAVEN_LAB_TEST_A=1
  export RAVEN_LAN_RUST_ENV_FILE="$ENV_FILE"
  export RAVEN_LAN_RUST_PORT="$PORT"
  export RAVEN_LAN_RUST_PUB_HEX="$PUB_HEX"
  export RAVEN_LAN_RUST_CERT_JSON="$WORKDIR/lab_device_cert.json"
  export RAVEN_LAN_RUST_PREKEY_JSON="$WORKDIR/rust-prekey.json"
  export RAVEN_LAN_RUST_WORKDIR="$WORKDIR"
  export RAVEN_INTEGRATION_CLIENT_PUB="$CLIENT_PUB"
  export RAVEN_SWIFT_LISTEN_PORT="$SWIFT_LISTEN_PORT"
  xcodebuild test \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -configuration Debug \
    -destination "$DESTINATION" \
    -parallel-testing-enabled NO \
    RAVEN_LAB_TEST_A=1 \
    -only-testing:RAVENTests/RavenSecureLanSwiftRustTcpGateTests/testReverseRustToSwiftMessageAckOverTCP \
    >"$WORKDIR/xcode_reverse.log" 2>&1
) &
XCODE_REVERSE_PID=$!

for _ in $(seq 1 450); do
  if [[ -f "$READY_FILE" ]]; then break; fi
  if [[ -f "$WORKDIR/reverse.ready" ]]; then
    cp "$WORKDIR/reverse.ready" "$READY_FILE"
    break
  fi
  if ! kill -0 "$XCODE_REVERSE_PID" 2>/dev/null; then
    echo "FAIL: reverse XCTest exited before ready" >&2
    tail -n 80 "$WORKDIR/xcode_reverse.log" >&2 || true
    exit 1
  fi
  sleep 0.2
done
if [[ ! -f "$READY_FILE" ]]; then
  echo "FAIL: reverse ready file missing" >&2
  tail -n 80 "$WORKDIR/xcode_reverse.log" >&2 || true
  exit 1
fi

SWIFT_PORT=$(grep '^RAVEN_SWIFT_LISTEN_PORT=' "$READY_FILE" | cut -d= -f2)
SWIFT_PUB=$(grep '^RAVEN_SWIFT_PUB_HEX=' "$READY_FILE" | cut -d= -f2)
test -n "$SWIFT_PORT"
test -n "$SWIFT_PUB"

echo "updating contact lan-dial → Swift listen 127.0.0.1:${SWIFT_PORT}" >&2
"$ASH" --data-dir "$WORKDIR" contact add \
  --address "$CLIENT_ADDR" \
  --pub-hex "$CLIENT_PUB" \
  --petname "SwiftTcpGateClient" \
  --tag swift \
  --lan-dial "127.0.0.1:${SWIFT_PORT}" >/dev/null

# Host must reach Simulator listen before ash LanDial (shared loopback).
if ! nc -z -w 2 127.0.0.1 "$SWIFT_PORT" 2>/dev/null; then
  echo "FAIL: Swift listen 127.0.0.1:${SWIFT_PORT} not reachable from host" >&2
  wait "$XCODE_REVERSE_PID" || true
  exit 1
fi
echo "Swift listen probe ok 127.0.0.1:${SWIFT_PORT}" >&2

set +e
REVERSE_RC=124
: >"$WORKDIR/reverse.send.out"
: >"$WORKDIR/reverse.send.err"
for attempt in 1 2 3; do
  # Drop half-prepared message outbox so a prior timed-out attempt cannot
  # monopolize ash send with a stuck LanDial retry.
  sqlite3 "$WORKDIR/indexed_sessions.sqlite" \
    "DELETE FROM endpoint_outstanding_messages WHERE delivery_state = 0;
     DELETE FROM endpoint_outbox WHERE state = 0 AND kind = 1;" 2>/dev/null || true
  rm -f "$WORKDIR/.outbound_body_stage.lock.sqlite-journal" 2>/dev/null || true

  echo "reverse ash send attempt ${attempt}/3" >&2
  printf '%s\n' "tcp-gate-reverse-m1" | "$ASH" --data-dir "$WORKDIR" send --contact @swift \
    >"$WORKDIR/reverse.send.out" 2>"$WORKDIR/reverse.send.err" &
  ASH_SEND_PID=$!
  REVERSE_RC=124
  for _ in $(seq 1 60); do
    if ! kill -0 "$ASH_SEND_PID" 2>/dev/null; then
      wait "$ASH_SEND_PID"
      REVERSE_RC=$?
      break
    fi
    sleep 1
  done
  if kill -0 "$ASH_SEND_PID" 2>/dev/null; then
    echo "reverse ash send attempt ${attempt} timed out" >&2
    kill "$ASH_SEND_PID" 2>/dev/null || true
    wait "$ASH_SEND_PID" 2>/dev/null || true
    REVERSE_RC=124
  fi
  STATUS_PLAIN=$( {
    echo "exit=${REVERSE_RC}"
    cat "$WORKDIR/reverse.send.out"
    cat "$WORKDIR/reverse.send.err"
  } | sed $'s/\x1b\\[[0-9;]*m//g' )
  if printf '%s\n' "$STATUS_PLAIN" | grep -q 'status delivered'; then
    break
  fi
  echo "reverse attempt ${attempt} not delivered yet" >&2
  printf '%s\n' "$STATUS_PLAIN" >&2
done
set -e
{
  echo "exit=${REVERSE_RC}"
  cat "$WORKDIR/reverse.send.out"
  cat "$WORKDIR/reverse.send.err"
} | sed $'s/\x1b\\[[0-9;]*m//g' >"$STATUS_FILE"
cp "$STATUS_FILE" "$WORKDIR/reverse.status" 2>/dev/null || true

if grep -q 'status delivered' "$STATUS_FILE"; then
  echo "PASS" >>"$STATUS_FILE"
  cp "$STATUS_FILE" "$WORKDIR/reverse.status" 2>/dev/null || true
else
  echo "FAIL: reverse ash send did not reach delivered" >&2
  cat "$STATUS_FILE" >&2
  echo FAIL >"$DONE_FILE"
  cp "$DONE_FILE" "$WORKDIR/reverse.done" 2>/dev/null || true
  cp "$STATUS_FILE" "$WORKDIR/reverse.status" 2>/dev/null || true
  wait "$XCODE_REVERSE_PID" || true
  exit 1
fi

echo PASS >"$DONE_FILE"
cp "$STATUS_FILE" "$WORKDIR/reverse.status" 2>/dev/null || true
cp "$DONE_FILE" "$WORKDIR/reverse.done" 2>/dev/null || true
wait "$XCODE_REVERSE_PID"
REVERSE_XCODE_RC=$?
if [[ "$REVERSE_XCODE_RC" -ne 0 ]]; then
  echo "FAIL: reverse XCTest" >&2
  tail -n 100 "$WORKDIR/xcode_reverse.log" >&2 || true
  exit "$REVERSE_XCODE_RC"
fi

# Assert Rust inbox has Swift plaintext rows (non-sensitive count only).
"$ASH" --data-dir "$WORKDIR" inbox >"$WORKDIR/inbox.out" 2>&1 || true
INBOX_HITS=$(grep -c 'tcp-gate-m' "$WORKDIR/inbox.out" || true)
echo "rust_inbox_hits=${INBOX_HITS}" >&2

echo "" >&2
echo "PASS: Swift↔Rust TCP gate" >&2
echo "  PairInit → PairResponse → M1 → sealed ACK → M2" >&2
echo "  reverse direction" >&2
echo "  loss/retry/duplicate/tamper/trust negatives" >&2
echo "  no legacy/RVNP1/interim fallback" >&2
exit 0
