#!/usr/bin/env bash
# Task 18 — Swift TCP dialer ↔ Rust raven-node lan_direct listener (127.0.0.1).
#
# Proves real TCP Noise+RLB1 interop without a physical iPhone.
# Phase 2: PairInit → PairResponse on the same TCP session.
#
# Usage:
#   ./node/scripts/ios_swift_rust_lan_integration.sh
#   DEST='platform=iOS Simulator,name=RAVEN-iPhone-15' ./node/scripts/ios_swift_rust_lan_integration.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NODE="$ROOT/node"
IOS="$ROOT/ios-native/RAVEN"
PROJECT="$IOS/RAVEN.xcodeproj"
SCHEME="RAVEN"
DEST="${DEST:-platform=iOS Simulator,name=RAVEN-iPhone-15}"
WORKDIR="/tmp/raven-swift-rust-lan-$$"
ENV_FILE="/tmp/raven_swift_rust_lan.env"
PORT="${PORT:-$((20000 + $$ % 10000))}"
NODE_PID=""

cleanup() {
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

echo "=== Task 18 Swift↔Rust LAN integration ===" >&2
echo "building raven-node + ash..." >&2
(cd "$NODE" && cargo build -p raven-node -p ash -q --offline 2>/dev/null || cargo build -p raven-node -p ash -q)

mkdir -p "$WORKDIR"
ASH="$NODE/target/debug/ash"
RNODE="$NODE/target/debug/raven-node"

"$ASH" --data-dir "$WORKDIR" init | tee "$WORKDIR/init.txt"
PUB_HEX=$(grep '^pub_hex=' "$WORKDIR/init.txt" | cut -d= -f2)
test -n "$PUB_HEX"

"$ASH" --data-dir "$WORKDIR" prekey publish --out "$WORKDIR/rust-prekey.json" >/dev/null
"$ASH" --data-dir "$WORKDIR" lab export-cert >/dev/null

CLIENT_LINES=$(
  cd "$NODE" && cargo test -p raven-core --lib lan_vectors::tests::integration_swift_client_pub_hex -- --exact --nocapture 2>&1 \
    | grep '^RAVEN_INTEGRATION_' || true
)
CLIENT_PUB=$(echo "$CLIENT_LINES" | sed -n 's/RAVEN_INTEGRATION_CLIENT_PUB=//p')
CLIENT_ADDR=$(echo "$CLIENT_LINES" | sed -n 's/RAVEN_INTEGRATION_CLIENT_ADDR=//p')
test -n "$CLIENT_PUB"
test -n "$CLIENT_ADDR"

echo "registering Swift integration client contact on Rust listener..." >&2
"$ASH" --data-dir "$WORKDIR" contact add \
  --address "$CLIENT_ADDR" \
  --pub-hex "$CLIENT_PUB" \
  --petname "SwiftIntegrationClient" >/dev/null

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
if ! grep -q "lan_direct: listen" "$WORKDIR/node.log"; then
  echo "FAIL: lan_direct did not bind" >&2
  cat "$WORKDIR/node.log" >&2 || true
  exit 1
fi

cat >"$ENV_FILE" <<EOF
RAVEN_LAN_RUST_PORT=${PORT}
RAVEN_LAN_RUST_PUB_HEX=${PUB_HEX}
RAVEN_LAN_RUST_CERT_JSON=${WORKDIR}/lab_device_cert.json
RAVEN_LAN_RUST_PREKEY_JSON=${WORKDIR}/rust-prekey.json
RAVEN_INTEGRATION_CLIENT_PUB=${CLIENT_PUB}
EOF
echo "env written: $ENV_FILE" >&2

echo "running Swift TCP integration tests..." >&2
(
  cd "$IOS"
  set -o pipefail
  export RAVEN_LAN_RUST_PORT="$PORT"
  export RAVEN_LAN_RUST_PUB_HEX="$PUB_HEX"
  export RAVEN_LAN_RUST_ENV_FILE="$ENV_FILE"
  export RAVEN_LAN_RUST_CERT_JSON="$WORKDIR/lab_device_cert.json"
  export RAVEN_LAN_RUST_PREKEY_JSON="$WORKDIR/rust-prekey.json"
  xcodebuild test \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -destination "$DEST" \
    -parallel-testing-enabled NO \
    -only-testing:RAVENTests/RavenSecureLanRustIntegrationTests \
    -only-testing:RAVENTests/ATSAMLabTask18Tests/testHostEndToEndMessageAckSecondMessage
)

echo "PASS: Swift↔Rust TCP integration (handshake + PairInit/PairResponse + host E2E msg→ACK→msg2)" >&2
echo "NOTE: Rust listener does not yet accept indexed RVNA1 messages; host E2E runs in-process XCTest." >&2
