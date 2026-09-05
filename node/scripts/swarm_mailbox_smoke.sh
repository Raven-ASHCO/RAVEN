#!/usr/bin/env bash
# Real localhost libp2p mailbox: PUT, sender exit, store restart, recipient GET.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# Same debug/lab identity override as lan_direct / ash menu (refused in Release).
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file

TMP="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

cargo build -q -p raven-swarm --features experimental-offline-mailbox \
  --bin raven-swarm-mailbox-experimental
BIN="$ROOT/target/debug/raven-swarm-mailbox-experimental"

STORE_TAG_HEX="$(python3 -c 'print("77" * 16)')"
OBJECT_HEX="$(python3 - <<'PY'
import struct
import time

created = int(time.time() * 1000)
expires = created + 60 * 60 * 1000
message_id = bytes.fromhex("42" * 16)
body = b"opaque-network-ciphertext"
envelope = b"".join([
    b"RVN1", bytes([1, 1]), struct.pack(">H", 0),
    message_id, bytes.fromhex("99" * 16), struct.pack(">Q", 7),
    struct.pack(">Q", created), struct.pack(">Q", expires),
    bytes([4, 2]), bytes.fromhex("18" * 12),
    struct.pack(">H", 0), struct.pack(">I", len(body)),
    struct.pack(">H", 64), body, bytes(64),
])
store_object = b"".join([
    b"RSO1", bytes([1]), bytes.fromhex("77" * 16), message_id,
    struct.pack(">Q", created), struct.pack(">Q", expires),
    struct.pack(">H", 0), struct.pack(">I", len(envelope)), envelope,
])
print(store_object.hex())
PY
)"

start_store() {
  local run="$1"
  local addr_file="$TMP/address-$run"
  local peer_file="$TMP/peer-$run"
  RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1 "$BIN" --allow-experimental-mailbox serve \
    --data-dir "$TMP/store" --listen /ip4/127.0.0.1/tcp/0 \
    --write-multiaddr "$addr_file" --write-peer-id "$peer_file" \
    >"$TMP/store-$run.log" 2>&1 &
  SERVER_PID=$!

  for _ in {1..200}; do
    if [[ -s "$addr_file" && -s "$peer_file" ]]; then
      STORE_ADDR="$(<"$addr_file")"
      STORE_PEER="$(<"$peer_file")"
      return 0
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      cat "$TMP/store-$run.log"
      return 1
    fi
    sleep 0.05
  done
  echo "FAIL: mailbox store did not publish a listen address"
  cat "$TMP/store-$run.log"
  return 1
}

stop_store() {
  kill "$SERVER_PID"
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
}

start_store first
RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1 "$BIN" --allow-experimental-mailbox put \
  --data-dir "$TMP/sender" --peer "$STORE_ADDR" --peer-id "$STORE_PEER" \
  --object-hex "$OBJECT_HEX" >"$TMP/put.log"
grep -q '^stored=1$' "$TMP/put.log"

# The PUT client has exited. Restart the store from its atomic on-disk snapshot.
stop_store
start_store restarted
RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1 "$BIN" --allow-experimental-mailbox get \
  --data-dir "$TMP/recipient" --peer "$STORE_ADDR" --peer-id "$STORE_PEER" \
  --store-tag-hex "$STORE_TAG_HEX" >"$TMP/get.log"

grep -q '^object_count=1$' "$TMP/get.log"
RETRIEVED_HEX="$(sed -n 's/^object_hex=//p' "$TMP/get.log")"
[[ "$RETRIEVED_HEX" == "$OBJECT_HEX" ]] || {
  echo "FAIL: retrieved opaque StoreObject bytes changed"
  exit 1
}
grep -q '^next_cursor=end$' "$TMP/get.log"

echo "OK libp2p mailbox opaque PUT + sender disconnect + store restart + byte-identical GET"
