#!/usr/bin/env bash
# Two-node LAN-direct slice: contact → send → inbox → sealed ACK.
# Does not use unsafe-demo-crypto or `ash lab import-*`.
# Does not replace lan_path_smoke.sh (that script stays the interim path).
set -euo pipefail
set +m

# Shared 0600 seed file so ash and raven-node read the same identity (no Keychain ACL).
# Chat-history uses the same debug/lab GNU/Linux SS connect-fail path as identity
# and prekey (derived per-data_dir key). Not a production 0600-key fallback;
# locked-file is refused in Release.
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug"
ASH="$BIN/ash"
NODE="$BIN/raven-node"
WORKDIR="/tmp/raven-lan-direct-$$"
A="$WORKDIR/a"
B="$WORKDIR/b"
A_PORT="${A_PORT:-$((18000 + $$ % 500))}"
B_PORT="${B_PORT:-$((18500 + $$ % 500))}"
A_PID=""
B_PID=""
C_PID=""

cleanup() {
  if [[ -n "${A_PID}" ]]; then kill "${A_PID}" 2>/dev/null || true; fi
  if [[ -n "${B_PID}" ]]; then kill "${B_PID}" 2>/dev/null || true; fi
  if [[ -n "${C_PID}" ]]; then kill "${C_PID}" 2>/dev/null || true; fi
  sleep 0.2
  if [[ -n "${A_PID}" ]]; then kill -9 "${A_PID}" 2>/dev/null || true; fi
  if [[ -n "${B_PID}" ]]; then kill -9 "${B_PID}" 2>/dev/null || true; fi
  if [[ -n "${C_PID}" ]]; then kill -9 "${C_PID}" 2>/dev/null || true; fi
  wait 2>/dev/null || true
  if [[ "${RAVEN_KEEP_LAN:-}" == "1" ]]; then
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
test -n "$A_ADDR" && test -n "$B_ADDR" && test -n "$A_PUB" && test -n "$B_PUB"

"$ASH" --data-dir "$A" prekey publish
"$ASH" --data-dir "$B" prekey publish

echo "=== start two raven-node service processes ==="
"$NODE" service --data-dir "$A" --lan-listen "127.0.0.1:${A_PORT}" --ble-listen "127.0.0.1:0" \
  >"$WORKDIR/a.node.log" 2>&1 &
A_PID=$!
"$NODE" service --data-dir "$B" --lan-listen "127.0.0.1:${B_PORT}" --ble-listen "127.0.0.1:0" \
  >"$WORKDIR/b.node.log" 2>&1 &
B_PID=$!

# IPC can come up before LAN preflight (session/prekey/history) finishes bind.
for _ in $(seq 1 150); do
  if [[ -S "$A/raven-node.sock" && -S "$B/raven-node.sock" ]] \
    && grep -q "lan_direct: listen" "$WORKDIR/a.node.log" \
    && grep -q "lan_direct: listen" "$WORKDIR/b.node.log"; then
    break
  fi
  if grep -Eqi 'lan_direct failed|service identity preflight failed' \
    "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" 2>/dev/null; then
    echo "lan_direct bind/preflight failed" >&2
    cat "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
    exit 1
  fi
  sleep 0.1
done
if [[ ! -S "$A/raven-node.sock" || ! -S "$B/raven-node.sock" ]]; then
  echo "daemons failed to create IPC sockets" >&2
  cat "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  exit 1
fi
"$ASH" --data-dir "$A" ipc-ping >/dev/null
"$ASH" --data-dir "$B" ipc-ping >/dev/null
if ! grep -q "lan_direct: listen" "$WORKDIR/a.node.log" || ! grep -q "lan_direct: listen" "$WORKDIR/b.node.log"; then
  echo "lan_direct did not bind" >&2
  cat "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  exit 1
fi
echo "A_PORT=$A_PORT B_PORT=$B_PORT"

echo "=== contact add (address + pub_hex + lan_dial) ==="
"$ASH" --data-dir "$A" contact add \
  --address "$B_ADDR" --pub-hex "$B_PUB" --petname "Bob" --tag bob \
  --lan-dial "127.0.0.1:${B_PORT}"
"$ASH" --data-dir "$B" contact add \
  --address "$A_ADDR" --pub-hex "$A_PUB" --petname "Alice" --tag alice \
  --lan-dial "127.0.0.1:${A_PORT}"

echo "=== ash send --contact @bob (no --peer / no lab import) ==="
set +e
printf '%s\n' "hello from a" | "$ASH" --data-dir "$A" send --contact @bob \
  >"$WORKDIR/a.send.out" 2>"$WORKDIR/a.send.err"
SEND_RC=$?
set -e
if [[ "$SEND_RC" -ne 0 ]]; then
  echo "send failed rc=$SEND_RC" >&2
  cat "$WORKDIR/a.send.out" "$WORKDIR/a.send.err" "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  exit 1
fi
if ! grep -qi 'status.*delivered' "$WORKDIR/a.send.out"; then
  echo "sender did not report delivered" >&2
  cat "$WORKDIR/a.send.out" "$WORKDIR/a.send.err" "$WORKDIR/b.node.log" >&2 || true
  exit 1
fi

echo "=== receiver inbox ==="
"$ASH" --data-dir "$B" inbox | tee "$WORKDIR/b.inbox.out"
if ! grep -q 'hello from a' "$WORKDIR/b.inbox.out"; then
  echo "inbox missing plaintext" >&2
  cat "$WORKDIR/b.inbox.out" "$WORKDIR/b.node.log" >&2 || true
  exit 1
fi

echo "=== ash chat EOF exits (no busy-loop) ==="
set +e
CHAT_OUT="$WORKDIR/a.chat.out"
CHAT_ERR="$WORKDIR/a.chat.err"
# Require exact 'left chat' and exit 0 only — timeout (124) is a failure.
if command -v timeout >/dev/null 2>&1; then
  timeout 8s bash -c "printf '' | \"$ASH\" --data-dir \"$A\" send --contact @bob --chat" \
    >"$CHAT_OUT" 2>"$CHAT_ERR"
else
  printf '' | "$ASH" --data-dir "$A" send --contact @bob --chat \
    >"$CHAT_OUT" 2>"$CHAT_ERR"
fi
CHAT_RC=$?
set -e
if ! grep -Fq 'left chat' "$CHAT_OUT"; then
  echo "chat EOF missing exact 'left chat' (rc=$CHAT_RC)" >&2
  cat "$CHAT_OUT" "$CHAT_ERR" >&2 || true
  exit 1
fi
if [[ "$CHAT_RC" -ne 0 ]]; then
  echo "chat exited unexpectedly rc=$CHAT_RC (timeout 124 is failure)" >&2
  cat "$CHAT_OUT" "$CHAT_ERR" >&2 || true
  exit 1
fi

echo "=== stranger PairInit refused (node C → B, no contact on B) ==="
C="$WORKDIR/c"
C_PORT="${C_PORT:-$((19000 + $$ % 500))}"
mkdir -p "$C"
"$ASH" --data-dir "$C" init | tee "$WORKDIR/c.init"
C_ADDR=$(grep '^address=' "$WORKDIR/c.init" | cut -d= -f2)
C_PUB=$(grep '^pub_hex=' "$WORKDIR/c.init" | cut -d= -f2)
test -n "$C_ADDR" && test -n "$C_PUB"
"$ASH" --data-dir "$C" prekey publish
"$NODE" service --data-dir "$C" --lan-listen "127.0.0.1:${C_PORT}" --ble-listen "127.0.0.1:0" \
  >"$WORKDIR/c.node.log" 2>&1 &
C_PID=$!
for _ in $(seq 1 80); do
  if [[ -S "$C/raven-node.sock" ]]; then
    break
  fi
  sleep 0.1
done
if [[ ! -S "$C/raven-node.sock" ]]; then
  echo "stranger daemon failed to create IPC socket" >&2
  cat "$WORKDIR/c.node.log" >&2 || true
  exit 1
fi
# C knows B; B does NOT know C — PairInit must be refused on B.
"$ASH" --data-dir "$C" contact add \
  --address "$B_ADDR" --pub-hex "$B_PUB" --petname "Bob" --tag bob \
  --lan-dial "127.0.0.1:${B_PORT}"
set +e
printf '%s\n' "stranger probe" | "$ASH" --data-dir "$C" send --contact @bob \
  >"$WORKDIR/c.send.out" 2>"$WORKDIR/c.send.err"
C_SEND_RC=$?
set -e
if [[ "$C_SEND_RC" -eq 0 ]]; then
  echo "stranger send unexpectedly succeeded" >&2
  cat "$WORKDIR/c.send.out" "$WORKDIR/c.send.err" "$WORKDIR/b.node.log" >&2 || true
  exit 1
fi
if grep -qi 'delivered' "$WORKDIR/c.send.out" 2>/dev/null; then
  echo "stranger send reported delivered" >&2
  exit 1
fi
if [[ -f "$B/peer_device_certs.json" ]]; then
  KEYS="$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))))" "$B/peer_device_certs.json")"
  if [[ "$KEYS" -gt 4 ]]; then
    echo "peer cert cache unexpectedly large after stranger probe: $KEYS" >&2
    exit 1
  fi
fi
if [[ -f "$B/peer_cache.stage.json" ]]; then
  echo "peer cache stage left behind" >&2
  exit 1
fi
if ! grep -Eqi 'not a local contact|pair init refused' "$WORKDIR/b.node.log" \
  && ! grep -Eqi 'not a local contact|pair init refused|failed|error|refused' \
    "$WORKDIR/c.send.err" "$WORKDIR/c.send.out"; then
  echo "expected stranger PairInit refusal in logs" >&2
  cat "$WORKDIR/c.send.out" "$WORKDIR/c.send.err" "$WORKDIR/b.node.log" >&2 || true
  exit 1
fi

echo "=== LAN DIRECT TWO-NODE PASSED ==="
