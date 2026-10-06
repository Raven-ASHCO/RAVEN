#!/usr/bin/env bash
# Two ash identities + contacts + LAN send (loopback) — proves contact→send→deliver
# through the SAME secure default-build path for the beginner menu and the CLI:
# LAN-direct (Noise XX) + PairInit + indexed session + sealed ACK.
# Never uses unsafe-demo-crypto / `raven-node run --body-mode unsafe-interim`.
# Safe: ephemeral /tmp only. No secrets.
#
# RAVEN_IDENTITY_BACKEND=locked-file — demo/CI file keystore so ash and
# raven-node share the same data_dir without macOS Keychain ACL prompts.
# RAVEN_CHAT_HISTORY_BACKEND=locked-file — same debug/lab SS connect-fail
# path for send (headless rust-linux has no org.freedesktop.secrets).
# RAVEN_BIN_DIR — optional prebuilt debug bin dir (default: node/target/debug).
set -euo pipefail
set +m

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${RAVEN_BIN_DIR:-$ROOT/target/debug}"
ASH="$BIN/ash"
NODE="$BIN/raven-node"
export PATH="${HOME}/.cargo/bin:${PATH}"
export NO_COLOR=1
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1
# Never let a failed preflight auto-start a service on 0.0.0.0:7420 here.
export RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0

# shellcheck source=../../scripts/lib/harness_util.sh
source "$ROOT/../scripts/lib/harness_util.sh"
source "${HOME}/.cargo/env" 2>/dev/null || true
if [[ ! -x "$ASH" || ! -x "$NODE" ]]; then
  echo "Building ash + raven-node…"
  (cd "$ROOT" && cargo build -p ash -p raven-node -q)
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/raven-ash-lan-XXXXXX")"
A="$WORKDIR/a"
B="$WORKDIR/b"
# Listeners bind port 0 and the harness reads the bound address back from the
# node log (no fixed-port collisions). A_PORT/B_PORT stay as optional overrides.
A_PORT="${A_PORT:-0}"
B_PORT="${B_PORT:-0}"
A_PID=""
B_PID=""
cleanup() {
  for pid in "$A_PID" "$B_PID"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

mkdir -p "$A" "$B"
echo "=== ash contacts LAN demo workdir=$WORKDIR ==="

"$ASH" --data-dir "$A" init | tee "$WORKDIR/a.init"
"$ASH" --data-dir "$B" init | tee "$WORKDIR/b.init"
A_ADDR=$(grep '^address=' "$WORKDIR/a.init" | cut -d= -f2)
A_PUB=$(grep '^pub_hex=' "$WORKDIR/a.init" | cut -d= -f2)
A_FP=$(grep '^fingerprint=' "$WORKDIR/a.init" | cut -d= -f2)
B_ADDR=$(grep '^address=' "$WORKDIR/b.init" | cut -d= -f2)
B_PUB=$(grep '^pub_hex=' "$WORKDIR/b.init" | cut -d= -f2)
B_FP=$(grep '^fingerprint=' "$WORKDIR/b.init" | cut -d= -f2)
"$ASH" --data-dir "$A" prekey publish >/dev/null
"$ASH" --data-dir "$B" prekey publish >/dev/null

echo "A $A_ADDR fp=$A_FP"
echo "B $B_ADDR fp=$B_FP"

# Both sides run the LAN-direct receiver + IPC service (what `ash listen` runs).
"$NODE" service --data-dir "$A" --lan-listen "127.0.0.1:${A_PORT}" --ble-listen "127.0.0.1:0" \
  >"$WORKDIR/a.node.log" 2>&1 &
A_PID=$!
"$NODE" service --data-dir "$B" --lan-listen "127.0.0.1:${B_PORT}" --ble-listen "127.0.0.1:0" \
  >"$WORKDIR/b.node.log" 2>&1 &
B_PID=$!
for _ in $(seq 1 150); do
  if raven_ipc_up "$ASH" "$A" && raven_ipc_up "$ASH" "$B" \
    && grep -q "lan_direct: listen" "$WORKDIR/a.node.log" \
    && grep -q "lan_direct: listen" "$WORKDIR/b.node.log"; then
    break
  fi
  sleep 0.1
done
if ! raven_ipc_up "$ASH" "$A" || ! raven_ipc_up "$ASH" "$B" \
  || ! grep -q "lan_direct: listen" "$WORKDIR/b.node.log"; then
  echo "raven-node service did not bind (IPC endpoint / LAN listener)" >&2
  cat "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  exit 1
fi

A_DIAL="$(raven_listen_addr "$WORKDIR/a.node.log" lan_direct)"
B_DIAL="$(raven_listen_addr "$WORKDIR/b.node.log" lan_direct)"
if [[ -z "$A_DIAL" || -z "$B_DIAL" ]]; then
  echo "could not read the bound lan_direct address from the node logs" >&2
  cat "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  exit 1
fi

# A adds B as contact with lan_dial (what beginners save after first ask)
"$ASH" --data-dir "$A" contact add \
  --address "$B_ADDR" \
  --pub-hex "$B_PUB" \
  --petname "Bob" \
  --tag bob \
  --lan-dial "$B_DIAL" \
  --verify-fp "$B_FP" | tee "$WORKDIR/a.contact"
grep -q 'contact saved' "$WORKDIR/a.contact"

# B adds A (the receiver only trusts peers in its own book)
"$ASH" --data-dir "$B" contact add \
  --address "$A_ADDR" \
  --pub-hex "$A_PUB" \
  --petname "Alice" \
  --tag alice \
  --verify-fp "$A_FP" >/dev/null

# Beginner path: menu 1 Send → contact #1 → message → q.
printf '1\n1\nhello-from-ash-menu\nq\n' | raven_timeout 90 "$ASH" --data-dir "$A" >"$WORKDIR/a.menu" 2>&1 || true
if grep -q 'unsafe-interim\|ATSAM_SESSION_REQUIRED' "$WORKDIR/a.menu"; then
  echo "menu send took the unsafe-interim lane" >&2
  cat "$WORKDIR/a.menu" >&2
  exit 1
fi
if ! grep -qi 'status.*delivered' "$WORKDIR/a.menu"; then
  echo "menu send did not report delivered" >&2
  cat "$WORKDIR/a.menu" "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  exit 1
fi

# CLI path (same secure send): ash send --contact @bob, message on stdin.
printf 'hello-from-ash-contact\n' | raven_timeout 90 "$ASH" --data-dir "$A" send --contact @bob \
  >"$WORKDIR/a.send" 2>&1
grep -qi 'status.*delivered' "$WORKDIR/a.send"

# Receiver inbox: both bodies, attributed to the pinned contact "Alice".
"$ASH" --data-dir "$B" inbox | tee "$WORKDIR/b.inbox"
grep -q 'hello-from-ash-menu' "$WORKDIR/b.inbox"
grep -q 'hello-from-ash-contact' "$WORKDIR/b.inbox"
grep -q 'Alice \[pinned' "$WORKDIR/b.inbox"

# Contact lan_dial persisted in contacts.json (no re-typing host:port)
SAVED_DIAL=$(python3 - <<PY
import json
rows=json.load(open("$A/contacts.json"))
print(next(c["lan_dial"] for c in rows if c.get("petname")=="Bob"))
PY
)
[[ "$SAVED_DIAL" == "$B_DIAL" ]]
echo "contact lan_dial persisted: $SAVED_DIAL"

echo "=== ASH CONTACTS LAN DEMO PASSED ==="
