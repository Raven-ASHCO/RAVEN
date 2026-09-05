#!/usr/bin/env bash
# Two ash identities + contacts + LAN send (loopback) — proves contact→send→deliver.
# Uses raven-node listener + ash contact add --lan-dial (beginner path).
# Safe: ephemeral /tmp only. No secrets.
#
# RAVEN_IDENTITY_BACKEND=locked-file — demo/CI file keystore so ash and
# raven-node share the same data_dir without macOS Keychain ACL prompts.
# RAVEN_CHAT_HISTORY_BACKEND=locked-file — same debug/lab SS connect-fail
# path for send (headless rust-linux has no org.freedesktop.secrets).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug"
ASH="$BIN/ash"
NODE="$BIN/raven-node"
export PATH="${HOME}/.cargo/bin:${PATH}"
export NO_COLOR=1
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file

source "${HOME}/.cargo/env" 2>/dev/null || true
if [[ ! -x "$ASH" || ! -x "$NODE" ]]; then
  echo "Building ash + raven-node…"
  (cd "$ROOT" && cargo build -p ash -p raven-node -q)
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/raven-ash-lan-XXXXXX")"
cleanup() {
  if [[ -n "${BPID:-}" ]] && kill -0 "$BPID" 2>/dev/null; then
    kill "$BPID" 2>/dev/null || true
    wait "$BPID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

mkdir -p "$WORKDIR/a" "$WORKDIR/b"
echo "=== ash contacts LAN demo workdir=$WORKDIR ==="

"$ASH" --data-dir "$WORKDIR/a" init | tee "$WORKDIR/a.init"
"$ASH" --data-dir "$WORKDIR/b" init | tee "$WORKDIR/b.init"
A_ADDR=$(grep '^address=' "$WORKDIR/a.init" | cut -d= -f2)
A_PUB=$(grep '^pub_hex=' "$WORKDIR/a.init" | cut -d= -f2)
A_FP=$(grep '^fingerprint=' "$WORKDIR/a.init" | cut -d= -f2)
B_ADDR=$(grep '^address=' "$WORKDIR/b.init" | cut -d= -f2)
B_PUB=$(grep '^pub_hex=' "$WORKDIR/b.init" | cut -d= -f2)
B_FP=$(grep '^fingerprint=' "$WORKDIR/b.init" | cut -d= -f2)

echo "A $A_ADDR fp=$A_FP"
echo "B $B_ADDR fp=$B_FP"

# B listens; write ephemeral port
rm -f "$WORKDIR/b.listen"
"$NODE" run \
  --data-dir "$WORKDIR/b" \
  --listen "127.0.0.1:0" \
  --peer-pub-hex "$A_PUB" \
  --write-addr "$WORKDIR/b.listen" \
  --exit-after-recv 1 \
  --timeout-secs 25 \
  >"$WORKDIR/b.log" 2>&1 &
BPID=$!

for _ in $(seq 1 100); do
  [[ -f "$WORKDIR/b.listen" ]] && break
  if ! kill -0 "$BPID" 2>/dev/null; then
    echo "raven-node exited early:" >&2
    cat "$WORKDIR/b.log" >&2 || true
    exit 1
  fi
  sleep 0.05
done
if [[ ! -f "$WORKDIR/b.listen" ]]; then
  echo "timeout waiting for listen addr" >&2
  cat "$WORKDIR/b.log" >&2 || true
  exit 1
fi
B_LISTEN=$(cat "$WORKDIR/b.listen")
echo "B listen $B_LISTEN"

# A adds B as contact with lan_dial (what beginners save after first ask)
"$ASH" --data-dir "$WORKDIR/a" contact add \
  --address "$B_ADDR" \
  --pub-hex "$B_PUB" \
  --petname "Bob" \
  --tag bob \
  --lan-dial "$B_LISTEN" \
  --verify-fp "$B_FP" | tee "$WORKDIR/a.contact"
grep -q 'contact saved' "$WORKDIR/a.contact"

# B adds A (optional reverse book — public only)
"$ASH" --data-dir "$WORKDIR/b" contact add \
  --address "$A_ADDR" \
  --pub-hex "$A_PUB" \
  --petname "Alice" \
  --tag alice \
  --verify-fp "$A_FP" >/dev/null

# Send via ash send using saved dial fields (simulates menu 2 after contact pick)
printf 'hello-from-ash-contact\n' | "$ASH" --data-dir "$WORKDIR/a" send \
  --peer "$B_LISTEN" \
  --peer-pub-hex "$B_PUB" \
  --stdin-text \
  >"$WORKDIR/a.send" 2>&1

wait "$BPID" || true
BPID=""

grep -qE 'ACK delivered|enqueued' "$WORKDIR/a.send"
grep -q 'DELIVERED' "$WORKDIR/b.log"

# Round 2: reuse contact lan_dial from contacts.json (prove dial persisted)
B_DIAL=$(python3 - <<PY
import json
rows=json.load(open("$WORKDIR/a/contacts.json"))
print(next(c["lan_dial"] for c in rows if c.get("petname")=="Bob"))
PY
)
[[ "$B_DIAL" == "$B_LISTEN" ]]
echo "contact lan_dial persisted: $B_DIAL"

echo "=== ASH CONTACTS LAN DEMO PASSED ==="
