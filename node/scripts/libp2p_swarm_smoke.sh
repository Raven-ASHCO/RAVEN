#!/usr/bin/env bash
# Live rust-libp2p TCP (+QUIC listen) swarm: two-node dial + Kad put/get of signed PeerRecord.
# No FastAPI. Separates libp2p PeerId from Raven identity.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug"
SWARM="$BIN/raven-swarm"
WORKDIR="${TMPDIR:-/tmp}/raven-libp2p-$$"
mkdir -p "$WORKDIR/a" "$WORKDIR/b"
# Headless rust-linux has no org.freedesktop.secrets. serve/dial create an
# ephemeral identity; locked-file is debug/lab only (refused in Release).
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
cleanup() {
  [[ -n "${SPID:-}" ]] && kill "$SPID" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT
source "${HOME}/.cargo/env" 2>/dev/null || true
[[ -x "$SWARM" ]] || (cd "$ROOT" && cargo build -p raven-swarm -q)

# §30 manual-peer-only bootstrap config on dialer (no Raven-owned required)
"$SWARM" bootstrap-init \
  --data-dir "$WORKDIR/b" \
  --manual-peer "/ip4/127.0.0.1/tcp/9" \
  --no-raven-defaults
"$SWARM" bootstrap-show --data-dir "$WORKDIR/b" | tee "$WORKDIR/boot.out"
grep -q 'manual_peer_only=true' "$WORKDIR/boot.out"

"$SWARM" serve \
  --data-dir "$WORKDIR/a" \
  --listen "/ip4/127.0.0.1/tcp/0" \
  --quic \
  --write-multiaddr "$WORKDIR/a.addr" \
  --write-peer-id "$WORKDIR/a.peer" \
  --timeout-secs 40 \
  >"$WORKDIR/a.log" 2>&1 &
SPID=$!

for _ in $(seq 1 120); do
  [[ -f "$WORKDIR/a.addr" && -f "$WORKDIR/a.peer" ]] && grep -q 'kad_put_ok' "$WORKDIR/a.log" 2>/dev/null && break
  sleep 0.1
done
if [[ ! -f "$WORKDIR/a.addr" ]]; then
  echo "serve failed to publish listen addr" >&2
  cat "$WORKDIR/a.log" >&2 || true
  exit 1
fi
A_ADDR=$(cat "$WORKDIR/a.addr")
A_PEER=$(cat "$WORKDIR/a.peer")
A_PUB=$(grep '^raven_pub_hex=' "$WORKDIR/a.log" | head -1 | cut -d= -f2)

# Update dialer bootstrap to the live listen multiaddr (still manual-only)
"$SWARM" bootstrap-init \
  --data-dir "$WORKDIR/b" \
  --manual-peer "$A_ADDR" \
  --no-raven-defaults

"$SWARM" dial \
  --data-dir "$WORKDIR/b" \
  --peer "$A_ADDR" \
  --peer-id "$A_PEER" \
  --raven-pub-hex "$A_PUB" \
  --timeout-secs 35 \
  | tee "$WORKDIR/b.log"

grep -q 'peer_record_verified=1' "$WORKDIR/b.log"
grep -q 'LIBP2P SWARM DIAL+KAD OK' "$WORKDIR/b.log"
! grep -qiE 'fastapi|localhost:8000|/api/' "$WORKDIR/a.log" "$WORKDIR/b.log"
grep -q 'libp2p PeerId is domain-separated' "$WORKDIR/a.log"
echo "=== LIBP2P SWARM SMOKE OK (TCP/Kad, no FastAPI) ==="
