#!/usr/bin/env bash
# §30: prove network startup with only a manually supplied peer — no Raven-owned bootstrap.
# Lab body path uses unsafe-demo-crypto (debug only). Always rebuild so a prior
# default-feature `cargo build -p raven-node` cannot leave a binary that refuses
# --body-mode unsafe-interim (that was the macOS CI SIGTERM race).
set -euo pipefail
set +m
# Ephemeral CI profile — Secret Service / Keychain ACL is not available to bots.
export RAVEN_IDENTITY_BACKEND=locked-file
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug"
NODE="$BIN/raven-node"
SWARM="$BIN/raven-swarm"
# Same debug/lab identity override as lan_direct / ash menu (refused in Release).
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
WORKDIR="${TMPDIR:-/tmp}/raven-boot-$$"
mkdir -p "$WORKDIR/a" "$WORKDIR/b"
BPID=""

dump_logs() {
  echo "=== bootstrap smoke logs ===" >&2
  for f in a.out b.out a.log b.log; do
    if [[ -f "$WORKDIR/$f" ]]; then
      echo "----- $f -----" >&2
      tail -n 80 "$WORKDIR/$f" >&2 || true
    fi
  done
}

cleanup() {
  if [[ -n "${BPID}" ]]; then
    kill -TERM "$BPID" 2>/dev/null || true
    sleep 0.2
    kill -KILL "$BPID" 2>/dev/null || true
    wait "$BPID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

source "${HOME}/.cargo/env" 2>/dev/null || true
echo "=== building raven-node + raven-swarm with unsafe-demo-crypto (debug) ==="
(cd "$ROOT" && cargo build -p raven-node -p raven-swarm --features raven-node/unsafe-demo-crypto -q)
[[ -x "$NODE" || -x "${NODE}.exe" ]]
[[ -x "$SWARM" || -x "${SWARM}.exe" ]]
if [[ ! -x "$NODE" && -x "${NODE}.exe" ]]; then NODE="${NODE}.exe"; fi
if [[ ! -x "$SWARM" && -x "${SWARM}.exe" ]]; then SWARM="${SWARM}.exe"; fi

# bootstrap.json: raven defaults disabled/empty; only manual peer
"$SWARM" bootstrap-init \
  --data-dir "$WORKDIR/b" \
  --manual-peer "127.0.0.1:0" \
  --no-raven-defaults
SHOW=$("$SWARM" bootstrap-show --data-dir "$WORKDIR/b")
echo "$SHOW" | grep -q 'manual_peer_only=true'
echo "$SHOW" | grep -q 'raven_defaults_count=0'
echo "$SHOW" | grep -q 'use_raven_defaults=false'

plant_ci_seed() {
  local dir="$1"
  mkdir -p "$dir"
  if [[ ! -s "$dir/identity.seed" ]]; then
    dd if=/dev/urandom of="$dir/identity.seed" bs=32 count=1 status=none
    chmod 600 "$dir/identity.seed"
  fi
}
# Headless Linux cannot prove Secret Service absence during first-install.
plant_ci_seed "$WORKDIR/a"
plant_ci_seed "$WORKDIR/b"
"$NODE" address --data-dir "$WORKDIR/a" | tee "$WORKDIR/a.out"
"$NODE" address --data-dir "$WORKDIR/b" | tee "$WORKDIR/b.out"
A_PUB=$(grep '^pub_hex=' "$WORKDIR/a.out" | cut -d= -f2)
B_PUB=$(grep '^pub_hex=' "$WORKDIR/b.out" | cut -d= -f2)
if [[ -z "$A_PUB" || -z "$B_PUB" ]]; then
  echo "init did not print pub_hex" >&2
  dump_logs
  exit 1
fi

"$NODE" run \
  --data-dir "$WORKDIR/b" \
  --listen "127.0.0.1:0" \
  --write-addr "$WORKDIR/b.addr" \
  --write-pub "$WORKDIR/b.pub" \
  --exit-after-recv 1 \
  --timeout-secs 40 \
  --peer-pub-hex "$A_PUB" \
  >"$WORKDIR/b.log" 2>&1 &
BPID=$!

for _ in $(seq 1 100); do
  if [[ -s "$WORKDIR/b.addr" ]]; then
    break
  fi
  if ! kill -0 "$BPID" 2>/dev/null; then
    echo "listener exited before writing b.addr" >&2
    dump_logs
    exit 1
  fi
  sleep 0.1
done
if [[ ! -s "$WORKDIR/b.addr" ]]; then
  echo "timed out waiting for b.addr" >&2
  dump_logs
  exit 1
fi
B_ADDR=$(tr -d '[:space:]' <"$WORKDIR/b.addr")
if [[ -z "$B_ADDR" ]]; then
  echo "b.addr empty" >&2
  dump_logs
  exit 1
fi

# Rewrite bootstrap to the live manual peer only
"$SWARM" bootstrap-init \
  --data-dir "$WORKDIR/a" \
  --manual-peer "$B_ADDR" \
  --no-raven-defaults
"$SWARM" bootstrap-show --data-dir "$WORKDIR/a" | grep -q "peer=$B_ADDR"

set +e
printf '%s\n' "manual-bootstrap-only" | "$NODE" run \
  --data-dir "$WORKDIR/a" \
  --listen "127.0.0.1:0" \
  --peer "$B_ADDR" \
  --peer-pub-hex "$B_PUB" \
  --send-stdin --body-mode unsafe-interim \
  --exit-after-ack \
  --timeout-secs 40 \
  >"$WORKDIR/a.log" 2>&1
SEND_RC=$?
set -e
if [[ "$SEND_RC" -ne 0 ]]; then
  echo "sender raven-node exited $SEND_RC" >&2
  dump_logs
  exit 1
fi

set +e
wait "$BPID"
RECV_RC=$?
set -e
BPID=""
if [[ "$RECV_RC" -ne 0 ]]; then
  echo "listener raven-node exited $RECV_RC" >&2
  dump_logs
  exit 1
fi

if ! grep -q 'ACK delivered' "$WORKDIR/a.log"; then
  echo "sender log missing ACK delivered" >&2
  dump_logs
  exit 1
fi
if ! grep -q 'DELIVERED' "$WORKDIR/b.log"; then
  echo "listener log missing DELIVERED" >&2
  dump_logs
  exit 1
fi
if grep -qiE 'fastapi|bootstrap\.raven|raven-owned' "$WORKDIR/a.log" "$WORKDIR/b.log"; then
  echo "forbidden central/bootstrap tokens in logs" >&2
  dump_logs
  exit 1
fi
echo "=== MANUAL-PEER-ONLY BOOTSTRAP SMOKE OK ==="
