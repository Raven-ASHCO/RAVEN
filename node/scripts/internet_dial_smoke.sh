#!/usr/bin/env bash
# Negative production gate for the legacy raw InternetTransport.
# The binary must refuse message origination until the authenticated indexed
# endpoint actor and sealed ACK lifecycle are wired to this carrier.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug"
NODE="$BIN/raven-node"
# Same debug/lab identity override as lan_direct / ash menu (refused in Release).
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
WORKDIR="${TMPDIR:-/tmp}/raven-inet-$$"
mkdir -p "$WORKDIR/a" "$WORKDIR/b"
cleanup() {
  if [[ -n "${BPID:-}" ]]; then
    kill "$BPID" 2>/dev/null || true
    wait "$BPID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT
source "${HOME}/.cargo/env" 2>/dev/null || true
[[ -x "$NODE" ]] || (cd "$ROOT" && cargo build -p raven-node -q)

"$NODE" init --data-dir "$WORKDIR/a" | tee "$WORKDIR/a.out"
"$NODE" init --data-dir "$WORKDIR/b" | tee "$WORKDIR/b.out"
A_PUB=$(grep '^pub_hex=' "$WORKDIR/a.out" | cut -d= -f2)
B_PUB=$(grep '^pub_hex=' "$WORKDIR/b.out" | cut -d= -f2)

"$NODE" run \
  --data-dir "$WORKDIR/b" \
  --listen "127.0.0.1:0" \
  --write-addr "$WORKDIR/b.addr" \
  --write-pub "$WORKDIR/b.pub" \
  --exit-after-recv 1 \
  --timeout-secs 25 \
  --peer-pub-hex "$A_PUB" \
  >"$WORKDIR/b.log" 2>&1 &
BPID=$!
for _ in $(seq 1 80); do
  [[ -f "$WORKDIR/b.addr" ]] && break
  sleep 0.05
done
B_ADDR=$(cat "$WORKDIR/b.addr")

set +e
printf '%s\n' "inet-transport-proof" | "$NODE" run \
  --data-dir "$WORKDIR/a" \
  --listen "127.0.0.1:0" \
  --peer "$B_ADDR" \
  --peer-pub-hex "$B_PUB" \
  --send-stdin \
  --exit-after-ack \
  --timeout-secs 25 \
  >"$WORKDIR/a.log" 2>&1
A_STATUS=$?
set -e

if [[ "$A_STATUS" -eq 0 ]]; then
  echo "INTERNET_TRANSPORT_FALSE_DELIVERY: raw path unexpectedly exited zero" >&2
  exit 1
fi
grep -q 'ATSAM_SESSION_REQUIRED: no authenticated persisted ATSAM session is available' "$WORKDIR/a.log"
! grep -q 'ACK delivered' "$WORKDIR/a.log"
! grep -q 'DELIVERED' "$WORKDIR/b.log"
echo "PASS: legacy InternetTransport remains fail-closed pending indexed endpoint wiring"
