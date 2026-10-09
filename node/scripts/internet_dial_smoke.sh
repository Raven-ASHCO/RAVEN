#!/usr/bin/env bash
# Negative production gate for the legacy raw InternetTransport.
# The binary must refuse message origination until the authenticated indexed
# endpoint actor and sealed ACK lifecycle are wired to this carrier.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../../scripts/lib/harness_util.sh
source "$ROOT/../scripts/lib/harness_util.sh"
BIN="${RAVEN_BIN_DIR:-$ROOT/target/debug}"   # optional prebuilt debug bin dir (skips the build)
NODE="$BIN/raven-node"
# Same debug/lab identity override as lan_direct / ash menu (refused in Release).
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
# mktemp: 0700 and never pre-existing (a predictable name can be pre-created or
# symlinked by another user).
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/raven-inet-XXXXXX")"
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
# Always builds (a no-op when fresh) unless RAVEN_BIN_DIR is given: an existing
# binary used to be reused however stale, so this gate could pass against old code.
raven_build_bins "$ROOT" raven-node
if [[ ! -x "$NODE" ]]; then
  echo "FAIL: $NODE is missing" >&2
  exit 1
fi

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
# Non-empty file (written create+truncate then write), daemon alive, 15 s budget.
raven_wait_file "$WORKDIR/b.addr" "$BPID" 15 "$WORKDIR/b.log"
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
if ! grep -q 'ATSAM_SESSION_REQUIRED: no authenticated persisted ATSAM session is available' "$WORKDIR/a.log"; then
  echo "INTERNET_TRANSPORT_WRONG_REFUSAL: rc=$A_STATUS without ATSAM_SESSION_REQUIRED" >&2
  cat "$WORKDIR/a.log" >&2 || true
  exit 1
fi
# Explicit if/exit: errexit never fires on a `!`-negated command.
if grep -q 'ACK delivered' "$WORKDIR/a.log"; then
  echo "INTERNET_TRANSPORT_FALSE_DELIVERY: sender logged an ACK" >&2
  exit 1
fi
if grep -q 'DELIVERED' "$WORKDIR/b.log"; then
  echo "INTERNET_TRANSPORT_FALSE_DELIVERY: receiver logged a delivery" >&2
  exit 1
fi
echo "PASS: legacy InternetTransport remains fail-closed pending indexed endpoint wiring"
