#!/usr/bin/env bash
# Fast shipping-terminal binary smoke for B1 always-on / bot re-triggers.
# Default features only (no unsafe-demo-crypto). Proves ash + raven-node run.
set -euo pipefail
# Ephemeral CI profile — Secret Service / Keychain ACL is not available to bots.
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR="${RAVEN_ALLOW_EPHEMERAL_DATA_DIR:-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="${TMPDIR:-/tmp}/raven-term-$$"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT
mkdir -p "$WORKDIR"
source "${HOME}/.cargo/env" 2>/dev/null || true

echo "=== building ash + raven-node (default features) ==="
(cd "$ROOT" && cargo build -p ash -p raven-node -q)

ASH="$ROOT/target/debug/ash"
NODE="$ROOT/target/debug/raven-node"
if [[ ! -x "$ASH" && -x "${ASH}.exe" ]]; then ASH="${ASH}.exe"; fi
if [[ ! -x "$NODE" && -x "${NODE}.exe" ]]; then NODE="${NODE}.exe"; fi
[[ -x "$ASH" && -x "$NODE" ]]

"$ASH" --help | grep -qi raven
"$NODE" --help | grep -qi raven

# Headless Linux cannot prove Secret Service absence during first-install
# unless the session bus is missing (`secret-service connect:`). Plant a
# 32-byte locked-file seed so we take the load path. macOS still requires
# proven-absent Keychain (Ok(None)); locked/denied is Continuity.
plant_ci_seed() {
  local dir="$1"
  mkdir -p "$dir"
  if [[ ! -s "$dir/identity.seed" ]]; then
    dd if=/dev/urandom of="$dir/identity.seed" bs=32 count=1 status=none
    chmod 600 "$dir/identity.seed"
  fi
}

echo "=== ash whoami (planted CI seed) ==="
plant_ci_seed "$WORKDIR/ash"
"$ASH" --data-dir "$WORKDIR/ash" whoami | tee "$WORKDIR/ash.whoami"
grep -qi address "$WORKDIR/ash.whoami"

echo "=== raven-node address + timed listen ==="
plant_ci_seed "$WORKDIR/node"
"$NODE" address --data-dir "$WORKDIR/node" | tee "$WORKDIR/node.addr.out"
grep -q '^address=' "$WORKDIR/node.addr.out"
"$NODE" run \
  --data-dir "$WORKDIR/node" \
  --listen "127.0.0.1:0" \
  --write-addr "$WORKDIR/node.addr" \
  --timeout-secs 2
[[ -s "$WORKDIR/node.addr" ]]

echo "=== TERMINAL HELP/INIT SMOKE OK ==="
