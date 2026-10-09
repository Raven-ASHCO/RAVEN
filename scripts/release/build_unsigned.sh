#!/usr/bin/env bash
# Build unsigned release layout for ash + raven-node (+ optional raven-swarm).
# Does NOT sign or notarize — see docs/SIGNING_NOTARIZATION_CHECKLIST.md.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
NODE="$REPO/node"
source "${HOME}/.cargo/env" 2>/dev/null || true
VER="${RAVEN_RELEASE_VERSION:-0.1.0-serverless}"
HOST="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${RAVEN_RELEASE_OUT:-$REPO/dist/raven-serverless-${VER}-${HOST}-${ARCH}-${STAMP}}"
mkdir -p "$OUT/bin" "$OUT/scripts" "$OUT/docs"

echo "Building release binaries…"
# --locked: ship exactly the audited Cargo.lock.
(cd "$NODE" && cargo build --locked -p raven-node -p ash -p raven-swarm --release -q)

install -m 755 "$NODE/target/release/ash" "$OUT/bin/ash"
install -m 755 "$NODE/target/release/raven-node" "$OUT/bin/raven-node"
install -m 755 "$NODE/target/release/raven-swarm" "$OUT/bin/raven-swarm"
# Safe product alias (never /bin/ash)
ln -sfn ash "$OUT/bin/raven"

cp "$NODE/scripts/install/"*.sh "$OUT/scripts/" 2>/dev/null || true
cp "$NODE/scripts/install/"*.ps1 "$OUT/scripts/" 2>/dev/null || true
cp "$NODE/scripts/install/"*.md "$OUT/scripts/" 2>/dev/null || true
cp "$REPO/docs/INSTALL_macOS.md" "$OUT/docs/" 2>/dev/null || true
cp "$REPO/docs/INSTALL_Linux.md" "$OUT/docs/" 2>/dev/null || true
cp "$REPO/docs/INSTALL_Windows.md" "$OUT/docs/" 2>/dev/null || true
cp "$REPO/docs/SIGNING_NOTARIZATION_CHECKLIST.md" "$OUT/docs/" 2>/dev/null || true
cp "$REPO/docs/SERVERLESS_MODEL.md" "$OUT/docs/" 2>/dev/null || true

cat >"$OUT/README.txt" <<EOF
RAVEN Serverless Terminal Messaging — unsigned release layout
version=$VER
host=$HOST-$ARCH
built_utc=$STAMP
binaries=ash, raven (symlink), raven-node, raven-swarm

THIS ARCHIVE IS NOT NOTARIZED / NOT AUTHENTICODE-SIGNED.
See docs/SIGNING_NOTARIZATION_CHECKLIST.md for operator signing steps.

Quick start:
  ./bin/ash --data-dir ./raven-data init
  ./bin/ash --data-dir ./raven-data doctor
  ./bin/raven-node service --data-dir ./raven-data --lan-listen 127.0.0.1:7420

LAN exposure is opt-in: the bare service default is 0.0.0.0:7420 (every
interface), so always pass an explicit address; use
--lan-listen <this-host-LAN-IP>:7420 to accept LAN peers. See docs/INSTALL_*.md.
EOF

(
  cd "$OUT"
  find . -type f ! -name 'SHA256SUMS.txt' -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256
) >"$OUT/SHA256SUMS.txt"

# Tarball
PARENT="$(dirname "$OUT")"
BASE="$(basename "$OUT")"
TAR="$PARENT/${BASE}.tar.gz"
tar -C "$PARENT" -czf "$TAR" "$BASE"
shasum -a 256 "$TAR" | tee "$PARENT/${BASE}.tar.gz.sha256"

echo "OUT=$OUT"
echo "TAR=$TAR"
echo "UNSIGNED_RELEASE_OK"
