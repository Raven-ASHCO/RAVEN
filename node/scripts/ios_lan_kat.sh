#!/usr/bin/env bash
# LAN handshake KAT (Noise XX + RLB1) and Release lab-gate verification.
#
# Cross-language vectors: shared-vectors/rvn1/lan/*.json
# Rust counterpart:  cd node && cargo test -p raven-core --lib lan_
# Manual Terminal↔iPhone lab: node/scripts/ios_lan_lab_checklist.md (design §11)
#
# Usage:
#   ./node/scripts/ios_lan_kat.sh
#   DEST='platform=iOS Simulator,name=RAVEN-iPhone-15' ./node/scripts/ios_lan_kat.sh
#   DEVICE_ID=<sim-udid> ./node/scripts/ios_lan_kat.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IOS="$ROOT/ios-native/RAVEN"
PROJECT="$IOS/RAVEN.xcodeproj"
SCHEME="RAVEN"

resolve_destination() {
  if [[ -n "${DEST:-}" ]]; then
    echo "$DEST"
    return
  fi
  if [[ -n "${DEVICE_ID:-}" ]]; then
    echo "platform=iOS Simulator,id=${DEVICE_ID}"
    return
  fi
  # Capture in a variable, not a fixed /tmp file: another user (or a concurrent
  # run) could otherwise pre-create/symlink the path or swap the simulator id.
  local sim_udid
  if sim_udid="$(xcrun simctl list devices available -j | python3 -c '
import json, sys
data = json.load(sys.stdin)["devices"]
candidates = [
    (runtime, d)
    for runtime, devices in data.items()
    for d in devices
    if d.get("isAvailable") and "iPhone" in d.get("name", "")
]
if not candidates:
    raise SystemExit("no available iPhone simulator")
def version(item):
    raw = item[0].rsplit("iOS-", 1)[-1]
    return tuple(int(part) for part in raw.split("-") if part.isdigit())
print(max(candidates, key=version)[1]["udid"])
' 2>/dev/null)" && [[ -n "$sim_udid" ]]; then
    echo "platform=iOS Simulator,id=${sim_udid}"
    return
  fi
  echo "platform=iOS Simulator,name=RAVEN-iPhone-15"
}

DESTINATION="$(resolve_destination)"
echo "ios_lan_kat: destination=${DESTINATION}" >&2

if [[ -n "${DEVICE_ID:-}" ]] || [[ "${DESTINATION}" == platform=iOS\ Simulator,id=* ]]; then
  SIM_ID="${DEVICE_ID:-${DESTINATION#platform=iOS Simulator,id=}}"
  xcrun simctl boot "$SIM_ID" 2>/dev/null || true
  xcrun simctl bootstatus "$SIM_ID" -b
fi

echo "=== Debug LAN KAT (Noise + RLB1, shared vectors) ===" >&2
(
  cd "$IOS"
  set -o pipefail
  xcodebuild test \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -destination "$DESTINATION" \
    -parallel-testing-enabled NO \
    -only-testing:RAVENTests/RavenSecureLanNoiseTests \
    -only-testing:RAVENTests/RavenSecureLanRlb1Tests
)

echo "=== Release lab gate (ATSAMLabGate fail-closed) ===" >&2
(
  cd "$IOS"
  set -o pipefail
  xcodebuild test \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -configuration Release \
    -destination "$DESTINATION" \
    -parallel-testing-enabled NO \
    CODE_SIGNING_ALLOWED=NO \
    -only-testing:RAVENTests/ATSAMLabGateReleaseVerificationTests
)

echo "ios_lan_kat: OK" >&2
