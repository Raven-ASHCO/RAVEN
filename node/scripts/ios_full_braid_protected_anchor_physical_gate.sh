#!/usr/bin/env bash
# Task 0B.2 — Physical iPhone protected-anchor gate (operator harness)
#
# Lab-only. Never stores seed bytes — only public SHA-256 digests on the host.
# No inter-phase Keychain cleanup. Ordered cleanup runs only after Phase D.
#
# Mandatory state machine (exact predecessor; completed phases not re-runnable):
#   A → B → C → D → cleanup
# Optional:
#   A_RESUME   only when last_phase is A/A_RESUME (exact-replay of Phase A)
#   recovery_cleanup
#     requires RECOVERY_CLEANUP_CONFIRM=YES-DELETE-SCOPED-FULLBRAID-KEYCHAIN
#     (out-of-order wipe only; not a substitute for D)
#
# ORDER_CHECK_ONLY=1 — enforce_phase_order only (no preflight/xcodebuild; for negatives)
#
# Phase D hold (when BFU cannot be exercised):
#   PLATFORM_HOLD must equal exactly:
#     FULL_BRAID_PHYSICAL_GATE_HOLD_MAIN_APP_CANNOT_RUN_BEFORE_FIRST_UNLOCK_V1
#
# Usage:
#   DEVICE_UDID=<physical-udid> ./node/scripts/ios_full_braid_protected_anchor_physical_gate.sh
#   DEVICE_UDID=... PHASE=B ...
#   DEVICE_UDID=... PHASE=recovery_cleanup \
#     RECOVERY_CLEANUP_CONFIRM=YES-DELETE-SCOPED-FULLBRAID-KEYCHAIN
#
# Forbidden: 0B.3+ without owner order, production enablement, commit/push/stage.
# Task 0B.2 Independent PASS recorded (ledger Rev27 §37).
# NOTE: lib/ios_full_braid_protected_anchor_physical_gate_lib.sh (the phase state
# machine this script and its _negatives sibling depend on) is NOT in this
# repository: it is absent from the tree and from git history. Until it is
# restored from the original author's copy, the recorded PASS cannot be
# reproduced or reviewed from this repo, and this script stops with a clear error.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IOS="$ROOT/ios-native/RAVEN"
PROJECT="$IOS/RAVEN.xcodeproj"
SCHEME="RAVEN"
TEST="RAVENTests/ATSAMFullBraidProtectedStorePhysicalGateTests/testPhysicalGatePhase"
RESULT_PREFIX="RAVEN_FB_PHYSICAL_GATE_JSON:"
HARNESS_ID="raven.atsam.full-braid.physical-gate.v1"
FROZEN_HOLD="FULL_BRAID_PHYSICAL_GATE_HOLD_MAIN_APP_CANNOT_RUN_BEFORE_FIRST_UNLOCK_V1"
RECOVERY_TOKEN="YES-DELETE-SCOPED-FULLBRAID-KEYCHAIN"
DEVELOPMENT_TEAM="${DEVELOPMENT_TEAM:-72QQ5Q324C}"

DEVICE_UDID="${DEVICE_UDID:-}"
PHASE="${PHASE:-all}"
EVIDENCE_DIR="${EVIDENCE_DIR:-$ROOT/artifacts/full-braid-0b2-physical-gate}"
PLATFORM_HOLD="${PLATFORM_HOLD:-}"
NONINTERACTIVE="${NONINTERACTIVE:-0}"
RECOVERY_CLEANUP_CONFIRM="${RECOVERY_CLEANUP_CONFIRM:-}"
RUN_ID="${RUN_ID:-}"
DERIVED_DATA="${DERIVED_DATA:-}"
ORDER_CHECK_ONLY="${ORDER_CHECK_ONLY:-0}"

log() { echo "=== $* ===" >&2; }

mkdir -p "$EVIDENCE_DIR"
STATE="$EVIDENCE_DIR/state.json"
LOG="$EVIDENCE_DIR/operator.log"
SUMMARY="$EVIDENCE_DIR/summary.md"
DERIVED_DATA="${DERIVED_DATA:-$EVIDENCE_DIR/DerivedData}"
PRODUCTS_IPHONEOS="$DERIVED_DATA/Build/Products/Debug-iphoneos"

GATE_LIB="$ROOT/node/scripts/lib/ios_full_braid_protected_anchor_physical_gate_lib.sh"
if [[ ! -f "$GATE_LIB" ]]; then
  echo "FAIL: $GATE_LIB is missing from this tree; the phase state machine (enforce_phase_order," >&2
  echo "      write_state_from_result, ...) cannot be reviewed or run. Restore it; do not re-create it by guesswork." >&2
  exit 1
fi
# shellcheck source=lib/ios_full_braid_protected_anchor_physical_gate_lib.sh
source "$GATE_LIB"

[[ -n "$DEVICE_UDID" ]] || die "set DEVICE_UDID to a physical iPhone UDID (not a simulator)"

if [[ "$ORDER_CHECK_ONLY" == "1" ]]; then
  enforce_phase_order "$PHASE"
  echo "PASS order-check-only phase=$PHASE last_phase=$(last_phase || true)"
  exit 0
fi

case "$DEVICE_UDID" in
  *-*-*-*-*) die "DEVICE_UDID looks like a simulator UUID; refuse" ;;
esac

if xcrun simctl list devices 2>/dev/null | grep -q "$DEVICE_UDID"; then
  die "DEVICE_UDID is a simulator; physical gate requires a real iPhone"
fi

touch "$LOG"
exec > >(tee -a "$LOG") 2>&1

log "Task 0B.2 physical gate harness"
echo "harness=$HARNESS_ID"
echo "device_udid=$DEVICE_UDID"
echo "evidence_dir=$EVIDENCE_DIR"
echo "derived_data=$DERIVED_DATA"
echo "development_team=$DEVELOPMENT_TEAM"
echo "phase_mode=$PHASE"
echo "frozen_hold=$FROZEN_HOLD"
echo "note: digests only — seed bytes never written to host evidence"
echo "note: RAVENTests signing forced YES for iphoneos physical gate only"
echo "note: exact predecessor order; completed phases refuse re-run"

pause() {
  local msg="$1"
  if [[ "$NONINTERACTIVE" == "1" ]]; then
    echo "NONINTERACTIVE=1 — skipping pause: $msg" >&2
    return 0
  fi
  echo >&2
  echo "OPERATOR ACTION REQUIRED:" >&2
  echo "  $msg" >&2
  read -r -p "Press Enter when ready to continue... " _
}

# Narrow device-only signing overrides (simulator/Catalyst/extensions untouched).
# Must stay as a bash array so "Apple Development" is not word-split.
DEVICE_SIGN_OVERRIDES=(
  "CODE_SIGNING_ALLOWED=YES"
  "CODE_SIGN_STYLE=Automatic"
  "CODE_SIGN_IDENTITY=Apple Development"
  "DEVELOPMENT_TEAM=${DEVELOPMENT_TEAM}"
)

require_codesigned_bundle() {
  local path="$1"
  local label="$2"
  [[ -e "$path" ]] || die "preflight: missing $label at $path"
  codesign --verify --deep --strict --verbose=2 "$path" 2>"$EVIDENCE_DIR/codesign_${label}.verify.log" \
    || die "preflight: codesign --verify failed for $label ($path)"
  local dv
  dv="$(mktemp)"
  codesign -dv --verbose=4 "$path" >"$dv" 2>&1 || die "preflight: codesign -dv failed for $label"
  if grep -qi 'Signature=adhoc' "$dv"; then
    cat "$dv" >&2
    rm -f "$dv"
    die "preflight: $label is adhoc-signed (not installable on device)"
  fi
  if ! grep -qi 'Authority=' "$dv"; then
    cat "$dv" >&2
    rm -f "$dv"
    die "preflight: $label missing signing Authority"
  fi
  cp "$dv" "$EVIDENCE_DIR/codesign_${label}.dv.txt"
  rm -f "$dv"
  echo "PASS preflight codesign: $label"
}

preflight_device_signed_products() {
  log "Preflight — build-for-testing + prove RAVEN.app and RAVENTests.xctest are signed"
  mkdir -p "$DERIVED_DATA"
  local build_log="$EVIDENCE_DIR/build-for-testing.log"
  (
    cd "$IOS"
    xcodebuild build-for-testing \
      -project "$PROJECT" \
      -scheme "$SCHEME" \
      -destination "platform=iOS,id=${DEVICE_UDID}" \
      -derivedDataPath "$DERIVED_DATA" \
      -only-testing:"$TEST" \
      "${DEVICE_SIGN_OVERRIDES[@]}" \
      2>&1
  ) | tee "$build_log"

  local app="$PRODUCTS_IPHONEOS/RAVEN.app"
  local xctest_product="$PRODUCTS_IPHONEOS/RAVENTests.xctest"
  local xctest_embedded="$PRODUCTS_IPHONEOS/RAVEN.app/PlugIns/RAVENTests.xctest"
  require_codesigned_bundle "$app" "RAVEN.app"
  if [[ -e "$xctest_product" ]]; then
    require_codesigned_bundle "$xctest_product" "RAVENTests.xctest"
  fi
  [[ -e "$xctest_embedded" ]] || die "preflight: missing embedded RAVENTests.xctest at $xctest_embedded"
  require_codesigned_bundle "$xctest_embedded" "RAVENTests.xctest.embedded"
  # Prove the Mach-O inside the bundle is signed (the prior failure mode).
  local macho="$xctest_embedded/RAVENTests"
  [[ -f "$macho" ]] || die "preflight: missing $macho"
  codesign --verify --strict --verbose=2 "$macho" 2>"$EVIDENCE_DIR/codesign_RAVENTests.macho.verify.log" \
    || die "preflight: RAVENTests Mach-O unsigned"
  echo "PASS preflight: app + RAVENTests.xctest team-signed for iphoneos"
}

run_phase() {
  local phase="$1"
  local hold="${2:-}"
  local out
  out="$(mktemp)"

  enforce_phase_order "$phase"

  local run_id
  run_id="$(json_get run_id)"
  [[ -n "$run_id" ]] || die "internal: missing run_id before phase $phase"

  if [[ "$phase" == "D" && -n "$hold" && "$hold" != "$FROZEN_HOLD" ]]; then
    die "PLATFORM_HOLD must be exactly: $FROZEN_HOLD"
  fi

  # Always re-prove signing before device execution (catches stale unsigned products).
  preflight_device_signed_products

  local -a env_args=(
    "TEST_RUNNER_RAVEN_FB_PHYSICAL_GATE_PHASE=${phase}"
    "TEST_RUNNER_RAVEN_FB_PHYSICAL_GATE_RUN_ID=${run_id}"
    "TEST_RUNNER_RAVEN_FB_PHYSICAL_GATE_DEVICE_UDID=${DEVICE_UDID}"
  )
  # Never forward ALLOW_SIMULATOR from this operator script.
  local seed seq1 seq2 chain scope
  seed="$(json_get seed_digest_sha256 || true)"
  seq1="$(json_get seq1_digest_sha256 || true)"
  seq2="$(json_get seq2_digest_sha256 || true)"
  chain="$(json_get chain_digest_sha256 || true)"
  scope="$(json_get scope_id_hex || true)"
  [[ -n "$seed" ]] && env_args+=("TEST_RUNNER_RAVEN_FB_PHYSICAL_GATE_EXPECT_SEED_DIGEST=${seed}")
  [[ -n "$seq1" ]] && env_args+=("TEST_RUNNER_RAVEN_FB_PHYSICAL_GATE_EXPECT_SEQ1_DIGEST=${seq1}")
  [[ -n "$seq2" ]] && env_args+=("TEST_RUNNER_RAVEN_FB_PHYSICAL_GATE_EXPECT_SEQ2_DIGEST=${seq2}")
  [[ -n "$chain" ]] && env_args+=("TEST_RUNNER_RAVEN_FB_PHYSICAL_GATE_EXPECT_CHAIN_DIGEST=${chain}")
  [[ -n "$scope" ]] && env_args+=("TEST_RUNNER_RAVEN_FB_PHYSICAL_GATE_EXPECT_SCOPE_HEX=${scope}")
  if [[ -n "$hold" ]]; then
    env_args+=("TEST_RUNNER_RAVEN_FB_PHYSICAL_GATE_PLATFORM_HOLD=${hold}")
  fi

  log "Phase ${phase} — xcodebuild test on device ${DEVICE_UDID} run_id=${run_id}"
  (
    cd "$IOS"
    env "${env_args[@]}" \
      xcodebuild test \
        -project "$PROJECT" \
        -scheme "$SCHEME" \
        -destination "platform=iOS,id=${DEVICE_UDID}" \
        -derivedDataPath "$DERIVED_DATA" \
        -only-testing:"$TEST" \
        "${DEVICE_SIGN_OVERRIDES[@]}" \
        2>&1
  ) | tee "$out"

  local json_line
  json_line="$(grep -F "$RESULT_PREFIX" "$out" | tail -n 1 | sed "s/^.*${RESULT_PREFIX}//" || true)"
  [[ -n "$json_line" ]] || die "phase ${phase}: missing ${RESULT_PREFIX} marker in xcodebuild output"
  echo "$json_line" | python3 -m json.tool >/dev/null || die "phase ${phase}: result JSON invalid"
  # Bind success before any host write (defense in depth vs false ok=true emit).
  python3 - "$json_line" "$run_id" "$DEVICE_UDID" "$phase" <<'PY'
import json,sys
r=json.loads(sys.argv[1])
run_id, udid, phase = sys.argv[2], sys.argv[3], sys.argv[4]
assert r.get("ok") is True, r
assert r.get("run_id") == run_id, (r.get("run_id"), run_id)
assert r.get("device_udid") == udid, (r.get("device_udid"), udid)
assert r.get("phase") == phase, (r.get("phase"), phase)
print(f"PASS phase={r.get('phase')} outcome={r.get('outcome')} detail={r.get('detail')}")
PY
  write_state_from_result "$json_line" >/dev/null
  echo "$json_line" >"$EVIDENCE_DIR/phase_${phase}.json"
  rm -f "$out"
}

write_summary() {
  python3 - "$STATE" "$SUMMARY" <<'PY'
import json,sys,datetime
state_path, summary_path = sys.argv[1:3]
with open(state_path) as f:
    st=json.load(f)
lines=[
  "# Task 0B.2 Physical Gate — operator summary",
  "",
  f"- Generated: {datetime.datetime.now().isoformat(timespec='seconds')}",
  f"- Device UDID: `{st.get('device_udid')}`",
  f"- Run ID: `{st.get('run_id')}`",
  f"- Harness: `{st.get('harness')}`",
  f"- Scope: `{st.get('scope_id_hex')}`",
  f"- Seed digest (SHA-256): `{st.get('seed_digest_sha256')}`",
  f"- Seq1 digest: `{st.get('seq1_digest_sha256')}`",
  f"- Seq2 digest: `{st.get('seq2_digest_sha256')}`",
  f"- Chain digest: `{st.get('chain_digest_sha256')}`",
  f"- production_enabled: `{st.get('production_enabled')}`",
  f"- release_hold: `{st.get('release_hold')}`",
  "",
  "## Phases",
  "",
]
for p in st.get("phases") or []:
    lines.append(
      f"- Phase `{p.get('phase')}`: ok={p.get('ok')} outcome=`{p.get('outcome')}` "
      f"hold=`{p.get('platform_hold_code')}` detail=`{p.get('detail')}`"
    )
lines += [
  "",
  "## Notes",
  "",
  "- Host evidence stores public digests only (no seed bytes).",
  "- Order enforced: exact predecessor A/A_RESUME → B → C → D → cleanup; completed phases refuse re-run.",
  "- Phase D requires complete Phase-C digest bundle + same run/device binding.",
  "- Task 0B.3+ remains blocked until full Independent 0B.2 PASS + owner order.",
  "",
]
with open(summary_path,"w") as f:
    f.write("\n".join(lines))
print(summary_path)
PY
}

start_phase_a() {
  # Refuse wipe if this evidence dir already has a completed phase (preserves run_id/A–C).
  enforce_phase_order A
  local rid
  rid="${RUN_ID:-$(uuidgen | tr '[:upper:]' '[:lower:]')}"
  init_fresh_run_state "$rid" >/dev/null
  echo "run_id=$rid (fresh state; prior digests discarded)"
  run_phase A
}

case "$PHASE" in
  A)
    start_phase_a
    ;;
  A_RESUME)
    run_phase A_RESUME
    ;;
  B)
    run_phase B
    ;;
  C)
    run_phase C
    ;;
  D)
    run_phase D "$PLATFORM_HOLD"
    ;;
  cleanup)
    run_phase cleanup
    ;;
  recovery_cleanup)
    run_phase recovery_cleanup
    ;;
  all)
    start_phase_a
    pause "Kill the RAVEN test host / app completely. Next xcodebuild relaunches. Confirm Keychain was not wiped."
    run_phase B
    pause "Lock the iPhone, then unlock it. Do not delete the app or reset Keychain."
    run_phase C
    echo >&2
    echo "Phase D — BFU / frozen platform hold:" >&2
    echo "  Option 1: reboot and run before first unlock (leave PLATFORM_HOLD empty)." >&2
    echo "  Option 2: PLATFORM_HOLD=$FROZEN_HOLD" >&2
    if [[ -z "$PLATFORM_HOLD" && "$NONINTERACTIVE" != "1" ]]; then
      read -r -p "Enter frozen PLATFORM_HOLD now (or leave empty for live BFU): " PLATFORM_HOLD || true
    fi
    if [[ -n "$PLATFORM_HOLD" && "$PLATFORM_HOLD" != "$FROZEN_HOLD" ]]; then
      die "PLATFORM_HOLD must be exactly: $FROZEN_HOLD"
    fi
    run_phase D "$PLATFORM_HOLD"
    run_phase cleanup
    write_summary
    log "Physical gate operator run complete — evidence in ${EVIDENCE_DIR}"
    echo "summary=$SUMMARY"
    echo "state=$STATE"
    echo "STOP: physical evidence ready for Independent review after device execution."
    echo "Task 0B.3+ / production / commit / push / stage remain forbidden."
    ;;
  *)
    die "PHASE must be A|A_RESUME|B|C|D|cleanup|recovery_cleanup|all"
    ;;
esac
