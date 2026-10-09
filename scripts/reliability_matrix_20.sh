#!/usr/bin/env bash
# Reliability matrix — loop communication scenarios across modes/platforms.
# Target: ≥20 successful scenario cycles total; prefer critical paths ≥3–5×.
# Writes: node/proof_artifacts/reliability_20_<run-id>/
# Exit 0 only when required pass budget is met and no hard FAIL remaining
# (platform SKIP / PASS_SOFTWARE_SUBSTITUTE allowed with notes).
#
# Usage:
#   bash scripts/reliability_matrix_20.sh
#   ITERS=3 bash scripts/reliability_matrix_20.sh          # per-scenario loops
#   SKIP_IOS=1 SKIP_DOCKER=1 bash scripts/reliability_matrix_20.sh
#   SKIP_WINDOWS=1 SKIP_LINUX_CONTAINER=1 ...    # skip release cross-build probes
#   bash scripts/reliability_matrix_20.sh --self-test   # runner self-test only
#
# Each scenario body runs through run_isolated (scripts/lib/proof_assert.sh):
# errexit + pipefail are really in force inside it, so ANY failing command or
# assertion fails that cycle. (Previously the matrix ran with errexit off and a
# scenario's status was just its last command — usually `rm -rf "$work"` — so
# every cycle "passed", including ones that could not deliver.)
# Return codes from a scenario: 0 PASS, PROOF_RC_SKIP (77) SKIP,
# PROOF_RC_SUBSTITUTE (78) PASS_SOFTWARE_SUBSTITUTE; run_isolated folds EVERY other
# status (including a tool's own exit 2 / 10) into FAIL — see proof_assert.sh.
#
# LAB BUILD: bridged delivery scenarios use raven-node's unsafe-demo-crypto
# `--body-mode unsafe-interim` (key derived from public keys). Default builds
# refuse origination without an ATSAM session (ATSAM_SESSION_REQUIRED).
set -u
# Intentionally NOT set -e at top level: scenario failures must be counted, not
# abort the matrix. Scenario bodies get errexit via run_isolated.
set -o pipefail 2>/dev/null || true

REPO="$(cd "$(dirname "$0")/.." && pwd)"
NODE_ROOT="$REPO/node"
# shellcheck source=scripts/lib/proof_assert.sh
source "$REPO/scripts/lib/proof_assert.sh"
# shellcheck source=scripts/lib/harness_util.sh
source "$REPO/scripts/lib/harness_util.sh"
# Plain statement on purpose: inside `||` bash would disable errexit again and
# the self-test would (correctly) report the runner as broken. Exits 97 on failure.
proof_harness_selftest
if [[ "${1:-}" == "--self-test" ]]; then
  exit 0
fi
source "${HOME}/.cargo/env" 2>/dev/null || true
# Debug/lab identity override (refused in Release) + no ~/.raven redirection.
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1

ITERS="${ITERS:-4}"                 # default 4 → many scenarios × 4 ≥ 20
MIN_TOTAL_PASS="${MIN_TOTAL_PASS:-20}"
SKIP_IOS="${SKIP_IOS:-0}"
SKIP_DOCKER="${SKIP_DOCKER:-0}"
SKIP_WINE="${SKIP_WINE:-0}"
SKIP_LINUX_CONTAINER="${SKIP_LINUX_CONTAINER:-0}"
SKIP_WINDOWS="${SKIP_WINDOWS:-0}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ART="$NODE_ROOT/proof_artifacts/reliability_20_$RUN_ID"
mkdir -p "$ART"/{logs,scenarios,cycles,platform}
SUMMARY="$ART/SUMMARY.md"
TABLE="$ART/RESULTS_TABLE.md"
TRANSCRIPT="$ART/transcript.log"
CSV="$ART/results.csv"

PASS=0
FAIL=0
SKIP=0
SUBST=0
declare -a SCENARIO_NAMES=()
declare -a SCENARIO_PASS=()
declare -a SCENARIO_FAIL=()
declare -a SCENARIO_SKIP=()
declare -a SCENARIO_NOTES=()

log() { echo "$*" | tee -a "$TRANSCRIPT"; }

echo "scenario,cycle,result,note,elapsed_s" >"$CSV"

record() {
  local scenario="$1" cycle="$2" result="$3" note="$4" elapsed="$5"
  echo "$scenario,$cycle,$result,\"$note\",$elapsed" >>"$CSV"
  echo "$result" >"$ART/scenarios/${scenario}_c${cycle}.result"
  printf '%s\n' "$note" >"$ART/scenarios/${scenario}_c${cycle}.note"
  case "$result" in
    PASS|PASS_SOFTWARE_SUBSTITUTE)
      PASS=$((PASS + 1))
      ;;
    FAIL)
      FAIL=$((FAIL + 1))
      ;;
    SKIP)
      SKIP=$((SKIP + 1))
      ;;
  esac
  if [[ "$result" == PASS_SOFTWARE_SUBSTITUTE ]]; then
    SUBST=$((SUBST + 1))
  fi
  return 0
}

# Lab build: bridged scenarios need --body-mode unsafe-interim.
build_demo_bins() {
  (cd "$NODE_ROOT" && cargo build --locked -p raven-node -p ash -p raven-swarm \
    --features raven-node/unsafe-demo-crypto -q)
}

ensure_bins() {
  log "=== build debug binaries (unsafe-demo-crypto lab build) ==="
  build_demo_bins 2>&1 | tee "$ART/logs/build.log" || return 1
  BIN="$NODE_ROOT/target/debug"
  NODE="$BIN/raven-node"
  ASH="$BIN/ash"
  SWARM="$BIN/raven-swarm"
  [[ -x "$NODE" && -x "$ASH" && -x "$SWARM" ]]
}

# Prefer Lima Docker context when host dockerd is down (macOS common).
ensure_docker_host() {
  if docker info >/dev/null 2>&1; then
    return 0
  fi
  local sock="$HOME/.lima/ash-amd64-preflight/sock/docker.sock"
  if [[ -S "$sock" ]]; then
    export DOCKER_HOST="unix://$sock"
    log "DOCKER_HOST=$DOCKER_HOST (lima)"
    docker info >/dev/null 2>&1 && return 0
  fi
  if docker context ls 2>/dev/null | grep -q 'lima-ash-amd64-preflight'; then
    export DOCKER_CONTEXT=lima-ash-amd64-preflight
    log "DOCKER_CONTEXT=$DOCKER_CONTEXT"
    docker info >/dev/null 2>&1 && return 0
  fi
  return 1
}

# ---- Scenario helpers -------------------------------------------------------

sc_internet_hold_and_swarm() {
  # Truthful software coverage: the legacy raw path must remain held while the
  # libp2p transport composition still completes its localhost smoke.
  local cycle="$1" work
  work=$(mktemp -d "${TMPDIR:-/tmp}/rel-inet.XXXXXX")
  bash "$NODE_ROOT/scripts/internet_dial_smoke.sh" >"$ART/logs/inet_c${cycle}.log" 2>&1
  must_grep 'PASS: legacy InternetTransport remains fail-closed' "$ART/logs/inet_c${cycle}.log"
  # swarm smoke once per cycle (heavier)
  bash "$NODE_ROOT/scripts/libp2p_swarm_smoke.sh" >"$ART/logs/swarm_c${cycle}.log" 2>&1
  must_grep 'LIBP2P SWARM SMOKE OK' "$ART/logs/swarm_c${cycle}.log"
  rm -rf "$work"
}

sc_mesh_relay() {
  local cycle="$1"
  (cd "$NODE_ROOT" && cargo test --locked -p raven-core --test bridge_v1 -- --nocapture) \
    >"$ART/logs/mesh_relay_c${cycle}.log" 2>&1
  must_grep -E 'test result: ok\. [1-9][0-9]* passed' "$ART/logs/mesh_relay_c${cycle}.log"
}

sc_bridge_up() {
  local cycle="$1"
  bash "$NODE_ROOT/scripts/bridge_abc_demo.sh" >"$ART/logs/bridge_up_c${cycle}.log" 2>&1
  must_grep 'ALL BRIDGE A-B-C CHECKS PASSED' "$ART/logs/bridge_up_c${cycle}.log"
  must_grep 'reverse path OK' "$ART/logs/bridge_up_c${cycle}.log"
}

# Wait until the bridge daemon ($2 = its pid, $3 = its log) has published both
# listen addresses. The files are written create+truncate then write, so wait for
# NON-EMPTY ones; fails fast (dumping the log) if the daemon dies or never listens.
wait_bridge_addrs() {
  local work="$1" pid="$2" log="$3"
  raven_wait_file "$work/b.lan" "$pid" 15 "$log"
  raven_wait_file "$work/b.ble" "$pid" 15 "$log"
}

sc_bridge_down_up() {
  # Store-carry then flush is already inside bridge_abc; isolate one more SCF loop
  local cycle="$1" work
  work=$(mktemp -d "${TMPDIR:-/tmp}/rel-scf.XXXXXX")
  build_demo_bins
  "$NODE" init --data-dir "$work/a" >"$work/a.init"
  "$NODE" init --data-dir "$work/b" >"$work/b.init"
  "$NODE" init --data-dir "$work/c" >"$work/c.init"
  local A_PUB B_PUB C_PUB
  A_PUB=$(grep '^pub_hex=' "$work/a.init" | cut -d= -f2)
  B_PUB=$(grep '^pub_hex=' "$work/b.init" | cut -d= -f2)
  C_PUB=$(grep '^pub_hex=' "$work/c.init" | cut -d= -f2)
  "$ASH" --data-dir "$work/b" node bridge on >/dev/null
  "$ASH" --data-dir "$work/b" node store on >/dev/null
  "$NODE" bridge --data-dir "$work/b" --lan-listen "127.0.0.1:0" --ble-listen "127.0.0.1:0" \
    --write-lan-addr "$work/b.lan" --write-ble-addr "$work/b.ble" --timeout-secs 45 \
    >"$work/b.log" 2>&1 &
  local BPID=$!
  wait_bridge_addrs "$work" "$BPID" "$work/b.log"
  local B_LAN B_BLE
  B_LAN=$(cat "$work/b.lan"); B_BLE=$(cat "$work/b.ble")
  printf '%s\n' "scf-down-up-$cycle" | "$NODE" run --data-dir "$work/a" --listen "127.0.0.1:0" \
    --peer "$B_LAN" --peer-pub-hex "$B_PUB" --seal-to-pub-hex "$C_PUB" --ack-pub-hex "$C_PUB" \
    --send-stdin --body-mode unsafe-interim --exit-after-ack --timeout-secs 40 \
    >"$work/a.log" 2>&1 &
  local APID=$!
  # Start C only once B has logged that it queued A's frame (no mock_ble peer yet).
  # A fixed sleep let a slow sender start after C attached, turning this "store-carry"
  # cycle into a plain live forward that still passed. Fails (with b.log) on timeout.
  raven_wait_log "$work/b.log" 'BRIDGE (queued waiting|store-carry)' "$BPID" 15
  "$NODE" run --data-dir "$work/c" --listen "127.0.0.1:0" --peer "$B_BLE" \
    --peer-pub-hex "$A_PUB" --origin-pub-hex "$A_PUB" --exit-after-recv 1 --timeout-secs 35 \
    >"$work/c.log" 2>&1 &
  local CPID=$!
  wait "$APID" || true
  wait "$CPID" || true
  kill "$BPID" 2>/dev/null || true
  wait "$BPID" 2>/dev/null || true
  for f in a b c; do cp "$work/$f.log" "$ART/logs/scf_${f}_c${cycle}.log" 2>/dev/null || true; done
  must_grep 'ACK delivered' "$work/a.log"
  must_grep 'DELIVERED bytes=' "$work/c.log"
  # The queued frame must have been flushed to C when it attached.
  must_grep 'BRIDGE flush → mock_ble' "$work/b.log"
  must_not_grep -F "scf-down-up-$cycle" "$work/b.log"
  rm -rf "$work"
}

sc_bridge_crash_restart() {
  local cycle="$1" work
  work=$(mktemp -d "${TMPDIR:-/tmp}/rel-bcrash.XXXXXX")
  build_demo_bins
  "$NODE" init --data-dir "$work/a" >"$work/a.init"
  "$NODE" init --data-dir "$work/b" >"$work/b.init"
  "$NODE" init --data-dir "$work/c" >"$work/c.init"
  local A_PUB B_PUB C_PUB
  A_PUB=$(grep '^pub_hex=' "$work/a.init" | cut -d= -f2)
  B_PUB=$(grep '^pub_hex=' "$work/b.init" | cut -d= -f2)
  C_PUB=$(grep '^pub_hex=' "$work/c.init" | cut -d= -f2)
  "$ASH" --data-dir "$work/b" node bridge on >/dev/null
  "$ASH" --data-dir "$work/b" node store on >/dev/null
  # Start bridge, hand it a queued message (C offline), SIGKILL it, restart,
  # then a fresh message must still be delivered end-to-end with an ACK.
  "$NODE" bridge --data-dir "$work/b" --lan-listen "127.0.0.1:0" --ble-listen "127.0.0.1:0" \
    --write-lan-addr "$work/b.lan" --write-ble-addr "$work/b.ble" --timeout-secs 20 \
    >"$work/b1.log" 2>&1 &
  local BPID=$!
  wait_bridge_addrs "$work" "$BPID" "$work/b1.log"
  local B_LAN
  B_LAN=$(cat "$work/b.lan")
  # No ACK can arrive (C offline, bridge about to die): bounded, outcome ignored.
  printf '%s\n' "pre-crash-$cycle" | "$NODE" run --data-dir "$work/a" --listen "127.0.0.1:0" \
    --peer "$B_LAN" --peer-pub-hex "$B_PUB" --seal-to-pub-hex "$C_PUB" --ack-pub-hex "$C_PUB" \
    --send-stdin --body-mode unsafe-interim --timeout-secs 4 >"$work/a_pre.log" 2>&1 || true
  kill -9 "$BPID" 2>/dev/null || true
  wait "$BPID" 2>/dev/null || true
  rm -f "$work/b.lan" "$work/b.ble"
  "$NODE" bridge --data-dir "$work/b" --lan-listen "127.0.0.1:0" --ble-listen "127.0.0.1:0" \
    --write-lan-addr "$work/b.lan" --write-ble-addr "$work/b.ble" --timeout-secs 45 \
    >"$work/b2.log" 2>&1 &
  BPID=$!
  wait_bridge_addrs "$work" "$BPID" "$work/b2.log"
  B_LAN=$(cat "$work/b.lan")
  local B_BLE
  B_BLE=$(cat "$work/b.ble")
  printf '%s\n' "post-crash-$cycle" | "$NODE" run --data-dir "$work/a" --listen "127.0.0.1:0" \
    --peer "$B_LAN" --peer-pub-hex "$B_PUB" --seal-to-pub-hex "$C_PUB" --ack-pub-hex "$C_PUB" \
    --send-stdin --body-mode unsafe-interim --exit-after-ack --timeout-secs 40 \
    >"$work/a.log" 2>&1 &
  local APID=$!
  sleep 0.6
  # C may first receive the pre-crash message if the store survived the crash,
  # so allow up to two deliveries; the post-crash ACK is what is asserted.
  "$NODE" run --data-dir "$work/c" --listen "127.0.0.1:0" --peer "$B_BLE" \
    --peer-pub-hex "$A_PUB" --origin-pub-hex "$A_PUB" --exit-after-recv 2 --timeout-secs 20 \
    >"$work/c.log" 2>&1 &
  local CPID=$!
  wait "$APID" || true
  wait "$CPID" || true
  kill "$BPID" 2>/dev/null || true
  wait "$BPID" 2>/dev/null || true
  for f in a_pre a b1 b2 c; do cp "$work/$f.log" "$ART/logs/bcrash_${f}_c${cycle}.log" 2>/dev/null || true; done
  must_grep 'ACK delivered' "$work/a.log"
  must_grep 'DELIVERED bytes=' "$work/c.log"
  rm -rf "$work"
}

sc_find_contact() {
  local cycle="$1" work
  work=$(mktemp -d "${TMPDIR:-/tmp}/rel-find.XXXXXX")
  "$ASH" --data-dir "$work/a" init >"$work/a.init"
  "$ASH" --data-dir "$work/b" init >"$work/b.init"
  local B_ADDR B_PUB B_FP
  B_ADDR=$(grep '^address=' "$work/b.init" | cut -d= -f2)
  B_PUB=$(grep '^pub_hex=' "$work/b.init" | cut -d= -f2)
  B_FP=$(grep '^fingerprint=' "$work/b.init" | cut -d= -f2)
  # find by exact id (no central DB: an unknown id may legitimately miss)
  "$ASH" --data-dir "$work/a" find --exact-id "$B_ADDR" --all >"$work/find.txt" 2>&1 || true
  "$ASH" --data-dir "$work/a" contact add \
    --address "$B_ADDR" --pub-hex "$B_PUB" --petname "Bob$cycle" --tag "bob$cycle" \
    --verify-fp "$B_FP" >"$work/add.txt" 2>&1
  must_grep -iE 'contact saved|pinned' "$work/add.txt"
  # A pinned contact must now resolve locally by tag (alias conflict path is non-silent).
  "$ASH" --data-dir "$work/a" find --all "bob$cycle" >"$work/find2.txt" 2>&1 || true
  must_grep -F "$B_ADDR" "$work/find2.txt"
  # Legacy contact request is on a security hold (no authenticated PairInit /
  # ATSAM session in default debug builds): it must REFUSE and create no wire.
  local req_rc=0
  "$ASH" --data-dir "$work/a" contact request --message "hi-$cycle" "$B_ADDR" \
    >"$work/req.txt" 2>&1 || req_rc=$?
  [[ $req_rc -ne 0 ]] || fail_assert "contact request unexpectedly succeeded while held"
  must_grep 'PRODUCTION_GATE_DISABLED' "$work/req.txt"
  if ls "$work/a"/contact_request_*.wire >/dev/null 2>&1; then
    fail_assert "held contact request still wrote a .wire file"
  fi
  cp "$work"/find.txt "$work"/find2.txt "$work"/req.txt "$ART/logs/" 2>/dev/null || true
  # discovery anti-spam / alias / replay / accept-decline-block unit matrix
  (cd "$NODE_ROOT" && cargo test --locked -p raven-core --test discovery_v1 -- --nocapture) \
    >"$ART/logs/discovery_c${cycle}.log" 2>&1
  must_grep -E 'test result: ok\. [1-9][0-9]* passed' "$ART/logs/discovery_c${cycle}.log"
  rm -rf "$work"
}

sc_offline_mailbox() {
  local cycle="$1"
  bash "$NODE_ROOT/scripts/mailbox_opaque_smoke.sh" >"$ART/logs/mailbox_c${cycle}.log" 2>&1
  must_grep 'OK mailbox' "$ART/logs/mailbox_c${cycle}.log"
}

sc_duplicate_multipath() {
  local cycle="$1"
  # Filters go after `--` (the test binary accepts several); a filter that
  # matches nothing prints "ok. 0 passed", which must not count as a pass.
  (cd "$NODE_ROOT" && cargo test --locked -p raven-core --test bridge_v1 -- \
    case04_dup case06_replay --nocapture) \
    >"$ART/logs/dedup_c${cycle}.log" 2>&1
  must_grep -E 'test result: ok\. [1-9][0-9]* passed' "$ART/logs/dedup_c${cycle}.log"
}

sc_tamper_replay() {
  local cycle="$1"
  (cd "$NODE_ROOT" && cargo test --locked -p raven-core --test discovery_v1 -- \
    a05_old_sequence_replay_rejected a04_forged_alias_rejected --nocapture) \
    >"$ART/logs/tamper_c${cycle}.log" 2>&1
  must_grep -E 'test result: ok\. 2 passed' "$ART/logs/tamper_c${cycle}.log"
  # Bridge / queue integrity unit tests
  (cd "$NODE_ROOT" && cargo test --locked -p raven-core --test reliability -- --nocapture) \
    >"$ART/logs/reliability_unit_c${cycle}.log" 2>&1
  must_grep -E 'test result: ok\. [1-9][0-9]* passed' "$ART/logs/reliability_unit_c${cycle}.log"
}

sc_fastapi_bootstrap_disabled() {
  local cycle="$1"
  bash "$NODE_ROOT/scripts/bootstrap_manual_peer_smoke.sh" \
    >"$ART/logs/bootstrap_c${cycle}.log" 2>&1
  must_grep 'MANUAL-PEER-ONLY BOOTSTRAP SMOKE OK' "$ART/logs/bootstrap_c${cycle}.log"
  local work
  work=$(mktemp -d "${TMPDIR:-/tmp}/rel-boot.XXXXXX")
  "$ASH" --data-dir "$work/t" init >"$work/init.txt"
  "$ASH" --data-dir "$work/t" doctor >"$work/doctor.txt"
  must_grep 'serverless_rvn1' "$work/doctor.txt"
  must_grep -i 'never silently uses FastAPI' "$work/doctor.txt"
  "$ASH" --data-dir "$work/t" node disable-raven-defaults >"$work/dis.txt"
  "$SWARM" bootstrap-init --data-dir "$work/t" --manual-peer "127.0.0.1:9" --no-raven-defaults
  "$SWARM" bootstrap-show --data-dir "$work/t" >"$work/show.txt"
  must_grep 'manual_peer_only=true' "$work/show.txt"
  must_grep 'use_raven_defaults=false' "$work/show.txt"
  rm -rf "$work"
}

sc_ash_close_service() {
  local cycle="$1" work
  work=$(mktemp -d "${TMPDIR:-/tmp}/rel-svc.XXXXXX")
  "$NODE" init --data-dir "$work/bridge" >"$work/init.txt"
  "$ASH" --data-dir "$work/bridge" node bridge on >/dev/null
  "$NODE" service --data-dir "$work/bridge" --lan-listen "127.0.0.1:0" --ble-listen "127.0.0.1:0" \
    --timeout-secs 0 >"$work/svc.log" 2>&1 &
  local SPID=$!
  for _ in $(seq 1 120); do
    raven_ipc_up "$ASH" "$work/bridge" && break
    sleep 0.05
  done
  if ! raven_ipc_up "$ASH" "$work/bridge"; then
    echo "no IPC answer; svc.log:" >>"$ART/logs/ash_close_c${cycle}.log"
    cat "$work/svc.log" >>"$ART/logs/ash_close_c${cycle}.log" 2>/dev/null || true
    kill "$SPID" 2>/dev/null || true
    rm -rf "$work"
    return 1
  fi
  # Simulate ash session then exit — retry ipc briefly (service warmup)
  "$ASH" --data-dir "$work/bridge" status >"$work/status.txt" 2>&1 || true
  local ping_ok=0
  for _ in $(seq 1 40); do
    if "$ASH" --data-dir "$work/bridge" ipc-ping >"$work/ping1.txt" 2>&1; then
      ping_ok=1
      break
    fi
    sleep 0.1
  done
  if [[ "$ping_ok" -ne 1 ]]; then
    echo "ipc-ping1 failed" >>"$ART/logs/ash_close_c${cycle}.log"
    cat "$work/ping1.txt" "$work/svc.log" >>"$ART/logs/ash_close_c${cycle}.log" 2>/dev/null || true
    kill "$SPID" 2>/dev/null || true
    rm -rf "$work"
    return 1
  fi
  # ash has exited; service must still be alive
  sleep 0.25
  if ! kill -0 "$SPID" 2>/dev/null; then
    echo "service died after ash exit" >>"$ART/logs/ash_close_c${cycle}.log"
    cat "$work/svc.log" >>"$ART/logs/ash_close_c${cycle}.log" 2>/dev/null || true
    rm -rf "$work"
    return 1
  fi
  ping_ok=0
  for _ in $(seq 1 20); do
    if "$ASH" --data-dir "$work/bridge" ipc-ping >"$work/ping2.txt" 2>&1; then
      ping_ok=1
      break
    fi
    sleep 0.1
  done
  if [[ "$ping_ok" -ne 1 ]]; then
    echo "ipc-ping2 failed (service should survive ash close)" >>"$ART/logs/ash_close_c${cycle}.log"
    cat "$work/ping2.txt" "$work/svc.log" >>"$ART/logs/ash_close_c${cycle}.log" 2>/dev/null || true
    kill "$SPID" 2>/dev/null || true
    rm -rf "$work"
    return 1
  fi
  kill "$SPID" 2>/dev/null || true
  wait "$SPID" 2>/dev/null || true
  cp "$work/ping1.txt" "$work/ping2.txt" "$ART/logs/" 2>/dev/null || true
  rm -rf "$work"
  return 0
}

run_ios_dest() {
  local dest_name="$1" cycle="$2" out="$3"
  local line udid
  if [[ ! -d "$REPO/ios-native/RAVEN/RAVEN.xcodeproj" ]] || ! command -v xcrun >/dev/null 2>&1; then
    echo "NO_IOS_TREE_OR_XCODE: ios-native/RAVEN absent on this tree or no Xcode" >>"$out"
    return "$PROOF_RC_SKIP"
  fi
  # Match device name on the device line (OS version is a section header, not same line).
  line=$(xcrun simctl list devices available | grep -F "$dest_name" | grep -v unavailable | head -1 || true)
  if [[ -z "$line" ]]; then
    echo "NO_SIM:$dest_name" >>"$out"
    return "$PROOF_RC_SKIP"
  fi
  udid=$(echo "$line" | sed -E 's/.*\(([A-F0-9-]{36})\).*/\1/')
  if [[ -z "$udid" || "$udid" == "$line" ]]; then
    echo "NO_UDID:$dest_name line=$line" >>"$out"
    return "$PROOF_RC_SKIP"
  fi
  xcrun simctl boot "$udid" 2>/dev/null || true
  local xdest="platform=iOS Simulator,id=$udid"
  (
    cd "$REPO/ios-native/RAVEN"
    xcodebuild test \
      -project RAVEN.xcodeproj \
      -scheme RAVEN \
      -destination "$xdest" \
      -only-testing:RAVENTests/DiscoveryResolverTests \
      -only-testing:RAVENTests/ContactRequestInboxTests \
      -only-testing:RAVENTests/RavenContactRequestV1Tests \
      -only-testing:RAVENTests/RavenEnvelopeV1VectorsTests \
      -only-testing:RAVENTests/RavenEnvelopeChatWireTests \
      -only-testing:RAVENTests/RavenBleRvn1CarrierTests \
      -parallel-testing-enabled NO
  ) >"$out" 2>&1
  grep -q 'TEST SUCCEEDED' "$out"
}

# try_ios_dests LOG CYCLE NAME...: run the iOS tests on the FIRST simulator that
# exists and return run_ios_dest's status unchanged. Only a missing simulator
# (the SKIP sentinel) falls through to the next NAME; a real test failure (1) on
# an installed simulator must not be retried elsewhere and then read as SKIP when
# the fallback is absent. All names missing = SKIP. (`|| rc=$?` is fine here:
# run_ios_dest decides only through its explicit returns and its final grep.)
try_ios_dests() {
  local log="$1" cycle="$2" name rc
  shift 2
  for name in "$@"; do
    rc=0
    run_ios_dest "$name" "$cycle" "$log" || rc=$?
    if [[ $rc -ne $PROOF_RC_SKIP ]]; then
      return "$rc"
    fi
  done
  return "$PROOF_RC_SKIP"
}

sc_ios_iphone() {
  local cycle="$1"
  [[ "$SKIP_IOS" == "1" ]] && { echo "SKIP_IOS"; return "$PROOF_RC_SKIP"; }
  try_ios_dests "$ART/logs/ios_iphone_c${cycle}.log" "$cycle" "RAVEN-iPhone-15" "iPhone 17"
}

sc_ios_ipad() {
  local cycle="$1"
  [[ "$SKIP_IOS" == "1" ]] && { echo "SKIP_IOS"; return "$PROOF_RC_SKIP"; }
  try_ios_dests "$ART/logs/ios_ipad_c${cycle}.log" "$cycle" \
    "iPad Air 11-inch" "iPad Pro 11-inch" "iPad (A16)"
}

sc_windows_wine() {
  local cycle="$1"
  [[ "$SKIP_WINDOWS" == "1" ]] && { echo "SKIP_WINDOWS"; return "$PROOF_RC_SKIP"; }
  local exe="$NODE_ROOT/target/x86_64-pc-windows-gnu/release/ash.exe"
  if [[ ! -f "$exe" ]]; then
    if ! rustup target list --installed 2>/dev/null | grep -qx 'x86_64-pc-windows-gnu'; then
      echo "x86_64-pc-windows-gnu target not installed"
      return "$PROOF_RC_SKIP"
    fi
    (cd "$NODE_ROOT" && cargo build --locked -p ash --release --target x86_64-pc-windows-gnu -q) \
      >"$ART/logs/win_build_c${cycle}.log" 2>&1
  fi
  [[ -f "$exe" ]] || fail_assert "cross build produced no $exe"
  file "$exe" | tee "$ART/platform/windows_file_c${cycle}.txt" | grep -qi 'PE32+'
  # Self-check: size + PE header
  python3 - <<PY | tee "$ART/platform/windows_pe_c${cycle}.txt"
import struct, pathlib
p = pathlib.Path("$exe")
data = p.read_bytes()[:0x200]
assert data[:2] == b'MZ', 'not MZ'
pe_off = struct.unpack_from('<I', data, 0x3C)[0]
assert data[pe_off:pe_off+4] == b'PE\0\0', 'not PE'
print(f'PASS_PE size={p.stat().st_size} pe_off={pe_off}')
PY
  if [[ "$SKIP_WINE" != "1" ]] && command -v wine64 >/dev/null 2>&1; then
    WINEPREFIX="$ART/platform/wineprefix" wine64 "$exe" --help \
      >"$ART/platform/wine_ash_help_c${cycle}.txt" 2>&1 \
      && grep -qiE 'ash|Usage|Raven' "$ART/platform/wine_ash_help_c${cycle}.txt" \
      && return 0
  fi
  # Software substitute accepted
  echo "PASS_SOFTWARE_SUBSTITUTE: PE self-check + cross-build (wine absent or failed)" \
    >"$ART/platform/windows_note_c${cycle}.txt"
  return "$PROOF_RC_SUBSTITUTE"
}

sc_linux_container() {
  local cycle="$1"
  [[ "$SKIP_LINUX_CONTAINER" == "1" ]] && { echo "SKIP_LINUX_CONTAINER"; return "$PROOF_RC_SKIP"; }
  local musl_ash=""
  for cand in \
    "$NODE_ROOT/target/x86_64-unknown-linux-musl/release/ash" \
    "$NODE_ROOT/target/aarch64-unknown-linux-musl/release/ash"
  do
    [[ -x "$cand" ]] && musl_ash="$cand" && break
  done
  if [[ -z "$musl_ash" ]]; then
    (cd "$NODE_ROOT" && cargo build --locked -p ash --release --target aarch64-unknown-linux-musl -q) \
      >"$ART/logs/linux_musl_build_c${cycle}.log" 2>&1 || true
    musl_ash="$NODE_ROOT/target/aarch64-unknown-linux-musl/release/ash"
  fi

  # Prefer docker (host dockerd or Lima-forwarded socket)
  if [[ "$SKIP_DOCKER" != "1" ]] && command -v docker >/dev/null 2>&1 && ensure_docker_host; then
    # Docker is available, so the NAT simulation is the thing under test: a
    # failure here is a FAIL, not a reason to fall back to a substitute.
    bash "$REPO/scripts/nat_docker_sim.sh" >"$ART/logs/nat_docker_c${cycle}.log" 2>&1
    must_grep 'NAT DOCKER SIM OK\|RESULT=PASS' "$ART/logs/nat_docker_c${cycle}.log"
    # Informational: Linux ash smoke inside lima VM (x86_64 musl)
    local x86_ash="$NODE_ROOT/target/x86_64-unknown-linux-musl/release/ash"
    if [[ -x "$x86_ash" ]] && command -v limactl >/dev/null 2>&1 \
      && limactl list 2>/dev/null | grep -q 'ash-amd64-preflight.*Running'; then
      limactl shell ash-amd64-preflight -- uname -a \
        >"$ART/platform/lima_uname_c${cycle}.txt" 2>&1 || true
      limactl copy "$x86_ash" ash-amd64-preflight:/tmp/raven-ash >/dev/null 2>&1 || true
      limactl shell ash-amd64-preflight -- bash -lc \
        'chmod +x /tmp/raven-ash && /tmp/raven-ash --help' \
        >"$ART/platform/lima_ash_help_c${cycle}.txt" 2>&1 || true
    fi
    # nat_docker_sim.sh is a Docker dual-bridge TOPOLOGY check (python TCP echo,
    # no ash / raven-node / raven-swarm): a substitute, never a Raven NAT/relay PASS.
    echo "PASS_SOFTWARE_SUBSTITUTE: docker dual-bridge topology only (no Raven code ran; not a relay/NAT-traversal proof)" \
      >"$ART/platform/linux_note_c${cycle}.txt"
    return "$PROOF_RC_SUBSTITUTE"
  fi

  # Lima fallback without docker NAT
  if command -v limactl >/dev/null 2>&1; then
    local inst="ash-amd64-preflight"
    if limactl list | grep -q "$inst.*Running"; then
      limactl shell "$inst" -- uname -a >"$ART/platform/lima_uname_c${cycle}.txt"
      local x86_ash="$NODE_ROOT/target/x86_64-unknown-linux-musl/release/ash"
      if [[ -x "$x86_ash" ]]; then
        limactl copy "$x86_ash" "$inst:/tmp/raven-ash" >/dev/null 2>&1 || true
        limactl shell "$inst" -- bash -lc 'chmod +x /tmp/raven-ash && /tmp/raven-ash --help' \
          >"$ART/platform/lima_ash_help_c${cycle}.txt" 2>&1 || true
        if grep -qiE 'Usage|Raven|ash' "$ART/platform/lima_ash_help_c${cycle}.txt" 2>/dev/null; then
          echo "PASS_SOFTWARE_SUBSTITUTE: lima linux ash --help (+ uname)" \
            >"$ART/platform/linux_note_c${cycle}.txt"
          return "$PROOF_RC_SUBSTITUTE"
        fi
      fi
      echo "PASS_SOFTWARE_SUBSTITUTE: lima running (uname only); docker NAT unavailable" \
        >"$ART/platform/linux_note_c${cycle}.txt"
      return "$PROOF_RC_SUBSTITUTE"
    fi
  fi

  # Static musl binary self-check on host (file/ELF)
  if [[ -x "$musl_ash" ]]; then
    file "$musl_ash" | tee "$ART/platform/linux_file_c${cycle}.txt" | grep -qiE 'ELF'
    echo "PASS_SOFTWARE_SUBSTITUTE: musl ELF present; docker/lima runtime unavailable" \
      >"$ART/platform/linux_note_c${cycle}.txt"
    return "$PROOF_RC_SUBSTITUTE"
  fi
  echo "no docker, lima or musl build available on this host"
  return "$PROOF_RC_SKIP"
}

# ---- Runner -----------------------------------------------------------------

run_scenario() {
  local name="$1" fn="$2" cycles="$3"
  local i t0 t1 elapsed rc result note
  local p=0 f=0 s=0
  log ""
  log "######## SCENARIO: $name ×$cycles ########"
  for i in $(seq 1 "$cycles"); do
    t0=$(date +%s)
    # Plain statement (never inside if/&&/||): keeps errexit live in the body.
    run_isolated "$fn" "$ART/cycles/${name}_c${i}.log" "$i"
    rc=$ISOLATED_RC
    t1=$(date +%s)
    elapsed=$((t1 - t0))
    note=""
    if [[ $rc -eq 0 ]]; then
      result=PASS
      p=$((p + 1))
    elif [[ $rc -eq $PROOF_RC_SUBSTITUTE ]]; then
      result=PASS_SOFTWARE_SUBSTITUTE
      note=$(ls "$ART/platform/"*"note_c${i}.txt" 2>/dev/null | head -1 | xargs cat 2>/dev/null \
        || echo "software substitute")
      p=$((p + 1))
    elif [[ $rc -eq $PROOF_RC_SKIP ]]; then
      result=SKIP
      note="unavailable on this host"
      s=$((s + 1))
    else
      result=FAIL
      note="rc=$rc see cycles/${name}_c${i}.log"
      f=$((f + 1))
      log "FAIL loud: $name cycle=$i rc=$rc"
    fi
    record "$name" "$i" "$result" "$note" "$elapsed" || true
    log "  [$name #$i] $result (${elapsed}s) $note"
  done
  SCENARIO_NAMES+=("$name")
  SCENARIO_PASS+=("$p")
  SCENARIO_FAIL+=("$f")
  SCENARIO_SKIP+=("$s")
  SCENARIO_NOTES+=("cycles=$cycles")
  return 0
}

# Critical paths get more iterations; platform probes fewer.
# Bash 3.2 (macOS /bin/bash) has no ?: in arithmetic — use if/else.
CRIT_ITERS="$ITERS"
if [[ "$ITERS" -gt 2 ]]; then
  LIGHT_ITERS=3
  PLATFORM_ITERS=2
  IOS_ITERS=2
else
  LIGHT_ITERS="$ITERS"
  PLATFORM_ITERS=1
  IOS_ITERS=1
fi

log "=== Raven reliability matrix 20× ==="
log "run_id=$RUN_ID"
log "art=$ART"
log "ITERS=$ITERS MIN_TOTAL_PASS=$MIN_TOTAL_PASS"
log "host=$(uname -srm)"
log "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if ! ensure_bins; then
  log "HARD FAIL — could not build the lab binaries"
  exit 1
fi

run_scenario "01_internet_hold_swarm"    sc_internet_hold_and_swarm    "$CRIT_ITERS"
run_scenario "02_mesh_relay"             sc_mesh_relay                 "$CRIT_ITERS"
run_scenario "03_bridge_up"              sc_bridge_up                  "$LIGHT_ITERS"
run_scenario "04_bridge_down_up"         sc_bridge_down_up             "$LIGHT_ITERS"
run_scenario "05_bridge_crash_restart"   sc_bridge_crash_restart       "$LIGHT_ITERS"
run_scenario "06_find_contact"           sc_find_contact               "$CRIT_ITERS"
run_scenario "07_offline_mailbox"        sc_offline_mailbox            "$CRIT_ITERS"
run_scenario "08_duplicate_multipath"    sc_duplicate_multipath        "$CRIT_ITERS"
run_scenario "09_tamper_replay"          sc_tamper_replay              "$CRIT_ITERS"
run_scenario "10_fastapi_bootstrap_off"  sc_fastapi_bootstrap_disabled "$CRIT_ITERS"
run_scenario "11_ash_close_service"      sc_ash_close_service          "$CRIT_ITERS"
run_scenario "12_ios_iphone_sim"         sc_ios_iphone                 "$IOS_ITERS"
run_scenario "13_ios_ipad_sim"           sc_ios_ipad                   "$IOS_ITERS"
run_scenario "14_windows_ash"            sc_windows_wine               "$PLATFORM_ITERS"
run_scenario "15_linux_container"        sc_linux_container            "$PLATFORM_ITERS"

# Software scenarios 01-11 have no legitimate reason to skip (only the platform
# probes 12-15 can be unavailable on a host): a SKIP there is a hidden failure,
# and skips are not subtracted from the pass total.
SOFT_SKIP=0
for i in 0 1 2 3 4 5 6 7 8 9 10; do
  SOFT_SKIP=$((SOFT_SKIP + ${SCENARIO_SKIP[$i]:-0}))
done

# Write table
{
  echo "# Reliability 20× results"
  echo
  echo "| Scenario | Pass | Fail | Skip | Notes |"
  echo "|----------|------|------|------|-------|"
  for i in "${!SCENARIO_NAMES[@]}"; do
    echo "| ${SCENARIO_NAMES[$i]} | ${SCENARIO_PASS[$i]} | ${SCENARIO_FAIL[$i]} | ${SCENARIO_SKIP[$i]} | ${SCENARIO_NOTES[$i]} |"
  done
  echo
  echo "- **total_pass_or_substitute:** $PASS"
  echo "- **total_fail:** $FAIL"
  echo "- **total_skip:** $SKIP"
  echo "- **software_skips (scenarios 01-11, must be 0):** $SOFT_SKIP"
  echo "- **substitutes:** $SUBST"
  echo "- **min_required:** $MIN_TOTAL_PASS"
} | tee "$TABLE"

{
  echo "# Reliability matrix SUMMARY"
  echo
  echo "- **run_id:** \`$RUN_ID\`"
  echo "- **utc:** $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- **pass (+ substitutes):** $PASS"
  echo "- **fail:** $FAIL"
  echo "- **skip:** $SKIP"
  echo "- **verdict:** $([[ $FAIL -eq 0 && $SOFT_SKIP -eq 0 && $PASS -ge $MIN_TOTAL_PASS ]] && echo 'RELIABILITY_20_GREEN' || echo 'RELIABILITY_20_RED')"
  echo
  cat "$TABLE"
  echo
  echo "## Claim"
  echo
  echo "Software communication paths exercised in a looped matrix. Physical BLE radios,"
  echo "public CGNAT/DCUtR, notarization, and external review remain out of band."
} >"$SUMMARY"

log ""
log "=== FINAL pass=$PASS fail=$FAIL skip=$SKIP subst=$SUBST ==="
cat "$SUMMARY" | tee -a "$TRANSCRIPT"
ln -sfn "reliability_20_$RUN_ID" "$NODE_ROOT/proof_artifacts/LATEST_RELIABILITY" 2>/dev/null || true
echo "reliability_20_$RUN_ID" >"$NODE_ROOT/proof_artifacts/LATEST_RELIABILITY_ID.txt"

if [[ "$FAIL" -gt 0 ]]; then
  log "HARD FAIL — see $ART"
  exit 1
fi
if [[ "$SOFT_SKIP" -gt 0 ]]; then
  log "HARD FAIL — $SOFT_SKIP software scenario cycle(s) (01-11) were SKIPPED; see $ART"
  exit 1
fi
if [[ "$PASS" -lt "$MIN_TOTAL_PASS" ]]; then
  log "PASS budget unmet ($PASS < $MIN_TOTAL_PASS)"
  exit 1
fi
log "RELIABILITY_20_GREEN artifacts=$ART"
exit 0
