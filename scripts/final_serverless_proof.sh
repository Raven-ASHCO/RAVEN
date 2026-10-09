#!/usr/bin/env bash
# §59 Final Serverless Proof — automatable software harness.
#
# Records every step that can run without Apple Developer certs, hired auditors,
# or physical phones the operator must drive. Hardware leftovers are listed in
# BLOCKED.md — this script does NOT claim full §59 DoD.
#
# LAB BUILD: the transport steps use `--features raven-node/unsafe-demo-crypto`
# and `--body-mode unsafe-interim`, whose pairwise key is derived from the two
# PUBLIC keys. Any observer that knows both public keys — including the bridge —
# can derive it. The plaintext checks below therefore prove only that the bridge
# does not log or store the plaintext, NOT that it cannot read it. Default builds
# refuse origination (ATSAM_SESSION_REQUIRED); see step 14.
#
# Every step body runs through run_isolated (scripts/lib/proof_assert.sh) so a
# failing command or assertion anywhere in the body fails the step. The old
# `( ... ) && step_ok || step_fail` form only honoured each step's last command.
#
# Artifacts (no secrets): node/proof_artifacts/<run-id>/
# Usage: bash scripts/final_serverless_proof.sh            # full run
#        bash scripts/final_serverless_proof.sh --self-test # harness self-test only
# Exit 0 only when all automated checks pass.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
NODE_ROOT="$REPO/node"
# shellcheck source=scripts/lib/proof_assert.sh
source "$REPO/scripts/lib/proof_assert.sh"
# shellcheck source=scripts/lib/harness_util.sh
source "$REPO/scripts/lib/harness_util.sh"

# Redact anything that looks like a seed / private key from copied logs.
# Python, not sed: BSD sed (macOS) has no `\b`, so the old `sed -E 's/\b...\b/'`
# silently redacted nothing there, and its `|| cp "$src" "$dst"` fallback then put
# the RAW file into redacted/. Now any failure removes the destination and fails.
# Drops lines mentioning seed/private; replaces every standalone 64-hex run.
redact_copy() {
  local src="$1" dst="$2"
  python3 - "$src" "$dst" <<'PY' || { rm -f "$dst"; return 1; }
import re, sys
drop = re.compile(rb"[Ss]eed|[Pp]rivate.?key|identity\.seed")
hex64 = re.compile(rb"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
with open(sys.argv[1], "rb") as src, open(sys.argv[2], "wb") as dst:
    for line in src:
        if not drop.search(line):
            dst.write(hex64.sub(b"<PUB_OR_HEX_REDACTED>", line))
PY
}

# Proves redact_copy really redacts on THIS platform (the BSD-sed no-op went
# unnoticed): a 64-hex run (also adjacent runs, and at line ends) must be replaced
# and a seed line dropped.
redact_selftest() {
  local d h
  d="$(mktemp -d "${TMPDIR:-/tmp}/redact-selftest.XXXXXX")"
  h="$(printf 'ab%.0s' {1..32})"
  printf 'pub_hex=%s\n%s %s\nplain line\nseed=%s\n' "$h" "$h" "$h" "$h" >"$d/in"
  redact_copy "$d/in" "$d/out" || { echo "REDACT SELF-TEST FAILED: redact_copy errored" >&2; rm -rf "$d"; exit 97; }
  printf 'pub_hex=<PUB_OR_HEX_REDACTED>\n<PUB_OR_HEX_REDACTED> <PUB_OR_HEX_REDACTED>\nplain line\n' >"$d/want"
  if ! cmp -s "$d/out" "$d/want"; then
    echo "REDACT SELF-TEST FAILED: 64-hex not redacted or seed line kept" >&2
    cat "$d/out" >&2
    rm -rf "$d"
    exit 97
  fi
  rm -rf "$d"
  echo "redaction self-test OK"
}

# Refuse to record anything unless errexit / negative assertions really work here.
proof_harness_selftest
redact_selftest
if [[ "${1:-}" == "--self-test" ]]; then
  exit 0
fi

source "${HOME}/.cargo/env" 2>/dev/null || true
# Debug/lab identity + chat-history override (refused in Release): keeps the
# ephemeral proof identities out of the login Keychain / Secret Service, and
# stops `ash` from redirecting temp data-dirs to the operator's ~/.raven.
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ART="$NODE_ROOT/proof_artifacts/$RUN_ID"
mkdir -p "$ART"/{logs,steps,redacted}
SUMMARY="$ART/SUMMARY.md"
TRANSCRIPT="$ART/transcript.log"
PASS=0
FAIL=0
SKIP=0

log() { echo "$*" | tee -a "$TRANSCRIPT"; }
step_begin() {
  local name="$1"
  STEP_NAME="$name"
  STEP_LOG="$ART/steps/${name}.log"
  log ""
  log "======== STEP: $name ========"
}
step_ok() {
  PASS=$((PASS + 1))
  echo "PASS" >"$ART/steps/${STEP_NAME}.result"
  log "OK: $STEP_NAME"
}
step_fail() {
  FAIL=$((FAIL + 1))
  echo "FAIL: $*" >"$ART/steps/${STEP_NAME}.result"
  log "FAIL: $STEP_NAME — $*"
}

# run_step NAME WHAT FN — FN's whole body is enforced (see header).
# Must be called as a plain statement, never from if / && / ||.
run_step() {
  local name="$1" what="$2" fn="$3"
  step_begin "$name"
  run_isolated "$fn" "$STEP_LOG"
  if [[ $ISOLATED_RC -eq 0 ]]; then
    step_ok
  else
    step_fail "$what (rc=$ISOLATED_RC; see steps/${name}.log)"
    tail -n 20 "$STEP_LOG" | sed 's/^/    | /' | tee -a "$TRANSCRIPT" || true
  fi
}

# Poll until every named file exists and is NON-EMPTY (daemons publish their bound
# addresses with create+truncate then write, so a bare existence test can see an
# empty file). 15 s budget; the loop exits as soon as they are all there.
wait_for_files() {
  local _i f missing
  for _i in $(seq 1 150); do
    missing=0
    for f in "$@"; do [[ -s "$f" ]] || missing=1; done
    [[ $missing -eq 0 ]] && return 0
    sleep 0.1
  done
  fail_assert "timed out waiting for non-empty: $*"
}

cleanup() {
  [[ -n "${WORKDIR:-}" && -d "$WORKDIR" ]] && rm -rf "$WORKDIR" || true
}
trap cleanup EXIT

# Write SUMMARY.md + BLOCKED.md and exit with the verdict.
finish() {
  local verdict=AUTOMATED_PROOF_RED
  [[ $FAIL -eq 0 && $PASS -gt 0 ]] && verdict=AUTOMATED_PROOF_GREEN
  # Documentation of what this harness cannot prove — not a check, not counted.
  cat >"$ART/BLOCKED.md" <<'BLOCKED'
# Not claimed by this automated run

## LAB_CRYPTO
- Transport steps use the unsafe-demo-crypto interim sealer (key derived from
  public keys). Bridge "blindness" under production ATSAM sessions is NOT shown.

## BLOCKED_HARDWARE
- Physical 3-phone BLE mesh with real radios
- Real CGNAT / multi-NAT / DCUtR hole-punch on public Internet
- Headless desktop CoreBluetooth GATT radio (see feature `corebluetooth` stub)
- Fresh Linux/Windows install on a clean machine (release tarball prep exists; operator must install)

## BLOCKED_HUMAN
- Apple notarization / Developer ID signing
- Windows Authenticode / MSI store signing
- Hired external protocol/crypto auditors (packet ready: docs/EXTERNAL_REVIEW_PACKET.md)
- Live credential rotation decisions from secret scan

See docs/PHYSICAL_BLE_THREE_DEVICE.md and docs/SIGNING_NOTARIZATION_CHECKLIST.md.
BLOCKED
  {
    echo "# §59 Automated Proof Summary"
    echo
    echo "- **run_id:** \`$RUN_ID\`"
    echo "- **utc:** $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "- **pass:** $PASS"
    echo "- **fail:** $FAIL"
    echo "- **skip:** $SKIP"
    echo "- **verdict:** $verdict"
    echo
    echo "## Claim"
    echo
    echo '**IMPLEMENTATION + PROOF HARNESS COMPLETE** for automatable §59 software steps (lab build).'
    echo
    echo 'This is **not** marketing READY / full §59 DoD, and bridged steps use the'
    echo 'unsafe-demo-crypto interim sealer. Hardware, human and production-crypto gates remain (BLOCKED.md).'
    echo
    echo "## Steps"
    echo
    for r in "$ART"/steps/*.result; do
      [[ -f "$r" ]] || continue
      bn=$(basename "$r" .result)
      echo "- \`$bn\`: $(cat "$r")"
    done
    echo
    echo "## Artifacts"
    echo
    echo "- transcript: \`transcript.log\`"
    echo "- steps/: full log of every step body"
    echo "- logs/: raw (public bits only; scrubbed of seeds)"
    echo "- redacted/: further hex-scrubbed copies"
    echo "- BLOCKED.md: hardware/human/lab-crypto leftovers"
  } >"$SUMMARY"

  log ""
  log "=== SUMMARY pass=$PASS fail=$FAIL skip=$SKIP ==="
  log "artifacts: $ART"
  tee -a "$TRANSCRIPT" <"$SUMMARY"

  # Pointer for latest
  ln -sfn "$RUN_ID" "$NODE_ROOT/proof_artifacts/LATEST" 2>/dev/null || true
  echo "$RUN_ID" >"$NODE_ROOT/proof_artifacts/LATEST_RUN_ID.txt"

  if [[ "$verdict" == AUTOMATED_PROOF_GREEN ]]; then
    exit 0
  fi
  exit 1
}

log "=== Raven §59 Final Serverless Proof (automated) ==="
log "run_id=$RUN_ID"
log "repo=$REPO"
log "artifacts=$ART"
log "host=$(uname -srm)"
log "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
step_00_build() {
  cd "$NODE_ROOT"
  cargo build --locked -p raven-node -p ash -p raven-swarm --features raven-node/unsafe-demo-crypto -q
}
run_step "00_build" "cargo build" step_00_build
BIN="$NODE_ROOT/target/debug"
NODE="$BIN/raven-node"
ASH="$BIN/ash"
SWARM="$BIN/raven-swarm"
if [[ ! -x "$NODE" || ! -x "$ASH" || ! -x "$SWARM" ]]; then
  log "binaries missing — cannot continue"
  finish
fi

# Keep this short anyway: raven-node binds <data-dir>/raven-node.sock, and AF_UNIX
# paths are limited to ~104 bytes on macOS (long $TMPDIR under /var/folders). A
# longer data dir still works (the daemon falls back to /tmp/raven-<uid>/...), but
# the steps below probe readiness with `ash ipc-ping` (raven_ipc_up), never by
# looking for the socket file.
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rs59.XXXXXX")"
mkdir -p "$WORKDIR"/{terminal,mobile,bridge,store}

# ---------------------------------------------------------------------------
step_01_init() {
  "$ASH" --data-dir "$WORKDIR/terminal" init | tee "$ART/logs/terminal_init.txt"
  "$ASH" --data-dir "$WORKDIR/mobile" init | tee "$ART/logs/mobile_init.txt"
  "$NODE" init --data-dir "$WORKDIR/bridge" | tee "$ART/logs/bridge_init.txt"
  "$NODE" init --data-dir "$WORKDIR/store" | tee "$ART/logs/store_init.txt"
  must_grep '^address=rvn' "$ART/logs/terminal_init.txt"
  must_grep '^fingerprint=' "$ART/logs/terminal_init.txt"
  must_grep '^pub_hex=' "$ART/logs/terminal_init.txt"
  must_grep '^pub_hex=' "$ART/logs/mobile_init.txt"
  must_grep '^pub_hex=' "$ART/logs/bridge_init.txt"
  # Never print seed (all four identities, not just the first)
  must_not_grep -iE 'seed=|private' "$ART/logs/terminal_init.txt" "$ART/logs/mobile_init.txt" \
    "$ART/logs/bridge_init.txt" "$ART/logs/store_init.txt"
}
run_step "01_fresh_dirs_ash_init" "init" step_01_init

init_field() { grep "^$2=" "$1" 2>/dev/null | head -1 | cut -d= -f2 || true; }
TERM_ADDR=$(init_field "$ART/logs/terminal_init.txt" address)
TERM_PUB=$(init_field "$ART/logs/terminal_init.txt" pub_hex)
TERM_FP=$(init_field "$ART/logs/terminal_init.txt" fingerprint)
MOB_ADDR=$(init_field "$ART/logs/mobile_init.txt" address)
MOB_PUB=$(init_field "$ART/logs/mobile_init.txt" pub_hex)
MOB_FP=$(init_field "$ART/logs/mobile_init.txt" fingerprint)
BR_PUB=$(init_field "$ART/logs/bridge_init.txt" pub_hex)
if [[ -z "$TERM_ADDR" || -z "$TERM_PUB" || -z "$TERM_FP" || -z "$MOB_ADDR" \
  || -z "$MOB_PUB" || -z "$MOB_FP" || -z "$BR_PUB" ]]; then
  log "identity init produced no public fields — cannot continue"
  finish
fi

# ---------------------------------------------------------------------------
step_02_whoami() {
  "$ASH" --data-dir "$WORKDIR/terminal" whoami | tee "$ART/logs/terminal_whoami.txt"
  must_grep -F "$TERM_ADDR" "$ART/logs/terminal_whoami.txt"
  must_grep -F "$TERM_FP" "$ART/logs/terminal_whoami.txt"
}
run_step "02_identity_display" "whoami" step_02_whoami

# ---------------------------------------------------------------------------
step_03_contact() {
  "$ASH" --data-dir "$WORKDIR/terminal" contact add \
    --address "$MOB_ADDR" \
    --pub-hex "$MOB_PUB" \
    --petname "Offline Mobile" \
    --tag "mobile" \
    --verify-fp "$MOB_FP" | tee "$ART/logs/contact_add.txt"
  must_grep -i 'contact saved' "$ART/logs/contact_add.txt"
  must_grep -iE 'pinned|fingerprint' "$ART/logs/contact_add.txt"
  "$ASH" --data-dir "$WORKDIR/terminal" contact verify --tag mobile | tee "$ART/logs/contact_verify.txt"
  "$ASH" --data-dir "$WORKDIR/terminal" contact list | tee "$ART/logs/contact_list.txt"
  must_grep 'Offline Mobile' "$ART/logs/contact_list.txt"
  # Refuse live routing hints — allow the explicit "no FastAPI" safety string.
  must_not_grep -iE 'localhost:8000|/api/messages|legacy_fastapi' "$ART/logs/contact_add.txt"
  must_grep -i 'no FastAPI' "$ART/logs/contact_add.txt"
}
run_step "03_contact_add_verify" "contact" step_03_contact

# ---------------------------------------------------------------------------
step_04_fastapi() {
  "$ASH" --data-dir "$WORKDIR/terminal" doctor | tee "$ART/logs/doctor.txt"
  must_grep 'serverless_rvn1' "$ART/logs/doctor.txt"
  must_grep -i 'never silently uses FastAPI' "$ART/logs/doctor.txt"
  # Refuse if the doctor reports FastAPI as the active path.
  must_not_grep -iE 'legacy_fastapi.*(active|selected|using)' "$ART/logs/doctor.txt"
}
run_step "04_fastapi_not_in_path" "fastapi path" step_04_fastapi

# ---------------------------------------------------------------------------
step_05_bootstrap() {
  "$ASH" --data-dir "$WORKDIR/terminal" node disable-raven-defaults | tee "$ART/logs/boot_disable.txt"
  "$ASH" --data-dir "$WORKDIR/terminal" node show-bootstrap | tee "$ART/logs/boot_show.txt"
  "$SWARM" bootstrap-init \
    --data-dir "$WORKDIR/terminal" \
    --manual-peer "127.0.0.1:9" \
    --no-raven-defaults
  "$SWARM" bootstrap-show --data-dir "$WORKDIR/terminal" | tee "$ART/logs/boot_manual.txt"
  must_grep 'manual_peer_only=true' "$ART/logs/boot_manual.txt"
  must_grep 'use_raven_defaults=false' "$ART/logs/boot_manual.txt"
}
run_step "05_bootstrap_disabled_manual_peer" "bootstrap" step_05_bootstrap

# ---------------------------------------------------------------------------
step_06_store_forward() {
  local marker="s59-offline-store-forward"
  # Bridge/store online; mobile (C) offline. Terminal sends → store/forward.
  "$ASH" --data-dir "$WORKDIR/bridge" node bridge on
  "$ASH" --data-dir "$WORKDIR/bridge" node store on
  rm -f "$WORKDIR/b.lan" "$WORKDIR/b.ble"
  "$NODE" bridge \
    --data-dir "$WORKDIR/bridge" \
    --lan-listen "127.0.0.1:0" \
    --ble-listen "127.0.0.1:0" \
    --write-lan-addr "$WORKDIR/b.lan" \
    --write-ble-addr "$WORKDIR/b.ble" \
    --write-status "$WORKDIR/b.status.json" \
    --timeout-secs 55 \
    >"$ART/logs/bridge_scf.log" 2>&1 &
  local BPID=$!
  wait_for_files "$WORKDIR/b.lan" "$WORKDIR/b.ble"
  local B_LAN B_BLE
  B_LAN=$(cat "$WORKDIR/b.lan")
  B_BLE=$(cat "$WORKDIR/b.ble")

  # A sends while C offline — expect queue / eventual ACK after C joins
  printf '%s\n' "$marker" | "$NODE" run \
    --data-dir "$WORKDIR/terminal" \
    --listen "127.0.0.1:0" \
    --peer "$B_LAN" \
    --peer-pub-hex "$BR_PUB" \
    --seal-to-pub-hex "$MOB_PUB" \
    --ack-pub-hex "$MOB_PUB" \
    --send-stdin --body-mode unsafe-interim \
    --exit-after-ack \
    --timeout-secs 45 \
    >"$ART/logs/terminal_scf.log" 2>&1 &
  local APID=$!
  # Start the mobile only once the bridge has logged that it queued the frame
  # (no mock_ble peer yet). A fixed sleep let a slow sender start after the mobile
  # had attached, so a plain live forward passed as "store-and-forward".
  raven_wait_log "$ART/logs/bridge_scf.log" 'BRIDGE (queued waiting|store-carry)' "$BPID" 15
  # Informational only: outbox / forward activity before mobile online.
  "$ASH" --data-dir "$WORKDIR/bridge" status >"$ART/logs/bridge_status_mid.txt" 2>&1 || true

  # Mobile comes online on mock BLE
  "$NODE" run \
    --data-dir "$WORKDIR/mobile" \
    --listen "127.0.0.1:0" \
    --peer "$B_BLE" \
    --peer-pub-hex "$TERM_PUB" \
    --origin-pub-hex "$TERM_PUB" \
    --exit-after-recv 1 \
    --timeout-secs 40 \
    >"$ART/logs/mobile_scf.log" 2>&1 &
  local CPID=$!
  local a_rc=0 c_rc=0
  wait "$APID" || a_rc=$?
  wait "$CPID" || c_rc=$?
  kill "$BPID" 2>/dev/null || true
  wait "$BPID" 2>/dev/null || true
  [[ $a_rc -eq 0 ]] || fail_assert "sender exited rc=$a_rc"
  [[ $c_rc -eq 0 ]] || fail_assert "offline recipient exited rc=$c_rc"

  must_grep 'ACK delivered' "$ART/logs/terminal_scf.log"
  must_grep 'DELIVERED bytes=' "$ART/logs/mobile_scf.log"
  # The queued frame must have been flushed to the mobile once it attached.
  must_grep 'BRIDGE flush → mock_ble' "$ART/logs/bridge_scf.log"
  # Sealed body: plaintext must not appear in the bridge log or anywhere in its
  # persisted state (queue / store DB). Lab cipher: see header — this shows the
  # bridge does not record plaintext, not that it could not derive the key.
  must_not_grep -F "$marker" "$ART/logs/bridge_scf.log"
  if grep -rqaF "$marker" "$WORKDIR/bridge"; then
    fail_assert "plaintext marker found in bridge data-dir state"
  fi
  must_not_grep -iE 'fastapi|/api/' "$ART/logs/terminal_scf.log" "$ART/logs/mobile_scf.log" "$ART/logs/bridge_scf.log"
}
run_step "06_offline_recipient_queue_store_forward" "store-forward" step_06_store_forward

# ---------------------------------------------------------------------------
step_07_service() {
  # Start raven-node service (bridge+ipc). "Close ash" = ash process ends;
  # service must still answer ipc-ping.
  "$ASH" --data-dir "$WORKDIR/bridge" node bridge on
  "$NODE" service \
    --data-dir "$WORKDIR/bridge" \
    --lan-listen "127.0.0.1:0" \
    --ble-listen "127.0.0.1:0" \
    --timeout-secs 0 \
    >"$ART/logs/service.log" 2>&1 &
  local SERVICE_PID=$!
  local _i
  for _i in $(seq 1 120); do
    raven_ipc_up "$ASH" "$WORKDIR/bridge" && break
    sleep 0.05
  done
  raven_ipc_up "$ASH" "$WORKDIR/bridge" || fail_assert "service never answered IPC for $WORKDIR/bridge"
  # Simulate ash session then exit
  "$ASH" --data-dir "$WORKDIR/bridge" status | tee "$ART/logs/ash_before_exit.txt"
  "$ASH" --data-dir "$WORKDIR/bridge" ipc-ping | tee "$ART/logs/ipc_ping1.txt"
  must_grep 'ipc pong' "$ART/logs/ipc_ping1.txt"
  # ash has exited; service still up
  sleep 0.2
  kill -0 "$SERVICE_PID" || fail_assert "service died after ash exit"
  "$ASH" --data-dir "$WORKDIR/bridge" ipc-ping | tee "$ART/logs/ipc_ping2.txt"
  must_grep 'ipc pong' "$ART/logs/ipc_ping2.txt"
  kill "$SERVICE_PID" 2>/dev/null || true
  wait "$SERVICE_PID" 2>/dev/null || true
}
run_step "07_service_survives_ash_exit" "service survives ash" step_07_service

# ---------------------------------------------------------------------------
step_08_ack() {
  # Direct two-node: send → ACK → Delivered state on sender queue
  rm -f "$WORKDIR/mob.listen"
  "$NODE" run \
    --data-dir "$WORKDIR/mobile" \
    --listen "127.0.0.1:0" \
    --write-addr "$WORKDIR/mob.listen" \
    --peer-pub-hex "$TERM_PUB" \
    --exit-after-recv 1 \
    --timeout-secs 25 \
    >"$ART/logs/ack_recv.log" 2>&1 &
  local CPID=$!
  wait_for_files "$WORKDIR/mob.listen"
  local MOB_LISTEN
  MOB_LISTEN=$(cat "$WORKDIR/mob.listen")
  printf '%s\n' "s59-ack-delivered" | "$NODE" run \
    --data-dir "$WORKDIR/terminal" \
    --listen "127.0.0.1:0" \
    --peer "$MOB_LISTEN" \
    --peer-pub-hex "$MOB_PUB" \
    --send-stdin --body-mode unsafe-interim \
    --exit-after-ack \
    --timeout-secs 25 \
    >"$ART/logs/ack_send.log" 2>&1
  local c_rc=0
  wait "$CPID" || c_rc=$?
  [[ $c_rc -eq 0 ]] || fail_assert "receiver exited rc=$c_rc"
  # raven-node prints "ACK delivered" only after the sender's queue entry was
  # committed to DeliveryState::Delivered (main.rs), so this IS the delivered-state
  # assertion; `ash status` has no per-message state and is recorded for the log only.
  must_grep 'ACK delivered' "$ART/logs/ack_send.log"
  must_grep 'DELIVERED' "$ART/logs/ack_recv.log"
  "$ASH" --data-dir "$WORKDIR/terminal" status | tee "$ART/logs/terminal_status_after_ack.txt"
}
run_step "08_ack_delivered_status" "ack/delivered" step_08_ack

# ---------------------------------------------------------------------------
step_09_bridge_abc() {
  # Delegate to the standalone demo (its own asserts are enforced) and
  # require every milestone banner.
  bash "$NODE_ROOT/scripts/bridge_abc_demo.sh" | tee "$ART/logs/bridge_abc_demo.log"
  must_grep 'store-carry OK' "$ART/logs/bridge_abc_demo.log"
  must_grep 'reverse path OK' "$ART/logs/bridge_abc_demo.log"
  must_grep 'bridge logs hold no plaintext' "$ART/logs/bridge_abc_demo.log"
  must_grep 'ALL BRIDGE A-B-C CHECKS PASSED' "$ART/logs/bridge_abc_demo.log"
}
run_step "09_bridge_abc_both_directions" "bridge abc" step_09_bridge_abc

# ---------------------------------------------------------------------------
step_10_dedup() {
  # bridge_v1 integration tests (dedup cases). pipefail makes a failing
  # cargo test fail the step; the grep only rejects a vacuous 0-test run.
  (cd "$NODE_ROOT" && cargo test --locked -p raven-core --test bridge_v1 -- --nocapture) \
    | tee "$ART/logs/bridge_v1_dedup.log"
  must_grep -E 'test result: ok\. [1-9][0-9]* passed' "$ART/logs/bridge_v1_dedup.log"
}
run_step "10_duplicate_suppression" "dedup" step_10_dedup

# ---------------------------------------------------------------------------
step_11_mailbox() {
  bash "$NODE_ROOT/scripts/mailbox_opaque_smoke.sh" | tee "$ART/logs/mailbox.log"
  must_grep 'OK mailbox' "$ART/logs/mailbox.log"
}
run_step "11_mailbox_opaque" "mailbox" step_11_mailbox

# ---------------------------------------------------------------------------
step_12_manual_boot() {
  bash "$NODE_ROOT/scripts/bootstrap_manual_peer_smoke.sh" | tee "$ART/logs/manual_boot.log"
  must_grep 'MANUAL-PEER-ONLY BOOTSTRAP SMOKE OK' "$ART/logs/manual_boot.log"
}
run_step "12_manual_peer_bootstrap_smoke" "manual bootstrap" step_12_manual_boot

# ---------------------------------------------------------------------------
step_13_swarm() {
  bash "$NODE_ROOT/scripts/libp2p_swarm_smoke.sh" | tee "$ART/logs/swarm.log"
  must_grep 'LIBP2P SWARM SMOKE OK' "$ART/logs/swarm.log"
}
run_step "13_libp2p_swarm_smoke" "swarm" step_13_swarm

# ---------------------------------------------------------------------------
step_14_lan_internet() {
  # Includes the fail-closed origination checks (atsam body mode refused with
  # ATSAM_SESSION_REQUIRED on both the LAN and the legacy Internet carrier).
  bash "$NODE_ROOT/scripts/lan_path_smoke.sh" | tee "$ART/logs/lan.log"
  must_grep 'mode=failclosed OK' "$ART/logs/lan.log"
  must_grep 'LAN PATH SMOKE PASSED' "$ART/logs/lan.log"
  bash "$NODE_ROOT/scripts/internet_dial_smoke.sh" | tee "$ART/logs/internet.log"
  must_grep 'PASS: legacy InternetTransport remains fail-closed' "$ART/logs/internet.log"
  bash "$NODE_ROOT/scripts/internet_indexed_two_node.sh" | tee "$ART/logs/internet_indexed.log"
  must_grep 'INTERNET_INDEXED_TWO_NODE_PASS' "$ART/logs/internet_indexed.log"
  bash "$NODE_ROOT/scripts/two_node_demo.sh" | tee "$ART/logs/two_node.log"
  must_grep 'ALL DEMO CHECKS PASSED' "$ART/logs/two_node.log"
}
run_step "14_lan_smoke_internet_hold" "lan/internet/two-node" step_14_lan_internet

# ---------------------------------------------------------------------------
step_15_secrets() {
  # Scan EVERYTHING the workflow uploads, not just logs/: stderr of tee'd commands
  # (e.g. `ash init`) only reaches steps/*.log and transcript.log. This step's own
  # log is skipped (it is being written by the same redirect). -l lists file names
  # only, so a match is never echoed back into the artifacts being uploaded.
  # grep rc: 0 = match (fail), 1 = clean (pass), anything else = scan error (fail).
  local rc=0 hits="$WORKDIR/secret_hits.txt"
  grep -rliE 'seed=[0-9a-f]{64}|private.?key.?=|BEGIN (RSA |OPENSSH |EC )?PRIVATE' "$ART" \
    --exclude='15_no_secrets_in_artifacts.*' >"$hits" 2>/dev/null || rc=$?
  case "$rc" in
    1) ;;
    0) fail_assert "secret-like material found in artifact file(s): $(tr '\n' ' ' <"$hits")" ;;
    *) fail_assert "secret scan could not run (grep rc=$rc)" ;;
  esac
  # Produce redacted copies, then prove the claim: no standalone 64-hex remains.
  local f base
  for f in "$ART"/logs/*.log "$ART"/logs/*.txt; do
    [[ -f "$f" ]] || continue
    base=$(basename "$f")
    redact_copy "$f" "$ART/redacted/$base"
  done
  must_not_grep -rE '(^|[^0-9a-fA-F])[0-9a-fA-F]{64}($|[^0-9a-fA-F])' "$ART/redacted"
  echo "redacted copies under redacted/"
}
run_step "15_no_secrets_in_artifacts" "secret scrub" step_15_secrets

finish
