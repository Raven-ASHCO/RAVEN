#!/usr/bin/env bash
# O6 M3 lab execute: two-process localhost Raven↔RDAP encrypted path.
#
# NON-RELEASE / HOLD active. Two logical devices on 127.0.0.1.
# Uses existing SealUnderSession (RDAP plaintext-to-daemon) + already-sealed
# LanDial (ash lab lan-dial-sealed). Does not flip PRODUCTION_ENABLED.
# Does not use unsafe-demo-crypto. mock_ble is untouched.
#
# CLAIM (exact):
#   Proven: lab localhost two-process encrypted Raven↔RDAP path under HOLD
#   Not Proven: O6 E2E, HOLD lift, WAN, confidential RDAP delivery,
#               RDAP ask-over-atsam_rvn1, physical two-device
#
# Matrix:
#   UNIT        — RDAP .venv/bin/python -m team_agents.selftest --unit
#   PIN         — mutual ash contact pin + M1 same-RVN1 pin files (D3)
#   RED         — raven-node up, no ATSAM session → ATSAM_SESSION_REQUIRED
#   GREEN       — two nodes, session via LAN send, RDAP seal, LanDial envelope,
#                 Bob inbox contains RAVEN_A2A_OK_M3_LAB
#   RED session — seal against never-paired hint → ATSAM_SESSION_REQUIRED
#   BLOCKED_HARDWARE — physical two-device WAN (this host has no second NIC/WAN peer)
#
# Env:
#   RDAP_HOME     existing checkout of raven-distributed-agent-protocol
#                 (default: clone pinned SHA into the workdir)
#   RDAP_SHA      default 3207e8ea56002ff0efe0909ec9b6ec233b920c05
#   EVIDENCE_OUT  optional directory to copy captured public logs
#   RAVEN_KEEP_M3=1  keep workdir
set -euo pipefail
set +m

export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1
export NO_COLOR=1

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NODE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$NODE_ROOT/target/debug"
ASH="$BIN/ash"
NODE="$BIN/raven-node"
WORKDIR="${TMPDIR:-/tmp}/raven-o6-m3-lab-$$"
EVIDENCE_OUT="${EVIDENCE_OUT:-}"
RDAP_SHA="${RDAP_SHA:-3207e8ea56002ff0efe0909ec9b6ec233b920c05}"
RDAP_REPO="${RDAP_REPO:-https://github.com/Raven-ASHCO/raven-distributed-agent-protocol}"
BANNER='NON-RELEASE / HOLD active. two-process localhost Raven↔RDAP lab only. Not O6 E2E Proven. No HOLD lift. dial≠WAN. Soft-load P0 held. PRODUCTION_ENABLED unchanged. mock_ble untouched.'
MARKER='RAVEN_A2A_OK_M3_LAB'
A_PID=""
B_PID=""
UNIT_RC=""
RED_NO_SESSION_RC=""
GREEN_SEAL_RC=""
GREEN_DIAL_RC=""
PIN_STATUS="PENDING"
RED_SESSION_STATUS="PENDING"

fail() {
  echo "O6_M3_TWO_NODE_LAB=FAIL: $*" >&2
  echo "HOLD=ACTIVE"
  echo "CLAIM=none (not O6 E2E Proven; not HOLD lift; not confidential RDAP delivery)"
  echo "TWO_DEVICE_WAN=BLOCKED_HARDWARE"
  echo "$BANNER" >&2
  exit 1
}

cleanup() {
  if [[ -n "${A_PID}" ]]; then kill "${A_PID}" 2>/dev/null || true; fi
  if [[ -n "${B_PID}" ]]; then kill "${B_PID}" 2>/dev/null || true; fi
  sleep 0.2
  if [[ -n "${A_PID}" ]]; then kill -9 "${A_PID}" 2>/dev/null || true; fi
  if [[ -n "${B_PID}" ]]; then kill -9 "${B_PID}" 2>/dev/null || true; fi
  wait 2>/dev/null || true
  if [[ -n "${EVIDENCE_OUT}" && -d "$WORKDIR" ]]; then
    mkdir -p "$EVIDENCE_OUT"
    # Public logs only — never copy identity.seed / session secrets / sqlite.
    find "$WORKDIR" -type f \( \
        -name '*.out' -o -name '*.err' -o -name '*.stdout' \
        -o -name '*.stderr' -o -name '*.combined' -o -name '*.status' \
        -o -name '*.listen.txt' \
        -o -name 'SUMMARY.txt' -o -name 'lab.status' -o -name '*.init' \
        -o -name '*.help' -o -name '*.whoami.json' -o -name '*.pin' \
        -o -name 'o6_m1_same_rvn1.json' -o -name '*.inbox.out' \
      \) ! -path '*/.venv/*' ! -name 'identity.seed' \
      -exec bash -c 'dest="$1"; src="$2"; rel="${src#"$3"/}"; mkdir -p "$dest/$(dirname "$rel")"; cp -a "$src" "$dest/$rel"' _ "$EVIDENCE_OUT" {} "$WORKDIR" \;
  fi
  if [[ "${RAVEN_KEEP_M3:-}" == "1" ]]; then
    echo "keeping $WORKDIR" >&2
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

source "${HOME}/.cargo/env" 2>/dev/null || true
export PATH="${HOME}/.cargo/bin:/usr/local/cargo/bin:${PATH}"

echo "$BANNER"
echo "RAVEN_TIP=$(git -C "$ROOT" rev-parse HEAD)"
echo "HOLD=ACTIVE"
echo "PRODUCTION_ENABLED tripwires: not flipped (script never exports them)"
echo "TWO_DEVICE_WAN=BLOCKED_HARDWARE (localhost two-process; no physical second device / WAN peer)"
echo "WORKDIR=$WORKDIR"
mkdir -p "$WORKDIR/red" "$WORKDIR/green" "$WORKDIR/unit" "$WORKDIR/pin-a" "$WORKDIR/pin-b"

echo "=== build ash + raven-node (debug; no unsafe-demo-crypto) ==="
(cd "$NODE_ROOT" && cargo build -p raven-node -p ash -q --offline 2>/dev/null \
  || cargo build -p raven-node -p ash -q)
[[ -x "$ASH" ]] || fail "ash binary missing"
[[ -x "$NODE" ]] || fail "raven-node binary missing"

echo "=== production tripwires stay false (HOLD) ==="
"$ASH" lab status >"$WORKDIR/lab.status" 2>&1 || true
if grep -E 'pair_init::PRODUCTION_ENABLED|atsam_indexed_session::PRODUCTION_ENABLED|INDEXED_SESSION_STORE_PRODUCTION_ENABLED|PREKEY_LIFECYCLE_PRODUCTION_ENABLED|INTERNET_DIRECT_PRODUCTION_ENABLED' \
     "$WORKDIR/lab.status" | grep -E 'true' >/dev/null; then
  cat "$WORKDIR/lab.status" >&2 || true
  fail "a HOLD PRODUCTION_ENABLED tripwire is true (this pack must not flip them)"
fi
echo "LAB_STATUS_OK (HOLD tripwires remain false; LAN_DIRECT_PRODUCTION_ENABLED is pre-existing on main)"

# ── RDAP companion (client invocation against pinned tip; no RDAP code change) ─
if [[ -n "${RDAP_HOME:-}" && -x "${RDAP_HOME}/rdap" ]]; then
  RDAP_DIR="$(cd "$RDAP_HOME" && pwd)"
else
  echo "=== clone RDAP @$RDAP_SHA ==="
  git clone --depth 50 "$RDAP_REPO" "$WORKDIR/rdap"
  git -C "$WORKDIR/rdap" fetch --depth 50 origin "$RDAP_SHA"
  git -C "$WORKDIR/rdap" checkout --detach "$RDAP_SHA"
  RDAP_DIR="$WORKDIR/rdap"
fi
RDAP_TIP="$(git -C "$RDAP_DIR" rev-parse HEAD)"
echo "RDAP_TIP=$RDAP_TIP"
if [[ "$RDAP_TIP" != "$RDAP_SHA"* && "$RDAP_TIP" != "$RDAP_SHA" ]]; then
  echo "warn: RDAP HEAD $RDAP_TIP (wanted $RDAP_SHA)" >&2
fi
RDAP="$RDAP_DIR/rdap"
[[ -x "$RDAP" ]] || fail "RDAP launcher missing"

echo "=== bootstrap RDAP venv (./rdap --help) ==="
# Some lab images ship python3 without ensurepip (python3-venv package absent).
# Prefer the RDAP launcher; fall back to virtualenv so the pack stays executable.
if [[ ! -x "$RDAP_DIR/.venv/bin/python" ]] \
  || ! "$RDAP_DIR/.venv/bin/python" -m pip --version >/dev/null 2>&1; then
  if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
    echo "ensurepip=missing; bootstrapping .venv via python3 -m virtualenv (lab fallback)"
    python3 -m pip install --user virtualenv >/dev/null
    python3 -m virtualenv "$RDAP_DIR/.venv" \
      || fail "virtualenv bootstrap failed (install python3-venv or virtualenv)"
    (cd "$RDAP_DIR" && .venv/bin/python -m pip install --require-hashes -r requirements.lock.txt) \
      || fail "RDAP requirements.lock.txt install failed"
  fi
fi
(cd "$RDAP_DIR" && ./rdap --help >"$WORKDIR/unit/rdap.help" 2>&1) \
  || fail "RDAP launcher failed (see $WORKDIR/unit/rdap.help)"
[[ -x "$RDAP_DIR/.venv/bin/python" ]] || fail "RDAP .venv/bin/python missing after launcher"

echo "=== UNIT baseline: .venv/bin/python -m team_agents.selftest --unit ==="
set +e
(cd "$RDAP_DIR" && .venv/bin/python -m team_agents.selftest --unit \
  >"$WORKDIR/unit/selftest.stdout" 2>"$WORKDIR/unit/selftest.stderr")
UNIT_RC=$?
set -e
cat "$WORKDIR/unit/selftest.stdout" "$WORKDIR/unit/selftest.stderr" \
  >"$WORKDIR/unit/selftest.combined" || true
if [[ "$UNIT_RC" -ne 0 ]] || ! grep -q 'RDAP_TRY_OK' "$WORKDIR/unit/selftest.combined"; then
  tail -n 80 "$WORKDIR/unit/selftest.combined" >&2 || true
  fail "RDAP unit selftest did not pass (rc=$UNIT_RC)"
fi
UNIT_PASSED="$(grep -Eo '[0-9]+ passed' "$WORKDIR/unit/selftest.combined" | tail -n1 || true)"
echo "UNIT_BASELINE=PASS rc=$UNIT_RC ${UNIT_PASSED:-} RDAP_TRY_OK"

# RDAP at this tip has seal-under-session only. ask remains HTTP signed A2A.
if grep -q 'Important integration gap' "$RDAP_DIR/README.md"; then
  echo "RDAP_README_GAP=present (honest; D5.5 not claimed)"
else
  echo "RDAP_README_GAP=missing — do not assume M3 closed the gap paragraph"
fi
if (cd "$RDAP_DIR" && ./rdap ask --help 2>/dev/null | grep -qi 'atsam_rvn1'); then
  echo "RDAP_ASK_ATSAM=help-mentions-atsam_rvn1 (still not Proven without execute)"
else
  echo "RDAP_ASK_ATSAM=BLOCKED (tip has seal-under-session only; ask remains http_signed)"
fi

# Caller-only request shape (RDAP does not construct ATSAM locally).
PYTHONPATH="$RDAP_DIR${PYTHONPATH:+:$PYTHONPATH}" "$RDAP_DIR/.venv/bin/python" - <<'PY' || fail "RDAP raven_ipc.py request-shape assert"
from team_agents.raven_ipc import seal_under_session_request
req = seal_under_session_request("ab" * 32, b"RAVEN_A2A_OK_M3_LAB")
allowed = {"op", "v", "peer_hint", "app_payload_b64"}
if set(req) != allowed:
    raise SystemExit(f"unexpected SealUnderSession keys: {sorted(req)}")
if req["op"] != "seal_under_session":
    raise SystemExit(f"op={req['op']!r}")
for bad in ("message_ciphertext", "plaintext", "seed", "private_key", "recovery"):
    if any(bad in str(k).lower() for k in req):
        raise SystemExit(f"forbidden field {bad}")
print("RDAP_NO_LOCAL_ATSAM=PASS (caller submits app_payload_b64 only)")
PY

wait_sock() {
  local dir="$1" log="$2" marker="$3"
  for _ in $(seq 1 150); do
    if [[ -S "$dir/raven-node.sock" ]] && grep -q "$marker" "$log"; then
      return 0
    fi
    if grep -Eqi 'lan_direct failed|service identity preflight failed' "$log" 2>/dev/null; then
      cat "$log" >&2 || true
      return 1
    fi
    sleep 0.1
  done
  cat "$log" >&2 || true
  return 1
}

# ── RED: no persisted ATSAM session ───────────────────────────────────────
echo "=== RED no-session: raven-node up, identity present, no ATSAM session ==="
RED="$WORKDIR/red/data"
mkdir -p "$RED"
"$ASH" --data-dir "$RED" init | tee "$WORKDIR/red/init.out"
"$NODE" service --data-dir "$RED" --lan-listen "127.0.0.1:0" --ble-listen "127.0.0.1:0" \
  >"$WORKDIR/red/node.log" 2>&1 &
A_PID=$!
wait_sock "$RED" "$WORKDIR/red/node.log" "lan_direct: listen" \
  || fail "RED raven-node failed to bind IPC/LAN"
"$ASH" --data-dir "$RED" ipc-ping >/dev/null || fail "RED ipc-ping failed"

DUMMY_HINT="$(printf 'ab%.0s' {1..32})"
PAYLOAD_B64="$(python3 -c 'import base64,sys; print(base64.b64encode(sys.argv[1].encode()).decode())' "$MARKER")"

echo "CMD: ./rdap seal-under-session --peer-hint <ab*32> --payload-b64 <marker> --data-dir \$RED"
set +e
(cd "$RDAP_DIR" && ./rdap seal-under-session \
  --peer-hint "$DUMMY_HINT" \
  --payload-b64 "$PAYLOAD_B64" \
  --data-dir "$RED" \
  >"$WORKDIR/red/cli.stdout" 2>"$WORKDIR/red/cli.stderr")
RED_NO_SESSION_RC=$?
set -e
cat "$WORKDIR/red/cli.stdout" "$WORKDIR/red/cli.stderr" >"$WORKDIR/red/cli.combined" || true
if [[ "$RED_NO_SESSION_RC" -eq 0 ]]; then
  cat "$WORKDIR/red/cli.combined" >&2 || true
  fail "RED no-session unexpectedly succeeded"
fi
if ! grep -q 'ATSAM_SESSION_REQUIRED' "$WORKDIR/red/cli.combined"; then
  cat "$WORKDIR/red/cli.combined" >&2 || true
  fail "RED no-session missing ATSAM_SESSION_REQUIRED"
fi
if grep -q 'ATSAM_LINEAGE_REVOKED' "$WORKDIR/red/cli.combined"; then
  cat "$WORKDIR/red/cli.combined" >&2 || true
  fail "RED no-session collapsed into ATSAM_LINEAGE_REVOKED"
fi
echo "RED_NO_SESSION=PASS rc=$RED_NO_SESSION_RC ATSAM_SESSION_REQUIRED (not LINEAGE_REVOKED)"

kill "${A_PID}" 2>/dev/null || true
wait "${A_PID}" 2>/dev/null || true
A_PID=""

# ── GREEN: two logical devices / two raven-node processes ─────────────────
echo "=== GREEN: two-process localhost (Alice + Bob) ==="
export RAVEN_LAB_TEST_A=1
A="$WORKDIR/green/a"
B="$WORKDIR/green/b"
A_PORT="${A_PORT:-$((18000 + $$ % 500))}"
B_PORT="${B_PORT:-$((18500 + $$ % 500))}"
mkdir -p "$A" "$B"

"$ASH" --data-dir "$A" init | tee "$WORKDIR/green/a.init"
"$ASH" --data-dir "$B" init | tee "$WORKDIR/green/b.init"
A_ADDR=$(grep '^address=' "$WORKDIR/green/a.init" | cut -d= -f2)
B_ADDR=$(grep '^address=' "$WORKDIR/green/b.init" | cut -d= -f2)
A_PUB=$(grep '^pub_hex=' "$WORKDIR/green/a.init" | cut -d= -f2)
B_PUB=$(grep '^pub_hex=' "$WORKDIR/green/b.init" | cut -d= -f2)
test -n "$A_ADDR" && test -n "$B_ADDR" && test -n "$A_PUB" && test -n "$B_PUB"
"$ASH" --data-dir "$A" prekey publish
"$ASH" --data-dir "$B" prekey publish

"$ASH" --data-dir "$A" whoami --json | tee "$WORKDIR/green/a.whoami.json"
"$ASH" --data-dir "$B" whoami --json | tee "$WORKDIR/green/b.whoami.json"

echo "=== M1 same-RVN1 pin files (public only; two RDAP homes) ==="
set +e
"$ROOT/scripts/o6_m1_same_rvn1_bind.sh" \
  --rdap-home "$WORKDIR/pin-a" \
  --whoami-json "$WORKDIR/green/a.whoami.json" \
  >"$WORKDIR/green/a.bind.out" 2>"$WORKDIR/green/a.bind.err"
BIND_A_RC=$?
"$ROOT/scripts/o6_m1_same_rvn1_bind.sh" \
  --rdap-home "$WORKDIR/pin-b" \
  --whoami-json "$WORKDIR/green/b.whoami.json" \
  >"$WORKDIR/green/b.bind.out" 2>"$WORKDIR/green/b.bind.err"
BIND_B_RC=$?
set -e
if [[ "$BIND_A_RC" -eq 0 && "$BIND_B_RC" -eq 0 ]] \
  && grep -q 'bind=same_rvn1' "$WORKDIR/green/a.bind.out" \
  && grep -q 'bind=same_rvn1' "$WORKDIR/green/b.bind.out"; then
  PIN_STATUS="PASS"
  echo "PIN_M1=PASS (Alice + Bob same-RVN1 public pin files; no seed copy)"
else
  cat "$WORKDIR/green/a.bind.out" "$WORKDIR/green/a.bind.err" \
    "$WORKDIR/green/b.bind.out" "$WORKDIR/green/b.bind.err" >&2 || true
  fail "M1 same-RVN1 pin bind failed"
fi

"$NODE" service --data-dir "$A" --lan-listen "127.0.0.1:${A_PORT}" --ble-listen "127.0.0.1:0" \
  >"$WORKDIR/green/a.node.log" 2>&1 &
A_PID=$!
"$NODE" service --data-dir "$B" --lan-listen "127.0.0.1:${B_PORT}" --ble-listen "127.0.0.1:0" \
  >"$WORKDIR/green/b.node.log" 2>&1 &
B_PID=$!
wait_sock "$A" "$WORKDIR/green/a.node.log" "lan_direct: listen" \
  || fail "GREEN node A failed to bind"
wait_sock "$B" "$WORKDIR/green/b.node.log" "lan_direct: listen" \
  || fail "GREEN node B failed to bind"
"$ASH" --data-dir "$A" ipc-ping >/dev/null
"$ASH" --data-dir "$B" ipc-ping >/dev/null
echo "TOPOLOGY=localhost_two_process A=127.0.0.1:${A_PORT} B=127.0.0.1:${B_PORT}"

"$ASH" --data-dir "$A" contact add \
  --address "$B_ADDR" --pub-hex "$B_PUB" --petname "Bob" --tag bob \
  --lan-dial "127.0.0.1:${B_PORT}"
"$ASH" --data-dir "$B" contact add \
  --address "$A_ADDR" --pub-hex "$A_PUB" --petname "Alice" --tag alice \
  --lan-dial "127.0.0.1:${A_PORT}"
echo "PIN_CONTACT=PASS (mutual ash contact pin of each node's RVN1)"

set +e
printf '%s\n' "hello from a (lab pair_init / session-ensure)" | "$ASH" --data-dir "$A" send --contact @bob \
  >"$WORKDIR/green/a.send.out" 2>"$WORKDIR/green/a.send.err"
SEND_RC=$?
set -e
if [[ "$SEND_RC" -ne 0 ]] || ! grep -qi 'status.*delivered' "$WORKDIR/green/a.send.out"; then
  cat "$WORKDIR/green/a.send.out" "$WORKDIR/green/a.send.err" \
    "$WORKDIR/green/a.node.log" "$WORKDIR/green/b.node.log" >&2 || true
  fail "GREEN session establish (ash send) failed rc=$SEND_RC"
fi
echo "LAB_SESSION=PASS (ash send delivered; persisted indexed ATSAM session)"

"$ASH" --data-dir "$B" lab export-cert >"$WORKDIR/green/b.export-cert.out" 2>&1 \
  || fail "ash lab export-cert failed on B"
PEER_HINT="$(python3 - <<'PY' "$B/lab_device_cert.json"
import json, sys
cert = json.load(open(sys.argv[1]))
hint = cert["device_ed_pub"]
if len(hint) != 64:
    raise SystemExit(f"device_ed_pub not 64 hex: {hint!r}")
print(hint.lower())
PY
)"
test -n "$PEER_HINT"
echo "PEER_HINT=$PEER_HINT (device Ed25519 from B lab_device_cert.json)"

echo "CMD: ./rdap seal-under-session --peer-hint \$PEER_HINT --payload-b64 <marker> --data-dir \$A"
set +e
(cd "$RDAP_DIR" && ./rdap seal-under-session \
  --peer-hint "$PEER_HINT" \
  --payload-b64 "$PAYLOAD_B64" \
  --data-dir "$A" \
  >"$WORKDIR/green/cli.stdout" 2>"$WORKDIR/green/cli.stderr")
GREEN_SEAL_RC=$?
set -e
cat "$WORKDIR/green/cli.stdout" "$WORKDIR/green/cli.stderr" \
  >"$WORKDIR/green/cli.combined" || true
if [[ "$GREEN_SEAL_RC" -ne 0 ]]; then
  cat "$WORKDIR/green/cli.combined" "$WORKDIR/green/a.node.log" >&2 || true
  fail "GREEN seal-under-session failed rc=$GREEN_SEAL_RC"
fi
if ! grep -q 'envelope_b64' "$WORKDIR/green/cli.stdout"; then
  cat "$WORKDIR/green/cli.combined" >&2 || true
  fail "GREEN missing envelope_b64 on stdout"
fi
python3 - <<'PY' "$WORKDIR/green/cli.stdout" || fail "GREEN envelope_b64 is not packed RavenEnvelopeV1"
import base64, json, sys
from pathlib import Path
obj = json.loads(Path(sys.argv[1]).read_text())
env = base64.b64decode(obj["envelope_b64"])
if env[:4] != b"RVN1":
    raise SystemExit(f"magic {env[:4]!r} != RVN1")
if env[4] != 1 or env[5] != 1:
    raise SystemExit(f"version/env_type {env[4]}/{env[5]} != 1/1 (RavenEnvelopeV1 Message)")
if len(env) < 86:
    raise SystemExit("envelope shorter than PREFIX_LEN")
ct_len = int.from_bytes(env[80:84], "big")
if ct_len == 0:
    raise SystemExit("empty message_ciphertext")
print(f"ENVELOPE=RVN1 v1 Message ct_len={ct_len} packed_len={len(env)}")
PY
echo "GREEN_LAB_SEAL=PASS rc=$GREEN_SEAL_RC envelope_b64=daemon-sealed RavenEnvelopeV1/RVN1"

ENVELOPE_B64="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["envelope_b64"])' "$WORKDIR/green/cli.stdout")"
test -n "$ENVELOPE_B64"

echo "CMD: ash lab lan-dial-sealed --dial 127.0.0.1:${B_PORT} --expected-pub-hex \$B_PUB --envelope-b64 \$ENVELOPE"
set +e
"$ASH" --data-dir "$A" lab lan-dial-sealed \
  --dial "127.0.0.1:${B_PORT}" \
  --expected-pub-hex "$B_PUB" \
  --envelope-b64 "$ENVELOPE_B64" \
  >"$WORKDIR/green/dial.stdout" 2>"$WORKDIR/green/dial.stderr"
GREEN_DIAL_RC=$?
set -e
cat "$WORKDIR/green/dial.stdout" "$WORKDIR/green/dial.stderr" \
  >"$WORKDIR/green/dial.combined" || true
if [[ "$GREEN_DIAL_RC" -ne 0 ]]; then
  cat "$WORKDIR/green/dial.combined" "$WORKDIR/green/a.node.log" "$WORKDIR/green/b.node.log" >&2 || true
  fail "GREEN lan-dial-sealed failed rc=$GREEN_DIAL_RC"
fi
if ! grep -q 'O6_M3_LAN_DIAL_SEALED=OK' "$WORKDIR/green/dial.stdout"; then
  cat "$WORKDIR/green/dial.combined" >&2 || true
  fail "GREEN missing O6_M3_LAN_DIAL_SEALED=OK"
fi
if ! grep -q 'NOT_PROVEN' "$WORKDIR/green/dial.stdout"; then
  fail "GREEN lan-dial-sealed missing NOT_PROVEN honesty line"
fi
echo "GREEN_LAN_DIAL=PASS rc=$GREEN_DIAL_RC already-sealed LanDial under HOLD"

sleep 0.4
"$ASH" --data-dir "$B" inbox | tee "$WORKDIR/green/b.inbox.out"
if ! grep -q "$MARKER" "$WORKDIR/green/b.inbox.out"; then
  cat "$WORKDIR/green/b.inbox.out" "$WORKDIR/green/b.node.log" >&2 || true
  fail "GREEN Bob inbox missing $MARKER (RDAP-sealed envelope did not open on node B)"
fi
echo "GREEN_INBOX=PASS marker=$MARKER (Bob opened daemon-sealed payload)"

# ── RED: seal against a never-paired hint (session missing for that peer) ─
echo "=== RED missing-session hint: seal against never-paired device hint ==="
set +e
(cd "$RDAP_DIR" && ./rdap seal-under-session \
  --peer-hint "$DUMMY_HINT" \
  --payload-b64 "$PAYLOAD_B64" \
  --data-dir "$A" \
  >"$WORKDIR/green/red-hint.stdout" 2>"$WORKDIR/green/red-hint.stderr")
RED_HINT_RC=$?
set -e
cat "$WORKDIR/green/red-hint.stdout" "$WORKDIR/green/red-hint.stderr" \
  >"$WORKDIR/green/red-hint.combined" || true
if [[ "$RED_HINT_RC" -eq 0 ]]; then
  cat "$WORKDIR/green/red-hint.combined" >&2 || true
  fail "RED missing-session hint unexpectedly sealed"
fi
if grep -q 'ATSAM_SESSION_REQUIRED' "$WORKDIR/green/red-hint.combined" \
  && ! grep -q 'ATSAM_LINEAGE_REVOKED' "$WORKDIR/green/red-hint.combined"; then
  echo "RED_MISSING_SESSION=PASS rc=$RED_HINT_RC ATSAM_SESSION_REQUIRED"
  RED_SESSION_STATUS="PASS"
else
  cat "$WORKDIR/green/red-hint.combined" >&2 || true
  fail "RED missing-session hint did not stay ATSAM_SESSION_REQUIRED"
fi

# Physical two-device WAN is not available in this lab VM.
echo "TWO_DEVICE_WAN=BLOCKED_HARDWARE"
echo "PHYSICAL_DEVICES=UNAVAILABLE"
echo "RDAP_ASK_ATSAM=BLOCKED (companion tip $RDAP_TIP: seal-under-session only; ask is http_signed)"
echo "CARRIER_ENUM_ATSAM_RVN1=BLOCKED (RDAP status does not report atsam_rvn1)"

# Public listen lines only (no identity material).
grep -E 'raven-node ipc: listening|lan_direct: listen' "$WORKDIR/red/node.log" \
  >"$WORKDIR/red/node.listen.txt" || true
grep -E 'raven-node ipc: listening|lan_direct: listen' "$WORKDIR/green/a.node.log" \
  >"$WORKDIR/green/a.node.listen.txt" || true
grep -E 'raven-node ipc: listening|lan_direct: listen' "$WORKDIR/green/b.node.log" \
  >"$WORKDIR/green/b.node.listen.txt" || true

cat >"$WORKDIR/SUMMARY.txt" <<EOF
O6_M3_TWO_NODE_LAB=PASS
HOLD=ACTIVE
LABEL=NON-RELEASE
RAVEN_TIP=$(git -C "$ROOT" rev-parse HEAD)
RDAP_TIP=$RDAP_TIP
TOPOLOGY=localhost_two_process
UNIT_BASELINE=PASS rc=$UNIT_RC ${UNIT_PASSED:-} RDAP_TRY_OK
PIN_M1=$PIN_STATUS
PIN_CONTACT=PASS
RED_NO_SESSION=PASS rc=$RED_NO_SESSION_RC ATSAM_SESSION_REQUIRED
GREEN_LAB_SEAL=PASS rc=$GREEN_SEAL_RC
GREEN_LAN_DIAL=PASS rc=$GREEN_DIAL_RC
GREEN_INBOX=PASS marker=$MARKER
RED_MISSING_SESSION=$RED_SESSION_STATUS
RDAP_NO_LOCAL_ATSAM=PASS
RDAP_ASK_ATSAM=BLOCKED
CARRIER_ENUM_ATSAM_RVN1=BLOCKED
TWO_DEVICE_WAN=BLOCKED_HARDWARE
PHYSICAL_DEVICES=UNAVAILABLE
CLAIM=lab localhost two-process encrypted Raven↔RDAP path under HOLD
NOT_PROVEN=O6 E2E; HOLD lift; WAN; confidential RDAP delivery; RDAP ask-over-atsam_rvn1; physical two-device
$BANNER
EOF
cat "$WORKDIR/SUMMARY.txt"
echo "$BANNER" >&2
echo "O6_M3_TWO_NODE_LAB=PASS"
exit 0
