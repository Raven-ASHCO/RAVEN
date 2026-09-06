#!/usr/bin/env bash
# O6 M2 lab execute: RDAP plaintext-to-daemon SealUnderSession vs raven-node IPC.
#
# NON-RELEASE / HOLD active. plaintext-to-daemon SealUnderSession only.
# Not O6 E2E Proven. No HOLD lift. Soft-load P0 held.
# Seal still requires a raven-node ATSAM session.
#
# Reuses the existing LAN indexed path (RAVEN_LAB_TEST_A=1 + ash send /
# pair_init_lab). RDAP has no session-ensure. Does not flip
# PRODUCTION_ENABLED tripwires. Does not use unsafe-demo-crypto.
#
# CLAIM (exact):
#   Proven: lab localhost IPC seal under HOLD
#   Not Proven: O6 E2E, HOLD lift, WAN, confidential RDAP delivery
#
# Matrix:
#   UNIT — RDAP .venv/bin/python -m team_agents.selftest --unit (mocked)
#   RED  — raven-node up, no ATSAM session → ATSAM_SESSION_REQUIRED
#   GREEN — persisted indexed session via LAN send, then
#           ./rdap seal-under-session --peer-hint <device Ed25519> --payload-b64 aGVsbG8=
#   RED revoke — ash device revoke (existing Identity loaders) →
#                ATSAM_LINEAGE_REVOKED, or honest BLOCKED
#
# Env:
#   RDAP_HOME     existing checkout of raven-distributed-agent-protocol
#                 (default: clone pinned SHA into the workdir)
#   RDAP_SHA      default 3207e8ea56002ff0efe0909ec9b6ec233b920c05
#   EVIDENCE_OUT  optional directory to copy captured logs
#   RAVEN_KEEP_M2=1  keep workdir
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
WORKDIR="${TMPDIR:-/tmp}/raven-o6-m2-seal-$$"
EVIDENCE_OUT="${EVIDENCE_OUT:-}"
RDAP_SHA="${RDAP_SHA:-3207e8ea56002ff0efe0909ec9b6ec233b920c05}"
RDAP_REPO="${RDAP_REPO:-https://github.com/Raven-ASHCO/raven-distributed-agent-protocol}"
BANNER='NON-RELEASE / HOLD active. plaintext-to-daemon SealUnderSession only. Not O6 E2E Proven. No HOLD lift. Soft-load P0 held. Seal still requires a raven-node ATSAM session.'
DUMMY_HINT="$(printf 'ab%.0s' {1..32})"
PAYLOAD_B64='aGVsbG8='
A_PID=""
B_PID=""
UNIT_RC=""
RED_NO_SESSION_RC=""
GREEN_RC=""
REVOKE_STATUS="PENDING"

fail() {
  echo "O6_M2_SEAL_LAB=FAIL: $*" >&2
  echo "HOLD=ACTIVE"
  echo "CLAIM=none (not O6 E2E Proven; not HOLD lift; not confidential RDAP delivery)"
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
        -name '*.log' -o -name '*.out' -o -name '*.err' -o -name '*.stdout' \
        -o -name '*.stderr' -o -name '*.combined' -o -name '*.status' \
        -o -name 'SUMMARY.txt' -o -name 'lab.status' -o -name '*.init' \
        -o -name '*.help' \
      \) ! -path '*/.venv/*' ! -name 'identity.seed' \
      -exec bash -c 'dest="$1"; src="$2"; rel="${src#"$3"/}"; mkdir -p "$dest/$(dirname "$rel")"; cp -a "$src" "$dest/$rel"' _ "$EVIDENCE_OUT" {} "$WORKDIR" \;
  fi
  if [[ "${RAVEN_KEEP_M2:-}" == "1" ]]; then
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
echo "WORKDIR=$WORKDIR"
mkdir -p "$WORKDIR/red" "$WORKDIR/green" "$WORKDIR/unit"

echo "=== build ash + raven-node (debug; no unsafe-demo-crypto) ==="
(cd "$NODE_ROOT" && cargo build -p raven-node -p ash -q --offline 2>/dev/null \
  || cargo build -p raven-node -p ash -q)
[[ -x "$ASH" ]] || fail "ash binary missing"
[[ -x "$NODE" ]] || fail "raven-node binary missing"

echo "=== production tripwires stay false (HOLD) ==="
"$ASH" lab status >"$WORKDIR/lab.status" 2>&1 || true
# LAN_DIRECT_PRODUCTION_ENABLED is already true on main (existing LAN slice).
# This pack must not flip the remaining HOLD tripwires.
if grep -E 'pair_init::PRODUCTION_ENABLED|atsam_indexed_session::PRODUCTION_ENABLED|INDEXED_SESSION_STORE_PRODUCTION_ENABLED|PREKEY_LIFECYCLE_PRODUCTION_ENABLED|INTERNET_DIRECT_PRODUCTION_ENABLED' \
     "$WORKDIR/lab.status" | grep -E 'true' >/dev/null; then
  cat "$WORKDIR/lab.status" >&2 || true
  fail "a HOLD PRODUCTION_ENABLED tripwire is true (this pack must not flip them)"
fi
echo "LAB_STATUS_OK (HOLD tripwires remain false; LAN_DIRECT_PRODUCTION_ENABLED is pre-existing on main)"

# ── RDAP companion ────────────────────────────────────────────────────────
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

# Assert caller-only request shape (RDAP does not construct ATSAM locally).
PYTHONPATH="$RDAP_DIR${PYTHONPATH:+:$PYTHONPATH}" "$RDAP_DIR/.venv/bin/python" - <<'PY' || fail "RDAP raven_ipc.py request-shape assert"
from team_agents.raven_ipc import seal_under_session_request
req = seal_under_session_request("ab" * 32, b"hello")
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

echo "CMD: ./rdap seal-under-session --peer-hint <ab*32> --payload-b64 aGVsbG8= --data-dir \$RAVEN_DATA_DIR"
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
if ! grep -q 'NON-RELEASE / HOLD active' "$WORKDIR/red/cli.stderr"; then
  cat "$WORKDIR/red/cli.stderr" >&2 || true
  fail "RED no-session missing honesty banner on stderr"
fi
echo "RED_NO_SESSION=PASS rc=$RED_NO_SESSION_RC ATSAM_SESSION_REQUIRED (not LINEAGE_REVOKED)"

kill "${A_PID}" 2>/dev/null || true
wait "${A_PID}" 2>/dev/null || true
A_PID=""

# ── GREEN: lab indexed session via existing LAN send path ─────────────────
echo "=== GREEN: RAVEN_LAB_TEST_A=1 + pair_init_lab / ash send (session-ensure is Raven, not RDAP) ==="
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

"$ASH" --data-dir "$A" contact add \
  --address "$B_ADDR" --pub-hex "$B_PUB" --petname "Bob" --tag bob \
  --lan-dial "127.0.0.1:${B_PORT}"
"$ASH" --data-dir "$B" contact add \
  --address "$A_ADDR" --pub-hex "$A_PUB" --petname "Alice" --tag alice \
  --lan-dial "127.0.0.1:${A_PORT}"

set +e
printf '%s\n' "hello from a (lab pair_init)" | "$ASH" --data-dir "$A" send --contact @bob \
  >"$WORKDIR/green/a.send.out" 2>"$WORKDIR/green/a.send.err"
SEND_RC=$?
set -e
if [[ "$SEND_RC" -ne 0 ]] || ! grep -qi 'status.*delivered' "$WORKDIR/green/a.send.out"; then
  cat "$WORKDIR/green/a.send.out" "$WORKDIR/green/a.send.err" \
    "$WORKDIR/green/a.node.log" "$WORKDIR/green/b.node.log" >&2 || true
  fail "GREEN session establish (ash send) failed rc=$SEND_RC"
fi
echo "LAB_SESSION=PASS (ash send delivered; persisted indexed ATSAM session)"

# Device Ed25519 plane (ash-primary cert.device_ed_pub). Export via existing lab helper.
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

echo "CMD: ./rdap seal-under-session --peer-hint \$PEER_HINT --payload-b64 aGVsbG8= --data-dir \$A"
set +e
(cd "$RDAP_DIR" && ./rdap seal-under-session \
  --peer-hint "$PEER_HINT" \
  --payload-b64 "$PAYLOAD_B64" \
  --data-dir "$A" \
  >"$WORKDIR/green/cli.stdout" 2>"$WORKDIR/green/cli.stderr")
GREEN_RC=$?
set -e
cat "$WORKDIR/green/cli.stdout" "$WORKDIR/green/cli.stderr" \
  >"$WORKDIR/green/cli.combined" || true
if [[ "$GREEN_RC" -ne 0 ]]; then
  cat "$WORKDIR/green/cli.combined" "$WORKDIR/green/a.node.log" >&2 || true
  fail "GREEN seal-under-session failed rc=$GREEN_RC"
fi
if ! grep -q 'envelope_b64' "$WORKDIR/green/cli.stdout"; then
  cat "$WORKDIR/green/cli.combined" >&2 || true
  fail "GREEN missing envelope_b64 on stdout"
fi
if ! grep -q 'RDAP did not construct ATSAM/RVNA1 ciphertext' "$WORKDIR/green/cli.stderr"; then
  cat "$WORKDIR/green/cli.stderr" >&2 || true
  fail "GREEN missing daemon-sealed honesty line"
fi
if ! grep -q 'NON-RELEASE / HOLD' "$WORKDIR/green/cli.stderr"; then
  fail "GREEN missing NON-RELEASE / HOLD on stderr"
fi
python3 - <<'PY' "$WORKDIR/green/cli.stdout" || fail "GREEN envelope_b64 is not packed RavenEnvelopeV1"
import base64, json, sys
from pathlib import Path
raw_json = Path(sys.argv[1]).read_text()
obj = json.loads(raw_json)
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
if env == b"hello":
    raise SystemExit("envelope is raw payload; RDAP/daemon did not pack RVN1")
print(f"ENVELOPE=RVN1 v1 Message ct_len={ct_len} packed_len={len(env)}")
PY
echo "GREEN_LAB_SEAL=PASS rc=$GREEN_RC envelope_b64=daemon-sealed RavenEnvelopeV1/RVN1"

# ── RED revoke via existing ash device revoke (Identity loaders) ──────────
echo "=== RED revoke: ash device revoke --device-id ash-primary (existing Identity path) ==="
set +e
"$ASH" --data-dir "$A" device revoke --device-id ash-primary --epoch 1 \
  >"$WORKDIR/green/revoke.out" 2>"$WORKDIR/green/revoke.err"
REVOKE_RC=$?
set -e
if [[ "$REVOKE_RC" -ne 0 ]]; then
  echo "RED_REVOKE=BLOCKED ash device revoke failed rc=$REVOKE_RC (Soft-load P0 / missing fixtures; no invented revoke plumbing)"
  cat "$WORKDIR/green/revoke.out" "$WORKDIR/green/revoke.err" || true
  REVOKE_STATUS="BLOCKED"
else
  set +e
  (cd "$RDAP_DIR" && ./rdap seal-under-session \
    --peer-hint "$PEER_HINT" \
    --payload-b64 "$PAYLOAD_B64" \
    --data-dir "$A" \
    >"$WORKDIR/green/revoke-cli.stdout" 2>"$WORKDIR/green/revoke-cli.stderr")
  REVOKE_SEAL_RC=$?
  set -e
  cat "$WORKDIR/green/revoke-cli.stdout" "$WORKDIR/green/revoke-cli.stderr" \
    >"$WORKDIR/green/revoke-cli.combined" || true
  if [[ "$REVOKE_SEAL_RC" -eq 0 ]]; then
    cat "$WORKDIR/green/revoke-cli.combined" >&2 || true
    fail "RED revoke unexpectedly sealed after ash device revoke"
  fi
  if grep -q 'ATSAM_LINEAGE_REVOKED' "$WORKDIR/green/revoke-cli.combined" \
    && ! grep -q 'ATSAM_SESSION_REQUIRED' "$WORKDIR/green/revoke-cli.combined"; then
    echo "RED_REVOKE=PASS rc=$REVOKE_SEAL_RC ATSAM_LINEAGE_REVOKED (distinct from SESSION_REQUIRED)"
    REVOKE_STATUS="PASS"
  elif grep -q 'ATSAM_LINEAGE_REVOKED' "$WORKDIR/green/revoke-cli.combined" \
    && grep -q 'ATSAM_SESSION_REQUIRED' "$WORKDIR/green/revoke-cli.combined"; then
    cat "$WORKDIR/green/revoke-cli.combined" >&2 || true
    fail "RED revoke collapsed LINEAGE_REVOKED with SESSION_REQUIRED"
  else
    echo "RED_REVOKE=BLOCKED expected ATSAM_LINEAGE_REVOKED; got rc=$REVOKE_SEAL_RC (honest; no invented revoke plumbing)"
    cat "$WORKDIR/green/revoke-cli.combined" || true
    REVOKE_STATUS="BLOCKED"
  fi
fi

cat >"$WORKDIR/SUMMARY.txt" <<EOF
O6_M2_SEAL_LAB=PASS
HOLD=ACTIVE
LABEL=NON-RELEASE
RAVEN_TIP=$(git -C "$ROOT" rev-parse HEAD)
RDAP_TIP=$RDAP_TIP
UNIT_BASELINE=PASS rc=$UNIT_RC ${UNIT_PASSED:-} RDAP_TRY_OK
RED_NO_SESSION=PASS rc=$RED_NO_SESSION_RC ATSAM_SESSION_REQUIRED
GREEN_LAB_SEAL=PASS rc=$GREEN_RC
RED_REVOKE=$REVOKE_STATUS
RDAP_NO_LOCAL_ATSAM=PASS
CLAIM=lab localhost IPC seal under HOLD
NOT_PROVEN=O6 E2E; HOLD lift; WAN; confidential RDAP delivery
$BANNER
EOF
cat "$WORKDIR/SUMMARY.txt"
echo "$BANNER" >&2
echo "O6_M2_SEAL_LAB=PASS"
exit 0
