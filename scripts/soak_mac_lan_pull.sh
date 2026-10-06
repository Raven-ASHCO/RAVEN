#!/usr/bin/env bash
# Long-running Mac LAN + ash local-listen enqueue + TCP pull soak.
#
# Each cycle (ephemeral dirs, no secrets logged):
#   1) init Mac + phone identities (ash)
#   2) contact add from whoami public bits
#   3) raven-node service (bridge+store+IPC) on ephemeral LAN port
#   4) ash send --peer local-listen (IPC enqueue)
#   5) phone raven-node dials Mac LAN → expect DELIVERED (≥1 frame)
#   6) assert no "peer parse" / "Connection refused" on chat path
#
# Defaults ≈ 10h: MAX_HOURS=10, SLEEP_SECS=12 → ~3000 cycles.
#
# Usage:
#   nohup bash scripts/soak_mac_lan_pull.sh >.cursor/soak_mac_lan_pull.nohup 2>&1 &
#   echo $! >.cursor/soak_mac_lan_pull.pid
#   tail -f .cursor/soak_mac_lan_pull.log
#
# Env overrides:
#   MAX_HOURS=10 SLEEP_SECS=12 MAX_CYCLES=0  (0 = derive from hours)
#   ALSO_DIRECT_LAN=1   every 5th cycle also run ash→host:port LAN send
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
NODE_ROOT="$REPO/node"
# shellcheck source=scripts/lib/harness_util.sh
source "$REPO/scripts/lib/harness_util.sh"
source "${HOME}/.cargo/env" 2>/dev/null || true
export PATH="${HOME}/.cargo/bin:${PATH}"
export NO_COLOR=1
export RAVEN_IDENTITY_BACKEND=locked-file

mkdir -p "$REPO/.cursor"
LOG="$REPO/.cursor/soak_mac_lan_pull.log"
SUMMARY="$REPO/.cursor/soak_mac_lan_pull.summary"
PIDFILE="$REPO/.cursor/soak_mac_lan_pull.pid"
README="$REPO/.cursor/SOAK_MAC_LAN_PULL_README.md"

MAX_HOURS="${MAX_HOURS:-10}"
SLEEP_SECS="${SLEEP_SECS:-12}"
MAX_CYCLES="${MAX_CYCLES:-0}"
ALSO_DIRECT_LAN="${ALSO_DIRECT_LAN:-1}"

if [[ "$MAX_CYCLES" -eq 0 ]]; then
  MAX_CYCLES=$(( (MAX_HOURS * 3600) / (SLEEP_SECS + 6) ))
  [[ "$MAX_CYCLES" -lt 1 ]] && MAX_CYCLES=1
fi

ASH="$NODE_ROOT/target/debug/ash"
NODE="$NODE_ROOT/target/debug/raven-node"

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

log() {
  printf '%s %s\n' "$(ts)" "$*" | tee -a "$LOG"
}

write_summary() {
  # verdict is self-describing for callers/schedulers that only read this file:
  # any failed cycle => FAIL; otherwise PASS once at least one cycle passed.
  local verdict=NONE
  if [[ "$2" -gt 0 ]]; then
    verdict=FAIL
  elif [[ "$1" -gt 0 ]]; then
    verdict=PASS
  fi
  cat >"$SUMMARY" <<EOF
soak_mac_lan_pull
updated_utc=$(ts)
cycle=$3 / max=$MAX_CYCLES
pass=$1
fail=$2
verdict=$verdict
max_hours=$MAX_HOURS
sleep_secs=$SLEEP_SECS
pid=$$
note=$4
log=$LOG
EOF
}

cat >"$README" <<'EOF'
# Mac LAN + ash local-listen soak

Long-running verification of Mac terminal (`ash` / `raven-node`) serverless path:
local-listen IPC enqueue → Mac service LAN → TCP pull (iPhone stand-in).

## Monitor (~10h)

```bash
cd /path/to/hybrid_messenger
tail -f .cursor/soak_mac_lan_pull.log
cat .cursor/soak_mac_lan_pull.summary
grep -c ' RESULT=PASS ' .cursor/soak_mac_lan_pull.log
grep -c ' RESULT=FAIL ' .cursor/soak_mac_lan_pull.log
```

## Stop

```bash
kill "$(cat .cursor/soak_mac_lan_pull.pid)"
# or: pkill -f soak_mac_lan_pull.sh
```

## Gaps (not covered by this soak)

- Physical iPhone Serverless LAN UI / Pull button
- Real ME↔EU internet path / CGNAT / DCUtR
- Apple notarization / device BLE radios

## Re-run

```bash
nohup bash scripts/soak_mac_lan_pull.sh >.cursor/soak_mac_lan_pull.nohup 2>&1 &
echo $! >.cursor/soak_mac_lan_pull.pid
```
EOF

echo $$ >"$PIDFILE"

if [[ ! -x "$ASH" || ! -x "$NODE" ]]; then
  log "BUILD starting ash + raven-node"
  if ! (cd "$NODE_ROOT" && cargo build -p ash -p raven-node -q); then
    log "BUILD FAIL"
    write_summary 0 1 0 "build_failed"
    exit 1
  fi
fi

PASS=0
FAIL=0
START_EPOCH=$(date +%s)
END_EPOCH=$((START_EPOCH + MAX_HOURS * 3600))

log "SOAK_START max_hours=$MAX_HOURS max_cycles=$MAX_CYCLES sleep_secs=$SLEEP_SECS"
log "bins ash=$ASH node=$NODE"
write_summary 0 0 0 "started"

# Python, not sed: BSD sed (macOS, where this soak runs) has no `\b`, so the old
# `sed -E 's/\b...\b/'` redacted nothing. On any failure print nothing rather than raw.
redact_file() {
  python3 - "$1" <<'PY' 2>/dev/null || echo "[redaction failed: output withheld]"
import re, sys
drop = re.compile(rb"[Ss]eed|[Pp]rivate.?key|identity\.seed")
hex64 = re.compile(rb"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
out = sys.stdout.buffer
with open(sys.argv[1], "rb") as f:
    for line in f:
        if not drop.search(line):
            out.write(hex64.sub(b"<HEX64>", line))
PY
}

pick_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# Returns 0 on pass. Sets FAIL_REASON on failure.
run_cycle() {
  local n="$1"
  FAIL_REASON=""
  local work mac phone svc_pid="" phone_pid="" lan_port
  work="$(mktemp -d "${TMPDIR:-/tmp}/raven-soak-c${n}-XXXXXX")"
  mac="$work/mac"
  phone="$work/phone"
  mkdir -p "$mac" "$phone"
  lan_port="$(pick_free_port)"

  cleanup_cycle() {
    [[ -n "${phone_pid:-}" ]] && kill "$phone_pid" 2>/dev/null || true
    [[ -n "${svc_pid:-}" ]] && kill "$svc_pid" 2>/dev/null || true
    wait "$phone_pid" 2>/dev/null || true
    wait "$svc_pid" 2>/dev/null || true
    rm -rf "$work" 2>/dev/null || true
  }

  if ! "$ASH" --data-dir "$mac" init >"$work/mac.init" 2>"$work/mac.init.err"; then
    FAIL_REASON="mac_init"; cleanup_cycle; return 1
  fi
  if ! "$ASH" --data-dir "$phone" init >"$work/phone.init" 2>"$work/phone.init.err"; then
    FAIL_REASON="phone_init"; cleanup_cycle; return 1
  fi

  local mac_pub phone_pub phone_addr phone_fp
  mac_pub=$(grep '^pub_hex=' "$work/mac.init" | cut -d= -f2)
  phone_pub=$(grep '^pub_hex=' "$work/phone.init" | cut -d= -f2)
  phone_addr=$(grep '^address=' "$work/phone.init" | cut -d= -f2)
  phone_fp=$(grep '^fingerprint=' "$work/phone.init" | cut -d= -f2)
  if [[ -z "$mac_pub" || -z "$phone_pub" || -z "$phone_addr" ]]; then
    FAIL_REASON="whoami_parse"; cleanup_cycle; return 1
  fi

  if ! "$ASH" --data-dir "$phone" whoami >"$work/phone.whoami"; then
    FAIL_REASON="whoami"; cleanup_cycle; return 1
  fi
  if ! grep -q "$phone_addr" "$work/phone.whoami"; then
    FAIL_REASON="whoami_mismatch"; cleanup_cycle; return 1
  fi

  "$ASH" --data-dir "$mac" node bridge on >/dev/null
  "$ASH" --data-dir "$mac" node store on >/dev/null

  "$NODE" service \
    --data-dir "$mac" \
    --lan-listen "127.0.0.1:${lan_port}" \
    --ble-listen "127.0.0.1:0" \
    --timeout-secs 0 \
    >"$work/svc.log" 2>&1 &
  svc_pid=$!

  local i
  for i in $(seq 1 100); do
    raven_ipc_up "$ASH" "$mac" && break
    if ! kill -0 "$svc_pid" 2>/dev/null; then
      FAIL_REASON="service_died"
      break
    fi
    sleep 0.05
  done
  if ! raven_ipc_up "$ASH" "$mac"; then
    FAIL_REASON="${FAIL_REASON:-service_sock}"
    # keep logs
    {
      echo "---- cycle $n fail ($FAIL_REASON) ----"
      redact_file "$work/svc.log" | tail -40
    } >>"$LOG"
    cleanup_cycle
    return 1
  fi

  if ! "$ASH" --data-dir "$mac" ipc-ping >"$work/ipc.txt" 2>&1; then
    FAIL_REASON="ipc_ping"; cleanup_cycle; return 1
  fi

  if ! "$ASH" --data-dir "$mac" contact add \
    --address "$phone_addr" \
    --pub-hex "$phone_pub" \
    --petname "PhoneSim" \
    --tag phonesim \
    --verify-fp "$phone_fp" \
    >"$work/contact.txt" 2>&1; then
    FAIL_REASON="contact_add"; cleanup_cycle; return 1
  fi
  if ! grep -qi 'contact saved' "$work/contact.txt"; then
    FAIL_REASON="contact_saved"; cleanup_cycle; return 1
  fi

  if ! printf 'soak-cycle-%s\n' "$n" | "$ASH" --data-dir "$mac" send \
    --peer local-listen \
    --peer-pub-hex "$phone_pub" \
    --stdin-text \
    >"$work/send.txt" 2>&1; then
    FAIL_REASON="send_enqueue"
    {
      echo "---- cycle $n fail ($FAIL_REASON) ----"
      redact_file "$work/send.txt" | tail -30
    } >>"$LOG"
    cleanup_cycle
    return 1
  fi
  if ! grep -qi 'enqueued' "$work/send.txt"; then
    FAIL_REASON="not_enqueued"
    {
      echo "---- cycle $n fail ($FAIL_REASON) ----"
      redact_file "$work/send.txt" | tail -30
    } >>"$LOG"
    cleanup_cycle
    return 1
  fi
  if grep -qi 'peer parse' "$work/send.txt" "$work/svc.log" 2>/dev/null; then
    FAIL_REASON="peer_parse"; cleanup_cycle; return 1
  fi
  if grep -qi 'Connection refused' "$work/send.txt" 2>/dev/null; then
    FAIL_REASON="conn_refused_send"; cleanup_cycle; return 1
  fi

  "$NODE" run \
    --data-dir "$phone" \
    --listen "127.0.0.1:0" \
    --peer "127.0.0.1:${lan_port}" \
    --peer-pub-hex "$mac_pub" \
    --exit-after-recv 1 \
    --timeout-secs 25 \
    >"$work/phone.log" 2>&1 &
  phone_pid=$!
  wait "$phone_pid" || true
  phone_pid=""

  if grep -qi 'Connection refused' "$work/phone.log" 2>/dev/null; then
    FAIL_REASON="conn_refused_pull"
    {
      echo "---- cycle $n fail ($FAIL_REASON) ----"
      redact_file "$work/phone.log" | tail -30
      redact_file "$work/svc.log" | tail -30
    } >>"$LOG"
    cleanup_cycle
    return 1
  fi
  if grep -qi 'peer parse' "$work/phone.log" "$work/svc.log" 2>/dev/null; then
    FAIL_REASON="peer_parse_pull"; cleanup_cycle; return 1
  fi
  if ! grep -qE 'DELIVERED (bytes=|opaque_atsam)' "$work/phone.log"; then
    FAIL_REASON="no_delivered_frame"
    {
      echo "---- cycle $n fail ($FAIL_REASON) ----"
      redact_file "$work/phone.log" | tail -40
      redact_file "$work/svc.log" | tail -40
    } >>"$LOG"
    cleanup_cycle
    return 1
  fi

  # Optional direct LAN every 5th cycle
  if [[ "$ALSO_DIRECT_LAN" == "1" && $((n % 5)) -eq 0 ]]; then
    local dwork="$work/direct" bp="" b_listen a_pub b_pub b_addr b_fp j
    mkdir -p "$dwork/a" "$dwork/b"
    "$ASH" --data-dir "$dwork/a" init >"$dwork/a.init"
    "$ASH" --data-dir "$dwork/b" init >"$dwork/b.init"
    a_pub=$(grep '^pub_hex=' "$dwork/a.init" | cut -d= -f2)
    b_pub=$(grep '^pub_hex=' "$dwork/b.init" | cut -d= -f2)
    b_addr=$(grep '^address=' "$dwork/b.init" | cut -d= -f2)
    b_fp=$(grep '^fingerprint=' "$dwork/b.init" | cut -d= -f2)
    rm -f "$dwork/b.listen"
    "$NODE" run \
      --data-dir "$dwork/b" \
      --listen "127.0.0.1:0" \
      --peer-pub-hex "$a_pub" \
      --write-addr "$dwork/b.listen" \
      --exit-after-recv 1 \
      --timeout-secs 20 \
      >"$dwork/b.log" 2>&1 &
    bp=$!
    for j in $(seq 1 80); do
      [[ -f "$dwork/b.listen" ]] && break
      sleep 0.05
    done
    if [[ ! -f "$dwork/b.listen" ]]; then
      kill "$bp" 2>/dev/null || true
      FAIL_REASON="direct_listen"; cleanup_cycle; return 1
    fi
    b_listen=$(cat "$dwork/b.listen")
    "$ASH" --data-dir "$dwork/a" contact add \
      --address "$b_addr" --pub-hex "$b_pub" --petname Bob --tag bob \
      --lan-dial "$b_listen" --verify-fp "$b_fp" >/dev/null
    printf 'direct-lan-%s\n' "$n" | "$ASH" --data-dir "$dwork/a" send \
      --peer "$b_listen" --peer-pub-hex "$b_pub" --stdin-text \
      >"$dwork/a.send" 2>&1
    wait "$bp" || true
    if ! grep -q 'ACK delivered' "$dwork/a.send" \
      || ! grep -q 'DELIVERED' "$dwork/b.log"; then
      FAIL_REASON="direct_lan"
      {
        echo "---- cycle $n fail ($FAIL_REASON) ----"
        redact_file "$dwork/a.send" | tail -20
        redact_file "$dwork/b.log" | tail -20
      } >>"$LOG"
      cleanup_cycle
      return 1
    fi
    if grep -qi 'peer parse\|Connection refused' "$dwork/a.send" "$dwork/b.log" 2>/dev/null; then
      FAIL_REASON="direct_lan_err"; cleanup_cycle; return 1
    fi
  fi

  log "cycle=$n RESULT=PASS lan_port=$lan_port"
  cleanup_cycle
  return 0
}

CYCLE=0
while true; do
  NOW=$(date +%s)
  if [[ "$NOW" -ge "$END_EPOCH" ]]; then
    log "SOAK_STOP reason=max_hours elapsed_s=$((NOW - START_EPOCH))"
    break
  fi
  if [[ "$CYCLE" -ge "$MAX_CYCLES" ]]; then
    log "SOAK_STOP reason=max_cycles"
    break
  fi
  CYCLE=$((CYCLE + 1))
  if run_cycle "$CYCLE"; then
    PASS=$((PASS + 1))
  else
    log "cycle=$CYCLE RESULT=FAIL reason=${FAIL_REASON:-unknown}"
    FAIL=$((FAIL + 1))
  fi
  write_summary "$PASS" "$FAIL" "$CYCLE" "running"
  sleep "$SLEEP_SECS"
done

log "SOAK_DONE pass=$PASS fail=$FAIL cycles=$CYCLE"
write_summary "$PASS" "$FAIL" "$CYCLE" "done"
# The verdict decides the exit code: a nohup/launchd/CI wrapper that only sees the
# status must not mark a soak green when cycles failed (or none ran).
if [[ "$FAIL" -eq 0 && "$PASS" -gt 0 ]]; then
  exit 0
fi
exit 1
