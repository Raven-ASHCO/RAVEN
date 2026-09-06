#!/usr/bin/env bash
# Positive lab smoke: indexed PairInit + sealed ACK over InternetTransport (RIH1).
#
# CLAIM (exact):
#   PASS = lab InternetTransport indexed two-node delivery (RIH1 hello + framed
#   PairInit/message + sealed ACK) on (1) 127.0.0.1 and (2) a same-host
#   non-loopback IPv4. dial≠WAN. Non-loopback RFC1918/same-host ≠ public
#   Internet, ≠ multi-NAT, ≠ WAN Proven. multi-NAT stays BLOCKED_HARDWARE.
#   INTERNET_DIRECT_PRODUCTION_ENABLED stays false; this uses debug
#   RAVEN_LAB_TEST_A=1. Legacy raven-node run remains fail-closed
#   (internet_dial_smoke.sh) — that negative gate is NOT this proof.
#   Named-pipe work ≠ WAN.
#
# Does not use unsafe-demo-crypto. Does not flip global PRODUCTION_ENABLED flags.
set -euo pipefail
set +m

export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
# Lab unlock only (debug). Production InternetTransport slice gate stays false.
export RAVEN_LAB_TEST_A=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug"
ASH="$BIN/ash"
NODE="$BIN/raven-node"
WORKDIR="${TMPDIR:-/tmp}/raven-inet-indexed-$$"
A="$WORKDIR/a"
B="$WORKDIR/b"
A_PORT="${A_PORT:-$((20000 + $$ % 500))}"
B_PORT="${B_PORT:-$((20500 + $$ % 500))}"
A_PID=""
B_PID=""
C_PID=""

fail() {
  echo "INTERNET_INDEXED_TWO_NODE_FAIL: $*" >&2
  echo "CLAIM: fail is lab InternetTransport — still not WAN / multi-NAT Proven" >&2
  exit 1
}

is_loopback_v4() {
  [[ "$1" == 127.* ]]
}

is_rfc1918_v4() {
  [[ "$1" == 10.* || "$1" == 192.168.* ]] && return 0
  [[ "$1" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]
}

classify_v4() {
  if is_loopback_v4 "$1"; then
    echo "loopback"
  elif is_rfc1918_v4 "$1"; then
    echo "rfc1918"
  else
    echo "other"
  fi
}

# Same-host non-loopback IPv4. Not a public-WAN peer. Override: RAVEN_INET_NON_LOOPBACK_IP.
pick_non_loopback_ipv4() {
  local ip
  if [[ -n "${RAVEN_INET_NON_LOOPBACK_IP:-}" ]]; then
    ip="${RAVEN_INET_NON_LOOPBACK_IP}"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_loopback_v4 "$ip"; then
      echo "$ip"
      return 0
    fi
    return 1
  fi
  if ips="$(hostname -I 2>/dev/null)"; then
    for ip in $ips; do
      [[ "$ip" == *:* ]] && continue
      if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_loopback_v4 "$ip"; then
        echo "$ip"
        return 0
      fi
    done
  fi
  if command -v ifconfig >/dev/null 2>&1; then
    while read -r ip; do
      ip="${ip#addr:}"
      if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_loopback_v4 "$ip"; then
        echo "$ip"
        return 0
      fi
    done < <(ifconfig 2>/dev/null | awk '/inet / {print $2}')
  fi
  return 1
}

cleanup() {
  if [[ -n "${A_PID}" ]]; then kill "${A_PID}" 2>/dev/null || true; fi
  if [[ -n "${B_PID}" ]]; then kill "${B_PID}" 2>/dev/null || true; fi
  if [[ -n "${C_PID}" ]]; then kill "${C_PID}" 2>/dev/null || true; fi
  sleep 0.2
  if [[ -n "${A_PID}" ]]; then kill -9 "${A_PID}" 2>/dev/null || true; fi
  if [[ -n "${B_PID}" ]]; then kill -9 "${B_PID}" 2>/dev/null || true; fi
  if [[ -n "${C_PID}" ]]; then kill -9 "${C_PID}" 2>/dev/null || true; fi
  wait 2>/dev/null || true
  if [[ "${RAVEN_KEEP_INET:-}" == "1" ]]; then
    echo "keeping $WORKDIR" >&2
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

source "${HOME}/.cargo/env" 2>/dev/null || true
echo "=== building ash + raven-node (no unsafe-demo-crypto) ==="
(cd "$ROOT" && cargo build -p raven-node -p ash -q --offline 2>/dev/null \
  || cargo build -p raven-node -p ash -q)

mkdir -p "$A" "$B"

echo "=== init + prekey publish ==="
"$ASH" --data-dir "$A" init | tee "$WORKDIR/a.init"
"$ASH" --data-dir "$B" init | tee "$WORKDIR/b.init"
A_ADDR=$(grep '^address=' "$WORKDIR/a.init" | cut -d= -f2)
B_ADDR=$(grep '^address=' "$WORKDIR/b.init" | cut -d= -f2)
A_PUB=$(grep '^pub_hex=' "$WORKDIR/a.init" | cut -d= -f2)
B_PUB=$(grep '^pub_hex=' "$WORKDIR/b.init" | cut -d= -f2)
test -n "$A_ADDR" && test -n "$B_ADDR" && test -n "$A_PUB" && test -n "$B_PUB"

"$ASH" --data-dir "$A" prekey publish
"$ASH" --data-dir "$B" prekey publish

NON_LOOP_IP="$(pick_non_loopback_ipv4 || true)"
if [[ -z "${NON_LOOP_IP}" ]]; then
  echo "INTERNET_INDEXED_NON_LOOPBACK_BLOCKED: no non-loopback IPv4 on this host" >&2
  echo "CLAIM: cannot prove non-loopback dial; still not WAN / multi-NAT" >&2
  fail "non-loopback IPv4 required (set RAVEN_INET_NON_LOOPBACK_IP or add a NIC address)"
fi
NON_LOOP_CLASS="$(classify_v4 "$NON_LOOP_IP")"
echo "NON_LOOPBACK_IP=$NON_LOOP_IP class=$NON_LOOP_CLASS (same-host; not public WAN)"

echo "=== start two raven-node service processes (0.0.0.0 internet listen; lab only) ==="
# Bind all interfaces so 127.0.0.1 and the non-loopback NIC share one listener.
# 0.0.0.0 listen is not a WAN advertisement.
"$NODE" service --data-dir "$A" \
  --lan-listen "127.0.0.1:0" --ble-listen "127.0.0.1:0" \
  --internet-listen "0.0.0.0:${A_PORT}" \
  >"$WORKDIR/a.node.log" 2>&1 &
A_PID=$!
"$NODE" service --data-dir "$B" \
  --lan-listen "127.0.0.1:0" --ble-listen "127.0.0.1:0" \
  --internet-listen "0.0.0.0:${B_PORT}" \
  >"$WORKDIR/b.node.log" 2>&1 &
B_PID=$!

for _ in $(seq 1 150); do
  if [[ -S "$A/raven-node.sock" && -S "$B/raven-node.sock" ]] \
    && grep -q "internet_direct: listen" "$WORKDIR/a.node.log" \
    && grep -q "internet_direct: listen" "$WORKDIR/b.node.log"; then
    break
  fi
  if grep -Eqi 'internet_direct failed|INTERNET_DIRECT_HOLD|service identity preflight failed' \
    "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" 2>/dev/null; then
    cat "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
    fail "internet_direct bind/preflight failed"
  fi
  sleep 0.1
done
if [[ ! -S "$A/raven-node.sock" || ! -S "$B/raven-node.sock" ]]; then
  cat "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  fail "daemons failed to create IPC sockets"
fi
"$ASH" --data-dir "$A" ipc-ping >/dev/null
"$ASH" --data-dir "$B" ipc-ping >/dev/null
if ! grep -q "internet_direct: listen" "$WORKDIR/a.node.log" \
  || ! grep -q "internet_direct: listen" "$WORKDIR/b.node.log"; then
  cat "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  fail "internet_direct did not bind"
fi
if ! grep -q "dial≠WAN" "$WORKDIR/a.node.log" || ! grep -q "dial≠WAN" "$WORKDIR/b.node.log"; then
  fail "missing dial≠WAN listen claim marker"
fi
echo "A_INET_PORT=$A_PORT B_INET_PORT=$B_PORT"

echo "=== contact add (trust only; send uses --carrier internet --peer) ==="
"$ASH" --data-dir "$A" contact add \
  --address "$B_ADDR" --pub-hex "$B_PUB" --petname "Bob" --tag bob
"$ASH" --data-dir "$B" contact add \
  --address "$A_ADDR" --pub-hex "$A_PUB" --petname "Alice" --tag alice

echo "=== ash send --carrier internet (localhost indexed; not WAN) ==="
set +e
printf '%s\n' "hello over internet transport" | "$ASH" --data-dir "$A" send \
  --peer "127.0.0.1:${B_PORT}" --peer-pub-hex "$B_PUB" --carrier internet \
  >"$WORKDIR/a.send.out" 2>"$WORKDIR/a.send.err"
SEND_RC=$?
set -e
if [[ "$SEND_RC" -ne 0 ]]; then
  cat "$WORKDIR/a.send.out" "$WORKDIR/a.send.err" "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  fail "send failed rc=$SEND_RC"
fi
if ! grep -qi 'status.*delivered' "$WORKDIR/a.send.out"; then
  cat "$WORKDIR/a.send.out" "$WORKDIR/a.send.err" "$WORKDIR/b.node.log" >&2 || true
  fail "sender did not report delivered"
fi
if ! grep -q 'carrier=internet_dial' "$WORKDIR/a.send.out"; then
  cat "$WORKDIR/a.send.out" >&2 || true
  fail "sender did not log internet_dial carrier"
fi

echo "=== receiver inbox (loopback) ==="
"$ASH" --data-dir "$B" inbox | tee "$WORKDIR/b.inbox.out"
if ! grep -q 'hello over internet transport' "$WORKDIR/b.inbox.out"; then
  cat "$WORKDIR/b.inbox.out" "$WORKDIR/b.node.log" >&2 || true
  fail "inbox missing loopback plaintext"
fi
echo "INTERNET_INDEXED_LOOPBACK_PASS: 127.0.0.1 indexed delivery (not WAN)"

echo "=== ash send --carrier internet via non-loopback ${NON_LOOP_IP} (same-host; not WAN) ==="
set +e
printf '%s\n' "hello over non-loopback internet transport" | "$ASH" --data-dir "$A" send \
  --peer "${NON_LOOP_IP}:${B_PORT}" --peer-pub-hex "$B_PUB" --carrier internet \
  >"$WORKDIR/a.send.nl.out" 2>"$WORKDIR/a.send.nl.err"
NL_RC=$?
set -e
if [[ "$NL_RC" -ne 0 ]]; then
  cat "$WORKDIR/a.send.nl.out" "$WORKDIR/a.send.nl.err" "$WORKDIR/a.node.log" "$WORKDIR/b.node.log" >&2 || true
  fail "non-loopback send failed rc=$NL_RC"
fi
if ! grep -qi 'status.*delivered' "$WORKDIR/a.send.nl.out"; then
  cat "$WORKDIR/a.send.nl.out" "$WORKDIR/a.send.nl.err" "$WORKDIR/b.node.log" >&2 || true
  fail "non-loopback sender did not report delivered"
fi
"$ASH" --data-dir "$B" inbox | tee "$WORKDIR/b.inbox.nl.out"
if ! grep -q 'hello over non-loopback internet transport' "$WORKDIR/b.inbox.nl.out"; then
  cat "$WORKDIR/b.inbox.nl.out" "$WORKDIR/b.node.log" >&2 || true
  fail "inbox missing non-loopback plaintext"
fi
echo "INTERNET_INDEXED_NON_LOOPBACK_PASS: same-host ${NON_LOOP_IP} class=${NON_LOOP_CLASS}"
echo "CLAIM: non-loopback same-host ≠ public-Internet / multi-NAT / WAN Proven"

echo "=== stranger PairInit refused (node C → B internet, no contact on B) ==="
C="$WORKDIR/c"
C_PORT="${C_PORT:-$((21000 + $$ % 500))}"
mkdir -p "$C"
"$ASH" --data-dir "$C" init | tee "$WORKDIR/c.init"
C_ADDR=$(grep '^address=' "$WORKDIR/c.init" | cut -d= -f2)
C_PUB=$(grep '^pub_hex=' "$WORKDIR/c.init" | cut -d= -f2)
test -n "$C_ADDR" && test -n "$C_PUB"
"$ASH" --data-dir "$C" prekey publish
"$NODE" service --data-dir "$C" \
  --lan-listen "127.0.0.1:0" --ble-listen "127.0.0.1:0" \
  --internet-listen "0.0.0.0:${C_PORT}" \
  >"$WORKDIR/c.node.log" 2>&1 &
C_PID=$!
for _ in $(seq 1 80); do
  if [[ -S "$C/raven-node.sock" ]] && grep -q "internet_direct: listen" "$WORKDIR/c.node.log"; then
    break
  fi
  sleep 0.1
done
if [[ ! -S "$C/raven-node.sock" ]]; then
  cat "$WORKDIR/c.node.log" >&2 || true
  fail "stranger daemon failed to create IPC socket"
fi
"$ASH" --data-dir "$C" contact add \
  --address "$B_ADDR" --pub-hex "$B_PUB" --petname "Bob" --tag bob
set +e
printf '%s\n' "stranger probe" | "$ASH" --data-dir "$C" send \
  --peer "127.0.0.1:${B_PORT}" --peer-pub-hex "$B_PUB" --carrier internet \
  >"$WORKDIR/c.send.out" 2>"$WORKDIR/c.send.err"
C_SEND_RC=$?
set -e
if [[ "$C_SEND_RC" -eq 0 ]]; then
  cat "$WORKDIR/c.send.out" "$WORKDIR/c.send.err" "$WORKDIR/b.node.log" >&2 || true
  fail "stranger send unexpectedly succeeded"
fi
if grep -qi 'delivered' "$WORKDIR/c.send.out" 2>/dev/null; then
  fail "stranger send reported delivered"
fi
if ! grep -Eqi 'not a local contact|pair init refused' "$WORKDIR/b.node.log" \
  && ! grep -Eqi 'not a local contact|pair init refused|failed|error|refused' \
    "$WORKDIR/c.send.err" "$WORKDIR/c.send.out"; then
  cat "$WORKDIR/c.send.out" "$WORKDIR/c.send.err" "$WORKDIR/b.node.log" >&2 || true
  fail "expected stranger PairInit refusal in logs"
fi

echo "INTERNET_INDEXED_TWO_NODE_PASS: lab indexed delivery over InternetTransport (RIH1)"
echo "CLAIM: dial≠WAN — loopback + same-host non-loopback (${NON_LOOP_IP}/${NON_LOOP_CLASS}) ≠ public-Internet"
echo "CLAIM: multi-NAT stays BLOCKED_HARDWARE — this smoke does not claim it"
echo "CLAIM: named-pipe ≠ WAN; INTERNET_DIRECT_PRODUCTION_ENABLED=false"
echo "CLAIM: internet_dial_smoke.sh remains the fail-closed gate for legacy raven-node run"
echo "=== INTERNET INDEXED TWO-NODE PASSED ==="
