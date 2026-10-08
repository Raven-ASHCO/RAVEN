#!/usr/bin/env bash
# C7 (docs/design/2026-10-transports-internet-mesh-bridge.md section 6.4): libp2p relay
# + DCUtR hole punching between two raven-node services that sit behind
# simulated NATs, built from Linux network namespaces and nftables.
#
# What it proves (debug build, lab unlock RAVEN_LAB_TEST_A=1, P2P gate off):
#   cone run       each router does plain `masquerade` (Linux keeps the source
#                  port where it can, so one inside port maps to one outside
#                  port for every destination). A and B reserve on relay R,
#                  `raven send --carrier p2p` is delivered both ways, and after
#                  a second message a service logs
#                  "raven-node p2p: direct connection upgraded (dcutr)". A
#                  third message A -> B is then sent, and A's newest link line
#                  must be "raven-node p2p: link via a direct connection" (A
#                  logs that line, with no ids, whenever its link to a peer
#                  changes between relayed and direct).
#   symmetric run  the routers do `masquerade random,fully-random` (a new outside
#                  port per destination, the stage-8 substitute): delivery both
#                  ways still works through the relay. The dcutr line is not
#                  required; the script reports whether it appeared.
#
# Topology (rebuilt from scratch for each run; no interface is created on the
# host, and every namespace name carries a per-run prefix):
#
#   hA 192.168.1.2 -- 192.168.1.1 rA 10.0.1.2 -- 10.0.1.1 \
#                    (nft masquerade)                     pub: relay R on 10.0.0.1
#   hB 192.168.2.2 -- 192.168.2.1 rB 10.0.2.2 -- 10.0.2.1 /   (routes the two links)
#
# The routers drop unsolicited inbound packets (like a home router) and forward
# only lan -> wan plus replies; pub has no route to either 192.168 network, so A
# and B can reach each other only through the NATs.
#
# HONEST CLAIM: a software substitute. It does NOT replace the physical rows R7b
# (DCUtR between two homes behind consumer NAT + a VPS relay) and R8 (relay-only
# behind CGNAT): Linux conntrack is not every consumer router, and both
# "Internet" links are one kernel (docs/NAT_SOFTWARE_SIM.md "Honest claim").
#
# Written on macOS and NOT run locally (macOS has no network namespaces); the
# lab CI job nat-sim-linux (.github/workflows/raven-serverless-lab.yml,
# advisory) runs it on ubuntu-latest.
#
# Usage: build the debug binaries first, as yourself (never cargo as root):
#   (cd node && cargo build --locked -p ash -p raven-node)
#   sudo -E env "PATH=$PATH" bash node/scripts/netns_nat_dcutr.sh
# or let the script re-run itself under `sudo -E`:
#   RAVEN_NETNS_ALLOW_SUDO=1 bash node/scripts/netns_nat_dcutr.sh
# Environment:
#   RAVEN_BIN_DIR              raven + raven-node (default <repo>/node/target/debug)
#   RAVEN_NETNS_TMP            base dir for the per-run temp dirs (kept afterwards;
#                              default: a mktemp -d dir, removed unless RAVEN_NETNS_KEEP=1)
#   RAVEN_NETNS_ALLOW_RELEASE=1  run against a release build path anyway (only
#                              useful once P2P_PRODUCTION_ENABLED is true)
# Exit: 0 = both runs met their expectations, 1 = a run failed, 2 = cannot run here.
set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
ROOT="$(cd "$(dirname "$SELF")/.." && pwd)"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "netns_nat_dcutr: Linux only (network namespaces + nftables); see docs/NAT_SOFTWARE_SIM.md for macOS substitutes" >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  if [[ "${RAVEN_NETNS_ALLOW_SUDO:-0}" == "1" ]]; then
    echo "netns_nat_dcutr: not root; re-running under sudo -E (RAVEN_NETNS_ALLOW_SUDO=1)" >&2
    exec sudo -E env "PATH=$PATH" bash "$SELF" "$@"
  fi
  echo "netns_nat_dcutr: needs root (it creates network namespaces and nftables NAT rules)." >&2
  echo "  Run: sudo -E env \"PATH=\$PATH\" bash $SELF" >&2
  echo "  or:  RAVEN_NETNS_ALLOW_SUDO=1 bash $SELF   (re-runs itself under sudo -E)" >&2
  exit 2
fi

BIN_DIR="${RAVEN_BIN_DIR:-$ROOT/target/debug}"
NODE="$BIN_DIR/raven-node"
RAVEN="$BIN_DIR/raven"
case "$BIN_DIR" in
  */release | */release/*)
    if [[ "${RAVEN_NETNS_ALLOW_RELEASE:-0}" != "1" ]]; then
      echo "netns_nat_dcutr: RAVEN_BIN_DIR=$BIN_DIR is a release build path. The lab unlock" >&2
      echo "  RAVEN_LAB_TEST_A=1 only works in debug builds, so a release raven-node keeps the p2p" >&2
      echo "  gate closed (P2P_PRODUCTION_ENABLED=false: it logs P2P_HOLD and never listens) and this" >&2
      echo "  test cannot pass. Use target/debug, or set RAVEN_NETNS_ALLOW_RELEASE=1 once the gate is open." >&2
      exit 2
    fi
    ;;
esac
for bin in "$NODE" "$RAVEN"; do
  if [[ ! -x "$bin" ]]; then
    echo "netns_nat_dcutr: missing $bin; build it first (as yourself, not root):" >&2
    echo "  (cd $ROOT && cargo build --locked -p ash -p raven-node)" >&2
    exit 2
  fi
done
for tool in ip nft timeout sysctl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "netns_nat_dcutr: missing '$tool' (Debian/Ubuntu: apt-get install -y iproute2 nftables coreutils procps)" >&2
    exit 2
  fi
done
if ! command -v python3 >/dev/null 2>&1 && ! command -v jq >/dev/null 2>&1; then
  echo "netns_nat_dcutr: needs python3 (or jq) to read relay_status.json" >&2
  exit 2
fi

# Same lab environment for every process (debug locked-file backends, as the
# other smokes use). Caller settings that would change the services are dropped:
# flags beat env, but RAVEN_P2P_RELAY=1 alone would turn A and B into relays.
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1
export RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0
export NO_COLOR=1
export RAVEN_LAB_TEST_A=1
unset RAVEN_P2P_LISTEN RAVEN_P2P_RELAYS RAVEN_P2P_RELAY RAVEN_INTERNET_LISTEN \
  RAVEN_DATA_DIR ASH_DATA_DIR 2>/dev/null || true

# Bounds (seconds). Every wait below is a deadline loop on an observable
# condition and fails with all logs printed.
RELAY_WAIT=30
RESERVE_WAIT=90
CLI_TIMEOUT=60
SEND_TIMEOUT=120
INBOX_WAIT=15
DCUTR_WAIT=90
DCUTR_OBSERVE=20

LINE_HOLD='P2P_HOLD:'
LINE_RESERVED='raven-node p2p: reservation accepted'
LINE_DCUTR='raven-node p2p: direct connection upgraded (dcutr)'
LINE_LINK='raven-node p2p: link via '
LINE_LINK_DIRECT='raven-node p2p: link via a direct connection'

# Per-run prefix: never touches (or deletes) a namespace this script did not make.
NSP="rvn$$"
NS_PUB="${NSP}-pub"
NS_RA="${NSP}-rA"
NS_RB="${NSP}-rB"
NS_HA="${NSP}-hA"
NS_HB="${NSP}-hB"

BASE_OWNED=0
if [[ -n "${RAVEN_NETNS_TMP:-}" ]]; then
  BASE="$RAVEN_NETNS_TMP"
  mkdir -p "$BASE"
else
  BASE="$(mktemp -d)"
  BASE_OWNED=1
fi
BASE="$(cd "$BASE" && pwd)"

# Namespaces with our prefix: kill whatever still runs inside, then delete them.
teardown_net() {
  local ns pids
  for ns in $(ip netns list 2>/dev/null | awk -v p="${NSP}-" 'index($1, p) == 1 { print $1 }'); do
    pids="$(ip netns pids "$ns" 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
      # shellcheck disable=SC2086 # one PID per word
      kill -KILL $pids 2>/dev/null || true
    fi
    ip netns del "$ns" 2>/dev/null || true
  done
}

main_cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  teardown_net
  if [[ "$BASE_OWNED" == "1" && "${RAVEN_NETNS_KEEP:-0}" != "1" ]]; then
    rm -rf "$BASE"
  else
    echo "netns_nat_dcutr: run dirs (logs under */logs) kept in $BASE" >&2
  fi
  exit "$rc"
}
trap main_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- per-run helpers (used inside the run subshell) -------------------------

PIDS=()
MODE=""
LOGS=""
R=""
VIA=""

dump_logs() {
  local f
  if [[ -z "$LOGS" || ! -d "$LOGS" ]]; then
    return 0
  fi
  echo "===== logs of the $MODE run ($LOGS) =====" >&2
  for f in "$LOGS"/*; do
    [[ -f "$f" ]] || continue
    echo "----- $(basename "$f")" >&2
    cat "$f" >&2 || true
  done
  if [[ -n "$R" && -s "$R/relay_status.json" ]]; then
    echo "----- relay_status.json" >&2
    cat "$R/relay_status.json" >&2 || true
    echo >&2
  fi
  echo "===== end of logs ($MODE) =====" >&2
}

fail() {
  echo "NETNS_NAT_DCUTR_FAIL ($MODE): $*" >&2
  dump_logs
  exit 1
}

stop_procs() {
  local pid alive i
  if [[ ${#PIDS[@]} -eq 0 ]]; then
    return 0
  fi
  for pid in "${PIDS[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done
  for ((i = 0; i < 50; i++)); do
    alive=0
    for pid in "${PIDS[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then alive=1; fi
    done
    [[ "$alive" -eq 1 ]] || break
    sleep 0.1
  done
  for pid in "${PIDS[@]}"; do
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  PIDS=()
}

run_cleanup() {
  trap - EXIT INT TERM
  stop_procs
  teardown_net
}

# in_ns NS CMD...: CMD inside NS, bounded by CLI_TIMEOUT.
in_ns() {
  local ns=$1
  shift
  timeout "$CLI_TIMEOUT" ip netns exec "$ns" "$@"
}

# Fails when any of the given PIDs has exited.
require_alive() {
  local pid
  for pid in "$@"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      fail "process $pid exited early"
    fi
  done
}

# Fails when a log says the p2p gate is closed.
check_hold() {
  local log
  for log in "$@"; do
    if grep -Fq -- "$LINE_HOLD" "$log" 2>/dev/null; then
      fail "$(basename "$log") logged $LINE_HOLD: the p2p gate is closed. The lab unlock RAVEN_LAB_TEST_A=1 only works in debug builds ($NODE)."
    fi
  done
}

# wait_line LOG FIXED_TEXT SECS PID...: until LOG contains FIXED_TEXT.
wait_line() {
  local log=$1 text=$2 secs=$3 deadline
  shift 3
  deadline=$((SECONDS + secs))
  while ((SECONDS < deadline)); do
    if grep -Fq -- "$text" "$log" 2>/dev/null; then
      return 0
    fi
    check_hold "$log"
    require_alive "$@"
    sleep 0.2
  done
  fail "'$text' not in $(basename "$log") within ${secs}s"
}

# wait_ipc NS DATA_DIR SECS PID: until the daemon answers `raven ipc-ping`.
wait_ipc() {
  local ns=$1 dir=$2 secs=$3 pid=$4 deadline
  deadline=$((SECONDS + secs))
  while ((SECONDS < deadline)); do
    if in_ns "$ns" "$RAVEN" --data-dir "$dir" ipc-ping >/dev/null 2>&1; then
      return 0
    fi
    require_alive "$pid"
    sleep 0.2
  done
  fail "daemon for $dir did not answer ipc-ping within ${secs}s"
}

# Prints relay_status.json's peer_id (nothing while the file is absent or partial).
relay_peer_id() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["peer_id"])' "$1" 2>/dev/null || true
  else
    jq -er '.peer_id' "$1" 2>/dev/null || true
  fi
}

# One router namespace: forwarding on, NAT out of "wan", drop unsolicited inbound.
nat_rules() {
  local ns=$1 masq=$2
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$ns" nft -f - <<EOF
table ip raven_nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname "wan" $masq
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "lan" oifname "wan" accept
  }
  chain input {
    type filter hook input priority 0; policy accept;
    iifname "wan" ct state new drop
  }
}
EOF
}

setup_net() {
  local masq=$1 ns
  for ns in "$NS_PUB" "$NS_RA" "$NS_RB" "$NS_HA" "$NS_HB"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
  done
  # veth pairs are created inside the namespaces: nothing appears on the host.
  ip -n "$NS_PUB" link add wa type veth peer name wan netns "$NS_RA"
  ip -n "$NS_PUB" link add wb type veth peer name wan netns "$NS_RB"
  ip -n "$NS_RA" link add lan type veth peer name eth0 netns "$NS_HA"
  ip -n "$NS_RB" link add lan type veth peer name eth0 netns "$NS_HB"
  # pub = "the Internet": R on 10.0.0.1, one link per router, routes between them.
  ip -n "$NS_PUB" addr add 10.0.0.1/32 dev lo
  ip -n "$NS_PUB" addr add 10.0.1.1/24 dev wa
  ip -n "$NS_PUB" addr add 10.0.2.1/24 dev wb
  ip -n "$NS_PUB" link set wa up
  ip -n "$NS_PUB" link set wb up
  ip netns exec "$NS_PUB" sysctl -qw net.ipv4.ip_forward=1
  ip -n "$NS_RA" addr add 10.0.1.2/24 dev wan
  ip -n "$NS_RA" addr add 192.168.1.1/24 dev lan
  ip -n "$NS_RA" link set wan up
  ip -n "$NS_RA" link set lan up
  ip -n "$NS_RA" route add default via 10.0.1.1
  ip -n "$NS_RB" addr add 10.0.2.2/24 dev wan
  ip -n "$NS_RB" addr add 192.168.2.1/24 dev lan
  ip -n "$NS_RB" link set wan up
  ip -n "$NS_RB" link set lan up
  ip -n "$NS_RB" route add default via 10.0.2.1
  ip -n "$NS_HA" addr add 192.168.1.2/24 dev eth0
  ip -n "$NS_HA" link set eth0 up
  ip -n "$NS_HA" route add default via 192.168.1.1
  ip -n "$NS_HB" addr add 192.168.2.2/24 dev eth0
  ip -n "$NS_HB" link set eth0 up
  ip -n "$NS_HB" route add default via 192.168.2.1
  nat_rules "$NS_RA" "$masq"
  nat_rules "$NS_RB" "$masq"
  {
    echo "== $MODE: routers do '$masq'"
    ip netns exec "$NS_RA" nft list ruleset
  } >"$LOGS/topology.log" 2>&1
  # Sanity (when ping exists): both hosts reach R through their NAT, and neither
  # reaches the other's private address.
  if command -v ping >/dev/null 2>&1; then
    in_ns "$NS_HA" ping -c 1 -W 2 10.0.0.1 >>"$LOGS/topology.log" 2>&1 || fail "hA cannot reach R (10.0.0.1) through rA"
    in_ns "$NS_HB" ping -c 1 -W 2 10.0.0.1 >>"$LOGS/topology.log" 2>&1 || fail "hB cannot reach R (10.0.0.1) through rB"
    if in_ns "$NS_HA" ping -c 1 -W 1 192.168.2.2 >>"$LOGS/topology.log" 2>&1; then
      fail "hA reaches hB's private address directly: the topology leaks"
    fi
  fi
}

# raven_init NS DIR NAME: init + prekey publish; sets INIT_FP (the fingerprint).
INIT_FP=""
raven_init() {
  local ns=$1 dir=$2 name=$3 out addr pub fp
  out="$LOGS/$name.init.out"
  in_ns "$ns" "$RAVEN" --data-dir "$dir" init >"$out" 2>&1 || fail "raven init ($name) failed"
  addr="$(sed -n 's/^address=//p' "$out" | head -n 1)"
  pub="$(sed -n 's/^pub_hex=//p' "$out" | head -n 1)"
  fp="$(sed -n 's/^fingerprint=//p' "$out" | head -n 1)"
  if [[ -z "$addr" || -z "$pub" || -z "$fp" ]]; then
    fail "raven init ($name) printed no address= / pub_hex= / fingerprint= line"
  fi
  in_ns "$ns" "$RAVEN" --data-dir "$dir" prekey publish >"$LOGS/$name.prekey.out" 2>&1 \
    || fail "raven prekey publish ($name) failed"
  INIT_FP="$fp"
}

# raven_card NS DIR NAME: sets CARD to the one raven-card/2 line (with via=$VIA).
CARD=""
raven_card() {
  local ns=$1 dir=$2 name=$3 out card
  out="$LOGS/$name.card.out"
  in_ns "$ns" "$RAVEN" --data-dir "$dir" whoami --card --via "$VIA" >"$out" 2>&1 \
    || fail "raven whoami --card ($name) failed"
  card="$(grep -m 1 '^raven-card/2' "$out" || true)"
  if [[ -z "$card" ]]; then
    fail "raven whoami --card --via ($name) printed no raven-card/2 line"
  fi
  if [[ "$card" != *" p2p="* ]]; then
    fail "the $name card has no p2p= field"
  fi
  CARD="$card"
}

# send_check NS DIR TO TEXT TAG: `raven send --carrier p2p` must report delivered.
send_check() {
  local ns=$1 dir=$2 to=$3 text=$4 tag=$5 rc=0
  printf '%s\n' "$text" | timeout "$SEND_TIMEOUT" ip netns exec "$ns" "$RAVEN" --data-dir "$dir" \
    send --contact "@$to" --carrier p2p >"$LOGS/$tag.send.out" 2>"$LOGS/$tag.send.err" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    fail "send $tag exited $rc"
  fi
  if ! awk 'tolower($0) ~ /status/ && tolower($0) ~ /delivered/ { found = 1 } END { exit !found }' \
    "$LOGS/$tag.send.out"; then
    fail "send $tag did not print a 'status ... delivered' line"
  fi
}

# inbox_once NS DIR TEXT TAG: the receiver's inbox shows TEXT exactly once.
inbox_once() {
  local ns=$1 dir=$2 text=$3 tag=$4 out deadline count
  out="$LOGS/$tag.inbox.out"
  deadline=$((SECONDS + INBOX_WAIT))
  while :; do
    in_ns "$ns" "$RAVEN" --data-dir "$dir" inbox >"$out" 2>&1 || fail "raven inbox ($tag) failed"
    count="$(grep -cF -- "$text" "$out" || true)"
    if [[ "$count" -ge 1 ]] || ((SECONDS >= deadline)); then
      break
    fi
    sleep 0.5
  done
  if [[ "$count" -ne 1 ]]; then
    fail "inbox ($tag) shows '$text' $count times, expected exactly once"
  fi
}

# dcutr_seen: true when either service logged the DCUtR upgrade.
dcutr_seen() {
  grep -Fq -- "$LINE_DCUTR" "$LOGS/a.service.log" "$LOGS/b.service.log" 2>/dev/null
}

# ---- one run ----------------------------------------------------------------

run_case() {
  local masq run_dir a b relay_pid a_pid b_pid peer deadline a_fp b_fp a_card b_card
  MODE=$1
  case "$MODE" in
    cone) masq="masquerade" ;;
    symmetric) masq="masquerade random,fully-random" ;;
    *) echo "unknown run $MODE" >&2; exit 1 ;;
  esac
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  run_dir="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$run_dir/logs"
  R="$run_dir/r"
  a="$run_dir/a"
  b="$run_dir/b"
  mkdir -p "$LOGS" "$R" "$a" "$b"
  chmod 700 "$R" "$a" "$b"
  echo "=== $MODE run: routers do '$masq' (dirs under $run_dir) ==="

  setup_net "$masq"

  echo "--- relay R in pub on 10.0.0.1:7423"
  ip netns exec "$NS_PUB" "$NODE" relay --data-dir "$R" --listen 10.0.0.1:7423 \
    >"$LOGS/relay.log" 2>&1 &
  relay_pid=$!
  PIDS+=("$relay_pid")
  peer=""
  deadline=$((SECONDS + RELAY_WAIT))
  while ((SECONDS < deadline)); do
    if [[ -s "$R/relay_status.json" ]]; then
      peer="$(relay_peer_id "$R/relay_status.json")"
      [[ -z "$peer" ]] || break
    fi
    check_hold "$LOGS/relay.log"
    require_alive "$relay_pid"
    sleep 0.2
  done
  if [[ -z "$peer" ]]; then
    fail "relay_status.json with a peer_id not written within ${RELAY_WAIT}s"
  fi
  if [[ ! "$peer" =~ ^[1-9A-HJ-NP-Za-km-z]+$ ]]; then
    fail "relay peer_id is not a base58 PeerId"
  fi
  VIA="/ip4/10.0.0.1/tcp/7423/p2p/$peer"
  echo "VIA=$VIA"

  echo "--- init A (hA) and B (hB), cards with via=, allow both on R"
  raven_init "$NS_HA" "$a" a
  a_fp="$INIT_FP"
  raven_init "$NS_HB" "$b" b
  b_fp="$INIT_FP"
  raven_card "$NS_HA" "$a" a
  a_card="$CARD"
  raven_card "$NS_HB" "$b" b
  b_card="$CARD"
  in_ns "$NS_PUB" "$RAVEN" --data-dir "$R" relay allow --card "$a_card" >"$LOGS/relay.allow.out" 2>&1 \
    || fail "raven relay allow (A) failed"
  in_ns "$NS_PUB" "$RAVEN" --data-dir "$R" relay allow --card "$b_card" >>"$LOGS/relay.allow.out" 2>&1 \
    || fail "raven relay allow (B) failed"

  echo "--- services: A in hA, B in hB (p2p 0.0.0.0:7423, relay R)"
  ip netns exec "$NS_HA" "$NODE" service --data-dir "$a" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen 0.0.0.0:7423 --p2p-relay "$VIA" --timeout-secs 0 \
    >"$LOGS/a.service.log" 2>&1 &
  a_pid=$!
  PIDS+=("$a_pid")
  ip netns exec "$NS_HB" "$NODE" service --data-dir "$b" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen 0.0.0.0:7423 --p2p-relay "$VIA" --timeout-secs 0 \
    >"$LOGS/b.service.log" 2>&1 &
  b_pid=$!
  PIDS+=("$b_pid")
  wait_line "$LOGS/a.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$a_pid" "$relay_pid"
  wait_line "$LOGS/b.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$b_pid" "$relay_pid"
  wait_ipc "$NS_HA" "$a" 30 "$a_pid"
  wait_ipc "$NS_HB" "$b" 30 "$b_pid"
  echo "both services hold a reservation on R"

  echo "--- pin each other (verified contacts only use p2p)"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact add --card "$b_card" \
    --petname bob --tag bob --verify-fp "$b_fp" >"$LOGS/a.contact.out" 2>&1 || fail "A contact add bob failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" contact add --card "$a_card" \
    --petname alice --tag alice --verify-fp "$a_fp" >"$LOGS/b.contact.out" 2>&1 || fail "B contact add alice failed"

  echo "--- A -> B and B -> A over --carrier p2p"
  send_check "$NS_HA" "$a" bob "hello-$MODE-a2b-1" a2b-1
  inbox_once "$NS_HB" "$b" "hello-$MODE-a2b-1" b-1
  send_check "$NS_HB" "$b" alice "hello-$MODE-b2a-1" b2a-1
  inbox_once "$NS_HA" "$a" "hello-$MODE-b2a-1" a-1
  echo "delivered both ways"

  echo "--- second message A -> B"
  send_check "$NS_HA" "$a" bob "hello-$MODE-a2b-2" a2b-2
  inbox_once "$NS_HB" "$b" "hello-$MODE-a2b-2" b-2
  check_hold "$LOGS/a.service.log" "$LOGS/b.service.log"

  if [[ "$MODE" == "cone" ]]; then
    wait_dcutr "$DCUTR_WAIT" "$a_pid" "$b_pid"
    if ! dcutr_seen; then
      fail "no service logged '$LINE_DCUTR' within ${DCUTR_WAIT}s (cone NAT: hole punching expected)"
    fi
    echo "--- third message A -> B (after the upgrade)"
    send_check "$NS_HA" "$a" bob "hello-$MODE-a2b-3" a2b-3
    inbox_once "$NS_HB" "$b" "hello-$MODE-a2b-3" b-3
    # The link line is logged only when the kind changes, so the newest one
    # says what the third message rode on.
    last_link="$(grep -F -- "$LINE_LINK" "$LOGS/a.service.log" | tail -n 1 || true)"
    if [[ "$last_link" != *"$LINE_LINK_DIRECT"* ]]; then
      fail "after the upgrade A's newest link line is '${last_link:-none}', not '$LINE_LINK_DIRECT'"
    fi
    echo "RESULT cone: delivered both ways; DCUtR upgraded the relayed connection to a direct one, and the next message used it"
  else
    wait_dcutr "$DCUTR_OBSERVE" "$a_pid" "$b_pid"
    if dcutr_seen; then
      echo "RESULT symmetric: delivered both ways; dcutr line APPEARED (not expected behind symmetric NAT; delivery is what this run requires)"
    else
      echo "RESULT symmetric: delivered both ways over the relay; dcutr line did not appear (expected behind symmetric NAT)"
    fi
  fi
  if [[ -s "$R/relay_status.json" ]]; then
    echo "relay_status.json: $(tr -d '\n' <"$R/relay_status.json")"
  fi
}

# wait_dcutr SECS PID...: until a service logs the upgrade (no failure on timeout).
wait_dcutr() {
  local secs=$1 deadline
  shift
  deadline=$((SECONDS + secs))
  while ((SECONDS < deadline)); do
    if dcutr_seen; then
      return 0
    fi
    require_alive "$@"
    sleep 0.5
  done
  return 0
}

# ---- main -------------------------------------------------------------------

echo "netns_nat_dcutr: binaries from $BIN_DIR, run dirs under $BASE, namespaces ${NSP}-*"
CONE_RC=0
SYMMETRIC_RC=0
# Each run in its own subshell (own traps, own cleanup) so the second run still
# happens and reports after a first-run failure. Plain statements, not `if`
# conditions: errexit stays on inside them.
set +e
(
  set -e
  run_case cone
)
CONE_RC=$?
(
  set -e
  run_case symmetric
)
SYMMETRIC_RC=$?
set -e

echo "=== summary ==="
if [[ "$CONE_RC" -eq 0 ]]; then
  echo "cone:      PASS (relay delivery both ways + DCUtR direct upgrade + a message over it)"
else
  echo "cone:      FAIL (exit $CONE_RC)"
fi
if [[ "$SYMMETRIC_RC" -eq 0 ]]; then
  echo "symmetric: PASS (relay delivery both ways)"
else
  echo "symmetric: FAIL (exit $SYMMETRIC_RC)"
fi
echo "CLAIM: software NAT substitute (netns + nftables masquerade); does NOT replace physical rows R7b / R8"
echo "CLAIM: debug build with RAVEN_LAB_TEST_A=1; P2P_PRODUCTION_ENABLED=false (not WAN Proven)"
if [[ "$CONE_RC" -ne 0 || "$SYMMETRIC_RC" -ne 0 ]]; then
  echo "NETNS_NAT_DCUTR_FAIL" >&2
  exit 1
fi
echo "NETNS_NAT_DCUTR_PASS"
