#!/usr/bin/env bash
# Docker dual-bridge TOPOLOGY check (no public CGNAT). Two isolated bridge
# networks + a relay container attached to both. Proves ONLY the topology:
# A and B cannot reach each other directly (connect times out / network
# unreachable), the dual-homed relay reaches A and B, and A reaches the relay.
# The containers run python TCP echo listeners: NO Raven code (no ash,
# raven-node or raven-swarm, no relay or NAT-traversal logic) runs here, so a
# pass is not evidence about Raven relay / NAT behaviour. The reliability matrix
# records it as PASS_SOFTWARE_SUBSTITUTE for that reason.
#
# Requires: Docker Desktop / Engine. Does NOT claim live CGNAT/DCUtR (§59 hardware).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
NODE_ROOT="$REPO/node"
ART_DIR="${RAVEN_NAT_ART:-$NODE_ROOT/proof_artifacts/nat_docker_$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$ART_DIR"
source "${HOME}/.cargo/env" 2>/dev/null || true

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker not available"
  {
    echo "RESULT=SKIP"
    echo "reason=docker_cli_missing"
    echo "claim=none — install Docker to run dual-network NAT substitute"
  } | tee "$ART_DIR/RESULT.txt"
  exit 0
fi
# Auto-wire Lima Docker socket when host dockerd is down (macOS).
if ! docker info >/dev/null 2>&1; then
  LIMA_SOCK="${HOME}/.lima/ash-amd64-preflight/sock/docker.sock"
  if [[ -S "$LIMA_SOCK" ]]; then
    export DOCKER_HOST="unix://$LIMA_SOCK"
    echo "Using Lima Docker: DOCKER_HOST=$DOCKER_HOST"
  elif docker context ls 2>/dev/null | grep -q 'lima-ash-amd64-preflight'; then
    export DOCKER_CONTEXT=lima-ash-amd64-preflight
    echo "Using Docker context: $DOCKER_CONTEXT"
  fi
fi
if ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker daemon not running"
  {
    echo "RESULT=SKIP"
    echo "reason=docker_daemon_down"
    echo "claim=none — start Docker Desktop / dockerd / limactl start ash-amd64-preflight, re-run scripts/nat_docker_sim.sh"
  } | tee "$ART_DIR/RESULT.txt"
  # Also leave a pointer under proof_artifacts for §59 operators
  mkdir -p "$NODE_ROOT/proof_artifacts"
  echo "$ART_DIR" >"$NODE_ROOT/proof_artifacts/NAT_DOCKER_LAST.txt"
  exit 0
fi

NET_A="raven-nat-a-$$"
NET_B="raven-nat-b-$$"
IMG="rust:1.85-bookworm"
cleanup() {
  docker rm -f "raven-relay-$$" "raven-peer-a-$$" "raven-peer-b-$$" 2>/dev/null || true
  docker network rm "$NET_A" "$NET_B" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== NAT docker sim art=$ART_DIR ==="
docker network create --driver bridge --internal=false "$NET_A" >/dev/null
docker network create --driver bridge --internal=false "$NET_B" >/dev/null

# Relay attached to BOTH networks (simulates a reachable store/relay on the public side)
docker run -d --name "raven-relay-$$" --network "$NET_A" "$IMG" sleep 600 >/dev/null
docker network connect "$NET_B" "raven-relay-$$"

# Peers each on one network only
docker run -d --name "raven-peer-a-$$" --network "$NET_A" "$IMG" sleep 600 >/dev/null
docker run -d --name "raven-peer-b-$$" --network "$NET_B" "$IMG" sleep 600 >/dev/null

# Topology proof via python TCP echo in the containers (no Raven binaries):
# A can reach relay; relay can reach A and B; A cannot reach B directly.

RELAY_IP_A=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "raven-relay-$$" | awk '{print $1}')
# Get IP of relay on net B
RELAY_IP_B=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET_B\").IPAddress}}" "raven-relay-$$")
PEER_A_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET_A\").IPAddress}}" "raven-peer-a-$$")
PEER_B_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET_B\").IPAddress}}" "raven-peer-b-$$")

{
  echo "net_a=$NET_A"
  echo "net_b=$NET_B"
  echo "relay_on_a=$RELAY_IP_A"
  echo "relay_on_b=$RELAY_IP_B"
  echo "peer_a=$PEER_A_IP"
  echo "peer_b=$PEER_B_IP"
} | tee "$ART_DIR/topology.txt"

# Peer listeners
docker exec -d "raven-peer-a-$$" bash -lc 'python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((\"0.0.0.0\",9100)); s.listen(1)
c,_=s.accept(); data=c.recv(64); c.sendall(b\"ACK-A:\"+data); c.close()
"'
docker exec -d "raven-peer-b-$$" bash -lc 'python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((\"0.0.0.0\",9100)); s.listen(1)
c,_=s.accept(); data=c.recv(64); c.sendall(b\"ACK-B:\"+data); c.close()
"'
# Readiness, not a fixed sleep: wait until each peer shows a LISTEN socket on
# 9100 in /proc/net/tcp (state 0A) WITHOUT connecting (the listeners are
# one-shot). Otherwise the isolation probe below could be refused for the wrong
# reason, which the probe now (correctly) treats as inconclusive.
wait_listening() {
  docker exec "$1" python3 -c "
import sys, time
want = ':%04X' % 9100
deadline = time.time() + 10
while time.time() < deadline:
    for line in open('/proc/net/tcp').read().splitlines()[1:]:
        f = line.split()
        if f[1].endswith(want) and f[3] == '0A':
            sys.exit(0)
    time.sleep(0.1)
sys.exit('no LISTEN socket on 9100 in $1')
"
}
wait_listening "raven-peer-a-$$"
wait_listening "raven-peer-b-$$"

# A reaches relay (same net): real TCP connect to a relay-side listener (connect
# retries absorb the listener start-up; no fixed sleep, no `|| true`).
docker exec -d "raven-relay-$$" bash -lc 'python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((\"0.0.0.0\",9200)); s.listen(1)
c,_=s.accept(); data=c.recv(64); c.sendall(b\"ACK-RELAY:\"+data); c.close()
"'
docker exec "raven-peer-a-$$" python3 -c "
import socket, time
deadline = time.time() + 10
while True:
    try:
        s = socket.create_connection(('$RELAY_IP_A', 9200), timeout=2)
        break
    except ConnectionRefusedError:
        if time.time() > deadline:
            raise
        time.sleep(0.2)
s.sendall(b'from-a')
print(s.recv(64))
" | tee "$ART_DIR/a_to_relay.txt"

# Prove A cannot route to B's IP (different isolated networks). ONLY a connect
# timeout or ENETUNREACH/EHOSTUNREACH counts as isolation: a refused connection
# means the host WAS reachable (nothing listening), which proves nothing.
set +e
docker exec "raven-peer-a-$$" python3 -c "
import errno, socket, sys
try:
    socket.create_connection(('$PEER_B_IP', 9100), timeout=2)
    print('UNEXPECTED_DIRECT_OK')
    sys.exit(2)
except socket.timeout:
    print('DIRECT_BLOCKED_OK', 'timeout')
except OSError as e:
    if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        print('DIRECT_BLOCKED_OK', errno.errorcode[e.errno])
    else:
        print('DIRECT_INCONCLUSIVE', type(e).__name__, e)
        sys.exit(3)
" | tee "$ART_DIR/a_to_b_direct.txt"
DIRECT_RC=$?
set -e

# Relay can reach both peers (simulates store/relay on "public" attachment)
docker exec "raven-relay-$$" bash -lc "python3 -c \"
import socket
sa=socket.create_connection(('$PEER_A_IP', 9100), timeout=5); sa.sendall(b'from-relay'); print(sa.recv(64))
\"" | tee "$ART_DIR/relay_to_a.txt"
docker exec -d "raven-peer-a-$$" bash -lc 'python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((\"0.0.0.0\",9100)); s.listen(1)
c,_=s.accept(); data=c.recv(64); c.sendall(b\"ACK-A:\"+data); c.close()
"' 2>/dev/null || true
sleep 0.5
# Re-bind B listener if consumed
docker exec -d "raven-peer-b-$$" bash -lc 'python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((\"0.0.0.0\",9100)); s.listen(1)
c,_=s.accept(); data=c.recv(64); c.sendall(b\"ACK-B:\"+data); c.close()
"'
sleep 0.5
docker exec "raven-relay-$$" bash -lc "python3 -c \"
import socket
sb=socket.create_connection(('$PEER_B_IP', 9100), timeout=5); sb.sendall(b'from-relay'); print(sb.recv(64))
\"" | tee "$ART_DIR/relay_to_b.txt"

if [[ "$DIRECT_RC" -ne 0 ]]; then
  echo "isolation probe inconclusive or A reached B directly (rc=$DIRECT_RC)" >&2
  exit 1
fi
grep -q 'DIRECT_BLOCKED_OK' "$ART_DIR/a_to_b_direct.txt"
grep -q 'ACK-RELAY' "$ART_DIR/a_to_relay.txt"
grep -q 'ACK-A' "$ART_DIR/relay_to_a.txt"
grep -q 'ACK-B' "$ART_DIR/relay_to_b.txt"

{
  echo "RESULT=PASS"
  echo "claim=docker dual-bridge topology only: A/B isolated, relay reaches both (python TCP echo; no Raven code)"
  echo "not_claimed=raven_relay,raven_swarm,public_CGNAT,DCUtR,AutoNAT"
} | tee "$ART_DIR/RESULT.txt"

echo "=== NAT DOCKER SIM OK ==="
echo "artifacts: $ART_DIR"
