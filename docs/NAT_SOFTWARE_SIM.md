# NAT / multi-homed software substitutes

**Live multi-NAT / CGNAT / DCUtR:** still `BLOCKED_HARDWARE` (see `node/NAT_TRAVERSAL.md`).

Sprint 0 inventory of raven-swarm status vs that target: [`docs/network/raven-swarm-connectivity-matrix.md`](network/raven-swarm-connectivity-matrix.md).

## What this Mac can automate

| Tool | Script / command | Proves |
|---|---|---|
| Docker dual bridge nets | `scripts/nat_docker_sim.sh` | Two peers on isolated L2 cannot dial each other; a dual-homed relay can reach both |
| pfctl | present at `/sbin/pfctl` | Operator may add divert rules; **not** automated here (needs root + careful host policy) |
| Linux `unshare` netns | **not** on macOS | Use Linux CI / VM for true netns |
| Localhost carrier checks | `bridge_abc_demo`, `internet_dial_smoke`, `libp2p_swarm_smoke` | Bridge/store software behavior plus an explicit raw-Internet production hold |

## Run Docker substitute

```bash
bash scripts/nat_docker_sim.sh
# → RESULT=PASS under node/proof_artifacts/nat_docker_*/
```

Requires Docker Desktop running. If Docker is absent/stopped, the script **SKIP**s (exit 0) so CI hosts without Docker stay green; treat SKIP as “substitute not executed”.

## Operator pf sketch (manual, root)

```bash
# Example only — do not paste blindly into production hosts.
# Create two utun/VM interfaces, assign RFC1918 ranges, deny direct A↔B, allow A/B→relay.
sudo pfctl -s rules   # inspect current
```

Document any pf experiment under `node/proof_artifacts/` (no secrets).

## Honest claim

Software substitutes **maximize** confidence that routing policy + relay/store paths work.  
They **do not** replace a carrier-grade NAT matrix or libp2p DCUtR on the public Internet.
