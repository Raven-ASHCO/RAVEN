# ADR 0002 — Internet networking

**Status:** Experimental / production hold (localhost lab path now wired)  
**Date:** 2026-08-12  
**Updated:** 2026-09-06

## Decision

1. **V1 laboratory path:** `InternetTransport` in `raven-core` is the RIH1 hello +
   length-prefix codec. `raven-node` `internet_direct` now opens sockets, exchanges
   that hello, then carries the same indexed PairInit / sealed message / sealed ACK
   dispatcher as LAN-direct. The slice gate
   `INTERNET_DIRECT_PRODUCTION_ENABLED` is **false**. Live CI uses debug
   `RAVEN_LAB_TEST_A=1`. This is **not** a shipping WAN path and is not a relay
   server.
2. **Target path:** `rust-libp2p` QUIC + TCP + Noise, DHT for signed discovery,
   AutoNAT / relay / DCUtR where network conditions permit.

## Why not full libp2p in the first land

Compile/integration cost and incomplete CGNAT hardware matrix. A real
non-localhost endpoint path remains an acceptance requirement.

## Evidence (honest)

| Gate | Claim |
|------|--------|
| `scripts/internet_dial_smoke.sh` | Negative: legacy `raven-node run` without a persisted ATSAM session still refuses with `ATSAM_SESSION_REQUIRED`. **Not** delivery. **Not** WAN. |
| `scripts/internet_indexed_two_node.sh` | Positive **lab** proof: RIH1 + indexed PairInit + sealed ACK on `127.0.0.1` only. **localhost-only.** **dial≠WAN.** multi-NAT stays **BLOCKED_HARDWARE**. |
| `INTERNET_DIRECT_PRODUCTION_ENABLED` | Stays **false** until founder GO after green lab evidence. |

**Do not claim WAN / multi-NAT / public-Internet Proven from either smoke.**
`127.0.0.1` is not WAN. Named-pipe work is not WAN.

## Invariants

- Transport encryption/auth ≠ Raven E2EE
- Relays never decrypt sealed content
- Capability ads are generic (`ble`/`internet`/`relay`/`store`/`bridge`) — never contact graphs
