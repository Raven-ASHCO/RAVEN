# Raven Serverless Model V1

**Status:** Binding product definition for terminal + flagged mobile path (product intent only; security status is governed by the RVN1 production HOLD — `protocol/SECURITY_ERRATA_RVN1_2026-08-13.md` and `docs/THREAT_MODEL.md` override any older wording here)  
**Branch (historical):** authored on `feature/raven-serverless-v1`; this file now lives on `main` and is a dated snapshot, not a statement about an open branch  
**Start commit:** `18fa01e2a32ef014387ae2857ca272f34555cddd`

## Exact meaning of “serverless”

Raven **does not require** a Raven-operated central message server (FastAPI inbox, WebSocket fan-out, or cloud message DB) for 1:1 text delivery on the V1 envelope path.

### Three planes (do not collapse)

| Plane | Meaning |
|-------|---------|
| **Trust / friendship** | QR/OOB + fingerprint + signed prekey + local contacts. **Never** a central people directory. |
| **Delivery** | Store-carry-forward of opaque ciphertext (mesh / relay / Internet dial). |
| **Interop (Bridge)** | Untrusted cross-transport forward of the **same** `RavenEnvelopeV1` (DTN gateway sense — Fall), not a social introducer. |

See `docs/SERVERLESS_FRIEND_MESH_BRIDGE_DESIGN.md`. V1 mesh claim: **Spray-and-Wait policy** (`replication_budget` / hop / TTL) — not BUBBLE/SimBet. `hop_limit` and `replication_budget` are **unauthenticated, cooperative-node limits only** (a relay can reset them; no Byzantine bound — `protocol/SECURITY_ERRATA_RVN1_2026-08-13.md` rule 8); only the TTL (`expires_at`) is signed.

Allowed (non-trusted) helpers:

- User-run or community **relay / store / bridge / bootstrap** nodes that forward **opaque** `RavenEnvelopeV1` bytes only
- Manual peer dial, LAN, BLE, DHT discovery records (signed)
- Optional push/APNs for wake — **never** as the E2EE plaintext path

Forbidden as mandatory dependencies for ash↔ash or ash↔iOS (`FeatureFlag.ravenEnvelopeV1` ON):

- FastAPI message APIs
- Central user-directory as sole contact discovery
- Server-held conversation plaintext or conversation keys

## One envelope rule

> One Raven message → one canonical encrypted `RavenEnvelopeV1` → any available route (direct Internet, relay, encrypted store, LAN, BLE Bridge) without trusting a central Raven message server.

Bridge / relay / store **never decrypt**. Endpoint ATSAM / Noise / interim seal owns plaintext.

## Component map

| Component | Role |
|-----------|------|
| `raven-core` | Identity, address, envelope, seal/ATSAM KATs, MessageRouter, forward queue |
| `raven-node` | Always-on daemon for the Unix secure-LAN slice; legacy raw InternetTransport remains fail-closed |
| `ash` / `raven` | Terminal UI + policy IPC client — closing ash must not stop the node |
| iOS (flag ON) | Parallel path: LAN + BLE RVN1 + ChatWire Delivered; MeshEnvelope default when flag OFF |

## Centralization inventory (baseline)

| Dependency | Role today | Serverless V1 |
|------------|------------|---------------|
| FastAPI `server/` | Legacy inbox / auth / prekey HTTP | **Not required** for flagged envelope path |
| WebSocket / RealtimeEngine | Online fan-out | Optional wake only |
| APNs | Push | Optional wake only |
| ATSAM online prekey HTTP | First contact | Prefer QR / offline bundle; HTTP optional |
| BLEMeshEngine MeshEnvelope | Default mobile mesh | Remains when flag OFF |
| `raven-node` TCP / bridge | Local serverless | **Required** for terminal path |

## Honest limitations (software)

- Full rust-libp2p DHT + DCUtR on real CGNAT: **experimental/held** — bounded client composition exists, but no production endpoint coordinator or relay server is wired; multi-NAT hardware proof is still BLOCKED.
- ML-KEM hybrid pairing in Rust: the ML-KEM-768 + X25519 hybrid is implemented in `raven-core` (`atsam_mlkem`, `pair_init`), but PairInit is production-disabled (live only on the unreviewed LAN-direct slice); the full PQ ratchet and iOS parity (OFF-MAIN) are still pending. Not a shipping claim.
- Real GATT in headless `raven-node`: mock_ble for CI; iOS BLEMeshEngine for hardware.
- External crypto review + notarized signing: **BLOCKED_HUMAN**.
