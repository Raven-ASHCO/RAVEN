# DONE_CHECKLIST (software slice — honest)

Companion to `docs/MASTER_CHECKLIST_STATUS.md`. This is **not** Final DoD §60. RVN1 messaging is under a production **HOLD** with no external review (`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`, `docs/THREAT_MODEL.md`); a ✅ here is a software/lab statement, not a security or release claim.

## P0 Cross-device reliability

| Item | Status | Evidence |
|------|--------|----------|
| senderUserId mapping (flag ON) | 🟡 unverified / absent on `main` | iOS/Swift tree (`RavenEnvelopeSenderResolver`, PeerKeyDirectory) is not in this repository (**OFF-MAIN**); old ✅ was not reproducible from this tree |
| Endpoint ingest → sealer + Delivered | 🟡 unverified / absent on `main` | iOS ChatWire is **OFF-MAIN**; endpoint acceptance is production-disabled per `docs/THREAT_MODEL.md` |
| A↔B↔C automated | ✅ | `bridge_abc_demo` + §59 harness |
| iOS hardware 3-phone | ❌ BLOCKED_HARDWARE | `docs/PHYSICAL_BLE_THREE_DEVICE.md` |

## P1 Crypto

| Item | Status | Evidence |
|------|--------|----------|
| ATSAM beyond 0x7F | ✅ subset | `atsam_root` + `atsam_kdf` + `atsam_aead` + shared vectors |
| ML-KEM full stack | 🟡 partial | Rust implements the ML-KEM-768 + X25519 hybrid (`raven_core::atsam_mlkem`, `pair_init`); PairInit is production-disabled globally (live only on the unreviewed LAN-direct slice, which is CI/lab-verified); full PQ ratchet and iOS parity (OFF-MAIN) still pending |
| KATs shared | ✅ | `shared-vectors/rvn1/atsam/*` |
| External review packet | ✅ written (no review has happened) | `docs/EXTERNAL_REVIEW_PACKET.md` — independent review is BLOCKED_HUMAN |

## P2 Networking / services

| Item | Status | Evidence |
|------|--------|----------|
| InternetTransport endpoint delivery | 🟡 lab localhost-only (not WAN) | Positive: `internet_indexed_two_node.sh` (RIH1 + indexed ACK on `127.0.0.1`). Negative: `internet_dial_smoke.sh` fail-closed. `INTERNET_DIRECT_PRODUCTION_ENABLED=false`. **dial≠WAN.** multi-NAT **BLOCKED_HARDWARE**. |
| Full libp2p QUIC/DHT/DCUtR public | ❌ BLOCKED_HARDWARE | local swarm smoke green |
| Capability advertisement | 🟡 bounded | Internet only; default swarm no longer falsely advertises Relay |
| Always-on node scripts | ✅ | launchd / systemd / Windows |
| ash↔node IPC | ✅ | service survives ash exit (§59) |
| NAT docker substitute | ✅ script | SKIP when Docker down |

## P3 BLE

| Item | Status | Evidence |
|------|--------|----------|
| mock_ble CI | ✅ software | `bridge_abc` + §59 — TCP `u32 BE len \|\| envelope` only; **not** RBF1 GATT |
| iOS GATT flagged | ❌ unverified / absent on `main` | 0 `.swift` / `ios-native` on `main` (old ✅ was aspirational vs this tree). SoT until B8 export (not merged; no PR onto `main`): `feature/raven-serverless-v1` — `ios-native/RAVEN/RAVEN/Core/Mesh/BLEMeshEngine.swift` (+ `BLEMeshEngine+AdaptiveSpray.swift`), `ios-native/RAVEN/RAVEN/Core/Protocol/RavenBleRvn1Carrier.swift`, `ios-native/RAVEN/RAVENTests/RavenBleRvn1CarrierTests.swift`. `FeatureFlag.ravenEnvelopeV1` default OFF (Phase G / experimental). Do not invent or check off as present on `main` |
| raven-node CoreBluetooth | 🟡 compile seam | `--features corebluetooth`; radio **BLOCKED_HARDWARE**; desktop stays mock-only; `BleStatus` fail-closed |
| RBF1 GATT framing | ❌ held Sprint 1 | spec `protocol/RAVEN_BLE_FRAMING_V1.md`; no implementation / shared-vectors in this repo |
| BlueZ / live desktop radio | ❌ missing | no BlueZ or CoreBluetooth live radio wiring |
| Physical 3-device | ❌ BLOCKED_HARDWARE | `docs/PHYSICAL_BLE_THREE_DEVICE.md` — READY FOR FULL TEST? **NO** |

## P4 Packaging

| Item | Status | Evidence |
|------|--------|----------|
| Unsigned release layout | ✅ | `scripts/release/build_unsigned.sh` + SHA256 |
| INSTALL_* docs | ✅ | macOS / Linux / Windows |
| Signing/notarize | ❌ BLOCKED_HUMAN | `docs/SIGNING_NOTARIZATION_CHECKLIST.md` |

## P5 Product freeze text path

| Item | Status | Evidence |
|------|--------|----------|
| Serverless without FastAPI | ✅ | §59 harness + demos |
| Rate/TTL/hop/dedup/restart | ✅ (lab) | bridge_v1 + demos; hop/replication budgets are unauthenticated cooperative limits only (errata rule 8) |
| §59 automated proof | ⚠️ RE-RUN | earlier `AUTOMATED_PROOF_GREEN` runs were false-green (only each step's last command counted); harness fixed 2026-09-29 |

## Suites last green (this machine)

- `scripts/final_serverless_proof.sh` — earlier "17/17" invalidated; the fixed harness has 16 enforced steps (re-run)
- `cargo test -p raven-core` / `ash` / bridge_v1 / fuzz_smoke
- bridge_abc, two_node, lan, internet, swarm, mailbox, manual bootstrap

## READY FOR YOUR FULL TEST?

**NO** (marketing READY) — hardware + external review remain.  
Harness fixed 2026-09-29; a fresh enforced run of `final_serverless_proof.sh` / `reliability_matrix_20.sh` is pending, so **IMPLEMENTATION + PROOF HARNESS COMPLETE** is not currently asserted. Any future green run is lab evidence only and does not lift the RVN1 production HOLD.
