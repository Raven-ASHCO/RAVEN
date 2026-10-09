# External Review Packet — Raven Serverless V1

**Purpose:** Hand this directory of pointers to an independent protocol/crypto reviewer.  
**Branch (historical):** authored on `feature/raven-serverless-v1`; this file now lives on `main` and is a dated snapshot, not a statement about an open branch  
**Claim:** Lab-level implementation and an automated proof harness exist for software-automatable §59 steps (harness fixed 2026-09-29; a fresh enforced run is pending, earlier green runs are INVALIDATED). This is **not** a security claim: RVN1 messaging is under a production HOLD.  
**Not claimed:** Full §59/§60 DoD, notarization, live CGNAT, physical BLE radio matrix, any external review sign-off, or any confidentiality guarantee.

> **Read first — production HOLD.** RVN1 messaging is **not approved for production** and no independent
> security review has happened. Before using any "Protected"-style statement in this packet, read
> [`THREAT_MODEL.md`](THREAT_MODEL.md) (current executable posture table; includes the live LAN-direct slice),
> [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md), and
> connectivity matrix §0 ([`network/raven-swarm-connectivity-matrix.md`](network/raven-swarm-connectivity-matrix.md)).
> Citations tagged **OFF-MAIN** (Swift / `ios-native`) point at a tree that is not in this repository.

---

## 1. Threat model

| Doc | Role |
|---|---|
| [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) | Serverless P2P threat model (Phase A) — 17 adversary classes |
| [`docs/AUDIT_SERVERLESS_PIVOT_2026-08-12.md`](AUDIT_SERVERLESS_PIVOT_2026-08-12.md) | Pivot audit notes |
| [`docs/SERVERLESS_MODEL.md`](SERVERLESS_MODEL.md) | Exact meaning of “serverless” (three planes) |

Reviewer should mark any row where shipped code diverges from a cited mechanism.

---

## 2. Protocol freeze — file list + hashes

Regenerate:

```bash
bash scripts/freeze_protocol_hashes.sh
# → docs/PROTOCOL_FREEZE_HASHES_V1.md
```

Normative specs live under `protocol/`:

| Spec | Topic |
|---|---|
| `RAVEN_IDENTITY_V1.md` | Ed25519 identity |
| `RAVEN_ADDRESS_V1.md` | Bech32m `rvn` addresses |
| `RAVEN_ENVELOPE_V1.md` | Canonical wire object |
| `RAVEN_ACK_V1.md` | Delivery ACK |
| `RAVEN_ALIAS_V1.md` / Soft Unique Tags (`docs/RAVEN_TAG_V1.md`) | Human labels |
| `RAVEN_ROUTING_TAG_V1.md` | Opaque store tags |
| `RAVEN_STORE_OBJECT_V1.md` | Store-and-forward object |
| `RAVEN_BRIDGE_V1.md` | DTN bridge (opaque) |
| `RAVEN_BLE_FRAMING_V1.md` | BLE frame |
| `RAVEN_TRANSPORT_INTERFACE_V1.md` | Transport adapters / NAT notes |
| `RAVEN_PREKEY_BUNDLE_V1.md` | Async first contact |
| `RAVEN_CAPABILITIES_V1.md` | Capability bits |
| `RAVEN_DELIVERY_STATE_V1.md` | Queue states |
| `RAVEN_ERROR_CODES_V1.md` | Errors |
| `ATSAM_PRIMITIVE_MAPPING_V1.md` | Crypto mapping |
| `RAVEN_INTEROPERABILITY_MATRIX.md` | Cross-platform |

Byte-exact fixtures: `shared-vectors/rvn1/**`.

---

## 3. Cryptographic mapping

Primary map: [`protocol/ATSAM_PRIMITIVE_MAPPING_V1.md`](../protocol/ATSAM_PRIMITIVE_MAPPING_V1.md)

| Layer | Primitive | Impl |
|---|---|---|
| Envelope auth | Ed25519 | `raven_core::envelope`, Swift `MeshCryptoService` (**OFF-MAIN**) |
| Address | SHA-256[:20] → Bech32m | `raven_core::address` |
| Routing tag | HMAC-SHA256 | `raven_core::routing_tag` |
| Message seal RVNA1 | ChaCha20-Poly1305 | iOS ATSAM (**OFF-MAIN**) + Rust `seal` |
| Hybrid root | X25519 ‖ ML-KEM-768 | `atsam_mlkem` + Swift hybrid pairing (**OFF-MAIN**) |
| Chain ratchet | HKDF-SHA256 | iOS `ATSAMChainRatchet` (**OFF-MAIN**) |

Known gaps called out in the mapping doc (PLACEHOLDER KATs, CryptoKit CT interop).

---

## 4. How to run vectors

```bash
# Python reference
cd protocol/reference && python -m pytest -q

# Rust
cd node && cargo test -p raven-core
cargo test -p raven-core --test bridge_v1 --test fuzz_smoke

# Shared vector sync (if tooling present)
# see protocol/reference + shared-vectors/README.md
```

---

## 5. Automated §59 proof (software)

```bash
bash scripts/final_serverless_proof.sh
cat node/proof_artifacts/LATEST/SUMMARY.md
```

Expect `AUTOMATED_PROOF_GREEN` (the script exits 1 otherwise; every assertion in a step is enforced and `--self-test` proves it). This is a **lab** build: transport steps use the `unsafe-demo-crypto` interim cipher, whose key any observer of the two public keys can derive. Hardware, human and lab-crypto leftovers are listed in each run’s `BLOCKED.md`.

---

## 6. Known gaps (honest)

### BLOCKED_HUMAN
- Independent freeze/crypto review (this packet)
- Apple / Windows signing & notarization
- Credential rotation decisions from `docs/SECRET_HISTORY_SCAN_REPORT.md`

### BLOCKED_HARDWARE
- Physical 3-phone BLE (`docs/PHYSICAL_BLE_THREE_DEVICE.md`)
- Public Internet Kad / CGNAT / DCUtR (`docs/NAT_SOFTWARE_SIM.md`)
- Headless CoreBluetooth radio (`raven-node --features corebluetooth` is a compile seam only)

### Software gaps / partials
- Long fuzz campaigns: `node/fuzz` cargo-fuzz targets exist (envelope, RSO1, RLB1, carrier frames, PairInit, device cert, revocation, IPC, session/records) and run briefly on a weekly schedule; no sustained campaign / coverage report yet
- Bridge confidentiality under authenticated ATSAM sessions has no automated end-to-end evidence (bridged harness paths use the lab interim cipher)
- Full ML-KEM CT interop KATs with CryptoKit
- MSI installer (unsigned layout exists; store packaging open)

---

## 7. Reviewer checklist (suggested)

1. Run `bash scripts/freeze_protocol_hashes.sh --check` (also a CI step); any drift from the committed manifest fails.
2. Walk threat-model table; spot-check citations against code.
3. Run Python + Rust vector suites; attach logs.
4. Read `bridge_abc_demo` + final proof SUMMARY — confirm the bridge never **logs or stores** plaintext. Note the bridged paths use the lab interim cipher (key derivable from public keys), so this does not show the bridge *cannot* decrypt; review the ATSAM session path for that.
5. File findings against branch tip SHA (local; may be unpublished).
