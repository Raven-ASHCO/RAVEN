# ATSAM Hybrid Threat Assumptions V1

**Kind:** normative addendum (binds existing sources; invents no primitives)  
**Sprint 0:** Crypto ATSAM Role #3  
**Status:** inventory / hold-preserving. **Does not lift HOLD. Does not approve Hybrid Ratchet V2 for production.**  
**Date:** 2026-09-04

This addendum is subordinate to [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) and [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md). Where those documents hold a path, this file cannot enable it.

Cited Swift / `ios-native/...` paths are **OFF-MAIN**: that tree is absent from `main`. Reconciliation of the SoT cited in [`protocol/ATSAM_PRIMITIVE_MAPPING_V1.md`](../../protocol/ATSAM_PRIMITIVE_MAPPING_V1.md) is deferred.

---

## 1. Combiner (frozen)

Both PairInit profiles use concatenation. No XOR, dual-PRF, or other combiner is specified.

```text
ikm = Z_X ‖ Z_PQ          # 32 ‖ 32
salt = transcript_hash    # PairInit transcript (profile-specific domain)
```

| Profile | Transcript / salt | HKDF info |
|---------|-------------------|-----------|
| PairInit V1 → `ATSAM/indexed-session/v1` | `SHA-256("ATSAM/v1/transcript" ‖ "rvn1/pair-init" ‖ complete_PairInit_V1)` | `"ATSAM/v1/pair-init" ‖ transcript_hash` → `K_root` (32) |
| PairInit V2 → `ATSAM/hybrid-ratchet/v2` | `SHA-256("ATSAM/v2/transcript" ‖ "ATSAM/v2/pair-init" ‖ complete_PairInit_V2)` | `"ATSAM/hybrid-ratchet/v2" ‖ 0x00 ‖ "pair-expand" ‖ transcript_hash` → `SK_ec ‖ SK_scka ‖ K_route_master ‖ K_confirm` |

Sources: [`protocol/RAVEN_PAIR_INIT_V1.md`](../../protocol/RAVEN_PAIR_INIT_V1.md) §4; [`protocol/ATSAM_PRIMITIVE_MAPPING_V1.md`](../../protocol/ATSAM_PRIMITIVE_MAPPING_V1.md) §3.4; [`protocol/ATSAM_HYBRID_RATCHET_V2.md`](../../protocol/ATSAM_HYBRID_RATCHET_V2.md) §0.3; `raven_core::atsam_root`.

**Both halves required (Seed-IND-style bound).** A conforming hybrid IKM is the 64-byte concatenation. Dropping, zeroing, or substituting either 32-byte share is not the frozen construction. Classical-only (`Z_PQ` omitted) or PQ-only (`Z_X` omitted) roots are laboratory fixtures, not production hybrid agreement. X25519 non-contributory / all-zero output is already rejected (`atsam_root::x25519_shared_checked`; PairInit V1 §4). This addendum does **not** introduce a new combiner or a dedicated combiner-negative vector (see KAT matrix gaps).

Order remains encapsulate → sign complete PairInit → hash transcript → expand. No substitute-transcript API.

---

## 2. Library matrix

| Language | Implementation on `main` | Role |
|----------|--------------------------|------|
| **Rust** | Workspace `ml-kem` **0.3** (`hazmat`) in `node/Cargo.toml`; used by `raven_core::atsam_mlkem` | Default ML-KEM-768 Encaps/Decaps for software KATs (`shared-vectors/rvn1/atsam/mlkem768_hybrid_kat_001.json`) |
| **Rust (lab)** | Optional `libcrux-ml-kem` **0.0.10** behind `mlkem768-incremental-lab` (`raven-core/Cargo.toml`); `raven_core::mlkem768_incremental` | Incremental Encaps1/2 lab only. Not a production backend. |
| **Swift** | **OFF-MAIN.** Mapping / comments cite CryptoKit `MLKEM768` on **iOS/macOS 26+**, fail-closed before 26 (`atsam_mlkem.rs` header; `ATSAM_PRIMITIVE_MAPPING_V1.md` SoT `ios-native/RAVEN/RAVEN/Core/Security/ATSAM/*`). Those sources are **not in this tree**. | Feature-branch claims only; unverified from `main`. |
| **Python** | `protocol/reference/raven_protocol/` — HKDF, codecs, transcripts, known-share expand | **No** ML-KEM Encaps/Decaps (`cryptography` does not expose ML-KEM; `generate_rvn1.py`). **MUST NOT seal** production or confidential traffic. Injected `Z_X`/`Z_PQ` and schema checks are oracles, not a sealer. |

ADR 0003 (`docs/adr/0003-wire-crypto-identity-bridge-ipc.md`) still lists iOS CryptoKit + ATSAM; that citation is historical and **OFF-MAIN** until `ios-native` is present.

---

## 3. Production HOLD (unchanged)

Normative executable rules remain the errata + threat-model posture:

1. **`ATSAM_SESSION_REQUIRED`.** No persisted, authenticated ATSAM/Noise session ⇒ emit no envelope (`SECURITY_ERRATA` Immediate rule 2; `raven-node` origination).
2. **No public-material / stub seal** in production paths. `STUB_PROTO=0x7F`, `RavenInterimSeal`, and any key derived only from public Ed25519 identities are laboratory fixtures (`SECURITY_ERRATA` rule 1; `unsafe-demo-crypto` off by default).
3. Synthetic “opaque ATSAM” bytes are not ciphertext and MUST NOT be originated.
4. Indexed-session v1 and Hybrid Ratchet v2 remain **production disabled** (`ATSAM_INDEXED_SESSION_PROFILE_V1.md`; `ATSAM_HYBRID_RATCHET_V2.md` header / §16). Companion APPROVED (e.g. RVDR1) does not enable flags.

This addendum restates those holds. It does not close any release gate in the errata.

---

## 4. Hybrid Ratchet V2 — §1 claims and non-claims

Bind [`protocol/ATSAM_HYBRID_RATCHET_V2.md`](../../protocol/ATSAM_HYBRID_RATCHET_V2.md) §1 only. Do not inherit SPQR/PQ3 claims by analogy.

**Claims (narrow, design-target; production held):**

| Goal | Bound |
|------|--------|
| Confidentiality vs classical network adversary | AEAD under Triple Ratchet hybrid keys |
| Harvest-now / decrypt-later | Attacker must break **both** EC and ML-KEM paths to distinguish message keys (`KDF_HYBRID`) |
| Classical FS | EC Double Ratchet + deletion of message/chain keys |
| Classical PCS | After attacker access **ends**, fresh EC DH entropy may heal EC state |
| PQ FS / sparse PQ PCS | Via ML-KEM Braid SCKA as analyzed with Triple Ratchet; healing needs successful SCKA epoch progress after compromise ends |
| Authentication (classical) | Ed25519 device signatures + cert / contact / revocation gates |
| Delivery | Only verified sealed AckV2 advances Delivered/Read |

**Non-claims (normative):**

1. **No active-quantum authentication.** Ed25519 is not PQ-safe.
2. **No PCS under ongoing compromise.** Healing requires attacker access to end **and** subsequent honest entropy.
3. Periodic Encaps ≠ Triple Ratchet.
4. **Relays and mailboxes are untrusted** for decrypt, ACK, and Delivered.

Status remains `REQUIRED / NOT YET APPROVED`. Crash-ordering KATs are not durability proof.

---

## 5. Profile split — indexed-session/v1 vs hybrid-ratchet/v2

| | Indexed-session v1 | Hybrid Ratchet v2 |
|--|--------------------|-------------------|
| Profile ASCII | `ATSAM/indexed-session/v1` | `ATSAM/hybrid-ratchet/v2` |
| Establishment | PairInit / PairResponse **V1** (`RVPI1` / `RVPR1`) | PairInit / PairResponse **V2** only (`RVPI2` / `RVPR2`) |
| Sealed proto | RVNA1 **`0x03`** | **`0x04`** (`SEALED_PROTO`) |
| `K_root` / expand | Single 32-byte root + directional HKDF lanes | Split `SK_ec` / `SK_scka` / route-master / confirm |

**PairInit V1 MUST NOT be read as V2** (`ATSAM_HYBRID_RATCHET_V2.md` §0; vector `shared-vectors/rvn1/atsam/negative/pair_init_v1_as_v2_001.json`; `hybrid_ratchet_v2::reject_if_pair_init_v1`). No silent upgrade. No overload of proto `0x03` as `0x04`. Indexed v1 is lab/interop only.

---

## 6. RDAP / O6 boundary

O6 ([`docs/engineering/baseline-freeze/ninety-day-outcomes.md`](../engineering/baseline-freeze/ninety-day-outcomes.md)): inventory Raven↔RDAP security/interop gaps. Confidentiality is **not** an RDAP property.

- **Confidential claims** are allowed only for traffic sealed by a **production-shaped ATSAM session** and originated/accepted through **`raven-node`** (canonical node: [`docs/adr/0001-rust-canonical-node.md`](../adr/0001-rust-canonical-node.md)). Full Raven↔RDAP contract text is **ADR 0004 ACK’d on `main`** ([`docs/adr/0004-raven-rdap-atsam-transport.md`](../adr/0004-raven-rdap-atsam-transport.md); G5 in [`docs/engineering/G5_CROSS_STACK_REVOKE_POLICY.md`](../engineering/G5_CROSS_STACK_REVOKE_POLICY.md)). M1–M3 production code and Release claims remain gated (terminal + RVN1 HOLD). Try-phase inventory: [`docs/engineering/baseline-freeze/o6-raven-rdap-try-phase-gap-board.md`](../engineering/baseline-freeze/o6-raven-rdap-try-phase-gap-board.md). This addendum does not implement that path or lift HOLD.
- **Experimental mailbox** (`experimental-offline-mailbox` / `--allow-experimental-mailbox`; [`protocol/RAVEN_MAILBOX_TRANSPORT_V1.md`](../../protocol/RAVEN_MAILBOX_TRANSPORT_V1.md); [`docs/network/raven-swarm-connectivity-matrix.md`](../network/raven-swarm-connectivity-matrix.md)) is opaque store-carry. **Never confidential.**
- **Signed HTTP** (RDAP request / task auth; Identity AuthZ inventory) authenticates a peer address. **Never confidential.** OPEN MODE makes no authz claim and no confidentiality claim.

Relays, stores, and RDAP HTTP terminate transport or task auth only. They MUST NOT be described as ATSAM E2EE.

---

## 7. Revoke

Bind Device Revocation V1 + G5; do not weaken either.

- An accepted **RVDR1** covering a device lineage (`device_id`, `device_ed_pub`, `device_x_pub`, `device_cert_hash`) is sticky deny. ATSAM / PairInit / envelope / ACK paths for that lineage **fail closed** ([`protocol/RAVEN_DEVICE_REVOCATION_V1.md`](../../protocol/RAVEN_DEVICE_REVOCATION_V1.md) §1.1, §6.3 `close_sessions`; Hybrid Ratchet V2 §3.2.1; G5 §2.2 rule 5).
- **No auto-heal.** Revoke V1 non-goal: automatic session healing. Re-pair only on a **new** lineage (no id/key reuse).
- Prefer a **hard revoke refuse** (explicit unauthorized / revoked) over a soft “session missing” UX that hides deny-set state. Soft `unwrap_or_default` loaders that empty a denylist remain a held P0 ([`docs/engineering/SPRINT0_IDENTITY_THREAT_MODEL.md`](../engineering/SPRINT0_IDENTITY_THREAT_MODEL.md) §3.2).
- Partition residual stands: a peer that has not observed the claim may still trust the device. UX MUST NOT claim “revoked everywhere” after local apply alone.

RVDR1 companion APPROVED does not enable production flags.

---

## 8. What this document is not

- Not a release gate, not an approval of Hybrid Ratchet V2, not a lift of `ATSAM_SESSION_REQUIRED`.
- Not a new combiner, KDF, sealed proto, or library.
- Not a claim that Swift CryptoKit ML-KEM is present or reviewed on `main`.
- Not permission for Python, experimental mailbox, or signed HTTP to originate confidential payloads.
