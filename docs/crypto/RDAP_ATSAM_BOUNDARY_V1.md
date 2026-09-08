# RDAP↔ATSAM boundary V1

**Kind:** normative honesty note (binds existing sources; invents no primitives)  
**Sprint 0:** Crypto ATSAM Role #3 / Manager item 5  
**Status:** inventory / hold-preserving. **Does not lift HOLD. Does not implement crypto.**  
**Date:** 2026-09-04

This note is subordinate to [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) and [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md). Where those documents hold a path, this file cannot enable it.

Swift / `ios-native` SoT reconciliation is **out of scope / parked** (`ios-native/` is absent from `main`).

---

## 1. Today on `main`

RDAP does **not** use production ATSAM E2EE. Current carriers:

| Carrier | What it is | Confidentiality |
|---------|------------|-----------------|
| Signed HTTP A2A | Ed25519-signed tasks over cleartext HTTP on a trusted LAN | **None.** Not Raven E2EE. Optional HTTPS is transport TLS only, still not ATSAM. |
| Experimental plaintext swarm mailbox | RDAP `team_agents/mesh.py`; opt-in (`RDAP_ENABLE_EXPERIMENTAL_PLAINTEXT_MAILBOX` / `--experimental-plaintext-mailbox`) | **None.** Signed JSON MAY occupy an RVN1 field named `message_ciphertext`. That field name is **not** confidentiality. |

Relays, stores, and RDAP HTTP terminate transport or task auth only. They MUST NOT be described as ATSAM E2EE.

---

## 2. Identity split (integration gap)

| Stack | Key material today |
|-------|--------------------|
| RDAP | `.team/keys` (parallel agent identity) |
| `raven-node` | `~/.raven` (or configured `--data-dir`) |

This split is the documented **Important integration gap**. O6/M1 closes it by pinning the **same RVN1** already owned by local `raven-node` ([ADR 0004](../adr/0004-raven-rdap-atsam-transport.md) D3; on `main`, three-way ACK’d 2026-09-04; historical merge [PR #3](https://github.com/Raven-ASHCO/RAVEN/pull/3)). A newly invented RDAP-only keypair that merely prints a similar address string is not that binding.

M1 MUST NOT invent a soft parallel identity, soft pin, or second trust root that bypasses PairInit / device-cert / transcript checks. Distinct `USER_AGENT_DEVICE` is a documented follow-on after M2.

---

## 3. Only honest confidential path

ADR 0004 is **accepted on `main`** ([`docs/adr/0004-raven-rdap-atsam-transport.md`](../adr/0004-raven-rdap-atsam-transport.md); three-way ACK 2026-09-04). The ADR does **not** implement M2. Crypto-owned seal-inside-daemon remains future work.

Confidential / encrypted RDAP task delivery is allowed only when **all** of the following hold:

1. Application payloads are sealed under a **production-shaped ATSAM** session (persisted, authenticated; no stub / public-material / interim seal).
2. Frames are originated and accepted through **`raven-node` IPC** only. **`LanDial` is primary** for O6. `EnqueueSealed` accepts already-sealed frames only.
3. **Today:** IPC is **sealed-frame-only**. The daemon does **not** seal plaintext for callers.
4. **M2 (ADR 0004 D4):** Crypto-owned seal-inside-daemon. Until that IPC exists, RDAP MUST NOT invent a seal path and MUST NOT claim confidential send.
5. Claims remain subordinate to the **RVN1 production HOLD**. Harness green ≠ hold lifted.

**Noise XX ≠ ATSAM confidentiality.** A successful `LanDial` Noise XX handshake authenticates the transport peer only. Reporting `atsam_rvn1` / claiming confidential delivery requires an ATSAM session seal of application payloads — not Noise encapsulation alone.

Python / RDAP MUST NOT reimplement ATSAM, derive conversation keys, or hold session/ratchet key material.

---

## 4. Carrier enum honesty

Status / doctor / RDAP status surfaces MUST report an explicit carrier enum:

| Value | Meaning | Confidentiality claim |
|-------|---------|-----------------------|
| `atsam_rvn1` | ATSAM + `raven-node` IPC (`LanDial` / sealed path) | Allowed **only** when §3 holds; still not Release until HOLD lifts |
| `http_signed` | Signed HTTP control plane | **Forbidden** |
| `experimental_plaintext_mailbox` | Opt-in experimental mailbox | **Forbidden** |

Non-ATSAM carriers MUST NOT be labeled confidential. Status MUST NOT leak confidential metadata (no plaintext task bodies, session keys, AEAD nonces/keys, or sealed payload bytes). Enum + coarse counters / error codes only.

---

## 5. Forbidden

1. Treating RDAP `message_ciphertext` (signed JSON in an RVN1 field) as ATSAM-sealed.
2. Python constructing RVNA1 / ATSAM ciphertext, stuffing plaintext into `message_ciphertext`, or client-triggered seal without a local authenticated ATSAM session in `raven-node`.
3. Lifting the RVN1 production HOLD because a harness went green. Lab / interop work is **non-release**, fail-closed containment.
4. Claiming signed HTTP, experimental mailbox, or Noise-only dial as Raven E2EE / ATSAM confidentiality.

---

## 6. G5 (one-liner)

Accepted **RVDR1** covering a device lineage in use on ATSAM / `LanDial` / task ⇒ **data-plane fail-closed**. No auto-heal. Hard revoke refuse (`DEVICE_REVOKED` / `ATSAM_LINEAGE_REVOKED` or equivalent), **not** soft `ATSAM_SESSION_REQUIRED` same-lineage re-pair. Re-pair only on a **new** lineage. RVDR1 does not auto-write RDAP address deny (playbook A). Full policy: [`docs/engineering/G5_CROSS_STACK_REVOKE_POLICY.md`](../engineering/G5_CROSS_STACK_REVOKE_POLICY.md); ADR 0004 [appendix G5](../adr/0004-appendix-g5-raven-rdap-revoke.md) on `main` (three-way ACK’d 2026-09-04).

---

## 7. Pointers

| Document | Role |
|----------|------|
| [`docs/adr/0004-raven-rdap-atsam-transport.md`](../adr/0004-raven-rdap-atsam-transport.md) | Accepted Raven↔RDAP production ATSAM transport (O6). Three-way ACK’d 2026-09-04 (Architect + Crypto ATSAM + Identity AuthZ, body + Appendix G5). On `main` (`ce087c7`; historical [PR #3](https://github.com/Raven-ASHCO/RAVEN/pull/3)). Single SoT for M1–M3. M2 seal-inside-daemon is still future work. |
| `docs/crypto/ATSAM_THREAT_ASSUMPTIONS_V1.md` ([PR #18](https://github.com/Raven-ASHCO/RAVEN/pull/18), when present) | Combiner, HOLD, library matrix, RDAP/O6, revoke. |
| `docs/crypto/ATSAM_KAT_CONSUMER_MATRIX_V1.md` ([PR #18](https://github.com/Raven-ASHCO/RAVEN/pull/18), when present) | Vector consumers. Python is not a seal oracle. |
| [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md) | Normative HOLD. `ATSAM_SESSION_REQUIRED`. |
| [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) | Executable posture. |

---

## 8. What this document is not

- Not a new primitive, combiner, sealed proto, IPC op, or library.
- Not approval of Hybrid Ratchet V2 or a lift of `ATSAM_SESSION_REQUIRED`.
- Not Swift / `ios-native` SoT reconciliation (parked).
- Not permission for Python, signed HTTP, or experimental mailbox to originate confidential payloads.
