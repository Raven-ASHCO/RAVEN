# ADR 0004 — Raven↔RDAP production ATSAM transport (O6)

**Status:** **ACK’d** 2026-09-04 — Architect (#1), Crypto ATSAM (#3), Identity AuthZ (#15) full (body + Appendix G5). Merge gate for docs OK when Eng Mgmt allows. **No M1–M3 production code** until terminal-path board green + HOLD lift process. RVN1 HOLD still bars production enablement / Release.
**Date:** 2026-09-04  
**Risk class (normative):** **R3** (ATSAM / crypto transport). Approvers: Architect (#1), Crypto ATSAM (#3), Identity AuthZ (#15); Security Board as matrix requires. **No R3 self-merge.**  
**Deciders (required ack before merge):** Architect (#1), Crypto ATSAM (#3), Identity AuthZ (#15); Security Board as matrix requires  
**Author:** Raven↔RDAP Integration Lead  
**Repos:** `Raven-ASHCO/RAVEN`, `Raven-ASHCO/raven-distributed-agent-protocol`  
**Related:** ADR 0003 (wire/crypto/identity/IPC), `docs/THREAT_MODEL.md`, `protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`, `protocol/RAVEN_MAILBOX_TRANSPORT_V1.md`, `protocol/RAVEN_DEVICE_REVOCATION_V1.md`, RDAP README “Important integration gap”, Manager Sprint 0 decisions 2026-09-04  
**Process:** **No R3 self-merge.** No production code merge implementing M1–M3 until required acks. Full text lives on this RAVEN PR (`docs/adr/0004-…` + `node/adr/` mirror).

## Hard gate — RVN1 production HOLD (normative)

**Citations:** `docs/THREAT_MODEL.md` (**executable posture**) and `protocol/SECURITY_ERRATA_RVN1_2026-08-13.md` (normative security errata). RVN1 messaging remains **not approved for production**.

This gate is binding for the whole ADR:

1. O6 claims of “**production ATSAM**” / **confidential delivery**, and M1–M3 **production enablement / Release**, are **subordinate** to the THREAT_MODEL executable posture and the RVN1 SECURITY_ERRATA HOLD.
2. Harness / lab / interop work against held paths MUST be labeled **non-release**, run under **fail-closed containment**, and MUST NOT be described as confidential Raven messaging or production-approved.
3. “Same RVN1 as local `raven-node`” (D3) MUST NOT bypass the hold, errata rules (no public-material cipher / `STUB_PROTO` / interim seal on production-shaped paths, authenticated session mandatory, fail-closed acceptance/ACK, etc.), or ATSAM session requirements.
4. Shipping/Release enablement remains blocked until the HOLD is lifted by the normal security process — harness green ≠ hold lifted.

## Context

RDAP today exchanges recipient-bound, Ed25519-signed A2A tasks primarily over **cleartext HTTP** on a trusted LAN, with an optional **experimental plaintext** libp2p mailbox (`raven-swarm-mailbox-experimental`, env `RDAP_ENABLE_EXPERIMENTAL_PLAINTEXT_MAILBOX` / `--experimental-plaintext-mailbox`). Task JSON may sit in an RVN1 field named `message_ciphertext` without being confidential.

Production-shaped Raven messaging is fail-closed: without a persisted authenticated **ATSAM** session, `raven-node` refuses origination with `ATSAM_SESSION_REQUIRED`. Local clients talk to the daemon over UDS IPC. **`EnqueueSealed`** / **`LanDial`** / **`InternetDial`** remain already-sealed-frame-only. **`SealUnderSession`** (M2, NON-RELEASE) seals application payload bytes *inside* the daemon under a persisted ATSAM session; it does not lift RVN1 HOLD and is not O6 E2E / confidential-delivery Proven. IPC auth is peer-cred (UDS) / pipe ACL (Windows) per ADR 0003.

RDAP also keeps a separate identity under `.team/keys`, while `raven-node` uses `~/.raven`. Closing the documented integration gap for an honest encrypted carrier is the O6 KPI: a **two-device encrypted E2E harness** (still under the RVN1 HOLD above).

## Manager decisions locked for M0 (2026-09-04)

1. **O6 = transport E2E harness only.** Do **not** block on `RAVEN_USER_OWNED_AGENT_RUNTIME_V1` approval.
2. **Demo / confidentiality claim path = production ATSAM via `raven-node` only.** Signed HTTP may remain LAN bootstrap / control plane but **must never** be claimed confidential.
3. **O6 primary path = `LanDial` direct.** Production mailbox / offline is stretch, not a gate.
4. **M1 harness:** pin/use the **same RVN1** as local `raven-node` first. Document distinct `USER_AGENT_DEVICE` as follow-on per draft §3 — **do not** block M2 on a distinct credential.

Architect non-blocking agreement (2026-09-04): items 1, 3, and sealing-stays-in-raven-core/node are accepted; required changes below are incorporated in this revision.

## Normative invariants (Architecture)

These are binding for any implementation claiming conformance to this ADR:

1. **Confidential data plane** = ATSAM-sealed `RavenEnvelopeV1` envelopes via **`raven-node` IPC only**, with **`LanDial` primary** for O6.
2. **Python / RDAP MUST NOT** reimplement ATSAM, derive conversation keys, or hold session/ratchet key material. Sealing and session state live only in `raven-core` / `raven-node` (or a future Crypto-owned FFI that does not relocate trust into the agent process).
3. **Signed HTTP** = LAN **control plane only** (bootstrap, invite/trust, Agent Card, ping, status). It MUST NEVER seal, open, or carry confidential plaintext task/reply bodies, and MUST NOT be able to trigger seal/open without a local authenticated ATSAM session already present in `raven-node`.
4. **Fail-closed** on missing, unbound, revoked, or otherwise unusable ATSAM session — aligned with current executable posture (`ATSAM_SESSION_REQUIRED` and errata session boundary). RDAP MUST NOT claim send/task success after Raven refuse.
5. **IPC peer-cred / named-pipe ACL** per ADR 0003 is **mandatory** on the confidential path. No confidential IPC over unauthenticated local sockets.

## Decision

### D1 — Carrier of record for O6

Any claim of confidential / encrypted RDAP task delivery MUST mean:

- Task and reply application payloads are sealed under a **production-shaped ATSAM** session bound to the peer’s pinned Raven identity / device binding.
- Sealed frames are submitted to and received from a running **`raven-node`** via documented IPC (`LanDial` primary; `EnqueueSealed` only for already-sealed frames where dial/session/routing already established as specified by Crypto/Node IPC).
- **`LanDial` Noise XX is transport peer authentication only.** O6 confidentiality claims require an **ATSAM session seal** of application payloads — Noise alone is not sufficient.
- Experimental swarm mailbox and cleartext HTTP A2A are **out of scope** for confidentiality claims.
- Claims remain subordinate to the **RVN1 production HOLD**.
- **IPC trust:** The confidential path requires ADR 0003 **peer-cred** on Unix domain sockets (or equivalent named-pipe ACL on Windows). Unsigned / unattributed local callers MUST NOT be permitted to `EnqueueSealed`, `LanDial`, or the future M2 daemon-seal IPC.

### D2 — Control plane vs data plane

| Plane | Allowed in O6 | Confidentiality claim |
|---|---|---|
| Signed HTTP A2A (LAN) | Bootstrap, invite/trust, Agent Card, ping, status | **No** |
| HTTPS + Bearer | Optional hardening of control plane | Transport TLS only; still not Raven E2EE |
| ATSAM via `raven-node` `LanDial` | **Primary** task/reply data plane | **Yes** for harness claims; **not** Release/production until HOLD lifts |
| Production opaque mailbox / bridge | Stretch | Yes if used; **not** O6 gate |
| `raven-swarm-mailbox-experimental` plaintext | Lab only, opt-in, labeled non-production | **Never** |

**Noise vs ATSAM:** A successful `LanDial` Noise XX handshake authenticates the transport peer only. Reporting `atsam_rvn1` / claiming confidential delivery requires ATSAM-sealed application payloads under a persisted session — not Noise encapsulation alone.

### D2.1 — Carrier status enum (normative names)

Status / doctor / RDAP status surfaces MUST report an explicit carrier enum. Normative values:

| Value | Meaning |
|---|---|
| `atsam_rvn1` | Confidential data plane via ATSAM + `raven-node` IPC (`LanDial` / sealed path) |
| `http_signed` | Signed HTTP control plane (not confidential) |
| `experimental_plaintext_mailbox` | Opt-in experimental mailbox (not confidential; non-production) |

Status output MUST NOT leak confidential metadata (no plaintext task bodies, no session keys, no AEAD nonces/keys, no sealed payload bytes). Enum + coarse counters / error codes only.

### D3 — Identity binding for M1 (no soft parallel identity)

- For the O6 harness, RDAP MUST use the **same RVN1** already owned by the local `raven-node` data dir (`~/.raven` or configured `--data-dir`).
- M1 binds to the node’s **user identity key material that derives that RVN1** (Identity V1: user identity → address), together with the PairInit / device certificate / transcript binding `raven-node` already uses for that data dir — **not** a parallel device-only key, and **not** a newly invented RDAP-only keypair under `.team/keys` that merely prints a similar address string.
- **Trust / invite MUST map to an ash-style contact pin of that same RVN1** — no second pin namespace and no parallel `trusted_peers` identity root beside the node’s contact/pin plane.
- Mapping mechanism (read-only import of public material, IPC-mediated signing, documented export of public whoami, etc.) is an M1 implementation choice owned with Identity + Node IPC; **private keys MUST NOT** appear in IPC JSON (ADR 0003 / `ipc.rs`).
- Distinct `USER_AGENT_DEVICE` is a **documented follow-on after M2** and MUST NOT block M2. When it lands, treat it as a **distinct principal under G5** (device lineage vs address / agent address) — do **not** silently share revoke or authority with the user identity. M1 MUST NOT invent a soft parallel identity, soft pin, or second trust root that bypasses PairInit/device-cert/transcript checks.
- This reuse still MUST NOT bypass the RVN1 HOLD or errata.

### D4 — Sealing ownership (M2)

- Sealing and session ratchet state live in **Raven** (`raven-core` / `raven-node`).
- **`EnqueueSealed` / `LanDial` / `InternetDial` remain sealed-frame-only** — those ops still never seal (`ipc.rs`). Python MUST NOT construct RVNA1/ATSAM ciphertext.
- **M2 daemon-seal IPC exists** as `IpcRequest::SealUnderSession`: the daemon seals application payload bytes under a persisted ATSAM session (indexed-session path already used by LAN / pair_init_lab). **NON-RELEASE.** Does **not** lift RVN1 HOLD / SECURITY_ERRATA. **Not** O6 E2E Proven, WAN Proven, or confidential RDAP delivery Proven. Python RDAP client is a separate follow-up.
- After this slice: Python RDAP must submit application payload bytes only to that daemon seal IPC (or receive already-sealed frames for dial), never sealing locally.
- Identity lineage/deny runs **before** seal crypto. Covered lineage (`device_id` / `device_ed_pub` / `device_x_pub` / `device_cert_hash` via existing Identity `RevocationStore` / `DeviceRegistry` loaders) refuses with frozen **`ATSAM_LINEAGE_REVOKED`**. Missing/unusable session remains **`ATSAM_SESSION_REQUIRED`**. Soft-load empty-denylist (`unwrap_or_default`) is out of scope on this path.
- **FFI (if ever):** Crypto-owned, **R3**, Architect + Protocol Spec (#4) ack, shared-vectors KATs before RDAP may consume it.
- Forbidden: stuffing application bytes into `message_ciphertext`; Python-side ATSAM; client-triggered seal without a local authenticated session; treating Noise-only dial as confidential.
- **IPC trust (repeat for M2):** Confidential seal/dial IPC MUST enforce ADR 0003 peer-cred (UDS) / equivalent pipe ACL; unsigned or unattributed local callers MUST NOT invoke seal, `EnqueueSealed`, or `LanDial`.

### D5 — Harness acceptance (M3)

Two devices (physical or VM), each with `raven-node` + RDAP:

1. Mutual pin of the same RVN1 / device bindings used by each node (D3).
2. Alice `ask` → Bob completes (echo provider fine); markers e.g. `RAVEN_A2A_OK_*`.
3. Data-plane frames are ATSAM-sealed (asserted by harness / negative: drop session → refuse).
4. Carrier enum reports `atsam_rvn1` for the confidential path; docs state HOLD / non-Release if errata still active.
5. Docs: replace “Important integration gap” with pointer to this ADR and O6 encrypted path.
6. Experimental mailbox remains opt-in, labeled non-production / non-confidential.

### D6 — Merge / production / R3 gate

- Risk class **R3**. Approvers: Architect #1, Crypto #3, Identity #15 (+ Security Board as matrix requires). **No R3 self-merge.** Risk class **R3** is restated on this ADR header (normative), not only in the touch-list or G5.
- **No production code merge** implementing M1–M3 until those acks are recorded on the PR or Eng Program tracker.
- M1–M3 **production enablement / Release** remains subordinate to THREAT_MODEL + RVN1 security errata HOLD even after ADR ack.
- **HOLD subordination:** O6 claims of “production ATSAM” / confidential delivery and M1–M3 production enablement / Release remain subordinate to the THREAT_MODEL **executable posture** and `protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`. Harness / lab / interop work is **non-release**, under **fail-closed containment**; harness green ≠ hold lifted.
- ADR lands under `docs/adr/0004-raven-rdap-atsam-transport.md` and `node/adr/` mirror.
- RDAP repo gets a short pointer to this RAVEN ADR (single source of truth).

## Consequences

### Positive

- Honest security claims; closes the documented integration gap for the harness path without bypassing RVN1 HOLD.
- Reuses fail-closed ATSAM + IPC seams; no parallel crypto stack in Python.
- Clear control vs data plane; explicit R3 process.

### Negative / costs

- O6 needs Python↔`raven-node` IPC client and session-ensure UX.
- Same-device-binding M1 defers proper agent principal separation.
- HTTP control plane remains a LAN trust assumption unless operators add HTTPS.
- Harness green ≠ production approved while HOLD remains.

### Out of scope (explicit)

- Approving or implementing `RAVEN_USER_OWNED_AGENT_RUNTIME_V1`.
- Lifting the RVN1 production HOLD / closing errata (Security / Crypto process).
- Making experimental mailbox production-ready.
- Full offline/DTN mailbox as O6 exit criterion.
- Changing Noise / libp2p swarm defaults unrelated to RDAP task path.

## Milestone sketch (for Eng Program; refine after ack)

| ID | Name | Target window (from 2026-09-04) | Owners (roles) |
|---|---|---|---|
| M0 | Spec freeze (this ADR) | Week 0–1 | Raven↔RDAP + Architect + Crypto + Identity |
| M1 | Identity bridge (same raven-node RVN1 device binding) | Week 1–3 | Identity + Node IPC + Python Runtime |
| M2 | Sealed carrier via IPC / LanDial | Week 3–6 | Node IPC + Crypto + RDAP Protocol + Python Runtime |
| M3 | Two-device encrypted harness | Week 6–8 | Adversarial QA + SRE + Eng Program + CLI DX |
| M4 | Doc/status: deprecate confidential claims for plaintext carriers | Parallel M3 | RDAP Protocol + Assurance |

Stretch: production mailbox offline leg after M3 green.

## CODEOWNERS touch list

See companion `docs/adr/0004-CODEOWNERS-touch-list.md`.

## Appendix G5 — Joint Raven↔RDAP revoke policy

See `docs/adr/0004-appendix-g5-raven-rdap-revoke.md` (Architecture SoT = Identity PR #5 §2.2 verbatim; R → fail-closed on bound data-plane; R ↛ auto address-deny). Architect + Crypto + Identity **ACK** Appendix G5 / ADR 0004 full (2026-09-04).

## References

- `docs/THREAT_MODEL.md`
- `protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`
- `node/crates/raven-core/src/ipc.rs` — `EnqueueSealed`, `LanDial`, `SealUnderSession` (M2 NON-RELEASE; HOLD unchanged)
- ADR 0003 — IPC peer-cred / services
- RDAP `team_agents/mesh.py` — experimental plaintext carrier
- RDAP README — Important integration gap
- RAVEN README — `ATSAM_SESSION_REQUIRED` / `unsafe-interim`
