# Sprint 0 — Identity AuthZ deliverable

**Owner:** Identity AuthZ (#15 / `@Raven-ASHCO/identity`)  
**Repos:** `Raven-ASHCO/RAVEN`, `Raven-ASHCO/raven-distributed-agent-protocol`  
**Date:** 2026-09-04  
**Status:** Outline + gap register (not implementation)

Crypto asks if a signature is valid. AuthZ asks whether the **key has authority for the action**. This note covers device lifecycle, fail-open auth risks, and cross-device / Raven↔RDAP revocation gaps.

---

## 1. Identity surfaces (inventory)

| Layer | Location | Role |
|-------|----------|------|
| User identity (Ed25519) | `RAVEN_IDENTITY_V1`, `identity.rs` / `identity_store` | Root of trust; address derivation; signs device certs + revokes |
| Device cert | `device_cert.rs`, `RavenDeviceCertificateV1` | Binds device Ed25519+X25519 to user identity for a window |
| Local device denylist | `DeviceRegistry.revoked` | Sticky local revoke; V1 software subset |
| Sync + partition model | `device_sync.rs`, `MULTI_DEVICE_PARTITION_REVOCATION.md` | Signed revoke records + epoch merge; documents lag |
| Normative revoke wire | `RAVEN_DEVICE_REVOCATION_V1` (`RVDR1`) | APPROVED companion; **production disabled** |
| Continuity / recovery | `RAVEN_IDENTITY_CONTINUITY_V2` | Quorum recovery; partitions; no instant global activate/revoke |
| Prekey lifecycle | `RAVEN_PREKEY_*`, `prekey_lifecycle.rs` | Claim / grace / fail-closed exhaustion |
| Seed storage | `IDENTITY_SEED_STORAGE.md` | Keychain/DPAPI; Linux Secret Service (load existing only — creation disabled before R1); locked-file is a debug/lab/CI-only override, refused in Release |
| RDAP authz | `team_agents/raven_identity.py`, `executor.py`, `server.py` | HTTP request auth + task delegation + address-level revoke list |

---

## 2. Device lifecycle threat model (outline)

### 2.1 Lifecycle stages

```text
[Generate user seed] → [Persist identity_store]
        ↓
[Mint device keys] → [Issue RavenDeviceCertificateV1]
        ↓
[Authorize PairInit / envelope / ACK / Noise bind]
        ↓
[Optional: multi-device contact sync]
        ↓
[Compromise / loss] → [Mint RavenDeviceRevocationV1 / local revoke]
        ↓
[Propagate revoke] → [Peers apply sticky deny] → [Re-pair on NEW lineage]
```

### 2.2 Assets

- User identity seed (loss = identity loss; compromise = forge certs + revokes)
- Device signing / X25519 secrets
- Device certificate validity window
- Revocation deny-set + protected anchors (anti-rollback)
- RDAP trusted-peer pin map + address revoke file
- ATSAM roots/chains still keyed by legacy `userId` (migration risk)

### 2.3 Adversaries (aligned with Device Revocation V1 §1.3)

| Adversary | Capability |
|-----------|------------|
| Network | Drop / reorder / inject; withhold revoke objects |
| Compromised device | Use device keys until cert expiry or peer learns revoke |
| Compromised identity | Forge certs and revokes; out-of-band recovery only |
| Malicious relay / mailbox | Deliver stale views; flood valid revokes (Deny-DoS) |
| Local disk attacker | Corrupt registry/SQL; rollback without protected anchor |
| Insider / open-mode operator | Disable `require_signed_tasks` |

### 2.4 Trust boundaries

1. **User identity ↔ device** — only identity-signed cert authorizes a device key.
2. **Local deny-set ↔ network gossip** — unsigned gossip MUST NOT authorize or clear revokes.
3. **Peer A view ↔ peer B view** — no instant global revoke under partition.
4. **RAVEN device lineage ↔ RDAP peer address** — different revoke granularities; G5 is **A ↛ R always**, **R ↛ auto address-deny**, and **R → fail-closed on bound data-plane** (lineage-scoped). See `G5_CROSS_STACK_REVOKE_POLICY.md` §2.2.
5. **Protected store ↔ SQL/journal** — corrupt/exhausted markers fail closed for authz.
6. **RDAP transport principal ↔ delegation sender** — mismatch must reject before replay consume.

### 2.5 Control objectives

| ID | Objective | Current posture |
|----|-----------|-----------------|
| D1 | Only identity key mints certs / revokes | Spec + code for certs; RVDR1 APPROVED |
| D2 | Sticky deny once applied | Local registry + RVDR1 append-only union |
| D3 | Fail-closed after apply / corrupt / exhausted | Spec strong; soft loaders are a gap (§3) |
| D4 | Eventual propagation | Manual/OOB + endpoint objects; no push-to-all |
| D5 | No lineage reuse after revoke | Spec MUST; tests for sticky denylist |
| D6 | Bounded cert lifetime as backstop | `not_after_ms` |

### 2.6 Stage-specific threats (STRIDE-flavored)

| Stage | Threat | Mitigation / residual |
|-------|--------|------------------------|
| Seed create/store | Seed in argv/logs; plaintext legacy file | Store backends; migration wipe; doctor redacts |
| Device enroll | Unauthorized cert if identity seed stolen | Physical/identity protection; Continuity V2 recovery |
| Session use | Stolen device keeps working | Short cert TTL; revoke + propagate |
| Sync | Revoked device pushes contacts | `is_authorized` gate on import |
| Revoke mint | Fork/equivocation on metadata | Union-apply both denys |
| Revoke apply | Corrupt store / rollback | Markers + protected anchors (prod path) |
| Partition | Lagging peer still trusts S | Documented residual; UX must not claim global |
| Replace device | Reuse device_id/keys | Protocol violation; verifier MUST deny |
| RDAP delegate | Unsigned / wrong peer tasks | `require_signed` + pin map |

---

## 3. Fail-open auth risks

### 3.1 Intentional / labeled

| Risk | Where | Notes |
|------|-------|-------|
| **OPEN MODE** | `TEAM_REQUIRE_SIGNED=0` / `require_signed_tasks=False` | Card warns `⚠ OPEN MODE`; accepts unsigned tasks. Ops risk if left on. |
| **Missing Raven HTTP headers in open mode** | `RpcIngressLimitMiddleware` | Owner becomes `open:{client}`; `is_authenticated=False`. |
| **Linux locked-file seed** | Debug / lab / CI only (`RAVEN_IDENTITY_BACKEND=locked-file`) | **Not** an approved fallback and refused in Release builds (Linux Release identity creation is disabled pending R1). Where used, host compromise ⇒ seed compromise. |
| **OTP soft anomaly** | Prekey bundle | Dual claim of same OTP logged soft, not hard-drop (availability > exclusivity). |

### 3.2 Dangerous defaults / API footguns (priority)

| Sev | Risk | Evidence | Recommended fix |
|-----|------|----------|-----------------|
| **P0** | Soft load of device registry / revocation store **swallows corrupt JSON → empty denylist** | `load_device_registry` / `RevocationStore::load` use `unwrap_or_default()` (2026-10-05: authz paths in `lan_dispatch.rs` use `*_checked`; `BlockList` has only `load_checked`; the soft loaders have no production callers, only tests) | Authz paths MUST use `*_checked`; treat soft APIs as display-only; add lint/CI ban on soft load in crypto paths |
| **P0** | `verify_delegation(..., required=False)` default | `raven_identity.py` | Flip default to `required=True` or rename to make opt-in explicit; OPEN MODE remains the only unsigned path |
| **P1** | Optional `revoked=None` skips revoke check | `verify_*` signatures | Require explicit empty set; never `None` meaning “don’t check” |
| **P1** | Address-level RDAP revoke ≠ device-level RAVEN revoke | RDAP JSON list of addresses vs RVDR1 lineage | See `G5_CROSS_STACK_REVOKE_POLICY.md` |
| **P1** | `RavenRequestAuthenticator` returns `(present, reason, owner)` with first bool ≠ auth-ok | Easy to misuse if caller checks first bool | Rename / return a struct; add typed result |
| **P2** | Incomplete Raven headers return `present=True` | Middleware still 401 when required or present | Keep; add unit tests so refactors don’t invert |
| **P2** | Cancellation early-out when `not require_signed` | `_authorize_cancellation` | Acceptable only while OPEN MODE; document |

### 3.3 Spec-good, prod-not-yet

Device Revocation V1 is **APPROVED** but **production disabled**. Shipping paths still lean on the software subset (local denylist + simpler sync records). Gap: operators may believe RVDR1 guarantees are live when they are not.

### 3.4 ATSAM `userId` migration (load-bearing)

Identity V1 §4: ATSAM roots/AAD still bind **server-issued `userId`**, not `RavenAddressV1`. Half-migrated pairs or wrong mapping ⇒ decrypt failure or worse, cross-pair replay if uniqueness lost. Owned jointly with Crypto ATSAM / Apple; AuthZ must gate “migrated ⇒ authority”.

---

## 4. Cross-device & Raven↔RDAP revocation gaps

### 4.1 Honest partition residual (documented)

From `MULTI_DEVICE_PARTITION_REVOCATION.md` / RVDR1 non-claim:

1. Online device A applies revoke epoch N for stolen S.
2. Partitioned B still authorizes S until it observes ≥ N.
3. S cannot mint new certs A will accept; cannot push sync into A’s registry.
4. After heal, B merges; denylist sticky.
5. **No** live DHT/gossip push-to-all contacts in V1 software subset.

`partition_lag_allows_stale_auth` encodes the residual for tests — it is a **known allow**, not a bug, until propagation improves.

### 4.2 Gap register

| ID | Gap | Impact | Owner propose |
|----|-----|--------|---------------|
| G1 | RVDR1 production flags off | Full fail-closed apply / corrupt / exhausted not enforced on shipping surfaces | Identity + Crypto + Architect gate |
| G2 | Soft `unwrap_or_default` on revoke/registry load | Corrupt file ⇒ appear unrevoked | Identity AuthZ **P0** (2026-10-05: mitigated in the authz paths via `*_checked`; the remaining soft loaders have no production callers — removal/lint still open) |
| G3 | No automatic contact warning UX on device change | Social engineering / late discovery | Apple/Windows + Identity |
| G4 | Manual OOB revoke exchange only (QR/file) | Slow propagation under partition | P2P/DTN + Identity |
| G5 | RDAP revokes **identity address**; RAVEN revokes **device lineage** | Steal one device ≠ RDAP peer revoke; revoke RDAP peer ≠ other devices of same user | See `G5_CROSS_STACK_REVOKE_POLICY.md` |
| G6 | RDAP revoke file optional / empty | Misconfig ⇒ no denylist | Fail closed if unset in signed mode? or require file |
| G7 | Identity Continuity V2 vs live device registry | Recovery activation delay ≠ device revoke propagation | Continuity + device revoke join plan |
| G8 | Prekey / session after revoke | Spec: close sessions; re-pair new lineage — verify all runtimes do | Adversarial QA + Identity |
| G9 | Org/CODEOWNERS not enforced yet | R3 identity PRs can merge without Security Board | Eng Mgmt (baseline audit) |

---

## 5. Sprint 0 exit criteria (Identity AuthZ)

- [x] Device lifecycle threat model outline (this doc §2)
- [x] Fail-open auth risk list with severity (§3)
- [x] Revocation / partition / Raven↔RDAP gap register (§4)
- [x] Architect ack on trust boundaries row (2026-09-04, PR #5)
- [ ] Security Board ack on trust boundaries row
- [ ] P0 soft-load ban ticketed with failing tests (held for Sprint 1 batch)
- [x] Joint note with Raven↔RDAP on G5 mapping (`G5_CROSS_STACK_REVOKE_POLICY.md`; ADR 0004 Appendix G5 on main / PR #3, three-way ACK closed)
- [ ] Confirm production flag status for RVDR1 on each surface

## 6. Asks

1. Accept as Sprint 0 Identity AuthZ baseline evidence.
2. G5 joint owners: Identity + Raven↔RDAP + RDAP Protocol.
3. Prioritize P0 soft-load ban for first eng sprint after freeze (batched).
4. Keep OPEN MODE off any shared/demo that claims authz.
