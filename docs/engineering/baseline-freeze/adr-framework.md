# ADR Framework — Raven-ASHCO (Sprint 0 proposal)

**Status:** Proposed (Architect draft)  
**Owner:** #1 Principal Architect (chair, Architecture Board)  
**Date:** 2026-09-04  
**Does not rewrite** existing [`docs/adr/0001-rust-canonical-node.md`](../../adr/0001-rust-canonical-node.md), [`docs/adr/0002-internet-transport.md`](../../adr/0002-internet-transport.md), [`docs/adr/0003-wire-crypto-identity-bridge-ipc.md`](../../adr/0003-wire-crypto-identity-bridge-ipc.md).

This framework tells the org **when** to write an Architecture Decision Record, **where** it lives, **who** approves it, and the hard rule that every ADR states **which invariant it affects**. It is process documentation (R0). An accepted ADR that changes a trust or wire contract is itself the audit trail for an R2/R3 change.

Related: [`architecture-dependency-map.md`](architecture-dependency-map.md), [`trust-boundaries.md`](trust-boundaries.md), [`risk-classes.md`](risk-classes.md), [`approval-matrix.md`](approval-matrix.md), [`org-structure.md`](org-structure.md).

---

## 1. What an ADR is here

An ADR is a **durable, numbered decision** about system shape: language, layer edges, wire versioning, trust cuts, identity namespaces, or “we will not do X.”

It is **not**: a protocol byte spec (those live in `protocol/RAVEN_*` / `ATSAM_*`), a threat-model row (`docs/THREAT_MODEL.md`), a Sprint 0 checklist item, or a PR description.

Normative stack (highest wins on conflict until an ADR + spec PR land together):

1. Production-hold errata — `protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`
2. Frozen wire specs + `shared-vectors/`
3. Accepted ADRs in `docs/adr/`
4. Implementation

If code and an accepted ADR disagree, **code is wrong** until a new ADR supersedes the old one (`THREAT_MODEL.md` §4 posture, applied to architecture).

---

## 2. When an ADR is required vs optional

### Required (do not merge the change without a new or updated ADR)

| Trigger | Typical risk | Notes |
|---------|--------------|--------|
| New **allowed or forbidden** dependency edge (crate, IPC op, RDAP→node carrier) | R2–R3 | Update the architecture map in the same PR or immediately after |
| Change to a **trust boundary** (TB1–TB5 in `trust-boundaries.md`) | R3 | Security Board second; no self-merge |
| New transport or carrier advertised by default | R2–R3 | e.g. enabling mailbox on default `raven-swarm` |
| Canonical implementation language / “what is the node” | R2 | 0001 already decided Rust core+node |
| Identity namespace split or merge (Raven user vs libp2p PeerId vs RDAP agent key) | R3 | #6 + #5 |
| Normative **protocol version** bump or new `env_type` | R3 | Spec lives in `protocol/`; ADR records *why* and invariants |
| “We will not support X” product-architecture (e.g. FastAPI never on DM path) | R2 | Already implicit in 0002/0003 + serverless docs; new exceptions need an ADR |
| Superseding or retiring an Accepted ADR | inherits prior class | Status → Superseded; do not silently edit history |

### Optional (ADR welcome, not a merge gate)

- Local refactors that do not change public API, wire, or trust cuts (R1).
- Adding tests, vectors, or docs that restate an existing decision.
- Platform-only UX that does not move keys or envelopes (R2 still needs matrix review; ADR only if the UX implies a new trust cut).
- Experimental **lab** features that remain default-off **and** cannot be enabled in production builds — still consider a short ADR if they introduce a new FFI or protocol id (so we do not mint `/raven/...` paths in a vacuum).

**If unsure whether an ADR is required, write one.** Cost of an extra Accepted/Proposed record is lower than an implicit cross-layer contract (see `undocumented-cross-layer-deps.md`).

---

## 3. Path and numbering

| Rule | Detail |
|------|--------|
| **Canonical directory** | `docs/adr/` (this repo). CODEOWNERS: `@Raven-ASHCO/architecture`. |
| **Filename** | `NNNN-kebab-title.md` — four-digit decimal, next unused number. Next proposed number after the existing trio: **0004**. |
| **One decision per file** | Do not bundle unrelated decisions to “save a number.” |
| **Never reuse a number** | Abandoned drafts stay `Proposed` → `Withdrawn` or `Rejected`. |
| **RDAP-local decisions** | If the decision is *only* inside `raven-distributed-agent-protocol` and does not change Raven layer edges, RDAP may keep a parallel `docs/adr/` **UNKNOWN today** (no `docs/adr/` in the RDAP tree as of 2026-09-04). Cross-repo decisions (carrier onto raven-node, shared `env_type`, identity merge) are recorded **here** and referenced from RDAP. |
| **Duplicates** | `node/adr/0001`–`0003` exist and match the `docs/adr/` titles. Treat `docs/adr/` as canonical; do not edit `node/adr/` except to add a one-line pointer, via a later R0 PR. Do not fork the two trees. |

Protocol specs stay in `protocol/`. An ADR may **cite** `RAVEN_ENVELOPE_V1.md`; it must not become a second wire SoT.

---

## 4. Template

Copy from the heading below. All fields are mandatory unless marked optional.

```markdown
# ADR NNNN — Title

**Status:** Proposed | Accepted | Deprecated | Superseded | Rejected | Withdrawn
**Date:** YYYY-MM-DD
**Risk class:** R0 | R1 | R2 | R3
**Owners:** primary role #… ; second approver role #…
**Supersedes / Superseded-by:** ADR NNNN or “none”

## Context

What problem or constraint exists. Link PRs, specs, threat-model rows, and the
architecture map. Do not hide uncertainty — write UNKNOWN.

## Decision

The change in one or two paragraphs. Include a “we will not” clause if relevant.

## Consequences

Positive, negative, and follow-on work. Name crates, IPC ops, and repos affected.

## Invariants affected

**Mandatory.** List every SPEC / mission / layer invariant this decision
touches, or explicitly write “None — no invariant change” with a one-line why.
Use the inventory in §6. A change that cannot name its invariant is not ready
for Architecture Board.

## Risk class (R0–R3)

Restate the class and why. If any slice is R3, the whole ADR is R3
(`risk-classes.md` mixing rule).

## Approval record

| Role | Name or team handle | Verdict | Date |
|------|---------------------|---------|------|
| Primary owner | | | |
| Mandatory second | | | |
| Architecture Board (#1 chair) | | | |
| Crypto/ATSAM (#5 and #3 if spec) | required if R3 crypto/wire | | |
| Security Board (#17) | required if R3 | | |

Author must not be the merging approver on R3.
```

Existing 0001–0003 predate this template. **Do not retrofit them** in this Sprint 0. New ADRs use the template. A future R0 PR may add an “Invariants affected” appendix *under* 0001–0003 without changing their Decision text (optional).

---

## 5. Relationship to ADR 0001–0003

| ADR | Decision (do not relitigate here) | Invariants it already implies |
|-----|-----------------------------------|-------------------------------|
| **0001** | `raven-core` + `raven-node` are the canonical node, in **Rust**. iOS/Android are first-class clients, not the daemon. Go `Libp2pBridge` may remain a mobile helper until Rust InternetTransport parity. | Mission: one canonical implementation for the headless node. Clients must not replace core as SoT. |
| **0002** | V1 laboratory internet path (production hold; `INTERNET_DIRECT_PRODUCTION_ENABLED=false`, localhost lab only, not a WAN or relay-server path) = `InternetTransport` (RIH1 hello + length-prefixed `RavenEnvelopeV1`). Target = rust-libp2p QUIC/TCP/Noise + DHT + AutoNAT/relay/DCUtR. Transport encryption ≠ E2EE. Relays never decrypt. Caps never carry contact graphs. | SPEC invariants 5 (same object on internet) and 2 (no plaintext on wire). Layer: swarm/node transport. |
| **0003** | Binary `RavenEnvelopeV1`; listed crypto libs; Ed25519 → `rvn1…`; transport peer id ≠ user id; Bridge opaque only; UDS IPC with peer-cred; `ash`/`raven` are clients; never overwrite `/bin/ash`. | SPEC identity + text + delivery; IPC TB1; Bridge plane 3. |

**Supersession:** a later ADR that changes any of the above must set `Supersedes: 000N` and the old file `Status: Superseded` with a pointer. Until then, new work **conforms**.

Phased note: 0002 is “Accepted (phased).” Enabling default libp2p mailbox or NAT on production bins is a **new** ADR (0002 already forbids treating stubs as the complete target).

---

## 6. Invariant inventory (use these names)

From `protocol/SPEC.md` unless noted:

| ID | Statement |
|----|-----------|
| I-ID | Self-sovereign Ed25519 identity; no server issues/stores/revokes it |
| I-TEXT | No plaintext content on any transport |
| I-DELIVERY | Delivered/read only on signed recipient ACK |
| I-OFFLINE | Store-and-forward without live recipient or central queue |
| I-INET | Internet object is the same `RavenEnvelopeV1` bytes |
| I-BLE | BLE object is the same bytes; relay does not re-author |
| I-E2EE | Only authenticated intended endpoint recovers plaintext (production **held**) |
| M-NOSRV | No trusted central message server |
| M-ENDPOINT | Only intended endpoint recovers plaintext (mission) |
| M-ONEOBJ | One protocol object across Internet / relay / BLE |
| M-ASH | `ash` hides DHT/QUIC/Noise/ratchets from the user |
| L-CORE | `raven-core` has no reverse deps on node/swarm/clients |
| L-SWARM | Clients do not import swarm internals |
| L-IPC | No secrets on IPC; daemon does not seal from IPC plaintext |
| L-RDAP | RDAP production carrier must not bypass ATSAM (today: no production carrier) |
| L-PLANE | Trust / delivery / bridge planes stay uncollapsed |

ADRs must cite `I-*` / `M-*` / `L-*` (or “None”).

---

## 7. Architecture Board approval path

```
Author (any role) drafts ADR NNNN in docs/adr/  [Status: Proposed]
        │
        ▼
Primary owner reviews  (CODEOWNERS + approval-matrix.md)
        │
        ├── R0–R1: one approving review; Architecture Board informed in weekly notes
        │
        ├── R2: primary + mandatory second from matrix
        │         Architecture Board (#1, #2, #4, #7) records Accept in the ADR table
        │
        └── R3: see §8 — extra Crypto/ATSAM + Security Board; no self-merge
        │
        ▼
Status → Accepted  in the same PR that relies on the decision
        or a dedicated docs PR that lands *before* the implementing PR
```

**Board composition** (`org-structure.md`): Architecture Board = #1 (chair), #2 Protocol, #4 Interop, #7 Core Runtime. Security Board = #17 (chair), #5 Crypto, #6 Identity; #1 non-voting consult.

**Eng Management** may prioritize which ADRs are written; they **cannot** accept an R3 ADR in place of Security Board, and cannot waive no-self-merge.

**RDAP-only Proposed ADRs** still need #14/#15 as primary when the file lives in RDAP; if the decision crosses Raven, #4 is primary and the record lives in **this** repo.

---

## 8. R3 ADRs — Crypto/ATSAM and no Architect self-merge

`approval-matrix.md` already maps change types. This framework adds ADR-specific gates:

1. **Always state invariants** (§6). An R3 ADR with “invariants affected: none” is rejected unless the Board agrees the decision is purely process.
2. **Crypto / ATSAM / key handling / identity store:** mandatory approval from **Crypto Lead (#5)** and, when a frozen spec or version byte changes, **Spec & Versioning Owner (#3)**. Sprint 0 instruction: *“R3 ADR changes need #3 Crypto/ATSAM approval.”* In the published org chart #3 is Spec & Versioning and #5 is Crypto Lead — **both** are required when the ADR moves ATSAM or a frozen crypto spec; #3 alone is not a Crypto substitute, and #5 alone is not a versioning substitute.
3. **Trust-boundary ADRs:** primary #1, second **Security Board (#17)**.
4. **Hard rule:** **Principal Architect (#1) must not self-merge R3**, including R3 ADRs they authored or chaired. Author ≠ merging approver (`risk-classes.md`). Apply even if one human temporarily holds #1 and #5.
5. **Implementing PR:** the ADR Accept and the code may be the same PR only if reviewers can reject the decision without shipping the code. Prefer ADR-first for R3.
6. **Do not** treat this docs PR (Sprint 0 maps) as accepting a new R3 boundary. Implementing G-items in `trust-boundaries.md` needs a later R3 ADR + #17/#6.

---

## 9. Status meanings

| Status | Meaning |
|--------|---------|
| Proposed | Under review; not binding |
| Accepted | Binding for new work |
| Deprecated | Still true for shipped V1; do not extend |
| Superseded | Replaced by a later ADR (link it) |
| Rejected | Considered; will not do |
| Withdrawn | Author pulled; number retired |

---

## 10. Suggested first new ADRs (not opened by this PR)

These close gaps in `undocumented-cross-layer-deps.md`. Each would be a later PR:

| Tentative | Topic | Risk |
|-----------|--------|------|
| 0004 | Canonical ADR path `docs/adr/` vs `node/adr/` mirrors | R0–R1 |
| 0005 | RDAP production carrier = `EnqueueSealed` only; mailbox plaintext never default | R3 |
| 0006 | `env_type` registry: reserve vs reclaim 4 from RDAP misuse | R3 |
| 0007 | One vs two Ed25519 principals (user device vs RDAP agent) | R3 |
| 0008 | Default queue encryption (SQLite vs SQLCipher) honesty | R2–R3 |
