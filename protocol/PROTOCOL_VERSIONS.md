# RAVEN Protocol Version Inventory

**Status:** Living inventory (docs only). Not a wire change.
**Updated:** 2026-09-06
**Audience:** protocol owners, ports, CI readers.

This page lists which protocol families are frozen, which are draft / production-disabled, and which CI jobs in `.github/workflows/raven-serverless.yml` (workflow display name: **Raven Serverless Node**) and `.github/workflows/raven-b1-always-on.yml` (workflow display name: **Raven B1 Always-On**) can be cited as evidence on the current serverless `main` tree.

Wire codecs, vectors, and workflow YAML are unchanged by this document.

---

## Frozen families

| Family | Spec | Vectors | Freeze rule | Breaking next |
|---|---|---|---|---|
| **Mesh BLE `v1`** | [`docs/MESH_PROTOCOL.md`](../docs/MESH_PROTOCOL.md) | [`shared-vectors/v1/`](../shared-vectors/v1/) | Frozen per [`shared-vectors/VERSIONING.md`](../shared-vectors/VERSIONING.md). Once a vector lands it never changes. | New tree `shared-vectors/v2/` plus `docs/MESH_PROTOCOL_v2.md` |
| **Serverless `rvn1`** | [`SPEC.md`](SPEC.md) Version 1 (`rvn1`) | [`shared-vectors/rvn1/`](../shared-vectors/rvn1/) | Wire codec frozen. Domain prefixes include `rvn1/ack`, `rvn1/alias`, `rvn1/devcert`, `rvn1/caps`, `rvn1/route` (and later record prefixes in the same `rvn1/*` namespace). | New version byte + `shared-vectors/rvn2/` |

**`rvn1` production hold.** The codec and committed vectors remain the contract. Production messaging is **not** approved: [`SECURITY_ERRATA_RVN1_2026-08-13.md`](SECURITY_ERRATA_RVN1_2026-08-13.md) overrides conflicting processing and release claims in the V1 family.

---

## Draft / not production wire

These are **not** production wire. Do not treat lab vectors or architecture approval as a Release flag.

| Profile | Spec | Status | Vectors |
|---|---|---|---|
| ATSAM hybrid-ratchet v2 + PairInit V2 | [`ATSAM_HYBRID_RATCHET_V2.md`](ATSAM_HYBRID_RATCHET_V2.md) | `REQUIRED / NOT YET APPROVED`; production disabled; PairInit V2 is new wire (`RVPI2` / `RVPR2`), not a reinterpretation of PairInit V1 | `shared-vectors/rvn1/atsam/pair_init_v2_001.json`, `atsam/negative/pair_init_v1_as_v2_001.json`, `atsam/tr_*.json` |
| Identity Continuity V2 | [`RAVEN_IDENTITY_CONTINUITY_V2.md`](RAVEN_IDENTITY_CONTINUITY_V2.md) | `REQUIRED / NOT YET APPROVED`; production disabled; no V2 address, codec, or Release flag | none yet |
| Unified Serverless Architecture V2 | [`RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md`](RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md) | Architecture **Approved**; **production disabled** until §8 companions are `APPROVED` and §9 / §10.2 gates pass. Does not freeze KDF, ratchet headers, or companion codecs. | — (umbrella; companions own vectors) |

Companions whose headers say **wire not frozen** (and remain production disabled / `NOT YET APPROVED`): [`RAVEN_ID_RESOLUTION_V1.md`](RAVEN_ID_RESOLUTION_V1.md), [`RAVEN_PRIVATE_DISCOVERY_V1.md`](RAVEN_PRIVATE_DISCOVERY_V1.md), [`RAVEN_PRIVATE_INTRODUCTION_V1.md`](RAVEN_PRIVATE_INTRODUCTION_V1.md), [`RAVEN_PRIVATE_RENDEZVOUS_V1.md`](RAVEN_PRIVATE_RENDEZVOUS_V1.md), [`RAVEN_PUBLIC_REPOSITORY_SYNC_V1.md`](RAVEN_PUBLIC_REPOSITORY_SYNC_V1.md). Related drafts that say wire/adapters or library/implementation profile not frozen: [`RAVEN_SOVEREIGN_INTEROPERABILITY_GATEWAY_V1.md`](RAVEN_SOVEREIGN_INTEROPERABILITY_GATEWAY_V1.md), [`RAVEN_SOVEREIGN_MEDIA_PROVENANCE_V1.md`](RAVEN_SOVEREIGN_MEDIA_PROVENANCE_V1.md), [`RAVEN_PRIVATE_REALTIME_MEDIA_V1.md`](RAVEN_PRIVATE_REALTIME_MEDIA_V1.md). Additive `rvn1` lab profiles that **do** freeze bytes but stay production-disabled are listed in [`RAVEN_INTEROPERABILITY_MATRIX.md`](RAVEN_INTEROPERABILITY_MATRIX.md) §5.

---

## Negotiation

| Mechanism | What it is | Known risk |
|---|---|---|
| `RavenProtocolCapabilitiesV1` | Signed, identity-scoped capability record (`env_type=4`). Domain `"rvn1/caps"`. See [`RAVEN_CAPABILITIES_V1.md`](RAVEN_CAPABILITIES_V1.md). | Single signed namespace going forward. |
| Legacy unsigned RUM v2 `Capabilities` | BLE GATT advertisement bitmask (`docs/MESH_PROTOCOL.md` §A). Anyone in radio range can observe or alter it. | Bits 0–12 agree across current clients. **Bit 13 `doubleRatchet`** is present on iOS/macOS and **unallocated** on Windows/Android. Documented platform drift; this inventory does not authorize a code fix. |

Capability negotiation is layered on version negotiation. Reconciling legacy RUM bits onto `RavenProtocolCapabilitiesV1.capability_bits` is not part of the `rvn1` freeze.

---

## RDAP (cross-repo note only)

[`Raven-ASHCO/raven-distributed-agent-protocol`](https://github.com/Raven-ASHCO/raven-distributed-agent-protocol) package **1.1.0** is an experimental A2A companion. It vendors `protocol/reference/raven_protocol`. It is **not** the `raven-node` identity store. Those package / companion facts are unchanged.

**RDAP B1 (main-green streak reset; required checks OFF / pin not enabled).** The six A2A selftest job names are unchanged. They are **not** “live B1 required pins” and are **not** “verified live required checks.” Branch-protection **required checks are OFF** (`required_status_checks: null`); the pin is **not** enabled. Manager GO asked to re-enable; that GO is **not applied yet**. Job display names are from workflow **RDAP selftest** (`.github/workflows/selftest.yml` in the RDAP repo):

1. `A2A selftest (ubuntu-latest, Python 3.10)`
2. `A2A selftest (ubuntu-latest, Python 3.12)`
3. `A2A selftest (macos-latest, Python 3.10)`
4. `A2A selftest (macos-latest, Python 3.12)`
5. `A2A selftest (windows-latest, Python 3.10)`
6. `A2A selftest (windows-latest, Python 3.12)`

Streak reset; ≥2 consecutive greens on tip `4307b86e` (`4307b86e69144f20480c24d6d6ce9f1e68a596e7`). DevSecOps reports the main-green streak reset after an intervening RDAP selftest failure on `3c5a0cb` (run [`34033634481`](https://github.com/Raven-ASHCO/raven-distributed-agent-protocol/actions/runs/34033634481)), then greens on `4d58dd46` (run [`34035297812`](https://github.com/Raven-ASHCO/raven-distributed-agent-protocol/actions/runs/34035297812)) and tip `4307b86e` (run [`34035600187`](https://github.com/Raven-ASHCO/raven-distributed-agent-protocol/actions/runs/34035600187)).

Do not treat RDAP B1 as RAVEN `main` branch protection. RAVEN Serverless names and status are in **RAVEN Serverless B1 (main-green verified, pin not enabled)** below (pending **founder GO**, not Manager GO). Do not use live-pin language for either repo until the matching GO is applied.

---

## RAVEN Serverless B1 (main-green verified, pin not enabled)

DevSecOps confirmed **main-green verified** on tip `e0a317aa` (`e0a317aa6d4873d13b674a8e62adc204950d7935`):

- Workflow **Raven Serverless Node** run [`33989477053`](https://github.com/Raven-ASHCO/RAVEN/actions/runs/33989477053) → success (push)
- Workflow **Raven B1 Always-On** run [`33989477009`](https://github.com/Raven-ASHCO/RAVEN/actions/runs/33989477009) → success (push); job `B1 always-on gate` success

These six check names were SUCCESS on that tip. They are **PR-green candidates now recorded as main-green**. Pin / branch-protection is **NOT enabled** — pending **founder GO**. They are **not** “live required B1 pins.” That language is reserved for after founder GO. RDAP B1 above is a separate-repo note: streak reset (≥2) on tip `4307b86e`, required checks **OFF**, pending **Manager GO**. Keep the distinction.

1. `B1 always-on gate`
2. `Messaging-only product boundary`
3. `Secret pattern scan`
4. `Rust + vectors (Linux)`
5. `Rust (macOS)`
6. `Rust (Windows)`

This inventory does **not** enable branch protection and does **not** promote these names to required checks on this repo’s `main`.

---

## CI consumers on serverless `main` (honesty)

This repo’s current `main` has **`node/`**, **`protocol/`**, and **`shared-vectors/`**. It has **0** `ios-native/` and **0** `RAVEN-WatchApp/` paths. iOS / Go / Watch jobs remain **skip-when-absent / N/A** on this serverless tree (unchanged honesty from [PR #9](https://github.com/Raven-ASHCO/RAVEN/pull/9)). This inventory does **not** treat those jobs as healthy required gates.

Cite present-tree evidence first. The six names in **RAVEN Serverless B1** above are **main-green verified** on `e0a317aa`; pin is **not** enabled.

| Workflow job `name:` | Step `name:` (when relevant) | Present-tree status |
|---|---|---|
| **Rust + vectors (Linux)** | **protocol vectors (python)** | Intended `rvn1` vector regen/drift gate (`pytest` + `generate_rvn1.py` + `git diff --exit-code` on `shared-vectors/rvn1`). Parent job is **main-green verified** on `e0a317aa` (pin not enabled). |
| **Rust + vectors (Linux)** | **experimental mailbox/NAT tests (still production-disabled)** | Intended fail-closed hold: experimental binaries must refuse to run without explicit opt-in. Parent job is **main-green verified** on `e0a317aa` (pin not enabled). Profile remains production-disabled. |
| **.NET / C# rvn1 shared-vector consumer** | — | **NOT YET.** No smoke gate in `raven-serverless.yml`. Do not invent a C# harness. |

Jobs that remain **skip-when-absent / N/A** on this serverless `main` (not B1 candidates; not required gates):

| Workflow job `name:` | Why it is not a healthy gate here |
|---|---|
| **Go libp2p bridge security** | `working-directory: ios-native/RAVEN/Libp2pBridge` (`go.mod` absent). **Skip-when-absent / N/A.** |
| **iOS protocol security tests** | `working-directory: ios-native/RAVEN`. **Skip-when-absent / N/A.** |
| **Full Braid Slice 2 lab (iOS)** | Lab workflow; requires `ios-native/RAVEN`. **Skip-when-absent / N/A.** |
| **Full Braid Task 0A macOS + iOS (0A.2–0A.4)** | Lab workflow; iOS half needs the same missing tree. **Skip-when-absent / N/A.** |

Watch jobs remain **N/A** on this serverless tree (no `RAVEN-WatchApp/` paths). Other lab job display names (not claimed as RAVEN B1 here): **ML-KEM-768 incremental (portable)**, **ML-KEM-768 incremental (AVX2)**, **ML-KEM-768 incremental (NEON)**, **Full Braid Slice 2 lab**, **Full Braid Task 0A provenance (0A.1)**, **Full Braid Task 0A Linux (0A.2/0A.4/0A.5)**, **Full Braid Task 0A Windows MSVC (0A.2/0A.4)**.

Platform vector consumers outside this workflow: see [`../shared-vectors/README.md`](../shared-vectors/README.md). **.NET / C# `rvn1` CI consumer is NOT YET.**
