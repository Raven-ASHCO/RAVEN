# RAVEN Protocol Version Inventory

**Status:** Living inventory (docs only). Not a wire change.
**Updated:** 2026-10-07
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

**RDAP B1 (main-green streak reset; required checks OFF / pin not enabled).** The six A2A selftest job names are unchanged. They are **not** “live B1 required pins” and are **not** “verified live required checks.” Branch-protection **required checks are OFF** (`required_status_checks: null`); the pin is **not** enabled. Founder **declined** pin-GO on 2026-09-06 (skipped the pin-GO widget; treat as **NO**). Pins remain **OFF** until an **explicit** founder GO. Do not re-ask this week. Job display names are from workflow **RDAP selftest** (`.github/workflows/selftest.yml` in the RDAP repo):

1. `A2A selftest (ubuntu-latest, Python 3.10)`
2. `A2A selftest (ubuntu-latest, Python 3.12)`
3. `A2A selftest (macos-latest, Python 3.10)`
4. `A2A selftest (macos-latest, Python 3.12)`
5. `A2A selftest (windows-latest, Python 3.10)`
6. `A2A selftest (windows-latest, Python 3.12)`

Streak reset; ≥2 consecutive greens on tip `4307b86e` (`4307b86e69144f20480c24d6d6ce9f1e68a596e7`). DevSecOps reports the main-green streak reset after an intervening RDAP selftest failure on `3c5a0cb` (run [`34033634481`](https://github.com/Raven-ASHCO/raven-distributed-agent-protocol/actions/runs/34033634481)), then greens on `4d58dd46` (run [`34035297812`](https://github.com/Raven-ASHCO/raven-distributed-agent-protocol/actions/runs/34035297812)) and tip `4307b86e` (run [`34035600187`](https://github.com/Raven-ASHCO/raven-distributed-agent-protocol/actions/runs/34035600187)).

Do not treat RDAP B1 as RAVEN `main` branch protection. RAVEN Serverless names and status are in **RAVEN Serverless B1 (main-green verified, pin not enabled)** below (also **OFF**; founder declined 2026-09-06). Do not use live-pin language for either repo until an explicit founder GO.

---

## RAVEN Serverless B1 (main-green verified, pin not enabled)

DevSecOps confirmed **main-green verified** on tip `e0a317aa` (`e0a317aa6d4873d13b674a8e62adc204950d7935`):

- Workflow **Raven Serverless Node** run [`33989477053`](https://github.com/Raven-ASHCO/RAVEN/actions/runs/33989477053) → success (push)
- Workflow **Raven B1 Always-On** run [`33989477009`](https://github.com/Raven-ASHCO/RAVEN/actions/runs/33989477009) → success (push); job `B1 always-on gate` success

These six check names were SUCCESS on that tip. They are **PR-green candidates now recorded as main-green**. Pin / branch-protection is **NOT enabled**. Founder **declined** pin-GO on 2026-09-06 (skipped the pin-GO widget; treat as **NO**). Pins remain **OFF** until an **explicit** founder GO. Do not re-ask this week. They are **not** “live required B1 pins.” That language is reserved for after an explicit founder GO. RDAP B1 above is a separate-repo note: streak reset (≥2) on tip `4307b86e`, required checks **OFF**, founder declined the same day. Keep the distinction.

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
| **Harness self-tests + protocol freeze** | **Protocol freeze hashes (docs/PROTOCOL_FREEZE_HASHES_V1.md)** | `scripts/freeze_protocol_hashes.sh --check`: any change / addition / removal under `protocol/` or `shared-vectors/rvn1/` fails unless the manifest is regenerated in the same change. New job; not a B1 name. |
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

---

## Freeze record changes (2026-10-07)

Owner-approved (2026-10-07) normative clarifications. **No wire format, key
derivation or signature input changed**; every pre-existing vector is
byte-identical. Docs / reference / additive vectors only:

- **Clock skew made normative.** `RAVEN_PAIR_INIT_V1.md` §1 / §5 name
  `MAX_PEER_CLOCK_SKEW_MS = 300000` (Rust `MAX_PREKEY_FUTURE_SKEW_MS`) for
  START bounds only (signed creation vs `now_ms`, and vs the trust-window
  start); expiry bounds are exact. The indexed-session windows use the same
  start-bound tolerance, applied after step-4 candidate selection
  (`ATSAM_ENDPOINT_TRANSACTION_V1.md` §1). `RAVEN_PREKEY_BUNDLE_V1.md` §4 now
  states the bundle's inclusive ±300000 ms window exactly as Rust and the
  `bundle_signing_00{1,2}` clock cases already did.
- **Other clarifications.** PairInit §1 now cites signed revocation (RVDR1)
  precisely instead of saying none exists; 24 h initiator session lifetime
  (informative, PairInit §4 and profile §2.4); `ATSAM_PRIMITIVE_MAPPING_V1.md`
  duplicate §3.4 heading fixed (root is §3.5) and the RVNA1 v1/v2 AAD string
  encodings specified as implemented; `ATSAM_HYBRID_RATCHET_V2.md` rev 11
  (§0.4 V2 signature domains, 227-byte PairResponse V2, reused V1 digest
  labels; §3.3 OTP / ML-KEM DK retention per the prekey lifecycle; §13.1
  known vector/spec discrepancies, vectors unchanged).
- **Owner waiver referenced.** The live LAN-direct indexed-session slice runs
  under [`WAIVER-LAN-DIRECT-2026-10-07`](../docs/WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md),
  now cited from umbrella §9.1 / §11, PairInit §7-§8, profile §7 and primitive
  mapping §3.4 as the only exception; everything else stays disabled.
- **Python reference.** One strict Ed25519 helper
  (`raven_protocol/ed25519_strict.py`: small-order A / R blocklist with the
  sign bit masked, canonical `s < L`) behind every reference signature check;
  PairInit V1 skew rule; PairInit V2 structural hard rejects aligned with V1;
  `prekey.verify(bundle, now_ms)` time window (old one-argument call kept).
- **Additive negative vectors** (generated by `generate_rvn1.py`):
  `negative/ed25519_weak_key_forgery_001.json`,
  `atsam/negative/pair_init_v1_small_order_ephemeral_001.json` (validly
  re-signed; only the structural rule fails) and
  `atsam/pair_init_v1_clock_skew_001.json`. Consumers:
  `protocol/reference/tests/` and
  `node/crates/raven-core/tests/rvn1_strict_vectors.rs`.

## Freeze record changes (2026-09-29)

No wire format, key derivation or signature input changed. Docs / vectors only:

- **Freeze manifest re-baselined.** `docs/PROTOCOL_FREEZE_HASHES_V1.md` (last
  generated 2026-08-12 at `7acbef7`) no longer matched the tree: 15 of its 68
  entries had changed — `SPEC.md`, `RAVEN_ENVELOPE_V1.md`, `RAVEN_ACK_V1.md`,
  `RAVEN_PREKEY_BUNDLE_V1.md`, `RAVEN_ROUTING_TAG_V1.md`,
  `RAVEN_STORE_OBJECT_V1.md`, `RAVEN_TRANSPORT_INTERFACE_V1.md`,
  `RAVEN_ALIAS_V1.md`, `RAVEN_INTEROPERABILITY_MATRIX.md`,
  `ATSAM_PRIMITIVE_MAPPING_V1.md`, `generate_rvn1.py`, `raven_protocol/__init__.py`,
  `raven_protocol/envelope.py` and two reference tests — mostly the post-freeze
  strict-decoder tightening and the security errata. The manifest is now a pure
  function of the tree (no timestamp header), covers **every** file under
  `protocol/` and `shared-vectors/rvn1/`, and CI enforces it with `--check`.
- **Additive vectors** (new files; no committed vector changed):
  `prekey/bundle_signing_001.json` / `_002.json`, `negative/prekey_bad_sig_002.json`,
  `negative/envelope_expired_002.json`, strict-decoder negatives
  `negative/envelope_{expires_not_after_created,auth_len_63,reserved_flag,env_type_0,env_type_5,trailing_byte,truncated,bad_version}_001.json`,
  and PairInit V1 structural negatives `atsam/negative/pair_init_v1_*.json`.
  Rust consumer: `node/crates/raven-core/tests/rvn1_strict_vectors.rs`; the
  generator asserts the Python reference agrees.
- `RAVEN_ENVELOPE_V1.md` §6.1 now states the `expires_at > created_at` decode
  rule both reference decoders already enforced. `SPEC.md` marks the
  formats that have no byte-level contract as **implementation-defined**.

