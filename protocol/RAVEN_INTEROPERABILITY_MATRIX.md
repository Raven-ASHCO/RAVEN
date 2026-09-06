# RAVEN Interoperability Matrix V1

**Version:** 1  
**Status:** Living evidence table for Phase A/B freeze  
**Updated:** 2026-09-06
**Version inventory:** [`PROTOCOL_VERSIONS.md`](PROTOCOL_VERSIONS.md)

CI names below are the `name:` strings from `.github/workflows/raven-serverless.yml` (workflow display name: **Raven Serverless Node**) and, for the thin always-on companion, `.github/workflows/raven-b1-always-on.yml` (**Raven B1 Always-On**). This serverless `main` has **no** `ios-native/` or `RAVEN-WatchApp/` tree. iOS / Go / Watch jobs remain **skip-when-absent / N/A** on this tree (unchanged honesty from [PR #9](https://github.com/Raven-ASHCO/RAVEN/pull/9)); they are **not** healthy required gates. Six RAVEN B1 check names are **main-green verified** on `e0a317aa`; pin / branch-protection is **NOT enabled** — pending **founder GO**. They are **not** “live required B1 pins” (that language is reserved for after founder GO; RDAP’s six A2A contexts are also not live required pins — required checks OFF, pending founder GO). See [`PROTOCOL_VERSIONS.md`](PROTOCOL_VERSIONS.md) § RAVEN Serverless B1. **.NET / C# `rvn1` shared-vector CI consumer is NOT YET** (no smoke gate in `raven-serverless.yml`).

## 1. Wire object parity

| Object | Spec | Python ref | Rust `raven-core` | Swift iOS | Notes |
|--------|------|------------|-------------------|-----------|-------|
| Identity / address | IDENTITY / ADDRESS | yes | yes | yes | bech32m `rvn` |
| Envelope RVN1 | ENVELOPE | yes | yes | yes (`RavenEnvelope*`) | Shared positive and strict-negative vectors |
| ACK plaintext record | ACK | yes | yes | chat wire codec | live paths held by security errata |
| Indexed session / sealed ACK | INDEXED_SESSION | exact vectors | pure KDF/codec parity | exact KDF/codec parity | RVNA1 `0x03`; **production disabled** — §5 |
| PairInit / response | PAIR_INIT | exact codec/KDF/signature KAT | exact codec/verification/KAT | exact codec/verification/KAT | offline provisional root; **production disabled** — §5 |
| Routing tag | ROUTING_TAG | yes | yes | GhostRoute related | |
| Alias / caps / cert | ALIAS / CAPS / IDENTITY | yes | signing bytes | partial | |
| Prekey bundle | PREKEY_BUNDLE | structural vectors | `prekey_bundle` | `ATSAMPrekeyService` | HTTP legacy optional; Rust lifecycle **production disabled** — §5 |
| Protected prekey lifecycle | local state, no wire type | normative state machine | `prekey_lifecycle` (**production disabled**) | pending | protected Rust actor; carrier and activation still blocked — §5 |
| Store object / mailbox transport | STORE_OBJECT / MAILBOX_TRANSPORT | vectors | strict object + real gated libp2p PUT/GET | bridge store path | mailbox transport **production disabled**; restart retrieval proven; TTL-only deletion; endpoint activation held — §5 |
| NAT traversal composition | NAT_CONNECTIVITY | — | gated AutoNAT v2 client + Relay v2 client + DCUtR | Go bridge precedent | **production disabled**; localhost TCP/QUIC/limit proof; real multi-NAT and CGNAT matrix pending — §5 |
| BLE framing | BLE_FRAMING | — | `ble_adapter` + mock | `RavenBleRvn1Carrier` | GATT hardware BLOCKED |
| Internet hello/frame | TRANSPORT | — | `internet` | LAN settings tests | |
| ATSAM root/KDF/AEAD | MAPPING | shared-vectors atsam/ | yes known-root | primary | ML-KEM: Rust+iOS |
| Bridge opaque forward | BRIDGE | — | `bridge` + demos | `RavenEnvelopeBridgeService` | |
| Endpoint transaction | ENDPOINT_TRANSACTION | — | production-disabled Rust actor | production-disabled Swift actor | no new envelope bytes; **production disabled** — §5 |
| Hybrid ratchet v2 / PairInit V2 | HYBRID_RATCHET_V2 | draft KATs | lab / Full Braid | lab FFI (tree absent here) | **REQUIRED / NOT YET APPROVED**; production disabled — §5 |
| Full Braid lab | HYBRID_RATCHET_V2 lab | `test_full_braid.py` | `full-braid-lab` feature | iOS lab gate (skip-when-absent / N/A) | lab-only vectors `production_enabled: false` — §5 |

## 2. Transport matrix

| Path | Software proof | Hardware leftover |
|------|----------------|-------------------|
| LAN TCP | `lan_path_smoke`, two_node | — |
| Internet/NAT | direct dial plus gated TCP/QUIC, Relay-client, AutoNAT-client, DCUtR localhost tests | multi-NAT / CGNAT / independently operated relay |
| mock_ble | `bridge_v1`, `bridge_abc` | — |
| BLE GATT | iOS unit/sim | physical 3-phone mesh |
| Store-carry | byte-identical libp2p sender-disconnect/store-restart/recipient-GET + bridge_abc | multi-store discovery/replication and real diverse operators |
| DHT discovery | signed record format | live libp2p DHT network |

## 3. Sealed content

| Frame | Rust | Swift |
|-------|------|-------|
| RVNA1 v2 known-root | seal + atsam_aead | ATSAMMessageSealer |
| RVNA1 `0x03` indexed ACK | pure KDF/codec + exact 143/293-byte vector | pure KDF/codec + same exact vector; not activated |
| RVNA1 hybrid PairInit | exact signed init/response + split ML-KEM + root HKDF | exact signed init/response verification + root HKDF; not activated |
| Noise RVNS1/RVNH1 | interim pairwise | NoiseSession |

## 4. How to extend

Add a row when a new platform claims parity; require shared-vector id or demo script SHA evidence in `docs/MASTER_CHECKLIST_STATUS.md`. A **.NET / C# `rvn1` shared-vector CI consumer is NOT YET** — do not add a green .NET cell until a real `raven-serverless.yml` smoke gate exists.

## 5. Production-disabled / gated profiles (vectors + CI)

Every row below is **production disabled** (or lab-only / not-yet-approved). Vector column uses committed path and `id`/`name` when present; otherwise `—` / `none yet`.

CI status labels: **present-tree evidence** (job can run against `node/` + `protocol/` + `shared-vectors/`; parent **Rust + vectors (Linux)** is **main-green verified** on `e0a317aa`, pin not enabled), **skip-when-absent / N/A**, **NOT YET**.

| Profile | Vectors / shared-vector ids | CI job `name:` / step `name:` | Status on serverless `main` |
|---|---|---|---|
| Indexed session / RVNA1 `0x03` | `shared-vectors/rvn1/atsam/indexed_session_v1_subkeys_001.json` (`atsam_indexed_session_v1_subkeys_001`); `indexed_session_v1_sealed_ack_001.json` (`atsam_indexed_session_v1_sealed_ack_001`) | **Rust + vectors (Linux)** → **protocol vectors (python)**; **iOS protocol security tests** (`ATSAMIndexedSessionProfileTests`) | Production disabled. Linux protocol-vector step is present-tree evidence; parent job **main-green verified** on `e0a317aa` (pin not enabled). iOS job **skip-when-absent / N/A**. |
| PairInit V1 | `shared-vectors/rvn1/atsam/pair_init_v1_001.json` (`atsam_pair_init_v1_001`) | **Rust + vectors (Linux)** → **protocol vectors (python)**; **iOS protocol security tests** (`ATSAMPairInitV1Tests`) | Production disabled. Same Linux vs iOS split as above. |
| Prekey lifecycle | none yet (local state; no wire type) | **Rust + vectors (Linux)** → **test raven-core + ash** (`raven_core::prekey_lifecycle`) | Production disabled. Isolated Rust actor only. Parent job **main-green verified** on `e0a317aa` (pin not enabled). |
| Prekey bundle (activation held) | `shared-vectors/rvn1/prekey/bundle_structure_001.json` (`bundle_structure_001`); `negative/prekey_bad_sig.json` (`prekey_bad_sig`) | **Rust + vectors (Linux)** → **protocol vectors (python)** | Structural KATs exist; production activation held with PairInit gates. |
| Endpoint transaction | none yet | **Rust + vectors (Linux)** → **test raven-core + ash**; **iOS protocol security tests** (`ATSAMEndpointTransactionV1Tests`) | Production disabled. No shared-vector id. iOS job **skip-when-absent / N/A**. |
| Mailbox transport | `shared-vectors/rvn1/store/mailbox_tag_001.json` (`mailbox_tag_001`) for tags; PUT/GET smokes are scripts, not KATs | **Rust + vectors (Linux)** → **experimental mailbox/NAT tests (still production-disabled)**; **mailbox opaque put/get smoke**; **libp2p offline mailbox restart smoke** | Production disabled. Fail-closed hold + smokes are present-tree evidence; parent job **main-green verified** on `e0a317aa` (pin not enabled). |
| NAT connectivity | — | **Rust + vectors (Linux)** → **experimental mailbox/NAT tests (still production-disabled)** | Production disabled. Fail-closed hold is present-tree evidence; parent job **main-green verified** on `e0a317aa` (pin not enabled). |
| Full Braid lab | `shared-vectors/rvn1/atsam/full_braid_sm_round_001.json`; `full_braid_full_exchange_2pq_2dh_001.json` (`production_enabled: false`, `lab_only: true`) | **Full Braid Slice 2 lab** → **Test Full Braid (Rust)**, **Python Full Braid reference**, **Production remains off (vectors + no app callsites)**; **Full Braid Slice 2 lab (iOS)** | Lab-only. Linux job is the named lab gate (not a RAVEN B1 name). iOS lab job **skip-when-absent / N/A**. |
| Hybrid ratchet v2 / PairInit V2 | `shared-vectors/rvn1/atsam/pair_init_v2_001.json` (name: PairInit V2 / PairResponse V2 wire + pair-expand); `atsam/negative/pair_init_v1_as_v2_001.json`; `atsam/tr_*.json` | **Rust + vectors (Linux)** → **protocol vectors (python)**; **Full Braid Slice 2 lab** | Draft / `NOT YET APPROVED`; production disabled. Wire not a production profile. |
| Identity Continuity V2 | none yet | — | Draft / production disabled. No CI consumer. |
| .NET / C# `rvn1` vectors | (would consume `shared-vectors/rvn1/` when added) | — | **NOT YET.** No job or step in `raven-serverless.yml`. |

iOS / Go / Watch jobs (and iOS Full Braid / Task 0A macOS+iOS lab jobs) remain **skip-when-absent / N/A** on this serverless tree. Do not cite them as healthy required gates. The six RAVEN B1 names in [`PROTOCOL_VERSIONS.md`](PROTOCOL_VERSIONS.md) are **main-green verified** on `e0a317aa` only — pin **not** enabled, pending founder GO. They are **not** live required B1 pins. See [`PROTOCOL_VERSIONS.md`](PROTOCOL_VERSIONS.md) § CI consumers.
