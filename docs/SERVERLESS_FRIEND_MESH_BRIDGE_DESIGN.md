# Serverless Friend Add, Mesh Relay, and Bridge — Design Memo

**Status:** Binding product/protocol UX for V1 terminal + flagged mobile  
**Security override:** [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md) overrides this memo where they conflict — in particular rule 6 (relays MUST NOT durably dedup on unverified `message_id`) and rule 8 (`hop_limit` / `replication_budget` are unauthenticated; they constrain cooperative nodes only, not Byzantine retransmission). The "bounds" below are cooperative policy, not enforced security properties.  
**Branch (historical):** authored on `feature/raven-serverless-v1`; this file now lives on `main` and is a dated snapshot, not a statement about an open branch  
**Companions:** `node/SERVERLESS_MODEL.md`, `protocol/RAVEN_BRIDGE_V1.md`, `protocol/RAVEN_PREKEY_BUNDLE_V1.md`, `docs/PRIOR_ART_REVIEW_V1.md`, `docs/MULTI_DEVICE_PARTITION_REVOCATION.md`

## Law: three planes (never collapse)

| Plane | What it is | What it is **not** |
|-------|------------|---------------------|
| **1. Trust / friendship** | OOB/QR, fingerprint verify, signed prekey, local contacts (+ optional later FOAF) | Central people directory, FastAPI user search, social “authority” nodes |
| **2. Delivery** | Store-carry-forward of **opaque** ciphertext (mesh / relay / Internet dial) | A place that knows who your friends are |
| **3. Interop (Bridge)** | Untrusted **cross-transport** forward of the **same** `RavenEnvelopeV1` (DTN gateway sense) | A “social bridge node,” friend introducer, or contact graph broker |

Aligns with Fall’s DTN gateway idea: custody transfer of opaque bundles across dissimilar links — **not** a trusted social intermediary.

---

## 1. Contact add (V1 UX + protocol)

### Happy path (terminal `ash` / mobile flag ON)

```
QR or OOB paste
  → Raven address (rvn1…) + Ed25519 pub hex
  → show fingerprint (RavenDeviceFingerprintV1)
  → user confirms match (in-person / voice / known channel)
  → optional local @alias (disambiguation UI if collision)
  → optional fetch/verify RavenPrekeyBundleV1 (file / store tag / DHT record)
  → first RavenEnvelopeV1 sealed to that identity
```

### CLI surface (V1)

| Command | Behavior |
|---------|----------|
| `ash contact add --address … --pub-hex … --petname "…" --tag ahmad [--verify-fp …]` | Local contact; verify pins Tag+key; never FastAPI |
| `ash contact list` | **Petname first**, `@tag` subtitle, fp on detail |
| `ash contact resolve --tag ahmad` | Ambiguity picker if multiple claims |
| `ash contact verify --tag\|--petname\|--address` | Fingerprint / pin check |
| Interactive Contacts menu | Same flow; stdin — no seeds in argv |

Alias / tag ambiguity: if `@bob` matches multiple local contacts, ash lists candidates with petnames + fingerprints and refuses silent pick. See `docs/RAVEN_TAG_V1.md` (Zooko's triangle).

### FOAF (explicitly later)

Friend-of-friend introductions are **out of V1 claims**. Optional bounded FOAF may appear later with:

- introducer signature + rate limits,
- no global social graph upload,
- clear UX that FOAF ≠ QR-level trust.

V1 = **local contacts + QR/OOB address + alias ambiguity UI**.

### Friendship never uses FastAPI

`ATSAMPrekeyService` HTTP remains **legacy optional** on iOS. Serverless path publishes/fetches prekeys via:

- OOB file / QR,
- opaque `StoreObject` tags,
- signed discovery / DHT values (`PeerRecord` / prekey records),

not a Raven-operated people directory.

---

## 2. Mesh / relay algorithm claim (V1)

**Claim for V1:** Spray-and-Wait–style **cooperative-policy bounds** only (not authenticated; see the security override above):

- `replication_budget` decremented on forward (unsigned, mutable; cooperative nodes only),
- `hop_limit` (unsigned, mutable; cooperative nodes only) and TTL (`expires_at`, which **is** signed),
- per-peer rate limits,
- relay dedup via a bounded, expiring replay cache keyed on `SHA-256(domain || envelope_signing_bytes || outer_signature)` (`raven_core::bridge::authenticated_object_digest`), recorded only after admission — a relay never durably dedups on an unverified `message_id`; endpoints dedup on `message_id` only inside the authenticated commit (errata rules 5 and 6).

Implemented in `raven-core::bridge` / forward queue. Software demos: `bridge_abc_demo`, mock_ble, store-carry.

**Not claimed for V1:**

- BUBBLE / BUBBLE-Rap community centrality,
- SimBet utility routing,
- optimal epidemic or “world’s best” DTN routing.

**Future research options** (cite, do not ship as product claims): Cambridge/Trinity lines of work on social-aware DTN (BUBBLE, SimBet) may inform **optional** heuristics behind the same opaque envelope — never as a trust plane.

---

## 3. Bridge = DTN gateway (Fall), not social bridge

Per `protocol/RAVEN_BRIDGE_V1.md`:

- Same `message_id` + ciphertext across transports.
- Bridge/relay/store **do not decrypt**.
- Roles: Endpoint vs Bridge/Relay/Store separated (iOS: BridgeService vs ChatWire).
- Capability ads are generic (`bridge`/`ble`/`internet`/`store`/`relay`) — **never** contact graphs.

“Bridge” in Raven marketing/docs MUST mean this interop plane. Do not overload with “bridge node that introduces friends.”

---

## 4. Honest limits

| Limit | Why it matters |
|-------|----------------|
| Bootstrap chicken-egg | First contact needs OOB/QR or a pre-existing dial/prekey path; empty DHT does not invent friends. |
| NAT helpers ≠ social authority | TURN/relay/bootstrap peers forward bytes; they MUST NOT mint trust or contact lists. Raven defaults: empty/disableable bootstrap (`BootstrapConfig`). |
| DHT privacy cost | Putting dial/prekey records in a public DHT leaks **availability metadata** (online windows, record churn). Prefer OOB for high-sensitivity adds. |
| Sybil | Cheap identities; fingerprint verify + rate limits + local accept lists are the V1 mitigations — not a global PKI. |
| Epidemic scale | Unbounded spray harms battery/radio; V1 applies cooperative-policy bounds only (hop/replication are unauthenticated and a relay can reset them; TTL is signed) — a relay can always copy ciphertext. |
| Partition revocation lag | See `docs/MULTI_DEVICE_PARTITION_REVOCATION.md`. |

---

## 5. Prior art (lessons — no “world’s first”)

| Source | Lesson for Raven | What we do **not** claim |
|--------|------------------|---------------------------|
| PeerSoN | P2P social storage; separate identity from ISP login | Copying PeerSoN DHT schema |
| Safebook | Matryoshka / FOAF-ish privacy overlays | Shipping Safebook FOAF in V1 |
| Grassroots Social Networking (arXiv:2306.13941) | Local-first social protocols without platform sovereigns | Being “first” grassroots messenger |
| Fall DTN | Custody, late binding, gateway across heterogeneous links | Replacing BP/BPv7 |
| Spray-and-Wait | Bounded replication | Exact Spyropoulos algorithm identity |
| BUBBLE / SimBet | Social-aware DTN research options | V1 product routing claims |
| Bridgefy / similar BLE meshes | Epidemic + abuse/privacy lessons; clear threat model | “Military-grade” marketing |
| Briar / Cwtch / Session | Offline-first, no central inbox | Their identity formats |
| libp2p | Dial/relay/DHT patterns | Mandatory IPFS stack |

Full table: `docs/PRIOR_ART_REVIEW_V1.md`.

---

## 6. Mapping to codebase

| Plane | Code / docs |
|-------|-------------|
| Trust | `ash contact *`, fingerprints, `prekey_bundle`, local `contacts.json`, QR OOB |
| Delivery | `OutgoingQueue`, `ForwardQueue`, `StoreObject`, InternetTransport, mock_ble, swarm |
| Interop | `bridge` / `BRIDGE_V1`, `RavenEnvelopeBridgeService` (flag ON) |
| Algorithm bounds | `hop_limit`, `replication_budget` in envelope + bridge decide (unauthenticated cooperative-node bounds) |
| Migration | `docs/MIGRATION_SERVERLESS_V1.md`, `messaging_path` labels; MeshEnvelope default when iOS flag OFF |

---

## 7. Checklist hooks

- §11 Aliases/contacts — local + sanitize + ambiguity  
- §12 Async first contact — prekey OOB/store/DHT; FastAPI optional legacy only  
- §32–35 Store / Bridge / routing policy  
- §39 Multi-device sync (separate from friendship plane)  
- §54 Migration labels — never silent FastAPI  
- §59/§60 — physical multi-device / external review still **BLOCKED_HUMAN/HARDWARE**
