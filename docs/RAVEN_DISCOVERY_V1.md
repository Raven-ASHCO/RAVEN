# Raven Discovery V1 — Multi-lane Search / Contact Request

**Status:** Software V1 implemented (authored on the historical branch `feature/raven-serverless-v1`; now on `main`)
**Companions:** [`RAVEN_TAG_V1.md`](RAVEN_TAG_V1.md), [`SERVERLESS_MODEL.md`](SERVERLESS_MODEL.md), [`SERVERLESS_FRIEND_MESH_BRIDGE_DESIGN.md`](SERVERLESS_FRIEND_MESH_BRIDGE_DESIGN.md), [`protocol/RAVEN_ALIAS_V1.md`](../protocol/RAVEN_ALIAS_V1.md), [`protocol/RAVEN_BRIDGE_V1.md`](../protocol/RAVEN_BRIDGE_V1.md), [`protocol/RAVEN_PREKEY_BUNDLE_V1.md`](../protocol/RAVEN_PREKEY_BUNDLE_V1.md), [`protocol/RAVEN_PROFILE_RECORD_V1.md`](../protocol/RAVEN_PROFILE_RECORD_V1.md), [`protocol/RAVEN_INTRODUCTION_V1.md`](../protocol/RAVEN_INTRODUCTION_V1.md), [`protocol/RAVEN_CONTACT_REQUEST_V1.md`](../protocol/RAVEN_CONTACT_REQUEST_V1.md)

## Architectural law

| Law | Meaning |
|-----|---------|
| Finding a name ≠ verifying a person | Search yields **candidates**; trust requires crypto verify / pin |
| `@alias` is NOT identity; `rvn1…` is | Contact keys bind to Raven address / pubkey |
| Show alias conflicts; never silent pick | Partition / Sybil competitors must surface |
| Bridge must NOT plaintext-search | Forward opaque discovery / contact envelopes only |
| No phone/email hashes in public DHT | PSI / private directory is post-V1 |
| No publishing friendship graphs | Friend receipts stay on-device |
| Zooko's triangle | No global unique short names without authority |

**Inspiration (cite, do not copy unsafely):** MIT UIA (user-relative names), CAP / partition naming limits, Cambridge Pudding (private directory research). Exact Raven ID + Alias V1 + QR/Nearby + introductions first.

## Identity hierarchy

| Layer | Name | V1 |
|-------|------|----|
| Raven ID | `rvn1…` self-certifying address | **Required** |
| Display name | Unrestricted label | Yes (profile) |
| Alias | Signed `@tag` (Alias V1) | Yes — non-unique |
| Local nickname / petname | Device-local (Tag V1 Layer C) | Yes |
| Scoped handle (`name@namespace`) | Namespace-certified | Spec only (optional later) |
| Transport Peer ID | libp2p / dial identity | Separate from Raven ID |

## DiscoveryResolver (canonical)

```text
DiscoveryResolver.search(query, scope)
scopes: LOCAL | EXACT_ID | EXACT_ALIAS | MY_NETWORK | NEARBY | PUBLIC | ALL
```

### Providers (V1)

| Provider | Status |
|----------|--------|
| LocalContactsProvider | Implemented |
| ExactRavenIdProvider | Implemented (`H("raven/profile/v1"\|\|id)`) |
| AliasDhtProvider | Implemented — bounded signed claims + conflict_count |
| NearbyBleProvider | Implemented as a resolver over *confirmed* nearby results — ephemeral adv; no permanent ID until confirm. The only producer in this repo, `ash nearby`, is a **local software mock** (it lists only this device's own ephemeral tokens; no BLE radio or receive side), so no real nearby peer is ever discovered here |
| SocialIntroductionProvider | Implemented — recipient-specific encrypted intros |
| PublicProfileIndexProvider | **STUB/OFF** (exact search first) |
| PrivateDirectoryProvider | **NOT V1** |
| LegacyServerProvider | Disabled when `serverless=true` (must not be required) |

### Result model

```text
DiscoveryResult {
  raven_id, display_name, aliases, profile_digest,
  source_set, verification_state, introductions,
  conflict_count, sequence, expires_at
}
```

### Verification states

`DIRECTLY_VERIFIED` · `TRUSTED_CONTACT` · `INTRODUCED` · `SCOPED_VERIFIED` (optional) · `NEARBY_VERIFIED` · `PUBLIC_SIGNED_PROFILE` · `ALIAS_CONFLICT` · `EXPIRED_OR_STALE` · `BLOCKED` · `UNVERIFIED` (checksum-valid exact ID with no signed profile)

## Protocol objects

| Object | Role |
|--------|------|
| `RavenProfileRecordV1` | Signed expiring profile; DHT key `H("raven/profile/v1"\|\|id)` |
| `RavenAliasRecordV1` | Bounded set of claims; charset `a-z0-9_-` |
| `RavenIntroductionV1` | Encrypted to recipient |
| `RavenContactRequestV1` + `ContactAcceptV1` | ATSAM-root codec frozen; product send/open held pending durable indexed-session state |
| `RavenPrivateIntroductionV1` | Separate production-disabled Raven-ID-to-inert-proposal architecture; no session/contact authority |

Contact requests ride existing **MessageRouter** paths: direct / relay / store / BLE / Bridge — opaque envelope, same `message_id`.

## ash CLI

```bash
ash find @poline
ash find rvn1…
ash find poline --local          # no public fuzzy in V1
ash nearby
ash alias publish --alias poline
ash contact add …                # QR / OOB pin
ash contact request @poline     # currently fails closed: ATSAM session required
ash contact request rvn1…       # currently fails closed: ATSAM session required
```

Those two held commands refer to the legacy session-root contact-request wire.
A future first-contact command may use
[`RAVEN_PRIVATE_INTRODUCTION_V1.md`](../protocol/RAVEN_PRIVATE_INTRODUCTION_V1.md)
only after that companion is APPROVED; it remains a quiet pending proposal, not
a chat message, contact, PairInit, or delivery claim.

Interactive picker on alias conflicts (same resolver as future mobile).

## iOS

`DiscoveryResolver`-equivalent types + tests under serverless flag; discovery path must not call FastAPI when RavenEnvelopeV1 / serverless is ON.

**Search UI (V1):** `FindContactsView` + `DiscoverySearchViewModel` behind `FeatureFlag.ravenEnvelopeV1` — scopes **All / My Network / Public (exact alias|id) / Nearby**, petname-first rows, provenance + alias-conflict picker (never silent pick). Contact-request send/open remains on a visible security hold until authenticated ATSAM root, crash-safe chain state, private routing, and sealed accepts interoperate. QR add remains available; no contacts FastAPI sync is introduced.

## V1 MUST NOT include

- Global fuzzy / trigram index
- Phone / email PSI
- Private directory committee
- Follow / social feed

## Phases

| Phase | Scope |
|-------|-------|
| **V1** | Exact ID, exact alias, local/QR, nearby ephemeral, session-root introductions/contact requests, conflict display, Sybil quota on alias publish; network first-contact remains held |
| **V1.5** | Opt-in public profile tokens (bounded), scoped handles, richer intro UX, mobile search UI parity |
| **V2** | Private directory / PSI research path, fuzzy index with cost, FOAF vouch (optional) |

## Acceptance

Automated suite: `cd node && cargo test -p raven-core --test discovery_v1` (research §22 cases 1–20).

## Cross-links

- Soft Unique Tags UX: [`RAVEN_TAG_V1.md`](RAVEN_TAG_V1.md)
- Checklist: [`MASTER_CHECKLIST_STATUS.md`](MASTER_CHECKLIST_STATUS.md) §11 / §29
- Rust: `raven_core::discovery_resolver`, `alias_record`, `profile_record`, `contact_request`, `nearby`, `introduction`
