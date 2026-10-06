# Raven Tag V1 — Petname + Public Tag + Address

**Status:** Binding UX for serverless friendship plane (V1)  
**Companions:** [`protocol/RAVEN_ALIAS_V1.md`](../protocol/RAVEN_ALIAS_V1.md), [`docs/SERVERLESS_FRIEND_MESH_BRIDGE_DESIGN.md`](SERVERLESS_FRIEND_MESH_BRIDGE_DESIGN.md), [`docs/SERVERLESS_MODEL.md`](SERVERLESS_MODEL.md)  
**Branch (historical):** authored on `feature/raven-serverless-v1`; this file now lives on `main` and is a dated snapshot, not a statement about an open branch

## Zooko's triangle (law)

You cannot have all three of: **human-meaningful**, **globally unique**, and **decentralized**.

Raven Alias V1 is therefore correct: self-signed, **non-unique** nicknames with **mandatory ambiguity surfacing**. There is:

- **NO** ENS / name registrar  
- **NO** Raven “is @ahmad taken?” API / username server  
- **NO** blockchain name marketplace  

Tags are **not transferable property**. DHT competitors never overwrite a locally **pinned** Tag↔key binding.

## Three layers

| Layer | Name | Properties | UI role |
|-------|------|------------|---------|
| **A** | RavenAddress / fingerprint | Globally unique + secure | Never the primary inbox label; verify / advanced |
| **B** | Public Tag (`@ahmad`) | Alias V1 self-claim — **not unique** | Subtitle under petname |
| **C** | Petname (`Ahmad — work`) | Unique **on this device only** | **Primary** inbox / contacts label |

**Inbox rule:** lead with petname → public tag as subtitle → address/fingerprint only on demand.

## Soft Unique Raven Tags (V1 primary)

1. **First-meet / QR verify → pin**  
   After fingerprint confirm, store `(public_tag, address, pub_hex)` as **pinned**. Later DHT/gossip claims for the same `@tag` that disagree with the pin are shown as competitors — they **never** silently replace the pin.

2. **Ambiguity picker**  
   Multiple live `@ahmad` claims → list with fingerprints/addresses → user picks → save distinct petnames (`Ahmad (Berlin)`, `Ahmad — work`). **Never silent pick.**

3. **Key-change warning**  
   If a previously pinned public tag is later claimed by a **different** address/key (or pin’s pubkey changes), surface a fingerprint-style warning before trust/update. Same posture as Alias V1 §3.

4. **Optional later (document only in V1)**  
   FOAF vouch, mutual-ACK stickiness, BLE scene tags, callsign defaults — not required for V1 ship.

## Refuse

| Refuse | Why |
|--------|-----|
| “Is @ahmad taken?” API | Reintroduces a registrar / central authority |
| Silent collision winner | Ambiguity rule / Sybil redirect |
| Tags as transferable property | Not Layer A; not a market |
| Tags in relay capability ads | Capabilities stay generic (`bridge`/`store`/…) — never contact graphs |

## Gossip vs local store

| Store | Contents |
|-------|----------|
| Local `contacts.json` (ash) | `petname`, `public_tag`, `address`, `pub_hex`, `pinned` |
| DHT / AliasRecord | Self-signed Layer B claims only — advisory |
| Relay / Bridge | Opaque envelopes only — no tags in caps |

Pinned local rows beat untrusted gossip for that device’s friendship plane.

## UX flows (terminal)

```
ash contact add --address rvn1… --pub-hex … --tag ahmad --petname "Ahmad — work" --verify-fp …
  → pin Tag+key locally

ash contact list
  → petname first, @tag subtitle, fp on detail

ash contact resolve --tag ahmad
  → if multiple local/pinned candidates: ambiguity picker (never silent)
```

Interactive Contacts menu: same rules; stdin for secrets; fingerprint confirm pins.

## Cross-links

- Friendship plane: `SERVERLESS_FRIEND_MESH_BRIDGE_DESIGN.md`  
- Wire alias: `protocol/RAVEN_ALIAS_V1.md`  
- Multi-lane discovery / search / contact request: [`RAVEN_DISCOVERY_V1.md`](RAVEN_DISCOVERY_V1.md)  
- Migration labels: `MIGRATION_SERVERLESS_V1.md` (`serverless_rvn1` vs `legacy_*`)
