# RavenIntroductionV1

**Version:** 1 (`rvn1`)  
**Status:** Discovery V1  
**Companion:** [`docs/RAVEN_DISCOVERY_V1.md`](../docs/RAVEN_DISCOVERY_V1.md)

Recipient-specific social introduction. Relays see opaque note ciphertext only.

| Field | Meaning |
|-------|---------|
| intro_id | 16 bytes |
| introducer_raven_id | Signer |
| subject_raven_id | Introduced identity |
| recipient_raven_id | Intended inbox |
| subject_display_name / subject_aliases | Advisory |
| note_ciphertext | E2EE to recipient |
| created_at / expires_at | unix ms |
| signature | Ed25519 by introducer |

**Domain:** `"rvn1/intro"`

Introductions never publish a friendship graph. Verification state for discovery: `INTRODUCED`.

## Admission rules

`verify()` only proves that the introducer's key signed the record, that
`introducer_raven_id` is that key's address, and that the record is within its
validity window. Anyone can self-sign an introduction mapping any alias to any
address, so a recipient inbox MUST additionally require, before an intro can
surface as `INTRODUCED`:

- `recipient_raven_id` equals the local user's Raven ID
  (`INTRO_WRONG_RECIPIENT`) — an intro captured from someone else's inbox is
  not replayable into ours;
- `introducer_raven_id` is an existing, non-blocked contact of the local user
  (`INTRO_UNTRUSTED_INTRODUCER`) — a stranger's introduction carries no
  social trust.

Deduplication is per `(introducer_raven_id, intro_id)`, so one introducer
cannot shadow another's intro by reusing its `intro_id`. The inbox prunes
expired intros and is size-capped (fails closed when full).

## Reference

`raven_core::introduction::{RavenIntroductionV1, IntroductionInbox}`
