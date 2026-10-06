# RavenContactRequestV1 / ContactAcceptV1

**Version:** 1 (`rvn1`)
**Status:** Codec frozen; product transport on security hold

**Companions:** [`docs/RAVEN_DISCOVERY_V1.md`](../docs/RAVEN_DISCOVERY_V1.md), [`RAVEN_PREKEY_BUNDLE_V1.md`](RAVEN_PREKEY_BUNDLE_V1.md), [`RAVEN_BRIDGE_V1.md`](RAVEN_BRIDGE_V1.md), [`RAVEN_PRIVATE_INTRODUCTION_V1.md`](RAVEN_PRIVATE_INTRODUCTION_V1.md)

> This V1 wire is session-root contact messaging, not first-contact bootstrap.
> The production-disabled Private Introduction companion defines the separate
> Raven-ID-to-inert-proposal architecture. It does not reinterpret this codec,
> reuse its keys, or open the held rootless APIs.

## Contact request

Sensitive fields live **inside** sealed ciphertext (`rvn1/contact-req-inner`).
Outer wire (`rvn1/contact-req-wire`) carries `request_id`, recipient address, expiry, ciphertext, sender auth + pub.

The ciphertext MUST be RVNA1 v2 under an authenticated ATSAM session root and
a crash-safely reserved chain index. Ed25519 public keys are never encryption
secrets. The rootless `create` / `open` compatibility APIs fail with
`CONTACT_REQ_SESSION_REQUIRED` in every build, including Debug and explicit
lab-feature builds.

Future delivery: pack **outer wire** as `RavenEnvelopeV1` message body only
after the durable indexed-session actor reserves the key/index and private
routing material. Bridge MUST NOT decrypt / `open`. The current ash and iOS UI
paths are deliberately held rather than synthesizing an incomplete session.

## Contact accept

Signed `ContactAcceptV1` from accepter to requester after local UI Accept.
Wire magic: `rvn1/contact-accept-wire`. A signature authenticates but does not
hide its Raven IDs, so the accept wire MUST be carried inside an authenticated
ATSAM-sealed body. Current product emission is held until that carrier exists.

Accept also binds a **local** contact: `raven_id` + petname, verification `TRUSTED_CONTACT`.
Decline drops pending. Block drops **all** of that sender's pending requests
and replay tombstones, adds the sender pub to the local block list, and from
then on refuses every request from that key (`CONTACT_REQ_BLOCKED`), replays
included. A sender can be blocked without a pending request (for example one
whose requests were all declined).

Verifying an accept (`ContactAcceptV1::verify`) checks the Ed25519 signature
under `accepter_pub` **and** `encode_address(accepter_pub) ==
accepter_raven_id`; a signature alone would let any key claim any accepter's
Raven ID. Before a requester trusts an accept (marks "accepted", binds a
contact) it MUST also check it against the request it sent
(`verify_for_request`): same `request_id`, `accepter_raven_id` equal to that
request's `recipient_raven_id`, and `requester_raven_id` equal to the
requester's own address. The accept wire decodes exactly — trailing bytes are
rejected.

## Rules

- Store/bridge see ciphertext only (inner plaintext never on wire).
- Multi-transport arrivals dedup the authenticated object digest; after
  successful decryption the inbox-level idempotency key is
  **`(sender_pub, request_id)`**, not `request_id` alone. `request_id` is
  visible on the outer wire, so a different paired sender could otherwise
  squat it and have the original silently dropped. Two pending requests from
  different senders may share a `request_id`; an Accept/Decline/Block that
  names only the `request_id` then fails closed (`CONTACT_REQ_AMBIGUOUS_ID`)
  and the caller must name the sender.
- Decrypted sender ID and timestamps MUST equal their authenticated outer
  counterparts before an inbox row or contact binding is created.
- **Validity window.** `expires_at - created_at` MUST NOT exceed 30 days
  (`CONTACT_REQ_LIFETIME_TOO_LONG`) and `created_at` MUST NOT be more than
  5 minutes ahead of the receiver's clock (`CONTACT_REQ_NOT_YET_VALID`).
- **Replay tombstones.** The inbox remembers every admitted
  `(sender_pub, request_id)` — pending, accepted or declined — until the
  request has expired *and* left the rate window. Blocking a sender replaces
  that sender's tombstones with the block entry. A re-delivery of a
  still-pending request is idempotent; a replay of a resolved one is refused
  (`CONTACT_REQ_REPLAY`). Implementations that persist the inbox MUST persist
  the tombstones (and the inbox's blocked-sender set) with it.
- **Tombstone budget.** At most 16 tombstones per sender: a sender at that
  bound is refused (`CONTACT_REQ_SENDER_CAP`) until its own tombstones
  expire, so one key pacing requests under the rate limit and having them
  declined cannot consume the shared budget. The shared set is capped at 4096
  (reachable only with 256 distinct paired senders each at its bound) and
  admission then fails closed (`CONTACT_REQ_INBOX_FULL`); the user can always
  free space by blocking a sender, which drops that sender's tombstones (the
  block itself takes over their replay protection). Per-sender limits are
  checked before the shared caps.
- **Anti-spam.** At most 64 pending requests, at most 3 pending per sender,
  and at most 5 admissions per sender per rolling hour — counting requests
  already resolved, so decline-and-resend cannot bypass the rate limit.
- Local block does not require a central moderation server.
- Contact binding is by Raven ID; alias changes do not rebind identity.

## Reference

`raven_core::contact_request::{RavenContactRequestV1, ContactAcceptV1, ContactRequestInbox}`
