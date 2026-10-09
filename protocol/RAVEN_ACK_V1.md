# RAVEN Ack V1

**Version:** 1 (`rvn1`)
**Status:** Record layout frozen; production security hold. Read
[`SECURITY_ERRATA_RVN1_2026-08-13.md`](SECURITY_ERRATA_RVN1_2026-08-13.md).
In particular, an ACK body is sealed: a relay or transport MUST NOT peek
`acked_message_id`, and an ID-only callback MUST NOT advance delivery.
**Audience:** re-implementers of delivery-state tracking on either the sending
or receiving side.

---

## 1. An ACK is a sealed `env_type=2` body

`RavenAckV1` is not a separate wire object with its own header — it is the
plaintext record that gets sealed (by the same ATSAM/Noise session sealer used
for message content) into `ratchet_header_ciphertext` +
`message_ciphertext` of an ordinary `RavenEnvelopeV1` with `env_type=2`
([`RAVEN_ENVELOPE_V1.md`](RAVEN_ENVELOPE_V1.md)).

Every rule in that document — the incoming-processing pipeline, the
mutable-field exclusion from the outer signature, dedup, replay, TTL — applies
identically to ACK envelopes. This document defines only what's specific to
the ACK payload itself.

The additive, production-disabled
[`ATSAM_INDEXED_SESSION_PROFILE_V1.md`](ATSAM_INDEXED_SESSION_PROFILE_V1.md)
freezes one exact construction: the 101-byte record below (including its
64-byte signature) becomes a 143-byte RVNA1 `0x03` ACK-lane ciphertext and a
293-byte signed outer envelope when `hdr_len=0`. It is not active until a
signed PairInit negotiates and transcript-binds that profile.

## 2. Record and signing bytes

| Field | Type | Meaning |
|---|---|---|
| `acked_message_id` | 16 bytes | the `message_id` of the envelope being acknowledged |
| `status` | 1 byte | `1` = delivered, `2` = read |
| `ack_nonce` | 12 bytes | per-ack randomness, distinct from the outer envelope's `anti_replay_nonce` |
| `created_at` | u64 (8-byte BE) | unix ms |

**Signing bytes:**

```
"rvn1/ack" || acked_message_id(16) || status(1) || ack_nonce(12) || u64(created_at_ms)
```

This signature is **separate from and in addition to** the outer envelope's
`sender_authentication`. It is signed with the acknowledging device's Ed25519
device-identity key ([`RAVEN_IDENTITY_V1.md`](RAVEN_IDENTITY_V1.md)) — the same
key type that authenticates envelopes. The ack record itself carries no
embedded public-key field; a verifier resolves which key to check against via
the established session or the counterpart's known `RavenDeviceCertificateV1`,
not from anything inside the ack payload.

**What the inner signature does *not* bind.** The signed bytes name only the
`acked_message_id`, which the *sender* chose and which is visible in the clear
outer envelope. They bind no conversation/session, no acknowledging-recipient
identity beyond the signing key, and no digest of the acknowledged object. A
V1 ack record is therefore **not** a transferable, context-free proof that
"message X was received/read": the same signed record is equally valid for
any object that carries (or is made to carry) that `message_id`. It is
meaningful only inside the checks of
[`SECURITY_ERRATA_RVN1_2026-08-13.md`](SECURITY_ERRATA_RVN1_2026-08-13.md)
rule 4: the ack must arrive sealed under the authenticated session AEAD
(whose AAD supplies the session/direction binding), from the expected
non-revoked device, and match an outstanding outbound row bound to that same
recipient device. Verifiers MUST NOT accept or relay a V1 ack record outside
that session context. `AckV2`
([`ATSAM_HYBRID_RATCHET_V2.md`](ATSAM_HYBRID_RATCHET_V2.md) §7.4) adds
`acked_object_digest`, a recipient-device binding and `session_id` to the
signed bytes and supersedes V1 for these bindings.

**Vector:** `shared-vectors/rvn1/ack/delivered_bob_to_alice.json` — bob
acknowledging alice's message (`status=1`, delivered).
**Wrong-signer vector:** `shared-vectors/rvn1/negative/ack_wrong_signer.json`
— the same signing bytes signed by alice's key but checked against bob's
public key; expected `verify_result: reject`.

`ack_nonce` is per-ack randomness for signature/domain separation — it exists
so two structurally identical acks don't produce identical signing bytes. It
is **not** a monotonic counter and MUST NOT be relied on as a replay-detection
mechanism on its own; see §4.

## 3. Delivery-state machine

```
CREATED → ENCRYPTED → QUEUED → ROUTE_DISCOVERING → FORWARDED → DELIVERED_TO_DEVICE → READ
                                                         ↓
                                                  EXPIRED / FAILED
```

| State | Meaning |
|---|---|
| `CREATED` | message object exists locally, not yet sealed |
| `ENCRYPTED` | sealed into `ratchet_header_ciphertext` + `message_ciphertext` |
| `QUEUED` | signed `RavenEnvelopeV1` built, handed to a transport-agnostic outbox |
| `ROUTE_DISCOVERING` | sender is resolving how to reach the recipient (DHT lookup, mesh peer discovery, relay selection) — the only state that is transport-specific |
| `FORWARDED` | the envelope has been handed to (or accepted by) at least one relay/transport — local transmission success, **not** recipient receipt |
| `DELIVERED_TO_DEVICE` | driven **only** by a verified `RavenAckV1` with `status=1` |
| `READ` | driven **only** by a verified `RavenAckV1` with `status=2` |
| `EXPIRED` | local `expires_at` reached (or a relay reported drop per the TTL stage, [`RAVEN_ENVELOPE_V1.md`](RAVEN_ENVELOPE_V1.md) §6) before `DELIVERED_TO_DEVICE` |
| `FAILED` | routes exhausted (`hop_limit`/`replication_budget` reached zero without reaching a relay) or an unrecoverable local error |

### The rule that matters most

**`FORWARDED → DELIVERED_TO_DEVICE` MUST be triggered only by successfully
authenticating and decrypting an inbound `env_type=2` envelope whose
`acked_message_id` matches and whose ack signature verifies against the
counterpart's known device key** (§2). Transport-level signals — "the stream
write succeeded," "a relay accepted the frame," "the bridge uplinked it" — MUST
NOT trigger this transition. They may only establish or hold `FORWARDED`.

> **Known issue — write-means-delivered, Phase B fix.**
> `ios-native/RAVEN/RAVEN/Core/Mesh/DeliveryJobRunner.swift:278-280` currently
> calls `DeliveryJobRepository.shared.markDelivered(messageId:channel:.bridge)`
> as soon as the libp2p stream write to the peer succeeds — i.e. on transport
> send success, not a verified ACK. The surrounding comment ("overall delivery
> state still tracked via ACK") shows this is intended as internal per-channel
> bookkeeping, not the protocol-level `DELIVERED_TO_DEVICE` transition — but
> the shared name `markDelivered` is a foot-gun: any future caller or UI
> surface that reads this per-channel flag as "message delivered" would
> violate the rule above. Phase B should rename this per-channel bookkeeping
> (e.g. `markTransmitted`) so `markDelivered`/`DELIVERED_TO_DEVICE` is reserved
> exclusively for a verified-ACK transition, and audit the same pattern on the
> `.mesh` and `.server` channels in the same file (around lines 363 and 556).

## 4. ACK replay and dedup

An ACK travels as an ordinary `env_type=2` envelope, so it gets the same
envelope-level replay handling as any message — which, per errata rule 6, is
**not** keyed on the unverified outer `message_id`. An endpoint records its
authenticated dedup receipt only in the successful commit after outer
authentication, AEAD open and inner-signature verification; an opaque relay
keys its bounded replay cache on
`SHA-256(domain || envelope_signing_bytes || outer_signature)`. Nothing may
durably suppress an ack solely because an unverified outer `message_id` was
seen before (an attacker could pre-burn a legitimate ack's ID).

Envelope-level dedup is also not sufficient on its own: a recipient may
legitimately resend a semantically-identical ack (same `acked_message_id` +
`status`) inside a *fresh* envelope — with a new `message_id`, a new
`ack_nonce`, and a slightly different `created_at` — after, say, a
route-failure retry. Envelope dedup will not catch this, because it's a
different envelope.

Implementations MUST therefore also dedup at the application layer on
`(acked_message_id, status)` — applied only to acks that already passed the
errata rule 4 checks for the outstanding row they match: a repeat `status=1`
ack for a message already at `DELIVERED_TO_DEVICE` is a no-op (idempotent),
and a repeat `status=2` for a message already at `READ` must not re-fire a
"message read" notification.
`ack_nonce` uniqueness is not a substitute for this check — it exists for
signature domain separation (§2), not for idempotency tracking.

## Reference implementation

`protocol/reference/raven_protocol/ack.py`. Vectors:
`shared-vectors/rvn1/ack/delivered_bob_to_alice.json`,
`shared-vectors/rvn1/negative/ack_wrong_signer.json`.

Indexed sealed-ACK fixture:
`shared-vectors/rvn1/atsam/indexed_session_v1_sealed_ack_001.json`.
