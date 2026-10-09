# ATSAM Endpoint Transaction V1

**Profile:** `ATSAM/indexed-session/v1`

**Status:** additive state-machine contract; **production disabled**

**Companions:** [`RAVEN_PAIR_INIT_V1.md`](RAVEN_PAIR_INIT_V1.md),
[`ATSAM_INDEXED_SESSION_PROFILE_V1.md`](ATSAM_INDEXED_SESSION_PROFILE_V1.md),
[`SECURITY_ERRATA_RVN1_2026-08-13.md`](SECURITY_ERRATA_RVN1_2026-08-13.md)

This contract defines the endpoint boundary that turns an opaque RVN1 object
into one durable inbox row and one ACK intent, and the inverse outbound
transaction that turns bounded text or a committed ACK intent into one exact
immutable queued RVN1 object. It does not change envelope or RVNA1 bytes. A
transport, relay, store, or UI must never implement a shorter "looks valid"
path around this actor.

## 1. Required input and ordering

The actor receives exact packed `RavenEnvelopeV1` bytes, a locally resolved
PairInit-bound session record, the verifier's current local device-revocation
decision, and `now_ms`. Processing order is mandatory:

1. Enforce the 1 MiB transport bound and strict RVN1 decode.
2. Require `env_type=message`, `created_at < expires_at`, and a locally
   acceptable time window.
3. Parse only the fixed, bounded RVNA1 `0x03` header to obtain its message-lane
   index. Reject every other protocol/suite for this profile.
4. Resolve exactly one session whose expected inbound direction, device hint,
   and derived route tag match. A `dest_device_hint` of `0` matches any
   session; a non-zero hint must equal the legacy hint of the local device
   (§4.1 step 2). Tag matching is only candidate selection.
   Session-specific lifetime checks run only after this selection, against the
   selected session, with the start-bound skew tolerance of
   [`RAVEN_PAIR_INIT_V1.md`](RAVEN_PAIR_INIT_V1.md) §1: neither `now_ms` nor
   the envelope `created_at` may precede the session start (its signed PairInit
   `created_at_ms`) by more than `MAX_PEER_CLOCK_SKEW_MS` (300000 ms), while
   `now_ms < session expires_at_ms` and envelope
   `expires_at <= session expires_at_ms` stay exact. A lifetime check placed
   before selection would refuse a valid envelope sealed under another live
   session with the same peer (for example the older of two crossed sessions).
   Outbound sealing applies the same session-window rule.
5. Require a currently accepted, non-revoked sender device certificate and
   verify the outer Ed25519 signature with that exact device key.
6. Compute the immutable object digest over the canonical signing bytes and
   outer signature. A read-only duplicate check may happen here; no attacker-
   chosen durable ID is inserted yet.
7. Derive the bounded receive key, open ChaCha20-Poly1305 with the profile AAD,
   and validate the text payload/application policy.
8. Execute the recoverable commit in §2.
9. Publish UI/notification state only from the committed inbox row. Schedule
   ACK transmission only from the committed ACK-intent row.

Any failure before step 8 produces no inbox row, no endpoint dedup row, no
delivery transition, and no ACK.

## 2. Recoverable commit boundary

The platform-protected session head and the local database cannot rely on an
impossible cross-system atomic rename. The implementation therefore uses a
small write-ahead acceptance journal inside the protected session state.

```
A. begin one immediate local-database transaction
B. authenticate/open using a candidate receive state
C. encrypt local plaintext for at-rest inbox storage
D. protected-write {
     advanced receive chain + skipped-key state,
     pending acceptance {
       session_id, object_digest, message_id, sender_device,
       sealed_local_inbox_row, ACK intent fields
     }
   }
E. in the still-open database transaction, idempotently insert:
     endpoint object receipt,
     encrypted inbox row,
     pending ACK intent,
     matching public session generation
F. commit and fsync the database transaction
G. clear the protected pending acceptance idempotently
H. only now return committed plaintext to the UI actor
```

The pending record contains no plaintext: the inbox payload is encrypted under
a session-derived, domain-separated local-storage key with a fresh nonce and
AAD binding `session_id || object_digest || message_id || sender_device`.
Database rows never contain root, chain, message, ACK, or route keys.

On open and before any new mutation, recovery examines every protected pending
acceptance represented by public session metadata. It repeats step E with
unique constraints, commits, then clears the journal. Thus a crash after D may
delay delivery but cannot roll the ratchet back, lose an authenticated message,
or emit an ACK without an inbox row. A crash after F merely repeats an
idempotent insert.

## 3. Identity and dedup keys

- Relay cache key: bounded/expiring `object_digest`; relay state is never
  endpoint delivery evidence.
- Endpoint receipt primary key: `(session_id, object_digest)`.
- Logical message uniqueness: `(session_id, sender_device, message_id)` maps to
  exactly one `object_digest`. A different authenticated object reusing that
  tuple is a sender/session integrity conflict, not a duplicate overwrite.
- ACK intent primary key: the committed endpoint receipt. It contains the
  exact acknowledged message ID, expected remote device, status, and session
  binding locally; none of those fields is exposed in the routed ACK body.

An exact committed duplicate is a no-op for the inbox and may re-schedule the
same still-pending ACK intent. It never advances a receive chain twice.

## 4. Outbound materialization and ACK worker

The ACK worker reads only committed intents. It reserves the next independent
ACK-lane key durably, creates the 101-byte device-signed record, seals it under
RVNA1 `0x03`, signs the outer envelope with the same authorized local device,
and atomically enqueues the immutable bytes before marking the intent queued.
Retries reuse those exact bytes. Relays route the ACK opaquely.

At the origin, ACK acceptance uses the same ordered outer-auth/route/AEAD/
inner-signature transaction and conditionally advances only the exact
outstanding `(message_id, recipient_device)` row. `read(2)` may advance
`delivered(1)` but no state may regress.

### 4.1 Outbound message transaction

The production-disabled Rust reference applies the same protected/database
ordering to ordinary outbound text:

1. Require a currently valid PairInit-bound session and bounded UTF-8 text.
   Confirmed sessions may send normally. To preserve the offline-first PairInit
   bootstrap in `RAVEN_PAIR_INIT_V1.md`, a provisional session has exactly one
   exception: only the local initiator may materialize/retry message-lane index
   zero. A provisional responder, every ACK, and message index one or later
   require a verified PairResponse confirmation. The local signer is represented
   by a field-private, checked borrowed capability over the exact current
   device-registry certificate and private signer; its public key, certificate
   hash, identity address, validity window, and PairInit role are rechecked
   before mutation and again before every queue handoff.
2. Generate non-zero `message_id`, sealing nonce, and anti-replay nonce from a
   caller-supplied cryptographic RNG. Require fixed `flags=0`,
   `hop_limit=8`, `replication_budget=2`, an empty ratchet-header field,
   `dest_device_hint=0`, and the derived message-lane route.

   *Erratum 2026-10-08.* Earlier revisions required the exact remote device
   hint `SHA-256("rvn1/device-hint/v1" || remote_device_pub)[:8]`. Anyone who
   holds the recipient's public key (its address) can compute that value, so a
   relay, store or bridge holding the object would recognise the recipient.
   New messages and ACKs (§4.2) therefore carry `0`. The field is outside the
   signing bytes and the object digest (`RAVEN_ENVELOPE_V1.md` §2), and `0` was
   always a valid value, so no wire format, signature input or vector changes.
   Revalidation of a stored object (retry below) accepts `0` or that legacy
   value, so objects queued before the change are retried with their exact
   bytes; receivers accept both (§1 step 4).
3. Reserve and advance the protected message-send ratchet, seal proto `0x03`,
   sign the outer envelope, and immediately verify that signature.
4. Protected-write the advanced ratchet plus one pending outbound journal
   containing only the exact packed signed ciphertext object and public binding
   coordinates. It contains neither plaintext nor the reserved message key.
5. In the still-open immediate database transaction, idempotently insert the
   exact outbox object and the outstanding
   `(session_id, message_id, recipient_device)` row, then commit.
6. Clear the protected pending journal and only then call the durable queue.
   The callback receives `(object_digest, exact_bytes)` and must return that
   same digest after persistence. Queue errors leave the outbox prepared.
   Concurrent retries may invoke the callback more than once, so its durable
   operation must be idempotent by digest and reject different bytes for an
   existing digest; all successful callers converge on the same queued row.

Only the explicit retry API may process a prepared outbox row. It reloads and
revalidates current local-device authorization, object/session/certificate time
windows, immutable signature, route, device, ratchet index, object digest, and
outstanding/intent binding, then retries identical bytes without invoking a
signing operation, RNG, nonce, or key reservation. Expired and over-skew
future objects never reach the queue callback. Message IDs, seal nonces,
anti-replay nonces, ACK nonces, object digests, and intent bindings have durable
collision gates. A crash after protected advancement may burn an index, but no
recovery path rolls the ratchet back or reseals with a new nonce/key.

### 4.2 ACK materialization binding

The public ACK worker selects only a committed ACK-intent digest. The
acknowledged message ID, remote device, and status come from that row and its
referenced committed receipt; none is supplied independently by a caller. It
uses the independent ACK-send ratchet, constructs and device-signs the exact
101-byte `AckV1`, seals proto `0x03`, derives the ACK route, signs the outer
envelope, and journals/commits it through the same outbox transaction. A unique
`source_ack_intent` binding permits at most one materialized object for an
intent. The intent becomes queued only in the same local transaction that marks
the exact outbox object queued after successful durable handoff.

## 5. Crash and negative gates

Tests must inject failure or termination:

- before and after protected-state replacement;
- before and after inbox transaction commit;
- before and after journal clear;
- before and after immutable ACK enqueue;
- before and after ordinary outbound queue handoff;
- on protected-store, database, fsync, and queue failures.

They must also cover wrong route/session/device, revoked device, bad outer
signature, wrong AAD/message ID, tampered AEAD, replay, public-ID collision,
index jump greater than 256, duplicate paths, out-of-order indexes, and restart.
Every pre-commit negative produces zero visible delivery and zero ACK.

## 6. Activation gate

This actor remains production-disabled until Rust and Swift implement the same
state transitions and failure matrix, exchange the same first-message/reply/
ACK vectors, and an external review approves the transcript and persistence
boundary. Merely having PairInit, a ratchet, or an encrypted SQLite column is
not sufficient activation evidence.

## 7. Reference implementation status

Production-disabled Rust and Swift actors implement message acceptance and
origin-side sealed-ACK acceptance with independent bounded lanes, protected
pending journals, exact object/logical/outstanding bindings, and monotonic
delivery state. Rust additionally implements the complete production-disabled
outbound text transaction and committed-intent ACK materializer described in
§4, including protected outbound recovery, exact-byte queue retries, and
collision gates. Their negative and injected-crash suites are executable
evidence for these state machines.

This does not close §6. Rust's outbound APIs are public reference surfaces, but
the crate-wide production flag remains false and there are no live callsites;
it still exposes no arbitrary raw materializer or production raw-session
constructor. The Rust durable handoff remains an injected callback awaiting an
approved concrete queue adapter. Swift currently defines storage/database/
queue protocols rather than the approved concrete Keychain/SQLCipher/outbox
adapters and does not yet implement the matching outbound transaction. Neither
actor has a live transport, UI, or notification callsite. A shared full
message/reply/ACK transaction vector, concrete adapters, real-device recovery
tests, and external review are still required.
