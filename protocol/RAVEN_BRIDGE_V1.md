# RAVEN Bridge V1 (protocol)

**Version:** 1  
**Status:** Binding for opaque cross-transport forward  
**Companion:** `node/BRIDGE_V1.md` (operator/demo), `docs/SERVERLESS_MODEL.md`

## Definition

A Raven Bridge is an **untrusted** cross-transport forwarding function inside Raven Node that receives the same opaque end-to-end encrypted `RavenEnvelopeV1` on one transport and forwards or stores it for another transport **without** decrypting, re-originating, or changing the logical `message_id`.

## Invariants

1. Same `message_id` across transports.
2. Same `message_ciphertext` + `sender_authentication` bytes (immutable).
3. Only mutable hop fields may change: `hop_limit`, `replication_budget`, `dest_device_hint`.
4. Bridge MUST NOT access conversation keys / ATSAM roots / Noise sessions.
5. Recipient ACK (`env_type=ack`) is emitted only by the true endpoint; Bridge may **relay** ACK bytes opaquely.
6. Dedup, TTL (`expires_at`), hop, replication, and per-peer rate limits apply.
7. Capability advertisement is generic (`bridge`/`ble`/`internet`/`store`/`relay`) — never contact graphs.

## Roles

| Role | Decrypt? | Emit Delivered ACK? |
|------|----------|---------------------|
| Endpoint | Yes (if capable) | Yes (recipient only) |
| Bridge / Relay / Store | No | No (may forward opaque ACK) |

Multi-role devices: BridgeSubsystem and endpoint ingest MUST be separated (iOS: `RavenEnvelopeBridgeService` vs `RavenEnvelopeChatWire`).

## Transports

- LAN / Internet: `u32 BE || RavenEnvelopeV1` — see [`RAVEN_TRANSPORT_INTERFACE_V1.md`](RAVEN_TRANSPORT_INTERFACE_V1.md)
- mock_ble (CI): same framing over TCP
- BLE GATT (iOS): `RavenBleRvn1Carrier` behind `FeatureFlag.ravenEnvelopeV1` — see [`RAVEN_BLE_FRAMING_V1.md`](RAVEN_BLE_FRAMING_V1.md)

## Store-Carry-Bridge

When egress radio is down, persist packed envelope to forward queue; flush when path returns. SQLite expires timestamps MUST clamp to `i64::MAX` (signed INTEGER). Opaque mailbox / store objects: [`RAVEN_STORE_OBJECT_V1.md`](RAVEN_STORE_OBJECT_V1.md). Delivery vs custody: [`RAVEN_DELIVERY_STATE_V1.md`](RAVEN_DELIVERY_STATE_V1.md).

## Relay runtime limits (raven-node)

Bridge listeners are unauthenticated, so the reference runtime bounds every
resource a peer can consume. These are local policy; frames and envelopes on
the wire are unchanged.

- **Frames:** the `u32 BE` length must lie in `[150, 1 MiB]` (smallest valid
  envelope .. `MAX_WIRE_ENVELOPE_BYTES`); other lengths close the connection.
  A started length prefix or body must complete within 30 s, and body buffers
  grow only as bytes arrive.
- **Connections:** at most 64 at once across both listeners, 32 per source
  (the IP; a native IPv6 source is its /64; every loopback address, 127/8 and
  `::1`, counts as one source). A connection is closed 600 s after its last
  progress: a newly admitted envelope or a completed outbound write. Junk,
  duplicate, rate-limited or refused frames are not progress and do not keep
  a connection open. Transient accept errors are logged and retried with
  back-off.
- **Subscription:** a connection receives queued envelopes only after it sends
  the pull hello `RVNP`, sends a framed envelope, or stays connected silently
  for 400 ms, on every transport. A connection that closes sooner (a port
  probe) never triggers a flush.
- **Fanout never blocks:** each subscriber has a 64-frame queue. A full queue
  is skipped and the object stays queued. A write that does not complete
  within 10 s closes that subscriber.
- **Custody states:** `Queued → InFlight` when handed to a socket writer;
  `Forwarded` only after a complete socket write; back to `Queued` when every
  hand-off failed. `InFlight` rows return to `Queued` on restart
  (at-least-once; endpoints deduplicate). V1 has no hop-level ACK, so a
  complete TCP write is the strongest delivery signal a relay has.
- **Admission quotas:** 64 pending objects, 30 enqueues and 256,000 bytes per
  60 s per source. For remote sources the key is the IP address (IPv6: the
  /64), never the source port, so reconnecting does not reset a quota.
  Loopback sources are keyed per connection: the carriers, `ash` and every
  other local process share the loopback address, so one shared bucket would
  let any local process starve the others. The node-wide caps bound them all:
  512 pending objects and 64 MiB; a full queue is `STORE_FULL`, not a
  malformed-envelope drop.
- **Lifetime:** custody lasts at most 7 days after admission
  (`min(expires_at, admitted_at + 7 d)`), matching the offline-mailbox cap.
- **Dedup:** an object whose digest is in the bounded seen cache, or that has a
  forward-queue row in any state, is a duplicate. An existing row is never
  overwritten or re-queued by a replay. A `Forwarded` tombstone lasts until
  the envelope's own `expires_at`, not just the 7-day custody, so an envelope
  claiming a longer life cannot be re-forwarded once per custody period.
- **Retention:** leaving custody (`Forwarded`, `Expired`, `Failed`) deletes the
  ciphertext at once. The payload-free tombstone is deleted when it expires,
  and at most 16,384 tombstones are kept (oldest evicted first), so a flood of
  new objects can still age out old dedup records.
- **Upgrade:** pending rows written by earlier builds are clamped to
  admission + 7 d and the pre-V2 table is emptied once migrated. The daemon
  (never `status` or IPC) rewrites a file created before incremental
  auto-vacuum once at startup.
- **Policy:** `node_policy.json` is replaced atomically (temp file + rename). A
  missing file means the defaults; a file that cannot be read or parsed
  disables the bridge (fail closed).
- **Opacity:** relays never inspect ciphertext. The lab Test A PairResponse
  sniff runs only in debug builds with `RAVEN_LAB_TEST_A=1`.
- **Known limit:** pulls are unauthenticated in V1. A local process that
  keeps its connections making progress can still hold connection slots, and
  a silent subscriber receives relayed ciphertext. Closing both needs an
  authenticated pull or a hop-level custody ACK (a wire change).

## Errors

Mapped codes: [`RAVEN_ERROR_CODES_V1.md`](RAVEN_ERROR_CODES_V1.md) (`ENVELOPE_*`, `STORE_*`, `RATE_LIMITED`, …).

## Tests

- `raven-core` `bridge_v1` cases 1–15 (replay after seen-cache eviction, `STORE_FULL`, custody TTL clamp, tombstone GC, far-future replay after custody)
- `raven-node` `bridge_run` unit tests (non-blocking fanout, probe does not drain, requeue on failed write, IP-keyed remote quotas and per-connection loopback quotas, folded admission keys, progress-only keepalive, connection cap, stalled frames, fail-closed policy, lab-gated sniff)
- `scripts/bridge_abc_demo.sh` A–B–C + store-carry
- iOS `RavenEnvelopeBridgeServiceTests` (simulator; no physical radios required for decision tests)
- Interop: [`RAVEN_INTEROPERABILITY_MATRIX.md`](RAVEN_INTEROPERABILITY_MATRIX.md)
