# Raven PairInit V1

**Version:** 1

**Suite:** 1 = X25519 + ML-KEM-768 + HKDF-SHA256 + Ed25519

**Negotiated profile:** `ATSAM/indexed-session/v1`

**Status:** additive byte contract; **production disabled** (one recorded
owner exception: the LAN-direct slice, §7)

This document freezes an offline-capable, signed session-establishment
transcript for
[`ATSAM_INDEXED_SESSION_PROFILE_V1.md`](ATSAM_INDEXED_SESSION_PROFILE_V1.md).
It deliberately does not activate RVNA1 `0x03`, assign a live network carrier,
or replace the durable session-state requirements in
[`SECURITY_ERRATA_RVN1_2026-08-13.md`](SECURITY_ERRATA_RVN1_2026-08-13.md).

PairInit is designed for the required asynchronous case: Alice can use Bob's
already identity-signed prekey bundle to create one signed PairInit, derive a
**provisional** hybrid root, seal indexed-session message 0, and queue both
while Bob is offline. Bob later validates the exact trust records and PairInit,
derives the same root, and returns a signed `PairResponse`. The response
confirms Bob's possession of that exact root; Alice does not wait for it before
encrypting message 0.

## 1. Security state and prerequisites

PairInit has immutable transcript roles:

| Role byte | Endpoint | Indexed-session direction |
|---:|---|---:|
| `0` | initiator (Alice) | Alice to Bob = `0` |
| `1` | responder (Bob) | Bob to Alice = `1` |

Before accepting a PairInit, an implementation MUST possess and validate:

1. Alice's and Bob's exact `RavenDeviceCertificateV1` records, including each
   identity signature, certificate validity, and the verifier's current local
   revocation decision.
2. Bob's exact `RavenPrekeyBundleV1`, including its identity signature,
   validity, nonzero ML-KEM-768 encapsulation key, and consistent one-time
   prekey fields.
3. Exact lowercase canonical `RavenAddressV1` values derived from the identity
   Ed25519 public keys that signed those records.
4. Equality between the prekey bundle's identity and Bob's certificate owner,
   and between its opaque `device_id` and Bob's certificate `device_id`.

The PairInit validity interval MUST be contained in the intersection of both
certificate validity intervals and Bob's prekey-bundle validity interval, with
one bounded clock-skew allowance. `created_at_ms` is stamped by the
initiator's clock, while the certificate `not_before_ms`, the prekey
`created_at_ms`, and the verifier's `now_ms` come from other clocks. START
bounds therefore tolerate exactly `MAX_PEER_CLOCK_SKEW_MS = 300000` (5 minutes;
Rust `prekey_lifecycle::MAX_PREKEY_FUTURE_SKEW_MS`), and every expiry bound is
exact:

```
trust_not_before = max(initiator cert not_before_ms,
                       responder cert not_before_ms, prekey created_at_ms)
trust_not_after  = min(initiator cert not_after_ms,
                       responder cert not_after_ms, prekey expires_at_ms)

accept only if   created_at_ms + MAX_PEER_CLOCK_SKEW_MS >= trust_not_before
            and  expires_at_ms <= trust_not_after
            and  created_at_ms <= now_ms + MAX_PEER_CLOCK_SKEW_MS
            and  now_ms < expires_at_ms
```

The certificates and the prekey bundle are additionally valid at `now_ms`
under their own rules (certificate `not_before_ms <= now_ms <= not_after_ms`;
prekey per [`RAVEN_PREKEY_BUNDLE_V1.md`](RAVEN_PREKEY_BUNDLE_V1.md) §4). The
session windows of the negotiated profile use the same start-bound tolerance
against the session's signed PairInit `created_at_ms` and keep their expiry
bounds exact ([`ATSAM_ENDPOINT_TRANSACTION_V1.md`](ATSAM_ENDPOINT_TRANSACTION_V1.md)
§1). Boundary vectors: `shared-vectors/rvn1/atsam/pair_init_v1_clock_skew_001.json`.
The initiator device signature is verified only after structural, trust-record,
identity, role, profile, suite, time, and resource checks.

Signed device revocation is defined separately by `RavenDeviceRevocationV1`
(RVDR1, [`RAVEN_DEVICE_REVOCATION_V1.md`](RAVEN_DEVICE_REVOCATION_V1.md)): an
identity-signed record that verifiers apply as a sticky local deny decision;
PairInit preflight consults only the local deny set, before any OTP claim
(that document's §7.2 and §9). RVDR1 propagates eventually: there is no instant
global revoke (its §7.3), and PairInit carries no revocation-freshness field.
Consequently, PairInit can bind the exact certificates and can require the
verifier's local revocation decision (local denylist plus every RVDR1 claim it
has applied), but it cannot prove that a partitioned verifier has the latest
revocation state. This is a protocol limitation, not a field that
implementations may replace with an unsigned "revocation hash."

## 2. Exact trust-record digests

The transcript binds the complete signed records, not only their key fields.
All hashes are SHA-256:

```
device_cert_hash = SHA-256(
    "rvn1/pair-devcert"
    || identity_ed25519_pub(32)
    || RavenDeviceCertificateV1.signing_bytes
    || certificate_signature(64)
)

prekey_bundle_hash = SHA-256(
    "rvn1/pair-prekey"
    || RavenPrekeyBundleV1.signing_bytes
    || prekey_signature(64)
)
```

Including the certificate signer makes a byte-identical certificate body
certified by a different identity produce a different digest. The prekey
signing bytes already include its identity Ed25519 public key.

## 3. PairInit wire (exactly 2788 bytes)

All integers are unsigned big-endian. Addresses are exact 44-byte ASCII
canonical `RavenAddressV1` strings. There are no optional or trailing bytes.
The one-time X25519 slot is fixed width so there is only one parse.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 8 | magic `RVPI1\0\0\0` |
| 8 | 1 | version = `0x01` |
| 9 | 1 | suite = `0x01` |
| 10 | 1 | role = initiator = `0x00` |
| 11 | 1 | profile length = `24` |
| 12 | 24 | ASCII `ATSAM/indexed-session/v1` |
| 36 | 44 | initiator address |
| 80 | 44 | responder address |
| 124 | 16 | fresh, nonzero `init_id` |
| 140 | 32 | fresh, nonzero `pairing_nonce` |
| 172 | 32 | initiator device Ed25519 public key |
| 204 | 32 | responder device Ed25519 public key |
| 236 | 32 | initiator fresh ephemeral X25519 public key |
| 268 | 32 | responder signed X25519 public key from prekey bundle |
| 300 | 32 | responder one-time X25519 public key, or all zero |
| 332 | 32 | initiator device-certificate hash |
| 364 | 32 | responder device-certificate hash |
| 396 | 32 | responder prekey-bundle hash |
| 428 | 4 | nonzero `signed_prekey_id` |
| 432 | 4 | `one_time_prekey_id`; zero means absent |
| 436 | 1184 | responder ML-KEM-768 encapsulation key |
| 1620 | 1088 | initiator's ML-KEM-768 ciphertext |
| 2708 | 8 | `created_at_ms` |
| 2716 | 8 | `expires_at_ms`, strictly greater than creation |
| 2724 | 64 | initiator-device Ed25519 signature |

If `one_time_prekey_id == 0`, the 32-byte one-time-key slot MUST be all zero.
If the id is nonzero, the slot MUST be nonzero and match the signed bundle.
The selected responder X25519 key is the one-time key when present and the
signed X25519 key otherwise. The initiator ephemeral key, selected responder
key, ML-KEM key, ciphertext, three record digests, nonce, and `init_id` MUST
not be all zero. X25519 agreement MUST additionally reject a non-contributory
(all-zero) shared result.

Decoders and verifiers MUST also reject, before any signature check, state
mutation, journal, or claim, an initiator ephemeral X25519 key in the
small-order torsion (for example `u = 1`, the two order-8 points, `p - 1`,
`p`, `p + 1`, and their encodings with bit 255 set). For every clamped
responder scalar the agreement with such a key is all-zero, so the check is
exactly "X25519(any fixed scalar, key) is all-zero". A signed PairInit carrying
one is a hard reject, not a deferred DH failure.

The signature input is exactly:

```
"rvn1/pair-init" || PairInit[0 .. 2724]
```

It is signed by the initiator device Ed25519 key at offset 172. That key is
authorized only by the exact initiator certificate whose digest is at offset
332; a self-asserted device key is insufficient.

Unknown version, suite, role, profile, noncanonical address, inconsistent
one-time fields, wrong fixed length, trailing bytes, invalid trust binding,
invalid time, or bad signature is a hard reject. There is no negotiation by
"pick the closest supported value."

## 4. Offline provisional hybrid root

Alice performs:

```
selected_pk_B = otp_x25519_pub if one_time_prekey_id != 0
                else signed_x25519_pub
Z_X = X25519(alice_fresh_ephemeral_secret, selected_pk_B)
(ct_PQ, Z_PQ) = ML-KEM-768.Encaps(responder_mlkem768_ek)
```

Alice places `ct_PQ` in PairInit, signs the complete prefix, and only then
derives the root. Bob first accepts the signed PairInit and then computes:

```
Z_X  = X25519(selected_responder_secret, initiator_ephemeral_x25519_pub)
Z_PQ = ML-KEM-768.Decaps(responder_mlkem768_secret, ct_PQ)
```

Both compute:

```
init_hash = SHA-256("rvn1/pair-init" || complete_PairInit_wire)

transcript_material = "rvn1/pair-init" || complete_PairInit_wire
transcript_hash = SHA-256("ATSAM/v1/transcript" || transcript_material)

K_root = HKDF-SHA256(
    IKM  = Z_X || Z_PQ,
    salt = transcript_hash,
    info = "ATSAM/v1/pair-init" || transcript_hash,
    L    = 32
)

session_id = SHA-256("rvn1/pair-session" || init_hash)
```

`complete_PairInit_wire` includes the initiator signature. Thus the root binds
the exact profile, suite, roles, identities, device keys, signed trust records,
prekey ids and material, both hybrid contributions, freshness, and the
initiator's authorization of all those bytes.

Because the ML-KEM ciphertext is part of the transcript, an initiator MUST NOT
use an API that derives the root before encapsulation and later substitutes a
different transcript. Rust exposes a zeroizing `PendingHybridInitiation` for
the required order: encapsulate, build/sign PairInit, hash, then consume and
finalize. A port without an equivalent split operation MUST remain disabled.

After deriving `K_root`, Alice may use indexed-session direction `0`, message
index `0`, and the profile's route derivation to seal and durably queue message
0 without a response. "Provisional" is a trust/UI state: the ciphertext is
hybrid encrypted to Bob's identity-signed prekey, but Bob has not yet confirmed
receipt and possession of the corresponding private material.

**Session lifetime (informative).** The PairInit validity interval is also the
session's lifetime, and the negotiated profile has no forward secrecy or
post-compromise security inside a session
([`ATSAM_INDEXED_SESSION_PROFILE_V1.md`](ATSAM_INDEXED_SESSION_PROFILE_V1.md)
§2.4). Initiators SHOULD therefore keep `expires_at_ms - created_at_ms` short.
This implementation initiates 24-hour sessions
(`lan_dispatch::LAN_SESSION_LIFETIME_MS`) and, as responder, still accepts the
7-day maximum of [`RAVEN_PREKEY_LIFECYCLE_V1.md`](RAVEN_PREKEY_LIFECYCLE_V1.md) §4.

## 5. PairResponse wire (exactly 228 bytes)

Bob returns this only after the accepted PairInit and provisional session have
been durably committed. It is key confirmation, not a message-delivery ACK.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 8 | magic `RVPR1\0\0\0` |
| 8 | 1 | version = `0x01` |
| 9 | 1 | suite = `0x01` |
| 10 | 1 | role = responder = `0x01` |
| 11 | 1 | profile length = `24` |
| 12 | 24 | ASCII `ATSAM/indexed-session/v1` |
| 36 | 16 | exact accepted `init_id` |
| 52 | 32 | exact accepted `init_hash` |
| 84 | 32 | responder device Ed25519 public key |
| 116 | 8 | response `created_at_ms` |
| 124 | 8 | response `expires_at_ms` |
| 132 | 32 | root-confirmation tag |
| 164 | 64 | responder-device Ed25519 signature |

The tag is:

```
confirmation_tag = HMAC-SHA256(
    K_root,
    "ATSAM/pair-init/v1/confirm" || 0x00 || init_hash
)
```

The signature input is:

```
"rvn1/pair-response" || PairResponse[0 .. 164]
```

The response signer MUST equal the responder device key bound in PairInit and
its certificate. Response creation must fall inside the PairInit interval
(`init.created_at_ms <= created_at_ms < init.expires_at_ms`, exact) and its
expiry must not exceed PairInit expiry (exact). Against the verifier's clock the
§1 rule applies: the start bound tolerates `MAX_PEER_CLOCK_SKEW_MS` and expiry
is exact, i.e. `created_at_ms <= now_ms + MAX_PEER_CLOCK_SKEW_MS` and
`now_ms < expires_at_ms`. Because the containment is exact, a responder whose
clock is behind the initiator's MUST NOT stamp `created_at_ms` earlier than the
PairInit's (Rust stamps `max(now_ms, init.created_at_ms)`). Verification
requires the exact accepted PairInit, exact root tag (constant-time
comparison), and signature. Only then may Alice change session state from
`provisional` to `confirmed`.

## 6. Replay, idempotency, and one-time prekeys

PairInit ingestion requires a durable atomic claim before any plaintext or
session-dependent ACK is accepted:

```
collision key = (responder_address, responder_device_ed_pub, init_id)
stored value  = (init_hash, session_id, transcript_hash, prekey ids, state)
```

- An exact `(init_id, init_hash)` duplicate is idempotent. It reuses the
  existing provisional session and MUST NOT decapsulate again, reset ratchets,
  duplicate message 0, or emit another state transition.
- The same collision key with a different `init_hash` is a conflict and MUST
  be rejected.
- A retry transmits the exact same PairInit bytes. Rebuilding with a new nonce,
  signature, or ciphertext creates a different session.
- PairResponse duplicates with the same signed bytes are idempotent. A
  different response for the same accepted init that fails any exact binding
  is rejected and does not mutate state.

`RAVEN_PREKEY_BUNDLE_V1.md` requires distinct valid sessions to survive a
distributed race where more than one sender obtained the same one-time prekey.
Therefore a receiver MUST NOT use `(one_time_prekey_id)` alone as a uniqueness
constraint. Each distinct, valid signed PairInit gets its own `init_hash`,
hybrid ciphertext, root, and session record; reuse is recorded as a bounded
local anomaly without logging identity/key bytes. Exact duplicates remain one
session.

The protected Rust lifecycle policy for this tradeoff is now frozen in
[`RAVEN_PREKEY_LIFECYCLE_V1.md`](RAVEN_PREKEY_LIFECYCLE_V1.md): retained
private material has a bundle-expiry-plus-7-day bound, distinct signed races
remain distinct, and exact claims/root handoffs are crash recoverable. That
actor remains production-disabled, has no Swift parity or live integration,
and does not solve the confidential carrier. No codec helper alone may pretend
to solve that storage or transport problem.

## 7. Privacy/carrier and activation gaps

The canonical PairInit bytes are signed but not encrypted and contain both
addresses and public trust material. They MUST NOT be placed directly in an
observable relay body when Raven claims relationship privacy. A confidential
bootstrap carrier and its opaque offline rendezvous derivation are not frozen
by this document. PairInit may currently be exercised only in vectors, local
tests, or an already confidential/OOB channel. The future carrier must deliver
PairInit plus indexed-session message 0 without changing any bytes defined
here and must tolerate reordering and exact retries.

Production remains disabled until, at minimum:

- the confidential asynchronous bootstrap carrier is specified and tested;
- the protected Rust prekey lifecycle actor is atomically integrated with the
  durable session actor and has equivalent Swift behavior;
- protected address-keyed storage, ratchet crash consistency, and zeroization
  pass the errata release gates;
- Swift and Rust verify these exact PairInit/response vectors and message-0
  state transitions; and
- external protocol/security review approves the transcript and state machine.

**Recorded owner exception.** The LAN-direct slice runs PairInit V1 /
PairResponse live in default and release builds under the owner waiver
[`WAIVER-LAN-DIRECT-2026-10-07`](../docs/WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md):
LAN direct TCP between two `raven-node` services inside a Noise XX channel bound
to the Raven identity, PairInits accepted only from local contacts. The waiver
does not satisfy the gates above; it accepts that scope's listed residual risks
until its review-by date. Every other carrier and every other use of PairInit
(including PairInit V2) remains disabled.

## 8. Reference and vectors

- Python: `protocol/reference/raven_protocol/pair_init.py`
- Rust: `node/crates/raven-core/src/pair_init.rs`
- Rust split hybrid primitive: `node/crates/raven-core/src/atsam_mlkem.rs`
- Swift: `ios-native/RAVEN/RAVEN/Core/Security/ATSAM/ATSAMPairInitV1.swift`
- KAT: `shared-vectors/rvn1/atsam/pair_init_v1_001.json`
- Clock-skew boundaries (§1, §5): `shared-vectors/rvn1/atsam/pair_init_v1_clock_skew_001.json`
- Structural negatives: `shared-vectors/rvn1/atsam/negative/pair_init_v1_*.json`
  (including `pair_init_v1_small_order_ephemeral_001`, validly signed but with a
  small-order initiator ephemeral)
- Strict Ed25519 (every signature above): `shared-vectors/rvn1/negative/ed25519_weak_key_forgery_001.json`

Outside the LAN-direct slice under the §7 waiver (`raven_core::lan_dispatch`),
all implementations are codec/KDF/verification support only, and relay and
other live classifiers intentionally do not recognize these records.
