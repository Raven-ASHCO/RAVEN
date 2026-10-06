# RAVEN Capabilities V1

**Version:** 1 (`rvn1`)
**Status:** Frozen. See [`SPEC.md`](SPEC.md) for scope and versioning policy.
**Audience:** re-implementers of feature negotiation between clients.

---

## 1. Signed capability set

`RavenProtocolCapabilitiesV1` is a self-signed, identity-scoped claim about
what protocol features an identity supports — carried on the wire as an
`env_type=4` `RavenEnvelopeV1` body ([`RAVEN_ENVELOPE_V1.md`](RAVEN_ENVELOPE_V1.md)).

| Field | Type | Meaning |
|---|---|---|
| `identity_address` | string | the `RavenAddressV1` making the claim ([`RAVEN_ADDRESS_V1.md`](RAVEN_ADDRESS_V1.md)) |
| `capability_bits` | u64 bitmask | the identity-scoped protocol capability set |
| `expires_at_ms` | u64 | unix ms |

**Signing bytes** (`lp(x) = len_be2 || x`, `u64(n)` = 8-byte big-endian):

```
"rvn1/caps" || lp(identity_address) || u64(capability_bits) || u64(expires_at_ms)
```

Signed by `identity_address`'s own Ed25519 identity key — the same
self-attestation pattern used by `RavenAliasRecordV1`
([`RAVEN_ALIAS_V1.md`](RAVEN_ALIAS_V1.md)).

**Vector:** `shared-vectors/rvn1/capabilities/alice_v1.json` — alice's
identity claiming `capability_bits = 15` (`0b1111`).

**No bit registry in V1.** V1 freezes only the record bytes. It assigns **no**
meaning to any `capability_bits` value; `0b1111` in the vector is an opaque
test value, not four named features. Until a registry exists, no
implementation can act on a bit, and no shipped code consumes `env_type=4`
records (the Rust core only checks the vector). The negotiation and
downgrade properties below are therefore design intent, not a guarantee in
force in any current build.

> `capability_bits` here is a distinct namespace from
> `RavenDeviceCertificateV1.capabilities` in
> [`RAVEN_IDENTITY_V1.md`](RAVEN_IDENTITY_V1.md) §2 — that one is
> device-scoped ("this device may act as a bridge/relay"); this one is
> identity-scoped ("this identity's protocol implementation supports these
> wire features"). The two bitmasks are unrelated and MUST NOT be conflated.

## 2. Authenticated negotiation

The legacy shipping mesh transport advertises a *different*, **unsigned**
`Capabilities` bitmask over a BLE GATT characteristic
(`ios-native/RAVEN/RAVEN/Core/Mesh/RUMProtocolV2.swift:155-218`; see
[`../docs/MESH_PROTOCOL.md`](../docs/MESH_PROTOCOL.md) §A) — anyone in radio
range, including an on-path relay, can observe or alter that read before a
peer sees it, and neither side can tell.

`RavenProtocolCapabilitiesV1` narrows that gap: a peer's claimed capability
set is cryptographically bound to its identity via the Ed25519 signature. An
on-path relay or MITM position cannot flip a bit in a record — say, stripping a
`pqHybridKEM` or `hopAuth`-equivalent bit to force both sides into a weaker
negotiated mode — without invalidating the signature. It **can** still
replay (or selectively withhold) *other* records the identity signed, which
§3 bounds only partially.

## 3. Downgrade protection — and its V1 replay window

The record is signed and time-bound (`expires_at_ms`), but it has **no
sequence number**. What V1 can and cannot guarantee:

- **Guaranteed:** a record cannot be altered (bit-flip) without breaking the
  signature, and a record is dead once its `expires_at_ms` has passed.
- **Not guaranteed — replay window:** any older record the identity signed
  that is *still unexpired* is indistinguishable from a current one. An
  attacker who captured such a lower-capability record can present it to a
  verifier that has not yet seen the newer one, forcing a downgrade until the
  old record's `expires_at_ms`. The window is the full remaining lifetime of
  every record the identity ever issued, so issuers SHOULD keep
  `expires_at_ms` short (and never extend a lower-capability record's
  lifetime past a higher one's).

**Choosing between records (normative for V1).** A verifier caches, per
`identity_address`, the valid record with the **latest `expires_at_ms`**, and
replaces it only with a valid record whose `expires_at_ms` is strictly later.
A record with an earlier or equal `expires_at_ms` never replaces the cached
one, whatever its bits, and two different records with equal
`expires_at_ms` are a conflict to surface, not to merge. Verifiers MUST NOT
"negotiate to the intersection" of overlapping records: the intersection is
exactly the downgrade an attacker obtains by replaying an old record next to
the current one. (Issuers therefore MUST give each new record a later
`expires_at_ms` than any record it supersedes.)

This is a documented scope limit, not a closed defense. A later version must
add an explicit monotonic `sequence` (as `RavenAliasRecordV1` has) and a bit
registry before capability negotiation is used for any security decision.

## 4. Mapping to legacy RUM v2 capability bits — known platform drift

The legacy, unsigned `Capabilities` `OptionSet`/enum described in §2 is
maintained independently on each platform today, and has already drifted.
Bits 0 through 12 agree across all four current clients; bit 13 does not:

| Bit | Name | iOS/macOS | Windows | Android |
|---|---|---|---|---|
| `1<<13` | `doubleRatchet` | present — `ios-native/RAVEN/RAVEN/Core/Mesh/RUMProtocolV2.swift:217` (also `RAVEN-MacApp/RAVEN/Core/Mesh/RUMProtocolV2.swift:210`) | **absent** — enum ends at `RotatingPeerId = 1u << 12`, `RAVEN-Windows/src/Mesh/RumProtocolV2.cs:243` | **absent** — object ends at `ROTATING_PEER_ID = 1u shl 12`, `RAVEN-Android/legacy/mesh-protocol/RumProtocolV2.kt:247` |

The bit is not mis-numbered on Windows/Android — it is entirely unallocated
there, not merely unset. Consequence: a Windows or Android peer cannot
advertise or negotiate `doubleRatchet` support via the legacy RUM v2 handshake
at all. (Android does have its own `DoubleRatchet` implementation —
`RAVEN-Android/feature/e2ee/src/main/kotlin/.../DoubleRatchet.kt` — but it is
not wired into `RumProtocolV2.Capabilities` negotiation, so peers cannot
discover support for it through this mechanism.)

This is exactly the kind of drift `RavenProtocolCapabilitiesV1`'s single,
signed, platform-agnostic bit namespace is meant to prevent going forward: one
registry, referenced by every implementation, rather than four hand-copied
enums. V1 does not yet map every legacy RUM v2 bit onto
`RavenProtocolCapabilitiesV1.capability_bits` — reconciling the two namespaces
is Phase B/C scope, not part of this freeze.

## Reference implementation

`protocol/reference/raven_protocol/capabilities.py`, built on the shared
`lp`/`u64` helpers in `protocol/reference/raven_protocol/_canon.py`. As with
alias records, `verify()` proves only that *some* key signed the set; a peer
MUST additionally bind it by checking `address.encode(signer_pub) ==
identity_address` before honouring the advertised capabilities (§1). Vectors:
`shared-vectors/rvn1/capabilities/alice_v1.json` and the negative
`shared-vectors/rvn1/negative/capabilities_tampered_bits.json` (a post-sign
bit flip must fail verification — the tamper defense; replay of an older
unexpired record is out of scope for V1, §3).
