# RAVEN Identity V1

**Version:** 1 (`rvn1`)
**Status:** Frozen. See [`SPEC.md`](SPEC.md) for scope and versioning policy.
**Audience:** re-implementers of the identity/device-authorization layer.

---

## 1. Two keypair tiers

RAVEN separates *who a person is* from *what device they're using right now*.
There are two distinct keypair tiers, and implementations MUST NOT collapse
them into one:

### 1.1 User Identity key

- **Algorithm:** Ed25519.
- **Scope:** one per person, **local-only**. Generated on-device, never
  transmitted, never escrowed — there is no server to escrow it to.
- **Role:** this is the protocol's root of trust. `RavenAddressV1`
  ([`RAVEN_ADDRESS_V1.md`](RAVEN_ADDRESS_V1.md)) is deterministically derived
  from this key's public half. Every self-signed record in this family —
  `RavenAliasRecordV1` ([`RAVEN_ALIAS_V1.md`](RAVEN_ALIAS_V1.md)),
  `RavenProtocolCapabilitiesV1` ([`RAVEN_CAPABILITIES_V1.md`](RAVEN_CAPABILITIES_V1.md)),
  `RavenDeviceCertificateV1` (below) — is authenticated by this key.
- Losing this key means losing the identity: there is no central authority
  that can reissue it. (Recovery mechanisms, if any, are out of scope for this
  document.)

### 1.2 Device Identity keys

- **Algorithm:** Ed25519 (signing) **and** X25519 (key agreement) — two
  distinct keypairs, generated **per device**. A person with N devices has N
  distinct device-key pairs.
- **Role:** the device's Ed25519 key signs `RavenEnvelopeV1.sender_authentication`
  ([`RAVEN_ENVELOPE_V1.md`](RAVEN_ENVELOPE_V1.md)) for traffic that device
  originates. The device's X25519 key participates in session
  establishment/ratcheting (the ATSAM/Noise session layer itself is out of
  scope for this V1 wire-format freeze).
- A device key is worthless to a verifier on its own — it only means anything
  once bound to a user identity by a `RavenDeviceCertificateV1` (§2).

### 1.3 Signature verification is strict

Every Ed25519 check in this family — device certificates, revocations,
PairInit/PairResponse, envelope `sender_authentication`, alias, profile,
introduction, contact-request/accept and ACK records — MUST use strict
verification: reject a public key `A` of small order ("weak" keys), reject a
signature whose `R` is of small order, and require canonical `s < L`
(RFC 8032 §5.1.7 plus the small-order checks, e.g. ed25519-dalek
`verify_strict`). Every key in this family is attacker-suppliable on the wire,
and under a weak key such as the identity point the pair `(R = identity,
s = 0)` satisfies the cofactorless equation for *every* message, so a lenient
verifier would accept a "signature" over arbitrary cert, pairing or record
bytes from someone holding no private key. Honestly generated keys and
signatures never trip these checks, so strictness changes no valid vector.
Reference: `raven_core::identity::Identity::verify`. The Python reference's
`verify()` helpers call OpenSSL's Ed25519 verify, which accepts the weak-key
forgery above; they are not yet an oracle for this rule.

## 2. `RavenDeviceCertificateV1`

The user-signs-device certificate. Possession of a valid certificate signed by
identity `X`'s Ed25519 key is the **only** thing that lets a peer treat a given
`device_ed_pub` as belonging to `X`, for the purposes of trusting envelopes or
ACKs signed by that device key.

| Field | Type | Meaning |
|---|---|---|
| `device_ed_pub` | 32 bytes | the device's Ed25519 signing public key |
| `device_x_pub` | 32 bytes | the device's X25519 agreement public key |
| `device_id` | string | opaque device label |
| `not_before_ms` | u64 | validity window start (unix ms) |
| `not_after_ms` | u64 | validity window end (unix ms) |
| `capabilities` | u64 bitmask | **device-level** capabilities (e.g. "this device may act as a bridge/relay") |

**Signing bytes** (length-prefixed, `lp(x) = len_be2 || x`, `u64(n)` = 8-byte
big-endian):

```
"rvn1/devcert" || lp(device_ed_pub) || lp(device_x_pub) || lp(device_id)
               || u64(not_before_ms) || u64(not_after_ms) || u64(capabilities)
```

Signed by the **user identity key** — not by the device itself. That is what
"authorizes a device" means: the certificate is signed by whichever identity
is vouching for the device, and a verifier recovers *which* identity that is
by checking the signature against the claimed signer's public key (which in
turn deterministically maps to a `RavenAddressV1`, §1 above).

> `capabilities` here is a **device-scoped** bitmask, independent of the
> **identity-scoped** `capability_bits` in `RavenProtocolCapabilitiesV1`
> ([`RAVEN_CAPABILITIES_V1.md`](RAVEN_CAPABILITIES_V1.md)). The two are
> separate namespaces signed by the same key type for different purposes —
> implementations MUST NOT conflate them.

**Vector:** `shared-vectors/rvn1/device_cert/bob_device1.json` — `device_id`
is the fixture label `"bob-device-1"`, signed by alice's identity key. This
fixture reuses the two demo keypairs available in `identities.json` purely to
exercise the signing-bytes formula with a signer distinct from the subject
device's own keys; the `device_id` string is an opaque label and its content
does not imply the protocol supports one identity certifying another
identity's device. The property under test is that the signature verifies
against the claimed signer's public key — in normal use that signer is the
device owner's own user identity key.

### 2.1 Revocation and what partitions can/can't guarantee

This V1 freeze defines certificate **issuance**, not a dedicated revocation
record type — there is no `shared-vectors/rvn1/` vector for revocation, and
this document does not invent wire bytes for one. Until a
`RavenDeviceRevocationV1` (or equivalent) is specified in a later version,
implementations have exactly two frozen-V1 tools for retiring a device:

1. **Natural expiry** — issue certificates with a bounded `not_after_ms` and
   don't renew a compromised device's certificate. This is reliable but not
   immediate: the device stays trusted until expiry.
2. **A fresher, narrower certificate** — the same versioned-record pattern
   used by `RavenAliasRecordV1` and `RavenProtocolCapabilitiesV1` (a verifier
   trusts the freshest signed claim it has seen). This is not immediate
   revocation either; it is eventual re-assertion.

**What a partitioned network can't guarantee:** a mesh peer that has not been
back in contact with the identity in question since a device was compromised
has no way to learn that fact until it reconnects and fetches whatever fresher
record exists. There is no push-revocation channel in V1. Any migration or
extension that adds true revocation must account for this: a device cert's
trust is only as fresh as the last record a given verifier has actually seen.

## 3. Fingerprint reconciliation

Two distinct fingerprint schemes exist over the same Ed25519 public key. Only
one is current.

| Scheme | Formula | Status |
|---|---|---|
| `RavenDeviceFingerprintV1` (canonical) | `SHA-256(edPub)[:9] → base64 → strip '+'/'/'  → first 12 chars → XXXX-XXXX-XXXX` | **current — app scheme** |
| MeshV1 hex | `SHA-256(edPub)[:6] → hex → uppercase → XXXX-XXXX-XXXX` | **deprecated** — frozen only because it is the value already committed in `shared-vectors/v1/identities.json` (the pre-`rvn1` vector tree) |

**Exact `RavenDeviceFingerprintV1` algorithm (a port MUST follow this precisely
— it is the human safety number, so any divergence reads to users as a MITM):**

1. `h = SHA-256(edPub_raw_32)`; take `h[:9]` (9 bytes).
2. Encode those 9 bytes with **standard** Base64 (RFC 4648 §4 alphabet `A–Za–z0–9+/`).
   9 bytes → exactly 12 Base64 chars, no `=` padding. **Do not use Base64URL** (`-_`).
3. **Remove** every `+` and `/` character. Do **not** re-pad and do **not**
   truncate to 12 *before* stripping. Each of the 12 characters is `+` or `/`
   with probability 1/32, independently, so the length of the result is **not**
   bounded below by 10: it is 12 chars for ~68.3% of keys, 11 for ~26.4%, 10
   for ~4.7%, and 9 or fewer for ~0.54% (any number of characters may be
   stripped; 0 chars remain with probability 2⁻⁶⁰). A port MUST handle every
   length from 0 to 12 and MUST NOT assume a minimum.
4. Insert `-` after every 4th character of the **remaining** string (so a
   12-char result is `XXXX-XXXX-XXXX`; an 11-char result is `XXXX-XXXX-XXX`;
   a 9-char result is `XXXX-XXXX-X`).

**Strength (known V1 limitation).** This is a short human cross-check, not a
cryptographic safety number. It carries at most 72 bits of `SHA-256(edPub)`,
and because deleting `+`/`/` discards *which* positions held them, the
mapping is not injective: for the ~31.7% of keys that lose a character, the
number of distinct 72-bit prefixes rendering to the same string grows with
each deletion (a key that loses three characters shows only 9 characters,
at most ~54 bits of direct content). There is no key stretching and no
pairwise binding of the two parties' keys, and a multi-target attacker gains a
further factor of the number of targets. A second preimage still needs an
Ed25519 keygen per attempt at ≳2⁶⁷ work for the stripped branch, so this is a
margin concern rather than a practical MITM today — but V1 fingerprints MUST
NOT be described as providing more than ~72 bits, and a successor
verification string (e.g. an iterated-hash pairwise safety number over both
identities of ≥ 100 bits) is required before this is presented as a
high-assurance MITM check. The derivation above is frozen and MUST NOT be
changed in place.

For alice's RFC-8032 test key (`d75a98…511a`): clean 12-char branch → `If4x-36FU-omFi`
(MeshV1 hex deprecated: `21FE-31DF-A154`). For dave's key
(`e61a18…7057`): the Base64 `NN72hvSxN/7W` contains `/`, so after stripping the
fingerprint is the 11-char `NN72-hvSx-N7W`.

**Vectors:** `shared-vectors/rvn1/identities/fingerprint_alice.json` (clean
branch) and `…/fingerprint_dave.json` (the `+`/`/` strip branch — ~31.7% of
real keys hit it; it is pinned so no port can silently diverge on it). Each carries
the deprecated MeshV1 hex value too, purely as a migration check.

**The machine identity is the `RavenAddressV1`** ([`RAVEN_ADDRESS_V1.md`](RAVEN_ADDRESS_V1.md)),
not either fingerprint. Fingerprints are **human cross-check strings** — read
aloud or compared visually during pairing, or shown next to a contact for a
manual "did the key change?" check. Never use a fingerprint as a lookup key,
routing target, or session identifier; use the address (or the raw Ed25519
public key it's derived from) for anything machine-consumed.

## 4. ATSAM `userId` → canonical-identity migration (load-bearing risk)

This is the one item in this document that describes a **need**, not a
finished design — flagged explicitly because getting it wrong is expensive.

**Today, as shipped:** the ATSAM security layer keys its persisted root
material and binds its sealed-frame AAD (additional authenticated data) by a
**server-issued `userId` string**, not by any `RavenAddressV1` or raw Ed25519
public key:

- Root/chain storage account names are literally `root|<userId>`,
  `chain|s|<userId>`, `chain|r|<userId>` (`ATSAMRootStorage.swift`).
- The AEAD associated data for every sealed frame is built from
  `senderUserId`/`recipientUserId` strings (`ATSAMMessageSealer.swift`'s
  `buildAAD(...)`), and chain-ratchet initialization derives directly from the
  same `userId` strings.

**The migration need:** this identity/address freeze introduces a canonical,
self-sovereign identity (Ed25519 keypair → `RavenAddressV1`) that by design
has **no server-issued `userId`** — there is no server left to issue one.
Every existing ATSAM root, ratchet chain, and AAD computation that keys or
binds on `userId` today needs a path to key/bind on the canonical identity
instead, without silently breaking already-established sessions or making
already-sealed history undecryptable mid-migration.

**Constraints any acceptable migration design must satisfy** (need, not
mechanism):

1. It must be possible, for every existing `userId`-keyed ATSAM root, to
   determine which canonical identity (`RavenAddressV1`) it now corresponds
   to.
2. A device that has migrated and one that has not must either still
   interoperate during a transition window, or the transition must be atomic
   per conversation pair — a half-migrated pair must not silently produce
   frames the other side can't decrypt.
3. Whatever value ends up in the AAD must keep the property that it cannot be
   replayed across a *different* (sender, recipient) pair — the most literal
   analog is swapping `userId` strings for `identity_address` strings, but any
   replacement must preserve this uniqueness property, not just resemble it.
4. The migration must not depend on a trusted-server rendezvous to hand out
   the `userId → address` mapping — introducing one would reinstate exactly
   the central dependency this identity model exists to remove.

The actual mechanism (e.g. whether to add an address field alongside `userId`,
run a one-time client-side re-key ceremony, or maintain a local translation
table) is Phase B/C implementation work and intentionally out of scope here.

## See also

- [`SPEC.md`](SPEC.md) — invariants and versioning policy.
- [`RAVEN_ADDRESS_V1.md`](RAVEN_ADDRESS_V1.md) — how the identity public key
  becomes an address.
- [`RAVEN_ENVELOPE_V1.md`](RAVEN_ENVELOPE_V1.md) — where a device's
  Ed25519 key is used to authenticate wire traffic.
- [`RAVEN_CAPABILITIES_V1.md`](RAVEN_CAPABILITIES_V1.md) — the separate,
  identity-scoped capability bitmask.

## Reference implementation

`protocol/reference/raven_protocol/fingerprint.py`,
`protocol/reference/raven_protocol/device_cert.py`. Vectors:
`shared-vectors/rvn1/identities.json`,
`shared-vectors/rvn1/identities/fingerprint_alice.json` (clean branch),
`shared-vectors/rvn1/identities/fingerprint_dave.json` (`+`/`/` strip branch),
`shared-vectors/rvn1/device_cert/bob_device1.json`, and the negative
`shared-vectors/rvn1/negative/device_cert_wrong_signer.json` (a cert not signed
by the claimed user identity must be rejected).
