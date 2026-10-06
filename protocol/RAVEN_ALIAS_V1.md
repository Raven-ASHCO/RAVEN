# RAVEN Alias V1

**Version:** 1 (`rvn1`)
**Status:** Frozen. See [`SPEC.md`](SPEC.md) for scope and versioning policy.
**Audience:** re-implementers of alias resolution/publication and anyone
building a DHT-backed alias store.

---

## 1. Record schema and signature

`RavenAliasRecordV1` is a self-signed claim: an identity publishing that a
human-readable string currently points at its own address.

| Field | Type | Meaning |
|---|---|---|
| `alias` | string | the human-chosen name, e.g. `"ahmad"` |
| `identity_address` | string | the `RavenAddressV1` this alias currently resolves to ([`RAVEN_ADDRESS_V1.md`](RAVEN_ADDRESS_V1.md)) |
| `sequence` | u64 | monotonically increasing per-alias counter |
| `expires_at` | u64 | unix ms |
| `signature` | 64 bytes | Ed25519, over the signing bytes below |

**Signing bytes** (`lp(x) = len_be2 || x`, `u64(n)` = 8-byte big-endian):

```
"rvn1/alias" || lp(alias) || lp(identity_address) || u64(sequence) || u64(expires_at_ms)
```

Signed by the **identity key of `identity_address` itself** — this is a
self-claim, not a third-party grant. Anyone can construct and sign a
`RavenAliasRecordV1` for any alias string they like, for their own address;
there is no registrar and no uniqueness enforcement at the signing layer (see
§3).

**Vector:** `shared-vectors/rvn1/alias/ahmad_seq42.json` — alice's identity
claiming alias `"ahmad"` at `sequence=42`.

## 2. Monotonic sequence freshness

A verifier or cache holding a record for a given alias at `sequence=N` MUST
reject any incoming record for the *same alias, same claiming identity* with
`sequence <= N`, even if the incoming record is validly signed. This defeats
replay of a stale-but-validly-signed older record — for example, an attacker
who captured an earlier signed record before the legitimate owner moved the
alias elsewhere, or before a key rotation, cannot use it to roll the alias
back.

**Vector:** `shared-vectors/rvn1/negative/alias_stale_sequence.json` — a
`sequence=41` record arriving after a `sequence=42` record is already cached
for the same alias; expected `resolver_action: reject_stale`.

## 3. The ambiguity rule

Because any identity can self-sign a claim on any alias string with no
registrar, **the alias namespace is not unique.** Two different
`identity_address` values can each publish a validly-signed, unexpired,
highest-known-`sequence` record claiming the exact same alias string — for
example if two people independently pick the same name, or if a DHT briefly
holds two independently-seeded copies during a network partition.

**A resolver that observes two live, conflicting claims for the same alias
string MUST surface this as an ambiguous or conflicting result — it MUST NOT
silently pick one.** Silent selection is exactly the failure mode that lets an
attacker who publishes a competing claim quietly redirect a lookup: if the
resolver's tie-break is deterministic and predictable (e.g. "prefer the
lexicographically smaller address" or "prefer whichever record arrived
first"), an attacker only needs to win that specific tie-break, not defeat any
cryptography.

**Key-change warning.** Separately from outright ambiguity: when a lookup for
a *previously resolved* alias returns a *different* `identity_address` (or the
same address's underlying device-certificate set has changed) than what was
last seen and pinned for that alias, implementations MUST surface a
key-change warning before delivering to or trusting the new identity — the
same "did the key change?" posture described for fingerprints in
[`RAVEN_IDENTITY_V1.md`](RAVEN_IDENTITY_V1.md) §3. An alias resolving to a new
address is exactly as significant, from a trust standpoint, as a contact's
fingerprint changing.

## Soft Unique Raven Tags

See [`docs/RAVEN_TAG_V1.md`](../docs/RAVEN_TAG_V1.md): Layer A address/fingerprint, Layer B public `@tag` (Alias V1, non-unique), Layer C device-local **petname** (inbox primary). Pin-on-verify; ambiguity picker; no registrar.

**Alias normalization (Discovery V1):** for V1 publish/lookup, aliases MUST match charset `a-z` `0-9` `_` `-` only (after lowercasing and stripping a leading `@`). See [`docs/RAVEN_DISCOVERY_V1.md`](../docs/RAVEN_DISCOVERY_V1.md).

---

## 4. DHT publication constraints

A `RavenAliasRecordV1` published to (or served from) a DHT or any other
untrusted store MUST satisfy all of:

- **Signed.** Unsigned records MUST be discarded on receipt — there is
  nothing else binding the claim to the identity making it.
- **Versioned.** `sequence` *is* the version. Replacement in the store must be
  keyed by `(alias, identity_address)` with last-write-wins by `sequence`,
  never by wall-clock receipt order (§2) — receipt order is not trustworthy in
  a store with multiple untrusted writers.
- **Expiry-bound.** A resolver MUST treat a record as absent once past
  `expires_at`. This is what keeps an abandoned or unrenewed alias claim from
  squatting the name indefinitely.
- **Size-limited.** `alias` and `identity_address` are the only
  variable-length fields, each length-prefixed with a 2-byte big-endian
  length (a 65,535-byte theoretical cap per field). A store implementation
  SHOULD impose a much smaller practical cap — a value approaching that
  theoretical ceiling has no legitimate use as a human-typed alias, and
  admitting oversized values is a cheap amplification/storage-exhaustion
  vector against the store.
  - **`lp()` overflow is fail-closed, not wrap-around.** The 2-byte length
    means a field longer than 65,535 bytes MUST be **rejected**, never
    truncated or wrapped. A naive port that writes `len as u16` (Rust/C#)
    would silently wrap the length and corrupt the field boundary, producing
    signing bytes that disagree across implementations. The reference `lp()`
    raises rather than emit a wrapped prefix; every port MUST do the same.
- **Bound to its signer.** `verify()` alone only proves the record is signed
  by *some* key; a resolver MUST additionally check that the verifying key's
  `RavenAddressV1` equals the record's `identity_address`. Otherwise a record
  validly signed by key K but carrying someone else's `identity_address` would
  pass a signature-only check. The binding is `address.encode(signer_pub) ==
  identity_address`. The same rule applies to `RavenProtocolCapabilitiesV1`
  ([`RAVEN_CAPABILITIES_V1.md`](RAVEN_CAPABILITIES_V1.md)).
- **Exactly decoded.** The stored encoding
  (`lp(alias) || lp(identity_address) || u64(sequence) || u64(expires_at) ||
  ed25519_pub(32) || signature(64)`) is decoded exactly; trailing bytes are
  rejected so each record has one encoding.

### 4.1 Store quotas

A store fed by untrusted publishers bounds each signing key and itself:

- **Live-claim quota** (default 8 per key). Only *unexpired* claims count;
  expired ones never consume quota. Expired records are kept as `sequence`
  high-water marks for §2 anti-rollback, and are evicted only when the store
  is at its global cap. Renewing an expired claim counts as a new live claim.
- **Publish rate** (default 16 per key per rolling hour), including sequence
  updates.
- **Global cap** across all keys (default 4096 records); admission of a new
  `(alias, identity_address)` fails closed (`ALIAS_STORE_FULL`) when the cap
  is reached after evicting expired records.

Records the local user published themselves and reloads from local storage
are not network publications: they go through signature, binding, expiry,
sequence and global-cap checks but not the per-key rate limit or live quota,
so a reload never silently drops rows.

## Reference implementation

`protocol/reference/raven_protocol/alias.py`. Vectors:
`shared-vectors/rvn1/alias/ahmad_seq42.json`,
`shared-vectors/rvn1/negative/alias_stale_sequence.json`.
