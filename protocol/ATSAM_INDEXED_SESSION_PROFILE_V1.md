# ATSAM Indexed Session Profile V1

**Profile identifier:** `ATSAM/indexed-session/v1`

**Sealed-frame protocol byte:** RVNA1 `0x03`

**Status:** additive byte contract; **production disabled**

**Outer envelope:** unchanged `RavenEnvelopeV1` (`RVN1`, 86-byte prefix)

This profile freezes the derivations and bytes needed for indexed message,
ACK, and route lanes without silently changing existing RVNA1 v2 semantics.
It is not a session-establishment protocol. The additive, production-disabled
[`RAVEN_PAIR_INIT_V1.md`](RAVEN_PAIR_INIT_V1.md) now freezes a signed
PairInit/response that negotiates this exact profile and binds the context
below, exact device certificates, both hybrid contributions, suite, roles, and
one-time-prekey state into the authenticated transcript. No endpoint may
activate the profile until PairInit's confidential carrier, durable state, OTP
lifecycle, cross-platform, and external-review gates are also satisfied.
Supplying a `K_root` to the reference helpers proves only deterministic
interoperation.

## 1. Canonical session context and roles

Both identifiers are exact, lowercase canonical `RavenAddressV1` strings.
Display form, mixed case, leading/trailing whitespace, a different address
version, or normalization during verification is an error.

```
session_context = UTF8("ATSAM/indexed-session/v1") || 0x00
               || ASCII(initiator_address) || 0x00
               || ASCII(responder_address)
```

The endpoints must differ. PairInit assigns immutable transcript roles:

| `direction` | Sender | Recipient |
|---:|---|---|
| `0` | initiator | responder |
| `1` | responder | initiator |

Direction is a role byte, not lexicographic address order and not local
send/receive perspective. Role reversal creates a different session context.

## 2. HKDF and lane derivations

Every HKDF below is HKDF-SHA256 with `L=32`. `salt=nil` means the RFC 5869
default salt of 32 zero bytes. Labels and NUL separators are exact ASCII bytes.
`K_root` is the 32-byte hybrid root from the authenticated PairInit transcript.

For a direction `d`, let `S` and `R` be its canonical sender and recipient
addresses from §1.

### 2.1 Message lane (unchanged ATSAM v2 chain)

```
CK_msg,0[d] = HKDF(K_root, salt=nil,
    info="ATSAM/v2/chain-init" || 0x00 || S || 0x00 || R)

K_msg,i[d] = HKDF(CK_msg,i[d], salt="ATSAM/v2/msg-seal/salt",
    info="ATSAM/v2/msg-key" || 0x00 || S || 0x00 || R)

CK_msg,i+1[d] = HKDF(CK_msg,i[d], salt=nil,
    info="ATSAM/v2/chain-advance")
```

This profile does not reinterpret or re-key the existing message chain.

### 2.2 ACK lane

```
K_ack_base = HKDF(K_root, salt=nil, info="ATSAM/v1/ack-seal")

CK_ack,0[d] = HKDF(K_ack_base, salt=nil,
    info="ATSAM/v2/chain-init" || 0x00 || S || 0x00 || R)

K_ack,i[d] = HKDF(CK_ack,i[d], salt="ATSAM/v2/msg-seal/salt",
    info="ATSAM/v2/msg-key" || 0x00 || S || 0x00 || R)

CK_ack,i+1[d] = HKDF(CK_ack,i[d], salt=nil,
    info="ATSAM/v2/chain-advance")
```

The extra root label separates ACK keys from message keys even at equal
direction and index. Message and ACK indexes are independent monotonic lanes.

### 2.3 Route lane

```
K_route_master = HKDF(K_root, salt=nil,
    info="ATSAM/v1/GhostRoute/recipient-tag")

K_route[d] = HKDF(K_route_master, salt=nil,
    info="ATSAM/v1/GhostRoute/rvn1-direction" || 0x00 || u8(d))
```

For an envelope with signed `created_at_ms`, RVNA1 chain `index`, `env_type`,
and transcript direction `d`:

```
epoch   = floor(created_at_ms / 1000)
counter = (u64(index) << 3) | ((u64(env_type) - 1) << 1) | u64(d)
tag     = HMAC-SHA256(K_route[d],
          "rvn1/route" || u64_be(epoch) || u64_be(counter))[:16]
```

`index` is a u32. `env_type` is 1 through 4 and `d` is 0 or 1. For messages
and ACKs, `index` is exactly the clear RVNA1 indexed-header value for that
type's lane. Values 3 and 4 have reserved counter partitions but MUST NOT be
originated under this profile until their authenticated indexed lane is
specified. An endpoint may read the bounded RVNA1 header to test candidate
session tags; this does not authorize or decrypt the object. Outer device
authentication and AEAD verification remain mandatory.

### 2.4 Security properties and explicit non-claims

Every message, ACK, route, and mailbox key of a session is a deterministic
function of `K_root` (§2.1-§2.3 and §6). There is no Diffie-Hellman or KEM
ratchet inside a session. Consequently:

- **No forward secrecy within a session.** Whoever obtains `K_root`, or the
  protected session state that holds it, can recompute every past and future
  `K_msg,i[d]`, `K_ack,i[d]`, `K_route[d]`, route tag, and mailbox tag of that
  session in both directions and decrypt every captured RVNA1 `0x03` frame of
  it. Advancing and discarding chain keys does not change this while
  `K_root` is retained, and the reference endpoint store retains `K_root` for
  the life of the session (route-tag checks and its local storage key are
  re-derived from it).
- **No post-compromise security.** A session never heals. After a compromise
  of its state, confidentiality returns only with a new PairInit, which
  contributes a fresh initiator X25519 ephemeral and ML-KEM ciphertext and
  derives an independent `K_root`.
- The protection that does exist is between sessions: roots of distinct
  PairInits are independent, a session accepts traffic only until its signed
  PairInit `expires_at_ms`, and destroying an expired session's root (plus the
  prekey private material that produced it, per
  [`RAVEN_PREKEY_LIFECYCLE_V1.md`](RAVEN_PREKEY_LIFECYCLE_V1.md)) protects
  that session's traffic against later compromise. Until then, at-rest
  protection of the session state is the only barrier.

**Session lifetime (informative).** Because the exposure above spans the whole
session, initiators SHOULD keep sessions short. This implementation initiates
sessions whose signed PairInit lifetime is 24 hours
(`lan_dispatch::LAN_SESSION_LIFETIME_MS`); as responder it still accepts the
7-day PairInit maximum of
[`RAVEN_PREKEY_LIFECYCLE_V1.md`](RAVEN_PREKEY_LIFECYCLE_V1.md) §4 from other
initiators. A short lifetime bounds, but does not remove, the in-session
exposure.

Implementations and product text MUST NOT describe this profile as providing
per-message forward secrecy or post-compromise security. Those properties
require a ratcheting successor profile (for example
[`ATSAM_HYBRID_RATCHET_V2.md`](ATSAM_HYBRID_RATCHET_V2.md)); the KDF above is
frozen for interoperation and is not altered to approximate them.

The stateless reference helpers that walk a chain from `CK_0`
(`message_key_at_index`, `ack_key_at_index`, `seal_ack`, `open_ack`) cost one
HKDF per index step, and `open_ack` reads the index from unauthenticated wire
bytes. They therefore reject `index > 4096` (the same bound as the portable
RVNA1 v2 helper) without changing any derivation below it. A stateful receiver
instead bounds each forward jump relative to its persisted counter.

## 3. Message-ID text in AEAD associated data

The outer raw 16-byte `message_id` is encoded in ATSAM AAD as exactly 36 ASCII
characters: uppercase hexadecimal in `8-4-4-4-12` UUID grouping. No braces,
prefix, terminating NUL, Unicode case folding, or UUID-version rewriting is
permitted.

```
00112233445546778899aabbccddeeff
-> "00112233-4455-4677-8899-AABBCCDDEEFF"
```

This freezes a prior cross-language ambiguity where UUID libraries emitted
different case while the raw identifier was identical.

## 4. Signed ACK plaintext (exactly 101 bytes)

The opened ACK record is:

```
acked_message_id(16)
|| status(1)                       # 1=delivered, 2=read only
|| ack_nonce(12)
|| created_at_ms_be64(8)
|| inner_ed25519_signature(64)
```

Total: `16 + 1 + 12 + 8 + 64 = 101` bytes. The inner signature is by the
acknowledging device over:

```
"rvn1/ack" || acked_message_id || status || ack_nonce || created_at_ms_be64
```

The inner `created_at_ms` MUST equal the outer ACK envelope's signed
`created_at` exactly. The inner signer and outer envelope signer MUST resolve
to the same expected, non-revoked recipient device. Verification also requires
an exact outstanding outbound row for `acked_message_id` bound to that device,
valid status/freshness, replay/idempotency checks, and one atomic conditional
delivery-state update. Decryption or a valid signature alone is not delivery
authorization.

## 5. RVNA1 `0x03` sealed ACK (exactly 143 bytes)

RVNA1 v2 already shipped with ambiguous session assumptions. This profile
therefore uses a new protocol byte while retaining the indexed header shape
and ChaCha20-Poly1305 construction. Every indexed-profile RVNA1 seal uses
`proto=0x03`: `env_type=1` selects `K_msg,index[d]`, while `env_type=2`
selects `K_ack,index[d]`. This section freezes the fixed-size ACK case:

```
"RVNA1\0\0\0"(8) || proto=0x03 || suite=0x01
|| ack_index_be32(4) || nonce(12) || ciphertext(101) || tag(16)
```

Total: `8 + 1 + 1 + 4 + 12 + 101 + 16 = 143` bytes. The AEAD key is
`K_ack,ack_index[d]`. The AAD is:

```
SHA-256(
  "ATSAM/v1/msg-seal/aad" || 0x00
  || 0x03 || 0x01 || ack_index_be32 || 0x00
  || ASCII(S) || 0x00 || ASCII(R) || 0x00
  || ASCII(uppercase_uuid_text(outer_ack_message_id))
)
```

The 12-byte AEAD nonce MUST NOT repeat for the same derived ACK key. The
deterministic fixture nonce is public test material only.

When `ratchet_header_ciphertext` is empty and outer authentication is a
64-byte Ed25519 signature, the complete ACK envelope is exactly:

```
86-byte RVN1 prefix + 0-byte header + 143-byte sealed body + 64-byte signature
= 293 bytes
```

This size is a fixture invariant, not permission to accept an envelope by
length. All `RavenEnvelopeV1` structural, TTL, route, device, outer-signature,
AEAD, inner-signature, replay, persistence, and authorization gates apply.

## 6. Offline mailbox namespace and deletion

Per-envelope routing tags are one-time delivery locators. They MUST NOT be
hashed or otherwise transformed into an offline polling address: a recipient
that has not seen an envelope cannot predict that envelope's tag.

For Store Object V1 compatibility, the indexed profile uses the separately
derived directional key from §2.3 with the existing mailbox primitive:

```
day_epoch  = floor(unix_ms / 86_400_000)
mailbox_tag[d] = HMAC-SHA256(K_route[d],
    "rvn1/mailbox" || u64_be(day_epoch) || u64_be(d))[:16]
store_tag[d] = SHA-256("raven/relay-tag/v1" || mailbox_tag[d])[:16]
```

Endpoints poll the current and previous day within the documented skew
window. Daily tag reuse exposes same-day mailbox access patterns; it does not
provide traffic-analysis resistance.

An opaque store cannot read `acked_message_id` from a sealed ACK and cannot
authenticate deletion from an ACK's mere arrival. Store Object V1 deletion is
TTL-only under this errata. Early deletion requires a future versioned,
store-verifiable deletion token bound to the exact custody object; no such
token is defined here.

## 7. Activation and vectors

Production activation remains forbidden until the release gates in
[`SECURITY_ERRATA_RVN1_2026-08-13.md`](SECURITY_ERRATA_RVN1_2026-08-13.md)
[`RAVEN_PAIR_INIT_V1.md`](RAVEN_PAIR_INIT_V1.md), and
[`ATSAM_ENDPOINT_TRANSACTION_V1.md`](ATSAM_ENDPOINT_TRANSACTION_V1.md) are
satisfied. PairInit V1
negotiates this profile context in pure codec/KDF vectors but is itself
production disabled.
In particular, RVNA1 `0x03` is intentionally absent from live endpoint and
relay classifiers today, with one scoped exception: the owner waiver
[`WAIVER-LAN-DIRECT-2026-10-07`](../docs/WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) keeps the LAN-direct slice (PairInit V1 /
PairResponse over Noise XX between two `raven-node` services, contacts only,
RVNA1 `0x03` messages and sealed ACKs) enabled in default and release builds.
The waiver does not satisfy the gates above, and every other carrier, relay,
mailbox, and store path for this profile stays disabled. It MUST NOT be
described as Session V2.

Deterministic fixtures:

- `shared-vectors/rvn1/atsam/indexed_session_v1_subkeys_001.json`
- `shared-vectors/rvn1/atsam/indexed_session_v1_sealed_ack_001.json`
- `shared-vectors/rvn1/atsam/pair_init_v1_001.json`

Reference implementations:

- `protocol/reference/raven_protocol/indexed_session.py`
- `node/crates/raven-core/src/atsam_indexed_session.rs` (pure KDF/codec/KAT
  support only; not an activated session engine)
