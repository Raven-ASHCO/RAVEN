# ATSAM ↔ Primitive Mapping V1

**Version:** 1 (normative mapping for serverless Phase B+)
**Status:** Primitive layout reference; **production security hold** under
[`SECURITY_ERRATA_RVN1_2026-08-13.md`](SECURITY_ERRATA_RVN1_2026-08-13.md).
Does **not** change `RavenEnvelopeV1` wire layout.
**Sources of truth (shipping):** `ios-native/RAVEN/RAVEN/Core/Security/ATSAM/*`, `MessageContentSealer.swift`, `NoiseSession*.swift`
**Public overview (non-wire):** `raven-security/ATSAM_PUBLIC_OVERVIEW.md`
**Outer envelope:** [`RAVEN_ENVELOPE_V1.md`](RAVEN_ENVELOPE_V1.md)
**Closeout:** [`docs/superpowers/specs/2026-08-12-phase-a-closeout-design.md`](../docs/superpowers/specs/2026-08-12-phase-a-closeout-design.md)

This document maps each ATSAM / sealed-content component to: primitive → purpose → threat → test-vector path → implementation path. Where vectors are still placeholders, that is stated explicitly.

---

## 1. Layering model

```
┌─────────────────────────────────────────────────────────────┐
│  RavenEnvelopeV1  magic RVN1 (4 B) — transport object       │
│  auth: Ed25519 sender_authentication over signing_bytes     │
│  body: opaque message_ciphertext + ratchet_header_ciphertext│
└───────────────────────────┬─────────────────────────────────┘
                            │ carries (does not redefine)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Sealed content frame (8 B magic + AEAD / handshake bytes)  │
│    RVNA1 — ATSAM ChaCha20-Poly1305 (prefer emit v2)         │
│    RVNS1 — Noise transport ciphertext                       │
│    RVNH1 — Noise handshake / 1-RTT                          │
│    RVNP1 — explicit plaintext (legacy / degrade; avoid)     │
└───────────────────────────┬─────────────────────────────────┘
                            │ keys from
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Session key material                                       │
│    ATSAM: hybrid root (X25519 ‖ ML-KEM-768) + chain ratchet │
│    Noise: Noise IK session keys                             │
└─────────────────────────────────────────────────────────────┘
```

**Rule:** Relays and bridges forward `RavenEnvelopeV1` bytes unchanged. They MUST NOT parse or rewrite sealed-content magics inside `message_ciphertext`.

---

## 2. Component map

| Component | Primitive(s) | Purpose | Threat addressed | Test vector path | Implementation path |
|---|---|---|---|---|---|
| **Hybrid pairing** | X25519 ECDH + ML-KEM-768 (FIPS 203) + SHA-256 transcript | Establish shared `K_root` from an identity-signed offline prekey without trusting a message server | Passive PQ break of classical ECDH alone; transcript confusion / cross-protocol replay | `shared-vectors/rvn1/atsam/mlkem768_hybrid_kat_001.json` + production-disabled `pair_init_v1_001.json`; live carrier/state still gated | `ATSAMHybridPairing.swift` + `raven_core::atsam_mlkem` (initiator API is only the split `begin_hybrid_initiation` → `PendingHybridInitiation::finalize`; caller-coin encapsulation is test-only) + [`RAVEN_PAIR_INIT_V1.md`](RAVEN_PAIR_INIT_V1.md) |
| **Root derivation** | HKDF-SHA256 | `K_root = HKDF(ikm=Z_X‖Z_PQ, salt=transcript, info="ATSAM/v1/pair-init"‖transcript, L=32)` | Binding pairing context into root; PRG expansion | `root_hkdf_001.json` and exact signed PairInit root in `pair_init_v1_001.json` | `ATSAMRootKey.swift` / `ATSAMRootDerivation` / pure Rust+Python PairInit |
| **Key tree** | HKDF-SHA256 per typed label | Domain-separated sub-keys: BBE, Ghost Handshake, Ghost Route, PV-Stealth, PV seed, msg-seal seed | Cross-layer key reuse | Indexed-profile ACK/route subset: `shared-vectors/rvn1/atsam/indexed_session_v1_subkeys_001.json`; other tree branches still lack committed KATs | `ATSAMKeyTree.swift`, labels in `ATSAMConstants.swift`; additive Rust/Python reference only for indexed profile |
| **Chain ratchet (v2)** | HKDF-SHA256 one-way chain | Intended per-direction FS only when predecessor destruction and state persistence are atomic; bounded skipped-key cache | Device compromise decrypting past traffic | Chain KDF KAT exists; crash/rollback vectors still required | `ATSAMChainRatchet.swift`, persistence in `ATSAMRootStorage.swift` |
| **Message seal RVNA1** | ChaCha20-Poly1305 (suite=1) | Confidentiality + integrity of text body; AAD binds sender/recipient/msgId (/index for v2) | Eavesdrop; ciphertext reroute; (v2) past-message recovery after compromise | Real known-root v2 KAT: `rvna1_v2_aead_known_root_001.json`; indexed sealed ACK KAT: `indexed_session_v1_sealed_ack_001.json`; outer envelope fixture remains a codec placeholder | `ATSAMMessageSealer.swift`, `raven_core::atsam_aead`, `atsam_indexed_session` |
| **Noise seal RVNS1** | Noise transport AEAD (existing session) | Fallback when no ATSAM root | Same content threats under classical Noise | Placeholder body in `rvn1/envelope/message_alice_to_bob.json` | `MessageContentSealer.swift` |
| **Noise handshake RVNH1** | Noise IK | First contact / QR bootstrap before ATSAM pair | Unauthenticated first message path | None in `rvn1/` | `NoiseSession.swift`, `MessageContentSealer.swift` |
| **Explicit plaintext RVNP1** | none (cleartext) | Legacy degrade path | **Does not address** confidentiality — receivers must treat carefully | N/A | `MessageContentSealer.swift` |
| **Ghost Route / K_route** | HKDF-SHA256 + HMAC-SHA256 | Directional, unlinkable recipient tags (pair-scoped) | Relay linkability of same recipient | Production-disabled indexed derivation: `shared-vectors/rvn1/atsam/indexed_session_v1_subkeys_001.json`; protocol HMAC primitive: `shared-vectors/rvn1/routing/` | [`ATSAM_INDEXED_SESSION_PROFILE_V1.md`](ATSAM_INDEXED_SESSION_PROFILE_V1.md); not wired into endpoints |
| **Protocol routing tag** | HMAC-SHA256(`K_route`, `"rvn1/route"‖epoch‖counter`)[:16] | Envelope `routing_tag` field (mailbox rendezvous) | Same class; **distinct domain** from ATSAM GhostRoute labels | `shared-vectors/rvn1/routing/*.json` — **REAL** | `protocol/reference/raven_protocol/routing_tag.py` |
| **Envelope auth** | Ed25519 | Authorship of immutable envelope fields + ciphertext hashes | Forgery / relay re-authoring | `shared-vectors/rvn1/envelope/`, negatives — **REAL** | `envelope.py`; device key per Identity V1 |
| **Identity / address** | Ed25519 → SHA-256[:20] → Bech32m HRP `rvn` | Self-sovereign addressing | Server-issued ID dependency | `shared-vectors/rvn1/address/`, `identities/` — **REAL** | `address.py`, `bech32m.py` |
| **BBE / Ghost Handshake / PV** | HMAC / (planned) Wegman-Carter | Discovery, live confirm, vault — **higher layers**, not required for Phase B DM | See public overview | Placeholder vectors under `raven-security/test-vectors/` | Mostly Stage-1 labels only; full layers incomplete |

---

## 3. Sealed content wire layouts (normative for implementers)

### 3.1 Magics (8 bytes, NUL-padded)

| Magic ASCII | Bytes (hex) | Role |
|---|---|---|
| `RVNA1\0\0\0` | `52 56 4E 41 31 00 00 00` | ATSAM sealed body |
| `RVNS1\0\0\0` | `52 56 4E 53 31 00 00 00` | Noise sealed body |
| `RVNH1\0\0\0` | `52 56 4E 48 31 00 00 00` | Noise handshake |
| `RVNP1\0\0\0` | `52 56 4E 50 31 00 00 00` | Explicit plaintext |

Outer envelope magic is **4-byte** `RVN1` = `52 56 4E 31` — different length and purpose.

### 3.2 RVNA1 v1 (accept only; do not emit)

```
magic(8) || proto=0x01 || suite=0x01 || nonce(12) || ciphertext || tag(16)
```

Key: deterministic HKDF from long-lived root + sender‖recipient‖msgId — **no forward secrecy**.

AAD (v1), exactly as `raven_core::atsam_aead::build_aad_v1` computes it and as
`aad_v1_hex` in `shared-vectors/rvn1/atsam/rvna1_v2_aead_known_root_001.json`
pins it:

```
AAD_v1 = SHA-256("ATSAM/v1/msg-seal/aad" || 0x00 || 0x00 || S || 0x00 || R || 0x00 || msgId)
```

The two leading zero bytes are the domain terminator and a zero separator (v1
binds no proto/suite/index). `S`, `R`, and `msgId` are the raw UTF-8 bytes of
the sender, recipient, and message-id strings, with no length prefix and no
terminator; the single `0x00` separators are the only delimiters (KAT:
`S = "alice"`, `R = "bob"`, `msgId = "msg-001"`).

### 3.3 RVNA1 v2 (emit)

```
magic(8) || proto=0x02 || suite=0x01 || index_be32(4) || nonce(12) || ciphertext || tag(16)
```

- AEAD: ChaCha20-Poly1305, max wire 256 KiB.
- Chain:
  - `CK₀ = HKDF(K_root, info="ATSAM/v2/chain-init"‖0‖S‖0‖R)`
  - `K_msg = HKDF(CK_i, salt="ATSAM/v2/msg-seal/salt", info="ATSAM/v2/msg-key"‖0‖S‖0‖R)` — **msgId is NOT in K_msg** (skipped-key cache cannot know future ids; Swift `ATSAMChainRatchet.messageKey` binds identity only; msgId is in AAD)
  - `CK_{i+1} = HKDF(CK_i, info="ATSAM/v2/chain-advance")`
- Bounds: `maxSkippedKeys = maxForwardJump = 256`.
- AAD (v2): `SHA-256("ATSAM/v1/msg-seal/aad" ‖ 0 ‖ proto ‖ suite ‖ index_be ‖ 0 ‖ sender ‖ 0 ‖ recipient ‖ 0 ‖ msgId)`.
  `proto` and `suite` are one byte each and `index_be` is the 4-byte big-endian
  chain index from the header (`build_aad_v2`; pinned by `aad_v2_hex`).
  `sender`, `recipient`, and `msgId` are encoded as in v1: raw UTF-8 string
  bytes, no length prefix, no terminator. Under the indexed-session profile
  (`0x03`) they are the canonical `RavenAddressV1` strings and the 36-character
  uppercase UUID text of the outer `message_id`
  ([`ATSAM_INDEXED_SESSION_PROFILE_V1.md`](ATSAM_INDEXED_SESSION_PROFILE_V1.md) §3).

RVNA1 v2's indexed byte layout is frozen, but its pre-profile session context
is ambiguous. It MUST NOT be silently treated as the indexed-session profile.
Production remains held unless the actual legacy v2 session was established
under an authenticated, mutually understood transcript.

### 3.4 RVNA1 `0x03` (indexed-session profile; production disabled)

The separately versioned
[`ATSAM_INDEXED_SESSION_PROFILE_V1.md`](ATSAM_INDEXED_SESSION_PROFILE_V1.md)
retains the indexed header and ChaCha20-Poly1305 construction but assigns
protocol byte `0x03`. It freezes canonical address context, transcript-role
directions, distinct message/ACK/route lanes, route allocation, uppercase UUID
AAD encoding, and the exact 101-byte signed / 143-byte sealed ACK.

`0x03` is intentionally not accepted by live classifiers. The additive
[`RAVEN_PAIR_INIT_V1.md`](RAVEN_PAIR_INIT_V1.md) codec negotiates
and transcript-binds profile identifier `ATSAM/indexed-session/v1`, but it and
this profile remain disabled pending the documented carrier/state gates. The
single recorded exception is the LAN-direct slice under the owner waiver
[`WAIVER-LAN-DIRECT-2026-10-07`](../docs/WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md), which keeps PairInit V1 and RVNA1 `0x03`
live for LAN direct between two `raven-node` services only; every other path
stays disabled.

### 3.5 Root (pairing)

```
ikm = Z_X || Z_PQ          # 32 ‖ 32
K_root = HKDF-SHA256(ikm, salt=transcript_hash,
                     info="ATSAM/v1/pair-init" || transcript_hash, L=32)
```

Transcript domain: `"ATSAM/v1/transcript"` prepended before SHA-256 (`ATSAMConstants.transcriptDomain`).

---

## 4. Binding: sealed frames ↔ RavenEnvelopeV1

**Normative binding (does not alter the 86-byte prefix):**

1. For `env_type = 1` (message), `message_ciphertext` MUST be a sealed content frame whose first 8 bytes are one of `RVNA1` / `RVNS1` / `RVNH1` (or, only for explicit degrade tests, `RVNP1`). Implementations MAY temporarily carry opaque test placeholders during codec vector tests; production sends MUST use a real sealer.
2. `ratchet_header_ciphertext` is opaque session metadata for the sealer (may be empty length `hdr_len=0` when the sealer encodes all needed state in the body, e.g. RVNA1 v2 index-in-body).
3. Base64 encoding of sealed frames is a **legacy MeshEnvelope / JSON** convenience. On the binary `RavenEnvelopeV1` wire, ciphertext fields are **raw bytes**.
4. Envelope pipeline stages 1–10 (`RAVEN_ENVELOPE_V1.md` §6) MUST succeed before any sealer decrypt. Signature verification does not imply plaintext recovery.
5. Flags bit0 (`hybridPQ`) SHOULD be set when the body is RVNA1 under a hybrid root; receivers MUST NOT treat the flag as authenticated proof of PQ (auth is the signature + sealer AAD).

**Migration note:** Until Phase G, iOS may still nest sealed frames inside `MeshEnvelope` JSON. Interop with `raven-node` requires packing the same frame bytes into `RavenEnvelopeV1`.

**Identity bind for serverless:** Phase B Rust SHOULD use `RavenAddressV1` (or raw 32-byte Ed25519 pub hex/bytes) in place of `userId` in AAD/chain-init, per Identity §4 constraints. Production send additionally requires an authenticated session transcript and persisted directional chain. A codec-compatible placeholder or demo AEAD is never an acceptable substitute for confidentiality.

**Unsafe interim stub (`proto=0x7F`):** Rust `raven-core::seal` and iOS `RavenInterimSeal` derive their AEAD key solely from public Ed25519 identities. Every observer can derive it. Default and release builds MUST reject it. Shipping ATSAM remains `0x01` (accept-only) / `0x02` (emit). A terminal without the authenticated session may relay a structurally bounded opaque frame but MUST NOT mark it delivered, persist plaintext, consume endpoint dedup state, or ACK it.

**Portable without ML-KEM:** Rust `raven-core::atsam_kdf` + `atsam_aead` match iOS chain labels / AAD / ChaCha20-Poly1305 for **known** `K_root` — see `shared-vectors/rvn1/atsam/chain_kdf_001.json` and `rvna1_v2_aead_known_root_001.json`. Network path without a root still classifies shipping ATSAM as opaque.

**iOS LAN + BLE (flagged):** `FeatureFlag.ravenEnvelopeV1` + `RavenServerlessLanPath` / `RavenBleRvn1Carrier`. MeshEnvelope remains default when the flag is off.

---

## 5. Honesty table — vectors

| Claim | Reality |
|---|---|
| Outer envelope pack/sign/verify | **Proven** by `shared-vectors/rvn1/envelope/*` + negatives |
| Address / fingerprint / ack / alias / caps / device cert / route tag | **Proven** under `shared-vectors/rvn1/` |
| Interim pairwise demo key (`0x7F`) | **Cryptographically unsafe by construction** — vector parity proves compatibility, not secrecy; production rejects it |
| ATSAM v2 chain HKDF labels (no AEAD) | **Proven** — `atsam/chain_kdf_001.json` (Rust `atsam_kdf` + Swift ratchet) |
| RVNA1 header layout classify | **Proven** — `atsam/rvna1_header_layouts_001.json` |
| RVNA1 v2 AEAD + AAD with **known** `K_root` | **Proven** — `atsam/rvna1_v2_aead_known_root_001.json` (Rust `atsam_aead`; no ML-KEM) |
| Indexed-session subkeys, allocator, and RVNA1 `0x03` ACK with known `K_root` | **Proven as deterministic KDF/codec bytes only** — `atsam/indexed_session_v1_*.json`; production disabled pending negotiated signed PairInit. No forward secrecy or post-compromise security inside a session (profile §2.4) |
| Signed offline PairInit, provisional root, and deferred key confirmation | **Proven as exact codec/KDF/signature bytes in Python, Rust, and Swift** — `atsam/pair_init_v1_001.json`; production disabled, carrier/endpoint-state/prekey-lifecycle/external review still open |
| Envelope body bytes are real ATSAM ciphertext | **False today** for envelope fixtures (ASCII placeholders); live iOS emits real RVNA1 |
| Rust decrypt without authenticated persisted session / ML-KEM pairing | **Not implemented** — network path relays opaque bytes and emits no endpoint ACK; KATs assume a supplied test `K_root` |
| `raven-security/test-vectors/pairing_root_vectors.json` | **Placeholder** |
| `bbe_discovery`, `live_confirmation`, `routing_tag` (security tree), `vault_mode` | **Placeholder** |
| iOS ATSAM unit tests | Exist for ratchet/pairing agreement; chain KDF shared with Rust |

Only the rows explicitly marked proven may be described as green. Placeholder
BBE/live-confirmation/vault fixtures and the production endpoint transaction
remain outside that claim.

---

## 6. KDF label catalog (stable strings)

Do not rename. Collision or rewrite invalidates sessions.

| Label | Use |
|---|---|
| `ATSAM/v1/pair-init` | Root HKDF info prefix |
| `ATSAM/v1/root` | Reserved second-stage root |
| `ATSAM/v1/BBE/discovery` | BBE discovery key |
| `ATSAM/v1/BBE/ratchet` | BBE epoch ratchet |
| `ATSAM/v1/BBE/pair-master` | Stable partition |
| `ATSAM/v1/BBE/slot` | Slot HMAC prefix |
| `ATSAM/v1/BBE/stable-partition-sort` | Sort HMAC prefix |
| `ATSAM/v1/GhostHandshake/live` | Live confirm key |
| `ATSAM/v1/GhostHandshake/response` | Response HMAC prefix |
| `ATSAM/v1/GhostRoute/recipient-tag` | Route tag key |
| `ATSAM/v1/GhostRoute/recipient` | Tag HMAC prefix |
| `ATSAM/v1/PV-Stealth/lookup` | Lookup tag key |
| `ATSAM/v1/ProximaVault/seed` | PV seed channel |
| `ATSAM/v1/msg-seal` | Msg-seal seed (v1 path) |
| `ATSAM/v1/msg-seal/aad` | AAD domain |
| `ATSAM/v1/ack-seal` | Indexed-profile ACK-lane base |
| `ATSAM/v1/GhostRoute/rvn1-direction` | Indexed-profile transcript-direction route subkey |
| `ATSAM/v2/chain-init` | Directional chain seed |
| `ATSAM/v2/msg-key` | Per-message key info |
| `ATSAM/v2/chain-advance` | One-way chain step |
| `ATSAM/v2/msg-seal/salt` | Msg-key HKDF salt |
| `ATSAM/v1/transcript` | Transcript domain separator |

Protocol (non-ATSAM) domains: `rvn1/ack`, `rvn1/alias`, `rvn1/devcert`, `rvn1/caps`, `rvn1/route`.

---

## 7. Phase B implementation guidance

1. Implement envelope/address/identity against `rvn1` first — gate for any network code.
2. Do not originate a two-node DM until a verified PairInit-derived root and
   protected directional ratchet are durably available. A shaped stub or
   known-root KAT is never a production substitute.
3. Persist outgoing queue encrypted at rest; never log private keys.
4. Prefer address-keyed session dirs from day one (`root|<rvn1…>`), with a commented migration path from `userId`.

---

## See also

- [`SPEC.md`](SPEC.md)
- [`RAVEN_ENVELOPE_V1.md`](RAVEN_ENVELOPE_V1.md) §7 Binding
- [`RAVEN_IDENTITY_V1.md`](RAVEN_IDENTITY_V1.md) §4
- `docs/THREAT_MODEL.md`
