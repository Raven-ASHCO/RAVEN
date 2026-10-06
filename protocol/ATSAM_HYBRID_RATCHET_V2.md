# ATSAM Hybrid Ratchet V2

**Profile identifier:** `ATSAM/hybrid-ratchet/v2`  
**Establishment:** **PairInit V2** / **PairResponse V2** (new wire; not PairInit V1)  
**Ratchet construction (normative):** Signal **Triple Ratchet** = EC **Double Ratchet** + **Sparse Post-Quantum Ratchet (SPQR)** over **ML-KEM Braid (SCKA)**; hybrid message key via `KDF_HYBRID(ec_mk, pq_mk)`  
**Suite (draft):** `0x01` = X25519 + ML-KEM-768 (FIPS 203) + HKDF-SHA256 / HMAC-SHA256 (as in Signal KDF recommendations) + ChaCha20-Poly1305 + Ed25519 (classical auth)  
**Document revision:** **10** (Full Braid lab §5.2: single-seal confirm AD, reject-vs-terminal, replay window; SCKA KDF byte tables; `pair_init_v2_002`)  
**Status:** **REQUIRED / NOT YET APPROVED** — draft companion under [`RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md`](RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md)  
**Approval prerequisites:** Umbrella **Approved** (met) + [`RAVEN_DEVICE_REVOCATION_V1.md`](RAVEN_DEVICE_REVOCATION_V1.md) **APPROVED** (met)  
**Production:** disabled

**Normative external specs (construction, not Raven wire):**

- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/) (Revision 4+; includes Triple Ratchet §6 and SPQR §5)
- [The ML-KEM Braid Protocol](https://signal.org/docs/specifications/mlkembraid/) (SCKA instantiation)

Raven adopts those **algorithms and state transitions**. Raven-specific domain strings, PairInit V2, AckV2, route/mailbox lanes, and durable transactions are defined here. This is **not** a custom “periodic Encaps” ratchet and MUST NOT inherit SPQR/PQ3 security claims by analogy alone.

**Umbrella invariants** remain binding. Companions cannot override them.

**Deferred to Carrier Conformance (non-blocking):** admit `expiry` must not extend signed object lifetime; digest≠bytes collision is hard error.

---

## 0. Normative decision: PairInit V2 (no silent upgrade)

### 0.1 Problem

PairInit V1 freezes profile ASCII `ATSAM/indexed-session/v1` under magic `RVPI1`. It MUST NOT be reinterpreted as hybrid-ratchet/v2.

### 0.2 Decision

| Artifact | Role |
|----------|------|
| PairInit / PairResponse **V1** | Compatibility parse → indexed-session/v1 only |
| PairInit / PairResponse **V2** | Sole establishment for `ATSAM/hybrid-ratchet/v2` |
| Indexed-session v1 | Lab/interop only |

Draft magics: `RVPI2` / `RVPR2`; `version=0x02`; profile exactly `ATSAM/hybrid-ratchet/v2` (23 ASCII bytes). Exact offsets frozen in `shared-vectors/rvn1/atsam/pair_init_v2_001.json` (`offsets.total_len` = **2787**).

### 0.3 Establishment outputs: `SK_ec` and `SK_scka`

PairInit V2 performs hybrid agreement (X25519 + ML-KEM-768) over the signed V2 transcript, producing shared material `IKM_pair`, then **splits** into Triple Ratchet inputs:

```text
transcript_hash = SHA-256("ATSAM/v2/transcript" || "ATSAM/v2/pair-init" || complete_PairInit_V2_wire)
init_hash_v2    = SHA-256("ATSAM/v2/pair-init" || complete_PairInit_V2_wire)

IKM_pair = Z_X || Z_PQ          # after encapsulate → sign wire → hash → finalize

SK_ec || SK_scka || K_route_master || K_confirm =
    HKDF-SHA256(
        IKM  = IKM_pair,
        salt = transcript_hash,
        info = "ATSAM/hybrid-ratchet/v2" || 0x00 || "pair-expand" || transcript_hash,
        L    = 32 + 32 + 32 + 32
    )

session_id = SHA-256("ATSAM/v2/pair-session" || init_hash_v2)
```

| Output | Use |
|--------|-----|
| `SK_ec` (32) | `RatchetInitAlice` / `RatchetInitBob` EC Double Ratchet input |
| `SK_scka` (32) | `RatchetInitAliceSCKA` / `RatchetInitBobSCKA` input |
| `K_route_master` (32) | **Stable** route/mailbox lane (§10); MUST NOT change with DH/PQ ratchets |
| `K_confirm` (32) | PairResponse V2 confirmation MAC key |

Alice MAY seal application message 0 under Triple Ratchet state after local init, before PairResponse (provisional). Confirmation does not rewrite historical `endpoint_object_bytes`.

`Z_X` MAY use Bob’s OTP X25519 when present (else SPK) for PairInit agreement only. Initial EC ratchet key remains **SPK** (§3.3).

Order: encapsulate → build/sign PairInit V2 → hash → expand. No substitute-transcript API.

---

## 1. Threat model and security properties

### 1.1 In scope

| Goal | Claim (narrow) |
|------|----------------|
| Confidentiality vs classical network adversary | AEAD under Triple Ratchet hybrid keys |
| **Harvest-now / decrypt-later** | Hybrid Triple Ratchet: attacker must break **both** EC and ML-KEM paths to distinguish message keys (`KDF_HYBRID`) after recording ciphertext |
| Classical FS | EC Double Ratchet + deletion of message/chain keys |
| Classical PCS | After **attacker access ends**, fresh EC DH ratchet entropy heals EC state |
| PQ FS / sparse PQ PCS | Via ML-KEM Braid SCKA as analyzed with Triple Ratchet; healing requires successful SCKA epoch progress after compromise ends |
| Authentication (classical) | Ed25519 device signatures + cert/contact/revocation gates |
| Delivery | Only verified sealed **AckV2** advances Delivered/Read |

### 1.2 Explicit non-claims

1. **No active-quantum authentication.** Ed25519 is not PQ-safe. An interactive quantum adversary that forges classical signatures / breaks device auth is **out of scope** until a future PQ-signature profile exists.
2. **No PCS while compromise is ongoing.** Healing requires attacker access to end **and** subsequent honest entropy (EC DH and/or SCKA epochs) to enter the session.
3. **No claim that “periodic Encaps” equals Triple Ratchet.** Raven uses the published construction.
4. Relays/mailboxes remain untrusted for decrypt, ACK, and Delivered.

### 1.3 Adversaries (summary)

Network (drop/reorder/inject), past device dump, ongoing device compromise (no heal until access ends), harvest-now quantum recorder. Active quantum forger of classical auth: out of scope.

---

## 2. Version / profile negotiation

```text
session_context = UTF8("ATSAM/hybrid-ratchet/v2") || 0x00
               || ASCII(initiator_address) || 0x00
               || ASCII(responder_address)
```

Hard reject: PairInit V1 as V2; wrong profile/suite; noncanonical addresses; dual interpretation.

---

## 3. Role-separated state machines

A single lifecycle that mixes initiator journaling with responder OTP claim is incorrect. Roles are immutable from PairInit V2.

### 3.1 Initiator (Alice)

```text
ABSENT
  → LOCAL_PENDING_INIT
        (exact PairInit V2 bytes journaled for exact retry;
         NO OTP claim — Alice does not own Bob’s one-time prekey)
  → PROVISIONAL_TR
        (SK_ec/SK_scka/K_route_master derived;
         Triple Ratchet Alice-init performed;
         message 0 MAY be sealed)
  → CONFIRMED
        (PairResponse V2 verified: init_hash, confirmation tag, device sig)
  → ACTIVE
        (first verified peer Triple Ratchet application frame accepted
         OR local policy mark after CONFIRMED + ready to send non-msg0;
         see §3.4)
  → BLOCKED / REVOKED / CLOSED
```

### 3.2 Responder (Bob)

```text
ABSENT
  → AUTH_PREFLIGHT_OK
        (in-memory only: strict parse + trust gates §3.2.1;
         NO durable OTP claim; NO session row; invalid input → ABSENT)
  → OTP_CLAIMED_PENDING
        (durable atomic OTP / PairInit claim AFTER §3.2.1 succeeds;
         exact PairInit V2 bytes journaled;
         then decapsulation / SK_* derivation)
  → PROVISIONAL_TR
        (Triple Ratchet Bob-init; mint exact PairResponse V2;
         cache response for duplicate completion)
  → CONFIRMED_LOCAL
        (PairResponse durably committed + cached)
  → ACTIVE
        (per §3.4)
  → BLOCKED / REVOKED / CLOSED
```

#### 3.2.1 Authenticated preflight before OTP claim (normative)

Durable OTP claim and ML-KEM / X25519 decapsulation MUST NOT run until **all** of the following succeed, in order:

1. Strict canonical parse (fixed length, magic/version/suite/profile, no trailing bytes).
2. Local **contact** membership for the initiator identity (fail-closed if absent/blocked).
3. Device certificate validation for both sides as required by PairInit V2.
4. Current local **revocation** decision (fail-closed if revoked).
5. Outer / initiator-device signature verify over the exact signed prefix.
6. Expiry / validity window checks (`created_at` / `expires_at` vs now and cert/prekey windows).
7. Exact prekey-bundle binding (ids, pubs, OTP slot consistency, bundle digest).

On any failure: leave **no** OTP claim, **no** session state, **no** journal. This prevents OTP poisoning via malformed or unauthenticated PairInit.

Contact delete/block/revoke → fail-closed for send/receive/PairInit/ACK on that device.

### 3.3 Initial Triple Ratchet keys (frozen intent)

**EC initial ratchet key (Signal-aligned):** Bob’s **signed X25519 prekey (SPK)** is always the initial EC Double Ratchet public/keypair (`bob_dh_public_key` / `bob_dh_key_pair`). This matches Signal PQXDH→Double Ratchet integration (`SPKB` → initial ratchet key).

**OTP role:** If a one-time X25519 prekey is present, it MAY contribute to PairInit `Z_X` / `IKM_pair` only. It MUST NOT be the initial EC ratchet key. OTP private material is consumed under prekey lifecycle after authenticated claim (§3.2.1); it is not retained as `DHs`.

| Role | EC init | Private material retained |
|------|---------|---------------------------|
| **Alice** | `RatchetInitAliceTR(..., bob_dh_public_key = SPK_B)` | Alice’s EC ratchet private `DHs`; SPQR Alice state; not Bob’s OTP |
| **Bob** | `RatchetInitBobTR(..., bob_dh_key_pair = SPK_B keypair)` | SPK private until later DH ratchet replaces `DHs`; PairInit ML-KEM DK used once for `Z_PQ`; SPQR Bob state |

Normative Triple Ratchet init (**role-specific SCKA**, Signal §5.4 — not a role-neutral `RatchetInitSCKA`):

```text
RatchetInitAliceTR(state, SK_ec, SK_scka, bob_dh_public_key):
    RatchetInitAlice(state.ec_state, SK_ec, bob_dh_public_key)   # SPK_B
    RatchetInitAliceSCKA(state.spqr_state, SK_scka)
    # SCKAInitAlice; direction A2B;
    # KDF_SCKA_INIT → (RK, CKs, CKr); send=CKs, receive=CKr

RatchetInitBobTR(state, SK_ec, SK_scka, bob_dh_key_pair):
    RatchetInitBob(state.ec_state, SK_ec, bob_dh_key_pair)       # SPK_B pair
    RatchetInitBobSCKA(state.spqr_state, SK_scka)
    # SCKAInitBob; direction B2A;
    # KDF_SCKA_INIT → (RK, CKr, CKs)  # note CK reorder
    # send=CKs, receive=CKr
```

Implementations that call a single role-neutral SCKA init are **non-conformant** (divergent send/receive chains).

**Message 0 (Alice):** encrypted with `RatchetEncryptTR` on `PROVISIONAL_TR` after Alice-init. Header carries Alice’s EC ratchet public and SPQR/SCKA send chunks per ML-KEM Braid. Plaintext is application (or padding); it is **not** PairResponse.

**PairResponse V2:** key confirmation only (not Delivered). Uses `K_confirm`:

```text
confirmation_tag = HMAC-SHA256(
    K_confirm,
    "ATSAM/v2/pair-init/confirm" || 0x00 || init_hash_v2
)
```

### 3.4 `CONFIRMED` → `ACTIVE`

`ACTIVE` means Triple Ratchet send/receive of application frames (including AckV2) is permitted under normal policy.

| Transition | Condition |
|------------|-----------|
| Alice | `CONFIRMED` after verifying PairResponse V2; MAY mark `ACTIVE` immediately thereafter |
| Bob | After `CONFIRMED_LOCAL` (response cached/committed); MUST be `ACTIVE` before accepting non-PairInit application ciphertext into inbox |
| Both | Blocked/revoked sessions MUST NOT enter or remain `ACTIVE` |

### 3.5 Duplicate PairInit (responder)

On a second delivery of the **exact** same PairInit V2 bytes (same `init_hash_v2`) after successful claim/init:

1. MUST NOT reclaim OTP.
2. MUST NOT re-run ML-KEM decapsulation for a new root.
3. MUST NOT reset Triple Ratchet state.
4. MUST return the **exact cached** PairResponse V2 bytes (exact retry).
5. Different PairInit bytes that collide on OTP id follow prekey-lifecycle reject/accept rules; they MUST NOT silently replace an established session.

---

## 4. Triple Ratchet (normative construction)

### 4.1 Composition

```text
ec_mk  ← EC Double Ratchet (X25519 DH + symmetric chains)
pq_mk  ← SPQR / SCKA chains (ML-KEM Braid epochs)
mk     ← KDF_HYBRID(ec_mk, pq_mk)     # AEAD key material
```

Encrypt/decrypt use Signal `RatchetEncryptTR` / `RatchetDecryptTR` control flow: obtain both message keys + composite header, then AEAD with `mk`.

### 4.2 Authenticated preflight, then candidate AEAD (Raven hardening)

Wire headers (EC DH public, `PN`/`N`, SCKA chunks, epochs) are **attacker-controlled until AEAD succeeds**. DH/SCKA work MUST NOT run on unauthenticated outer input.

Receive path MUST:

1. Strict framing / size limits on the envelope and sealed body.
2. Outer trust gates **before** candidate ratchet work: local contact, device certificate, revocation, outer envelope/device signature, TTL/expiry as applicable.
3. Compute `object_digest = SHA-256(endpoint_object_bytes)`. If a committed inbound **message** dedup row already exists for that digest:
   - MUST NOT advance Triple Ratchet again;
   - MUST re-queue the **exact retained AckV2 bytes** for that source (§11.4) onto the outbound carrier path;
   - then stop (idempotent with respect to inbox/ratchet, not a silent drop of ACK retransmission).
   If a committed inbound **AckV2** dedup row exists for that digest → idempotent success / stop (no ACK-of-ACK).
4. Select bounded session candidates via route lane (§10); load durable head for the chosen session.
5. Clone a **candidate** Triple Ratchet state (EC + SPQR + MKSKIPPED).
6. Run TR receive key derivation **only on the candidate** (skipped-key try, possible DH ratchet, SCKA Receive, hybrid mk).
7. `DECRYPT` with candidate `mk`. On **any** failure: discard candidate; **zero** durable mutation; **zero** in-memory promotion.
8. On success: branch by inner type into §11.1 (application message) or §11.2 (AckV2).

Implementations that mutate the live head before AEAD, or that run candidate DH/SCKA before steps 1–3, are non-conformant even if they “roll back on error.”

### 4.3 Loss / reorder / replay (EC + SCKA)

| Event | Behavior |
|-------|----------|
| EC out-of-order | `PN`/`N` + `MKSKIPPED` per Double Ratchet; `MAX_SKIP` bound |
| SCKA loss/reorder | ML-KEM Braid Send/Receive epoch rules; chunks may arrive sparse; `sending_epoch` / `receiving_epoch` govern which PQ chain key applies |
| Concurrent EC + SCKA updates | Composite header carries both; hybrid mk ties both; no Raven-specific “merge RK with ss_PQ” shortcut |
| Replay | After successful commit, `(session_id, ec_dh_pub, N, scka_epoch, scka_ctr)` accept once |
| Dropped messages vs PCS | Dropped traffic delays healing; does not authorize skipping AEAD or mutating on guess |

### 4.4 Compromise windows (informal; proofs external)

| Secret exposed | Exposed traffic (intent) |
|----------------|--------------------------|
| Single EC message key | That message only (if erased after use) |
| EC chain key | Future EC mk until DH ratchet heals **and** access ends |
| SCKA decapsulation key for epoch e | Secrets for that Braid epoch until epoch FS deletion rules fire; PCS after later epochs mix per ML-KEM Braid / Triple Ratchet analysis |
| Both EC and SCKA roots at time T | Hybrid security lost for keys derived until **both** sides heal after access ends |

Exact formal statements: Signal Triple Ratchet + ML-KEM Braid papers/specs. Raven MUST NOT invent stronger claims.

---

## 5. ML-KEM Braid / SCKA lifecycle (adopted, not reinvented)

Raven’s SPQR **is** ML-KEM Braid as SCKA inside Triple Ratchet. Normative answers:

| Question | Answer |
|----------|--------|
| One-time vs reusable PQ keys | Braid epochs use KEM keypairs per protocol rules; decapsulation keys are **epoch-scoped**, not a single long-lived `peer_pq_ek` for ad-hoc Encaps |
| Who generates the next key | Alternating Braid roles per epoch (header → ct parallelization per Braid spec) |
| When private keys delete | Per Braid/SPQR clearing past epoch state after FS window; Raven MUST implement secure deletion |
| Concurrent rekeys | Epoch identifiers totally order SCKA outputs; Triple Ratchet uses `sending_epoch`/`receiving_epoch` for chain selection |
| Loss/reorder/replay | Handled by Braid message types + SPQR skipped maps; Raven adds AEAD + durable idempotency |
| Decap key compromise | Limits exposure to dependent epochs until subsequent honest epochs; not “all future forever” if PCS progresses |

**Forbidden:** Raven-only `Encaps(peer_pq_ek)` into `HKDF(ss_PQ \|\| RK)` as the PQ story.

ML-KEM-768 MUST track FIPS 203 final (+ errata). Braid `PROTOCOL_INFO` / Raven `SPQR_PROTOCOL_INFO` constants are profile-specific (§6).

### 5.1 Braid chunk wire + message types (pre–Full Braid freeze)

Raven freezes the following **before** Full Signal Braid incremental Encaps1/Encaps2 + erasure coding. Status remains **REQUIRED / NOT YET APPROVED**.

**Epoch type (normative):** `EPOCH_TYPE = u64`. Wire encoding is **big-endian u64** (`ToBytes`). Implementations **MUST NOT wrap** on increment; advancing past `2^64-1` is fail-closed. This matches Signal’s recommendation and Raven route/mailbox `u64` epoch usage.

**Chunk frame (experimental lab codec, header 23 bytes):**

```text
magic(8="RVBC1\0\0\0") || epoch_u64be(8) || type_u8(1) || index_u32be(4) || plen_u16be(2)
|| payload(plen) || binding_digest_sha256(32)
```

Exact length: `wire.len == 23 + plen + 32`. Trailing bytes rejected. Binding digest is **canonical binding only** (not a MAC); authentication remains outer signature then AEAD.

**Resource caps (default conforming receiver):**

| Cap | Value |
|-----|-------|
| `BRAID_MAX_TOTAL_PAYLOAD_BYTES` | 8192 |
| `BRAID_MAX_PAYLOAD` (per chunk) | **8192** (MUST equal total budget so encoder cannot emit frames a default receiver rejects) |
| `BRAID_MAX_CHUNKS_PER_EPOCH` | 64 |
| `session_id` | exactly 32 bytes (encode/decode/binding) |

**ML-KEM-768 object sizes (Signal; Full Braid target):** Header=`64`, `EK_VECTOR_SIZE=1152`, CT1=`960`, CT2=`128`. The complete FIPS 203 encapsulation key is `FIPS_EK` (**1184**) = `ek_vector` (1152) ‖ `ρ` (32), **not** Header (64) ‖ `ek_vector`. The incremental Header (64) = `ρ` ‖ `H(FIPS_EK)`, where `H` is SHA3-256. Compressed libcrux 0.0.10 key-buffer layout: `ek_vector` starts at byte offset 1152; Header starts at byte offset 2304 and occupies 64 bytes; `z` follows. Do not treat 1152 as the full EK.

**Seven message types (normative names/roles from Signal ML-KEM Braid):**

| Code | Type | Payload rule |
|------|------|----------------|
| 0 | `None` | MUST be empty; `chunk_index` MUST be `0` |
| 1 | `Hdr` | MUST be non-empty erasure chunk of 64-byte header |
| 2 | `Ek` | MUST be non-empty erasure chunk of **ek_vector** (1152) |
| 3 | `EkCt1Ack` | MUST be non-empty erasure chunk of ek_vector; sender has completely received CT1 |
| 4 | `Ct1Ack` | MUST be empty; `chunk_index` MUST be `0`; sender has completely received CT1 |
| 5 | `Ct1` | MUST be non-empty erasure chunk of 960-byte CT1 |
| 6 | `Ct2` | MUST be non-empty erasure chunk of 128-byte CT2 |

Full Braid MUST still implement incremental `KeyGen → Encaps1 → Encaps2 → Decaps`, real erasure recovery from any sufficient chunk set, the Signal state machine, and dense negatives (duplicate/loss/reorder/tamper/epoch-wrap/caps).

**Epoch width in pre–Full Braid stubs:** the frozen KAT stubs (composite TR header / AAD in `tr_hybrid_aead_001`, the SCKA `AcceptKey` packing in `tr_replay_duplicate_001`) keep their frozen 4-byte epoch fields. They are superseded by the u64be epochs of RVBC1/RVCH1/RVFB1 and MUST reject (never truncate or wrap) any epoch ≥ 2^32. In-memory SCKA epochs are u64 everywhere and every increment is checked.

### 5.2 Full Braid lab engine (lab-only; `full-braid-lab`)

These rules are normative for the lab engine (`hybrid_ratchet_v2_full_braid`, Python `full_braid_*`) and pinned by `full_braid_*` vectors. Lab wire may still change; production stays disabled.

**RVFI1 init (§3.3).** `SK_ec` is only the EC root key. Alice's `role_material` is her ephemeral EC ratchet private key: `RatchetInitAlice(SK_ec, role_material, SPK_B)`. Bob's `role_material` is the SPK private key (checked against `bob_spk_pub`): `RatchetInitBob(SK_ec, SPK_B keypair)`. A root key MUST NOT double as a DH private key. Bob has no EC sending chain until he receives Alice's first EC message, so an encapsulator Bob cannot run the nested confirm before that; such a Send is rejected without commit and the host sends without the confirm.

**Nested TR confirm (single seal).** The encapsulator seals at most one confirm per SCKA epoch, on the HeaderReceived Send that emits the first CT1 frame, and places `RVCH1 || sealed_ct` in RVBO1 next to that frame:

```text
AD = u32be_len(RVBA1) || RVBA1 || u32be_len(RVCH1) || RVCH1 || u32be_len(RVBC1) || RVBC1
RVBC1 = the encapsulator's first CT1 frame of the epoch (type CT1, index 0)
(key, nonce) = KDF_HYBRID(ec_mk, scka_mk)      # scka_mk = KDF_OK epoch secret
```

The keygen side opens **exactly those `sealed_ct` bytes** on the Receive whose CT2 chunk completes Decaps. It rebuilds the AD's RVBC1 from the decapsulated CT1 (systematic chunk 0, binding over the peer's direction), not from the CT2 frame it is processing. Each `(ec_mk, scka_mk)` therefore produces exactly one ciphertext; resealing under the same key with a different AD is forbidden (it reuses the ChaCha20-Poly1305 nonce, §6.4).

**Failure semantics (§4.2 step 7).** Everything that can be caused by unauthenticated input is a no-commit **Reject** (`ERR_PARSE`, zero durable mutation): a chunk whose index is already stored with a different payload, RVCH1/EC header validation (DH, `MAX_SKIP`, skipped-key budget), confirm seal mismatch, and AEAD open failure. Terminal states are reserved for authenticator MAC failure on a reassembled HDR/CT2 source, ML-KEM failures, and explicit repair/expiry. EC skipped keys are bounded by the RVFT1 cap (1000) **before** any AEAD, so an accepted message is always encodable.

**Chunk emission.** Chunk indices live in `[0, 64)`. A sender's cursor cycles through that space instead of stalling after 64 Sends in one state; re-sent indices carry identical deterministic payloads and are decoder no-ops at the receiver. `EkSentCt1Received` emits `Ct1Ack` (pinned SPQR behaviour).

**Durable pipeline.** Replay records are a FIFO window in commit order (oldest first, unique transition ids). On each commit the oldest records are evicted so that at most `min(64, cap_replay_entries, floor(cap_replay_bytes / 102))` remain, the new record included; a window of 0 is `ERR_NEED_CAPACITY`. The `input_digest` persisted in RVBJ1/RVOR1 is `SHA-256("ATSAM/v2/full-braid/input" || RVBI1')`, where RVBI1' is the input with any mode-0 (seal_compare) plaintext body replaced by the same number of zero bytes; `expected_ct` still binds the plaintext, but retained evidence no longer allows offline plaintext confirmation. `terminalize_conflict` repairs only when the live state contradicts the journaled intent (same or older generation, or the next generation reached through a different transition); a stale journal for a session that has advanced further returns `ERR_CAS`.

**Lab C ABI.** Output buffers and out-parameters MUST NOT overlap inputs or each other; an overlapping call returns `ERR_PARSE` and writes nothing. Inputs longer than `RAVEN_FB_MAX_RVBJ1` are `ERR_PARSE` before any slice is formed. Secret-bearing lab state (RVFB1 auth keys, TLVs, RVFT1, RVBE1 seeds, RVFI1, RVBM1 bodies) is wiped on drop and redacted from debug output.

---

## 6. KDFs — published interfaces, Raven domain strings

Raven instantiates Signal’s **named** functions. Ellipses are not normative. Exact `info` bytes and lengths freeze in §14 vectors; until then this section defines the **contract**.

### 6.1 Protocol info constants (frozen)

```text
TR_PROTOCOL_INFO   = "ATSAM/hybrid-ratchet/v2" || 0x00 || "TR"
SPQR_PROTOCOL_INFO = "ATSAM/hybrid-ratchet/v2" || 0x00 || "SPQR"
EC_RK_INFO         = "ATSAM/hybrid-ratchet/v2" || 0x00 || "EC-KDF-RK"
SCKA_INIT_INFO     = SPQR_PROTOCOL_INFO || 0x00 || "SCKA-INIT"
```

Catalog: `shared-vectors/rvn1/atsam/tr_domain_labels_001.json`.
### 6.2 EC Double Ratchet (Signal §3 / §7.2)

```text
KDF_RK(rk, dh_out) -> (rk', ck):
    # HKDF-SHA256: salt=rk, IKM=dh_out, info=EC_RK_INFO, L=64
    # rk' || ck = first 32 || last 32

KDF_CK(ck) -> (ck', mk):
    # HMAC-SHA256(ck, 0x01) -> mk
    # HMAC-SHA256(ck, 0x02) -> ck'
    # If ck is None: hard fail
```

`GENERATE_DH` / `DH`: X25519. Non-contributory shared secrets MUST be rejected in Raven even if some classical DR notes omit the check.

### 6.3 SPQR / SCKA KDFs (Signal §5 / §7.2)

Use Signal’s `KDF_SCKA_INIT`, `KDF_SCKA_RK`, `KDF_SCKA_CK` with `SPQR_PROTOCOL_INFO` and recommended salts/lengths from Double Ratchet Rev 4 §7.2. Vector suite MUST pin every byte; ports match vectors, not prose memory. The exact instantiation (pinned by `tr_scka_init_001`, `tr_braid_epoch_001`, `full_braid_*`):

```text
KDF_SCKA_INIT(SK_scka) -> (RK, CK_A2B, CK_B2A):
    # HKDF-SHA256: salt = 32×0x00, IKM = SK_scka, info = SCKA_INIT_INFO, L = 96
    # RK = okm[0:32], CK_A2B = okm[32:64], CK_B2A = okm[64:96]
    # Alice: send = CK_A2B, recv = CK_B2A;  Bob: send = CK_B2A, recv = CK_A2B

KDF_SCKA_RK(rk, epoch_secret) -> (rk', ck):
    # HKDF-SHA256: salt = rk, IKM = epoch_secret, info = SPQR_PROTOCOL_INFO, L = 64
    # rk' = okm[0:32], ck = okm[32:64]; all-zero epoch_secret is a hard fail

KDF_SCKA_CK(ck) = KDF_CK(ck)          # §6.2: HMAC(ck, 0x01) → mk, HMAC(ck, 0x02) → ck'

epoch_secret (Full Braid) = KDF_OK(ML-KEM shared secret, epoch)
    # pinned SPQR: HKDF info "Signal_PQCKA_V1_MLKEM768:SCKA Key" || u64be(epoch)
```

SCKA epochs are `EPOCH_TYPE = u64` (§5.1); chain counters are u32. Every increment is checked and overflow is a hard fail.

### 6.4 Hybrid message key

```text
KDF_HYBRID(ec_mk, scka_mk) -> aead_key_material:
    # HKDF-SHA256: salt=scka_mk, IKM=ec_mk, info=TR_PROTOCOL_INFO,
    # L = key length required by ChaCha20-Poly1305 (32) [+ nonce policy below]
```

**AEAD:** ChaCha20-Poly1305. **Frozen nonce policy:** `KDF_HYBRID` with `L=44` → `aead_key(32) || nonce(12)`. Never reuse under the same key.

### 6.5 What this section deliberately removes

Prior draft normative-looking forms `HKDF(IKM = DH_out || RK, …)` and `HKDF(IKM = ss_PQ || RK, …)` are **rejected**. They are not the published Double/Triple Ratchet contracts.

---

## 7. Headers, AAD, and AckV2

### 7.1 Decision: ACK is a Triple Ratchet application message

There is **no** independent symmetric ACK chain from a frozen root.

**AckV2** is an application record encrypted with `RatchetEncryptTR` under the same Triple Ratchet as chat messages (distinct inner type byte). It therefore receives every relevant EC DH and SCKA epoch that advances message keys.

### 7.2 Composite header (logical)

| Field class | Content |
|-------------|---------|
| EC header | `dh_pub`, `PN`, `N` |
| SPQR/SCKA | Braid chunks / epoch fields required by Send |
| Clear envelope | RVN1/successor outer fields; no session secrets |

New sealed proto/version for this profile (not silent reuse of indexed `0x03`) — exact byte frozen with vectors.

### 7.3 AAD

AEAD AD MUST bind: profile, `session_id`, suite/proto, transcript direction addresses, EC `(dh_pub,N)` and SCKA epoch/ctr used for `mk`, sender device cert digest class, and header bytes as required by TR.

Frozen stub byte layout (pinned by `tr_hybrid_aead_001`; the Full Braid lab uses the RVBA1‖RVCH1‖RVBC1 AD of §5.2 instead):

```text
header = "ATSAM/v2/tr-header" || u8(SEALED_PROTO) || dh_pub(32) || u32be(PN) || u32be(N)
      || u32be(sending_epoch) || u32be(receiving_epoch) || u32be(send_ctr)
      || u8(chunk_flags) || kem_ct_digest(32)
AD     = "ATSAM/v2/aad" || "ATSAM/hybrid-ratchet/v2" || u8(0x01 suite) || u8(SEALED_PROTO)
      || u8(direction) || session_id(32) || ASCII(initiator_address) || 0x00
      || ASCII(responder_address) || sender_device_cert_hash(32) || dh_pub(32)
      || u32be(N) || u32be(sending_epoch) || u32be(send_ctr) || header
```

The u32 epoch fields are the frozen stub width (§5.1): values ≥ 2^32 are rejected.

### 7.4 AckV2 plaintext (logical; exact layout in vectors)

```text
acked_message_id(16)
|| acked_object_digest(32)      # SHA-256(endpoint_object_bytes) of acked object
|| status(u8)                   # 1=delivered, 2=read
|| ack_nonce(12)
|| created_at_ms(u64be)
|| recipient_device_binding     # cert digest or device pub class
|| session_id(32)
|| inner_ed25519_signature(64)
```

Inner signature covers all prior AckV2 fields under domain `"ATSAM/v2/ack"`.

Exact frozen layout (197 bytes; `tr_ackv2_001`): `acked_message_id(16) || acked_object_digest(32) || status(u8) || ack_nonce(12) || u64be(created_at_ms) || recipient_device_cert_hash(32) || session_id(32) || ed25519_signature(64)`; the signature is over `"ATSAM/v2/ack"` followed by the first 133 bytes.

**Multi-path cancel** keys on `acked_object_digest` (and matching outbound row), not `message_id` alone.

Mint AckV2 only after §11 transaction completes (umbrella ACK-after-commit). Transport success MUST NOT mint AckV2.

---

## 8. Out-of-order, skipped keys, replay

1. EC `MAX_SKIP`: draft default 1000; hard fail beyond.
2. SPQR skipped maps: per Signal SPQR bounds; Raven MUST set finite limits.
3. Skipped keys expire by deterministic events (messages/epochs), then secure-delete.
4. Exact-byte duplicate objects → idempotent (§12), not second accept.

---

## 9. Multi-device session binding

Sessions bind PairInit V2 device certificates/pubs. New device ⇒ new PairInit V2. Revocation fail-closed (Revocation companion). No silent session clone across devices.

---

## 10. Route and mailbox lane (pre-decrypt session select)

### 10.1 Why a stable lane

Endpoint MUST select a **device-pair session candidate set** before Triple Ratchet decrypt. Evolving `RK` / SCKA roots MUST NOT be required to predict routing tags for unseen messages.

### 10.2 Stable keys

`K_route_master` from §0.3 is fixed for the life of the session (until CLOSE/REVOKE).

```text
K_route[d] = HKDF-SHA256(
    IKM  = K_route_master,
    salt = 32×0x00,
    info = "ATSAM/hybrid-ratchet/v2" || 0x00 || "route" || 0x00 || u8(d),
    L    = 32
)
```

`d` is transcript direction (0 initiator→responder, 1 reverse).

### 10.3 Per-object routing tag

For sealed application/AckV2 envelopes with clear `created_at_ms`, EC chain index `N`, env/app type, direction `d`:

```text
epoch   = floor(created_at_ms / 1000)
counter = (u64(N) << 8) | (u64(app_type) << 1) | u64(d)
routing_tag = HMAC-SHA256(
    K_route[d],
    "ATSAM/v2/route" || u64be(epoch) || u64be(counter) || session_id
)[:16]
```

`app_type` is 7 bits (`app_type & 0x7f`): `0x01` application message, `0x02` AckV2, others reserved. `d` is 1 bit. Pinned by `tr_route_mailbox_001`.

### 10.4 Out-of-order candidate lookup

Receiver MAY test routing tags for `N' ∈ [N_expected, N_expected + ROUTE_LOOKAHEAD]` with frozen `ROUTE_LOOKAHEAD = 32` (not `MAX_SKIP`) across sessions bound to the sending device. **Candidate session cap:** draft `MAX_SESSION_CANDIDATES = 8` per peer device. Exceeding → drop/fail-closed for that object (no unbounded trial decrypt).

Trial decrypt still uses §4.2 candidate state; failed trials must not mutate.

### 10.5 Daily mailbox tags and catch-up polling

```text
day_epoch = floor(unix_ms / 86_400_000)
mailbox_tag[d] = HMAC-SHA256(
    K_route[d],
    "ATSAM/v2/mailbox" || u64be(day_epoch) || u64be(d) || session_id
)[:16]
store_tag[d] = SHA-256("raven/relay-tag/v1" || mailbox_tag[d])[:16]
```

Mailbox addresses remain predictable from `K_route_master` without knowing current ratchet heads. Opaque store deletion remains TTL/errata-bound; AckV2 alone does not authorize store delete.

**Polling MUST NOT be limited to “today and yesterday” only, and MUST NOT permanently close mutable day buckets.** Each endpoint persists:

- `catchup_cursor_day[session_id, d]` — highest **fully enumerated historical** day (all pages completed);
- optional page cursor within the day being enumerated.

On each poll cycle:

1. Let `today = floor(now_ms / 86_400_000)`.
2. Let `ttl_horizon = today - mailbox_TTL_days` (store policy; objects older than TTL are gone).
3. Let `late_arrival_floor = today - MAILBOX_LATE_ARRIVAL_DAYS` with frozen `MAILBOX_LATE_ARRIVAL_DAYS = 7` (re-poll the late-arrival window for skew/late writes). Mutable **current day** is always re-polled and is **never** advanced past by the historical cursor alone.
4. Historical catch-up range: every day epoch `e` with  
   `max(catchup_cursor_day + 1, ttl_horizon) ≤ e ≤ today - 1`  
   (and any day in `[late_arrival_floor, today-1]` not yet fully paged in this cycle). The catch-up horizon MUST cover the **complete mailbox TTL** (`ttl_horizon`), not a shorter fixed cap such as 14 days. A draft `MAILBOX_CATCHUP_MAX_DAYS` MAY exist only as an implementation scheduling throttle **within one wake**; unfinished TTL days remain due and MUST continue on later wakes until `catchup_cursor_day` reaches `today - 1` or TTL expires them.
5. For each historical day `e` under catch-up: fetch **all pages** before treating the day complete. Advance `catchup_cursor_day` to `e` only after the last page succeeds. Partial page failure MUST NOT advance the cursor.
6. Separately, always re-poll `today` (and days in the late-arrival window) with page cursors that may reset each cycle; success here MUST NOT set `catchup_cursor_day = today` in a way that skips future late writes to that bucket while the day is still “current” or inside the late-arrival window.
7. If the device was offline longer than TTL, objects older than TTL are gone by store policy — not a protocol bug. Remaining valid objects inside TTL MUST still be reachable via steps 3–6.

---

## 11. Recoverable transactions (crash ordering)

**Forbidden:** finalize an advanced ratchet head before the corresponding SQL commit (burns mk / loses message or breaks outbox). **Forbidden:** key rollback or mk reuse. Recovery is always **roll-forward**. Network I/O is always **outside** the mutation lease.

Shared preamble after §4.2 AEAD success (still no durable head write):

```text
Write protected PENDING journal:
  {session_id, generation_prev, candidate_state_blob,
   object_digest, exact_object_bytes, direction=inbound|outbound,
   inner_type=message|ackv2, intent fields...}
```

### 11.1 Inbound application message (not AckV2)

```text
1. §4.2 preflight + candidate AEAD success; inner type = message
2. PENDING journal (inbound, message)
3. SQL transaction (atomic):
     receipt row
   + inbox / plaintext metadata
   + dedup(object_digest)
   + ACK-intent row in state Pending
     (source_message_digest bound; no AckV2 bytes yet)
4. Protected FINALIZED head = candidate; generation := generation_prev+1
5. Clear PENDING journal
6. Later: materialize exact AckV2 via §11.4
7. Network send of retained AckV2 OUTSIDE lease
```

Plaintext MUST NOT be UI-visible as accepted until step 3 commits. AckV2 MUST NOT be sealed until an ACK-intent exists; materialize follows §11.4 (`PENDING_ACK_SEND` before CAS).

### 11.2 Inbound AckV2 (separate branch — no ACK-of-ACK)

```text
1. §4.2 preflight + candidate AEAD success; inner type = AckV2
2. PENDING journal (inbound, ackv2)
3. Parse AckV2 plaintext (status ∈ {1,2}, time window, session_id,
   field layout, acked_object_digest / acked_message_id present).
4. Cryptographically verify inner Ed25519 signature over the canonical
   AckV2 signing bytes (domain "ATSAM/v2/ack" || fields per §7.4)
   using the public key of the authenticated outer sender device.
   Layout checks alone are insufficient.
5. Require that authenticated outer sender device == intended recipient
   device bound on the outstanding outbound row for acked_object_digest
   (exact device binding; mismatch → hard reject).
6. SQL transaction (atomic):
     INSERT UNIQUE(session_id, ack_sender_device, ack_nonce)
       where ack_sender_device is the authenticated outer sender device
       # conflict → replay: idempotent no-op or reject; no second CAS effect
   + receipt/dedup for this AckV2 object_digest
   + CAS delivery state on that outstanding outbound row per lattice:
       Queued|Sent → Delivered     (status=1)
       Queued|Sent|Delivered → Read (status=2)
   # Outcome rule (single freeze): any ACK that would not raise delivery
   # rank (same status, lower status, or Read→Delivered) MUST leave SQL
   # state unchanged and return explicit result replay_or_downgrade_ignored.
   # Ports MUST NOT hard-fail the TR receive solely for that case if AEAD
   # and signature already succeeded; ratchet commit still follows success
   # path only when this AckV2 object_digest is newly accepted for dedup.
   # Never apply a downgrade mutation.
   # MUST NOT insert inbox row
   # MUST NOT insert ACK-intent   (no ACK-of-ACK)
7. Protected FINALIZED head = candidate; generation := generation_prev+1
8. Clear PENDING journal
9. No automatic outbound AckV2
```

If steps 3–5 fail (bad signature, no outstanding row, digest mismatch, device mismatch, bad status): discard candidate and journal; **zero** head promotion; hard reject (or idempotent no-op only when exact duplicate AckV2 object already committed). UNIQUE nonce conflict without a new digest accept MUST NOT advance delivery twice.

### 11.3 Outbound application message (normal send)

```text
1. Clone live head → candidate send state
2. RatchetEncryptTR on candidate → exact endpoint_object_bytes
   (header + AEAD ciphertext); compute object_digest
3. PENDING journal (outbound, message):
     {generation_prev, candidate_state_blob after send ratchet,
      object_digest, exact_object_bytes, outbox intent}
4. SQL transaction (atomic):
     outbox / stage row (exact bytes + digest + session binding)
   + outbound outstanding map for later AckV2 CAS
     (includes intended recipient device binding)
5. Protected FINALIZED head = candidate; generation := generation_prev+1
6. Clear PENDING journal
7. Network admit/send OUTSIDE lease; retries use exact bytes (§12)
```

Crash between seal and finalize: roll-forward from journal (bytes already fixed); never reseal with a new mk.

### 11.4 Outbound AckV2 materialize, retain, and send (exact ACK recovery)

SQL and the protected ratchet store are **not** one shared atomic transaction. Ordering MUST tolerate crash between them via roll-forward only. CAS to `Materialized` MUST NOT precede durable exact ACK bytes.

ACK-intent states: `Pending` → `Materialized` (terminal for seal). Exactly one successful materialization per intent.

Under the cross-process / session **mutation lease**:

```text
1. Acquire session mutation lease.
2. Load ACK-intent.
   - If state == Materialized: first inspect for a matching
     PENDING_ACK_SEND journal (§11.5). If present (SQL committed before
     protected head finalize), roll-forward: finalize journaled candidate,
     clear journal, then continue at step 8 with retained exact bytes.
     If no journal, skip to step 8 using retained exact bytes
     (no new seal / no ratchet).
   - If state == Pending: continue at step 3.
3. Clone live head → candidate send state; seal AckV2 (RatchetEncryptTR)
   → exact_ack_endpoint_object_bytes; ack_object_digest =
   SHA-256(exact bytes). Intent remains Pending.
4. Write protected PENDING_ACK_SEND journal:
     {session_id, intent_id, source_message_digest,
      generation_prev, candidate_state_blob after seal,
      ack_object_digest, exact_ack_endpoint_object_bytes}
5. SQL transaction (atomic):
     CAS intent Pending → Materialized
   + insert/upsert ACK outbox row with
       source_message_digest, ack_object_digest,
       exact_ack_endpoint_object_bytes
   # If CAS loses: abort SQL changes for this worker; go to step 5b
5b. CAS loss: discard candidate; delete/ignore this worker’s
    PENDING_ACK_SEND if present; release lease; MUST NOT finalize head;
    MUST NOT advance send ratchet. Winner’s retained bytes remain authoritative.
6. On CAS win: finalize protected ratchet head = candidate;
   generation := generation_prev+1.
7. Clear PENDING_ACK_SEND journal.
8. Release mutation lease.
9. Network admit/send OUTSIDE lease using retained exact bytes.
10. Transport success MUST NOT delete the materialized ACK.
    Retain exact bytes until the source message’s receipt / replay horizon
    expires (aligned with inbound dedup TTL for source_message_digest).
11. Duplicate inbound delivery of the committed source message (§4.2):
    re-queue the same retained exact ACK bytes; do not create a new intent,
    do not CAS Pending again, do not advance the send ratchet again.
```

**Forbidden window:** `Materialized` with absent exact ACK bytes and old ratchet head. Achieved by sealing + `PENDING_ACK_SEND` **before** CAS, and by requiring SQL outbox insert of exact bytes in the same SQL transaction as CAS.

Recovery (roll-forward only):

| Crash | Action |
|-------|--------|
| After seal, before/during PENDING_ACK_SEND | Discard incomplete journal; intent still Pending; another attempt may seal under lease (prior candidate unused) |
| PENDING_ACK_SEND present, SQL incomplete | Re-read journal; retry SQL CAS+outbox with journaled exact bytes (**do not reseal**) |
| SQL Materialized+outbox done, head not finalized | Finalize head from journal candidate; then clear journal |
| Head finalized, journal not cleared | Clear journal if head matches |
| Materialized + bytes retained, network pending | Exact-byte retry |
| CAS lost after local seal | Step 5b: no head promotion |

Two workers: lease serializes seal attempts; CAS ensures only one `Materialized` row and only the winning path finalizes head. A losing CAS never consumes a committed send-ratchet step.

### 11.5 Recovery matrix

| Crash boundary | Recovery |
|----------------|----------|
| PENDING written, SQL incomplete | Re-read journal; complete the matching §11.1 / §11.2 / §11.3 / §11.4 SQL; never reuse keys |
| SQL done, head not finalized | Finalize head from journal candidate |
| Head finalized, journal not cleared | Clear journal if head matches |
| Finalized / Materialized, network not done | Exact-byte retry from outbox or retained AckV2 row |
| Duplicate source message after Materialized ACK | Re-queue retained exact AckV2 bytes only |
| §11.4 CAS lost after local seal | Discard candidate/journal; no head promotion |

Generation decrease on load is a hard security failure.

---

## 12. Exact retry and duplicates

1. Pending PairInit V2 / message / AckV2 → resend exact `endpoint_object_bytes`.
2. No rebuild of `init_id`, KEM CT, AEAD nonce, or ciphertext.
3. Duplicate exact digest after commit:
   - inbound message → re-queue retained exact AckV2 (§4.2 / §11.4);
   - inbound AckV2 → idempotent success / stop.
4. Same `message_id`, different bytes → hard reject.
5. Duplicate PairInit → §3.5.

---

## 13. Shared vectors (Python / Rust / Swift)

| Class | Path / status |
|-------|----------------|
| `pair_init_v2_001` | Wire + expand + confirm — **frozen**; codec + expand KAT only: its `Z_X` is injected from the hybrid KAT and its prekey digest is not a RavenPrekeyBundleV1 digest, so it is **non-conformant for trust binding** |
| `pair_init_v2_002` | Trust-binding KAT: `Z_X = X25519(eph, OTP)` over the wire keys, identity-signed RavenPrekeyBundleV1 digest, dedicated device X keys; supersedes `_001` for trust binding |
| `full_braid_full_exchange_2pq_2dh_001` | Full Braid lab: 2 PQ epochs, 4 nested confirms (each receive opens the peer's exact `sealed_ct`), 2 DH ratchets — lab-only |
| `full_braid_rvfi1_init_001` | Full Braid lab: RVFI1 → initial RVFB1 for both roles (Python-computed; §3.3 EC keys) — lab-only |
| `negative/pair_init_v1_as_v2_001` | V1≠V2 — **frozen** |
| `tr_domain_labels_001` | Domain/info catalog — **frozen** |
| `tr_ec_kdf_001` | `KDF_RK` / `KDF_CK` — **frozen** |
| `tr_scka_init_001` | Alice/Bob SCKA init — **frozen** |
| `tr_hybrid_aead_001` | `KDF_HYBRID` + AEAD — **frozen** |
| `tr_ackv2_001` | AckV2 + `acked_object_digest` — **frozen** |
| `tr_candidate_fail_001` | Candidate AEAD fail-closed — **frozen** |
| `tr_crash_ack_cas_001` | PENDING_ACK_SEND before CAS — **frozen** (ordering KAT only; not durable crash/restart proof) |
| `tr_braid_epoch_001` | SCKA promote + CK reorder — **partial** (ss injected; superseded for KEM path by `tr_braid_kem_chunk_001`) |
| `tr_ec_ooo_001` | Same-chain OOO — **partial** (see `tr_ec_dh_ratchet_001` for DH) |
| `tr_ec_dh_ratchet_001` | EC DH transition + PN/N + cross-boundary skip + all-zero reject — **in progress** |
| `tr_braid_kem_chunk_001` | Chunk codec + ML-KEM CT reassembly/tamper/dk-zero + SCKA promote from KAT `z_pq` — **in progress** (not full Signal incremental Encaps1/2 + erasure code) |
| `tr_braid_codec_negatives_001` | Strict wire (header 23 / epoch u64); session_id=32; encode max=8192; empty-type payload; MKSKIPPED cap; binding role — **in progress** |
| `tr_combo_multi_001` | ≥2 DH + ≥2 SCKA hybrid steps — **in progress** |
| `tr_skip_boundary_001` / `tr_replay_duplicate_001` / `tr_tamper_candidate_001` / `tr_route_mailbox_001` | Stateful matrix — **in progress** |
| `tr_crash_*` (receive/skip/epoch/ack_cas) | Ordering machines — **KAT only**; not durable store proof |
| Remaining (blocking APPROVED) | Full Signal ML-KEM Braid incremental Encaps1/2 + erasure coding; durable crash/restart evidence on persistent store; independent review + human APPROVED |

Frozen constants: `SEALED_PROTO=0x04`, `MAX_SKIP=1000`, `ROUTE_LOOKAHEAD=32`, `MAILBOX_LATE_ARRIVAL_DAYS=7`, hybrid L=44 (key32‖nonce12), SCKA init shared expand + role CK swap; braid `EPOCH_TYPE=u64be`, header=23, `BRAID_MAX_PAYLOAD=BRAID_MAX_TOTAL_PAYLOAD_BYTES=8192`, `session_id=32`.

**Status remains `REQUIRED / NOT YET APPROVED`.** Crash ordering fixtures MUST NOT be cited as durability implementation proof.

Reference: `protocol/reference/raven_protocol/{pair_init_v2,hybrid_ratchet_v2,hybrid_ratchet_v2_state}.py`, `generate_hybrid_ratchet_v2.py`.

Negatives: PairInit V1 as V2; mutate-on-bad-header; role-neutral SCKA init; OTP claim before auth; ACK-of-ACK intent; CAS-before-seal Materialized-without-bytes; dual ACK materialize; route from evolving RK; poll-only yesterday; advance day cursor mid-page; drop ACK on transport success; AckV2 layout-only “verify”; delivery downgrade.

---

## 14. Formal / differential verification

1. Differential Python/Rust/Swift on §13.
2. Construction security inherits Triple Ratchet + ML-KEM Braid analyses **only** if algorithms match; Raven domain strings are a labeled instantiation.
3. Independent review **or** recorded owner waiver (umbrella §9.1) before Release.
4. Custom PQ ratchet would have required its own proof — **not applicable** under this revision’s Triple Ratchet decision.
5. KAT-alone insufficient.

---

## 15. Migration from indexed-session V1

| Topic | Rule |
|-------|------|
| Parse V1 | Allowed for lab indexed profile only |
| Silent upgrade | Forbidden |
| Route labels | New `ATSAM/v2/route` domains; no cross-import of indexed `K_root` chains into TR |
| Codecs | New proto; no overload of indexed `0x03` without explicit revision |
| Flags | Default off |

---

## 16. Production holds

### 16.1 Cannot APPROVE until

1. Revocation companion APPROVED;
2. PairInit V2 bytes + §13 vectors complete across languages;
3. No open P0 on role-SCKA init, authenticated OTP claim, candidate decrypt order, AckV2 vs message commits, outbound send journal, PENDING_ACK_SEND-before-CAS materialize, AckV2 digest, route/mailbox catch-up;
4. Human approval in header.

### 16.2 Cannot enable production flags until

Companion APPROVED + umbrella §9–§10 for carriers; lab indexed/A2 not rebranded as TR.

### 16.3 Document control

| Field | Value |
|-------|-------|
| Created | 2026-08-16 |
| Revision | **10** (Full Braid lab rules §5.2; SCKA KDF byte tables §6.3; exact stub AAD/AckV2 layouts; `pair_init_v2_002`). Rev 9: bidirectional payload rules; empty-type `chunk_index=0`; `EK_VECTOR_SIZE=1152` vs FIPS EK 1184 |
| Status | **REQUIRED / NOT YET APPROVED** |
| Next | Full Signal Braid incremental Encaps1/Encaps2 + erasure coding; durable restart evidence; independent review; then human APPROVED |
| Explicitly not next | Production flags; PairInit V1 reinterpret; marking APPROVED before Remaining §13 items close |

**Frozen in rev9 (no longer open as “next”):** PairInit V2 offsets; `MAX_SKIP` / `ROUTE_LOOKAHEAD=32` / `MAILBOX_LATE_ARRIVAL_DAYS=7`; sealed proto `0x04`; AEAD nonce = hybrid L=44 trailing 12; SCKA init shared expand + role CK swap; AckV2 plaintext layout (197 bytes); EC DH transition KATs; braid exact-length decode; encode/reassembly/MKSKIPPED caps; **epoch=u64be**, **header=23**, **session_id=32**, **BRAID_MAX_PAYLOAD=BRAID_MAX_TOTAL_PAYLOAD_BYTES=8192**; seven Braid message types with bidirectional payload rules + empty-type `chunk_index=0`; **`EK_VECTOR_SIZE=1152`** / FIPS EK `1184`; combo multi-msg matrix (partial vs full Signal Braid).

**Still open (blocks APPROVED):** Full Signal ML-KEM Braid incremental Encaps1/2 + erasure coding; durable crash/restart on persistent store; independent review; human approval.
