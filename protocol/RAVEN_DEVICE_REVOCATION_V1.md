# RAVEN Device Revocation V1

**Version:** 1
**Document revision:** **6** (exhausted retains exact claim; anchored exhausted marker; corrupt journal state)
**Record:** `RavenDeviceRevocationV1`
**Status:** **APPROVED** — companion under [`RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md`](RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md) (umbrella Document revision 2 permits bare public RVDR1)
**Approved:** 2026-08-16 — human/protocol-owner approval (independent technical review PASS: Py 11/11, Rust 10/10, Swift 12/12, clippy `-D warnings`)
**Approval prerequisites:** Umbrella **Approved** (met)
**Unblocks:** [`ATSAM_HYBRID_RATCHET_V2.md`](ATSAM_HYBRID_RATCHET_V2.md), [`RAVEN_ID_RESOLUTION_V1.md`](RAVEN_ID_RESOLUTION_V1.md) (their remaining gates still apply)
**Production:** **disabled** — companion APPROVED does not enable production/Release flags; umbrella §9–§10 and per-surface gates still required

This document freezes **signed device revocation**: how an identity retires a device lineage, how verifiers apply a sticky local deny decision, and what partitions can and cannot guarantee. It supersedes the “no dedicated revocation record” gap in [`RAVEN_IDENTITY_V1.md`](RAVEN_IDENTITY_V1.md) §2.1 for V2 production paths. Certificate issuance remains in Identity V1 (`RavenDeviceCertificateV1` has **no** certificate-generation field; this companion MUST NOT assume one).

**Umbrella invariants** remain binding. Companions cannot override them.

**Non-claim:** There is **no instant global revoke**. A partitioned verifier that has not received a revocation remains able to trust a still-unexpired certificate until it learns otherwise.

---

## 1. Threat model

### 1.1 Goals

| Goal | Meaning |
|------|---------|
| Authorized retire | Only the owning **identity** Ed25519 key MAY mint a revocation for its devices |
| Sticky deny | An accepted revocation **never disappears** because a newer record arrives |
| Fail-closed apply | Once any covering revocation is accepted, crypto paths for that lineage fail closed |
| Eventual propagation | Revocations travel as ordinary endpoint objects; inventory/sync MAY help |
| Fork honesty | Concurrent valid owner mints may equivocate on metadata; **both** deny targets still apply |
| Partition honesty | Eventual consistency only; no push-to-all guarantee |

### 1.2 Non-goals

- Revoking an entire Raven identity / address.
- Server CRL / OCSP.
- PQ signatures.
- Automatic session healing after revoke (close; re-pair on a **new** device lineage).
- Using unsigned network gossip to authorize devices or clear revocations.

### 1.3 Adversaries

Network drop/reorder/inject; malicious relay withholding; stale views; compromised **device** keys; compromised **identity** key (can forge revokes — out-of-band recovery).

---

## 2. Device lineage target (normative)

A revocation permanently retires a **complete device lineage**, not merely the latest cert-hash row.

### 2.1 Covered identifiers

Every accepted record permanently denies **all** of:

| Identifier | Rule |
|------------|------|
| `device_id` | Exact bytes; MUST NOT be reused on a replacement device |
| `device_ed_pub` | MUST NOT be reused |
| `device_x_pub` | MUST NOT be reused |
| `device_cert_hash` | Exact PairInit-family cert digest of the retired certificate |

`device_cert_hash` continues to use:

```text
SHA-256(
  "rvn1/pair-devcert"
  || identity_ed25519_pub(32)
  || RavenDeviceCertificateV1.signing_bytes
  || certificate_signature(64)
)
```

### 2.2 Replacement device

A replacement MUST use a **new** `device_id` **and** new Ed25519 **and** new X25519 keys, with a new certificate. Reusing any of `{device_id, device_ed_pub, device_x_pub}` after revoke is a protocol violation; verifiers MUST treat such certs as unauthorized even if signatures verify.

### 2.3 `device_id` encoding

| Rule | Value |
|------|-------|
| Encoding | UTF-8 |
| Length | nonempty; **1..64** bytes (UTF-8 byte length, not Unicode scalars) |
| Wire | `u16be` length + exact bytes (`lp` with 2-byte BE length) |
| Equality | Exact byte compare; no Unicode normalization |

---

## 3. Wire record (frozen offsets)

Magic `RVDR1\0\0\0`, `version = 0x01`, `suite = 0x01`. Variable-length `device_id` / `issuer_device_id` use `u16be` length **1..64**.

For the frozen fixture `device_id = "bob-device-1"` (12 bytes) and `issuer_device_id = "alice-primary"` (13 bytes):

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 8 | magic `RVDR1\0\0\0` |
| 8 | 1 | version = `0x01` |
| 9 | 1 | suite = `0x01` |
| 10 | 44 | `identity_address` ASCII |
| 54 | 2 | `device_id` length |
| 56 | 12 | `device_id` UTF-8 |
| 68 | 32 | `device_ed_pub` |
| 100 | 32 | `device_x_pub` |
| 132 | 32 | `device_cert_hash` |
| 164 | 2 | `issuer_device_id` length |
| 166 | 13 | `issuer_device_id` UTF-8 |
| 179 | 8 | `issuer_seq` u64be |
| 187 | 16 | `revocation_id` |
| 203 | 1 | `reason_code` |
| 204 | 8 | `created_at_ms` u64be |
| 212 | 64 | identity Ed25519 signature |
| **276** |  | **total length** (`offsets.total_len` in `valid_001.json`) |

**Signing bytes:**

```text
"rvn1/device-revocation" || version || suite
  || identity_address
  || lp(device_id) || device_ed_pub || device_x_pub || device_cert_hash
  || lp(issuer_device_id) || u64be(issuer_seq)
  || revocation_id || u8(reason_code) || u64be(created_at_ms)
```

Wire body without magic/signature equals `signing_bytes` without the domain prefix. Signed by the **identity** key for `identity_address`.

Hard reject: unknown version/suite, noncanonical address, id length out of range, zero `revocation_id`, bad signature, trailing bytes, and any fixed-size field that runs past the end of the input. The minimum-length check assumes 1-byte ids, so a long `device_id` / `issuer_device_id` with a short tail passes it; decoders MUST bounds-check every field after each `lp` read and return an error (never read out of range or abort).

Vectors: `shared-vectors/rvn1/device_revocation/valid_001.json`, `shared-vectors/rvn1/negative/device_revocation_wrong_signer.json`, `shared-vectors/rvn1/negative/device_revocation_long_id_short_tail.json`.

---

## 4. Digests and packaging (frozen for V1)

### 4.1 Two digest domains

| Name | Definition | Used by |
|------|------------|---------|
| `revocation_record_bytes` | Exact signed `RavenDeviceRevocationV1` wire | Endpoint crypto |
| `claim_digest` | `SHA-256(revocation_record_bytes)` | Endpoint claim dedup / deny-set keys after verification |
| `endpoint_object_bytes` | Bytes admitted to carriers as the application object | Umbrella object identity |
| `object_digest` | `SHA-256(endpoint_object_bytes)` | Carriers, inventory, multi-path cancel |

Carriers MUST use **`object_digest` only** and remain opaque. Claim-level dedup by `claim_digest` MAY occur **only after** endpoint verification of `revocation_record_bytes`.

### 4.2 Propagation packaging (V1 choice)

**Frozen:** for Device Revocation V1, `endpoint_object_bytes = revocation_record_bytes` (bare `RVDR1` record), as an umbrella **immutable authenticated public endpoint record** ([umbrella Document revision 2](RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md)).

Consequently `object_digest = claim_digest` **under this packaging only**. Implementations MUST still compute and name both digests so a future packaging revision can wrap the record without collapsing domains.

**Disclosure (intentional non-confidentiality):** bare RVDR1 exposes identity address, `device_id`, both device public keys, cert hash, issuer device id, reason code, and timestamps to any carrier observer. This is an explicit design choice so revocation can propagate without a pairwise session. V1 does **not** claim confidentiality of revocation metadata. Sealed-envelope wrapping remains out of scope for V1 and would need a new revision + vectors.

---

## 5. Accept model: append-only union (no sequence safety gate)

Revocation is **deny-only and irreversible**. A valid identity-signed claim MUST be applied to the deny-set even if another claim shares an `issuer_seq` or arrives “out of order.”

### 5.1 Safety predicate

**Apply if and only if** the record passes §3 parse + identity signature + optional cert consistency (§5.3).

**Do not** use `issuer_seq` (or any global sequence) to drop a valid deny claim. `issuer_seq` is for issuer-local ordering, sync hints, and fork/equivocation **reporting** only.

### 5.2 Append-only store layout

Persist separately:

1. **`revoked_targets`** — append-only set of denied lineage keys under `identity_address`:
   - by `device_id`
   - by `device_ed_pub`
   - by `device_x_pub`
   - by `device_cert_hash`
   - each entry references `claim_digest`, `revocation_id`, `applied_at_ms`, `exact_record_bytes` (or content-addressed blob)

2. **`claims_by_digest`** — map `claim_digest → exact_record_bytes` (idempotent insert).

3. **`issuer_heads`** — optional metadata `(identity_address, issuer_device_id) → {highest_issuer_seq, claim_digest, fork_flags}` for UX/sync. Updating heads MUST NOT delete or shrink `revoked_targets`.

**Invariant:** accepting claim B with a “newer” `issuer_seq` MUST NOT remove targets introduced by claim A. An older revoked certificate MUST remain denied forever once applied.

### 5.2.1 Quotas and exhaustion (append-only)

Append-only stores are bounded. Draft defaults (freeze with vectors / deployment profile):

| Quota | Draft default |
|-------|----------------|
| Max claims per `identity_address` | 10_000 |
| Max total claim bytes per identity | 32 MiB |
| Max global claims (optional) | implementation-defined ≥ sum of per-identity caps |
| Emergency metadata reservation | Separate from claim quotas; MUST hold `IDENTITY_REVOKE_EXHAUSTED` rows (with `claim_digest` + content-addressed exact bytes), `REVOCATION_STORE_CORRUPT` markers, and related journal metadata per affected identity |

On insert that would exceed a **claim** quota (§6.1.1 transitions to `PENDING_REVOKE_EXHAUSTED` / durable exhausted marker — not an ambiguous keep-or-clear of `PENDING_REVOKE`):

1. MUST NOT evict or compact away any existing `revoked_targets` / claims.
2. MUST reject applying the new claim into the deny-set until capacity is expanded and the claim is replayed (§6.1.3).
3. MUST fail-closed **authorization for that identity namespace** while an exhausted marker is present (treat all its devices as unauthorized for PairInit/envelope/ACK/bind).
4. MUST surface exhaustion to logs/UX.

A malicious contact that floods valid signed claims therefore Deny-DoS’s **that identity’s** accept path, not other identities’ stores (unless a global cap is hit — then process-wide revoke-apply fail-closed until expanded).

### 5.3 Cert consistency (when local cert known)

If the verifier holds a certificate matching `device_cert_hash`, then `device_id`, `device_ed_pub`, and `device_x_pub` in the revocation MUST match that cert. Mismatch → reject this claim (do not apply a confused revoke). Absence of the cert is OK — still apply the signed lineage deny.

### 5.4 Idempotency and forks

Authoritative claim identity is **`claim_digest`**. `revocation_id` is issuer hygiene and observability only — **not** a safety gate.

| Case | Action |
|------|--------|
| Same `claim_digest` again | Idempotent success |
| Same `revocation_id`, different bytes, **both** validly identity-signed | **Union-apply both** deny targets; record `revocation_id` **collision/equivocation**; never leave the second target trusted |
| Different valid claims, overlapping or distinct targets | **Union-apply** all targets |
| Two valid claims, same `(identity, issuer_device_id, issuer_seq)`, different `claim_digest` | Surface **equivocation/fork**; **still union-apply both** |
| Unsigned gossip / relay hint | MUST NOT authorize a device, clear a signed revoke, or remove deny-set entries |

Owners SHOULD still mint unique `revocation_id` values; collisions are treated as equivocation signals, not as permission to drop a valid deny.

### 5.5 Local policy vs signed state

- **Local contact/device block** MAY always deny access even when a certificate is cryptographically valid and unrevoked.
- **Unsigned** network or local cache data MUST NOT authorize a device, MUST NOT clear signed revocations, and MUST NOT lower signed revocation state.
- Signed revoke accept only **adds** deny coverage (monotonic deny).

### 5.6 Authorization check

A peer device is **locally authorized** for PairInit / envelope / ACK / Noise expected-bind only if **all** hold:

1. Local contact policy allows the identity (and does not block that device);
2. A valid `RavenDeviceCertificateV1` verifies and is inside `[not_before, not_after)`;
3. None of `{device_id, device_ed_pub, device_x_pub, device_cert_hash}` appear in `revoked_targets` for that identity;
4. No durable `IDENTITY_REVOKE_EXHAUSTED` marker is active for that identity (§6.1.3);
5. No durable `REVOCATION_STORE_CORRUPT` marker is active for the store scope that covers that identity (§6.0 / §6.2).

Natural cert expiry remains a backstop when no revocation has been learned yet.

---

## 6. Apply transaction (fail-closed, durable first)

SQL and protected storage are not one atomic cross-store transaction. Ordering MUST roll-forward. **Anti-rollback anchors live in protected storage**, not only inside SQL. The mutation lease is **non-reentrant**.

### 6.0 Load / recovery order (before any idempotent lookup)

On process start or before applying/serving authorization:

```text
1. If REVOCATION_STORE_CORRUPT marker is set → fail closed for that store
   scope; do not apply; await explicit repair (§6.2).
2. If PENDING_REVOKE or PENDING_REVOKE_EXHAUSTED exists:
     a. Acquire mutation lease (unless already held by crash recovery).
     b. Re-read exact_bytes from the journal.
     c. Strict-parse; recompute claim_digest; verify identity signature,
        identity_address binding, and optional cert consistency (§5.3).
        A protected journal alone is NOT proof of verification.
        On re-verify failure:
          write durable REVOCATION_STORE_CORRUPT
            {scope, journal_kind, observed_digest_or_none, reason}
            via SQL generation bump + FINALIZED_REVOKE_ANCHOR
            (emergency metadata capacity);
          only then clear the corrupt journal;
          fail closed until explicit repair — never “clear and forget”.
     d. If journal kind == PENDING_REVOKE (re-verify OK):
          apply_verified_revoke_under_existing_lease(
            exact_bytes, pending_already_written=true)
        If journal kind == PENDING_REVOKE_EXHAUSTED (re-verify OK):
          ensure_exhausted_anchored(exact_bytes) per §6.1.3
            (SQL marker + FINALIZED_REVOKE_ANCHOR if missing);
          MUST NOT auto-insert the claim;
          MUST NOT clear PENDING_REVOKE_EXHAUSTED here;
          MUST NOT treat this as a normal apply retry loop
            (expand+replay uses convert→PENDING then helper).
     e. Release lease if acquired here.
3. Read protected FINALIZED_REVOKE_ANCHOR {generation, store_hash} if present.
4. Read SQL revocation_store_generation / compute SQL store_hash.
5. Compare:
   - missing SQL after a finalized anchor existed → fail closed
   - SQL generation < anchor.generation OR hash mismatch → fail closed (rollback)
   - no anchor + empty SQL:
       allowed ONLY if this is a true first install
       (no pre-existing identity/security namespace on device).
       If any identity/security namespace already exists → fail closed
       (missing anchor is not “fresh empty”).
6. Only then perform claims_by_digest lookups or §5.6 checks
   (exhausted / corrupt markers still fail-close authorization).
```

### 6.1 Public entry: acquire lease then apply

For inbound verified claims **without** a pre-held lease:

```text
apply_verified_revoke(exact_bytes):
  1. §6.0 recovery/anchor checks as needed
  2. Acquire identity/revocation mutation lease
  3. claim_digest = SHA-256(exact_bytes)
  4. If claims_by_digest has claim_digest:
       reconcile_idempotent_claim(claim_digest)   # §6.1.2
       Release lease; return idempotent success
  5. Write PENDING_REVOKE journal
       {claim_digest, exact_record_bytes, generation_prev, store_hash_prev}
  6. apply_verified_revoke_under_existing_lease(
       exact_bytes, pending_already_written=true)
  7. Release lease
  8. Network I/O (if fan-out) OUTSIDE lease — never required for local deny
```

### 6.1.1 Helper: `apply_verified_revoke_under_existing_lease`

**Preconditions:** caller **already holds** the mutation lease; `exact_bytes` have been **cryptographically verified in this call path** (or just re-verified per §6.0); if `pending_already_written=true`, `PENDING_REVOKE` already matches `exact_bytes` / `claim_digest`.

**MUST NOT** reacquire the lease. **MUST NOT** overwrite an existing matching `PENDING_REVOKE` / `PENDING_REVOKE_EXHAUSTED`.

```text
apply_verified_revoke_under_existing_lease(
    exact_bytes,
    pending_already_written = false):

  claim_digest = SHA-256(exact_bytes)

  if claims_by_digest has claim_digest:
    reconcile_idempotent_claim(claim_digest)
    if pending_already_written: clear PENDING_REVOKE if it matches
    return idempotent success   # caller releases lease

  if not pending_already_written:
    write PENDING_REVOKE {claim_digest, exact_bytes, generation_prev, store_hash_prev}
  else:
    require PENDING_REVOKE.claim_digest == claim_digest
      and PENDING_REVOKE.exact_bytes == exact_bytes

  if insert would exceed §5.2.1 claim quotas:
    # Single frozen transition — exact claim bytes MUST survive:
    atomically replace PENDING_REVOKE with PENDING_REVOKE_EXHAUSTED
      {claim_digest, exact_bytes, identity_address, generation_prev, reason=quota}
    # PENDING_REVOKE_EXHAUSTED is STABLE until expand+replay succeeds.
    # Do NOT clear it after writing the SQL marker.
    ensure_exhausted_anchored(exact_bytes):  # §6.1.3
      SQL transaction (atomic, emergency metadata capacity):
        upsert IDENTITY_REVOKE_EXHAUSTED {
          identity_address,
          claim_digest,
          exact_record_bytes OR content_addressed_blob_ref,
          reason=quota
        }
        # exact bytes MUST be recoverable from marker blob and/or
        # PENDING_REVOKE_EXHAUSTED — both MUST agree on claim_digest
      + bump revocation_store_generation
      + store_hash includes exhausted-marker material
      Write protected FINALIZED_REVOKE_ANCHOR {generation, store_hash}
    return resource_exhaustion
    # Deny-set unchanged; authorization fail-closed via exhausted marker.
    # Normal recovery MUST NOT auto-retry claim insert (no infinite loop).

  SQL transaction (atomic):
    insert claim blob keyed by claim_digest
  + append lineage keys into revoked_targets
  + update issuer_heads / fork / revocation_id-collision metadata
  + upsert required CLEANUP_REVOKE work items (§6.3)
  + bump revocation_store_generation
  + store SQL copy of revocation_store_hash = H(canonical snapshot)

  Write protected FINALIZED_REVOKE_ANCHOR:
    {generation = new generation, store_hash = same H(...)}
  # MUST succeed before journal clear.

  Clear PENDING_REVOKE.
  return applied
  # Caller releases lease. Deny is live from SQL+anchor.
```

After a successful `applied` return, §5.6 MUST fail closed for newly denied lineage **immediately**. While `IDENTITY_REVOKE_EXHAUSTED` is set, §5.6 fails closed for the **entire** identity namespace.

### 6.1.2 Idempotent reconcile

When `claim_digest` is already present, **do not** merely release:

1. Ensure `FINALIZED_REVOKE_ANCHOR` matches SQL generation/hash for current store; if SQL has the claim but anchor is behind/missing → roll-forward anchor write from current SQL commitment under lease.
2. Ensure all required §6.3 cleanup work items for that claim’s lineage exist; upsert any missing items.
3. Clear a stale matching `PENDING_REVOKE` if present.
4. Then return idempotent success.

### 6.1.3 Exhaustion automaton (normative)

```text
PENDING_REVOKE
  --quota--> PENDING_REVOKE_EXHAUSTED   # retains exact_bytes (protected)
            + IDENTITY_REVOKE_EXHAUSTED # SQL, in store_hash
            + FINALIZED_REVOKE_ANCHOR   # protected anti-rollback
            (PENDING_REVOKE_EXHAUSTED NOT cleared)

PENDING_REVOKE_EXHAUSTED + IDENTITY_REVOKE_EXHAUSTED
  --capacity expanded-->
      re-verify exact_bytes (from journal and/or marker blob)
  --under same lease-->
      convert PENDING_REVOKE_EXHAUSTED → PENDING_REVOKE (same exact bytes)
      # apply_verified_revoke_under_existing_lease accepts PENDING_REVOKE only
  --exact replay OK-->
      SQL atomic: insert claim + append targets + delete IDENTITY_REVOKE_EXHAUSTED
                  + cleanup upsert + bump generation
      + FINALIZED_REVOKE_ANCHOR
  --then-->
      clear PENDING_REVOKE
```

**Replay path (frozen):** the helper does **not** consume `PENDING_REVOKE_EXHAUSTED` directly. Under the existing lease, implementations MUST rewrite the journal to `PENDING_REVOKE` with the same `exact_bytes` / `claim_digest`, then call `apply_verified_revoke_under_existing_lease(..., pending_already_written=true)`. Crash order is locked in `shared-vectors/rvn1/device_revocation/crash_replay_order_001.json`.

| State | Meaning | Auto-retry insert? |
|-------|---------|-------------------|
| `PENDING_REVOKE_EXHAUSTED` | Protected stable journal holding **exact** claim bytes until expand+replay | **No** |
| `IDENTITY_REVOKE_EXHAUSTED` | SQL row included in `store_hash` / generation; fail-closed identity auth | n/a |

**Anti-rollback (normative):** `IDENTITY_REVOKE_EXHAUSTED` lives in **SQL** and MUST be part of the canonical snapshot hashed into `revocation_store_hash`. Creating or clearing it MUST bump generation and write a new protected `FINALIZED_REVOKE_ANCHOR` **before** any related journal clear. A SQL-only marker without an updated anchor is non-conformant. Rollback that drops the marker while the anchor still attests a higher generation MUST fail closed (§6.0 compare).

The marker MUST store at least `identity_address`, `claim_digest`, and `exact_record_bytes` or a content-addressed blob of those exact bytes (emergency capacity). `PENDING_REVOKE_EXHAUSTED` MUST remain until successful anchored apply (or corrupt path §6.0); it is the primary crash-safe holder of exact bytes, with the marker blob as redundant recoverable copy.

Clearing exhaustion states is allowed **only** after the automaton’s successful expand → re-verify → convert → anchored apply path above (or explicit abandon solely when re-verify fails and `REVOCATION_STORE_CORRUPT` / operator repair records that decision — never silently drop a still-valid signed claim).

### 6.1.4 Canonical `revocation_store_hash` (frozen)

```text
canonical_snapshot =
  "rvn1/device-revocation/store-v1" || 0x00
  || u64be(generation)
  || u32be(n_claims)
  || for each claim in ascending claim_digest order:
       claim_digest(32) || u32be(len(exact)) || exact_record_bytes
  || u32be(n_exhausted)
  || for each exhausted in (identity_address, claim_digest) ascending:
       lp(identity_address ASCII) || claim_digest(32)
       || u32be(len(exact)) || exact_record_bytes
  || u32be(n_corrupt)
  || for each corrupt in scope ascending:
       lp(scope UTF-8) || u8(reason_code)

revocation_store_hash = SHA-256(canonical_snapshot)
```

Vectors: `store_hash_001.json`, `store_hash_exhausted_001.json`.

**Corrupt `reason_code` values (frozen).** The code is hashed into `revocation_store_hash`, so every implementation MUST emit the same value. §6.0 step 2c re-verify checks run in this order and the first failure wins:

| Code | Reason | Condition |
|---:|---|---|
| 1 | `truncated` | Journal bytes are not one complete canonical record: shorter than 54 bytes, **or** any §3 strict-parse failure at any length (bad magic/version/suite, id length out of range, short fixed-size tail, zero `revocation_id`, trailing bytes) |
| 2 | `digest_mismatch` | Journal `claim_digest` ≠ SHA-256(exact bytes) (exact lowercase-hex compare of the journal field) |
| 3 | `bad_signature` | Record parses but the identity signature or `identity_address` binding fails |

All other values are reserved and MUST NOT be emitted. Vectors: `corrupt_journal_truncated_001.json` (short), `corrupt_journal_malformed_001.json` (≥ 54 bytes, undecodable), `corrupt_journal_digest_mismatch_001.json`, `corrupt_journal_bad_signature_001.json`.

### 6.2 Store integrity

After successful initialization (explicit empty-store initialized anchor on true first install, or at least one apply/exhausted/corrupt anchor):

- Missing protected anchor (when identity/security namespace exists), missing/truncated SQL, or SQL behind the protected anchor MUST fail closed for device authorization under that store scope until repaired from backup / re-sync of exact claims.
- `REVOCATION_STORE_CORRUPT` MUST fail closed for the marked scope until explicit repair clears it under lease with a new `FINALIZED_REVOKE_ANCHOR`.
- Recovery always prefers journal roll-forward via §6.1.1 / §6.1.3, then anchor compare (§6.0).

### 6.3 Side effects (durable cleanup work items)

Deny is immediate from `revoked_targets`. Required cleanup items are inserted/upserted **inside the deny SQL transaction** (§6.1.1), not after journal clear:

| Work item | Action |
|-----------|--------|
| `close_sessions(device_ed_pub)` | Sessions → REVOKED/CLOSED |
| `cancel_outbox(device)` | Cancel local outbound attempts targeting only that device |
| `ux_notify` | Optional |

Workers roll-forward these items until complete; success of cleanup MUST NOT reopen authorization. Idempotent path (§6.1.2) repairs missing items.

---

## 7. Propagation and partitions

### 7.1 Admit path

Owner or peer admits `endpoint_object_bytes` (bare RVDR1) with umbrella `object_digest`. Relays forward opaquely.

### 7.2 Learning paths

| Path | Role |
|------|------|
| LAN / Internet / BLE | Admit exact object |
| Mailbox | Opaque store |
| Object Sync inventory | Advertise `object_digest` on authenticated peer-eligible links |
| PairInit preflight | Local `revoked_targets` only — no network fetch under lease |

### 7.3 Partition semantics

1. Eventual only; offline verifiers may trust until they apply a claim.
2. Relay withholding delays learning; does not unset applied denies.
3. UX MUST NOT claim “revoked everywhere” after local apply alone.
4. Owners SHOULD fan out exact `revocation_record_bytes` best-effort.

---

## 8. Issuance rules (owner)

Single lease; no re-entry into §6.1’s acquire path:

```text
1. §6.0 recover / anchor-check.
2. Acquire mutation lease (once).
3. Mint RavenDeviceRevocationV1 with identity key
   (full lineage; issuer_device_id; issuer_seq observability-only;
    fresh revocation_id — hygiene only).
4. Write PENDING_REVOKE with exact revocation_record_bytes
   (pending_already_written path).
5. apply_verified_revoke_under_existing_lease(
     exact_bytes, pending_already_written=true)
   → SQL deny + cleanup upsert → FINALIZED_REVOKE_ANCHOR → clear journal.
6. Release lease.
7. Only then admit endpoint_object_bytes to carriers; exact-byte retry.
```

Concurrent owner devices MAY mint while partitioned; verifiers union-apply (§5). Never reuse revoked lineage ids/keys (§2.2). **Forbidden:** network before step 5 success; calling `apply_verified_revoke` (which reacquires the lease) while already holding the lease.
---

## 9. Integration matrix

| Surface | Requirement |
|---------|-------------|
| PairInit V1/V2 | Consult `revoked_targets` before OTP claim / TR init |
| Hybrid Ratchet | Denied device → CLOSED |
| AckV2 / envelopes | Outer device signer vs deny-set |
| ID Resolution | DeviceSet excludes any denied lineage key |
| Local block | Always may deny; orthogonal to signed revoke |
| Relays | Opaque; `object_digest` only |

### 9.1 Current endpoint enforcement (informative)

This subsection records what the node implementation enforces today; it does not change §1–§8 or the production status.

- **Certificate under test.** Revocation for PairInit, envelopes, ACKs and in-daemon seal is evaluated against the exact certificate bound into the session (its `device_certificate_hash` equals the PairInit-recorded digest), never against a cached or ephemeral offer for the same key.
- **Deny sources.** (a) Legacy local `rvn1/devrevoke/v1` records name only `(identity, device_id)` and deny that exact `device_id` (byte compare, no trimming); (b) verified RVDR1 claims (strict parse + identity signature, union by `claim_digest`) deny all four §2.1 identifiers for their identity; (c) the local device registry retains the full lineage of every local certificate it revokes, so a re-issued certificate reusing any retired identifier is refused (§2.2).
- **Not yet implemented at the endpoint.** §6 journal / anchor / quota / corrupt-marker machinery, §6.3 cleanup work items, and any network or IPC ingest of RVDR1 objects. Legacy records cannot carry `device_ed_pub` / `device_x_pub` / `device_cert_hash`, so re-certification of a *peer* lineage under a new `device_id` is only denied once an RVDR1 claim for it has been ingested.
- **Collapsed device tier.** The node issues its local certificate with `device_ed_pub` equal to the identity key and one X25519 device key per data directory, so all local "devices" share one lineage. Retiring any local lineage therefore retires the identity key's device role (§2.2) and the node must move to a new identity; per-device containment requires a separate per-install device key (not yet implemented). LAN peers are accepted only with self-certified certificates (`device_ed_pub == user_ed_pub == Noise-bound key`).

---

## 10. Shared vectors (conformance suite)

| Class | Path / covers |
|-------|----------------|
| `valid_001` | Wire, offsets, digests, verify |
| `store_hash_*` | Canonical snapshot + hash |
| `crash_replay_order_001` | Expand replay step order |
| `device_revocation_wrong_signer` | Negative verify |
| `union_001` | Append-only union of two claims |
| `collision_revocation_id_001` | Same `revocation_id`, different bytes → union + collision |
| `quota_machine_001` | Exhaustion → expand → convert → replay crash windows |
| `corrupt_journal_*` | Truncated (short and ≥ 54-byte malformed) / digest mismatch / bad signature + recovery fail-closed |
| `device_revocation_long_id_short_tail` | Negative decode: long id, short fixed-size tail → error, never out-of-range read |
| `apply_gates_001` | PairInit V1/V2, Session, Message, ACK, Noise bind |
| `pending_binding_negatives_001` | `pending_already_written` wrong bytes/digest/missing/EXHAUSTED |

Reference: `protocol/reference/raven_protocol/device_revocation.py` (+ `_conformance`), `node/crates/raven-core/src/device_revocation*.rs`, `ios-native/.../RavenDeviceRevocation*.swift`.

**Parity:** core + conformance KATs green across Python/Rust/Swift (authorize executed vs fixture; pending binding enforced; full `revoked_targets` / collision compare).

---

## 11. Production holds

### 11.1 Approval checklist (met)

1. This revision’s P0 design accepted;
2. Exact wire table + §10 vectors match Python/Rust/Swift;
3. Apply/store integrity tests pass;
4. Human/protocol-owner approval recorded in header (2026-08-16).

### 11.2 Document control

| Field | Value |
|-------|-------|
| Created | 2026-08-16 |
| Revision | **6** (+ conformance fixtures: union/collision/quota/corrupt/apply-gates/pending-binding; Py/Rust/Swift KATs) |
| Status | **APPROVED** |
| Approved | 2026-08-16 (human/protocol-owner; independent technical review PASS) |
| Next | Session companion vector freeze ([`ATSAM_HYBRID_RATCHET_V2.md`](ATSAM_HYBRID_RATCHET_V2.md)); ID Resolution may proceed on its prerequisites |
| Explicitly not next | Production flags / transport enablement |

**Production remains disabled** despite companion APPROVED until umbrella §9–§10 and relevant surface gates pass.
