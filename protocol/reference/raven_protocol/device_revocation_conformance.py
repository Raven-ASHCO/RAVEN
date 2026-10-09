"""Revocation store conformance helpers (deny-set union, quota, auth gates).

Deterministic reference for shared-vectors under device_revocation/.
Not a production SQL engine — models §5–§6 semantics for KATs only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .device_revocation import (
    FIXED_PREFIX_LEN,
    CorruptMarker,
    DeviceRevocationV1,
    ExhaustedMarker,
    StoreClaim,
    claim_digest,
    decode,
    revocation_store_hash,
    verify,
)


@dataclass
class RevokedTarget:
    kind: str  # device_id | device_ed_pub | device_x_pub | device_cert_hash
    value_hex: str
    claim_digest_hex: str
    revocation_id_hex: str


@dataclass
class ConformanceStore:
    """In-memory append-only revoke store for vector generation/tests."""

    identity_address: str
    generation: int = 0
    claims: dict[str, bytes] = field(default_factory=dict)  # digest_hex → wire
    revoked: list[RevokedTarget] = field(default_factory=list)
    exhausted: list[ExhaustedMarker] = field(default_factory=list)
    corrupt: list[CorruptMarker] = field(default_factory=list)
    seen_revocation_ids: dict[str, str] = field(default_factory=dict)  # id_hex → first digest
    collisions: list[dict[str, str]] = field(default_factory=list)
    forks: list[dict[str, Any]] = field(default_factory=list)
    issuer_heads: dict[str, dict[str, Any]] = field(default_factory=dict)
    max_claims: int = 10_000
    journal: dict[str, Any] | None = None

    def store_hash(self) -> bytes:
        claims = [StoreClaim(b) for b in self.claims.values()]
        return revocation_store_hash(
            self.generation, claims, list(self.exhausted), list(self.corrupt)
        )

    def snapshot_dict(self) -> dict[str, Any]:
        return {
            "generation": self.generation,
            "claims_wire_hex": sorted(
                (h for h in (b.hex() for b in self.claims.values())),
                key=lambda hx: claim_digest(bytes.fromhex(hx)).hex(),
            ),
            # Stable order by claim digest then kind/value
            "revoked_targets": sorted(
                [
                    {
                        "kind": t.kind,
                        "value_hex": t.value_hex,
                        "claim_digest_hex": t.claim_digest_hex,
                        "revocation_id_hex": t.revocation_id_hex,
                    }
                    for t in self.revoked
                ],
                key=lambda r: (r["claim_digest_hex"], r["kind"], r["value_hex"]),
            ),
            "exhausted": [
                {
                    "identity_address": e.identity_address,
                    "claim_digest_hex": e.claim_digest.hex(),
                    "exact_record_bytes_hex": e.exact_record_bytes.hex(),
                }
                for e in sorted(
                    self.exhausted,
                    key=lambda e: (e.identity_address, e.claim_digest),
                )
            ],
            "corrupt": [
                {"scope": c.scope, "reason_code": c.reason_code}
                for c in sorted(self.corrupt, key=lambda c: c.scope)
            ],
            "revocation_id_collisions": list(self.collisions),
            "forks": list(self.forks),
            "revocation_store_hash_hex": self.store_hash().hex(),
            "journal": self.journal,
        }


def lineage_targets(rec: DeviceRevocationV1, cd: bytes) -> list[RevokedTarget]:
    rid = rec.revocation_id.hex()
    cd_h = cd.hex()
    return [
        RevokedTarget("device_id", rec.device_id.hex(), cd_h, rid),
        RevokedTarget("device_ed_pub", rec.device_ed_pub.hex(), cd_h, rid),
        RevokedTarget("device_x_pub", rec.device_x_pub.hex(), cd_h, rid),
        RevokedTarget("device_cert_hash", rec.device_cert_hash.hex(), cd_h, rid),
    ]


def _append_targets(store: ConformanceStore, rec: DeviceRevocationV1, cd: bytes) -> None:
    existing = {(t.kind, t.value_hex) for t in store.revoked}
    for t in lineage_targets(rec, cd):
        if (t.kind, t.value_hex) not in existing:
            store.revoked.append(t)
            existing.add((t.kind, t.value_hex))


def apply_verified_claim(
    store: ConformanceStore,
    wire: bytes,
    identity_ed_pub: bytes,
    *,
    pending_already_written: bool = False,
) -> dict[str, Any]:
    """Model §6.1.1 helper under an existing lease (tests assume lease held).

    When ``pending_already_written=True``, journal MUST be ``PENDING_REVOKE`` with
    matching ``exact_record_bytes`` and ``claim_digest``. Direct consumption of
    ``PENDING_REVOKE_EXHAUSTED`` is rejected (convert under lease first).
    """
    rec = decode(wire)
    if rec.identity_address != store.identity_address:
        raise ValueError("identity_address mismatch")
    if not verify(rec, identity_ed_pub):
        raise ValueError("verify failed")
    cd = claim_digest(wire)
    cd_h = cd.hex()

    if pending_already_written:
        j = store.journal
        if j is None:
            raise ValueError("missing_pending")
        kind = j.get("kind")
        if kind == "PENDING_REVOKE_EXHAUSTED":
            raise ValueError("direct_exhausted_consumption")
        if kind != "PENDING_REVOKE":
            raise ValueError("missing_pending")
        if j.get("exact_record_bytes_hex") != wire.hex():
            raise ValueError("pending_bytes_mismatch")
        if j.get("claim_digest_hex") != cd_h:
            raise ValueError("pending_digest_mismatch")
    elif store.journal and store.journal.get("kind") == "PENDING_REVOKE_EXHAUSTED":
        # Must convert → PENDING before helper accepts the claim
        raise ValueError("direct_exhausted_consumption")

    if cd_h in store.claims:
        return {"result": "idempotent", "claim_digest_hex": cd_h, "store": store.snapshot_dict()}

    if store.corrupt:
        raise ValueError("REVOCATION_STORE_CORRUPT — fail closed")

    if len(store.claims) >= store.max_claims:
        # Transition to exhausted; do not insert claim
        exh = ExhaustedMarker(
            identity_address=store.identity_address,
            claim_digest=cd,
            exact_record_bytes=wire,
        )
        # Replace/keep single exhausted entry for this digest
        store.exhausted = [e for e in store.exhausted if e.claim_digest != cd] + [exh]
        store.journal = {
            "kind": "PENDING_REVOKE_EXHAUSTED",
            "claim_digest_hex": cd_h,
            "exact_record_bytes_hex": wire.hex(),
        }
        store.generation += 1  # marker + generation bump (anchored exhausted)
        return {
            "result": "exhausted",
            "claim_digest_hex": cd_h,
            "store": store.snapshot_dict(),
        }

    # Normal insert
    rid = rec.revocation_id.hex()
    if rid in store.seen_revocation_ids and store.seen_revocation_ids[rid] != cd_h:
        store.collisions.append(
            {
                "revocation_id_hex": rid,
                "first_claim_digest_hex": store.seen_revocation_ids[rid],
                "second_claim_digest_hex": cd_h,
            }
        )
    else:
        store.seen_revocation_ids[rid] = cd_h

    issuer_key = rec.issuer_device_id.hex()
    head = store.issuer_heads.get(issuer_key)
    if head and head["issuer_seq"] == rec.issuer_seq and head["claim_digest_hex"] != cd_h:
        store.forks.append(
            {
                "issuer_device_id_hex": issuer_key,
                "issuer_seq": rec.issuer_seq,
                "first_claim_digest_hex": head["claim_digest_hex"],
                "second_claim_digest_hex": cd_h,
            }
        )
    store.issuer_heads[issuer_key] = {
        "issuer_seq": rec.issuer_seq,
        "claim_digest_hex": cd_h,
        "fork_flags": bool(
            head
            and head["issuer_seq"] == rec.issuer_seq
            and head["claim_digest_hex"] != cd_h
        ),
    }

    store.claims[cd_h] = wire
    _append_targets(store, rec, cd)
    # Clear matching exhausted marker if replaying after expand
    store.exhausted = [e for e in store.exhausted if e.claim_digest != cd]
    if pending_already_written or (
        store.journal and store.journal.get("kind") == "PENDING_REVOKE"
    ):
        store.journal = None
    store.generation += 1
    return {"result": "applied", "claim_digest_hex": cd_h, "store": store.snapshot_dict()}


# Frozen corrupt-marker reason codes (RAVEN_DEVICE_REVOCATION_V1 §6.0); they
# are hashed into revocation_store_hash, so every implementation must agree.
CORRUPT_TRUNCATED = 1  # journal bytes are not one complete canonical RVDR1 record
CORRUPT_DIGEST_MISMATCH = 2  # journal claim_digest != SHA-256(exact bytes)
CORRUPT_BAD_SIGNATURE = 3  # parses, but identity signature/address binding fails


def expand_quota(store: ConformanceStore, new_max: int) -> None:
    if new_max < store.max_claims:
        raise ValueError("quota may only expand")
    store.max_claims = new_max


def convert_exhausted_journal_to_pending(store: ConformanceStore) -> None:
    """Frozen replay path: EXHAUSTED → PENDING under lease (same exact bytes)."""
    if not store.journal or store.journal.get("kind") != "PENDING_REVOKE_EXHAUSTED":
        raise ValueError("no PENDING_REVOKE_EXHAUSTED journal")
    store.journal = {
        "kind": "PENDING_REVOKE",
        "claim_digest_hex": store.journal["claim_digest_hex"],
        "exact_record_bytes_hex": store.journal["exact_record_bytes_hex"],
        "converted_from": "PENDING_REVOKE_EXHAUSTED",
    }


def reverify_journal(
    store: ConformanceStore,
    identity_ed_pub: bytes,
    *,
    exact_bytes: bytes | None = None,
    claimed_digest: bytes | None = None,
) -> dict[str, Any]:
    """§6.0 journal re-verify. On failure: write corrupt, clear journal."""
    if store.journal is None and exact_bytes is None:
        raise ValueError("no journal")
    wire = exact_bytes if exact_bytes is not None else bytes.fromhex(
        store.journal["exact_record_bytes_hex"]
    )
    reason: str | None = None
    rec = None
    cd = claim_digest(wire)
    if len(wire) < FIXED_PREFIX_LEN:
        reason = "truncated"
    else:
        try:
            rec = decode(wire)
        except (ValueError, IndexError):
            # Any strict-parse failure (short tail, bad magic/version, lp out of
            # range, trailing bytes) is "not a complete record": code 1.
            reason = "truncated"
    if reason is None and claimed_digest is not None and claimed_digest != cd:
        reason = "digest_mismatch"
    if reason is None and store.journal is not None:
        # Exact lowercase-hex compare, as the Rust implementation does.
        if store.journal.get("claim_digest_hex") != cd.hex():
            reason = "digest_mismatch"
    if reason is None:
        try:
            ok = verify(rec, identity_ed_pub)
        except (ValueError, TypeError):
            ok = False
        if not ok:
            reason = "bad_signature"
    if reason is None:
        return {"result": "ok", "claim_digest_hex": cd.hex()}
    reason_code = {
        "truncated": CORRUPT_TRUNCATED,
        "digest_mismatch": CORRUPT_DIGEST_MISMATCH,
        "bad_signature": CORRUPT_BAD_SIGNATURE,
    }[reason]
    store.corrupt.append(CorruptMarker(scope=store.identity_address, reason_code=reason_code))
    store.journal = None
    store.generation += 1
    return {
        "result": "corrupt",
        "reason": reason,
        "reason_code": reason_code,
        "store": store.snapshot_dict(),
    }


def authorize_device(
    store: ConformanceStore,
    *,
    device_id: bytes | None = None,
    device_ed_pub: bytes | None = None,
    device_x_pub: bytes | None = None,
    device_cert_hash: bytes | None = None,
    surface: str,
) -> dict[str, Any]:
    """§5.6 local authorization for PairInit/session/message/ACK/Noise bind."""
    if store.corrupt:
        return {"authorized": False, "reason": "REVOCATION_STORE_CORRUPT", "surface": surface}
    if any(e.identity_address == store.identity_address for e in store.exhausted):
        return {
            "authorized": False,
            "reason": "IDENTITY_REVOKE_EXHAUSTED",
            "surface": surface,
        }
    checks = [
        ("device_id", device_id.hex() if device_id is not None else None),
        ("device_ed_pub", device_ed_pub.hex() if device_ed_pub is not None else None),
        ("device_x_pub", device_x_pub.hex() if device_x_pub is not None else None),
        (
            "device_cert_hash",
            device_cert_hash.hex() if device_cert_hash is not None else None,
        ),
    ]
    for kind, val in checks:
        if val is None:
            continue
        for t in store.revoked:
            if t.kind == kind and t.value_hex == val:
                return {
                    "authorized": False,
                    "reason": "revoked_target",
                    "matched_kind": kind,
                    "surface": surface,
                }
    return {"authorized": True, "reason": "ok", "surface": surface}


SURFACES = (
    "pair_init_v1",
    "pair_init_v2",
    "session",
    "message",
    "ack",
    "noise_bind",
)
