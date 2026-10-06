"""RavenDeviceRevocationV1 — exact wire codec + store snapshot hash (vector freeze)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._canon import lp, u64
from . import address as raven_address
from .pair_init import device_certificate_hash

MAGIC = b"RVDR1\0\0\0"
VERSION = 0x01
SUITE = 0x01
SIGNING_DOMAIN = b"rvn1/device-revocation"
STORE_SNAPSHOT_DOMAIN = b"rvn1/device-revocation/store-v1"
ADDRESS_LEN = 44
PUB_LEN = 32
HASH_LEN = 32
REVOCATION_ID_LEN = 16
SIGNATURE_LEN = 64
ID_MIN = 1
ID_MAX = 64

# Fixed header before first variable lp(device_id)
# magic(8)+version(1)+suite(1)+address(44) = 54
FIXED_PREFIX_LEN = 54


@dataclass
class DeviceRevocationV1:
    identity_address: str
    device_id: bytes  # raw UTF-8 bytes
    device_ed_pub: bytes
    device_x_pub: bytes
    device_cert_hash: bytes
    issuer_device_id: bytes
    issuer_seq: int
    revocation_id: bytes
    reason_code: int
    created_at_ms: int
    signature: bytes = field(default=b"")


def _require_id(label: str, raw: bytes) -> bytes:
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError(f"{label} must be bytes")
    raw = bytes(raw)
    if not (ID_MIN <= len(raw) <= ID_MAX):
        raise ValueError(f"{label} length must be 1..64")
    return raw


def _require_address(addr: str) -> bytes:
    if not isinstance(addr, str) or len(addr) != ADDRESS_LEN:
        raise ValueError("identity_address must be exactly 44 ASCII chars")
    decoded = raven_address.decode(addr)
    if decoded is None:
        raise ValueError("identity_address is not a valid RavenAddressV1")
    if addr != addr.lower() or not addr.startswith("rvn1"):
        raise ValueError("identity_address must be canonical lowercase")
    return addr.encode("ascii")


def signing_bytes(r: DeviceRevocationV1) -> bytes:
    device_id = _require_id("device_id", r.device_id)
    issuer = _require_id("issuer_device_id", r.issuer_device_id)
    addr = _require_address(r.identity_address)
    if len(r.device_ed_pub) != PUB_LEN or len(r.device_x_pub) != PUB_LEN:
        raise ValueError("device pubs must be 32 bytes")
    if len(r.device_cert_hash) != HASH_LEN:
        raise ValueError("device_cert_hash must be 32 bytes")
    if len(r.revocation_id) != REVOCATION_ID_LEN or r.revocation_id == bytes(REVOCATION_ID_LEN):
        raise ValueError("revocation_id must be 16 nonzero bytes")
    if not (0 <= r.reason_code <= 255):
        raise ValueError("reason_code out of range")
    if r.issuer_seq < 0 or r.issuer_seq >= 2**64:
        raise ValueError("issuer_seq out of range")
    if r.created_at_ms < 0 or r.created_at_ms >= 2**64:
        raise ValueError("created_at_ms out of range")
    return (
        SIGNING_DOMAIN
        + bytes([VERSION, SUITE])
        + addr
        + lp(device_id)
        + r.device_ed_pub
        + r.device_x_pub
        + r.device_cert_hash
        + lp(issuer)
        + u64(r.issuer_seq)
        + r.revocation_id
        + bytes([r.reason_code & 0xFF])
        + u64(r.created_at_ms)
    )


def encode(r: DeviceRevocationV1) -> bytes:
    if len(r.signature) != SIGNATURE_LEN:
        raise ValueError("signature must be 64 bytes")
    sb = signing_bytes(r)
    body = MAGIC + sb[len(SIGNING_DOMAIN) :] + r.signature
    return body


def _read_lp(buf: bytes, off: int) -> tuple[bytes, int]:
    if off + 2 > len(buf):
        raise ValueError("truncated lp")
    n = int.from_bytes(buf[off : off + 2], "big")
    off += 2
    if not (ID_MIN <= n <= ID_MAX):
        raise ValueError("lp length out of 1..64")
    if off + n > len(buf):
        raise ValueError("truncated lp body")
    return buf[off : off + n], off + n


def _take(buf: bytes, off: int, n: int) -> tuple[bytes, int]:
    """Bounds-checked fixed-size read (the length floor assumes 1-byte ids)."""
    end = off + n
    if end > len(buf):
        raise ValueError("truncated field")
    return buf[off:end], end


def decode(wire: bytes) -> DeviceRevocationV1:
    if not isinstance(wire, (bytes, bytearray)):
        raise ValueError("wire must be bytes")
    wire = bytes(wire)
    if len(wire) < FIXED_PREFIX_LEN + 2 + ID_MIN + PUB_LEN * 2 + HASH_LEN + 2 + ID_MIN + 8 + 16 + 1 + 8 + 64:
        raise ValueError("wire too short")
    if wire[:8] != MAGIC:
        raise ValueError("bad magic")
    if wire[8] != VERSION or wire[9] != SUITE:
        raise ValueError("bad version/suite")
    off = 10
    addr = wire[off : off + ADDRESS_LEN]
    off += ADDRESS_LEN
    try:
        identity_address = addr.decode("ascii")
    except UnicodeDecodeError as e:
        raise ValueError("identity_address not ASCII") from e
    _require_address(identity_address)
    device_id, off = _read_lp(wire, off)
    device_ed, off = _take(wire, off, PUB_LEN)
    device_x, off = _take(wire, off, PUB_LEN)
    cert_hash, off = _take(wire, off, HASH_LEN)
    issuer_id, off = _read_lp(wire, off)
    seq_raw, off = _take(wire, off, 8)
    issuer_seq = int.from_bytes(seq_raw, "big")
    rev_id, off = _take(wire, off, REVOCATION_ID_LEN)
    reason_raw, off = _take(wire, off, 1)
    reason = reason_raw[0]
    created_raw, off = _take(wire, off, 8)
    created = int.from_bytes(created_raw, "big")
    sig, off = _take(wire, off, SIGNATURE_LEN)
    if off != len(wire):
        raise ValueError("trailing bytes")
    if rev_id == bytes(REVOCATION_ID_LEN):
        raise ValueError("revocation_id all-zero")
    return DeviceRevocationV1(
        identity_address=identity_address,
        device_id=device_id,
        device_ed_pub=device_ed,
        device_x_pub=device_x,
        device_cert_hash=cert_hash,
        issuer_device_id=issuer_id,
        issuer_seq=issuer_seq,
        revocation_id=rev_id,
        reason_code=reason,
        created_at_ms=created,
        signature=sig,
    )


def sign(r: DeviceRevocationV1, identity_ed_priv: bytes) -> DeviceRevocationV1:
    priv = Ed25519PrivateKey.from_private_bytes(identity_ed_priv)
    pub = priv.public_key().public_bytes_raw()
    # Address must match signer
    if raven_address.encode(pub) != r.identity_address:
        raise ValueError("identity_address does not match signing key")
    sig = priv.sign(signing_bytes(r))
    return DeviceRevocationV1(
        identity_address=r.identity_address,
        device_id=r.device_id,
        device_ed_pub=r.device_ed_pub,
        device_x_pub=r.device_x_pub,
        device_cert_hash=r.device_cert_hash,
        issuer_device_id=r.issuer_device_id,
        issuer_seq=r.issuer_seq,
        revocation_id=r.revocation_id,
        reason_code=r.reason_code,
        created_at_ms=r.created_at_ms,
        signature=sig,
    )


def verify(r: DeviceRevocationV1, identity_ed_pub: bytes) -> bool:
    if raven_address.encode(identity_ed_pub) != r.identity_address:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(identity_ed_pub).verify(
            r.signature, signing_bytes(r)
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def claim_digest(wire: bytes) -> bytes:
    return hashlib.sha256(bytes(wire)).digest()


def object_digest(wire: bytes) -> bytes:
    """Under bare packaging, equals claim_digest."""
    return claim_digest(wire)


def wire_offsets(device_id: bytes, issuer_device_id: bytes) -> dict[str, int]:
    """Document exact offsets for a concrete id pair (vector metadata)."""
    device_id = _require_id("device_id", device_id)
    issuer = _require_id("issuer_device_id", issuer_device_id)
    o = 0
    offsets = {"magic": o}
    o += 8
    offsets["version"] = o
    o += 1
    offsets["suite"] = o
    o += 1
    offsets["identity_address"] = o
    o += ADDRESS_LEN
    offsets["device_id_len"] = o
    o += 2
    offsets["device_id"] = o
    o += len(device_id)
    offsets["device_ed_pub"] = o
    o += PUB_LEN
    offsets["device_x_pub"] = o
    o += PUB_LEN
    offsets["device_cert_hash"] = o
    o += HASH_LEN
    offsets["issuer_device_id_len"] = o
    o += 2
    offsets["issuer_device_id"] = o
    o += len(issuer)
    offsets["issuer_seq"] = o
    o += 8
    offsets["revocation_id"] = o
    o += REVOCATION_ID_LEN
    offsets["reason_code"] = o
    o += 1
    offsets["created_at_ms"] = o
    o += 8
    offsets["signature"] = o
    o += SIGNATURE_LEN
    offsets["total_len"] = o
    return offsets


@dataclass(frozen=True)
class StoreClaim:
    exact_record_bytes: bytes

    @property
    def claim_digest(self) -> bytes:
        return claim_digest(self.exact_record_bytes)


@dataclass(frozen=True)
class ExhaustedMarker:
    identity_address: str
    claim_digest: bytes
    exact_record_bytes: bytes


@dataclass(frozen=True)
class CorruptMarker:
    scope: str
    reason_code: int


def canonical_store_snapshot(
    generation: int,
    claims: list[StoreClaim],
    exhausted: list[ExhaustedMarker],
    corrupt: list[CorruptMarker],
) -> bytes:
    if generation < 0 or generation >= 2**64:
        raise ValueError("generation out of range")
    claims_sorted = sorted(claims, key=lambda c: c.claim_digest)
    exh_sorted = sorted(
        exhausted, key=lambda e: (e.identity_address.encode("ascii"), e.claim_digest)
    )
    cor_sorted = sorted(corrupt, key=lambda c: c.scope.encode("utf-8"))

    out = STORE_SNAPSHOT_DOMAIN + b"\x00" + u64(generation)

    out += len(claims_sorted).to_bytes(4, "big")
    for c in claims_sorted:
        d = c.claim_digest
        b = c.exact_record_bytes
        if len(d) != 32:
            raise ValueError("bad claim digest")
        out += d + len(b).to_bytes(4, "big") + b

    out += len(exh_sorted).to_bytes(4, "big")
    for e in exh_sorted:
        addr = e.identity_address.encode("ascii")
        if len(e.claim_digest) != 32:
            raise ValueError("bad exhausted digest")
        if claim_digest(e.exact_record_bytes) != e.claim_digest:
            raise ValueError("exhausted blob digest mismatch")
        out += lp(addr) + e.claim_digest + len(e.exact_record_bytes).to_bytes(4, "big")
        out += e.exact_record_bytes

    out += len(cor_sorted).to_bytes(4, "big")
    for c in cor_sorted:
        scope = c.scope.encode("utf-8")
        if len(scope) > 0xFFFF:
            raise ValueError("corrupt scope too long")
        out += lp(scope) + bytes([c.reason_code & 0xFF])

    return out


def revocation_store_hash(
    generation: int,
    claims: list[StoreClaim],
    exhausted: list[ExhaustedMarker],
    corrupt: list[CorruptMarker],
) -> bytes:
    return hashlib.sha256(
        canonical_store_snapshot(generation, claims, exhausted, corrupt)
    ).digest()


# Re-export for generators that already hash certs via pair_init
__all__ = [
    "DeviceRevocationV1",
    "MAGIC",
    "VERSION",
    "SUITE",
    "signing_bytes",
    "encode",
    "decode",
    "sign",
    "verify",
    "claim_digest",
    "object_digest",
    "wire_offsets",
    "StoreClaim",
    "ExhaustedMarker",
    "CorruptMarker",
    "canonical_store_snapshot",
    "revocation_store_hash",
    "device_certificate_hash",
]
