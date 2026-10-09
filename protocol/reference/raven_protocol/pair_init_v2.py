"""Production-disabled PairInit / PairResponse V2 canonical codec.

Profile: ATSAM/hybrid-ratchet/v2
MUST NOT parse or reinterpret PairInit V1 (RVPI1) as V2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac

from . import address, ed25519_strict, indexed_session
from .pair_init import (
    ADDRESS_LEN,
    DEVICE_CERT_HASH_DOMAIN,
    ED25519_KEY_LEN,
    INIT_ID_LEN,
    MLKEM768_CT_LEN,
    MLKEM768_EK_LEN,
    NONCE_LEN,
    PREKEY_BUNDLE_HASH_DOMAIN,
    SIGNATURE_LEN,
    X25519_KEY_LEN,
    device_certificate_hash,
    is_contributory_x25519,
    prekey_bundle_hash,
)

VERSION = 2
SUITE = 1
PRODUCTION_ENABLED = False
PROFILE_ID = b"ATSAM/hybrid-ratchet/v2"
PROFILE_LEN = len(PROFILE_ID)  # 23
INIT_MAGIC = b"RVPI2\x00\x00\x00"
RESPONSE_MAGIC = b"RVPR2\x00\x00\x00"
TRANSCRIPT_DOMAIN = b"ATSAM/v2/transcript"
PAIR_INIT_LABEL = b"ATSAM/v2/pair-init"
INIT_SIGNING_DOMAIN = b"rvn1/pair-init-v2"
RESPONSE_SIGNING_DOMAIN = b"rvn1/pair-response-v2"
CONFIRM_LABEL = b"ATSAM/v2/pair-init/confirm"
SESSION_ID_DOMAIN = b"ATSAM/v2/pair-session"
PAIR_EXPAND_INFO_PREFIX = b"ATSAM/hybrid-ratchet/v2\x00pair-expand"
INITIATOR_ROLE = 0
RESPONDER_ROLE = 1

INIT_SIGNED_PREFIX_LEN = (
    8
    + 1
    + 1
    + 1
    + 1
    + PROFILE_LEN
    + ADDRESS_LEN * 2
    + INIT_ID_LEN
    + NONCE_LEN
    + ED25519_KEY_LEN * 2
    + X25519_KEY_LEN * 3
    + 32 * 3
    + 4
    + 4
    + MLKEM768_EK_LEN
    + MLKEM768_CT_LEN
    + 8
    + 8
)
INIT_WIRE_LEN = INIT_SIGNED_PREFIX_LEN + SIGNATURE_LEN
RESPONSE_SIGNED_PREFIX_LEN = (
    8 + 1 + 1 + 1 + 1 + PROFILE_LEN + INIT_ID_LEN + 32 + ED25519_KEY_LEN + 8 + 8 + 32
)
RESPONSE_WIRE_LEN = RESPONSE_SIGNED_PREFIX_LEN + SIGNATURE_LEN


@dataclass
class PairInitV2:
    initiator_address: str
    responder_address: str
    init_id: bytes
    pairing_nonce: bytes
    initiator_device_ed_pub: bytes
    responder_device_ed_pub: bytes
    initiator_ephemeral_x25519_pub: bytes
    responder_signed_x25519_pub: bytes  # SPK — initial EC ratchet key
    responder_one_time_x25519_pub: bytes  # OTP — PairInit Z_X only; may be zero slot
    initiator_device_cert_hash: bytes
    responder_device_cert_hash: bytes
    responder_prekey_bundle_hash: bytes
    signed_prekey_id: int
    one_time_prekey_id: int
    responder_mlkem768_ek: bytes
    mlkem768_ciphertext: bytes
    created_at_ms: int
    expires_at_ms: int
    signature: bytes = field(default=b"")


@dataclass
class PairResponseV2:
    init_id: bytes
    init_hash: bytes
    responder_device_ed_pub: bytes
    created_at_ms: int
    expires_at_ms: int
    confirmation_tag: bytes
    signature: bytes = field(default=b"")


@dataclass(frozen=True)
class PairExpandV2:
    sk_ec: bytes
    sk_scka: bytes
    k_route_master: bytes
    k_confirm: bytes
    transcript_hash: bytes
    init_hash_v2: bytes
    session_id: bytes


def _u32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("value must fit u32")
    return value.to_bytes(4, "big")


def _u64(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("value must fit u64")
    return value.to_bytes(8, "big")


def _require_bytes(value: bytes, length: int, field_name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"{field_name} must be exactly {length} bytes")
    return value


def _address_bytes(value: str, field_name: str) -> bytes:
    try:
        encoded = indexed_session.require_canonical_address(value).encode("ascii")
    except ValueError as exc:
        raise ValueError(f"invalid {field_name}: {exc}") from exc
    if len(encoded) != ADDRESS_LEN:
        raise ValueError(f"{field_name} must be exactly {ADDRESS_LEN} ASCII bytes")
    return encoded


def _validate_time(created_at_ms: int, expires_at_ms: int) -> None:
    _u64(created_at_ms)
    _u64(expires_at_ms)
    if expires_at_ms <= created_at_ms:
        raise ValueError("expires_at_ms must be greater than created_at_ms")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 extract+expand."""
    if salt is None or salt == b"":
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def _validate_init(value: PairInitV2, require_signature: bool) -> None:
    initiator = _address_bytes(value.initiator_address, "initiator_address")
    responder = _address_bytes(value.responder_address, "responder_address")
    if initiator == responder:
        raise ValueError("PairInit endpoints must differ")
    _require_bytes(value.init_id, INIT_ID_LEN, "init_id")
    if value.init_id == bytes(INIT_ID_LEN):
        raise ValueError("init_id must not be all-zero")
    _require_bytes(value.pairing_nonce, NONCE_LEN, "pairing_nonce")
    if value.pairing_nonce == bytes(NONCE_LEN):
        raise ValueError("pairing_nonce must not be all-zero")
    _require_bytes(value.initiator_device_ed_pub, ED25519_KEY_LEN, "initiator_device_ed_pub")
    _require_bytes(value.responder_device_ed_pub, ED25519_KEY_LEN, "responder_device_ed_pub")
    if (
        value.initiator_device_ed_pub == bytes(ED25519_KEY_LEN)
        or value.responder_device_ed_pub == bytes(ED25519_KEY_LEN)
    ):
        raise ValueError("PairInit device signing keys must not be all-zero")
    if value.initiator_device_ed_pub == value.responder_device_ed_pub:
        raise ValueError("PairInit device signing keys must differ")
    _require_bytes(
        value.initiator_ephemeral_x25519_pub, X25519_KEY_LEN, "initiator_ephemeral_x25519_pub"
    )
    # Same structural hard rejects as PairInit V1 (RAVEN_PAIR_INIT_V1.md §3):
    # never sign, hash, journal, or claim a non-contributory ephemeral.
    if value.initiator_ephemeral_x25519_pub == bytes(X25519_KEY_LEN):
        raise ValueError("initiator_ephemeral_x25519_pub must not be all-zero")
    if not is_contributory_x25519(value.initiator_ephemeral_x25519_pub):
        raise ValueError("initiator_ephemeral_x25519_pub must not be a low-order point")
    _require_bytes(
        value.responder_signed_x25519_pub, X25519_KEY_LEN, "responder_signed_x25519_pub"
    )
    if value.responder_signed_x25519_pub == bytes(X25519_KEY_LEN):
        raise ValueError("responder_signed_x25519_pub (SPK) must not be all-zero")
    _require_bytes(
        value.responder_one_time_x25519_pub, X25519_KEY_LEN, "responder_one_time_x25519_pub"
    )
    _require_bytes(value.initiator_device_cert_hash, 32, "initiator_device_cert_hash")
    _require_bytes(value.responder_device_cert_hash, 32, "responder_device_cert_hash")
    _require_bytes(value.responder_prekey_bundle_hash, 32, "responder_prekey_bundle_hash")
    if any(
        digest == bytes(32)
        for digest in (
            value.initiator_device_cert_hash,
            value.responder_device_cert_hash,
            value.responder_prekey_bundle_hash,
        )
    ):
        raise ValueError("certificate and prekey hashes must not be all-zero")
    _u32(value.signed_prekey_id)
    if value.signed_prekey_id == 0:
        raise ValueError("signed_prekey_id must be non-zero")
    _u32(value.one_time_prekey_id)
    if value.one_time_prekey_id == 0:
        if value.responder_one_time_x25519_pub != bytes(X25519_KEY_LEN):
            raise ValueError("zero one_time_prekey_id requires an all-zero one-time key slot")
    elif value.responder_one_time_x25519_pub == bytes(X25519_KEY_LEN):
        raise ValueError("non-zero one_time_prekey_id requires a one-time X25519 key")
    _require_bytes(value.responder_mlkem768_ek, MLKEM768_EK_LEN, "responder_mlkem768_ek")
    if value.responder_mlkem768_ek == bytes(MLKEM768_EK_LEN):
        raise ValueError("responder_mlkem768_ek must not be all-zero")
    _require_bytes(value.mlkem768_ciphertext, MLKEM768_CT_LEN, "mlkem768_ciphertext")
    if value.mlkem768_ciphertext == bytes(MLKEM768_CT_LEN):
        raise ValueError("mlkem768_ciphertext must not be all-zero")
    _validate_time(value.created_at_ms, value.expires_at_ms)
    if require_signature:
        _require_bytes(value.signature, SIGNATURE_LEN, "signature")


def init_signing_bytes(value: PairInitV2) -> bytes:
    _validate_init(value, require_signature=False)
    out = b"".join(
        (
            INIT_MAGIC,
            bytes((VERSION, SUITE, INITIATOR_ROLE, PROFILE_LEN)),
            PROFILE_ID,
            _address_bytes(value.initiator_address, "initiator_address"),
            _address_bytes(value.responder_address, "responder_address"),
            value.init_id,
            value.pairing_nonce,
            value.initiator_device_ed_pub,
            value.responder_device_ed_pub,
            value.initiator_ephemeral_x25519_pub,
            value.responder_signed_x25519_pub,
            value.responder_one_time_x25519_pub,
            value.initiator_device_cert_hash,
            value.responder_device_cert_hash,
            value.responder_prekey_bundle_hash,
            _u32(value.signed_prekey_id),
            _u32(value.one_time_prekey_id),
            value.responder_mlkem768_ek,
            value.mlkem768_ciphertext,
            _u64(value.created_at_ms),
            _u64(value.expires_at_ms),
        )
    )
    if len(out) != INIT_SIGNED_PREFIX_LEN:
        raise AssertionError("PairInit V2 canonical length mismatch")
    return INIT_SIGNING_DOMAIN + out


def encode_init(value: PairInitV2) -> bytes:
    _validate_init(value, require_signature=True)
    wire = init_signing_bytes(value)[len(INIT_SIGNING_DOMAIN) :] + value.signature
    if len(wire) != INIT_WIRE_LEN:
        raise AssertionError("PairInit V2 wire length mismatch")
    return wire


def decode_init(wire: bytes) -> PairInitV2:
    if not isinstance(wire, bytes):
        raise ValueError("PairInit V2 wire must be bytes")
    if len(wire) >= 8 and wire[:8] == b"RVPI1\x00\x00\x00":
        raise ValueError("PairInit V1 must not be reinterpreted as V2")
    if len(wire) != INIT_WIRE_LEN:
        raise ValueError(f"PairInit V2 wire must be exactly {INIT_WIRE_LEN} bytes")
    if wire[:8] != INIT_MAGIC:
        raise ValueError("PairInit V2 magic mismatch")
    if wire[8] != VERSION or wire[9] != SUITE or wire[10] != INITIATOR_ROLE:
        raise ValueError("PairInit V2 version, suite, or role mismatch")
    if wire[11] != PROFILE_LEN or wire[12 : 12 + PROFILE_LEN] != PROFILE_ID:
        raise ValueError("PairInit V2 profile mismatch")
    offset = 12 + PROFILE_LEN

    def take(length: int) -> bytes:
        nonlocal offset
        result = wire[offset : offset + length]
        offset += length
        return result

    try:
        initiator_address = take(ADDRESS_LEN).decode("ascii")
        responder_address = take(ADDRESS_LEN).decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("PairInit address is not ASCII") from exc
    value = PairInitV2(
        initiator_address=initiator_address,
        responder_address=responder_address,
        init_id=take(INIT_ID_LEN),
        pairing_nonce=take(NONCE_LEN),
        initiator_device_ed_pub=take(ED25519_KEY_LEN),
        responder_device_ed_pub=take(ED25519_KEY_LEN),
        initiator_ephemeral_x25519_pub=take(X25519_KEY_LEN),
        responder_signed_x25519_pub=take(X25519_KEY_LEN),
        responder_one_time_x25519_pub=take(X25519_KEY_LEN),
        initiator_device_cert_hash=take(32),
        responder_device_cert_hash=take(32),
        responder_prekey_bundle_hash=take(32),
        signed_prekey_id=int.from_bytes(take(4), "big"),
        one_time_prekey_id=int.from_bytes(take(4), "big"),
        responder_mlkem768_ek=take(MLKEM768_EK_LEN),
        mlkem768_ciphertext=take(MLKEM768_CT_LEN),
        created_at_ms=int.from_bytes(take(8), "big"),
        expires_at_ms=int.from_bytes(take(8), "big"),
        signature=take(SIGNATURE_LEN),
    )
    if offset != len(wire):
        raise ValueError("PairInit V2 trailing bytes")
    _validate_init(value, require_signature=True)
    return value


def wire_offsets() -> dict[str, int]:
    """Frozen offsets for PairInit V2 (PROFILE_LEN=23)."""
    o = 0
    out: dict[str, int] = {"magic": o}
    o += 8
    out["version"] = o
    o += 1
    out["suite"] = o
    o += 1
    out["role"] = o
    o += 1
    out["profile_len"] = o
    o += 1
    out["profile"] = o
    o += PROFILE_LEN
    out["initiator_address"] = o
    o += ADDRESS_LEN
    out["responder_address"] = o
    o += ADDRESS_LEN
    out["init_id"] = o
    o += INIT_ID_LEN
    out["pairing_nonce"] = o
    o += NONCE_LEN
    out["initiator_device_ed_pub"] = o
    o += 32
    out["responder_device_ed_pub"] = o
    o += 32
    out["initiator_ephemeral_x25519_pub"] = o
    o += 32
    out["responder_signed_x25519_pub"] = o
    o += 32
    out["responder_one_time_x25519_pub"] = o
    o += 32
    out["initiator_device_cert_hash"] = o
    o += 32
    out["responder_device_cert_hash"] = o
    o += 32
    out["responder_prekey_bundle_hash"] = o
    o += 32
    out["signed_prekey_id"] = o
    o += 4
    out["one_time_prekey_id"] = o
    o += 4
    out["responder_mlkem768_ek"] = o
    o += MLKEM768_EK_LEN
    out["mlkem768_ciphertext"] = o
    o += MLKEM768_CT_LEN
    out["created_at_ms"] = o
    o += 8
    out["expires_at_ms"] = o
    o += 8
    out["signature"] = o
    o += 64
    out["total_len"] = o
    return out


def init_hash_v2(wire: bytes) -> bytes:
    _require_bytes(wire, INIT_WIRE_LEN, "pair_init_v2_wire")
    return hashlib.sha256(PAIR_INIT_LABEL + wire).digest()


def transcript_hash(wire: bytes) -> bytes:
    _require_bytes(wire, INIT_WIRE_LEN, "pair_init_v2_wire")
    return hashlib.sha256(TRANSCRIPT_DOMAIN + PAIR_INIT_LABEL + wire).digest()


def pair_expand(z_x: bytes, z_pq: bytes, wire: bytes) -> PairExpandV2:
    """IKM_pair = Z_X || Z_PQ → SK_ec || SK_scka || K_route_master || K_confirm."""
    _require_bytes(z_x, 32, "z_x")
    _require_bytes(z_pq, 32, "z_pq")
    th = transcript_hash(wire)
    ih = init_hash_v2(wire)
    okm = hkdf_sha256(
        ikm=z_x + z_pq,
        salt=th,
        info=PAIR_EXPAND_INFO_PREFIX + th,
        length=128,
    )
    return PairExpandV2(
        sk_ec=okm[0:32],
        sk_scka=okm[32:64],
        k_route_master=okm[64:96],
        k_confirm=okm[96:128],
        transcript_hash=th,
        init_hash_v2=ih,
        session_id=hashlib.sha256(SESSION_ID_DOMAIN + ih).digest(),
    )


def confirmation_tag(k_confirm: bytes, init_digest: bytes) -> bytes:
    _require_bytes(k_confirm, 32, "k_confirm")
    _require_bytes(init_digest, 32, "init_hash_v2")
    return hmac.new(
        k_confirm, CONFIRM_LABEL + b"\x00" + init_digest, hashlib.sha256
    ).digest()


def _validate_response(value: PairResponseV2, require_signature: bool) -> None:
    _require_bytes(value.init_id, INIT_ID_LEN, "init_id")
    if value.init_id == bytes(INIT_ID_LEN):
        raise ValueError("init_id must not be all-zero")
    _require_bytes(value.init_hash, 32, "init_hash")
    _require_bytes(value.responder_device_ed_pub, 32, "responder_device_ed_pub")
    _validate_time(value.created_at_ms, value.expires_at_ms)
    _require_bytes(value.confirmation_tag, 32, "confirmation_tag")
    if require_signature:
        _require_bytes(value.signature, SIGNATURE_LEN, "signature")


def response_signing_bytes(value: PairResponseV2) -> bytes:
    _validate_response(value, require_signature=False)
    out = b"".join(
        (
            RESPONSE_MAGIC,
            bytes((VERSION, SUITE, RESPONDER_ROLE, PROFILE_LEN)),
            PROFILE_ID,
            value.init_id,
            value.init_hash,
            value.responder_device_ed_pub,
            _u64(value.created_at_ms),
            _u64(value.expires_at_ms),
            value.confirmation_tag,
        )
    )
    if len(out) != RESPONSE_SIGNED_PREFIX_LEN:
        raise AssertionError("PairResponse V2 canonical length mismatch")
    return RESPONSE_SIGNING_DOMAIN + out


def encode_response(value: PairResponseV2) -> bytes:
    _validate_response(value, require_signature=True)
    wire = response_signing_bytes(value)[len(RESPONSE_SIGNING_DOMAIN) :] + value.signature
    if len(wire) != RESPONSE_WIRE_LEN:
        raise AssertionError("PairResponse V2 wire length mismatch")
    return wire


def decode_response(wire: bytes) -> PairResponseV2:
    if not isinstance(wire, bytes) or len(wire) != RESPONSE_WIRE_LEN:
        raise ValueError(f"PairResponse V2 wire must be exactly {RESPONSE_WIRE_LEN} bytes")
    if wire[:8] == b"RVPR1\x00\x00\x00":
        raise ValueError("PairResponse V1 must not be reinterpreted as V2")
    if wire[:8] != RESPONSE_MAGIC:
        raise ValueError("PairResponse V2 magic mismatch")
    if wire[8] != VERSION or wire[9] != SUITE or wire[10] != RESPONDER_ROLE:
        raise ValueError("PairResponse V2 version, suite, or role mismatch")
    if wire[11] != PROFILE_LEN or wire[12 : 12 + PROFILE_LEN] != PROFILE_ID:
        raise ValueError("PairResponse V2 profile mismatch")
    offset = 12 + PROFILE_LEN

    def take(length: int) -> bytes:
        nonlocal offset
        result = wire[offset : offset + length]
        offset += length
        return result

    value = PairResponseV2(
        init_id=take(INIT_ID_LEN),
        init_hash=take(32),
        responder_device_ed_pub=take(32),
        created_at_ms=int.from_bytes(take(8), "big"),
        expires_at_ms=int.from_bytes(take(8), "big"),
        confirmation_tag=take(32),
        signature=take(SIGNATURE_LEN),
    )
    if offset != len(wire):
        raise ValueError("PairResponse V2 trailing bytes")
    _validate_response(value, require_signature=True)
    return value


def verify_init_signature(value: PairInitV2) -> bool:
    try:
        return ed25519_strict.verify(
            value.initiator_device_ed_pub, value.signature, init_signing_bytes(value)
        )
    except ValueError:
        return False


def verify_response_signature(value: PairResponseV2) -> bool:
    try:
        return ed25519_strict.verify(
            value.responder_device_ed_pub, value.signature, response_signing_bytes(value)
        )
    except ValueError:
        return False


__all__ = [
    "PairInitV2",
    "PairResponseV2",
    "PairExpandV2",
    "VERSION",
    "SUITE",
    "PROFILE_ID",
    "PROFILE_LEN",
    "INIT_MAGIC",
    "RESPONSE_MAGIC",
    "INIT_WIRE_LEN",
    "RESPONSE_WIRE_LEN",
    "PRODUCTION_ENABLED",
    "device_certificate_hash",
    "prekey_bundle_hash",
    "DEVICE_CERT_HASH_DOMAIN",
    "PREKEY_BUNDLE_HASH_DOMAIN",
    "init_signing_bytes",
    "encode_init",
    "decode_init",
    "wire_offsets",
    "init_hash_v2",
    "transcript_hash",
    "pair_expand",
    "confirmation_tag",
    "response_signing_bytes",
    "encode_response",
    "decode_response",
    "verify_init_signature",
    "verify_response_signature",
    "hkdf_sha256",
]
