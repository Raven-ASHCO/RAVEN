"""Production-disabled Raven PairInit V1 canonical codec.

This is an additive protocol/vector reference.  It authenticates transcript
bytes and derives an offline-capable provisional hybrid root; it deliberately
does not perform networking, persistence, prekey consumption, or activation of
the ATSAM indexed-session profile.
"""

from dataclasses import dataclass, field
import hashlib
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from . import address, indexed_session


VERSION = 1
SUITE = 1
PRODUCTION_ENABLED = False
PROFILE_ID = indexed_session.PROFILE_ID
INIT_MAGIC = b"RVPI1\x00\x00\x00"
RESPONSE_MAGIC = b"RVPR1\x00\x00\x00"
TRANSCRIPT_DOMAIN = b"ATSAM/v1/transcript"
PAIR_INIT_LABEL = b"ATSAM/v1/pair-init"
INIT_SIGNING_DOMAIN = b"rvn1/pair-init"
RESPONSE_SIGNING_DOMAIN = b"rvn1/pair-response"
CONFIRM_LABEL = b"ATSAM/pair-init/v1/confirm"
DEVICE_CERT_HASH_DOMAIN = b"rvn1/pair-devcert"
PREKEY_BUNDLE_HASH_DOMAIN = b"rvn1/pair-prekey"
SESSION_ID_DOMAIN = b"rvn1/pair-session"
INITIATOR_ROLE = 0
RESPONDER_ROLE = 1
INIT_ID_LEN = 16
NONCE_LEN = 32
ED25519_KEY_LEN = 32
X25519_KEY_LEN = 32
MLKEM768_EK_LEN = 1184
MLKEM768_CT_LEN = 1088
SIGNATURE_LEN = 64
ADDRESS_LEN = 44
PROFILE_LEN = len(PROFILE_ID)

INIT_SIGNED_PREFIX_LEN = (
    8 + 1 + 1 + 1 + 1 + PROFILE_LEN + ADDRESS_LEN * 2 + INIT_ID_LEN
    + NONCE_LEN + ED25519_KEY_LEN * 2 + X25519_KEY_LEN * 3 + 32 * 3 + 4 + 4
    + MLKEM768_EK_LEN + MLKEM768_CT_LEN + 8 + 8
)
INIT_WIRE_LEN = INIT_SIGNED_PREFIX_LEN + SIGNATURE_LEN
RESPONSE_SIGNED_PREFIX_LEN = (
    8 + 1 + 1 + 1 + 1 + PROFILE_LEN + INIT_ID_LEN + 32
    + ED25519_KEY_LEN + 8 + 8 + 32
)
RESPONSE_WIRE_LEN = RESPONSE_SIGNED_PREFIX_LEN + SIGNATURE_LEN


@dataclass
class PairInit:
    initiator_address: str
    responder_address: str
    init_id: bytes
    pairing_nonce: bytes
    initiator_device_ed_pub: bytes
    responder_device_ed_pub: bytes
    initiator_ephemeral_x25519_pub: bytes
    responder_signed_x25519_pub: bytes
    responder_one_time_x25519_pub: bytes
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
class PairResponse:
    init_id: bytes
    init_hash: bytes
    responder_device_ed_pub: bytes
    created_at_ms: int
    expires_at_ms: int
    confirmation_tag: bytes
    signature: bytes = field(default=b"")


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


# Any scalar works: clamped X25519 scalars are cofactor multiples smaller than
# both prime orders, so the agreement is all-zero exactly for small-order
# inputs, whatever the responder's real private key is.
_CONTRIBUTORY_PROBE = X25519PrivateKey.from_private_bytes(bytes([0x5A]) * 32)


def is_contributory_x25519(public: bytes) -> bool:
    """False for low-order (non-contributory) X25519 public keys."""
    try:
        _CONTRIBUTORY_PROBE.exchange(X25519PublicKey.from_public_bytes(public))
    except ValueError:
        return False
    return True


def _validate_time(created_at_ms: int, expires_at_ms: int) -> None:
    _u64(created_at_ms)
    _u64(expires_at_ms)
    if expires_at_ms <= created_at_ms:
        raise ValueError("expires_at_ms must be greater than created_at_ms")


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    _require_bytes(salt, 32, "HKDF salt")
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def device_certificate_hash(
    identity_ed25519_pub: bytes, certificate_signing_bytes: bytes, signature: bytes
) -> bytes:
    """Digest an exact, already-validated device certificate."""
    _require_bytes(identity_ed25519_pub, 32, "identity_ed25519_pub")
    if not isinstance(certificate_signing_bytes, bytes) or not certificate_signing_bytes:
        raise ValueError("certificate_signing_bytes must be non-empty bytes")
    _require_bytes(signature, SIGNATURE_LEN, "certificate signature")
    return hashlib.sha256(
        DEVICE_CERT_HASH_DOMAIN
        + identity_ed25519_pub
        + certificate_signing_bytes
        + signature
    ).digest()


def prekey_bundle_hash(bundle_signing_bytes: bytes, signature: bytes) -> bytes:
    """Digest an exact, already-validated responder prekey bundle."""
    if not isinstance(bundle_signing_bytes, bytes) or not bundle_signing_bytes:
        raise ValueError("bundle_signing_bytes must be non-empty bytes")
    _require_bytes(signature, SIGNATURE_LEN, "prekey signature")
    return hashlib.sha256(
        PREKEY_BUNDLE_HASH_DOMAIN + bundle_signing_bytes + signature
    ).digest()


def _validate_init(value: PairInit, require_signature: bool) -> None:
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
        value.initiator_ephemeral_x25519_pub,
        X25519_KEY_LEN,
        "initiator_ephemeral_x25519_pub",
    )
    if value.initiator_ephemeral_x25519_pub == bytes(X25519_KEY_LEN):
        raise ValueError("initiator_ephemeral_x25519_pub must not be all-zero")
    if not is_contributory_x25519(value.initiator_ephemeral_x25519_pub):
        raise ValueError("initiator_ephemeral_x25519_pub must not be a low-order point")
    _require_bytes(
        value.responder_signed_x25519_pub,
        X25519_KEY_LEN,
        "responder_signed_x25519_pub",
    )
    if value.responder_signed_x25519_pub == bytes(X25519_KEY_LEN):
        raise ValueError("responder_signed_x25519_pub must not be all-zero")
    _require_bytes(
        value.responder_one_time_x25519_pub,
        X25519_KEY_LEN,
        "responder_one_time_x25519_pub",
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


def init_signing_bytes(value: PairInit) -> bytes:
    """Exact bytes signed by the initiator device."""
    _validate_init(value, require_signature=False)
    out = b"".join(
        (
            INIT_MAGIC,
            bytes((VERSION, SUITE, INITIATOR_ROLE, len(PROFILE_ID))),
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
        raise AssertionError("PairInit canonical length mismatch")
    return INIT_SIGNING_DOMAIN + out


def encode_init(value: PairInit) -> bytes:
    _validate_init(value, require_signature=True)
    wire = init_signing_bytes(value)[len(INIT_SIGNING_DOMAIN):] + value.signature
    if len(wire) != INIT_WIRE_LEN:
        raise AssertionError("PairInit wire length mismatch")
    return wire


def decode_init(wire: bytes) -> PairInit:
    if not isinstance(wire, bytes) or len(wire) != INIT_WIRE_LEN:
        raise ValueError(f"PairInit wire must be exactly {INIT_WIRE_LEN} bytes")
    if wire[:8] != INIT_MAGIC:
        raise ValueError("PairInit magic mismatch")
    if wire[8] != VERSION or wire[9] != SUITE or wire[10] != INITIATOR_ROLE:
        raise ValueError("PairInit version, suite, or role mismatch")
    if wire[11] != PROFILE_LEN or wire[12 : 12 + PROFILE_LEN] != PROFILE_ID:
        raise ValueError("PairInit profile mismatch")
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
    value = PairInit(
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
        raise ValueError("PairInit trailing bytes")
    _validate_init(value, require_signature=True)
    return value


def init_hash(value: PairInit) -> bytes:
    """SHA-256 of the exact signed PairInit wire, including its signature."""
    return hashlib.sha256(INIT_SIGNING_DOMAIN + encode_init(value)).digest()


def session_id(value: PairInit) -> bytes:
    """Stable opaque session key for one exact accepted PairInit."""
    return hashlib.sha256(SESSION_ID_DOMAIN + init_hash(value)).digest()


def transcript_material(value: PairInit) -> bytes:
    """Canonical ATSAM material used for the provisional hybrid root.

    The full signed PairInit hash binds profile, roles, addresses, both exact
    device keys, responder prekey id/material, the ML-KEM contribution, nonce,
    validity window, and initiator signature.  Binding the signature prevents a
    forged unsigned body from deriving the same accepted transcript.
    """
    _validate_init(value, require_signature=True)
    return INIT_SIGNING_DOMAIN + encode_init(value)


def transcript_hash(value: PairInit) -> bytes:
    return hashlib.sha256(TRANSCRIPT_DOMAIN + transcript_material(value)).digest()


def derive_provisional_root(z_x: bytes, z_pq: bytes, value: PairInit) -> bytes:
    _require_bytes(z_x, 32, "z_x")
    _require_bytes(z_pq, 32, "z_pq")
    digest = transcript_hash(value)
    return _hkdf_sha256(z_x + z_pq, digest, PAIR_INIT_LABEL + digest)


def verify_init(
    value: PairInit,
    initiator_identity_ed_pub: bytes,
    responder_identity_ed_pub: bytes,
    *,
    expected_initiator_device_ed_pub: bytes,
    expected_responder_device_ed_pub: bytes,
    expected_responder_signed_x25519_pub: bytes,
    expected_responder_one_time_x25519_pub: bytes,
    expected_initiator_device_cert_hash: bytes,
    expected_responder_device_cert_hash: bytes,
    expected_responder_prekey_bundle_hash: bytes,
    expected_signed_prekey_id: int,
    expected_one_time_prekey_id: int,
    expected_responder_mlkem768_ek: bytes,
    expected_trust_not_before_ms: int,
    expected_trust_not_after_ms: int,
    now_ms: int,
) -> bool:
    """Verify a PairInit against already-validated cert and prekey state.

    Certificate signatures, validity/revocation state, and the responder prekey
    bundle signature/validity MUST be checked by the caller before passing their
    exact expected fields here.  This function never normalizes or discovers
    identities from untrusted PairInit bytes.
    """
    try:
        _validate_init(value, require_signature=True)
        if address.encode(_require_bytes(initiator_identity_ed_pub, 32, "initiator_identity_ed_pub")) != value.initiator_address:
            return False
        if address.encode(_require_bytes(responder_identity_ed_pub, 32, "responder_identity_ed_pub")) != value.responder_address:
            return False
        if value.initiator_device_ed_pub != _require_bytes(expected_initiator_device_ed_pub, 32, "expected_initiator_device_ed_pub"):
            return False
        if value.responder_device_ed_pub != _require_bytes(expected_responder_device_ed_pub, 32, "expected_responder_device_ed_pub"):
            return False
        if value.responder_signed_x25519_pub != _require_bytes(expected_responder_signed_x25519_pub, 32, "expected_responder_signed_x25519_pub"):
            return False
        if value.responder_one_time_x25519_pub != _require_bytes(expected_responder_one_time_x25519_pub, 32, "expected_responder_one_time_x25519_pub"):
            return False
        if value.initiator_device_cert_hash != _require_bytes(expected_initiator_device_cert_hash, 32, "expected_initiator_device_cert_hash"):
            return False
        if value.responder_device_cert_hash != _require_bytes(expected_responder_device_cert_hash, 32, "expected_responder_device_cert_hash"):
            return False
        if value.responder_prekey_bundle_hash != _require_bytes(expected_responder_prekey_bundle_hash, 32, "expected_responder_prekey_bundle_hash"):
            return False
        if value.signed_prekey_id != expected_signed_prekey_id:
            return False
        if value.one_time_prekey_id != expected_one_time_prekey_id:
            return False
        if value.responder_mlkem768_ek != _require_bytes(expected_responder_mlkem768_ek, MLKEM768_EK_LEN, "expected_responder_mlkem768_ek"):
            return False
        if (
            value.created_at_ms < expected_trust_not_before_ms
            or value.expires_at_ms > expected_trust_not_after_ms
        ):
            return False
        if not value.created_at_ms <= now_ms < value.expires_at_ms:
            return False
        Ed25519PublicKey.from_public_bytes(value.initiator_device_ed_pub).verify(
            value.signature, init_signing_bytes(value)
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def confirmation_tag(root: bytes, init_digest: bytes) -> bytes:
    _require_bytes(root, 32, "root")
    _require_bytes(init_digest, 32, "init_hash")
    return hmac.new(
        root, CONFIRM_LABEL + b"\x00" + init_digest, hashlib.sha256
    ).digest()


def _validate_response(value: PairResponse, require_signature: bool) -> None:
    _require_bytes(value.init_id, INIT_ID_LEN, "init_id")
    if value.init_id == bytes(INIT_ID_LEN):
        raise ValueError("init_id must not be all-zero")
    _require_bytes(value.init_hash, 32, "init_hash")
    _require_bytes(value.responder_device_ed_pub, 32, "responder_device_ed_pub")
    _validate_time(value.created_at_ms, value.expires_at_ms)
    _require_bytes(value.confirmation_tag, 32, "confirmation_tag")
    if any(
        field == bytes(len(field))
        for field in (
            value.init_hash,
            value.responder_device_ed_pub,
            value.confirmation_tag,
        )
    ):
        raise ValueError("PairResponse fixed fields must not be all-zero")
    if require_signature:
        _require_bytes(value.signature, SIGNATURE_LEN, "signature")


def response_signing_bytes(value: PairResponse) -> bytes:
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
        raise AssertionError("PairResponse canonical length mismatch")
    return RESPONSE_SIGNING_DOMAIN + out


def encode_response(value: PairResponse) -> bytes:
    _validate_response(value, require_signature=True)
    wire = response_signing_bytes(value)[len(RESPONSE_SIGNING_DOMAIN):] + value.signature
    if len(wire) != RESPONSE_WIRE_LEN:
        raise AssertionError("PairResponse wire length mismatch")
    return wire


def decode_response(wire: bytes) -> PairResponse:
    if not isinstance(wire, bytes) or len(wire) != RESPONSE_WIRE_LEN:
        raise ValueError(f"PairResponse wire must be exactly {RESPONSE_WIRE_LEN} bytes")
    if wire[:8] != RESPONSE_MAGIC:
        raise ValueError("PairResponse magic mismatch")
    if wire[8] != VERSION or wire[9] != SUITE or wire[10] != RESPONDER_ROLE:
        raise ValueError("PairResponse version, suite, or role mismatch")
    if wire[11] != PROFILE_LEN:
        raise ValueError("PairResponse profile mismatch")
    if wire[12 : 12 + PROFILE_LEN] != PROFILE_ID:
        raise ValueError("PairResponse profile mismatch")
    offset = 12 + PROFILE_LEN

    def take(length: int) -> bytes:
        nonlocal offset
        result = wire[offset : offset + length]
        offset += length
        return result

    value = PairResponse(
        init_id=take(INIT_ID_LEN),
        init_hash=take(32),
        responder_device_ed_pub=take(32),
        created_at_ms=int.from_bytes(take(8), "big"),
        expires_at_ms=int.from_bytes(take(8), "big"),
        confirmation_tag=take(32),
        signature=take(SIGNATURE_LEN),
    )
    if offset != len(wire):
        raise ValueError("PairResponse trailing bytes")
    _validate_response(value, require_signature=True)
    return value


def verify_response(
    value: PairResponse,
    accepted_init: PairInit,
    root: bytes,
    *,
    now_ms: int,
) -> bool:
    try:
        _validate_response(value, require_signature=True)
        if value.init_id != accepted_init.init_id:
            return False
        digest = init_hash(accepted_init)
        if value.init_hash != digest:
            return False
        if value.responder_device_ed_pub != accepted_init.responder_device_ed_pub:
            return False
        if (
            value.created_at_ms < accepted_init.created_at_ms
            or value.created_at_ms >= accepted_init.expires_at_ms
            or value.expires_at_ms > accepted_init.expires_at_ms
        ):
            return False
        if not value.created_at_ms <= now_ms < value.expires_at_ms:
            return False
        if not hmac.compare_digest(
            value.confirmation_tag, confirmation_tag(root, digest)
        ):
            return False
        Ed25519PublicKey.from_public_bytes(value.responder_device_ed_pub).verify(
            value.signature, response_signing_bytes(value)
        )
        return True
    except (InvalidSignature, ValueError):
        return False
