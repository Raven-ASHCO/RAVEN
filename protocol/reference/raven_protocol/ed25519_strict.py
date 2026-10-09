"""Strict Ed25519 verification shared by every reference verifier.

``cryptography`` delegates Ed25519 to OpenSSL, which checks the cofactorless
RFC 8032 equation ``[s]B = R + [k]A`` but does not reject small-order points.
With ``A = R = 01 00..00`` (the identity) and ``s = 0`` that equation holds for
every message, so plain OpenSSL verification accepts the forgery for any input.
The Rust verifier (``Identity::verify``: weak-key check, then ed25519-dalek
``verify_strict``) rejects it, and so must this reference.

Before calling OpenSSL, :func:`verify` applies the libsodium rules:

- a public key ``A`` or signature ``R`` whose 32-byte encoding, with the sign
  bit (bit 255) masked, is one of the seven small-order encodings below is
  rejected; and
- a non-canonical scalar ``s >= L`` is rejected.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PUBLIC_KEY_LEN = 32
SIGNATURE_LEN = 64
# Order of the edwards25519 prime-order subgroup.
L = 2**252 + 27742317777372353535851937790883648493

# libsodium ``ge25519_has_small_order`` blocklist (y-coordinate encodings with
# bit 255 clear). Together with the masked sign bit it covers all eight
# small-order points and the non-canonical encodings y = p and y = p + 1.
SMALL_ORDER_ENCODINGS = tuple(
    bytes.fromhex(value)
    for value in (
        # y = 0: the two order-4 points
        "0000000000000000000000000000000000000000000000000000000000000000",
        # y = 1: the identity (order 1)
        "0100000000000000000000000000000000000000000000000000000000000000",
        # order-8 points
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        # y = p - 1: order 2
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        # y = p and y = p + 1: non-canonical encodings of y = 0 and y = 1
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    )
)


def is_small_order_encoding(encoding: bytes) -> bool:
    """True when a 32-byte point encoding is on the small-order blocklist."""
    if len(encoding) != PUBLIC_KEY_LEN:
        raise ValueError("Ed25519 point encoding must be 32 bytes")
    masked = bytes(encoding[:31]) + bytes([encoding[31] & 0x7F])
    return masked in SMALL_ORDER_ENCODINGS


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Strict Ed25519 verification; never raises for malformed input."""
    try:
        public_key = bytes(public_key)
        signature = bytes(signature)
        message = bytes(message)
    except TypeError:
        return False
    if len(public_key) != PUBLIC_KEY_LEN or len(signature) != SIGNATURE_LEN:
        return False
    if is_small_order_encoding(public_key) or is_small_order_encoding(signature[:32]):
        return False
    if int.from_bytes(signature[32:], "little") >= L:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True
