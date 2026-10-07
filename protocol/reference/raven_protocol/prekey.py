"""RavenPrekeyBundleV1 canonical signing form.

This module intentionally covers the signed bundle container, not ML-KEM itself.
The encapsulation key in structural vectors is deterministic test material.
"""

from dataclasses import dataclass, field

from . import ed25519_strict
from ._canon import lp, u64


DOMAIN = b"rvn1/prekey"
VERSION = 1
MLKEM768_EK_LEN = 1184
MAX_DEVICE_ID_BYTES = 64
# RAVEN_PREKEY_BUNDLE_V1.md §4 clock tolerance, applied to both window bounds
# (Rust `PrekeyBundle::verify`): valid iff
# created_at_ms - 300000 <= now_ms <= expires_at_ms + 300000.
CLOCK_SKEW_MS = 300_000


@dataclass
class PrekeyBundle:
    identity_ed25519_pub: bytes
    device_id: str
    x25519_pub: bytes
    mlkem768_ek: bytes
    signed_prekey_id: int
    one_time_prekey_id: int
    one_time_x25519_pub: bytes | None
    created_at_ms: int
    expires_at_ms: int
    signature: bytes = field(default=b"")


def signing_bytes(bundle: PrekeyBundle) -> bytes:
    if len(bundle.identity_ed25519_pub) != 32:
        raise ValueError("identity Ed25519 public key must be 32 bytes")
    if len(bundle.x25519_pub) != 32:
        raise ValueError("X25519 public key must be 32 bytes")
    if len(bundle.mlkem768_ek) != MLKEM768_EK_LEN:
        raise ValueError(f"ML-KEM-768 encapsulation key must be {MLKEM768_EK_LEN} bytes")
    if len(bundle.device_id.encode("utf-8")) > MAX_DEVICE_ID_BYTES:
        raise ValueError(f"device_id must be at most {MAX_DEVICE_ID_BYTES} UTF-8 bytes")
    if not 0 <= bundle.signed_prekey_id <= 0xFFFFFFFF:
        raise ValueError("signed prekey id exceeds u32")
    if not 0 <= bundle.one_time_prekey_id <= 0xFFFFFFFF:
        raise ValueError("one-time prekey id exceeds u32")
    if bundle.one_time_prekey_id == 0 and bundle.one_time_x25519_pub is not None:
        raise ValueError("one-time public key present with zero id")
    if bundle.one_time_prekey_id != 0:
        if bundle.one_time_x25519_pub is None or len(bundle.one_time_x25519_pub) != 32:
            raise ValueError("non-zero one-time prekey id requires a 32-byte public key")

    out = bytearray(DOMAIN)
    out.append(VERSION)
    out.extend(bundle.identity_ed25519_pub)
    out.extend(lp(bundle.device_id.encode("utf-8")))
    out.extend(bundle.x25519_pub)
    out.extend(bundle.mlkem768_ek)
    out.extend(bundle.signed_prekey_id.to_bytes(4, "big"))
    out.extend(bundle.one_time_prekey_id.to_bytes(4, "big"))
    if bundle.one_time_x25519_pub is not None:
        out.extend(bundle.one_time_x25519_pub)
    out.extend(u64(bundle.created_at_ms))
    out.extend(u64(bundle.expires_at_ms))
    return bytes(out)


def check_time(bundle: PrekeyBundle, now_ms: int) -> str | None:
    """§4 window: None if valid at ``now_ms``, else the Rust error code."""
    if bundle.expires_at_ms <= bundle.created_at_ms:
        return "PREKEY_EXPIRED"
    if now_ms + CLOCK_SKEW_MS < bundle.created_at_ms:
        return "PREKEY_NOT_YET_VALID"
    if now_ms > bundle.expires_at_ms + CLOCK_SKEW_MS:
        return "PREKEY_EXPIRED"
    return None


def verify(bundle: PrekeyBundle, now_ms: int | None = None) -> bool:
    """Signature (strict Ed25519) and, when ``now_ms`` is given, the §4 window.

    ``now_ms=None`` keeps the original signature-and-structure-only check for
    callers that validate time separately; acceptance decisions MUST pass the
    verifier's clock.
    """
    if len(bundle.signature) != 64:
        return False
    if now_ms is not None and check_time(bundle, now_ms) is not None:
        return False
    if bundle.mlkem768_ek == bytes(len(bundle.mlkem768_ek)):
        return False
    try:
        return ed25519_strict.verify(
            bundle.identity_ed25519_pub, bundle.signature, signing_bytes(bundle)
        )
    except ValueError:
        return False
