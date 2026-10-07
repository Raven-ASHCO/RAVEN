from dataclasses import dataclass, field
from ._canon import lp, u64
from . import ed25519_strict


@dataclass
class Capabilities:
    identity_address: str
    capability_bits: int
    expires_at: int
    signature: bytes = field(default=b"")


def signing_bytes(c: Capabilities) -> bytes:
    return (b"rvn1/caps" + lp(c.identity_address.encode())
            + u64(c.capability_bits) + u64(c.expires_at))


def verify(c: Capabilities, identity_ed_pub: bytes) -> bool:
    try:
        return ed25519_strict.verify(identity_ed_pub, c.signature, signing_bytes(c))
    except ValueError:
        return False
