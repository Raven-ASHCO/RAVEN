from dataclasses import dataclass, field
from ._canon import lp, u64
from . import ed25519_strict

@dataclass
class DeviceCert:
    device_ed_pub: bytes; device_x_pub: bytes; device_id: str
    not_before: int; not_after: int; capabilities: int
    signature: bytes = field(default=b"")

def signing_bytes(c: DeviceCert) -> bytes:
    return (b"rvn1/devcert" + lp(c.device_ed_pub) + lp(c.device_x_pub)
            + lp(c.device_id.encode()) + u64(c.not_before) + u64(c.not_after) + u64(c.capabilities))

def verify(c: DeviceCert, user_identity_ed_pub: bytes) -> bool:
    try:
        return ed25519_strict.verify(user_identity_ed_pub, c.signature, signing_bytes(c))
    except ValueError:
        return False
