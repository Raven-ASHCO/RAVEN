from dataclasses import dataclass, field
from ._canon import lp, u64
from . import ed25519_strict

@dataclass
class AliasRecord:
    alias: str; identity_address: str; sequence: int; expires_at: int
    signature: bytes = field(default=b"")

def signing_bytes(r: AliasRecord) -> bytes:
    return (b"rvn1/alias" + lp(r.alias.encode()) + lp(r.identity_address.encode())
            + u64(r.sequence) + u64(r.expires_at))

def verify(r: AliasRecord, identity_ed_pub: bytes) -> bool:
    try:
        return ed25519_strict.verify(identity_ed_pub, r.signature, signing_bytes(r))
    except ValueError:
        return False
