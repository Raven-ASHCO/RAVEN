from dataclasses import dataclass
from ._canon import u64
from . import ed25519_strict

@dataclass
class Ack:
    acked_message_id: bytes; status: int; ack_nonce: bytes; created_at: int

def signing_bytes(a: Ack) -> bytes:
    # Fixed-width fields are concatenated without length prefixes, so their sizes
    # are load-bearing invariants: a mis-sized value would silently shift field
    # boundaries. Assert them (ports MUST reject rather than truncate/pad).
    if len(a.acked_message_id) != 16:
        raise ValueError("acked_message_id must be exactly 16 bytes")
    if len(a.ack_nonce) != 12:
        raise ValueError("ack_nonce must be exactly 12 bytes")
    if not 0 <= a.status <= 255:
        raise ValueError("status must fit in one byte")
    return b"rvn1/ack" + a.acked_message_id + bytes([a.status]) + a.ack_nonce + u64(a.created_at)

def verify(a: Ack, sig: bytes, signer_ed_pub: bytes) -> bool:
    try:
        return ed25519_strict.verify(signer_ed_pub, sig, signing_bytes(a))
    except ValueError:
        return False
