# raven_protocol/envelope.py
import hashlib, struct
from dataclasses import dataclass
from . import ed25519_strict

MAGIC = b"RVN1"
VERSION = 1
PREFIX_FMT = ">4sBBH16s16sQQQBB12sHIH"   # 86 bytes
PREFIX_LEN = struct.calcsize(PREFIX_FMT)
assert PREFIX_LEN == 86
MAX_WIRE_ENVELOPE_BYTES = 1_048_576
REGISTERED_ENV_TYPES = frozenset((1, 2, 3, 4))
ALLOWED_FLAGS = 0x0003
AUTHENTICATION_LEN = 64

@dataclass
class Envelope:
    env_type: int; flags: int
    message_id: bytes; routing_tag: bytes
    dest_device_hint: int; created_at: int; expires_at: int
    hop_limit: int; replication_budget: int; anti_replay_nonce: bytes
    ratchet_header_ciphertext: bytes; message_ciphertext: bytes
    sender_authentication: bytes

def pack(e: Envelope) -> bytes:
    prefix = struct.pack(
        PREFIX_FMT, MAGIC, VERSION, e.env_type, e.flags,
        e.message_id, e.routing_tag, e.dest_device_hint,
        e.created_at, e.expires_at, e.hop_limit, e.replication_budget,
        e.anti_replay_nonce, len(e.ratchet_header_ciphertext),
        len(e.message_ciphertext), len(e.sender_authentication),
    )
    return prefix + e.ratchet_header_ciphertext + e.message_ciphertext + e.sender_authentication

def unpack(raw: bytes):
    if (len(raw) < PREFIX_LEN or len(raw) > MAX_WIRE_ENVELOPE_BYTES
            or raw[:4] != MAGIC or raw[4] != VERSION):
        return None
    (_, _, env_type, flags, message_id, routing_tag, dest_hint, created_at,
     expires_at, hop_limit, repl, nonce, hdr_len, body_len, auth_len) = struct.unpack(
        PREFIX_FMT, raw[:PREFIX_LEN])
    if (env_type not in REGISTERED_ENV_TYPES or flags & ~ALLOWED_FLAGS
            or expires_at <= created_at or auth_len != AUTHENTICATION_LEN):
        return None
    # Python integers do not overflow, but explicit bounded endpoints model the
    # checked arithmetic required by fixed-width Rust/Swift decoders.
    header_end = PREFIX_LEN + hdr_len
    body_end = header_end + body_len
    authentication_end = body_end + auth_len
    if authentication_end > MAX_WIRE_ENVELOPE_BYTES or len(raw) != authentication_end:
        return None
    hdr = raw[PREFIX_LEN:header_end]
    body = raw[header_end:body_end]
    auth = raw[body_end:authentication_end]
    return Envelope(env_type, flags, message_id, routing_tag, dest_hint, created_at,
                    expires_at, hop_limit, repl, nonce, hdr, body, auth)

def signing_bytes(e: Envelope) -> bytes:
    # Zero the three relay-mutable fields; bind ciphertext blobs by hash.
    prefix = struct.pack(
        PREFIX_FMT, MAGIC, VERSION, e.env_type, e.flags,
        e.message_id, e.routing_tag, 0,          # dest_device_hint zeroed
        e.created_at, e.expires_at, 0, 0,        # hop_limit, replication_budget zeroed
        e.anti_replay_nonce, len(e.ratchet_header_ciphertext),
        len(e.message_ciphertext), 64,           # canonical auth_len for signing = 64
    )
    return prefix + hashlib.sha256(e.ratchet_header_ciphertext).digest() \
                  + hashlib.sha256(e.message_ciphertext).digest()

def verify(e: Envelope, signer_ed_pub: bytes) -> bool:
    try:
        return ed25519_strict.verify(
            signer_ed_pub, e.sender_authentication, signing_bytes(e))
    except ValueError:
        return False
