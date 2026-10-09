"""ATSAM Indexed Session Profile V1 deterministic primitives.

This module is a protocol/vector reference only.  The profile is deliberately
not activated by any endpoint: a future signed PairInit must negotiate and bind
``PROFILE_ID`` into its transcript before these derivations are safe to use.
"""

from dataclasses import dataclass
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import address, ack, routing_tag, store_tags


PROFILE_ID = b"ATSAM/indexed-session/v1"
PRODUCTION_ENABLED = False
RVNA1_MAGIC = b"RVNA1\x00\x00\x00"
RVNA1_PROTO = 0x03
RVNA1_SUITE = 0x01

LABEL_ACK_BASE = b"ATSAM/v1/ack-seal"
LABEL_ROUTE_MASTER = b"ATSAM/v1/GhostRoute/recipient-tag"
LABEL_ROUTE_DIRECTION = b"ATSAM/v1/GhostRoute/rvn1-direction"
LABEL_CHAIN_INIT = b"ATSAM/v2/chain-init"
LABEL_CHAIN_ADVANCE = b"ATSAM/v2/chain-advance"
LABEL_MSG_KEY = b"ATSAM/v2/msg-key"
SALT_MSG_SEAL = b"ATSAM/v2/msg-seal/salt"
AAD_DOMAIN = b"ATSAM/v1/msg-seal/aad"

# Stateless helpers re-derive from CK_0 and do O(index) HKDF work (in open_ack
# before authentication). They have no counter, so skips are bounded relative
# to index 0; stateful receivers bound jumps relative to their own counter.
MAX_STATELESS_CHAIN_INDEX = 4_096

DIRECTION_INITIATOR_TO_RESPONDER = 0
DIRECTION_RESPONDER_TO_INITIATOR = 1
ACK_PLAINTEXT_LEN = 101
ACK_SEALED_WIRE_LEN = 143


def _hkdf_sha256(ikm: bytes, salt: bytes | None, info: bytes, length: int = 32) -> bytes:
    if salt is None:
        salt = bytes(32)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _require_root(root: bytes) -> None:
    if len(root) != 32:
        raise ValueError("K_root must be exactly 32 bytes")


def require_canonical_address(value: str) -> str:
    """Return an exact lowercase RavenAddressV1 string or raise.

    Display spellings, surrounding whitespace, mixed case, other versions, and
    malformed Bech32m are rejected instead of being silently normalized.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("address must be a non-empty string")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("address must be ASCII") from exc
    decoded = address.decode(value)
    if value != value.strip() or value != value.lower() or decoded is None:
        raise ValueError("address must be canonical lowercase RavenAddressV1")
    _, version = decoded
    if version != address.ADDRESS_VERSION:
        raise ValueError("unsupported Raven address version")
    return value


def session_context(initiator_address: str, responder_address: str) -> bytes:
    """PairInit transcript context: profile || NUL || initiator || NUL || responder."""
    initiator = require_canonical_address(initiator_address).encode("ascii")
    responder = require_canonical_address(responder_address).encode("ascii")
    if initiator == responder:
        raise ValueError("session endpoints must differ")
    return PROFILE_ID + b"\x00" + initiator + b"\x00" + responder


def _endpoints(initiator_address: str, responder_address: str, direction: int) -> tuple[str, str]:
    session_context(initiator_address, responder_address)
    if direction == DIRECTION_INITIATOR_TO_RESPONDER:
        return initiator_address, responder_address
    if direction == DIRECTION_RESPONDER_TO_INITIATOR:
        return responder_address, initiator_address
    raise ValueError("direction must be 0 or 1")


def initial_chain_key(root: bytes, sender: str, recipient: str) -> bytes:
    _require_root(root)
    sender_b = require_canonical_address(sender).encode("ascii")
    recipient_b = require_canonical_address(recipient).encode("ascii")
    if sender_b == recipient_b:
        raise ValueError("chain endpoints must differ")
    return _hkdf_sha256(root, None, LABEL_CHAIN_INIT + b"\x00" + sender_b + b"\x00" + recipient_b)


def advance_chain_key(chain_key: bytes) -> bytes:
    if len(chain_key) != 32:
        raise ValueError("chain key must be exactly 32 bytes")
    return _hkdf_sha256(chain_key, None, LABEL_CHAIN_ADVANCE)


def lane_message_key(chain_key: bytes, sender: str, recipient: str) -> bytes:
    if len(chain_key) != 32:
        raise ValueError("chain key must be exactly 32 bytes")
    sender_b = require_canonical_address(sender).encode("ascii")
    recipient_b = require_canonical_address(recipient).encode("ascii")
    return _hkdf_sha256(
        chain_key,
        SALT_MSG_SEAL,
        LABEL_MSG_KEY + b"\x00" + sender_b + b"\x00" + recipient_b,
    )


def chain_key_at_index(root: bytes, sender: str, recipient: str, index: int) -> bytes:
    if not 0 <= index <= 0xFFFFFFFF:
        raise ValueError("index must fit u32")
    if index > MAX_STATELESS_CHAIN_INDEX:
        raise ValueError("chain index exceeds the stateless derivation bound")
    chain_key = initial_chain_key(root, sender, recipient)
    for _ in range(index):
        chain_key = advance_chain_key(chain_key)
    return chain_key


def message_key_at_index(
    root: bytes,
    initiator_address: str,
    responder_address: str,
    direction: int,
    index: int,
) -> bytes:
    """Existing ATSAM message lane, unchanged by this profile."""
    sender, recipient = _endpoints(initiator_address, responder_address, direction)
    return lane_message_key(chain_key_at_index(root, sender, recipient, index), sender, recipient)


def ack_base_key(root: bytes) -> bytes:
    _require_root(root)
    return _hkdf_sha256(root, None, LABEL_ACK_BASE)


def ack_chain_key_at_index(
    root: bytes,
    initiator_address: str,
    responder_address: str,
    direction: int,
    index: int,
) -> bytes:
    sender, recipient = _endpoints(initiator_address, responder_address, direction)
    return chain_key_at_index(ack_base_key(root), sender, recipient, index)


def ack_key_at_index(
    root: bytes,
    initiator_address: str,
    responder_address: str,
    direction: int,
    index: int,
) -> bytes:
    sender, recipient = _endpoints(initiator_address, responder_address, direction)
    return lane_message_key(
        ack_chain_key_at_index(root, initiator_address, responder_address, direction, index),
        sender,
        recipient,
    )


def route_master_key(root: bytes) -> bytes:
    _require_root(root)
    return _hkdf_sha256(root, None, LABEL_ROUTE_MASTER)


def route_direction_key(root: bytes, direction: int) -> bytes:
    if direction not in (DIRECTION_INITIATOR_TO_RESPONDER, DIRECTION_RESPONDER_TO_INITIATOR):
        raise ValueError("direction must be 0 or 1")
    return _hkdf_sha256(
        route_master_key(root),
        None,
        LABEL_ROUTE_DIRECTION + b"\x00" + bytes([direction]),
    )


def route_coordinates(
    created_at_ms: int, index: int, env_type: int, direction: int
) -> tuple[int, int]:
    if not 0 <= created_at_ms <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("created_at_ms must fit u64")
    if not 0 <= index <= 0xFFFFFFFF:
        raise ValueError("index must fit u32")
    if env_type not in (1, 2, 3, 4):
        raise ValueError("env_type must be 1 through 4")
    if direction not in (DIRECTION_INITIATOR_TO_RESPONDER, DIRECTION_RESPONDER_TO_INITIATOR):
        raise ValueError("direction must be 0 or 1")
    epoch = created_at_ms // 1000
    counter = (index << 3) | ((env_type - 1) << 1) | direction
    return epoch, counter


def derive_route_tag(
    root: bytes, created_at_ms: int, index: int, env_type: int, direction: int
) -> bytes:
    epoch, counter = route_coordinates(created_at_ms, index, env_type, direction)
    return routing_tag.derive(route_direction_key(root, direction), epoch, counter)


def mailbox_coordinates(unix_ms: int, direction: int) -> tuple[int, int]:
    if not 0 <= unix_ms <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("unix_ms must fit u64")
    if direction not in (DIRECTION_INITIATOR_TO_RESPONDER, DIRECTION_RESPONDER_TO_INITIATOR):
        raise ValueError("direction must be 0 or 1")
    return unix_ms // 86_400_000, direction


def derive_mailbox_tags(root: bytes, unix_ms: int, direction: int) -> tuple[bytes, bytes]:
    day_epoch, slot = mailbox_coordinates(unix_ms, direction)
    mailbox = store_tags.mailbox_tag(
        route_direction_key(root, direction), day_epoch, slot
    )
    return mailbox, store_tags.store_tag(mailbox)


def uuid_text(message_id: bytes) -> str:
    """Raw 16-byte ID as uppercase 8-4-4-4-12 UUID text for ATSAM AAD."""
    if len(message_id) != 16:
        raise ValueError("message_id must be exactly 16 bytes")
    value = message_id.hex().upper()
    return f"{value[:8]}-{value[8:12]}-{value[12:16]}-{value[16:20]}-{value[20:]}"


def build_aad(index: int, sender: str, recipient: str, message_id: bytes) -> bytes:
    if not 0 <= index <= 0xFFFFFFFF:
        raise ValueError("index must fit u32")
    sender_b = require_canonical_address(sender).encode("ascii")
    recipient_b = require_canonical_address(recipient).encode("ascii")
    msg_id_b = uuid_text(message_id).encode("ascii")
    return hashlib.sha256(
        AAD_DOMAIN
        + b"\x00"
        + bytes([RVNA1_PROTO, RVNA1_SUITE])
        + index.to_bytes(4, "big")
        + b"\x00"
        + sender_b
        + b"\x00"
        + recipient_b
        + b"\x00"
        + msg_id_b
    ).digest()


@dataclass(frozen=True)
class SignedAck:
    record: ack.Ack
    signature: bytes


def encode_signed_ack(record: ack.Ack, signature: bytes) -> bytes:
    # Validate all fixed-width fields through the canonical signing codec.
    ack.signing_bytes(record)
    if record.status not in (1, 2):
        raise ValueError("ACK status must be delivered(1) or read(2)")
    if len(signature) != 64:
        raise ValueError("ACK signature must be exactly 64 bytes")
    out = (
        record.acked_message_id
        + bytes([record.status])
        + record.ack_nonce
        + record.created_at.to_bytes(8, "big")
        + signature
    )
    assert len(out) == ACK_PLAINTEXT_LEN
    return out


def decode_signed_ack(data: bytes) -> SignedAck:
    if len(data) != ACK_PLAINTEXT_LEN:
        raise ValueError("signed ACK plaintext must be exactly 101 bytes")
    status = data[16]
    if status not in (1, 2):
        raise ValueError("ACK status must be delivered(1) or read(2)")
    record = ack.Ack(
        acked_message_id=data[:16],
        status=status,
        ack_nonce=data[17:29],
        created_at=int.from_bytes(data[29:37], "big"),
    )
    return SignedAck(record=record, signature=data[37:101])


def seal_ack(
    root: bytes,
    initiator_address: str,
    responder_address: str,
    direction: int,
    index: int,
    outer_message_id: bytes,
    plaintext: bytes,
    nonce: bytes,
) -> bytes:
    if len(plaintext) != ACK_PLAINTEXT_LEN:
        raise ValueError("signed ACK plaintext must be exactly 101 bytes")
    decode_signed_ack(plaintext)
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 nonce must be exactly 12 bytes")
    sender, recipient = _endpoints(initiator_address, responder_address, direction)
    key = ack_key_at_index(root, initiator_address, responder_address, direction, index)
    aad = build_aad(index, sender, recipient, outer_message_id)
    ciphertext_and_tag = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    wire = (
        RVNA1_MAGIC
        + bytes([RVNA1_PROTO, RVNA1_SUITE])
        + index.to_bytes(4, "big")
        + nonce
        + ciphertext_and_tag
    )
    assert len(wire) == ACK_SEALED_WIRE_LEN
    return wire


def open_ack(
    root: bytes,
    initiator_address: str,
    responder_address: str,
    direction: int,
    outer_message_id: bytes,
    wire: bytes,
) -> bytes:
    if len(wire) != ACK_SEALED_WIRE_LEN:
        raise ValueError("sealed ACK body must be exactly 143 bytes")
    if wire[:8] != RVNA1_MAGIC or wire[8] != RVNA1_PROTO or wire[9] != RVNA1_SUITE:
        raise ValueError("unsupported sealed ACK header")
    index = int.from_bytes(wire[10:14], "big")
    if index > MAX_STATELESS_CHAIN_INDEX:
        raise ValueError("chain index exceeds the stateless derivation bound")
    nonce = wire[14:26]
    sender, recipient = _endpoints(initiator_address, responder_address, direction)
    key = ack_key_at_index(root, initiator_address, responder_address, direction, index)
    aad = build_aad(index, sender, recipient, outer_message_id)
    plaintext = ChaCha20Poly1305(key).decrypt(nonce, wire[26:], aad)
    if len(plaintext) != ACK_PLAINTEXT_LEN:
        raise ValueError("opened ACK plaintext has wrong size")
    decode_signed_ack(plaintext)
    return plaintext
