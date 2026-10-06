"""ATSAM/hybrid-ratchet/v2 Triple Ratchet Raven labels + AckV2 (vector freeze).

Implements Raven domain strings and KDF contracts from ATSAM_HYBRID_RATCHET_V2.
Does not implement full ML-KEM Braid epoch machinery yet — SCKA init KATs freeze
role-specific KDF_SCKA_INIT outputs only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .pair_init_v2 import hkdf_sha256

PROFILE = b"ATSAM/hybrid-ratchet/v2"
TR_PROTOCOL_INFO = PROFILE + b"\x00TR"
SPQR_PROTOCOL_INFO = PROFILE + b"\x00SPQR"
EC_RK_INFO = PROFILE + b"\x00EC-KDF-RK"
AEAD_NONCE_INFO = PROFILE + b"\x00AEAD-nonce"
SCKA_INIT_INFO = SPQR_PROTOCOL_INFO + b"\x00SCKA-INIT"
SCKA_INIT_ALICE_INFO = SCKA_INIT_INFO  # retained alias for catalog
SCKA_INIT_BOB_INFO = SCKA_INIT_INFO  # same expand; role reorders CKs

ACK_DOMAIN = b"ATSAM/v2/ack"
AAD_DOMAIN = b"ATSAM/v2/aad"
HEADER_DOMAIN = b"ATSAM/v2/tr-header"

# Sealed inner proto for this profile (not indexed 0x03)
SEALED_PROTO = 0x04
INNER_TYPE_MESSAGE = 0x01
INNER_TYPE_ACKV2 = 0x02

MAX_SKIP = 1000
ROUTE_LOOKAHEAD = 32
MAILBOX_LATE_ARRIVAL_DAYS = 7

PRODUCTION_ENABLED = False


def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """KDF_RK(rk, dh_out) -> (rk', ck). salt=rk, IKM=dh_out, info=EC_RK_INFO, L=64."""
    if len(rk) != 32 or len(dh_out) != 32:
        raise ValueError("rk and dh_out must be 32 bytes")
    if dh_out == bytes(32):
        raise ValueError("non-contributory DH rejected")
    okm = hkdf_sha256(ikm=dh_out, salt=rk, info=EC_RK_INFO, length=64)
    return okm[:32], okm[32:]


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """KDF_CK(ck) -> (ck', mk). HMAC 0x01→mk, 0x02→ck'."""
    if ck is None or len(ck) != 32:
        raise ValueError("ck must be 32 bytes")
    mk = hmac.new(ck, b"\x01", hashlib.sha256).digest()
    ck2 = hmac.new(ck, b"\x02", hashlib.sha256).digest()
    return ck2, mk


def kdf_hybrid(ec_mk: bytes, scka_mk: bytes) -> tuple[bytes, bytes]:
    """KDF_HYBRID → (aead_key32, nonce12). salt=scka_mk, IKM=ec_mk, info=TR, L=44."""
    if len(ec_mk) != 32 or len(scka_mk) != 32:
        raise ValueError("message keys must be 32 bytes")
    okm = hkdf_sha256(ikm=ec_mk, salt=scka_mk, info=TR_PROTOCOL_INFO, length=44)
    return okm[:32], okm[32:44]


@dataclass(frozen=True)
class SckaInitOut:
    rk: bytes
    ck_send: bytes
    ck_recv: bytes


def ratchet_init_alice_scka(sk_scka: bytes) -> SckaInitOut:
    """RatchetInitAliceSCKA — A2B: (RK, CKs, CKr) from shared SCKA-INIT expand."""
    if len(sk_scka) != 32:
        raise ValueError("SK_scka must be 32 bytes")
    okm = hkdf_sha256(ikm=sk_scka, salt=bytes(32), info=SCKA_INIT_INFO, length=96)
    return SckaInitOut(rk=okm[0:32], ck_send=okm[32:64], ck_recv=okm[64:96])


def ratchet_init_bob_scka(sk_scka: bytes) -> SckaInitOut:
    """RatchetInitBobSCKA — B2A: same expand, CK send/recv swapped."""
    if len(sk_scka) != 32:
        raise ValueError("SK_scka must be 32 bytes")
    okm = hkdf_sha256(ikm=sk_scka, salt=bytes(32), info=SCKA_INIT_INFO, length=96)
    return SckaInitOut(rk=okm[0:32], ck_send=okm[64:96], ck_recv=okm[32:64])


@dataclass
class EcHeader:
    dh_pub: bytes  # 32
    pn: int  # u32
    n: int  # u32


@dataclass
class SpqrHeader:
    """Minimal frozen SPQR chunk stub for vectors (epoch + ctr + optional ct digest)."""

    sending_epoch: int  # u32
    receiving_epoch: int  # u32
    send_ctr: int  # u32
    chunk_flags: int  # u8
    kem_ct_digest: bytes  # 32; SHA-256 of Braid CT chunk or zeros if none


def encode_composite_header(ec: EcHeader, spqr: SpqrHeader) -> bytes:
    """Frozen pre-Full-Braid stub header (u32 epoch/counter fields).

    Normative Braid epochs are u64be (§5.1; Full Braid RVCH1/RVBC1). This stub
    keeps its frozen width, so out-of-range values fail closed rather than
    truncating or wrapping.
    """
    if len(ec.dh_pub) != 32:
        raise ValueError("dh_pub")
    if len(spqr.kem_ct_digest) != 32:
        raise ValueError("kem_ct_digest")
    for name, value in (
        ("pn", ec.pn),
        ("n", ec.n),
        ("sending_epoch", spqr.sending_epoch),
        ("receiving_epoch", spqr.receiving_epoch),
        ("send_ctr", spqr.send_ctr),
    ):
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(f"composite header {name} out of u32 range")
    return b"".join(
        (
            HEADER_DOMAIN,
            bytes([SEALED_PROTO]),
            ec.dh_pub,
            ec.pn.to_bytes(4, "big"),
            ec.n.to_bytes(4, "big"),
            spqr.sending_epoch.to_bytes(4, "big"),
            spqr.receiving_epoch.to_bytes(4, "big"),
            spqr.send_ctr.to_bytes(4, "big"),
            bytes([spqr.chunk_flags & 0xFF]),
            spqr.kem_ct_digest,
        )
    )


COMPOSITE_HEADER_LEN = len(HEADER_DOMAIN) + 1 + 32 + 4 + 4 + 4 + 4 + 4 + 1 + 32


def aead_aad(
    *,
    session_id: bytes,
    initiator_address: str,
    responder_address: str,
    direction: int,  # 0=A2B, 1=B2A
    sender_device_cert_hash: bytes,
    ec: EcHeader,
    spqr: SpqrHeader,
    header_bytes: bytes,
) -> bytes:
    if len(session_id) != 32 or len(sender_device_cert_hash) != 32:
        raise ValueError("digest lengths")
    return b"".join(
        (
            AAD_DOMAIN,
            PROFILE,
            bytes([0x01, SEALED_PROTO, direction & 0xFF]),
            session_id,
            initiator_address.encode("ascii"),
            b"\x00",
            responder_address.encode("ascii"),
            sender_device_cert_hash,
            ec.dh_pub,
            ec.n.to_bytes(4, "big"),
            spqr.sending_epoch.to_bytes(4, "big"),
            spqr.send_ctr.to_bytes(4, "big"),
            header_bytes,
        )
    )


def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


@dataclass
class AckV2:
    acked_message_id: bytes  # 16
    acked_object_digest: bytes  # 32
    status: int  # 1 delivered, 2 read
    ack_nonce: bytes  # 12
    created_at_ms: int
    recipient_device_cert_hash: bytes  # 32
    session_id: bytes  # 32
    signature: bytes = field(default=b"")


def ack_signing_bytes(ack: AckV2) -> bytes:
    if len(ack.acked_message_id) != 16:
        raise ValueError("acked_message_id")
    if len(ack.acked_object_digest) != 32:
        raise ValueError("acked_object_digest")
    if ack.status not in (1, 2):
        raise ValueError("status")
    if len(ack.ack_nonce) != 12:
        raise ValueError("ack_nonce")
    if len(ack.recipient_device_cert_hash) != 32 or len(ack.session_id) != 32:
        raise ValueError("binding")
    return b"".join(
        (
            ACK_DOMAIN,
            ack.acked_message_id,
            ack.acked_object_digest,
            bytes([ack.status]),
            ack.ack_nonce,
            ack.created_at_ms.to_bytes(8, "big"),
            ack.recipient_device_cert_hash,
            ack.session_id,
        )
    )


def encode_ack_plaintext(ack: AckV2) -> bytes:
    if len(ack.signature) != 64:
        raise ValueError("signature")
    return ack_signing_bytes(ack)[len(ACK_DOMAIN) :] + ack.signature


ACK_PLAINTEXT_LEN = 16 + 32 + 1 + 12 + 8 + 32 + 32 + 64  # 197


def decode_ack_plaintext(buf: bytes) -> AckV2:
    if len(buf) != ACK_PLAINTEXT_LEN:
        raise ValueError("AckV2 plaintext length")
    off = 0

    def take(n: int) -> bytes:
        nonlocal off
        b = buf[off : off + n]
        off += n
        return b

    ack = AckV2(
        acked_message_id=take(16),
        acked_object_digest=take(32),
        status=take(1)[0],
        ack_nonce=take(12),
        created_at_ms=int.from_bytes(take(8), "big"),
        recipient_device_cert_hash=take(32),
        session_id=take(32),
        signature=take(64),
    )
    return ack


def sign_ack(ack: AckV2, device_ed_priv: bytes) -> AckV2:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.from_private_bytes(device_ed_priv)
    sig = priv.sign(ack_signing_bytes(ack))
    return AckV2(
        acked_message_id=ack.acked_message_id,
        acked_object_digest=ack.acked_object_digest,
        status=ack.status,
        ack_nonce=ack.ack_nonce,
        created_at_ms=ack.created_at_ms,
        recipient_device_cert_hash=ack.recipient_device_cert_hash,
        session_id=ack.session_id,
        signature=sig,
    )


def verify_ack(ack: AckV2, device_ed_pub: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(device_ed_pub).verify(
            ack.signature, ack_signing_bytes(ack)
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def domain_catalog() -> dict[str, str]:
    """Frozen domain / info labels for vector metadata."""
    return {
        "PROFILE": PROFILE.hex(),
        "TR_PROTOCOL_INFO": TR_PROTOCOL_INFO.hex(),
        "SPQR_PROTOCOL_INFO": SPQR_PROTOCOL_INFO.hex(),
        "EC_RK_INFO": EC_RK_INFO.hex(),
        "AEAD_NONCE_INFO": AEAD_NONCE_INFO.hex(),
        "SCKA_INIT_INFO": SCKA_INIT_INFO.hex(),
        "SCKA_INIT_ALICE_INFO": SCKA_INIT_ALICE_INFO.hex(),
        "SCKA_INIT_BOB_INFO": SCKA_INIT_BOB_INFO.hex(),
        "ACK_DOMAIN": ACK_DOMAIN.hex(),
        "AAD_DOMAIN": AAD_DOMAIN.hex(),
        "HEADER_DOMAIN": HEADER_DOMAIN.hex(),
        "SEALED_PROTO": f"{SEALED_PROTO:02x}",
        "MAX_SKIP": str(MAX_SKIP),
        "ROUTE_LOOKAHEAD": str(ROUTE_LOOKAHEAD),
        "MAILBOX_LATE_ARRIVAL_DAYS": str(MAILBOX_LATE_ARRIVAL_DAYS),
        "COMPOSITE_HEADER_LEN": str(COMPOSITE_HEADER_LEN),
        "ACK_PLAINTEXT_LEN": str(ACK_PLAINTEXT_LEN),
        "KDF_HYBRID_L": "44",
        "AEAD": "ChaCha20-Poly1305",
    }


__all__ = [
    "PROFILE",
    "TR_PROTOCOL_INFO",
    "SPQR_PROTOCOL_INFO",
    "EC_RK_INFO",
    "SEALED_PROTO",
    "MAX_SKIP",
    "PRODUCTION_ENABLED",
    "kdf_rk",
    "kdf_ck",
    "kdf_hybrid",
    "ratchet_init_alice_scka",
    "ratchet_init_bob_scka",
    "SckaInitOut",
    "EcHeader",
    "SpqrHeader",
    "encode_composite_header",
    "COMPOSITE_HEADER_LEN",
    "aead_aad",
    "aead_seal",
    "aead_open",
    "AckV2",
    "ack_signing_bytes",
    "encode_ack_plaintext",
    "decode_ack_plaintext",
    "sign_ack",
    "verify_ack",
    "ACK_PLAINTEXT_LEN",
    "domain_catalog",
    "INNER_TYPE_MESSAGE",
    "INNER_TYPE_ACKV2",
]
