import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from raven_protocol import (
    ack,
    alias,
    capabilities,
    device_cert,
    ed25519_strict,
    envelope,
    pair_init_v2,
    prekey,
)

RVN1 = Path(__file__).resolve().parents[3] / "shared-vectors" / "rvn1"


def _load(rel):
    return json.loads((RVN1 / rel).read_text())


@pytest.fixture(scope="module")
def forgery():
    return _load("negative/ed25519_weak_key_forgery_001.json")


def test_forgery_vector_is_rejected_for_every_message(forgery):
    inputs = forgery["inputs"]
    public_key = bytes.fromhex(inputs["public_key_hex"])
    signature = bytes.fromhex(inputs["signature_hex"])
    assert public_key == bytes([1]) + bytes(31)
    assert signature == public_key + bytes(32)
    assert forgery["expected"]["verify_result"] == "reject"
    for message in inputs["messages_hex"]:
        assert not ed25519_strict.verify(public_key, signature, bytes.fromhex(message))


def test_plain_openssl_accepts_the_forgery_so_the_helper_is_load_bearing(forgery):
    inputs = forgery["inputs"]
    public_key = bytes.fromhex(inputs["public_key_hex"])
    signature = bytes.fromhex(inputs["signature_hex"])
    try:
        for message in inputs["messages_hex"]:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature, bytes.fromhex(message)
            )
    except InvalidSignature:
        pytest.skip("this OpenSSL already rejects small-order Ed25519 points")


def test_every_record_verifier_rejects_the_forgery(forgery):
    inputs = forgery["inputs"]
    weak = bytes.fromhex(inputs["public_key_hex"])
    sig = bytes.fromhex(inputs["signature_hex"])
    packed = bytes.fromhex(inputs["envelope_packed_hex"])
    forged = envelope.unpack(packed)
    assert forged is not None  # structurally valid; only the signature is forged
    assert forgery["expected"]["envelope_unpack_result"] == "accept"
    assert not envelope.verify(forged, weak)
    assert not ack.verify(
        ack.Ack(acked_message_id=bytes(16), status=1, ack_nonce=bytes(12), created_at=1),
        sig,
        weak,
    )
    record = alias.AliasRecord(alias="a", identity_address="b", sequence=1, expires_at=2)
    record.signature = sig
    assert not alias.verify(record, weak)
    caps = capabilities.Capabilities(identity_address="x", capability_bits=1, expires_at=2)
    caps.signature = sig
    assert not capabilities.verify(caps, weak)
    cert = device_cert.DeviceCert(
        device_ed_pub=bytes([2]) * 32, device_x_pub=bytes([3]) * 32, device_id="d",
        not_before=0, not_after=1, capabilities=0, signature=sig,
    )
    assert not device_cert.verify(cert, weak)
    bundle = prekey.PrekeyBundle(
        identity_ed25519_pub=weak, device_id="d", x25519_pub=bytes([7]) * 32,
        mlkem768_ek=bytes([3]) * prekey.MLKEM768_EK_LEN, signed_prekey_id=1,
        one_time_prekey_id=0, one_time_x25519_pub=None, created_at_ms=0,
        expires_at_ms=1, signature=sig,
    )
    assert not prekey.verify(bundle)
    v2 = _load("atsam/pair_init_v2_001.json")
    init = pair_init_v2.decode_init(bytes.fromhex(v2["expected"]["pair_init_wire_hex"]))
    init.initiator_device_ed_pub = weak
    init.signature = sig
    assert not pair_init_v2.verify_init_signature(init)


def _decode_point(encoding):
    p = 2**255 - 19
    d = (-121665 * pow(121666, -1, p)) % p
    y = int.from_bytes(encoding, "little") & ((1 << 255) - 1)
    y %= p
    x2 = (y * y - 1) * pow(d * y * y + 1, -1, p) % p
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p:
        x = x * pow(2, (p - 1) // 4, p) % p
    assert (x * x - x2) % p == 0, "blocklist entry is not on the curve"
    return x, y, p, d


def test_blocklist_entries_are_exactly_small_order_points():
    assert len(ed25519_strict.SMALL_ORDER_ENCODINGS) == 7
    for entry in ed25519_strict.SMALL_ORDER_ENCODINGS:
        assert entry[31] & 0x80 == 0
        for sign in (0x00, 0x80):
            encoding = entry[:31] + bytes([entry[31] | sign])
            assert ed25519_strict.is_small_order_encoding(encoding)
            x, y, p, d = _decode_point(encoding)
            point, acc = (x, y), (x, y)
            for _ in range(7):  # [8]P must be the identity
                x1, y1 = acc
                x2, y2 = point
                t = d * x1 * x2 * y1 * y2
                acc = (
                    (x1 * y2 + x2 * y1) * pow(1 + t, -1, p) % p,
                    (y1 * y2 + x1 * x2) * pow(1 - t, -1, p) % p,
                )
            assert acc == (0, 1)


def test_noncanonical_s_is_rejected_and_valid_signatures_still_verify():
    vector = _load("envelope/message_alice_to_bob.json")
    signer = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    packed = bytes.fromhex(vector["expected"]["packed_hex"])
    value = envelope.unpack(packed)
    assert envelope.verify(value, signer)
    signature = value.sender_authentication
    s = int.from_bytes(signature[32:], "little")
    assert s < ed25519_strict.L
    malleated = signature[:32] + (s + ed25519_strict.L).to_bytes(32, "little")
    assert not ed25519_strict.verify(signer, malleated, envelope.signing_bytes(value))
    assert not ed25519_strict.verify(signer, signature[:63], envelope.signing_bytes(value))
    assert not ed25519_strict.verify(signer[:31], signature, envelope.signing_bytes(value))
