import pytest
from cryptography.exceptions import InvalidTag

from raven_protocol import ack, address, indexed_session


ALICE_ED_PUB = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
BOB_ED_PUB = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)
ALICE = address.encode(ALICE_ED_PUB)
BOB = address.encode(BOB_ED_PUB)
ROOT = bytes([0x11]) * 32


def test_session_context_is_exact_and_rejects_normalization():
    assert indexed_session.PRODUCTION_ENABLED is False
    expected = b"ATSAM/indexed-session/v1\x00" + ALICE.encode() + b"\x00" + BOB.encode()
    assert indexed_session.session_context(ALICE, BOB) == expected
    for invalid in (ALICE.upper(), f" {ALICE}", address.to_display(ALICE)):
        with pytest.raises(ValueError):
            indexed_session.session_context(invalid, BOB)


def test_lanes_and_transcript_directions_are_separated():
    message = indexed_session.message_key_at_index(ROOT, ALICE, BOB, 0, 0)
    ack_key = indexed_session.ack_key_at_index(ROOT, ALICE, BOB, 0, 0)
    reverse_ack = indexed_session.ack_key_at_index(ROOT, ALICE, BOB, 1, 0)
    route_0 = indexed_session.route_direction_key(ROOT, 0)
    route_1 = indexed_session.route_direction_key(ROOT, 1)
    assert len({message, ack_key, reverse_ack, route_0, route_1}) == 5


def test_route_allocator_freezes_epoch_counter_bits():
    assert indexed_session.route_coordinates(1_700_000_001_999, 7, 2, 1) == (
        1_700_000_001,
        59,
    )
    with pytest.raises(ValueError):
        indexed_session.route_coordinates(0, 0, 0, 0)
    with pytest.raises(ValueError):
        indexed_session.route_coordinates(0, 0, 1, 2)


def test_offline_mailbox_uses_day_and_direction_not_envelope_tag():
    day, slot = indexed_session.mailbox_coordinates(1_700_000_000_000, 1)
    assert (day, slot) == (19_675, 1)
    mailbox, store = indexed_session.derive_mailbox_tags(
        ROOT, 1_700_000_000_000, 1
    )
    envelope_tag = indexed_session.derive_route_tag(
        ROOT, 1_700_000_000_000, 0, 1, 1
    )
    assert len(mailbox) == len(store) == 16
    assert mailbox != envelope_tag and store != envelope_tag


def test_message_id_aad_text_is_uppercase_uuid():
    raw = bytes.fromhex("00112233445546778899aabbccddeeff")
    assert indexed_session.uuid_text(raw) == "00112233-4455-4677-8899-AABBCCDDEEFF"


def _signed_ack():
    record = ack.Ack(
        acked_message_id=(1).to_bytes(16, "big"),
        status=1,
        ack_nonce=(2).to_bytes(12, "big"),
        created_at=1_700_000_001_000,
    )
    # Codec/AEAD round-trip fixture only. Cross-language vector parity separately
    # proves the deterministic Ed25519 signature over these signing bytes.
    signature = bytes([0x55]) * 64
    return record, signature


def test_signed_ack_codec_is_exactly_101_bytes_and_strict():
    record, signature = _signed_ack()
    encoded = indexed_session.encode_signed_ack(record, signature)
    assert len(encoded) == indexed_session.ACK_PLAINTEXT_LEN == 101
    assert indexed_session.decode_signed_ack(encoded) == indexed_session.SignedAck(
        record, signature
    )
    with pytest.raises(ValueError):
        indexed_session.decode_signed_ack(encoded + b"\x00")
    with pytest.raises(ValueError):
        indexed_session.decode_signed_ack(encoded[:16] + b"\x03" + encoded[17:])


def test_rvna1_v3_ack_is_143_bytes_and_binds_outer_message_id():
    record, signature = _signed_ack()
    plaintext = indexed_session.encode_signed_ack(record, signature)
    outer_id = bytes.fromhex("00112233445546778899aabbccddeeff")
    wire = indexed_session.seal_ack(
        ROOT,
        ALICE,
        BOB,
        direction=1,
        index=7,
        outer_message_id=outer_id,
        plaintext=plaintext,
        nonce=bytes([0xCD]) * 12,
    )
    assert len(wire) == indexed_session.ACK_SEALED_WIRE_LEN == 143
    assert wire[:10] == b"RVNA1\x00\x00\x00\x03\x01"
    assert indexed_session.open_ack(ROOT, ALICE, BOB, 1, outer_id, wire) == plaintext
    wrong_id = bytearray(outer_id)
    wrong_id[-1] ^= 1
    with pytest.raises(InvalidTag):
        indexed_session.open_ack(ROOT, ALICE, BOB, 1, bytes(wrong_id), wire)
    with pytest.raises(InvalidTag):
        indexed_session.open_ack(ROOT, ALICE, BOB, 0, outer_id, wire)


def test_stateless_index_work_is_bounded_before_authentication():
    limit = indexed_session.MAX_STATELESS_CHAIN_INDEX
    assert limit == 4_096
    indexed_session.message_key_at_index(ROOT, ALICE, BOB, 0, limit)
    for index in (limit + 1, 0xFFFFFFFF):
        with pytest.raises(ValueError):
            indexed_session.message_key_at_index(ROOT, ALICE, BOB, 0, index)
        with pytest.raises(ValueError):
            indexed_session.ack_key_at_index(ROOT, ALICE, BOB, 0, index)
    record, signature = _signed_ack()
    plaintext = indexed_session.encode_signed_ack(record, signature)
    outer_id = bytes(range(16))
    wire = indexed_session.seal_ack(
        ROOT, ALICE, BOB, 1, 0, outer_id, plaintext, bytes([0xCD]) * 12
    )
    forged = wire[:10] + (0xFFFFFFFF).to_bytes(4, "big") + wire[14:]
    with pytest.raises(ValueError, match="stateless derivation bound"):
        indexed_session.open_ack(ROOT, ALICE, BOB, 1, outer_id, forged)
