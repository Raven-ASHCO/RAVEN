import copy
import json
from pathlib import Path

import pytest

from raven_protocol import device_cert, ed25519_strict, pair_init, prekey


VECTOR = (
    Path(__file__).resolve().parents[3]
    / "shared-vectors"
    / "rvn1"
    / "atsam"
    / "pair_init_v1_001.json"
)


@pytest.fixture(scope="module")
def kat():
    return json.loads(VECTOR.read_text())


@pytest.fixture()
def decoded(kat):
    return pair_init.decode_init(bytes.fromhex(kat["expected"]["pair_init_wire_hex"]))


def _verify_args(kat, value):
    inputs = kat["input"]
    return dict(
        initiator_identity_ed_pub=bytes.fromhex(inputs["initiator_identity_ed_pub_hex"]),
        responder_identity_ed_pub=bytes.fromhex(inputs["responder_identity_ed_pub_hex"]),
        expected_initiator_device_ed_pub=value.initiator_device_ed_pub,
        expected_responder_device_ed_pub=value.responder_device_ed_pub,
        expected_responder_signed_x25519_pub=value.responder_signed_x25519_pub,
        expected_responder_one_time_x25519_pub=value.responder_one_time_x25519_pub,
        expected_initiator_device_cert_hash=bytes.fromhex(
            kat["expected"]["initiator_device_cert_hash_hex"]
        ),
        expected_responder_device_cert_hash=bytes.fromhex(
            kat["expected"]["responder_device_cert_hash_hex"]
        ),
        expected_responder_prekey_bundle_hash=bytes.fromhex(
            kat["expected"]["responder_prekey_bundle_hash_hex"]
        ),
        expected_signed_prekey_id=value.signed_prekey_id,
        expected_one_time_prekey_id=value.one_time_prekey_id,
        expected_responder_mlkem768_ek=value.responder_mlkem768_ek,
        expected_trust_not_before_ms=value.created_at_ms - 60_000,
        expected_trust_not_after_ms=value.created_at_ms + 604_800_000,
        now_ms=value.created_at_ms + 1,
    )


def test_shared_vector_codec_signatures_transcript_and_offline_root(kat, decoded):
    expected = kat["expected"]
    inputs = kat["input"]
    assert pair_init.PRODUCTION_ENABLED is False
    assert pair_init.encode_init(decoded).hex() == expected["pair_init_wire_hex"]
    assert len(pair_init.encode_init(decoded)) == expected["pair_init_wire_len"]
    assert pair_init.init_signing_bytes(decoded).hex() == expected[
        "pair_init_signing_bytes_hex"
    ]
    assert pair_init.init_hash(decoded).hex() == expected["pair_init_hash_hex"]
    assert pair_init.session_id(decoded).hex() == expected["session_id_hex"]
    assert pair_init.transcript_hash(decoded).hex() == expected["transcript_hash_hex"]
    assert pair_init.verify_init(decoded, **_verify_args(kat, decoded))

    # Bob may be offline: Alice derives this provisional root and queues sealed
    # message 0 without possessing or waiting for PairResponse bytes.
    root = pair_init.derive_provisional_root(
        bytes.fromhex(inputs["z_x_hex"]), bytes.fromhex(inputs["z_pq_hex"]), decoded
    )
    assert root.hex() == expected["provisional_k_root_hex"]

    response = pair_init.decode_response(
        bytes.fromhex(expected["pair_response_wire_hex"])
    )
    assert pair_init.encode_response(response).hex() == expected[
        "pair_response_wire_hex"
    ]
    assert len(pair_init.encode_response(response)) == expected[
        "pair_response_wire_len"
    ]
    assert pair_init.response_signing_bytes(response).hex() == expected[
        "pair_response_signing_bytes_hex"
    ]
    assert pair_init.verify_response(
        response, decoded, root, now_ms=response.created_at_ms + 1
    )


def test_exact_certificate_and_prekey_digests_match_vector(kat):
    inputs = kat["input"]
    expected = kat["expected"]
    assert pair_init.device_certificate_hash(
        bytes.fromhex(inputs["initiator_identity_ed_pub_hex"]),
        bytes.fromhex(inputs["initiator_device_cert_signing_bytes_hex"]),
        bytes.fromhex(inputs["initiator_device_cert_signature_hex"]),
    ).hex() == expected["initiator_device_cert_hash_hex"]
    assert pair_init.device_certificate_hash(
        bytes.fromhex(inputs["responder_identity_ed_pub_hex"]),
        bytes.fromhex(inputs["responder_device_cert_signing_bytes_hex"]),
        bytes.fromhex(inputs["responder_device_cert_signature_hex"]),
    ).hex() == expected["responder_device_cert_hash_hex"]
    assert pair_init.prekey_bundle_hash(
        bytes.fromhex(inputs["responder_prekey_signing_bytes_hex"]),
        bytes.fromhex(inputs["responder_prekey_signature_hex"]),
    ).hex() == expected["responder_prekey_bundle_hash_hex"]


@pytest.mark.parametrize("offset", [8, 9, 10, 12])
def test_init_rejects_version_suite_role_and_profile_downgrade(kat, offset):
    wire = bytearray.fromhex(kat["expected"]["pair_init_wire_hex"])
    wire[offset] ^= 1
    with pytest.raises(ValueError):
        pair_init.decode_init(bytes(wire))


def test_init_rejects_truncation_extension_and_otp_inconsistency(kat, decoded):
    wire = bytes.fromhex(kat["expected"]["pair_init_wire_hex"])
    with pytest.raises(ValueError):
        pair_init.decode_init(wire[:-1])
    with pytest.raises(ValueError):
        pair_init.decode_init(wire + b"\x00")
    invalid = copy.copy(decoded)
    invalid.one_time_prekey_id = 0
    with pytest.raises(ValueError):
        pair_init.init_signing_bytes(invalid)


def test_signature_role_identity_prekey_and_freshness_mismatches_fail(kat, decoded):
    args = _verify_args(kat, decoded)
    tampered = copy.copy(decoded)
    tampered.signature = bytes([decoded.signature[0] ^ 1]) + decoded.signature[1:]
    assert not pair_init.verify_init(tampered, **args)

    swapped = copy.copy(decoded)
    swapped.initiator_address, swapped.responder_address = (
        swapped.responder_address,
        swapped.initiator_address,
    )
    assert not pair_init.verify_init(swapped, **args)

    wrong = dict(args)
    wrong["expected_signed_prekey_id"] += 1
    assert not pair_init.verify_init(decoded, **wrong)
    wrong = dict(args)
    wrong["expected_responder_prekey_bundle_hash"] = bytes(32)
    assert not pair_init.verify_init(decoded, **wrong)
    expired = dict(args)
    expired["now_ms"] = decoded.expires_at_ms
    assert not pair_init.verify_init(decoded, **expired)


def test_exact_duplicate_is_idempotent_but_distinct_init_is_not_same_transcript(decoded):
    duplicate = pair_init.decode_init(pair_init.encode_init(decoded))
    assert pair_init.init_hash(duplicate) == pair_init.init_hash(decoded)
    distinct = copy.copy(decoded)
    distinct.init_id = bytes([decoded.init_id[0] ^ 1]) + decoded.init_id[1:]
    # The old signature cannot authenticate a different init id, and its
    # transcript/root identity is necessarily distinct.
    assert pair_init.init_hash(distinct) != pair_init.init_hash(decoded)


def test_response_is_bound_to_exact_init_root_role_profile_and_time(kat, decoded):
    expected = kat["expected"]
    inputs = kat["input"]
    root = bytes.fromhex(expected["provisional_k_root_hex"])
    response_wire = bytes.fromhex(expected["pair_response_wire_hex"])
    response = pair_init.decode_response(response_wire)
    assert not pair_init.verify_response(
        response, decoded, bytes([root[0] ^ 1]) + root[1:], now_ms=response.created_at_ms + 1
    )
    assert not pair_init.verify_response(
        response, decoded, root, now_ms=response.expires_at_ms
    )

    other_init = copy.copy(decoded)
    other_init.signature = bytes([decoded.signature[0] ^ 1]) + decoded.signature[1:]
    assert not pair_init.verify_response(
        response, other_init, root, now_ms=response.created_at_ms + 1
    )
    for offset in (8, 9, 10, 12):
        tampered = bytearray(response_wire)
        tampered[offset] ^= 1
        with pytest.raises(ValueError):
            pair_init.decode_response(bytes(tampered))
    assert inputs["z_x_hex"] and inputs["z_pq_hex"]


LOW_ORDER_X25519 = [
    bytes.fromhex("00" * 32),
    bytes.fromhex("01" + "00" * 31),
    bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
    bytes.fromhex("ec" + "ff" * 30 + "7f"),
    bytes.fromhex("ed" + "ff" * 30 + "7f"),
    bytes.fromhex("ee" + "ff" * 30 + "7f"),
]


def test_low_order_initiator_ephemeral_is_rejected(kat, decoded):
    assert pair_init.is_contributory_x25519(decoded.initiator_ephemeral_x25519_pub)
    wire = bytes.fromhex(kat["expected"]["pair_init_wire_hex"])
    offset = 236
    assert wire[offset : offset + 32] == decoded.initiator_ephemeral_x25519_pub
    for point in LOW_ORDER_X25519:
        assert not pair_init.is_contributory_x25519(point)
        with pytest.raises(ValueError):
            pair_init.decode_init(wire[:offset] + point + wire[offset + 32 :])
        hostile = copy.copy(decoded)
        hostile.initiator_ephemeral_x25519_pub = point
        with pytest.raises(ValueError):
            pair_init.init_signing_bytes(hostile)
        assert not pair_init.verify_init(hostile, **_verify_args(kat, hostile))


SKEW = pair_init.MAX_PEER_CLOCK_SKEW_MS
RVN1 = Path(__file__).resolve().parents[3] / "shared-vectors" / "rvn1"


def test_clock_skew_constant_matches_rust_bound():
    # Rust: prekey_lifecycle::MAX_PREKEY_FUTURE_SKEW_MS = 5 * 60 * 1_000.
    assert SKEW == 300_000


def test_verify_init_start_bound_tolerates_exactly_the_skew(kat, decoded):
    args = _verify_args(kat, decoded)
    created = decoded.created_at_ms
    for now_ms, accepted in (
        (created - SKEW, True),
        (created - SKEW - 1, False),
        (decoded.expires_at_ms - 1, True),
        (decoded.expires_at_ms, False),  # expiry stays exact
    ):
        assert pair_init.verify_init(decoded, **{**args, "now_ms": now_ms}) is accepted, now_ms


def test_verify_init_trust_window_start_tolerates_exactly_the_skew(kat, decoded):
    args = _verify_args(kat, decoded)
    created = decoded.created_at_ms
    for not_before, accepted in ((created + SKEW, True), (created + SKEW + 1, False)):
        assert pair_init.verify_init(
            decoded, **{**args, "expected_trust_not_before_ms": not_before}
        ) is accepted, not_before
    # The trust-window end is exact.
    expires = decoded.expires_at_ms
    for not_after, accepted in ((expires, True), (expires - 1, False)):
        assert pair_init.verify_init(
            decoded, **{**args, "expected_trust_not_after_ms": not_after}
        ) is accepted, not_after


def test_verify_response_start_bound_tolerates_exactly_the_skew(kat, decoded):
    expected = kat["expected"]
    root = bytes.fromhex(expected["provisional_k_root_hex"])
    response = pair_init.decode_response(bytes.fromhex(expected["pair_response_wire_hex"]))
    for now_ms, accepted in (
        (response.created_at_ms - SKEW, True),
        (response.created_at_ms - SKEW - 1, False),
        (response.expires_at_ms - 1, True),
        (response.expires_at_ms, False),
    ):
        assert pair_init.verify_response(response, decoded, root, now_ms=now_ms) is accepted


def test_shared_clock_skew_vector(kat):
    vector = json.loads((RVN1 / "atsam" / "pair_init_v1_clock_skew_001.json").read_text())
    inputs = vector["input"]
    assert inputs["max_peer_clock_skew_ms"] == SKEW
    alice_cert = inputs["initiator_device_cert"]
    bob_cert = inputs["responder_device_cert"]
    certs = {}
    for name, fields in (("initiator", alice_cert), ("responder", bob_cert)):
        cert = device_cert.DeviceCert(
            device_ed_pub=bytes.fromhex(fields["device_ed_pub_hex"]),
            device_x_pub=bytes.fromhex(fields["device_x_pub_hex"]),
            device_id=fields["device_id"],
            not_before=fields["not_before_ms"],
            not_after=fields["not_after_ms"],
            capabilities=fields["capabilities"],
            signature=bytes.fromhex(fields["signature_hex"]),
        )
        identity = bytes.fromhex(fields["user_ed_pub_hex"])
        assert device_cert.verify(cert, identity)
        certs[name] = (cert, identity)
        assert pair_init.device_certificate_hash(
            identity, device_cert.signing_bytes(cert), cert.signature
        ).hex() == kat["expected"][f"{name}_device_cert_hash_hex"]
    ek = bytes.fromhex(inputs["responder_mlkem768_ek_hex"])
    seen = {"accept": 0, "reject": 0}
    for case in vector["expected"]["init_cases"]:
        value = pair_init.decode_init(bytes.fromhex(case["pair_init_wire_hex"]))
        fields = case["responder_prekey"]
        bundle = prekey.PrekeyBundle(
            identity_ed25519_pub=bytes.fromhex(fields["identity_ed25519_pub_hex"]),
            device_id=fields["device_id"],
            x25519_pub=bytes.fromhex(fields["x25519_pub_hex"]),
            mlkem768_ek=ek,
            signed_prekey_id=fields["signed_prekey_id"],
            one_time_prekey_id=fields["one_time_prekey_id"],
            one_time_x25519_pub=bytes.fromhex(fields["one_time_x25519_pub_hex"]),
            created_at_ms=fields["created_at_ms"],
            expires_at_ms=fields["expires_at_ms"],
            signature=bytes.fromhex(fields["signature_hex"]),
        )
        assert prekey.verify(bundle, case["now_ms"]), case["label"]
        initiator, responder = certs["initiator"], certs["responder"]
        assert case["trust_not_before_ms"] == max(
            initiator[0].not_before, responder[0].not_before, bundle.created_at_ms
        )
        assert case["trust_not_after_ms"] == min(
            initiator[0].not_after, responder[0].not_after, bundle.expires_at_ms
        )
        accepted = pair_init.verify_init(
            value,
            initiator[1],
            responder[1],
            expected_initiator_device_ed_pub=initiator[0].device_ed_pub,
            expected_responder_device_ed_pub=responder[0].device_ed_pub,
            expected_responder_signed_x25519_pub=bundle.x25519_pub,
            expected_responder_one_time_x25519_pub=bundle.one_time_x25519_pub,
            expected_initiator_device_cert_hash=pair_init.device_certificate_hash(
                initiator[1], device_cert.signing_bytes(initiator[0]), initiator[0].signature
            ),
            expected_responder_device_cert_hash=pair_init.device_certificate_hash(
                responder[1], device_cert.signing_bytes(responder[0]), responder[0].signature
            ),
            expected_responder_prekey_bundle_hash=pair_init.prekey_bundle_hash(
                prekey.signing_bytes(bundle), bundle.signature
            ),
            expected_signed_prekey_id=bundle.signed_prekey_id,
            expected_one_time_prekey_id=bundle.one_time_prekey_id,
            expected_responder_mlkem768_ek=ek,
            expected_trust_not_before_ms=case["trust_not_before_ms"],
            expected_trust_not_after_ms=case["trust_not_after_ms"],
            now_ms=case["now_ms"],
        )
        assert accepted is (case["result"] == "accept"), case["label"]
        seen[case["result"]] += 1
    assert seen == {"accept": 3, "reject": 3}
    source = pair_init.decode_init(bytes.fromhex(kat["expected"]["pair_init_wire_hex"]))
    root = bytes.fromhex(inputs["provisional_k_root_hex"])
    response = pair_init.decode_response(bytes.fromhex(inputs["pair_response_wire_hex"]))
    for case in vector["expected"]["response_cases"]:
        assert pair_init.verify_response(
            response, source, root, now_ms=case["now_ms"]
        ) is (case["result"] == "accept"), case["label"]


def test_shared_small_order_ephemeral_vector_fails_only_the_structural_rule():
    vector = json.loads(
        (RVN1 / "atsam" / "negative" / "pair_init_v1_small_order_ephemeral_001.json").read_text()
    )
    inputs = vector["input"]
    wire = bytes.fromhex(inputs["pair_init_wire_hex"])
    offset = inputs["initiator_ephemeral_offset"]
    point = bytes.fromhex(inputs["initiator_ephemeral_x25519_pub_hex"])
    assert wire[offset : offset + 32] == point
    assert not pair_init.is_contributory_x25519(point)
    signing = pair_init.INIT_SIGNING_DOMAIN + wire[: pair_init.INIT_SIGNED_PREFIX_LEN]
    assert vector["expected"]["initiator_signature_valid"] is True
    assert ed25519_strict.verify(
        bytes.fromhex(inputs["initiator_device_ed_pub_hex"]), wire[-64:], signing
    )
    with pytest.raises(ValueError, match="low-order"):
        pair_init.decode_init(wire)
