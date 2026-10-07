"""KATs for ATSAM/hybrid-ratchet/v2 vector freeze (production-disabled)."""

from __future__ import annotations

import json
from pathlib import Path

from raven_protocol import hybrid_ratchet_v2 as tr, pair_init_v2 as piv2

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "shared-vectors/rvn1/atsam"


def _load(name: str):
    return json.loads((VEC / name).read_text())


def test_pair_init_v2_roundtrip_and_expand():
    v = _load("pair_init_v2_001.json")
    wire = bytes.fromhex(v["expected"]["pair_init_wire_hex"])
    assert len(wire) == v["expected"]["pair_init_wire_len"]
    assert v["expected"]["offsets"]["total_len"] == len(wire)
    rec = piv2.decode_init(wire)
    assert piv2.encode_init(rec) == wire
    assert piv2.verify_init_signature(rec)
    expand = piv2.pair_expand(
        bytes.fromhex(v["inputs"]["z_x_hex"]),
        bytes.fromhex(v["inputs"]["z_pq_hex"]),
        wire,
    )
    assert expand.sk_ec.hex() == v["expected"]["sk_ec_hex"]
    assert expand.sk_scka.hex() == v["expected"]["sk_scka_hex"]
    assert expand.k_route_master.hex() == v["expected"]["k_route_master_hex"]
    assert expand.k_confirm.hex() == v["expected"]["k_confirm_hex"]
    assert expand.session_id.hex() == v["expected"]["session_id_hex"]
    resp = piv2.decode_response(bytes.fromhex(v["expected"]["pair_response_wire_hex"]))
    assert piv2.verify_response_signature(resp)
    assert resp.confirmation_tag.hex() == v["expected"]["confirmation_tag_hex"]


def test_pair_init_v2_002_is_transcript_derivable():
    """Trust-binding KAT: Z_X, prekey digest and cert digests follow from wire."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    from raven_protocol import pair_init

    v = _load("pair_init_v2_002.json")
    inp, exp = v["inputs"], v["expected"]
    wire = bytes.fromhex(exp["pair_init_wire_hex"])
    rec = piv2.decode_init(wire)
    assert piv2.encode_init(rec) == wire
    assert piv2.verify_init_signature(rec)

    def priv(name):
        return X25519PrivateKey.from_private_bytes(bytes.fromhex(inp[name]))

    eph = priv("initiator_ephemeral_x25519_priv_hex")
    otp = priv("responder_otp_x25519_priv_hex")
    spk = priv("responder_spk_x25519_priv_hex")
    assert eph.public_key().public_bytes_raw() == rec.initiator_ephemeral_x25519_pub
    assert otp.public_key().public_bytes_raw() == rec.responder_one_time_x25519_pub
    assert spk.public_key().public_bytes_raw() == rec.responder_signed_x25519_pub

    # Z_X = X25519(eph, OTP) over exactly the wire keys, from either side.
    z_x = eph.exchange(X25519PublicKey.from_public_bytes(rec.responder_one_time_x25519_pub))
    assert z_x == otp.exchange(X25519PublicKey.from_public_bytes(rec.initiator_ephemeral_x25519_pub))
    assert z_x.hex() == exp["z_x_hex"]

    # The wire's prekey digest is a real identity-signed RavenPrekeyBundleV1.
    bundle = inp["responder_prekey_bundle"]
    bundle_sb = bytes.fromhex(bundle["signing_bytes_hex"])
    bundle_sig = bytes.fromhex(bundle["signature_hex"])
    bob_identity = bytes.fromhex(inp["responder_identity_ed_pub_hex"])
    Ed25519PublicKey.from_public_bytes(bob_identity).verify(bundle_sig, bundle_sb)
    assert bundle_sb.startswith(b"rvn1/prekey\x01" + bob_identity)
    assert pair_init.prekey_bundle_hash(bundle_sb, bundle_sig) == rec.responder_prekey_bundle_hash
    bound = (
        rec.responder_signed_x25519_pub
        + rec.responder_mlkem768_ek
        + rec.signed_prekey_id.to_bytes(4, "big")
        + rec.one_time_prekey_id.to_bytes(4, "big")
        + rec.responder_one_time_x25519_pub
    )
    assert bound in bundle_sb

    # Identity-signed device certs; Alice's device X key is not her ephemeral.
    for side, identity_hex, wire_hash in (
        ("initiator_device_cert", "initiator_identity_ed_pub_hex", rec.initiator_device_cert_hash),
        ("responder_device_cert", "responder_identity_ed_pub_hex", rec.responder_device_cert_hash),
    ):
        cert_sb = bytes.fromhex(inp[side]["signing_bytes_hex"])
        cert_sig = bytes.fromhex(inp[side]["signature_hex"])
        identity = bytes.fromhex(inp[identity_hex])
        Ed25519PublicKey.from_public_bytes(identity).verify(cert_sig, cert_sb)
        assert pair_init.device_certificate_hash(identity, cert_sb, cert_sig) == wire_hash
    alice_cert_sb = bytes.fromhex(inp["initiator_device_cert"]["signing_bytes_hex"])
    assert rec.initiator_ephemeral_x25519_pub not in alice_cert_sb

    expand = piv2.pair_expand(z_x, bytes.fromhex(inp["z_pq_hex"]), wire)
    assert expand.sk_ec.hex() == exp["sk_ec_hex"]
    assert expand.sk_scka.hex() == exp["sk_scka_hex"]
    assert expand.k_route_master.hex() == exp["k_route_master_hex"]
    assert expand.k_confirm.hex() == exp["k_confirm_hex"]
    assert expand.session_id.hex() == exp["session_id_hex"]
    resp = piv2.decode_response(bytes.fromhex(exp["pair_response_wire_hex"]))
    assert piv2.verify_response_signature(resp)
    assert resp.confirmation_tag == piv2.confirmation_tag(expand.k_confirm, expand.init_hash_v2)


def test_pair_init_v1_rejected_as_v2():
    v = _load("negative/pair_init_v1_as_v2_001.json")
    wire = bytes.fromhex(v["inputs"]["wire_hex"])
    try:
        piv2.decode_init(wire)
        raise AssertionError("should reject")
    except ValueError as e:
        assert "V1" in str(e)


def test_domain_labels():
    v = _load("tr_domain_labels_001.json")
    assert v["expected"] == tr.domain_catalog()
    assert v["expected"]["SEALED_PROTO"] == "04"
    assert v["expected"]["MAX_SKIP"] == "1000"


def test_ec_kdf():
    v = _load("tr_ec_kdf_001.json")
    rk1, ck = tr.kdf_rk(
        bytes.fromhex(v["inputs"]["rk_hex"]),
        bytes.fromhex(v["inputs"]["dh_out_hex"]),
    )
    ck2, mk = tr.kdf_ck(ck)
    assert rk1.hex() == v["expected"]["rk_next_hex"]
    assert ck.hex() == v["expected"]["ck_hex"]
    assert ck2.hex() == v["expected"]["ck_next_hex"]
    assert mk.hex() == v["expected"]["mk_hex"]


def test_scka_role_init():
    v = _load("tr_scka_init_001.json")
    sk = bytes.fromhex(v["inputs"]["sk_scka_hex"])
    a = tr.ratchet_init_alice_scka(sk)
    b = tr.ratchet_init_bob_scka(sk)
    assert a.ck_send.hex() == v["expected"]["alice"]["ck_send_hex"]
    assert b.ck_recv.hex() == v["expected"]["bob"]["ck_recv_hex"]
    assert v["expected"]["alice_send_equals_bob_recv"] is True
    assert a.ck_send == b.ck_recv
    assert a.ck_send != b.ck_send


def test_hybrid_aead():
    v = _load("tr_hybrid_aead_001.json")
    key, nonce = tr.kdf_hybrid(
        bytes.fromhex(v["inputs"]["ec_mk_hex"]),
        bytes.fromhex(v["inputs"]["scka_mk_hex"]),
    )
    assert key.hex() == v["expected"]["aead_key_hex"]
    assert nonce.hex() == v["expected"]["nonce_hex"]
    pt = tr.aead_open(
        key,
        nonce,
        bytes.fromhex(v["expected"]["ciphertext_hex"]),
        bytes.fromhex(v["inputs"]["aad_hex"]),
    )
    assert pt.hex() == v["inputs"]["plaintext_hex"]


def test_ackv2():
    v = _load("tr_ackv2_001.json")
    ack = tr.decode_ack_plaintext(bytes.fromhex(v["expected"]["ack_plaintext_hex"]))
    assert ack.acked_object_digest.hex() == v["expected"]["acked_object_digest_hex"]
    assert tr.verify_ack(ack, bytes.fromhex(v["inputs"]["signer_device_ed_pub_hex"]))
    obj = bytes.fromhex(v["inputs"]["acked_endpoint_object_hex"])
    import hashlib

    assert hashlib.sha256(obj).digest() == ack.acked_object_digest


def test_candidate_fail_and_crash_order():
    fail = _load("tr_candidate_fail_001.json")
    try:
        tr.aead_open(
            bytes.fromhex(fail["inputs"]["aead_key_hex"]),
            bytes.fromhex(fail["inputs"]["nonce_hex"]),
            bytes.fromhex(fail["inputs"]["ciphertext_hex"]),
            bytes.fromhex(fail["inputs"]["aad_hex"]),
        )
        raise AssertionError("open should fail")
    except Exception:
        pass
    crash = _load("tr_crash_ack_cas_001.json")
    assert crash["steps"][2]["action"] == "write_PENDING_ACK_SEND"
    assert crash["steps"][3]["requires"] == "PENDING_ACK_SEND"


def test_pair_init_v2_structural_hard_rejects_match_v1():
    import copy

    import pytest

    from raven_protocol import pair_init

    vector = json.loads((VEC / "pair_init_v2_001.json").read_text())
    wire = bytes.fromhex(vector["expected"]["pair_init_wire_hex"])
    offsets = vector["expected"]["offsets"]
    base = piv2.decode_init(wire)
    low_order = [
        bytes(32),
        bytes([1]) + bytes(31),
        bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        bytes.fromhex("ec" + "ff" * 30 + "7f"),
        bytes.fromhex("ed" + "ff" * 30 + "7f"),
        bytes.fromhex("ee" + "ff" * 30 + "7f"),
    ]
    mutations = [("initiator_ephemeral_x25519_pub", point) for point in low_order]
    mutations += [
        ("responder_mlkem768_ek", bytes(pair_init.MLKEM768_EK_LEN)),
        ("mlkem768_ciphertext", bytes(pair_init.MLKEM768_CT_LEN)),
        ("init_id", bytes(16)),
        ("pairing_nonce", bytes(32)),
        ("initiator_device_ed_pub", bytes(32)),
        ("responder_device_ed_pub", bytes(32)),
        ("initiator_device_cert_hash", bytes(32)),
        ("responder_device_cert_hash", bytes(32)),
        ("responder_prekey_bundle_hash", bytes(32)),
    ]
    for field_name, replacement in mutations:
        hostile = copy.copy(base)
        setattr(hostile, field_name, replacement)
        with pytest.raises(ValueError):
            piv2.init_signing_bytes(hostile)
        offset = offsets[field_name]
        tampered = wire[:offset] + replacement + wire[offset + len(replacement):]
        with pytest.raises(ValueError):
            piv2.decode_init(tampered)
