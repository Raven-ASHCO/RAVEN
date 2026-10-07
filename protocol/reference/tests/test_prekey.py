from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from raven_protocol import prekey


ALICE_ED_PRIV = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
ALICE_ED_PUB = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)


def bundle() -> prekey.PrekeyBundle:
    return prekey.PrekeyBundle(
        identity_ed25519_pub=ALICE_ED_PUB,
        device_id="dev1",
        x25519_pub=bytes([7]) * 32,
        mlkem768_ek=bytes([3]) * prekey.MLKEM768_EK_LEN,
        signed_prekey_id=1,
        one_time_prekey_id=0,
        one_time_x25519_pub=None,
        created_at_ms=1_700_000_000_000,
        expires_at_ms=1_700_604_800_000,
    )


def test_prekey_signing_form_and_signature():
    value = bundle()
    value.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(
        prekey.signing_bytes(value)
    )
    assert prekey.signing_bytes(value).startswith(b"rvn1/prekey\x01")
    assert prekey.verify(value)


def test_tampered_signature_rejected():
    value = bundle()
    signature = bytearray(
        Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(
            prekey.signing_bytes(value)
        )
    )
    signature[0] ^= 0x80
    value.signature = bytes(signature)
    assert not prekey.verify(value)


def test_inconsistent_one_time_prekey_rejected():
    value = bundle()
    value.one_time_prekey_id = 1
    try:
        prekey.signing_bytes(value)
    except ValueError as error:
        assert "requires" in str(error)
    else:
        raise AssertionError("inconsistent one-time prekey was accepted")


def test_device_id_is_bounded_to_64_utf8_bytes():
    value = bundle()
    value.device_id = "d" * prekey.MAX_DEVICE_ID_BYTES
    prekey.signing_bytes(value)
    value.device_id = "d" * (prekey.MAX_DEVICE_ID_BYTES + 1)
    try:
        prekey.signing_bytes(value)
    except ValueError as error:
        assert "device_id" in str(error)
    else:
        raise AssertionError("oversized device_id was accepted")
    value.signature = bytes(64)
    assert not prekey.verify(value)


def _signing_kat(case_id):
    import json
    from pathlib import Path

    vector = json.loads(
        (Path(__file__).resolve().parents[3] / "shared-vectors" / "rvn1" / "prekey"
         / f"{case_id}.json").read_text()
    )
    inputs = vector["inputs"]
    otp = inputs["one_time_x25519_pub_hex"]
    value = prekey.PrekeyBundle(
        identity_ed25519_pub=bytes.fromhex(inputs["identity_ed25519_pub_hex"]),
        device_id=inputs["device_id"],
        x25519_pub=bytes.fromhex(inputs["x25519_pub_hex"]),
        mlkem768_ek=bytes.fromhex(inputs["mlkem768_ek_hex"]),
        signed_prekey_id=inputs["signed_prekey_id"],
        one_time_prekey_id=inputs["one_time_prekey_id"],
        one_time_x25519_pub=None if otp is None else bytes.fromhex(otp),
        created_at_ms=inputs["created_at_ms"],
        expires_at_ms=inputs["expires_at_ms"],
        signature=bytes.fromhex(vector["expected"]["signature_hex"]),
    )
    return value, vector["expected"]["clock_cases"]


def test_prekey_time_window_matches_shared_clock_cases():
    for case_id in ("bundle_signing_001", "bundle_signing_002"):
        value, cases = _signing_kat(case_id)
        assert prekey.verify(value)  # legacy call: signature and structure only
        assert prekey.verify(value, value.created_at_ms)
        for case in cases:
            accepted = case["result"] == "accept"
            assert prekey.verify(value, case["now_ms"]) is accepted, (case_id, case)
            assert prekey.check_time(value, case["now_ms"]) == case.get("error"), case


def test_prekey_time_window_bounds_are_inclusive_and_require_ordered_window():
    value, _ = _signing_kat("bundle_signing_002")
    skew = prekey.CLOCK_SKEW_MS
    assert skew == 300_000
    assert prekey.check_time(value, value.created_at_ms - skew) is None
    assert prekey.check_time(value, value.created_at_ms - skew - 1) == "PREKEY_NOT_YET_VALID"
    assert prekey.check_time(value, value.expires_at_ms + skew) is None
    assert prekey.check_time(value, value.expires_at_ms + skew + 1) == "PREKEY_EXPIRED"
    inverted = prekey.PrekeyBundle(**{**value.__dict__})
    inverted.expires_at_ms = inverted.created_at_ms
    assert prekey.check_time(inverted, inverted.created_at_ms) == "PREKEY_EXPIRED"


def test_all_zero_mlkem_key_is_rejected_even_when_signed():
    value = bundle()
    value.mlkem768_ek = bytes(prekey.MLKEM768_EK_LEN)
    value.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(
        prekey.signing_bytes(value)
    )
    assert not prekey.verify(value)
