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
