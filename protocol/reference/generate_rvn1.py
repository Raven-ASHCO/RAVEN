#!/usr/bin/env python3
# protocol/reference/generate_rvn1.py
"""Deterministic generator for the frozen rvn1 cross-platform vector tree.
Source of truth: raven_protocol.*  ·  Fixed keys: shared-vectors identities  ·  Epoch 1700000000."""
import argparse, json, hashlib, hmac, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from raven_protocol import (
    ack,
    address,
    alias,
    capabilities,
    device_cert,
    device_revocation,
    device_revocation_conformance as rev_conf,
    envelope,
    fingerprint,
    indexed_session,
    pair_init,
    prekey,
    routing_tag,
    store_tags,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

EPOCH_S = 1700000000
EPOCH_MS = EPOCH_S * 1000
ALICE_ED_PRIV = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
ALICE_ED_PUB  = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
BOB_ED_PRIV   = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
BOB_ED_PUB    = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
BOB_X_PUB     = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
CAROL_ED_PUB  = bytes.fromhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
CAROL_X_PUB   = bytes.fromhex("05ee18184ed593900f639b87b8d99a7a5c5c00cc0aaac5629c45f8869c602907")
# dave: SHA-256(edPub)[:9] base64 contains '/', so its device fingerprint hits the
# strip-shortens-to-11-chars branch — the ~31% path no clean-key vector exercises.
DAVE_ED_PUB   = bytes.fromhex("e61a185bcef2613a6c7cb79763ce945d3b245d76114dd440bcf5f2dc1aa57057")
K_ROUTE       = bytes(range(32))
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MLKEM_INTEROP_VECTOR = pathlib.Path("atsam/mlkem768_hybrid_kat_001.json")
MLKEM_INTEROP_SHA256 = "7c9b4cc0c46c81fe55541021fbe114341c88601691a3a79ded2567a833105931"

def hkdf_sha256(ikm, salt, info, length=32):
    """RFC 5869 HKDF-SHA256 (salt None → HashLen zeros). Matches CryptoKit / Rust hkdf."""
    if salt is None:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]

def write(out, rel, obj):
    p = pathlib.Path(out) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def write_frozen_order(out, rel, obj):
    """Preserve the byte order of post-freeze vectors added before this generator.

    Their object-member order is not semantically significant, but keeping the
    committed bytes stable avoids needless churn for downstream consumers that
    integrity-pin the complete fixture file.
    """
    p = pathlib.Path(out) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")

def vec(name, desc, inputs, expected, **extra):
    return {"name": name, "description": desc, "protocol_version": "rvn1",
            "deterministic": True, "inputs": inputs, "expected": expected, **extra}

def copy_integrity_pinned_vector(out, relative_path, expected_sha256):
    """Copy a deterministic external KAT after verifying its exact reviewed bytes.

    The ML-KEM fixture is produced by the Rust `ml-kem` implementation and Apple
    CryptoKit, because Python's `cryptography` package does not expose ML-KEM.
    Keeping its reviewed digest here makes it part of the complete generator
    manifest without falsely claiming this Python program can derive the KAT.
    """
    source = REPO_ROOT / "shared-vectors/rvn1" / relative_path
    raw = source.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected_sha256:
        raise RuntimeError(
            f"integrity-pinned vector changed: {relative_path} "
            f"(expected {expected_sha256}, got {actual})"
        )
    destination = pathlib.Path(out) / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)

def build_message_envelope():
    rt = routing_tag.derive(K_ROUTE, EPOCH_S, 0)
    e = envelope.Envelope(
        env_type=1, flags=0, message_id=(1).to_bytes(16, "big"), routing_tag=rt,
        dest_device_hint=0, created_at=EPOCH_MS, expires_at=EPOCH_MS + 86400000,
        hop_limit=8, replication_budget=3, anti_replay_nonce=(1).to_bytes(12, "big"),
        ratchet_header_ciphertext=b"RVNA1-header-fixture",
        message_ciphertext=b"RVNS1-sealed-body-fixture", sender_authentication=b"")
    priv = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV)
    e.sender_authentication = priv.sign(envelope.signing_bytes(e))
    return e

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default=str(
        pathlib.Path(__file__).resolve().parents[2] / "shared-vectors/rvn1"))
    out = ap.parse_args().out

    write(out, "identities.json", {
        "protocol_version": "rvn1", "epoch_seconds": EPOCH_S,
        "note": "Same RFC-8032 keys as shared-vectors/v1/identities.json.",
        "alice_address": address.encode(ALICE_ED_PUB), "bob_address": address.encode(BOB_ED_PUB)})

    write(out, "address/encode_alice.json", vec(
        "RavenAddressV1 encode — alice", "bech32m over version||SHA256(edPub)[:20]",
        {"ed_public_hex": ALICE_ED_PUB.hex()},
        {"address": address.encode(ALICE_ED_PUB),
         "display": address.to_display(address.encode(ALICE_ED_PUB))}))

    write(out, "identities/fingerprint_alice.json", vec(
        "Fingerprints — alice (clean base64 branch)", "canonical device fp (app scheme) + deprecated MeshV1 hex",
        {"ed_public_hex": ALICE_ED_PUB.hex()},
        {"device_fingerprint_v1": fingerprint.device_fingerprint_v1(ALICE_ED_PUB),
         "mesh_v1_hex_deprecated": fingerprint.mesh_v1_hex_fingerprint(ALICE_ED_PUB)}))
    write(out, "identities/fingerprint_dave.json", vec(
        "Fingerprints — dave (strip branch)",
        "SHA256(edPub)[:9] base64 contains '/'; stripping shortens to 11 chars → last group is 3. "
        "Pins the ~31% branch: standard base64, strip '+'/'/' only, group the remaining chars.",
        {"ed_public_hex": DAVE_ED_PUB.hex()},
        {"device_fingerprint_v1": fingerprint.device_fingerprint_v1(DAVE_ED_PUB),
         "mesh_v1_hex_deprecated": fingerprint.mesh_v1_hex_fingerprint(DAVE_ED_PUB)}))

    write(out, "routing/tag_alice_bob_000.json", vec(
        "RavenRoutingTagV1 — counter 0", "HMAC-SHA256(K_route, label||epoch||counter)[:16]",
        {"k_route_hex": K_ROUTE.hex(), "epoch": EPOCH_S, "counter": 0},
        {"tag_hex": routing_tag.derive(K_ROUTE, EPOCH_S, 0).hex()}))
    write(out, "routing/tag_unlinkable_001.json", vec(
        "RavenRoutingTagV1 — counter 1 differs", "unlinkability across counters",
        {"k_route_hex": K_ROUTE.hex(), "epoch": EPOCH_S, "counter": 1},
        {"tag_hex": routing_tag.derive(K_ROUTE, EPOCH_S, 1).hex()}))

    e = build_message_envelope()
    write(out, "envelope/message_alice_to_bob.json", vec(
        "RavenEnvelopeV1 — message", "packed bytes, signing bytes, Ed25519 signature (alice)",
        {"signer_ed_public_hex": ALICE_ED_PUB.hex(),
         "message_id_hex": e.message_id.hex(), "routing_tag_hex": e.routing_tag.hex(),
         "created_at_ms": e.created_at, "expires_at_ms": e.expires_at,
         "ratchet_header_ciphertext_hex": e.ratchet_header_ciphertext.hex(),
         "message_ciphertext_hex": e.message_ciphertext.hex()},
        {"packed_hex": envelope.pack(e).hex(),
         "signing_bytes_hex": envelope.signing_bytes(e).hex(),
         "sender_authentication_hex": e.sender_authentication.hex()}))

    a = ack.Ack(acked_message_id=e.message_id, status=1, ack_nonce=(2).to_bytes(12, "big"),
                created_at=EPOCH_MS + 1000)
    asig = Ed25519PrivateKey.from_private_bytes(BOB_ED_PRIV).sign(ack.signing_bytes(a))
    write(out, "ack/delivered_bob_to_alice.json", vec(
        "RavenAckV1 — delivered", "ack signing bytes + Ed25519 signature (bob)",
        {"acked_message_id_hex": a.acked_message_id.hex(), "status": a.status,
         "ack_nonce_hex": a.ack_nonce.hex(), "created_at_ms": a.created_at,
         "signer_ed_public_hex": BOB_ED_PUB.hex()},
        {"signing_bytes_hex": ack.signing_bytes(a).hex(), "signature_hex": asig.hex()}))

    r = alias.AliasRecord(alias="ahmad", identity_address=address.encode(ALICE_ED_PUB),
                          sequence=42, expires_at=EPOCH_MS + 604800000)
    r.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(alias.signing_bytes(r))
    write(out, "alias/ahmad_seq42.json", vec(
        "RavenAliasRecordV1 — @ahmad seq 42", "identity-signed alias record",
        {"alias": r.alias, "identity_address": r.identity_address, "sequence": r.sequence,
         "expires_at_ms": r.expires_at, "identity_ed_public_hex": ALICE_ED_PUB.hex()},
        {"signing_bytes_hex": alias.signing_bytes(r).hex(), "signature_hex": r.signature.hex()}))

    c = device_cert.DeviceCert(device_ed_pub=BOB_ED_PUB, device_x_pub=BOB_X_PUB,
                               device_id="bob-device-1", not_before=EPOCH_MS,
                               not_after=EPOCH_MS + 31536000000, capabilities=0b111)
    c.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(device_cert.signing_bytes(c))
    write(out, "device_cert/bob_device1.json", vec(
        "RavenDeviceCertificateV1 — bob device authorized by alice-identity",
        "user-identity-signed device certificate",
        {"device_ed_public_hex": BOB_ED_PUB.hex(), "device_x_public_hex": BOB_X_PUB.hex(),
         "device_id": c.device_id, "not_before_ms": c.not_before, "not_after_ms": c.not_after,
         "capabilities": c.capabilities, "user_identity_ed_public_hex": ALICE_ED_PUB.hex()},
        {"signing_bytes_hex": device_cert.signing_bytes(c).hex(), "signature_hex": c.signature.hex()}))

    # RavenProtocolCapabilitiesV1 — signed capability set (downgrade protection).
    cap = capabilities.Capabilities(identity_address=address.encode(ALICE_ED_PUB),
                                    capability_bits=0b1111, expires_at=EPOCH_MS + 604800000)
    cap.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(capabilities.signing_bytes(cap))
    write(out, "capabilities/alice_v1.json", vec(
        "RavenProtocolCapabilitiesV1 — alice", "identity-signed capability set for downgrade protection",
        {"identity_address": cap.identity_address, "capability_bits": cap.capability_bits,
         "expires_at_ms": cap.expires_at, "identity_ed_public_hex": ALICE_ED_PUB.hex()},
        {"signing_bytes_hex": capabilities.signing_bytes(cap).hex(), "signature_hex": cap.signature.hex()}))

    # RavenPrekeyBundleV1 — deterministic structural fixture. Keep the frozen
    # JSON shape stable; canonical signing behavior is exercised by
    # tests/test_prekey.py. The repeated ML-KEM bytes below are deliberately
    # non-production material and therefore are not serialized into this vector.
    pk = prekey.PrekeyBundle(
        identity_ed25519_pub=ALICE_ED_PUB,
        device_id="dev1",
        x25519_pub=bytes([7]) * 32,
        mlkem768_ek=bytes([3]) * prekey.MLKEM768_EK_LEN,
        signed_prekey_id=1,
        one_time_prekey_id=0,
        one_time_x25519_pub=None,
        created_at_ms=EPOCH_MS,
        expires_at_ms=EPOCH_MS + 604800000,
    )
    pk.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(
        prekey.signing_bytes(pk)
    )
    write_frozen_order(out, "prekey/bundle_structure_001.json", {
        "id": "bundle_structure_001",
        "description": "Prekey bundle field sizes and domain (EK is test pattern, not a live ML-KEM key)",
        "input": {
            "domain_utf8": prekey.DOMAIN.decode(),
            "version": prekey.VERSION,
            "device_id": pk.device_id,
            "mlkem768_ek_len": len(pk.mlkem768_ek),
            "signed_prekey_id": pk.signed_prekey_id,
            "one_time_prekey_id": pk.one_time_prekey_id,
        },
        "expected": {
            "mlkem768_ek_len": prekey.MLKEM768_EK_LEN,
            "signature_len": len(pk.signature),
        },
    })

    # RavenPrekeyBundleV1 — full canonical signing KATs (bundle_structure_001 is
    # frozen and carries only sizes). Both OTP branches, a real ML-KEM-768 EK
    # (from the integrity-pinned hybrid KAT) and the section 4 clock window.
    kat = json.loads((REPO_ROOT / "shared-vectors/rvn1" / MLKEM_INTEROP_VECTOR).read_text())
    kat_exp = kat["expected"]
    real_ek = bytes.fromhex(kat_exp["mlkem_ek_hex"])
    otp_pub = bytes.fromhex(kat_exp["bob_x25519_public_hex"])
    spk_pub = bytes.fromhex(kat_exp["alice_x25519_public_hex"])
    prekey_signing = {}
    for case_id, otp_id, otp_key, desc in (
        ("bundle_signing_001", 7, otp_pub, "one-time prekey present (otp id 7)"),
        ("bundle_signing_002", 0, None, "no one-time prekey (otp id 0, key omitted from signing bytes)"),
    ):
        b = prekey.PrekeyBundle(
            identity_ed25519_pub=ALICE_ED_PUB,
            device_id="alice-device-1",
            x25519_pub=spk_pub,
            mlkem768_ek=real_ek,
            signed_prekey_id=3,
            one_time_prekey_id=otp_id,
            one_time_x25519_pub=otp_key,
            created_at_ms=EPOCH_MS,
            expires_at_ms=EPOCH_MS + 604800000,
        )
        b.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(prekey.signing_bytes(b))
        assert prekey.verify(b)
        prekey_signing[case_id] = b
        write(out, f"prekey/{case_id}.json", vec(
            f"RavenPrekeyBundleV1 — canonical signing bytes ({desc})",
            "identity-signed prekey bundle; verify with identity_ed25519_pub; "
            "validity window per RAVEN_PREKEY_BUNDLE_V1 section 4 (5 min skew)",
            {"identity_ed25519_pub_hex": b.identity_ed25519_pub.hex(),
             "device_id": b.device_id,
             "x25519_pub_hex": b.x25519_pub.hex(),
             "mlkem768_ek_hex": b.mlkem768_ek.hex(),
             "mlkem768_ek_source_vector": MLKEM_INTEROP_VECTOR.as_posix(),
             "signed_prekey_id": b.signed_prekey_id,
             "one_time_prekey_id": b.one_time_prekey_id,
             "one_time_x25519_pub_hex": None if otp_key is None else otp_key.hex(),
             "created_at_ms": b.created_at_ms,
             "expires_at_ms": b.expires_at_ms},
            {"signing_bytes_hex": prekey.signing_bytes(b).hex(),
             "signature_hex": b.signature.hex(),
             "verify_result": "accept",
             "clock_cases": [
                 {"now_ms": b.created_at_ms - 300000, "result": "accept"},
                 {"now_ms": b.created_at_ms - 300001, "result": "reject", "error": "PREKEY_NOT_YET_VALID"},
                 {"now_ms": b.expires_at_ms + 300000, "result": "accept"},
                 {"now_ms": b.expires_at_ms + 300001, "result": "reject", "error": "PREKEY_EXPIRED"},
             ]}))

    mailbox = store_tags.mailbox_tag(K_ROUTE, EPOCH_S, 0)
    write_frozen_order(out, "store/mailbox_tag_001.json", {
        "id": "mailbox_tag_001",
        "description": "Opaque rotating mailbox tag + store_tag (not username)",
        "input": {
            "k_route_hex": K_ROUTE.hex(),
            "epoch": EPOCH_S,
            "slot": 0,
            "mailbox_label_utf8": store_tags.MAILBOX_LABEL.decode(),
            "store_domain_utf8": store_tags.STORE_DOMAIN.decode(),
        },
        "expected": {
            "mailbox_tag_hex": mailbox.hex(),
            "store_tag_hex": store_tags.store_tag(mailbox).hex(),
        },
    })

    # ---- negative vectors ----
    bad_addr = address.encode(ALICE_ED_PUB)
    bad_addr = bad_addr[:-1] + ("q" if bad_addr[-1] != "q" else "p")
    write(out, "negative/address_bad_checksum.json", vec(
        "Address with corrupted checksum must fail to decode", "single-char corruption",
        {"address": bad_addr}, {"decode_result": "reject"}))

    raw = bytearray(envelope.pack(e)); raw[0] = 0
    write(out, "negative/envelope_bad_magic.json", vec(
        "Envelope with wrong magic must be rejected", "magic byte zeroed",
        {"packed_hex": bytes(raw).hex()}, {"unpack_result": "reject"}))

    tam = build_message_envelope(); tam.message_ciphertext = b"RVNS1-sealed-body-TAMPERED"
    write(out, "negative/envelope_tampered_body.json", vec(
        "Envelope body tampered after signing must fail verify", "ciphertext changed post-sign",
        {"packed_hex": envelope.pack(tam).hex(), "signer_ed_public_hex": ALICE_ED_PUB.hex()},
        {"verify_result": "reject"}))

    write(out, "negative/envelope_expired.json", vec(
        "Envelope past expires_at must be dropped by relays", "expires_at < validation clock",
        {"expires_at_ms": EPOCH_MS - 1000, "validation_clock_ms": EPOCH_MS},
        {"relay_action": "drop"}))

    r2 = alias.AliasRecord(alias="ahmad", identity_address=address.encode(ALICE_ED_PUB),
                           sequence=41, expires_at=EPOCH_MS + 604800000)
    r2.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(alias.signing_bytes(r2))
    write(out, "negative/alias_stale_sequence.json", vec(
        "Older-sequence alias record must not replace a newer one", "seq 41 vs cached 42",
        {"cached_sequence": 42, "incoming_sequence": 41,
         "incoming_signing_bytes_hex": alias.signing_bytes(r2).hex()},
        {"resolver_action": "reject_stale"}))

    awrong = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(ack.signing_bytes(a))
    write(out, "negative/ack_wrong_signer.json", vec(
        "ACK verified against wrong key must fail", "signed by alice, verified as bob",
        {"signing_bytes_hex": ack.signing_bytes(a).hex(), "signature_hex": awrong.hex(),
         "claimed_signer_ed_public_hex": BOB_ED_PUB.hex()},
        {"verify_result": "reject"}))

    # Device cert signed by a non-identity key must not authorize the device.
    dc_wrong = Ed25519PrivateKey.from_private_bytes(BOB_ED_PRIV).sign(device_cert.signing_bytes(c))
    write(out, "negative/device_cert_wrong_signer.json", vec(
        "Device certificate not signed by the claimed user identity must fail",
        "signed by bob, verified against alice-identity",
        {"signing_bytes_hex": device_cert.signing_bytes(c).hex(), "signature_hex": dc_wrong.hex(),
         "claimed_user_identity_ed_public_hex": ALICE_ED_PUB.hex()},
        {"verify_result": "reject"}))

    # Capability set with a flipped bit after signing must fail verification (downgrade defense).
    cap_tam = capabilities.Capabilities(identity_address=cap.identity_address,
                                        capability_bits=0b0001, expires_at=cap.expires_at)
    write(out, "negative/capabilities_tampered_bits.json", vec(
        "Capability bits changed after signing must fail verify", "advertised bits downgraded post-sign",
        {"signing_bytes_hex": capabilities.signing_bytes(cap_tam).hex(),
         "original_signature_hex": cap.signature.hex(),
         "identity_ed_public_hex": ALICE_ED_PUB.hex()},
        {"verify_result": "reject"}))

    write_frozen_order(out, "negative/prekey_bad_sig.json", {
        "id": "prekey_bad_sig",
        "description": "Tampered prekey signature must reject with PREKEY_BAD_SIG",
        "expected": {"verify_result": "reject", "error": "PREKEY_BAD_SIG"},
    })

    # prekey_bad_sig.json (frozen) has no inputs; _002 is a concrete bundle.
    good = prekey_signing["bundle_signing_001"]
    bad_sig = bytearray(good.signature); bad_sig[0] ^= 0x01
    tampered = prekey.PrekeyBundle(**{**good.__dict__, "signature": bytes(bad_sig)})
    assert not prekey.verify(tampered)
    write(out, "negative/prekey_bad_sig_002.json", vec(
        "Prekey bundle with a flipped signature bit must reject",
        "bundle_signing_001 with signature byte 0 xor 0x01",
        {"bundle_vector": "prekey/bundle_signing_001.json",
         "signing_bytes_hex": prekey.signing_bytes(tampered).hex(),
         "signature_hex": bytes(bad_sig).hex(),
         "identity_ed25519_pub_hex": ALICE_ED_PUB.hex(),
         "validation_clock_ms": EPOCH_MS},
        {"verify_result": "reject", "error": "PREKEY_BAD_SIG"}))

    # Strict RVN1 decoder rules (post-freeze tightening) as shared negatives so
    # every port rejects the same bytes. Each case is re-signed where the field
    # is covered by the signature, so only the rule under test is violated.
    def signed_envelope(**overrides):
        env = build_message_envelope()
        for k, v in overrides.items():
            setattr(env, k, v)
        env.sender_authentication = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(
            envelope.signing_bytes(env))
        return env

    base_packed = envelope.pack(e)
    short_auth = signed_envelope()
    short_auth.sender_authentication = short_auth.sender_authentication[:63]
    strict_cases = [
        ("envelope_expires_not_after_created_001", "expires_at == created_at",
         envelope.pack(signed_envelope(expires_at=EPOCH_MS)), "RVN1 requires expires_at > created_at"),
        ("envelope_auth_len_63_001", "auth_len 63 (signature truncated)",
         envelope.pack(short_auth), "auth_len MUST be exactly 64"),
        ("envelope_reserved_flag_001", "flags bit 2 set",
         envelope.pack(signed_envelope(flags=0x0004)), "only flag bits 0-1 are defined"),
        ("envelope_env_type_0_001", "env_type 0",
         envelope.pack(signed_envelope(env_type=0)), "env_type MUST be registered (1-4)"),
        ("envelope_env_type_5_001", "env_type 5",
         envelope.pack(signed_envelope(env_type=5)), "env_type MUST be registered (1-4)"),
        ("envelope_trailing_byte_001", "one byte after the signature",
         base_packed + b"\x00", "total length MUST equal the declared lengths"),
        ("envelope_truncated_001", "last signature byte missing",
         base_packed[:-1], "total length MUST equal the declared lengths"),
        ("envelope_bad_version_001", "version byte 2",
         base_packed[:4] + b"\x02" + base_packed[5:], "version MUST be 1"),
    ]
    for case_id, desc, packed, rule in strict_cases:
        assert envelope.unpack(packed) is None, case_id
        write(out, f"negative/{case_id}.json", vec(
            f"Strict RVN1 decoder must reject: {desc}", rule,
            {"packed_hex": packed.hex()}, {"unpack_result": "reject"}))

    # envelope_expired.json (frozen) carries only integers; _002 is a real,
    # correctly signed envelope that a relay must drop at the given clock.
    expired = signed_envelope(created_at=EPOCH_MS - 10_000, expires_at=EPOCH_MS - 1000)
    assert envelope.unpack(envelope.pack(expired)) is not None
    write(out, "negative/envelope_expired_002.json", vec(
        "Signed envelope past expires_at must be dropped by relays",
        "decodes (well-formed) but expires_at < validation clock",
        {"packed_hex": envelope.pack(expired).hex(), "validation_clock_ms": EPOCH_MS,
         "signer_ed_public_hex": ALICE_ED_PUB.hex()},
        {"unpack_result": "accept", "relay_action": "drop", "drop_reason": "expired"}))

    # --- Portable ATSAM / interim KATs (no ML-KEM; label agreement only) ---
    local_pub = bytes([0x01] * 32)
    peer_pub = bytes([0x02] * 32)
    a, b = (local_pub, peer_pub) if local_pub <= peer_pub else (peer_pub, local_pub)
    interim_ikm = hashlib.sha256(b"raven/rvn1/interim-psk" + a + b"|" + b).digest()
    # NOTE: the frozen `notes` string below says "HKDF-Expand", but this (and
    # raven-core seal.rs) is full RFC 5869 HKDF with a zero salt — extract,
    # then expand. The vector bytes are frozen; see protocol/SPEC.md known issues.
    interim_key = hkdf_sha256(interim_ikm, None, b"raven/rvn1/interim-seal/v0")
    write(out, "seal/interim_pairwise_001.json", {
        "id": "rvn1_interim_pairwise_001",
        "description": "Interim seal pairwise demo key (proto 0x7F). Not shipping ATSAM.",
        "local_pub_hex": local_pub.hex(),
        "peer_pub_hex": peer_pub.hex(),
        "pairwise_key_hex": interim_key.hex(),
        "notes": "SHA-256(raven/rvn1/interim-psk || sort(pubA,pubB) with '|') then HKDF-Expand info raven/rvn1/interim-seal/v0",
    })

    root = bytes([0x11] * 32)
    s, r = b"alice", b"bob"
    ck0 = hkdf_sha256(root, None, b"ATSAM/v2/chain-init\x00" + s + b"\x00" + r)
    ck1 = hkdf_sha256(ck0, None, b"ATSAM/v2/chain-advance")
    kmsg = hkdf_sha256(ck0, b"ATSAM/v2/msg-seal/salt", b"ATSAM/v2/msg-key\x00" + s + b"\x00" + r)
    write(out, "atsam/chain_kdf_001.json", {
        "id": "rvn1_atsam_chain_kdf_001",
        "description": "ATSAM v2 chain HKDF labels without ML-KEM — portable KAT for Rust/Swift agreement",
        "root_hex": root.hex(),
        "sender": "alice",
        "recipient": "bob",
        "ck0_hex": ck0.hex(),
        "ck1_hex": ck1.hex(),
        "k_msg_hex": kmsg.hex(),
        "labels": {
            "chain_init": "ATSAM/v2/chain-init",
            "chain_advance": "ATSAM/v2/chain-advance",
            "msg_key": "ATSAM/v2/msg-key",
            "msg_seal_salt": "ATSAM/v2/msg-seal/salt",
        },
        "gap": "ML-KEM hybrid root establishment is NOT covered — this KAT assumes a known K_root. iOS remains canonical for pairing until Rust ports ML-KEM-768.",
    })

    # ATSAM Indexed Session Profile V1 — additive, production-disabled KATs.
    # These freeze derivation and codec bytes only.  A future signed PairInit
    # must negotiate/profile-bind the session context before endpoint use.
    alice_address = address.encode(ALICE_ED_PUB)
    bob_address = address.encode(BOB_ED_PUB)
    profile_root = bytes([0x11] * 32)
    ack_base = indexed_session.ack_base_key(profile_root)
    route_master = indexed_session.route_master_key(profile_root)
    mailbox_day, _ = indexed_session.mailbox_coordinates(EPOCH_MS, 0)
    direction_vectors = []
    for direction in (0, 1):
        sender, recipient = (
            (alice_address, bob_address) if direction == 0
            else (bob_address, alice_address)
        )
        message_ck0 = indexed_session.chain_key_at_index(
            profile_root, sender, recipient, 0
        )
        ack_ck0 = indexed_session.ack_chain_key_at_index(
            profile_root, alice_address, bob_address, direction, 0
        )
        profile_mailbox_tag, profile_store_tag = indexed_session.derive_mailbox_tags(
            profile_root, EPOCH_MS, direction
        )
        direction_vectors.append({
            "direction": direction,
            "sender_address": sender,
            "recipient_address": recipient,
            "message_ck0_hex": message_ck0.hex(),
            "message_key_index0_hex": indexed_session.message_key_at_index(
                profile_root, alice_address, bob_address, direction, 0
            ).hex(),
            "ack_ck0_hex": ack_ck0.hex(),
            "ack_key_index0_hex": indexed_session.ack_key_at_index(
                profile_root, alice_address, bob_address, direction, 0
            ).hex(),
            "route_direction_key_hex": indexed_session.route_direction_key(
                profile_root, direction
            ).hex(),
            "mailbox_day_epoch": mailbox_day,
            "mailbox_slot": direction,
            "mailbox_tag_hex": profile_mailbox_tag.hex(),
            "store_tag_hex": profile_store_tag.hex(),
        })
    write(out, "atsam/indexed_session_v1_subkeys_001.json", {
        "id": "atsam_indexed_session_v1_subkeys_001",
        "description": "Separately versioned ATSAM indexed-session subkeys and transcript-role directions",
        "profile_version": indexed_session.PROFILE_ID.decode(),
        "deterministic": True,
        "production_enabled": indexed_session.PRODUCTION_ENABLED,
        "production_activation": "disabled_pending_signed_pairinit_negotiation",
        "input": {
            "k_root_hex": profile_root.hex(),
            "k_root_note": "public deterministic fixture material; never a live session root",
            "initiator_address": alice_address,
            "responder_address": bob_address,
            "mailbox_time_ms": EPOCH_MS,
        },
        "labels": {
            "ack_base": indexed_session.LABEL_ACK_BASE.decode(),
            "route_master": indexed_session.LABEL_ROUTE_MASTER.decode(),
            "route_direction": indexed_session.LABEL_ROUTE_DIRECTION.decode(),
            "chain_init": indexed_session.LABEL_CHAIN_INIT.decode(),
            "chain_advance": indexed_session.LABEL_CHAIN_ADVANCE.decode(),
            "lane_message_key": indexed_session.LABEL_MSG_KEY.decode(),
            "lane_message_salt": indexed_session.SALT_MSG_SEAL.decode(),
        },
        "expected": {
            "session_context_hex": indexed_session.session_context(
                alice_address, bob_address
            ).hex(),
            "ack_base_key_hex": ack_base.hex(),
            "route_master_key_hex": route_master.hex(),
            "directions": direction_vectors,
        },
    })

    ack_outer_message_id = bytes.fromhex("00112233445546778899aabbccddeeff")
    ack_created_at = EPOCH_MS + 1000
    ack_index = 7
    ack_direction = indexed_session.DIRECTION_RESPONDER_TO_INITIATOR
    ack_record = ack.Ack(
        acked_message_id=e.message_id,
        status=1,
        ack_nonce=(2).to_bytes(12, "big"),
        created_at=ack_created_at,
    )
    ack_inner_signature = Ed25519PrivateKey.from_private_bytes(BOB_ED_PRIV).sign(
        ack.signing_bytes(ack_record)
    )
    ack_plaintext = indexed_session.encode_signed_ack(
        ack_record, ack_inner_signature
    )
    ack_seal_nonce = bytes([0xCD] * 12)
    ack_wire = indexed_session.seal_ack(
        profile_root,
        alice_address,
        bob_address,
        ack_direction,
        ack_index,
        ack_outer_message_id,
        ack_plaintext,
        ack_seal_nonce,
    )
    ack_epoch, ack_counter = indexed_session.route_coordinates(
        ack_created_at, ack_index, 2, ack_direction
    )
    ack_route_tag = indexed_session.derive_route_tag(
        profile_root, ack_created_at, ack_index, 2, ack_direction
    )
    ack_aad = indexed_session.build_aad(
        ack_index, bob_address, alice_address, ack_outer_message_id
    )
    ack_envelope = envelope.Envelope(
        env_type=2,
        # Known-root KAT: do not claim hybrid-PQ establishment in outer flags.
        flags=0,
        message_id=ack_outer_message_id,
        routing_tag=ack_route_tag,
        dest_device_hint=0,
        created_at=ack_created_at,
        expires_at=ack_created_at + 86400000,
        hop_limit=8,
        replication_budget=3,
        anti_replay_nonce=(3).to_bytes(12, "big"),
        ratchet_header_ciphertext=b"",
        message_ciphertext=ack_wire,
        sender_authentication=b"",
    )
    ack_envelope.sender_authentication = Ed25519PrivateKey.from_private_bytes(
        BOB_ED_PRIV
    ).sign(envelope.signing_bytes(ack_envelope))
    ack_packed = envelope.pack(ack_envelope)
    assert len(ack_plaintext) == 101
    assert len(ack_wire) == 143
    assert len(ack_packed) == 293
    write(out, "atsam/indexed_session_v1_sealed_ack_001.json", {
        "id": "atsam_indexed_session_v1_sealed_ack_001",
        "description": "Exact 101-byte signed ACK sealed as 143-byte RVNA1 proto 0x03 and packed in a 293-byte RVN1 envelope",
        "profile_version": indexed_session.PROFILE_ID.decode(),
        "deterministic": True,
        "production_enabled": indexed_session.PRODUCTION_ENABLED,
        "production_activation": "disabled_pending_signed_pairinit_negotiation",
        "input": {
            "k_root_hex": profile_root.hex(),
            "k_root_note": "public deterministic fixture material; never a live session root",
            "initiator_address": alice_address,
            "responder_address": bob_address,
            "direction": ack_direction,
            "ack_chain_index": ack_index,
            "acked_message_id_hex": ack_record.acked_message_id.hex(),
            "status": ack_record.status,
            "ack_nonce_hex": ack_record.ack_nonce.hex(),
            "created_at_ms": ack_record.created_at,
            "expires_at_ms": ack_envelope.expires_at,
            "inner_signer_ed_public_hex": BOB_ED_PUB.hex(),
            "outer_message_id_hex": ack_outer_message_id.hex(),
            "outer_message_id_aad_uuid": indexed_session.uuid_text(
                ack_outer_message_id
            ),
            "seal_nonce_hex": ack_seal_nonce.hex(),
            "anti_replay_nonce_hex": ack_envelope.anti_replay_nonce.hex(),
            "hop_limit": ack_envelope.hop_limit,
            "replication_budget": ack_envelope.replication_budget,
            "outer_flags": ack_envelope.flags,
        },
        "allocator": {
            "epoch": ack_epoch,
            "counter": ack_counter,
            "env_type": 2,
            "formula": "counter=(index<<3)|((env_type-1)<<1)|direction",
        },
        "expected": {
            "ack_signing_bytes_hex": ack.signing_bytes(ack_record).hex(),
            "inner_signature_hex": ack_inner_signature.hex(),
            "ack_plaintext_len": len(ack_plaintext),
            "ack_plaintext_hex": ack_plaintext.hex(),
            "ack_key_index7_hex": indexed_session.ack_key_at_index(
                profile_root, alice_address, bob_address, ack_direction, ack_index
            ).hex(),
            "aad_sha256_hex": ack_aad.hex(),
            "routing_tag_hex": ack_route_tag.hex(),
            "rvna1_proto": indexed_session.RVNA1_PROTO,
            "rvna1_suite": indexed_session.RVNA1_SUITE,
            "sealed_body_len": len(ack_wire),
            "sealed_body_hex": ack_wire.hex(),
            "outer_signing_bytes_hex": envelope.signing_bytes(ack_envelope).hex(),
            "outer_signature_hex": ack_envelope.sender_authentication.hex(),
            "packed_envelope_len": len(ack_packed),
            "packed_envelope_hex": ack_packed.hex(),
        },
    })

    # Raven PairInit V1 — an additive, production-disabled, offline-capable
    # session-establishment transcript. The responder's already signed prekey
    # permits Alice to derive and queue message 0 before the signed response;
    # the response confirms possession of the exact provisional root later.
    hybrid_kat = json.loads(
        (REPO_ROOT / "shared-vectors/rvn1" / MLKEM_INTEROP_VECTOR).read_text()
    )
    hybrid_in = hybrid_kat["input"]
    hybrid_exp = hybrid_kat["expected"]
    alice_device_seed = bytes(range(32))
    bob_device_seed = bytes(range(32, 64))
    alice_device_private = Ed25519PrivateKey.from_private_bytes(alice_device_seed)
    bob_device_private = Ed25519PrivateKey.from_private_bytes(bob_device_seed)
    alice_device_ed = alice_device_private.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    bob_device_ed = bob_device_private.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    alice_device_x = X25519PrivateKey.from_private_bytes(bytes([0x41]) * 32).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    bob_signed_x = X25519PrivateKey.from_private_bytes(bytes([0x52]) * 32).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    alice_ephemeral_x = bytes.fromhex(hybrid_exp["alice_x25519_public_hex"])
    bob_one_time_x = bytes.fromhex(hybrid_exp["bob_x25519_public_hex"])
    mlkem_ek = bytes.fromhex(hybrid_exp["mlkem_ek_hex"])
    mlkem_ct = bytes.fromhex(hybrid_exp["mlkem_ct_hex"])

    alice_cert = device_cert.DeviceCert(
        device_ed_pub=alice_device_ed,
        device_x_pub=alice_device_x,
        device_id="alice-device-1",
        not_before=EPOCH_MS - 86_400_000,
        not_after=EPOCH_MS + 31_536_000_000,
        capabilities=0,
    )
    alice_cert.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(
        device_cert.signing_bytes(alice_cert)
    )
    bob_cert = device_cert.DeviceCert(
        device_ed_pub=bob_device_ed,
        device_x_pub=bob_signed_x,
        device_id="bob-device-1",
        not_before=EPOCH_MS - 86_400_000,
        not_after=EPOCH_MS + 31_536_000_000,
        capabilities=0,
    )
    bob_cert.signature = Ed25519PrivateKey.from_private_bytes(BOB_ED_PRIV).sign(
        device_cert.signing_bytes(bob_cert)
    )
    bob_prekey = prekey.PrekeyBundle(
        identity_ed25519_pub=BOB_ED_PUB,
        device_id=bob_cert.device_id,
        x25519_pub=bob_signed_x,
        mlkem768_ek=mlkem_ek,
        signed_prekey_id=42,
        one_time_prekey_id=7,
        one_time_x25519_pub=bob_one_time_x,
        created_at_ms=EPOCH_MS - 60_000,
        expires_at_ms=EPOCH_MS + 604_800_000,
    )
    bob_prekey.signature = Ed25519PrivateKey.from_private_bytes(BOB_ED_PRIV).sign(
        prekey.signing_bytes(bob_prekey)
    )
    alice_cert_hash = pair_init.device_certificate_hash(
        ALICE_ED_PUB, device_cert.signing_bytes(alice_cert), alice_cert.signature
    )
    bob_cert_hash = pair_init.device_certificate_hash(
        BOB_ED_PUB, device_cert.signing_bytes(bob_cert), bob_cert.signature
    )
    bob_prekey_hash = pair_init.prekey_bundle_hash(
        prekey.signing_bytes(bob_prekey), bob_prekey.signature
    )
    pair = pair_init.PairInit(
        initiator_address=alice_address,
        responder_address=bob_address,
        init_id=bytes.fromhex("102132435465768798a9bacbdcedfe0f"),
        pairing_nonce=bytes(
            (0x91 + index * 7) & 0xFF for index in range(pair_init.NONCE_LEN)
        ),
        initiator_device_ed_pub=alice_device_ed,
        responder_device_ed_pub=bob_device_ed,
        initiator_ephemeral_x25519_pub=alice_ephemeral_x,
        responder_signed_x25519_pub=bob_signed_x,
        responder_one_time_x25519_pub=bob_one_time_x,
        initiator_device_cert_hash=alice_cert_hash,
        responder_device_cert_hash=bob_cert_hash,
        responder_prekey_bundle_hash=bob_prekey_hash,
        signed_prekey_id=bob_prekey.signed_prekey_id,
        one_time_prekey_id=bob_prekey.one_time_prekey_id,
        responder_mlkem768_ek=mlkem_ek,
        mlkem768_ciphertext=mlkem_ct,
        created_at_ms=EPOCH_MS,
        expires_at_ms=EPOCH_MS + 86_400_000,
    )
    pair.signature = alice_device_private.sign(pair_init.init_signing_bytes(pair))
    z_x = bytes.fromhex(hybrid_exp["z_x_hex"])
    z_pq = bytes.fromhex(hybrid_exp["z_pq_hex"])
    provisional_root = pair_init.derive_provisional_root(z_x, z_pq, pair)
    pair_digest = pair_init.init_hash(pair)
    response = pair_init.PairResponse(
        init_id=pair.init_id,
        init_hash=pair_digest,
        responder_device_ed_pub=bob_device_ed,
        created_at_ms=EPOCH_MS + 1000,
        expires_at_ms=EPOCH_MS + 86_400_000,
        confirmation_tag=pair_init.confirmation_tag(provisional_root, pair_digest),
    )
    response.signature = bob_device_private.sign(
        pair_init.response_signing_bytes(response)
    )
    write(out, "atsam/pair_init_v1_001.json", {
        "id": "atsam_pair_init_v1_001",
        "description": "Production-disabled offline PairInit: exact signed prekey/cert bindings, provisional hybrid root, and deferred signed confirmation",
        "profile_version": pair_init.PROFILE_ID.decode(),
        "deterministic": True,
        "production_enabled": pair_init.PRODUCTION_ENABLED,
        "production_activation": "disabled_pending_durable_session_actor_and_external_review",
        "input": {
            "initiator_identity_ed_pub_hex": ALICE_ED_PUB.hex(),
            "responder_identity_ed_pub_hex": BOB_ED_PUB.hex(),
            "initiator_device_ed_pub_hex": alice_device_ed.hex(),
            "responder_device_ed_pub_hex": bob_device_ed.hex(),
            "initiator_device_cert_signing_bytes_hex": device_cert.signing_bytes(alice_cert).hex(),
            "initiator_device_cert_signature_hex": alice_cert.signature.hex(),
            "responder_device_cert_signing_bytes_hex": device_cert.signing_bytes(bob_cert).hex(),
            "responder_device_cert_signature_hex": bob_cert.signature.hex(),
            "responder_prekey_signing_bytes_hex": prekey.signing_bytes(bob_prekey).hex(),
            "responder_prekey_signature_hex": bob_prekey.signature.hex(),
            "z_x_hex": z_x.hex(),
            "z_pq_hex": z_pq.hex(),
            "mlkem_source_vector": MLKEM_INTEROP_VECTOR.as_posix(),
            "mlkem_m_hex": hybrid_in["mlkem_m_hex"],
        },
        "expected": {
            "initiator_device_cert_hash_hex": alice_cert_hash.hex(),
            "responder_device_cert_hash_hex": bob_cert_hash.hex(),
            "responder_prekey_bundle_hash_hex": bob_prekey_hash.hex(),
            "pair_init_signing_bytes_hex": pair_init.init_signing_bytes(pair).hex(),
            "pair_init_signature_hex": pair.signature.hex(),
            "pair_init_wire_hex": pair_init.encode_init(pair).hex(),
            "pair_init_wire_len": pair_init.INIT_WIRE_LEN,
            "pair_init_hash_hex": pair_digest.hex(),
            "session_id_hex": pair_init.session_id(pair).hex(),
            "transcript_hash_hex": pair_init.transcript_hash(pair).hex(),
            "provisional_k_root_hex": provisional_root.hex(),
            "confirmation_tag_hex": response.confirmation_tag.hex(),
            "pair_response_signing_bytes_hex": pair_init.response_signing_bytes(response).hex(),
            "pair_response_signature_hex": response.signature.hex(),
            "pair_response_wire_hex": pair_init.encode_response(response).hex(),
            "pair_response_wire_len": pair_init.RESPONSE_WIRE_LEN,
        },
    })
    # PairInit V1 structural negatives derived from the pair_init_v1_001 wire.
    # Each must be rejected by decode_init before any signature work.
    pi_wire = pair_init.encode_init(pair)
    otp_id_offset = (12 + pair_init.PROFILE_LEN + 2 * pair_init.ADDRESS_LEN
                     + pair_init.INIT_ID_LEN + pair_init.NONCE_LEN + 5 * 32 + 3 * 32 + 4)
    assert pair.one_time_prekey_id != 0
    assert pi_wire[otp_id_offset:otp_id_offset + 4] == pair.one_time_prekey_id.to_bytes(4, "big")

    def patched(offset, new_bytes):
        return pi_wire[:offset] + new_bytes + pi_wire[offset + len(new_bytes):]

    pi_cases = [
        ("pair_init_v1_trailing_byte_001", "one byte after the signature",
         pi_wire + b"\x00", "InvalidLength"),
        ("pair_init_v1_truncated_001", "last byte missing", pi_wire[:-1], "InvalidLength"),
        ("pair_init_v1_bad_magic_001", "magic byte 0 changed",
         patched(0, bytes([pi_wire[0] ^ 0x01])), "InvalidMagic"),
        ("pair_init_v1_bad_version_001", "version byte 2", patched(8, b"\x02"), "InvalidVersion"),
        ("pair_init_v1_responder_role_001", "role byte = responder (1)",
         patched(10, b"\x01"), "InvalidRole"),
        ("pair_init_v1_wrong_profile_001", "profile id byte changed",
         patched(12, bytes([pi_wire[12] ^ 0x01])), "InvalidProfile"),
        ("pair_init_v1_otp_slot_inconsistent_001",
         "one_time_prekey_id zeroed while the one-time X25519 slot is non-zero",
         patched(otp_id_offset, b"\x00\x00\x00\x00"), "InvalidOneTimePrekey"),
    ]
    for case_id, desc, wire, err in pi_cases:
        try:
            pair_init.decode_init(wire)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{case_id}: reference decoder accepted a negative")
        write(out, f"atsam/negative/{case_id}.json", {
            "id": case_id,
            "description": f"PairInit V1 decode must reject: {desc}",
            "protocol_version": "rvn1",
            "deterministic": True,
            "production_enabled": pair_init.PRODUCTION_ENABLED,
            "source_vector": "atsam/pair_init_v1_001.json",
            "input": {"pair_init_wire_hex": wire.hex()},
            "expected": {"decode_result": "reject", "rust_error": err},
        })

    # Root HKDF (Z_X||Z_PQ + transcript) — matches raven-core::atsam_root / ATSAMRootDerivation
    z_x = bytes([0x11] * 32)
    z_pq = bytes([0x22] * 32)
    transcript_material = b"kat-pair-material"
    transcript_hash = hashlib.sha256(b"ATSAM/v1/transcript" + transcript_material).digest()
    k_root = hkdf_sha256(z_x + z_pq, transcript_hash, b"ATSAM/v1/pair-init" + transcript_hash)
    write(out, "atsam/root_hkdf_001.json", {
        "id": "atsam_root_hkdf_001",
        "description": "ATSAM K_root HKDF with known Z_X||Z_PQ and transcript (no ML-KEM). Matches raven-core::atsam_root and iOS ATSAMRootDerivation labels.",
        "input": {
            "z_x_hex": z_x.hex(),
            "z_pq_hex": z_pq.hex(),
            "transcript_material_utf8": transcript_material.decode(),
            "transcript_domain_utf8": "ATSAM/v1/transcript",
            "pair_init_utf8": "ATSAM/v1/pair-init",
        },
        "expected": {
            "transcript_hash_hex": transcript_hash.hex(),
            "k_root_hex": k_root.hex(),
        },
    })
    # AAD + AEAD with known K_root (no ML-KEM) — matches ATSAMMessageSealer v2
    msg_id = b"msg-001"
    index = 0
    nonce = bytes([0xAB] * 12)
    plaintext = b"portable-atsam-v2"
    aad_v2 = hashlib.sha256(
        b"ATSAM/v1/msg-seal/aad\x00"
        + bytes([0x02, 0x01])
        + index.to_bytes(4, "big")
        + b"\x00" + s + b"\x00" + r + b"\x00" + msg_id
    ).digest()
    aad_v1 = hashlib.sha256(
        b"ATSAM/v1/msg-seal/aad\x00\x00" + s + b"\x00" + r + b"\x00" + msg_id
    ).digest()
    ct_tag = ChaCha20Poly1305(kmsg).encrypt(nonce, plaintext, aad_v2)
    wire = b"RVNA1\x00\x00\x00" + bytes([0x02, 0x01]) + index.to_bytes(4, "big") + nonce + ct_tag
    write(out, "atsam/rvna1_v2_aead_known_root_001.json", {
        "id": "rvn1_atsam_rvna1_v2_aead_known_root_001",
        "description": "RVNA1 v2 ChaCha20-Poly1305 + AAD given known K_root (no ML-KEM pairing)",
        "root_hex": root.hex(),
        "sender": "alice",
        "recipient": "bob",
        "msg_id": msg_id.decode(),
        "index": index,
        "nonce_hex": nonce.hex(),
        "plaintext_hex": plaintext.hex(),
        "k_msg_hex": kmsg.hex(),
        "aad_v2_hex": aad_v2.hex(),
        "aad_v1_hex": aad_v1.hex(),
        "wire_hex": wire.hex(),
        "gap": "Does not cover ML-KEM hybrid pairing or skipped-key cache; only AEAD+AAD+chain index 0.",
    })
    write(out, "atsam/rvna1_header_layouts_001.json", {
        "id": "rvn1_rvna1_header_layouts_001",
        "description": "RVNA1 header layouts for classification (no AEAD)",
        "cases": [
            {
                "name": "interim_0x7f",
                "wire_prefix_hex": "52564e41310000007f01",
                "min_len": 38,
                "class": "interim_stub",
                "index": None,
            },
            {
                "name": "atsam_v1",
                "wire_prefix_hex": "52564e41310000000101",
                "min_len": 38,
                "class": "opaque_atsam",
                "proto": 1,
                "index": None,
            },
            {
                "name": "atsam_v2_index7",
                "wire_prefix_hex": "52564e4131000000020100000007",
                "min_len": 42,
                "class": "opaque_atsam",
                "proto": 2,
                "index": 7,
            },
        ],
    })

    copy_integrity_pinned_vector(out, MLKEM_INTEROP_VECTOR, MLKEM_INTEROP_SHA256)

    # ---- RavenDeviceRevocationV1 (vector freeze) ----
    alice_addr = address.encode(ALICE_ED_PUB)
    bob_cert = device_cert.DeviceCert(
        device_ed_pub=BOB_ED_PUB,
        device_x_pub=BOB_X_PUB,
        device_id="bob-device-1",
        not_before=EPOCH_MS,
        not_after=EPOCH_MS + 365 * 86400 * 1000,
        capabilities=0,
    )
    bob_cert.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(
        device_cert.signing_bytes(bob_cert)
    )
    cert_hash = pair_init.device_certificate_hash(
        ALICE_ED_PUB, device_cert.signing_bytes(bob_cert), bob_cert.signature
    )
    device_id_b = b"bob-device-1"
    issuer_id_b = b"alice-primary"
    rev_id = bytes(range(1, 17))
    rec = device_revocation.DeviceRevocationV1(
        identity_address=alice_addr,
        device_id=device_id_b,
        device_ed_pub=BOB_ED_PUB,
        device_x_pub=BOB_X_PUB,
        device_cert_hash=cert_hash,
        issuer_device_id=issuer_id_b,
        issuer_seq=1,
        revocation_id=rev_id,
        reason_code=1,
        created_at_ms=EPOCH_MS,
    )
    rec = device_revocation.sign(rec, ALICE_ED_PRIV)
    wire = device_revocation.encode(rec)
    offsets = device_revocation.wire_offsets(device_id_b, issuer_id_b)
    cd = device_revocation.claim_digest(wire)
    write(
        out,
        "device_revocation/valid_001.json",
        vec(
            "RavenDeviceRevocationV1 valid wire",
            "Alice revokes bob-device-1 lineage; bare RVDR1 packaging",
            {
                "identity_ed_priv_hex": ALICE_ED_PRIV.hex(),
                "identity_ed_pub_hex": ALICE_ED_PUB.hex(),
                "identity_address": alice_addr,
                "device_id_utf8": "bob-device-1",
                "device_ed_pub_hex": BOB_ED_PUB.hex(),
                "device_x_pub_hex": BOB_X_PUB.hex(),
                "device_cert_signing_bytes_hex": device_cert.signing_bytes(bob_cert).hex(),
                "device_cert_signature_hex": bob_cert.signature.hex(),
                "device_cert_hash_hex": cert_hash.hex(),
                "issuer_device_id_utf8": "alice-primary",
                "issuer_seq": 1,
                "revocation_id_hex": rev_id.hex(),
                "reason_code": 1,
                "created_at_ms": EPOCH_MS,
            },
            {
                "wire_hex": wire.hex(),
                "wire_len": len(wire),
                "signing_bytes_hex": device_revocation.signing_bytes(rec).hex(),
                "signature_hex": rec.signature.hex(),
                "claim_digest_hex": cd.hex(),
                "object_digest_hex": cd.hex(),
                "offsets": offsets,
                "verify": True,
            },
        ),
    )

    # wrong signer (bob signs alice identity address — verify must fail)
    bad = device_revocation.DeviceRevocationV1(
        identity_address=alice_addr,
        device_id=device_id_b,
        device_ed_pub=BOB_ED_PUB,
        device_x_pub=BOB_X_PUB,
        device_cert_hash=cert_hash,
        issuer_device_id=issuer_id_b,
        issuer_seq=1,
        revocation_id=rev_id,
        reason_code=1,
        created_at_ms=EPOCH_MS,
        signature=Ed25519PrivateKey.from_private_bytes(BOB_ED_PRIV).sign(
            device_revocation.signing_bytes(rec)
        ),
    )
    bad_wire = device_revocation.encode(bad)
    write(
        out,
        "negative/device_revocation_wrong_signer.json",
        vec(
            "Revocation signed by non-identity key must fail verify",
            "bob signs alice-addressed RVDR1",
            {
                "wire_hex": bad_wire.hex(),
                "claimed_identity_ed_pub_hex": ALICE_ED_PUB.hex(),
            },
            {"verify_result": "reject"},
        ),
    )

    # store hash: one claim
    claims = [device_revocation.StoreClaim(exact_record_bytes=wire)]
    snap = device_revocation.canonical_store_snapshot(1, claims, [], [])
    sh = device_revocation.revocation_store_hash(1, claims, [], [])
    write(
        out,
        "device_revocation/store_hash_001.json",
        vec(
            "Canonical revocation_store_hash with one claim",
            "generation=1; empty exhausted/corrupt",
            {
                "generation": 1,
                "claims_wire_hex": [wire.hex()],
                "exhausted": [],
                "corrupt": [],
            },
            {
                "canonical_snapshot_hex": snap.hex(),
                "revocation_store_hash_hex": sh.hex(),
            },
        ),
    )

    # exhausted marker in snapshot (claim not in claims list)
    exh = device_revocation.ExhaustedMarker(
        identity_address=alice_addr,
        claim_digest=cd,
        exact_record_bytes=wire,
    )
    snap2 = device_revocation.canonical_store_snapshot(2, [], [exh], [])
    sh2 = device_revocation.revocation_store_hash(2, [], [exh], [])
    write(
        out,
        "device_revocation/store_hash_exhausted_001.json",
        vec(
            "Store hash with IDENTITY_REVOKE_EXHAUSTED blob only",
            "generation=2; claim deferred",
            {
                "generation": 2,
                "claims_wire_hex": [],
                "exhausted": [
                    {
                        "identity_address": alice_addr,
                        "claim_digest_hex": cd.hex(),
                        "exact_record_bytes_hex": wire.hex(),
                    }
                ],
                "corrupt": [],
            },
            {
                "canonical_snapshot_hex": snap2.hex(),
                "revocation_store_hash_hex": sh2.hex(),
            },
        ),
    )

    # crash-state ordering for expand replay (documentary + hash chain)
    # After successful apply: claims=[wire], exhausted=[], generation=3
    claims_after = [device_revocation.StoreClaim(exact_record_bytes=wire)]
    sh3 = device_revocation.revocation_store_hash(3, claims_after, [], [])
    write(
        out,
        "device_revocation/crash_replay_order_001.json",
        {
            "name": "Exhausted expand replay crash order",
            "description": (
                "Under lease: re-verify EXHAUSTED journal bytes; convert "
                "PENDING_REVOKE_EXHAUSTED→PENDING_REVOKE (same exact bytes); "
                "SQL atomic: insert claim + delete exhausted marker + bump gen; "
                "FINALIZED_REVOKE_ANCHOR; clear PENDING_REVOKE. "
                "Helper accepts only PENDING_REVOKE."
            ),
            "protocol_version": "rvn1",
            "deterministic": True,
            "steps": [
                {
                    "id": 1,
                    "state": "PENDING_REVOKE_EXHAUSTED+IDENTITY_REVOKE_EXHAUSTED",
                    "generation": 2,
                    "store_hash_hex": sh2.hex(),
                },
                {
                    "id": 2,
                    "action": "reverify_exact_bytes",
                    "source": "PENDING_REVOKE_EXHAUSTED",
                },
                {
                    "id": 3,
                    "action": "journal_convert",
                    "from": "PENDING_REVOKE_EXHAUSTED",
                    "to": "PENDING_REVOKE",
                    "same_exact_bytes": True,
                },
                {
                    "id": 4,
                    "action": "sql_atomic",
                    "ops": [
                        "insert_claim",
                        "append_revoked_targets",
                        "delete_IDENTITY_REVOKE_EXHAUSTED",
                        "upsert_cleanup",
                        "bump_generation",
                    ],
                },
                {
                    "id": 5,
                    "action": "write_FINALIZED_REVOKE_ANCHOR",
                    "generation": 3,
                    "store_hash_hex": sh3.hex(),
                },
                {"id": 6, "action": "clear_PENDING_REVOKE"},
            ],
            "expected_after": {
                "generation": 3,
                "claims_wire_hex": [wire.hex()],
                "exhausted": [],
                "revocation_store_hash_hex": sh3.hex(),
            },
        },
    )

    # ---- Revocation conformance fixtures (union / collision / quota / corrupt / gates) ----
    def mint_device_cert(ed_pub, x_pub, device_id: str):
        c = device_cert.DeviceCert(
            device_ed_pub=ed_pub,
            device_x_pub=x_pub,
            device_id=device_id,
            not_before=EPOCH_MS,
            not_after=EPOCH_MS + 365 * 86400 * 1000,
            capabilities=0,
        )
        c.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(
            device_cert.signing_bytes(c)
        )
        ch = pair_init.device_certificate_hash(
            ALICE_ED_PUB, device_cert.signing_bytes(c), c.signature
        )
        return c, ch

    def mint_revoke(
        *,
        device_id: bytes,
        ed_pub: bytes,
        x_pub: bytes,
        cert_hash: bytes,
        issuer_seq: int,
        revocation_id: bytes,
        reason_code: int = 1,
    ):
        r = device_revocation.DeviceRevocationV1(
            identity_address=alice_addr,
            device_id=device_id,
            device_ed_pub=ed_pub,
            device_x_pub=x_pub,
            device_cert_hash=cert_hash,
            issuer_device_id=issuer_id_b,
            issuer_seq=issuer_seq,
            revocation_id=revocation_id,
            reason_code=reason_code,
            created_at_ms=EPOCH_MS,
        )
        r = device_revocation.sign(r, ALICE_ED_PRIV)
        w = device_revocation.encode(r)
        return r, w

    carol_cert, carol_cert_hash = mint_device_cert(CAROL_ED_PUB, CAROL_X_PUB, "carol-device-1")
    rev_id_bob = bytes(range(1, 17))
    rev_id_carol = bytes(range(17, 33))
    _, wire_bob = mint_revoke(
        device_id=b"bob-device-1",
        ed_pub=BOB_ED_PUB,
        x_pub=BOB_X_PUB,
        cert_hash=cert_hash,
        issuer_seq=1,
        revocation_id=rev_id_bob,
    )
    _, wire_carol = mint_revoke(
        device_id=b"carol-device-1",
        ed_pub=CAROL_ED_PUB,
        x_pub=CAROL_X_PUB,
        cert_hash=carol_cert_hash,
        issuer_seq=2,
        revocation_id=rev_id_carol,
    )
    # Same revocation_id, different target (collision / equivocation)
    _, wire_carol_collision = mint_revoke(
        device_id=b"carol-device-1",
        ed_pub=CAROL_ED_PUB,
        x_pub=CAROL_X_PUB,
        cert_hash=carol_cert_hash,
        issuer_seq=3,
        revocation_id=rev_id_bob,  # collide with bob's id
    )

    # union_001: apply bob then carol
    store_u = rev_conf.ConformanceStore(identity_address=alice_addr, max_claims=10_000)
    a1 = rev_conf.apply_verified_claim(store_u, wire_bob, ALICE_ED_PUB)
    a2 = rev_conf.apply_verified_claim(store_u, wire_carol, ALICE_ED_PUB)
    write(
        out,
        "device_revocation/union_001.json",
        vec(
            "Append-only union of two distinct claims",
            "bob then carol; both digests and all lineage keys denied",
            {
                "identity_ed_pub_hex": ALICE_ED_PUB.hex(),
                "identity_address": alice_addr,
                "claims_wire_hex": [wire_bob.hex(), wire_carol.hex()],
                "apply_order": ["bob", "carol"],
            },
            {
                "apply_results": [a1["result"], a2["result"]],
                "store": store_u.snapshot_dict(),
                "revocation_id_collisions": [],
            },
        ),
    )

    # revocation_id collision
    store_c = rev_conf.ConformanceStore(identity_address=alice_addr, max_claims=10_000)
    c1 = rev_conf.apply_verified_claim(store_c, wire_bob, ALICE_ED_PUB)
    c2 = rev_conf.apply_verified_claim(store_c, wire_carol_collision, ALICE_ED_PUB)
    write(
        out,
        "device_revocation/collision_revocation_id_001.json",
        vec(
            "Same revocation_id different bytes — union both",
            "equivocation recorded; neither target left trusted",
            {
                "identity_ed_pub_hex": ALICE_ED_PUB.hex(),
                "identity_address": alice_addr,
                "claims_wire_hex": [wire_bob.hex(), wire_carol_collision.hex()],
                "shared_revocation_id_hex": rev_id_bob.hex(),
            },
            {
                "apply_results": [c1["result"], c2["result"]],
                "store": store_c.snapshot_dict(),
                "must_union_apply_both": True,
            },
        ),
    )

    # quota state machine (test profile max_claims=1)
    store_q = rev_conf.ConformanceStore(identity_address=alice_addr, max_claims=1)
    steps_q = []
    q1 = rev_conf.apply_verified_claim(store_q, wire_bob, ALICE_ED_PUB)
    steps_q.append(
        {
            "id": 1,
            "action": "apply",
            "label": "bob",
            "result": q1["result"],
            "store_hash_hex": store_q.store_hash().hex(),
            "generation": store_q.generation,
            "claims_count": len(store_q.claims),
        }
    )
    q2 = rev_conf.apply_verified_claim(store_q, wire_carol, ALICE_ED_PUB)
    steps_q.append(
        {
            "id": 2,
            "action": "apply",
            "label": "carol_hits_quota",
            "result": q2["result"],
            "journal_kind": store_q.journal["kind"] if store_q.journal else None,
            "store_hash_hex": store_q.store_hash().hex(),
            "generation": store_q.generation,
            "exhausted_count": len(store_q.exhausted),
            "claims_count": len(store_q.claims),
        }
    )
    # crash window: exhausted anchored, claim not inserted
    steps_q.append(
        {
            "id": 3,
            "state": "PENDING_REVOKE_EXHAUSTED+IDENTITY_REVOKE_EXHAUSTED",
            "note": "MUST NOT auto-retry apply; fail-closed auth for identity",
            "store_hash_hex": store_q.store_hash().hex(),
            "journal_kind": store_q.journal["kind"],
            "exhausted_count": len(store_q.exhausted),
            "claims_count": len(store_q.claims),
        }
    )
    # no-auto-retry: helper must reject direct EXHAUSTED consumption
    no_retry_err = None
    try:
        rev_conf.apply_verified_claim(
            store_q, wire_carol, ALICE_ED_PUB, pending_already_written=True
        )
    except ValueError as e:
        no_retry_err = str(e)
    if no_retry_err != "direct_exhausted_consumption":
        raise AssertionError(no_retry_err)
    steps_q.append(
        {
            "id": 3.1,
            "action": "no_auto_retry_apply",
            "expected_error": "direct_exhausted_consumption",
            "store_hash_hex": store_q.store_hash().hex(),
        }
    )
    exh_auth = [
        rev_conf.authorize_device(
            store_q,
            device_id=b"carol-device-1",
            device_ed_pub=CAROL_ED_PUB,
            device_x_pub=CAROL_X_PUB,
            device_cert_hash=carol_cert_hash,
            surface=s,
        )
        for s in rev_conf.SURFACES
    ]
    steps_q.append(
        {
            "id": 3.2,
            "action": "authorize_under_exhausted",
            "gates": exh_auth,
            "all_unauthorized": True,
        }
    )
    rev_conf.expand_quota(store_q, 2)
    steps_q.append({"id": 4, "action": "expand_quota", "max_claims": 2})
    # reverify exhausted journal
    rv = rev_conf.reverify_journal(store_q, ALICE_ED_PUB)
    steps_q.append({"id": 5, "action": "reverify_exact_bytes", "result": rv["result"]})
    rev_conf.convert_exhausted_journal_to_pending(store_q)
    steps_q.append(
        {
            "id": 6,
            "action": "journal_convert",
            "from": "PENDING_REVOKE_EXHAUSTED",
            "to": "PENDING_REVOKE",
            "same_exact_bytes": True,
        }
    )
    q3 = rev_conf.apply_verified_claim(
        store_q, wire_carol, ALICE_ED_PUB, pending_already_written=True
    )
    steps_q.append(
        {
            "id": 7,
            "action": "sql_atomic_apply_pending",
            "result": q3["result"],
            "ops": [
                "insert_claim",
                "append_revoked_targets",
                "delete_IDENTITY_REVOKE_EXHAUSTED",
                "upsert_cleanup",
                "bump_generation",
            ],
            "store_hash_hex": store_q.store_hash().hex(),
            "generation": store_q.generation,
        }
    )
    steps_q.append(
        {
            "id": 8,
            "action": "write_FINALIZED_REVOKE_ANCHOR",
            "generation": store_q.generation,
            "store_hash_hex": store_q.store_hash().hex(),
        }
    )
    steps_q.append({"id": 9, "action": "clear_PENDING_REVOKE"})
    write(
        out,
        "device_revocation/quota_machine_001.json",
        {
            "name": "Quota exhaustion → expand → replay",
            "description": (
                "Test profile max_claims=1. Second claim becomes EXHAUSTED; "
                "expand to 2; convert journal; apply under lease; anchor."
            ),
            "protocol_version": "rvn1",
            "deterministic": True,
            "inputs": {
                "identity_ed_pub_hex": ALICE_ED_PUB.hex(),
                "identity_address": alice_addr,
                "max_claims_initial": 1,
                "max_claims_after_expand": 2,
                "wire_bob_hex": wire_bob.hex(),
                "wire_carol_hex": wire_carol.hex(),
            },
            "steps": steps_q,
            "expected_after": store_q.snapshot_dict(),
        },
    )

    # corrupt-journal fixtures
    def corrupt_fixture(name, rel, desc, mutate_journal):
        st = rev_conf.ConformanceStore(identity_address=alice_addr, max_claims=10_000)
        st.journal = {
            "kind": "PENDING_REVOKE",
            "claim_digest_hex": device_revocation.claim_digest(wire_bob).hex(),
            "exact_record_bytes_hex": wire_bob.hex(),
        }
        mutate_journal(st)
        journal_before = dict(st.journal)
        out_rv = rev_conf.reverify_journal(st, ALICE_ED_PUB)
        write(
            out,
            rel,
            vec(
                name,
                desc,
                {
                    "identity_ed_pub_hex": ALICE_ED_PUB.hex(),
                    "identity_address": alice_addr,
                    "journal_before": journal_before,
                },
                {
                    "reverify_result": out_rv["result"],
                    "reason": out_rv.get("reason"),
                    "reason_code": out_rv.get("reason_code"),
                    "store": out_rv["store"],
                    "must_fail_closed": True,
                    "must_not_clear_without_corrupt_marker": True,
                },
            ),
        )
    def trunc(st):
        st.journal["exact_record_bytes_hex"] = wire_bob[:40].hex()

    def dig_mis(st):
        st.journal["claim_digest_hex"] = ("00" * 32)

    def bad_sig(st):
        # Flip last signature byte
        w = bytearray(wire_bob)
        w[-1] ^= 0xFF
        st.journal["exact_record_bytes_hex"] = bytes(w).hex()
        st.journal["claim_digest_hex"] = device_revocation.claim_digest(bytes(w)).hex()

    corrupt_fixture(
        "Corrupt journal truncated",
        "device_revocation/corrupt_journal_truncated_001.json",
        "Short journal bytes → REVOCATION_STORE_CORRUPT then clear journal",
        trunc,
    )
    corrupt_fixture(
        "Corrupt journal digest mismatch",
        "device_revocation/corrupt_journal_digest_mismatch_001.json",
        "Journal claim_digest ≠ SHA-256(exact_bytes)",
        dig_mis,
    )
    corrupt_fixture(
        "Corrupt journal bad signature",
        "device_revocation/corrupt_journal_bad_signature_001.json",
        "Parseable wire with invalid identity signature",
        bad_sig,
    )

    # recovery: after corrupt marker, all gates fail closed
    store_bad = rev_conf.ConformanceStore(identity_address=alice_addr, max_claims=10_000)
    store_bad.corrupt.append(
        device_revocation.CorruptMarker(
            scope=alice_addr, reason_code=rev_conf.CORRUPT_BAD_SIGNATURE
        )
    )
    store_bad.generation = 1
    gates_corrupt = [
        rev_conf.authorize_device(
            store_bad,
            device_id=b"bob-device-1",
            device_ed_pub=BOB_ED_PUB,
            device_x_pub=BOB_X_PUB,
            device_cert_hash=cert_hash,
            surface=s,
        )
        for s in rev_conf.SURFACES
    ]
    # corrupt_journal_recovery_001.json is written once, below (with
    # identity_ed_pub_hex); an earlier duplicate write here was dead code.

    # apply gates: bob revoked, carol not
    store_g = rev_conf.ConformanceStore(identity_address=alice_addr, max_claims=10_000)
    rev_conf.apply_verified_claim(store_g, wire_bob, ALICE_ED_PUB)
    bob_gates = [
        rev_conf.authorize_device(
            store_g,
            device_id=b"bob-device-1",
            device_ed_pub=BOB_ED_PUB,
            device_x_pub=BOB_X_PUB,
            device_cert_hash=cert_hash,
            surface=s,
        )
        for s in rev_conf.SURFACES
    ]
    carol_gates = [
        rev_conf.authorize_device(
            store_g,
            device_id=b"carol-device-1",
            device_ed_pub=CAROL_ED_PUB,
            device_x_pub=CAROL_X_PUB,
            device_cert_hash=carol_cert_hash,
            surface=s,
        )
        for s in rev_conf.SURFACES
    ]
    # exhausted identity: even unrevoked device denied
    store_ex = rev_conf.ConformanceStore(identity_address=alice_addr, max_claims=1)
    rev_conf.apply_verified_claim(store_ex, wire_bob, ALICE_ED_PUB)
    rev_conf.apply_verified_claim(store_ex, wire_carol, ALICE_ED_PUB)
    exh_gates = [
        rev_conf.authorize_device(
            store_ex,
            device_id=b"carol-device-1",
            device_ed_pub=CAROL_ED_PUB,
            device_x_pub=CAROL_X_PUB,
            device_cert_hash=carol_cert_hash,
            surface=s,
        )
        for s in rev_conf.SURFACES
    ]
    write(
        out,
        "device_revocation/apply_gates_001.json",
        vec(
            "Apply gates for PairInit/Session/Message/ACK/Noise bind",
            "Revoked bob denied on all surfaces; carol allowed; exhausted denies carol",
            {
                "identity_ed_pub_hex": ALICE_ED_PUB.hex(),
                "identity_address": alice_addr,
                "revoked_wire_hex": wire_bob.hex(),
                "carol_wire_hex": wire_carol.hex(),
                "bob_peer": {
                    "device_id_utf8": "bob-device-1",
                    "device_ed_pub_hex": BOB_ED_PUB.hex(),
                    "device_x_pub_hex": BOB_X_PUB.hex(),
                    "device_cert_hash_hex": cert_hash.hex(),
                },
                "carol_peer": {
                    "device_id_utf8": "carol-device-1",
                    "device_ed_pub_hex": CAROL_ED_PUB.hex(),
                    "device_x_pub_hex": CAROL_X_PUB.hex(),
                    "device_cert_hash_hex": carol_cert_hash.hex(),
                },
                "surfaces": list(rev_conf.SURFACES),
            },
            {
                "bob_revoked_gates": bob_gates,
                "carol_unrevoked_gates": carol_gates,
                "carol_under_exhausted_gates": exh_gates,
                "bob_all_denied": True,
                "carol_all_allowed": True,
                "exhausted_all_denied": True,
            },
        ),
    )

    write(
        out,
        "device_revocation/corrupt_journal_recovery_001.json",
        vec(
            "Corrupt marker fail-closed authorization",
            "Until explicit repair, every surface denies",
            {
                "identity_address": alice_addr,
                "identity_ed_pub_hex": ALICE_ED_PUB.hex(),
                "corrupt": [{"scope": alice_addr, "reason_code": 3}],
                "peer": {
                    "device_id_utf8": "bob-device-1",
                    "device_ed_pub_hex": BOB_ED_PUB.hex(),
                    "device_x_pub_hex": BOB_X_PUB.hex(),
                    "device_cert_hash_hex": cert_hash.hex(),
                },
                "surfaces": list(rev_conf.SURFACES),
            },
            {
                "gates": gates_corrupt,
                "all_unauthorized": True,
            },
        ),
    )

    def _pending_neg(case_id, desc, journal, wire_apply, expect_error):
        st = rev_conf.ConformanceStore(identity_address=alice_addr, max_claims=10_000)
        st.journal = journal
        err = None
        try:
            rev_conf.apply_verified_claim(
                st, wire_apply, ALICE_ED_PUB, pending_already_written=True
            )
        except ValueError as e:
            err = str(e)
        if err != expect_error:
            raise AssertionError(f"{case_id}: got {err!r} want {expect_error!r}")
        return {
            "id": case_id,
            "description": desc,
            "journal_before": None if journal is None else dict(journal),
            "apply_wire_hex": wire_apply.hex(),
            "expected_error": expect_error,
        }

    pending_cases = [
        _pending_neg(
            "missing_pending",
            "pending_already_written with no journal",
            None,
            wire_bob,
            "missing_pending",
        ),
        _pending_neg(
            "wrong_bytes",
            "PENDING_REVOKE holds bob; apply carol bytes",
            {
                "kind": "PENDING_REVOKE",
                "claim_digest_hex": device_revocation.claim_digest(wire_bob).hex(),
                "exact_record_bytes_hex": wire_bob.hex(),
            },
            wire_carol,
            "pending_bytes_mismatch",
        ),
        _pending_neg(
            "wrong_digest",
            "PENDING_REVOKE bytes match but claim_digest wrong",
            {
                "kind": "PENDING_REVOKE",
                "claim_digest_hex": "00" * 32,
                "exact_record_bytes_hex": wire_bob.hex(),
            },
            wire_bob,
            "pending_digest_mismatch",
        ),
        _pending_neg(
            "direct_exhausted",
            "Helper must not consume PENDING_REVOKE_EXHAUSTED directly",
            {
                "kind": "PENDING_REVOKE_EXHAUSTED",
                "claim_digest_hex": device_revocation.claim_digest(wire_carol).hex(),
                "exact_record_bytes_hex": wire_carol.hex(),
            },
            wire_carol,
            "direct_exhausted_consumption",
        ),
    ]
    write(
        out,
        "device_revocation/pending_binding_negatives_001.json",
        {
            "name": "pending_already_written binding negatives",
            "description": (
                "Helper with pending_already_written=true requires PENDING_REVOKE "
                "and exact bytes + claim_digest match; rejects EXHAUSTED direct use"
            ),
            "protocol_version": "rvn1",
            "deterministic": True,
            "inputs": {
                "identity_ed_pub_hex": ALICE_ED_PUB.hex(),
                "identity_address": alice_addr,
            },
            "cases": pending_cases,
        },
    )


if __name__ == "__main__":
    main()