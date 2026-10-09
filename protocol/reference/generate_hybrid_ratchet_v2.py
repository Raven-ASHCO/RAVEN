#!/usr/bin/env python3
"""Generate ATSAM/hybrid-ratchet/v2 vector freeze fixtures (production-disabled)."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from raven_protocol import address, hybrid_ratchet_v2 as tr, pair_init, pair_init_v2 as piv2
from raven_protocol import hybrid_ratchet_v2_state as trs
from raven_protocol import hybrid_ratchet_v2_tr as trtr

REPO = pathlib.Path(__file__).resolve().parents[2]
OUT = REPO / "shared-vectors/rvn1"
EPOCH_MS = 1700000000_000

ALICE_ED_PRIV = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
ALICE_ED_PUB = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
BOB_ED_PRIV = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)
BOB_ED_PUB = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)


def write(rel: str, obj: dict) -> None:
    p = OUT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def vec(name, desc, inputs, expected, **extra):
    return {
        "name": name,
        "description": desc,
        "protocol_version": "rvn1",
        "profile": "ATSAM/hybrid-ratchet/v2",
        "deterministic": True,
        "production_enabled": False,
        "inputs": inputs,
        "expected": expected,
        **extra,
    }


def write_pair_init_v2_002(
    *,
    alice_addr: str,
    bob_addr: str,
    alice_dev: Ed25519PrivateKey,
    bob_dev: Ed25519PrivateKey,
    alice_dev_priv: bytes,
    bob_dev_priv: bytes,
    mlkem_ek: bytes,
    mlkem_ct: bytes,
    z_pq: bytes,
) -> None:
    """Trust-binding PairInit V2 KAT: every derived value follows from the wire.

    - `responder_prekey_bundle_hash` digests a real RavenPrekeyBundleV1 signed by
      Bob's identity key (not an ad-hoc SPK||OTP||EK string signed by a device).
    - `Z_X = X25519(alice_eph, bob_otp)` over exactly the wire keys (§0.3).
    - Device certs carry dedicated device X25519 keys (never the ephemeral).
    - The ML-KEM ek/ct/Z_PQ triple is the hybrid KAT's consistent triple.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    from raven_protocol import device_cert, prekey

    def x25519_priv(label: bytes) -> X25519PrivateKey:
        return X25519PrivateKey.from_private_bytes(hashlib.sha256(label).digest())

    def raw_priv(key: X25519PrivateKey) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    alice_eph = x25519_priv(b"atsam-v2/002/alice-eph-x")
    alice_dev_x = x25519_priv(b"atsam-v2/002/alice-device-x")
    bob_dev_x = x25519_priv(b"atsam-v2/002/bob-device-x")
    bob_spk = x25519_priv(b"atsam-v2/002/bob-spk-x")
    bob_otp = x25519_priv(b"atsam-v2/002/bob-otp-x")
    alice_eph_pub = alice_eph.public_key().public_bytes_raw()
    bob_spk_pub = bob_spk.public_key().public_bytes_raw()
    bob_otp_pub = bob_otp.public_key().public_bytes_raw()
    alice_dev_pub = alice_dev.public_key().public_bytes_raw()
    bob_dev_pub = bob_dev.public_key().public_bytes_raw()

    def signed_cert(identity_priv: bytes, identity_pub: bytes, dev_pub: bytes, dev_x, device_id):
        cert = device_cert.DeviceCert(
            device_ed_pub=dev_pub,
            device_x_pub=dev_x.public_key().public_bytes_raw(),
            device_id=device_id,
            not_before=EPOCH_MS,
            not_after=EPOCH_MS + 365 * 86400_000,
            capabilities=0,
        )
        cert.signature = Ed25519PrivateKey.from_private_bytes(identity_priv).sign(
            device_cert.signing_bytes(cert)
        )
        digest = pair_init.device_certificate_hash(
            identity_pub, device_cert.signing_bytes(cert), cert.signature
        )
        return cert, digest

    alice_cert, alice_cert_hash = signed_cert(
        ALICE_ED_PRIV, ALICE_ED_PUB, alice_dev_pub, alice_dev_x, "alice-device-v2"
    )
    bob_cert, bob_cert_hash = signed_cert(
        BOB_ED_PRIV, BOB_ED_PUB, bob_dev_pub, bob_dev_x, "bob-device-v2"
    )
    assert alice_cert.device_x_pub != alice_eph_pub

    bundle = prekey.PrekeyBundle(
        identity_ed25519_pub=BOB_ED_PUB,
        device_id="bob-device-v2",
        x25519_pub=bob_spk_pub,
        mlkem768_ek=mlkem_ek,
        signed_prekey_id=42,
        one_time_prekey_id=7,
        one_time_x25519_pub=bob_otp_pub,
        created_at_ms=EPOCH_MS - 86400_000,
        expires_at_ms=EPOCH_MS + 30 * 86400_000,
    )
    bundle_sb = prekey.signing_bytes(bundle)
    bundle.signature = Ed25519PrivateKey.from_private_bytes(BOB_ED_PRIV).sign(bundle_sb)
    assert prekey.verify(bundle)
    prekey_hash = pair_init.prekey_bundle_hash(bundle_sb, bundle.signature)

    # §0.3: Z_X over the wire's ephemeral × OTP (OTP present); both sides agree.
    z_x = alice_eph.exchange(X25519PublicKey.from_public_bytes(bob_otp_pub))
    assert z_x == bob_otp.exchange(X25519PublicKey.from_public_bytes(alice_eph_pub))

    init_id = bytes(range(0x30, 0x40))
    pairing_nonce = bytes(range(0x40, 0x60))
    pair = piv2.PairInitV2(
        initiator_address=alice_addr,
        responder_address=bob_addr,
        init_id=init_id,
        pairing_nonce=pairing_nonce,
        initiator_device_ed_pub=alice_dev_pub,
        responder_device_ed_pub=bob_dev_pub,
        initiator_ephemeral_x25519_pub=alice_eph_pub,
        responder_signed_x25519_pub=bob_spk_pub,
        responder_one_time_x25519_pub=bob_otp_pub,
        initiator_device_cert_hash=alice_cert_hash,
        responder_device_cert_hash=bob_cert_hash,
        responder_prekey_bundle_hash=prekey_hash,
        signed_prekey_id=bundle.signed_prekey_id,
        one_time_prekey_id=bundle.one_time_prekey_id,
        responder_mlkem768_ek=mlkem_ek,
        mlkem768_ciphertext=mlkem_ct,
        created_at_ms=EPOCH_MS,
        expires_at_ms=EPOCH_MS + 7 * 86400_000,
    )
    pair.signature = alice_dev.sign(piv2.init_signing_bytes(pair))
    wire = piv2.encode_init(pair)
    assert piv2.verify_init_signature(pair)
    expand = piv2.pair_expand(z_x, z_pq, wire)
    tag = piv2.confirmation_tag(expand.k_confirm, expand.init_hash_v2)
    resp = piv2.PairResponseV2(
        init_id=init_id,
        init_hash=expand.init_hash_v2,
        responder_device_ed_pub=bob_dev_pub,
        created_at_ms=EPOCH_MS + 1000,
        expires_at_ms=EPOCH_MS + 7 * 86400_000,
        confirmation_tag=tag,
    )
    resp.signature = bob_dev.sign(piv2.response_signing_bytes(resp))
    resp_wire = piv2.encode_response(resp)

    write(
        "atsam/pair_init_v2_002.json",
        vec(
            "PairInit V2 trust-binding KAT (transcript-derivable)",
            "Z_X = X25519(eph, OTP) over wire keys; real identity-signed "
            "RavenPrekeyBundleV1 digest; dedicated device X keys; supersedes "
            "pair_init_v2_001 for trust binding (001 stays codec + expand only)",
            {
                "z_pq_hex": z_pq.hex(),
                "mlkem_source_vector": "atsam/mlkem768_hybrid_kat_001.json",
                "initiator_identity_ed_pub_hex": ALICE_ED_PUB.hex(),
                "responder_identity_ed_pub_hex": BOB_ED_PUB.hex(),
                "initiator_device_ed_priv_hex": alice_dev_priv.hex(),
                "responder_device_ed_priv_hex": bob_dev_priv.hex(),
                "initiator_ephemeral_x25519_priv_hex": raw_priv(alice_eph).hex(),
                "responder_spk_x25519_priv_hex": raw_priv(bob_spk).hex(),
                "responder_otp_x25519_priv_hex": raw_priv(bob_otp).hex(),
                "initiator_device_cert": {
                    "signing_bytes_hex": device_cert.signing_bytes(alice_cert).hex(),
                    "signature_hex": alice_cert.signature.hex(),
                },
                "responder_device_cert": {
                    "signing_bytes_hex": device_cert.signing_bytes(bob_cert).hex(),
                    "signature_hex": bob_cert.signature.hex(),
                },
                "responder_prekey_bundle": {
                    "signing_bytes_hex": bundle_sb.hex(),
                    "signature_hex": bundle.signature.hex(),
                    "signed_prekey_id": bundle.signed_prekey_id,
                    "one_time_prekey_id": bundle.one_time_prekey_id,
                },
            },
            {
                "z_x_hex": z_x.hex(),
                "initiator_device_cert_hash_hex": alice_cert_hash.hex(),
                "responder_device_cert_hash_hex": bob_cert_hash.hex(),
                "responder_prekey_bundle_hash_hex": prekey_hash.hex(),
                "pair_init_wire_hex": wire.hex(),
                "pair_init_wire_len": len(wire),
                "offsets": piv2.wire_offsets(),
                "transcript_hash_hex": expand.transcript_hash.hex(),
                "init_hash_v2_hex": expand.init_hash_v2.hex(),
                "session_id_hex": expand.session_id.hex(),
                "sk_ec_hex": expand.sk_ec.hex(),
                "sk_scka_hex": expand.sk_scka.hex(),
                "k_route_master_hex": expand.k_route_master.hex(),
                "k_confirm_hex": expand.k_confirm.hex(),
                "confirmation_tag_hex": tag.hex(),
                "pair_response_wire_hex": resp_wire.hex(),
                "pair_response_wire_len": len(resp_wire),
            },
            supersedes={"pair_init_v2_001": "trust binding (001 = codec + expand only)"},
        ),
    )


def main() -> None:
    hybrid = json.loads((OUT / "atsam/mlkem768_hybrid_kat_001.json").read_text())
    z_x = bytes.fromhex(hybrid["expected"]["z_x_hex"])
    z_pq = bytes.fromhex(hybrid["expected"]["z_pq_hex"])
    mlkem_ek = bytes.fromhex(hybrid["expected"]["mlkem_ek_hex"])
    mlkem_ct = bytes.fromhex(hybrid["expected"]["mlkem_ct_hex"])

    alice_addr = address.encode(ALICE_ED_PUB)
    bob_addr = address.encode(BOB_ED_PUB)

    # Deterministic device keys for V2 PairInit (distinct from identity keys)
    alice_dev_priv = hashlib.sha256(b"atsam-v2/alice-device-ed").digest()
    bob_dev_priv = hashlib.sha256(b"atsam-v2/bob-device-ed").digest()
    alice_dev = Ed25519PrivateKey.from_private_bytes(alice_dev_priv)
    bob_dev = Ed25519PrivateKey.from_private_bytes(bob_dev_priv)
    alice_dev_pub = alice_dev.public_key().public_bytes_raw()
    bob_dev_pub = bob_dev.public_key().public_bytes_raw()

    alice_eph = X25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"atsam-v2/alice-eph-x").digest()
    )
    bob_spk = X25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"atsam-v2/bob-spk-x").digest()
    )
    bob_otp = X25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"atsam-v2/bob-otp-x").digest()
    )
    alice_eph_pub = alice_eph.public_key().public_bytes_raw()
    bob_spk_pub = bob_spk.public_key().public_bytes_raw()
    bob_otp_pub = bob_otp.public_key().public_bytes_raw()

    # Cert digests: identity-signed device certs hashed like the V1 generator.
    # NOTE (_001 only): Alice's cert reuses her ephemeral as device_x_pub, the
    # prekey hash below is not a RavenPrekeyBundleV1 digest, and Z_X comes from
    # the hybrid KAT rather than the wire keys. `_001` is therefore a codec +
    # expand KAT only; `pair_init_v2_002` (below) is the trust-binding KAT.
    from raven_protocol import device_cert

    alice_cert = device_cert.DeviceCert(
        device_ed_pub=alice_dev_pub,
        device_x_pub=alice_eph_pub,
        device_id="alice-device-v2",
        not_before=EPOCH_MS,
        not_after=EPOCH_MS + 365 * 86400_000,
        capabilities=0,
    )
    alice_cert.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(
        device_cert.signing_bytes(alice_cert)
    )
    bob_cert = device_cert.DeviceCert(
        device_ed_pub=bob_dev_pub,
        device_x_pub=bob_spk_pub,
        device_id="bob-device-v2",
        not_before=EPOCH_MS,
        not_after=EPOCH_MS + 365 * 86400_000,
        capabilities=0,
    )
    bob_cert.signature = Ed25519PrivateKey.from_private_bytes(BOB_ED_PRIV).sign(
        device_cert.signing_bytes(bob_cert)
    )
    alice_cert_hash = pair_init.device_certificate_hash(
        ALICE_ED_PUB, device_cert.signing_bytes(alice_cert), alice_cert.signature
    )
    bob_cert_hash = pair_init.device_certificate_hash(
        BOB_ED_PUB, device_cert.signing_bytes(bob_cert), bob_cert.signature
    )

    # Minimal prekey bundle hash: hash of SPK||OTP||EK under V1 domain with fake sig
    prekey_sb = bob_spk_pub + bob_otp_pub + mlkem_ek
    prekey_sig = bob_dev.sign(prekey_sb)
    prekey_hash = pair_init.prekey_bundle_hash(prekey_sb, prekey_sig)

    init_id = bytes(range(0x10, 0x20))
    pairing_nonce = bytes(range(0x20, 0x40))

    # Recompute Z_X from ephemeral × OTP for consistency with wire pubs
    # (vector pins hybrid KAT z_x for expand IKM; wire still carries OTP pub)
    # Spec: Z_X MAY use OTP when present — freeze IKM from KAT for cross-lang parity.
    pair = piv2.PairInitV2(
        initiator_address=alice_addr,
        responder_address=bob_addr,
        init_id=init_id,
        pairing_nonce=pairing_nonce,
        initiator_device_ed_pub=alice_dev_pub,
        responder_device_ed_pub=bob_dev_pub,
        initiator_ephemeral_x25519_pub=alice_eph_pub,
        responder_signed_x25519_pub=bob_spk_pub,
        responder_one_time_x25519_pub=bob_otp_pub,
        initiator_device_cert_hash=alice_cert_hash,
        responder_device_cert_hash=bob_cert_hash,
        responder_prekey_bundle_hash=prekey_hash,
        signed_prekey_id=42,
        one_time_prekey_id=7,
        responder_mlkem768_ek=mlkem_ek,
        mlkem768_ciphertext=mlkem_ct,
        created_at_ms=EPOCH_MS,
        expires_at_ms=EPOCH_MS + 7 * 86400_000,
    )
    pair.signature = alice_dev.sign(piv2.init_signing_bytes(pair))
    wire = piv2.encode_init(pair)
    assert piv2.verify_init_signature(pair)
    expand = piv2.pair_expand(z_x, z_pq, wire)
    tag = piv2.confirmation_tag(expand.k_confirm, expand.init_hash_v2)

    resp = piv2.PairResponseV2(
        init_id=init_id,
        init_hash=expand.init_hash_v2,
        responder_device_ed_pub=bob_dev_pub,
        created_at_ms=EPOCH_MS + 1000,
        expires_at_ms=EPOCH_MS + 7 * 86400_000,
        confirmation_tag=tag,
    )
    resp.signature = bob_dev.sign(piv2.response_signing_bytes(resp))
    resp_wire = piv2.encode_response(resp)

    write(
        "atsam/pair_init_v2_001.json",
        vec(
            "PairInit V2 / PairResponse V2 wire + pair-expand",
            "RVPI2/RVPR2; SK_ec/SK_scka/K_route_master/K_confirm; no V1 reinterpret",
            {
                "z_x_hex": z_x.hex(),
                "z_pq_hex": z_pq.hex(),
                "mlkem_source_vector": "atsam/mlkem768_hybrid_kat_001.json",
                "initiator_identity_ed_pub_hex": ALICE_ED_PUB.hex(),
                "responder_identity_ed_pub_hex": BOB_ED_PUB.hex(),
                "initiator_device_ed_priv_hex": alice_dev_priv.hex(),
                "responder_device_ed_priv_hex": bob_dev_priv.hex(),
                "bob_spk_x25519_pub_hex": bob_spk_pub.hex(),
                "bob_otp_x25519_pub_hex": bob_otp_pub.hex(),
            },
            {
                "pair_init_wire_hex": wire.hex(),
                "pair_init_wire_len": len(wire),
                "pair_init_signing_bytes_hex": piv2.init_signing_bytes(pair).hex(),
                "offsets": piv2.wire_offsets(),
                "transcript_hash_hex": expand.transcript_hash.hex(),
                "init_hash_v2_hex": expand.init_hash_v2.hex(),
                "session_id_hex": expand.session_id.hex(),
                "sk_ec_hex": expand.sk_ec.hex(),
                "sk_scka_hex": expand.sk_scka.hex(),
                "k_route_master_hex": expand.k_route_master.hex(),
                "k_confirm_hex": expand.k_confirm.hex(),
                "confirmation_tag_hex": tag.hex(),
                "pair_response_wire_hex": resp_wire.hex(),
                "pair_response_wire_len": len(resp_wire),
                "pair_response_signing_bytes_hex": piv2.response_signing_bytes(resp).hex(),
            },
        ),
    )

    write_pair_init_v2_002(
        alice_addr=alice_addr,
        bob_addr=bob_addr,
        alice_dev=alice_dev,
        bob_dev=bob_dev,
        alice_dev_priv=alice_dev_priv,
        bob_dev_priv=bob_dev_priv,
        mlkem_ek=mlkem_ek,
        mlkem_ct=mlkem_ct,
        z_pq=z_pq,
    )

    # Negative: V1 wire rejected by V2 decoder
    v1 = json.loads((OUT / "atsam/pair_init_v1_001.json").read_text())
    v1_wire = bytes.fromhex(v1["expected"]["pair_init_wire_hex"])
    write(
        "atsam/negative/pair_init_v1_as_v2_001.json",
        vec(
            "PairInit V1 must not decode as V2",
            "RVPI1 wire → hard reject",
            {"wire_hex": v1_wire.hex()},
            {"decode_result": "reject", "reason": "PairInit V1 must not be reinterpreted as V2"},
        ),
    )

    write(
        "atsam/tr_domain_labels_001.json",
        vec(
            "Frozen hybrid-ratchet/v2 domain and info labels",
            "Catalog for §6 / header / AckV2",
            {},
            tr.domain_catalog(),
        ),
    )

    # EC KDFs
    rk0 = expand.sk_ec
    dh_out = hashlib.sha256(b"atsam-v2/ec-dh-sample").digest()
    rk1, ck = tr.kdf_rk(rk0, dh_out)
    ck2, mk = tr.kdf_ck(ck)
    write(
        "atsam/tr_ec_kdf_001.json",
        vec(
            "EC KDF_RK / KDF_CK",
            "info=EC_RK_INFO; HMAC 0x01/0x02",
            {"rk_hex": rk0.hex(), "dh_out_hex": dh_out.hex()},
            {
                "rk_next_hex": rk1.hex(),
                "ck_hex": ck.hex(),
                "ck_next_hex": ck2.hex(),
                "mk_hex": mk.hex(),
            },
        ),
    )

    alice_scka = tr.ratchet_init_alice_scka(expand.sk_scka)
    bob_scka = tr.ratchet_init_bob_scka(expand.sk_scka)
    write(
        "atsam/tr_scka_init_001.json",
        vec(
            "Role-specific RatchetInitAliceSCKA / RatchetInitBobSCKA",
            "A2B vs B2A CK assignment; shared SK_scka",
            {"sk_scka_hex": expand.sk_scka.hex()},
            {
                "alice": {
                    "rk_hex": alice_scka.rk.hex(),
                    "ck_send_hex": alice_scka.ck_send.hex(),
                    "ck_recv_hex": alice_scka.ck_recv.hex(),
                },
                "bob": {
                    "rk_hex": bob_scka.rk.hex(),
                    "ck_send_hex": bob_scka.ck_send.hex(),
                    "ck_recv_hex": bob_scka.ck_recv.hex(),
                },
                "send_chains_differ": alice_scka.ck_send != bob_scka.ck_send,
                "alice_send_equals_bob_recv": alice_scka.ck_send == bob_scka.ck_recv,
            },
        ),
    )

    # Hybrid AEAD
    aead_key, nonce = tr.kdf_hybrid(mk, alice_scka.ck_send)
    ec_hdr = tr.EcHeader(dh_pub=alice_eph_pub, pn=0, n=0)
    spqr_hdr = tr.SpqrHeader(
        sending_epoch=0,
        receiving_epoch=0,
        send_ctr=0,
        chunk_flags=0,
        kem_ct_digest=bytes(32),
    )
    header = tr.encode_composite_header(ec_hdr, spqr_hdr)
    aad = tr.aead_aad(
        session_id=expand.session_id,
        initiator_address=alice_addr,
        responder_address=bob_addr,
        direction=0,
        sender_device_cert_hash=alice_cert_hash,
        ec=ec_hdr,
        spqr=spqr_hdr,
        header_bytes=header,
    )
    pt = b"\x01" + b"hello-tr-v2"  # inner type message + body
    ct = tr.aead_seal(aead_key, nonce, pt, aad)
    write(
        "atsam/tr_hybrid_aead_001.json",
        vec(
            "KDF_HYBRID + ChaCha20-Poly1305 first message",
            "L=44 key||nonce; AAD binds header/session",
            {
                "ec_mk_hex": mk.hex(),
                "scka_mk_hex": alice_scka.ck_send.hex(),
                "plaintext_hex": pt.hex(),
                "header_hex": header.hex(),
                "aad_hex": aad.hex(),
            },
            {
                "aead_key_hex": aead_key.hex(),
                "nonce_hex": nonce.hex(),
                "ciphertext_hex": ct.hex(),
                "open_ok": True,
            },
        ),
    )

    # AckV2
    msg_obj = header + ct
    obj_digest = hashlib.sha256(msg_obj).digest()
    ack = tr.AckV2(
        acked_message_id=bytes(range(1, 17)),
        acked_object_digest=obj_digest,
        status=1,
        ack_nonce=bytes(range(0xA0, 0xAC)),
        created_at_ms=EPOCH_MS + 2000,
        recipient_device_cert_hash=alice_cert_hash,
        session_id=expand.session_id,
    )
    ack = tr.sign_ack(ack, bob_dev_priv)
    ack_pt = tr.encode_ack_plaintext(ack)
    write(
        "atsam/tr_ackv2_001.json",
        vec(
            "AckV2 plaintext with acked_object_digest",
            "Inner Ed25519 under ATSAM/v2/ack",
            {
                "signer_device_ed_pub_hex": bob_dev_pub.hex(),
                "acked_endpoint_object_hex": msg_obj.hex(),
            },
            {
                "acked_object_digest_hex": obj_digest.hex(),
                "ack_plaintext_hex": ack_pt.hex(),
                "ack_plaintext_len": len(ack_pt),
                "signing_bytes_hex": tr.ack_signing_bytes(ack).hex(),
                "verify": True,
                "status": 1,
            },
        ),
    )

    # Crash / pending binding documentary vectors (ordering)
    write(
        "atsam/tr_crash_ack_cas_001.json",
        {
            "name": "PENDING_ACK_SEND before CAS Materialized",
            "description": "Exact ACK materialize order; no Materialized without retained bytes",
            "protocol_version": "rvn1",
            "profile": "ATSAM/hybrid-ratchet/v2",
            "deterministic": True,
            "production_enabled": False,
            "steps": [
                {"id": 1, "action": "clone_candidate_send_state"},
                {"id": 2, "action": "seal_AckV2", "retain": "exact_bytes"},
                {"id": 3, "action": "write_PENDING_ACK_SEND", "binds": "acked_object_digest"},
                {
                    "id": 4,
                    "action": "CAS_Materialized",
                    "requires": "PENDING_ACK_SEND",
                    "forbidden_without_pending": True,
                },
                {"id": 5, "action": "network_send_OUTSIDE_lease", "exact_retry": True},
                {"id": 6, "action": "clear_PENDING_ACK_SEND_on_success"},
            ],
            "negatives": [
                "CAS_Materialized_without_PENDING_ACK_SEND",
                "rebuild_ack_bytes_on_retry",
                "ack_of_ack",
            ],
        },
    )

    write(
        "atsam/tr_candidate_fail_001.json",
        {
            "name": "Candidate AEAD failure discards state",
            "description": "Bad header/mk → zero durable mutation; zero live-head promotion",
            "protocol_version": "rvn1",
            "profile": "ATSAM/hybrid-ratchet/v2",
            "deterministic": True,
            "production_enabled": False,
            "inputs": {
                "header_hex": header.hex(),
                "ciphertext_hex": (ct[:-1] + bytes([ct[-1] ^ 0xFF])).hex(),
                "aad_hex": aad.hex(),
                "aead_key_hex": aead_key.hex(),
                "nonce_hex": nonce.hex(),
            },
            "expected": {
                "open_result": "fail",
                "durable_mutation": False,
                "promote_live_head": False,
            },
        },
    )

    # --- Stateful matrix ---
    ss1 = hashlib.sha256(b"atsam-v2/braid-ss-epoch1").digest()
    ss2 = hashlib.sha256(b"atsam-v2/braid-ss-epoch2").digest()
    braid = trs.run_braid_epoch_matrix(expand.sk_scka, ss1, ss2)
    write(
        "atsam/tr_braid_epoch_001.json",
        vec(
            "SCKA/Braid epoch promote + bidirectional CK reorder",
            "Alice initiates e0→e1; Bob initiates e1→e2; matching mk both ways",
            {
                "sk_scka_hex": expand.sk_scka.hex(),
                "ss_epoch1_hex": ss1.hex(),
                "ss_epoch2_hex": ss2.hex(),
            },
            braid,
        ),
    )

    dh_pub = alice_eph_pub
    _, ck_chain = tr.kdf_rk(expand.sk_ec, dh_out)
    ooo = trs.run_ec_ooo_matrix(ck_chain, dh_pub)
    write(
        "atsam/tr_ec_ooo_001.json",
        vec(
            "EC out-of-order + skipped-key recovery",
            "Receive order 0,3,1,2 recovers sender mks without loss",
            {"ck_hex": ck_chain.hex(), "dh_pub_hex": dh_pub.hex()},
            ooo,
        ),
    )

    skip = trs.run_skip_boundary(ck_chain, dh_pub)
    write(
        "atsam/tr_skip_boundary_001.json",
        vec(
            "MAX_SKIP boundary 0/1/999/1000/1001",
            "1001 rejects with zero allocation and zero state advance",
            {"ck_hex": ck_chain.hex(), "dh_pub_hex": dh_pub.hex()},
            skip,
        ),
    )

    ledger = trs.CommitLedger()
    accept_key = trs.AcceptKey(
        session_id=expand.session_id,
        dh_pub=dh_pub,
        n=0,
        scka_epoch=0,
        scka_ctr=0,
    )
    retained_ack = ack_pt
    obj_d = obj_digest
    ledger, r1 = trs.commit_accept(ledger, accept_key, obj_d, retained_ack)
    fp_after_accept = ledger.fingerprint()
    ledger2, r2 = trs.commit_accept(ledger, accept_key, obj_d, retained_ack)
    fp_after_replay = ledger2.fingerprint()
    dup_ack = trs.duplicate_ack_exact(ledger2, obj_d)
    write(
        "atsam/tr_replay_duplicate_001.json",
        vec(
            "One-shot accept; replay no mutation; duplicate → exact ACK",
            "Accept key consumed once; exact-byte duplicate returns retained AckV2",
            {
                "session_id_hex": expand.session_id.hex(),
                "dh_pub_hex": dh_pub.hex(),
                "object_digest_hex": obj_d.hex(),
                "retained_ack_hex": retained_ack.hex(),
                "accept_key": {"n": 0, "scka_epoch": 0, "scka_ctr": 0},
            },
            {
                "first_result": r1,
                "replay_result": r2,
                "fp_after_accept_hex": fp_after_accept.hex(),
                "fp_after_replay_hex": fp_after_replay.hex(),
                "replay_fp_unchanged": fp_after_accept == fp_after_replay,
                "duplicate_ack_hex": dup_ack.hex() if dup_ack else None,
                "duplicate_ack_matches_retained": dup_ack == retained_ack,
                "mutation_count": ledger2.mutation_count,
            },
        ),
    )

    live_fp = hashlib.sha256(b"live-head-v2").digest()
    tamper_cases = {
        "good": trs.candidate_decrypt(
            key=aead_key, nonce=nonce, ciphertext=ct, aad=aad, live_fp=live_fp
        ),
        "bad_ciphertext": trs.candidate_decrypt(
            key=aead_key,
            nonce=nonce,
            ciphertext=ct[:-1] + bytes([ct[-1] ^ 0x01]),
            aad=aad,
            live_fp=live_fp,
        ),
        "bad_nonce": trs.candidate_decrypt(
            key=aead_key,
            nonce=bytes([nonce[0] ^ 0x01]) + nonce[1:],
            ciphertext=ct,
            aad=aad,
            live_fp=live_fp,
        ),
        "bad_aad_header": trs.candidate_decrypt(
            key=aead_key,
            nonce=nonce,
            ciphertext=ct,
            aad=aad[:-1] + bytes([aad[-1] ^ 0x01]),
            live_fp=live_fp,
        ),
        "wrong_root_key": trs.candidate_decrypt(
            key=hashlib.sha256(aead_key).digest(),
            nonce=nonce,
            ciphertext=ct,
            aad=aad,
            live_fp=live_fp,
        ),
    }
    write(
        "atsam/tr_tamper_candidate_001.json",
        vec(
            "Tampered candidate decrypt never promotes live head",
            "header/nonce/ciphertext/wrong-root fail-closed",
            {
                "aead_key_hex": aead_key.hex(),
                "nonce_hex": nonce.hex(),
                "ciphertext_hex": ct.hex(),
                "aad_hex": aad.hex(),
                "live_fp_hex": live_fp.hex(),
            },
            tamper_cases,
        ),
    )

    kr0 = trs.k_route(expand.k_route_master, 0)
    kr1 = trs.k_route(expand.k_route_master, 1)
    created = EPOCH_MS + 5000
    rtag0 = trs.routing_tag(
        k_route_d=kr0,
        created_at_ms=created,
        n=7,
        app_type=1,
        direction=0,
        session_id=expand.session_id,
    )
    rtag1 = trs.routing_tag(
        k_route_d=kr1,
        created_at_ms=created,
        n=7,
        app_type=1,
        direction=1,
        session_id=expand.session_id,
    )
    now_ms = EPOCH_MS + 10 * 86_400_000
    cursor_day = (now_ms // 86_400_000) - 12
    mtag0 = trs.mailbox_tag(
        k_route_d=kr0, unix_ms=now_ms, direction=0, session_id=expand.session_id
    )
    stag0 = trs.store_tag(mtag0)
    plan = trs.mailbox_catchup_plan(
        now_ms=now_ms,
        catchup_cursor_day=cursor_day,
        mailbox_ttl_days=30,
        late_arrival_days=tr.MAILBOX_LATE_ARRIVAL_DAYS,
    )
    write(
        "atsam/tr_route_mailbox_001.json",
        vec(
            "Directional route tags, day epoch, mailbox catch-up TTL horizon",
            "K_route[d] stable; catch-up covers full TTL not yesterday-only",
            {
                "k_route_master_hex": expand.k_route_master.hex(),
                "session_id_hex": expand.session_id.hex(),
                "created_at_ms": created,
                "n": 7,
                "app_type": 1,
                "now_ms": now_ms,
                "catchup_cursor_day": cursor_day,
                "mailbox_ttl_days": 30,
            },
            {
                "k_route_0_hex": kr0.hex(),
                "k_route_1_hex": kr1.hex(),
                "routing_tag_d0_hex": rtag0.hex(),
                "routing_tag_d1_hex": rtag1.hex(),
                "tags_differ_by_direction": rtag0 != rtag1,
                "mailbox_tag_d0_hex": mtag0.hex(),
                "store_tag_d0_hex": stag0.hex(),
                "day_epoch": now_ms // 86_400_000,
                "catchup": {
                    "today": plan.today,
                    "ttl_horizon": plan.ttl_horizon,
                    "late_arrival_floor": plan.late_arrival_floor,
                    "historical_days": plan.historical_days,
                    "always_repoll_days": plan.always_repoll_days,
                    "historical_span": len(plan.historical_days),
                },
            },
        ),
    )

    def crash_vec(name, desc, steps, negatives):
        return {
            "name": name,
            "description": desc,
            "protocol_version": "rvn1",
            "profile": "ATSAM/hybrid-ratchet/v2",
            "deterministic": True,
            "production_enabled": False,
            "steps": steps,
            "negatives": negatives,
        }

    write(
        "atsam/tr_crash_receive_commit_001.json",
        crash_vec(
            "Inbound receive commit order",
            "PENDING → SQL receipt/dedup → FINALIZE head; never finalize before SQL",
            [
                {"id": 1, "action": "clone_candidate"},
                {"id": 2, "action": "derive_keys_on_candidate"},
                {"id": 3, "action": "aead_ok"},
                {"id": 4, "action": "write_PENDING_inbound"},
                {"id": 5, "action": "sql_commit_receipt_dedup"},
                {"id": 6, "action": "FINALIZE_head"},
                {"id": 7, "action": "clear_PENDING"},
            ],
            ["FINALIZE_before_sql"],
        ),
    )
    write(
        "atsam/tr_crash_skipped_persist_001.json",
        crash_vec(
            "Skipped-key persistence before finalize",
            "MKSKIPPED durable with SQL commit before head finalize",
            [
                {"id": 1, "action": "clone_candidate"},
                {"id": 2, "action": "derive_keys_on_candidate"},
                {"id": 3, "action": "aead_ok"},
                {"id": 4, "action": "write_PENDING_inbound"},
                {"id": 5, "action": "sql_commit_receipt_dedup"},
                {"id": 6, "action": "persist_MKSKIPPED"},
                {"id": 7, "action": "FINALIZE_head"},
                {"id": 8, "action": "clear_PENDING"},
            ],
            ["FINALIZE_before_sql"],
        ),
    )
    write(
        "atsam/tr_crash_epoch_promote_001.json",
        crash_vec(
            "SCKA epoch promotion with SQL then finalize",
            "Epoch promote on candidate; durable only after SQL + commit_epoch_with_finalize",
            [
                {"id": 1, "action": "clone_candidate"},
                {"id": 2, "action": "derive_keys_on_candidate"},
                {"id": 3, "action": "promote_scka_epoch_on_candidate"},
                {"id": 4, "action": "aead_ok"},
                {"id": 5, "action": "write_PENDING_inbound"},
                {"id": 6, "action": "sql_commit_receipt_dedup"},
                {"id": 7, "action": "commit_epoch_with_finalize"},
                {"id": 8, "action": "clear_PENDING"},
            ],
            ["promote_epoch_before_sql", "FINALIZE_before_sql"],
        ),
    )

    # P0: real EC DH ratchet
    alice_priv0 = hashlib.sha256(b"atsam-v2/ec-dh/alice0").digest()
    bob_priv0 = hashlib.sha256(b"atsam-v2/ec-dh/bob0").digest()
    bob_priv1 = hashlib.sha256(b"atsam-v2/ec-dh/bob1").digest()
    alice_priv1 = hashlib.sha256(b"atsam-v2/ec-dh/alice1").digest()
    ec_dh = trtr.run_ec_dh_ratchet_matrix(
        expand.sk_ec, alice_priv0, bob_priv0, bob_priv1, alice_priv1
    )
    write(
        "atsam/tr_ec_dh_ratchet_001.json",
        vec(
            "EC Double Ratchet DH transition + PN/N + cross-boundary skip",
            "OOO across DH boundary; KDF_RK; all-zero X25519 rejected",
            {
                "rk0_hex": expand.sk_ec.hex(),
                "alice_priv0_hex": alice_priv0.hex(),
                "bob_priv0_hex": bob_priv0.hex(),
                "bob_priv1_hex": bob_priv1.hex(),
                "alice_priv1_hex": alice_priv1.hex(),
            },
            ec_dh,
        ),
    )

    # P0: Braid chunk + KEM ss from frozen ML-KEM KAT (not synthetic ss alone)
    braid_kem = trtr.run_braid_kem_chunk_matrix(expand.session_id, expand.sk_scka)
    write(
        "atsam/tr_braid_kem_chunk_001.json",
        vec(
            "Braid chunk codec + ML-KEM CT reassembly + SCKA promote",
            "Loss/reorder/tamper/epoch-key zero; ss from mlkem768_hybrid_kat_001",
            {
                "session_id_hex": expand.session_id.hex(),
                "sk_scka_hex": expand.sk_scka.hex(),
            },
            braid_kem,
        ),
    )

    braid_neg = trtr.run_braid_codec_negatives(expand.session_id)
    write(
        "atsam/tr_braid_codec_negatives_001.json",
        vec(
            "Strict braid codec negatives + reassembly/MKSKIPPED caps",
            "Exact wire length; type/u16 encode; index/byte caps; binding not MAC",
            {"session_id_hex": expand.session_id.hex()},
            braid_neg,
        ),
    )

    combo = trtr.run_tr_combo_matrix(
        sk_ec=expand.sk_ec,
        sk_scka=expand.sk_scka,
        session_id=expand.session_id,
        alice_priv0=alice_priv0,
        bob_priv0=bob_priv0,
        bob_priv1=bob_priv1,
        alice_priv1=alice_priv1,
        ss_scka1=ss1,
        ss_scka2=bytes.fromhex(braid_kem["z_pq_hex"]),
    )
    write(
        "atsam/tr_combo_multi_001.json",
        vec(
            "Combined multi-message TR across ≥2 DH and ≥2 SCKA epochs",
            "Hybrid keys bind EC mk + SCKA mk after dual ratchet progress",
            {
                "sk_ec_hex": expand.sk_ec.hex(),
                "sk_scka_hex": expand.sk_scka.hex(),
                "session_id_hex": expand.session_id.hex(),
                "alice_priv0_hex": alice_priv0.hex(),
                "bob_priv0_hex": bob_priv0.hex(),
                "bob_priv1_hex": bob_priv1.hex(),
                "alice_priv1_hex": alice_priv1.hex(),
                "ss_scka1_hex": ss1.hex(),
                "ss_scka2_hex": braid_kem["z_pq_hex"],
            },
            combo,
        ),
    )

    print("wrote hybrid-ratchet/v2 freeze vectors under", OUT / "atsam")


if __name__ == "__main__":
    main()
