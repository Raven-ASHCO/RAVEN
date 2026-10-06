from raven_protocol import device_revocation, address
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "shared-vectors/rvn1"


def test_valid_vector_roundtrip():
    v = json.loads((VEC / "device_revocation/valid_001.json").read_text())
    wire = bytes.fromhex(v["expected"]["wire_hex"])
    rec = device_revocation.decode(wire)
    assert device_revocation.encode(rec) == wire
    pub = bytes.fromhex(v["inputs"]["identity_ed_pub_hex"])
    assert device_revocation.verify(rec, pub)
    assert device_revocation.claim_digest(wire).hex() == v["expected"]["claim_digest_hex"]
    assert v["expected"]["offsets"]["total_len"] == len(wire)
    assert address.encode(pub) == v["inputs"]["identity_address"]


def test_wrong_signer_rejects():
    v = json.loads((VEC / "negative/device_revocation_wrong_signer.json").read_text())
    wire = bytes.fromhex(v["inputs"]["wire_hex"])
    rec = device_revocation.decode(wire)
    pub = bytes.fromhex(v["inputs"]["claimed_identity_ed_pub_hex"])
    assert device_revocation.verify(rec, pub) is False


def test_long_id_short_tail_rejects_without_index_error():
    v = json.loads(
        (VEC / "negative/device_revocation_long_id_short_tail.json").read_text()
    )
    wire = bytes.fromhex(v["inputs"]["wire_hex"])
    assert len(wire) == v["expected"]["wire_len"]
    try:
        device_revocation.decode(wire)
    except ValueError:
        pass
    else:  # pragma: no cover - must reject
        raise AssertionError("decode accepted a truncated tail")
    # device_id 64 + issuer 20 at the 253-byte floor: the old decoder raised
    # IndexError reading reason_code past the end.
    w = bytearray(wire[:56])
    w[54:56] = (64).to_bytes(2, "big")
    w += b"d" * 64 + bytes(96) + (20).to_bytes(2, "big") + b"i" * 20
    w += bytes(253 - len(w))
    try:
        device_revocation.decode(bytes(w))
    except ValueError:
        pass
    else:  # pragma: no cover - must reject
        raise AssertionError("decode accepted a truncated tail")


def test_decode_never_raises_non_value_error():
    v = json.loads((VEC / "device_revocation/valid_001.json").read_text())
    wire = bytes.fromhex(v["expected"]["wire_hex"])
    # Every truncation, and every device_id length prefix, must be a ValueError.
    candidates = [wire[:n] for n in range(len(wire))]
    for n in range(0, 70):
        w = bytearray(wire)
        w[54:56] = n.to_bytes(2, "big")
        candidates.append(bytes(w))
        candidates.append(bytes(w[:253]))
    for w in candidates:
        try:
            device_revocation.decode(w)
        except ValueError:
            continue
        # Only the untouched prefix length (12) re-parses successfully.
        assert w == wire


def test_store_hash_vectors():
    for name in (
        "device_revocation/store_hash_001.json",
        "device_revocation/store_hash_exhausted_001.json",
    ):
        v = json.loads((VEC / name).read_text())
        claims = [
            device_revocation.StoreClaim(bytes.fromhex(h))
            for h in v["inputs"]["claims_wire_hex"]
        ]
        exhausted = [
            device_revocation.ExhaustedMarker(
                identity_address=e["identity_address"],
                claim_digest=bytes.fromhex(e["claim_digest_hex"]),
                exact_record_bytes=bytes.fromhex(e["exact_record_bytes_hex"]),
            )
            for e in v["inputs"]["exhausted"]
        ]
        h = device_revocation.revocation_store_hash(
            v["inputs"]["generation"], claims, exhausted, []
        )
        assert h.hex() == v["expected"]["revocation_store_hash_hex"]
        snap = device_revocation.canonical_store_snapshot(
            v["inputs"]["generation"], claims, exhausted, []
        )
        assert snap.hex() == v["expected"]["canonical_snapshot_hex"]


def test_crash_replay_order_fixture_present():
    v = json.loads((VEC / "device_revocation/crash_replay_order_001.json").read_text())
    assert v["steps"][2]["action"] == "journal_convert"
    assert v["steps"][2]["from"] == "PENDING_REVOKE_EXHAUSTED"
    assert v["steps"][2]["to"] == "PENDING_REVOKE"
    assert "delete_IDENTITY_REVOKE_EXHAUSTED" in v["steps"][3]["ops"]
