"""Conformance KATs for RavenDeviceRevocationV1 remaining fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from raven_protocol import device_revocation, device_revocation_conformance as rev_conf

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "shared-vectors/rvn1/device_revocation"


def _load(name: str):
    return json.loads((VEC / name).read_text())


def _peer_kwargs(peer: dict):
    return dict(
        device_id=peer["device_id_utf8"].encode(),
        device_ed_pub=bytes.fromhex(peer["device_ed_pub_hex"]),
        device_x_pub=bytes.fromhex(peer["device_x_pub_hex"]),
        device_cert_hash=bytes.fromhex(peer["device_cert_hash_hex"]),
    )


def test_union_001():
    v = _load("union_001.json")
    store = rev_conf.ConformanceStore(
        identity_address=v["inputs"]["identity_address"], max_claims=10_000
    )
    pub = bytes.fromhex(v["inputs"]["identity_ed_pub_hex"])
    results = []
    for hx in v["inputs"]["claims_wire_hex"]:
        results.append(
            rev_conf.apply_verified_claim(store, bytes.fromhex(hx), pub)["result"]
        )
    assert results == v["expected"]["apply_results"]
    assert store.snapshot_dict() == v["expected"]["store"]
    assert store.snapshot_dict()["revocation_id_collisions"] == []


def test_collision_revocation_id_001():
    v = _load("collision_revocation_id_001.json")
    store = rev_conf.ConformanceStore(
        identity_address=v["inputs"]["identity_address"], max_claims=10_000
    )
    pub = bytes.fromhex(v["inputs"]["identity_ed_pub_hex"])
    for hx in v["inputs"]["claims_wire_hex"]:
        rev_conf.apply_verified_claim(store, bytes.fromhex(hx), pub)
    snap = store.snapshot_dict()
    assert snap == v["expected"]["store"]
    assert snap["revoked_targets"] == v["expected"]["store"]["revoked_targets"]
    assert snap["revocation_id_collisions"] == v["expected"]["store"][
        "revocation_id_collisions"
    ]
    assert len(snap["revocation_id_collisions"]) == 1
    assert (
        snap["revocation_id_collisions"][0]["revocation_id_hex"]
        == v["inputs"]["shared_revocation_id_hex"]
    )


def test_quota_machine_001():
    v = _load("quota_machine_001.json")
    store = rev_conf.ConformanceStore(
        identity_address=v["inputs"]["identity_address"],
        max_claims=v["inputs"]["max_claims_initial"],
    )
    pub = bytes.fromhex(v["inputs"]["identity_ed_pub_hex"])
    wire_bob = bytes.fromhex(v["inputs"]["wire_bob_hex"])
    wire_carol = bytes.fromhex(v["inputs"]["wire_carol_hex"])
    assert rev_conf.apply_verified_claim(store, wire_bob, pub)["result"] == "applied"
    assert rev_conf.apply_verified_claim(store, wire_carol, pub)["result"] == "exhausted"
    assert store.journal["kind"] == "PENDING_REVOKE_EXHAUSTED"
    assert len(store.claims) == 1
    # intermediate hash from fixture step 3
    step3 = next(s for s in v["steps"] if s.get("id") == 3)
    assert store.store_hash().hex() == step3["store_hash_hex"]
    # no-auto-retry
    try:
        rev_conf.apply_verified_claim(
            store, wire_carol, pub, pending_already_written=True
        )
        raise AssertionError("expected direct_exhausted_consumption")
    except ValueError as e:
        assert str(e) == "direct_exhausted_consumption"
    # exhausted authorization
    g = _load("apply_gates_001.json")
    carol_peer = g["inputs"]["carol_peer"]
    for s in rev_conf.SURFACES:
        auth = rev_conf.authorize_device(store, surface=s, **_peer_kwargs(carol_peer))
        assert auth["authorized"] is False
        assert auth["reason"] == "IDENTITY_REVOKE_EXHAUSTED"
    rev_conf.expand_quota(store, v["inputs"]["max_claims_after_expand"])
    assert rev_conf.reverify_journal(store, pub)["result"] == "ok"
    rev_conf.convert_exhausted_journal_to_pending(store)
    assert store.journal["kind"] == "PENDING_REVOKE"
    assert (
        rev_conf.apply_verified_claim(
            store, wire_carol, pub, pending_already_written=True
        )["result"]
        == "applied"
    )
    assert store.snapshot_dict() == v["expected_after"]
    convert = next(s for s in v["steps"] if s.get("action") == "journal_convert")
    assert convert["from"] == "PENDING_REVOKE_EXHAUSTED"
    assert convert["to"] == "PENDING_REVOKE"


def test_corrupt_journal_matrix():
    cases = [
        ("corrupt_journal_truncated_001.json", "truncated", 1),
        # >= 54 bytes but not one complete RVDR1 record: same frozen code as Rust.
        ("corrupt_journal_malformed_001.json", "truncated", 1),
        ("corrupt_journal_digest_mismatch_001.json", "digest_mismatch", 2),
        ("corrupt_journal_bad_signature_001.json", "bad_signature", 3),
    ]
    for name, reason, code in cases:
        v = _load(name)
        store = rev_conf.ConformanceStore(
            identity_address=v["inputs"]["identity_address"], max_claims=10_000
        )
        store.journal = dict(v["inputs"]["journal_before"])
        pub = bytes.fromhex(v["inputs"]["identity_ed_pub_hex"])
        out = rev_conf.reverify_journal(store, pub)
        assert out["result"] == "corrupt"
        assert out["reason"] == reason
        assert out["reason_code"] == code
        assert store.journal is None
        assert len(store.corrupt) == 1
        assert out["store"] == v["expected"]["store"]


def test_corrupt_recovery_authorize_executed():
    v = _load("corrupt_journal_recovery_001.json")
    store = rev_conf.ConformanceStore(
        identity_address=v["inputs"]["identity_address"], max_claims=10_000
    )
    for c in v["inputs"]["corrupt"]:
        store.corrupt.append(
            device_revocation.CorruptMarker(
                scope=c["scope"], reason_code=c["reason_code"]
            )
        )
    peer = v["inputs"]["peer"]
    computed = [
        rev_conf.authorize_device(store, surface=s, **_peer_kwargs(peer))
        for s in v["inputs"]["surfaces"]
    ]
    assert computed == v["expected"]["gates"]
    assert all(not g["authorized"] for g in computed)


def test_apply_gates_authorize_executed():
    g = _load("apply_gates_001.json")
    pub = bytes.fromhex(g["inputs"]["identity_ed_pub_hex"])
    store = rev_conf.ConformanceStore(
        identity_address=g["inputs"]["identity_address"], max_claims=10_000
    )
    rev_conf.apply_verified_claim(
        store, bytes.fromhex(g["inputs"]["revoked_wire_hex"]), pub
    )
    bob = [
        rev_conf.authorize_device(
            store, surface=s, **_peer_kwargs(g["inputs"]["bob_peer"])
        )
        for s in g["inputs"]["surfaces"]
    ]
    carol = [
        rev_conf.authorize_device(
            store, surface=s, **_peer_kwargs(g["inputs"]["carol_peer"])
        )
        for s in g["inputs"]["surfaces"]
    ]
    assert bob == g["expected"]["bob_revoked_gates"]
    assert carol == g["expected"]["carol_unrevoked_gates"]
    assert all(not x["authorized"] for x in bob)
    assert all(x["authorized"] for x in carol)

    store_ex = rev_conf.ConformanceStore(
        identity_address=g["inputs"]["identity_address"], max_claims=1
    )
    rev_conf.apply_verified_claim(
        store_ex, bytes.fromhex(g["inputs"]["revoked_wire_hex"]), pub
    )
    rev_conf.apply_verified_claim(
        store_ex, bytes.fromhex(g["inputs"]["carol_wire_hex"]), pub
    )
    exh = [
        rev_conf.authorize_device(
            store_ex, surface=s, **_peer_kwargs(g["inputs"]["carol_peer"])
        )
        for s in g["inputs"]["surfaces"]
    ]
    assert exh == g["expected"]["carol_under_exhausted_gates"]
    assert all(not x["authorized"] for x in exh)


def test_pending_binding_negatives():
    v = _load("pending_binding_negatives_001.json")
    pub = bytes.fromhex(v["inputs"]["identity_ed_pub_hex"])
    for case in v["cases"]:
        store = rev_conf.ConformanceStore(
            identity_address=v["inputs"]["identity_address"], max_claims=10_000
        )
        store.journal = (
            None if case["journal_before"] is None else dict(case["journal_before"])
        )
        try:
            rev_conf.apply_verified_claim(
                store,
                bytes.fromhex(case["apply_wire_hex"]),
                pub,
                pending_already_written=True,
            )
            raise AssertionError(f"{case['id']} should fail")
        except ValueError as e:
            assert str(e) == case["expected_error"]
