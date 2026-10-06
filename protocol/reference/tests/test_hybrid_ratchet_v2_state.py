"""Stateful matrix KATs for ATSAM/hybrid-ratchet/v2."""

from __future__ import annotations

import json
from pathlib import Path

from raven_protocol import hybrid_ratchet_v2_state as trs

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "shared-vectors/rvn1/atsam"


def _load(name: str):
    return json.loads((VEC / name).read_text())


def test_braid_epoch_001():
    v = _load("tr_braid_epoch_001.json")
    out = trs.run_braid_epoch_matrix(
        bytes.fromhex(v["inputs"]["sk_scka_hex"]),
        bytes.fromhex(v["inputs"]["ss_epoch1_hex"]),
        bytes.fromhex(v["inputs"]["ss_epoch2_hex"]),
    )
    assert out == v["expected"]
    assert out["epoch1"]["alice_send_equals_bob_recv"] is True
    assert out["epoch2"]["bob_send_equals_alice_recv"] is True


def test_ec_ooo_001():
    v = _load("tr_ec_ooo_001.json")
    out = trs.run_ec_ooo_matrix(
        bytes.fromhex(v["inputs"]["ck_hex"]),
        bytes.fromhex(v["inputs"]["dh_pub_hex"]),
    )
    assert out == v["expected"]
    assert out["ooo_ok"] is True


def test_skip_boundary_001():
    v = _load("tr_skip_boundary_001.json")
    out = trs.run_skip_boundary(
        bytes.fromhex(v["inputs"]["ck_hex"]),
        bytes.fromhex(v["inputs"]["dh_pub_hex"]),
    )
    assert out == v["expected"]
    by_count = {c["skip_count"]: c for c in out["cases"]}
    assert by_count[1000]["result"] == "ok"
    assert by_count[1001]["result"] == "reject"
    assert by_count[1001]["state_unchanged"] is True
    assert by_count[1001]["allocation"] is False
    assert by_count[1001]["state_advance"] is False


def test_replay_duplicate_001():
    v = _load("tr_replay_duplicate_001.json")
    inp = v["inputs"]
    ledger = trs.CommitLedger()
    key = trs.AcceptKey(
        session_id=bytes.fromhex(inp["session_id_hex"]),
        dh_pub=bytes.fromhex(inp["dh_pub_hex"]),
        n=inp["accept_key"]["n"],
        scka_epoch=inp["accept_key"]["scka_epoch"],
        scka_ctr=inp["accept_key"]["scka_ctr"],
    )
    digest = bytes.fromhex(inp["object_digest_hex"])
    ack = bytes.fromhex(inp["retained_ack_hex"])
    ledger, r1 = trs.commit_accept(ledger, key, digest, ack)
    fp1 = ledger.fingerprint()
    ledger2, r2 = trs.commit_accept(ledger, key, digest, ack)
    fp2 = ledger2.fingerprint()
    dup = trs.duplicate_ack_exact(ledger2, digest)
    assert r1 == v["expected"]["first_result"]
    assert r2 == v["expected"]["replay_result"]
    assert fp1.hex() == v["expected"]["fp_after_accept_hex"]
    assert fp2.hex() == v["expected"]["fp_after_replay_hex"]
    assert fp1 == fp2
    assert dup == ack
    assert ledger2.mutation_count == 1


def test_tamper_candidate_001():
    v = _load("tr_tamper_candidate_001.json")
    inp = v["inputs"]
    live = bytes.fromhex(inp["live_fp_hex"])
    key = bytes.fromhex(inp["aead_key_hex"])
    nonce = bytes.fromhex(inp["nonce_hex"])
    ct = bytes.fromhex(inp["ciphertext_hex"])
    aad = bytes.fromhex(inp["aad_hex"])
    import hashlib

    cases = {
        "good": trs.candidate_decrypt(key=key, nonce=nonce, ciphertext=ct, aad=aad, live_fp=live),
        "bad_ciphertext": trs.candidate_decrypt(
            key=key,
            nonce=nonce,
            ciphertext=ct[:-1] + bytes([ct[-1] ^ 0x01]),
            aad=aad,
            live_fp=live,
        ),
        "bad_nonce": trs.candidate_decrypt(
            key=key,
            nonce=bytes([nonce[0] ^ 0x01]) + nonce[1:],
            ciphertext=ct,
            aad=aad,
            live_fp=live,
        ),
        "bad_aad_header": trs.candidate_decrypt(
            key=key,
            nonce=nonce,
            ciphertext=ct,
            aad=aad[:-1] + bytes([aad[-1] ^ 0x01]),
            live_fp=live,
        ),
        "wrong_root_key": trs.candidate_decrypt(
            key=hashlib.sha256(key).digest(),
            nonce=nonce,
            ciphertext=ct,
            aad=aad,
            live_fp=live,
        ),
    }
    assert cases == v["expected"]
    assert cases["good"]["promote_live_head"] is True
    for name in ("bad_ciphertext", "bad_nonce", "bad_aad_header", "wrong_root_key"):
        assert cases[name]["promote_live_head"] is False
        assert cases[name]["durable_mutation"] is False
        assert cases[name]["live_fp_after_hex"] == live.hex()


def test_route_mailbox_001():
    v = _load("tr_route_mailbox_001.json")
    inp = v["inputs"]
    kr0 = trs.k_route(bytes.fromhex(inp["k_route_master_hex"]), 0)
    kr1 = trs.k_route(bytes.fromhex(inp["k_route_master_hex"]), 1)
    sid = bytes.fromhex(inp["session_id_hex"])
    r0 = trs.routing_tag(
        k_route_d=kr0,
        created_at_ms=inp["created_at_ms"],
        n=inp["n"],
        app_type=inp["app_type"],
        direction=0,
        session_id=sid,
    )
    r1 = trs.routing_tag(
        k_route_d=kr1,
        created_at_ms=inp["created_at_ms"],
        n=inp["n"],
        app_type=inp["app_type"],
        direction=1,
        session_id=sid,
    )
    m0 = trs.mailbox_tag(
        k_route_d=kr0, unix_ms=inp["now_ms"], direction=0, session_id=sid
    )
    s0 = trs.store_tag(m0)
    plan = trs.mailbox_catchup_plan(
        now_ms=inp["now_ms"],
        catchup_cursor_day=inp["catchup_cursor_day"],
        mailbox_ttl_days=inp["mailbox_ttl_days"],
    )
    assert kr0.hex() == v["expected"]["k_route_0_hex"]
    assert kr1.hex() == v["expected"]["k_route_1_hex"]
    assert r0.hex() == v["expected"]["routing_tag_d0_hex"]
    assert r1.hex() == v["expected"]["routing_tag_d1_hex"]
    assert r0 != r1
    assert m0.hex() == v["expected"]["mailbox_tag_d0_hex"]
    assert s0.hex() == v["expected"]["store_tag_d0_hex"]
    assert plan.today == v["expected"]["catchup"]["today"]
    assert plan.ttl_horizon == v["expected"]["catchup"]["ttl_horizon"]
    assert plan.historical_days == v["expected"]["catchup"]["historical_days"]
    assert plan.always_repoll_days == v["expected"]["catchup"]["always_repoll_days"]
    assert len(plan.historical_days) >= 7  # not yesterday-only
    assert plan.late_arrival_floor == v["expected"]["catchup"]["late_arrival_floor"]
    assert plan.ttl_horizon == v["expected"]["catchup"]["ttl_horizon"]
    assert v["expected"]["catchup"]["historical_span"] == len(plan.historical_days)

def _run_crash(name: str):
    v = _load(name)
    m = trs.ReceiveCommitMachine()
    for step in v["steps"]:
        m.apply(step["action"])
    assert m.state == "cleared"
    for neg in v["negatives"]:
        bad = trs.ReceiveCommitMachine()
        try:
            bad.apply(neg)
            raise AssertionError(f"expected reject for {neg}")
        except trs.CrashMachineError:
            pass
    return m


def test_crash_receive_commit_001():
    m = _run_crash("tr_crash_receive_commit_001.json")
    assert m.durable_mutation is True
    assert m.generation == 1


def test_crash_skipped_persist_001():
    m = _run_crash("tr_crash_skipped_persist_001.json")
    assert m.skipped_persisted is True


def test_crash_epoch_promote_001():
    m = _run_crash("tr_crash_epoch_promote_001.json")
    assert m.epoch_promoted is True
    assert m.durable_mutation is True


def test_ec_dh_ratchet_001():
    from raven_protocol import hybrid_ratchet_v2_tr as trtr

    v = _load("tr_ec_dh_ratchet_001.json")
    out = trtr.run_ec_dh_ratchet_matrix(
        bytes.fromhex(v["inputs"]["rk0_hex"]),
        bytes.fromhex(v["inputs"]["alice_priv0_hex"]),
        bytes.fromhex(v["inputs"]["bob_priv0_hex"]),
        bytes.fromhex(v["inputs"]["bob_priv1_hex"]),
        bytes.fromhex(v["inputs"]["alice_priv1_hex"]),
    )
    assert out == v["expected"]
    assert out["cross_boundary_ok"] is True
    assert "rejected" in out["negatives"]["all_zero_pub"]


def test_braid_kem_chunk_001():
    from raven_protocol import hybrid_ratchet_v2_tr as trtr

    v = _load("tr_braid_kem_chunk_001.json")
    out = trtr.run_braid_kem_chunk_matrix(
        bytes.fromhex(v["inputs"]["session_id_hex"]),
        bytes.fromhex(v["inputs"]["sk_scka_hex"]),
    )
    assert out == v["expected"]
    assert out["reassembled_ct_ok"] is True
    assert out["tamper_result"] == "braid chunk tamper"
    assert out["prev_dk_zeroed"] is True


def test_braid_codec_negatives_001():
    from raven_protocol import hybrid_ratchet_v2_tr as trtr

    v = _load("tr_braid_codec_negatives_001.json")
    out = trtr.run_braid_codec_negatives(bytes.fromhex(v["inputs"]["session_id_hex"]))
    assert out == v["expected"]
    by_name = {c["name"]: c for c in out["cases"]}
    assert by_name["truncated_plen"]["result"] == "reject"
    assert by_name["trailing_bytes"]["result"] == "reject"
    assert by_name["oversized_plen_field"]["result"] == "reject"
    assert by_name["encode_unknown_type"]["result"] == "reject"
    assert by_name["encode_payload_gt_max"]["result"] == "reject"
    assert by_name["session_id_bad_len"]["result"] == "reject"
    assert by_name["empty_type_nonempty_payload"]["result"] == "reject"
    assert by_name["data_type_empty_payload"]["result"] == "reject"
    assert by_name["empty_type_nonzero_index"]["result"] == "reject"
    assert by_name["ingest_index_oob"]["result"] == "index_out_of_range"
    assert by_name["ingest_byte_cap"]["result"] == "byte_cap_exceeded"
    assert by_name["mkskipped_global_cap"]["result"] == "reject"
    assert by_name["binding_digest_role"]["result"] == "canonical_binding_only"
    assert by_name["epoch_width_policy"]["result"] == "u64be_no_wrap"
    assert out["epoch_type"] == "u64"
    assert out["braid_header_len"] == 23
    assert out["braid_max_payload"] == out["braid_max_total_bytes"] == 8192
    assert out["mlkem768_ek_vector_size"] == 1152
    assert out["mlkem768_ek_fips_size"] == 1184
    assert out["mlkem768_header_size"] == 64


def test_tr_combo_multi_001():
    from raven_protocol import hybrid_ratchet_v2_tr as trtr

    v = _load("tr_combo_multi_001.json")
    inp = v["inputs"]
    out = trtr.run_tr_combo_matrix(
        sk_ec=bytes.fromhex(inp["sk_ec_hex"]),
        sk_scka=bytes.fromhex(inp["sk_scka_hex"]),
        session_id=bytes.fromhex(inp["session_id_hex"]),
        alice_priv0=bytes.fromhex(inp["alice_priv0_hex"]),
        bob_priv0=bytes.fromhex(inp["bob_priv0_hex"]),
        bob_priv1=bytes.fromhex(inp["bob_priv1_hex"]),
        alice_priv1=bytes.fromhex(inp["alice_priv1_hex"]),
        ss_scka1=bytes.fromhex(inp["ss_scka1_hex"]),
        ss_scka2=bytes.fromhex(inp["ss_scka2_hex"]),
    )
    assert out == v["expected"]
    assert out["dh_epochs"] == 2
    assert out["scka_epochs"] == 2


def test_scka_epochs_are_u64_and_fail_closed():
    import pytest

    state = trs.scka_from_init(True, bytes([0x42]) * 32)
    ss = bytes([0x07]) * 32
    state.sending_epoch = (1 << 32) - 1
    # Past the old u32 range: no wrap, no truncation.
    assert trs.scka_epoch_promote_initiator(state, ss).sending_epoch == 1 << 32
    state.sending_epoch = trs.EPOCH_MAX
    state.receiving_epoch = trs.EPOCH_MAX
    with pytest.raises(ValueError, match="EPOCH_TYPE=u64"):
        trs.scka_epoch_promote_initiator(state, ss)
    with pytest.raises(ValueError, match="EPOCH_TYPE=u64"):
        trs.scka_epoch_promote_responder(state, ss)
    state.send_ctr = trs.CTR_MAX
    with pytest.raises(ValueError, match="counter overflow"):
        trs.scka_next_send_mk(state)


def test_ec_skip_keys_global_retention_cap():
    import pytest

    dh = bytes([0x04]) * 32
    state = trs.EcRecvState(ck=bytes([0x03]) * 32, n=0, dh_pub=dh)
    for n in range(1500):
        state.mkskipped[bytes([0x05]) * 32 + n.to_bytes(4, "big")] = bytes(32)
    with pytest.raises(ValueError, match="MAX_MKSKIPPED_RETAINED"):
        trs.ec_skip_keys(state, 600)
    assert len(trs.ec_skip_keys(state, 500).mkskipped) == trs.MAX_MKSKIPPED_RETAINED


def test_braid_promote_erases_callers_prev_dk():
    import pytest

    from raven_protocol import hybrid_ratchet_v2_tr as trtr

    reb = trtr.BraidReassembly(epoch=1, expected_count=1)
    reb.parts[0] = b"ct"
    prev_dk = bytearray(b"\x55" * 32)
    assert reb.promote_with_ss(b"\x66" * 32, prev_dk) == b"\x66" * 32
    assert prev_dk == bytearray(32)
    assert reb.deleted_prev_dk is True and reb.prev_dk is None
    with pytest.raises(TypeError):
        trtr.BraidReassembly(epoch=1, expected_count=1, parts={0: b"x"}).promote_with_ss(
            b"\x66" * 32, b"\x55" * 32
        )


def test_composite_header_stub_rejects_out_of_range_epoch():
    import pytest

    from raven_protocol import hybrid_ratchet_v2 as tr

    ec = tr.EcHeader(dh_pub=bytes(32), pn=0, n=0)
    spqr = tr.SpqrHeader(
        sending_epoch=1 << 32,
        receiving_epoch=0,
        send_ctr=0,
        chunk_flags=0,
        kem_ct_digest=bytes(32),
    )
    with pytest.raises(ValueError, match="u32 range"):
        tr.encode_composite_header(ec, spqr)
