"""KATs for Full Braid Slice 2 computing reference (Task 11; production-disabled)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from raven_protocol import full_braid_digest as dig
from raven_protocol import full_braid_auth as auth
from raven_protocol import full_braid_state as state
from raven_protocol import full_braid_transition as sm
from raven_protocol import full_braid_wire as wire

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "shared-vectors/rvn1/atsam"


def _load(name: str):
    return json.loads((VEC / name).read_text())


def test_domain_catalog_and_digests():
    v = _load("full_braid_digests_001.json")
    assert v["expected"]["domains"] == dig.domain_catalog()
    assert v["expected"]["domains"]["RVBE1_SCHEMA"] == "0002"
    assert v["expected"]["empty_rvbo1_len"] == 14

    inputs = v["inputs"]
    rvfb1 = bytes.fromhex(inputs["rvfb1_stub_hex"])
    rvbi = bytes.fromhex(inputs["rvbi_stub_hex"])
    rvbe = bytes.fromhex(inputs["rvbe_stub_hex"])
    sid = bytes.fromhex(inputs["session_id_hex"])
    before = bytes.fromhex(inputs["before_state_digest_hex"])
    source = bytes.fromhex(inputs["source_bytes_hex"])
    payload = bytes.fromhex(inputs["chunk_payload_hex"])
    endpoint = bytes.fromhex(inputs["endpoint_object_hex"])

    assert dig.state_digest(inputs["schema_rev"], rvfb1).hex() == v["expected"]["state_digest_hex"]
    assert dig.input_digest(rvbi).hex() == v["expected"]["input_digest_hex"]
    exec_d = dig.execution_digest(rvbi, rvbe)
    assert exec_d.hex() == v["expected"]["execution_digest_hex"]
    empty = wire.encode_empty_rvbo1()
    assert empty.hex() == v["expected"]["empty_rvbo1_hex"]
    assert dig.output_digest(empty).hex() == v["expected"]["output_digest_empty_rvbo1_hex"]
    assert dig.object_digest(endpoint).hex() == v["expected"]["object_digest_hex"]
    assert dig.send_source_digest(source).hex() == v["expected"]["send_source_digest_hex"]
    assert (
        dig.braid_object_digest(
            sid, inputs["direction"], 1, inputs["source_kind"], source
        ).hex()
        == v["expected"]["braid_object_digest_hex"]
    )
    assert (
        dig.binding_digest(
            inputs["direction"],
            inputs["chunk_epoch"],
            inputs["chunk_type"],
            inputs["chunk_index"],
            payload,
            sid,
        ).hex()
        == v["expected"]["binding_digest_hex"]
    )
    assert (
        dig.transition_id_digest(
            sid,
            inputs["role"],
            inputs["direction"],
            inputs["generation"],
            exec_d,
            before,
        ).hex()
        == v["expected"]["transition_id_digest_hex"]
    )


def test_send_receive_round_wire_and_digests():
    v = _load("full_braid_send_receive_round_001.json")
    env_wire = bytes.fromhex(v["expected"]["rvbe1_wire_hex"])
    assert env_wire[8:10] == (2).to_bytes(2, "big")
    env = wire.decode_rvbe1(env_wire)
    assert env.admitted_trust is not None
    assert wire.encode_rvbe1(env) == env_wire

    send_wire = bytes.fromhex(v["expected"]["send_rvbi1_hex"])
    recv_wire = bytes.fromhex(v["expected"]["receive_rvbi1_hex"])
    assert wire.encode_rvbi1(wire.decode_rvbi1(send_wire)) == send_wire
    assert wire.encode_rvbi1(wire.decode_rvbi1(recv_wire)) == recv_wire

    assert dig.input_digest(send_wire).hex() == v["expected"]["send_input_digest_hex"]
    assert dig.input_digest(recv_wire).hex() == v["expected"]["receive_input_digest_hex"]
    assert (
        dig.execution_digest(send_wire, env_wire).hex()
        == v["expected"]["send_execution_digest_hex"]
    )
    assert (
        dig.execution_digest(recv_wire, env_wire).hex()
        == v["expected"]["receive_execution_digest_hex"]
    )

    flipped = bytearray(env_wire)
    flipped[len(flipped) - 4 - wire.ADMITTED_TRUST_LEN] ^= 0x01
    assert (
        dig.execution_digest(send_wire, bytes(flipped)).hex()
        == v["expected"]["trust_flip_execution_digest_hex"]
    )
    assert dig.execution_digest(send_wire, env_wire) != dig.execution_digest(
        send_wire, bytes(flipped)
    )


def test_rvbe1_negatives():
    v = _load("full_braid_rvbe1_negatives_001.json")
    for key, expected in zip(
        (
            "schema1_wire_hex",
            "truncated_wire_hex",
            "wrong_trust_len_wire_hex",
        ),
        v["expected"]["reject_reasons"],
    ):
        with pytest.raises(ValueError, match=expected):
            wire.decode_rvbe1(bytes.fromhex(v["inputs"][key]))


def test_wire_negatives_shared_vector():
    v = _load("full_braid_wire_negatives_001.json")
    decoders = {
        "rvbe1": wire.decode_rvbe1,
        "rvbi1": wire.decode_rvbi1,
    }
    for case in v["inputs"]["cases"]:
        decode = decoders[case["decoder"]]
        with pytest.raises(ValueError, match=case["expected_error"]):
            decode(bytes.fromhex(case["wire_hex"]))


def test_full_braid_authenticator_kats():
    initialized = auth.AuthState.init(1, bytes([0x11]) * 32)
    assert initialized.root_key.hex() == (
        "2f179ff05522a6967efdfd38f84955b2e3594eee23199c11c33e5bd7f5a56046"
    )
    assert initialized.mac_key.hex() == (
        "9437200f1c144f85cbd110895621e622cc6be705ee72934399121e8ce8708b9f"
    )

    hdr_auth = auth.AuthState.init(1, bytes([0x44]) * 32)
    assert hdr_auth.mac_hdr(1, bytes([0x55]) * 64).hex() == (
        "e6e70fede67dd441db684e5d5d92e55385328842ce73ac905b9e2c9872a44276"
    )


def test_full_braid_sm_round_is_computed_by_python():
    v = _load("full_braid_sm_round_001.json")
    inputs = v["inputs"]
    expected = v["expected"]
    material = sm.KeygenMaterial(
        dk=bytes.fromhex(inputs["keygen_dk_hex"]),
        header=bytes.fromhex(inputs["keygen_header_hex"]),
        ek_vector=bytes.fromhex(inputs["keygen_ek_vector_hex"]),
    )

    alice_before = bytes.fromhex(inputs["alice_before_hex"])
    assert state.encode_rvfb1(state.decode_rvfb1(alice_before)) == alice_before
    alice = sm.transition_prepare(
        alice_before,
        bytes.fromhex(inputs["send_input_hex"]),
        bytes.fromhex(inputs["send_env_hex"]),
        keygen_material=material,
    )
    assert alice.candidate_bytes.hex() == expected["alice_candidate_hex"]
    assert alice.outputs_bytes.hex() == expected["alice_rvbo1_hex"]
    assert alice.intent_bytes.hex() == expected["alice_intent_hex"]
    assert alice.meta.as_dict() == expected["alice_meta"]
    assert state.decode_rvfb1(alice.candidate_bytes).prefix.agent == expected["alice_agent"]

    bob_before = bytes.fromhex(inputs["bob_before_hex"])
    assert state.encode_rvfb1(state.decode_rvfb1(bob_before)) == bob_before
    bob = sm.transition_prepare(
        bob_before,
        bytes.fromhex(inputs["receive_input_hex"]),
        bytes.fromhex(inputs["receive_env_hex"]),
    )
    assert bob.candidate_bytes.hex() == expected["bob_candidate_hex"]
    assert bob.outputs_bytes.hex() == expected["bob_rvbo1_hex"]
    assert bob.intent_bytes.hex() == expected["bob_intent_hex"]
    assert bob.meta.as_dict() == expected["bob_meta"]
    assert state.decode_rvfb1(bob.candidate_bytes).prefix.agent == expected["bob_agent"]

    assert dig.state_digest(1, alice_before).hex() == expected["digests"][
        "alice_before_state_digest_hex"
    ]
    assert dig.output_digest(alice.outputs_bytes).hex() == expected["digests"][
        "alice_output_digest_hex"
    ]
    assert dig.state_digest(1, bob_before).hex() == expected["digests"][
        "bob_before_state_digest_hex"
    ]
    assert dig.output_digest(bob.outputs_bytes).hex() == expected["digests"][
        "bob_output_digest_hex"
    ]


def test_transition_rejects_wrong_direction_and_tampered_binding():
    v = _load("full_braid_sm_round_001.json")
    inputs = v["inputs"]
    material = sm.KeygenMaterial(
        dk=bytes.fromhex(inputs["keygen_dk_hex"]),
        header=bytes.fromhex(inputs["keygen_header_hex"]),
        ek_vector=bytes.fromhex(inputs["keygen_ek_vector_hex"]),
    )
    alice_before = bytes.fromhex(inputs["alice_before_hex"])
    bob_before = bytes.fromhex(inputs["bob_before_hex"])
    send_env = bytes.fromhex(inputs["send_env_hex"])
    bob_env = bytes.fromhex(inputs["receive_env_hex"])

    # Alice Send with B2A (should be A2B)
    bad_send = bytearray(bytes.fromhex(inputs["send_input_hex"]))
    bad_send[11] = state.DIR_B2A
    with pytest.raises(ValueError, match="role/op/direction"):
        sm.transition_prepare(alice_before, bytes(bad_send), send_env, material)

    # Bob Receive with B2A (should be A2B)
    bad_recv = bytearray(bytes.fromhex(inputs["receive_input_hex"]))
    bad_recv[11] = state.DIR_B2A
    with pytest.raises(ValueError, match="role/op/direction"):
        sm.transition_prepare(bob_before, bytes(bad_recv), bob_env)

    # Tampered binding on otherwise-valid receive (after direction stays A2B)
    recv = bytearray(bytes.fromhex(inputs["receive_input_hex"]))
    # Frame starts after object_digest; flip last binding byte inside RVBC1.
    # Layout: ... od(32) + frame_len(4) + frame ...
    # Easier: decode, flip binding, re-encode frame into a fresh RVBI1.
    good = wire.decode_rvbi1(bytes.fromhex(inputs["receive_input_hex"]))
    frame = wire.decode_rvbc1(good.frame)
    flipped = bytearray(frame.binding)
    flipped[0] ^= 0x01
    tampered = wire.Rvbc1(
        epoch=frame.epoch,
        chunk_type=frame.chunk_type,
        index=frame.index,
        payload=frame.payload,
        binding=bytes(flipped),
    )
    tampered_input = wire.Rvbi1(
        op=wire.OP_RECEIVE,
        direction=state.DIR_A2B,
        object_digest=good.object_digest,
        frame=wire.encode_rvbc1(tampered),
        mutation=wire.Rvbm1.no_aead(),
    )
    with pytest.raises(ValueError, match="binding digest mismatch"):
        sm.transition_prepare(
            bob_before, wire.encode_rvbi1(tampered_input), bob_env
        )


def test_rvfb1_rejects_orphan_bitmap_bit():
    v = _load("full_braid_sm_round_001.json")
    bob = state.decode_rvfb1(bytes.fromhex(v["inputs"]["bob_before_hex"]))
    inbound = bob.inbound_sets[0]
    # Set bit 0 without adding a chunk → orphan.
    bitmap = bytearray(inbound.bitmap)
    bitmap[0] |= 0x01
    inbound.bitmap = bytes(bitmap)
    with pytest.raises(ValueError, match="orphan bit"):
        state.encode_rvfb1(bob)


def test_full_exchange_aead_checkpoints_replay_in_python():
    vector = _load("full_braid_full_exchange_2pq_2dh_001.json")
    checkpoints = vector["aead_checkpoints"]
    assert len(checkpoints) == vector["counts"]["aead_promotions"] == 4

    def tlv_value(decoded: state.Rvfb1State, tag: int) -> bytes:
        return next(entry.value for entry in decoded.tlvs if entry.tag == tag)

    # The vector intentionally does not duplicate ML-KEM shared-secret fields.
    # Derive each honest encapsulation secret from the send checkpoint's
    # header + coins, and retain only Encaps1's opaque polynomial outputs as
    # the same lab boundary oracle used by the existing Task-11 reference.
    material_by_name = {}
    shared_secret_by_epoch = {}
    for checkpoint in checkpoints:
        before = state.decode_rvfb1(bytes.fromhex(checkpoint["before_hex"]))
        inp = wire.decode_rvbi1(bytes.fromhex(checkpoint["input_hex"]))
        env = wire.decode_rvbe1(bytes.fromhex(checkpoint["env_hex"]))
        if inp.op != wire.OP_SEND:
            continue
        header = tlv_value(before, 2) + tlv_value(before, 3)
        shared_secret = sm.mlkem_encaps_shared_secret(header, env.encaps_coins)
        expected_candidate = state.decode_rvfb1(
            bytes.fromhex(checkpoint["expected"]["candidate_hex"])
        )
        material_by_name[checkpoint["name"]] = sm.PromoteMaterial(
            shared_secret=shared_secret,
            encaps_state=tlv_value(expected_candidate, 5),
            ct1=tlv_value(expected_candidate, 6),
        )
        shared_secret_by_epoch[before.prefix.braid_agent_epoch] = shared_secret

    output_epochs = []
    for checkpoint in checkpoints:
        name = checkpoint["name"]
        before_bytes = bytes.fromhex(checkpoint["before_hex"])
        input_bytes = bytes.fromhex(checkpoint["input_hex"])
        env_bytes = bytes.fromhex(checkpoint["env_hex"])
        before = state.decode_rvfb1(before_bytes)
        inp = wire.decode_rvbi1(input_bytes)
        env = wire.decode_rvbe1(env_bytes)
        assert state.encode_rvfb1(before) == before_bytes
        assert wire.encode_rvbi1(inp) == input_bytes
        assert wire.encode_rvbe1(env) == env_bytes
        assert inp.mutation.needs_aead == 1

        material = material_by_name.get(name)
        if material is None:
            material = sm.PromoteMaterial(
                shared_secret=shared_secret_by_epoch[before.prefix.braid_agent_epoch]
            )

        result = sm.transition(
            before_bytes,
            input_bytes,
            env_bytes,
            promote_material=material,
        )
        expected = checkpoint["expected"]
        assert result.disposition == expected["disposition"], name
        assert result.candidate_bytes.hex() == expected["candidate_hex"], name
        assert (
            result.frame_bytes.hex() if result.frame_bytes is not None else None
        ) == expected["frame_hex"], name
        assert (
            result.ch_out_bytes.hex() if result.ch_out_bytes is not None else None
        ) == expected["ch_out_hex"], name
        assert (
            result.sealed_ct.hex() if result.sealed_ct is not None else None
        ) == expected["sealed_ct_hex"], name

        decoded = state.decode_rvfb1(result.candidate_bytes)
        prefix = expected["prefix"]
        assert decoded.prefix.agent == prefix["agent"], name
        assert decoded.prefix.braid_agent_epoch == prefix["braid_agent_epoch"], name
        assert decoded.prefix.auth_root.hex() == prefix["auth_root_hex"], name

        tr = state.decode_rvft1(decoded.tr_bytes)
        ec = expected["ec"]
        assert tr.ec_rk.hex() == ec["ec_rk_hex"], name
        assert tr.ec_dhs_pub.hex() == ec["ec_dhs_pub_hex"], name
        assert tr.ec_dhr_pub.hex() == ec["ec_dhr_pub_hex"], name
        assert tr.ec_dhr_present == ec["ec_dhr_present"], name
        assert tr.ec_ck_send_present == ec["ec_ck_send_present"], name
        assert tr.ec_ck_recv_present == ec["ec_ck_recv_present"], name
        assert tr.ec_ns == ec["ec_ns"], name
        assert tr.ec_nr == ec["ec_nr"], name
        assert tr.ec_pn == ec["ec_pn"], name

        meta = expected["meta"]
        assert result.meta.sending_epoch == meta["sending_epoch"], name
        assert result.meta.receiving_epoch == meta["receiving_epoch"], name
        assert result.meta.output_key_epoch == meta["output_key_epoch"], name
        assert result.meta.flags == meta["flags"], name

        prepared = sm.transition_prepare(
            before_bytes,
            input_bytes,
            env_bytes,
            promote_material=material,
        )
        assert prepared.candidate_bytes.hex() == expected["prepared_candidate_hex"], name
        assert prepared.outputs_bytes.hex() == expected["rvbo1_hex"], name
        assert prepared.intent_bytes.hex() == expected["rvbj1_hex"], name
        assert prepared.meta.sending_epoch == meta["sending_epoch"], name
        assert prepared.meta.receiving_epoch == meta["receiving_epoch"], name
        assert prepared.meta.output_key_epoch == meta["output_key_epoch"], name
        assert prepared.meta.flags == meta["flags"], name
        assert prepared.meta.terminal_reason == meta["terminal_reason"], name
        assert prepared.meta.pending_phase == meta["pending_phase"], name
        assert prepared.meta.transition_id.hex() == meta["transition_id_hex"], name
        output_epochs.append(result.meta.output_key_epoch)

    assert sorted(set(output_epochs)) == [1, 2]


def test_replay_window_is_fifo_and_never_wedges():
    v = _load("full_braid_sm_round_001.json")
    inputs = v["inputs"]
    material = sm.KeygenMaterial(
        dk=bytes.fromhex(inputs["keygen_dk_hex"]),
        header=bytes.fromhex(inputs["keygen_header_hex"]),
        ek_vector=bytes.fromhex(inputs["keygen_ek_vector_hex"]),
    )
    alice = state.decode_rvfb1(bytes.fromhex(inputs["alice_before_hex"]))
    # A full window in commit order (newest last), deliberately unsorted.
    alice.replays = [
        state.ReplayRecord(
            transition_id=bytes([255 - i]) * 32,
            execution_digest=bytes([i]) * 32,
            output_digest=bytes(32),
            output_len=14,
            flags=0,
        )
        for i in range(sm.MAX_REPLAYS)
    ]
    full = state.encode_rvfb1(alice)
    assert state.decode_rvfb1(full).replays == alice.replays

    prepared = sm.transition_prepare(
        full,
        bytes.fromhex(inputs["send_input_hex"]),
        bytes.fromhex(inputs["send_env_hex"]),
        keygen_material=material,
    )
    replays = state.decode_rvfb1(prepared.candidate_bytes).replays
    assert len(replays) == sm.MAX_REPLAYS
    assert replays[:-1] == alice.replays[1:]  # oldest evicted
    assert replays[-1].transition_id == prepared.meta.transition_id

    alice.replays = alice.replays[:2] + [alice.replays[0]]
    with pytest.raises(ValueError, match="duplicate transition_id"):
        state.encode_rvfb1(alice)


def test_journal_input_digest_redacts_seal_plaintext():
    vector = _load("full_braid_full_exchange_2pq_2dh_001.json")
    send = next(cp for cp in vector["aead_checkpoints"] if cp["op"] == wire.OP_SEND)
    inp = wire.decode_rvbi1(bytes.fromhex(send["input_hex"]))
    assert inp.mutation.mode == wire.MODE_SEAL_COMPARE and inp.mutation.body
    persisted = sm.journal_input_digest(inp)
    assert persisted != dig.input_digest(bytes.fromhex(send["input_hex"]))
    guess = sm.dataclasses.replace(
        inp, mutation=sm.dataclasses.replace(inp.mutation, body=b"\x00" * len(inp.mutation.body))
    )
    assert sm.journal_input_digest(guess) == persisted
    rvbj1 = bytes.fromhex(send["expected"]["rvbj1_hex"])
    # RVBJ1 header: magic(8) schema(2) sid(32) role dir kind rsv(4) gen(8) tid exec input...
    input_off = 8 + 2 + 32 + 4 + 8 + 32 + 32
    assert rvbj1[input_off : input_off + 32] == persisted


def test_rvfi1_init_vector_is_computed_by_python():
    v = _load("full_braid_rvfi1_init_001.json")
    for role in ("alice", "bob"):
        init = bytes.fromhex(v["inputs"][f"{role}_rvfi1_hex"])
        assert sm.init_write(init).hex() == v["expected"][f"{role}_rvfb1_hex"], role
    bob = state.decode_rvfb1(bytes.fromhex(v["expected"]["bob_rvfb1_hex"]))
    bob_tr = state.decode_rvft1(bob.tr_bytes)
    # Bob ratchets with his SPK; SK_ec (0x11…) is the root, never a DH key.
    assert bob_tr.ec_rk == bytes([0x11]) * 32
    assert bob_tr.ec_dhs_priv != bob_tr.ec_rk
