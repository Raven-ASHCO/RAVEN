#!/usr/bin/env python3
"""Generate Full Braid Slice 2 shared-vector freeze (Task 11; production-disabled)."""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from raven_protocol import full_braid_digest as dig
from raven_protocol import full_braid_wire as wire

REPO = pathlib.Path(__file__).resolve().parents[2]
OUT = REPO / "shared-vectors/rvn1/atsam"
CLOCK = 1_700_000_000_000
PROFILE = "ATSAM/hybrid-ratchet/v2/full-braid"


def write(name: str, obj: dict) -> None:
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def vec(name: str, desc: str, inputs: dict, expected: dict, **extra) -> dict:
    return {
        "name": name,
        "description": desc,
        "protocol_version": "rvn1",
        "profile": PROFILE,
        "deterministic": True,
        "production_enabled": False,
        "lab_only": True,
        "inputs": inputs,
        "expected": expected,
        **extra,
    }


def main() -> None:
    session_id = bytes([0x55]) * 32
    before_state = bytes([0x44]) * 32
    source = b"full-braid-send-source-v1"

    # Digests KAT (fixed synthetic inputs; no SM)
    rvfb1_stub = b"rvfb1-body"
    rvbi_stub = b"rvbi"
    rvbe_stub = b"rvbe"
    rvbo_empty = wire.encode_empty_rvbo1()
    exec_d = dig.execution_digest(rvbi_stub, rvbe_stub)
    write(
        "full_braid_digests_001.json",
        vec(
            "Full Braid digests §2.3",
            "Domain-separated digests + empty RVBO1 + domain catalog",
            {
                "schema_rev": 1,
                "rvfb1_stub_hex": rvfb1_stub.hex(),
                "rvbi_stub_hex": rvbi_stub.hex(),
                "rvbe_stub_hex": rvbe_stub.hex(),
                "session_id_hex": session_id.hex(),
                "role": 0,
                "direction": 0,
                "generation": 0,
                "before_state_digest_hex": before_state.hex(),
                "source_bytes_hex": source.hex(),
                "chunk_epoch": 1,
                "chunk_type": 1,
                "chunk_index": 0,
                "chunk_payload_hex": bytes(32).hex(),
                "endpoint_object_hex": b"endpoint-object".hex(),
                "source_kind": 1,
            },
            {
                "domains": dig.domain_catalog(),
                "state_digest_hex": dig.state_digest(1, rvfb1_stub).hex(),
                "input_digest_hex": dig.input_digest(rvbi_stub).hex(),
                "execution_digest_hex": exec_d.hex(),
                "output_digest_empty_rvbo1_hex": dig.output_digest(rvbo_empty).hex(),
                "empty_rvbo1_hex": rvbo_empty.hex(),
                "empty_rvbo1_len": len(rvbo_empty),
                "object_digest_hex": dig.object_digest(b"endpoint-object").hex(),
                "send_source_digest_hex": dig.send_source_digest(source).hex(),
                "braid_object_digest_hex": dig.braid_object_digest(
                    session_id, 0, 1, 1, source
                ).hex(),
                "binding_digest_hex": dig.binding_digest(
                    0, 1, 1, 0, bytes(32), session_id
                ).hex(),
                "transition_id_digest_hex": dig.transition_id_digest(
                    session_id, 0, 0, 0, exec_d, before_state
                ).hex(),
            },
        ),
    )
    assert len(rvbo_empty) == 14

    # Send / receive round (wire + digests; needs_aead=0)
    env = wire.Rvbe1.default_caps(CLOCK).with_lab_trust()
    env_wire = wire.encode_rvbe1(env)
    assert env_wire[8:10] == (2).to_bytes(2, "big")

    send = wire.Rvbi1(op=wire.OP_SEND, direction=0, mutation=wire.Rvbm1.no_aead())
    send_wire = wire.encode_rvbi1(send)

    frame = wire.make_receive_frame(session_id=session_id, direction=0)
    obj_d = dig.object_digest(b"full-braid/lab-endpoint-object")
    recv = wire.Rvbi1(
        op=wire.OP_RECEIVE,
        direction=0,
        object_digest=obj_d,
        frame=frame,
        mutation=wire.Rvbm1.no_aead(),
    )
    recv_wire = wire.encode_rvbi1(recv)

    # Evidence byte flip changes execution_digest
    flipped = bytearray(env_wire)
    trust_body_off = len(flipped) - 4 - wire.ADMITTED_TRUST_LEN
    flipped[trust_body_off] ^= 0x01
    exec_base = dig.execution_digest(send_wire, env_wire)
    exec_flip = dig.execution_digest(send_wire, bytes(flipped))
    assert exec_base != exec_flip

    schema1 = wire.encode_superseded_rvbe1_schema1(CLOCK)
    try:
        wire.decode_rvbe1(schema1)
        raise AssertionError("schema1 must reject")
    except ValueError:
        pass

    write(
        "full_braid_send_receive_round_001.json",
        vec(
            "Full Braid Send/Receive wire round",
            "RVBI1 send+receive (needs_aead=0), RVBE1 schema=2 with admitted_trust, digests",
            {
                "clock": CLOCK,
                "session_id_hex": session_id.hex(),
                "endpoint_object_hex": b"full-braid/lab-endpoint-object".hex(),
            },
            {
                "rvbe1_schema": 2,
                "rvbe1_wire_hex": env_wire.hex(),
                "rvbe1_wire_len": len(env_wire),
                "admitted_trust_len": wire.ADMITTED_TRUST_LEN,
                "send_rvbi1_hex": send_wire.hex(),
                "receive_rvbi1_hex": recv_wire.hex(),
                "receive_frame_hex": frame.hex(),
                "object_digest_hex": obj_d.hex(),
                "empty_rvbo1_hex": rvbo_empty.hex(),
                "send_input_digest_hex": dig.input_digest(send_wire).hex(),
                "receive_input_digest_hex": dig.input_digest(recv_wire).hex(),
                "send_execution_digest_hex": exec_base.hex(),
                "receive_execution_digest_hex": dig.execution_digest(
                    recv_wire, env_wire
                ).hex(),
                "output_digest_empty_hex": dig.output_digest(rvbo_empty).hex(),
                "trust_flip_execution_digest_hex": exec_flip.hex(),
                "superseded_rvbe1_schema1_hex": schema1.hex(),
            },
            notes=[
                "RVBE1 schema_rev=2 required; schema 1 superseded / PARSE",
                "needs_aead=0 round only — AEAD confirm vectors remain Rust Task 10",
            ],
        ),
    )

    # Wire negatives (checked readers + cap/contract validation)
    truncated = env_wire[:-1]
    wrong_len = bytearray(env_wire)
    len_off = len(wrong_len) - 4 - wire.ADMITTED_TRUST_LEN - 2
    wrong_len[len_off : len_off + 2] = (64).to_bytes(2, "big")
    env_base = wire.encode_rvbe1(wire.Rvbe1.default_caps(CLOCK))
    cap_chunks_bad = bytearray(env_wire)
    cap_chunks_bad[22:26] = (65).to_bytes(4, "big")
    keygen_bad = bytearray(env_base)
    keygen_bad[38:40] = (1).to_bytes(2, "big")
    keygen_bad.insert(40, 0x42)

    send_op2 = bytearray(send_wire)
    send_op2[10] = 2

    send_od = bytearray(send_wire)
    # od_present at offset 18; insert 32-byte digest before mutation (offset 20)
    send_od[18] = 1
    send_od[19] = 0
    send_od[20:20] = bytes([0x99]) * 32

    wire_neg_cases = [
        {
            "name": "rvbe1_schema1",
            "decoder": "rvbe1",
            "wire_hex": schema1.hex(),
            "expected_error": "rvbe1 bad schema",
        },
        {
            "name": "rvbe1_truncated",
            "decoder": "rvbe1",
            "wire_hex": truncated.hex(),
            "expected_error": "truncated",
        },
        {
            "name": "rvbe1_wrong_trust_len",
            "decoder": "rvbe1",
            "wire_hex": bytes(wrong_len).hex(),
            "expected_error": "rvbe1 admitted_trust_len",
        },
        {
            "name": "rvbe1_cap_chunks_65",
            "decoder": "rvbe1",
            "wire_hex": bytes(cap_chunks_bad).hex(),
            "expected_error": "rvbe1 cap_chunks",
        },
        {
            "name": "rvbe1_keygen_seed_len_1",
            "decoder": "rvbe1",
            "wire_hex": bytes(keygen_bad).hex(),
            "expected_error": "rvbe1 keygen_seed len",
        },
        {
            "name": "rvbi1_op_2",
            "decoder": "rvbi1",
            "wire_hex": bytes(send_op2).hex(),
            "expected_error": "rvbi1 op",
        },
        {
            "name": "rvbi1_send_object_digest",
            "decoder": "rvbi1",
            "wire_hex": bytes(send_od).hex(),
            "expected_error": "rvbi1 send field contract",
        },
    ]

    write(
        "full_braid_wire_negatives_001.json",
        vec(
            "Full Braid wire negatives",
            "RVBE1/RVBI1 decode must reject with exact ValueError substrings",
            {"cases": wire_neg_cases},
            {"case_count": len(wire_neg_cases)},
        ),
    )

    write(
        "full_braid_rvbe1_negatives_001.json",
        vec(
            "RVBE1 schema=2 negatives",
            "old-schema / truncated / wrong admitted_trust_len must PARSE-fail",
            {
                "schema1_wire_hex": schema1.hex(),
                "truncated_wire_hex": truncated.hex(),
                "wrong_trust_len_wire_hex": bytes(wrong_len).hex(),
            },
            {
                "reject_reasons": [
                    "rvbe1 bad schema",
                    "truncated",
                    "rvbe1 admitted_trust_len",
                ]
            },
        ),
    )

    # --- SM round: Python independently computes transition_prepare ---
    from raven_protocol import full_braid_state as fbstate
    from raven_protocol import full_braid_transition as sm

    oracle_path = pathlib.Path(__file__).resolve().parent / "fixtures" / "full_braid_sm_round_oracle.json"
    if not oracle_path.exists():
        raise SystemExit(
            "missing fixtures/full_braid_sm_round_oracle.json"
        )
    oracle = json.loads(oracle_path.read_text())
    material = sm.KeygenMaterial(
        dk=bytes.fromhex(oracle["DK"]),
        header=bytes.fromhex(oracle["HEADER"]),
        ek_vector=bytes.fromhex(oracle["EK"]),
    )
    alice_before = bytes.fromhex(oracle["ALICE_BEFORE"])
    bob_before = bytes.fromhex(oracle["BOB_BEFORE"])
    send_in = bytes.fromhex(oracle["SEND_IN"])
    send_env = bytes.fromhex(oracle["ENV"])
    recv_in = bytes.fromhex(oracle["RECV_IN"])
    bob_env = bytes.fromhex(oracle["BOB_ENV"])

    alice = sm.transition_prepare(alice_before, send_in, send_env, material)
    bob = sm.transition_prepare(bob_before, recv_in, bob_env)
    # Self-check vs Rust oracle (generator must not drift)
    assert alice.candidate_bytes.hex() == oracle["ALICE_CAND"]
    assert alice.outputs_bytes.hex() == oracle["ALICE_OUT"]
    assert alice.intent_bytes.hex() == oracle["ALICE_INTENT"]
    assert bob.candidate_bytes.hex() == oracle["BOB_CAND"]
    assert bob.outputs_bytes.hex() == oracle["BOB_OUT"]
    assert bob.intent_bytes.hex() == oracle["BOB_INTENT"]

    write(
        "full_braid_sm_round_001.json",
        vec(
            "Full Braid SM Send/Receive transition_prepare round",
            "Python-computed KeysUnsampled Send + NoHeaderReceived HDR Receive",
            {
                "alice_before_hex": alice_before.hex(),
                "bob_before_hex": bob_before.hex(),
                "send_input_hex": send_in.hex(),
                "send_env_hex": send_env.hex(),
                "receive_input_hex": recv_in.hex(),
                "receive_env_hex": bob_env.hex(),
                "keygen_dk_hex": material.dk.hex(),
                "keygen_header_hex": material.header.hex(),
                "keygen_ek_vector_hex": material.ek_vector.hex(),
                "keygen_seed_hex": bytes([0x5A] * 64).hex(),
            },
            {
                "alice_candidate_hex": alice.candidate_bytes.hex(),
                "alice_rvbo1_hex": alice.outputs_bytes.hex(),
                "alice_intent_hex": alice.intent_bytes.hex(),
                "alice_meta": alice.meta.as_dict(),
                "alice_agent": fbstate.AGENT_KEYS_SAMPLED,
                "bob_candidate_hex": bob.candidate_bytes.hex(),
                "bob_rvbo1_hex": bob.outputs_bytes.hex(),
                "bob_intent_hex": bob.intent_bytes.hex(),
                "bob_meta": bob.meta.as_dict(),
                "bob_agent": fbstate.AGENT_NO_HEADER_RECEIVED,
                "digests": {
                    "alice_before_state_digest_hex": dig.state_digest(1, alice_before).hex(),
                    "alice_output_digest_hex": dig.output_digest(alice.outputs_bytes).hex(),
                    "bob_before_state_digest_hex": dig.state_digest(1, bob_before).hex(),
                    "bob_output_digest_hex": dig.output_digest(bob.outputs_bytes).hex(),
                },
            },
            notes=[
                "Keygen materials are lab oracle for seed 0x5A*64; Authenticator+SPQR systematic computed in Python",
                "Bob receive Accept inserts HDR chunk 0; agent stays NoHeaderReceived until N=3",
            ],
        ),
    )

    # --- RVFI1 init: Python computes the initial RVFB1 for both roles ---
    from raven_protocol import hybrid_ratchet_v2_tr as ec

    def rvfi1(role: int, role_material: bytes, bob_spk_pub: bytes) -> bytes:
        return (
            sm.RVFI1_MAGIC
            + (1).to_bytes(2, "big")
            + bytes([0x53]) * 32
            + bytes([role, 0])
            + bytes([0x11]) * 32
            + bytes([0x22]) * 32
            + bob_spk_pub
            + role_material
            + bytes(4)
        )

    alice_eph_priv = bytes([0x44]) * 32
    bob_spk_priv = bytes([0x33]) * 32
    bob_spk_pub = ec.x25519_public(bob_spk_priv)
    alice_init = rvfi1(0, alice_eph_priv, bob_spk_pub)
    bob_init = rvfi1(1, bob_spk_priv, bob_spk_pub)
    alice_state = sm.init_write(alice_init)
    bob_state = sm.init_write(bob_init)
    alice_tr = fbstate.decode_rvft1(fbstate.decode_rvfb1(alice_state).tr_bytes)
    bob_tr = fbstate.decode_rvft1(fbstate.decode_rvfb1(bob_state).tr_bytes)
    assert alice_tr.ec_dhs_pub == ec.x25519_public(alice_eph_priv)
    assert bob_tr.ec_dhs_pub == bob_spk_pub and bob_tr.ec_rk == bytes([0x11]) * 32
    write(
        "full_braid_rvfi1_init_001.json",
        vec(
            "Full Braid RVFI1 init",
            "Python-computed initial RVFB1 for Alice and Bob: SK_ec is only the EC "
            "root; Alice ratchets with her ephemeral, Bob with his SPK (§3.3)",
            {
                "alice_rvfi1_hex": alice_init.hex(),
                "bob_rvfi1_hex": bob_init.hex(),
            },
            {
                "alice_rvfb1_hex": alice_state.hex(),
                "bob_rvfb1_hex": bob_state.hex(),
                "alice_ec_dhs_pub_hex": alice_tr.ec_dhs_pub.hex(),
                "bob_ec_dhs_pub_hex": bob_tr.ec_dhs_pub.hex(),
            },
        ),
    )

    print("wrote full_braid_* vectors under", OUT)


if __name__ == "__main__":
    main()
