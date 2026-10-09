//! Shared-vector parity for Full Braid Task 11 (lab-only).

use crate::hybrid_ratchet_v2_full_braid::digest::{
    binding_digest, braid_object_digest, execution_digest, input_digest, object_digest,
    output_digest, send_source_digest, state_digest, transition_id_digest,
};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbe1::{decode_rvbe1, encode_rvbe1, RVBE1_SCHEMA};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbi1::{decode_rvbi1, encode_rvbi1};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbo1::encode_empty_rvbo1;
use serde_json::Value;
use std::path::PathBuf;

fn root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.join("shared-vectors/rvn1/atsam")
}

fn load(name: &str) -> Value {
    let path = root().join(name);
    serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
    )
    .unwrap()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn hex32(s: &str) -> [u8; 32] {
    let v = hex_bytes(s);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

#[test]
fn shared_vector_digests_001() {
    let v = load("full_braid_digests_001.json");
    let inputs = &v["inputs"];
    let expected = &v["expected"];

    let rvfb1 = hex_bytes(inputs["rvfb1_stub_hex"].as_str().unwrap());
    let rvbi = hex_bytes(inputs["rvbi_stub_hex"].as_str().unwrap());
    let rvbe = hex_bytes(inputs["rvbe_stub_hex"].as_str().unwrap());
    let sid = hex32(inputs["session_id_hex"].as_str().unwrap());
    let before = hex32(inputs["before_state_digest_hex"].as_str().unwrap());
    let source = hex_bytes(inputs["source_bytes_hex"].as_str().unwrap());
    let payload = hex_bytes(inputs["chunk_payload_hex"].as_str().unwrap());
    let endpoint = hex_bytes(inputs["endpoint_object_hex"].as_str().unwrap());

    assert_eq!(
        hex::encode(state_digest(
            inputs["schema_rev"].as_u64().unwrap() as u16,
            &rvfb1
        )),
        expected["state_digest_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(input_digest(&rvbi)),
        expected["input_digest_hex"].as_str().unwrap()
    );
    let exec = execution_digest(&rvbi, &rvbe);
    assert_eq!(
        hex::encode(exec),
        expected["execution_digest_hex"].as_str().unwrap()
    );
    let empty = encode_empty_rvbo1();
    assert_eq!(empty.len(), 14);
    assert_eq!(
        hex::encode(&empty),
        expected["empty_rvbo1_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(output_digest(&empty)),
        expected["output_digest_empty_rvbo1_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(object_digest(&endpoint)),
        expected["object_digest_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(send_source_digest(&source)),
        expected["send_source_digest_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(braid_object_digest(
            &sid,
            inputs["direction"].as_u64().unwrap() as u8,
            1,
            inputs["source_kind"].as_u64().unwrap() as u8,
            &source
        )),
        expected["braid_object_digest_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(binding_digest(
            inputs["direction"].as_u64().unwrap() as u8,
            inputs["chunk_epoch"].as_u64().unwrap(),
            inputs["chunk_type"].as_u64().unwrap() as u8,
            inputs["chunk_index"].as_u64().unwrap() as u32,
            &payload,
            &sid
        )),
        expected["binding_digest_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(transition_id_digest(
            &sid,
            inputs["role"].as_u64().unwrap() as u8,
            inputs["direction"].as_u64().unwrap() as u8,
            inputs["generation"].as_u64().unwrap(),
            &exec,
            &before
        )),
        expected["transition_id_digest_hex"].as_str().unwrap()
    );
}

#[test]
fn shared_vector_send_receive_round_001() {
    let v = load("full_braid_send_receive_round_001.json");
    let expected = &v["expected"];
    assert_eq!(
        expected["rvbe1_schema"].as_u64().unwrap(),
        u64::from(RVBE1_SCHEMA)
    );

    let env_wire = hex_bytes(expected["rvbe1_wire_hex"].as_str().unwrap());
    assert_eq!(env_wire[8..10], RVBE1_SCHEMA.to_be_bytes());
    let env = decode_rvbe1(&env_wire).unwrap();
    assert!(env.admitted_trust.is_some());
    assert_eq!(encode_rvbe1(&env).unwrap(), env_wire);

    let send_wire = hex_bytes(expected["send_rvbi1_hex"].as_str().unwrap());
    let recv_wire = hex_bytes(expected["receive_rvbi1_hex"].as_str().unwrap());
    assert_eq!(
        encode_rvbi1(&decode_rvbi1(&send_wire).unwrap()).unwrap(),
        send_wire
    );
    assert_eq!(
        encode_rvbi1(&decode_rvbi1(&recv_wire).unwrap()).unwrap(),
        recv_wire
    );

    assert_eq!(
        hex::encode(input_digest(&send_wire)),
        expected["send_input_digest_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(input_digest(&recv_wire)),
        expected["receive_input_digest_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(execution_digest(&send_wire, &env_wire)),
        expected["send_execution_digest_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(execution_digest(&recv_wire, &env_wire)),
        expected["receive_execution_digest_hex"].as_str().unwrap()
    );

    let mut flipped = env_wire.clone();
    let trust_off = flipped.len() - 4 - 128;
    flipped[trust_off] ^= 0x01;
    assert_eq!(
        hex::encode(execution_digest(&send_wire, &flipped)),
        expected["trust_flip_execution_digest_hex"]
            .as_str()
            .unwrap()
    );
    assert_ne!(
        execution_digest(&send_wire, &env_wire),
        execution_digest(&send_wire, &flipped)
    );
}

#[test]
fn shared_vector_rvbe1_negatives_001() {
    let v = load("full_braid_rvbe1_negatives_001.json");
    let inputs = &v["inputs"];
    for key in [
        "schema1_wire_hex",
        "truncated_wire_hex",
        "wrong_trust_len_wire_hex",
    ] {
        let wire = hex_bytes(inputs[key].as_str().unwrap());
        assert!(
            decode_rvbe1(&wire).is_err(),
            "expected PARSE reject for {key}"
        );
    }
}

#[test]
fn shared_vector_wire_negatives_001() {
    let v = load("full_braid_wire_negatives_001.json");
    for case in v["inputs"]["cases"].as_array().unwrap() {
        let wire_hex = case["wire_hex"].as_str().unwrap();
        let decoder = case["decoder"].as_str().unwrap();
        let expected = case["expected_error"].as_str().unwrap();
        let wire = hex_bytes(wire_hex);
        let err = match decoder {
            "rvbe1" => decode_rvbe1(&wire).err(),
            "rvbi1" => decode_rvbi1(&wire).err(),
            other => panic!("unknown decoder {other}"),
        };
        let msg = err.unwrap_or_else(|| panic!("expected reject for {}", case["name"]));
        assert!(
            msg.contains(expected),
            "case {}: expected substring {:?} in {:?}",
            case["name"],
            expected,
            msg
        );
    }
}

#[test]
fn shared_vector_sm_round_001_runs_transition_prepare() {
    use crate::hybrid_ratchet_v2_full_braid::pipeline::transition_prepare;
    use crate::hybrid_ratchet_v2_full_braid::state_codec::decode_rvfb1;
    use crate::hybrid_ratchet_v2_full_braid::transition::LabCrypto;
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbo1::decode_rvbo1;

    let v = load("full_braid_sm_round_001.json");
    let inputs = &v["inputs"];
    let expected = &v["expected"];

    let alice_before = hex_bytes(inputs["alice_before_hex"].as_str().unwrap());
    let send_in = hex_bytes(inputs["send_input_hex"].as_str().unwrap());
    let send_env = hex_bytes(inputs["send_env_hex"].as_str().unwrap());
    let mut crypto = LabCrypto::default();
    let alice = transition_prepare(&alice_before, &send_in, &send_env, &mut crypto).unwrap();
    assert_eq!(
        hex::encode(&alice.candidate_bytes),
        expected["alice_candidate_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&alice.outputs_bytes),
        expected["alice_rvbo1_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&alice.intent_bytes),
        expected["alice_intent_hex"].as_str().unwrap()
    );
    assert_eq!(
        decode_rvfb1(&alice.candidate_bytes).unwrap().prefix.agent,
        expected["alice_agent"].as_u64().unwrap() as u8
    );
    assert_eq!(decode_rvbo1(&alice.outputs_bytes).unwrap().frames.len(), 1);

    let bob_before = hex_bytes(inputs["bob_before_hex"].as_str().unwrap());
    let recv_in = hex_bytes(inputs["receive_input_hex"].as_str().unwrap());
    let bob_env = hex_bytes(inputs["receive_env_hex"].as_str().unwrap());
    let mut bob_crypto = LabCrypto::default();
    let bob = transition_prepare(&bob_before, &recv_in, &bob_env, &mut bob_crypto).unwrap();
    assert_eq!(
        hex::encode(&bob.candidate_bytes),
        expected["bob_candidate_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&bob.outputs_bytes),
        expected["bob_rvbo1_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&bob.intent_bytes),
        expected["bob_intent_hex"].as_str().unwrap()
    );
    assert_eq!(
        decode_rvfb1(&bob.candidate_bytes).unwrap().prefix.agent,
        expected["bob_agent"].as_u64().unwrap() as u8
    );
    assert!(decode_rvbo1(&bob.outputs_bytes).unwrap().is_empty14());

    let alice_meta = &expected["alice_meta"];
    assert_eq!(
        alice.meta.sending_epoch,
        alice_meta["sending_epoch"].as_u64().unwrap()
    );
    assert_eq!(
        alice.meta.receiving_epoch,
        alice_meta["receiving_epoch"].as_u64().unwrap()
    );
    assert_eq!(
        alice.meta.output_key_epoch,
        alice_meta["output_key_epoch"].as_u64().unwrap()
    );
    assert_eq!(
        alice.meta.flags,
        alice_meta["flags"].as_u64().unwrap() as u32
    );
    assert_eq!(
        alice.meta.terminal_reason,
        alice_meta["terminal_reason"].as_u64().unwrap() as u16
    );
    assert_eq!(
        alice.meta.pending_phase,
        alice_meta["pending_phase"].as_u64().unwrap() as u16
    );
    assert_eq!(
        hex::encode(alice.meta.transition_id),
        alice_meta["transition_id_hex"].as_str().unwrap()
    );

    let bob_meta = &expected["bob_meta"];
    assert_eq!(
        bob.meta.sending_epoch,
        bob_meta["sending_epoch"].as_u64().unwrap()
    );
    assert_eq!(
        bob.meta.receiving_epoch,
        bob_meta["receiving_epoch"].as_u64().unwrap()
    );
    assert_eq!(
        bob.meta.output_key_epoch,
        bob_meta["output_key_epoch"].as_u64().unwrap()
    );
    assert_eq!(bob.meta.flags, bob_meta["flags"].as_u64().unwrap() as u32);
    assert_eq!(
        bob.meta.terminal_reason,
        bob_meta["terminal_reason"].as_u64().unwrap() as u16
    );
    assert_eq!(
        bob.meta.pending_phase,
        bob_meta["pending_phase"].as_u64().unwrap() as u16
    );
    assert_eq!(
        hex::encode(bob.meta.transition_id),
        bob_meta["transition_id_hex"].as_str().unwrap()
    );
}

#[test]
fn shared_vector_rvfi1_init_001_matches_python_init() {
    use crate::hybrid_ratchet_v2_full_braid::init::init_write;
    use crate::hybrid_ratchet_v2_full_braid::state_codec::decode_rvfb1;

    let v = load("full_braid_rvfi1_init_001.json");
    assert_eq!(v["production_enabled"], false);
    for role in ["alice", "bob"] {
        let init = hex_bytes(v["inputs"][format!("{role}_rvfi1_hex")].as_str().unwrap());
        let state = init_write(&init).unwrap();
        assert_eq!(
            hex::encode(&state),
            v["expected"][format!("{role}_rvfb1_hex")].as_str().unwrap(),
            "{role}"
        );
        assert_eq!(
            hex::encode(decode_rvfb1(&state).unwrap().tr.ec_dhs_pub),
            v["expected"][format!("{role}_ec_dhs_pub_hex")]
                .as_str()
                .unwrap(),
            "{role}"
        );
    }
}

#[test]
fn shared_vector_full_exchange_2pq_2dh_001_replays_aead_checkpoints() {
    use crate::hybrid_ratchet_v2_full_braid::agent::{
        AGENT_EK_SENT_CT1_RECEIVED, AGENT_HEADER_RECEIVED,
    };
    use crate::hybrid_ratchet_v2_full_braid::digest::state_digest;
    use crate::hybrid_ratchet_v2_full_braid::pipeline::transition_prepare;
    use crate::hybrid_ratchet_v2_full_braid::spqr_pin_audit::N_CT1;
    use crate::hybrid_ratchet_v2_full_braid::state_codec::{
        decode_rvfb1, encode_rvfb1, RVFB1_SCHEMA,
    };
    use crate::hybrid_ratchet_v2_full_braid::transition::{transition, Disposition, LabCrypto};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbc1::encode_rvbc1;
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbi1::{OP_RECEIVE, OP_SEND};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::{MODE_OPEN, MODE_SEAL_COMPARE};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvch1::encode_rvch1;
    use sha2::{Digest, Sha256};

    let v = load("full_braid_full_exchange_2pq_2dh_001.json");
    assert_eq!(v["schema"], 1);
    assert_eq!(v["lab_only"], true);
    assert_eq!(v["production_enabled"], false);
    assert_eq!(v["counts"]["pq_epochs"], 2);
    assert_eq!(v["counts"]["aead_promotions"], 4);
    assert_eq!(v["counts"]["dh_ratchets"], 2);

    let checkpoints = v["aead_checkpoints"].as_array().unwrap();
    assert_eq!(checkpoints.len(), 4);
    let mut output_epochs = Vec::new();
    let mut send_count = 0usize;
    let mut receive_count = 0usize;
    let mut prior_send_sealed = None;

    for checkpoint in checkpoints {
        let name = checkpoint["name"].as_str().unwrap();
        let before_bytes = hex_bytes(checkpoint["before_hex"].as_str().unwrap());
        let input_bytes = hex_bytes(checkpoint["input_hex"].as_str().unwrap());
        let env_bytes = hex_bytes(checkpoint["env_hex"].as_str().unwrap());
        let before = decode_rvfb1(&before_bytes).unwrap();
        let input = decode_rvbi1(&input_bytes).unwrap();
        let env = decode_rvbe1(&env_bytes).unwrap();
        assert_eq!(encode_rvfb1(&before).unwrap(), before_bytes, "{name}");
        assert_eq!(encode_rvbi1(&input).unwrap(), input_bytes, "{name}");
        assert_eq!(encode_rvbe1(&env).unwrap(), env_bytes, "{name}");
        assert_eq!(input.mutation.needs_aead, 1, "{name}");
        assert!(env.admitted_trust.is_some(), "{name}");

        match input.op {
            OP_SEND => {
                send_count += 1;
                assert_eq!(before.prefix.agent, AGENT_HEADER_RECEIVED, "{name}");
                assert_eq!(input.mutation.mode, MODE_SEAL_COMPARE, "{name}");
                assert!(env.ec_dh_seed.is_empty(), "{name}");
            }
            OP_RECEIVE => {
                receive_count += 1;
                assert_eq!(before.prefix.agent, AGENT_EK_SENT_CT1_RECEIVED, "{name}");
                assert_eq!(input.mutation.mode, MODE_OPEN, "{name}");
                assert_eq!(env.ec_dh_seed.len(), 32, "{name}");
                // One ciphertext per hybrid key: the receive confirm opens the
                // peer's RVBO1 sealed_ct byte-for-byte (no second seal).
                assert_eq!(
                    prior_send_sealed.as_ref(),
                    Some(&input.mutation.body),
                    "{name}: Receive must open the peer's exact sealed_ct"
                );
            }
            _ => panic!("{name}: invalid operation"),
        }

        let result = transition(&before, &input, &env, &mut LabCrypto::default());
        assert_eq!(result.disposition, Disposition::Accept, "{name}");
        let expected = &checkpoint["expected"];
        assert_eq!(expected["disposition"], "accept");
        assert_eq!(
            hex::encode(encode_rvfb1(&result.candidate).unwrap()),
            expected["candidate_hex"].as_str().unwrap(),
            "{name}: candidate"
        );
        assert_eq!(
            result
                .frame
                .as_ref()
                .map(|frame| hex::encode(encode_rvbc1(frame).unwrap()))
                .as_deref(),
            expected["frame_hex"].as_str(),
            "{name}: frame"
        );
        assert_eq!(
            result
                .ch_out
                .as_ref()
                .map(|ch| hex::encode(encode_rvch1(ch)))
                .as_deref(),
            expected["ch_out_hex"].as_str(),
            "{name}: ch_out"
        );
        assert_eq!(
            result.sealed_ct.as_ref().map(hex::encode).as_deref(),
            expected["sealed_ct_hex"].as_str(),
            "{name}: sealed_ct"
        );

        let prepared = transition_prepare(
            &before_bytes,
            &input_bytes,
            &env_bytes,
            &mut LabCrypto::default(),
        )
        .unwrap_or_else(|code| panic!("{name}: prepare failed status={code}"));
        assert_eq!(
            hex::encode(&prepared.candidate_bytes),
            expected["prepared_candidate_hex"].as_str().unwrap(),
            "{name}: prepared_candidate"
        );
        assert_eq!(
            hex::encode(&prepared.outputs_bytes),
            expected["rvbo1_hex"].as_str().unwrap(),
            "{name}: rvbo1"
        );
        assert_eq!(
            hex::encode(&prepared.intent_bytes),
            expected["rvbj1_hex"].as_str().unwrap(),
            "{name}: rvbj1"
        );

        let meta = &expected["meta"];
        assert_eq!(
            prepared.meta.sending_epoch,
            meta["sending_epoch"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            prepared.meta.receiving_epoch,
            meta["receiving_epoch"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            prepared.meta.output_key_epoch,
            meta["output_key_epoch"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            prepared.meta.flags,
            meta["flags"].as_u64().unwrap() as u32,
            "{name}"
        );
        assert_eq!(
            prepared.meta.terminal_reason,
            meta["terminal_reason"].as_u64().unwrap() as u16,
            "{name}"
        );
        assert_eq!(
            prepared.meta.pending_phase,
            meta["pending_phase"].as_u64().unwrap() as u16,
            "{name}"
        );
        assert_eq!(
            hex::encode(prepared.meta.transition_id),
            meta["transition_id_hex"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            result.meta.sending_epoch, prepared.meta.sending_epoch,
            "{name}: engine/prepare sending_epoch"
        );
        assert_eq!(
            result.meta.receiving_epoch, prepared.meta.receiving_epoch,
            "{name}: engine/prepare receiving_epoch"
        );
        assert_eq!(
            result.meta.output_key_epoch,
            Some(prepared.meta.output_key_epoch),
            "{name}: engine/prepare output_key_epoch"
        );
        assert_eq!(
            result.meta.flags, prepared.meta.flags,
            "{name}: engine/prepare flags"
        );
        output_epochs.push(prepared.meta.output_key_epoch);

        let expected_prefix = &expected["prefix"];
        assert_eq!(
            result.candidate.prefix.agent,
            expected_prefix["agent"].as_u64().unwrap() as u8,
            "{name}"
        );
        assert_eq!(
            result.candidate.prefix.braid_agent_epoch,
            expected_prefix["braid_agent_epoch"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            hex::encode(result.candidate.prefix.auth_root),
            expected_prefix["auth_root_hex"].as_str().unwrap(),
            "{name}"
        );

        let expected_ec = &expected["ec"];
        assert_eq!(
            hex::encode(result.candidate.tr.ec_rk),
            expected_ec["ec_rk_hex"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            hex::encode(result.candidate.tr.ec_dhs_pub),
            expected_ec["ec_dhs_pub_hex"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            hex::encode(result.candidate.tr.ec_dhr_pub),
            expected_ec["ec_dhr_pub_hex"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            result.candidate.tr.ec_dhr_present,
            expected_ec["ec_dhr_present"].as_u64().unwrap() as u8,
            "{name}"
        );
        assert_eq!(
            result.candidate.tr.ec_ck_send_present,
            expected_ec["ec_ck_send_present"].as_u64().unwrap() as u8,
            "{name}"
        );
        assert_eq!(
            result.candidate.tr.ec_ck_recv_present,
            expected_ec["ec_ck_recv_present"].as_u64().unwrap() as u8,
            "{name}"
        );
        assert_eq!(
            result.candidate.tr.ec_ns,
            expected_ec["ec_ns"].as_u64().unwrap() as u32,
            "{name}"
        );
        assert_eq!(
            result.candidate.tr.ec_nr,
            expected_ec["ec_nr"].as_u64().unwrap() as u32,
            "{name}"
        );
        assert_eq!(
            result.candidate.tr.ec_pn,
            expected_ec["ec_pn"].as_u64().unwrap() as u32,
            "{name}"
        );

        if input.op == OP_SEND {
            prior_send_sealed = result.sealed_ct;
        }
    }
    assert_eq!(send_count, 2);
    assert_eq!(receive_count, 2);
    output_epochs.sort_unstable();
    output_epochs.dedup();
    assert_eq!(output_epochs, vec![1, 2]);

    let final_expected = &v["final"];
    let alice_bytes = hex_bytes(final_expected["alice_state_hex"].as_str().unwrap());
    let bob_bytes = hex_bytes(final_expected["bob_state_hex"].as_str().unwrap());
    assert_eq!(
        hex::encode(state_digest(RVFB1_SCHEMA, &alice_bytes)),
        final_expected["alice_state_digest_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(state_digest(RVFB1_SCHEMA, &bob_bytes)),
        final_expected["bob_state_digest_hex"].as_str().unwrap()
    );
    let alice = decode_rvfb1(&alice_bytes).unwrap();
    let bob = decode_rvfb1(&bob_bytes).unwrap();
    assert_eq!(encode_rvfb1(&alice).unwrap(), alice_bytes);
    assert_eq!(encode_rvfb1(&bob).unwrap(), bob_bytes);
    assert_eq!(alice.tr.ec_dhs_pub, bob.tr.ec_dhr_pub);
    assert_eq!(bob.tr.ec_dhs_pub, alice.tr.ec_dhr_pub);
    assert_eq!(alice.tr.scka_rk, bob.tr.scka_rk);
    assert_eq!(alice.prefix.auth_root, bob.prefix.auth_root);
    assert_eq!(alice.prefix.auth_mac_key, bob.prefix.auth_mac_key);
    assert_eq!(
        hex::encode(alice.tr.ec_rk),
        final_expected["alice_ec_rk_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(bob.tr.ec_rk),
        final_expected["bob_ec_rk_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(alice.tr.scka_rk),
        final_expected["scka_rk_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(alice.prefix.auth_root),
        final_expected["auth_root_hex"].as_str().unwrap()
    );

    let mut convergence = Sha256::new();
    convergence.update(b"ATSAM/v2/full-braid/full-exchange-convergence");
    convergence.update(alice.tr.scka_rk);
    convergence.update(alice.prefix.auth_root);
    convergence.update(alice.prefix.auth_mac_key);
    convergence.update(alice.tr.ec_dhs_pub);
    convergence.update(alice.tr.ec_dhr_pub);
    convergence.update(bob.tr.ec_dhs_pub);
    convergence.update(bob.tr.ec_dhr_pub);
    assert_eq!(
        hex::encode(convergence.finalize()),
        final_expected["convergence_digest_hex"].as_str().unwrap()
    );

    let mailbox = &v["mailbox_scenario"];
    assert_eq!(mailbox["phase"], "ct1");
    assert_eq!(mailbox["wire"], "RVBC1");
    assert_eq!(mailbox["dropped_indices"][0], 0);
    assert_eq!(mailbox["duplicate_disposition"], "accept_noop");
    assert_eq!(mailbox["expected_peer_agent"], "Ct1Received");
    assert_eq!(mailbox["expected_active_wire"], "EK_CT1_ACK");
    let delivered = mailbox["delivery_indices"].as_array().unwrap();
    assert_eq!(delivered.len(), N_CT1 + 1);
    assert_eq!(delivered[0], N_CT1 as u64);
    assert_eq!(delivered[1], N_CT1 as u64);
    assert_eq!(delivered.last().unwrap(), 1);
}

/// Strictness sweeps for every Full Braid wire codec, built from real fixtures
/// (the frozen `full_braid_sm_round_001` states/intents/outputs/inputs/envs).
///
/// The shared `wire_negatives` vector only dispatches RVBE1/RVBI1, so a dropped
/// `reject_trailing` or bounds check in any other decoder would otherwise ship
/// unnoticed. For each codec: the fixture round-trips byte-exactly, every
/// proper prefix is rejected, one trailing byte is rejected, and every
/// single-byte corruption either fails or decodes to something that re-encodes
/// to exactly the corrupted bytes (no lenient, non-canonical acceptance).
mod codec_sweeps {
    use super::{hex_bytes, load};
    use crate::hybrid_ratchet_v2_full_braid::pipeline::materialize_rvor;
    use crate::hybrid_ratchet_v2_full_braid::state_codec::{decode_rvfb1, encode_rvfb1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbc1::{decode_rvbc1, encode_rvbc1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbe1::{decode_rvbe1, encode_rvbe1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbi1::{decode_rvbi1, encode_rvbi1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbj1::{decode_rvbj1, encode_rvbj1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::{decode_rvbm1, encode_rvbm1, Rvbm1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbo1::{decode_rvbo1, encode_rvbo1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvch1::{decode_rvch1, encode_rvch1, Rvch1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvft1::{decode_rvft1, encode_rvft1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvor1::{decode_rvor1, encode_rvor1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvqi1::{
        decode_rvqi1, encode_rvqi1, Rvqi1, RVQI1_STATUS_QUARANTINED,
    };

    /// `accept` returns the canonical re-encoding when the input decodes.
    fn sweep(name: &str, valid: &[u8], accept: impl Fn(&[u8]) -> Option<Vec<u8>>) {
        assert_eq!(
            accept(valid).as_deref(),
            Some(valid),
            "{name}: fixture must round-trip byte-exactly"
        );
        for cut in 0..valid.len() {
            assert!(
                accept(&valid[..cut]).is_none(),
                "{name}: truncation to {cut} of {} bytes was accepted",
                valid.len()
            );
        }
        let mut longer = valid.to_vec();
        longer.push(0);
        assert!(accept(&longer).is_none(), "{name}: trailing byte accepted");
        for index in 0..valid.len() {
            for mask in [0x01u8, 0x80, 0xFF] {
                let mut mutated = valid.to_vec();
                mutated[index] ^= mask;
                if let Some(reencoded) = accept(&mutated) {
                    assert_eq!(
                        reencoded, mutated,
                        "{name}: byte {index} ^ {mask:#04x} decoded non-canonically"
                    );
                }
            }
        }
    }

    #[test]
    fn every_full_braid_codec_rejects_truncation_and_stays_canonical() {
        let v = load("full_braid_sm_round_001.json");
        let (inputs, expected) = (&v["inputs"], &v["expected"]);
        let hex = |value: &serde_json::Value| hex_bytes(value.as_str().unwrap());

        let bob_candidate = hex(&expected["bob_candidate_hex"]);
        let alice_candidate = hex(&expected["alice_candidate_hex"]);
        let alice_intent = hex(&expected["alice_intent_hex"]);
        let bob_intent = hex(&expected["bob_intent_hex"]);
        let alice_rvbo1 = hex(&expected["alice_rvbo1_hex"]);

        sweep("RVFB1 (bob)", &bob_candidate, |b| {
            decode_rvfb1(b)
                .ok()
                .map(|s| encode_rvfb1(&s).expect("accepted RVFB1 re-encodes"))
        });
        sweep("RVFB1 (alice)", &alice_candidate, |b| {
            decode_rvfb1(b)
                .ok()
                .map(|s| encode_rvfb1(&s).expect("accepted RVFB1 re-encodes"))
        });
        sweep(
            "RVFT1",
            &encode_rvft1(&decode_rvfb1(&bob_candidate).unwrap().tr).unwrap(),
            |b| {
                decode_rvft1(b)
                    .ok()
                    .map(|t| encode_rvft1(&t).expect("accepted RVFT1 re-encodes"))
            },
        );
        for (name, intent) in [
            ("RVBJ1 (alice)", &alice_intent),
            ("RVBJ1 (bob)", &bob_intent),
        ] {
            sweep(name, intent, |b| {
                decode_rvbj1(b)
                    .ok()
                    .map(|j| encode_rvbj1(&j).expect("accepted RVBJ1 re-encodes"))
            });
        }
        sweep("RVBO1", &alice_rvbo1, |b| {
            decode_rvbo1(b)
                .ok()
                .map(|o| encode_rvbo1(&o).expect("accepted RVBO1 re-encodes"))
        });
        let frame = decode_rvbo1(&alice_rvbo1).unwrap().frames.remove(0);
        sweep("RVBC1", &frame, |b| {
            decode_rvbc1(b)
                .ok()
                .map(|c| encode_rvbc1(&c).expect("accepted RVBC1 re-encodes"))
        });
        let rvor = materialize_rvor(&alice_intent).unwrap().rvor_bytes;
        sweep("RVOR1", &rvor, |b| {
            decode_rvor1(b)
                .ok()
                .map(|r| encode_rvor1(&r).expect("accepted RVOR1 re-encodes"))
        });
        for key in ["send_input_hex", "receive_input_hex"] {
            sweep(&format!("RVBI1 ({key})"), &hex(&inputs[key]), |b| {
                decode_rvbi1(b)
                    .ok()
                    .map(|i| encode_rvbi1(&i).expect("accepted RVBI1 re-encodes"))
            });
        }
        for key in ["send_env_hex", "receive_env_hex"] {
            sweep(&format!("RVBE1 ({key})"), &hex(&inputs[key]), |b| {
                decode_rvbe1(b)
                    .ok()
                    .map(|e| encode_rvbe1(&e).expect("accepted RVBE1 re-encodes"))
            });
        }
        sweep("RVBM1", &encode_rvbm1(&Rvbm1::no_aead()).unwrap(), |b| {
            decode_rvbm1(b)
                .ok()
                .map(|m| encode_rvbm1(&m).expect("accepted RVBM1 re-encodes"))
        });
        let rvqi = encode_rvqi1(&Rvqi1 {
            transition_id: [0x11; 32],
            object_digest: [0x22; 32],
            status: RVQI1_STATUS_QUARANTINED,
            cas_tag: 7,
        })
        .unwrap();
        sweep("RVQI1", &rvqi, |b| {
            decode_rvqi1(b)
                .ok()
                .map(|q| encode_rvqi1(&q).expect("accepted RVQI1 re-encodes"))
        });
        let rvch = encode_rvch1(&Rvch1 {
            ec_dh_pub: [0x33; 32],
            ec_pn: 1,
            ec_n: 2,
            scka_epoch: 3,
            scka_pn: 4,
            scka_n: 5,
            direction: 1,
        });
        sweep("RVCH1", &rvch, |b| {
            decode_rvch1(b).ok().map(|c| encode_rvch1(&c))
        });
    }
}
