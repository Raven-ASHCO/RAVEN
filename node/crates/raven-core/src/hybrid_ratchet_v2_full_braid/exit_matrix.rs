//! Exit matrix gates for Full Braid Slice 2 (design §9).
//!
//! These tests are the Task 13 checklist anchors. Companion coverage also lives
//! in `host_lab`, `transition`, `ffi`, and `spqr_codec`; this module binds the
//! exit wording to executable assertions.

#![cfg(test)]

use crate::hybrid_ratchet_v2_full_braid::constants::{ERR_INTERNAL, ERR_OK};
use crate::hybrid_ratchet_v2_full_braid::ffi::{
    force_panic_once_for_test, raven_fb_init_measure, RavenFbSizes,
};
use crate::hybrid_ratchet_v2_full_braid::host_lab::{DedupState, HostLab, HostLabError};
use crate::hybrid_ratchet_v2_full_braid::init::{
    init_write, ROLE_ALICE, ROLE_BOB, RVFI1_MAGIC, RVFI1_SCHEMA,
};
use crate::hybrid_ratchet_v2_full_braid::pipeline::{materialize_rvor, transition_prepare};
use crate::hybrid_ratchet_v2_full_braid::spqr_codec::{WIRE_CT1, WIRE_EK_CT1_ACK};
use crate::hybrid_ratchet_v2_full_braid::spqr_pin_audit::{L_CT1, N_CT1, N_HDR};
use crate::hybrid_ratchet_v2_full_braid::state_codec::{decode_rvfb1, DIR_A2B, DIR_B2A};
use crate::hybrid_ratchet_v2_full_braid::transition::{transition, Disposition, LabCrypto};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbc1::{encode_rvbc1, Rvbc1};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbe1::{encode_rvbe1, Rvbe1};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbi1::{encode_rvbi1, Rvbi1, OP_RECEIVE, OP_SEND};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::Rvbm1;
use crate::hybrid_ratchet_v2_full_braid::wire_rvor1::decode_rvor1;
use crate::hybrid_ratchet_v2_full_braid::wire_util::{
    write_array32, write_bytes, write_u16be, write_u32be, write_u8,
};
use crate::hybrid_ratchet_v2_tr::x25519_public;
use crate::mlkem768_incremental as mlkem;
use std::path::PathBuf;

const OBJECT: [u8; 32] = [0; 32];
const OWNER: u64 = 0xA11C_E017;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root")
}

fn before_bytes() -> Vec<u8> {
    actor_before_bytes(ROLE_ALICE)
}

fn actor_before_bytes(role: u8) -> Vec<u8> {
    let bob_spk_priv = [0x33; 32];
    let bob_spk_pub = x25519_public(&[0x33; 32]).unwrap();
    let mut init = Vec::new();
    write_bytes(&mut init, RVFI1_MAGIC);
    write_u16be(&mut init, RVFI1_SCHEMA);
    write_array32(&mut init, &[0x53; 32]);
    write_u8(&mut init, role);
    write_u8(&mut init, 0);
    write_array32(&mut init, &[0x11; 32]);
    write_array32(&mut init, &[0x22; 32]);
    write_array32(&mut init, &bob_spk_pub);
    write_array32(
        &mut init,
        if role == ROLE_ALICE {
            &[0x44; 32]
        } else {
            &bob_spk_priv
        },
    );
    write_u32be(&mut init, 0);
    init_write(&init).unwrap()
}

fn send_input_bytes() -> Vec<u8> {
    encode_rvbi1(&Rvbi1 {
        op: OP_SEND,
        direction: 0,
        ch: None,
        expected_ch: None,
        object_digest: None,
        frame: None,
        mutation: Rvbm1::no_aead(),
    })
    .unwrap()
}

fn env_bytes(clock: u64) -> Vec<u8> {
    let mut env = Rvbe1::default_caps(clock);
    env.keygen_seed = vec![0x5A; mlkem::SEED_LEN];
    encode_rvbe1(&env).unwrap()
}

#[test]
fn production_remains_lab_default_off() {
    let vector = repo_root().join("shared-vectors/rvn1/atsam/full_braid_sm_round_001.json");
    let raw = std::fs::read_to_string(&vector).expect("shared vector");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("json");
    assert_eq!(json["production_enabled"], false);
    assert_eq!(json["lab_only"], true);
}

#[test]
fn catch_unwind_maps_to_internal_and_zeroes_sizes() {
    let state = before_bytes();
    let mut need = RavenFbSizes {
        candidate_len: 9,
        outputs_len: 8,
        intent_len: 7,
        reserved0: 6,
    };
    force_panic_once_for_test();
    let code = unsafe { raven_fb_init_measure(state.as_ptr(), state.len(), &mut need) };
    assert_eq!(code, ERR_INTERNAL);
    assert_eq!(need, RavenFbSizes::default());
    assert_ne!(ERR_OK, ERR_INTERNAL);
}

#[test]
fn pending_plus_rvor_duplicate_resumes_clear_not_release() {
    let host = HostLab::new();
    let prepared = host
        .with_lease(|lease| {
            let reservation = lease.try_reserve(OBJECT, OWNER, 900_000_000)?;
            let mut crypto = LabCrypto::default();
            let prepared = transition_prepare(
                &before_bytes(),
                &send_input_bytes(),
                &env_bytes(11_000),
                &mut crypto,
            )
            .unwrap();
            reservation.mark_pending_with_session(
                prepared.meta.transition_id,
                prepared.intent_bytes.clone(),
                prepared.candidate_bytes.clone(),
            )?;
            Ok(prepared)
        })
        .unwrap();
    host.with_lease(|lease| lease.promote_pending(OBJECT))
        .unwrap();
    let rvor = materialize_rvor(&prepared.intent_bytes).unwrap().rvor_bytes;
    host.with_lease(|lease| lease.insert_rvor(prepared.meta.transition_id, rvor.clone()))
        .unwrap();

    let reserve_err = host
        .with_lease(|lease| match lease.try_reserve(OBJECT, OWNER + 1, 1) {
            Ok(reservation) => {
                drop(reservation);
                Err(HostLabError::WrongState)
            }
            Err(error) => Ok(error),
        })
        .unwrap();
    assert_eq!(
        reserve_err,
        HostLabError::DedupConflict(DedupState::Pending)
    );
    assert_eq!(
        host.with_lease(|lease| lease.try_release(OBJECT))
            .unwrap_err(),
        HostLabError::NotActive
    );

    let cleared = host
        .with_lease(|lease| lease.clear_barrier(OBJECT, 11_001))
        .unwrap();
    assert_eq!(decode_rvfb1(&cleared).unwrap().prefix.pending_phase, 0);
    assert_eq!(
        host.with_lease(|lease| lease.try_release(OBJECT)).unwrap(),
        decode_rvor1(&rvor).unwrap().outputs_bytes
    );
}

fn send_input(direction: u8) -> Rvbi1 {
    Rvbi1 {
        op: OP_SEND,
        direction,
        ch: None,
        expected_ch: None,
        object_digest: None,
        frame: None,
        mutation: Rvbm1::no_aead(),
    }
}

fn receive_input(direction: u8, frame: &Rvbc1) -> Rvbi1 {
    Rvbi1 {
        op: OP_RECEIVE,
        direction,
        ch: None,
        expected_ch: None,
        object_digest: Some([0xD2; 32]),
        frame: Some(encode_rvbc1(frame).unwrap()),
        mutation: Rvbm1::no_aead(),
    }
}

#[test]
fn actor_mailbox_loss_reorder_duplicate_ct1_completes_with_erasure() {
    use crate::hybrid_ratchet_v2_full_braid::agent::{
        AGENT_CT1_RECEIVED, AGENT_HEADER_RECEIVED, AGENT_HEADER_SENT,
    };

    let mut alice = decode_rvfb1(&actor_before_bytes(ROLE_ALICE)).unwrap();
    let mut bob = decode_rvfb1(&actor_before_bytes(ROLE_BOB)).unwrap();
    let mut alice_crypto = LabCrypto::default();
    let mut bob_crypto = LabCrypto::default();
    let plain_env = Rvbe1::default_caps(0);
    let mut alice_env = Rvbe1::default_caps(0);
    alice_env.keygen_seed = vec![0x91; mlkem::SEED_LEN];
    let mut bob_env = Rvbe1::default_caps(0);
    bob_env.encaps_coins = vec![0x92; mlkem::COINS_LEN];

    for _ in 0..N_HDR {
        let sent = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
        assert_eq!(sent.disposition, Disposition::Accept);
        alice = sent.candidate;
        let frame = sent.frame.unwrap();
        let received = transition(
            &bob,
            &receive_input(DIR_A2B, &frame),
            &plain_env,
            &mut bob_crypto,
        );
        assert_eq!(received.disposition, Disposition::Accept);
        bob = received.candidate;
    }
    assert_eq!(bob.prefix.agent, AGENT_HEADER_RECEIVED);

    // This Vec is the actor-to-actor RVBC1 mailbox. Emit one redundancy frame
    // beyond the N_CT1 systematic threshold before applying network faults.
    let mut mailbox = Vec::with_capacity(N_CT1 + 1);
    for _ in 0..=N_CT1 {
        let sent = transition(&bob, &send_input(DIR_B2A), &bob_env, &mut bob_crypto);
        assert_eq!(sent.disposition, Disposition::Accept);
        bob = sent.candidate;
        let frame = sent.frame.unwrap();
        assert_eq!(frame.chunk_type, WIRE_CT1);
        mailbox.push(frame);
    }
    assert_eq!(
        mailbox.iter().map(|frame| frame.index).collect::<Vec<_>>(),
        (0..=N_CT1 as u32).collect::<Vec<_>>()
    );

    // Drop systematic index 0, reverse the remaining queue, and duplicate
    // parity index N_CT1 before delivery.
    mailbox.retain(|frame| frame.index != 0);
    mailbox.sort_by_key(|frame| std::cmp::Reverse(frame.index));
    mailbox.insert(0, mailbox[0].clone());
    assert_eq!(mailbox[0].index, N_CT1 as u32);
    assert_eq!(mailbox[1].index, N_CT1 as u32);

    for (position, frame) in mailbox.into_iter().enumerate() {
        let before = alice.clone();
        let received = transition(
            &alice,
            &receive_input(DIR_B2A, &frame),
            &plain_env,
            &mut alice_crypto,
        );
        assert_eq!(received.disposition, Disposition::Accept);
        if position == 0 {
            assert_eq!(received.candidate.prefix.agent, AGENT_HEADER_SENT);
        } else if position == 1 {
            // An identical duplicate is an accepted decoder no-op, not a
            // conflict or replay terminal.
            assert_eq!(received.candidate, before);
        }
        alice = received.candidate;
    }

    assert_eq!(alice.prefix.agent, AGENT_CT1_RECEIVED);
    assert_eq!(
        alice.active_send.as_ref().unwrap().wire_type,
        WIRE_EK_CT1_ACK
    );
    assert_eq!(
        alice
            .tlvs
            .iter()
            .find(|entry| entry.tag == 6)
            .unwrap()
            .value
            .len(),
        L_CT1
    );
}

/// Mailbox faults on the EK and CT2 phases (the CT1 phase has its own test):
/// systematic index 0 is lost, the queue is delivered in reverse order, and the
/// parity frame is duplicated. Both phases still complete from the remaining
/// distinct chunks (any `N` distinct chunks decode), duplicates are decoder
/// no-ops, and the epoch hands off to the next PQ epoch.
#[test]
fn actor_mailbox_loss_reorder_duplicate_ek_and_ct2_complete_with_erasure() {
    use crate::hybrid_ratchet_v2_full_braid::agent::{
        AGENT_CT1_ACKNOWLEDGED, AGENT_CT1_RECEIVED, AGENT_CT2_SAMPLED, AGENT_EK_SENT_CT1_RECEIVED,
        AGENT_NO_HEADER_RECEIVED,
    };
    use crate::hybrid_ratchet_v2_full_braid::spqr_codec::WIRE_CT2;
    use crate::hybrid_ratchet_v2_full_braid::spqr_pin_audit::{N_CT2, N_EK};

    /// Drop index 0, reverse, then duplicate the parity frame at the front.
    fn fault(mut mailbox: Vec<Rvbc1>, n: u32) -> Vec<Rvbc1> {
        mailbox.retain(|frame| frame.index != 0);
        mailbox.sort_by_key(|frame| std::cmp::Reverse(frame.index));
        mailbox.insert(0, mailbox[0].clone());
        assert_eq!(mailbox[0].index, n);
        assert_eq!(mailbox[1].index, n);
        mailbox
    }

    let mut alice = decode_rvfb1(&actor_before_bytes(ROLE_ALICE)).unwrap();
    let mut bob = decode_rvfb1(&actor_before_bytes(ROLE_BOB)).unwrap();
    let mut alice_crypto = LabCrypto::default();
    let mut bob_crypto = LabCrypto::default();
    let plain_env = Rvbe1::default_caps(0);
    let mut alice_env = Rvbe1::default_caps(0);
    alice_env.keygen_seed = vec![0x91; mlkem::SEED_LEN];
    let mut bob_env = Rvbe1::default_caps(0);
    bob_env.encaps_coins = vec![0x92; mlkem::COINS_LEN];

    // HDR then CT1 in order: this test is about the later phases.
    for _ in 0..N_HDR {
        let sent = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
        assert_eq!(sent.disposition, Disposition::Accept);
        alice = sent.candidate;
        let frame = sent.frame.unwrap();
        let received = transition(
            &bob,
            &receive_input(DIR_A2B, &frame),
            &plain_env,
            &mut bob_crypto,
        );
        assert_eq!(received.disposition, Disposition::Accept);
        bob = received.candidate;
    }
    for _ in 0..N_CT1 {
        let sent = transition(&bob, &send_input(DIR_B2A), &bob_env, &mut bob_crypto);
        assert_eq!(sent.disposition, Disposition::Accept);
        bob = sent.candidate;
        let frame = sent.frame.unwrap();
        let received = transition(
            &alice,
            &receive_input(DIR_B2A, &frame),
            &plain_env,
            &mut alice_crypto,
        );
        assert_eq!(received.disposition, Disposition::Accept);
        alice = received.candidate;
    }
    assert_eq!(alice.prefix.agent, AGENT_CT1_RECEIVED);
    let epoch = alice.prefix.braid_agent_epoch;

    // EK phase (Alice -> Bob): one redundancy frame beyond N_EK.
    let mut mailbox = Vec::new();
    for _ in 0..=N_EK {
        let sent = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
        assert_eq!(sent.disposition, Disposition::Accept);
        alice = sent.candidate;
        let frame = sent.frame.unwrap();
        assert_eq!(frame.chunk_type, WIRE_EK_CT1_ACK);
        mailbox.push(frame);
    }
    for (position, frame) in fault(mailbox, N_EK as u32).into_iter().enumerate() {
        let before = bob.clone();
        let received = transition(
            &bob,
            &receive_input(DIR_A2B, &frame),
            &plain_env,
            &mut bob_crypto,
        );
        assert_eq!(
            received.disposition,
            Disposition::Accept,
            "ek frame {position}"
        );
        match position {
            // First frame carries the CT1 ack: Bob stops sending CT1.
            0 => assert_eq!(received.candidate.prefix.agent, AGENT_CT1_ACKNOWLEDGED),
            // Identical duplicate: accepted decoder no-op.
            1 => assert_eq!(received.candidate, before),
            _ => {}
        }
        bob = received.candidate;
    }
    assert_eq!(bob.prefix.agent, AGENT_CT2_SAMPLED);
    assert_eq!(bob.prefix.braid_agent_epoch, epoch);

    // CT2 phase (Bob -> Alice): one redundancy frame beyond N_CT2.
    let mut mailbox = Vec::new();
    for _ in 0..=N_CT2 {
        let sent = transition(&bob, &send_input(DIR_B2A), &bob_env, &mut bob_crypto);
        assert_eq!(sent.disposition, Disposition::Accept);
        bob = sent.candidate;
        let frame = sent.frame.unwrap();
        assert_eq!(frame.chunk_type, WIRE_CT2);
        mailbox.push(frame);
    }
    let mut saw_ek_sent = false;
    for (position, frame) in fault(mailbox, N_CT2 as u32).into_iter().enumerate() {
        let before = alice.clone();
        let received = transition(
            &alice,
            &receive_input(DIR_B2A, &frame),
            &plain_env,
            &mut alice_crypto,
        );
        assert_eq!(
            received.disposition,
            Disposition::Accept,
            "ct2 frame {position}"
        );
        if position == 1 && received.candidate.prefix.agent == AGENT_EK_SENT_CT1_RECEIVED {
            assert_eq!(received.candidate, before, "duplicate CT2 is a no-op");
        }
        saw_ek_sent |= received.candidate.prefix.agent == AGENT_EK_SENT_CT1_RECEIVED;
        alice = received.candidate;
    }
    assert!(saw_ek_sent, "Alice must pass through EkSentCt1Received");
    assert_eq!(alice.prefix.agent, AGENT_NO_HEADER_RECEIVED);
    assert_eq!(alice.prefix.braid_agent_epoch, epoch + 1);
    // Both sides derived the same epoch secret: Bob's next-epoch handoff frame
    // advances him as well.
    let handoff = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
    assert_eq!(handoff.disposition, Disposition::Accept);
    let frame = handoff.frame.unwrap();
    assert_eq!(frame.epoch, epoch + 1);
    let received = transition(
        &bob,
        &receive_input(DIR_A2B, &frame),
        &plain_env,
        &mut bob_crypto,
    );
    assert_eq!(received.disposition, Disposition::Accept);
    assert_eq!(received.candidate.prefix.braid_agent_epoch, epoch + 1);
}
