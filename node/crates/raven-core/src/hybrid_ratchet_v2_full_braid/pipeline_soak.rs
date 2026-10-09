//! End-to-end soak through the durable pipeline (lab-only tests).
//!
//! Both parties start from RVFI1 init and every step runs
//! `transition_prepare → promote_state → materialize_rvor → clear_pending`, the
//! way a host drives the engine. It covers what single-transition tests do not:
//! RVFI1 EC init feeding real nested AEAD confirms, the bounded replay window
//! across hundreds of commits, and one-sided send bursts past the 64-index
//! chunk space.

#![cfg(test)]

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest, Sha256};

use crate::hybrid_ratchet_v2_full_braid::agent::{
    AGENT_CT1_ACKNOWLEDGED, AGENT_CT1_RECEIVED, AGENT_CT2_SAMPLED, AGENT_EK_SENT_CT1_RECEIVED,
    AGENT_HEADER_RECEIVED, AGENT_HEADER_SENT, AGENT_KEYS_SAMPLED, AGENT_KEYS_UNSAMPLED,
    AGENT_NO_HEADER_RECEIVED,
};
use crate::hybrid_ratchet_v2_full_braid::authenticator::kdf_ok;
use crate::hybrid_ratchet_v2_full_braid::constants::{ERR_NEED_CAPACITY, ERR_PARSE};
use crate::hybrid_ratchet_v2_full_braid::init::{init_write, RVFI1_MAGIC, RVFI1_SCHEMA};
use crate::hybrid_ratchet_v2_full_braid::pipeline::{
    clear_pending, materialize_rvor, promote_state, transition_prepare, PipelineResult,
};
use crate::hybrid_ratchet_v2_full_braid::spqr_codec::{
    BRAID_MAX_CHUNKS_PER_EPOCH, WIRE_CT1, WIRE_CT1_ACK, WIRE_CT2, WIRE_EK_CT1_ACK, WIRE_HDR,
};
use crate::hybrid_ratchet_v2_full_braid::spqr_pin_audit::{N_CT1, N_CT2, N_EK, N_HDR};
use crate::hybrid_ratchet_v2_full_braid::state_codec::{
    decode_rvfb1, Rvfb1State, DIR_A2B, DIR_B2A, MAX_REPLAYS, ROLE_ALICE, ROLE_BOB,
};
use crate::hybrid_ratchet_v2_full_braid::tr_confirm::{
    advance_ec_candidate, build_effective_ad, encode_rvba1, rvch1_from_send_state,
    AdmittedTrustEvidence, Rvba1,
};
use crate::hybrid_ratchet_v2_full_braid::transition::{
    transition, BraidCrypto, Disposition, LabCrypto,
};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbc1::{decode_rvbc1, encode_rvbc1};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbe1::{encode_rvbe1, Rvbe1};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbi1::{encode_rvbi1, Rvbi1, OP_RECEIVE, OP_SEND};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::{Rvbm1, MODE_OPEN, MODE_SEAL_COMPARE};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbo1::decode_rvbo1;
use crate::hybrid_ratchet_v2_full_braid::wire_rvch1::{encode_rvch1, Rvch1};
use crate::hybrid_ratchet_v2_full_braid::wire_util::{
    write_array32, write_bytes, write_u16be, write_u32be, write_u8,
};
use crate::hybrid_ratchet_v2_tr::{x25519_public, EcDrHeader};
use crate::mlkem768_incremental as mlkem;

const SESSION: [u8; 32] = [0x5E; 32];
const SK_EC: [u8; 32] = [0x11; 32];
const SK_SCKA: [u8; 32] = [0x22; 32];
const ALICE_EPH: [u8; 32] = [0x44; 32];
const BOB_SPK: [u8; 32] = [0x33; 32];
/// One-sided burst length: past the 64-index chunk space.
const BURST: usize = BRAID_MAX_CHUNKS_PER_EPOCH + 6;

fn rvfi1(role: u8) -> Vec<u8> {
    let mut out = Vec::new();
    write_bytes(&mut out, RVFI1_MAGIC);
    write_u16be(&mut out, RVFI1_SCHEMA);
    write_array32(&mut out, &SESSION);
    write_u8(&mut out, role);
    write_u8(&mut out, 0);
    write_array32(&mut out, &SK_EC);
    write_array32(&mut out, &SK_SCKA);
    write_array32(&mut out, &x25519_public(&BOB_SPK).unwrap());
    write_array32(
        &mut out,
        if role == ROLE_ALICE {
            &ALICE_EPH
        } else {
            &BOB_SPK
        },
    );
    write_u32be(&mut out, 0);
    out
}

fn seed(label: &[u8], clock: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(clock.to_be_bytes());
    h.finalize().into()
}

fn lab_rvba1(direction: u8) -> Vec<u8> {
    let evidence = AdmittedTrustEvidence::lab_default();
    encode_rvba1(
        &Rvba1::build(
            SESSION,
            direction,
            evidence.initiator_cert_digest,
            evidence.initiator_identity_pub,
            evidence.responder_cert_digest,
            evidence.responder_identity_pub,
        )
        .unwrap(),
    )
    .unwrap()
}

/// Peer's nested confirm as carried in its RVBO1 (`ch_out` + `sealed_ct`).
#[derive(Clone)]
struct SealedConfirm {
    ch: Rvch1,
    sealed_ct: Vec<u8>,
    plaintext: Vec<u8>,
}

struct Party {
    state: Vec<u8>,
    send_dir: u8,
    clock: u64,
    commits: usize,
}

impl Party {
    fn new(role: u8, clock: u64) -> Self {
        Self {
            state: init_write(&rvfi1(role)).unwrap(),
            send_dir: if role == ROLE_ALICE { DIR_A2B } else { DIR_B2A },
            clock,
            commits: 0,
        }
    }

    fn decoded(&self) -> Rvfb1State {
        decode_rvfb1(&self.state).unwrap()
    }

    fn agent(&self) -> u8 {
        self.decoded().prefix.agent
    }

    fn recv_dir(&self) -> u8 {
        self.send_dir ^ 1
    }

    fn next_env(&mut self) -> Rvbe1 {
        self.clock += 1;
        let mut env = Rvbe1::default_caps(self.clock).with_lab_trust();
        let mut keygen = seed(b"keygen-a", self.clock).to_vec();
        keygen.extend_from_slice(&seed(b"keygen-b", self.clock));
        env.keygen_seed = keygen;
        env.encaps_coins = seed(b"coins", self.clock).to_vec();
        env.ec_dh_seed = seed(b"ec-dh", self.clock).to_vec();
        env
    }

    /// Run one input through the whole durable pipeline, committing any intent.
    fn commit(&mut self, input: &Rvbi1, env: &Rvbe1) -> Result<PipelineResult, i32> {
        let input_bytes = encode_rvbi1(input).unwrap();
        let env_bytes = encode_rvbe1(env).unwrap();
        let prepared = transition_prepare(
            &self.state,
            &input_bytes,
            &env_bytes,
            &mut LabCrypto::default(),
        )?;
        if !prepared.intent_bytes.is_empty() {
            let promoted = promote_state(&self.state, &prepared.intent_bytes)
                .unwrap()
                .state_bytes;
            let rvor = materialize_rvor(&prepared.intent_bytes).unwrap().rvor_bytes;
            self.state = clear_pending(&promoted, &prepared.intent_bytes, &rvor, env.clock)
                .unwrap()
                .state_bytes;
            self.commits += 1;
        }
        Ok(prepared)
    }

    /// Plain Send; returns the single emitted RVBC1.
    fn send(&mut self) -> Vec<u8> {
        self.send_capped(BRAID_MAX_CHUNKS_PER_EPOCH as u32)
            .expect("send commits")
    }

    /// Plain Send under a host-tightened `cap_chunks` (RVBE1).
    fn send_capped(&mut self, cap_chunks: u32) -> Result<Vec<u8>, i32> {
        let mut env = self.next_env();
        env.cap_chunks = cap_chunks;
        let prepared = self.commit(&send_input(self.send_dir, Rvbm1::no_aead()), &env)?;
        let mut outputs = decode_rvbo1(&prepared.outputs_bytes).unwrap();
        assert!(outputs.sealed_ct.is_none());
        assert_eq!(outputs.frames.len(), 1);
        Ok(outputs.frames.remove(0))
    }

    fn receive(&mut self, frame: &[u8]) -> Result<PipelineResult, i32> {
        let env = self.next_env();
        let input = Rvbi1 {
            op: OP_RECEIVE,
            direction: self.recv_dir(),
            ch: None,
            expected_ch: None,
            object_digest: Some(Sha256::digest(frame).into()),
            frame: Some(frame.to_vec()),
            mutation: Rvbm1::no_aead(),
        };
        self.commit(&input, &env)
    }

    /// HeaderReceived Send with a nested confirm (`seal_compare`).
    fn send_with_confirm(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, SealedConfirm), i32> {
        let env = self.next_env();
        let state = self.decoded();
        assert_eq!(state.prefix.agent, AGENT_HEADER_RECEIVED);
        let ep = state.prefix.braid_agent_epoch;
        let tlv = |tag: u16| {
            state
                .tlvs
                .iter()
                .find(|entry| entry.tag == tag)
                .unwrap()
                .value
                .clone()
        };
        let mut header = [0u8; mlkem::HEADER_LEN];
        header[..32].copy_from_slice(&tlv(2));
        header[32..].copy_from_slice(&tlv(3));
        let coins: [u8; mlkem::COINS_LEN] = env.encaps_coins.as_slice().try_into().unwrap();
        let encaps = LabCrypto::default().encaps1(&header, &coins).unwrap();
        let scka_mk = kdf_ok(&encaps.shared_secret, ep);
        let ch = rvch1_from_send_state(&state.tr, self.send_dir, ep).unwrap();
        let ec_header = EcDrHeader {
            dh_pub: ch.ec_dh_pub,
            pn: ch.ec_pn,
            n: ch.ec_n,
        };
        // No sending chain yet (Bob before his first EC receive): the confirm is
        // rejected without commit, exactly like any other TR confirm failure.
        let ec_mk = match advance_ec_candidate(&state.tr, OP_SEND, &ec_header, None) {
            Ok((_, ec_mk)) => ec_mk,
            Err(_) => {
                let expected_ct = vec![0; plaintext.len() + 16];
                let input = send_input(
                    self.send_dir,
                    seal_mutation(self.send_dir, plaintext, expected_ct),
                );
                let code = self
                    .commit(&input, &env)
                    .expect_err("confirm without an EC sending chain must fail");
                return Err(code);
            }
        };
        let preview = transition(
            &state,
            &send_input(self.send_dir, Rvbm1::no_aead()),
            &env,
            &mut LabCrypto::default(),
        );
        let frame = encode_rvbc1(&preview.frame.unwrap()).unwrap();
        let ad = build_effective_ad(&lab_rvba1(self.send_dir), &encode_rvch1(&ch), &frame).unwrap();
        let (key, nonce) = crate::hybrid_ratchet_v2::kdf_hybrid(&ec_mk, &scka_mk);
        let expected_ct = ChaCha20Poly1305::new((&key).into())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &ad,
                },
            )
            .unwrap();
        let input = send_input(
            self.send_dir,
            seal_mutation(self.send_dir, plaintext, expected_ct),
        );
        let prepared = self.commit(&input, &env)?;
        let mut outputs = decode_rvbo1(&prepared.outputs_bytes).unwrap();
        assert_eq!(outputs.frames[0], frame);
        let confirm = SealedConfirm {
            ch: outputs.ch_out.clone().unwrap(),
            sealed_ct: outputs.sealed_ct.clone().unwrap(),
            plaintext: plaintext.to_vec(),
        };
        Ok((outputs.frames.remove(0), confirm))
    }

    /// Final CT2 receive that opens the peer's one sealed confirm.
    fn receive_with_confirm(
        &mut self,
        frame: &[u8],
        confirm: &SealedConfirm,
    ) -> Result<PipelineResult, i32> {
        let env = self.next_env();
        let input = Rvbi1 {
            op: OP_RECEIVE,
            direction: self.recv_dir(),
            ch: Some(confirm.ch.clone()),
            expected_ch: Some(confirm.ch.clone()),
            object_digest: Some(Sha256::digest(frame).into()),
            frame: Some(frame.to_vec()),
            mutation: Rvbm1 {
                needs_aead: 1,
                ec_mk_oracle_len: 0,
                ec_mk_oracle: [0; 32],
                aad: lab_rvba1(self.recv_dir()),
                mode: MODE_OPEN,
                body: confirm.sealed_ct.clone(),
                expected_ct: None,
            },
        };
        self.commit(&input, &env)
    }
}

fn send_input(direction: u8, mutation: Rvbm1) -> Rvbi1 {
    Rvbi1 {
        op: OP_SEND,
        direction,
        ch: None,
        expected_ch: None,
        object_digest: None,
        frame: None,
        mutation,
    }
}

fn seal_mutation(direction: u8, plaintext: &[u8], expected_ct: Vec<u8>) -> Rvbm1 {
    Rvbm1 {
        needs_aead: 1,
        ec_mk_oracle_len: 0,
        ec_mk_oracle: [0; 32],
        aad: lab_rvba1(direction),
        mode: MODE_SEAL_COMPARE,
        body: plaintext.to_vec(),
        expected_ct: Some(expected_ct),
    }
}

fn chunk_type(frame: &[u8]) -> u8 {
    decode_rvbc1(frame).unwrap().chunk_type
}

fn deliver_all(to: &mut Party, frames: &[Vec<u8>]) {
    for frame in frames {
        to.receive(frame).expect("delivery never errors");
    }
}

/// One full PQ epoch: `keygen` samples keys, `encaps` encapsulates. Returns
/// whether the nested AEAD confirm ran (it needs an EC sending chain).
fn run_epoch(keygen: &mut Party, encaps: &mut Party, epoch: u64, burst: bool) -> bool {
    assert_eq!(keygen.agent(), AGENT_KEYS_UNSAMPLED);
    assert_eq!(encaps.agent(), AGENT_NO_HEADER_RECEIVED);
    assert_eq!(keygen.decoded().prefix.braid_agent_epoch, epoch);
    assert_eq!(encaps.decoded().prefix.braid_agent_epoch, epoch);

    // HDR: optionally a one-sided burst while the peer is offline. The
    // sender never stalls; re-sent indices apply as no-ops or are ignored.
    let hdr_sends = if burst { BURST } else { N_HDR };
    let hdr: Vec<Vec<u8>> = (0..hdr_sends).map(|_| keygen.send()).collect();
    assert!(hdr.iter().all(|frame| chunk_type(frame) == WIRE_HDR));
    assert_eq!(keygen.agent(), AGENT_KEYS_SAMPLED);
    deliver_all(encaps, &hdr);
    assert_eq!(encaps.agent(), AGENT_HEADER_RECEIVED);

    // First CT1 carries the nested confirm when the encapsulator can seal.
    let plaintext = format!("soak-confirm-epoch-{epoch}").into_bytes();
    let has_send_chain = encaps.decoded().tr.ec_ck_send_present == 1;
    let (first_ct1, confirm) = if has_send_chain {
        let (frame, confirm) = encaps.send_with_confirm(&plaintext).unwrap();
        (frame, Some(confirm))
    } else {
        let before = encaps.state.clone();
        assert_eq!(encaps.send_with_confirm(&plaintext).err(), Some(ERR_PARSE));
        assert_eq!(encaps.state, before, "failed confirm must not commit");
        (encaps.send(), None)
    };
    assert_eq!(chunk_type(&first_ct1), WIRE_CT1);
    let mut ct1 = vec![first_ct1];
    let ct1_sends = if burst { BURST } else { N_CT1 };
    ct1.extend((1..ct1_sends).map(|_| encaps.send()));
    deliver_all(keygen, &ct1);
    assert_eq!(keygen.agent(), AGENT_CT1_RECEIVED);

    let ek: Vec<Vec<u8>> = (0..N_EK).map(|_| keygen.send()).collect();
    assert!(ek.iter().all(|frame| chunk_type(frame) == WIRE_EK_CT1_ACK));
    deliver_all(encaps, &ek[..1]);
    assert_eq!(encaps.agent(), AGENT_CT1_ACKNOWLEDGED);
    deliver_all(encaps, &ek[1..]);
    assert_eq!(encaps.agent(), AGENT_CT2_SAMPLED);

    let ct2: Vec<Vec<u8>> = (0..N_CT2).map(|_| encaps.send()).collect();
    assert!(ct2.iter().all(|frame| chunk_type(frame) == WIRE_CT2));
    deliver_all(keygen, &ct2[..N_CT2 - 1]);
    assert_eq!(keygen.agent(), AGENT_EK_SENT_CT1_RECEIVED);
    // SPQR EkSentCt1Received keeps acknowledging CT1; the encapsulator in
    // Ct2Sampled treats the same-epoch ack as a no-commit Ignore.
    let ack = keygen.send();
    assert_eq!(chunk_type(&ack), WIRE_CT1_ACK);
    let encaps_before = encaps.state.clone();
    let ignored = encaps.receive(&ack).unwrap();
    assert!(ignored.intent_bytes.is_empty());
    assert_eq!(encaps.state, encaps_before);

    let last = &ct2[N_CT2 - 1];
    let promoted = match &confirm {
        Some(confirm) => keygen.receive_with_confirm(last, confirm).unwrap(),
        None => keygen.receive(last).unwrap(),
    };
    assert_eq!(promoted.meta.output_key_epoch, epoch);
    assert_eq!(keygen.agent(), AGENT_NO_HEADER_RECEIVED);
    if let Some(confirm) = &confirm {
        assert!(!confirm.plaintext.is_empty());
    }

    // Keygen's next Send hands the following epoch to the encapsulator.
    let handoff = keygen.send();
    deliver_all(encaps, &[handoff]);
    assert_eq!(encaps.agent(), AGENT_KEYS_UNSAMPLED);

    let (k, e) = (keygen.decoded(), encaps.decoded());
    assert_eq!(k.tr.scka_rk, e.tr.scka_rk);
    assert_eq!(k.prefix.auth_root, e.prefix.auth_root);
    assert_eq!(k.prefix.braid_agent_epoch, epoch + 1);
    assert_eq!(e.prefix.braid_agent_epoch, epoch + 1);
    confirm.is_some()
}

#[test]
fn rvfi1_init_to_four_pq_epochs_through_durable_pipeline() {
    let mut alice = Party::new(ROLE_ALICE, 1_000);
    let mut bob = Party::new(ROLE_BOB, 5_000_000);

    // Epoch 1: Bob encapsulates but has no EC sending chain until he receives
    // an EC message, so only the plain promotion path is available.
    assert!(!run_epoch(&mut alice, &mut bob, 1, true));
    // Epoch 2: Alice seals with her RVFI1 chain; Bob's open performs the first
    // DH ratchet from his SPK (this failed before the RVFI1 init fix).
    assert!(run_epoch(&mut bob, &mut alice, 2, false));
    // Epochs 3 and 4: both directions now confirm with fresh DH ratchets.
    assert!(run_epoch(&mut alice, &mut bob, 3, true));
    assert!(run_epoch(&mut bob, &mut alice, 4, false));

    let (a, b) = (alice.decoded(), bob.decoded());
    // Bob's last open ratcheted onto Alice's newest DH key.
    assert_eq!(a.tr.ec_dhs_pub, b.tr.ec_dhr_pub);
    // Hundreds of commits per side: the replay table is a bounded window, not a
    // lifetime cap that wedges the session at commit 65.
    assert!(alice.commits > 2 * MAX_REPLAYS, "{}", alice.commits);
    assert!(bob.commits > 2 * MAX_REPLAYS, "{}", bob.commits);
    assert_eq!(a.replays.len(), MAX_REPLAYS);
    assert_eq!(b.replays.len(), MAX_REPLAYS);
    assert_eq!(a.prefix.generation, alice.commits as u64);
    assert_eq!(b.prefix.generation, bob.commits as u64);
}

#[test]
fn sender_burst_cycles_chunk_indices_instead_of_stalling() {
    let mut alice = Party::new(ROLE_ALICE, 1_000);
    let frames: Vec<Vec<u8>> = (0..2 * BRAID_MAX_CHUNKS_PER_EPOCH + 1)
        .map(|_| alice.send())
        .collect();
    let indices: Vec<u32> = frames
        .iter()
        .map(|frame| decode_rvbc1(frame).unwrap().index)
        .collect();
    let expected: Vec<u32> = (0..indices.len())
        .map(|i| (i % BRAID_MAX_CHUNKS_PER_EPOCH) as u32)
        .collect();
    assert_eq!(indices, expected);
    // A wrapped index re-emits the identical frame.
    assert_eq!(frames[0], frames[BRAID_MAX_CHUNKS_PER_EPOCH]);
    assert_eq!(alice.agent(), AGENT_KEYS_SAMPLED);

    // The keygen side can keep emitting EK while its peer is offline, too.
    let mut bob = Party::new(ROLE_BOB, 9_000_000);
    deliver_all(&mut bob, &frames[..N_HDR]);
    let ct1 = bob.send();
    deliver_all(&mut alice, &[ct1]);
    assert_eq!(alice.agent(), AGENT_HEADER_SENT);
    for _ in 0..BURST {
        alice.send();
    }
}

/// A host that tightens `cap_chunks` to the systematic chunk count must still be
/// able to re-send a chunk the peer lost: the cursor wraps at the cap instead of
/// running into it and wedging every later Send with `ERR_NEED_CAPACITY`.
#[test]
fn tightened_cap_chunks_cursor_wraps_so_lost_hdr_chunk_is_resent() {
    let cap = N_HDR as u32;
    let mut alice = Party::new(ROLE_ALICE, 1_000);
    let mut bob = Party::new(ROLE_BOB, 5_000_000);
    let frames: Vec<Vec<u8>> = (0..2 * N_HDR + 1)
        .map(|_| {
            alice
                .send_capped(cap)
                .expect("send must not wedge at the cap")
        })
        .collect();
    let indices: Vec<u32> = frames
        .iter()
        .map(|frame| decode_rvbc1(frame).unwrap().index)
        .collect();
    assert_eq!(indices, [0, 1, 2, 0, 1, 2, 0]);
    // The first transmission of index 1 is lost; the re-send completes HDR.
    deliver_all(&mut bob, &[frames[0].clone(), frames[2].clone()]);
    assert_eq!(bob.agent(), AGENT_NO_HEADER_RECEIVED);
    deliver_all(&mut bob, &[frames[4].clone()]);
    assert_eq!(bob.agent(), AGENT_HEADER_RECEIVED);
}

#[test]
fn tightened_cap_chunks_cursor_wraps_so_lost_ek_chunk_is_resent() {
    let cap = N_EK as u32;
    let mut alice = Party::new(ROLE_ALICE, 1_000);
    let mut bob = Party::new(ROLE_BOB, 5_000_000);
    let hdr: Vec<Vec<u8>> = (0..N_HDR).map(|_| alice.send()).collect();
    deliver_all(&mut bob, &hdr);
    let ct1: Vec<Vec<u8>> = (0..N_CT1).map(|_| bob.send()).collect();
    deliver_all(&mut alice, &ct1);
    assert_eq!(alice.agent(), AGENT_CT1_RECEIVED);

    // Alice's cursor reaches the cap (36) and must wrap to 0, 1, ... 9.
    let ek: Vec<Vec<u8>> = (0..N_EK + 10)
        .map(|_| {
            alice
                .send_capped(cap)
                .expect("send must not wedge at the cap")
        })
        .collect();
    let indices: Vec<u32> = ek
        .iter()
        .map(|frame| decode_rvbc1(frame).unwrap().index)
        .collect();
    let expected: Vec<u32> = (0..indices.len()).map(|i| (i % N_EK) as u32).collect();
    assert_eq!(indices, expected);
    assert!(ek.iter().all(|frame| chunk_type(frame) == WIRE_EK_CT1_ACK));

    // Bob misses chunk 7 the first time round; every other index arrives.
    deliver_all(&mut bob, &ek[..1]);
    assert_eq!(bob.agent(), AGENT_CT1_ACKNOWLEDGED);
    deliver_all(&mut bob, &ek[1..7]);
    deliver_all(&mut bob, &ek[8..N_EK]);
    assert_eq!(bob.agent(), AGENT_CT1_ACKNOWLEDGED);
    // The re-sent index 7 (second lap) completes the EK.
    deliver_all(&mut bob, &ek[N_EK + 7..N_EK + 8]);
    assert_eq!(bob.agent(), AGENT_CT2_SAMPLED);
}

#[test]
fn cursor_persisted_under_larger_cap_wraps_when_cap_is_tightened() {
    let mut alice = Party::new(ROLE_ALICE, 1_000);
    for _ in 0..10 {
        alice.send();
    }
    assert_eq!(alice.decoded().active_send.unwrap().next_spqr_index, 10);
    // Cursor 10 is above a cap of 4: the next index is 10 % 4 and later sends
    // keep cycling inside the cap.
    let indices: Vec<u32> = (0..6)
        .map(|_| decode_rvbc1(&alice.send_capped(4).unwrap()).unwrap().index)
        .collect();
    assert_eq!(indices, [2, 3, 0, 1, 2, 3]);
    // A zero cap can never emit a chunk and stays a clean capacity failure.
    let before = alice.state.clone();
    assert_eq!(alice.send_capped(0).unwrap_err(), ERR_NEED_CAPACITY);
    assert_eq!(alice.state, before);
}

#[test]
fn replay_window_keeps_latest_commit_as_replay_hit() {
    // The most recent commit's execution digest is still a ReplayHit.
    let mut alice = Party::new(ROLE_ALICE, 1_000);
    let env = alice.next_env();
    let input = send_input(DIR_A2B, Rvbm1::no_aead());
    alice.commit(&input, &env).unwrap();
    let replay = alice.commit(&input, &env).unwrap();
    assert!(replay.intent_bytes.is_empty());
    assert_eq!(
        replay.meta.flags,
        crate::hybrid_ratchet_v2_full_braid::pipeline::META_FLAG_REPLAY_HIT
    );
    let state = alice.decoded();
    assert_eq!(
        transition(&state, &input, &env, &mut LabCrypto::default()).disposition,
        Disposition::ReplayHit
    );
}
