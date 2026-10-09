//! Task 7 Full Braid Send/Receive transition engine (design §§4.13, 5.1–5.7).
//!
//! Decoder insertion, CT1-ack once semantics, active-send continuity, role/mode
//! checks, and epoch bookkeeping are implemented here. Crypto path follows the
//! pinned Signal/SPQR Authenticator + `KDF_OK` (`authenticator.rs`): Encaps1 /
//! Decaps produce a raw ML-KEM secret that MUST pass through epoch-bound
//! `KDF_OK` before Authenticator.Update and nested SCKA promotion. Ct2 MAC is
//! over `ct1‖ct2` with the post-Update mac key. Nested TR AEAD confirm lives in
//! `tr_confirm.rs` (Task 10); pipeline journaling is in `pipeline.rs`.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::hybrid_ratchet_v2_full_braid::agent::{
    BraidAgent, AGENT_CT1_ACKNOWLEDGED, AGENT_CT1_RECEIVED, AGENT_CT1_SAMPLED, AGENT_CT2_SAMPLED,
    AGENT_EK_RECEIVED_CT1_SAMPLED, AGENT_EK_SENT_CT1_RECEIVED, AGENT_HEADER_RECEIVED,
    AGENT_HEADER_SENT, AGENT_KEYS_SAMPLED, AGENT_KEYS_UNSAMPLED, AGENT_NO_HEADER_RECEIVED,
    AGENT_TERMINAL,
};
use crate::hybrid_ratchet_v2_full_braid::authenticator::{self, AuthState};
use crate::hybrid_ratchet_v2_full_braid::constants::{
    ERR_EPOCH, ERR_OK, ERR_PARSE, ERR_TERMINAL_STATE_OP, FLAG_CT1_ACK_APPLIED, FLAG_TERMINAL,
};
use crate::hybrid_ratchet_v2_full_braid::digest::{
    binding_digest, execution_digest, send_source_digest,
};
use crate::hybrid_ratchet_v2_full_braid::spqr_codec::{
    BraidDecoder, BraidEncoder, BRAID_MAX_CHUNKS_PER_EPOCH, BRAID_MAX_CHUNK_INDEX, WIRE_CT1,
    WIRE_CT1_ACK, WIRE_CT2, WIRE_EK, WIRE_EK_CT1_ACK, WIRE_HDR, WIRE_NONE,
};
use crate::hybrid_ratchet_v2_full_braid::spqr_pin_audit::{CW, L_CT1, L_CT2, L_EK, L_HDR};
use crate::hybrid_ratchet_v2_full_braid::state_codec::{
    rvfb1_encodable, ActiveSend, InboundChunk, InboundSet, Rvfb1State, TlvEntry, DIR_A2B, DIR_B2A,
    ROLE_ALICE, ROLE_BOB, SOURCE_KIND_CT1, SOURCE_KIND_CT2, SOURCE_KIND_EK, SOURCE_KIND_HDR,
};
use crate::hybrid_ratchet_v2_full_braid::tr_confirm::{
    self, confirm_before_scka_promote, materialize_ec_dh_priv, ConfirmOutputs, TrConfirmError,
};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbc1::{decode_rvbc1, Rvbc1};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbe1::{encode_rvbe1, Rvbe1};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbi1::{encode_rvbi1, Rvbi1, OP_RECEIVE, OP_SEND};
use crate::hybrid_ratchet_v2_full_braid::wire_rvft1::{Rvft1, SckaChainEntry, MAX_SCKA_CHAIN};
use crate::hybrid_ratchet_v2_state::kdf_scka_rk;
use crate::mlkem768_incremental as mlkem;

pub const META_FLAG_IGNORED: u32 = 1 << 0;
pub const META_FLAG_TERMINAL: u32 = 1 << 1;
pub const META_FLAG_REPLAY_HIT: u32 = 1 << 2;

pub const TERMINAL_REASON_CONFLICT: u16 = 1;
pub const TERMINAL_REASON_MAC: u16 = 2;
pub const TERMINAL_REASON_HEK: u16 = 3;
pub const TERMINAL_REASON_KEM: u16 = 4;
pub const TERMINAL_REASON_TR_CONFIRM: u16 = tr_confirm::TERMINAL_REASON_TR_CONFIRM;
pub const TERMINAL_REASON_REPAIR: u16 = 6;
pub const TERMINAL_REASON_EXPIRED: u16 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    Parse,
    Epoch,
    TerminalStateOp,
}

impl RejectReason {
    pub const PARSE: Self = Self::Parse;
    pub const EPOCH: Self = Self::Epoch;
    pub const TERMINAL_STATE_OP: Self = Self::TerminalStateOp;

    pub const fn abi_code(self) -> i32 {
        match self {
            Self::Parse => ERR_PARSE,
            Self::Epoch => ERR_EPOCH,
            Self::TerminalStateOp => ERR_TERMINAL_STATE_OP,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Accept,
    Ignore,
    Reject { reason: RejectReason },
    Terminal { reason: u16 },
    ReplayHit,
}

impl Disposition {
    pub const fn abi_code(self) -> i32 {
        match self {
            Self::Reject { reason } => reason.abi_code(),
            Self::Accept | Self::Ignore | Self::Terminal { .. } | Self::ReplayHit => ERR_OK,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionMeta {
    pub sending_epoch: u64,
    pub receiving_epoch: u64,
    pub output_key_epoch: Option<u64>,
    pub flags: u32,
}

impl TransitionMeta {
    fn unchanged(state: &Rvfb1State, flags: u32) -> Self {
        Self {
            sending_epoch: state.prefix.braid_send_epoch,
            receiving_epoch: state.prefix.braid_recv_epoch,
            output_key_epoch: None,
            flags,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionResult {
    pub disposition: Disposition,
    /// Candidate state for Accept/Terminal; exact input state for no-commit outcomes.
    pub candidate: Rvfb1State,
    /// The one RVBC1 frame emitted by a successful Send; absent for Receive.
    pub frame: Option<Rvbc1>,
    /// Send `needs_aead=1`: exact RVCH1 placed in RVBO1.
    pub ch_out: Option<crate::hybrid_ratchet_v2_full_braid::wire_rvch1::Rvch1>,
    /// Send `needs_aead=1`: exact sealed AEAD ciphertext placed in RVBO1.
    pub sealed_ct: Option<Vec<u8>>,
    pub meta: TransitionMeta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraidCryptoError {
    Parse,
    Terminal { reason: u16 },
}

/// ML-KEM keygen outputs. Secrets (`dk`) are zeroized on drop; no Debug/Clone.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeygenMaterial {
    pub dk: [u8; mlkem::DK_LEN],
    pub header: [u8; mlkem::HEADER_LEN],
    pub ek_vector: [u8; mlkem::EK_VECTOR_LEN],
}

/// Encaps1 outputs. Secrets (`encaps_state`, `shared_secret`) zeroize on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Encaps1Material {
    pub encaps_state: [u8; mlkem::STATE_LEN],
    pub ct1: [u8; mlkem::CT1_LEN],
    pub shared_secret: [u8; mlkem::SS_LEN],
}

/// ML-KEM boundary only. Authenticator / KDF_OK live in `authenticator` and are
/// applied directly by the transition tables (not stubbable).
pub trait BraidCrypto {
    fn keygen(&mut self, seed: &[u8; mlkem::SEED_LEN]) -> Result<KeygenMaterial, BraidCryptoError>;

    fn encaps1(
        &mut self,
        header: &[u8; mlkem::HEADER_LEN],
        coins: &[u8; mlkem::COINS_LEN],
    ) -> Result<Encaps1Material, BraidCryptoError>;

    fn ct1_ack_advance(&mut self, agent_epoch: u64) -> Result<(), BraidCryptoError>;

    fn encaps2(
        &mut self,
        encaps_state: &[u8; mlkem::STATE_LEN],
        header: &[u8; mlkem::HEADER_LEN],
        ek_vector: &[u8; mlkem::EK_VECTOR_LEN],
    ) -> Result<[u8; mlkem::CT2_LEN], BraidCryptoError>;

    fn decaps(
        &mut self,
        dk: &[u8; mlkem::DK_LEN],
        ct1: &[u8; mlkem::CT1_LEN],
        ct2: &[u8; mlkem::CT2_LEN],
    ) -> Result<[u8; mlkem::SS_LEN], BraidCryptoError>;
}

/// Lab implementation: real incremental ML-KEM (Authenticator is not stubbed).
#[derive(Debug, Default)]
pub struct LabCrypto {
    ack_advances: u64,
}

impl LabCrypto {
    pub const fn ack_advances(&self) -> u64 {
        self.ack_advances
    }
}

impl BraidCrypto for LabCrypto {
    fn keygen(&mut self, seed: &[u8; mlkem::SEED_LEN]) -> Result<KeygenMaterial, BraidCryptoError> {
        let (dk, header, ek_vector) = mlkem::keygen_split(seed);
        let mut dk_bytes = [0u8; mlkem::DK_LEN];
        dk_bytes.copy_from_slice(dk.as_ref());
        Ok(KeygenMaterial {
            dk: dk_bytes,
            header,
            ek_vector,
        })
    }

    fn encaps1(
        &mut self,
        header: &[u8; mlkem::HEADER_LEN],
        coins: &[u8; mlkem::COINS_LEN],
    ) -> Result<Encaps1Material, BraidCryptoError> {
        let (encaps_state, ct1, shared_secret) =
            mlkem::encaps1(header, coins).map_err(|_| BraidCryptoError::Terminal {
                reason: TERMINAL_REASON_KEM,
            })?;
        let mut state_bytes = [0u8; mlkem::STATE_LEN];
        state_bytes.copy_from_slice(encaps_state.as_ref());
        let mut ss = [0u8; mlkem::SS_LEN];
        ss.copy_from_slice(shared_secret.as_ref());
        Ok(Encaps1Material {
            encaps_state: state_bytes,
            ct1,
            shared_secret: ss,
        })
    }

    fn ct1_ack_advance(&mut self, _agent_epoch: u64) -> Result<(), BraidCryptoError> {
        self.ack_advances = self
            .ack_advances
            .checked_add(1)
            .ok_or(BraidCryptoError::Parse)?;
        Ok(())
    }

    fn encaps2(
        &mut self,
        encaps_state: &[u8; mlkem::STATE_LEN],
        header: &[u8; mlkem::HEADER_LEN],
        ek_vector: &[u8; mlkem::EK_VECTOR_LEN],
    ) -> Result<[u8; mlkem::CT2_LEN], BraidCryptoError> {
        let state = mlkem::EncapsState::from_bytes(encaps_state);
        mlkem::encaps2(&state, header, ek_vector).map_err(|_| BraidCryptoError::Terminal {
            reason: TERMINAL_REASON_HEK,
        })
    }

    fn decaps(
        &mut self,
        dk: &[u8; mlkem::DK_LEN],
        ct1: &[u8; mlkem::CT1_LEN],
        ct2: &[u8; mlkem::CT2_LEN],
    ) -> Result<[u8; mlkem::SS_LEN], BraidCryptoError> {
        let dk = mlkem::DkCompressed::from_bytes(dk);
        let shared_secret = mlkem::decaps(&dk, ct1, ct2);
        let mut ss = [0u8; mlkem::SS_LEN];
        ss.copy_from_slice(shared_secret.as_ref());
        Ok(ss)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EngineFailure {
    Reject(RejectReason),
    Terminal(u16),
}

impl From<BraidCryptoError> for EngineFailure {
    fn from(value: BraidCryptoError) -> Self {
        match value {
            BraidCryptoError::Parse => Self::Reject(RejectReason::Parse),
            BraidCryptoError::Terminal { reason } => Self::Terminal(reason),
        }
    }
}

fn auth_from_state(state: &Rvfb1State) -> AuthState {
    AuthState {
        root_key: state.prefix.auth_root,
        mac_key: state.prefix.auth_mac_key,
    }
}

fn store_auth(state: &mut Rvfb1State, auth: &AuthState) {
    state.prefix.auth_root = auth.root_key;
    state.prefix.auth_mac_key = auth.mac_key;
}

fn split_hdr_source(source: &[u8]) -> Result<([u8; mlkem::HEADER_LEN], [u8; 32]), EngineFailure> {
    let source: &[u8; L_HDR] = source
        .try_into()
        .map_err(|_| EngineFailure::Reject(RejectReason::Parse))?;
    let mut header = [0u8; mlkem::HEADER_LEN];
    header.copy_from_slice(&source[..mlkem::HEADER_LEN]);
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&source[mlkem::HEADER_LEN..]);
    Ok((header, mac))
}

fn split_ct2_source(source: &[u8]) -> Result<([u8; mlkem::CT2_LEN], [u8; 32]), EngineFailure> {
    let source: &[u8; L_CT2] = source
        .try_into()
        .map_err(|_| EngineFailure::Reject(RejectReason::Parse))?;
    let mut ct2 = [0u8; mlkem::CT2_LEN];
    ct2.copy_from_slice(&source[..mlkem::CT2_LEN]);
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&source[mlkem::CT2_LEN..]);
    Ok((ct2, mac))
}

fn full_ciphertext(ct1: &[u8; mlkem::CT1_LEN], ct2: &[u8; mlkem::CT2_LEN]) -> Vec<u8> {
    let mut full = Vec::with_capacity(mlkem::CT1_LEN + mlkem::CT2_LEN);
    full.extend_from_slice(ct1);
    full.extend_from_slice(ct2);
    full
}

struct AcceptOutput {
    frame: Option<Rvbc1>,
    ch_out: Option<crate::hybrid_ratchet_v2_full_braid::wire_rvch1::Rvch1>,
    sealed_ct: Option<Vec<u8>>,
    sending_epoch: u64,
    receiving_epoch: u64,
    output_key_epoch: Option<u64>,
}

/// Apply one decoded transition input to a canonical RVFB1 state.
///
/// No pipeline state is prepared here. Reject/Ignore/ReplayHit return the exact
/// input state, while Accept and Terminal return an in-memory candidate.
pub fn transition<C: BraidCrypto>(
    state: &Rvfb1State,
    input: &Rvbi1,
    env: &Rvbe1,
    crypto: &mut C,
) -> TransitionResult {
    if !rvfb1_encodable(state) {
        return reject_result(state, RejectReason::Parse);
    }
    // Scratch encodings carry the plaintext body and the env seeds/coins.
    let input_bytes = match encode_rvbi1(input) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(_) => return reject_result(state, RejectReason::Parse),
    };
    let env_bytes = match encode_rvbe1(env) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(_) => return reject_result(state, RejectReason::Parse),
    };
    let Some(agent) = BraidAgent::from_code(state.prefix.agent) else {
        return reject_result(state, RejectReason::Parse);
    };
    if validate_role_mode(state.prefix.role, input.op, input.direction).is_err() {
        return reject_result(state, RejectReason::Parse);
    }
    if agent == BraidAgent::Terminal {
        return reject_result(state, RejectReason::TerminalStateOp);
    }

    let exec = execution_digest(&input_bytes, &env_bytes);
    if state
        .replays
        .iter()
        .any(|record| record.execution_digest == exec)
    {
        return TransitionResult {
            disposition: Disposition::ReplayHit,
            candidate: state.clone(),
            frame: None,
            ch_out: None,
            sealed_ct: None,
            meta: TransitionMeta::unchanged(state, META_FLAG_REPLAY_HIT),
        };
    }

    let frame = if input.op == OP_RECEIVE {
        match decode_and_validate_frame(state, input) {
            Ok(frame) => Some(frame),
            Err(reason) => return reject_result(state, reason),
        }
    } else {
        None
    };

    let mut candidate = state.clone();
    let applied = match input.op {
        OP_SEND => apply_send(&mut candidate, input, env, crypto),
        OP_RECEIVE => apply_receive(
            &mut candidate,
            input,
            frame.as_ref().expect("Receive frame validated"),
            env,
            crypto,
        ),
        _ => Err(EngineFailure::Reject(RejectReason::Parse)),
    };

    match applied {
        Ok(None) => TransitionResult {
            disposition: Disposition::Ignore,
            candidate: state.clone(),
            frame: None,
            ch_out: None,
            sealed_ct: None,
            meta: TransitionMeta::unchanged(state, META_FLAG_IGNORED),
        },
        Ok(Some(output)) => {
            if input.mutation.needs_aead == 1 && output.output_key_epoch.is_none() {
                // needs_aead=1 is only legal on the SCKA-promote Accept path.
                return reject_result(state, RejectReason::Parse);
            }
            if !rvfb1_encodable(&candidate) {
                return reject_result(state, RejectReason::Parse);
            }
            TransitionResult {
                disposition: Disposition::Accept,
                candidate,
                frame: output.frame,
                ch_out: output.ch_out,
                sealed_ct: output.sealed_ct,
                meta: TransitionMeta {
                    sending_epoch: output.sending_epoch,
                    receiving_epoch: output.receiving_epoch,
                    output_key_epoch: output.output_key_epoch,
                    flags: 0,
                },
            }
        }
        Err(EngineFailure::Reject(reason)) => reject_result(state, reason),
        Err(EngineFailure::Terminal(reason)) if (1..=7).contains(&reason) => {
            terminal_result(candidate, state, reason)
        }
        Err(EngineFailure::Terminal(_)) => reject_result(state, RejectReason::Parse),
    }
}

fn reject_result(state: &Rvfb1State, reason: RejectReason) -> TransitionResult {
    TransitionResult {
        disposition: Disposition::Reject { reason },
        candidate: state.clone(),
        frame: None,
        ch_out: None,
        sealed_ct: None,
        meta: TransitionMeta::unchanged(state, 0),
    }
}

fn terminal_result(
    mut candidate: Rvfb1State,
    original: &Rvfb1State,
    reason: u16,
) -> TransitionResult {
    terminalize(&mut candidate, reason);
    debug_assert!(rvfb1_encodable(&candidate));
    TransitionResult {
        disposition: Disposition::Terminal { reason },
        candidate,
        frame: None,
        ch_out: None,
        sealed_ct: None,
        meta: TransitionMeta::unchanged(original, META_FLAG_TERMINAL),
    }
}

fn validate_role_mode(role: u8, op: u8, direction: u8) -> Result<(), ()> {
    let expected = match (role, op) {
        (ROLE_ALICE, OP_SEND) => DIR_A2B,
        (ROLE_ALICE, OP_RECEIVE) => DIR_B2A,
        (ROLE_BOB, OP_SEND) => DIR_B2A,
        (ROLE_BOB, OP_RECEIVE) => DIR_A2B,
        _ => return Err(()),
    };
    if direction == expected {
        Ok(())
    } else {
        Err(())
    }
}

fn decode_and_validate_frame(state: &Rvfb1State, input: &Rvbi1) -> Result<Rvbc1, RejectReason> {
    let bytes = input.frame.as_ref().ok_or(RejectReason::Parse)?;
    let frame = decode_rvbc1(bytes).map_err(|_| RejectReason::Parse)?;
    frame
        .verify_binding(input.direction, &state.prefix.session_id)
        .map_err(|_| RejectReason::Parse)?;
    validate_chunk_contract(&frame)?;
    Ok(frame)
}

fn validate_chunk_contract(frame: &Rvbc1) -> Result<(), RejectReason> {
    match frame.chunk_type {
        WIRE_NONE | WIRE_CT1_ACK => {
            if frame.index != 0 || !frame.payload.is_empty() {
                return Err(RejectReason::Parse);
            }
        }
        WIRE_HDR | WIRE_EK | WIRE_EK_CT1_ACK | WIRE_CT1 | WIRE_CT2 => {
            if frame.index > BRAID_MAX_CHUNK_INDEX || frame.payload.len() != CW {
                return Err(RejectReason::Parse);
            }
        }
        _ => return Err(RejectReason::Parse),
    }
    Ok(())
}

/// Nested TR confirm failures are pre-commit rejections (ATSAM §4.2 step 7):
/// RVCH1/DH/skip validation runs on attacker-controlled header fields and an
/// AEAD failure proves nothing about the peer, so the candidate is discarded
/// with zero durable mutation instead of terminalizing the session.
fn map_tr_confirm(err: TrConfirmError) -> EngineFailure {
    match err {
        TrConfirmError::Parse | TrConfirmError::TrConfirm => {
            EngineFailure::Reject(RejectReason::Parse)
        }
    }
}

fn apply_send<C: BraidCrypto>(
    state: &mut Rvfb1State,
    input: &Rvbi1,
    env: &Rvbe1,
    crypto: &mut C,
) -> Result<Option<AcceptOutput>, EngineFailure> {
    let direction = input.direction;
    let ep = state.prefix.braid_agent_epoch;
    let send_epoch = ep
        .checked_sub(1)
        .ok_or(EngineFailure::Reject(RejectReason::Parse))?;
    let agent = BraidAgent::from_code(state.prefix.agent)
        .ok_or(EngineFailure::Reject(RejectReason::Parse))?;
    let mut output_key_epoch = None;
    let mut confirm_out = ConfirmOutputs::default();

    let frame = match agent {
        BraidAgent::KeysUnsampled => {
            let seed = fixed_array_zeroizing::<{ mlkem::SEED_LEN }>(&env.keygen_seed)?;
            let material = crypto.keygen(&seed)?;
            let auth = auth_from_state(state);
            let tag = auth.mac_hdr(ep, &material.header);
            let mut source = Vec::with_capacity(L_HDR);
            source.extend_from_slice(&material.header);
            source.extend_from_slice(&tag);

            state.tlvs = vec![
                tlv_entry(1, &material.dk),
                tlv_entry(2, &material.header[..32]),
                tlv_entry(3, &material.header[32..]),
                tlv_entry(4, &material.ek_vector),
                tlv_entry(8, &material.header),
            ];
            state.active_send = Some(new_active_send(
                direction,
                ep,
                WIRE_HDR,
                SOURCE_KIND_HDR,
                source,
            ));
            state.prefix.agent = AGENT_KEYS_SAMPLED;
            emit_active(state, env.cap_chunks)?
        }
        BraidAgent::KeysSampled => emit_expected_active(state, WIRE_HDR, env.cap_chunks)?,
        BraidAgent::HeaderSent => emit_expected_active(state, WIRE_EK, env.cap_chunks)?,
        BraidAgent::Ct1Received => emit_expected_active(state, WIRE_EK_CT1_ACK, env.cap_chunks)?,
        // Pinned SPQR: EkSentCt1Received keeps acknowledging CT1 until Ct2 completes.
        BraidAgent::EkSentCt1Received => empty_frame(state, direction, WIRE_CT1_ACK),
        BraidAgent::NoHeaderReceived | BraidAgent::Ct1Acknowledged => {
            empty_frame(state, direction, WIRE_NONE)
        }
        BraidAgent::HeaderReceived => {
            let header = header_from_tlvs(state)?;
            let coins = fixed_array_zeroizing::<{ mlkem::COINS_LEN }>(&env.encaps_coins)?;
            let encaps = crypto.encaps1(&header, &coins)?;
            // Encaps1 → KDF_OK → Auth.Update → (optional TR AEAD) → SCKA promote.
            let mut raw_ss = encaps.shared_secret;
            let output_key = Zeroizing::new(authenticator::kdf_ok(&raw_ss, ep));
            raw_ss.zeroize();
            let mut auth = auth_from_state(state);
            auth.update(ep, &output_key);
            store_auth(state, &auth);
            let rho = tlv_array::<32>(state, 2)?;
            let hek = tlv_array::<32>(state, 3)?;
            state.tlvs = vec![
                tlv_entry(2, &rho),
                tlv_entry(3, &hek),
                tlv_entry(5, &encaps.encaps_state),
                tlv_entry(6, &encaps.ct1),
            ];
            state.active_send = Some(new_active_send(
                direction,
                ep,
                WIRE_CT1,
                SOURCE_KIND_CT1,
                encaps.ct1.to_vec(),
            ));
            state.prefix.agent = AGENT_CT1_SAMPLED;
            let frame = emit_active(state, env.cap_chunks)?;
            if input.mutation.needs_aead == 1 {
                let evidence = env
                    .admitted_trust
                    .as_ref()
                    .ok_or(EngineFailure::Reject(RejectReason::Parse))?;
                confirm_out = confirm_before_scka_promote(
                    state,
                    input,
                    &frame,
                    &output_key,
                    ep,
                    evidence,
                    None,
                )
                .map_err(map_tr_confirm)?;
            }
            promote_scka_send(&mut state.tr, ep, &output_key)?;
            output_key_epoch = Some(ep);
            frame
        }
        BraidAgent::Ct1Sampled | BraidAgent::EkReceivedCt1Sampled => {
            emit_expected_active(state, WIRE_CT1, env.cap_chunks)?
        }
        BraidAgent::Ct2Sampled => emit_expected_active(state, WIRE_CT2, env.cap_chunks)?,
        BraidAgent::Terminal => {
            return Err(EngineFailure::Reject(RejectReason::TerminalStateOp));
        }
    };

    state.prefix.braid_send_epoch = send_epoch;
    Ok(Some(AcceptOutput {
        frame: Some(frame),
        ch_out: confirm_out.ch_out,
        sealed_ct: confirm_out.sealed_ct,
        sending_epoch: send_epoch,
        receiving_epoch: state.prefix.braid_recv_epoch,
        output_key_epoch,
    }))
}

fn apply_receive<C: BraidCrypto>(
    state: &mut Rvfb1State,
    input: &Rvbi1,
    frame: &Rvbc1,
    env: &Rvbe1,
    crypto: &mut C,
) -> Result<Option<AcceptOutput>, EngineFailure> {
    let direction = input.direction;
    let ep = state.prefix.braid_agent_epoch;
    let recv_epoch = ep
        .checked_sub(1)
        .ok_or(EngineFailure::Reject(RejectReason::Parse))?;
    let agent = BraidAgent::from_code(state.prefix.agent)
        .ok_or(EngineFailure::Reject(RejectReason::Parse))?;
    let mut output_key_epoch = None;
    let mut accepted_receiving_epoch = recv_epoch;

    let accepted = match agent {
        BraidAgent::KeysUnsampled | BraidAgent::HeaderReceived => false,
        BraidAgent::KeysSampled => {
            if frame.epoch != ep || frame.chunk_type != WIRE_CT1 {
                false
            } else {
                let _ = decoder_insert(state, direction, frame, SOURCE_KIND_CT1)?;
                let dk = tlv_array::<{ mlkem::DK_LEN }>(state, 1)?;
                let ek_vector = tlv_array::<{ mlkem::EK_VECTOR_LEN }>(state, 4)?;
                state.tlvs = vec![tlv_entry(1, &dk), tlv_entry(4, &ek_vector)];
                state.active_send = Some(new_active_send(
                    send_direction(state.prefix.role)?,
                    ep,
                    WIRE_EK,
                    SOURCE_KIND_EK,
                    ek_vector.to_vec(),
                ));
                state.prefix.agent = AGENT_HEADER_SENT;
                true
            }
        }
        BraidAgent::HeaderSent => {
            if frame.epoch != ep || frame.chunk_type != WIRE_CT1 {
                false
            } else {
                if let Some(ct1) = decoder_insert(state, direction, frame, SOURCE_KIND_CT1)? {
                    let dk = tlv_array::<{ mlkem::DK_LEN }>(state, 1)?;
                    let ek_vector = tlv_array::<{ mlkem::EK_VECTOR_LEN }>(state, 4)?;
                    state.tlvs = vec![
                        tlv_entry(1, &dk),
                        tlv_entry(4, &ek_vector),
                        tlv_entry(6, &ct1),
                    ];
                    let active = state
                        .active_send
                        .as_mut()
                        .ok_or(EngineFailure::Reject(RejectReason::Parse))?;
                    if active.wire_type != WIRE_EK || active.source_kind != SOURCE_KIND_EK {
                        return Err(EngineFailure::Reject(RejectReason::Parse));
                    }
                    // §5.4: preserve source bytes/digest and encoder position exactly.
                    active.wire_type = WIRE_EK_CT1_ACK;
                    state.prefix.agent = AGENT_CT1_RECEIVED;
                }
                true
            }
        }
        BraidAgent::Ct1Received => {
            if frame.epoch != ep || frame.chunk_type != WIRE_CT2 {
                false
            } else {
                let _ = decoder_insert(state, direction, frame, SOURCE_KIND_CT2)?;
                let dk = tlv_array::<{ mlkem::DK_LEN }>(state, 1)?;
                let ct1 = tlv_array::<{ mlkem::CT1_LEN }>(state, 6)?;
                state.tlvs = vec![tlv_entry(1, &dk), tlv_entry(6, &ct1)];
                state.active_send = None;
                state.prefix.agent = AGENT_EK_SENT_CT1_RECEIVED;
                true
            }
        }
        BraidAgent::EkSentCt1Received => {
            if frame.epoch != ep || frame.chunk_type != WIRE_CT2 {
                false
            } else {
                if let Some(source) = decoder_insert(state, direction, frame, SOURCE_KIND_CT2)? {
                    // Decaps → KDF_OK → Auth.Update → VfyCt → (optional TR AEAD) → SCKA promote.
                    let (ct2, expected_mac) = split_ct2_source(&source)?;
                    let dk = tlv_array::<{ mlkem::DK_LEN }>(state, 1)?;
                    let ct1 = tlv_array::<{ mlkem::CT1_LEN }>(state, 6)?;
                    let mut raw_ss = crypto.decaps(&dk, &ct1, &ct2)?;
                    let output_key = Zeroizing::new(authenticator::kdf_ok(&raw_ss, ep));
                    raw_ss.zeroize();
                    let mut auth = auth_from_state(state);
                    auth.update(ep, &output_key);
                    let full_ct = full_ciphertext(&ct1, &ct2);
                    if !auth.verify_ct(ep, &full_ct, &expected_mac) {
                        return Err(EngineFailure::Terminal(TERMINAL_REASON_MAC));
                    }
                    store_auth(state, &auth);
                    if input.mutation.needs_aead == 1 {
                        let evidence = env
                            .admitted_trust
                            .as_ref()
                            .ok_or(EngineFailure::Reject(RejectReason::Parse))?;
                        let new_dh = if env.ec_dh_seed.len() == 32 {
                            let mut seed = Zeroizing::new([0u8; 32]);
                            seed.copy_from_slice(&env.ec_dh_seed);
                            Some(Zeroizing::new(
                                materialize_ec_dh_priv(
                                    &seed,
                                    &state.prefix.session_id,
                                    state.prefix.generation,
                                )
                                .map_err(map_tr_confirm)?,
                            ))
                        } else {
                            None
                        };
                        // The peer sealed its confirm once, at HeaderReceived, bound to the
                        // first CT1 frame it emitted. Rebuild that exact RVBC1 so both
                        // sides share one AD and each (ec_mk, scka_mk) seals exactly one
                        // ciphertext (no second seal under the same key/nonce).
                        let confirm_frame = first_ct1_frame(state, direction, ep, &ct1[..])?;
                        confirm_before_scka_promote(
                            state,
                            input,
                            &confirm_frame,
                            &output_key,
                            ep,
                            evidence,
                            new_dh.as_deref(),
                        )
                        .map_err(map_tr_confirm)?;
                    }
                    promote_scka_receive(&mut state.tr, ep, &output_key)?;
                    let next_ep = ep
                        .checked_add(1)
                        .ok_or(EngineFailure::Reject(RejectReason::Epoch))?;
                    state.prefix.braid_agent_epoch = next_ep;
                    state.prefix.agent = AGENT_NO_HEADER_RECEIVED;
                    state.prefix.flags &= !FLAG_CT1_ACK_APPLIED;
                    state.tlvs.clear();
                    state.active_send = None;
                    state.inbound_sets =
                        vec![empty_inbound_set(direction, next_ep, SOURCE_KIND_HDR)?];
                    output_key_epoch = Some(ep);
                }
                true
            }
        }
        BraidAgent::NoHeaderReceived => {
            if frame.epoch != ep || frame.chunk_type != WIRE_HDR {
                false
            } else {
                if let Some(source) = decoder_insert(state, direction, frame, SOURCE_KIND_HDR)? {
                    let (header, expected_mac) = split_hdr_source(&source)?;
                    let auth = auth_from_state(state);
                    if !auth.verify_hdr(ep, &header, &expected_mac) {
                        return Err(EngineFailure::Terminal(TERMINAL_REASON_MAC));
                    }
                    state.tlvs = vec![tlv_entry(2, &header[..32]), tlv_entry(3, &header[32..])];
                    state.inbound_sets = vec![empty_inbound_set(direction, ep, SOURCE_KIND_EK)?];
                    state.prefix.agent = AGENT_HEADER_RECEIVED;
                }
                true
            }
        }
        BraidAgent::Ct1Sampled => match (frame.epoch == ep, frame.chunk_type) {
            (true, WIRE_EK) => {
                if let Some(ek) = decoder_insert(state, direction, frame, SOURCE_KIND_EK)? {
                    let rho = tlv_array::<32>(state, 2)?;
                    let hek = tlv_array::<32>(state, 3)?;
                    let encaps_state = tlv_array::<{ mlkem::STATE_LEN }>(state, 5)?;
                    let ct1 = tlv_array::<{ mlkem::CT1_LEN }>(state, 6)?;
                    state.tlvs = vec![
                        tlv_entry(2, &rho),
                        tlv_entry(3, &hek),
                        tlv_entry(4, &ek),
                        tlv_entry(5, &encaps_state),
                        tlv_entry(6, &ct1),
                    ];
                    state.prefix.agent = AGENT_EK_RECEIVED_CT1_SAMPLED;
                }
                true
            }
            (true, WIRE_EK_CT1_ACK) => {
                let ek = decoder_insert(state, direction, frame, SOURCE_KIND_EK)?;
                apply_first_ct1_ack(state, crypto)?;
                if let Some(ek) = ek {
                    finish_encaps2(state, &ek, crypto)?;
                } else {
                    enter_ct1_acknowledged(state)?;
                }
                true
            }
            (true, WIRE_CT1_ACK) => {
                apply_first_ct1_ack(state, crypto)?;
                enter_ct1_acknowledged(state)?;
                true
            }
            _ => false,
        },
        BraidAgent::EkReceivedCt1Sampled => {
            if frame.epoch != ep || !matches!(frame.chunk_type, WIRE_EK_CT1_ACK | WIRE_CT1_ACK) {
                false
            } else {
                if frame.chunk_type == WIRE_EK_CT1_ACK {
                    let _ = decoder_insert(state, direction, frame, SOURCE_KIND_EK)?;
                }
                apply_first_ct1_ack(state, crypto)?;
                let ek = tlv_array::<{ mlkem::EK_VECTOR_LEN }>(state, 4)?;
                finish_encaps2(state, &ek[..], crypto)?;
                true
            }
        }
        BraidAgent::Ct1Acknowledged => {
            if frame.epoch != ep || frame.chunk_type != WIRE_EK_CT1_ACK {
                false
            } else {
                if let Some(ek) = decoder_insert(state, direction, frame, SOURCE_KIND_EK)? {
                    finish_encaps2(state, &ek, crypto)?;
                }
                true
            }
        }
        BraidAgent::Ct2Sampled => {
            let next_ep = ep
                .checked_add(1)
                .ok_or(EngineFailure::Reject(RejectReason::Epoch))?;
            if frame.epoch == ep {
                false
            } else if frame.epoch == next_ep {
                state.prefix.braid_agent_epoch = next_ep;
                state.prefix.agent = AGENT_KEYS_UNSAMPLED;
                state.prefix.flags &= !FLAG_CT1_ACK_APPLIED;
                state.prefix.terminal_reason = 0;
                state.active_send = None;
                state.tlvs.clear();
                state.inbound_sets.clear();
                accepted_receiving_epoch = ep;
                true
            } else {
                return Err(EngineFailure::Reject(RejectReason::Epoch));
            }
        }
        BraidAgent::Terminal => {
            return Err(EngineFailure::Reject(RejectReason::TerminalStateOp));
        }
    };

    if !accepted {
        return Ok(None);
    }
    state.prefix.braid_recv_epoch = accepted_receiving_epoch;
    Ok(Some(AcceptOutput {
        frame: None,
        ch_out: None,
        sealed_ct: None,
        sending_epoch: state.prefix.braid_send_epoch,
        receiving_epoch: accepted_receiving_epoch,
        output_key_epoch,
    }))
}

fn send_direction(role: u8) -> Result<u8, EngineFailure> {
    match role {
        ROLE_ALICE => Ok(DIR_A2B),
        ROLE_BOB => Ok(DIR_B2A),
        _ => Err(EngineFailure::Reject(RejectReason::Parse)),
    }
}

fn fixed_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], EngineFailure> {
    bytes
        .try_into()
        .map_err(|_| EngineFailure::Reject(RejectReason::Parse))
}

/// Like [`fixed_array`] for secret material (host-supplied seeds/coins, the
/// ML-KEM `dk`, Encaps1 state): the copy is filled in place in a wipe-on-drop
/// buffer instead of passing through a plain, never-wiped array.
fn fixed_array_zeroizing<const N: usize>(
    bytes: &[u8],
) -> Result<Zeroizing<[u8; N]>, EngineFailure> {
    if bytes.len() != N {
        return Err(EngineFailure::Reject(RejectReason::Parse));
    }
    let mut out = Zeroizing::new([0u8; N]);
    out.copy_from_slice(bytes);
    Ok(out)
}

fn tlv_entry<T: AsRef<[u8]> + ?Sized>(tag: u16, value: &T) -> TlvEntry {
    TlvEntry {
        tag,
        value: value.as_ref().to_vec(),
    }
}

/// Wipe-on-drop fixed-size copy of a TLV value (the ML-KEM `dk` and Encaps1
/// state live in TLVs).
fn tlv_array<const N: usize>(
    state: &Rvfb1State,
    tag: u16,
) -> Result<Zeroizing<[u8; N]>, EngineFailure> {
    let value = state
        .tlvs
        .iter()
        .find(|entry| entry.tag == tag)
        .ok_or(EngineFailure::Reject(RejectReason::Parse))?;
    fixed_array_zeroizing::<N>(&value.value)
}

fn header_from_tlvs(state: &Rvfb1State) -> Result<[u8; mlkem::HEADER_LEN], EngineFailure> {
    let rho = tlv_array::<32>(state, 2)?;
    let hek = tlv_array::<32>(state, 3)?;
    let mut header = [0u8; mlkem::HEADER_LEN];
    header[..32].copy_from_slice(&rho[..]);
    header[32..].copy_from_slice(&hek[..]);
    Ok(header)
}

fn new_active_send(
    direction: u8,
    epoch: u64,
    wire_type: u8,
    source_kind: u8,
    source_bytes: Vec<u8>,
) -> ActiveSend {
    ActiveSend {
        direction,
        epoch,
        wire_type,
        source_kind,
        source_len: source_bytes.len() as u32,
        source_digest: send_source_digest(&source_bytes),
        source_bytes,
        next_spqr_index: 0,
    }
}

fn emit_expected_active(
    state: &mut Rvfb1State,
    wire_type: u8,
    cap_chunks: u32,
) -> Result<Rvbc1, EngineFailure> {
    if state.active_send.as_ref().map(|active| active.wire_type) != Some(wire_type) {
        return Err(EngineFailure::Reject(RejectReason::Parse));
    }
    emit_active(state, cap_chunks)
}

fn emit_active(state: &mut Rvfb1State, cap_chunks: u32) -> Result<Rvbc1, EngineFailure> {
    let active = state
        .active_send
        .as_mut()
        .ok_or(EngineFailure::Reject(RejectReason::Parse))?;
    if active.epoch != state.prefix.braid_agent_epoch
        || active.direction != send_direction(state.prefix.role)?
        || active.next_spqr_index > BRAID_MAX_CHUNKS_PER_EPOCH as u32
    {
        return Err(EngineFailure::Reject(RejectReason::Parse));
    }
    let index = cursor_index(active.next_spqr_index, cap_chunks);
    let payload = encoded_chunk(&active.source_bytes, index)?;
    let frame = Rvbc1 {
        epoch: active.epoch,
        chunk_type: active.wire_type,
        index,
        binding_digest: binding_digest(
            active.direction,
            active.epoch,
            active.wire_type,
            index,
            &payload,
            &state.prefix.session_id,
        ),
        payload,
    };
    // The index space is bounded by the receivers' inbound cap, so the cursor
    // cycles instead of stalling: a re-sent index carries the identical
    // deterministic payload and is applied by the peer as a decoder no-op.
    // It wraps at the host's `cap_chunks` (never above 64): wrapping only at 64
    // would walk into `enforce_env_caps` under a tightened cap and wedge every
    // later Send, so a lost low index could never be re-sent.
    active.next_spqr_index = (index + 1) % cursor_modulus(cap_chunks);
    Ok(frame)
}

/// Size of the chunk-index space a sender cycles through: the host's inbound
/// `cap_chunks` clamped to `1..=BRAID_MAX_CHUNKS_PER_EPOCH`. A zero cap still
/// maps to 1 (no `% 0`); such a Send is refused as `ERR_NEED_CAPACITY` by the
/// pipeline's cap checks instead of being emitted.
pub(crate) fn cursor_modulus(cap_chunks: u32) -> u32 {
    cap_chunks.clamp(1, BRAID_MAX_CHUNKS_PER_EPOCH as u32)
}

/// Chunk index emitted for a persisted cursor (`64` is the legacy exhausted
/// sentinel and wraps to index 0). A cursor persisted under a larger cap than
/// the current one is folded into the current index space.
pub(crate) fn cursor_index(next_spqr_index: u32, cap_chunks: u32) -> u32 {
    let index = if next_spqr_index > BRAID_MAX_CHUNK_INDEX {
        0
    } else {
        next_spqr_index
    };
    index % cursor_modulus(cap_chunks)
}

fn encoded_chunk(source: &[u8], index: u32) -> Result<Vec<u8>, EngineFailure> {
    let mut encoder =
        BraidEncoder::encode(source).map_err(|_| EngineFailure::Reject(RejectReason::Parse))?;
    Ok(encoder
        .chunk_at(index)
        .map_err(|_| EngineFailure::Reject(RejectReason::Parse))?
        .to_vec())
}

/// The first CT1 frame (index 0) an encapsulator emits for `epoch`; its nested
/// TR confirm is bound to exactly this RVBC1 (see `apply_send` HeaderReceived).
fn first_ct1_frame(
    state: &Rvfb1State,
    direction: u8,
    epoch: u64,
    ct1: &[u8],
) -> Result<Rvbc1, EngineFailure> {
    let payload = encoded_chunk(ct1, 0)?;
    Ok(Rvbc1 {
        epoch,
        chunk_type: WIRE_CT1,
        index: 0,
        binding_digest: binding_digest(
            direction,
            epoch,
            WIRE_CT1,
            0,
            &payload,
            &state.prefix.session_id,
        ),
        payload,
    })
}

fn empty_frame(state: &Rvfb1State, direction: u8, wire_type: u8) -> Rvbc1 {
    let epoch = state.prefix.braid_agent_epoch;
    Rvbc1 {
        epoch,
        chunk_type: wire_type,
        index: 0,
        payload: Vec::new(),
        binding_digest: binding_digest(
            direction,
            epoch,
            wire_type,
            0,
            &[],
            &state.prefix.session_id,
        ),
    }
}

fn source_len(source_kind: u8) -> Result<usize, EngineFailure> {
    match source_kind {
        SOURCE_KIND_HDR => Ok(L_HDR),
        SOURCE_KIND_EK => Ok(L_EK),
        SOURCE_KIND_CT1 => Ok(L_CT1),
        SOURCE_KIND_CT2 => Ok(L_CT2),
        _ => Err(EngineFailure::Reject(RejectReason::Parse)),
    }
}

fn empty_inbound_set(
    direction: u8,
    epoch: u64,
    source_kind: u8,
) -> Result<InboundSet, EngineFailure> {
    Ok(InboundSet {
        direction,
        epoch,
        source_kind,
        expected_source_len: source_len(source_kind)? as u32,
        max_index: BRAID_MAX_CHUNK_INDEX,
        bitmap: vec![0u8; BRAID_MAX_CHUNKS_PER_EPOCH.div_ceil(8)],
        chunks: Vec::new(),
    })
}

fn decoder_insert(
    state: &mut Rvfb1State,
    direction: u8,
    frame: &Rvbc1,
    source_kind: u8,
) -> Result<Option<Vec<u8>>, EngineFailure> {
    let key = (direction, frame.epoch, source_kind);
    let position = state
        .inbound_sets
        .iter()
        .position(|set| (set.direction, set.epoch, set.source_kind) == key);
    let set_index = if let Some(index) = position {
        index
    } else {
        if state.inbound_sets.len() >= 8 {
            return Err(EngineFailure::Reject(RejectReason::Parse));
        }
        state
            .inbound_sets
            .push(empty_inbound_set(direction, frame.epoch, source_kind)?);
        state
            .inbound_sets
            .sort_by_key(|set| (set.direction, set.epoch, set.source_kind));
        state
            .inbound_sets
            .iter()
            .position(|set| (set.direction, set.epoch, set.source_kind) == key)
            .expect("inserted inbound set")
    };
    let set = &mut state.inbound_sets[set_index];
    if set.expected_source_len as usize != source_len(source_kind)?
        || set.max_index != BRAID_MAX_CHUNK_INDEX
        || set.bitmap.len() != BRAID_MAX_CHUNKS_PER_EPOCH.div_ceil(8)
    {
        return Err(EngineFailure::Reject(RejectReason::Parse));
    }

    match set
        .chunks
        .binary_search_by_key(&frame.index, |chunk| chunk.index)
    {
        Ok(index) => {
            // Chunks are deterministic per (epoch, kind, index), so a differing
            // payload is unauthenticated noise or injection: drop it without
            // commit rather than letting one bad chunk terminalize the session.
            if set.chunks[index].payload != frame.payload {
                return Err(EngineFailure::Reject(RejectReason::Parse));
            }
        }
        Err(index) => {
            if set.chunks.len() >= BRAID_MAX_CHUNKS_PER_EPOCH {
                return Err(EngineFailure::Reject(RejectReason::Parse));
            }
            set.chunks.insert(
                index,
                InboundChunk {
                    index: frame.index,
                    payload: frame.payload.clone(),
                },
            );
            let byte = frame.index as usize / 8;
            let bit = frame.index % 8;
            set.bitmap[byte] |= 1 << bit;
        }
    }

    let mut decoder = BraidDecoder::new(set.expected_source_len as usize)
        .map_err(|_| EngineFailure::Reject(RejectReason::Parse))?;
    for chunk in &set.chunks {
        decoder
            .add_chunk(chunk.index, &chunk.payload)
            .map_err(|_| EngineFailure::Reject(RejectReason::Parse))?;
    }
    if decoder.has_message() {
        decoder
            .message()
            .map(Some)
            .map_err(|_| EngineFailure::Reject(RejectReason::Parse))
    } else {
        Ok(None)
    }
}

fn apply_first_ct1_ack<C: BraidCrypto>(
    state: &mut Rvfb1State,
    crypto: &mut C,
) -> Result<(), EngineFailure> {
    if state.prefix.flags & FLAG_CT1_ACK_APPLIED != 0 {
        return Ok(());
    }
    crypto.ct1_ack_advance(state.prefix.braid_agent_epoch)?;
    state.prefix.flags |= FLAG_CT1_ACK_APPLIED;
    Ok(())
}

fn enter_ct1_acknowledged(state: &mut Rvfb1State) -> Result<(), EngineFailure> {
    let rho = tlv_array::<32>(state, 2)?;
    let hek = tlv_array::<32>(state, 3)?;
    let encaps_state = tlv_array::<{ mlkem::STATE_LEN }>(state, 5)?;
    let ct1 = tlv_array::<{ mlkem::CT1_LEN }>(state, 6)?;
    state.tlvs = vec![
        tlv_entry(2, &rho),
        tlv_entry(3, &hek),
        tlv_entry(5, &encaps_state),
        tlv_entry(6, &ct1),
    ];
    state.active_send = None;
    state.prefix.agent = AGENT_CT1_ACKNOWLEDGED;
    Ok(())
}

fn finish_encaps2<C: BraidCrypto>(
    state: &mut Rvfb1State,
    ek_vector: &[u8],
    crypto: &mut C,
) -> Result<(), EngineFailure> {
    let ek: [u8; mlkem::EK_VECTOR_LEN] = fixed_array(ek_vector)?;
    let header = header_from_tlvs(state)?;
    let encaps_state = tlv_array::<{ mlkem::STATE_LEN }>(state, 5)?;
    let ct1 = tlv_array::<{ mlkem::CT1_LEN }>(state, 6)?;
    let ct2 = crypto.encaps2(&encaps_state, &header, &ek)?;
    let ep = state.prefix.braid_agent_epoch;
    let auth = auth_from_state(state);
    let full_ct = full_ciphertext(&ct1, &ct2);
    let tag = auth.mac_ct(ep, &full_ct);
    let mut source = Vec::with_capacity(L_CT2);
    source.extend_from_slice(&ct2);
    source.extend_from_slice(&tag);
    state.tlvs = vec![tlv_entry(6, &ct1), tlv_entry(7, &ct2)];
    state.active_send = Some(new_active_send(
        send_direction(state.prefix.role)?,
        state.prefix.braid_agent_epoch,
        WIRE_CT2,
        SOURCE_KIND_CT2,
        source,
    ));
    state.prefix.flags |= FLAG_CT1_ACK_APPLIED;
    state.prefix.agent = AGENT_CT2_SAMPLED;
    Ok(())
}

fn promote_scka_send(
    tr: &mut Rvft1,
    epoch: u64,
    shared_secret: &[u8; 32],
) -> Result<(), EngineFailure> {
    let (rk, ck) = kdf_scka_rk(&tr.scka_rk, shared_secret)
        .map_err(|_| EngineFailure::Terminal(TERMINAL_REASON_TR_CONFIRM))?;
    tr.scka_rk = rk;
    tr.scka_sending_epoch = epoch;
    insert_chain(&mut tr.scka_send_chain, SckaChainEntry { epoch, ck, n: 0 });
    Ok(())
}

fn promote_scka_receive(
    tr: &mut Rvft1,
    epoch: u64,
    shared_secret: &[u8; 32],
) -> Result<(), EngineFailure> {
    let (rk, ck) = kdf_scka_rk(&tr.scka_rk, shared_secret)
        .map_err(|_| EngineFailure::Terminal(TERMINAL_REASON_TR_CONFIRM))?;
    tr.scka_rk = rk;
    tr.scka_receiving_epoch = epoch;
    insert_chain(&mut tr.scka_recv_chain, SckaChainEntry { epoch, ck, n: 0 });
    Ok(())
}

fn insert_chain(chain: &mut Vec<SckaChainEntry>, entry: SckaChainEntry) {
    chain.retain(|existing| existing.epoch != entry.epoch);
    chain.push(entry);
    chain.sort_by_key(|existing| existing.epoch);
    if chain.len() > MAX_SCKA_CHAIN {
        chain.remove(0);
    }
}

/// Single terminalization routine (engine terminals and pipeline repairs).
pub(crate) fn terminalize(state: &mut Rvfb1State, reason: u16) {
    state.prefix.agent = AGENT_TERMINAL;
    state.prefix.terminal_reason = reason;
    state.prefix.flags = FLAG_TERMINAL;
    state.prefix.auth_root = [0u8; 32];
    state.prefix.auth_mac_key = [0u8; 32];
    state.active_send = None;
    state.tlvs.clear();
    zeroize_tr(&mut state.tr);
}

fn zeroize_tr(tr: &mut Rvft1) {
    tr.scka_rk = [0u8; 32];
    tr.scka_sending_epoch = 0;
    tr.scka_receiving_epoch = 0;
    tr.scka_send_chain.clear();
    tr.scka_recv_chain.clear();
    tr.scka_send_pn = 0;
    tr.scka_skipped.clear();
    tr.ec_rk = [0u8; 32];
    tr.ec_dhs_priv = [0u8; 32];
    tr.ec_dhs_pub = [0u8; 32];
    tr.ec_dhr_present = 0;
    tr.ec_dhr_pub = [0u8; 32];
    tr.ec_ck_send_present = 0;
    tr.ec_ck_recv_present = 0;
    tr.ec_ck_send = [0u8; 32];
    tr.ec_ck_recv = [0u8; 32];
    tr.ec_ns = 0;
    tr.ec_nr = 0;
    tr.ec_pn = 0;
    tr.ec_skipped.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_ratchet_v2_full_braid::constants::{FLAG_CT1_ACK_APPLIED, FLAG_TERMINAL};
    use crate::hybrid_ratchet_v2_full_braid::digest::{
        binding_digest, execution_digest, send_source_digest,
    };
    use crate::hybrid_ratchet_v2_full_braid::spqr_codec::{
        BraidEncoder, BRAID_MAX_CHUNK_INDEX, WIRE_CT1, WIRE_EK, WIRE_EK_CT1_ACK, WIRE_NONE,
    };
    use crate::hybrid_ratchet_v2_full_braid::spqr_pin_audit::{
        CW, L_CT1, L_CT2, L_EK, L_HDR, N_CT1, N_CT2, N_EK, N_HDR,
    };
    use crate::hybrid_ratchet_v2_full_braid::state_codec::{
        encode_rvfb1, ActiveSend, InboundChunk, InboundSet, ReplayRecord, Rvfb1Prefix, Rvfb1State,
        TlvEntry, DIR_A2B, DIR_B2A, ROLE_ALICE, ROLE_BOB, SOURCE_KIND_CT1, SOURCE_KIND_CT2,
        SOURCE_KIND_EK, SOURCE_KIND_HDR,
    };
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbc1::{encode_rvbc1, Rvbc1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbe1::{encode_rvbe1, Rvbe1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbi1::{
        encode_rvbi1, Rvbi1, OP_RECEIVE, OP_SEND,
    };
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::Rvbm1;
    use crate::hybrid_ratchet_v2_full_braid::wire_rvft1::{Rvft1, SckaChainEntry};

    fn tlv(tag: u16, len: usize, byte: u8) -> TlvEntry {
        TlvEntry {
            tag,
            value: vec![byte; len],
        }
    }

    fn tlvs_for_agent(agent: u8) -> Vec<TlvEntry> {
        match agent {
            AGENT_KEYS_UNSAMPLED | AGENT_NO_HEADER_RECEIVED | AGENT_TERMINAL => Vec::new(),
            AGENT_KEYS_SAMPLED => vec![
                tlv(1, 2400, 1),
                tlv(2, 32, 2),
                tlv(3, 32, 3),
                tlv(4, L_EK, 4),
                tlv(8, 64, 8),
            ],
            AGENT_HEADER_SENT => vec![tlv(1, 2400, 1), tlv(4, L_EK, 4)],
            AGENT_CT1_RECEIVED => vec![tlv(1, 2400, 1), tlv(4, L_EK, 4), tlv(6, L_CT1, 6)],
            AGENT_EK_SENT_CT1_RECEIVED => {
                vec![tlv(1, 2400, 1), tlv(6, L_CT1, 6)]
            }
            AGENT_HEADER_RECEIVED => vec![tlv(2, 32, 2), tlv(3, 32, 3)],
            AGENT_CT1_SAMPLED | AGENT_CT1_ACKNOWLEDGED => vec![
                tlv(2, 32, 2),
                tlv(3, 32, 3),
                tlv(5, 2080, 5),
                tlv(6, L_CT1, 6),
            ],
            AGENT_EK_RECEIVED_CT1_SAMPLED => vec![
                tlv(2, 32, 2),
                tlv(3, 32, 3),
                tlv(4, L_EK, 4),
                tlv(5, 2080, 5),
                tlv(6, L_CT1, 6),
            ],
            AGENT_CT2_SAMPLED => vec![tlv(7, 128, 7)],
            _ => panic!("unsupported test agent"),
        }
    }

    fn test_tr() -> Rvft1 {
        Rvft1 {
            scka_rk: [0x11; 32],
            scka_sending_epoch: 0,
            scka_receiving_epoch: 0,
            scka_send_chain: vec![SckaChainEntry {
                epoch: 0,
                ck: [0x12; 32],
                n: 0,
            }],
            scka_recv_chain: vec![SckaChainEntry {
                epoch: 0,
                ck: [0x13; 32],
                n: 0,
            }],
            scka_send_pn: 0,
            scka_skipped: Vec::new(),
            ec_rk: [0x21; 32],
            ec_dhs_priv: [0x22; 32],
            ec_dhs_pub: [0x23; 32],
            ec_dhr_present: 0,
            ec_dhr_pub: [0; 32],
            ec_ck_send_present: 0,
            ec_ck_recv_present: 0,
            ec_ck_send: [0; 32],
            ec_ck_recv: [0; 32],
            ec_ns: 0,
            ec_nr: 0,
            ec_pn: 0,
            ec_skipped: Vec::new(),
        }
    }

    fn test_state(agent: u8, role: u8) -> Rvfb1State {
        let flags = match agent {
            AGENT_CT1_ACKNOWLEDGED | AGENT_CT2_SAMPLED => FLAG_CT1_ACK_APPLIED,
            AGENT_TERMINAL => FLAG_TERMINAL,
            _ => 0,
        };
        let terminal_reason = if agent == AGENT_TERMINAL {
            TERMINAL_REASON_CONFLICT
        } else {
            0
        };
        let state = Rvfb1State {
            prefix: Rvfb1Prefix {
                session_id: [0xA5; 32],
                role,
                generation: 0,
                agent,
                terminal_reason,
                auth_root: [0x31; 32],
                auth_mac_key: [0x32; 32],
                braid_agent_epoch: 1,
                braid_send_epoch: 0,
                braid_recv_epoch: 0,
                flags,
                pending_phase: 0,
                pending_transition_id: [0; 32],
                pending_before_digest: [0; 32],
                pending_output_digest: [0; 32],
                pending_execution_digest: [0; 32],
            },
            inbound_sets: Vec::new(),
            active_send: None,
            objects: Vec::new(),
            replays: Vec::new(),
            tlvs: tlvs_for_agent(agent),
            tr: test_tr(),
        };
        encode_rvfb1(&state).expect("test state is canonical");
        state
    }

    fn expected_len(kind: u8) -> usize {
        match kind {
            SOURCE_KIND_HDR => L_HDR,
            SOURCE_KIND_EK => L_EK,
            SOURCE_KIND_CT1 => L_CT1,
            SOURCE_KIND_CT2 => L_CT2,
            _ => panic!("source kind"),
        }
    }

    fn inbound_set(
        direction: u8,
        epoch: u64,
        source_kind: u8,
        chunks: Vec<InboundChunk>,
    ) -> InboundSet {
        let mut bitmap = vec![0u8; 8];
        for chunk in &chunks {
            bitmap[chunk.index as usize / 8] |= 1 << (chunk.index % 8);
        }
        InboundSet {
            direction,
            epoch,
            source_kind,
            expected_source_len: expected_len(source_kind) as u32,
            max_index: BRAID_MAX_CHUNK_INDEX,
            bitmap,
            chunks,
        }
    }

    fn frame(
        state: &Rvfb1State,
        direction: u8,
        epoch: u64,
        typ: u8,
        index: u32,
        payload: Vec<u8>,
    ) -> Rvbc1 {
        Rvbc1 {
            epoch,
            chunk_type: typ,
            index,
            binding_digest: binding_digest(
                direction,
                epoch,
                typ,
                index,
                &payload,
                &state.prefix.session_id,
            ),
            payload,
        }
    }

    fn receive_input(_state: &Rvfb1State, direction: u8, chunk: Rvbc1) -> Rvbi1 {
        Rvbi1 {
            op: OP_RECEIVE,
            direction,
            ch: None,
            expected_ch: None,
            object_digest: Some([0xD0; 32]),
            frame: Some(encode_rvbc1(&chunk).unwrap()),
            mutation: Rvbm1::no_aead(),
        }
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

    fn seal_mutation_for(state: &Rvfb1State, direction: u8) -> Rvbm1 {
        use crate::hybrid_ratchet_v2_full_braid::tr_confirm::{encode_rvba1, Rvba1};
        use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::{MODE_SEAL_COMPARE, RVBA1_LEN};
        let rvba1 = Rvba1::build(
            state.prefix.session_id,
            direction,
            [0x21; 32],
            [0x22; 32],
            [0x31; 32],
            [0x32; 32],
        )
        .unwrap();
        let aad = encode_rvba1(&rvba1).unwrap();
        assert_eq!(aad.len(), RVBA1_LEN);
        let body = b"tr-confirm-body".to_vec();
        Rvbm1 {
            needs_aead: 1,
            ec_mk_oracle_len: 0,
            ec_mk_oracle: [0u8; 32],
            aad,
            mode: MODE_SEAL_COMPARE,
            body: body.clone(),
            expected_ct: Some(vec![0u8; body.len() + 16]),
        }
    }

    #[test]
    fn needs_aead_accept_without_scka_promote_is_rejected() {
        let state = test_state(AGENT_KEYS_UNSAMPLED, ROLE_ALICE);
        let mut env = Rvbe1::default_caps(0).with_lab_trust();
        env.keygen_seed = vec![0xA1; mlkem::SEED_LEN];
        let mut input = send_input(DIR_A2B);
        input.mutation = seal_mutation_for(&state, DIR_A2B);
        let mut crypto = LabCrypto::default();
        let result = transition(&state, &input, &env, &mut crypto);
        assert_eq!(
            result.disposition,
            Disposition::Reject {
                reason: RejectReason::Parse
            }
        );
        assert_eq!(result.candidate.prefix.agent, AGENT_KEYS_UNSAMPLED);
    }

    #[test]
    fn needs_aead_requires_env_admitted_trust_not_labcrypto() {
        let state = test_state(AGENT_KEYS_UNSAMPLED, ROLE_ALICE);
        let mut env = Rvbe1::default_caps(0); // no admitted_trust
        env.keygen_seed = vec![0xA1; mlkem::SEED_LEN];
        // Even on non-promote path, needs_aead=1 without env trust is rejected at Accept gate.
        let mut input = send_input(DIR_A2B);
        input.mutation = seal_mutation_for(&state, DIR_A2B);
        let mut crypto = LabCrypto::default();
        let result = transition(&state, &input, &env, &mut crypto);
        assert_eq!(
            result.disposition,
            Disposition::Reject {
                reason: RejectReason::Parse
            }
        );
    }

    #[test]
    fn needs_aead_at_promote_invokes_hook_before_scka() {
        let mut alice = test_state(AGENT_KEYS_UNSAMPLED, ROLE_ALICE);
        let mut bob = test_state(AGENT_NO_HEADER_RECEIVED, ROLE_BOB);
        bob.inbound_sets = vec![inbound_set(DIR_A2B, 1, SOURCE_KIND_HDR, Vec::new())];
        let mut alice_env = Rvbe1::default_caps(0);
        alice_env.keygen_seed = vec![0xA7; mlkem::SEED_LEN];
        let mut bob_env = Rvbe1::default_caps(0).with_lab_trust();
        bob_env.encaps_coins = vec![0xB8; mlkem::COINS_LEN];
        let mut alice_crypto = LabCrypto::default();
        let mut bob_crypto = LabCrypto::default();

        for _ in 0..N_HDR {
            let sent = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
            alice = sent.candidate;
            bob = transition(
                &bob,
                &receive_input(&bob, DIR_A2B, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut bob_crypto,
            )
            .candidate;
        }
        assert_eq!(bob.prefix.agent, AGENT_HEADER_RECEIVED);
        let before_scka = bob.tr.scka_sending_epoch;
        let before_ec_ns = bob.tr.ec_ns;

        let mut input = send_input(DIR_B2A);
        input.mutation = seal_mutation_for(&bob, DIR_B2A);
        // Wrong expected_ct fails the confirm before promote: a no-commit Reject
        // (§4.2 step 7), not a durable terminal; SCKA/EC must stay put.
        let result = transition(&bob, &input, &bob_env, &mut bob_crypto);
        assert_eq!(
            result.disposition,
            Disposition::Reject {
                reason: RejectReason::Parse
            }
        );
        assert_eq!(result.candidate, bob);
        assert_eq!(result.candidate.prefix.agent, AGENT_HEADER_RECEIVED);
        assert_eq!(bob.tr.scka_sending_epoch, before_scka);
        assert_eq!(bob.tr.ec_ns, before_ec_ns);
        assert!(result.ch_out.is_none());
        assert!(result.sealed_ct.is_none());
    }

    #[test]
    fn needs_aead_rejects_env_trust_mismatch_vs_rvba1() {
        let mut alice = test_state(AGENT_KEYS_UNSAMPLED, ROLE_ALICE);
        let mut bob = test_state(AGENT_NO_HEADER_RECEIVED, ROLE_BOB);
        bob.inbound_sets = vec![inbound_set(DIR_A2B, 1, SOURCE_KIND_HDR, Vec::new())];
        let bob_priv = [0x71; 32];
        let bob_pub = crate::hybrid_ratchet_v2_tr::x25519_public(&bob_priv).unwrap();
        let peer = bob.tr.ec_dhs_pub;
        let ss = crate::hybrid_ratchet_v2_tr::x25519_dh(&bob_priv, &peer).unwrap();
        let (rk, ck) = crate::hybrid_ratchet_v2::kdf_rk(&bob.tr.ec_rk, &ss).unwrap();
        bob.tr.ec_rk = rk;
        bob.tr.ec_dhs_priv = bob_priv;
        bob.tr.ec_dhs_pub = bob_pub;
        bob.tr.ec_dhr_present = 1;
        bob.tr.ec_dhr_pub = peer;
        bob.tr.ec_ck_send_present = 1;
        bob.tr.ec_ck_send = ck;

        let mut alice_env = Rvbe1::default_caps(0);
        alice_env.keygen_seed = vec![0xAA; mlkem::SEED_LEN];
        let mut bob_env = Rvbe1::default_caps(0).with_lab_trust();
        bob_env.encaps_coins = vec![0xBB; mlkem::COINS_LEN];
        // Mutate admitted trust away from the RVBA1 built by seal_mutation_for.
        bob_env
            .admitted_trust
            .as_mut()
            .unwrap()
            .initiator_cert_digest[0] ^= 0xFF;
        let mut alice_crypto = LabCrypto::default();
        let mut bob_crypto = LabCrypto::default();
        for _ in 0..N_HDR {
            let sent = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
            alice = sent.candidate;
            bob = transition(
                &bob,
                &receive_input(&bob, DIR_A2B, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut bob_crypto,
            )
            .candidate;
        }
        let mut input = send_input(DIR_B2A);
        input.mutation = seal_mutation_for(&bob, DIR_B2A);
        let result = transition(&bob, &input, &bob_env, &mut bob_crypto);
        assert_eq!(
            result.disposition,
            Disposition::Reject {
                reason: RejectReason::Parse
            }
        );
    }

    #[test]
    fn needs_aead_success_commits_ec_and_emits_exact_rvbo1() {
        use crate::hybrid_ratchet_v2_full_braid::tr_confirm::{
            advance_ec_candidate, build_effective_ad, encode_rvba1, rvch1_from_send_state,
            seal_compare, Rvba1,
        };
        use crate::hybrid_ratchet_v2_full_braid::wire_rvbo1::{decode_rvbo1, encode_rvbo1, Rvbo1};
        use crate::hybrid_ratchet_v2_full_braid::wire_rvch1::encode_rvch1;
        use crate::hybrid_ratchet_v2_tr::EcDrHeader;
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let mut alice = test_state(AGENT_KEYS_UNSAMPLED, ROLE_ALICE);
        let mut bob = test_state(AGENT_NO_HEADER_RECEIVED, ROLE_BOB);
        bob.inbound_sets = vec![inbound_set(DIR_A2B, 1, SOURCE_KIND_HDR, Vec::new())];
        // Alice init has ck_send; Bob needs a send chain before AEAD confirm.
        let bob_priv = [0x71; 32];
        let bob_pub = crate::hybrid_ratchet_v2_tr::x25519_public(&bob_priv).unwrap();
        let peer = bob.tr.ec_dhs_pub;
        let ss = crate::hybrid_ratchet_v2_tr::x25519_dh(&bob_priv, &peer).unwrap();
        let (rk, ck) = crate::hybrid_ratchet_v2::kdf_rk(&bob.tr.ec_rk, &ss).unwrap();
        bob.tr.ec_rk = rk;
        bob.tr.ec_dhs_priv = bob_priv;
        bob.tr.ec_dhs_pub = bob_pub;
        bob.tr.ec_dhr_present = 1;
        bob.tr.ec_dhr_pub = peer;
        bob.tr.ec_ck_send_present = 1;
        bob.tr.ec_ck_send = ck;
        bob.tr.ec_ns = 0;
        bob.tr.ec_pn = 0;

        let mut alice_env = Rvbe1::default_caps(0);
        alice_env.keygen_seed = vec![0xA9; mlkem::SEED_LEN];
        let mut bob_env = Rvbe1::default_caps(0).with_lab_trust();
        bob_env.encaps_coins = vec![0xB9; mlkem::COINS_LEN];
        let mut alice_crypto = LabCrypto::default();
        let mut bob_crypto = LabCrypto::default();

        for _ in 0..N_HDR {
            let sent = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
            alice = sent.candidate;
            bob = transition(
                &bob,
                &receive_input(&bob, DIR_A2B, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut bob_crypto,
            )
            .candidate;
        }
        assert_eq!(bob.prefix.agent, AGENT_HEADER_RECEIVED);
        let ep = bob.prefix.braid_agent_epoch;
        let before_ec_ns = bob.tr.ec_ns;

        let rho = bob.tlvs.iter().find(|t| t.tag == 2).unwrap();
        let hek = bob.tlvs.iter().find(|t| t.tag == 3).unwrap();
        let mut header = [0u8; mlkem::HEADER_LEN];
        header[..32].copy_from_slice(&rho.value);
        header[32..].copy_from_slice(&hek.value);
        let coins: [u8; mlkem::COINS_LEN] = bob_env.encaps_coins.as_slice().try_into().unwrap();
        let encaps = LabCrypto::default().encaps1(&header, &coins).unwrap();
        let scka_mk = authenticator::kdf_ok(&encaps.shared_secret, ep);

        let evidence =
            crate::hybrid_ratchet_v2_full_braid::tr_confirm::AdmittedTrustEvidence::lab_default();
        let rvba1 = Rvba1::build(
            bob.prefix.session_id,
            DIR_B2A,
            evidence.initiator_cert_digest,
            evidence.initiator_identity_pub,
            evidence.responder_cert_digest,
            evidence.responder_identity_pub,
        )
        .unwrap();
        let ch = rvch1_from_send_state(&bob.tr, DIR_B2A, ep).unwrap();
        let hdr = EcDrHeader {
            dh_pub: ch.ec_dh_pub,
            pn: ch.ec_pn,
            n: ch.ec_n,
        };
        let (_cand, ec_mk) = advance_ec_candidate(&bob.tr, OP_SEND, &hdr, None).unwrap();

        // Preview frame via no-AEAD transition on a clone (same encaps coins).
        let preview = transition(
            &bob,
            &send_input(DIR_B2A),
            &bob_env,
            &mut LabCrypto::default(),
        );
        assert_eq!(preview.disposition, Disposition::Accept);
        let frame = preview.frame.clone().unwrap();
        let rvba1_bytes = encode_rvba1(&rvba1).unwrap();
        let rvch1_bytes = encode_rvch1(&ch);
        let rvbc1_bytes = encode_rvbc1(&frame).unwrap();
        let ad = build_effective_ad(&rvba1_bytes, &rvch1_bytes, &rvbc1_bytes).unwrap();
        let body = b"tr-confirm-body".to_vec();
        let (key, nonce) = crate::hybrid_ratchet_v2::kdf_hybrid(&ec_mk, &scka_mk);
        let sealed = ChaCha20Poly1305::new((&key).into())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &body,
                    aad: &ad,
                },
            )
            .unwrap();
        seal_compare(&ec_mk, &scka_mk, &ad, &body, &sealed, 0, &[0u8; 32]).unwrap();

        let mut input = send_input(DIR_B2A);
        input.mutation = Rvbm1 {
            needs_aead: 1,
            ec_mk_oracle_len: 0,
            ec_mk_oracle: [0u8; 32],
            aad: rvba1_bytes,
            mode: crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::MODE_SEAL_COMPARE,
            body,
            expected_ct: Some(sealed.clone()),
        };
        let result = transition(&bob, &input, &bob_env, &mut LabCrypto::default());
        assert_eq!(result.disposition, Disposition::Accept);
        assert_eq!(result.ch_out.as_ref(), Some(&ch));
        assert_eq!(result.sealed_ct.as_ref(), Some(&sealed));
        assert_eq!(result.candidate.tr.ec_ns, before_ec_ns + 1);
        assert!(
            result.candidate.tr.scka_sending_epoch >= 1 || result.meta.output_key_epoch == Some(ep)
        );

        let outputs = encode_rvbo1(&Rvbo1 {
            frames: vec![encode_rvbc1(result.frame.as_ref().unwrap()).unwrap()],
            ch_out: result.ch_out.clone(),
            sealed_ct: result.sealed_ct.clone(),
        })
        .unwrap();
        let decoded = decode_rvbo1(&outputs).unwrap();
        assert_eq!(decoded.frames.len(), 1);
        assert_eq!(decoded.ch_out.as_ref(), Some(&ch));
        assert_eq!(decoded.sealed_ct.as_ref(), Some(&sealed));
    }

    #[test]
    fn header_sent_receive_ct1_keeps_ek_encoder_position_and_source() {
        let mut state = test_state(AGENT_HEADER_SENT, ROLE_ALICE);
        let source = (0..L_EK).map(|i| i as u8).collect::<Vec<_>>();
        let active = ActiveSend {
            direction: DIR_A2B,
            epoch: 1,
            wire_type: WIRE_EK,
            source_kind: SOURCE_KIND_EK,
            source_len: L_EK as u32,
            source_digest: send_source_digest(&source),
            source_bytes: source,
            next_spqr_index: 7,
        };
        state.active_send = Some(active.clone());

        let ct1 = (0..L_CT1)
            .map(|i| (i as u8).wrapping_mul(17))
            .collect::<Vec<_>>();
        let mut encoder = BraidEncoder::encode(&ct1).unwrap();
        let mut prior = Vec::new();
        for index in 0..(N_CT1 as u32 - 1) {
            prior.push(InboundChunk {
                index,
                payload: encoder.chunk_at(index).unwrap().to_vec(),
            });
        }
        state.inbound_sets = vec![inbound_set(DIR_B2A, 1, SOURCE_KIND_CT1, prior)];
        encode_rvfb1(&state).unwrap();

        let last = N_CT1 as u32 - 1;
        let chunk = frame(
            &state,
            DIR_B2A,
            1,
            WIRE_CT1,
            last,
            encoder.chunk_at(last).unwrap().to_vec(),
        );
        let input = receive_input(&state, DIR_B2A, chunk);
        let mut crypto = LabCrypto::default();
        let result = transition(&state, &input, &Rvbe1::default_caps(0), &mut crypto);

        assert_eq!(result.disposition, Disposition::Accept);
        assert_eq!(result.candidate.prefix.agent, AGENT_CT1_RECEIVED);
        let after = result.candidate.active_send.as_ref().unwrap();
        assert_eq!(after.wire_type, WIRE_EK_CT1_ACK);
        assert_eq!(after.source_kind, SOURCE_KIND_EK);
        assert_eq!(after.source_bytes, active.source_bytes);
        assert_eq!(after.source_digest, active.source_digest);
        assert_eq!(after.next_spqr_index, active.next_spqr_index);
        assert_eq!(
            result
                .candidate
                .tlvs
                .iter()
                .find(|entry| entry.tag == 6)
                .unwrap()
                .value,
            ct1
        );
        encode_rvfb1(&result.candidate).unwrap();
    }

    #[test]
    fn ek_then_identical_ek_ct1_ack_applies_ack_despite_decoder_noop() {
        let mut state = test_state(AGENT_CT1_SAMPLED, ROLE_BOB);
        state.inbound_sets = vec![inbound_set(DIR_A2B, 1, SOURCE_KIND_EK, Vec::new())];
        let source = vec![0x42; L_EK];
        let mut encoder = BraidEncoder::encode(&source).unwrap();
        let payload = encoder.chunk_at(0).unwrap().to_vec();
        let ek = frame(&state, DIR_A2B, 1, WIRE_EK, 0, payload.clone());
        let mut crypto = LabCrypto::default();
        let inserted = transition(
            &state,
            &receive_input(&state, DIR_A2B, ek),
            &Rvbe1::default_caps(0),
            &mut crypto,
        );

        assert_eq!(inserted.disposition, Disposition::Accept);
        assert_eq!(inserted.candidate.prefix.agent, AGENT_CT1_SAMPLED);
        assert_eq!(inserted.candidate.prefix.flags & FLAG_CT1_ACK_APPLIED, 0);

        let ack = frame(&inserted.candidate, DIR_A2B, 1, WIRE_EK_CT1_ACK, 0, payload);
        let acknowledged = transition(
            &inserted.candidate,
            &receive_input(&inserted.candidate, DIR_A2B, ack),
            &Rvbe1::default_caps(0),
            &mut crypto,
        );

        assert_eq!(acknowledged.disposition, Disposition::Accept);
        assert_eq!(acknowledged.candidate.prefix.agent, AGENT_CT1_ACKNOWLEDGED);
        assert_ne!(
            acknowledged.candidate.prefix.flags & FLAG_CT1_ACK_APPLIED,
            0
        );
        assert_eq!(crypto.ack_advances(), 1);
        assert_eq!(acknowledged.candidate.inbound_sets[0].chunks.len(), 1);
    }

    #[test]
    fn second_ek_ct1_ack_does_not_double_advance_ack() {
        let mut state = test_state(AGENT_CT1_SAMPLED, ROLE_BOB);
        let payload = vec![0x77; CW];
        state.inbound_sets = vec![inbound_set(
            DIR_A2B,
            1,
            SOURCE_KIND_EK,
            vec![InboundChunk {
                index: 0,
                payload: payload.clone(),
            }],
        )];
        let mut crypto = LabCrypto::default();
        let first_frame = frame(&state, DIR_A2B, 1, WIRE_EK_CT1_ACK, 0, payload.clone());
        let first = transition(
            &state,
            &receive_input(&state, DIR_A2B, first_frame),
            &Rvbe1::default_caps(0),
            &mut crypto,
        );
        assert_eq!(crypto.ack_advances(), 1);

        let second_frame = frame(&first.candidate, DIR_A2B, 1, WIRE_EK_CT1_ACK, 0, payload);
        let second = transition(
            &first.candidate,
            &receive_input(&first.candidate, DIR_A2B, second_frame),
            &Rvbe1::default_caps(0),
            &mut crypto,
        );

        assert_eq!(second.disposition, Disposition::Accept);
        assert_eq!(second.candidate.prefix.agent, AGENT_CT1_ACKNOWLEDGED);
        assert_eq!(crypto.ack_advances(), 1);
    }

    #[test]
    fn spqr_ct1_ack_is_emitted_and_completes_the_encapsulator() {
        let mut alice = test_state(AGENT_KEYS_UNSAMPLED, ROLE_ALICE);
        let mut bob = test_state(AGENT_NO_HEADER_RECEIVED, ROLE_BOB);
        bob.inbound_sets = vec![inbound_set(DIR_A2B, 1, SOURCE_KIND_HDR, Vec::new())];
        let mut alice_env = Rvbe1::default_caps(0);
        alice_env.keygen_seed = vec![0xE1; mlkem::SEED_LEN];
        let mut bob_env = Rvbe1::default_caps(0);
        bob_env.encaps_coins = vec![0xE2; mlkem::COINS_LEN];
        let plain = Rvbe1::default_caps(0);
        let mut alice_crypto = LabCrypto::default();
        let mut bob_crypto = LabCrypto::default();

        for _ in 0..N_HDR {
            let frame = plain_send(&mut alice, DIR_A2B, &alice_env, &mut alice_crypto);
            plain_receive(&mut bob, DIR_A2B, frame, &plain, &mut bob_crypto);
        }
        let first_ct1 = plain_send(&mut bob, DIR_B2A, &bob_env, &mut bob_crypto);
        plain_receive(&mut alice, DIR_B2A, first_ct1, &plain, &mut alice_crypto);
        assert_eq!(alice.prefix.agent, AGENT_HEADER_SENT);
        // Full EK before any ack: Ct1Sampled → EkReceivedCt1Sampled.
        for _ in 0..N_EK {
            let frame = plain_send(&mut alice, DIR_A2B, &alice_env, &mut alice_crypto);
            assert_eq!(frame.chunk_type, WIRE_EK);
            plain_receive(&mut bob, DIR_A2B, frame, &plain, &mut bob_crypto);
        }
        assert_eq!(bob.prefix.agent, AGENT_EK_RECEIVED_CT1_SAMPLED);

        // The pinned SPQR Ct1Ack (empty, index 0) finishes Encaps2.
        let ack = frame(&bob, DIR_A2B, 1, WIRE_CT1_ACK, 0, Vec::new());
        plain_receive(&mut bob, DIR_A2B, ack.clone(), &plain, &mut bob_crypto);
        assert_eq!(bob.prefix.agent, AGENT_CT2_SAMPLED);
        assert_eq!(bob_crypto.ack_advances(), 1);

        // And a Ct1Ack before any EK chunk moves Ct1Sampled → Ct1Acknowledged.
        let mut early = test_state(AGENT_CT1_SAMPLED, ROLE_BOB);
        early.inbound_sets = vec![inbound_set(DIR_A2B, 1, SOURCE_KIND_EK, Vec::new())];
        let mut crypto = LabCrypto::default();
        let ack = frame(&early, DIR_A2B, 1, WIRE_CT1_ACK, 0, Vec::new());
        let acked = plain_receive(&mut early, DIR_A2B, ack, &plain, &mut crypto);
        assert_eq!(acked.candidate.prefix.agent, AGENT_CT1_ACKNOWLEDGED);
        assert_eq!(crypto.ack_advances(), 1);

        // EkSentCt1Received emits exactly that Ct1Ack frame.
        let mut keygen = test_state(AGENT_EK_SENT_CT1_RECEIVED, ROLE_ALICE);
        let sent = plain_send(&mut keygen, DIR_A2B, &plain, &mut LabCrypto::default());
        assert_eq!(sent.chunk_type, WIRE_CT1_ACK);
        assert_eq!(sent.index, 0);
        assert!(sent.payload.is_empty());
    }

    #[test]
    fn keys_unsampled_receive_is_ignored_without_commit() {
        let state = test_state(AGENT_KEYS_UNSAMPLED, ROLE_ALICE);
        let chunk = frame(&state, DIR_B2A, 1, WIRE_NONE, 0, Vec::new());
        let mut crypto = LabCrypto::default();
        let result = transition(
            &state,
            &receive_input(&state, DIR_B2A, chunk),
            &Rvbe1::default_caps(0),
            &mut crypto,
        );

        assert_eq!(result.disposition, Disposition::Ignore);
        assert_eq!(result.meta.flags, META_FLAG_IGNORED);
        assert_eq!(result.candidate, state);
    }

    #[test]
    fn terminal_agent_operation_returns_abi_9() {
        let state = test_state(AGENT_TERMINAL, ROLE_ALICE);
        let mut crypto = LabCrypto::default();
        let result = transition(
            &state,
            &send_input(DIR_A2B),
            &Rvbe1::default_caps(0),
            &mut crypto,
        );

        assert_eq!(
            result.disposition,
            Disposition::Reject {
                reason: RejectReason::TerminalStateOp
            }
        );
        assert_eq!(result.disposition.abi_code(), 9);
        assert_eq!(result.candidate, state);
    }

    #[test]
    fn ct2_sampled_wrong_epoch_rejects_epoch() {
        let mut state = test_state(AGENT_CT2_SAMPLED, ROLE_BOB);
        state.prefix.braid_agent_epoch = 4;
        let chunk = frame(&state, DIR_A2B, 6, WIRE_NONE, 0, Vec::new());
        let mut crypto = LabCrypto::default();
        let result = transition(
            &state,
            &receive_input(&state, DIR_A2B, chunk),
            &Rvbe1::default_caps(0),
            &mut crypto,
        );

        assert_eq!(
            result.disposition,
            Disposition::Reject {
                reason: RejectReason::Epoch
            }
        );
        assert_eq!(result.disposition.abi_code(), 3);
        assert_eq!(result.candidate, state);
    }

    #[test]
    fn role_direction_mismatch_rejects_parse() {
        let state = test_state(AGENT_KEYS_UNSAMPLED, ROLE_ALICE);
        let mut crypto = LabCrypto::default();
        let result = transition(
            &state,
            &send_input(DIR_B2A),
            &Rvbe1::default_caps(0),
            &mut crypto,
        );

        assert_eq!(
            result.disposition,
            Disposition::Reject {
                reason: RejectReason::Parse
            }
        );
        assert_eq!(result.disposition.abi_code(), 2);
    }

    #[test]
    fn conflicting_chunk_is_rejected_without_commit() {
        let mut state = test_state(AGENT_CT1_SAMPLED, ROLE_BOB);
        state.inbound_sets = vec![inbound_set(
            DIR_A2B,
            1,
            SOURCE_KIND_EK,
            vec![InboundChunk {
                index: 0,
                payload: vec![0x10; CW],
            }],
        )];
        let conflict = frame(&state, DIR_A2B, 1, WIRE_EK, 0, vec![0x20; CW]);
        let mut crypto = LabCrypto::default();
        let result = transition(
            &state,
            &receive_input(&state, DIR_A2B, conflict),
            &Rvbe1::default_caps(0),
            &mut crypto,
        );

        // An unauthenticated same-index chunk must not kill the session (§4.2).
        assert_eq!(
            result.disposition,
            Disposition::Reject {
                reason: RejectReason::Parse
            }
        );
        assert_eq!(result.candidate, state);

        // The honest chunk already stored still applies as a no-op afterwards.
        let honest = frame(&state, DIR_A2B, 1, WIRE_EK, 0, vec![0x10; CW]);
        let replayed = transition(
            &state,
            &receive_input(&state, DIR_A2B, honest),
            &Rvbe1::default_caps(0),
            &mut crypto,
        );
        assert_eq!(replayed.disposition, Disposition::Accept);
        assert_eq!(replayed.candidate.prefix.agent, AGENT_CT1_SAMPLED);
    }

    #[test]
    fn matching_execution_digest_is_replay_hit_before_table_dispatch() {
        let mut state = test_state(AGENT_KEYS_UNSAMPLED, ROLE_ALICE);
        let chunk = frame(&state, DIR_B2A, 1, WIRE_NONE, 0, Vec::new());
        let input = receive_input(&state, DIR_B2A, chunk);
        let env = Rvbe1::default_caps(0);
        let exec = execution_digest(&encode_rvbi1(&input).unwrap(), &encode_rvbe1(&env).unwrap());
        state.replays.push(ReplayRecord {
            transition_id: [0x01; 32],
            execution_digest: exec,
            output_digest: [0x02; 32],
            output_len: 14,
            flags: 0,
        });
        let mut crypto = LabCrypto::default();
        let result = transition(&state, &input, &env, &mut crypto);

        assert_eq!(result.disposition, Disposition::ReplayHit);
        assert_eq!(result.meta.flags, META_FLAG_REPLAY_HIT);
        assert_eq!(result.candidate, state);
    }

    #[test]
    fn keys_unsampled_send_uses_env_seed_and_emits_header_zero() {
        let state = test_state(AGENT_KEYS_UNSAMPLED, ROLE_ALICE);
        let mut env = Rvbe1::default_caps(0);
        env.keygen_seed = vec![0x5A; 64];
        let mut crypto = LabCrypto::default();
        let result = transition(&state, &send_input(DIR_A2B), &env, &mut crypto);

        assert_eq!(result.disposition, Disposition::Accept);
        assert_eq!(result.candidate.prefix.agent, AGENT_KEYS_SAMPLED);
        assert_eq!(result.meta.sending_epoch, 0);
        let output = result.frame.as_ref().expect("send frame");
        assert_eq!(
            output.chunk_type,
            crate::hybrid_ratchet_v2_full_braid::spqr_codec::WIRE_HDR
        );
        assert_eq!(output.index, 0);
        assert_eq!(output.payload.len(), CW);
        assert_eq!(
            result
                .candidate
                .active_send
                .as_ref()
                .unwrap()
                .next_spqr_index,
            1
        );
        encode_rvfb1(&result.candidate).unwrap();
    }

    #[derive(Clone)]
    struct FullExchangeAeadCheckpoint {
        name: &'static str,
        before: Rvfb1State,
        input: Rvbi1,
        env: Rvbe1,
        result: TransitionResult,
    }

    struct FullExchangeFixture {
        checkpoints: Vec<FullExchangeAeadCheckpoint>,
        alice_final: Rvfb1State,
        bob_final: Rvfb1State,
        alice_ec_rk_frozen: [u8; 32],
        bob_ec_rk_frozen: [u8; 32],
        pq_epochs: usize,
        dh_ratchets: usize,
    }

    fn install_ec_state(tr: &mut Rvft1, ec: &crate::hybrid_ratchet_v2_tr::EcDrState) {
        assert!(
            ec.mkskipped.is_empty(),
            "fixture has no skipped EC messages"
        );
        tr.ec_rk = ec.rk;
        tr.ec_dhs_priv = ec.dhs_priv;
        tr.ec_dhs_pub = ec.dhs_pub;
        match ec.dhr_pub {
            Some(dhr) => {
                tr.ec_dhr_present = 1;
                tr.ec_dhr_pub = dhr;
            }
            None => {
                tr.ec_dhr_present = 0;
                tr.ec_dhr_pub = [0; 32];
            }
        }
        match ec.cks {
            Some(cks) => {
                tr.ec_ck_send_present = 1;
                tr.ec_ck_send = cks;
            }
            None => {
                tr.ec_ck_send_present = 0;
                tr.ec_ck_send = [0; 32];
            }
        }
        match ec.ckr {
            Some(ckr) => {
                tr.ec_ck_recv_present = 1;
                tr.ec_ck_recv = ckr;
            }
            None => {
                tr.ec_ck_recv_present = 0;
                tr.ec_ck_recv = [0; 32];
            }
        }
        tr.ec_ns = ec.ns;
        tr.ec_nr = ec.nr;
        tr.ec_pn = ec.pn;
        tr.ec_skipped.clear();
    }

    fn aligned_full_exchange_states(
        alice_receive_seed: &[u8; 32],
        bob_receive_seed: &[u8; 32],
    ) -> (Rvfb1State, Rvfb1State) {
        use crate::hybrid_ratchet_v2_full_braid::tr_confirm::materialize_ec_dh_priv;
        use crate::hybrid_ratchet_v2_tr::{
            ec_dr_decrypt, ec_dr_encrypt, ec_dr_init_alice, ec_dr_init_bob, MAX_MKSKIPPED_RETAINED,
        };

        let mut alice = test_state(AGENT_KEYS_UNSAMPLED, ROLE_ALICE);
        let mut bob = test_state(AGENT_NO_HEADER_RECEIVED, ROLE_BOB);
        bob.inbound_sets = vec![inbound_set(DIR_A2B, 1, SOURCE_KIND_HDR, Vec::new())];

        let rk0 = [0x51; 32];
        let alice_priv0 = [0x61; 32];
        let bob_priv0 = [0x62; 32];
        let bob_pub0 = crate::hybrid_ratchet_v2_tr::x25519_public(&bob_priv0).unwrap();
        let alice_priv1 = materialize_ec_dh_priv(
            alice_receive_seed,
            &alice.prefix.session_id,
            alice.prefix.generation,
        )
        .unwrap();
        let bob_priv1 = materialize_ec_dh_priv(
            bob_receive_seed,
            &bob.prefix.session_id,
            bob.prefix.generation,
        )
        .unwrap();
        assert_ne!(alice_priv0, alice_priv1);
        assert_ne!(bob_priv0, bob_priv1);

        let alice_ec = ec_dr_init_alice(&rk0, &alice_priv0, &bob_pub0).unwrap();
        let bob_ec = ec_dr_init_bob(&rk0, &bob_priv0).unwrap();

        // Pre-ratchet Bob with one aligned Alice EC message so epoch-1 Bob has
        // a real sending chain. Alice commits the matching send-chain advance.
        let (alice_ec, pre_header, pre_mk) = ec_dr_encrypt(&alice_ec).unwrap();
        let (bob_ec, recovered_pre_mk) = ec_dr_decrypt(
            &bob_ec,
            &pre_header,
            crate::hybrid_ratchet_v2::MAX_SKIP,
            Some(&bob_priv1),
            MAX_MKSKIPPED_RETAINED,
        )
        .unwrap();
        assert_eq!(recovered_pre_mk, pre_mk);

        install_ec_state(&mut alice.tr, &alice_ec);
        install_ec_state(&mut bob.tr, &bob_ec);
        assert_eq!(bob.tr.ec_ck_send_present, 1);
        assert_eq!(bob.tr.ec_dhr_pub, alice.tr.ec_dhs_pub);
        (alice, bob)
    }

    fn plain_send(
        state: &mut Rvfb1State,
        direction: u8,
        env: &Rvbe1,
        crypto: &mut LabCrypto,
    ) -> Rvbc1 {
        let result = transition(state, &send_input(direction), env, crypto);
        assert_eq!(result.disposition, Disposition::Accept);
        let frame = result.frame.clone().expect("Send emits RVBC1");
        *state = result.candidate;
        frame
    }

    fn plain_receive(
        state: &mut Rvfb1State,
        direction: u8,
        frame: Rvbc1,
        env: &Rvbe1,
        crypto: &mut LabCrypto,
    ) -> TransitionResult {
        let result = transition(state, &receive_input(state, direction, frame), env, crypto);
        assert_eq!(result.disposition, Disposition::Accept);
        *state = result.candidate.clone();
        result
    }

    #[allow(clippy::type_complexity)]
    fn prepare_aead_send(
        state: &Rvfb1State,
        direction: u8,
        env: &Rvbe1,
        plaintext: &[u8],
    ) -> (
        Rvbi1,
        crate::hybrid_ratchet_v2_full_braid::wire_rvch1::Rvch1,
        [u8; 32],
        [u8; 32],
        Rvbc1,
    ) {
        use crate::hybrid_ratchet_v2_full_braid::tr_confirm::{
            advance_ec_candidate, build_effective_ad, encode_rvba1, rvch1_from_send_state,
            AdmittedTrustEvidence, Rvba1,
        };
        use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::MODE_SEAL_COMPARE;
        use crate::hybrid_ratchet_v2_full_braid::wire_rvch1::encode_rvch1;
        use crate::hybrid_ratchet_v2_tr::EcDrHeader;
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        assert_eq!(state.prefix.agent, AGENT_HEADER_RECEIVED);
        let rho = state.tlvs.iter().find(|entry| entry.tag == 2).unwrap();
        let hek = state.tlvs.iter().find(|entry| entry.tag == 3).unwrap();
        let mut header = [0u8; mlkem::HEADER_LEN];
        header[..32].copy_from_slice(&rho.value);
        header[32..].copy_from_slice(&hek.value);
        let coins: [u8; mlkem::COINS_LEN] = env.encaps_coins.as_slice().try_into().unwrap();
        let encaps = LabCrypto::default().encaps1(&header, &coins).unwrap();
        let scka_mk = authenticator::kdf_ok(&encaps.shared_secret, state.prefix.braid_agent_epoch);

        let ch =
            rvch1_from_send_state(&state.tr, direction, state.prefix.braid_agent_epoch).unwrap();
        let header = EcDrHeader {
            dh_pub: ch.ec_dh_pub,
            pn: ch.ec_pn,
            n: ch.ec_n,
        };
        let (_, ec_mk) = advance_ec_candidate(&state.tr, OP_SEND, &header, None).unwrap();

        // Preview only the exact RVBC1 that becomes part of this Send's AD.
        let preview = transition(
            state,
            &send_input(direction),
            env,
            &mut LabCrypto::default(),
        );
        assert_eq!(preview.disposition, Disposition::Accept);
        let frame = preview.frame.unwrap();

        let evidence = AdmittedTrustEvidence::lab_default();
        let rvba1 = Rvba1::build(
            state.prefix.session_id,
            direction,
            evidence.initiator_cert_digest,
            evidence.initiator_identity_pub,
            evidence.responder_cert_digest,
            evidence.responder_identity_pub,
        )
        .unwrap();
        let rvba1_bytes = encode_rvba1(&rvba1).unwrap();
        let effective_ad = build_effective_ad(
            &rvba1_bytes,
            &encode_rvch1(&ch),
            &encode_rvbc1(&frame).unwrap(),
        )
        .unwrap();
        let (key, nonce) = crate::hybrid_ratchet_v2::kdf_hybrid(&ec_mk, &scka_mk);
        let expected_ct = ChaCha20Poly1305::new((&key).into())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &effective_ad,
                },
            )
            .unwrap();

        let mut input = send_input(direction);
        input.mutation = Rvbm1 {
            needs_aead: 1,
            ec_mk_oracle_len: 0,
            ec_mk_oracle: [0; 32],
            aad: rvba1_bytes,
            mode: MODE_SEAL_COMPARE,
            body: plaintext.to_vec(),
            expected_ct: Some(expected_ct),
        };
        (input, ch, ec_mk, *scka_mk, frame)
    }

    /// Receive-side confirm input: the body is exactly the peer's RVBO1
    /// `sealed_ct` (the one ciphertext under that epoch's hybrid key).
    fn prepare_aead_receive(
        state: &Rvfb1State,
        direction: u8,
        frame: &Rvbc1,
        ch: &crate::hybrid_ratchet_v2_full_braid::wire_rvch1::Rvch1,
        sealed_ct: &[u8],
    ) -> Rvbi1 {
        use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::MODE_OPEN;

        assert_eq!(state.prefix.agent, AGENT_EK_SENT_CT1_RECEIVED);
        Rvbi1 {
            op: OP_RECEIVE,
            direction,
            ch: Some(ch.clone()),
            expected_ch: Some(ch.clone()),
            object_digest: Some([0xD1; 32]),
            frame: Some(encode_rvbc1(frame).unwrap()),
            mutation: Rvbm1 {
                needs_aead: 1,
                ec_mk_oracle_len: 0,
                ec_mk_oracle: [0; 32],
                aad: lab_rvba1_bytes(state, direction),
                mode: MODE_OPEN,
                body: sealed_ct.to_vec(),
                expected_ct: None,
            },
        }
    }

    fn lab_rvba1_bytes(state: &Rvfb1State, direction: u8) -> Vec<u8> {
        use crate::hybrid_ratchet_v2_full_braid::tr_confirm::{
            encode_rvba1, AdmittedTrustEvidence, Rvba1,
        };
        let evidence = AdmittedTrustEvidence::lab_default();
        encode_rvba1(
            &Rvba1::build(
                state.prefix.session_id,
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

    /// Seal `plaintext` under `(ec_mk, scka_mk)` with an arbitrary RVBC1 in the AD.
    fn seal_with_frame_ad(
        state: &Rvfb1State,
        direction: u8,
        ch: &crate::hybrid_ratchet_v2_full_braid::wire_rvch1::Rvch1,
        frame: &Rvbc1,
        ec_mk: &[u8; 32],
        scka_mk: &[u8; 32],
        plaintext: &[u8],
    ) -> Vec<u8> {
        use crate::hybrid_ratchet_v2_full_braid::tr_confirm::build_effective_ad;
        use crate::hybrid_ratchet_v2_full_braid::wire_rvch1::encode_rvch1;
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let effective_ad = build_effective_ad(
            &lab_rvba1_bytes(state, direction),
            &encode_rvch1(ch),
            &encode_rvbc1(frame).unwrap(),
        )
        .unwrap();
        let (key, nonce) = crate::hybrid_ratchet_v2::kdf_hybrid(ec_mk, scka_mk);
        ChaCha20Poly1305::new((&key).into())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &effective_ad,
                },
            )
            .unwrap()
    }

    fn run_full_exchange_two_pq_two_dh_fixture() -> FullExchangeFixture {
        let alice_receive_seed = [0xA3; 32];
        let bob_receive_seed = [0xB4; 32];
        let (mut alice, mut bob) =
            aligned_full_exchange_states(&alice_receive_seed, &bob_receive_seed);
        let mut alice_crypto = LabCrypto::default();
        let mut bob_crypto = LabCrypto::default();
        let plain_env = Rvbe1::default_caps(0);
        let mut checkpoints = Vec::new();
        let mut dh_ratchets = 0usize;

        let mut alice_keygen_env = Rvbe1::default_caps(0);
        alice_keygen_env.keygen_seed = vec![0xA7; mlkem::SEED_LEN];
        let mut bob_encaps_env = Rvbe1::default_caps(0).with_lab_trust();
        bob_encaps_env.encaps_coins = vec![0xB8; mlkem::COINS_LEN];

        for _ in 0..N_HDR {
            let frame = plain_send(&mut alice, DIR_A2B, &alice_keygen_env, &mut alice_crypto);
            plain_receive(&mut bob, DIR_A2B, frame, &plain_env, &mut bob_crypto);
        }
        assert_eq!(bob.prefix.agent, AGENT_HEADER_RECEIVED);

        let epoch1_plaintext = b"full-exchange-epoch-1-confirm";
        let bob_send_before = bob.clone();
        let bob_ns_before = bob.tr.ec_ns;
        let (bob_send_input, bob_ch, epoch1_ec_mk, epoch1_scka_mk, preview_frame) =
            prepare_aead_send(&bob_send_before, DIR_B2A, &bob_encaps_env, epoch1_plaintext);
        let bob_send = transition(
            &bob_send_before,
            &bob_send_input,
            &bob_encaps_env,
            &mut bob_crypto,
        );
        assert_eq!(bob_send.disposition, Disposition::Accept);
        assert_eq!(bob_send.meta.output_key_epoch, Some(1));
        assert_eq!(bob_send.frame.as_ref(), Some(&preview_frame));
        assert_eq!(bob_send.candidate.tr.ec_ns, bob_ns_before + 1);
        assert_eq!(
            bob_send.sealed_ct.as_ref(),
            bob_send_input.mutation.expected_ct.as_ref()
        );
        checkpoints.push(FullExchangeAeadCheckpoint {
            name: "epoch1_bob_header_received_send",
            before: bob_send_before,
            input: bob_send_input,
            env: bob_encaps_env.clone(),
            result: bob_send.clone(),
        });
        bob = bob_send.candidate;
        let first_ct1 = bob_send.frame.unwrap();
        plain_receive(
            &mut alice,
            DIR_B2A,
            first_ct1,
            &plain_env,
            &mut alice_crypto,
        );
        for _ in 1..N_CT1 {
            let frame = plain_send(&mut bob, DIR_B2A, &bob_encaps_env, &mut bob_crypto);
            plain_receive(&mut alice, DIR_B2A, frame, &plain_env, &mut alice_crypto);
        }
        assert_eq!(alice.prefix.agent, AGENT_CT1_RECEIVED);

        for _ in 0..N_EK {
            let frame = plain_send(&mut alice, DIR_A2B, &alice_keygen_env, &mut alice_crypto);
            plain_receive(&mut bob, DIR_A2B, frame, &plain_env, &mut bob_crypto);
        }
        assert_eq!(bob.prefix.agent, AGENT_CT2_SAMPLED);

        let mut epoch1_last_ct2 = None;
        for index in 0..N_CT2 {
            let frame = plain_send(&mut bob, DIR_B2A, &bob_encaps_env, &mut bob_crypto);
            if index + 1 == N_CT2 {
                epoch1_last_ct2 = Some(frame);
            } else {
                plain_receive(&mut alice, DIR_B2A, frame, &plain_env, &mut alice_crypto);
            }
        }
        let epoch1_last_ct2 = epoch1_last_ct2.unwrap();
        assert_eq!(alice.prefix.agent, AGENT_EK_SENT_CT1_RECEIVED);
        let alice_dhr_before = alice.tr.ec_dhr_pub;
        let alice_receive_before = alice.clone();
        let epoch1_sealed = checkpoints[0].result.sealed_ct.clone().unwrap();
        let mut alice_receive_env = Rvbe1::default_caps(0).with_lab_trust();
        alice_receive_env.ec_dh_seed = alice_receive_seed.to_vec();
        // Regression (key/nonce reuse): a second ciphertext under the epoch-1
        // hybrid key, re-sealed against the final-CT2 frame, must never open.
        let resealed = seal_with_frame_ad(
            &alice_receive_before,
            DIR_B2A,
            &bob_ch,
            &epoch1_last_ct2,
            &epoch1_ec_mk,
            &epoch1_scka_mk,
            epoch1_plaintext,
        );
        let rejected = transition(
            &alice_receive_before,
            &prepare_aead_receive(
                &alice_receive_before,
                DIR_B2A,
                &epoch1_last_ct2,
                &bob_ch,
                &resealed,
            ),
            &alice_receive_env,
            &mut alice_crypto,
        );
        assert_eq!(
            rejected.disposition,
            Disposition::Reject {
                reason: RejectReason::Parse
            }
        );
        assert_eq!(rejected.candidate, alice_receive_before);
        let alice_receive_input = prepare_aead_receive(
            &alice_receive_before,
            DIR_B2A,
            &epoch1_last_ct2,
            &bob_ch,
            &epoch1_sealed,
        );
        assert_eq!(
            alice_receive_input.mutation.body, epoch1_sealed,
            "Receive opens exactly the peer's one sealed_ct"
        );
        let alice_receive = transition(
            &alice_receive_before,
            &alice_receive_input,
            &alice_receive_env,
            &mut alice_crypto,
        );
        assert_eq!(alice_receive.disposition, Disposition::Accept);
        assert_eq!(alice_receive.meta.output_key_epoch, Some(1));
        assert!(alice_receive.ch_out.is_none());
        assert!(alice_receive.sealed_ct.is_none());
        assert_ne!(alice_receive.candidate.tr.ec_dhr_pub, alice_dhr_before);
        dh_ratchets += 1;
        checkpoints.push(FullExchangeAeadCheckpoint {
            name: "epoch1_alice_ek_sent_ct1_received_receive",
            before: alice_receive_before,
            input: alice_receive_input,
            env: alice_receive_env,
            result: alice_receive.clone(),
        });
        alice = alice_receive.candidate;
        assert_eq!(alice.prefix.agent, AGENT_NO_HEADER_RECEIVED);
        assert_eq!(alice.prefix.braid_agent_epoch, 2);
        assert_eq!(alice.tr.scka_rk, bob.tr.scka_rk);
        assert_eq!(alice.prefix.auth_root, bob.prefix.auth_root);
        assert_eq!(alice.prefix.auth_mac_key, bob.prefix.auth_mac_key);
        let alice_ec_rk_frozen = alice.tr.ec_rk;

        // WIRE_NONE hands the next PQ epoch to Bob without an AEAD hook.
        let epoch_signal = plain_send(&mut alice, DIR_A2B, &plain_env, &mut alice_crypto);
        plain_receive(&mut bob, DIR_A2B, epoch_signal, &plain_env, &mut bob_crypto);
        assert_eq!(bob.prefix.agent, AGENT_KEYS_UNSAMPLED);
        assert_eq!(bob.prefix.braid_agent_epoch, 2);

        let mut bob_keygen_env = Rvbe1::default_caps(0);
        bob_keygen_env.keygen_seed = vec![0xC9; mlkem::SEED_LEN];
        let mut alice_encaps_env = Rvbe1::default_caps(0).with_lab_trust();
        alice_encaps_env.encaps_coins = vec![0xD0; mlkem::COINS_LEN];

        for _ in 0..N_HDR {
            let frame = plain_send(&mut bob, DIR_B2A, &bob_keygen_env, &mut bob_crypto);
            plain_receive(&mut alice, DIR_B2A, frame, &plain_env, &mut alice_crypto);
        }
        assert_eq!(alice.prefix.agent, AGENT_HEADER_RECEIVED);

        let epoch2_plaintext = b"full-exchange-epoch-2-confirm";
        let alice_send_before = alice.clone();
        let alice_ns_before = alice.tr.ec_ns;
        let (alice_send_input, alice_ch, epoch2_ec_mk, epoch2_scka_mk, preview_frame) =
            prepare_aead_send(
                &alice_send_before,
                DIR_A2B,
                &alice_encaps_env,
                epoch2_plaintext,
            );
        let alice_send = transition(
            &alice_send_before,
            &alice_send_input,
            &alice_encaps_env,
            &mut alice_crypto,
        );
        assert_eq!(alice_send.disposition, Disposition::Accept);
        assert_eq!(alice_send.meta.output_key_epoch, Some(2));
        assert_eq!(alice_send.frame.as_ref(), Some(&preview_frame));
        assert_eq!(alice_send.candidate.tr.ec_ns, alice_ns_before + 1);
        assert_eq!(alice_send.candidate.tr.ec_rk, alice_ec_rk_frozen);
        checkpoints.push(FullExchangeAeadCheckpoint {
            name: "epoch2_alice_header_received_send",
            before: alice_send_before,
            input: alice_send_input,
            env: alice_encaps_env.clone(),
            result: alice_send.clone(),
        });
        alice = alice_send.candidate;
        let first_ct1 = alice_send.frame.unwrap();
        plain_receive(&mut bob, DIR_A2B, first_ct1, &plain_env, &mut bob_crypto);
        for _ in 1..N_CT1 {
            let frame = plain_send(&mut alice, DIR_A2B, &alice_encaps_env, &mut alice_crypto);
            plain_receive(&mut bob, DIR_A2B, frame, &plain_env, &mut bob_crypto);
        }
        assert_eq!(bob.prefix.agent, AGENT_CT1_RECEIVED);

        for _ in 0..N_EK {
            let frame = plain_send(&mut bob, DIR_B2A, &bob_keygen_env, &mut bob_crypto);
            plain_receive(&mut alice, DIR_B2A, frame, &plain_env, &mut alice_crypto);
        }
        assert_eq!(alice.prefix.agent, AGENT_CT2_SAMPLED);

        let mut epoch2_last_ct2 = None;
        for index in 0..N_CT2 {
            let frame = plain_send(&mut alice, DIR_A2B, &alice_encaps_env, &mut alice_crypto);
            if index + 1 == N_CT2 {
                epoch2_last_ct2 = Some(frame);
            } else {
                plain_receive(&mut bob, DIR_A2B, frame, &plain_env, &mut bob_crypto);
            }
        }
        let epoch2_last_ct2 = epoch2_last_ct2.unwrap();
        assert_eq!(bob.prefix.agent, AGENT_EK_SENT_CT1_RECEIVED);
        let bob_dhr_before = bob.tr.ec_dhr_pub;
        let bob_ec_rk_before_dh2 = bob.tr.ec_rk;
        let bob_receive_before = bob.clone();
        let epoch2_sealed = checkpoints[2].result.sealed_ct.clone().unwrap();
        let resealed = seal_with_frame_ad(
            &bob_receive_before,
            DIR_A2B,
            &alice_ch,
            &epoch2_last_ct2,
            &epoch2_ec_mk,
            &epoch2_scka_mk,
            epoch2_plaintext,
        );
        assert_ne!(resealed, epoch2_sealed);
        let bob_receive_input = prepare_aead_receive(
            &bob_receive_before,
            DIR_A2B,
            &epoch2_last_ct2,
            &alice_ch,
            &epoch2_sealed,
        );
        let mut bob_receive_env = Rvbe1::default_caps(0).with_lab_trust();
        // This materializes the pre-ratchet Bob key. Reusing the durable local
        // key keeps both final DH pub cross-links exact while still exercising
        // the second peer-DH ratchet and its new receive/send chains.
        bob_receive_env.ec_dh_seed = bob_receive_seed.to_vec();
        let bob_receive = transition(
            &bob_receive_before,
            &bob_receive_input,
            &bob_receive_env,
            &mut bob_crypto,
        );
        assert_eq!(bob_receive.disposition, Disposition::Accept);
        assert_eq!(bob_receive.meta.output_key_epoch, Some(2));
        assert!(bob_receive.ch_out.is_none());
        assert!(bob_receive.sealed_ct.is_none());
        assert_ne!(bob_receive.candidate.tr.ec_dhr_pub, bob_dhr_before);
        assert_ne!(bob_receive.candidate.tr.ec_rk, bob_ec_rk_before_dh2);
        dh_ratchets += 1;
        checkpoints.push(FullExchangeAeadCheckpoint {
            name: "epoch2_bob_ek_sent_ct1_received_receive",
            before: bob_receive_before,
            input: bob_receive_input,
            env: bob_receive_env,
            result: bob_receive.clone(),
        });
        bob = bob_receive.candidate;

        let bob_ec_rk_frozen = bob.tr.ec_rk;
        assert_eq!(alice.tr.ec_rk, alice_ec_rk_frozen);
        assert_eq!(bob.tr.ec_rk, bob_ec_rk_frozen);
        assert_eq!(alice.tr.ec_dhs_pub, bob.tr.ec_dhr_pub);
        assert_eq!(bob.tr.ec_dhs_pub, alice.tr.ec_dhr_pub);
        assert_eq!(alice.tr.scka_rk, bob.tr.scka_rk);
        assert_eq!(alice.prefix.auth_root, bob.prefix.auth_root);
        assert_eq!(alice.prefix.auth_mac_key, bob.prefix.auth_mac_key);
        assert_eq!(bob.prefix.agent, AGENT_NO_HEADER_RECEIVED);
        assert_eq!(bob.prefix.braid_agent_epoch, 3);
        assert_eq!(dh_ratchets, 2);

        FullExchangeFixture {
            checkpoints,
            alice_final: alice,
            bob_final: bob,
            alice_ec_rk_frozen,
            bob_ec_rk_frozen,
            pq_epochs: 2,
            dh_ratchets,
        }
    }

    #[test]
    fn full_exchange_two_pq_two_dh_with_aead_confirm() {
        let fixture = run_full_exchange_two_pq_two_dh_fixture();
        assert_eq!(fixture.pq_epochs, 2);
        assert_eq!(fixture.dh_ratchets, 2);
        assert_eq!(fixture.checkpoints.len(), 4);
        assert_eq!(
            fixture
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.name)
                .collect::<Vec<_>>(),
            vec![
                "epoch1_bob_header_received_send",
                "epoch1_alice_ek_sent_ct1_received_receive",
                "epoch2_alice_header_received_send",
                "epoch2_bob_ek_sent_ct1_received_receive",
            ]
        );
        // Key/nonce uniqueness: every receive confirm opens the ciphertext its
        // peer sealed (same bytes), so each hybrid key produced exactly one seal.
        for pair in fixture.checkpoints.chunks(2) {
            assert_eq!(pair[0].input.op, OP_SEND);
            assert_eq!(pair[1].input.op, OP_RECEIVE);
            assert_eq!(
                pair[0].result.sealed_ct.as_ref(),
                Some(&pair[1].input.mutation.body)
            );
        }
        for (index, checkpoint) in fixture.checkpoints.iter().enumerate() {
            assert_eq!(checkpoint.input.mutation.needs_aead, 1);
            assert!(checkpoint.env.admitted_trust.is_some());
            assert_eq!(
                checkpoint.result.meta.output_key_epoch,
                Some((index / 2 + 1) as u64)
            );
            match checkpoint.input.op {
                OP_SEND => assert_eq!(checkpoint.before.prefix.agent, AGENT_HEADER_RECEIVED),
                OP_RECEIVE => {
                    assert_eq!(checkpoint.before.prefix.agent, AGENT_EK_SENT_CT1_RECEIVED);
                    assert_eq!(checkpoint.env.ec_dh_seed.len(), 32);
                }
                _ => panic!("AEAD checkpoint operation"),
            }
        }
        assert_eq!(fixture.alice_final.tr.ec_rk, fixture.alice_ec_rk_frozen);
        assert_eq!(fixture.bob_final.tr.ec_rk, fixture.bob_ec_rk_frozen);
        assert_eq!(
            fixture.alice_final.tr.ec_dhs_pub,
            fixture.bob_final.tr.ec_dhr_pub
        );
        assert_eq!(
            fixture.bob_final.tr.ec_dhs_pub,
            fixture.alice_final.tr.ec_dhr_pub
        );
    }

    #[test]
    #[ignore = "regenerates the checked-in Task 13 shared vector"]
    fn dump_full_exchange_2pq_2dh_shared_vector() {
        use crate::hybrid_ratchet_v2_full_braid::digest::state_digest;
        use crate::hybrid_ratchet_v2_full_braid::pipeline::transition_prepare;
        use crate::hybrid_ratchet_v2_full_braid::state_codec::RVFB1_SCHEMA;
        use crate::hybrid_ratchet_v2_full_braid::wire_rvch1::encode_rvch1;
        use serde_json::{json, Value};
        use sha2::{Digest, Sha256};

        let fixture = run_full_exchange_two_pq_two_dh_fixture();
        let checkpoints = fixture
            .checkpoints
            .iter()
            .map(|checkpoint| {
                let before_bytes = encode_rvfb1(&checkpoint.before).unwrap();
                let input_bytes = encode_rvbi1(&checkpoint.input).unwrap();
                let env_bytes = encode_rvbe1(&checkpoint.env).unwrap();
                let prepared = transition_prepare(
                    &before_bytes,
                    &input_bytes,
                    &env_bytes,
                    &mut LabCrypto::default(),
                )
                .expect("AEAD checkpoint must prepare");
                let candidate = &checkpoint.result.candidate;
                let candidate_bytes = encode_rvfb1(candidate).unwrap();
                let frame_hex = checkpoint
                    .result
                    .frame
                    .as_ref()
                    .map(|frame| hex::encode(encode_rvbc1(frame).unwrap()));
                let ch_out_hex = checkpoint
                    .result
                    .ch_out
                    .as_ref()
                    .map(|ch| hex::encode(encode_rvch1(ch)));
                let sealed_ct_hex = checkpoint.result.sealed_ct.as_ref().map(hex::encode);
                json!({
                    "name": checkpoint.name,
                    "before_hex": hex::encode(&before_bytes),
                    "input_hex": hex::encode(&input_bytes),
                    "env_hex": hex::encode(&env_bytes),
                    "op": checkpoint.input.op,
                    "direction": checkpoint.input.direction,
                    "expected": {
                        "disposition": "accept",
                        "candidate_hex": hex::encode(candidate_bytes),
                        "prepared_candidate_hex": hex::encode(&prepared.candidate_bytes),
                        "rvbo1_hex": hex::encode(&prepared.outputs_bytes),
                        "rvbj1_hex": hex::encode(&prepared.intent_bytes),
                        "frame_hex": frame_hex,
                        "ch_out_hex": ch_out_hex,
                        "sealed_ct_hex": sealed_ct_hex,
                        "meta": {
                            "sending_epoch": prepared.meta.sending_epoch,
                            "receiving_epoch": prepared.meta.receiving_epoch,
                            "output_key_epoch": prepared.meta.output_key_epoch,
                            "flags": prepared.meta.flags,
                            "terminal_reason": prepared.meta.terminal_reason,
                            "pending_phase": prepared.meta.pending_phase,
                            "transition_id_hex": hex::encode(prepared.meta.transition_id),
                        },
                        "prefix": {
                            "agent": candidate.prefix.agent,
                            "braid_agent_epoch": candidate.prefix.braid_agent_epoch,
                            "braid_send_epoch": candidate.prefix.braid_send_epoch,
                            "braid_recv_epoch": candidate.prefix.braid_recv_epoch,
                            "auth_root_hex": hex::encode(candidate.prefix.auth_root),
                        },
                        "ec": {
                            "ec_rk_hex": hex::encode(candidate.tr.ec_rk),
                            "ec_dhs_pub_hex": hex::encode(candidate.tr.ec_dhs_pub),
                            "ec_dhr_present": candidate.tr.ec_dhr_present,
                            "ec_dhr_pub_hex": hex::encode(candidate.tr.ec_dhr_pub),
                            "ec_ck_send_present": candidate.tr.ec_ck_send_present,
                            "ec_ck_recv_present": candidate.tr.ec_ck_recv_present,
                            "ec_ns": candidate.tr.ec_ns,
                            "ec_nr": candidate.tr.ec_nr,
                            "ec_pn": candidate.tr.ec_pn,
                        },
                    },
                })
            })
            .collect::<Vec<Value>>();

        let alice_final = encode_rvfb1(&fixture.alice_final).unwrap();
        let bob_final = encode_rvfb1(&fixture.bob_final).unwrap();
        let mut convergence = Sha256::new();
        convergence.update(b"ATSAM/v2/full-braid/full-exchange-convergence");
        convergence.update(fixture.alice_final.tr.scka_rk);
        convergence.update(fixture.alice_final.prefix.auth_root);
        convergence.update(fixture.alice_final.prefix.auth_mac_key);
        convergence.update(fixture.alice_final.tr.ec_dhs_pub);
        convergence.update(fixture.alice_final.tr.ec_dhr_pub);
        convergence.update(fixture.bob_final.tr.ec_dhs_pub);
        convergence.update(fixture.bob_final.tr.ec_dhr_pub);
        let convergence_digest: [u8; 32] = convergence.finalize().into();
        let mut delivery_indices = vec![N_CT1 as u32, N_CT1 as u32];
        delivery_indices.extend((1..N_CT1 as u32).rev());

        let vector = json!({
            "name": "full_braid_full_exchange_2pq_2dh_001",
            "schema": 1,
            "lab_only": true,
            "production_enabled": false,
            "description": "Two full PQ epochs with four nested AEAD promotion checkpoints, two peer EC-DH ratchets, and actor-mailbox erasure recovery.",
            "counts": {
                "pq_epochs": fixture.pq_epochs,
                "aead_promotions": fixture.checkpoints.len(),
                "dh_ratchets": fixture.dh_ratchets,
            },
            "aead_checkpoints": checkpoints,
            "final": {
                "alice_state_hex": hex::encode(&alice_final),
                "bob_state_hex": hex::encode(&bob_final),
                "alice_state_digest_hex": hex::encode(state_digest(RVFB1_SCHEMA, &alice_final)),
                "bob_state_digest_hex": hex::encode(state_digest(RVFB1_SCHEMA, &bob_final)),
                "convergence_digest_hex": hex::encode(convergence_digest),
                "alice_ec_rk_hex": hex::encode(fixture.alice_ec_rk_frozen),
                "bob_ec_rk_hex": hex::encode(fixture.bob_ec_rk_frozen),
                "scka_rk_hex": hex::encode(fixture.alice_final.tr.scka_rk),
                "auth_root_hex": hex::encode(fixture.alice_final.prefix.auth_root),
                "auth_mac_key_hex": hex::encode(fixture.alice_final.prefix.auth_mac_key),
                "alice_ec_dhs_pub_hex": hex::encode(fixture.alice_final.tr.ec_dhs_pub),
                "alice_ec_dhr_pub_hex": hex::encode(fixture.alice_final.tr.ec_dhr_pub),
                "bob_ec_dhs_pub_hex": hex::encode(fixture.bob_final.tr.ec_dhs_pub),
                "bob_ec_dhr_pub_hex": hex::encode(fixture.bob_final.tr.ec_dhr_pub),
            },
            "mailbox_scenario": {
                "phase": "ct1",
                "wire": "RVBC1",
                "source_len": L_CT1,
                "systematic_threshold": N_CT1,
                "emitted_indices": (0..=N_CT1 as u32).collect::<Vec<_>>(),
                "dropped_indices": [0],
                "delivery_indices": delivery_indices,
                "duplicate_disposition": "accept_noop",
                "expected_peer_agent": "Ct1Received",
                "expected_active_wire": "EK_CT1_ACK",
            },
        });

        let mut root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        root.pop();
        root.pop();
        root.pop();
        let path = root.join("shared-vectors/rvn1/atsam/full_braid_full_exchange_2pq_2dh_001.json");
        let mut encoded = serde_json::to_string_pretty(&vector).unwrap();
        encoded.push('\n');
        std::fs::write(&path, encoded).unwrap();
        eprintln!("wrote {}", path.display());
    }

    #[test]
    fn real_lab_crypto_drives_one_structural_braid_exchange() {
        let mut alice = test_state(AGENT_KEYS_UNSAMPLED, ROLE_ALICE);
        let mut bob = test_state(AGENT_NO_HEADER_RECEIVED, ROLE_BOB);
        bob.inbound_sets = vec![inbound_set(DIR_A2B, 1, SOURCE_KIND_HDR, Vec::new())];
        let mut alice_env = Rvbe1::default_caps(0);
        alice_env.keygen_seed = vec![0xA7; mlkem::SEED_LEN];
        let mut bob_env = Rvbe1::default_caps(0);
        bob_env.encaps_coins = vec![0xB8; mlkem::COINS_LEN];
        let mut alice_crypto = LabCrypto::default();
        let mut bob_crypto = LabCrypto::default();

        for _ in 0..N_HDR {
            let sent = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
            assert_eq!(sent.disposition, Disposition::Accept);
            alice = sent.candidate;
            let received = transition(
                &bob,
                &receive_input(&bob, DIR_A2B, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut bob_crypto,
            );
            assert_eq!(received.disposition, Disposition::Accept);
            bob = received.candidate;
        }
        assert_eq!(bob.prefix.agent, AGENT_HEADER_RECEIVED);

        for _ in 0..N_CT1 {
            let sent = transition(&bob, &send_input(DIR_B2A), &bob_env, &mut bob_crypto);
            assert_eq!(sent.disposition, Disposition::Accept);
            bob = sent.candidate;
            let received = transition(
                &alice,
                &receive_input(&alice, DIR_B2A, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut alice_crypto,
            );
            assert_eq!(received.disposition, Disposition::Accept);
            alice = received.candidate;
        }
        assert_eq!(alice.prefix.agent, AGENT_CT1_RECEIVED);
        assert_eq!(bob.prefix.agent, AGENT_CT1_SAMPLED);

        for _ in 0..N_EK {
            let sent = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
            assert_eq!(sent.disposition, Disposition::Accept);
            alice = sent.candidate;
            let received = transition(
                &bob,
                &receive_input(&bob, DIR_A2B, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut bob_crypto,
            );
            assert_eq!(received.disposition, Disposition::Accept);
            bob = received.candidate;
        }
        assert_eq!(bob.prefix.agent, AGENT_CT2_SAMPLED);
        assert_eq!(bob_crypto.ack_advances(), 1);

        for _ in 0..N_CT2 {
            let sent = transition(&bob, &send_input(DIR_B2A), &bob_env, &mut bob_crypto);
            assert_eq!(sent.disposition, Disposition::Accept);
            bob = sent.candidate;
            let received = transition(
                &alice,
                &receive_input(&alice, DIR_B2A, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut alice_crypto,
            );
            assert_eq!(received.disposition, Disposition::Accept);
            alice = received.candidate;
        }
        assert_eq!(alice.prefix.agent, AGENT_NO_HEADER_RECEIVED);
        assert_eq!(alice.prefix.braid_agent_epoch, 2);
        assert_eq!(alice.tr.scka_rk, bob.tr.scka_rk);
        assert_eq!(alice.prefix.auth_root, bob.prefix.auth_root);
        assert_eq!(alice.prefix.auth_mac_key, bob.prefix.auth_mac_key);
        assert_ne!(alice.prefix.auth_mac_key, [0x32; 32]);

        let epoch_signal = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
        assert_eq!(epoch_signal.disposition, Disposition::Accept);
        alice = epoch_signal.candidate;
        let advanced = transition(
            &bob,
            &receive_input(&bob, DIR_A2B, epoch_signal.frame.unwrap()),
            &Rvbe1::default_caps(0),
            &mut bob_crypto,
        );
        assert_eq!(advanced.disposition, Disposition::Accept);
        bob = advanced.candidate;
        assert_eq!(bob.prefix.agent, AGENT_KEYS_UNSAMPLED);
        assert_eq!(bob.prefix.braid_agent_epoch, 2);
        assert_eq!(alice.prefix.braid_send_epoch, 1);
        assert_eq!(bob.prefix.braid_recv_epoch, 1);

        // Second PQ+DH epoch with roles reversed (Bob KeysUnsampled → Alice NoHeader).
        bob_env.keygen_seed = vec![0xC9; mlkem::SEED_LEN];
        alice_env.encaps_coins = vec![0xD0; mlkem::COINS_LEN];
        alice.inbound_sets = vec![inbound_set(
            DIR_B2A,
            bob.prefix.braid_send_epoch + 1,
            SOURCE_KIND_HDR,
            Vec::new(),
        )];

        for _ in 0..N_HDR {
            let sent = transition(&bob, &send_input(DIR_B2A), &bob_env, &mut bob_crypto);
            assert_eq!(sent.disposition, Disposition::Accept);
            bob = sent.candidate;
            let received = transition(
                &alice,
                &receive_input(&alice, DIR_B2A, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut alice_crypto,
            );
            assert_eq!(received.disposition, Disposition::Accept);
            alice = received.candidate;
        }
        assert_eq!(alice.prefix.agent, AGENT_HEADER_RECEIVED);

        for _ in 0..N_CT1 {
            let sent = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
            assert_eq!(sent.disposition, Disposition::Accept);
            alice = sent.candidate;
            let received = transition(
                &bob,
                &receive_input(&bob, DIR_A2B, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut bob_crypto,
            );
            assert_eq!(received.disposition, Disposition::Accept);
            bob = received.candidate;
        }

        for _ in 0..N_EK {
            let sent = transition(&bob, &send_input(DIR_B2A), &bob_env, &mut bob_crypto);
            assert_eq!(sent.disposition, Disposition::Accept);
            bob = sent.candidate;
            let received = transition(
                &alice,
                &receive_input(&alice, DIR_B2A, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut alice_crypto,
            );
            assert_eq!(received.disposition, Disposition::Accept);
            alice = received.candidate;
        }
        assert_eq!(alice_crypto.ack_advances(), 1);

        for _ in 0..N_CT2 {
            let sent = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
            assert_eq!(sent.disposition, Disposition::Accept);
            alice = sent.candidate;
            let received = transition(
                &bob,
                &receive_input(&bob, DIR_A2B, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut bob_crypto,
            );
            assert_eq!(received.disposition, Disposition::Accept);
            bob = received.candidate;
        }
        assert_eq!(bob.prefix.agent, AGENT_NO_HEADER_RECEIVED);
        assert!(alice.prefix.braid_agent_epoch >= 3 || bob.prefix.braid_agent_epoch >= 3);
        assert_eq!(alice.tr.scka_rk, bob.tr.scka_rk);
        assert_eq!(alice.prefix.auth_root, bob.prefix.auth_root);
        assert!(bob_crypto.ack_advances() >= 1);
        assert!(alice_crypto.ack_advances() >= 1);
    }

    #[test]
    fn signal_kdf_ok_and_auth_state_agree_across_roles() {
        // Output key from KDF_OK must feed SCKA (not raw ML-KEM SS); roles converge.
        let ss = [0x7Eu8; 32];
        let epoch = 1u64;
        let mut output_key = authenticator::kdf_ok(&ss, epoch);
        let mut alice_auth = AuthState {
            root_key: [0x31; 32],
            mac_key: [0x32; 32],
        };
        let mut bob_auth = AuthState {
            root_key: [0x31; 32],
            mac_key: [0x32; 32],
        };
        alice_auth.update(epoch, &output_key);
        bob_auth.update(epoch, &output_key);
        assert_eq!(alice_auth.root_key, bob_auth.root_key);
        assert_eq!(alice_auth.mac_key, bob_auth.mac_key);

        let (rk_a, _) = kdf_scka_rk(&[0x10; 32], &output_key).unwrap();
        let (rk_b, _) = kdf_scka_rk(&[0x10; 32], &ss).unwrap();
        assert_ne!(
            rk_a, rk_b,
            "raw ML-KEM SS must not equal KDF_OK-derived SCKA input"
        );
        output_key.zeroize();
    }

    #[test]
    fn tampered_ct2_mac_does_not_promote_scka_chain() {
        let mut alice = test_state(AGENT_KEYS_UNSAMPLED, ROLE_ALICE);
        let mut bob = test_state(AGENT_NO_HEADER_RECEIVED, ROLE_BOB);
        bob.inbound_sets = vec![inbound_set(DIR_A2B, 1, SOURCE_KIND_HDR, Vec::new())];
        let mut alice_env = Rvbe1::default_caps(0);
        alice_env.keygen_seed = vec![0xC1; mlkem::SEED_LEN];
        let mut bob_env = Rvbe1::default_caps(0);
        bob_env.encaps_coins = vec![0xC2; mlkem::COINS_LEN];
        let mut alice_crypto = LabCrypto::default();
        let mut bob_crypto = LabCrypto::default();

        for _ in 0..N_HDR {
            let sent = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
            alice = sent.candidate;
            bob = transition(
                &bob,
                &receive_input(&bob, DIR_A2B, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut bob_crypto,
            )
            .candidate;
        }
        for _ in 0..N_CT1 {
            let sent = transition(&bob, &send_input(DIR_B2A), &bob_env, &mut bob_crypto);
            bob = sent.candidate;
            alice = transition(
                &alice,
                &receive_input(&alice, DIR_B2A, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut alice_crypto,
            )
            .candidate;
        }
        for _ in 0..N_EK {
            let sent = transition(&alice, &send_input(DIR_A2B), &alice_env, &mut alice_crypto);
            alice = sent.candidate;
            bob = transition(
                &bob,
                &receive_input(&bob, DIR_A2B, sent.frame.unwrap()),
                &Rvbe1::default_caps(0),
                &mut bob_crypto,
            )
            .candidate;
        }
        assert_eq!(bob.prefix.agent, AGENT_CT2_SAMPLED);

        let before_rk = alice.tr.scka_rk;
        let before_auth = alice.prefix.auth_mac_key;
        let mut last = None;
        for i in 0..N_CT2 {
            let sent = transition(&bob, &send_input(DIR_B2A), &bob_env, &mut bob_crypto);
            bob = sent.candidate;
            let mut frame = sent.frame.unwrap();
            if i + 1 == N_CT2 {
                // Tamper the reconstructed source by flipping a MAC byte in the
                // final chunk payload (last CW of L_CT2 includes the trailing MAC).
                frame.payload[0] ^= 0xFF;
                frame.binding_digest = binding_digest(
                    DIR_B2A,
                    frame.epoch,
                    frame.chunk_type,
                    frame.index,
                    &frame.payload,
                    &alice.prefix.session_id,
                );
                let before = alice.clone();
                let result = transition(
                    &alice,
                    &receive_input(&alice, DIR_B2A, frame),
                    &Rvbe1::default_caps(0),
                    &mut alice_crypto,
                );
                assert_eq!(
                    result.disposition,
                    Disposition::Terminal {
                        reason: TERMINAL_REASON_MAC
                    }
                );
                assert_eq!(before.tr.scka_rk, before_rk);
                assert_eq!(before.prefix.auth_mac_key, before_auth);
                assert_eq!(result.candidate.prefix.agent, AGENT_TERMINAL);
                assert_eq!(result.candidate.tr.scka_rk, [0u8; 32]);
                return;
            }
            alice = transition(
                &alice,
                &receive_input(&alice, DIR_B2A, frame),
                &Rvbe1::default_caps(0),
                &mut alice_crypto,
            )
            .candidate;
            last = Some(());
        }
        let _ = last;
        panic!("expected tampered final Ct2 chunk");
    }
}
