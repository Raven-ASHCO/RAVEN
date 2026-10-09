//! Durable Full Braid mutation pipeline (design §§2.1, 4.10–4.11, 6.5).
//!
//! This module owns phase preparation and the pure CAS transforms. Hosts own
//! persistence, mutation leases, RVQI checks, and the atomic clear barrier.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::hybrid_ratchet_v2_full_braid::agent::AGENT_TERMINAL;
use crate::hybrid_ratchet_v2_full_braid::constants::{
    BRAID_MAX_CANONICAL_STATE_BYTES, BRAID_MAX_RVOR_RECORD_BYTES, ERR_CAS, ERR_EPOCH,
    ERR_NEED_CAPACITY, ERR_PARSE, FLAG_AWAITING_COMPLETE, FLAG_TERMINAL, MAX_RVBO1,
    RVBJ1_HEADER_LEN,
};
use crate::hybrid_ratchet_v2_full_braid::digest::{
    execution_digest, input_digest, output_digest, state_digest, transition_id_digest,
};
use crate::hybrid_ratchet_v2_full_braid::spqr_pin_audit::CW;
use crate::hybrid_ratchet_v2_full_braid::state_codec::{
    decode_rvfb1, encode_rvfb1, rvfb1_encodes_to, ReplayRecord, Rvfb1Prefix, Rvfb1State,
    MAX_REPLAYS, REPLAY_RECORD_LEN, RVFB1_SCHEMA,
};
use crate::hybrid_ratchet_v2_full_braid::transition::{
    cursor_index, terminalize, transition, BraidCrypto, Disposition, TERMINAL_REASON_EXPIRED,
    TERMINAL_REASON_REPAIR,
};
pub use crate::hybrid_ratchet_v2_full_braid::transition::{
    META_FLAG_IGNORED, META_FLAG_REPLAY_HIT, META_FLAG_TERMINAL,
};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbc1::{decode_rvbc1, encode_rvbc1};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbe1::{decode_rvbe1, encode_rvbe1, Rvbe1};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbi1::{
    decode_rvbi1, encode_rvbi1, Rvbi1, OP_RECEIVE, OP_SEND,
};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbj1::{
    decode_rvbj1, encode_rvbj1, Rvbj1, Rvbj1Header, INTENT_NORMAL, INTENT_REPAIR_CONFLICT,
    INTENT_REPAIR_EXPIRED,
};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::MODE_SEAL_COMPARE;
use crate::hybrid_ratchet_v2_full_braid::wire_rvbo1::{
    decode_rvbo1, encode_empty_rvbo1, encode_rvbo1, validate_receive_success,
    validate_repair_or_terminal_empty, validate_send_success, Rvbo1,
};
use crate::hybrid_ratchet_v2_full_braid::wire_rvor1::{
    decode_rvor1, encode_rvor1, Rvor1, RVOR1_FLAG_REPAIR,
};

pub const BRAID_RVOR_TTL_MS: u64 = 604_800_000;
pub const MAX_RVBJ1: usize = RVBJ1_HEADER_LEN + BRAID_MAX_CANONICAL_STATE_BYTES + MAX_RVBO1;

pub const RECOVER_BEFORE: u32 = 0x10;
pub const RECOVER_PREPARED: u32 = 0x20;
pub const RECOVER_PROMOTED: u32 = 0x40;
pub const RECOVER_CLEARED: u32 = 0x80;
pub const RECOVER_CONFLICT: u32 = 0x100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PipelineMeta {
    pub sending_epoch: u64,
    pub receiving_epoch: u64,
    pub output_key_epoch: u64,
    pub flags: u32,
    pub terminal_reason: u16,
    pub pending_phase: u16,
    pub transition_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineResult {
    pub candidate_bytes: Vec<u8>,
    pub outputs_bytes: Vec<u8>,
    pub intent_bytes: Vec<u8>,
    pub meta: PipelineMeta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateResult {
    pub state_bytes: Vec<u8>,
    pub meta: PipelineMeta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializeResult {
    pub rvor_bytes: Vec<u8>,
    pub meta: PipelineMeta,
}

struct ValidatedIntent {
    intent: Rvbj1,
    prepared_state: Rvfb1State,
    promoted_bytes: Vec<u8>,
    cleared_bytes: Vec<u8>,
}

impl Drop for ValidatedIntent {
    fn drop(&mut self) {
        // Encoded states carry every ratchet secret; callers get their own copies.
        // (`intent.candidate_bytes` is wiped by `Rvbj1`'s own Drop.)
        self.promoted_bytes.zeroize();
        self.cleared_bytes.zeroize();
    }
}

fn is_zero_pending(prefix: &Rvfb1Prefix) -> bool {
    prefix.pending_transition_id == [0; 32]
        && prefix.pending_before_digest == [0; 32]
        && prefix.pending_output_digest == [0; 32]
        && prefix.pending_execution_digest == [0; 32]
}

fn validate_state_semantics(state: &Rvfb1State) -> Result<(), i32> {
    let terminal_agent = state.prefix.agent == AGENT_TERMINAL;
    let terminal_flag = state.prefix.flags & FLAG_TERMINAL != 0;
    let terminal_reason = (1..=7).contains(&state.prefix.terminal_reason);
    if terminal_agent != terminal_flag || terminal_agent != terminal_reason {
        return Err(ERR_PARSE);
    }
    if !terminal_agent && state.prefix.terminal_reason != 0 {
        return Err(ERR_PARSE);
    }

    match state.prefix.pending_phase {
        0 if is_zero_pending(&state.prefix) && state.prefix.flags & FLAG_AWAITING_COMPLETE == 0 => {
        }
        1 if state.prefix.flags & FLAG_AWAITING_COMPLETE == 0 => {}
        2 if state.prefix.flags & FLAG_AWAITING_COMPLETE != 0 => {}
        _ => return Err(ERR_PARSE),
    }
    Ok(())
}

fn decode_canonical_state(bytes: &[u8]) -> Result<Rvfb1State, i32> {
    if bytes.is_empty() || bytes.len() > BRAID_MAX_CANONICAL_STATE_BYTES {
        return Err(ERR_PARSE);
    }
    let state = decode_rvfb1(bytes).map_err(|_| ERR_PARSE)?;
    validate_state_semantics(&state)?;
    if !rvfb1_encodes_to(&state, bytes).map_err(|_| ERR_PARSE)? {
        return Err(ERR_PARSE);
    }
    Ok(state)
}

fn clean_for_transition(state: &Rvfb1State) -> bool {
    state.prefix.pending_phase == 0
        && is_zero_pending(&state.prefix)
        && state.prefix.flags & FLAG_AWAITING_COMPLETE == 0
}

fn state_meta(
    state: &Rvfb1State,
    flags: u32,
    output_key_epoch: Option<u64>,
    transition_id: [u8; 32],
) -> PipelineMeta {
    PipelineMeta {
        sending_epoch: state.prefix.braid_send_epoch,
        receiving_epoch: state.prefix.braid_recv_epoch,
        output_key_epoch: output_key_epoch.unwrap_or(0),
        flags,
        terminal_reason: state.prefix.terminal_reason,
        pending_phase: state.prefix.pending_phase as u16,
        transition_id,
    }
}

fn outputs_for_disposition(
    disposition: Disposition,
    frame: Option<&crate::hybrid_ratchet_v2_full_braid::wire_rvbc1::Rvbc1>,
    ch_out: Option<&crate::hybrid_ratchet_v2_full_braid::wire_rvch1::Rvch1>,
    sealed_ct: Option<&[u8]>,
) -> Result<Vec<u8>, i32> {
    match disposition {
        Disposition::ReplayHit => Ok(Vec::new()),
        Disposition::Ignore | Disposition::Terminal { .. } => Ok(encode_empty_rvbo1()),
        Disposition::Accept => {
            let Some(frame) = frame else {
                return Ok(encode_empty_rvbo1());
            };
            let frame_bytes = encode_rvbc1(frame).map_err(|_| ERR_PARSE)?;
            encode_rvbo1(&Rvbo1 {
                frames: vec![frame_bytes],
                ch_out: ch_out.cloned(),
                sealed_ct: sealed_ct.map(|ct| ct.to_vec()),
            })
            .map_err(|_| ERR_PARSE)
        }
        Disposition::Reject { reason } => Err(reason.abi_code()),
    }
}

fn validate_journal_outputs(
    role: u8,
    direction: u8,
    intent_kind: u8,
    terminal: bool,
    outputs: &Rvbo1,
    output_bytes: &[u8],
) -> Result<(), i32> {
    if terminal || intent_kind != INTENT_NORMAL {
        return validate_repair_or_terminal_empty(output_bytes).map_err(|_| ERR_PARSE);
    }
    let send = matches!((role, direction), (0, 0) | (1, 1));
    if send {
        validate_send_success(outputs).map_err(|_| ERR_PARSE)
    } else {
        validate_receive_success(outputs).map_err(|_| ERR_PARSE)
    }
}

fn enforce_env_caps(
    state: &Rvfb1State,
    candidate_len: usize,
    outputs: &[u8],
    env: &Rvbe1,
) -> Result<(), i32> {
    if candidate_len > env.cap_state as usize {
        return Err(ERR_NEED_CAPACITY);
    }
    if state.replays.len() as u32 > env.cap_replay_entries {
        return Err(ERR_NEED_CAPACITY);
    }
    if state.replays.len().saturating_mul(REPLAY_RECORD_LEN) > env.cap_replay_bytes as usize {
        return Err(ERR_NEED_CAPACITY);
    }
    if outputs.len() > MAX_RVBO1 {
        return Err(ERR_PARSE);
    }
    let decoded = decode_rvbo1(outputs).map_err(|_| ERR_PARSE)?;
    for frame_bytes in &decoded.frames {
        let frame = decode_rvbc1(frame_bytes).map_err(|_| ERR_PARSE)?;
        if frame.payload.len() as u32 > env.cap_payload {
            return Err(ERR_NEED_CAPACITY);
        }
        if frame.index >= env.cap_chunks {
            return Err(ERR_NEED_CAPACITY);
        }
    }
    Ok(())
}

/// Capacity checks decidable before the transition engine (no crypto side-effects).
fn preflight_env_caps(state: &Rvfb1State, input: &Rvbi1, env: &Rvbe1) -> Result<(), i32> {
    match input.op {
        OP_RECEIVE => {
            let Some(frame_bytes) = input.frame.as_ref() else {
                return Err(ERR_PARSE);
            };
            let frame = decode_rvbc1(frame_bytes).map_err(|_| ERR_PARSE)?;
            if frame.payload.len() as u32 > env.cap_payload {
                return Err(ERR_NEED_CAPACITY);
            }
            if frame.index >= env.cap_chunks {
                return Err(ERR_NEED_CAPACITY);
            }
        }
        OP_SEND => {
            let next_index = state
                .active_send
                .as_ref()
                .map(|active| cursor_index(active.next_spqr_index, env.cap_chunks))
                .unwrap_or(0);
            // `emit_active` wraps the cursor inside `cap_chunks`, so only a zero
            // cap leaves no legal index for this Send.
            if next_index >= env.cap_chunks {
                return Err(ERR_NEED_CAPACITY);
            }
            // CW-sized braid payloads cannot fit when cap_payload < CW.
            // Agents that only emit empty WIRE_NONE frames remain allowed.
            let empty_none_only = matches!(
                state.prefix.agent,
                crate::hybrid_ratchet_v2_full_braid::agent::AGENT_EK_SENT_CT1_RECEIVED
                    | crate::hybrid_ratchet_v2_full_braid::agent::AGENT_NO_HEADER_RECEIVED
                    | crate::hybrid_ratchet_v2_full_braid::agent::AGENT_CT1_ACKNOWLEDGED
            );
            if env.cap_payload < CW as u32 && !empty_none_only {
                return Err(ERR_NEED_CAPACITY);
            }
        }
        _ => return Err(ERR_PARSE),
    }
    Ok(())
}

/// Input digest persisted in RVBJ1/RVOR1.
///
/// A mode-0 (seal_compare) Send carries the application plaintext, and every
/// other RVBI1 field is public or derivable, so an unsalted digest over it
/// would let anyone who dumps retained RVOR1 evidence confirm guessed
/// plaintexts after the message keys are gone. The plaintext bytes are zeroed
/// before hashing; the input stays uniquely bound because `expected_ct` (the
/// ChaCha20-Poly1305 ciphertext of that plaintext) is still covered.
fn journal_input_digest(input: &Rvbi1) -> Result<[u8; 32], i32> {
    if input.mutation.needs_aead != 1 || input.mutation.mode != MODE_SEAL_COMPARE {
        return Ok(input_digest(&encode_rvbi1(input).map_err(|_| ERR_PARSE)?));
    }
    let mut redacted = input.clone();
    redacted.mutation.body.zeroize();
    redacted.mutation.body.resize(input.mutation.body.len(), 0);
    let mut bytes = encode_rvbi1(&redacted).map_err(|_| ERR_PARSE)?;
    let digest = input_digest(&bytes);
    bytes.zeroize();
    Ok(digest)
}

fn bind_live_session_role(live: &Rvfb1State, header: &Rvbj1Header) -> Result<(), i32> {
    if live.prefix.session_id != header.session_id || live.prefix.role != header.role {
        return Err(ERR_CAS);
    }
    Ok(())
}

/// Replay-window size for a transition: the codec cap narrowed by the host's
/// replay entry/byte capacities from RVBE1.
fn replay_window(env: &Rvbe1) -> usize {
    MAX_REPLAYS
        .min(env.cap_replay_entries as usize)
        .min(env.cap_replay_bytes as usize / REPLAY_RECORD_LEN)
}

/// Append the new transition's replay record, evicting the oldest records so
/// the window never exceeds `window`. Only the pending transition's record must
/// survive (RVBJ1 validation); older transitions are already cleared, so a
/// session never wedges on a full replay table.
fn insert_replay(
    candidate: &mut Rvfb1State,
    transition_id: [u8; 32],
    execution: [u8; 32],
    output: [u8; 32],
    output_len: usize,
    flags: u32,
    window: usize,
) -> Result<(), i32> {
    if window == 0 {
        return Err(ERR_NEED_CAPACITY);
    }
    if candidate
        .replays
        .iter()
        .any(|record| record.transition_id == transition_id)
    {
        return Err(ERR_PARSE);
    }
    let excess = (candidate.replays.len() + 1).saturating_sub(window.min(MAX_REPLAYS));
    candidate.replays.drain(..excess);
    candidate.replays.push(ReplayRecord {
        transition_id,
        execution_digest: execution,
        output_digest: output,
        output_len: output_len.try_into().map_err(|_| ERR_PARSE)?,
        flags: flags.try_into().map_err(|_| ERR_PARSE)?,
    });
    Ok(())
}

fn clear_pending_fields(prefix: &mut Rvfb1Prefix) {
    prefix.pending_phase = 0;
    prefix.pending_transition_id = [0; 32];
    prefix.pending_before_digest = [0; 32];
    prefix.pending_output_digest = [0; 32];
    prefix.pending_execution_digest = [0; 32];
    prefix.flags &= !FLAG_AWAITING_COMPLETE;
}

fn promoted_and_cleared(prepared: &Rvfb1State) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let mut promoted = prepared.clone();
    promoted.prefix.pending_phase = 2;
    promoted.prefix.flags |= FLAG_AWAITING_COMPLETE;
    // Wiped if the cleared encoding below fails.
    let mut promoted_bytes = Zeroizing::new(encode_rvfb1(&promoted).map_err(|_| ERR_PARSE)?);

    let mut cleared = promoted;
    clear_pending_fields(&mut cleared.prefix);
    cleared.prefix.generation = cleared.prefix.generation.checked_add(1).ok_or(ERR_EPOCH)?;
    let cleared_bytes = encode_rvfb1(&cleared).map_err(|_| ERR_PARSE)?;
    Ok((std::mem::take(&mut *promoted_bytes), cleared_bytes))
}

#[allow(clippy::too_many_arguments)]
fn prepare_candidate(
    before: &Rvfb1State,
    before_bytes: &[u8],
    mut candidate: Rvfb1State,
    direction: u8,
    intent_kind: u8,
    execution: [u8; 32],
    input: [u8; 32],
    object: [u8; 32],
    outputs: Vec<u8>,
    retention_origin_ms: u64,
    meta_flags: u32,
    output_key_epoch: Option<u64>,
    replay_window: usize,
) -> Result<PipelineResult, i32> {
    if direction > 1
        || !matches!(
            intent_kind,
            INTENT_NORMAL | INTENT_REPAIR_CONFLICT | INTENT_REPAIR_EXPIRED
        )
        || !clean_for_transition(&candidate)
        || candidate.prefix.session_id != before.prefix.session_id
        || candidate.prefix.role != before.prefix.role
        || candidate.prefix.generation != before.prefix.generation
    {
        return Err(ERR_PARSE);
    }
    let decoded_outputs = decode_rvbo1(&outputs).map_err(|_| ERR_PARSE)?;
    validate_journal_outputs(
        before.prefix.role,
        direction,
        intent_kind,
        candidate.prefix.flags & FLAG_TERMINAL != 0,
        &decoded_outputs,
        &outputs,
    )?;
    if intent_kind != INTENT_NORMAL && object != [0; 32] {
        return Err(ERR_PARSE);
    }

    let before_digest = state_digest(RVFB1_SCHEMA, before_bytes);
    let output = output_digest(&outputs);
    let transition_id = transition_id_digest(
        &before.prefix.session_id,
        before.prefix.role,
        direction,
        before.prefix.generation,
        &execution,
        &before_digest,
    );
    insert_replay(
        &mut candidate,
        transition_id,
        execution,
        output,
        outputs.len(),
        meta_flags,
        replay_window,
    )?;
    candidate.prefix.flags &= !FLAG_AWAITING_COMPLETE;
    candidate.prefix.pending_phase = 1;
    candidate.prefix.pending_transition_id = transition_id;
    candidate.prefix.pending_before_digest = before_digest;
    candidate.prefix.pending_output_digest = output;
    candidate.prefix.pending_execution_digest = execution;

    // Full serialized session state: wiped on every early return below, and
    // handed to the caller (by `mem::take`, no extra copy) only on success.
    let mut candidate_bytes = Zeroizing::new(encode_rvfb1(&candidate).map_err(|_| ERR_PARSE)?);
    if candidate_bytes.len() > BRAID_MAX_CANONICAL_STATE_BYTES {
        return Err(ERR_PARSE);
    }
    let (mut promoted_bytes, mut cleared_bytes) = promoted_and_cleared(&candidate)?;
    let promoted_state_digest = state_digest(RVFB1_SCHEMA, &promoted_bytes);
    let cleared_state_digest = state_digest(RVFB1_SCHEMA, &cleared_bytes);
    promoted_bytes.zeroize();
    cleared_bytes.zeroize();
    let retention_expiry_ms = retention_origin_ms
        .checked_add(BRAID_RVOR_TTL_MS)
        .ok_or(ERR_PARSE)?;
    let header = Rvbj1Header {
        session_id: before.prefix.session_id,
        role: before.prefix.role,
        direction,
        intent_kind,
        generation: before.prefix.generation,
        transition_id,
        execution_digest: execution,
        input_digest: input,
        before_state_digest: before_digest,
        prepared_state_digest: state_digest(RVFB1_SCHEMA, &candidate_bytes),
        promoted_state_digest,
        cleared_state_digest,
        output_digest: output,
        object_digest: object,
        retention_origin_ms,
        retention_expiry_ms,
        candidate_len: candidate_bytes.len().try_into().map_err(|_| ERR_PARSE)?,
        outputs_len: outputs.len().try_into().map_err(|_| ERR_PARSE)?,
    };
    // `Rvbj1` wipes its copy of the candidate state when it drops.
    let journal = Rvbj1 {
        header,
        candidate_bytes: candidate_bytes.to_vec(),
        outputs_bytes: outputs.clone(),
    };
    let mut intent_bytes = Zeroizing::new(encode_rvbj1(&journal).map_err(|_| ERR_PARSE)?);
    if intent_bytes.len() > MAX_RVBJ1 {
        return Err(ERR_PARSE);
    }
    let meta = state_meta(&candidate, meta_flags, output_key_epoch, transition_id);
    Ok(PipelineResult {
        candidate_bytes: std::mem::take(&mut *candidate_bytes),
        outputs_bytes: outputs,
        intent_bytes: std::mem::take(&mut *intent_bytes),
        meta,
    })
}

/// Parse a transition and produce its phase-1 candidate, RVBO1, and RVBJ1.
pub fn transition_prepare<C: BraidCrypto>(
    state_bytes: &[u8],
    input_bytes: &[u8],
    env_bytes: &[u8],
    crypto: &mut C,
) -> Result<PipelineResult, i32> {
    let state = decode_canonical_state(state_bytes)?;
    if !clean_for_transition(&state) {
        return Err(ERR_CAS);
    }
    let input = decode_rvbi1(input_bytes).map_err(|_| ERR_PARSE)?;
    let env = decode_rvbe1(env_bytes).map_err(|_| ERR_PARSE)?;
    let reencoded_input = Zeroizing::new(encode_rvbi1(&input).map_err(|_| ERR_PARSE)?);
    let reencoded_env = Zeroizing::new(encode_rvbe1(&env).map_err(|_| ERR_PARSE)?);
    if reencoded_input.as_slice() != input_bytes || reencoded_env.as_slice() != env_bytes {
        return Err(ERR_PARSE);
    }
    preflight_env_caps(&state, &input, &env)?;

    let transitioned = transition(&state, &input, &env, crypto);
    match transitioned.disposition {
        Disposition::Reject { reason } => Err(reason.abi_code()),
        Disposition::ReplayHit => {
            let execution = execution_digest(input_bytes, env_bytes);
            let replay = state
                .replays
                .iter()
                .find(|record| record.execution_digest == execution)
                .ok_or(ERR_PARSE)?;
            Ok(PipelineResult {
                candidate_bytes: Vec::new(),
                outputs_bytes: Vec::new(),
                intent_bytes: Vec::new(),
                meta: PipelineMeta {
                    sending_epoch: transitioned.meta.sending_epoch,
                    receiving_epoch: transitioned.meta.receiving_epoch,
                    output_key_epoch: 0,
                    flags: META_FLAG_REPLAY_HIT,
                    terminal_reason: 0,
                    pending_phase: state.prefix.pending_phase as u16,
                    transition_id: replay.transition_id,
                },
            })
        }
        Disposition::Ignore => {
            let outputs = outputs_for_disposition(Disposition::Ignore, None, None, None)?;
            Ok(PipelineResult {
                candidate_bytes: state_bytes.to_vec(),
                outputs_bytes: outputs,
                intent_bytes: Vec::new(),
                meta: PipelineMeta {
                    sending_epoch: transitioned.meta.sending_epoch,
                    receiving_epoch: transitioned.meta.receiving_epoch,
                    output_key_epoch: 0,
                    flags: META_FLAG_IGNORED,
                    terminal_reason: 0,
                    pending_phase: state.prefix.pending_phase as u16,
                    transition_id: [0; 32],
                },
            })
        }
        disposition @ (Disposition::Accept | Disposition::Terminal { .. }) => {
            let outputs = outputs_for_disposition(
                disposition,
                transitioned.frame.as_ref(),
                transitioned.ch_out.as_ref(),
                transitioned.sealed_ct.as_deref(),
            )?;
            let flags = match disposition {
                Disposition::Terminal { .. } => META_FLAG_TERMINAL,
                _ => transitioned.meta.flags,
            };
            let mut result = prepare_candidate(
                &state,
                state_bytes,
                transitioned.candidate,
                input.direction,
                INTENT_NORMAL,
                execution_digest(input_bytes, env_bytes),
                journal_input_digest(&input)?,
                input.object_digest.unwrap_or([0; 32]),
                outputs,
                env.clock,
                flags,
                transitioned.meta.output_key_epoch,
                replay_window(&env),
            )?;
            // `ERR_NEED_CAPACITY` is an ordinary outcome when the host tightens
            // caps: the rejected candidate/journal carry the whole session
            // state, so wipe them instead of freeing them as plain `Vec`s.
            let checked = decode_canonical_state(&result.candidate_bytes).and_then(|candidate| {
                enforce_env_caps(
                    &candidate,
                    result.candidate_bytes.len(),
                    &result.outputs_bytes,
                    &env,
                )
            });
            if let Err(code) = checked {
                result.candidate_bytes.zeroize();
                result.intent_bytes.zeroize();
                return Err(code);
            }
            Ok(result)
        }
    }
}

fn validate_intent(intent_bytes: &[u8]) -> Result<ValidatedIntent, i32> {
    if intent_bytes.is_empty() || intent_bytes.len() > MAX_RVBJ1 {
        return Err(ERR_PARSE);
    }
    let intent = decode_rvbj1(intent_bytes).map_err(|_| ERR_PARSE)?;
    if encode_rvbj1(&intent).map_err(|_| ERR_PARSE)? != intent_bytes {
        return Err(ERR_PARSE);
    }
    let header = &intent.header;
    if header.role > 1
        || header.direction > 1
        || !matches!(
            header.intent_kind,
            INTENT_NORMAL | INTENT_REPAIR_CONFLICT | INTENT_REPAIR_EXPIRED
        )
        || header.retention_origin_ms.checked_add(BRAID_RVOR_TTL_MS)
            != Some(header.retention_expiry_ms)
    {
        return Err(ERR_PARSE);
    }
    let decoded_outputs = decode_rvbo1(&intent.outputs_bytes).map_err(|_| ERR_PARSE)?;
    if output_digest(&intent.outputs_bytes) != header.output_digest {
        return Err(ERR_PARSE);
    }
    if header.intent_kind != INTENT_NORMAL {
        if header.object_digest != [0; 32] {
            return Err(ERR_PARSE);
        }
        validate_repair_or_terminal_empty(&intent.outputs_bytes).map_err(|_| ERR_PARSE)?;
    }

    let prepared_state = decode_canonical_state(&intent.candidate_bytes)?;
    let prefix = &prepared_state.prefix;
    validate_journal_outputs(
        header.role,
        header.direction,
        header.intent_kind,
        prefix.flags & FLAG_TERMINAL != 0,
        &decoded_outputs,
        &intent.outputs_bytes,
    )?;
    if prefix.session_id != header.session_id
        || prefix.role != header.role
        || prefix.generation != header.generation
        || prefix.pending_phase != 1
        || prefix.flags & FLAG_AWAITING_COMPLETE != 0
        || prefix.pending_transition_id != header.transition_id
        || prefix.pending_before_digest != header.before_state_digest
        || prefix.pending_output_digest != header.output_digest
        || prefix.pending_execution_digest != header.execution_digest
        || state_digest(RVFB1_SCHEMA, &intent.candidate_bytes) != header.prepared_state_digest
        || transition_id_digest(
            &header.session_id,
            header.role,
            header.direction,
            header.generation,
            &header.execution_digest,
            &header.before_state_digest,
        ) != header.transition_id
    {
        return Err(ERR_PARSE);
    }
    let expected_replay_flags = if prefix.flags & FLAG_TERMINAL != 0 {
        META_FLAG_TERMINAL as u16
    } else {
        0
    };
    if !prepared_state.replays.iter().any(|record| {
        record.transition_id == header.transition_id
            && record.execution_digest == header.execution_digest
            && record.output_digest == header.output_digest
            && record.output_len == header.outputs_len
            && record.flags == expected_replay_flags
    }) {
        return Err(ERR_PARSE);
    }
    if header.intent_kind == INTENT_REPAIR_CONFLICT
        && prefix.terminal_reason != TERMINAL_REASON_REPAIR
        || header.intent_kind == INTENT_REPAIR_EXPIRED
            && prefix.terminal_reason != TERMINAL_REASON_EXPIRED
    {
        return Err(ERR_PARSE);
    }

    let (promoted_bytes, cleared_bytes) = promoted_and_cleared(&prepared_state)?;
    // Own the encoded states before comparing so a mismatch wipes them (Drop).
    let validated = ValidatedIntent {
        intent,
        prepared_state,
        promoted_bytes,
        cleared_bytes,
    };
    let header = &validated.intent.header;
    if state_digest(RVFB1_SCHEMA, &validated.promoted_bytes) != header.promoted_state_digest
        || state_digest(RVFB1_SCHEMA, &validated.cleared_bytes) != header.cleared_state_digest
    {
        return Err(ERR_PARSE);
    }
    Ok(validated)
}

/// Promote a clean/before or prepared state to phase 2.
pub fn promote_state(live_bytes: &[u8], intent_bytes: &[u8]) -> Result<StateResult, i32> {
    let live = decode_canonical_state(live_bytes)?;
    let validated = validate_intent(intent_bytes)?;
    let header = &validated.intent.header;
    let live_digest = state_digest(RVFB1_SCHEMA, live_bytes);
    let state_bytes = if live_digest == header.before_state_digest {
        validated.promoted_bytes.clone()
    } else if live_digest == header.prepared_state_digest {
        if live.prefix.pending_phase != 1
            || live.prefix.pending_transition_id != header.transition_id
        {
            return Err(ERR_CAS);
        }
        validated.promoted_bytes.clone()
    } else if live_digest == header.promoted_state_digest {
        if live.prefix.pending_phase != 2
            || live.prefix.pending_transition_id != header.transition_id
        {
            return Err(ERR_CAS);
        }
        live_bytes.to_vec()
    } else {
        return Err(ERR_CAS);
    };
    let state = decode_canonical_state(&state_bytes)?;
    Ok(StateResult {
        state_bytes,
        meta: state_meta(&state, 0, None, header.transition_id),
    })
}

fn materialize_validated(validated: &ValidatedIntent) -> Result<Vec<u8>, i32> {
    let header = &validated.intent.header;
    let repair = header.intent_kind != INTENT_NORMAL;
    let record = Rvor1 {
        transition_id: header.transition_id,
        object_digest: if repair {
            [0; 32]
        } else {
            header.object_digest
        },
        execution_digest: header.execution_digest,
        input_digest: header.input_digest,
        output_digest: header.output_digest,
        retention_origin_ms: header.retention_origin_ms,
        retention_expiry_ms: header.retention_expiry_ms,
        flags: if repair { RVOR1_FLAG_REPAIR } else { 0 },
        outputs_bytes: validated.intent.outputs_bytes.clone(),
    };
    let bytes = encode_rvor1(&record).map_err(|_| ERR_PARSE)?;
    if bytes.len() > BRAID_MAX_RVOR_RECORD_BYTES {
        return Err(ERR_PARSE);
    }
    Ok(bytes)
}

/// Deterministically materialize immutable RVOR1 bytes from RVBJ1.
pub fn materialize_rvor(intent_bytes: &[u8]) -> Result<MaterializeResult, i32> {
    let validated = validate_intent(intent_bytes)?;
    let rvor_bytes = materialize_validated(&validated)?;
    let flags = if validated.prepared_state.prefix.flags & FLAG_TERMINAL != 0 {
        META_FLAG_TERMINAL
    } else {
        0
    };
    Ok(MaterializeResult {
        rvor_bytes,
        meta: state_meta(
            &validated.prepared_state,
            flags,
            None,
            validated.intent.header.transition_id,
        ),
    })
}

fn verify_rvor_evidence(validated: &ValidatedIntent, rvor_bytes: &[u8]) -> Result<(), i32> {
    let rvor = decode_rvor1(rvor_bytes).map_err(|_| ERR_PARSE)?;
    if encode_rvor1(&rvor).map_err(|_| ERR_PARSE)? != rvor_bytes {
        return Err(ERR_PARSE);
    }
    if materialize_validated(validated)? != rvor_bytes {
        return Err(ERR_CAS);
    }
    Ok(())
}

/// Validate a repair RVBJ1 and confirm its input digest binds to `original_transition_id`.
///
/// Returns the repair transition id on success.
pub fn repair_intent_binds_original(
    original_transition_id: &[u8; 32],
    repair_intent_bytes: &[u8],
) -> Result<[u8; 32], i32> {
    let validated = validate_intent(repair_intent_bytes)?;
    let kind = validated.intent.header.intent_kind;
    let reason = match kind {
        INTENT_REPAIR_CONFLICT => TERMINAL_REASON_REPAIR,
        INTENT_REPAIR_EXPIRED => TERMINAL_REASON_EXPIRED,
        _ => return Err(ERR_PARSE),
    };
    if validated.intent.header.input_digest
        != repair_input_digest(original_transition_id, kind, reason)
    {
        return Err(ERR_CAS);
    }
    Ok(validated.intent.header.transition_id)
}

/// Require `rvor_bytes` to be the exact materialization of a validated repair RVBJ1.
pub fn verify_repair_rvor_evidence(
    repair_intent_bytes: &[u8],
    rvor_bytes: &[u8],
) -> Result<[u8; 32], i32> {
    let validated = validate_intent(repair_intent_bytes)?;
    if validated.intent.header.intent_kind == INTENT_NORMAL {
        return Err(ERR_PARSE);
    }
    verify_rvor_evidence(&validated, rvor_bytes)?;
    Ok(validated.intent.header.transition_id)
}

/// Verify RVBJ1↔RVOR1 evidence and clear a matching promoted state.
pub fn clear_pending(
    live_bytes: &[u8],
    intent_bytes: &[u8],
    rvor_bytes: &[u8],
    now_ms: u64,
) -> Result<StateResult, i32> {
    let live = decode_canonical_state(live_bytes)?;
    let validated = validate_intent(intent_bytes)?;
    verify_rvor_evidence(&validated, rvor_bytes)?;
    let header = &validated.intent.header;
    if header.retention_expiry_ms < now_ms {
        return Err(ERR_CAS);
    }

    let live_digest = state_digest(RVFB1_SCHEMA, live_bytes);
    let state_bytes = if live_digest == header.promoted_state_digest {
        if live.prefix.pending_phase != 2
            || live.prefix.pending_transition_id != header.transition_id
        {
            return Err(ERR_CAS);
        }
        validated.cleared_bytes.clone()
    } else if live_digest == header.cleared_state_digest {
        if live.prefix.pending_phase != 0 {
            return Err(ERR_CAS);
        }
        live_bytes.to_vec()
    } else {
        return Err(ERR_CAS);
    };
    let state = decode_canonical_state(&state_bytes)?;
    Ok(StateResult {
        state_bytes,
        meta: state_meta(&state, 0, None, header.transition_id),
    })
}

/// Classify recovery state without mutating it.
pub fn recover_state(live_bytes: &[u8], intent_bytes: &[u8]) -> Result<StateResult, i32> {
    let live = decode_canonical_state(live_bytes)?;
    let validated = validate_intent(intent_bytes)?;
    let header = &validated.intent.header;
    let digest = state_digest(RVFB1_SCHEMA, live_bytes);
    let flags = if digest == header.before_state_digest {
        RECOVER_BEFORE
    } else if digest == header.prepared_state_digest {
        RECOVER_PREPARED
    } else if digest == header.promoted_state_digest {
        RECOVER_PROMOTED
    } else if digest == header.cleared_state_digest {
        RECOVER_CLEARED
    } else {
        RECOVER_CONFLICT
    };
    let transition_id = if flags == RECOVER_CONFLICT {
        [0; 32]
    } else {
        header.transition_id
    };
    Ok(StateResult {
        state_bytes: live_bytes.to_vec(),
        meta: state_meta(&live, flags, None, transition_id),
    })
}

fn repair_input_digest(
    original_transition_id: &[u8; 32],
    intent_kind: u8,
    reason: u16,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ATSAM/v2/full-braid/repair-input");
    digest.update(original_transition_id);
    digest.update([intent_kind]);
    digest.update(reason.to_be_bytes());
    digest.finalize().into()
}

fn repair_execution_digest(
    original_transition_id: &[u8; 32],
    original_execution_digest: &[u8; 32],
    intent_kind: u8,
    reason: u16,
    now_ms: u64,
    before_state_digest: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ATSAM/v2/full-braid/repair-execution");
    digest.update(original_transition_id);
    digest.update(original_execution_digest);
    digest.update([intent_kind]);
    digest.update(reason.to_be_bytes());
    digest.update(now_ms.to_be_bytes());
    digest.update(before_state_digest);
    digest.finalize().into()
}

fn terminalize_state(state: &mut Rvfb1State, reason: u16) {
    terminalize(state, reason);
    clear_pending_fields(&mut state.prefix);
}

fn build_repair(
    live: Rvfb1State,
    live_bytes: &[u8],
    original: &ValidatedIntent,
    now_ms: u64,
    intent_kind: u8,
    reason: u16,
) -> Result<PipelineResult, i32> {
    let before_digest = state_digest(RVFB1_SCHEMA, live_bytes);
    let execution = repair_execution_digest(
        &original.intent.header.transition_id,
        &original.intent.header.execution_digest,
        intent_kind,
        reason,
        now_ms,
        &before_digest,
    );
    let input = repair_input_digest(&original.intent.header.transition_id, intent_kind, reason);
    let mut candidate = live.clone();
    terminalize_state(&mut candidate, reason);
    let mut result = prepare_candidate(
        &live,
        live_bytes,
        candidate,
        original.intent.header.direction,
        intent_kind,
        execution,
        input,
        [0; 32],
        encode_empty_rvbo1(),
        now_ms,
        META_FLAG_TERMINAL,
        None,
        MAX_REPLAYS,
    )?;
    // The repair RVBO1 is embedded in RVBJ1; terminalize FFI has no RVBO output.
    result.outputs_bytes.clear();
    Ok(result)
}

/// Terminalize a state that conflicts with all states named by an original intent.
pub fn terminalize_conflict(
    live_bytes: &[u8],
    original_intent_bytes: &[u8],
    now_ms: u64,
) -> Result<PipelineResult, i32> {
    let live = decode_canonical_state(live_bytes)?;
    let original = validate_intent(original_intent_bytes)?;
    if original.intent.header.intent_kind != INTENT_NORMAL {
        return Err(ERR_PARSE);
    }
    bind_live_session_role(&live, &original.intent.header)?;
    let digest = state_digest(RVFB1_SCHEMA, live_bytes);
    let header = &original.intent.header;
    if [
        header.before_state_digest,
        header.prepared_state_digest,
        header.promoted_state_digest,
        header.cleared_state_digest,
    ]
    .contains(&digest)
    {
        return Err(ERR_CAS);
    }
    if !live_contradicts_intent(&live, header) {
        return Err(ERR_CAS);
    }
    build_repair(
        live,
        live_bytes,
        &original,
        now_ms,
        INTENT_REPAIR_CONFLICT,
        TERMINAL_REASON_REPAIR,
    )
}

/// Whether a live state that matches none of an intent's four digests proves a
/// conflict with that intent, rather than the intent merely being stale.
///
/// Generation only increments when a transition clears, so the live state
/// contradicts intent `T` (prepared from generation `g`) iff:
/// - it sits at or below `g` (a different state occupies `T`'s slot, or the
///   session was rolled back behind a journaled transition), or
/// - it sits at `g + 1` and the transition cleared from `g` was not `T`
///   (phase 0 with a different digest, or a pending transition whose before
///   state is not `T`'s cleared state).
///
/// Beyond `g + 1` the session has advanced past `T`; an old journal left behind
/// (for example by a crash between clear and journal deletion) must not
/// terminalize a healthy session.
fn live_contradicts_intent(live: &Rvfb1State, header: &Rvbj1Header) -> bool {
    let generation = live.prefix.generation;
    if generation <= header.generation {
        return true;
    }
    if generation != header.generation.saturating_add(1) {
        return false;
    }
    live.prefix.pending_phase == 0
        || live.prefix.pending_before_digest != header.cleared_state_digest
}

/// Terminalize an expired original transition after validating its RVOR1.
pub fn terminalize_expired(
    live_bytes: &[u8],
    original_intent_bytes: &[u8],
    rvor_bytes: &[u8],
    now_ms: u64,
) -> Result<PipelineResult, i32> {
    if rvor_bytes.is_empty() {
        return Err(ERR_PARSE);
    }
    let live = decode_canonical_state(live_bytes)?;
    let original = validate_intent(original_intent_bytes)?;
    if original.intent.header.intent_kind != INTENT_NORMAL {
        return Err(ERR_PARSE);
    }
    bind_live_session_role(&live, &original.intent.header)?;
    verify_rvor_evidence(&original, rvor_bytes)?;
    if now_ms <= original.intent.header.retention_expiry_ms {
        return Err(ERR_CAS);
    }
    let live_digest = state_digest(RVFB1_SCHEMA, live_bytes);
    let header = &original.intent.header;
    if ![
        header.before_state_digest,
        header.prepared_state_digest,
        header.promoted_state_digest,
    ]
    .contains(&live_digest)
    {
        return Err(ERR_CAS);
    }
    build_repair(
        live,
        live_bytes,
        &original,
        now_ms,
        INTENT_REPAIR_EXPIRED,
        TERMINAL_REASON_EXPIRED,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_ratchet_v2_full_braid::constants::{
        ERR_CAS, ERR_NEED_CAPACITY, ERR_PARSE, FLAG_AWAITING_COMPLETE, FLAG_TERMINAL,
    };
    use crate::hybrid_ratchet_v2_full_braid::digest::{
        execution_digest, output_digest, state_digest,
    };
    use crate::hybrid_ratchet_v2_full_braid::init::{
        init_write, ROLE_ALICE, ROLE_BOB, RVFI1_MAGIC, RVFI1_SCHEMA,
    };
    use crate::hybrid_ratchet_v2_full_braid::spqr_pin_audit::CW;
    use crate::hybrid_ratchet_v2_full_braid::state_codec::{
        decode_rvfb1, encode_rvfb1, ReplayRecord, RVFB1_SCHEMA,
    };
    use crate::hybrid_ratchet_v2_full_braid::transition::{
        BraidCrypto, BraidCryptoError, Encaps1Material, KeygenMaterial, LabCrypto,
        META_FLAG_IGNORED, META_FLAG_REPLAY_HIT, META_FLAG_TERMINAL, TERMINAL_REASON_MAC,
    };
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbc1::{encode_rvbc1, Rvbc1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbe1::{encode_rvbe1, Rvbe1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbi1::{
        encode_rvbi1, Rvbi1, OP_RECEIVE, OP_SEND,
    };
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbj1::{
        decode_rvbj1, encode_rvbj1, INTENT_NORMAL, INTENT_REPAIR_CONFLICT, INTENT_REPAIR_EXPIRED,
    };
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::Rvbm1;
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbo1::{decode_rvbo1, encode_empty_rvbo1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvor1::{
        decode_rvor1, encode_rvor1, RVOR1_FLAG_REPAIR,
    };
    use crate::hybrid_ratchet_v2_full_braid::wire_util::{
        write_array32, write_bytes, write_u16be, write_u32be, write_u8,
    };
    use crate::hybrid_ratchet_v2_tr::x25519_public;
    use crate::mlkem768_incremental as mlkem;

    fn sample_init_bytes() -> Vec<u8> {
        let bob_spk_pub = x25519_public(&[0x33; 32]).unwrap();
        let mut out = Vec::new();
        write_bytes(&mut out, RVFI1_MAGIC);
        write_u16be(&mut out, RVFI1_SCHEMA);
        write_array32(&mut out, &[0x53; 32]);
        write_u8(&mut out, ROLE_ALICE);
        write_u8(&mut out, 0);
        write_array32(&mut out, &[0x11; 32]);
        write_array32(&mut out, &[0x22; 32]);
        write_array32(&mut out, &bob_spk_pub);
        write_array32(&mut out, &[0x44; 32]);
        write_u32be(&mut out, 0);
        out
    }

    fn before_bytes() -> Vec<u8> {
        init_write(&sample_init_bytes()).unwrap()
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

    fn accepted() -> (Vec<u8>, Vec<u8>, Vec<u8>, PipelineResult) {
        let before = before_bytes();
        let input = send_input_bytes();
        let env = env_bytes(1_000);
        let mut crypto = LabCrypto::default();
        let result = transition_prepare(&before, &input, &env, &mut crypto).unwrap();
        (before, input, env, result)
    }

    fn expected_states(intent_bytes: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let intent = decode_rvbj1(intent_bytes).unwrap();
        let prepared = intent.candidate_bytes.clone();
        let mut promoted_state = decode_rvfb1(&prepared).unwrap();
        promoted_state.prefix.pending_phase = 2;
        promoted_state.prefix.flags |= FLAG_AWAITING_COMPLETE;
        let promoted = encode_rvfb1(&promoted_state).unwrap();
        let mut cleared_state = promoted_state;
        cleared_state.prefix.pending_phase = 0;
        cleared_state.prefix.pending_transition_id = [0; 32];
        cleared_state.prefix.pending_before_digest = [0; 32];
        cleared_state.prefix.pending_output_digest = [0; 32];
        cleared_state.prefix.pending_execution_digest = [0; 32];
        cleared_state.prefix.generation += 1;
        cleared_state.prefix.flags &= !FLAG_AWAITING_COMPLETE;
        let cleared = encode_rvfb1(&cleared_state).unwrap();
        (prepared, promoted, cleared)
    }

    fn rewrite_intent_outputs(intent_bytes: &[u8], outputs: Vec<u8>) -> Vec<u8> {
        let replacement_digest = output_digest(&outputs);
        let mut intent = decode_rvbj1(intent_bytes).unwrap();
        let mut prepared = decode_rvfb1(&intent.candidate_bytes).unwrap();
        prepared.prefix.pending_output_digest = replacement_digest;
        let replay = prepared
            .replays
            .iter_mut()
            .find(|record| record.transition_id == intent.header.transition_id)
            .unwrap();
        replay.output_digest = replacement_digest;
        replay.output_len = outputs.len() as u32;
        let prepared_bytes = encode_rvfb1(&prepared).unwrap();
        let mut promoted = prepared;
        promoted.prefix.pending_phase = 2;
        promoted.prefix.flags |= FLAG_AWAITING_COMPLETE;
        let promoted_bytes = encode_rvfb1(&promoted).unwrap();
        clear_pending_fields(&mut promoted.prefix);
        promoted.prefix.generation += 1;
        let cleared_bytes = encode_rvfb1(&promoted).unwrap();

        intent.header.output_digest = replacement_digest;
        intent.header.outputs_len = outputs.len() as u32;
        intent.header.prepared_state_digest = state_digest(RVFB1_SCHEMA, &prepared_bytes);
        intent.header.promoted_state_digest = state_digest(RVFB1_SCHEMA, &promoted_bytes);
        intent.header.cleared_state_digest = state_digest(RVFB1_SCHEMA, &cleared_bytes);
        intent.header.candidate_len = prepared_bytes.len() as u32;
        intent.candidate_bytes = prepared_bytes;
        intent.outputs_bytes = outputs;
        encode_rvbj1(&intent).unwrap()
    }

    #[test]
    fn accept_prepares_phase_one_and_binds_all_state_digests() {
        let (before, input, env, result) = accepted();
        let intent = decode_rvbj1(&result.intent_bytes).unwrap();
        let prepared = decode_rvfb1(&result.candidate_bytes).unwrap();
        let (expected_prepared, promoted, cleared) = expected_states(&result.intent_bytes);

        assert_eq!(result.candidate_bytes, expected_prepared);
        assert_eq!(prepared.prefix.pending_phase, 1);
        assert_eq!(
            prepared.prefix.pending_transition_id,
            intent.header.transition_id
        );
        assert_eq!(
            prepared.prefix.pending_before_digest,
            state_digest(RVFB1_SCHEMA, &before)
        );
        assert_eq!(
            prepared.prefix.pending_output_digest,
            output_digest(&result.outputs_bytes)
        );
        assert_eq!(
            prepared.prefix.pending_execution_digest,
            execution_digest(&input, &env)
        );
        assert_eq!(
            intent.header.prepared_state_digest,
            state_digest(RVFB1_SCHEMA, &result.candidate_bytes)
        );
        assert_eq!(
            intent.header.promoted_state_digest,
            state_digest(RVFB1_SCHEMA, &promoted)
        );
        assert_eq!(
            intent.header.cleared_state_digest,
            state_digest(RVFB1_SCHEMA, &cleared)
        );
        assert_eq!(intent.header.intent_kind, INTENT_NORMAL);
        assert_eq!(intent.outputs_bytes, result.outputs_bytes);
        assert_eq!(decode_rvbo1(&result.outputs_bytes).unwrap().frames.len(), 1);
        assert_eq!(result.meta.pending_phase, 1);
        assert_eq!(result.meta.transition_id, intent.header.transition_id);
        assert!(prepared.replays.iter().any(|entry| {
            entry.transition_id == intent.header.transition_id
                && entry.execution_digest == intent.header.execution_digest
                && entry.output_digest == intent.header.output_digest
        }));
    }

    #[test]
    fn journal_input_digest_never_depends_on_seal_plaintext() {
        use crate::hybrid_ratchet_v2_full_braid::digest::input_digest;
        use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::{MODE_SEAL_COMPARE, RVBA1_LEN};

        let seal_input = |body: &[u8]| Rvbi1 {
            op: OP_SEND,
            direction: 0,
            ch: None,
            expected_ch: None,
            object_digest: None,
            frame: None,
            mutation: Rvbm1 {
                needs_aead: 1,
                ec_mk_oracle_len: 0,
                ec_mk_oracle: [0; 32],
                aad: vec![0xAA; RVBA1_LEN],
                mode: MODE_SEAL_COMPARE,
                body: body.to_vec(),
                expected_ct: Some(vec![0xC7; body.len() + 16]),
            },
        };
        let yes = seal_input(b"yes");
        let no = seal_input(b"no!");
        // A guessed plaintext cannot be confirmed against the persisted digest.
        assert_ne!(
            journal_input_digest(&yes).unwrap(),
            input_digest(&encode_rvbi1(&yes).unwrap())
        );
        assert_eq!(
            journal_input_digest(&yes).unwrap(),
            journal_input_digest(&no).unwrap()
        );
        // The ciphertext still binds the input.
        let mut other_ct = seal_input(b"yes");
        other_ct.mutation.expected_ct = Some(vec![0xC8; 19]);
        assert_ne!(
            journal_input_digest(&yes).unwrap(),
            journal_input_digest(&other_ct).unwrap()
        );
        // Plaintext-free inputs keep the plain RVBI1 input digest.
        let plain = send_input_bytes();
        assert_eq!(
            journal_input_digest(&decode_rvbi1(&plain).unwrap()).unwrap(),
            input_digest(&plain)
        );
    }

    #[test]
    fn promote_handles_before_prepared_promoted_and_rejects_cleared() {
        let (before, _, _, result) = accepted();
        let (prepared, promoted, cleared) = expected_states(&result.intent_bytes);

        assert_eq!(
            promote_state(&before, &result.intent_bytes)
                .unwrap()
                .state_bytes,
            promoted
        );
        assert_eq!(
            promote_state(&prepared, &result.intent_bytes)
                .unwrap()
                .state_bytes,
            promoted
        );
        assert_eq!(
            promote_state(&promoted, &result.intent_bytes)
                .unwrap()
                .state_bytes,
            promoted
        );
        assert_eq!(
            promote_state(&cleared, &result.intent_bytes).unwrap_err(),
            ERR_CAS
        );
    }

    #[test]
    fn materialize_is_stable_and_repair_zeroes_object_digest() {
        let (before, _, _, result) = accepted();
        let first = materialize_rvor(&result.intent_bytes).unwrap();
        let second = materialize_rvor(&result.intent_bytes).unwrap();
        assert_eq!(first.rvor_bytes, second.rvor_bytes);
        assert_eq!(decode_rvor1(&first.rvor_bytes).unwrap().flags, 0);

        // Same generation as the intent's before state, different content.
        let mut conflict_live = decode_rvfb1(&before).unwrap();
        conflict_live.prefix.auth_root[0] ^= 1;
        let conflict_live = encode_rvfb1(&conflict_live).unwrap();
        let repair = terminalize_conflict(&conflict_live, &result.intent_bytes, 2_000).unwrap();
        let repair_intent = decode_rvbj1(&repair.intent_bytes).unwrap();
        assert_eq!(repair_intent.header.intent_kind, INTENT_REPAIR_CONFLICT);
        assert_eq!(repair_intent.header.object_digest, [0; 32]);
        assert_eq!(repair_intent.outputs_bytes, encode_empty_rvbo1());

        let repair_record =
            decode_rvor1(&materialize_rvor(&repair.intent_bytes).unwrap().rvor_bytes).unwrap();
        assert_eq!(repair_record.flags, RVOR1_FLAG_REPAIR);
        assert_eq!(repair_record.object_digest, [0; 32]);
    }

    #[test]
    fn clear_requires_matching_rvor_and_increments_generation_once() {
        let (before, _, _, result) = accepted();
        let promoted = promote_state(&before, &result.intent_bytes)
            .unwrap()
            .state_bytes;
        let rvor = materialize_rvor(&result.intent_bytes).unwrap().rvor_bytes;

        let cleared = clear_pending(&promoted, &result.intent_bytes, &rvor, 1_001)
            .unwrap()
            .state_bytes;
        let cleared_state = decode_rvfb1(&cleared).unwrap();
        assert_eq!(cleared_state.prefix.pending_phase, 0);
        assert_eq!(cleared_state.prefix.pending_transition_id, [0; 32]);
        assert_eq!(cleared_state.prefix.generation, 1);
        assert_eq!(cleared_state.prefix.flags & FLAG_AWAITING_COMPLETE, 0);
        assert_eq!(
            clear_pending(&cleared, &result.intent_bytes, &rvor, 1_001)
                .unwrap()
                .state_bytes,
            cleared
        );

        let mut mismatched = decode_rvor1(&rvor).unwrap();
        mismatched.transition_id[0] ^= 1;
        let mismatched = encode_rvor1(&mismatched).unwrap();
        assert_eq!(
            clear_pending(&promoted, &result.intent_bytes, &mismatched, 1_001).unwrap_err(),
            ERR_CAS
        );
        assert_eq!(
            clear_pending(&promoted, &result.intent_bytes, b"not-rvor", 1_001).unwrap_err(),
            ERR_PARSE
        );
    }

    #[test]
    fn recover_echoes_live_and_classifies_all_digest_states() {
        let (before, _, _, result) = accepted();
        let (prepared, promoted, cleared) = expected_states(&result.intent_bytes);
        for (live, expected_flag) in [
            (before.clone(), RECOVER_BEFORE),
            (prepared, RECOVER_PREPARED),
            (promoted, RECOVER_PROMOTED),
            (cleared, RECOVER_CLEARED),
        ] {
            let recovered = recover_state(&live, &result.intent_bytes).unwrap();
            assert_eq!(recovered.state_bytes, live);
            assert_eq!(recovered.meta.flags, expected_flag);
            assert_ne!(recovered.meta.transition_id, [0; 32]);
        }

        let mut conflict = decode_rvfb1(&before).unwrap();
        conflict.prefix.generation = 99;
        let conflict = encode_rvfb1(&conflict).unwrap();
        let recovered = recover_state(&conflict, &result.intent_bytes).unwrap();
        assert_eq!(recovered.state_bytes, conflict);
        assert_eq!(recovered.meta.flags, RECOVER_CONFLICT);
        assert_eq!(recovered.meta.transition_id, [0; 32]);
    }

    #[test]
    fn ignore_returns_no_intent_but_a_canonical_empty_output() {
        let before = before_bytes();
        let state = decode_rvfb1(&before).unwrap();
        let frame = Rvbc1 {
            epoch: 1,
            chunk_type: 0,
            index: 0,
            payload: Vec::new(),
            binding_digest: crate::hybrid_ratchet_v2_full_braid::digest::binding_digest(
                1,
                1,
                0,
                0,
                &[],
                &state.prefix.session_id,
            ),
        };
        let input = encode_rvbi1(&Rvbi1 {
            op: OP_RECEIVE,
            direction: 1,
            ch: None,
            expected_ch: None,
            object_digest: Some([0xAB; 32]),
            frame: Some(encode_rvbc1(&frame).unwrap()),
            mutation: Rvbm1::no_aead(),
        })
        .unwrap();
        let env = env_bytes(1_000);
        let mut crypto = LabCrypto::default();
        let result = transition_prepare(&before, &input, &env, &mut crypto).unwrap();

        assert_eq!(result.candidate_bytes, before);
        assert_eq!(result.outputs_bytes, encode_empty_rvbo1());
        assert!(result.intent_bytes.is_empty());
        assert_eq!(result.meta.flags, META_FLAG_IGNORED);
        assert_eq!(result.meta.transition_id, [0; 32]);
    }

    #[test]
    fn replay_hit_returns_only_matching_transition_metadata() {
        let input = send_input_bytes();
        let env = env_bytes(1_000);
        let exec = execution_digest(&input, &env);
        let mut state = decode_rvfb1(&before_bytes()).unwrap();
        state.replays.push(ReplayRecord {
            transition_id: [0xA7; 32],
            execution_digest: exec,
            output_digest: [0xB8; 32],
            output_len: 14,
            flags: 0,
        });
        let state = encode_rvfb1(&state).unwrap();
        let mut crypto = LabCrypto::default();
        let result = transition_prepare(&state, &input, &env, &mut crypto).unwrap();

        assert!(result.candidate_bytes.is_empty());
        assert!(result.outputs_bytes.is_empty());
        assert!(result.intent_bytes.is_empty());
        assert_eq!(result.meta.flags, META_FLAG_REPLAY_HIT);
        assert_eq!(result.meta.transition_id, [0xA7; 32]);
    }

    struct TerminalCrypto;

    impl BraidCrypto for TerminalCrypto {
        fn keygen(
            &mut self,
            _seed: &[u8; mlkem::SEED_LEN],
        ) -> Result<KeygenMaterial, BraidCryptoError> {
            Err(BraidCryptoError::Terminal {
                reason: TERMINAL_REASON_MAC,
            })
        }

        fn encaps1(
            &mut self,
            _header: &[u8; mlkem::HEADER_LEN],
            _coins: &[u8; mlkem::COINS_LEN],
        ) -> Result<Encaps1Material, BraidCryptoError> {
            Err(BraidCryptoError::Parse)
        }

        fn ct1_ack_advance(&mut self, _agent_epoch: u64) -> Result<(), BraidCryptoError> {
            Err(BraidCryptoError::Parse)
        }

        fn encaps2(
            &mut self,
            _encaps_state: &[u8; mlkem::STATE_LEN],
            _header: &[u8; mlkem::HEADER_LEN],
            _ek_vector: &[u8; mlkem::EK_VECTOR_LEN],
        ) -> Result<[u8; mlkem::CT2_LEN], BraidCryptoError> {
            Err(BraidCryptoError::Parse)
        }

        fn decaps(
            &mut self,
            _dk: &[u8; mlkem::DK_LEN],
            _ct1: &[u8; mlkem::CT1_LEN],
            _ct2: &[u8; mlkem::CT2_LEN],
        ) -> Result<[u8; mlkem::SS_LEN], BraidCryptoError> {
            Err(BraidCryptoError::Parse)
        }
    }

    #[test]
    fn terminal_transition_is_journaled_with_empty_outputs() {
        let before = before_bytes();
        let mut crypto = TerminalCrypto;
        let result =
            transition_prepare(&before, &send_input_bytes(), &env_bytes(1_000), &mut crypto)
                .unwrap();
        let state = decode_rvfb1(&result.candidate_bytes).unwrap();
        let intent = decode_rvbj1(&result.intent_bytes).unwrap();

        assert_eq!(state.prefix.flags & FLAG_TERMINAL, FLAG_TERMINAL);
        assert_eq!(state.prefix.terminal_reason, TERMINAL_REASON_MAC);
        assert_eq!(state.prefix.pending_phase, 1);
        assert_eq!(result.outputs_bytes, encode_empty_rvbo1());
        assert_eq!(result.meta.flags, META_FLAG_TERMINAL);
        assert_eq!(
            intent.header.output_digest,
            output_digest(&encode_empty_rvbo1())
        );
    }

    #[test]
    fn terminal_intent_rejects_self_consistent_nonempty_outputs() {
        let before = before_bytes();
        let mut crypto = TerminalCrypto;
        let terminal =
            transition_prepare(&before, &send_input_bytes(), &env_bytes(1_000), &mut crypto)
                .unwrap();
        let nonempty_outputs = accepted().3.outputs_bytes;
        let malformed = rewrite_intent_outputs(&terminal.intent_bytes, nonempty_outputs);

        assert_eq!(materialize_rvor(&malformed).unwrap_err(), ERR_PARSE);
    }

    #[test]
    fn successful_send_intent_rejects_self_consistent_empty_outputs() {
        let accepted = accepted().3;
        let malformed = rewrite_intent_outputs(&accepted.intent_bytes, encode_empty_rvbo1());
        assert_eq!(materialize_rvor(&malformed).unwrap_err(), ERR_PARSE);
    }

    #[test]
    fn expired_terminalization_requires_rvor_and_builds_repair_intent() {
        let (before, _, _, result) = accepted();
        let promoted = promote_state(&before, &result.intent_bytes)
            .unwrap()
            .state_bytes;
        let rvor = materialize_rvor(&result.intent_bytes).unwrap().rvor_bytes;
        let expiry = decode_rvor1(&rvor).unwrap().retention_expiry_ms;

        assert_eq!(
            terminalize_expired(&promoted, &result.intent_bytes, &[], expiry + 1).unwrap_err(),
            ERR_PARSE
        );
        let repair =
            terminalize_expired(&promoted, &result.intent_bytes, &rvor, expiry + 1).unwrap();
        let repair_intent = decode_rvbj1(&repair.intent_bytes).unwrap();
        assert_eq!(repair_intent.header.intent_kind, INTENT_REPAIR_EXPIRED);
        assert_eq!(repair_intent.header.object_digest, [0; 32]);
        assert_eq!(repair.meta.terminal_reason, 7);
    }

    #[test]
    fn terminalize_conflict_rejects_wrong_session_and_role() {
        let (before, _, _, result) = accepted();
        let mut conflict = decode_rvfb1(&before).unwrap();
        conflict.prefix.auth_root[0] ^= 1;
        let same_session = encode_rvfb1(&conflict).unwrap();
        assert!(terminalize_conflict(&same_session, &result.intent_bytes, 2_000).is_ok());

        let mut wrong_session = decode_rvfb1(&same_session).unwrap();
        wrong_session.prefix.session_id[0] ^= 0x5A;
        let wrong_session = encode_rvfb1(&wrong_session).unwrap();
        assert_eq!(
            terminalize_conflict(&wrong_session, &result.intent_bytes, 2_000).unwrap_err(),
            ERR_CAS
        );

        let mut wrong_role = decode_rvfb1(&same_session).unwrap();
        wrong_role.prefix.role = ROLE_BOB;
        let wrong_role = encode_rvfb1(&wrong_role).unwrap();
        assert_eq!(
            terminalize_conflict(&wrong_role, &result.intent_bytes, 2_000).unwrap_err(),
            ERR_CAS
        );
    }

    /// prepare → promote → materialize → clear one Send; returns (cleared, intent).
    fn commit_send(live: &[u8], clock: u64, env: &mut Rvbe1) -> (Vec<u8>, Vec<u8>) {
        env.clock = clock;
        let prepared = transition_prepare(
            live,
            &send_input_bytes(),
            &encode_rvbe1(env).unwrap(),
            &mut LabCrypto::default(),
        )
        .unwrap();
        let promoted = promote_state(live, &prepared.intent_bytes)
            .unwrap()
            .state_bytes;
        let rvor = materialize_rvor(&prepared.intent_bytes).unwrap().rvor_bytes;
        let cleared = clear_pending(&promoted, &prepared.intent_bytes, &rvor, clock)
            .unwrap()
            .state_bytes;
        (cleared, prepared.intent_bytes)
    }

    #[test]
    fn replay_window_evicts_oldest_in_commit_order() {
        let mut env = Rvbe1::default_caps(0);
        env.keygen_seed = vec![0x5A; mlkem::SEED_LEN];
        env.cap_replay_entries = 2;
        let mut live = before_bytes();
        let mut ids = Vec::new();
        for clock in 1..=5 {
            let (cleared, intent) = commit_send(&live, clock, &mut env);
            ids.push(decode_rvbj1(&intent).unwrap().header.transition_id);
            live = cleared;
        }
        let state = decode_rvfb1(&live).unwrap();
        assert_eq!(state.prefix.generation, 5);
        assert_eq!(
            state
                .replays
                .iter()
                .map(|record| record.transition_id)
                .collect::<Vec<_>>(),
            ids[3..].to_vec()
        );
    }

    #[test]
    fn terminalize_conflict_ignores_stale_intents_of_an_advanced_session() {
        let mut env = Rvbe1::default_caps(0);
        env.keygen_seed = vec![0x5A; mlkem::SEED_LEN];
        let before = before_bytes();
        let (cleared1, intent1) = commit_send(&before, 1, &mut env);

        // T2 pending from T1's cleared state: T1's journal is merely stale.
        env.clock = 2;
        let pending2 = transition_prepare(
            &cleared1,
            &send_input_bytes(),
            &encode_rvbe1(&env).unwrap(),
            &mut LabCrypto::default(),
        )
        .unwrap()
        .candidate_bytes;
        assert_eq!(
            terminalize_conflict(&pending2, &intent1, 3_000).unwrap_err(),
            ERR_CAS
        );
        // Two generations past T1: a crash-leftover journal must not kill it.
        let (cleared2, _) = commit_send(&cleared1, 2, &mut env);
        let (cleared3, _) = commit_send(&cleared2, 3, &mut env);
        for live in [&cleared2, &cleared3] {
            assert_eq!(
                terminalize_conflict(live, &intent1, 3_000).unwrap_err(),
                ERR_CAS
            );
        }

        // Real conflicts still repair: a different state in T1's generation…
        let mut other = decode_rvfb1(&before).unwrap();
        other.prefix.auth_mac_key[0] ^= 1;
        assert!(terminalize_conflict(&encode_rvfb1(&other).unwrap(), &intent1, 3_000).is_ok());
        // …or T1's successor generation reached through a different transition.
        let mut forked = decode_rvfb1(&cleared1).unwrap();
        forked.prefix.auth_mac_key[0] ^= 1;
        assert!(terminalize_conflict(&encode_rvfb1(&forked).unwrap(), &intent1, 3_000).is_ok());
    }

    #[derive(Default)]
    struct CountingCrypto {
        inner: LabCrypto,
        keygens: u64,
    }

    impl BraidCrypto for CountingCrypto {
        fn keygen(
            &mut self,
            seed: &[u8; mlkem::SEED_LEN],
        ) -> Result<KeygenMaterial, BraidCryptoError> {
            self.keygens = self.keygens.saturating_add(1);
            self.inner.keygen(seed)
        }

        fn encaps1(
            &mut self,
            header: &[u8; mlkem::HEADER_LEN],
            coins: &[u8; mlkem::COINS_LEN],
        ) -> Result<Encaps1Material, BraidCryptoError> {
            self.inner.encaps1(header, coins)
        }

        fn ct1_ack_advance(&mut self, agent_epoch: u64) -> Result<(), BraidCryptoError> {
            self.inner.ct1_ack_advance(agent_epoch)
        }

        fn encaps2(
            &mut self,
            encaps_state: &[u8; mlkem::STATE_LEN],
            header: &[u8; mlkem::HEADER_LEN],
            ek_vector: &[u8; mlkem::EK_VECTOR_LEN],
        ) -> Result<[u8; mlkem::CT2_LEN], BraidCryptoError> {
            self.inner.encaps2(encaps_state, header, ek_vector)
        }

        fn decaps(
            &mut self,
            dk: &[u8; mlkem::DK_LEN],
            ct1: &[u8; mlkem::CT1_LEN],
            ct2: &[u8; mlkem::CT2_LEN],
        ) -> Result<[u8; mlkem::SS_LEN], BraidCryptoError> {
            self.inner.decaps(dk, ct1, ct2)
        }
    }

    #[test]
    fn tightened_payload_and_chunks_preflight_need_capacity_without_crypto() {
        let before = before_bytes();
        let input = send_input_bytes();
        let mut env = Rvbe1::default_caps(1_000);
        env.keygen_seed = vec![0x5A; mlkem::SEED_LEN];
        env.cap_payload = (CW as u32) - 1; // 31 vs CW=32
        let env_wire = encode_rvbe1(&env).unwrap();
        let mut crypto = CountingCrypto::default();
        assert_eq!(
            transition_prepare(&before, &input, &env_wire, &mut crypto).unwrap_err(),
            ERR_NEED_CAPACITY
        );
        assert_eq!(crypto.keygens, 0);

        env.cap_payload = CW as u32;
        env.cap_chunks = 0;
        let env_wire = encode_rvbe1(&env).unwrap();
        assert_eq!(
            transition_prepare(&before, &input, &env_wire, &mut crypto).unwrap_err(),
            ERR_NEED_CAPACITY
        );
        assert_eq!(crypto.keygens, 0);
    }

    #[test]
    fn receive_frame_above_payload_or_chunk_cap_need_capacity() {
        let before = before_bytes();
        let state = decode_rvfb1(&before).unwrap();
        let payload = vec![0x11; CW];
        let frame = Rvbc1 {
            epoch: 1,
            chunk_type: 0,
            index: 0,
            payload: payload.clone(),
            binding_digest: crate::hybrid_ratchet_v2_full_braid::digest::binding_digest(
                1,
                1,
                0,
                0,
                &payload,
                &state.prefix.session_id,
            ),
        };
        let input = encode_rvbi1(&Rvbi1 {
            op: OP_RECEIVE,
            direction: 1,
            ch: None,
            expected_ch: None,
            object_digest: Some([0xAB; 32]),
            frame: Some(encode_rvbc1(&frame).unwrap()),
            mutation: Rvbm1::no_aead(),
        })
        .unwrap();

        let mut env = Rvbe1::default_caps(1_000);
        env.cap_payload = (CW as u32) - 1;
        let env_wire = encode_rvbe1(&env).unwrap();
        let mut crypto = CountingCrypto::default();
        assert_eq!(
            transition_prepare(&before, &input, &env_wire, &mut crypto).unwrap_err(),
            ERR_NEED_CAPACITY
        );
        assert_eq!(crypto.keygens, 0);

        env.cap_payload = CW as u32;
        env.cap_chunks = 0;
        let env_wire = encode_rvbe1(&env).unwrap();
        assert_eq!(
            transition_prepare(&before, &input, &env_wire, &mut crypto).unwrap_err(),
            ERR_NEED_CAPACITY
        );
    }

    #[test]
    fn state_and_replay_caps_return_need_capacity_at_exact_boundary() {
        let before = before_bytes();
        let input = send_input_bytes();
        let mut env = Rvbe1::default_caps(1_000);
        env.keygen_seed = vec![0x5A; mlkem::SEED_LEN];
        let mut crypto = LabCrypto::default();
        let ok =
            transition_prepare(&before, &input, &encode_rvbe1(&env).unwrap(), &mut crypto).unwrap();
        let exact = ok.candidate_bytes.len() as u32;

        env.cap_state = exact;
        let mut crypto = LabCrypto::default();
        assert!(
            transition_prepare(&before, &input, &encode_rvbe1(&env).unwrap(), &mut crypto).is_ok()
        );

        env.cap_state = exact - 1;
        let mut crypto = LabCrypto::default();
        assert_eq!(
            transition_prepare(&before, &input, &encode_rvbe1(&env).unwrap(), &mut crypto)
                .unwrap_err(),
            ERR_NEED_CAPACITY
        );

        // Replay entry/byte caps: one unit under the post-accept requirement.
        env.cap_state = exact;
        env.cap_replay_entries = 0;
        let mut crypto = LabCrypto::default();
        assert_eq!(
            transition_prepare(&before, &input, &encode_rvbe1(&env).unwrap(), &mut crypto)
                .unwrap_err(),
            ERR_NEED_CAPACITY
        );

        env.cap_replay_entries = 1;
        env.cap_replay_bytes = 101; // one Accept adds 102-byte replay record
        let mut crypto = LabCrypto::default();
        assert_eq!(
            transition_prepare(&before, &input, &encode_rvbe1(&env).unwrap(), &mut crypto)
                .unwrap_err(),
            ERR_NEED_CAPACITY
        );

        env.cap_replay_bytes = 102;
        let mut crypto = LabCrypto::default();
        assert!(
            transition_prepare(&before, &input, &encode_rvbe1(&env).unwrap(), &mut crypto).is_ok()
        );
    }
}
