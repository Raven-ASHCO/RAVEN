//! Canonical RVFB1 state codec — outer prefix + typed tail sections (design §6).

use std::fmt;

use zeroize::Zeroize;

use crate::hybrid_ratchet_v2_full_braid::constants::{
    ACTIVE_SEND_MAX, AGENT_CT1_ACKNOWLEDGED, AGENT_CT2_SAMPLED, AGENT_TERMINAL,
    BRAID_MAX_CANONICAL_STATE_BYTES, FLAG_CT1_ACK_APPLIED, RVFB1_PREFIX,
};
use crate::hybrid_ratchet_v2_full_braid::digest::state_digest;
use crate::hybrid_ratchet_v2_full_braid::spqr_codec::{
    wire_needs_decoder, BRAID_MAX_CHUNKS_PER_EPOCH, BRAID_MAX_CHUNK_INDEX, WIRE_CT1, WIRE_CT2,
    WIRE_EK, WIRE_EK_CT1_ACK, WIRE_HDR,
};
use crate::hybrid_ratchet_v2_full_braid::spqr_pin_audit::{
    CW, INBOUND_BUDGET, L_CT1, L_CT2, L_EK, L_HDR, N_HDR,
};
use crate::hybrid_ratchet_v2_full_braid::wire_rvft1::{decode_rvft1, encode_rvft1, Rvft1};
use crate::hybrid_ratchet_v2_full_braid::wire_util::{
    expect_magic, read_array32, read_bytes, read_u16be, read_u32be, read_u64be, read_u8,
    reject_trailing, write_array32, write_bytes, write_u16be, write_u32be, write_u64be, write_u8,
    WireResult,
};

pub const RVFB1_MAGIC: &[u8; 8] = b"RVFB1\0\0\0";
pub const RVFB1_SCHEMA: u16 = 1;

pub const DIR_A2B: u8 = 0;
pub const DIR_B2A: u8 = 1;
pub const ROLE_ALICE: u8 = 0;
pub const ROLE_BOB: u8 = 1;
pub const SOURCE_KIND_HDR: u8 = 1;
pub const SOURCE_KIND_EK: u8 = 2;
pub const SOURCE_KIND_CT1: u8 = 5;
pub const SOURCE_KIND_CT2: u8 = 6;

const MAX_INBOUND_SETS: usize = 8;
const MAX_OBJECTS: usize = 32;
/// Replay window capacity. Records are kept in commit order (oldest first) and
/// the pipeline evicts the oldest once the window is full.
pub const MAX_REPLAYS: usize = 64;
/// Encoded size of one replay record (transition, execution, output digests +
/// output_len u32 + flags u16).
pub const REPLAY_RECORD_LEN: usize = 102;

/// Exact TLV tag lengths (design §6.3).
const TLV_LEN: [(u16, usize); 8] = [
    (1, 2400),
    (2, 32),
    (3, 32),
    (4, 1152),
    (5, 2080),
    (6, 960),
    (7, 128),
    (8, 64),
];

/// Agents that require `CT1_ACK_APPLIED` (design §6.1).
pub fn agent_requires_ct1_ack(agent: u8) -> bool {
    agent == AGENT_CT1_ACKNOWLEDGED || agent == AGENT_CT2_SAMPLED
}

#[derive(Clone, PartialEq, Eq)]
pub struct Rvfb1Prefix {
    pub session_id: [u8; 32],
    pub role: u8,
    pub generation: u64,
    pub agent: u8,
    pub terminal_reason: u16,
    pub auth_root: [u8; 32],
    pub auth_mac_key: [u8; 32],
    pub braid_agent_epoch: u64,
    pub braid_send_epoch: u64,
    pub braid_recv_epoch: u64,
    pub flags: u32,
    pub pending_phase: u8,
    pub pending_transition_id: [u8; 32],
    pub pending_before_digest: [u8; 32],
    pub pending_output_digest: [u8; 32],
    pub pending_execution_digest: [u8; 32],
}

impl fmt::Debug for Rvfb1Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rvfb1Prefix")
            .field("session_id", &self.session_id)
            .field("role", &self.role)
            .field("generation", &self.generation)
            .field("agent", &self.agent)
            .field("terminal_reason", &self.terminal_reason)
            .field("braid_agent_epoch", &self.braid_agent_epoch)
            .field("braid_send_epoch", &self.braid_send_epoch)
            .field("braid_recv_epoch", &self.braid_recv_epoch)
            .field("flags", &self.flags)
            .field("pending_phase", &self.pending_phase)
            .field("pending_transition_id", &self.pending_transition_id)
            .field("auth_keys", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Drop for Rvfb1Prefix {
    fn drop(&mut self) {
        self.auth_root.zeroize();
        self.auth_mac_key.zeroize();
    }
}

impl Rvfb1Prefix {
    pub fn ct1_ack_applied(&self) -> bool {
        self.flags & FLAG_CT1_ACK_APPLIED != 0
    }

    pub fn validate_ct1_ack_invariant(&self) -> WireResult<()> {
        let bit = self.ct1_ack_applied();
        let req = agent_requires_ct1_ack(self.agent);
        if bit != req {
            return Err("rvfb1 CT1_ACK_APPLIED iff agent".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundChunk {
    pub index: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSet {
    pub direction: u8,
    pub epoch: u64,
    pub source_kind: u8,
    pub expected_source_len: u32,
    pub max_index: u32,
    pub bitmap: Vec<u8>,
    pub chunks: Vec<InboundChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSend {
    pub direction: u8,
    pub epoch: u64,
    pub wire_type: u8,
    pub source_kind: u8,
    pub source_len: u32,
    pub source_digest: [u8; 32],
    pub source_bytes: Vec<u8>,
    pub next_spqr_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraidObject {
    pub direction: u8,
    pub epoch: u64,
    pub source_kind: u8,
    pub object_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRecord {
    pub transition_id: [u8; 32],
    pub execution_digest: [u8; 32],
    pub output_digest: [u8; 32],
    pub output_len: u32,
    pub flags: u16,
}

/// Agent TLV (ML-KEM `dk`, Encaps1 state, …): value wiped on drop, never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct TlvEntry {
    pub tag: u16,
    pub value: Vec<u8>,
}

impl fmt::Debug for TlvEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlvEntry")
            .field("tag", &self.tag)
            .field("len", &self.value.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for TlvEntry {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rvfb1State {
    pub prefix: Rvfb1Prefix,
    pub inbound_sets: Vec<InboundSet>,
    pub active_send: Option<ActiveSend>,
    pub objects: Vec<BraidObject>,
    pub replays: Vec<ReplayRecord>,
    pub tlvs: Vec<TlvEntry>,
    pub tr: Rvft1,
}

/// Canonicality probe: encodes and wipes the scratch bytes (they hold every
/// ratchet secret).
pub fn rvfb1_encodable(state: &Rvfb1State) -> bool {
    match encode_rvfb1(state) {
        Ok(mut bytes) => {
            bytes.zeroize();
            true
        }
        Err(_) => false,
    }
}

/// Whether `state` encodes to exactly `bytes`; the scratch encoding is wiped.
pub fn rvfb1_encodes_to(state: &Rvfb1State, bytes: &[u8]) -> WireResult<bool> {
    let mut encoded = encode_rvfb1(state)?;
    let same = encoded == bytes;
    encoded.zeroize();
    Ok(same)
}

impl Rvfb1State {
    pub fn digest(&self) -> WireResult<[u8; 32]> {
        let bytes = encode_rvfb1(self)?;
        Ok(state_digest(RVFB1_SCHEMA, &bytes))
    }
}

pub fn encode_rvfb1_prefix(prefix: &Rvfb1Prefix) -> WireResult<Vec<u8>> {
    prefix.validate_ct1_ack_invariant()?;
    let mut out = Vec::with_capacity(RVFB1_PREFIX);
    write_bytes(&mut out, RVFB1_MAGIC);
    write_u16be(&mut out, RVFB1_SCHEMA);
    write_array32(&mut out, &prefix.session_id);
    write_u8(&mut out, prefix.role);
    write_u64be(&mut out, prefix.generation);
    write_u8(&mut out, prefix.agent);
    write_u16be(&mut out, prefix.terminal_reason);
    write_array32(&mut out, &prefix.auth_root);
    write_array32(&mut out, &prefix.auth_mac_key);
    write_u64be(&mut out, prefix.braid_agent_epoch);
    write_u64be(&mut out, prefix.braid_send_epoch);
    write_u64be(&mut out, prefix.braid_recv_epoch);
    write_u32be(&mut out, prefix.flags);
    write_u8(&mut out, prefix.pending_phase);
    write_array32(&mut out, &prefix.pending_transition_id);
    write_array32(&mut out, &prefix.pending_before_digest);
    write_array32(&mut out, &prefix.pending_output_digest);
    write_array32(&mut out, &prefix.pending_execution_digest);
    if out.len() != RVFB1_PREFIX {
        return Err("rvfb1 prefix length".into());
    }
    Ok(out)
}

pub fn decode_rvfb1_prefix(data: &[u8]) -> WireResult<Rvfb1Prefix> {
    if data.len() < RVFB1_PREFIX {
        return Err("rvfb1 prefix truncated".into());
    }
    expect_magic(data, RVFB1_MAGIC)?;
    let mut off = 8;
    let schema = read_u16be(data, &mut off)?;
    if schema != RVFB1_SCHEMA {
        return Err("rvfb1 bad schema".into());
    }
    let session_id = read_array32(data, &mut off)?;
    let role = read_u8(data, &mut off)?;
    let generation = read_u64be(data, &mut off)?;
    let agent = read_u8(data, &mut off)?;
    let terminal_reason = read_u16be(data, &mut off)?;
    let auth_root = read_array32(data, &mut off)?;
    let auth_mac_key = read_array32(data, &mut off)?;
    let braid_agent_epoch = read_u64be(data, &mut off)?;
    let braid_send_epoch = read_u64be(data, &mut off)?;
    let braid_recv_epoch = read_u64be(data, &mut off)?;
    let flags = read_u32be(data, &mut off)?;
    let pending_phase = read_u8(data, &mut off)?;
    let pending_transition_id = read_array32(data, &mut off)?;
    let pending_before_digest = read_array32(data, &mut off)?;
    let pending_output_digest = read_array32(data, &mut off)?;
    let pending_execution_digest = read_array32(data, &mut off)?;
    if off != RVFB1_PREFIX {
        return Err("rvfb1 prefix length".into());
    }
    let prefix = Rvfb1Prefix {
        session_id,
        role,
        generation,
        agent,
        terminal_reason,
        auth_root,
        auth_mac_key,
        braid_agent_epoch,
        braid_send_epoch,
        braid_recv_epoch,
        flags,
        pending_phase,
        pending_transition_id,
        pending_before_digest,
        pending_output_digest,
        pending_execution_digest,
    };
    prefix.validate_ct1_ack_invariant()?;
    Ok(prefix)
}

fn validate_inbound_sets_sorted(sets: &[InboundSet]) -> WireResult<()> {
    for w in sets.windows(2) {
        let a = (w[0].direction, w[0].epoch, w[0].source_kind);
        let b = (w[1].direction, w[1].epoch, w[1].source_kind);
        if a >= b {
            return Err("rvfb1 inbound sets unsorted".into());
        }
    }
    Ok(())
}

fn source_kind_ok(kind: u8) -> bool {
    matches!(
        kind,
        SOURCE_KIND_HDR | SOURCE_KIND_EK | SOURCE_KIND_CT1 | SOURCE_KIND_CT2
    )
}

fn expected_len_for_source_kind(kind: u8) -> Option<u32> {
    match kind {
        SOURCE_KIND_HDR => Some(L_HDR as u32),
        SOURCE_KIND_EK => Some(L_EK as u32),
        SOURCE_KIND_CT1 => Some(L_CT1 as u32),
        SOURCE_KIND_CT2 => Some(L_CT2 as u32),
        _ => None,
    }
}

fn bitmap_required_len(max_index: u32) -> usize {
    ((max_index as usize) + 1).div_ceil(8)
}

fn bitmap_get(bitmap: &[u8], index: u32) -> bool {
    let i = index as usize;
    let byte = i / 8;
    let bit = i % 8;
    bitmap
        .get(byte)
        .map(|b| (b & (1u8 << bit)) != 0)
        .unwrap_or(false)
}

fn validate_inbound_set(set: &InboundSet) -> WireResult<()> {
    if set.direction > DIR_B2A {
        return Err("rvfb1 inbound direction".into());
    }
    if !source_kind_ok(set.source_kind) {
        return Err("rvfb1 inbound source_kind".into());
    }
    if let Some(expect) = expected_len_for_source_kind(set.source_kind) {
        if set.expected_source_len != expect {
            return Err("rvfb1 inbound expected_source_len".into());
        }
    }
    // Cap admits redundancy indices through BRAID_MAX_CHUNK_INDEX.
    if set.max_index != BRAID_MAX_CHUNK_INDEX {
        return Err("rvfb1 inbound max_index must be BRAID_MAX_CHUNK_INDEX".into());
    }
    let need = bitmap_required_len(set.max_index);
    if set.bitmap.len() != need {
        return Err("rvfb1 inbound bitmap_len".into());
    }
    if set.chunks.len() > BRAID_MAX_CHUNKS_PER_EPOCH {
        return Err("rvfb1 inbound num_chunks".into());
    }
    for w in set.chunks.windows(2) {
        if w[0].index >= w[1].index {
            return Err("rvfb1 inbound chunks unsorted".into());
        }
    }
    for chunk in &set.chunks {
        if chunk.index > BRAID_MAX_CHUNK_INDEX || chunk.index > set.max_index {
            return Err("rvfb1 inbound chunk index".into());
        }
        if chunk.payload.len() != CW {
            return Err("rvfb1 inbound chunk plen".into());
        }
        if !bitmap_get(&set.bitmap, chunk.index) {
            return Err("rvfb1 inbound bitmap missing chunk bit".into());
        }
    }
    // Every set bit must have a matching chunk (strict consistency).
    let mut bit_count = 0usize;
    for i in 0..=set.max_index {
        if bitmap_get(&set.bitmap, i) {
            bit_count += 1;
            if !set.chunks.iter().any(|c| c.index == i) {
                return Err("rvfb1 inbound bitmap orphan bit".into());
            }
        }
    }
    if bit_count != set.chunks.len() {
        return Err("rvfb1 inbound bitmap/chunk count".into());
    }
    Ok(())
}

fn decode_inbound_sets(data: &[u8], off: &mut usize) -> WireResult<(Vec<InboundSet>, usize)> {
    let start = *off;
    let count = read_u16be(data, off)? as usize;
    if count > MAX_INBOUND_SETS {
        return Err("rvfb1 too many inbound sets".into());
    }
    let mut sets = Vec::with_capacity(count);
    for _ in 0..count {
        let direction = read_u8(data, off)?;
        let epoch = read_u64be(data, off)?;
        let source_kind = read_u8(data, off)?;
        let expected_source_len = read_u32be(data, off)?;
        let max_index = read_u32be(data, off)?;
        let bitmap_len = read_u16be(data, off)? as usize;
        let bitmap = read_bytes(data, off, bitmap_len)?.to_vec();
        let num_chunks = read_u16be(data, off)? as usize;
        if num_chunks > BRAID_MAX_CHUNKS_PER_EPOCH {
            return Err("rvfb1 inbound num_chunks".into());
        }
        let mut chunks = Vec::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            let index = read_u32be(data, off)?;
            let plen = read_u16be(data, off)? as usize;
            let payload = read_bytes(data, off, plen)?.to_vec();
            chunks.push(InboundChunk { index, payload });
        }
        let set = InboundSet {
            direction,
            epoch,
            source_kind,
            expected_source_len,
            max_index,
            bitmap,
            chunks,
        };
        validate_inbound_set(&set)?;
        sets.push(set);
    }
    validate_inbound_sets_sorted(&sets)?;
    Ok((sets, *off - start))
}

fn encode_inbound_sets(sets: &[InboundSet]) -> WireResult<Vec<u8>> {
    if sets.len() > MAX_INBOUND_SETS {
        return Err("rvfb1 too many inbound sets".into());
    }
    validate_inbound_sets_sorted(sets)?;
    for set in sets {
        validate_inbound_set(set)?;
    }
    let mut out = Vec::new();
    write_u16be(&mut out, sets.len() as u16);
    for set in sets {
        write_u8(&mut out, set.direction);
        write_u64be(&mut out, set.epoch);
        write_u8(&mut out, set.source_kind);
        write_u32be(&mut out, set.expected_source_len);
        write_u32be(&mut out, set.max_index);
        write_u16be(&mut out, set.bitmap.len() as u16);
        write_bytes(&mut out, &set.bitmap);
        write_u16be(&mut out, set.chunks.len() as u16);
        for chunk in &set.chunks {
            write_u32be(&mut out, chunk.index);
            write_u16be(&mut out, chunk.payload.len() as u16);
            write_bytes(&mut out, &chunk.payload);
        }
    }
    Ok(out)
}

fn validate_objects_sorted(objects: &[BraidObject]) -> WireResult<()> {
    for w in objects.windows(2) {
        let a = (w[0].direction, w[0].epoch, w[0].source_kind);
        let b = (w[1].direction, w[1].epoch, w[1].source_kind);
        if a >= b {
            return Err("rvfb1 objects unsorted".into());
        }
    }
    Ok(())
}

fn validate_object(obj: &BraidObject) -> WireResult<()> {
    if obj.direction > DIR_B2A {
        return Err("rvfb1 object direction".into());
    }
    if !source_kind_ok(obj.source_kind) {
        return Err("rvfb1 object source_kind".into());
    }
    Ok(())
}

fn decode_objects(data: &[u8], off: &mut usize) -> WireResult<Vec<BraidObject>> {
    let count = read_u16be(data, off)? as usize;
    if count > MAX_OBJECTS {
        return Err("rvfb1 too many objects".into());
    }
    let mut objects = Vec::with_capacity(count);
    for _ in 0..count {
        let obj = BraidObject {
            direction: read_u8(data, off)?,
            epoch: read_u64be(data, off)?,
            source_kind: read_u8(data, off)?,
            object_digest: read_array32(data, off)?,
        };
        validate_object(&obj)?;
        objects.push(obj);
    }
    validate_objects_sorted(&objects)?;
    Ok(objects)
}

fn encode_objects(objects: &[BraidObject]) -> WireResult<Vec<u8>> {
    if objects.len() > MAX_OBJECTS {
        return Err("rvfb1 too many objects".into());
    }
    validate_objects_sorted(objects)?;
    for obj in objects {
        validate_object(obj)?;
    }
    let mut out = Vec::new();
    write_u16be(&mut out, objects.len() as u16);
    for obj in objects {
        write_u8(&mut out, obj.direction);
        write_u64be(&mut out, obj.epoch);
        write_u8(&mut out, obj.source_kind);
        write_array32(&mut out, &obj.object_digest);
    }
    Ok(out)
}

/// Replay records are a FIFO window in commit order, so canonical form is the
/// recorded sequence itself; transition ids must be unique.
fn validate_replays_unique(replays: &[ReplayRecord]) -> WireResult<()> {
    for (i, record) in replays.iter().enumerate() {
        if replays[..i]
            .iter()
            .any(|prior| prior.transition_id == record.transition_id)
        {
            return Err("rvfb1 replays duplicate transition_id".into());
        }
    }
    Ok(())
}

fn decode_replays(data: &[u8], off: &mut usize) -> WireResult<Vec<ReplayRecord>> {
    let count = read_u16be(data, off)? as usize;
    if count > MAX_REPLAYS {
        return Err("rvfb1 too many replays".into());
    }
    let mut replays = Vec::with_capacity(count);
    for _ in 0..count {
        replays.push(ReplayRecord {
            transition_id: read_array32(data, off)?,
            execution_digest: read_array32(data, off)?,
            output_digest: read_array32(data, off)?,
            output_len: read_u32be(data, off)?,
            flags: read_u16be(data, off)?,
        });
    }
    validate_replays_unique(&replays)?;
    Ok(replays)
}

fn encode_replays(replays: &[ReplayRecord]) -> WireResult<Vec<u8>> {
    if replays.len() > MAX_REPLAYS {
        return Err("rvfb1 too many replays".into());
    }
    validate_replays_unique(replays)?;
    let mut out = Vec::new();
    write_u16be(&mut out, replays.len() as u16);
    for replay in replays {
        write_array32(&mut out, &replay.transition_id);
        write_array32(&mut out, &replay.execution_digest);
        write_array32(&mut out, &replay.output_digest);
        write_u32be(&mut out, replay.output_len);
        write_u16be(&mut out, replay.flags);
    }
    Ok(out)
}

fn validate_tlvs_sorted(tlvs: &[TlvEntry]) -> WireResult<()> {
    for w in tlvs.windows(2) {
        if w[0].tag >= w[1].tag {
            return Err("rvfb1 tlvs unsorted".into());
        }
    }
    Ok(())
}

fn tlv_exact_len(tag: u16) -> Option<usize> {
    TLV_LEN.iter().find(|(t, _)| *t == tag).map(|(_, l)| *l)
}

/// Required / optional / forbidden tags per agent (design §6.3).
fn tlv_matrix(agent: u8) -> WireResult<(&'static [u16], &'static [u16], &'static [u16])> {
    match agent {
        0 | 5 | AGENT_TERMINAL => Ok((&[], &[], &[1, 2, 3, 4, 5, 6, 7, 8])),
        1 => Ok((&[1, 2, 3, 4, 8], &[], &[5, 6, 7])),
        2 => Ok((&[1, 4], &[], &[2, 3, 5, 6, 7, 8])),
        3 => Ok((&[1, 4, 6], &[], &[2, 3, 5, 7, 8])),
        4 => Ok((&[1, 6], &[], &[2, 3, 4, 5, 7, 8])),
        6 => Ok((&[2, 3], &[], &[1, 4, 5, 6, 7, 8])),
        7 | 9 => Ok((&[2, 3, 5, 6], &[], &[1, 4, 7, 8])),
        8 => Ok((&[2, 3, 4, 5, 6], &[], &[1, 7, 8])),
        10 => Ok((&[7], &[6], &[1, 2, 3, 4, 5, 8])),
        _ => Err("rvfb1 unknown agent for tlv matrix".into()),
    }
}

fn validate_tlvs_for_agent(agent: u8, tlvs: &[TlvEntry]) -> WireResult<()> {
    validate_tlvs_sorted(tlvs)?;
    let (required, optional, forbidden) = tlv_matrix(agent)?;
    for tlv in tlvs {
        let Some(expect) = tlv_exact_len(tlv.tag) else {
            return Err("rvfb1 unknown tlv tag".into());
        };
        if tlv.value.len() != expect {
            return Err("rvfb1 tlv length".into());
        }
        if forbidden.contains(&tlv.tag) {
            return Err("rvfb1 tlv forbidden for agent".into());
        }
        if !(required.contains(&tlv.tag) || optional.contains(&tlv.tag)) {
            return Err("rvfb1 tlv not allowed for agent".into());
        }
    }
    for &req in required {
        if !tlvs.iter().any(|t| t.tag == req) {
            return Err("rvfb1 tlv required missing".into());
        }
    }
    Ok(())
}

fn decode_tlvs(data: &[u8], off: &mut usize) -> WireResult<Vec<TlvEntry>> {
    let count = read_u16be(data, off)? as usize;
    // `count` is attacker-controlled: each TLV needs at least tag(2) + len(4)
    // bytes, so never reserve more than the remaining bytes can hold.
    let mut tlvs = Vec::with_capacity(count.min(data.len().saturating_sub(*off) / 6));
    for _ in 0..count {
        let tag = read_u16be(data, off)?;
        let len = read_u32be(data, off)? as usize;
        let value = read_bytes(data, off, len)?.to_vec();
        tlvs.push(TlvEntry { tag, value });
    }
    Ok(tlvs)
}

fn encode_tlvs(tlvs: &[TlvEntry]) -> WireResult<Vec<u8>> {
    validate_tlvs_sorted(tlvs)?;
    let mut out = Vec::new();
    write_u16be(&mut out, tlvs.len() as u16);
    for tlv in tlvs {
        write_u16be(&mut out, tlv.tag);
        write_u32be(&mut out, tlv.value.len() as u32);
        write_bytes(&mut out, &tlv.value);
    }
    Ok(out)
}

fn validate_active_send(active: &ActiveSend) -> WireResult<()> {
    if active.direction > DIR_B2A {
        return Err("rvfb1 active_send direction".into());
    }
    if active.source_bytes.len() as u32 != active.source_len {
        return Err("rvfb1 active_send source_len".into());
    }
    // `next_spqr_index` is a cursor, so 64 is the exhausted sentinel even
    // though the largest emitted chunk index is 63.
    if active.next_spqr_index > BRAID_MAX_CHUNKS_PER_EPOCH as u32 {
        return Err("rvfb1 active_send next_spqr_index".into());
    }
    let needs = wire_needs_decoder(active.wire_type).map_err(|_| "rvfb1 active_send wire_type")?;
    if needs {
        if !source_kind_ok(active.source_kind) {
            return Err("rvfb1 active_send source_kind".into());
        }
        if let Some(expect) = expected_len_for_source_kind(active.source_kind) {
            if active.source_len != expect {
                return Err("rvfb1 active_send source_len".into());
            }
        }
        match active.wire_type {
            WIRE_HDR if active.source_kind != SOURCE_KIND_HDR => {
                return Err("rvfb1 active_send kind mismatch".into());
            }
            WIRE_EK | WIRE_EK_CT1_ACK if active.source_kind != SOURCE_KIND_EK => {
                return Err("rvfb1 active_send kind mismatch".into());
            }
            WIRE_CT1 if active.source_kind != SOURCE_KIND_CT1 => {
                return Err("rvfb1 active_send kind mismatch".into());
            }
            WIRE_CT2 if active.source_kind != SOURCE_KIND_CT2 => {
                return Err("rvfb1 active_send kind mismatch".into());
            }
            _ => {}
        }
    } else {
        // None / Ct1Ack: no erasure payload.
        if active.source_len != 0 || !active.source_bytes.is_empty() {
            return Err("rvfb1 active_send empty source required".into());
        }
        if active.source_kind != 0 {
            return Err("rvfb1 active_send source_kind".into());
        }
    }
    Ok(())
}

fn decode_active_send(data: &[u8], off: &mut usize) -> WireResult<Option<ActiveSend>> {
    let present = read_u8(data, off)?;
    if present > 1 {
        return Err("rvfb1 active_send present".into());
    }
    if present == 0 {
        return Ok(None);
    }
    let direction = read_u8(data, off)?;
    let epoch = read_u64be(data, off)?;
    let wire_type = read_u8(data, off)?;
    let source_kind = read_u8(data, off)?;
    let source_len = read_u32be(data, off)?;
    let source_digest = read_array32(data, off)?;
    let source_bytes = read_bytes(data, off, source_len as usize)?.to_vec();
    let next_spqr_index = read_u32be(data, off)?;
    let active = ActiveSend {
        direction,
        epoch,
        wire_type,
        source_kind,
        source_len,
        source_digest,
        source_bytes,
        next_spqr_index,
    };
    validate_active_send(&active)?;
    Ok(Some(active))
}

fn encode_active_send(active: &Option<ActiveSend>) -> WireResult<Vec<u8>> {
    let mut out = Vec::new();
    match active {
        None => write_u8(&mut out, 0),
        Some(a) => {
            validate_active_send(a)?;
            write_u8(&mut out, 1);
            write_u8(&mut out, a.direction);
            write_u64be(&mut out, a.epoch);
            write_u8(&mut out, a.wire_type);
            write_u8(&mut out, a.source_kind);
            write_u32be(&mut out, a.source_len);
            write_array32(&mut out, &a.source_digest);
            write_bytes(&mut out, &a.source_bytes);
            write_u32be(&mut out, a.next_spqr_index);
        }
    }
    if out.len() > ACTIVE_SEND_MAX {
        return Err("rvfb1 active_send too large".into());
    }
    Ok(out)
}

fn validate_prefix_allowlists(prefix: &Rvfb1Prefix) -> WireResult<()> {
    if prefix.role > ROLE_BOB {
        return Err("rvfb1 role".into());
    }
    prefix.validate_ct1_ack_invariant()?;
    Ok(())
}

pub fn encode_rvfb1(state: &Rvfb1State) -> WireResult<Vec<u8>> {
    validate_prefix_allowlists(&state.prefix)?;
    validate_tlvs_for_agent(state.prefix.agent, &state.tlvs)?;
    let tr_bytes = encode_rvft1(&state.tr)?;
    let mut out = encode_rvfb1_prefix(&state.prefix)?;
    let inbound = encode_inbound_sets(&state.inbound_sets)?;
    if inbound.len() > INBOUND_BUDGET {
        return Err("rvfb1 inbound budget exceeded".into());
    }
    out.extend_from_slice(&inbound);
    out.extend_from_slice(&encode_active_send(&state.active_send)?);
    out.extend_from_slice(&encode_objects(&state.objects)?);
    out.extend_from_slice(&encode_replays(&state.replays)?);
    out.extend_from_slice(&encode_tlvs(&state.tlvs)?);
    write_u32be(&mut out, tr_bytes.len() as u32);
    write_bytes(&mut out, &tr_bytes);

    if out.len() > BRAID_MAX_CANONICAL_STATE_BYTES {
        return Err("rvfb1 exceeds max state bytes".into());
    }
    Ok(out)
}

pub fn decode_rvfb1(data: &[u8]) -> WireResult<Rvfb1State> {
    if data.len() > BRAID_MAX_CANONICAL_STATE_BYTES {
        return Err("rvfb1 exceeds max state bytes".into());
    }
    let prefix = decode_rvfb1_prefix(data)?;
    validate_prefix_allowlists(&prefix)?;
    let mut off = RVFB1_PREFIX;
    let (inbound_sets, inbound_len) = decode_inbound_sets(data, &mut off)?;
    if inbound_len > INBOUND_BUDGET {
        return Err("rvfb1 inbound budget exceeded".into());
    }
    let active_send = decode_active_send(data, &mut off)?;
    let objects = decode_objects(data, &mut off)?;
    let replays = decode_replays(data, &mut off)?;
    let tlvs = decode_tlvs(data, &mut off)?;
    validate_tlvs_for_agent(prefix.agent, &tlvs)?;
    let tr_len = read_u32be(data, &mut off)? as usize;
    let tr_bytes = read_bytes(data, &mut off, tr_len)?;
    let tr = decode_rvft1(tr_bytes)?;
    reject_trailing(data, off)?;
    Ok(Rvfb1State {
        prefix,
        inbound_sets,
        active_send,
        objects,
        replays,
        tlvs,
        tr,
    })
}

/// Empty inbound Hdr set for Bob post-init (design §4.2).
///
/// `max_index` is frozen to `BRAID_MAX_CHUNK_INDEX` so redundancy indices remain
/// admissible; empty bitmap (all clear) with exact length for that cap.
pub fn bob_empty_hdr_inbound_set() -> InboundSet {
    InboundSet {
        direction: DIR_A2B,
        epoch: 1,
        source_kind: SOURCE_KIND_HDR,
        expected_source_len: (N_HDR * CW) as u32,
        max_index: BRAID_MAX_CHUNK_INDEX,
        bitmap: vec![0u8; bitmap_required_len(BRAID_MAX_CHUNK_INDEX)],
        chunks: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_ratchet_v2_full_braid::digest::send_source_digest;
    use crate::hybrid_ratchet_v2_full_braid::wire_rvft1::{
        EcSkippedEntry, Rvft1, SckaChainEntry, SckaSkippedEntry,
    };

    fn sample_prefix(agent: u8, flags: u32) -> Rvfb1Prefix {
        Rvfb1Prefix {
            session_id: [0x01; 32],
            role: 0,
            generation: 0,
            agent,
            terminal_reason: 0,
            auth_root: [0x02; 32],
            auth_mac_key: [0x03; 32],
            braid_agent_epoch: 1,
            braid_send_epoch: 0,
            braid_recv_epoch: 0,
            flags,
            pending_phase: 0,
            pending_transition_id: [0; 32],
            pending_before_digest: [0; 32],
            pending_output_digest: [0; 32],
            pending_execution_digest: [0; 32],
        }
    }

    fn minimal_tr() -> Rvft1 {
        Rvft1 {
            scka_rk: [0x99; 32],
            scka_sending_epoch: 0,
            scka_receiving_epoch: 0,
            scka_send_chain: Vec::new(),
            scka_recv_chain: Vec::new(),
            scka_send_pn: 0,
            scka_skipped: Vec::new(),
            ec_rk: [0xAA; 32],
            ec_dhs_priv: [0xBB; 32],
            ec_dhs_pub: [0xCC; 32],
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

    fn minimal_state() -> Rvfb1State {
        Rvfb1State {
            prefix: sample_prefix(0, 0),
            inbound_sets: Vec::new(),
            active_send: None,
            objects: Vec::new(),
            replays: Vec::new(),
            tlvs: Vec::new(),
            tr: minimal_tr(),
        }
    }

    #[test]
    fn prefix_exactly_275_bytes() {
        let prefix = sample_prefix(0, 0);
        assert_eq!(encode_rvfb1_prefix(&prefix).unwrap().len(), RVFB1_PREFIX);
    }

    #[test]
    fn ct1_ack_iff_agents_9_10() {
        assert!(sample_prefix(AGENT_CT1_ACKNOWLEDGED, FLAG_CT1_ACK_APPLIED)
            .validate_ct1_ack_invariant()
            .is_ok());
        assert!(sample_prefix(AGENT_CT2_SAMPLED, FLAG_CT1_ACK_APPLIED)
            .validate_ct1_ack_invariant()
            .is_ok());
        assert!(sample_prefix(AGENT_CT1_ACKNOWLEDGED, 0)
            .validate_ct1_ack_invariant()
            .is_err());
        assert!(sample_prefix(0, FLAG_CT1_ACK_APPLIED)
            .validate_ct1_ack_invariant()
            .is_err());
    }

    #[test]
    fn roundtrip_minimal_state() {
        let state = minimal_state();
        let wire = encode_rvfb1(&state).unwrap();
        assert!(wire.len() >= RVFB1_PREFIX);
        assert_eq!(decode_rvfb1(&wire).unwrap(), state);
    }

    #[test]
    fn roundtrip_inbound_set_with_chunks() {
        let mut bitmap = vec![0u8; bitmap_required_len(BRAID_MAX_CHUNK_INDEX)];
        bitmap[0] |= 1 << 0;
        bitmap[0] |= 1 << 1;
        // Redundancy index 3 also present.
        bitmap[0] |= 1 << 3;
        let mut state = minimal_state();
        state.inbound_sets.push(InboundSet {
            direction: DIR_A2B,
            epoch: 1,
            source_kind: SOURCE_KIND_HDR,
            expected_source_len: 96,
            max_index: BRAID_MAX_CHUNK_INDEX,
            bitmap,
            chunks: vec![
                InboundChunk {
                    index: 0,
                    payload: vec![0xAA; CW],
                },
                InboundChunk {
                    index: 1,
                    payload: vec![0xBB; CW],
                },
                InboundChunk {
                    index: 3,
                    payload: vec![0xCC; CW],
                },
            ],
        });
        let wire = encode_rvfb1(&state).unwrap();
        assert_eq!(decode_rvfb1(&wire).unwrap(), state);
    }

    #[test]
    fn reject_inbound_empty_payload_and_bad_index() {
        let mut bitmap = vec![0u8; bitmap_required_len(BRAID_MAX_CHUNK_INDEX)];
        bitmap[0] |= 1;
        let mut state = minimal_state();
        state.inbound_sets.push(InboundSet {
            direction: DIR_A2B,
            epoch: 1,
            source_kind: SOURCE_KIND_HDR,
            expected_source_len: 96,
            max_index: BRAID_MAX_CHUNK_INDEX,
            bitmap: bitmap.clone(),
            chunks: vec![InboundChunk {
                index: 0,
                payload: Vec::new(),
            }],
        });
        assert!(encode_rvfb1(&state).is_err());

        state.inbound_sets[0].chunks[0].payload = vec![0u8; CW];
        state.inbound_sets[0].chunks[0].index = 64;
        state.inbound_sets[0].bitmap = bitmap;
        assert!(encode_rvfb1(&state).is_err());
    }

    #[test]
    fn roundtrip_active_send_present() {
        let source_bytes = vec![0xCC; 96];
        let mut state = minimal_state();
        state.active_send = Some(ActiveSend {
            direction: DIR_A2B,
            epoch: 1,
            wire_type: WIRE_HDR,
            source_kind: SOURCE_KIND_HDR,
            source_len: 96,
            source_digest: send_source_digest(&source_bytes),
            source_bytes,
            next_spqr_index: 1,
        });
        let wire = encode_rvfb1(&state).unwrap();
        assert_eq!(decode_rvfb1(&wire).unwrap(), state);
    }

    #[test]
    fn active_send_allows_exhausted_next_index_sentinel() {
        let source_bytes = vec![0xCC; 96];
        let mut state = minimal_state();
        state.active_send = Some(ActiveSend {
            direction: DIR_A2B,
            epoch: 1,
            wire_type: WIRE_HDR,
            source_kind: SOURCE_KIND_HDR,
            source_len: 96,
            source_digest: send_source_digest(&source_bytes),
            source_bytes,
            next_spqr_index: BRAID_MAX_CHUNKS_PER_EPOCH as u32,
        });
        let wire = encode_rvfb1(&state).unwrap();
        assert_eq!(decode_rvfb1(&wire).unwrap(), state);
    }

    #[test]
    fn roundtrip_objects_replays_no_tlvs_on_agent0() {
        let mut state = minimal_state();
        state.objects.push(BraidObject {
            direction: 0,
            epoch: 1,
            source_kind: 1,
            object_digest: [0x11; 32],
        });
        state.replays.push(ReplayRecord {
            transition_id: [0x22; 32],
            execution_digest: [0x33; 32],
            output_digest: [0x44; 32],
            output_len: 14,
            flags: 0,
        });
        // Agent 0 forbids all TLVs.
        state.tlvs.clear();
        let wire = encode_rvfb1(&state).unwrap();
        assert_eq!(decode_rvfb1(&wire).unwrap(), state);
    }

    #[test]
    fn tlv_rof_enforced_for_agent() {
        let mut state = minimal_state();
        // Forbidden on agent 0.
        state.tlvs.push(TlvEntry {
            tag: 2,
            value: vec![0u8; 32],
        });
        assert!(encode_rvfb1(&state).is_err());

        // Agent 10: required 7, optional 6, CT1_ACK bit set.
        state.prefix.agent = AGENT_CT2_SAMPLED;
        state.prefix.flags = FLAG_CT1_ACK_APPLIED;
        state.tlvs = vec![TlvEntry {
            tag: 7,
            value: vec![0u8; 128],
        }];
        assert!(encode_rvfb1(&state).is_ok());
        state.tlvs.push(TlvEntry {
            tag: 1,
            value: vec![0u8; 2400],
        });
        assert!(encode_rvfb1(&state).is_err());
    }

    #[test]
    fn inbound_budget_independent_of_rvft1() {
        // Large TR must not consume inbound budget; only inbound section does.
        let state = minimal_state();
        // Keep inbound empty (tiny). Total still under 262144.
        let wire = encode_rvfb1(&state).unwrap();
        let (_sets, inbound_len) = {
            let mut off = RVFB1_PREFIX;
            decode_inbound_sets(&wire, &mut off).unwrap()
        };
        assert!(inbound_len <= INBOUND_BUDGET);
        assert!(wire.len() <= BRAID_MAX_CANONICAL_STATE_BYTES);
        assert!(decode_rvfb1(&wire).is_ok());
    }

    #[test]
    fn roundtrip_rvft1_with_skipped_maps() {
        let mut state = minimal_state();
        state.tr = minimal_tr();
        state.tr.scka_send_chain = vec![SckaChainEntry {
            epoch: 1,
            ck: [0x01; 32],
            n: 0,
        }];
        state.tr.scka_skipped = vec![SckaSkippedEntry {
            direction: 0,
            epoch: 1,
            n: 0,
            mk: [0x10; 32],
        }];
        state.tr.ec_skipped = vec![EcSkippedEntry {
            dh_pub: [0x20; 32],
            n: 0,
            mk: [0x21; 32],
        }];
        let wire = encode_rvfb1(&state).unwrap();
        assert_eq!(decode_rvfb1(&wire).unwrap(), state);
    }

    #[test]
    fn reject_unsorted_objects() {
        let mut state = minimal_state();
        state.objects = vec![
            BraidObject {
                direction: 1,
                epoch: 1,
                source_kind: 1,
                object_digest: [0; 32],
            },
            BraidObject {
                direction: 0,
                epoch: 1,
                source_kind: 1,
                object_digest: [0; 32],
            },
        ];
        assert!(encode_rvfb1(&state).is_err());
    }

    #[test]
    fn debug_output_never_prints_secret_state() {
        use crate::hybrid_ratchet_v2_full_braid::wire_rvbe1::Rvbe1;

        let mut state = minimal_state();
        state.prefix.auth_root = [0xAB; 32];
        state.prefix.auth_mac_key = [0xAB; 32];
        state.tr.scka_rk = [0xAB; 32];
        state.tr.ec_rk = [0xAB; 32];
        state.tr.ec_dhs_priv = [0xAB; 32];
        state.tr.ec_skipped = vec![EcSkippedEntry {
            dh_pub: [0x01; 32],
            n: 0,
            mk: [0xAB; 32],
        }];
        let tlv = TlvEntry {
            tag: 1,
            value: vec![0xAB; 2400],
        };
        let mut env = Rvbe1::default_caps(0);
        env.keygen_seed = vec![0xAB; 64];
        env.ec_dh_seed = vec![0xAB; 32];
        let printed = format!("{state:?}{tlv:?}{env:?}");
        assert!(printed.contains("<redacted>"));
        assert!(!printed.contains("171, 171"), "{printed}");
    }

    #[test]
    fn replays_keep_commit_order_and_reject_duplicate_ids() {
        let record = |id: u8| ReplayRecord {
            transition_id: [id; 32],
            execution_digest: [0; 32],
            output_digest: [0; 32],
            output_len: 0,
            flags: 0,
        };
        let mut state = minimal_state();
        // FIFO window: newest last, not sorted by transition id.
        state.replays = vec![record(0x02), record(0x01)];
        let wire = encode_rvfb1(&state).unwrap();
        assert_eq!(decode_rvfb1(&wire).unwrap().replays, state.replays);

        state.replays = vec![record(0x02), record(0x01), record(0x02)];
        assert!(encode_rvfb1(&state).is_err());
    }

    #[test]
    fn reject_unsorted_tlvs() {
        let mut state = minimal_state();
        state.prefix.agent = AGENT_CT2_SAMPLED;
        state.prefix.flags = FLAG_CT1_ACK_APPLIED;
        state.tlvs = vec![
            TlvEntry {
                tag: 7,
                value: vec![0u8; 128],
            },
            TlvEntry {
                tag: 6,
                value: vec![0u8; 960],
            },
        ];
        assert!(encode_rvfb1(&state).is_err());
    }

    #[test]
    fn reject_active_send_present_gt_one() {
        let mut wire = encode_rvfb1(&minimal_state()).unwrap();
        let active_off = RVFB1_PREFIX + 2; // after num_inbound_sets=0
        wire[active_off] = 2;
        assert!(decode_rvfb1(&wire).is_err());
    }

    #[test]
    fn reject_trailing_bytes() {
        let mut wire = encode_rvfb1(&minimal_state()).unwrap();
        wire.push(0);
        assert!(decode_rvfb1(&wire).is_err());
    }

    #[test]
    fn bob_hdr_inbound_set_fields() {
        let set = bob_empty_hdr_inbound_set();
        assert_eq!(set.expected_source_len, 96);
        assert_eq!(set.max_index, BRAID_MAX_CHUNK_INDEX);
        assert_eq!(set.bitmap.len(), bitmap_required_len(BRAID_MAX_CHUNK_INDEX));
        assert!(set.bitmap.iter().all(|&b| b == 0));
        assert!(set.chunks.is_empty());
    }
}
