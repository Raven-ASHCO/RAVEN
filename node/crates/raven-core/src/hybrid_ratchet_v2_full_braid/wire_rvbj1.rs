//! RVBJ1 mutation journal intent wire codec (design §4.10).

use std::fmt;

use zeroize::Zeroize;

use crate::hybrid_ratchet_v2_full_braid::constants::RVBJ1_HEADER_LEN;
use crate::hybrid_ratchet_v2_full_braid::wire_util::{
    expect_magic, read_array32, read_bytes, read_u32be, read_u64be, read_u8, reject_trailing,
    write_array32, write_bytes, write_u16be, write_u32be, write_u64be, write_u8, WireResult,
};

pub const RVBJ1_MAGIC: &[u8; 8] = b"RVBJ1\0\0\0";
pub const RVBJ1_SCHEMA: u16 = 1;

pub const INTENT_NORMAL: u8 = 0;
pub const INTENT_REPAIR_CONFLICT: u8 = 1;
pub const INTENT_REPAIR_EXPIRED: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rvbj1Header {
    pub session_id: [u8; 32],
    pub role: u8,
    pub direction: u8,
    pub intent_kind: u8,
    pub generation: u64,
    pub transition_id: [u8; 32],
    pub execution_digest: [u8; 32],
    pub input_digest: [u8; 32],
    pub before_state_digest: [u8; 32],
    pub prepared_state_digest: [u8; 32],
    pub promoted_state_digest: [u8; 32],
    pub cleared_state_digest: [u8; 32],
    pub output_digest: [u8; 32],
    pub object_digest: [u8; 32],
    pub retention_origin_ms: u64,
    pub retention_expiry_ms: u64,
    pub candidate_len: u32,
    pub outputs_len: u32,
}

/// Decoded journal intent. `candidate_bytes` is the complete canonical RVFB1
/// state (auth keys, ratchet keys, ML-KEM `dk`, skipped keys), so it is wiped on
/// drop (every early-return path after `decode_rvbj1` included) and redacted
/// from `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Rvbj1 {
    pub header: Rvbj1Header,
    pub candidate_bytes: Vec<u8>,
    pub outputs_bytes: Vec<u8>,
}

impl fmt::Debug for Rvbj1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rvbj1")
            .field("header", &self.header)
            .field("candidate_len", &self.candidate_bytes.len())
            .field("outputs_len", &self.outputs_bytes.len())
            .finish()
    }
}

impl Drop for Rvbj1 {
    fn drop(&mut self) {
        self.candidate_bytes.zeroize();
    }
}

pub fn encode_rvbj1_header(header: &Rvbj1Header) -> Vec<u8> {
    let mut out = Vec::with_capacity(RVBJ1_HEADER_LEN);
    write_bytes(&mut out, RVBJ1_MAGIC);
    write_u16be(&mut out, RVBJ1_SCHEMA);
    write_array32(&mut out, &header.session_id);
    write_u8(&mut out, header.role);
    write_u8(&mut out, header.direction);
    write_u8(&mut out, header.intent_kind);
    write_u8(&mut out, 0); // reserved0
    write_u64be(&mut out, header.generation);
    write_array32(&mut out, &header.transition_id);
    write_array32(&mut out, &header.execution_digest);
    write_array32(&mut out, &header.input_digest);
    write_array32(&mut out, &header.before_state_digest);
    write_array32(&mut out, &header.prepared_state_digest);
    write_array32(&mut out, &header.promoted_state_digest);
    write_array32(&mut out, &header.cleared_state_digest);
    write_array32(&mut out, &header.output_digest);
    write_array32(&mut out, &header.object_digest);
    write_u64be(&mut out, header.retention_origin_ms);
    write_u64be(&mut out, header.retention_expiry_ms);
    write_u32be(&mut out, header.candidate_len);
    write_u32be(&mut out, header.outputs_len);
    debug_assert_eq!(out.len(), RVBJ1_HEADER_LEN);
    out
}

pub fn decode_rvbj1_header(data: &[u8]) -> WireResult<Rvbj1Header> {
    if data.len() < RVBJ1_HEADER_LEN {
        return Err("rvbj1 header truncated".into());
    }
    expect_magic(data, RVBJ1_MAGIC)?;
    let mut off = 8;
    let schema = crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)?;
    if schema != RVBJ1_SCHEMA {
        return Err("rvbj1 bad schema".into());
    }
    let session_id = read_array32(data, &mut off)?;
    let role = read_u8(data, &mut off)?;
    let direction = read_u8(data, &mut off)?;
    let intent_kind = read_u8(data, &mut off)?;
    let reserved0 = read_u8(data, &mut off)?;
    if reserved0 != 0 {
        return Err("rvbj1 reserved0".into());
    }
    let generation = read_u64be(data, &mut off)?;
    let transition_id = read_array32(data, &mut off)?;
    let execution_digest = read_array32(data, &mut off)?;
    let input_digest = read_array32(data, &mut off)?;
    let before_state_digest = read_array32(data, &mut off)?;
    let prepared_state_digest = read_array32(data, &mut off)?;
    let promoted_state_digest = read_array32(data, &mut off)?;
    let cleared_state_digest = read_array32(data, &mut off)?;
    let output_digest = read_array32(data, &mut off)?;
    let object_digest = read_array32(data, &mut off)?;
    let retention_origin_ms = read_u64be(data, &mut off)?;
    let retention_expiry_ms = read_u64be(data, &mut off)?;
    let candidate_len = read_u32be(data, &mut off)?;
    let outputs_len = read_u32be(data, &mut off)?;
    if off != RVBJ1_HEADER_LEN {
        return Err("rvbj1 header length mismatch".into());
    }
    Ok(Rvbj1Header {
        session_id,
        role,
        direction,
        intent_kind,
        generation,
        transition_id,
        execution_digest,
        input_digest,
        before_state_digest,
        prepared_state_digest,
        promoted_state_digest,
        cleared_state_digest,
        output_digest,
        object_digest,
        retention_origin_ms,
        retention_expiry_ms,
        candidate_len,
        outputs_len,
    })
}

pub fn encode_rvbj1(intent: &Rvbj1) -> WireResult<Vec<u8>> {
    if intent.candidate_bytes.len() != intent.header.candidate_len as usize {
        return Err("rvbj1 candidate_len mismatch".into());
    }
    if intent.outputs_bytes.len() != intent.header.outputs_len as usize {
        return Err("rvbj1 outputs_len mismatch".into());
    }
    let mut out = encode_rvbj1_header(&intent.header);
    write_bytes(&mut out, &intent.candidate_bytes);
    write_bytes(&mut out, &intent.outputs_bytes);
    Ok(out)
}

pub fn decode_rvbj1(data: &[u8]) -> WireResult<Rvbj1> {
    let header = decode_rvbj1_header(data)?;
    let total = RVBJ1_HEADER_LEN + header.candidate_len as usize + header.outputs_len as usize;
    if data.len() != total {
        return Err("rvbj1 total length mismatch".into());
    }
    let mut off = RVBJ1_HEADER_LEN;
    let candidate_bytes = read_bytes(data, &mut off, header.candidate_len as usize)?.to_vec();
    let outputs_bytes = read_bytes(data, &mut off, header.outputs_len as usize)?.to_vec();
    reject_trailing(data, off)?;
    Ok(Rvbj1 {
        header,
        candidate_bytes,
        outputs_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Rvbj1Header {
        Rvbj1Header {
            session_id: [0x01; 32],
            role: 0,
            direction: 0,
            intent_kind: INTENT_NORMAL,
            generation: 0,
            transition_id: [0x02; 32],
            execution_digest: [0x03; 32],
            input_digest: [0x04; 32],
            before_state_digest: [0x05; 32],
            prepared_state_digest: [0x06; 32],
            promoted_state_digest: [0x07; 32],
            cleared_state_digest: [0x08; 32],
            output_digest: [0x09; 32],
            object_digest: [0x0A; 32],
            retention_origin_ms: 100,
            retention_expiry_ms: 200,
            candidate_len: 3,
            outputs_len: 14,
        }
    }

    #[test]
    fn header_exactly_366_bytes() {
        let hdr = sample_header();
        let wire = encode_rvbj1_header(&hdr);
        assert_eq!(wire.len(), RVBJ1_HEADER_LEN);
        assert_eq!(decode_rvbj1_header(&wire).unwrap(), hdr);
    }

    #[test]
    fn full_intent_roundtrip() {
        use crate::hybrid_ratchet_v2_full_braid::wire_rvbo1::encode_empty_rvbo1;
        let outputs = encode_empty_rvbo1();
        let intent = Rvbj1 {
            header: sample_header(),
            candidate_bytes: vec![0xAA, 0xBB, 0xCC],
            outputs_bytes: outputs,
        };
        let wire = encode_rvbj1(&intent).unwrap();
        assert_eq!(decode_rvbj1(&wire).unwrap(), intent);
    }

    #[test]
    fn debug_redacts_candidate_state() {
        let intent = Rvbj1 {
            header: sample_header(),
            candidate_bytes: vec![0xDE, 0xAD, 0xBE],
            outputs_bytes: vec![0u8; 14],
        };
        let shown = format!("{intent:?}");
        assert!(shown.contains("candidate_len: 3"), "{shown}");
        assert!(!shown.contains("222") && !shown.contains("0xDE"), "{shown}");
        assert!(!shown.contains("candidate_bytes"), "{shown}");
    }

    #[test]
    fn reject_trailing_on_full_intent() {
        let intent = Rvbj1 {
            header: sample_header(),
            candidate_bytes: vec![1, 2, 3],
            outputs_bytes: vec![0u8; 14],
        };
        let mut wire = encode_rvbj1(&intent).unwrap();
        wire.push(0);
        assert!(decode_rvbj1(&wire).is_err());
    }
}
