//! RVBO1 transition outputs wire codec (design §4.9).

use crate::hybrid_ratchet_v2_full_braid::constants::{EMPTY_RVBO1_LEN, MAX_RVBO1};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbc1::decode_rvbc1;
use crate::hybrid_ratchet_v2_full_braid::wire_rvch1::{decode_rvch1, encode_rvch1, Rvch1};
use crate::hybrid_ratchet_v2_full_braid::wire_util::{
    expect_magic, read_bytes, read_u32be, read_u8, reject_trailing, write_bytes, write_u16be,
    write_u32be, write_u8, WireResult,
};

pub const RVBO1_MAGIC: &[u8; 8] = b"RVBO1\0\0\0";
pub const RVBO1_SCHEMA: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rvbo1 {
    pub frames: Vec<Vec<u8>>,
    pub ch_out: Option<Rvch1>,
    pub sealed_ct: Option<Vec<u8>>,
}

impl Rvbo1 {
    pub fn empty() -> Self {
        Self {
            frames: Vec::new(),
            ch_out: None,
            sealed_ct: None,
        }
    }

    pub fn is_empty14(&self) -> bool {
        self.frames.is_empty() && self.ch_out.is_none() && self.sealed_ct.is_none()
    }
}

/// Exact 14-byte empty RVBO1 (design §4.9).
pub fn encode_empty_rvbo1() -> Vec<u8> {
    let mut out = Vec::with_capacity(EMPTY_RVBO1_LEN);
    write_bytes(&mut out, RVBO1_MAGIC);
    write_u16be(&mut out, RVBO1_SCHEMA);
    write_u16be(&mut out, 0); // num_frames
    write_u8(&mut out, 0); // ch_out_present
    write_u8(&mut out, 0); // sealed_ct_present
    debug_assert_eq!(out.len(), EMPTY_RVBO1_LEN);
    out
}

pub fn encode_rvbo1(outputs: &Rvbo1) -> WireResult<Vec<u8>> {
    if outputs.frames.len() > u16::MAX as usize {
        return Err("rvbo1 too many frames".into());
    }
    let mut out = Vec::new();
    write_bytes(&mut out, RVBO1_MAGIC);
    write_u16be(&mut out, RVBO1_SCHEMA);
    write_u16be(&mut out, outputs.frames.len() as u16);
    for frame in &outputs.frames {
        write_u32be(&mut out, frame.len() as u32);
        write_bytes(&mut out, frame);
    }
    let ch_present = outputs.ch_out.is_some() as u8;
    write_u8(&mut out, ch_present);
    if let Some(ch) = &outputs.ch_out {
        write_bytes(&mut out, &encode_rvch1(ch));
    }
    let sealed_present = outputs.sealed_ct.is_some() as u8;
    write_u8(&mut out, sealed_present);
    if let Some(ct) = &outputs.sealed_ct {
        write_u32be(&mut out, ct.len() as u32);
        write_bytes(&mut out, ct);
    }
    if out.len() > MAX_RVBO1 {
        return Err("rvbo1 too large".into());
    }
    Ok(out)
}

pub fn decode_rvbo1(data: &[u8]) -> WireResult<Rvbo1> {
    // Cap the input before parsing (RVBC1/RVOR1/RVFT1/RVFB1 do the same).
    if data.len() > MAX_RVBO1 {
        return Err("rvbo1 too large".into());
    }
    if data.len() == EMPTY_RVBO1_LEN {
        let empty = encode_empty_rvbo1();
        if data == empty.as_slice() {
            return Ok(Rvbo1::empty());
        }
    }
    expect_magic(data, RVBO1_MAGIC)?;
    let mut off = 8;
    let schema = crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)?;
    if schema != RVBO1_SCHEMA {
        return Err("rvbo1 bad schema".into());
    }
    let num_frames =
        crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)? as usize;
    // `num_frames` is attacker-controlled: each frame needs at least its 4-byte
    // length prefix, so never reserve more than the remaining bytes can hold.
    let mut frames = Vec::with_capacity(num_frames.min(data.len().saturating_sub(off) / 4));
    for _ in 0..num_frames {
        let frame_len = read_u32be(data, &mut off)? as usize;
        let frame = read_bytes(data, &mut off, frame_len)?.to_vec();
        decode_rvbc1(&frame)?;
        frames.push(frame);
    }
    let ch_present = read_u8(data, &mut off)?;
    let ch_out = if ch_present == 1 {
        Some(decode_rvch1(read_bytes(data, &mut off, 68)?)?)
    } else if ch_present == 0 {
        None
    } else {
        return Err("rvbo1 ch_out_present".into());
    };
    let sealed_present = read_u8(data, &mut off)?;
    let sealed_ct = if sealed_present == 1 {
        let ct_len = read_u32be(data, &mut off)? as usize;
        Some(read_bytes(data, &mut off, ct_len)?.to_vec())
    } else if sealed_present == 0 {
        None
    } else {
        return Err("rvbo1 sealed_present".into());
    };
    reject_trailing(data, off)?;
    Ok(Rvbo1 {
        frames,
        ch_out,
        sealed_ct,
    })
}

/// Successful Send (incl. wire type None) → num_frames == 1.
/// When AEAD outputs are present, both `ch_out` and `sealed_ct` MUST be set.
pub fn validate_send_success(outputs: &Rvbo1) -> WireResult<()> {
    if outputs.frames.len() != 1 {
        return Err("rvbo1 send_success num_frames".into());
    }
    match (&outputs.ch_out, &outputs.sealed_ct) {
        (None, None) | (Some(_), Some(_)) => Ok(()),
        _ => Err("rvbo1 send_success ch_out/sealed_ct pair".into()),
    }
}

/// Successful Receive → num_frames == 0.
pub fn validate_receive_success(outputs: &Rvbo1) -> WireResult<()> {
    if !outputs.is_empty14() {
        return Err("rvbo1 receive_success must be empty14".into());
    }
    Ok(())
}

/// Journaled-terminal / repair intent outputs → exact empty 14-byte RVBO1.
pub fn validate_repair_or_terminal_empty(wire: &[u8]) -> WireResult<()> {
    if wire.len() != EMPTY_RVBO1_LEN {
        return Err("rvbo1 repair/terminal must be 14 bytes".into());
    }
    if wire != encode_empty_rvbo1().as_slice() {
        return Err("rvbo1 repair/terminal exact empty".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_ratchet_v2_full_braid::digest::binding_digest;
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbc1::{encode_rvbc1, Rvbc1};

    #[test]
    fn empty14_exact_bytes() {
        let wire = encode_empty_rvbo1();
        assert_eq!(wire.len(), EMPTY_RVBO1_LEN);
        validate_repair_or_terminal_empty(&wire).unwrap();
        assert!(decode_rvbo1(&wire).unwrap().is_empty14());
    }

    #[test]
    fn send_success_one_frame() {
        let sid = [0x01; 32];
        let payload = vec![0u8; 32];
        let chunk = Rvbc1 {
            epoch: 1,
            chunk_type: 0,
            index: 0,
            payload: payload.clone(),
            binding_digest: binding_digest(0, 1, 0, 0, &payload, &sid),
        };
        let frame = encode_rvbc1(&chunk).unwrap();
        let outputs = Rvbo1 {
            frames: vec![frame],
            ch_out: None,
            sealed_ct: None,
        };
        validate_send_success(&outputs).unwrap();
        let wire = encode_rvbo1(&outputs).unwrap();
        assert_eq!(decode_rvbo1(&wire).unwrap(), outputs);
    }

    #[test]
    fn receive_success_empty14() {
        let outputs = Rvbo1::empty();
        validate_receive_success(&outputs).unwrap();
    }

    #[test]
    fn reject_trailing() {
        let mut wire = encode_empty_rvbo1();
        wire.push(0);
        assert!(decode_rvbo1(&wire).is_err());
    }

    #[test]
    fn oversize_and_inflated_frame_count_are_rejected_without_parsing() {
        // magic | schema | num_frames = 0xFFFF, but no frame bytes follow.
        let mut inflated = Vec::new();
        inflated.extend_from_slice(RVBO1_MAGIC);
        inflated.extend_from_slice(&RVBO1_SCHEMA.to_be_bytes());
        inflated.extend_from_slice(&0xFFFFu16.to_be_bytes());
        assert!(decode_rvbo1(&inflated).is_err());
        inflated.extend_from_slice(&[0u8; 3]);
        assert!(decode_rvbo1(&inflated).is_err());
        // Anything above MAX_RVBO1 is refused before the body is looked at.
        assert!(decode_rvbo1(&vec![0u8; MAX_RVBO1 + 1]).is_err());
        let mut valid_prefix_oversize = encode_empty_rvbo1();
        valid_prefix_oversize.resize(MAX_RVBO1 + 1, 0);
        assert!(decode_rvbo1(&valid_prefix_oversize).is_err());
    }
}
