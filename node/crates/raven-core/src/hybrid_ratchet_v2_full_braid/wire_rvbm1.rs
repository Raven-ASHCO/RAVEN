//! RVBM1 mutation body wire codec (design §4.6).

use std::fmt;

use zeroize::Zeroize;

use crate::hybrid_ratchet_v2_full_braid::wire_util::{
    expect_magic, read_bytes, read_u32be, read_u8, reject_trailing, write_bytes, write_u16be,
    write_u32be, write_u8, WireResult,
};

pub const RVBM1_MAGIC: &[u8; 8] = b"RVBM1\0\0\0";
pub const RVBM1_SCHEMA: u16 = 1;
pub const RVBA1_LEN: usize = 176;
pub const BRAID_MAX_AEAD_PLAINTEXT_BYTES: usize = 8192;
pub const BRAID_MAX_AEAD_CIPHERTEXT_BYTES: usize = 8208;
pub const BRAID_MIN_AEAD_CIPHERTEXT_BYTES: usize = 16;

pub const MODE_SEAL_COMPARE: u8 = 0;
pub const MODE_OPEN: u8 = 1;

/// Mode-0 `body` is application plaintext and `ec_mk_oracle` may be a message
/// key: both are wiped on drop and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Rvbm1 {
    pub needs_aead: u8,
    pub ec_mk_oracle_len: u16,
    pub ec_mk_oracle: [u8; 32],
    pub aad: Vec<u8>,
    pub mode: u8,
    pub body: Vec<u8>,
    pub expected_ct: Option<Vec<u8>>,
}

impl fmt::Debug for Rvbm1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rvbm1")
            .field("needs_aead", &self.needs_aead)
            .field("ec_mk_oracle_len", &self.ec_mk_oracle_len)
            .field("aad_len", &self.aad.len())
            .field("mode", &self.mode)
            .field("body_len", &self.body.len())
            .field("expected_ct_len", &self.expected_ct.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

impl Drop for Rvbm1 {
    fn drop(&mut self) {
        self.ec_mk_oracle.zeroize();
        self.body.zeroize();
    }
}

impl Rvbm1 {
    pub fn no_aead() -> Self {
        Self {
            needs_aead: 0,
            ec_mk_oracle_len: 0,
            ec_mk_oracle: [0u8; 32],
            aad: Vec::new(),
            mode: 0,
            body: Vec::new(),
            expected_ct: None,
        }
    }
}

pub fn encode_rvbm1(body: &Rvbm1) -> WireResult<Vec<u8>> {
    if body.needs_aead > 1 {
        return Err("rvbm1 needs_aead".into());
    }
    if body.needs_aead == 0 {
        if body.ec_mk_oracle_len != 0
            || body.ec_mk_oracle != [0u8; 32]
            || !body.aad.is_empty()
            || body.mode != 0
            || !body.body.is_empty()
            || body.expected_ct.is_some()
        {
            return Err("rvbm1 needs_aead=0 contract".into());
        }
    } else {
        if body.ec_mk_oracle_len != 0 && body.ec_mk_oracle_len != 32 {
            return Err("rvbm1 oracle_len".into());
        }
        if body.aad.len() != RVBA1_LEN {
            return Err("rvbm1 aad_len".into());
        }
        if body.mode > 1 {
            return Err("rvbm1 mode".into());
        }
        match body.mode {
            MODE_SEAL_COMPARE => {
                if body.body.len() > BRAID_MAX_AEAD_PLAINTEXT_BYTES {
                    return Err("rvbm1 body_len".into());
                }
                let ct = body
                    .expected_ct
                    .as_ref()
                    .ok_or_else(|| "rvbm1 missing expected_ct".to_string())?;
                if ct.len()
                    != body
                        .body
                        .len()
                        .checked_add(16)
                        .ok_or_else(|| "overflow".to_string())?
                {
                    return Err("rvbm1 expected_ct_len".into());
                }
            }
            MODE_OPEN => {
                if body.body.len() < BRAID_MIN_AEAD_CIPHERTEXT_BYTES
                    || body.body.len() > BRAID_MAX_AEAD_CIPHERTEXT_BYTES
                {
                    return Err("rvbm1 body_len".into());
                }
                if body.expected_ct.is_some() {
                    return Err("rvbm1 unexpected expected_ct".into());
                }
            }
            _ => return Err("rvbm1 mode".into()),
        }
    }

    let mut out = Vec::new();
    write_bytes(&mut out, RVBM1_MAGIC);
    write_u16be(&mut out, RVBM1_SCHEMA);
    write_u8(&mut out, body.needs_aead);
    write_u8(&mut out, 0); // reserved0
    write_u16be(&mut out, body.ec_mk_oracle_len);
    write_bytes(&mut out, &body.ec_mk_oracle);
    write_u16be(&mut out, body.aad.len() as u16);
    write_bytes(&mut out, &body.aad);
    write_u8(&mut out, body.mode);
    write_u32be(&mut out, body.body.len() as u32);
    write_bytes(&mut out, &body.body);
    if body.needs_aead == 1 && body.mode == MODE_SEAL_COMPARE {
        let ct = body.expected_ct.as_ref().unwrap();
        write_u32be(&mut out, ct.len() as u32);
        write_bytes(&mut out, ct);
    }
    Ok(out)
}

pub fn decode_rvbm1(data: &[u8]) -> WireResult<Rvbm1> {
    expect_magic(data, RVBM1_MAGIC)?;
    let mut off = 8;
    let schema = crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)?;
    if schema != RVBM1_SCHEMA {
        return Err("rvbm1 bad schema".into());
    }
    let needs_aead = read_u8(data, &mut off)?;
    let reserved0 = read_u8(data, &mut off)?;
    if reserved0 != 0 {
        return Err("rvbm1 reserved0".into());
    }
    let ec_mk_oracle_len =
        crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)?;
    let mut ec_mk_oracle = [0u8; 32];
    ec_mk_oracle.copy_from_slice(read_bytes(data, &mut off, 32)?);
    let aad_len =
        crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)? as usize;
    let aad = read_bytes(data, &mut off, aad_len)?.to_vec();
    let mode = read_u8(data, &mut off)?;
    let body_len = read_u32be(data, &mut off)? as usize;
    let body = read_bytes(data, &mut off, body_len)?.to_vec();

    let expected_ct = if needs_aead == 1 && mode == MODE_SEAL_COMPARE {
        let ct_len = read_u32be(data, &mut off)? as usize;
        Some(read_bytes(data, &mut off, ct_len)?.to_vec())
    } else {
        None
    };

    reject_trailing(data, off)?;

    let parsed = Rvbm1 {
        needs_aead,
        ec_mk_oracle_len,
        ec_mk_oracle,
        aad,
        mode,
        body,
        expected_ct,
    };
    // Re-validate contract on decode
    encode_rvbm1(&parsed)?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_aead_roundtrip() {
        let body = Rvbm1::no_aead();
        let wire = encode_rvbm1(&body).unwrap();
        assert_eq!(decode_rvbm1(&wire).unwrap(), body);
    }

    #[test]
    fn seal_compare_requires_expected_ct() {
        let mut body = Rvbm1::no_aead();
        body.needs_aead = 1;
        body.ec_mk_oracle_len = 32;
        body.aad = vec![0xCC; RVBA1_LEN];
        body.mode = MODE_SEAL_COMPARE;
        body.body = vec![0x01, 0x02];
        assert!(encode_rvbm1(&body).is_err());
        body.expected_ct = Some(vec![0u8; body.body.len() + 16]);
        let wire = encode_rvbm1(&body).unwrap();
        assert_eq!(decode_rvbm1(&wire).unwrap(), body);
    }

    #[test]
    fn open_mode_no_expected_ct() {
        let mut body = Rvbm1::no_aead();
        body.needs_aead = 1;
        body.ec_mk_oracle_len = 0;
        body.aad = vec![0xDD; RVBA1_LEN];
        body.mode = MODE_OPEN;
        body.body = vec![0u8; 32];
        let wire = encode_rvbm1(&body).unwrap();
        assert_eq!(decode_rvbm1(&wire).unwrap(), body);
    }

    #[test]
    fn reject_trailing() {
        let body = Rvbm1::no_aead();
        let mut wire = encode_rvbm1(&body).unwrap();
        wire.push(0);
        assert!(decode_rvbm1(&wire).is_err());
    }
}
