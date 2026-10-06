//! RVCH1 chain header wire codec (design §4.3).

use crate::hybrid_ratchet_v2_full_braid::wire_util::{
    expect_magic, read_array32, read_u32be, read_u64be, read_u8, reject_trailing, write_array32,
    write_bytes, write_u16be, write_u32be, write_u64be, write_u8, WireResult,
};

pub const RVCH1_MAGIC: &[u8; 8] = b"RVCH1\0\0\0";
pub const RVCH1_LEN: usize = 68;
pub const RVCH1_SCHEMA: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rvch1 {
    pub ec_dh_pub: [u8; 32],
    pub ec_pn: u32,
    pub ec_n: u32,
    pub scka_epoch: u64,
    pub scka_pn: u32,
    pub scka_n: u32,
    pub direction: u8,
}

pub fn encode_rvch1(hdr: &Rvch1) -> Vec<u8> {
    let mut out = Vec::with_capacity(RVCH1_LEN);
    write_bytes(&mut out, RVCH1_MAGIC);
    write_u16be(&mut out, RVCH1_SCHEMA);
    write_array32(&mut out, &hdr.ec_dh_pub);
    write_u32be(&mut out, hdr.ec_pn);
    write_u32be(&mut out, hdr.ec_n);
    write_u64be(&mut out, hdr.scka_epoch);
    write_u32be(&mut out, hdr.scka_pn);
    write_u32be(&mut out, hdr.scka_n);
    write_u8(&mut out, hdr.direction);
    write_u8(&mut out, 0); // reserved0
    debug_assert_eq!(out.len(), RVCH1_LEN);
    out
}

pub fn decode_rvch1(data: &[u8]) -> WireResult<Rvch1> {
    if data.len() != RVCH1_LEN {
        return Err("rvch1 bad length".into());
    }
    expect_magic(data, RVCH1_MAGIC)?;
    let mut off = 8;
    let schema = crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)?;
    if schema != RVCH1_SCHEMA {
        return Err("rvch1 bad schema".into());
    }
    let ec_dh_pub = read_array32(data, &mut off)?;
    let ec_pn = read_u32be(data, &mut off)?;
    let ec_n = read_u32be(data, &mut off)?;
    let scka_epoch = read_u64be(data, &mut off)?;
    let scka_pn = read_u32be(data, &mut off)?;
    let scka_n = read_u32be(data, &mut off)?;
    let direction = read_u8(data, &mut off)?;
    let reserved0 = read_u8(data, &mut off)?;
    if reserved0 != 0 {
        return Err("rvch1 reserved0".into());
    }
    reject_trailing(data, off)?;
    Ok(Rvch1 {
        ec_dh_pub,
        ec_pn,
        ec_n,
        scka_epoch,
        scka_pn,
        scka_n,
        direction,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_fixed_68() {
        let hdr = Rvch1 {
            ec_dh_pub: [0x11; 32],
            ec_pn: 1,
            ec_n: 2,
            scka_epoch: 3,
            scka_pn: 4,
            scka_n: 5,
            direction: 0,
        };
        let wire = encode_rvch1(&hdr);
        assert_eq!(wire.len(), RVCH1_LEN);
        assert_eq!(decode_rvch1(&wire).unwrap(), hdr);
    }

    #[test]
    fn reject_trailing_and_truncated_bytes() {
        let hdr = Rvch1 {
            ec_dh_pub: [0x11; 32],
            ec_pn: 1,
            ec_n: 2,
            scka_epoch: 3,
            scka_pn: 4,
            scka_n: 5,
            direction: 1,
        };
        let wire = encode_rvch1(&hdr);
        let mut longer = wire.clone();
        longer.push(0);
        assert!(decode_rvch1(&longer).is_err());
        assert!(decode_rvch1(&wire[..RVCH1_LEN - 1]).is_err());
        assert!(decode_rvch1(&[]).is_err());
    }
}
