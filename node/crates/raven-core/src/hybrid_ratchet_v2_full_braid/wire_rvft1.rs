//! RVFT1 nested Triple Ratchet state wire codec (design §6.2).

use std::fmt;

use zeroize::Zeroize;

use crate::hybrid_ratchet_v2_full_braid::state_codec::DIR_B2A;
use crate::hybrid_ratchet_v2_full_braid::wire_util::{
    expect_magic, read_array32, read_u16be, read_u32be, read_u64be, read_u8, reject_trailing,
    write_array32, write_bytes, write_u16be, write_u32be, write_u64be, write_u8, WireResult,
};

pub const RVFT1_MAGIC: &[u8; 8] = b"RVFT1\0\0\0";
pub const RVFT1_SCHEMA: u16 = 1;
pub const RVFT1_MAX_SIZE: usize = 80_505;
pub const MAX_SCKA_CHAIN: usize = 8;
pub const MAX_SCKA_SKIPPED: usize = 256;
pub const MAX_EC_SKIPPED: usize = 1000;

// Every chain/message/root/private key below is wiped on drop and redacted
// from Debug; only public keys, epochs and counters are printed.

#[derive(Clone, PartialEq, Eq)]
pub struct SckaChainEntry {
    pub epoch: u64,
    pub ck: [u8; 32],
    pub n: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SckaSkippedEntry {
    pub direction: u8,
    pub epoch: u64,
    pub n: u32,
    pub mk: [u8; 32],
}

#[derive(Clone, PartialEq, Eq)]
pub struct EcSkippedEntry {
    pub dh_pub: [u8; 32],
    pub n: u32,
    pub mk: [u8; 32],
}

impl fmt::Debug for SckaChainEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SckaChainEntry")
            .field("epoch", &self.epoch)
            .field("n", &self.n)
            .field("ck", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for SckaSkippedEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SckaSkippedEntry")
            .field("direction", &self.direction)
            .field("epoch", &self.epoch)
            .field("n", &self.n)
            .field("mk", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for EcSkippedEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcSkippedEntry")
            .field("dh_pub", &self.dh_pub)
            .field("n", &self.n)
            .field("mk", &"<redacted>")
            .finish()
    }
}

impl Drop for SckaChainEntry {
    fn drop(&mut self) {
        self.ck.zeroize();
    }
}

impl Drop for SckaSkippedEntry {
    fn drop(&mut self) {
        self.mk.zeroize();
    }
}

impl Drop for EcSkippedEntry {
    fn drop(&mut self) {
        self.mk.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Rvft1 {
    pub scka_rk: [u8; 32],
    pub scka_sending_epoch: u64,
    pub scka_receiving_epoch: u64,
    pub scka_send_chain: Vec<SckaChainEntry>,
    pub scka_recv_chain: Vec<SckaChainEntry>,
    pub scka_send_pn: u32,
    pub scka_skipped: Vec<SckaSkippedEntry>,
    pub ec_rk: [u8; 32],
    pub ec_dhs_priv: [u8; 32],
    pub ec_dhs_pub: [u8; 32],
    pub ec_dhr_present: u8,
    pub ec_dhr_pub: [u8; 32],
    pub ec_ck_send_present: u8,
    pub ec_ck_recv_present: u8,
    pub ec_ck_send: [u8; 32],
    pub ec_ck_recv: [u8; 32],
    pub ec_ns: u32,
    pub ec_nr: u32,
    pub ec_pn: u32,
    pub ec_skipped: Vec<EcSkippedEntry>,
}

impl fmt::Debug for Rvft1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rvft1")
            .field("scka_sending_epoch", &self.scka_sending_epoch)
            .field("scka_receiving_epoch", &self.scka_receiving_epoch)
            .field("scka_send_chain", &self.scka_send_chain)
            .field("scka_recv_chain", &self.scka_recv_chain)
            .field("scka_send_pn", &self.scka_send_pn)
            .field("scka_skipped", &self.scka_skipped)
            .field("ec_dhs_pub", &self.ec_dhs_pub)
            .field("ec_dhr_present", &self.ec_dhr_present)
            .field("ec_dhr_pub", &self.ec_dhr_pub)
            .field("ec_ck_send_present", &self.ec_ck_send_present)
            .field("ec_ck_recv_present", &self.ec_ck_recv_present)
            .field("ec_ns", &self.ec_ns)
            .field("ec_nr", &self.ec_nr)
            .field("ec_pn", &self.ec_pn)
            .field("ec_skipped", &self.ec_skipped)
            .field("secrets", &"<redacted>")
            .finish()
    }
}

impl Drop for Rvft1 {
    fn drop(&mut self) {
        self.scka_rk.zeroize();
        self.ec_rk.zeroize();
        self.ec_dhs_priv.zeroize();
        self.ec_ck_send.zeroize();
        self.ec_ck_recv.zeroize();
        // Entries wipe themselves on drop.
        self.scka_send_chain.clear();
        self.scka_recv_chain.clear();
        self.scka_skipped.clear();
        self.ec_skipped.clear();
    }
}

fn validate_scka_chain_ascending(chain: &[SckaChainEntry]) -> WireResult<()> {
    for w in chain.windows(2) {
        if w[0].epoch >= w[1].epoch {
            return Err("rvft1 scka chain unsorted".into());
        }
    }
    Ok(())
}

fn validate_scka_skipped_sorted(skipped: &[SckaSkippedEntry]) -> WireResult<()> {
    for w in skipped.windows(2) {
        let a = (w[0].direction, w[0].epoch, w[0].n);
        let b = (w[1].direction, w[1].epoch, w[1].n);
        if a >= b {
            return Err("rvft1 scka skipped unsorted".into());
        }
    }
    // Python `_validate_rvft1`: direction is DIR_A2B or DIR_B2A only. An entry
    // with any other direction can never match a lookup yet would occupy the
    // 256-entry cap.
    if skipped.iter().any(|entry| entry.direction > DIR_B2A) {
        return Err("rvft1 scka skipped direction".into());
    }
    Ok(())
}

fn validate_ec_skipped_sorted(skipped: &[EcSkippedEntry]) -> WireResult<()> {
    for w in skipped.windows(2) {
        let a = (&w[0].dh_pub, w[0].n);
        let b = (&w[1].dh_pub, w[1].n);
        if a >= b {
            return Err("rvft1 ec skipped unsorted".into());
        }
    }
    Ok(())
}

fn validate_optional_key(present: u8, key: &[u8; 32], field: &str) -> WireResult<()> {
    match present {
        0 => {
            if key != &[0u8; 32] {
                return Err(format!("rvft1 {field} must be zero when absent"));
            }
        }
        1 => {}
        _ => return Err(format!("rvft1 {field}_present")),
    }
    Ok(())
}

fn encode_optional_key(out: &mut Vec<u8>, present: u8, key: &[u8; 32]) {
    if present == 1 {
        write_array32(out, key);
    } else {
        write_array32(out, &[0u8; 32]);
    }
}

pub fn encode_rvft1(tr: &Rvft1) -> WireResult<Vec<u8>> {
    if tr.scka_send_chain.len() > MAX_SCKA_CHAIN || tr.scka_recv_chain.len() > MAX_SCKA_CHAIN {
        return Err("rvft1 scka chain cap".into());
    }
    if tr.scka_skipped.len() > MAX_SCKA_SKIPPED {
        return Err("rvft1 scka skipped cap".into());
    }
    if tr.ec_skipped.len() > MAX_EC_SKIPPED {
        return Err("rvft1 ec skipped cap".into());
    }
    validate_scka_chain_ascending(&tr.scka_send_chain)?;
    validate_scka_chain_ascending(&tr.scka_recv_chain)?;
    validate_scka_skipped_sorted(&tr.scka_skipped)?;
    validate_ec_skipped_sorted(&tr.ec_skipped)?;
    validate_optional_key(tr.ec_dhr_present, &tr.ec_dhr_pub, "ec_dhr_pub")?;
    validate_optional_key(tr.ec_ck_send_present, &tr.ec_ck_send, "ec_ck_send")?;
    validate_optional_key(tr.ec_ck_recv_present, &tr.ec_ck_recv, "ec_ck_recv")?;

    let mut out = Vec::new();
    write_bytes(&mut out, RVFT1_MAGIC);
    write_u16be(&mut out, RVFT1_SCHEMA);
    write_array32(&mut out, &tr.scka_rk);
    write_u64be(&mut out, tr.scka_sending_epoch);
    write_u64be(&mut out, tr.scka_receiving_epoch);

    write_u16be(&mut out, tr.scka_send_chain.len() as u16);
    for entry in &tr.scka_send_chain {
        write_u64be(&mut out, entry.epoch);
        write_array32(&mut out, &entry.ck);
        write_u32be(&mut out, entry.n);
    }

    write_u16be(&mut out, tr.scka_recv_chain.len() as u16);
    for entry in &tr.scka_recv_chain {
        write_u64be(&mut out, entry.epoch);
        write_array32(&mut out, &entry.ck);
        write_u32be(&mut out, entry.n);
    }

    write_u32be(&mut out, tr.scka_send_pn);

    write_u16be(&mut out, tr.scka_skipped.len() as u16);
    for entry in &tr.scka_skipped {
        write_u8(&mut out, entry.direction);
        write_u64be(&mut out, entry.epoch);
        write_u32be(&mut out, entry.n);
        write_array32(&mut out, &entry.mk);
    }

    write_array32(&mut out, &tr.ec_rk);
    write_array32(&mut out, &tr.ec_dhs_priv);
    write_array32(&mut out, &tr.ec_dhs_pub);
    write_u8(&mut out, tr.ec_dhr_present);
    encode_optional_key(&mut out, tr.ec_dhr_present, &tr.ec_dhr_pub);
    write_u8(&mut out, tr.ec_ck_send_present);
    write_u8(&mut out, tr.ec_ck_recv_present);
    encode_optional_key(&mut out, tr.ec_ck_send_present, &tr.ec_ck_send);
    encode_optional_key(&mut out, tr.ec_ck_recv_present, &tr.ec_ck_recv);
    write_u32be(&mut out, tr.ec_ns);
    write_u32be(&mut out, tr.ec_nr);
    write_u32be(&mut out, tr.ec_pn);

    write_u16be(&mut out, tr.ec_skipped.len() as u16);
    for entry in &tr.ec_skipped {
        write_array32(&mut out, &entry.dh_pub);
        write_u32be(&mut out, entry.n);
        write_array32(&mut out, &entry.mk);
    }

    write_u32be(&mut out, 0); // reserved_tail

    if out.len() > RVFT1_MAX_SIZE {
        return Err("rvft1 exceeds max size".into());
    }
    Ok(out)
}

pub fn decode_rvft1(data: &[u8]) -> WireResult<Rvft1> {
    if data.len() > RVFT1_MAX_SIZE {
        return Err("rvft1 exceeds max size".into());
    }
    expect_magic(data, RVFT1_MAGIC)?;
    let mut off = 8;
    let schema = read_u16be(data, &mut off)?;
    if schema != RVFT1_SCHEMA {
        return Err("rvft1 bad schema".into());
    }
    let scka_rk = read_array32(data, &mut off)?;
    let scka_sending_epoch = read_u64be(data, &mut off)?;
    let scka_receiving_epoch = read_u64be(data, &mut off)?;

    let num_scka_send = read_u16be(data, &mut off)? as usize;
    if num_scka_send > MAX_SCKA_CHAIN {
        return Err("rvft1 scka send cap".into());
    }
    let mut scka_send_chain = Vec::with_capacity(num_scka_send);
    for _ in 0..num_scka_send {
        scka_send_chain.push(SckaChainEntry {
            epoch: read_u64be(data, &mut off)?,
            ck: read_array32(data, &mut off)?,
            n: read_u32be(data, &mut off)?,
        });
    }

    let num_scka_recv = read_u16be(data, &mut off)? as usize;
    if num_scka_recv > MAX_SCKA_CHAIN {
        return Err("rvft1 scka recv cap".into());
    }
    let mut scka_recv_chain = Vec::with_capacity(num_scka_recv);
    for _ in 0..num_scka_recv {
        scka_recv_chain.push(SckaChainEntry {
            epoch: read_u64be(data, &mut off)?,
            ck: read_array32(data, &mut off)?,
            n: read_u32be(data, &mut off)?,
        });
    }

    let scka_send_pn = read_u32be(data, &mut off)?;

    let num_scka_skipped = read_u16be(data, &mut off)? as usize;
    if num_scka_skipped > MAX_SCKA_SKIPPED {
        return Err("rvft1 scka skipped cap".into());
    }
    let mut scka_skipped = Vec::with_capacity(num_scka_skipped);
    for _ in 0..num_scka_skipped {
        scka_skipped.push(SckaSkippedEntry {
            direction: read_u8(data, &mut off)?,
            epoch: read_u64be(data, &mut off)?,
            n: read_u32be(data, &mut off)?,
            mk: read_array32(data, &mut off)?,
        });
    }

    let ec_rk = read_array32(data, &mut off)?;
    let ec_dhs_priv = read_array32(data, &mut off)?;
    let ec_dhs_pub = read_array32(data, &mut off)?;
    let ec_dhr_present = read_u8(data, &mut off)?;
    let ec_dhr_pub = read_array32(data, &mut off)?;
    let ec_ck_send_present = read_u8(data, &mut off)?;
    let ec_ck_recv_present = read_u8(data, &mut off)?;
    let ec_ck_send = read_array32(data, &mut off)?;
    let ec_ck_recv = read_array32(data, &mut off)?;
    let ec_ns = read_u32be(data, &mut off)?;
    let ec_nr = read_u32be(data, &mut off)?;
    let ec_pn = read_u32be(data, &mut off)?;

    let num_ec_skipped = read_u16be(data, &mut off)? as usize;
    if num_ec_skipped > MAX_EC_SKIPPED {
        return Err("rvft1 ec skipped cap".into());
    }
    let mut ec_skipped = Vec::with_capacity(num_ec_skipped);
    for _ in 0..num_ec_skipped {
        ec_skipped.push(EcSkippedEntry {
            dh_pub: read_array32(data, &mut off)?,
            n: read_u32be(data, &mut off)?,
            mk: read_array32(data, &mut off)?,
        });
    }

    let reserved_tail = read_u32be(data, &mut off)?;
    if reserved_tail != 0 {
        return Err("rvft1 reserved_tail".into());
    }
    reject_trailing(data, off)?;

    let tr = Rvft1 {
        scka_rk,
        scka_sending_epoch,
        scka_receiving_epoch,
        scka_send_chain,
        scka_recv_chain,
        scka_send_pn,
        scka_skipped,
        ec_rk,
        ec_dhs_priv,
        ec_dhs_pub,
        ec_dhr_present,
        ec_dhr_pub,
        ec_ck_send_present,
        ec_ck_recv_present,
        ec_ck_send,
        ec_ck_recv,
        ec_ns,
        ec_nr,
        ec_pn,
        ec_skipped,
    };

    validate_scka_chain_ascending(&tr.scka_send_chain)?;
    validate_scka_chain_ascending(&tr.scka_recv_chain)?;
    validate_scka_skipped_sorted(&tr.scka_skipped)?;
    validate_ec_skipped_sorted(&tr.ec_skipped)?;
    validate_optional_key(tr.ec_dhr_present, &tr.ec_dhr_pub, "ec_dhr_pub")?;
    validate_optional_key(tr.ec_ck_send_present, &tr.ec_ck_send, "ec_ck_send")?;
    validate_optional_key(tr.ec_ck_recv_present, &tr.ec_ck_recv, "ec_ck_recv")?;

    Ok(tr)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn roundtrip_minimal() {
        let tr = minimal_tr();
        let wire = encode_rvft1(&tr).unwrap();
        assert_eq!(decode_rvft1(&wire).unwrap(), tr);
    }

    #[test]
    fn roundtrip_with_skipped_maps() {
        let tr = Rvft1 {
            scka_send_chain: vec![
                SckaChainEntry {
                    epoch: 1,
                    ck: [0x01; 32],
                    n: 0,
                },
                SckaChainEntry {
                    epoch: 2,
                    ck: [0x02; 32],
                    n: 1,
                },
            ],
            scka_recv_chain: vec![SckaChainEntry {
                epoch: 1,
                ck: [0x03; 32],
                n: 0,
            }],
            scka_skipped: vec![
                SckaSkippedEntry {
                    direction: 0,
                    epoch: 1,
                    n: 0,
                    mk: [0x10; 32],
                },
                SckaSkippedEntry {
                    direction: 0,
                    epoch: 1,
                    n: 1,
                    mk: [0x11; 32],
                },
            ],
            ec_dhr_present: 1,
            ec_dhr_pub: [0xDD; 32],
            ec_ck_send_present: 1,
            ec_ck_send: [0xEE; 32],
            ec_skipped: vec![
                EcSkippedEntry {
                    dh_pub: [0x20; 32],
                    n: 0,
                    mk: [0x21; 32],
                },
                EcSkippedEntry {
                    dh_pub: [0x30; 32],
                    n: 0,
                    mk: [0x31; 32],
                },
            ],
            ..minimal_tr()
        };
        let wire = encode_rvft1(&tr).unwrap();
        assert_eq!(decode_rvft1(&wire).unwrap(), tr);
    }

    #[test]
    fn reject_unsorted_scka_skipped() {
        let mut tr = minimal_tr();
        tr.scka_skipped = vec![
            SckaSkippedEntry {
                direction: 0,
                epoch: 2,
                n: 0,
                mk: [0; 32],
            },
            SckaSkippedEntry {
                direction: 0,
                epoch: 1,
                n: 0,
                mk: [0; 32],
            },
        ];
        assert!(encode_rvft1(&tr).is_err());
    }

    #[test]
    fn reject_scka_skipped_direction_above_b2a() {
        let entry = |direction: u8| SckaSkippedEntry {
            direction,
            epoch: 1,
            n: 0,
            mk: [0xA5; 32],
        };
        // Both directions the reference allows still round-trip.
        for direction in [0u8, 1] {
            let mut tr = minimal_tr();
            tr.scka_skipped = vec![entry(direction)];
            let wire = encode_rvft1(&tr).unwrap();
            assert_eq!(decode_rvft1(&wire).unwrap(), tr);
        }
        // Encode refuses direction 2..=255.
        for direction in [2u8, 7, 255] {
            let mut tr = minimal_tr();
            tr.scka_skipped = vec![entry(direction)];
            assert!(encode_rvft1(&tr).is_err(), "{direction}");
        }
        // Decode refuses a wire whose single entry carries direction 7 (the
        // byte sits 13 bytes before the unique message key: dir|epoch|n|mk).
        let mut tr = minimal_tr();
        tr.scka_skipped = vec![entry(0)];
        let mut wire = encode_rvft1(&tr).unwrap();
        let mk_at = wire
            .windows(32)
            .position(|window| window == [0xA5; 32])
            .unwrap();
        assert_eq!(wire[mk_at - 13], 0);
        wire[mk_at - 13] = 7;
        assert!(decode_rvft1(&wire).is_err());
    }

    #[test]
    fn reject_unsorted_ec_skipped() {
        let mut tr = minimal_tr();
        tr.ec_skipped = vec![
            EcSkippedEntry {
                dh_pub: [0x02; 32],
                n: 0,
                mk: [0; 32],
            },
            EcSkippedEntry {
                dh_pub: [0x01; 32],
                n: 0,
                mk: [0; 32],
            },
        ];
        assert!(encode_rvft1(&tr).is_err());
    }

    #[test]
    fn reject_present_key_nonzero_when_absent() {
        let mut tr = minimal_tr();
        tr.ec_dhr_present = 0;
        tr.ec_dhr_pub = [0x01; 32];
        assert!(encode_rvft1(&tr).is_err());
    }

    #[test]
    fn reject_trailing_bytes() {
        let mut wire = encode_rvft1(&minimal_tr()).unwrap();
        wire.push(0);
        assert!(decode_rvft1(&wire).is_err());
    }
}
