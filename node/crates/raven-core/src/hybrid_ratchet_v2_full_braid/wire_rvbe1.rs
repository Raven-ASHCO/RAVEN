//! RVBE1 transition environment wire codec (design §4.8 + admitted-trust extension).
//!
//! Optional `admitted_trust` (0|128 bytes) is part of the RVBE1 encoding and therefore
//! bound into `execution_digest`. Host trust admission supplies it before FFI.

use std::fmt;

use zeroize::Zeroize;

use crate::hybrid_ratchet_v2_full_braid::constants::BRAID_MAX_CANONICAL_STATE_BYTES;
use crate::hybrid_ratchet_v2_full_braid::tr_confirm::AdmittedTrustEvidence;
use crate::hybrid_ratchet_v2_full_braid::wire_util::{
    expect_magic, read_array32, read_bytes, read_u32be, read_u64be, reject_trailing, write_bytes,
    write_u16be, write_u32be, write_u64be, WireResult,
};

pub const RVBE1_MAGIC: &[u8; 8] = b"RVBE1\0\0\0";
/// Current byte-exact layout (admitted_trust). Schema 1 is superseded / rejected.
pub const RVBE1_SCHEMA: u16 = 2;
/// Pre-vector layout without admitted_trust (MUST reject).
pub const RVBE1_SCHEMA_V1_SUPERSEDED: u16 = 1;

pub const BRAID_MAX_PAYLOAD: u32 = 8192;
pub const BRAID_MAX_CHUNKS_PER_EPOCH: u32 = 64;
pub const BRAID_MAX_REPLAY_ENTRIES: u32 = 64;
pub const BRAID_MAX_REPLAY_BYTES: u32 = 8192;
pub const ADMITTED_TRUST_LEN: usize = 128;

/// Seeds/coins are secret key material: wiped on drop, redacted from Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct Rvbe1 {
    pub clock: u64,
    pub cap_payload: u32,
    pub cap_chunks: u32,
    pub cap_state: u32,
    pub cap_replay_entries: u32,
    pub cap_replay_bytes: u32,
    pub keygen_seed: Vec<u8>,
    pub encaps_coins: Vec<u8>,
    pub ec_dh_seed: Vec<u8>,
    /// Host-admitted cert/identity evidence (digest-bound via execution_digest).
    pub admitted_trust: Option<AdmittedTrustEvidence>,
}

impl fmt::Debug for Rvbe1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rvbe1")
            .field("clock", &self.clock)
            .field("cap_payload", &self.cap_payload)
            .field("cap_chunks", &self.cap_chunks)
            .field("cap_state", &self.cap_state)
            .field("cap_replay_entries", &self.cap_replay_entries)
            .field("cap_replay_bytes", &self.cap_replay_bytes)
            .field("keygen_seed_len", &self.keygen_seed.len())
            .field("encaps_coins_len", &self.encaps_coins.len())
            .field("ec_dh_seed_len", &self.ec_dh_seed.len())
            .field("admitted_trust", &self.admitted_trust)
            .finish()
    }
}

impl Drop for Rvbe1 {
    fn drop(&mut self) {
        self.keygen_seed.zeroize();
        self.encaps_coins.zeroize();
        self.ec_dh_seed.zeroize();
    }
}

impl Rvbe1 {
    pub fn default_caps(clock: u64) -> Self {
        Self {
            clock,
            cap_payload: BRAID_MAX_PAYLOAD,
            cap_chunks: BRAID_MAX_CHUNKS_PER_EPOCH,
            cap_state: BRAID_MAX_CANONICAL_STATE_BYTES as u32,
            cap_replay_entries: BRAID_MAX_REPLAY_ENTRIES,
            cap_replay_bytes: BRAID_MAX_REPLAY_BYTES,
            keygen_seed: Vec::new(),
            encaps_coins: Vec::new(),
            ec_dh_seed: Vec::new(),
            admitted_trust: None,
        }
    }

    /// Lab helper: attach default admitted trust evidence for AEAD confirms.
    pub fn with_lab_trust(mut self) -> Self {
        self.admitted_trust = Some(AdmittedTrustEvidence::lab_default());
        self
    }
}

fn encode_admitted_trust(evidence: &AdmittedTrustEvidence) -> [u8; ADMITTED_TRUST_LEN] {
    let mut out = [0u8; ADMITTED_TRUST_LEN];
    out[..32].copy_from_slice(&evidence.initiator_cert_digest);
    out[32..64].copy_from_slice(&evidence.initiator_identity_pub);
    out[64..96].copy_from_slice(&evidence.responder_cert_digest);
    out[96..128].copy_from_slice(&evidence.responder_identity_pub);
    out
}

fn decode_admitted_trust(data: &[u8]) -> WireResult<AdmittedTrustEvidence> {
    if data.len() != ADMITTED_TRUST_LEN {
        return Err("rvbe1 admitted_trust len".into());
    }
    let mut off = 0usize;
    let initiator_cert_digest = read_array32(data, &mut off)?;
    let initiator_identity_pub = read_array32(data, &mut off)?;
    let responder_cert_digest = read_array32(data, &mut off)?;
    let responder_identity_pub = read_array32(data, &mut off)?;
    Ok(AdmittedTrustEvidence {
        initiator_cert_digest,
        initiator_identity_pub,
        responder_cert_digest,
        responder_identity_pub,
    })
}

fn validate_seed_lens(env: &Rvbe1) -> WireResult<()> {
    let kg = env.keygen_seed.len();
    if kg != 0 && kg != 64 {
        return Err("rvbe1 keygen_seed len".into());
    }
    let enc = env.encaps_coins.len();
    if enc != 0 && enc != 32 {
        return Err("rvbe1 encaps_coins len".into());
    }
    let dh = env.ec_dh_seed.len();
    if dh != 0 && dh != 32 {
        return Err("rvbe1 ec_dh_seed len".into());
    }
    Ok(())
}

fn validate_caps(env: &Rvbe1) -> WireResult<()> {
    if env.cap_payload > BRAID_MAX_PAYLOAD {
        return Err("rvbe1 cap_payload".into());
    }
    if env.cap_chunks > BRAID_MAX_CHUNKS_PER_EPOCH {
        return Err("rvbe1 cap_chunks".into());
    }
    if env.cap_state > BRAID_MAX_CANONICAL_STATE_BYTES as u32 {
        return Err("rvbe1 cap_state".into());
    }
    if env.cap_replay_entries > BRAID_MAX_REPLAY_ENTRIES {
        return Err("rvbe1 cap_replay_entries".into());
    }
    if env.cap_replay_bytes > BRAID_MAX_REPLAY_BYTES {
        return Err("rvbe1 cap_replay_bytes".into());
    }
    validate_seed_lens(env)?;
    Ok(())
}

pub fn encode_rvbe1(env: &Rvbe1) -> WireResult<Vec<u8>> {
    validate_caps(env)?;
    let mut out = Vec::new();
    write_bytes(&mut out, RVBE1_MAGIC);
    write_u16be(&mut out, RVBE1_SCHEMA);
    write_u64be(&mut out, env.clock);
    write_u32be(&mut out, env.cap_payload);
    write_u32be(&mut out, env.cap_chunks);
    write_u32be(&mut out, env.cap_state);
    write_u32be(&mut out, env.cap_replay_entries);
    write_u32be(&mut out, env.cap_replay_bytes);
    write_u16be(&mut out, env.keygen_seed.len() as u16);
    write_bytes(&mut out, &env.keygen_seed);
    write_u16be(&mut out, env.encaps_coins.len() as u16);
    write_bytes(&mut out, &env.encaps_coins);
    write_u16be(&mut out, env.ec_dh_seed.len() as u16);
    write_bytes(&mut out, &env.ec_dh_seed);
    match &env.admitted_trust {
        None => write_u16be(&mut out, 0),
        Some(evidence) => {
            write_u16be(&mut out, ADMITTED_TRUST_LEN as u16);
            write_bytes(&mut out, &encode_admitted_trust(evidence));
        }
    }
    write_u32be(&mut out, 0); // reserved_tail
    Ok(out)
}

pub fn decode_rvbe1(data: &[u8]) -> WireResult<Rvbe1> {
    expect_magic(data, RVBE1_MAGIC)?;
    let mut off = 8;
    let schema = crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)?;
    if schema != RVBE1_SCHEMA {
        return Err("rvbe1 bad schema".into());
    }
    let clock = read_u64be(data, &mut off)?;
    let cap_payload = read_u32be(data, &mut off)?;
    let cap_chunks = read_u32be(data, &mut off)?;
    let cap_state = read_u32be(data, &mut off)?;
    let cap_replay_entries = read_u32be(data, &mut off)?;
    let cap_replay_bytes = read_u32be(data, &mut off)?;
    let keygen_len =
        crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)? as usize;
    let keygen_seed = read_bytes(data, &mut off, keygen_len)?.to_vec();
    let encaps_len =
        crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)? as usize;
    let encaps_coins = read_bytes(data, &mut off, encaps_len)?.to_vec();
    let dh_len =
        crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)? as usize;
    let ec_dh_seed = read_bytes(data, &mut off, dh_len)?.to_vec();
    let trust_len =
        crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)? as usize;
    let admitted_trust = match trust_len {
        0 => None,
        ADMITTED_TRUST_LEN => {
            let bytes = read_bytes(data, &mut off, ADMITTED_TRUST_LEN)?;
            Some(decode_admitted_trust(bytes)?)
        }
        _ => return Err("rvbe1 admitted_trust_len".into()),
    };
    let reserved_tail = read_u32be(data, &mut off)?;
    if reserved_tail != 0 {
        return Err("rvbe1 reserved_tail".into());
    }
    reject_trailing(data, off)?;

    let env = Rvbe1 {
        clock,
        cap_payload,
        cap_chunks,
        cap_state,
        cap_replay_entries,
        cap_replay_bytes,
        keygen_seed,
        encaps_coins,
        ec_dh_seed,
        admitted_trust,
    };
    validate_caps(&env)?;
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_ratchet_v2_full_braid::digest::execution_digest;

    #[test]
    fn roundtrip_empty_seeds() {
        let env = Rvbe1::default_caps(1_700_000_000_000);
        let wire = encode_rvbe1(&env).unwrap();
        assert_eq!(wire[8..10], RVBE1_SCHEMA.to_be_bytes());
        assert_eq!(decode_rvbe1(&wire).unwrap(), env);
    }

    #[test]
    fn roundtrip_with_admitted_trust() {
        let env = Rvbe1::default_caps(0).with_lab_trust();
        let wire = encode_rvbe1(&env).unwrap();
        let decoded = decode_rvbe1(&wire).unwrap();
        assert_eq!(decoded, env);
        assert_eq!(
            decoded
                .admitted_trust
                .as_ref()
                .unwrap()
                .initiator_cert_digest,
            [0x21; 32]
        );
    }

    #[test]
    fn admitted_trust_byte_flip_changes_execution_digest() {
        let rvbi = b"RVBI1-placeholder";
        let env = Rvbe1::default_caps(0).with_lab_trust();
        let mut wire = encode_rvbe1(&env).unwrap();
        let digest_a = execution_digest(rvbi, &wire);
        // Flip one byte inside admitted_trust body (after trust_len_u16).
        let trust_body_off = wire.len() - 4 /* reserved */ - ADMITTED_TRUST_LEN;
        wire[trust_body_off] ^= 0x01;
        let digest_b = execution_digest(rvbi, &wire);
        assert_ne!(digest_a, digest_b);
        // Still schema-2 parseable with different evidence.
        assert!(decode_rvbe1(&wire).is_ok());
    }

    #[test]
    fn reject_superseded_schema_v1() {
        // Pre-vector layout: no admitted_trust fields; ends with reserved_tail after ec_dh_seed.
        let mut wire = Vec::new();
        write_bytes(&mut wire, RVBE1_MAGIC);
        write_u16be(&mut wire, RVBE1_SCHEMA_V1_SUPERSEDED);
        write_u64be(&mut wire, 0);
        write_u32be(&mut wire, BRAID_MAX_PAYLOAD);
        write_u32be(&mut wire, BRAID_MAX_CHUNKS_PER_EPOCH);
        write_u32be(&mut wire, BRAID_MAX_CANONICAL_STATE_BYTES as u32);
        write_u32be(&mut wire, BRAID_MAX_REPLAY_ENTRIES);
        write_u32be(&mut wire, BRAID_MAX_REPLAY_BYTES);
        write_u16be(&mut wire, 0); // keygen
        write_u16be(&mut wire, 0); // encaps
        write_u16be(&mut wire, 0); // ec_dh
        write_u32be(&mut wire, 0); // reserved_tail
        assert!(decode_rvbe1(&wire).is_err());

        // Schema byte patched on a valid schema-2 frame also rejects.
        let mut v2 = encode_rvbe1(&Rvbe1::default_caps(0)).unwrap();
        v2[8..10].copy_from_slice(&RVBE1_SCHEMA_V1_SUPERSEDED.to_be_bytes());
        assert!(decode_rvbe1(&v2).is_err());
    }

    #[test]
    fn reject_truncated_before_reserved_tail() {
        let wire = encode_rvbe1(&Rvbe1::default_caps(0).with_lab_trust()).unwrap();
        assert!(decode_rvbe1(&wire[..wire.len() - 1]).is_err());
        assert!(decode_rvbe1(&wire[..wire.len() - 4]).is_err());
        // Cut inside admitted_trust body.
        assert!(decode_rvbe1(&wire[..wire.len() - 4 - 16]).is_err());
    }

    #[test]
    fn reject_wrong_admitted_trust_len() {
        let env = Rvbe1::default_caps(0).with_lab_trust();
        let mut wire = encode_rvbe1(&env).unwrap();
        // admitted_trust_len sits immediately before the 128-byte body and reserved_tail.
        let len_off = wire.len() - 4 - ADMITTED_TRUST_LEN - 2;
        wire[len_off..len_off + 2].copy_from_slice(&64u16.to_be_bytes());
        assert!(decode_rvbe1(&wire).is_err());

        // Len=128 but body truncated (drop reserved + some trust bytes).
        let mut short = encode_rvbe1(&env).unwrap();
        short.truncate(short.len() - 4 - 8);
        assert!(decode_rvbe1(&short).is_err());
    }

    #[test]
    fn reject_trailing() {
        let env = Rvbe1::default_caps(0);
        let mut wire = encode_rvbe1(&env).unwrap();
        wire.push(0);
        assert!(decode_rvbe1(&wire).is_err());
    }

    #[test]
    fn reject_tightened_caps_above_constants() {
        let mut env = Rvbe1::default_caps(0);
        env.cap_payload = BRAID_MAX_PAYLOAD + 1;
        assert!(encode_rvbe1(&env).is_err());
    }
}
