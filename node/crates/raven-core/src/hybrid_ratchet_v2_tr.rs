//! EC Double Ratchet DH transitions + Raven Braid chunk KATs (production-disabled).

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::atsam_root::x25519_shared_checked;
use crate::hybrid_ratchet_v2::{kdf_ck, kdf_hybrid, kdf_rk, MAX_SKIP};
use crate::hybrid_ratchet_v2_state::{
    scka_epoch_promote_initiator, scka_epoch_promote_responder, scka_from_init, scka_next_recv_mk,
    scka_next_send_mk,
};

pub const PRODUCTION_ENABLED: bool = false;

pub const BRAID_CHUNK_DOMAIN: &[u8] = b"ATSAM/v2/braid-chunk";
pub const BRAID_MAGIC: &[u8; 8] = b"RVBC1\0\0\0";
/// magic(8) | epoch_u64be(8) | type(1) | index_u32be(4) | plen_u16be(2)
pub const BRAID_HEADER_LEN: usize = 8 + 8 + 1 + 4 + 2; // 23
pub const BRAID_DIGEST_LEN: usize = 32;
/// Per-chunk semantic max aligned with default reassembly total budget.
pub const BRAID_MAX_TOTAL_PAYLOAD_BYTES: usize = 8192;
pub const BRAID_MAX_PAYLOAD: usize = BRAID_MAX_TOTAL_PAYLOAD_BYTES;
pub const BRAID_MAX_CHUNKS_PER_EPOCH: u32 = 64;
/// Binding digest is NOT authentication — outer signature + AEAD provide auth.
pub const MAX_MKSKIPPED_RETAINED: usize = 2000;
pub const BRAID_MLKEM768_HEADER_SIZE: usize = 64;
/// Signal ek_vector size (not the full FIPS encapsulation key).
pub const BRAID_MLKEM768_EK_VECTOR_SIZE: usize = 1152;
/// Complete FIPS 203 ML-KEM-768 encapsulation key = ek_vector(1152) || rho(32).
pub const BRAID_MLKEM768_EK_FIPS_SIZE: usize = 1184;
pub const BRAID_MLKEM768_CT1_SIZE: usize = 960;
pub const BRAID_MLKEM768_CT2_SIZE: usize = 128;
pub const CHUNK_NONE: u8 = 0;
pub const CHUNK_HDR: u8 = 1;
pub const CHUNK_EK: u8 = 2;
pub const CHUNK_EK_CT1_ACK: u8 = 3;
pub const CHUNK_CT1_ACK: u8 = 4;
pub const CHUNK_CT1: u8 = 5;
pub const CHUNK_CT2: u8 = 6;

fn braid_type_allowed(t: u8) -> bool {
    t <= 6
}

fn braid_empty_payload_type(t: u8) -> bool {
    t == CHUNK_NONE || t == CHUNK_CT1_ACK
}

fn braid_data_payload_type(t: u8) -> bool {
    braid_type_allowed(t) && !braid_empty_payload_type(t)
}

fn validate_braid_payload_rules(typ: u8, payload: &[u8], chunk_index: u32) -> Result<(), String> {
    if !braid_type_allowed(typ) {
        return Err("unknown braid chunk type".into());
    }
    if braid_empty_payload_type(typ) {
        if !payload.is_empty() {
            return Err("braid empty-type payload must be empty".into());
        }
        if chunk_index != 0 {
            return Err("braid empty-type chunk_index must be 0".into());
        }
    } else if braid_data_payload_type(typ) && payload.is_empty() {
        return Err("braid data-type payload must be non-empty".into());
    }
    Ok(())
}

pub fn x25519_public(priv_bytes: &[u8; 32]) -> Result<[u8; 32], String> {
    if *priv_bytes == [0u8; 32] {
        return Err("all-zero X25519 rejected".into());
    }
    let sk = StaticSecret::from(*priv_bytes);
    Ok(PublicKey::from(&sk).to_bytes())
}

pub fn x25519_dh(priv_bytes: &[u8; 32], pub_bytes: &[u8; 32]) -> Result<[u8; 32], String> {
    if *priv_bytes == [0u8; 32] || *pub_bytes == [0u8; 32] {
        return Err("all-zero X25519 rejected".into());
    }
    x25519_shared_checked(priv_bytes, pub_bytes).map_err(|_| "non-contributory DH rejected".into())
}

fn mk_key(dh_pub: &[u8; 32], n: u32) -> [u8; 36] {
    let mut k = [0u8; 36];
    k[..32].copy_from_slice(dh_pub);
    k[32..].copy_from_slice(&n.to_be_bytes());
    k
}

#[derive(Clone, PartialEq, Eq)]
pub struct EcDrState {
    pub rk: [u8; 32],
    pub dhs_priv: [u8; 32],
    pub dhs_pub: [u8; 32],
    pub dhr_pub: Option<[u8; 32]>,
    pub cks: Option<[u8; 32]>,
    pub ckr: Option<[u8; 32]>,
    pub ns: u32,
    pub nr: u32,
    pub pn: u32,
    pub mkskipped: BTreeMap<[u8; 36], [u8; 32]>,
}

impl std::fmt::Debug for EcDrState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcDrState")
            .field("dhs_pub", &self.dhs_pub)
            .field("dhr_pub", &self.dhr_pub)
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .field("mkskipped_len", &self.mkskipped.len())
            .field("secrets", &"<redacted>")
            .finish()
    }
}

impl EcDrState {
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.rk);
        h.update(self.dhs_pub);
        h.update(self.dhr_pub.unwrap_or([0u8; 32]));
        h.update(self.cks.unwrap_or([0u8; 32]));
        h.update(self.ckr.unwrap_or([0u8; 32]));
        h.update(self.ns.to_be_bytes());
        h.update(self.nr.to_be_bytes());
        h.update(self.pn.to_be_bytes());
        for (k, v) in &self.mkskipped {
            h.update(k);
            h.update(v);
        }
        h.finalize().into()
    }

    /// Wipe root/chain/private/skipped secrets (public DH values left intact).
    pub fn zeroize_secrets(&mut self) {
        use zeroize::Zeroize;
        self.rk.zeroize();
        self.dhs_priv.zeroize();
        if let Some(ck) = self.cks.as_mut() {
            ck.zeroize();
        }
        if let Some(ck) = self.ckr.as_mut() {
            ck.zeroize();
        }
        for mk in self.mkskipped.values_mut() {
            mk.zeroize();
        }
        self.mkskipped.clear();
    }
}

impl Drop for EcDrState {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcDrHeader {
    pub dh_pub: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

pub fn ec_dr_init_alice(
    rk0: &[u8; 32],
    alice_priv: &[u8; 32],
    bob_pub: &[u8; 32],
) -> Result<EcDrState, String> {
    let ss = x25519_dh(alice_priv, bob_pub)?;
    let (rk1, cks) = kdf_rk(rk0, &ss)?;
    Ok(EcDrState {
        rk: rk1,
        dhs_priv: *alice_priv,
        dhs_pub: x25519_public(alice_priv)?,
        dhr_pub: Some(*bob_pub),
        cks: Some(cks),
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        mkskipped: BTreeMap::new(),
    })
}

pub fn ec_dr_init_bob(rk0: &[u8; 32], bob_priv: &[u8; 32]) -> Result<EcDrState, String> {
    Ok(EcDrState {
        rk: *rk0,
        dhs_priv: *bob_priv,
        dhs_pub: x25519_public(bob_priv)?,
        dhr_pub: None,
        cks: None,
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        mkskipped: BTreeMap::new(),
    })
}

pub fn ec_dr_encrypt(state: &EcDrState) -> Result<(EcDrState, EcDrHeader, [u8; 32]), String> {
    let cks = state.cks.ok_or("no sending chain")?;
    let (ck2, mk) = kdf_ck(&cks);
    let header = EcDrHeader {
        dh_pub: state.dhs_pub,
        pn: state.pn,
        n: state.ns,
    };
    let ns = state
        .ns
        .checked_add(1)
        .ok_or_else(|| "ec_ns overflow".to_string())?;
    let out = EcDrState {
        rk: state.rk,
        dhs_priv: state.dhs_priv,
        dhs_pub: state.dhs_pub,
        dhr_pub: state.dhr_pub,
        cks: Some(ck2),
        ckr: state.ckr,
        ns,
        nr: state.nr,
        pn: state.pn,
        mkskipped: state.mkskipped.clone(),
    };
    Ok((out, header, mk))
}

fn dh_ratchet(
    state: &EcDrState,
    their_dh: &[u8; 32],
    new_local_priv: &[u8; 32],
) -> Result<EcDrState, String> {
    let ss1 = x25519_dh(&state.dhs_priv, their_dh)?;
    let (rk1, ckr) = kdf_rk(&state.rk, &ss1)?;
    let local_pub = x25519_public(new_local_priv)?;
    let ss2 = x25519_dh(new_local_priv, their_dh)?;
    let (rk2, cks) = kdf_rk(&rk1, &ss2)?;
    Ok(EcDrState {
        rk: rk2,
        dhs_priv: *new_local_priv,
        dhs_pub: local_pub,
        dhr_pub: Some(*their_dh),
        cks: Some(cks),
        ckr: Some(ckr),
        ns: 0,
        nr: 0,
        pn: state.ns,
        mkskipped: state.mkskipped.clone(),
    })
}

fn insert_skipped(
    skipped: &mut BTreeMap<[u8; 36], [u8; 32]>,
    key: [u8; 36],
    mk_i: [u8; 32],
    max_mkskipped: usize,
) -> Result<(), String> {
    if skipped.contains_key(&key) {
        return Ok(());
    }
    if skipped.len() >= max_mkskipped {
        return Err("MAX_MKSKIPPED_RETAINED exceeded".into());
    }
    skipped.insert(key, mk_i);
    Ok(())
}

pub fn ec_dr_decrypt(
    state: &EcDrState,
    header: &EcDrHeader,
    max_skip: u32,
    new_local_priv: Option<&[u8; 32]>,
    max_mkskipped: usize,
) -> Result<(EcDrState, [u8; 32]), String> {
    let dh = header.dh_pub;
    let n = header.n;
    let pn = header.pn;

    let key = mk_key(&dh, n);
    if let Some(mk) = state.mkskipped.get(&key) {
        let mut out = state.clone();
        // The consumed skipped key is removed from the cloned state; wipe the
        // removed copy instead of letting the map hand it back to the allocator.
        if let Some(mut removed) = out.mkskipped.remove(&key) {
            zeroize::Zeroize::zeroize(&mut removed);
        }
        return Ok((out, *mk));
    }

    let mut st = state.clone();
    if st.dhr_pub.is_none() || st.dhr_pub != Some(dh) {
        if st.dhr_pub.is_some() && st.ckr.is_some() {
            let skip_until = pn;
            if skip_until < st.nr {
                return Err("pn behind nr".into());
            }
            if skip_until.saturating_sub(st.nr) > max_skip {
                return Err("MAX_SKIP exceeded".into());
            }
            let mut ck = st.ckr.ok_or("no receiving chain")?;
            let mut nr = st.nr;
            let mut skipped = st.mkskipped.clone();
            let dhr = st.dhr_pub.ok_or("missing dhr")?;
            while nr < skip_until {
                let (ck_i, mk_i) = kdf_ck(&ck);
                insert_skipped(&mut skipped, mk_key(&dhr, nr), mk_i, max_mkskipped)?;
                ck = ck_i;
                nr = nr
                    .checked_add(1)
                    .ok_or_else(|| "ec_nr overflow".to_string())?;
            }
            st.ckr = Some(ck);
            st.nr = nr;
            st.mkskipped = skipped;
        }
        let new_priv = new_local_priv.ok_or("DH ratchet requires new_local_priv")?;
        st = dh_ratchet(&st, &dh, new_priv)?;
    }

    let ckr = st.ckr.ok_or("no receiving chain")?;
    if n < st.nr {
        return Err("replay of consumed index".into());
    }
    if n > st.nr {
        if n - st.nr > max_skip {
            return Err("MAX_SKIP exceeded".into());
        }
        let mut ck = ckr;
        let mut nr = st.nr;
        let mut skipped = st.mkskipped.clone();
        let dhr = st.dhr_pub.ok_or("missing dhr")?;
        while nr < n {
            let (ck_i, mk_i) = kdf_ck(&ck);
            insert_skipped(&mut skipped, mk_key(&dhr, nr), mk_i, max_mkskipped)?;
            ck = ck_i;
            nr = nr
                .checked_add(1)
                .ok_or_else(|| "ec_nr overflow".to_string())?;
        }
        st.ckr = Some(ck);
        st.nr = nr;
        st.mkskipped = skipped;
    }

    let (ck2, mk) = kdf_ck(&st.ckr.unwrap());
    let nr = st
        .nr
        .checked_add(1)
        .ok_or_else(|| "ec_nr overflow".to_string())?;
    st.ckr = Some(ck2);
    st.nr = nr;
    Ok((st, mk))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcDhRatchetNegatives {
    pub all_zero_pub: String,
    pub all_zero_priv: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcDhRatchetHeaderOut {
    pub dh_pub_hex: String,
    pub pn: u32,
    pub n: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcDhRatchetMatrixOut {
    pub alice_pub0_hex: String,
    pub bob_pub0_hex: String,
    pub bob_pub1_hex: String,
    pub alice_pub1_hex: String,
    pub recv_order: Vec<u32>,
    pub alice_mks_hex: Vec<String>,
    pub bob_recovered_mks_hex: Vec<String>,
    pub bob_send_mk_hex: String,
    pub alice_recovered_bob_mk_hex: String,
    pub cross_boundary_ok: bool,
    pub headers: Vec<EcDhRatchetHeaderOut>,
    pub bob_header: EcDhRatchetHeaderOut,
    pub negatives: EcDhRatchetNegatives,
    pub final_alice_fp_hex: String,
    pub final_bob_fp_hex: String,
}

pub fn run_ec_dh_ratchet_matrix(
    rk0: &[u8; 32],
    alice_priv0: &[u8; 32],
    bob_priv0: &[u8; 32],
    bob_priv1: &[u8; 32],
    alice_priv1: &[u8; 32],
) -> Result<EcDhRatchetMatrixOut, String> {
    let bob_pub0 = x25519_public(bob_priv0)?;
    let mut alice = ec_dr_init_alice(rk0, alice_priv0, &bob_pub0)?;
    let mut bob = ec_dr_init_bob(rk0, bob_priv0)?;

    let mut sealed: Vec<(EcDrHeader, [u8; 32])> = Vec::new();
    for _ in 0..2 {
        let (a, hdr, mk) = ec_dr_encrypt(&alice)?;
        alice = a;
        sealed.push((hdr, mk));
    }

    let (hdr1, mk1_expected) = &sealed[1];
    let (bob1, mk1) = ec_dr_decrypt(
        &bob,
        hdr1,
        MAX_SKIP,
        Some(bob_priv1),
        MAX_MKSKIPPED_RETAINED,
    )?;
    bob = bob1;
    if mk1 != *mk1_expected {
        return Err("mk1 mismatch".into());
    }

    let (hdr0, mk0_expected) = &sealed[0];
    let (bob2, mk0) = ec_dr_decrypt(&bob, hdr0, MAX_SKIP, None, MAX_MKSKIPPED_RETAINED)?;
    bob = bob2;
    if mk0 != *mk0_expected {
        return Err("mk0 mismatch".into());
    }

    let (bob3, bob_hdr, bob_mk) = ec_dr_encrypt(&bob)?;
    bob = bob3;
    let (alice2, amk) = ec_dr_decrypt(
        &alice,
        &bob_hdr,
        MAX_SKIP,
        Some(alice_priv1),
        MAX_MKSKIPPED_RETAINED,
    )?;
    alice = alice2;
    if amk != bob_mk {
        return Err("bob mk mismatch".into());
    }

    let all_zero_pub = match x25519_dh(alice_priv0, &[0u8; 32]) {
        Ok(_) => "accepted".into(),
        Err(e) => e,
    };
    let all_zero_priv = match x25519_public(&[0u8; 32]) {
        Ok(_) => "accepted".into(),
        Err(e) => e,
    };

    Ok(EcDhRatchetMatrixOut {
        alice_pub0_hex: hex::encode(x25519_public(alice_priv0)?),
        bob_pub0_hex: hex::encode(bob_pub0),
        bob_pub1_hex: hex::encode(x25519_public(bob_priv1)?),
        alice_pub1_hex: hex::encode(x25519_public(alice_priv1)?),
        recv_order: vec![1, 0],
        alice_mks_hex: sealed.iter().map(|(_, mk)| hex::encode(mk)).collect(),
        bob_recovered_mks_hex: vec![hex::encode(mk0), hex::encode(mk1)],
        bob_send_mk_hex: hex::encode(bob_mk),
        alice_recovered_bob_mk_hex: hex::encode(amk),
        cross_boundary_ok: true,
        headers: sealed
            .iter()
            .map(|(h, _)| EcDhRatchetHeaderOut {
                dh_pub_hex: hex::encode(h.dh_pub),
                pn: h.pn,
                n: h.n,
            })
            .collect(),
        bob_header: EcDhRatchetHeaderOut {
            dh_pub_hex: hex::encode(bob_hdr.dh_pub),
            pn: bob_hdr.pn,
            n: bob_hdr.n,
        },
        negatives: EcDhRatchetNegatives {
            all_zero_pub,
            all_zero_priv,
        },
        final_alice_fp_hex: hex::encode(alice.fingerprint()),
        final_bob_fp_hex: hex::encode(bob.fingerprint()),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BraidChunk {
    pub epoch: u64,
    pub chunk_type: u8,
    pub chunk_index: u32,
    pub payload: Vec<u8>,
    pub session_id: [u8; 32],
    pub binding_digest: [u8; 32],
}

pub fn braid_binding(chunk: &BraidChunk) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BRAID_CHUNK_DOMAIN);
    h.update(chunk.epoch.to_be_bytes());
    h.update([chunk.chunk_type]);
    h.update(chunk.chunk_index.to_be_bytes());
    h.update(&chunk.payload);
    h.update(chunk.session_id);
    h.finalize().into()
}

pub fn encode_braid_chunk(chunk: &BraidChunk) -> Result<Vec<u8>, String> {
    validate_braid_payload_rules(chunk.chunk_type, &chunk.payload, chunk.chunk_index)?;
    if chunk.payload.len() > BRAID_MAX_PAYLOAD {
        return Err("braid payload exceeds max".into());
    }
    let dig = braid_binding(chunk);
    let mut out = Vec::new();
    out.extend_from_slice(BRAID_MAGIC);
    out.extend_from_slice(&chunk.epoch.to_be_bytes());
    out.push(chunk.chunk_type);
    out.extend_from_slice(&chunk.chunk_index.to_be_bytes());
    out.extend_from_slice(&(chunk.payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&chunk.payload);
    out.extend_from_slice(&dig);
    Ok(out)
}

pub fn decode_braid_chunk(wire: &[u8], session_id: &[u8; 32]) -> Result<BraidChunk, String> {
    // Fail-closed: wire.len == BRAID_HEADER_LEN + plen + BRAID_DIGEST_LEN
    if wire.len() < BRAID_HEADER_LEN + BRAID_DIGEST_LEN {
        return Err("short braid chunk".into());
    }
    if &wire[..8] != BRAID_MAGIC.as_slice() {
        return Err("bad braid magic".into());
    }
    let typ = wire[8 + 8];
    if !braid_type_allowed(typ) {
        return Err("unknown braid chunk type".into());
    }
    let plen_off = 8 + 8 + 1 + 4;
    let plen = u16::from_be_bytes(wire[plen_off..plen_off + 2].try_into().unwrap()) as usize;
    let expected = BRAID_HEADER_LEN
        .checked_add(plen)
        .and_then(|v| v.checked_add(BRAID_DIGEST_LEN))
        .ok_or("braid length overflow")?;
    if wire.len() != expected {
        return Err("braid chunk length mismatch".into());
    }
    if plen > BRAID_MAX_PAYLOAD {
        return Err("braid payload exceeds max".into());
    }
    let mut off = 8;
    let epoch = u64::from_be_bytes(wire[off..off + 8].try_into().unwrap());
    off += 8;
    off += 1; // type
    let chunk_index = u32::from_be_bytes(wire[off..off + 4].try_into().unwrap());
    off += 4;
    off += 2; // plen
    let payload = wire[off..off + plen].to_vec();
    off += plen;
    let mut dig = [0u8; 32];
    dig.copy_from_slice(&wire[off..off + BRAID_DIGEST_LEN]);
    validate_braid_payload_rules(typ, &payload, chunk_index)?;
    let chunk = BraidChunk {
        epoch,
        chunk_type: typ,
        chunk_index,
        payload,
        session_id: *session_id,
        binding_digest: dig,
    };
    if braid_binding(&chunk) != dig {
        return Err("braid chunk tamper".into());
    }
    Ok(chunk)
}

#[derive(Clone, Debug)]
pub struct BraidReassembly {
    pub epoch: u64,
    pub expected_count: u32,
    pub parts: BTreeMap<u32, Vec<u8>>,
    pub promoted: bool,
    pub deleted_prev_dk: bool,
    pub prev_dk: Option<Vec<u8>>,
    pub total_payload_bytes: usize,
    pub max_chunks: u32,
    pub max_total_bytes: usize,
}

impl BraidReassembly {
    pub fn new(epoch: u64, expected_count: u32) -> Result<Self, String> {
        if expected_count == 0 || expected_count > BRAID_MAX_CHUNKS_PER_EPOCH {
            return Err("braid expected_count out of bounds".into());
        }
        Ok(Self {
            epoch,
            expected_count,
            parts: BTreeMap::new(),
            promoted: false,
            deleted_prev_dk: false,
            prev_dk: None,
            total_payload_bytes: 0,
            max_chunks: BRAID_MAX_CHUNKS_PER_EPOCH,
            max_total_bytes: BRAID_MAX_TOTAL_PAYLOAD_BYTES,
        })
    }

    pub fn ingest(&mut self, chunk: &BraidChunk) -> &'static str {
        if chunk.epoch != self.epoch {
            return "epoch_mismatch";
        }
        if !braid_type_allowed(chunk.chunk_type) {
            return "unknown_type";
        }
        if chunk.chunk_index >= self.expected_count {
            return "index_out_of_range";
        }
        if self.parts.contains_key(&chunk.chunk_index) {
            return "duplicate_chunk";
        }
        if self.parts.len() as u32 >= self.max_chunks {
            return "chunk_cap_exceeded";
        }
        let nxt = self.total_payload_bytes.saturating_add(chunk.payload.len());
        if nxt > self.max_total_bytes {
            return "byte_cap_exceeded";
        }
        self.parts.insert(chunk.chunk_index, chunk.payload.clone());
        self.total_payload_bytes = nxt;
        "stored"
    }

    pub fn try_complete(&self) -> Option<Vec<u8>> {
        for i in 0..self.expected_count {
            if !self.parts.contains_key(&i) {
                return None;
            }
        }
        let mut body = Vec::new();
        for i in 0..self.expected_count {
            body.extend_from_slice(&self.parts[&i]);
        }
        Some(body)
    }

    /// Promote the epoch and erase the previous epoch's decapsulation key in
    /// the caller's own buffer; `deleted_prev_dk` is only set once that buffer
    /// is observably all-zero (the KAT field asserts real deletion).
    pub fn promote_with_ss(
        &mut self,
        ss: &[u8; 32],
        prev_dk: &mut [u8; 32],
    ) -> Result<[u8; 32], String> {
        use zeroize::Zeroize;

        if self.promoted {
            return Err("already promoted".into());
        }
        if self.try_complete().is_none() {
            return Err("incomplete".into());
        }
        prev_dk.zeroize();
        if prev_dk.iter().any(|&byte| byte != 0) {
            return Err("previous decapsulation key not erased".into());
        }
        self.prev_dk = None;
        self.deleted_prev_dk = true;
        self.promoted = true;
        Ok(*ss)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BraidKemChunkMatrixOut {
    pub mlkem_source: String,
    pub ek_len: usize,
    pub ct_len: usize,
    pub z_pq_hex: String,
    pub chunk_count: usize,
    pub chunk_size: usize,
    pub deliver_order: Vec<u32>,
    pub reassembled_ct_ok: bool,
    pub tamper_result: String,
    pub epoch_promoted: bool,
    pub prev_dk_zeroed: bool,
    pub scka_rk_hex: String,
    pub alice_ck_send_hex: String,
    pub bob_ck_recv_hex: String,
    pub first_chunk_wire_hex: String,
    pub hdr_chunk_type: u8,
    pub ct1_chunk_type: u8,
    pub ct2_chunk_type: u8,
}

fn load_mlkem_kat() -> Result<serde_json::Value, String> {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    let path = p.join("shared-vectors/rvn1/atsam/mlkem768_hybrid_kat_001.json");
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

pub fn run_braid_kem_chunk_matrix(
    session_id: &[u8; 32],
    sk_scka: &[u8; 32],
) -> Result<BraidKemChunkMatrixOut, String> {
    let kat = load_mlkem_kat()?;
    let ek = hex::decode(
        kat["expected"]["mlkem_ek_hex"]
            .as_str()
            .ok_or("missing mlkem_ek_hex")?,
    )
    .map_err(|e| e.to_string())?;
    let ct = hex::decode(
        kat["expected"]["mlkem_ct_hex"]
            .as_str()
            .ok_or("missing mlkem_ct_hex")?,
    )
    .map_err(|e| e.to_string())?;
    let z_pq = hex32(
        kat["expected"]["z_pq_hex"]
            .as_str()
            .ok_or("missing z_pq_hex")?,
    )?;

    let chunk_size = 42usize;
    let pieces: Vec<Vec<u8>> = ct.chunks(chunk_size).map(|c| c.to_vec()).collect();
    let mut wires = Vec::new();
    for (i, payload) in pieces.iter().enumerate() {
        let ch = BraidChunk {
            epoch: 1,
            chunk_type: if i == pieces.len() - 1 {
                CHUNK_CT2
            } else {
                CHUNK_CT1
            },
            chunk_index: i as u32,
            payload: payload.clone(),
            session_id: *session_id,
            binding_digest: [0u8; 32],
        };
        wires.push(encode_braid_chunk(&ch)?);
    }

    let mut order: Vec<u32> = (0..pieces.len() as u32).collect();
    order = order[2..]
        .iter()
        .copied()
        .chain(order[..2].iter().copied())
        .collect();

    let mut reb = BraidReassembly::new(1, pieces.len() as u32)?;
    for &idx in &order {
        let ch = decode_braid_chunk(&wires[idx as usize], session_id)?;
        if reb.ingest(&ch) != "stored" {
            return Err(format!("ingest failed for chunk {idx}"));
        }
    }
    let body = reb.try_complete().ok_or("incomplete reassembly")?;
    if body != ct {
        return Err("reassembled ct mismatch".into());
    }

    let mut tampered = wires[0].clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let tamper_result = match decode_braid_chunk(&tampered, session_id) {
        Ok(_) => "accepted".into(),
        Err(e) => e,
    };

    let prev_dk = Sha256::digest(b"prev-epoch-dk");
    let mut prev_dk_arr = [0u8; 32];
    prev_dk_arr.copy_from_slice(&prev_dk);
    let ss = reb.promote_with_ss(&z_pq, &mut prev_dk_arr)?;
    if prev_dk_arr != [0u8; 32] {
        return Err("prev dk still live after promote".into());
    }

    let alice = scka_from_init(true, sk_scka);
    let bob = scka_from_init(false, sk_scka);
    let alice_p = scka_epoch_promote_initiator(&alice, &ss)?;
    let bob_p = scka_epoch_promote_responder(&bob, &ss)?;

    Ok(BraidKemChunkMatrixOut {
        mlkem_source: "atsam/mlkem768_hybrid_kat_001.json".into(),
        ek_len: ek.len(),
        ct_len: ct.len(),
        z_pq_hex: hex::encode(z_pq),
        chunk_count: pieces.len(),
        chunk_size,
        deliver_order: order,
        reassembled_ct_ok: body == ct,
        tamper_result,
        epoch_promoted: reb.promoted,
        prev_dk_zeroed: reb.deleted_prev_dk,
        scka_rk_hex: hex::encode(alice_p.rk),
        alice_ck_send_hex: hex::encode(alice_p.ck_send),
        bob_ck_recv_hex: hex::encode(bob_p.ck_recv),
        first_chunk_wire_hex: hex::encode(&wires[0]),
        hdr_chunk_type: CHUNK_HDR,
        ct1_chunk_type: CHUNK_CT1,
        ct2_chunk_type: CHUNK_CT2,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BraidCodecNegCase {
    pub name: String,
    pub result: String,
    pub reason: Option<String>,
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BraidCodecNegativesOut {
    pub braid_header_len: usize,
    pub braid_digest_len: usize,
    pub braid_max_payload: usize,
    pub braid_max_chunks: u32,
    pub braid_max_total_bytes: usize,
    pub max_mkskipped_retained: usize,
    pub epoch_type: String,
    pub mlkem768_header_size: usize,
    pub mlkem768_ek_vector_size: usize,
    pub mlkem768_ek_fips_size: usize,
    pub mlkem768_ct1_size: usize,
    pub mlkem768_ct2_size: usize,
    pub cases: Vec<BraidCodecNegCase>,
}

fn craft_braid_wire(
    plen_field: u16,
    payload: &[u8],
    typ: u8,
    epoch: u64,
    index: u32,
    session_id: &[u8; 32],
    trailing: &[u8],
) -> Vec<u8> {
    let tmp = BraidChunk {
        epoch,
        chunk_type: typ,
        chunk_index: index,
        payload: payload.to_vec(),
        session_id: *session_id,
        binding_digest: [0u8; 32],
    };
    let dig = braid_binding(&tmp);
    let mut body = Vec::new();
    body.extend_from_slice(BRAID_MAGIC);
    body.extend_from_slice(&epoch.to_be_bytes());
    body.push(typ);
    body.extend_from_slice(&index.to_be_bytes());
    body.extend_from_slice(&plen_field.to_be_bytes());
    body.extend_from_slice(payload);
    body.extend_from_slice(&dig);
    body.extend_from_slice(trailing);
    body
}

pub fn run_braid_codec_negatives(session_id: &[u8; 32]) -> BraidCodecNegativesOut {
    let mut cases = Vec::new();

    let good = encode_braid_chunk(&BraidChunk {
        epoch: 1,
        chunk_type: CHUNK_CT1,
        chunk_index: 0,
        payload: b"abc".to_vec(),
        session_id: *session_id,
        binding_digest: [0u8; 32],
    })
    .expect("good encode");

    let trunc = &good[..good.len().saturating_sub(5)];
    match decode_braid_chunk(trunc, session_id) {
        Ok(_) => cases.push(BraidCodecNegCase {
            name: "truncated_plen".into(),
            result: "accepted".into(),
            reason: None,
            note: None,
        }),
        Err(e) => cases.push(BraidCodecNegCase {
            name: "truncated_plen".into(),
            result: "reject".into(),
            reason: Some(e),
            note: None,
        }),
    }

    let mut trailing = good.clone();
    trailing.push(0);
    match decode_braid_chunk(&trailing, session_id) {
        Ok(_) => cases.push(BraidCodecNegCase {
            name: "trailing_bytes".into(),
            result: "accepted".into(),
            reason: None,
            note: None,
        }),
        Err(e) => cases.push(BraidCodecNegCase {
            name: "trailing_bytes".into(),
            result: "reject".into(),
            reason: Some(e),
            note: None,
        }),
    }

    let over = craft_braid_wire(1000, b"x", CHUNK_CT1, 1, 0, session_id, &[]);
    match decode_braid_chunk(&over, session_id) {
        Ok(_) => cases.push(BraidCodecNegCase {
            name: "oversized_plen_field".into(),
            result: "accepted".into(),
            reason: None,
            note: None,
        }),
        Err(e) => cases.push(BraidCodecNegCase {
            name: "oversized_plen_field".into(),
            result: "reject".into(),
            reason: Some(e),
            note: None,
        }),
    }

    match encode_braid_chunk(&BraidChunk {
        epoch: 1,
        chunk_type: 99,
        chunk_index: 0,
        payload: b"x".to_vec(),
        session_id: *session_id,
        binding_digest: [0u8; 32],
    }) {
        Ok(_) => cases.push(BraidCodecNegCase {
            name: "encode_unknown_type".into(),
            result: "accepted".into(),
            reason: None,
            note: None,
        }),
        Err(e) => cases.push(BraidCodecNegCase {
            name: "encode_unknown_type".into(),
            result: "reject".into(),
            reason: Some(e),
            note: None,
        }),
    }

    match encode_braid_chunk(&BraidChunk {
        epoch: 1,
        chunk_type: CHUNK_CT1,
        chunk_index: 0,
        payload: vec![0u8; BRAID_MAX_PAYLOAD + 1],
        session_id: *session_id,
        binding_digest: [0u8; 32],
    }) {
        Ok(_) => cases.push(BraidCodecNegCase {
            name: "encode_payload_gt_max".into(),
            result: "accepted".into(),
            reason: None,
            note: None,
        }),
        Err(e) => cases.push(BraidCodecNegCase {
            name: "encode_payload_gt_max".into(),
            result: "reject".into(),
            reason: Some(e),
            note: None,
        }),
    }

    // Rust session_id is [u8;32]; document parity with Py/Swift runtime reject.
    cases.push(BraidCodecNegCase {
        name: "session_id_bad_len".into(),
        result: "reject".into(),
        reason: Some("session_id must be 32 bytes".into()),
        note: None,
    });

    match encode_braid_chunk(&BraidChunk {
        epoch: 1,
        chunk_type: CHUNK_CT1_ACK,
        chunk_index: 0,
        payload: b"x".to_vec(),
        session_id: *session_id,
        binding_digest: [0u8; 32],
    }) {
        Ok(_) => cases.push(BraidCodecNegCase {
            name: "empty_type_nonempty_payload".into(),
            result: "accepted".into(),
            reason: None,
            note: None,
        }),
        Err(e) => cases.push(BraidCodecNegCase {
            name: "empty_type_nonempty_payload".into(),
            result: "reject".into(),
            reason: Some(e),
            note: None,
        }),
    }

    match encode_braid_chunk(&BraidChunk {
        epoch: 1,
        chunk_type: CHUNK_CT1,
        chunk_index: 0,
        payload: Vec::new(),
        session_id: *session_id,
        binding_digest: [0u8; 32],
    }) {
        Ok(_) => cases.push(BraidCodecNegCase {
            name: "data_type_empty_payload".into(),
            result: "accepted".into(),
            reason: None,
            note: None,
        }),
        Err(e) => cases.push(BraidCodecNegCase {
            name: "data_type_empty_payload".into(),
            result: "reject".into(),
            reason: Some(e),
            note: None,
        }),
    }

    match encode_braid_chunk(&BraidChunk {
        epoch: 1,
        chunk_type: CHUNK_NONE,
        chunk_index: 1,
        payload: Vec::new(),
        session_id: *session_id,
        binding_digest: [0u8; 32],
    }) {
        Ok(_) => cases.push(BraidCodecNegCase {
            name: "empty_type_nonzero_index".into(),
            result: "accepted".into(),
            reason: None,
            note: None,
        }),
        Err(e) => cases.push(BraidCodecNegCase {
            name: "empty_type_nonzero_index".into(),
            result: "reject".into(),
            reason: Some(e),
            note: None,
        }),
    }

    let mut reb = BraidReassembly::new(1, 2).expect("reb");
    let ch = BraidChunk {
        epoch: 1,
        chunk_type: CHUNK_CT1,
        chunk_index: 2,
        payload: b"z".to_vec(),
        session_id: *session_id,
        binding_digest: [0u8; 32],
    };
    cases.push(BraidCodecNegCase {
        name: "ingest_index_oob".into(),
        result: reb.ingest(&ch).into(),
        reason: None,
        note: None,
    });

    let mut reb2 = BraidReassembly {
        max_total_bytes: 10,
        ..BraidReassembly::new(1, 2).expect("reb2")
    };
    let a = BraidChunk {
        epoch: 1,
        chunk_type: CHUNK_CT1,
        chunk_index: 0,
        payload: vec![0u8; 8],
        session_id: *session_id,
        binding_digest: [0u8; 32],
    };
    let b = BraidChunk {
        epoch: 1,
        chunk_type: CHUNK_CT1,
        chunk_index: 1,
        payload: vec![0u8; 8],
        session_id: *session_id,
        binding_digest: [0u8; 32],
    };
    assert_eq!(reb2.ingest(&a), "stored");
    cases.push(BraidCodecNegCase {
        name: "ingest_byte_cap".into(),
        result: reb2.ingest(&b).into(),
        reason: None,
        note: None,
    });

    cases.push(BraidCodecNegCase {
        name: "binding_digest_role".into(),
        result: "canonical_binding_only".into(),
        reason: None,
        note: Some("auth via outer signature then AEAD; SHA-256 binding is not a MAC".into()),
    });

    cases.push(BraidCodecNegCase {
        name: "epoch_width_policy".into(),
        result: "u64be_no_wrap".into(),
        reason: None,
        note: Some("EPOCH_TYPE=u64; ToBytes=big-endian; MUST NOT wrap on increment".into()),
    });

    let alice_priv: [u8; 32] = Sha256::digest(b"atsam-v2/mkskip-cap/a0").into();
    let bob_priv: [u8; 32] = Sha256::digest(b"atsam-v2/mkskip-cap/b0").into();
    let bob_priv2: [u8; 32] = Sha256::digest(b"atsam-v2/mkskip-cap/b1").into();
    let rk0: [u8; 32] = Sha256::digest(b"atsam-v2/mkskip-cap/rk").into();
    let bob_pub = x25519_public(&bob_priv).expect("bob pub");
    let mut alice = ec_dr_init_alice(&rk0, &alice_priv, &bob_pub).expect("alice");
    let bob = ec_dr_init_bob(&rk0, &bob_priv).expect("bob");
    let mut sealed = Vec::new();
    for _ in 0..5 {
        let (a2, hdr, mk) = ec_dr_encrypt(&alice).expect("enc");
        alice = a2;
        sealed.push((hdr, mk));
    }
    match ec_dr_decrypt(&bob, &sealed[4].0, MAX_SKIP, Some(&bob_priv2), 2) {
        Ok(_) => cases.push(BraidCodecNegCase {
            name: "mkskipped_global_cap".into(),
            result: "accepted".into(),
            reason: None,
            note: None,
        }),
        Err(e) => cases.push(BraidCodecNegCase {
            name: "mkskipped_global_cap".into(),
            result: "reject".into(),
            reason: Some(e),
            note: None,
        }),
    }

    BraidCodecNegativesOut {
        braid_header_len: BRAID_HEADER_LEN,
        braid_digest_len: BRAID_DIGEST_LEN,
        braid_max_payload: BRAID_MAX_PAYLOAD,
        braid_max_chunks: BRAID_MAX_CHUNKS_PER_EPOCH,
        braid_max_total_bytes: BRAID_MAX_TOTAL_PAYLOAD_BYTES,
        max_mkskipped_retained: MAX_MKSKIPPED_RETAINED,
        epoch_type: "u64".into(),
        mlkem768_header_size: BRAID_MLKEM768_HEADER_SIZE,
        mlkem768_ek_vector_size: BRAID_MLKEM768_EK_VECTOR_SIZE,
        mlkem768_ek_fips_size: BRAID_MLKEM768_EK_FIPS_SIZE,
        mlkem768_ct1_size: BRAID_MLKEM768_CT1_SIZE,
        mlkem768_ct2_size: BRAID_MLKEM768_CT2_SIZE,
        cases,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrComboStep {
    pub phase: String,
    pub hybrid_key_hex: Option<String>,
    pub rk_hex: Option<String>,
    pub alice_send_equals_bob_recv: Option<bool>,
    pub bob_send_equals_alice_recv: Option<bool>,
    pub alice_dh_pub1_hex: Option<String>,
    pub bob_dh_pub1_hex: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrComboMatrixOut {
    pub dh_epochs: u32,
    pub scka_epochs: u32,
    pub session_id_hex: String,
    pub steps: Vec<TrComboStep>,
    pub final_alice_ec_fp_hex: String,
    pub final_bob_ec_fp_hex: String,
}

#[allow(clippy::too_many_arguments)]
pub fn run_tr_combo_matrix(
    sk_ec: &[u8; 32],
    sk_scka: &[u8; 32],
    session_id: &[u8; 32],
    alice_priv0: &[u8; 32],
    bob_priv0: &[u8; 32],
    bob_priv1: &[u8; 32],
    alice_priv1: &[u8; 32],
    ss_scka1: &[u8; 32],
    ss_scka2: &[u8; 32],
) -> Result<TrComboMatrixOut, String> {
    let bob_pub0 = x25519_public(bob_priv0)?;
    let mut alice = ec_dr_init_alice(sk_ec, alice_priv0, &bob_pub0)?;
    let mut bob = ec_dr_init_bob(sk_ec, bob_priv0)?;
    let mut a_scka = scka_from_init(true, sk_scka);
    let mut b_scka = scka_from_init(false, sk_scka);
    let mut steps = Vec::new();

    let (alice1, h0, mk_a0) = ec_dr_encrypt(&alice)?;
    alice = alice1;
    let (alice2, h1, mk_a1) = ec_dr_encrypt(&alice)?;
    alice = alice2;

    let (bob1, mk1) = ec_dr_decrypt(&bob, &h1, MAX_SKIP, Some(bob_priv1), MAX_MKSKIPPED_RETAINED)?;
    bob = bob1;
    let (bob2, mk0) = ec_dr_decrypt(&bob, &h0, MAX_SKIP, None, MAX_MKSKIPPED_RETAINED)?;
    bob = bob2;
    if mk0 != mk_a0 || mk1 != mk_a1 {
        return Err("ec mk mismatch".into());
    }

    let (a_scka1, pq0) = scka_next_send_mk(&a_scka)?;
    a_scka = a_scka1;
    let (b_scka1, pq0b) = scka_next_recv_mk(&b_scka)?;
    b_scka = b_scka1;
    let (hy0, _) = kdf_hybrid(&mk0, &pq0);
    if pq0 != pq0b {
        return Err("pq0 mismatch".into());
    }
    steps.push(TrComboStep {
        phase: "ec0_ooo".into(),
        hybrid_key_hex: Some(hex::encode(hy0)),
        rk_hex: None,
        alice_send_equals_bob_recv: None,
        bob_send_equals_alice_recv: None,
        alice_dh_pub1_hex: None,
        bob_dh_pub1_hex: None,
    });

    a_scka = scka_epoch_promote_initiator(&a_scka, ss_scka1)?;
    b_scka = scka_epoch_promote_responder(&b_scka, ss_scka1)?;
    steps.push(TrComboStep {
        phase: "scka1".into(),
        hybrid_key_hex: None,
        rk_hex: Some(hex::encode(a_scka.rk)),
        alice_send_equals_bob_recv: Some(a_scka.ck_send == b_scka.ck_recv),
        bob_send_equals_alice_recv: None,
        alice_dh_pub1_hex: None,
        bob_dh_pub1_hex: None,
    });

    let (bob3, hb, mk_b) = ec_dr_encrypt(&bob)?;
    bob = bob3;
    let (alice3, mkb) = ec_dr_decrypt(
        &alice,
        &hb,
        MAX_SKIP,
        Some(alice_priv1),
        MAX_MKSKIPPED_RETAINED,
    )?;
    alice = alice3;
    if mkb != mk_b {
        return Err("mk_b mismatch".into());
    }

    let b_scka2 = scka_epoch_promote_initiator(&b_scka, ss_scka2)?;
    let a_scka2 = scka_epoch_promote_responder(&a_scka, ss_scka2)?;
    let (b_scka3, pq_b) = scka_next_send_mk(&b_scka2)?;
    let (a_scka3, pq_a) = scka_next_recv_mk(&a_scka2)?;
    if pq_b != pq_a {
        return Err("pq_b/pq_a mismatch".into());
    }
    let (hy1, _) = kdf_hybrid(&mkb, &pq_b);
    steps.push(TrComboStep {
        phase: "ec1_scka2".into(),
        hybrid_key_hex: Some(hex::encode(hy1)),
        rk_hex: None,
        alice_send_equals_bob_recv: None,
        bob_send_equals_alice_recv: Some(b_scka3.ck_send == a_scka3.ck_recv),
        alice_dh_pub1_hex: Some(hex::encode(alice.dhs_pub)),
        bob_dh_pub1_hex: Some(hex::encode(bob.dhs_pub)),
    });

    Ok(TrComboMatrixOut {
        dh_epochs: 2,
        scka_epochs: 2,
        session_id_hex: hex::encode(session_id),
        steps,
        final_alice_ec_fp_hex: hex::encode(alice.fingerprint()),
        final_bob_ec_fp_hex: hex::encode(bob.fingerprint()),
    })
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s).map_err(|e| e.to_string())?;
    if v.len() != 32 {
        return Err("expected 32 bytes".into());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.pop();
        p.join("shared-vectors/rvn1/atsam")
    }

    fn load(name: &str) -> Value {
        serde_json::from_str(&std::fs::read_to_string(root().join(name)).unwrap()).unwrap()
    }

    #[test]
    fn promote_with_ss_erases_the_callers_previous_dk() {
        let mut reb = BraidReassembly::new(1, 1).unwrap();
        let session = [0x5A; 32];
        let chunk = BraidChunk {
            epoch: 1,
            chunk_type: CHUNK_CT1,
            chunk_index: 0,
            payload: vec![0x11; 8],
            session_id: session,
            binding_digest: [0u8; 32],
        };
        let wire = encode_braid_chunk(&chunk).unwrap();
        assert_eq!(
            reb.ingest(&decode_braid_chunk(&wire, &session).unwrap()),
            "stored"
        );
        let mut prev_dk = [0x55; 32];
        let ss = reb.promote_with_ss(&[0x66; 32], &mut prev_dk).unwrap();
        assert_eq!(ss, [0x66; 32]);
        // The flag now reflects real deletion of the caller's key material.
        assert_eq!(prev_dk, [0u8; 32]);
        assert!(reb.deleted_prev_dk);
        assert!(reb.prev_dk.is_none());
    }

    fn assert_ec_dh_expected(out: &EcDhRatchetMatrixOut, exp: &Value) {
        assert_eq!(out.alice_pub0_hex, exp["alice_pub0_hex"].as_str().unwrap());
        assert_eq!(out.bob_pub0_hex, exp["bob_pub0_hex"].as_str().unwrap());
        assert_eq!(out.bob_pub1_hex, exp["bob_pub1_hex"].as_str().unwrap());
        assert_eq!(out.alice_pub1_hex, exp["alice_pub1_hex"].as_str().unwrap());
        assert_eq!(
            out.recv_order,
            exp["recv_order"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as u32)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            out.alice_mks_hex,
            exp["alice_mks_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            out.bob_recovered_mks_hex,
            exp["bob_recovered_mks_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            out.bob_send_mk_hex,
            exp["bob_send_mk_hex"].as_str().unwrap()
        );
        assert_eq!(
            out.alice_recovered_bob_mk_hex,
            exp["alice_recovered_bob_mk_hex"].as_str().unwrap()
        );
        assert_eq!(
            out.cross_boundary_ok,
            exp["cross_boundary_ok"].as_bool().unwrap()
        );
        assert_eq!(
            out.negatives.all_zero_pub,
            exp["negatives"]["all_zero_pub"].as_str().unwrap()
        );
        assert_eq!(
            out.negatives.all_zero_priv,
            exp["negatives"]["all_zero_priv"].as_str().unwrap()
        );
        assert_eq!(
            out.final_alice_fp_hex,
            exp["final_alice_fp_hex"].as_str().unwrap()
        );
        assert_eq!(
            out.final_bob_fp_hex,
            exp["final_bob_fp_hex"].as_str().unwrap()
        );
        let headers = exp["headers"].as_array().unwrap();
        for (i, h) in out.headers.iter().enumerate() {
            assert_eq!(h.dh_pub_hex, headers[i]["dh_pub_hex"].as_str().unwrap());
            assert_eq!(h.pn, headers[i]["pn"].as_u64().unwrap() as u32);
            assert_eq!(h.n, headers[i]["n"].as_u64().unwrap() as u32);
        }
        let bh = &exp["bob_header"];
        assert_eq!(
            out.bob_header.dh_pub_hex,
            bh["dh_pub_hex"].as_str().unwrap()
        );
        assert_eq!(out.bob_header.pn, bh["pn"].as_u64().unwrap() as u32);
        assert_eq!(out.bob_header.n, bh["n"].as_u64().unwrap() as u32);
    }

    fn assert_braid_expected(out: &BraidKemChunkMatrixOut, exp: &Value) {
        assert_eq!(out.mlkem_source, exp["mlkem_source"].as_str().unwrap());
        assert_eq!(out.ek_len, exp["ek_len"].as_u64().unwrap() as usize);
        assert_eq!(out.ct_len, exp["ct_len"].as_u64().unwrap() as usize);
        assert_eq!(out.z_pq_hex, exp["z_pq_hex"].as_str().unwrap());
        assert_eq!(
            out.chunk_count,
            exp["chunk_count"].as_u64().unwrap() as usize
        );
        assert_eq!(out.chunk_size, exp["chunk_size"].as_u64().unwrap() as usize);
        assert_eq!(
            out.deliver_order,
            exp["deliver_order"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as u32)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            out.reassembled_ct_ok,
            exp["reassembled_ct_ok"].as_bool().unwrap()
        );
        assert_eq!(out.tamper_result, exp["tamper_result"].as_str().unwrap());
        assert_eq!(out.epoch_promoted, exp["epoch_promoted"].as_bool().unwrap());
        assert_eq!(out.prev_dk_zeroed, exp["prev_dk_zeroed"].as_bool().unwrap());
        assert_eq!(out.scka_rk_hex, exp["scka_rk_hex"].as_str().unwrap());
        assert_eq!(
            out.alice_ck_send_hex,
            exp["alice_ck_send_hex"].as_str().unwrap()
        );
        assert_eq!(
            out.bob_ck_recv_hex,
            exp["bob_ck_recv_hex"].as_str().unwrap()
        );
        assert_eq!(
            out.first_chunk_wire_hex,
            exp["first_chunk_wire_hex"].as_str().unwrap()
        );
        assert_eq!(
            out.hdr_chunk_type,
            exp["hdr_chunk_type"].as_u64().unwrap() as u8
        );
        assert_eq!(
            out.ct1_chunk_type,
            exp["ct1_chunk_type"].as_u64().unwrap() as u8
        );
        assert_eq!(
            out.ct2_chunk_type,
            exp["ct2_chunk_type"].as_u64().unwrap() as u8
        );
    }

    fn assert_combo_expected(out: &TrComboMatrixOut, exp: &Value) {
        assert_eq!(out.dh_epochs, exp["dh_epochs"].as_u64().unwrap() as u32);
        assert_eq!(out.scka_epochs, exp["scka_epochs"].as_u64().unwrap() as u32);
        assert_eq!(out.session_id_hex, exp["session_id_hex"].as_str().unwrap());
        assert_eq!(
            out.final_alice_ec_fp_hex,
            exp["final_alice_ec_fp_hex"].as_str().unwrap()
        );
        assert_eq!(
            out.final_bob_ec_fp_hex,
            exp["final_bob_ec_fp_hex"].as_str().unwrap()
        );
        let steps = exp["steps"].as_array().unwrap();
        assert_eq!(out.steps.len(), steps.len());
        for (out_step, exp_step) in out.steps.iter().zip(steps.iter()) {
            assert_eq!(out_step.phase, exp_step["phase"].as_str().unwrap());
            if let Some(h) = exp_step.get("hybrid_key_hex") {
                assert_eq!(out_step.hybrid_key_hex.as_deref(), h.as_str());
            }
            if let Some(r) = exp_step.get("rk_hex") {
                assert_eq!(out_step.rk_hex.as_deref(), r.as_str());
            }
            if let Some(v) = exp_step.get("alice_send_equals_bob_recv") {
                assert_eq!(
                    out_step.alice_send_equals_bob_recv,
                    Some(v.as_bool().unwrap())
                );
            }
            if let Some(v) = exp_step.get("bob_send_equals_alice_recv") {
                assert_eq!(
                    out_step.bob_send_equals_alice_recv,
                    Some(v.as_bool().unwrap())
                );
            }
            if let Some(v) = exp_step.get("alice_dh_pub1_hex") {
                assert_eq!(out_step.alice_dh_pub1_hex.as_deref(), v.as_str());
            }
            if let Some(v) = exp_step.get("bob_dh_pub1_hex") {
                assert_eq!(out_step.bob_dh_pub1_hex.as_deref(), v.as_str());
            }
        }
    }

    #[test]
    fn tr_ec_dh_ratchet_001() {
        let v = load("tr_ec_dh_ratchet_001.json");
        let inp = &v["inputs"];
        let out = run_ec_dh_ratchet_matrix(
            &hex32(inp["rk0_hex"].as_str().unwrap()).unwrap(),
            &hex32(inp["alice_priv0_hex"].as_str().unwrap()).unwrap(),
            &hex32(inp["bob_priv0_hex"].as_str().unwrap()).unwrap(),
            &hex32(inp["bob_priv1_hex"].as_str().unwrap()).unwrap(),
            &hex32(inp["alice_priv1_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_ec_dh_expected(&out, &v["expected"]);
    }

    #[test]
    fn tr_braid_kem_chunk_001() {
        let v = load("tr_braid_kem_chunk_001.json");
        let inp = &v["inputs"];
        let out = run_braid_kem_chunk_matrix(
            &hex32(inp["session_id_hex"].as_str().unwrap()).unwrap(),
            &hex32(inp["sk_scka_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_braid_expected(&out, &v["expected"]);
    }

    #[test]
    fn tr_braid_codec_negatives_001() {
        let v = load("tr_braid_codec_negatives_001.json");
        let sid = hex32(v["inputs"]["session_id_hex"].as_str().unwrap()).unwrap();
        let out = run_braid_codec_negatives(&sid);
        let exp = &v["expected"];
        assert_eq!(
            out.braid_header_len,
            exp["braid_header_len"].as_u64().unwrap() as usize
        );
        assert_eq!(
            out.braid_digest_len,
            exp["braid_digest_len"].as_u64().unwrap() as usize
        );
        assert_eq!(
            out.braid_max_payload,
            exp["braid_max_payload"].as_u64().unwrap() as usize
        );
        assert_eq!(
            out.braid_max_chunks,
            exp["braid_max_chunks"].as_u64().unwrap() as u32
        );
        assert_eq!(
            out.braid_max_total_bytes,
            exp["braid_max_total_bytes"].as_u64().unwrap() as usize
        );
        assert_eq!(
            out.max_mkskipped_retained,
            exp["max_mkskipped_retained"].as_u64().unwrap() as usize
        );
        assert_eq!(out.epoch_type, exp["epoch_type"].as_str().unwrap());
        assert_eq!(
            out.mlkem768_header_size,
            exp["mlkem768_header_size"].as_u64().unwrap() as usize
        );
        assert_eq!(
            out.mlkem768_ek_vector_size,
            exp["mlkem768_ek_vector_size"].as_u64().unwrap() as usize
        );
        assert_eq!(
            out.mlkem768_ek_fips_size,
            exp["mlkem768_ek_fips_size"].as_u64().unwrap() as usize
        );
        assert_eq!(
            out.mlkem768_ct1_size,
            exp["mlkem768_ct1_size"].as_u64().unwrap() as usize
        );
        assert_eq!(
            out.mlkem768_ct2_size,
            exp["mlkem768_ct2_size"].as_u64().unwrap() as usize
        );
        let cases = exp["cases"].as_array().unwrap();
        assert_eq!(out.cases.len(), cases.len());
        for (got, want) in out.cases.iter().zip(cases.iter()) {
            assert_eq!(got.name, want["name"].as_str().unwrap());
            assert_eq!(got.result, want["result"].as_str().unwrap());
            if let Some(r) = want.get("reason").and_then(|x| x.as_str()) {
                assert_eq!(got.reason.as_deref(), Some(r));
            }
            if let Some(n) = want.get("note").and_then(|x| x.as_str()) {
                assert_eq!(got.note.as_deref(), Some(n));
            }
        }
    }

    #[test]
    fn tr_combo_multi_001() {
        let v = load("tr_combo_multi_001.json");
        let inp = &v["inputs"];
        let out = run_tr_combo_matrix(
            &hex32(inp["sk_ec_hex"].as_str().unwrap()).unwrap(),
            &hex32(inp["sk_scka_hex"].as_str().unwrap()).unwrap(),
            &hex32(inp["session_id_hex"].as_str().unwrap()).unwrap(),
            &hex32(inp["alice_priv0_hex"].as_str().unwrap()).unwrap(),
            &hex32(inp["bob_priv0_hex"].as_str().unwrap()).unwrap(),
            &hex32(inp["bob_priv1_hex"].as_str().unwrap()).unwrap(),
            &hex32(inp["alice_priv1_hex"].as_str().unwrap()).unwrap(),
            &hex32(inp["ss_scka1_hex"].as_str().unwrap()).unwrap(),
            &hex32(inp["ss_scka2_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_combo_expected(&out, &v["expected"]);
    }

    #[test]
    fn ec_ns_overflow_is_fail_closed() {
        let bob_pub = x25519_public(&[0x77; 32]).unwrap();
        let alice_priv = [0x42; 32];
        let mut alice = ec_dr_init_alice(&[0x11; 32], &alice_priv, &bob_pub).unwrap();
        alice.ns = u32::MAX;
        let err = ec_dr_encrypt(&alice).unwrap_err();
        assert!(err.contains("ec_ns overflow"), "{err}");
    }

    #[test]
    fn ec_nr_overflow_is_fail_closed() {
        let bob_priv = [0x61; 32];
        let bob_pub = x25519_public(&bob_priv).unwrap();
        let alice_priv = [0x62; 32];
        let alice = ec_dr_init_alice(&[0x10; 32], &alice_priv, &bob_pub).unwrap();
        let (_alice, hdr, _mk) = ec_dr_encrypt(&alice).unwrap();
        let bob = ec_dr_init_bob(&[0x10; 32], &bob_priv).unwrap();
        let bob_priv1 = [0x63; 32];
        let (mut bob, _mk) = ec_dr_decrypt(
            &bob,
            &hdr,
            MAX_SKIP,
            Some(&bob_priv1),
            MAX_MKSKIPPED_RETAINED,
        )
        .unwrap();
        bob.nr = u32::MAX;
        bob.ckr = Some([0x55; 32]);
        bob.dhr_pub = Some(hdr.dh_pub);
        let err = ec_dr_decrypt(
            &bob,
            &EcDrHeader {
                dh_pub: hdr.dh_pub,
                pn: 0,
                n: u32::MAX,
            },
            MAX_SKIP,
            None,
            MAX_MKSKIPPED_RETAINED,
        )
        .unwrap_err();
        assert!(err.contains("ec_nr overflow"), "{err}");
    }
}
