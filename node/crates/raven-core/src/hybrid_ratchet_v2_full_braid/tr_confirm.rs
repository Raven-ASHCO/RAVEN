//! Nested TR AEAD confirm (design §§4.4–4.6, 7).
//!
//! Builds length-delimited AEAD AD from RVBA1‖RVCH1‖RVBC1, enforces mode0/mode1
//! body caps, rejects all-zero DH shared secrets as `TR_CONFIRM`, and seals /
//! opens with `KDF_HYBRID` + ChaCha20-Poly1305. The engine maps every confirm
//! error to a no-commit Reject (ATSAM §4.2 step 7); the RVBC1 in the AD is the
//! encapsulator's first CT1 frame on both sides, so each hybrid key seals once.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::hybrid_ratchet_v2::{kdf_hybrid, MAX_SKIP, PROFILE, SEALED_PROTO};
use crate::hybrid_ratchet_v2_full_braid::state_codec::Rvfb1State;
use crate::hybrid_ratchet_v2_full_braid::wire_rvbc1::{
    decode_rvbc1, encode_rvbc1, Rvbc1, RVBC1_MAX_LEN, RVBC1_MIN_LEN,
};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbi1::{Rvbi1, OP_RECEIVE, OP_SEND};
use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::{
    BRAID_MAX_AEAD_CIPHERTEXT_BYTES, BRAID_MAX_AEAD_PLAINTEXT_BYTES,
    BRAID_MIN_AEAD_CIPHERTEXT_BYTES, MODE_OPEN, MODE_SEAL_COMPARE, RVBA1_LEN,
};
use crate::hybrid_ratchet_v2_full_braid::wire_rvch1::{
    decode_rvch1, encode_rvch1, Rvch1, RVCH1_LEN,
};
use crate::hybrid_ratchet_v2_full_braid::wire_rvft1::{EcSkippedEntry, Rvft1, MAX_EC_SKIPPED};
use crate::hybrid_ratchet_v2_full_braid::wire_util::{
    expect_magic, read_array32, read_u8, reject_trailing, write_array32, write_bytes, write_u16be,
    write_u32be, write_u8, WireResult,
};
use crate::hybrid_ratchet_v2_tr::{
    ec_dr_decrypt, ec_dr_encrypt, x25519_dh, x25519_public, EcDrHeader, EcDrState,
};

type HmacSha256 = Hmac<Sha256>;

pub const RVBA1_MAGIC: &[u8; 8] = b"RVBA1\0\0\0";
pub const RVBA1_SCHEMA: u16 = 1;
pub const SEALED_PROTO_U16: u16 = 0x0004;
pub const SUITE_V1: u16 = 1;
pub const TRANSCRIPT_ADDR_DOMAIN: &[u8] = b"ATSAM/v2/full-braid/transcript-addr";
/// Same value as `transition::TERMINAL_REASON_TR_CONFIRM` (avoid module cycles).
pub const TERMINAL_REASON_TR_CONFIRM: u16 = 5;

const _: () = assert!(SEALED_PROTO as u16 == SEALED_PROTO_U16);
const _: () = assert!(RVBA1_LEN == 176);

/// `Parse`: malformed/inconsistent confirm input. `TrConfirm`: cryptographic
/// confirm failure (DH, skip budget, AEAD). Both are no-commit rejections in
/// the engine; neither terminalizes the session (ATSAM §4.2 step 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrConfirmError {
    Parse,
    TrConfirm,
}

/// `SHA-256("ATSAM/hybrid-ratchet/v2")`.
pub fn profile_id_digest() -> [u8; 32] {
    Sha256::digest(PROFILE).into()
}

/// `SHA-256("ATSAM/v2/full-braid/transcript-addr" || session_id || party || cert || identity_pub)`.
pub fn transcript_addr_binding(
    session_id: &[u8; 32],
    party: u8,
    cert_digest: &[u8; 32],
    identity_pub: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TRANSCRIPT_ADDR_DOMAIN);
    h.update(session_id);
    h.update([party]);
    h.update(cert_digest);
    h.update(identity_pub);
    h.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rvba1 {
    pub profile_id: [u8; 32],
    pub session_id: [u8; 32],
    pub suite: u16,
    pub sealed_proto: u16,
    pub direction: u8,
    pub initiator_binding: [u8; 32],
    pub responder_binding: [u8; 32],
    pub sender_device_cert_digest: [u8; 32],
}

impl Rvba1 {
    pub fn build(
        session_id: [u8; 32],
        direction: u8,
        initiator_cert: [u8; 32],
        initiator_identity_pub: [u8; 32],
        responder_cert: [u8; 32],
        responder_identity_pub: [u8; 32],
    ) -> Result<Self, TrConfirmError> {
        if direction > 1 {
            return Err(TrConfirmError::Parse);
        }
        let initiator_binding =
            transcript_addr_binding(&session_id, 0x00, &initiator_cert, &initiator_identity_pub);
        let responder_binding =
            transcript_addr_binding(&session_id, 0x01, &responder_cert, &responder_identity_pub);
        let sender_device_cert_digest = if direction == 0 {
            initiator_cert
        } else {
            responder_cert
        };
        Ok(Self {
            profile_id: profile_id_digest(),
            session_id,
            suite: SUITE_V1,
            sealed_proto: SEALED_PROTO_U16,
            direction,
            initiator_binding,
            responder_binding,
            sender_device_cert_digest,
        })
    }
}

pub fn encode_rvba1(record: &Rvba1) -> WireResult<Vec<u8>> {
    if record.suite != SUITE_V1
        || record.sealed_proto != SEALED_PROTO_U16
        || record.direction > 1
        || record.profile_id != profile_id_digest()
    {
        return Err("rvba1 fields".into());
    }
    let mut out = Vec::with_capacity(RVBA1_LEN);
    write_bytes(&mut out, RVBA1_MAGIC);
    write_u16be(&mut out, RVBA1_SCHEMA);
    write_array32(&mut out, &record.profile_id);
    write_array32(&mut out, &record.session_id);
    write_u16be(&mut out, record.suite);
    write_u16be(&mut out, record.sealed_proto);
    write_u8(&mut out, record.direction);
    write_u8(&mut out, 0);
    write_array32(&mut out, &record.initiator_binding);
    write_array32(&mut out, &record.responder_binding);
    write_array32(&mut out, &record.sender_device_cert_digest);
    debug_assert_eq!(out.len(), RVBA1_LEN);
    Ok(out)
}

pub fn decode_rvba1(data: &[u8]) -> WireResult<Rvba1> {
    if data.len() != RVBA1_LEN {
        return Err("rvba1 length".into());
    }
    expect_magic(data, RVBA1_MAGIC)?;
    let mut off = 8;
    let schema = crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)?;
    if schema != RVBA1_SCHEMA {
        return Err("rvba1 schema".into());
    }
    let profile_id = read_array32(data, &mut off)?;
    let session_id = read_array32(data, &mut off)?;
    let suite = crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)?;
    let sealed_proto = crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)?;
    let direction = read_u8(data, &mut off)?;
    let reserved0 = read_u8(data, &mut off)?;
    if reserved0 != 0 {
        return Err("rvba1 reserved0".into());
    }
    let initiator_binding = read_array32(data, &mut off)?;
    let responder_binding = read_array32(data, &mut off)?;
    let sender_device_cert_digest = read_array32(data, &mut off)?;
    reject_trailing(data, off)?;
    let record = Rvba1 {
        profile_id,
        session_id,
        suite,
        sealed_proto,
        direction,
        initiator_binding,
        responder_binding,
        sender_device_cert_digest,
    };
    encode_rvba1(&record)?;
    Ok(record)
}

/// `u32be_len(RVBA1)||RVBA1 || u32be_len(RVCH1)||RVCH1 || u32be_len(RVBC1)||RVBC1`.
pub fn build_effective_ad(
    rvba1_bytes: &[u8],
    rvch1_bytes: &[u8],
    rvbc1_bytes: &[u8],
) -> Result<Vec<u8>, TrConfirmError> {
    decode_rvba1(rvba1_bytes).map_err(|_| TrConfirmError::Parse)?;
    if rvch1_bytes.len() != RVCH1_LEN {
        return Err(TrConfirmError::Parse);
    }
    decode_rvch1(rvch1_bytes).map_err(|_| TrConfirmError::Parse)?;
    if !(RVBC1_MIN_LEN..=RVBC1_MAX_LEN).contains(&rvbc1_bytes.len()) {
        return Err(TrConfirmError::Parse);
    }
    decode_rvbc1(rvbc1_bytes).map_err(|_| TrConfirmError::Parse)?;

    let mut out =
        Vec::with_capacity(12 + rvba1_bytes.len() + rvch1_bytes.len() + rvbc1_bytes.len());
    write_u32be(&mut out, rvba1_bytes.len() as u32);
    write_bytes(&mut out, rvba1_bytes);
    write_u32be(&mut out, rvch1_bytes.len() as u32);
    write_bytes(&mut out, rvch1_bytes);
    write_u32be(&mut out, rvbc1_bytes.len() as u32);
    write_bytes(&mut out, rvbc1_bytes);
    Ok(out)
}

pub type EffectiveAdParts = (Vec<u8>, Vec<u8>, Vec<u8>);

pub fn parse_effective_ad(ad: &[u8]) -> Result<EffectiveAdParts, TrConfirmError> {
    let mut off = 0usize;
    let take = |data: &[u8], off: &mut usize| -> Result<Vec<u8>, TrConfirmError> {
        if *off + 4 > data.len() {
            return Err(TrConfirmError::Parse);
        }
        let len = u32::from_be_bytes(data[*off..*off + 4].try_into().unwrap()) as usize;
        *off += 4;
        if *off + len > data.len() {
            return Err(TrConfirmError::Parse);
        }
        let slice = data[*off..*off + len].to_vec();
        *off += len;
        Ok(slice)
    };
    let rvba1 = take(ad, &mut off)?;
    let rvch1 = take(ad, &mut off)?;
    let rvbc1 = take(ad, &mut off)?;
    if off != ad.len() {
        return Err(TrConfirmError::Parse);
    }
    // Re-validate through builder (byte-exact contracts).
    let rebuilt = build_effective_ad(&rvba1, &rvch1, &rvbc1)?;
    if rebuilt != ad {
        return Err(TrConfirmError::Parse);
    }
    Ok((rvba1, rvch1, rvbc1))
}

/// Mode0 PT ≤ 8192; mode1 CT ∈ [16, 8208]. Oversized mode max → PARSE.
pub fn validate_mode_body_caps(mode: u8, body_len: usize) -> Result<(), TrConfirmError> {
    match mode {
        MODE_SEAL_COMPARE => {
            if body_len > BRAID_MAX_AEAD_PLAINTEXT_BYTES {
                return Err(TrConfirmError::Parse);
            }
        }
        MODE_OPEN => {
            if !(BRAID_MIN_AEAD_CIPHERTEXT_BYTES..=BRAID_MAX_AEAD_CIPHERTEXT_BYTES)
                .contains(&body_len)
            {
                return Err(TrConfirmError::Parse);
            }
        }
        _ => return Err(TrConfirmError::Parse),
    }
    Ok(())
}

/// Send ⇒ mode0; Receive ⇒ mode1 (design §4.6 / §5.2).
pub fn expected_mode_for_op(op: u8) -> Result<u8, TrConfirmError> {
    match op {
        OP_SEND => Ok(MODE_SEAL_COMPARE),
        OP_RECEIVE => Ok(MODE_OPEN),
        _ => Err(TrConfirmError::Parse),
    }
}

/// Reject non-contributory / all-zero DH shared secrets as `TR_CONFIRM`.
pub fn contributory_dh(sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; 32], TrConfirmError> {
    let ss = x25519_dh(sk, pk).map_err(|_| TrConfirmError::TrConfirm)?;
    if ss == [0u8; 32] {
        return Err(TrConfirmError::TrConfirm);
    }
    Ok(ss)
}

/// Constant-time equality after callers enforce equal lengths.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    ct_eq(a, b)
}

/// Build the local send-side RVCH1 snapshot from canonical TR state.
pub fn rvch1_from_send_state(
    tr: &Rvft1,
    direction: u8,
    scka_epoch: u64,
) -> Result<Rvch1, TrConfirmError> {
    if direction > 1 {
        return Err(TrConfirmError::Parse);
    }
    let scka_n = tr
        .scka_send_chain
        .iter()
        .find(|entry| entry.epoch == scka_epoch)
        .map(|entry| entry.n)
        .unwrap_or(0);
    Ok(Rvch1 {
        ec_dh_pub: tr.ec_dhs_pub,
        ec_pn: tr.ec_pn,
        ec_n: tr.ec_ns,
        scka_epoch,
        scka_pn: tr.scka_send_pn,
        scka_n,
        direction,
    })
}

/// Host-admitted certificate/identity evidence used to rebuild RVBA1 bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedTrustEvidence {
    pub initiator_cert_digest: [u8; 32],
    pub initiator_identity_pub: [u8; 32],
    pub responder_cert_digest: [u8; 32],
    pub responder_identity_pub: [u8; 32],
}

impl AdmittedTrustEvidence {
    /// Lab default materials (matches Task 10 AEAD fixtures).
    pub const fn lab_default() -> Self {
        Self {
            initiator_cert_digest: [0x21; 32],
            initiator_identity_pub: [0x22; 32],
            responder_cert_digest: [0x31; 32],
            responder_identity_pub: [0x32; 32],
        }
    }
}

/// AEAD confirm outputs placed into RVBO1 on Send `needs_aead=1`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfirmOutputs {
    pub ch_out: Option<Rvch1>,
    pub sealed_ct: Option<Vec<u8>>,
}

/// Admit RVBA1 by rebuilding bindings from trust-admitted cert/identity evidence.
pub fn validate_rvba1_admitted(
    rvba1: &Rvba1,
    session_id: &[u8; 32],
    direction: u8,
    evidence: &AdmittedTrustEvidence,
) -> Result<(), TrConfirmError> {
    let expected = Rvba1::build(
        *session_id,
        direction,
        evidence.initiator_cert_digest,
        evidence.initiator_identity_pub,
        evidence.responder_cert_digest,
        evidence.responder_identity_pub,
    )?;
    if rvba1.session_id != expected.session_id
        || rvba1.direction != expected.direction
        || rvba1.profile_id != expected.profile_id
        || rvba1.suite != expected.suite
        || rvba1.sealed_proto != expected.sealed_proto
        || !ct_eq32(&rvba1.initiator_binding, &expected.initiator_binding)
        || !ct_eq32(&rvba1.responder_binding, &expected.responder_binding)
        || !ct_eq32(
            &rvba1.sender_device_cert_digest,
            &expected.sender_device_cert_digest,
        )
    {
        return Err(TrConfirmError::Parse);
    }
    Ok(())
}

/// `HMAC-SHA256(ec_dh_seed, "ATSAM/v2/full-braid/ec-dh-seed"||session_id||generation)`.
pub fn materialize_ec_dh_priv(
    ec_dh_seed: &[u8; 32],
    session_id: &[u8; 32],
    generation: u64,
) -> Result<[u8; 32], TrConfirmError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(ec_dh_seed).expect("HMAC accepts 32-byte keys");
    mac.update(b"ATSAM/v2/full-braid/ec-dh-seed");
    mac.update(session_id);
    mac.update(&generation.to_be_bytes());
    let mat_arr: [u8; 32] = mac.finalize().into_bytes()[..32]
        .try_into()
        .expect("HMAC-SHA256 is 32 bytes");
    let mat = Zeroizing::new(mat_arr);
    let mut priv_bytes = Zeroizing::new([0u8; 32]);
    priv_bytes.copy_from_slice(mat.as_ref());
    // Reject unusable / all-zero private material before DH ratchet.
    x25519_public(&priv_bytes).map_err(|_| TrConfirmError::TrConfirm)?;
    Ok(*priv_bytes)
}

fn rvft1_to_ec_dr(tr: &Rvft1) -> EcDrState {
    let mut mkskipped = std::collections::BTreeMap::new();
    for entry in &tr.ec_skipped {
        let mut key = [0u8; 36];
        key[..32].copy_from_slice(&entry.dh_pub);
        key[32..].copy_from_slice(&entry.n.to_be_bytes());
        mkskipped.insert(key, entry.mk);
    }
    EcDrState {
        rk: tr.ec_rk,
        dhs_priv: tr.ec_dhs_priv,
        dhs_pub: tr.ec_dhs_pub,
        dhr_pub: if tr.ec_dhr_present == 1 {
            Some(tr.ec_dhr_pub)
        } else {
            None
        },
        cks: if tr.ec_ck_send_present == 1 {
            Some(tr.ec_ck_send)
        } else {
            None
        },
        ckr: if tr.ec_ck_recv_present == 1 {
            Some(tr.ec_ck_recv)
        } else {
            None
        },
        ns: tr.ec_ns,
        nr: tr.ec_nr,
        pn: tr.ec_pn,
        mkskipped,
    }
}

fn apply_ec_dr_to_rvft1(tr: &mut Rvft1, ec: &EcDrState) {
    tr.ec_rk = ec.rk;
    tr.ec_dhs_priv = ec.dhs_priv;
    tr.ec_dhs_pub = ec.dhs_pub;
    match ec.dhr_pub {
        Some(pub_key) => {
            tr.ec_dhr_present = 1;
            tr.ec_dhr_pub = pub_key;
        }
        None => {
            tr.ec_dhr_present = 0;
            tr.ec_dhr_pub = [0u8; 32];
        }
    }
    match ec.cks {
        Some(ck) => {
            tr.ec_ck_send_present = 1;
            tr.ec_ck_send = ck;
        }
        None => {
            tr.ec_ck_send_present = 0;
            tr.ec_ck_send = [0u8; 32];
        }
    }
    match ec.ckr {
        Some(ck) => {
            tr.ec_ck_recv_present = 1;
            tr.ec_ck_recv = ck;
        }
        None => {
            tr.ec_ck_recv_present = 0;
            tr.ec_ck_recv = [0u8; 32];
        }
    }
    tr.ec_ns = ec.ns;
    tr.ec_nr = ec.nr;
    tr.ec_pn = ec.pn;
    tr.ec_skipped = ec
        .mkskipped
        .iter()
        .map(|(key, mk)| EcSkippedEntry {
            dh_pub: key[..32].try_into().expect("32"),
            n: u32::from_be_bytes(key[32..].try_into().expect("4")),
            mk: *mk,
        })
        .collect();
}

/// Cross-validate RVCH1 vs role/op, optional `expected_ch`, chain counters, and frame.
#[allow(clippy::too_many_arguments)]
pub fn validate_rvch1_context(
    ch: &Rvch1,
    expected_ch: Option<&Rvch1>,
    tr: &Rvft1,
    role: u8,
    op: u8,
    session_id: &[u8; 32],
    frame: Option<&Rvbc1>,
    scka_confirm_epoch: u64,
) -> Result<(), TrConfirmError> {
    let expected_dir = match (role, op) {
        (0, OP_SEND) | (1, OP_RECEIVE) => 0u8,
        (1, OP_SEND) | (0, OP_RECEIVE) => 1u8,
        _ => return Err(TrConfirmError::Parse),
    };
    if ch.direction != expected_dir {
        return Err(TrConfirmError::Parse);
    }
    if let Some(exp) = expected_ch {
        if ch != exp {
            return Err(TrConfirmError::Parse);
        }
    }
    if let Some(chunk) = frame {
        chunk
            .verify_binding(ch.direction, session_id)
            .map_err(|_| TrConfirmError::Parse)?;
    }
    match op {
        OP_SEND => {
            let local = rvch1_from_send_state(tr, expected_dir, scka_confirm_epoch)?;
            if ch.ec_dh_pub != local.ec_dh_pub
                || ch.ec_pn != local.ec_pn
                || ch.ec_n != local.ec_n
                || ch.scka_epoch != local.scka_epoch
                || ch.scka_pn != local.scka_pn
                || ch.scka_n != local.scka_n
            {
                return Err(TrConfirmError::Parse);
            }
        }
        OP_RECEIVE => {
            if ch.scka_epoch != scka_confirm_epoch {
                return Err(TrConfirmError::Parse);
            }
            if tr.ec_dhr_present == 1 && ch.ec_dh_pub == tr.ec_dhr_pub {
                // Same peer DH: counters must not rewind past the committed recv chain.
                if ch.ec_n < tr.ec_nr {
                    return Err(TrConfirmError::Parse);
                }
            }
        }
        _ => return Err(TrConfirmError::Parse),
    }
    Ok(())
}

/// Advance the EC Double Ratchet on a candidate and return `(candidate, mk, header)`.
///
/// Does not mutate durable TR state; caller commits only after AEAD success.
pub fn advance_ec_candidate(
    tr: &Rvft1,
    op: u8,
    header: &EcDrHeader,
    new_local_dh_priv: Option<&[u8; 32]>,
) -> Result<(EcDrState, [u8; 32]), TrConfirmError> {
    let current = rvft1_to_ec_dr(tr);
    match op {
        OP_SEND => {
            let (next, enc_header, mk) =
                ec_dr_encrypt(&current).map_err(|_| TrConfirmError::TrConfirm)?;
            if enc_header.dh_pub != header.dh_pub
                || enc_header.pn != header.pn
                || enc_header.n != header.n
            {
                return Err(TrConfirmError::Parse);
            }
            Ok((next, mk))
        }
        OP_RECEIVE => {
            // Retain at most what RVFT1 can encode: a larger skipped map would
            // pass the AEAD and then fail canonical encoding on every retry.
            let (next, mk) = ec_dr_decrypt(
                &current,
                header,
                MAX_SKIP,
                new_local_dh_priv,
                MAX_EC_SKIPPED,
            )
            .map_err(|err| {
                if err.contains("MAX_SKIP")
                    || err.contains("MAX_MKSKIPPED")
                    || err.contains("non-contributory")
                    || err.contains("all-zero")
                    || err.contains("invalid X25519")
                    || err.contains("ec_ns overflow")
                    || err.contains("ec_nr overflow")
                {
                    TrConfirmError::TrConfirm
                } else if err.contains("new_local_priv") {
                    TrConfirmError::Parse
                } else {
                    TrConfirmError::TrConfirm
                }
            })?;
            Ok((next, mk))
        }
        _ => Err(TrConfirmError::Parse),
    }
}

fn check_ec_mk_oracle(
    ec_mk: &[u8; 32],
    oracle_len: u16,
    oracle: &[u8; 32],
) -> Result<(), TrConfirmError> {
    match oracle_len {
        0 => {
            if *oracle != [0u8; 32] {
                return Err(TrConfirmError::Parse);
            }
            Ok(())
        }
        32 => {
            if !ct_eq32(ec_mk, oracle) {
                return Err(TrConfirmError::TrConfirm);
            }
            Ok(())
        }
        _ => Err(TrConfirmError::Parse),
    }
}

fn aead_cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

/// Mode0 seal_compare: seal `plaintext` under `KDF_HYBRID`, require exact `expected_ct`,
/// and return the authenticated ciphertext for RVBO1.
pub fn seal_compare(
    ec_mk: &[u8; 32],
    scka_mk: &[u8; 32],
    effective_ad: &[u8],
    plaintext: &[u8],
    expected_ct: &[u8],
    oracle_len: u16,
    oracle: &[u8; 32],
) -> Result<Vec<u8>, TrConfirmError> {
    validate_mode_body_caps(MODE_SEAL_COMPARE, plaintext.len())?;
    if expected_ct.len()
        != plaintext
            .len()
            .checked_add(16)
            .ok_or(TrConfirmError::Parse)?
    {
        return Err(TrConfirmError::Parse);
    }
    check_ec_mk_oracle(ec_mk, oracle_len, oracle)?;
    let (key_raw, nonce_raw) = kdf_hybrid(ec_mk, scka_mk);
    let key = Zeroizing::new(key_raw);
    let nonce = Zeroizing::new(nonce_raw);
    let cipher = aead_cipher(&key);
    let sealed = match cipher.encrypt(
        Nonce::from_slice(nonce.as_ref()),
        Payload {
            msg: plaintext,
            aad: effective_ad,
        },
    ) {
        Ok(bytes) => bytes,
        Err(_) => return Err(TrConfirmError::TrConfirm),
    };
    if !ct_eq(&sealed, expected_ct) {
        return Err(TrConfirmError::TrConfirm);
    }
    Ok(sealed)
}

/// Mode1 open: decrypt ciphertext; opened PT > 8192 → `TR_CONFIRM`.
///
/// The opened application body is wiped on drop (including the oversize
/// rejection below); the pipeline only needs the tag/length check.
pub fn open_confirm(
    ec_mk: &[u8; 32],
    scka_mk: &[u8; 32],
    effective_ad: &[u8],
    ciphertext: &[u8],
    oracle_len: u16,
    oracle: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, TrConfirmError> {
    validate_mode_body_caps(MODE_OPEN, ciphertext.len())?;
    check_ec_mk_oracle(ec_mk, oracle_len, oracle)?;
    let (key_raw, nonce_raw) = kdf_hybrid(ec_mk, scka_mk);
    let key = Zeroizing::new(key_raw);
    let nonce = Zeroizing::new(nonce_raw);
    let cipher = aead_cipher(&key);
    let plaintext = Zeroizing::new(
        match cipher.decrypt(
            Nonce::from_slice(nonce.as_ref()),
            Payload {
                msg: ciphertext,
                aad: effective_ad,
            },
        ) {
            Ok(bytes) => bytes,
            Err(_) => return Err(TrConfirmError::TrConfirm),
        },
    );
    if plaintext.len() > BRAID_MAX_AEAD_PLAINTEXT_BYTES {
        return Err(TrConfirmError::TrConfirm);
    }
    Ok(plaintext)
}

/// Run the §7 TR hook for `needs_aead=1` before SCKA promotion.
///
/// Advances EC Double Ratchet on a candidate; commits into `state.tr` only after
/// AEAD success. Send returns exact `RVCH1 + sealed_ct` for RVBO1.
#[allow(clippy::too_many_arguments)]
pub fn confirm_before_scka_promote(
    state: &mut Rvfb1State,
    input: &Rvbi1,
    frame: &Rvbc1,
    scka_mk: &[u8; 32],
    scka_confirm_epoch: u64,
    evidence: &AdmittedTrustEvidence,
    new_local_dh_priv: Option<&[u8; 32]>,
) -> Result<ConfirmOutputs, TrConfirmError> {
    let mutation = &input.mutation;
    if mutation.needs_aead != 1 {
        return Err(TrConfirmError::Parse);
    }
    let expected_mode = expected_mode_for_op(input.op)?;
    if mutation.mode != expected_mode {
        return Err(TrConfirmError::Parse);
    }
    let rvba1 = decode_rvba1(&mutation.aad).map_err(|_| TrConfirmError::Parse)?;
    validate_rvba1_admitted(&rvba1, &state.prefix.session_id, input.direction, evidence)?;

    let ch = match input.op {
        OP_SEND => rvch1_from_send_state(&state.tr, input.direction, scka_confirm_epoch)?,
        OP_RECEIVE => input.ch.clone().ok_or(TrConfirmError::Parse)?,
        _ => return Err(TrConfirmError::Parse),
    };
    validate_rvch1_context(
        &ch,
        input.expected_ch.as_ref(),
        &state.tr,
        state.prefix.role,
        input.op,
        &state.prefix.session_id,
        Some(frame),
        scka_confirm_epoch,
    )?;

    let rvba1_bytes = encode_rvba1(&rvba1).map_err(|_| TrConfirmError::Parse)?;
    let rvch1_bytes = encode_rvch1(&ch);
    let rvbc1_bytes = encode_rvbc1(frame).map_err(|_| TrConfirmError::Parse)?;
    let ad = build_effective_ad(&rvba1_bytes, &rvch1_bytes, &rvbc1_bytes)?;

    let header = EcDrHeader {
        dh_pub: ch.ec_dh_pub,
        pn: ch.ec_pn,
        n: ch.ec_n,
    };
    let (ec_candidate, mut ec_mk) =
        advance_ec_candidate(&state.tr, input.op, &header, new_local_dh_priv)?;

    let result = match input.op {
        OP_SEND => {
            let expected_ct = mutation.expected_ct.as_ref().ok_or(TrConfirmError::Parse)?;
            seal_compare(
                &ec_mk,
                scka_mk,
                &ad,
                &mutation.body,
                expected_ct,
                mutation.ec_mk_oracle_len,
                &mutation.ec_mk_oracle,
            )
            .map(|sealed| ConfirmOutputs {
                ch_out: Some(ch.clone()),
                sealed_ct: Some(sealed),
            })
        }
        OP_RECEIVE => open_confirm(
            &ec_mk,
            scka_mk,
            &ad,
            &mutation.body,
            mutation.ec_mk_oracle_len,
            &mutation.ec_mk_oracle,
        )
        .map(|_| ConfirmOutputs::default()),
        _ => Err(TrConfirmError::Parse),
    };
    ec_mk.zeroize();
    let outputs = result?;
    // Commit EC candidate only after AEAD success.
    apply_ec_dr_to_rvft1(&mut state.tr, &ec_candidate);
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_ratchet_v2_full_braid::digest::binding_digest;
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbc1::encode_rvbc1;
    use crate::hybrid_ratchet_v2_full_braid::wire_rvch1::encode_rvch1;
    use crate::hybrid_ratchet_v2_tr::x25519_public;

    fn sample_rvba1(direction: u8) -> (Rvba1, Vec<u8>) {
        let record = Rvba1::build(
            [0x11; 32], direction, [0x21; 32], [0x22; 32], [0x31; 32], [0x32; 32],
        )
        .unwrap();
        let bytes = encode_rvba1(&record).unwrap();
        (record, bytes)
    }

    fn sample_rvch1(direction: u8) -> (Rvch1, Vec<u8>) {
        let ch = Rvch1 {
            ec_dh_pub: [0x41; 32],
            ec_pn: 1,
            ec_n: 2,
            scka_epoch: 3,
            scka_pn: 4,
            scka_n: 5,
            direction,
        };
        (ch.clone(), encode_rvch1(&ch))
    }

    fn sample_rvbc1(direction: u8, session_id: &[u8; 32]) -> (Rvbc1, Vec<u8>) {
        let payload = vec![0x55; 32];
        let binding = binding_digest(direction, 7, 1, 0, &payload, session_id);
        let chunk = Rvbc1 {
            epoch: 7,
            chunk_type: 1,
            index: 0,
            payload,
            binding_digest: binding,
        };
        let bytes = encode_rvbc1(&chunk).unwrap();
        (chunk, bytes)
    }

    #[test]
    fn rvba1_is_exactly_176_and_bindings_match_domain() {
        let (record, bytes) = sample_rvba1(0);
        assert_eq!(bytes.len(), RVBA1_LEN);
        assert_eq!(decode_rvba1(&bytes).unwrap(), record);
        assert_eq!(
            record.initiator_binding,
            transcript_addr_binding(&[0x11; 32], 0x00, &[0x21; 32], &[0x22; 32])
        );
        assert_eq!(
            record.responder_binding,
            transcript_addr_binding(&[0x11; 32], 0x01, &[0x31; 32], &[0x32; 32])
        );
        assert_eq!(record.sender_device_cert_digest, [0x21; 32]);
        assert_eq!(record.profile_id, profile_id_digest());
        assert_eq!(record.sealed_proto, SEALED_PROTO_U16);
    }

    #[test]
    fn effective_ad_is_length_delimited_rvba_rvch_rvbc() {
        let session = [0x11; 32];
        let (_, rvba1) = sample_rvba1(0);
        let (_, rvch1) = sample_rvch1(0);
        let (_, rvbc1) = sample_rvbc1(0, &session);
        let ad = build_effective_ad(&rvba1, &rvch1, &rvbc1).unwrap();
        assert_eq!(&ad[0..4], &(RVBA1_LEN as u32).to_be_bytes());
        assert_eq!(&ad[4..4 + RVBA1_LEN], rvba1.as_slice());
        let ch_off = 4 + RVBA1_LEN;
        assert_eq!(&ad[ch_off..ch_off + 4], &(RVCH1_LEN as u32).to_be_bytes());
        assert_eq!(&ad[ch_off + 4..ch_off + 4 + RVCH1_LEN], rvch1.as_slice());
        let bc_off = ch_off + 4 + RVCH1_LEN;
        assert_eq!(&ad[bc_off..bc_off + 4], &(rvbc1.len() as u32).to_be_bytes());
        assert_eq!(&ad[bc_off + 4..], rvbc1.as_slice());
        let (a, b, c) = parse_effective_ad(&ad).unwrap();
        assert_eq!(a, rvba1);
        assert_eq!(b, rvch1);
        assert_eq!(c, rvbc1);
    }

    #[test]
    fn mode_body_caps_parse_and_expected_modes() {
        assert_eq!(expected_mode_for_op(OP_SEND).unwrap(), MODE_SEAL_COMPARE);
        assert_eq!(expected_mode_for_op(OP_RECEIVE).unwrap(), MODE_OPEN);
        assert!(validate_mode_body_caps(MODE_SEAL_COMPARE, 8192).is_ok());
        assert_eq!(
            validate_mode_body_caps(MODE_SEAL_COMPARE, 8193).unwrap_err(),
            TrConfirmError::Parse
        );
        assert!(validate_mode_body_caps(MODE_OPEN, 16).is_ok());
        assert!(validate_mode_body_caps(MODE_OPEN, 8208).is_ok());
        assert_eq!(
            validate_mode_body_caps(MODE_OPEN, 15).unwrap_err(),
            TrConfirmError::Parse
        );
        assert_eq!(
            validate_mode_body_caps(MODE_OPEN, 8209).unwrap_err(),
            TrConfirmError::Parse
        );
    }

    #[test]
    fn zero_dh_shared_secret_is_tr_confirm() {
        let sk = [0x42; 32];
        assert_eq!(
            contributory_dh(&sk, &[0u8; 32]).unwrap_err(),
            TrConfirmError::TrConfirm
        );
        let pk = x25519_public(&[0x77; 32]).unwrap();
        assert_ne!(contributory_dh(&sk, &pk).unwrap(), [0u8; 32]);
    }

    #[test]
    fn seal_compare_and_open_roundtrip_under_effective_ad() {
        let session = [0x11; 32];
        let (_, rvba1) = sample_rvba1(0);
        let (_, rvch1) = sample_rvch1(0);
        let (_, rvbc1) = sample_rvbc1(0, &session);
        let ad = build_effective_ad(&rvba1, &rvch1, &rvbc1).unwrap();
        let ec_mk = [0x91; 32];
        let scka_mk = [0x92; 32];
        let plaintext = b"full-braid-tr-confirm".to_vec();
        let (key, nonce) = kdf_hybrid(&ec_mk, &scka_mk);
        let expected = ChaCha20Poly1305::new((&key).into())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &ad,
                },
            )
            .unwrap();
        seal_compare(&ec_mk, &scka_mk, &ad, &plaintext, &expected, 32, &ec_mk).unwrap();
        assert_eq!(
            seal_compare(
                &ec_mk,
                &scka_mk,
                &ad,
                &plaintext,
                &expected,
                32,
                &[0x00; 32],
            )
            .unwrap_err(),
            TrConfirmError::TrConfirm
        );
        let opened = open_confirm(&ec_mk, &scka_mk, &ad, &expected, 0, &[0u8; 32]).unwrap();
        assert_eq!(*opened, plaintext);
        let mut bad = expected.clone();
        bad[0] ^= 1;
        assert_eq!(
            open_confirm(&ec_mk, &scka_mk, &ad, &bad, 0, &[0u8; 32]).unwrap_err(),
            TrConfirmError::TrConfirm
        );
    }

    #[test]
    fn open_accepts_max_8192_plaintext_and_rejects_oversize_ct_as_parse() {
        let session = [0x11; 32];
        let (_, rvba1) = sample_rvba1(0);
        let (_, rvch1) = sample_rvch1(0);
        let (_, rvbc1) = sample_rvbc1(0, &session);
        let ad = build_effective_ad(&rvba1, &rvch1, &rvbc1).unwrap();
        let ec_mk = [0xA1; 32];
        let scka_mk = [0xA2; 32];
        let max_pt = vec![0xAB; BRAID_MAX_AEAD_PLAINTEXT_BYTES];
        let (key, nonce) = kdf_hybrid(&ec_mk, &scka_mk);
        let ct = ChaCha20Poly1305::new((&key).into())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &max_pt,
                    aad: &ad,
                },
            )
            .unwrap();
        assert_eq!(ct.len(), BRAID_MAX_AEAD_CIPHERTEXT_BYTES);
        assert_eq!(
            *open_confirm(&ec_mk, &scka_mk, &ad, &ct, 0, &[0u8; 32]).unwrap(),
            max_pt
        );
        let mut oversize_ct = ct.clone();
        oversize_ct.push(0);
        assert_eq!(
            open_confirm(&ec_mk, &scka_mk, &ad, &oversize_ct, 0, &[0u8; 32]).unwrap_err(),
            TrConfirmError::Parse
        );
    }

    #[test]
    fn rvch1_role_direction_and_frame_binding() {
        let session = [0x11; 32];
        let mut tr = Rvft1 {
            scka_rk: [0; 32],
            scka_sending_epoch: 0,
            scka_receiving_epoch: 0,
            scka_send_chain: Vec::new(),
            scka_recv_chain: Vec::new(),
            scka_send_pn: 4,
            scka_skipped: Vec::new(),
            ec_rk: [0; 32],
            ec_dhs_priv: [0x22; 32],
            ec_dhs_pub: [0x41; 32],
            ec_dhr_present: 1,
            ec_dhr_pub: [0x42; 32],
            ec_ck_send_present: 1,
            ec_ck_recv_present: 0,
            ec_ck_send: [0x55; 32],
            ec_ck_recv: [0; 32],
            ec_ns: 2,
            ec_nr: 0,
            ec_pn: 1,
            ec_skipped: Vec::new(),
        };
        let (ch, _) = sample_rvch1(0);
        // Align sample header counters with the local send snapshot.
        let mut ch = ch;
        ch.ec_dh_pub = tr.ec_dhs_pub;
        ch.ec_pn = tr.ec_pn;
        ch.ec_n = tr.ec_ns;
        ch.scka_epoch = 3;
        ch.scka_pn = tr.scka_send_pn;
        ch.scka_n = 0;
        let (frame, _) = sample_rvbc1(0, &session);
        validate_rvch1_context(&ch, None, &tr, 0, OP_SEND, &session, Some(&frame), 3).unwrap();
        assert_eq!(
            validate_rvch1_context(&ch, None, &tr, 0, OP_RECEIVE, &session, Some(&frame), 3)
                .unwrap_err(),
            TrConfirmError::Parse
        );
        let mut bad_frame = frame.clone();
        bad_frame.binding_digest[0] ^= 1;
        assert_eq!(
            validate_rvch1_context(&ch, None, &tr, 0, OP_SEND, &session, Some(&bad_frame), 3)
                .unwrap_err(),
            TrConfirmError::Parse
        );
        let mut wrong = ch.clone();
        wrong.ec_n ^= 1;
        assert_eq!(
            validate_rvch1_context(&wrong, None, &tr, 0, OP_SEND, &session, Some(&frame), 3)
                .unwrap_err(),
            TrConfirmError::Parse
        );
        let expected = ch.clone();
        validate_rvch1_context(
            &ch,
            Some(&expected),
            &tr,
            0,
            OP_SEND,
            &session,
            Some(&frame),
            3,
        )
        .unwrap();
        let mut other = expected.clone();
        other.scka_n = 9;
        assert_eq!(
            validate_rvch1_context(
                &ch,
                Some(&other),
                &tr,
                0,
                OP_SEND,
                &session,
                Some(&frame),
                3,
            )
            .unwrap_err(),
            TrConfirmError::Parse
        );
        let _ = &mut tr;
    }

    #[test]
    fn rvba1_admitted_requires_exact_trust_evidence_rebuild() {
        let session = [0x11; 32];
        let evidence = AdmittedTrustEvidence::lab_default();
        let (record, _) = sample_rvba1(0);
        validate_rvba1_admitted(&record, &session, 0, &evidence).unwrap();
        let mut bad = evidence.clone();
        bad.initiator_cert_digest[0] ^= 1;
        assert_eq!(
            validate_rvba1_admitted(&record, &session, 0, &bad).unwrap_err(),
            TrConfirmError::Parse
        );
    }

    #[test]
    fn sequential_ec_send_advances_chain_counters() {
        let bob_pub = x25519_public(&[0x77; 32]).unwrap();
        let alice_priv = [0x42; 32];
        let alice_pub = x25519_public(&alice_priv).unwrap();
        let (rk, ck) = crate::hybrid_ratchet_v2::kdf_rk(
            &[0x11; 32],
            &contributory_dh(&alice_priv, &bob_pub).unwrap(),
        )
        .unwrap();
        let mut tr = Rvft1 {
            scka_rk: [0; 32],
            scka_sending_epoch: 0,
            scka_receiving_epoch: 0,
            scka_send_chain: Vec::new(),
            scka_recv_chain: Vec::new(),
            scka_send_pn: 0,
            scka_skipped: Vec::new(),
            ec_rk: rk,
            ec_dhs_priv: alice_priv,
            ec_dhs_pub: alice_pub,
            ec_dhr_present: 1,
            ec_dhr_pub: bob_pub,
            ec_ck_send_present: 1,
            ec_ck_recv_present: 0,
            ec_ck_send: ck,
            ec_ck_recv: [0; 32],
            ec_ns: 0,
            ec_nr: 0,
            ec_pn: 0,
            ec_skipped: Vec::new(),
        };
        let h0 = EcDrHeader {
            dh_pub: alice_pub,
            pn: 0,
            n: 0,
        };
        let (c1, mk0) = advance_ec_candidate(&tr, OP_SEND, &h0, None).unwrap();
        apply_ec_dr_to_rvft1(&mut tr, &c1);
        assert_eq!(tr.ec_ns, 1);
        let h1 = EcDrHeader {
            dh_pub: alice_pub,
            pn: 0,
            n: 1,
        };
        let (c2, mk1) = advance_ec_candidate(&tr, OP_SEND, &h1, None).unwrap();
        apply_ec_dr_to_rvft1(&mut tr, &c2);
        assert_eq!(tr.ec_ns, 2);
        assert_ne!(mk0, mk1);
        // Reusing n=0 against advanced state fails closed.
        assert!(advance_ec_candidate(&tr, OP_SEND, &h0, None).is_err());
    }

    #[test]
    fn ec_receive_new_dh_and_ooo_skipped_keys() {
        let bob_priv0 = [0x61; 32];
        let bob_pub0 = x25519_public(&bob_priv0).unwrap();
        let alice_priv0 = [0x62; 32];
        let alice_pub0 = x25519_public(&alice_priv0).unwrap();
        let (rk, ck) = crate::hybrid_ratchet_v2::kdf_rk(
            &[0x10; 32],
            &contributory_dh(&alice_priv0, &bob_pub0).unwrap(),
        )
        .unwrap();
        let mut alice = Rvft1 {
            scka_rk: [0; 32],
            scka_sending_epoch: 0,
            scka_receiving_epoch: 0,
            scka_send_chain: Vec::new(),
            scka_recv_chain: Vec::new(),
            scka_send_pn: 0,
            scka_skipped: Vec::new(),
            ec_rk: rk,
            ec_dhs_priv: alice_priv0,
            ec_dhs_pub: alice_pub0,
            ec_dhr_present: 1,
            ec_dhr_pub: bob_pub0,
            ec_ck_send_present: 1,
            ec_ck_recv_present: 0,
            ec_ck_send: ck,
            ec_ck_recv: [0; 32],
            ec_ns: 0,
            ec_nr: 0,
            ec_pn: 0,
            ec_skipped: Vec::new(),
        };
        let mut bob = Rvft1 {
            scka_rk: [0; 32],
            scka_sending_epoch: 0,
            scka_receiving_epoch: 0,
            scka_send_chain: Vec::new(),
            scka_recv_chain: Vec::new(),
            scka_send_pn: 0,
            scka_skipped: Vec::new(),
            ec_rk: [0x10; 32],
            ec_dhs_priv: bob_priv0,
            ec_dhs_pub: bob_pub0,
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
        };

        let h0 = EcDrHeader {
            dh_pub: alice_pub0,
            pn: 0,
            n: 0,
        };
        let (a1, mk0) = advance_ec_candidate(&alice, OP_SEND, &h0, None).unwrap();
        apply_ec_dr_to_rvft1(&mut alice, &a1);
        let h1 = EcDrHeader {
            dh_pub: alice_pub0,
            pn: 0,
            n: 1,
        };
        let (a2, mk1) = advance_ec_candidate(&alice, OP_SEND, &h1, None).unwrap();
        apply_ec_dr_to_rvft1(&mut alice, &a2);

        let bob_priv1 = [0x63; 32];
        // OOO: decrypt n=1 first (DH ratchet), then n=0 from skipped.
        let (b1, got1) = advance_ec_candidate(&bob, OP_RECEIVE, &h1, Some(&bob_priv1)).unwrap();
        apply_ec_dr_to_rvft1(&mut bob, &b1);
        assert_eq!(got1, mk1);
        assert!(!bob.ec_skipped.is_empty());
        let before_ns = bob.ec_ns;
        let (b2, got0) = advance_ec_candidate(&bob, OP_RECEIVE, &h0, None).unwrap();
        apply_ec_dr_to_rvft1(&mut bob, &b2);
        assert_eq!(got0, mk0);
        assert_eq!(bob.ec_ns, before_ns);
        assert!(bob.ec_skipped.is_empty());
    }

    #[test]
    fn receive_skip_budget_never_exceeds_rvft1_encodable_cap() {
        use crate::hybrid_ratchet_v2_full_braid::wire_rvft1::encode_rvft1;

        let bob_priv = [0x71; 32];
        let alice_old = x25519_public(&[0x72; 32]).unwrap();
        let alice_new = x25519_public(&[0x73; 32]).unwrap();
        let mut tr = Rvft1 {
            scka_rk: [0; 32],
            scka_sending_epoch: 0,
            scka_receiving_epoch: 0,
            scka_send_chain: Vec::new(),
            scka_recv_chain: Vec::new(),
            scka_send_pn: 0,
            scka_skipped: Vec::new(),
            ec_rk: [0x10; 32],
            ec_dhs_priv: bob_priv,
            ec_dhs_pub: x25519_public(&bob_priv).unwrap(),
            ec_dhr_present: 1,
            ec_dhr_pub: alice_old,
            ec_ck_send_present: 0,
            ec_ck_recv_present: 1,
            ec_ck_send: [0; 32],
            ec_ck_recv: [0x20; 32],
            ec_ns: 0,
            ec_nr: 0,
            ec_pn: 0,
            ec_skipped: Vec::new(),
        };
        // Each chain stays within MAX_SKIP, but together they need 1200
        // skipped keys: more than RVFT1 can persist. Fail before any AEAD.
        let header = EcDrHeader {
            dh_pub: alice_new,
            pn: 600,
            n: 600,
        };
        assert_eq!(
            advance_ec_candidate(&tr, OP_RECEIVE, &header, Some(&[0x74; 32])).unwrap_err(),
            TrConfirmError::TrConfirm
        );
        // At the cap the candidate always stays canonically encodable.
        let header = EcDrHeader {
            dh_pub: alice_new,
            pn: 500,
            n: 500,
        };
        let (candidate, _) =
            advance_ec_candidate(&tr, OP_RECEIVE, &header, Some(&[0x74; 32])).unwrap();
        apply_ec_dr_to_rvft1(&mut tr, &candidate);
        assert_eq!(tr.ec_skipped.len(), MAX_EC_SKIPPED);
        encode_rvft1(&tr).unwrap();
    }

    #[test]
    fn aead_failure_discards_ec_candidate_without_mutation() {
        use crate::hybrid_ratchet_v2_full_braid::state_codec::{
            Rvfb1Prefix, Rvfb1State, ROLE_ALICE,
        };
        let bob_pub = x25519_public(&[0x77; 32]).unwrap();
        let alice_priv = [0x42; 32];
        let alice_pub = x25519_public(&alice_priv).unwrap();
        let (rk, ck) = crate::hybrid_ratchet_v2::kdf_rk(
            &[0x11; 32],
            &contributory_dh(&alice_priv, &bob_pub).unwrap(),
        )
        .unwrap();
        let mut state = Rvfb1State {
            prefix: Rvfb1Prefix {
                session_id: [0x11; 32],
                role: ROLE_ALICE,
                generation: 0,
                agent: 0,
                terminal_reason: 0,
                auth_root: [0; 32],
                auth_mac_key: [0; 32],
                braid_agent_epoch: 1,
                braid_send_epoch: 0,
                braid_recv_epoch: 0,
                flags: 0,
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
            tlvs: Vec::new(),
            tr: Rvft1 {
                scka_rk: [0; 32],
                scka_sending_epoch: 0,
                scka_receiving_epoch: 0,
                scka_send_chain: Vec::new(),
                scka_recv_chain: Vec::new(),
                scka_send_pn: 0,
                scka_skipped: Vec::new(),
                ec_rk: rk,
                ec_dhs_priv: alice_priv,
                ec_dhs_pub: alice_pub,
                ec_dhr_present: 1,
                ec_dhr_pub: bob_pub,
                ec_ck_send_present: 1,
                ec_ck_recv_present: 0,
                ec_ck_send: ck,
                ec_ck_recv: [0; 32],
                ec_ns: 0,
                ec_nr: 0,
                ec_pn: 0,
                ec_skipped: Vec::new(),
            },
        };
        let before = state.tr.clone();
        let (frame, _) = sample_rvbc1(0, &state.prefix.session_id);
        let evidence = AdmittedTrustEvidence::lab_default();
        let rvba1 = Rvba1::build(
            state.prefix.session_id,
            0,
            evidence.initiator_cert_digest,
            evidence.initiator_identity_pub,
            evidence.responder_cert_digest,
            evidence.responder_identity_pub,
        )
        .unwrap();
        let body = b"fail-body".to_vec();
        let input = Rvbi1 {
            op: OP_SEND,
            direction: 0,
            ch: None,
            expected_ch: None,
            object_digest: None,
            frame: None,
            mutation: crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::Rvbm1 {
                needs_aead: 1,
                ec_mk_oracle_len: 0,
                ec_mk_oracle: [0u8; 32],
                aad: encode_rvba1(&rvba1).unwrap(),
                mode: MODE_SEAL_COMPARE,
                body: body.clone(),
                expected_ct: Some(vec![0u8; body.len() + 16]),
            },
        };
        assert_eq!(
            confirm_before_scka_promote(
                &mut state,
                &input,
                &frame,
                &[0x99; 32],
                0,
                &evidence,
                None,
            )
            .unwrap_err(),
            TrConfirmError::TrConfirm
        );
        assert_eq!(state.tr, before);
    }
}
