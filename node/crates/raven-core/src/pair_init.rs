//! Raven PairInit V1 — additive, production-disabled session transcript codec.
//!
//! This module freezes canonical bytes, verification, hybrid-root binding, and
//! deferred key confirmation for `ATSAM/indexed-session/v1`. It does not touch
//! networking or activate RVNA1 protocol `0x03`.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::address::encode_address;
use crate::atsam_indexed_session::{session_context, PROFILE_ID};
use crate::atsam_root::{
    derive_root, transcript_hash as atsam_transcript_hash, x25519_public_is_contributory,
};
use crate::device_cert::DeviceCertificate;
use crate::identity::Identity;
use crate::prekey_bundle::{PrekeyBundle, MLKEM768_EK_LEN};
use crate::prekey_lifecycle::MAX_PREKEY_FUTURE_SKEW_MS;
use crate::records::device_cert_signing_bytes;

pub const VERSION: u8 = 1;
pub const SUITE: u8 = 1;
/// Compile-time Release tripwire. Remains `false` so vector/unit asserts stay
/// honest. Lab Test A unlocks via [`lab_test_a_enabled`] (debug + env only).
pub const PRODUCTION_ENABLED: bool = false;

/// `RAVEN_LAB_TEST_A=1` in debug/dev builds only. Release binaries always false.
pub fn lab_test_a_enabled() -> bool {
    if !cfg!(debug_assertions) {
        return false;
    }
    match std::env::var("RAVEN_LAB_TEST_A") {
        Ok(v) => matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"),
        Err(_) => false,
    }
}

/// Generic PairInit live tripwire. LAN-direct must not flip this — it leaks
/// into contact-request and other non-LAN CLIs. LAN send uses
/// [`crate::lan_direct_live_enabled`] at the callsite instead.
pub fn live_enabled() -> bool {
    PRODUCTION_ENABLED || lab_test_a_enabled()
}
pub const INIT_MAGIC: [u8; 8] = *b"RVPI1\0\0\0";
pub const RESPONSE_MAGIC: [u8; 8] = *b"RVPR1\0\0\0";
pub const INIT_SIGNING_DOMAIN: &[u8] = b"rvn1/pair-init";
pub const RESPONSE_SIGNING_DOMAIN: &[u8] = b"rvn1/pair-response";
pub const DEVICE_CERT_HASH_DOMAIN: &[u8] = b"rvn1/pair-devcert";
pub const PREKEY_BUNDLE_HASH_DOMAIN: &[u8] = b"rvn1/pair-prekey";
pub const SESSION_ID_DOMAIN: &[u8] = b"rvn1/pair-session";
pub const CONFIRM_LABEL: &[u8] = b"ATSAM/pair-init/v1/confirm";
pub const INITIATOR_ROLE: u8 = 0;
pub const RESPONDER_ROLE: u8 = 1;
pub const MLKEM768_CT_LEN: usize = 1088;
pub const ADDRESS_LEN: usize = 44;

pub const INIT_SIGNED_PREFIX_LEN: usize = 8
    + 4
    + PROFILE_ID.len()
    + ADDRESS_LEN * 2
    + 16
    + 32
    + 32 * 2
    + 32 * 3
    + 32 * 3
    + 4
    + 4
    + MLKEM768_EK_LEN
    + MLKEM768_CT_LEN
    + 8
    + 8;
pub const INIT_WIRE_LEN: usize = INIT_SIGNED_PREFIX_LEN + 64;
pub const RESPONSE_SIGNED_PREFIX_LEN: usize = 8 + 4 + PROFILE_ID.len() + 16 + 32 + 32 + 8 + 8 + 32;
pub const RESPONSE_WIRE_LEN: usize = RESPONSE_SIGNED_PREFIX_LEN + 64;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairInit {
    pub initiator_address: String,
    pub responder_address: String,
    pub init_id: [u8; 16],
    pub pairing_nonce: [u8; 32],
    pub initiator_device_ed_pub: [u8; 32],
    pub responder_device_ed_pub: [u8; 32],
    pub initiator_ephemeral_x25519_pub: [u8; 32],
    pub responder_signed_x25519_pub: [u8; 32],
    /// All-zero iff `one_time_prekey_id == 0`.
    pub responder_one_time_x25519_pub: [u8; 32],
    pub initiator_device_cert_hash: [u8; 32],
    pub responder_device_cert_hash: [u8; 32],
    pub responder_prekey_bundle_hash: [u8; 32],
    pub signed_prekey_id: u32,
    pub one_time_prekey_id: u32,
    pub responder_mlkem768_ek: Vec<u8>,
    pub mlkem768_ciphertext: Vec<u8>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairResponse {
    pub init_id: [u8; 16],
    pub init_hash: [u8; 32],
    pub responder_device_ed_pub: [u8; 32],
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub confirmation_tag: [u8; 32],
    pub signature: [u8; 64],
}

/// Exact already-validated trust records required to accept a PairInit.
/// Local revocation decisions are explicit because V1 has no signed global
/// revocation-state record to hash into the transcript.
pub struct PairInitTrust<'a> {
    pub initiator_certificate: &'a DeviceCertificate,
    pub responder_certificate: &'a DeviceCertificate,
    pub responder_prekey: &'a PrekeyBundle,
    pub initiator_revoked: bool,
    pub responder_revoked: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PairInitError {
    #[error("PairInit has an invalid fixed length")]
    InvalidLength,
    #[error("PairInit magic mismatch")]
    InvalidMagic,
    #[error("PairInit version mismatch")]
    InvalidVersion,
    #[error("PairInit suite mismatch")]
    InvalidSuite,
    #[error("PairInit transcript role mismatch")]
    InvalidRole,
    #[error("PairInit indexed-session profile mismatch")]
    InvalidProfile,
    #[error("PairInit address is not an exact canonical RavenAddressV1")]
    InvalidAddress,
    #[error("PairInit endpoints must differ")]
    SameEndpoint,
    #[error("PairInit required field is all-zero")]
    AllZeroField,
    #[error("PairInit initiator ephemeral X25519 key is low-order (non-contributory)")]
    NonContributoryKey,
    #[error("PairInit one-time prekey id/key slot is inconsistent")]
    InvalidOneTimePrekey,
    #[error("PairInit validity interval is invalid")]
    InvalidTime,
    #[error("PairInit is not currently valid")]
    NotCurrentlyValid,
    #[error("PairInit identity/address binding mismatch")]
    IdentityMismatch,
    #[error("PairInit device certificate binding mismatch")]
    CertificateMismatch,
    #[error("PairInit responder prekey binding mismatch")]
    PrekeyMismatch,
    #[error("PairInit device is locally revoked")]
    RevokedDevice,
    #[error("PairInit validity exceeds its certificate/prekey trust window")]
    TrustWindowMismatch,
    #[error("PairInit signature verification failed")]
    BadSignature,
    #[error("PairResponse does not confirm the exact accepted PairInit")]
    ConfirmationMismatch,
    #[error("canonical trust-record encoding failed")]
    TrustEncoding,
}

fn all_zero(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn validate_init(value: &PairInit) -> Result<(), PairInitError> {
    if value.initiator_address.len() != ADDRESS_LEN || value.responder_address.len() != ADDRESS_LEN
    {
        return Err(PairInitError::InvalidAddress);
    }
    session_context(&value.initiator_address, &value.responder_address).map_err(|error| {
        if error.to_string().contains("endpoints must differ") {
            PairInitError::SameEndpoint
        } else {
            PairInitError::InvalidAddress
        }
    })?;
    if all_zero(&value.init_id)
        || all_zero(&value.pairing_nonce)
        || all_zero(&value.initiator_device_ed_pub)
        || all_zero(&value.responder_device_ed_pub)
        || all_zero(&value.initiator_ephemeral_x25519_pub)
        || all_zero(&value.responder_signed_x25519_pub)
        || all_zero(&value.initiator_device_cert_hash)
        || all_zero(&value.responder_device_cert_hash)
        || all_zero(&value.responder_prekey_bundle_hash)
        || all_zero(&value.responder_mlkem768_ek)
        || all_zero(&value.mlkem768_ciphertext)
    {
        return Err(PairInitError::AllZeroField);
    }
    // Every responder X25519 agreement with a small-order point is all-zero.
    // Reject it structurally so such a PairInit is never signed, hashed,
    // journaled, or claimed; the later checked DH is only a second guard.
    if !x25519_public_is_contributory(&value.initiator_ephemeral_x25519_pub) {
        return Err(PairInitError::NonContributoryKey);
    }
    if value.initiator_device_ed_pub == value.responder_device_ed_pub {
        return Err(PairInitError::CertificateMismatch);
    }
    if value.signed_prekey_id == 0 {
        return Err(PairInitError::PrekeyMismatch);
    }
    if value.one_time_prekey_id == 0 {
        if !all_zero(&value.responder_one_time_x25519_pub) {
            return Err(PairInitError::InvalidOneTimePrekey);
        }
    } else if all_zero(&value.responder_one_time_x25519_pub) {
        return Err(PairInitError::InvalidOneTimePrekey);
    }
    if value.responder_mlkem768_ek.len() != MLKEM768_EK_LEN
        || value.mlkem768_ciphertext.len() != MLKEM768_CT_LEN
    {
        return Err(PairInitError::InvalidLength);
    }
    if value.expires_at_ms <= value.created_at_ms {
        return Err(PairInitError::InvalidTime);
    }
    Ok(())
}

fn init_prefix(value: &PairInit) -> Result<Vec<u8>, PairInitError> {
    validate_init(value)?;
    let mut out = Vec::with_capacity(INIT_SIGNED_PREFIX_LEN);
    out.extend_from_slice(&INIT_MAGIC);
    out.extend_from_slice(&[VERSION, SUITE, INITIATOR_ROLE, PROFILE_ID.len() as u8]);
    out.extend_from_slice(PROFILE_ID);
    out.extend_from_slice(value.initiator_address.as_bytes());
    out.extend_from_slice(value.responder_address.as_bytes());
    out.extend_from_slice(&value.init_id);
    out.extend_from_slice(&value.pairing_nonce);
    out.extend_from_slice(&value.initiator_device_ed_pub);
    out.extend_from_slice(&value.responder_device_ed_pub);
    out.extend_from_slice(&value.initiator_ephemeral_x25519_pub);
    out.extend_from_slice(&value.responder_signed_x25519_pub);
    out.extend_from_slice(&value.responder_one_time_x25519_pub);
    out.extend_from_slice(&value.initiator_device_cert_hash);
    out.extend_from_slice(&value.responder_device_cert_hash);
    out.extend_from_slice(&value.responder_prekey_bundle_hash);
    out.extend_from_slice(&value.signed_prekey_id.to_be_bytes());
    out.extend_from_slice(&value.one_time_prekey_id.to_be_bytes());
    out.extend_from_slice(&value.responder_mlkem768_ek);
    out.extend_from_slice(&value.mlkem768_ciphertext);
    out.extend_from_slice(&value.created_at_ms.to_be_bytes());
    out.extend_from_slice(&value.expires_at_ms.to_be_bytes());
    debug_assert_eq!(out.len(), INIT_SIGNED_PREFIX_LEN);
    Ok(out)
}

pub fn init_signing_bytes(value: &PairInit) -> Result<Vec<u8>, PairInitError> {
    let prefix = init_prefix(value)?;
    let mut out = Vec::with_capacity(INIT_SIGNING_DOMAIN.len() + prefix.len());
    out.extend_from_slice(INIT_SIGNING_DOMAIN);
    out.extend_from_slice(&prefix);
    Ok(out)
}

pub fn encode_init(value: &PairInit) -> Result<Vec<u8>, PairInitError> {
    let mut out = init_prefix(value)?;
    out.extend_from_slice(&value.signature);
    debug_assert_eq!(out.len(), INIT_WIRE_LEN);
    Ok(out)
}

pub fn decode_init(wire: &[u8]) -> Result<PairInit, PairInitError> {
    if wire.len() != INIT_WIRE_LEN {
        return Err(PairInitError::InvalidLength);
    }
    if wire[..8] != INIT_MAGIC {
        return Err(PairInitError::InvalidMagic);
    }
    if wire[8] != VERSION {
        return Err(PairInitError::InvalidVersion);
    }
    if wire[9] != SUITE {
        return Err(PairInitError::InvalidSuite);
    }
    if wire[10] != INITIATOR_ROLE {
        return Err(PairInitError::InvalidRole);
    }
    if wire[11] as usize != PROFILE_ID.len() || wire[12..12 + PROFILE_ID.len()] != *PROFILE_ID {
        return Err(PairInitError::InvalidProfile);
    }
    let mut offset = 12 + PROFILE_ID.len();
    let initiator_address = take_string(wire, &mut offset, ADDRESS_LEN)?;
    let responder_address = take_string(wire, &mut offset, ADDRESS_LEN)?;
    let value = PairInit {
        initiator_address,
        responder_address,
        init_id: take_array(wire, &mut offset),
        pairing_nonce: take_array(wire, &mut offset),
        initiator_device_ed_pub: take_array(wire, &mut offset),
        responder_device_ed_pub: take_array(wire, &mut offset),
        initiator_ephemeral_x25519_pub: take_array(wire, &mut offset),
        responder_signed_x25519_pub: take_array(wire, &mut offset),
        responder_one_time_x25519_pub: take_array(wire, &mut offset),
        initiator_device_cert_hash: take_array(wire, &mut offset),
        responder_device_cert_hash: take_array(wire, &mut offset),
        responder_prekey_bundle_hash: take_array(wire, &mut offset),
        signed_prekey_id: u32::from_be_bytes(take_array(wire, &mut offset)),
        one_time_prekey_id: u32::from_be_bytes(take_array(wire, &mut offset)),
        responder_mlkem768_ek: take_vec(wire, &mut offset, MLKEM768_EK_LEN),
        mlkem768_ciphertext: take_vec(wire, &mut offset, MLKEM768_CT_LEN),
        created_at_ms: u64::from_be_bytes(take_array(wire, &mut offset)),
        expires_at_ms: u64::from_be_bytes(take_array(wire, &mut offset)),
        signature: take_array(wire, &mut offset),
    };
    debug_assert_eq!(offset, wire.len());
    validate_init(&value)?;
    Ok(value)
}

fn take_array<const N: usize>(wire: &[u8], offset: &mut usize) -> [u8; N] {
    let value = wire[*offset..*offset + N]
        .try_into()
        .expect("fixed wire length checked");
    *offset += N;
    value
}

fn take_vec(wire: &[u8], offset: &mut usize, length: usize) -> Vec<u8> {
    let value = wire[*offset..*offset + length].to_vec();
    *offset += length;
    value
}

fn take_string(wire: &[u8], offset: &mut usize, length: usize) -> Result<String, PairInitError> {
    let value = std::str::from_utf8(&wire[*offset..*offset + length])
        .map_err(|_| PairInitError::InvalidAddress)?
        .to_string();
    *offset += length;
    Ok(value)
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub fn device_certificate_hash(certificate: &DeviceCertificate) -> Result<[u8; 32], PairInitError> {
    let signing = device_cert_signing_bytes(
        &certificate.device_ed_pub,
        &certificate.device_x_pub,
        &certificate.device_id,
        certificate.not_before_ms,
        certificate.not_after_ms,
        certificate.capabilities,
    )
    .map_err(|_| PairInitError::TrustEncoding)?;
    Ok(hash_parts(&[
        DEVICE_CERT_HASH_DOMAIN,
        &certificate.user_ed_pub,
        &signing,
        &certificate.signature,
    ]))
}

pub fn prekey_bundle_hash(bundle: &PrekeyBundle) -> Result<[u8; 32], PairInitError> {
    let signing = bundle
        .signing_bytes()
        .map_err(|_| PairInitError::TrustEncoding)?;
    Ok(hash_parts(&[
        PREKEY_BUNDLE_HASH_DOMAIN,
        &signing,
        &bundle.signature,
    ]))
}

pub fn init_hash(value: &PairInit) -> Result<[u8; 32], PairInitError> {
    let wire = encode_init(value)?;
    Ok(hash_parts(&[INIT_SIGNING_DOMAIN, &wire]))
}

pub fn session_id(value: &PairInit) -> Result<[u8; 32], PairInitError> {
    Ok(session_id_from_init_hash(&init_hash(value)?))
}

pub fn session_id_from_init_hash(init_digest: &[u8; 32]) -> [u8; 32] {
    hash_parts(&[SESSION_ID_DOMAIN, init_digest])
}

pub fn transcript_hash(value: &PairInit) -> Result<[u8; 32], PairInitError> {
    let wire = encode_init(value)?;
    let mut material = Vec::with_capacity(INIT_SIGNING_DOMAIN.len() + wire.len());
    material.extend_from_slice(INIT_SIGNING_DOMAIN);
    material.extend_from_slice(&wire);
    Ok(atsam_transcript_hash(&material))
}

pub fn derive_provisional_root(
    z_x: &[u8; 32],
    z_pq: &[u8; 32],
    value: &PairInit,
) -> Result<[u8; 32], PairInitError> {
    Ok(derive_root(z_x, z_pq, &transcript_hash(value)?))
}

pub fn verify_init(
    value: &PairInit,
    trust: &PairInitTrust<'_>,
    now_ms: u64,
) -> Result<(), PairInitError> {
    validate_init(value)?;
    if trust.initiator_revoked || trust.responder_revoked {
        return Err(PairInitError::RevokedDevice);
    }
    trust
        .initiator_certificate
        .verify(now_ms)
        .map_err(|_| PairInitError::CertificateMismatch)?;
    trust
        .responder_certificate
        .verify(now_ms)
        .map_err(|_| PairInitError::CertificateMismatch)?;
    trust
        .responder_prekey
        .verify(now_ms)
        .map_err(|_| PairInitError::PrekeyMismatch)?;

    if encode_address(&trust.initiator_certificate.user_ed_pub) != value.initiator_address
        || encode_address(&trust.responder_certificate.user_ed_pub) != value.responder_address
    {
        return Err(PairInitError::IdentityMismatch);
    }
    if trust.initiator_certificate.device_ed_pub != value.initiator_device_ed_pub
        || trust.responder_certificate.device_ed_pub != value.responder_device_ed_pub
        || device_certificate_hash(trust.initiator_certificate)? != value.initiator_device_cert_hash
        || device_certificate_hash(trust.responder_certificate)? != value.responder_device_cert_hash
    {
        return Err(PairInitError::CertificateMismatch);
    }
    let prekey = trust.responder_prekey;
    let expected_one_time = prekey.one_time_x25519_pub.unwrap_or([0u8; 32]);
    if prekey.identity_ed25519_pub != trust.responder_certificate.user_ed_pub
        || prekey.device_id != trust.responder_certificate.device_id
        || prekey.x25519_pub != value.responder_signed_x25519_pub
        || prekey.signed_prekey_id != value.signed_prekey_id
        || prekey.one_time_prekey_id != value.one_time_prekey_id
        || expected_one_time != value.responder_one_time_x25519_pub
        || prekey.mlkem768_ek != value.responder_mlkem768_ek
        || prekey_bundle_hash(prekey)? != value.responder_prekey_bundle_hash
    {
        return Err(PairInitError::PrekeyMismatch);
    }
    let trust_not_before = trust
        .initiator_certificate
        .not_before_ms
        .max(trust.responder_certificate.not_before_ms)
        .max(prekey.created_at_ms);
    let trust_not_after = trust
        .initiator_certificate
        .not_after_ms
        .min(trust.responder_certificate.not_after_ms)
        .min(prekey.expires_at_ms);
    // The two peers' wall clocks are never identical: the initiator stamps
    // `created_at_ms` from its clock while the cert/prekey `created`/`not_before`
    // instants come from the responder's. Tolerate the same bounded skew as
    // `PrekeyBundle::verify` and the claim path (`MAX_PREKEY_FUTURE_SKEW_MS`),
    // otherwise that tolerance is dead and a few seconds of drift makes pairing
    // fail with a time error on one side after the other already accepted it.
    if value
        .created_at_ms
        .saturating_add(MAX_PREKEY_FUTURE_SKEW_MS)
        < trust_not_before
        || value.expires_at_ms > trust_not_after
    {
        return Err(PairInitError::TrustWindowMismatch);
    }
    if value.created_at_ms > now_ms.saturating_add(MAX_PREKEY_FUTURE_SKEW_MS)
        || now_ms >= value.expires_at_ms
    {
        return Err(PairInitError::NotCurrentlyValid);
    }
    let signing = init_signing_bytes(value)?;
    if !Identity::verify(&value.initiator_device_ed_pub, &signing, &value.signature) {
        return Err(PairInitError::BadSignature);
    }
    Ok(())
}

pub fn confirmation_tag(root: &[u8; 32], init_digest: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(root).expect("HMAC accepts 32-byte keys");
    mac.update(CONFIRM_LABEL);
    mac.update(&[0]);
    mac.update(init_digest);
    mac.finalize().into_bytes().into()
}

fn validate_response(value: &PairResponse) -> Result<(), PairInitError> {
    if all_zero(&value.init_id)
        || all_zero(&value.init_hash)
        || all_zero(&value.responder_device_ed_pub)
        || all_zero(&value.confirmation_tag)
    {
        return Err(PairInitError::AllZeroField);
    }
    if value.expires_at_ms <= value.created_at_ms {
        return Err(PairInitError::InvalidTime);
    }
    Ok(())
}

fn response_prefix(value: &PairResponse) -> Result<Vec<u8>, PairInitError> {
    validate_response(value)?;
    let mut out = Vec::with_capacity(RESPONSE_SIGNED_PREFIX_LEN);
    out.extend_from_slice(&RESPONSE_MAGIC);
    out.extend_from_slice(&[VERSION, SUITE, RESPONDER_ROLE, PROFILE_ID.len() as u8]);
    out.extend_from_slice(PROFILE_ID);
    out.extend_from_slice(&value.init_id);
    out.extend_from_slice(&value.init_hash);
    out.extend_from_slice(&value.responder_device_ed_pub);
    out.extend_from_slice(&value.created_at_ms.to_be_bytes());
    out.extend_from_slice(&value.expires_at_ms.to_be_bytes());
    out.extend_from_slice(&value.confirmation_tag);
    debug_assert_eq!(out.len(), RESPONSE_SIGNED_PREFIX_LEN);
    Ok(out)
}

pub fn response_signing_bytes(value: &PairResponse) -> Result<Vec<u8>, PairInitError> {
    let prefix = response_prefix(value)?;
    let mut out = Vec::with_capacity(RESPONSE_SIGNING_DOMAIN.len() + prefix.len());
    out.extend_from_slice(RESPONSE_SIGNING_DOMAIN);
    out.extend_from_slice(&prefix);
    Ok(out)
}

pub fn encode_response(value: &PairResponse) -> Result<Vec<u8>, PairInitError> {
    let mut out = response_prefix(value)?;
    out.extend_from_slice(&value.signature);
    debug_assert_eq!(out.len(), RESPONSE_WIRE_LEN);
    Ok(out)
}

pub fn decode_response(wire: &[u8]) -> Result<PairResponse, PairInitError> {
    if wire.len() != RESPONSE_WIRE_LEN {
        return Err(PairInitError::InvalidLength);
    }
    if wire[..8] != RESPONSE_MAGIC {
        return Err(PairInitError::InvalidMagic);
    }
    if wire[8] != VERSION {
        return Err(PairInitError::InvalidVersion);
    }
    if wire[9] != SUITE {
        return Err(PairInitError::InvalidSuite);
    }
    if wire[10] != RESPONDER_ROLE {
        return Err(PairInitError::InvalidRole);
    }
    if wire[11] as usize != PROFILE_ID.len() || wire[12..12 + PROFILE_ID.len()] != *PROFILE_ID {
        return Err(PairInitError::InvalidProfile);
    }
    let mut offset = 12 + PROFILE_ID.len();
    let value = PairResponse {
        init_id: take_array(wire, &mut offset),
        init_hash: take_array(wire, &mut offset),
        responder_device_ed_pub: take_array(wire, &mut offset),
        created_at_ms: u64::from_be_bytes(take_array(wire, &mut offset)),
        expires_at_ms: u64::from_be_bytes(take_array(wire, &mut offset)),
        confirmation_tag: take_array(wire, &mut offset),
        signature: take_array(wire, &mut offset),
    };
    debug_assert_eq!(offset, wire.len());
    validate_response(&value)?;
    Ok(value)
}

pub fn verify_response(
    value: &PairResponse,
    accepted_init: &PairInit,
    root: &[u8; 32],
    now_ms: u64,
) -> Result<(), PairInitError> {
    validate_response(value)?;
    let digest = init_hash(accepted_init)?;
    if value.init_id != accepted_init.init_id
        || value.init_hash != digest
        || value.responder_device_ed_pub != accepted_init.responder_device_ed_pub
        || value.created_at_ms < accepted_init.created_at_ms
        || value.created_at_ms >= accepted_init.expires_at_ms
        || value.expires_at_ms > accepted_init.expires_at_ms
        // Same bounded peer-clock skew as `verify_init`: the responder stamps
        // the response from its own clock.
        || value.created_at_ms > now_ms.saturating_add(MAX_PREKEY_FUTURE_SKEW_MS)
        || now_ms >= value.expires_at_ms
    {
        return Err(PairInitError::ConfirmationMismatch);
    }
    let mut mac = HmacSha256::new_from_slice(root).expect("HMAC accepts 32-byte keys");
    mac.update(CONFIRM_LABEL);
    mac.update(&[0]);
    mac.update(&digest);
    mac.verify_slice(&value.confirmation_tag)
        .map_err(|_| PairInitError::ConfirmationMismatch)?;
    let signing = response_signing_bytes(value)?;
    if !Identity::verify(&value.responder_device_ed_pub, &signing, &value.signature) {
        return Err(PairInitError::BadSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::path::PathBuf;

    fn vector() -> Value {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.pop();
        path.push("shared-vectors/rvn1/atsam/pair_init_v1_001.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn hex_arr<const N: usize>(value: &str) -> [u8; N] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    #[test]
    fn shared_vector_codec_root_and_confirmation() {
        let vector = vector();
        let input = &vector["input"];
        let expected = &vector["expected"];
        let init_wire = hex::decode(expected["pair_init_wire_hex"].as_str().unwrap()).unwrap();
        let init = decode_init(&init_wire).unwrap();
        const { assert!(!PRODUCTION_ENABLED) };
        assert_eq!(encode_init(&init).unwrap(), init_wire);
        assert_eq!(
            hex::encode(init_signing_bytes(&init).unwrap()),
            expected["pair_init_signing_bytes_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(init_hash(&init).unwrap()),
            expected["pair_init_hash_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(session_id(&init).unwrap()),
            expected["session_id_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(transcript_hash(&init).unwrap()),
            expected["transcript_hash_hex"].as_str().unwrap()
        );
        let root = derive_provisional_root(
            &hex_arr(input["z_x_hex"].as_str().unwrap()),
            &hex_arr(input["z_pq_hex"].as_str().unwrap()),
            &init,
        )
        .unwrap();
        assert_eq!(
            hex::encode(root),
            expected["provisional_k_root_hex"].as_str().unwrap()
        );
        let response_wire =
            hex::decode(expected["pair_response_wire_hex"].as_str().unwrap()).unwrap();
        let response = decode_response(&response_wire).unwrap();
        assert_eq!(encode_response(&response).unwrap(), response_wire);
        verify_response(&response, &init, &root, response.created_at_ms + 1).unwrap();
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert_eq!(
            verify_response(&response, &init, &wrong_root, response.created_at_ms + 1),
            Err(PairInitError::ConfirmationMismatch)
        );
    }

    #[test]
    fn shared_vector_verifies_exact_certificates_and_prekey() {
        let vector = vector();
        let expected = &vector["expected"];
        let init =
            decode_init(&hex::decode(expected["pair_init_wire_hex"].as_str().unwrap()).unwrap())
                .unwrap();
        let alice_user = Identity::from_seed(&hex_arr(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        let bob_user = Identity::from_seed(&hex_arr(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        ));
        let alice_device = Identity::from_seed(&std::array::from_fn(|index| index as u8));
        let bob_device = Identity::from_seed(&std::array::from_fn(|index| (index + 32) as u8));
        let alice_cert = DeviceCertificate::issue(
            &alice_user,
            alice_device.public_key_bytes(),
            hex_arr("7a1a4e709bf085ac494aba0469b9b1eda0ab1f78b16aabb79ffeda90623e8522"),
            "alice-device-1",
            init.created_at_ms - 86_400_000,
            init.created_at_ms + 31_536_000_000,
            0,
        )
        .unwrap();
        let bob_cert = DeviceCertificate::issue(
            &bob_user,
            bob_device.public_key_bytes(),
            init.responder_signed_x25519_pub,
            "bob-device-1",
            init.created_at_ms - 86_400_000,
            init.created_at_ms + 31_536_000_000,
            0,
        )
        .unwrap();
        let prekey = PrekeyBundle {
            identity_ed25519_pub: bob_user.public_key_bytes(),
            device_id: "bob-device-1".into(),
            x25519_pub: init.responder_signed_x25519_pub,
            mlkem768_ek: init.responder_mlkem768_ek.clone(),
            signed_prekey_id: init.signed_prekey_id,
            one_time_prekey_id: init.one_time_prekey_id,
            one_time_x25519_pub: Some(init.responder_one_time_x25519_pub),
            created_at_ms: init.created_at_ms - 60_000,
            expires_at_ms: init.created_at_ms + 604_800_000,
            signature: [0u8; 64],
        }
        .sign(&bob_user)
        .unwrap();
        assert_eq!(
            hex::encode(device_certificate_hash(&alice_cert).unwrap()),
            expected["initiator_device_cert_hash_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(device_certificate_hash(&bob_cert).unwrap()),
            expected["responder_device_cert_hash_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(prekey_bundle_hash(&prekey).unwrap()),
            expected["responder_prekey_bundle_hash_hex"]
                .as_str()
                .unwrap()
        );
        let trust = PairInitTrust {
            initiator_certificate: &alice_cert,
            responder_certificate: &bob_cert,
            responder_prekey: &prekey,
            initiator_revoked: false,
            responder_revoked: false,
        };
        verify_init(&init, &trust, init.created_at_ms + 1).unwrap();
        let revoked = PairInitTrust {
            responder_revoked: true,
            ..trust
        };
        assert_eq!(
            verify_init(&init, &revoked, init.created_at_ms + 1),
            Err(PairInitError::RevokedDevice)
        );
    }

    /// Self-contained trust records where a test picks the init's and the
    /// prekey's instants independently (the vector fixes them together).
    fn skew_fixture(
        init_created: u64,
        prekey_created: u64,
    ) -> (PairInit, DeviceCertificate, DeviceCertificate, PrekeyBundle) {
        let base = 1_700_000_000_000u64;
        let alice_user = Identity::from_seed(&[0x31; 32]);
        let bob_user = Identity::from_seed(&[0x32; 32]);
        let alice_device = Identity::from_seed(&[0x33; 32]);
        let bob_device = Identity::from_seed(&[0x34; 32]);
        let issue = |user: &Identity, device: &Identity, id: &str| {
            DeviceCertificate::issue(
                user,
                device.public_key_bytes(),
                [0x62; 32],
                id,
                base - 86_400_000,
                base + 31_536_000_000,
                0,
            )
            .unwrap()
        };
        let alice_cert = issue(&alice_user, &alice_device, "alice-device");
        let bob_cert = issue(&bob_user, &bob_device, "bob-device");
        let prekey = PrekeyBundle {
            identity_ed25519_pub: bob_user.public_key_bytes(),
            device_id: "bob-device".into(),
            x25519_pub: [0x62; 32],
            mlkem768_ek: vec![0x63; MLKEM768_EK_LEN],
            signed_prekey_id: 1,
            one_time_prekey_id: 0,
            one_time_x25519_pub: None,
            created_at_ms: prekey_created,
            expires_at_ms: base + 604_800_000,
            signature: [0u8; 64],
        }
        .sign(&bob_user)
        .unwrap();
        let ephemeral =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x42; 32]));
        let mut init = PairInit {
            initiator_address: encode_address(&alice_user.public_key_bytes()),
            responder_address: encode_address(&bob_user.public_key_bytes()),
            init_id: [7; 16],
            pairing_nonce: [8; 32],
            initiator_device_ed_pub: alice_device.public_key_bytes(),
            responder_device_ed_pub: bob_device.public_key_bytes(),
            initiator_ephemeral_x25519_pub: ephemeral.to_bytes(),
            responder_signed_x25519_pub: prekey.x25519_pub,
            responder_one_time_x25519_pub: [0u8; 32],
            initiator_device_cert_hash: device_certificate_hash(&alice_cert).unwrap(),
            responder_device_cert_hash: device_certificate_hash(&bob_cert).unwrap(),
            responder_prekey_bundle_hash: prekey_bundle_hash(&prekey).unwrap(),
            signed_prekey_id: 1,
            one_time_prekey_id: 0,
            responder_mlkem768_ek: prekey.mlkem768_ek.clone(),
            mlkem768_ciphertext: vec![0x55; MLKEM768_CT_LEN],
            created_at_ms: init_created,
            expires_at_ms: init_created + 3_600_000,
            signature: [0u8; 64],
        };
        init.signature = alice_device.sign(&init_signing_bytes(&init).unwrap());
        (init, alice_cert, bob_cert, prekey)
    }

    #[test]
    fn verify_init_tolerates_bounded_peer_clock_skew() {
        let base = 1_700_000_000_000u64;
        let skew = MAX_PREKEY_FUTURE_SKEW_MS;
        let (init, alice, bob, prekey) = skew_fixture(base, base - 60_000);
        let trust = PairInitTrust {
            initiator_certificate: &alice,
            responder_certificate: &bob,
            responder_prekey: &prekey,
            initiator_revoked: false,
            responder_revoked: false,
        };
        // The verifier's clock is behind the initiator's by up to the bound.
        verify_init(&init, &trust, base).unwrap();
        verify_init(&init, &trust, base - skew).unwrap();
        assert_eq!(
            verify_init(&init, &trust, base - skew - 1),
            Err(PairInitError::NotCurrentlyValid)
        );
        // Expiry stays exact.
        assert_eq!(
            verify_init(&init, &trust, init.expires_at_ms),
            Err(PairInitError::NotCurrentlyValid)
        );
    }

    #[test]
    fn verify_init_trust_window_tolerates_bounded_peer_clock_skew() {
        let base = 1_700_000_000_000u64;
        let skew = MAX_PREKEY_FUTURE_SKEW_MS;
        // The responder's prekey "was created" up to the bound after the
        // initiator's own clock reads at init time.
        let (init, alice, bob, prekey) = skew_fixture(base, base + skew);
        let trust = PairInitTrust {
            initiator_certificate: &alice,
            responder_certificate: &bob,
            responder_prekey: &prekey,
            initiator_revoked: false,
            responder_revoked: false,
        };
        verify_init(&init, &trust, base + skew).unwrap();
        let (init, alice, bob, prekey) = skew_fixture(base, base + skew + 1);
        let trust = PairInitTrust {
            initiator_certificate: &alice,
            responder_certificate: &bob,
            responder_prekey: &prekey,
            initiator_revoked: false,
            responder_revoked: false,
        };
        assert_eq!(
            verify_init(&init, &trust, base + skew + 1),
            Err(PairInitError::TrustWindowMismatch)
        );
    }

    #[test]
    fn verify_response_tolerates_bounded_peer_clock_skew() {
        let vector = vector();
        let input = &vector["input"];
        let expected = &vector["expected"];
        let init =
            decode_init(&hex::decode(expected["pair_init_wire_hex"].as_str().unwrap()).unwrap())
                .unwrap();
        let root = derive_provisional_root(
            &hex_arr(input["z_x_hex"].as_str().unwrap()),
            &hex_arr(input["z_pq_hex"].as_str().unwrap()),
            &init,
        )
        .unwrap();
        let response = decode_response(
            &hex::decode(expected["pair_response_wire_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        // The responder's clock is ahead of the verifier's by up to the bound.
        let behind = response.created_at_ms - MAX_PREKEY_FUTURE_SKEW_MS;
        verify_response(&response, &init, &root, behind).unwrap();
        assert_eq!(
            verify_response(&response, &init, &root, behind - 1),
            Err(PairInitError::ConfirmationMismatch)
        );
    }

    #[test]
    fn strict_decoder_and_signed_bindings_reject_tampering() {
        let vector = vector();
        let wire = hex::decode(vector["expected"]["pair_init_wire_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            decode_init(&wire[..wire.len() - 1]),
            Err(PairInitError::InvalidLength)
        );
        for offset in [8usize, 9, 10, 12] {
            let mut tampered = wire.clone();
            tampered[offset] ^= 1;
            assert!(decode_init(&tampered).is_err());
        }
        let init = decode_init(&wire).unwrap();
        let mut swapped = init.clone();
        std::mem::swap(
            &mut swapped.initiator_address,
            &mut swapped.responder_address,
        );
        assert!(!Identity::verify(
            &swapped.initiator_device_ed_pub,
            &init_signing_bytes(&swapped).unwrap(),
            &swapped.signature,
        ));
        let mut inconsistent = init;
        inconsistent.one_time_prekey_id = 0;
        assert_eq!(
            init_signing_bytes(&inconsistent),
            Err(PairInitError::InvalidOneTimePrekey)
        );
    }

    #[test]
    fn low_order_initiator_ephemeral_is_rejected_before_any_use() {
        let vector = vector();
        let wire = hex::decode(vector["expected"]["pair_init_wire_hex"].as_str().unwrap()).unwrap();
        let init = decode_init(&wire).unwrap();
        // Spec §3 offset 236: initiator ephemeral X25519 public key.
        let offset = 12 + PROFILE_ID.len() + ADDRESS_LEN * 2 + 16 + 32 + 32 * 2;
        assert_eq!(offset, 236);
        assert_eq!(
            wire[offset..offset + 32],
            init.initiator_ephemeral_x25519_pub
        );
        let mut u_one = [0u8; 32];
        u_one[0] = 1;
        let mut tampered = wire.clone();
        tampered[offset..offset + 32].copy_from_slice(&u_one);
        assert_eq!(
            decode_init(&tampered),
            Err(PairInitError::NonContributoryKey)
        );
        let mut low = init;
        low.initiator_ephemeral_x25519_pub = u_one;
        assert_eq!(
            init_signing_bytes(&low),
            Err(PairInitError::NonContributoryKey)
        );
        assert_eq!(init_hash(&low), Err(PairInitError::NonContributoryKey));
        assert_eq!(
            transcript_hash(&low),
            Err(PairInitError::NonContributoryKey)
        );
    }

    #[test]
    fn pending_hybrid_initiation_is_finalized_only_after_transcript_exists() {
        use crate::atsam_mlkem::{begin_hybrid_initiation, HybridKeypair};
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::seed_from_u64(7);
        let alice = HybridKeypair::generate(&mut rng);
        let bob = HybridKeypair::generate(&mut rng);
        let pending = begin_hybrid_initiation(
            &mut rng,
            &alice.x25519_secret,
            &bob.x25519_public,
            &bob.mlkem_ek_bytes,
        )
        .unwrap();
        assert_eq!(pending.ciphertext().len(), MLKEM768_CT_LEN);
        let ciphertext = pending.ciphertext().to_vec();
        let transcript = atsam_transcript_hash(b"complete-signed-pairinit-fixture");
        let (returned_ciphertext, root_a) = pending.finalize(&transcript);
        assert_eq!(returned_ciphertext, ciphertext);
        let root_b = crate::atsam_mlkem::respond_hybrid_root(
            &bob.x25519_secret,
            &alice.x25519_public,
            &bob.mlkem_seed,
            &ciphertext,
            &transcript,
        )
        .unwrap();
        assert_eq!(root_a, root_b);
    }
}
