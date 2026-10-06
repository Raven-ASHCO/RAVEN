//! ATSAM Indexed Session Profile V1 byte-exact reference primitives.
//!
//! This is deliberately **not** wired into `raven-node`, endpoint routing, or
//! the shipping RVNA1 classifier.  A future signed, versioned PairInit must
//! negotiate and transcript-bind [`PROFILE_ID`] before production activation.
//! Protocol byte `0x03` avoids silently reinterpreting existing RVNA1 v2.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::ack::Ack;
use crate::address::{decode_address, ADDRESS_VERSION};
use crate::atsam_kdf::{advance_chain_key, initial_chain_key, message_key};
use crate::routing_tag;
use crate::seal::SEAL_MAGIC_RVNA1;
use crate::store_object::{mailbox_tag, store_tag_from_mailbox};

pub const PROFILE_ID: &[u8] = b"ATSAM/indexed-session/v1";
pub const PRODUCTION_ENABLED: bool = false;

pub fn live_enabled() -> bool {
    PRODUCTION_ENABLED || crate::pair_init::lab_test_a_enabled()
}
pub const RVNA1_PROTO: u8 = 0x03;
pub const RVNA1_SUITE: u8 = 0x01;

pub const LABEL_ACK_BASE: &[u8] = b"ATSAM/v1/ack-seal";
pub const LABEL_ROUTE_MASTER: &[u8] = b"ATSAM/v1/GhostRoute/recipient-tag";
pub const LABEL_ROUTE_DIRECTION: &[u8] = b"ATSAM/v1/GhostRoute/rvn1-direction";
pub const AAD_DOMAIN: &[u8] = b"ATSAM/v1/msg-seal/aad";

pub const ACK_PLAINTEXT_LEN: usize = 101;
pub const ACK_SEALED_WIRE_LEN: usize = 143;
pub const INDEXED_SEALED_HEADER_LEN: usize = 26;
pub const INDEXED_SEALED_MIN_WIRE_LEN: usize = INDEXED_SEALED_HEADER_LEN + 16;
/// The stateless `*_key_at_index` helpers and `seal_ack`/`open_ack` re-derive
/// from `CK_0` and do O(index) HKDF work, in `open_ack` before any
/// authentication. They have no persisted counter, so skips are bounded
/// relative to index 0; the durable endpoint store bounds its receive jumps
/// relative to its own counter instead. Derivation below the bound is
/// unchanged.
pub const MAX_STATELESS_CHAIN_INDEX: u32 = crate::atsam_aead::MAX_PORTABLE_CHAIN_INDEX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    InitiatorToResponder = 0,
    ResponderToInitiator = 1,
}

impl Direction {
    pub fn from_u8(value: u8) -> Result<Self, IndexedSessionError> {
        match value {
            0 => Ok(Self::InitiatorToResponder),
            1 => Ok(Self::ResponderToInitiator),
            _ => Err(IndexedSessionError::InvalidDirection),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IndexedSessionError {
    #[error("address must be an exact lowercase RavenAddressV1 string")]
    NonCanonicalAddress,
    #[error("session endpoints must differ")]
    SameEndpoint,
    #[error("direction must be 0 or 1")]
    InvalidDirection,
    #[error("env_type must be 1 through 4")]
    InvalidEnvelopeType,
    #[error("ACK status must be delivered(1) or read(2)")]
    InvalidAckStatus,
    #[error("signed ACK plaintext must be exactly 101 bytes")]
    InvalidAckLength,
    #[error("sealed ACK body must be exactly 143 bytes")]
    InvalidSealedAckLength,
    #[error("unsupported sealed ACK header")]
    InvalidSealedAckHeader,
    #[error("indexed message is truncated")]
    InvalidIndexedMessageLength,
    #[error("unsupported indexed message header")]
    InvalidIndexedMessageHeader,
    #[error("ChaCha20-Poly1305 authentication failed")]
    AuthenticationFailed,
    #[error("chain index exceeds the stateless derivation bound")]
    ChainIndexTooLarge,
}

/// Parses only the fixed, bounded RVNA1 indexed header. This is candidate
/// selection, not authentication; callers must still verify the outer device
/// signature, route binding, and AEAD before accepting an object.
pub fn parse_indexed_message_header(wire: &[u8]) -> Result<u32, IndexedSessionError> {
    if wire.len() < INDEXED_SEALED_MIN_WIRE_LEN {
        return Err(IndexedSessionError::InvalidIndexedMessageLength);
    }
    if wire[..8] != SEAL_MAGIC_RVNA1 || wire[8] != RVNA1_PROTO || wire[9] != RVNA1_SUITE {
        return Err(IndexedSessionError::InvalidIndexedMessageHeader);
    }
    Ok(u32::from_be_bytes(
        wire[10..14].try_into().expect("fixed indexed header"),
    ))
}

/// Seals one message with an already durably reserved message-lane key.
///
/// This helper deliberately does not derive or reserve keys. The endpoint
/// actor owns ratchet persistence and must never call this with a reused key.
#[allow(clippy::too_many_arguments)]
pub fn seal_indexed_message_with_key(
    key: &[u8; 32],
    initiator_address: &str,
    responder_address: &str,
    direction: Direction,
    index: u32,
    outer_message_id: &[u8; 16],
    plaintext: &[u8],
    nonce12: &[u8; 12],
) -> Result<Vec<u8>, IndexedSessionError> {
    let (sender, recipient) = endpoints(initiator_address, responder_address, direction)?;
    let aad = build_aad(index, sender, recipient, outer_message_id)?;
    let ciphertext = ChaCha20Poly1305::new(key.into())
        .encrypt(
            Nonce::from_slice(nonce12),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| IndexedSessionError::AuthenticationFailed)?;
    let mut wire = Vec::with_capacity(INDEXED_SEALED_HEADER_LEN + ciphertext.len());
    wire.extend_from_slice(&SEAL_MAGIC_RVNA1);
    wire.push(RVNA1_PROTO);
    wire.push(RVNA1_SUITE);
    wire.extend_from_slice(&index.to_be_bytes());
    wire.extend_from_slice(nonce12);
    wire.extend_from_slice(&ciphertext);
    Ok(wire)
}

/// Opens one proto `0x03` message with the receive-ratchet candidate key.
#[allow(clippy::too_many_arguments)]
pub fn open_indexed_message_with_key(
    key: &[u8; 32],
    initiator_address: &str,
    responder_address: &str,
    direction: Direction,
    outer_message_id: &[u8; 16],
    wire: &[u8],
) -> Result<Vec<u8>, IndexedSessionError> {
    let index = parse_indexed_message_header(wire)?;
    let (sender, recipient) = endpoints(initiator_address, responder_address, direction)?;
    let aad = build_aad(index, sender, recipient, outer_message_id)?;
    ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(&wire[14..INDEXED_SEALED_HEADER_LEN]),
            Payload {
                msg: &wire[INDEXED_SEALED_HEADER_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| IndexedSessionError::AuthenticationFailed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAck {
    pub record: Ack,
    pub signature: [u8; 64],
}

fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("32-byte HKDF output");
    okm
}

fn canonical_address(value: &str) -> Result<&str, IndexedSessionError> {
    if value.is_empty()
        || value != value.trim()
        || !value.is_ascii()
        || value != value.to_ascii_lowercase()
    {
        return Err(IndexedSessionError::NonCanonicalAddress);
    }
    let (_, version) = decode_address(value).ok_or(IndexedSessionError::NonCanonicalAddress)?;
    if version != ADDRESS_VERSION {
        return Err(IndexedSessionError::NonCanonicalAddress);
    }
    Ok(value)
}

pub fn session_context(
    initiator_address: &str,
    responder_address: &str,
) -> Result<Vec<u8>, IndexedSessionError> {
    let initiator = canonical_address(initiator_address)?;
    let responder = canonical_address(responder_address)?;
    if initiator == responder {
        return Err(IndexedSessionError::SameEndpoint);
    }
    let mut out = Vec::with_capacity(PROFILE_ID.len() + initiator.len() + responder.len() + 2);
    out.extend_from_slice(PROFILE_ID);
    out.push(0);
    out.extend_from_slice(initiator.as_bytes());
    out.push(0);
    out.extend_from_slice(responder.as_bytes());
    Ok(out)
}

fn endpoints<'a>(
    initiator_address: &'a str,
    responder_address: &'a str,
    direction: Direction,
) -> Result<(&'a str, &'a str), IndexedSessionError> {
    session_context(initiator_address, responder_address)?;
    Ok(match direction {
        Direction::InitiatorToResponder => (initiator_address, responder_address),
        Direction::ResponderToInitiator => (responder_address, initiator_address),
    })
}

fn chain_key_at_index(
    root: &[u8; 32],
    sender: &str,
    recipient: &str,
    index: u32,
) -> Result<Zeroizing<[u8; 32]>, IndexedSessionError> {
    if index > MAX_STATELESS_CHAIN_INDEX {
        return Err(IndexedSessionError::ChainIndexTooLarge);
    }
    let mut chain_key = Zeroizing::new(initial_chain_key(root, sender, recipient));
    for _ in 0..index {
        *chain_key = advance_chain_key(&chain_key);
    }
    Ok(chain_key)
}

/// Existing ATSAM message lane; this profile does not change its KDF.
pub fn message_key_at_index(
    root: &[u8; 32],
    initiator_address: &str,
    responder_address: &str,
    direction: Direction,
    index: u32,
) -> Result<[u8; 32], IndexedSessionError> {
    let (sender, recipient) = endpoints(initiator_address, responder_address, direction)?;
    let chain_key = chain_key_at_index(root, sender, recipient, index)?;
    Ok(message_key(&chain_key, sender, recipient))
}

pub fn ack_base_key(root: &[u8; 32]) -> [u8; 32] {
    hkdf32(root, LABEL_ACK_BASE)
}

pub fn ack_chain_key_at_index(
    root: &[u8; 32],
    initiator_address: &str,
    responder_address: &str,
    direction: Direction,
    index: u32,
) -> Result<[u8; 32], IndexedSessionError> {
    let (sender, recipient) = endpoints(initiator_address, responder_address, direction)?;
    let ack_base = Zeroizing::new(ack_base_key(root));
    Ok(*chain_key_at_index(&ack_base, sender, recipient, index)?)
}

pub fn ack_key_at_index(
    root: &[u8; 32],
    initiator_address: &str,
    responder_address: &str,
    direction: Direction,
    index: u32,
) -> Result<[u8; 32], IndexedSessionError> {
    let (sender, recipient) = endpoints(initiator_address, responder_address, direction)?;
    let chain_key = Zeroizing::new(ack_chain_key_at_index(
        root,
        initiator_address,
        responder_address,
        direction,
        index,
    )?);
    Ok(message_key(&chain_key, sender, recipient))
}

pub fn route_master_key(root: &[u8; 32]) -> [u8; 32] {
    hkdf32(root, LABEL_ROUTE_MASTER)
}

pub fn route_direction_key(root: &[u8; 32], direction: Direction) -> [u8; 32] {
    let mut info = Vec::with_capacity(LABEL_ROUTE_DIRECTION.len() + 2);
    info.extend_from_slice(LABEL_ROUTE_DIRECTION);
    info.push(0);
    info.push(direction as u8);
    hkdf32(&route_master_key(root), &info)
}

pub fn route_coordinates(
    created_at_ms: u64,
    index: u32,
    env_type: u8,
    direction: Direction,
) -> Result<(u64, u64), IndexedSessionError> {
    if !(1..=4).contains(&env_type) {
        return Err(IndexedSessionError::InvalidEnvelopeType);
    }
    let epoch = created_at_ms / 1000;
    let counter = ((index as u64) << 3) | (((env_type - 1) as u64) << 1) | direction as u64;
    Ok((epoch, counter))
}

pub fn derive_route_tag(
    root: &[u8; 32],
    created_at_ms: u64,
    index: u32,
    env_type: u8,
    direction: Direction,
) -> Result<[u8; 16], IndexedSessionError> {
    let (epoch, counter) = route_coordinates(created_at_ms, index, env_type, direction)?;
    Ok(routing_tag::derive(
        &route_direction_key(root, direction),
        epoch,
        counter,
    ))
}

pub fn mailbox_coordinates(unix_ms: u64, direction: Direction) -> (u64, u64) {
    (unix_ms / 86_400_000, direction as u64)
}

pub fn derive_mailbox_tags(
    root: &[u8; 32],
    unix_ms: u64,
    direction: Direction,
) -> ([u8; 16], [u8; 16]) {
    let (day_epoch, slot) = mailbox_coordinates(unix_ms, direction);
    let mailbox = mailbox_tag(&route_direction_key(root, direction), day_epoch, slot);
    let store = store_tag_from_mailbox(&mailbox);
    (mailbox, store)
}

/// Raw 16-byte ID as uppercase `8-4-4-4-12` UUID text for ATSAM AAD.
pub fn uuid_text(message_id: &[u8; 16]) -> String {
    let value = hex::encode_upper(message_id);
    format!(
        "{}-{}-{}-{}-{}",
        &value[0..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..32]
    )
}

pub fn build_aad(
    index: u32,
    sender: &str,
    recipient: &str,
    outer_message_id: &[u8; 16],
) -> Result<[u8; 32], IndexedSessionError> {
    let sender = canonical_address(sender)?;
    let recipient = canonical_address(recipient)?;
    let mut hasher = Sha256::new();
    hasher.update(AAD_DOMAIN);
    hasher.update([0]);
    hasher.update([RVNA1_PROTO, RVNA1_SUITE]);
    hasher.update(index.to_be_bytes());
    hasher.update([0]);
    hasher.update(sender.as_bytes());
    hasher.update([0]);
    hasher.update(recipient.as_bytes());
    hasher.update([0]);
    hasher.update(uuid_text(outer_message_id).as_bytes());
    Ok(hasher.finalize().into())
}

pub fn encode_signed_ack(
    value: &SignedAck,
) -> Result<[u8; ACK_PLAINTEXT_LEN], IndexedSessionError> {
    if !matches!(value.record.status, 1 | 2) {
        return Err(IndexedSessionError::InvalidAckStatus);
    }
    let mut out = [0u8; ACK_PLAINTEXT_LEN];
    out[0..16].copy_from_slice(&value.record.acked_message_id);
    out[16] = value.record.status;
    out[17..29].copy_from_slice(&value.record.ack_nonce);
    out[29..37].copy_from_slice(&value.record.created_at.to_be_bytes());
    out[37..101].copy_from_slice(&value.signature);
    Ok(out)
}

pub fn decode_signed_ack(data: &[u8]) -> Result<SignedAck, IndexedSessionError> {
    if data.len() != ACK_PLAINTEXT_LEN {
        return Err(IndexedSessionError::InvalidAckLength);
    }
    if !matches!(data[16], 1 | 2) {
        return Err(IndexedSessionError::InvalidAckStatus);
    }
    let mut acked_message_id = [0u8; 16];
    acked_message_id.copy_from_slice(&data[0..16]);
    let mut ack_nonce = [0u8; 12];
    ack_nonce.copy_from_slice(&data[17..29]);
    let created_at = u64::from_be_bytes(data[29..37].try_into().expect("fixed slice"));
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[37..101]);
    Ok(SignedAck {
        record: Ack {
            acked_message_id,
            status: data[16],
            ack_nonce,
            created_at,
        },
        signature,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn seal_ack(
    root: &[u8; 32],
    initiator_address: &str,
    responder_address: &str,
    direction: Direction,
    index: u32,
    outer_message_id: &[u8; 16],
    plaintext: &[u8; ACK_PLAINTEXT_LEN],
    nonce12: &[u8; 12],
) -> Result<Vec<u8>, IndexedSessionError> {
    decode_signed_ack(plaintext)?;
    let (sender, recipient) = endpoints(initiator_address, responder_address, direction)?;
    let key = Zeroizing::new(ack_key_at_index(
        root,
        initiator_address,
        responder_address,
        direction,
        index,
    )?);
    let aad = build_aad(index, sender, recipient, outer_message_id)?;
    let ciphertext = ChaCha20Poly1305::new((&*key).into())
        .encrypt(
            Nonce::from_slice(nonce12),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| IndexedSessionError::AuthenticationFailed)?;
    let mut wire = Vec::with_capacity(ACK_SEALED_WIRE_LEN);
    wire.extend_from_slice(&SEAL_MAGIC_RVNA1);
    wire.push(RVNA1_PROTO);
    wire.push(RVNA1_SUITE);
    wire.extend_from_slice(&index.to_be_bytes());
    wire.extend_from_slice(nonce12);
    wire.extend_from_slice(&ciphertext);
    debug_assert_eq!(wire.len(), ACK_SEALED_WIRE_LEN);
    Ok(wire)
}

pub fn open_ack(
    root: &[u8; 32],
    initiator_address: &str,
    responder_address: &str,
    direction: Direction,
    outer_message_id: &[u8; 16],
    wire: &[u8],
) -> Result<[u8; ACK_PLAINTEXT_LEN], IndexedSessionError> {
    if wire.len() != ACK_SEALED_WIRE_LEN {
        return Err(IndexedSessionError::InvalidSealedAckLength);
    }
    if wire[..8] != SEAL_MAGIC_RVNA1 || wire[8] != RVNA1_PROTO || wire[9] != RVNA1_SUITE {
        return Err(IndexedSessionError::InvalidSealedAckHeader);
    }
    let index = u32::from_be_bytes(wire[10..14].try_into().expect("fixed slice"));
    if index > MAX_STATELESS_CHAIN_INDEX {
        return Err(IndexedSessionError::ChainIndexTooLarge);
    }
    let (sender, recipient) = endpoints(initiator_address, responder_address, direction)?;
    let key = Zeroizing::new(ack_key_at_index(
        root,
        initiator_address,
        responder_address,
        direction,
        index,
    )?);
    let aad = build_aad(index, sender, recipient, outer_message_id)?;
    let plaintext = ChaCha20Poly1305::new((&*key).into())
        .decrypt(
            Nonce::from_slice(&wire[14..26]),
            Payload {
                msg: &wire[26..],
                aad: &aad,
            },
        )
        .map_err(|_| IndexedSessionError::AuthenticationFailed)?;
    let plaintext: [u8; ACK_PLAINTEXT_LEN] = plaintext
        .try_into()
        .map_err(|_| IndexedSessionError::InvalidAckLength)?;
    decode_signed_ack(&plaintext)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_addresses() -> (String, String) {
        (
            "rvn1qysluvwl5922yctzd0u9gpr06gn3k7ldfvecule0".to_string(),
            "rvn1qyulwy7s5ezz20cy222zrw04rwds39uapqakqskn".to_string(),
        )
    }

    #[test]
    fn profile_is_not_a_v2_reinterpretation() {
        const { assert!(!PRODUCTION_ENABLED) };
        assert_eq!(RVNA1_PROTO, 0x03);
        assert_ne!(RVNA1_PROTO, crate::seal::ATSAM_PROTO_V2);
        // The live classifier intentionally does not activate this profile.
        let mut prefix = Vec::from(SEAL_MAGIC_RVNA1);
        prefix.extend_from_slice(&[RVNA1_PROTO, RVNA1_SUITE]);
        assert_eq!(
            crate::seal::classify_sealed_body(&prefix),
            crate::seal::SealClass::Other
        );
    }

    #[test]
    fn allocator_and_uuid_encoding_are_frozen() {
        assert_eq!(
            route_coordinates(1_700_000_001_999, 7, 2, Direction::ResponderToInitiator).unwrap(),
            (1_700_000_001, 59)
        );
        let id = hex::decode("00112233445546778899aabbccddeeff").unwrap();
        assert_eq!(
            uuid_text(id.as_slice().try_into().unwrap()),
            "00112233-4455-4677-8899-AABBCCDDEEFF"
        );
        assert_eq!(
            mailbox_coordinates(1_700_000_000_000, Direction::ResponderToInitiator),
            (19_675, 1)
        );
    }

    #[test]
    fn signed_and_sealed_ack_round_trip_with_exact_lengths() {
        let (alice, bob) = fixture_addresses();
        let record = Ack {
            acked_message_id: 1u128.to_be_bytes(),
            status: 1,
            ack_nonce: {
                let mut value = [0u8; 12];
                value[11] = 2;
                value
            },
            created_at: 1_700_000_001_000,
        };
        let signed = SignedAck {
            signature: [0x55; 64],
            record,
        };
        let plaintext = encode_signed_ack(&signed).unwrap();
        assert_eq!(decode_signed_ack(&plaintext).unwrap(), signed);
        let mut invalid = signed.clone();
        invalid.record.status = 3;
        assert_eq!(
            encode_signed_ack(&invalid),
            Err(IndexedSessionError::InvalidAckStatus)
        );
        let root = [0x11; 32];
        let outer_id = hex::decode("00112233445546778899aabbccddeeff").unwrap();
        let outer_id: [u8; 16] = outer_id.try_into().unwrap();
        let wire = seal_ack(
            &root,
            &alice,
            &bob,
            Direction::ResponderToInitiator,
            7,
            &outer_id,
            &plaintext,
            &[0xCD; 12],
        )
        .unwrap();
        assert_eq!(wire.len(), ACK_SEALED_WIRE_LEN);
        assert_eq!(
            open_ack(
                &root,
                &alice,
                &bob,
                Direction::ResponderToInitiator,
                &outer_id,
                &wire,
            )
            .unwrap(),
            plaintext
        );
        let mut wrong_id = outer_id;
        wrong_id[15] ^= 1;
        assert_eq!(
            open_ack(
                &root,
                &alice,
                &bob,
                Direction::ResponderToInitiator,
                &wrong_id,
                &wire,
            ),
            Err(IndexedSessionError::AuthenticationFailed)
        );
    }

    #[test]
    fn stateless_index_work_is_bounded_before_authentication() {
        let (alice, bob) = fixture_addresses();
        let root = [0x21; 32];
        let direction = Direction::InitiatorToResponder;
        let at_limit = MAX_STATELESS_CHAIN_INDEX;
        assert!(message_key_at_index(&root, &alice, &bob, direction, at_limit).is_ok());
        for index in [MAX_STATELESS_CHAIN_INDEX + 1, u32::MAX] {
            assert_eq!(
                message_key_at_index(&root, &alice, &bob, direction, index),
                Err(IndexedSessionError::ChainIndexTooLarge)
            );
            assert_eq!(
                ack_key_at_index(&root, &alice, &bob, direction, index),
                Err(IndexedSessionError::ChainIndexTooLarge)
            );
        }
        // A forged ACK claiming index 0xFFFFFFFF is rejected without walking
        // the chain (this previously ran ~4.3e9 HKDF steps).
        let record = Ack {
            acked_message_id: [0x01; 16],
            status: 1,
            ack_nonce: [0x02; 12],
            created_at: 1_700_000_001_000,
        };
        let plaintext = encode_signed_ack(&SignedAck {
            record,
            signature: [0x55; 64],
        })
        .unwrap();
        let outer_id = [0x03; 16];
        let mut wire = seal_ack(
            &root,
            &alice,
            &bob,
            direction,
            0,
            &outer_id,
            &plaintext,
            &[0x04; 12],
        )
        .unwrap();
        wire[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            open_ack(&root, &alice, &bob, direction, &outer_id, &wire),
            Err(IndexedSessionError::ChainIndexTooLarge)
        );
        assert_eq!(
            seal_ack(
                &root,
                &alice,
                &bob,
                direction,
                MAX_STATELESS_CHAIN_INDEX + 1,
                &outer_id,
                &plaintext,
                &[0x04; 12]
            ),
            Err(IndexedSessionError::ChainIndexTooLarge)
        );
    }

    #[test]
    fn indexed_message_keyed_open_is_exact_and_aad_bound() {
        let (alice, bob) = fixture_addresses();
        let root = [0x31; 32];
        let index = 9;
        let direction = Direction::ResponderToInitiator;
        let outer_id = [0x32; 16];
        let key = message_key_at_index(&root, &alice, &bob, direction, index).unwrap();
        let wire = seal_indexed_message_with_key(
            &key,
            &alice,
            &bob,
            direction,
            index,
            &outer_id,
            b"proto-03-message",
            &[0x33; 12],
        )
        .unwrap();
        assert_eq!(parse_indexed_message_header(&wire).unwrap(), index);
        assert_eq!(
            open_indexed_message_with_key(&key, &alice, &bob, direction, &outer_id, &wire,)
                .unwrap(),
            b"proto-03-message"
        );
        let mut wrong_id = outer_id;
        wrong_id[0] ^= 1;
        assert_eq!(
            open_indexed_message_with_key(&key, &alice, &bob, direction, &wrong_id, &wire,),
            Err(IndexedSessionError::AuthenticationFailed)
        );
        let mut tampered = wire.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            open_indexed_message_with_key(&key, &alice, &bob, direction, &outer_id, &tampered,),
            Err(IndexedSessionError::AuthenticationFailed)
        );
        assert_eq!(
            parse_indexed_message_header(&wire[..INDEXED_SEALED_MIN_WIRE_LEN - 1]),
            Err(IndexedSessionError::InvalidIndexedMessageLength)
        );
    }
}
