//! RavenEnvelopeV1 — pack/unpack + signing bytes (mutable-field rule).

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::identity::Identity;

pub const MAGIC: &[u8; 4] = b"RVN1";
pub const VERSION: u8 = 1;
pub const PREFIX_LEN: usize = 86;
/// Canonical RVN1 object ceiling. The current serverless text sealer is capped
/// at 256 KiB; 1 MiB leaves ample envelope/header room while matching the Rust
/// queue, store, Internet, LAN, and Swift carrier boundaries. Media is outside
/// this milestone and must use a separately versioned chunk transport.
pub const MAX_WIRE_ENVELOPE_BYTES: usize = 1_048_576;
const ALLOWED_FLAGS: u16 = 0b0000_0011;
const ED25519_SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EnvType {
    Message = 1,
    Ack = 2,
    AliasGossip = 3,
    Capabilities = 4,
}

impl EnvType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Message),
            2 => Some(Self::Ack),
            3 => Some(Self::AliasGossip),
            4 => Some(Self::Capabilities),
            _ => None,
        }
    }
}

/// A locally built envelope that cannot be encoded canonically. Encoders fail
/// closed instead of wrapping a length into its fixed-width field.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeEncodeError {
    #[error("ratchet header does not fit the u16 hdr_len field")]
    HeaderTooLong,
    #[error("message ciphertext does not fit the u32 body_len field")]
    BodyTooLong,
    #[error("sender authentication does not fit the u16 auth_len field")]
    AuthenticationTooLong,
    #[error("envelope exceeds MAX_WIRE_ENVELOPE_BYTES")]
    TooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub env_type: u8,
    pub flags: u16,
    pub message_id: [u8; 16],
    pub routing_tag: [u8; 16],
    pub dest_device_hint: u64,
    pub created_at: u64,
    pub expires_at: u64,
    pub hop_limit: u8,
    pub replication_budget: u8,
    pub anti_replay_nonce: [u8; 12],
    pub ratchet_header_ciphertext: Vec<u8>,
    pub message_ciphertext: Vec<u8>,
    pub sender_authentication: Vec<u8>,
}

impl Envelope {
    fn body_lengths(&self) -> Result<(u16, u32), EnvelopeEncodeError> {
        let hdr_len = u16::try_from(self.ratchet_header_ciphertext.len())
            .map_err(|_| EnvelopeEncodeError::HeaderTooLong)?;
        let body_len = u32::try_from(self.message_ciphertext.len())
            .map_err(|_| EnvelopeEncodeError::BodyTooLong)?;
        Ok((hdr_len, body_len))
    }

    fn length_fields(&self) -> Result<(u16, u32, u16), EnvelopeEncodeError> {
        let (hdr_len, body_len) = self.body_lengths()?;
        let auth_len = u16::try_from(self.sender_authentication.len())
            .map_err(|_| EnvelopeEncodeError::AuthenticationTooLong)?;
        Ok((hdr_len, body_len, auth_len))
    }

    fn check_canonical_size(&self, auth_len: usize) -> Result<(), EnvelopeEncodeError> {
        let total = PREFIX_LEN
            .checked_add(self.ratchet_header_ciphertext.len())
            .and_then(|total| total.checked_add(self.message_ciphertext.len()))
            .and_then(|total| total.checked_add(auth_len))
            .ok_or(EnvelopeEncodeError::TooLarge)?;
        if total > MAX_WIRE_ENVELOPE_BYTES {
            return Err(EnvelopeEncodeError::TooLarge);
        }
        Ok(())
    }

    /// Fail-closed canonical encoder: rejects any length that does not fit its
    /// wire field and any envelope above [`MAX_WIRE_ENVELOPE_BYTES`].
    pub fn try_pack(&self) -> Result<Vec<u8>, EnvelopeEncodeError> {
        let lengths = self.length_fields()?;
        self.check_canonical_size(self.sender_authentication.len())?;
        Ok(self.pack_with(lengths))
    }

    /// Encodes the envelope. Size policy (the 1 MiB ceiling) is left to the
    /// caller or [`Self::try_pack`].
    ///
    /// # Panics
    ///
    /// If a length does not fit its fixed-width field (header or
    /// authentication above 65,535 bytes, body above `u32::MAX`). Emitting a
    /// wrapped length would corrupt field boundaries. Envelopes produced by
    /// [`Self::unpack`] can never trigger this.
    pub fn pack(&self) -> Vec<u8> {
        let lengths = self
            .length_fields()
            .unwrap_or_else(|error| panic!("RVN1 pack: {error}"));
        self.pack_with(lengths)
    }

    fn pack_with(&self, (hdr_len, body_len, auth_len): (u16, u32, u16)) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            PREFIX_LEN
                + self.ratchet_header_ciphertext.len()
                + self.message_ciphertext.len()
                + self.sender_authentication.len(),
        );
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(self.env_type);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.message_id);
        out.extend_from_slice(&self.routing_tag);
        out.extend_from_slice(&self.dest_device_hint.to_be_bytes());
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.push(self.hop_limit);
        out.push(self.replication_budget);
        out.extend_from_slice(&self.anti_replay_nonce);
        out.extend_from_slice(&hdr_len.to_be_bytes());
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(&auth_len.to_be_bytes());
        out.extend_from_slice(&self.ratchet_header_ciphertext);
        out.extend_from_slice(&self.message_ciphertext);
        out.extend_from_slice(&self.sender_authentication);
        out
    }

    pub fn unpack(raw: &[u8]) -> Option<Self> {
        // This is the network-strict decoder used by every Raven core ingress.
        // Reject the total-size bound before reading any attacker-controlled
        // length fields.
        if raw.len() < PREFIX_LEN
            || raw.len() > MAX_WIRE_ENVELOPE_BYTES
            || &raw[0..4] != MAGIC
            || raw[4] != VERSION
        {
            return None;
        }
        let env_type = raw[5];
        EnvType::from_u8(env_type)?;
        let flags = u16::from_be_bytes([raw[6], raw[7]]);
        if flags & !ALLOWED_FLAGS != 0 {
            return None;
        }
        let mut message_id = [0u8; 16];
        message_id.copy_from_slice(&raw[8..24]);
        let mut routing_tag = [0u8; 16];
        routing_tag.copy_from_slice(&raw[24..40]);
        let dest_device_hint = u64::from_be_bytes(raw[40..48].try_into().ok()?);
        let created_at = u64::from_be_bytes(raw[48..56].try_into().ok()?);
        let expires_at = u64::from_be_bytes(raw[56..64].try_into().ok()?);
        if expires_at <= created_at {
            return None;
        }
        let hop_limit = raw[64];
        let replication_budget = raw[65];
        let mut anti_replay_nonce = [0u8; 12];
        anti_replay_nonce.copy_from_slice(&raw[66..78]);
        let hdr_len = usize::from(u16::from_be_bytes([raw[78], raw[79]]));
        let body_len = usize::try_from(u32::from_be_bytes(raw[80..84].try_into().ok()?)).ok()?;
        let auth_len = usize::from(u16::from_be_bytes([raw[84], raw[85]]));
        if auth_len != ED25519_SIGNATURE_LEN {
            return None;
        }

        let hdr_end = PREFIX_LEN.checked_add(hdr_len)?;
        let body_end = hdr_end.checked_add(body_len)?;
        let auth_end = body_end.checked_add(auth_len)?;
        if raw.len() != auth_end {
            return None;
        }
        let ratchet_header_ciphertext = raw[PREFIX_LEN..hdr_end].to_vec();
        let message_ciphertext = raw[hdr_end..body_end].to_vec();
        let sender_authentication = raw[body_end..auth_end].to_vec();
        Some(Self {
            env_type,
            flags,
            message_id,
            routing_tag,
            dest_device_hint,
            created_at,
            expires_at,
            hop_limit,
            replication_budget,
            anti_replay_nonce,
            ratchet_header_ciphertext,
            message_ciphertext,
            sender_authentication,
        })
    }

    /// Fail-closed signing bytes: rejects lengths that do not fit their
    /// fields and any envelope whose canonical encoding (with a 64-byte
    /// signature) would exceed [`MAX_WIRE_ENVELOPE_BYTES`].
    pub fn try_signing_bytes(&self) -> Result<Vec<u8>, EnvelopeEncodeError> {
        let lengths = self.body_lengths()?;
        self.check_canonical_size(ED25519_SIGNATURE_LEN)?;
        Ok(self.signing_bytes_with(lengths))
    }

    /// Signing bytes: mutable fields zeroed, auth_len fixed to 64, ciphertext blobs by hash.
    ///
    /// # Panics
    ///
    /// Under the same field-width condition as [`Self::pack`].
    pub fn signing_bytes(&self) -> Vec<u8> {
        let lengths = self
            .body_lengths()
            .unwrap_or_else(|error| panic!("RVN1 signing bytes: {error}"));
        self.signing_bytes_with(lengths)
    }

    fn signing_bytes_with(&self, (hdr_len, body_len): (u16, u32)) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(PREFIX_LEN);
        prefix.extend_from_slice(MAGIC);
        prefix.push(VERSION);
        prefix.push(self.env_type);
        prefix.extend_from_slice(&self.flags.to_be_bytes());
        prefix.extend_from_slice(&self.message_id);
        prefix.extend_from_slice(&self.routing_tag);
        prefix.extend_from_slice(&0u64.to_be_bytes()); // dest_device_hint
        prefix.extend_from_slice(&self.created_at.to_be_bytes());
        prefix.extend_from_slice(&self.expires_at.to_be_bytes());
        prefix.push(0); // hop_limit
        prefix.push(0); // replication_budget
        prefix.extend_from_slice(&self.anti_replay_nonce);
        prefix.extend_from_slice(&hdr_len.to_be_bytes());
        prefix.extend_from_slice(&body_len.to_be_bytes());
        prefix.extend_from_slice(&64u16.to_be_bytes()); // canonical auth_len
        debug_assert_eq!(prefix.len(), PREFIX_LEN);

        let mut out = prefix;
        out.extend_from_slice(&Sha256::digest(&self.ratchet_header_ciphertext));
        out.extend_from_slice(&Sha256::digest(&self.message_ciphertext));
        out
    }

    pub fn sign_with(&mut self, identity: &Identity) {
        let sig = identity.sign(&self.signing_bytes());
        self.sender_authentication = sig.to_vec();
    }

    pub fn verify(&self, signer_ed_pub: &[u8; 32]) -> bool {
        if self.sender_authentication.len() != ED25519_SIGNATURE_LEN {
            return false;
        }
        // A non-canonical (unencodable or oversized) envelope never verifies.
        let Ok(signing) = self.try_signing_bytes() else {
            return false;
        };
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&self.sender_authentication);
        Identity::verify(signer_ed_pub, &signing, &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn structurally_valid_envelope() -> Envelope {
        Envelope {
            env_type: EnvType::Message as u8,
            flags: 0,
            message_id: [0x11; 16],
            routing_tag: [0x22; 16],
            dest_device_hint: 0,
            created_at: 10,
            expires_at: 20,
            hop_limit: 8,
            replication_budget: 3,
            anti_replay_nonce: [0x33; 12],
            ratchet_header_ciphertext: vec![0x44; 3],
            message_ciphertext: vec![0x55; 5],
            // Structure decoding checks the canonical signature width. Signature
            // authenticity remains the caller's subsequent endpoint check.
            sender_authentication: vec![0; ED25519_SIGNATURE_LEN],
        }
    }

    #[test]
    fn strict_unpack_accepts_registered_type_and_defined_flags() {
        let mut env = structurally_valid_envelope();
        env.env_type = EnvType::Capabilities as u8;
        env.flags = ALLOWED_FLAGS;

        assert_eq!(Envelope::unpack(&env.pack()), Some(env));
    }

    #[test]
    fn strict_unpack_rejects_unknown_type_and_reserved_flags() {
        let packed = structurally_valid_envelope().pack();

        for unknown_type in [0, 5, u8::MAX] {
            let mut malformed = packed.clone();
            malformed[5] = unknown_type;
            assert!(Envelope::unpack(&malformed).is_none());
        }

        let mut reserved_flags = packed;
        reserved_flags[6..8].copy_from_slice(&0x0004u16.to_be_bytes());
        assert!(Envelope::unpack(&reserved_flags).is_none());
    }

    #[test]
    fn strict_unpack_requires_canonical_authentication_length() {
        let mut env = structurally_valid_envelope();
        env.sender_authentication
            .truncate(ED25519_SIGNATURE_LEN - 1);
        assert!(Envelope::unpack(&env.pack()).is_none());

        env.sender_authentication.clear();
        assert!(Envelope::unpack(&env.pack()).is_none());
    }

    #[test]
    fn strict_unpack_rejects_non_increasing_time_interval() {
        let mut env = structurally_valid_envelope();
        env.expires_at = env.created_at;
        assert!(Envelope::unpack(&env.pack()).is_none());

        env.expires_at = env.created_at - 1;
        assert!(Envelope::unpack(&env.pack()).is_none());
    }

    #[test]
    fn encoders_fail_closed_instead_of_wrapping_lengths() {
        let identity = Identity::from_seed(&[0x61; 32]);
        let mut header_overflow = structurally_valid_envelope();
        header_overflow.ratchet_header_ciphertext = vec![0x44; usize::from(u16::MAX) + 1];
        assert_eq!(
            header_overflow.try_pack(),
            Err(EnvelopeEncodeError::HeaderTooLong)
        );
        assert_eq!(
            header_overflow.try_signing_bytes(),
            Err(EnvelopeEncodeError::HeaderTooLong)
        );
        assert!(std::panic::catch_unwind(|| header_overflow.pack()).is_err());
        assert!(std::panic::catch_unwind(|| header_overflow.signing_bytes()).is_err());
        // Previously these wrapped hdr_len to 0 and signed/emitted the result.
        // Verification of such a value is a clean `false`, never a panic.
        let mut signed_overflow = header_overflow.clone();
        signed_overflow.sender_authentication = vec![0x11; ED25519_SIGNATURE_LEN];
        assert!(!signed_overflow.verify(&identity.public_key_bytes()));

        let mut auth_overflow = structurally_valid_envelope();
        auth_overflow.sender_authentication = vec![0; usize::from(u16::MAX) + 1];
        assert_eq!(
            auth_overflow.try_pack(),
            Err(EnvelopeEncodeError::AuthenticationTooLong)
        );

        let mut oversized = structurally_valid_envelope();
        oversized.message_ciphertext = vec![0x55; MAX_WIRE_ENVELOPE_BYTES];
        assert_eq!(oversized.try_pack(), Err(EnvelopeEncodeError::TooLarge));
        assert_eq!(
            oversized.try_signing_bytes(),
            Err(EnvelopeEncodeError::TooLarge)
        );
        oversized.sign_with(&identity);
        assert!(!oversized.verify(&identity.public_key_bytes()));
        // The size policy of `pack` itself is unchanged; receivers reject it.
        assert!(Envelope::unpack(&oversized.pack()).is_none());

        let mut canonical = structurally_valid_envelope();
        canonical.sign_with(&identity);
        assert_eq!(canonical.try_pack().unwrap(), canonical.pack());
        assert_eq!(
            canonical.try_signing_bytes().unwrap(),
            canonical.signing_bytes()
        );
        assert!(canonical.verify(&identity.public_key_bytes()));
    }

    #[test]
    fn strict_unpack_rejects_length_abuse_and_oversized_frames() {
        let mut impossible_body = structurally_valid_envelope().pack();
        impossible_body[80..84].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Envelope::unpack(&impossible_body).is_none());

        let oversized = vec![0u8; MAX_WIRE_ENVELOPE_BYTES + 1];
        assert!(Envelope::unpack(&oversized).is_none());
    }
}
