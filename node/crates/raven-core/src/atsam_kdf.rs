//! ATSAM chain / label KATs portable without ML-KEM.
//!
//! Hybrid ML-KEM pairing lives in `atsam_mlkem.rs` (`begin_hybrid_initiation` /
//! `respond_hybrid_root`); this module performs no pairing itself and mirrors
//! the iOS chain ratchet (`ATSAMChainRatchet.swift`). These helpers prove
//! label/info encoding and HKDF agreement so Rust can verify shared vectors and
//! harden the opaque path.
//! See `protocol/ATSAM_PRIMITIVE_MAPPING_V1.md` § honesty table.

use hkdf::Hkdf;
use sha2::Sha256;

pub const LABEL_CHAIN_INIT: &[u8] = b"ATSAM/v2/chain-init";
pub const LABEL_CHAIN_ADVANCE: &[u8] = b"ATSAM/v2/chain-advance";
pub const LABEL_MSG_KEY: &[u8] = b"ATSAM/v2/msg-key";
pub const SALT_MSG_SEAL: &[u8] = b"ATSAM/v2/msg-seal/salt";

fn hkdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 32] {
    let hk = match salt {
        Some(s) => Hkdf::<Sha256>::new(Some(s), ikm),
        None => Hkdf::<Sha256>::new(None, ikm),
    };
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("hkdf");
    okm
}

/// `CK₀ = HKDF(K_root, info = "ATSAM/v2/chain-init" ‖ 0 ‖ S ‖ 0 ‖ R)`.
pub fn initial_chain_key(root: &[u8; 32], sender: &str, recipient: &str) -> [u8; 32] {
    let mut info = Vec::with_capacity(LABEL_CHAIN_INIT.len() + 2 + sender.len() + recipient.len());
    info.extend_from_slice(LABEL_CHAIN_INIT);
    info.push(0);
    info.extend_from_slice(sender.as_bytes());
    info.push(0);
    info.extend_from_slice(recipient.as_bytes());
    hkdf32(root, None, &info)
}

/// `CK_{i+1} = HKDF(CK_i, info = "ATSAM/v2/chain-advance")`.
pub fn advance_chain_key(chain_key: &[u8; 32]) -> [u8; 32] {
    hkdf32(chain_key, None, LABEL_CHAIN_ADVANCE)
}

/// `K_msg = HKDF(CK, salt = "ATSAM/v2/msg-seal/salt", info = "ATSAM/v2/msg-key" ‖ 0 ‖ S ‖ 0 ‖ R)`.
pub fn message_key(chain_key: &[u8; 32], sender: &str, recipient: &str) -> [u8; 32] {
    let mut info = Vec::with_capacity(LABEL_MSG_KEY.len() + 2 + sender.len() + recipient.len());
    info.extend_from_slice(LABEL_MSG_KEY);
    info.push(0);
    info.extend_from_slice(sender.as_bytes());
    info.push(0);
    info.extend_from_slice(recipient.as_bytes());
    hkdf32(chain_key, Some(SALT_MSG_SEAL), &info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_kdf_fixed_vector() {
        let root = [0x11u8; 32];
        let ck0 = initial_chain_key(&root, "alice", "bob");
        assert_eq!(
            hex::encode(ck0),
            "39f17981af60a336e251a8febf51c70f559c536fad19875776cc87fd7f76781d"
        );
        let ck1 = advance_chain_key(&ck0);
        assert_eq!(
            hex::encode(ck1),
            "6aaed354f7111c07091980aaa6c700464439f7b9d2033f59178f960261a4a0cd"
        );
        let kmsg = message_key(&ck0, "alice", "bob");
        assert_eq!(
            hex::encode(kmsg),
            "d74716298bd6d3a7211ace359f053f6417f9ad6d6b485257a0846d14da9cd5a0"
        );
        // Directions must diverge.
        assert_ne!(message_key(&ck0, "bob", "alice"), kmsg);
    }
}
