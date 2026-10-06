//! Portable ATSAM RVNA1 v2 AEAD given a known `K_root` (no ML-KEM).
//!
//! Primitives match `ATSAMMessageSealer` / `ATSAMChainRatchet` on iOS:
//! HKDF-SHA256 chain labels + ChaCha20-Poly1305 + SHA-256 AAD.
//! This module does **not** establish a hybrid root itself: ML-KEM + X25519
//! pairing (`begin_hybrid_initiation` / `respond_hybrid_root`) lives in
//! `atsam_mlkem.rs`. Relays must still treat unknown-root frames as opaque.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::atsam_kdf::{advance_chain_key, initial_chain_key, message_key};
use crate::seal::{ATSAM_PROTO_V2, SEAL_MAGIC_RVNA1, STUB_SUITE};

pub const AAD_DOMAIN: &[u8] = b"ATSAM/v1/msg-seal/aad";
/// Stateless portable helpers derive from `CK0` and therefore do O(index)
/// work. Bound that work; production ratchets must use persisted chain state.
pub const MAX_PORTABLE_CHAIN_INDEX: u32 = 4_096;

/// AAD for RVNA1 v1 (accept-only layout): no proto/suite/index in the hash.
pub fn build_aad_v1(sender: &str, recipient: &str, msg_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(AAD_DOMAIN);
    h.update([0]);
    h.update([0]);
    h.update(sender.as_bytes());
    h.update([0]);
    h.update(recipient.as_bytes());
    h.update([0]);
    h.update(msg_id.as_bytes());
    h.finalize().into()
}

/// AAD for RVNA1 v2: binds proto, suite, and chain index (Swift `buildAAD`).
pub fn build_aad_v2(
    proto: u8,
    suite: u8,
    index: u32,
    sender: &str,
    recipient: &str,
    msg_id: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(AAD_DOMAIN);
    h.update([0]);
    h.update([proto, suite]);
    h.update(index.to_be_bytes());
    h.update([0]);
    h.update(sender.as_bytes());
    h.update([0]);
    h.update(recipient.as_bytes());
    h.update([0]);
    h.update(msg_id.as_bytes());
    h.finalize().into()
}

/// Derive `K_msg` at chain `index` from `K_root` (send/receive at exact index).
fn key_at_index(root: &[u8; 32], sender: &str, recipient: &str, index: u32) -> Zeroizing<[u8; 32]> {
    let mut ck = Zeroizing::new(initial_chain_key(root, sender, recipient));
    for _ in 0..index {
        *ck = advance_chain_key(&ck);
    }
    Zeroizing::new(message_key(&ck, sender, recipient))
}

/// Seal plaintext under RVNA1 v2 with a known root and fixed nonce (KATs / tests).
pub fn seal_rvna1_v2(
    root: &[u8; 32],
    sender: &str,
    recipient: &str,
    msg_id: &str,
    index: u32,
    plaintext: &[u8],
    nonce12: &[u8; 12],
) -> Result<Vec<u8>, String> {
    if index > MAX_PORTABLE_CHAIN_INDEX {
        return Err("chain index exceeds portable helper limit".into());
    }
    if sender.is_empty()
        || recipient.is_empty()
        || msg_id.is_empty()
        || sender.contains('\0')
        || recipient.contains('\0')
        || msg_id.contains('\0')
    {
        return Err("empty or NUL id".into());
    }
    let key = key_at_index(root, sender, recipient, index);
    let aad = build_aad_v2(ATSAM_PROTO_V2, STUB_SUITE, index, sender, recipient, msg_id);
    let cipher = ChaCha20Poly1305::new((&*key).into());
    let nonce = Nonce::from_slice(nonce12);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| "seal failed".to_string())?;
    let mut wire = Vec::with_capacity(8 + 2 + 4 + 12 + ct.len());
    wire.extend_from_slice(&SEAL_MAGIC_RVNA1);
    wire.push(ATSAM_PROTO_V2);
    wire.push(STUB_SUITE);
    wire.extend_from_slice(&index.to_be_bytes());
    wire.extend_from_slice(nonce12);
    wire.extend_from_slice(&ct);
    Ok(wire)
}

/// Unseal RVNA1 v2 when `K_root` is known (portable path — no ML-KEM).
pub fn unseal_rvna1_v2(
    root: &[u8; 32],
    wire: &[u8],
    sender: &str,
    recipient: &str,
    msg_id: &str,
) -> Result<Vec<u8>, String> {
    if wire.len() < 8 + 2 + 4 + 12 + 16 {
        return Err("truncated".into());
    }
    if wire[..8] != SEAL_MAGIC_RVNA1 {
        return Err("bad magic".into());
    }
    if wire[8] != ATSAM_PROTO_V2 || wire[9] != STUB_SUITE {
        return Err("unsupported proto/suite".into());
    }
    let index = u32::from_be_bytes([wire[10], wire[11], wire[12], wire[13]]);
    if index > MAX_PORTABLE_CHAIN_INDEX {
        return Err("chain index exceeds portable helper limit".into());
    }
    let nonce = Nonce::from_slice(&wire[14..26]);
    let ct = &wire[26..];
    let key = key_at_index(root, sender, recipient, index);
    let aad = build_aad_v2(ATSAM_PROTO_V2, STUB_SUITE, index, sender, recipient, msg_id);
    let cipher = ChaCha20Poly1305::new((&*key).into());
    cipher
        .decrypt(nonce, Payload { msg: ct, aad: &aad })
        .map_err(|_| "unseal failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_v2_diverges_on_index() {
        let a = build_aad_v2(0x02, 0x01, 0, "alice", "bob", "m1");
        let b = build_aad_v2(0x02, 0x01, 1, "alice", "bob", "m1");
        assert_ne!(a, b);
    }

    #[test]
    fn roundtrip_known_root() {
        let root = [0x11u8; 32];
        let nonce = [0xABu8; 12];
        let wire = seal_rvna1_v2(
            &root,
            "alice",
            "bob",
            "msg-001",
            0,
            b"portable-atsam-v2",
            &nonce,
        )
        .unwrap();
        assert_eq!(&wire[..8], &SEAL_MAGIC_RVNA1);
        assert_eq!(wire[8], ATSAM_PROTO_V2);
        let pt = unseal_rvna1_v2(&root, &wire, "alice", "bob", "msg-001").unwrap();
        assert_eq!(pt, b"portable-atsam-v2");
    }

    #[test]
    fn wrong_msg_id_fails() {
        let root = [0x11u8; 32];
        let nonce = [0xABu8; 12];
        let wire = seal_rvna1_v2(&root, "alice", "bob", "msg-001", 0, b"x", &nonce).unwrap();
        assert!(unseal_rvna1_v2(&root, &wire, "alice", "bob", "msg-002").is_err());
    }

    #[test]
    fn portable_index_work_is_bounded() {
        let err = seal_rvna1_v2(
            &[0x11; 32],
            "alice",
            "bob",
            "msg-001",
            MAX_PORTABLE_CHAIN_INDEX + 1,
            b"x",
            &[0xAB; 12],
        )
        .unwrap_err();
        assert!(err.contains("portable helper limit"));
    }
}
