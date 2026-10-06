//! ATSAM hybrid root derivation given known shared secrets (no ML-KEM eng).
//!
//! Matches iOS `ATSAMRootDerivation.deriveRoot`:
//!   K_root = HKDF(ikm=Z_X||Z_PQ, salt=transcript_hash,
//!                 info="ATSAM/v1/pair-init"||transcript_hash, L=32)
//!
//! This module only derives the root from supplied shares; ML-KEM
//! encapsulation/decapsulation and the checked X25519 ECDH that feed it live in
//! `atsam_mlkem.rs` (`begin_hybrid_initiation` / `respond_hybrid_root`).

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const PAIR_INIT: &[u8] = b"ATSAM/v1/pair-init";
pub const TRANSCRIPT_DOMAIN: &[u8] = b"ATSAM/v1/transcript";

/// SHA-256(domain || material) — matches ATSAMTranscript domain prepend.
pub fn transcript_hash(material: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TRANSCRIPT_DOMAIN);
    h.update(material);
    h.finalize().into()
}

/// Derive K_root from 32-byte classical + 32-byte PQ shares + transcript hash.
pub fn derive_root(z_x: &[u8; 32], z_pq: &[u8; 32], transcript_hash: &[u8; 32]) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(z_x);
    ikm[32..].copy_from_slice(z_pq);
    let mut info = Vec::with_capacity(PAIR_INIT.len() + 32);
    info.extend_from_slice(PAIR_INIT);
    info.extend_from_slice(transcript_hash);
    let hk = Hkdf::<Sha256>::new(Some(transcript_hash.as_slice()), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("hkdf");
    ikm.zeroize();
    okm
}

/// X25519 ECDH → Z_X. Caller supplies Z_PQ (zeros for classical-only KAT).
pub fn x25519_shared(secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*secret);
    let pk = PublicKey::from(*peer_public);
    sk.diffie_hellman(&pk).to_bytes()
}

/// Production pairing variant: rejects non-contributory/low-order peer keys
/// instead of feeding an all-zero X25519 result into the hybrid root.
pub fn x25519_shared_checked(
    secret: &[u8; 32],
    peer_public: &[u8; 32],
) -> Result<[u8; 32], String> {
    let shared = x25519_shared(secret, peer_public);
    if shared.iter().all(|byte| *byte == 0) {
        return Err("X25519 non-contributory peer key".into());
    }
    Ok(shared)
}

/// Any 32 bytes work: X25519 clamps them to `8·k` with `2^251 <= k < 2^252`.
const CONTRIBUTORY_PROBE_SCALAR: [u8; 32] = [0x5a; 32];

/// Public-key check equivalent to `x25519_shared_checked` succeeding for every
/// private key. Clamped X25519 scalars are multiples of the cofactor and are
/// smaller than both the curve and twist prime orders, so the ladder output
/// is all-zero exactly for inputs in the small-order torsion (u = 0, 1, the
/// order-8 points, p-1, p, p+1, ...), independent of the scalar. Receivers use
/// this to reject a non-contributory peer key before any state is persisted;
/// `pair_init::validate_init` is the receive-path call site (the checked DH in
/// `x25519_shared_checked` is the second guard inside `respond_hybrid_root`).
pub fn x25519_public_is_contributory(public: &[u8; 32]) -> bool {
    let mut probe = x25519_shared(&CONTRIBUTORY_PROBE_SCALAR, public);
    let contributory = probe.iter().any(|byte| *byte != 0);
    probe.zeroize();
    contributory
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_known_vector() {
        let z_x = [0x11u8; 32];
        let z_pq = [0x22u8; 32];
        let th = transcript_hash(b"kat-pair-material");
        assert_eq!(
            hex::encode(th),
            "46256683869ab07b5ea52f5d46628d027b04a400d8ee160366388e38606ffe46"
        );
        let root = derive_root(&z_x, &z_pq, &th);
        // Locked for shared-vector export — do not change without bumping vector id.
        assert_eq!(
            hex::encode(root),
            "67d6ad5db5b0e7012df9e9a7c7167cddb238b8c4bd0b4098a36cfbe7452ed8de"
        );
    }

    #[test]
    fn x25519_agreement() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        // clamp-ish: x25519-dalek StaticSecret clamps internally
        let pa = PublicKey::from(&StaticSecret::from(a)).to_bytes();
        let pb = PublicKey::from(&StaticSecret::from(b)).to_bytes();
        let zab = x25519_shared(&a, &pb);
        let zba = x25519_shared(&b, &pa);
        assert_eq!(zab, zba);
    }

    #[test]
    fn non_contributory_x25519_key_is_rejected() {
        assert!(x25519_shared_checked(&[7u8; 32], &[0u8; 32]).is_err());
    }

    /// Canonical and non-canonical encodings of the small-order points.
    fn low_order_encodings() -> Vec<[u8; 32]> {
        let hex_points = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ];
        let mut points: Vec<[u8; 32]> = hex_points
            .iter()
            .map(|value| hex::decode(value).unwrap().try_into().unwrap())
            .collect();
        // X25519 ignores the top bit, so the same points with bit 255 set are
        // equally non-contributory.
        let with_top_bit: Vec<[u8; 32]> = points
            .iter()
            .map(|point| {
                let mut point = *point;
                point[31] |= 0x80;
                point
            })
            .collect();
        points.extend(with_top_bit);
        points
    }

    #[test]
    fn low_order_public_keys_are_not_contributory_for_any_secret() {
        for point in low_order_encodings() {
            assert!(!x25519_public_is_contributory(&point), "{point:02x?}");
            for secret in [[0x01u8; 32], [0x77; 32], [0xff; 32]] {
                assert!(x25519_shared_checked(&secret, &point).is_err());
            }
        }
    }

    #[test]
    fn honest_public_keys_are_contributory() {
        for seed in [[0x01u8; 32], [0x42; 32], [0xfe; 32]] {
            let public = PublicKey::from(&StaticSecret::from(seed)).to_bytes();
            assert!(x25519_public_is_contributory(&public));
        }
        assert!(x25519_public_is_contributory(
            &x25519_dalek::X25519_BASEPOINT_BYTES
        ));
    }
}
