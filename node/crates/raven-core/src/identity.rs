//! Ed25519 identity — never log or print private keys.

use crate::address::encode_address;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

pub struct Identity {
    verifying: VerifyingKey,
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self { verifying, signing }
    }

    /// Load from 32-byte RFC-8032 seed (test vectors / persistence).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let verifying = signing.verifying_key();
        Self { verifying, signing }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    pub fn address(&self) -> String {
        encode_address(&self.public_key_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// Strict Ed25519 verification for every identity/device/record signature.
    ///
    /// Rejects small-order ("weak") public keys and small-order `R`, and
    /// requires canonical `s`. A weak key such as the identity point accepts
    /// `(R = identity, s = 0)` for *every* message, so non-strict
    /// verification would let a crafted key "sign" arbitrary PairInit, cert,
    /// revocation or record bytes without a private key. Honestly generated
    /// keys never hit these checks, so interop with other RFC 8032 signers is
    /// unchanged.
    pub fn verify(pub_key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(pub_key) else {
            return false;
        };
        if vk.is_weak() {
            return false;
        }
        let Ok(signature) = Signature::from_slice(sig) else {
            return false;
        };
        vk.verify_strict(msg, &signature).is_ok()
    }

    /// Seed bytes for encrypted persistence only — callers MUST NOT print.
    ///
    /// Returns a plain `Copy` array; the caller owns wiping it. New code should
    /// prefer [`Identity::seed_zeroizing`], which wipes itself on drop.
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Same bytes as [`Identity::seed_bytes`], wrapped so the copy is wiped on
    /// drop (and cannot be silently left behind in a plain local).
    pub fn seed_zeroizing(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    /// Compressed Edwards identity point (y = 1): order 1, i.e. a weak key.
    const IDENTITY_POINT: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    #[test]
    fn weak_key_universal_forgery_rejected() {
        // (R = identity, s = 0) satisfies the cofactorless equation for any
        // message under the identity public key.
        let mut forged = [0u8; 64];
        forged[..32].copy_from_slice(&IDENTITY_POINT);
        for msg in [&b"rvn1/devcert anything"[..], b"PairInit transcript"] {
            let vk = VerifyingKey::from_bytes(&IDENTITY_POINT).unwrap();
            assert!(
                vk.verify(msg, &Signature::from_bytes(&forged)).is_ok(),
                "non-strict verify accepts the forgery"
            );
            assert!(!Identity::verify(&IDENTITY_POINT, msg, &forged));
        }
    }

    #[test]
    fn seed_zeroizing_matches_seed_bytes_and_roundtrips() {
        let id = Identity::from_seed(&[9u8; 32]);
        let wrapped = id.seed_zeroizing();
        assert_eq!(*wrapped, id.seed_bytes());
        assert_eq!(*wrapped, [9u8; 32]);
        let back = Identity::from_seed(&wrapped);
        assert_eq!(back.public_key_bytes(), id.public_key_bytes());
    }

    #[test]
    fn honest_signatures_still_verify_strictly() {
        let id = Identity::from_seed(&[7u8; 32]);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&IDENTITY_POINT);
        assert!(!Identity::verify(&id.public_key_bytes(), b"m", &sig));
        let good = id.sign(b"m");
        assert!(Identity::verify(&id.public_key_bytes(), b"m", &good));
        assert!(!Identity::verify(&id.public_key_bytes(), b"n", &good));
    }
}
