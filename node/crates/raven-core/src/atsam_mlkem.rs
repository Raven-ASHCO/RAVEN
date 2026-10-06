//! ML-KEM-768 + X25519 hybrid pairing toward ATSAM K_root.
//!
//! Spec: `protocol/ATSAM_PRIMITIVE_MAPPING_V1.md`
//! Uses RustCrypto `ml-kem` (FIPS 203). Shared secret feeds `atsam_root::derive_root`
//! together with X25519 ECDH — matching the iOS hybrid composition.
//!
//! RNG bridging: workspace `rand` 0.8 ≠ ml-kem's rand_core 0.10 `CryptoRng`, so we
//! draw bytes via `RngCore` and feed seed / deterministic encap (`hazmat`) APIs.
//!
//! Honest gap closed for software KATs: shared-vectors/rvn1/atsam/mlkem768_hybrid_kat_001.json
//! is verified by Rust (`atsam_mlkem` tests) and by Swift CryptoKit on macOS/iOS 26+
//! (`ATSAMMlKemHybridKatTests`). Public Internet Kad / CGNAT remain BLOCKED_HARDWARE.

use ml_kem::kem::{Decapsulate, Key, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768, Seed, B32};
use rand_core::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::atsam_root::{derive_root, x25519_shared_checked};

/// ML-KEM-768 encapsulation key size (FIPS 203).
pub const EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext size.
pub const CT_LEN: usize = 1088;
/// Preferred private seed size for ML-KEM DK.
pub const DK_SEED_LEN: usize = 64;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridKeypair {
    pub x25519_secret: [u8; 32],
    pub x25519_public: [u8; 32],
    /// 64-byte ML-KEM seed (preferred private form).
    pub mlkem_seed: [u8; DK_SEED_LEN],
    pub mlkem_ek_bytes: Vec<u8>,
}

impl HybridKeypair {
    pub fn generate<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        let mut x_seed = [0u8; 32];
        rng.fill_bytes(&mut x_seed);
        let sk = StaticSecret::from(x_seed);
        x_seed.zeroize();
        let x25519_public = PublicKey::from(&sk).to_bytes();
        let x25519_secret = sk.to_bytes();

        let mut seed_bytes = [0u8; DK_SEED_LEN];
        rng.fill_bytes(&mut seed_bytes);
        let mut seed = Seed::try_from(seed_bytes.as_slice()).expect("seed len");
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        seed.as_mut_slice().zeroize();
        let mlkem_seed = seed_bytes;
        seed_bytes.zeroize();
        let ek_encoded = dk.encapsulation_key().to_bytes();
        let mlkem_ek_bytes = ek_encoded.as_slice().to_vec();
        assert_eq!(mlkem_ek_bytes.len(), EK_LEN);
        Self {
            x25519_secret,
            x25519_public,
            mlkem_seed,
            mlkem_ek_bytes,
        }
    }
}

/// Zeroizing initiator-side shares retained only until the complete signed
/// PairInit transcript (which includes the ML-KEM ciphertext) is available.
/// This closes the transcript/ciphertext dependency without deriving a root
/// from an incomplete or unsigned transcript.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PendingHybridInitiation {
    ciphertext: Vec<u8>,
    z_x: [u8; 32],
    z_pq: [u8; 32],
}

impl PendingHybridInitiation {
    /// Public ML-KEM ciphertext to place in the PairInit before it is signed.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Bind both shares to the hash of the complete signed PairInit. Consuming
    /// `self` zeroizes the retained shares; the returned root becomes the
    /// caller's protected-session-storage responsibility.
    pub fn finalize(mut self, transcript_hash: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        let root = derive_root(&self.z_x, &self.z_pq, transcript_hash);
        let ciphertext = std::mem::take(&mut self.ciphertext);
        (ciphertext, root)
    }
}

fn parse_ek(bytes: &[u8]) -> Result<EncapsulationKey<MlKem768>, String> {
    if bytes.len() != EK_LEN {
        return Err("mlkem ek length".into());
    }
    let key: Key<EncapsulationKey<MlKem768>> =
        bytes.try_into().map_err(|_| "ek array".to_string())?;
    EncapsulationKey::<MlKem768>::new(&key).map_err(|_| "ek decode".into())
}

/// Begin an offline hybrid PairInit without prematurely deriving `K_root`.
/// The caller signs a PairInit containing `pending.ciphertext()`, computes the
/// full transcript hash, and only then consumes the pending value via
/// [`PendingHybridInitiation::finalize`].
pub fn begin_hybrid_initiation<R: RngCore + ?Sized>(
    rng: &mut R,
    our_x_secret: &[u8; 32],
    peer_x_public: &[u8; 32],
    peer_mlkem_ek: &[u8],
) -> Result<PendingHybridInitiation, String> {
    let ek = parse_ek(peer_mlkem_ek)?;
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);
    let (ciphertext, mut z_pq) = {
        let mut m_arr = match B32::try_from(m.as_slice()) {
            Ok(value) => value,
            Err(_) => {
                m.zeroize();
                return Err("m".into());
            }
        };
        let (ct, mut ss) = ek.encapsulate_deterministic(&m_arr);
        // Either the coins or the shared key alone recompute Z_PQ.
        m.zeroize();
        m_arr.as_mut_slice().zeroize();
        let mut z_pq = [0u8; 32];
        z_pq.copy_from_slice(ss.as_slice());
        ss.as_mut_slice().zeroize();
        let ciphertext = ct.as_slice().to_vec();
        if ciphertext.len() != CT_LEN {
            z_pq.zeroize();
            return Err("ct length".into());
        }
        (ciphertext, z_pq)
    };
    let mut z_x = match x25519_shared_checked(our_x_secret, peer_x_public) {
        Ok(shared) => shared,
        Err(error) => {
            z_pq.zeroize();
            return Err(error);
        }
    };
    let pending = PendingHybridInitiation {
        ciphertext,
        z_x,
        z_pq,
    };
    z_x.zeroize();
    z_pq.zeroize();
    Ok(pending)
}

/// Responder: ECDH + ML-KEM.Decap(ct) → K_root.
pub fn respond_hybrid_root(
    our_x_secret: &[u8; 32],
    peer_x_public: &[u8; 32],
    our_mlkem_seed: &[u8; DK_SEED_LEN],
    ct_pq: &[u8],
    transcript_hash: &[u8; 32],
) -> Result<[u8; 32], String> {
    if ct_pq.len() != CT_LEN {
        return Err("mlkem ct length".into());
    }
    let mut seed = Seed::try_from(our_mlkem_seed.as_slice()).map_err(|_| "seed")?;
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
    // `Seed` is `Copy`; wipe the local copy of the long-term decapsulation seed
    // (mirrors `HybridKeypair::generate`). `dk` zeroizes itself on drop.
    seed.as_mut_slice().zeroize();
    let ct = ct_pq.try_into().map_err(|_| "ct array")?;
    let mut ss = dk.decapsulate(&ct);
    let mut z_pq = [0u8; 32];
    z_pq.copy_from_slice(ss.as_slice());
    ss.as_mut_slice().zeroize();
    let mut z_x = match x25519_shared_checked(our_x_secret, peer_x_public) {
        Ok(shared) => shared,
        Err(error) => {
            z_pq.zeroize();
            return Err(error);
        }
    };
    let root = derive_root(&z_x, &z_pq, transcript_hash);
    z_x.zeroize();
    z_pq.zeroize();
    Ok(root)
}

/// Deterministic encap for KATs only. Caller-chosen coins make `Z_PQ`
/// predictable, so this is not part of the default-build API.
#[cfg(any(test, feature = "test-helpers"))]
pub fn encapsulate_deterministic(
    peer_mlkem_ek: &[u8],
    m: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let ek = parse_ek(peer_mlkem_ek)?;
    let m_arr = B32::try_from(m.as_slice()).map_err(|_| "m")?;
    let (ct, ss) = ek.encapsulate_deterministic(&m_arr);
    let mut z = [0u8; 32];
    z.copy_from_slice(ss.as_slice());
    Ok((ct.as_slice().to_vec(), z))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atsam_root::{derive_root, transcript_hash, x25519_shared};
    use ml_kem::kem::Decapsulate;
    use ml_kem::{DecapsulationKey, MlKem768, Seed};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use serde_json::Value;
    use std::path::PathBuf;

    #[test]
    fn hybrid_agreement() {
        let mut rng = StdRng::seed_from_u64(42);
        let alice = HybridKeypair::generate(&mut rng);
        let bob = HybridKeypair::generate(&mut rng);
        let th = transcript_hash(b"hybrid-kat");
        let (ct, root_a) = begin_hybrid_initiation(
            &mut rng,
            &alice.x25519_secret,
            &bob.x25519_public,
            &bob.mlkem_ek_bytes,
        )
        .unwrap()
        .finalize(&th);
        let root_b = respond_hybrid_root(
            &bob.x25519_secret,
            &alice.x25519_public,
            &bob.mlkem_seed,
            &ct,
            &th,
        )
        .unwrap();
        assert_eq!(root_a, root_b);
        assert_eq!(ct.len(), CT_LEN);
        assert_eq!(bob.mlkem_ek_bytes.len(), EK_LEN);
    }

    fn vectors_root() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.pop();
        p.join("shared-vectors").join("rvn1")
    }

    fn load_kat() -> Value {
        let path = vectors_root().join("atsam/mlkem768_hybrid_kat_001.json");
        let raw =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{e} {}", path.display()));
        serde_json::from_str(&raw).expect("json")
    }

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    fn hex64(s: &str) -> [u8; 64] {
        let v = hex::decode(s).unwrap();
        let mut a = [0u8; 64];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn shared_vector_rust_deterministic_encap_and_hybrid_root() {
        let v = load_kat();
        let inp = &v["input"];
        let exp = &v["expected"];
        let seed = hex64(inp["mlkem_seed_hex"].as_str().unwrap());
        let m = hex32(inp["mlkem_m_hex"].as_str().unwrap());
        let (ct, z_pq) = encapsulate_deterministic(
            &hex::decode(exp["mlkem_ek_hex"].as_str().unwrap()).unwrap(),
            &m,
        )
        .unwrap();
        assert_eq!(hex::encode(&ct), exp["mlkem_ct_hex"].as_str().unwrap());
        assert_eq!(hex::encode(z_pq), exp["z_pq_hex"].as_str().unwrap());

        // Seed → EK match
        let dk_seed = Seed::try_from(seed.as_slice()).unwrap();
        let dk = DecapsulationKey::<MlKem768>::from_seed(dk_seed);
        assert_eq!(
            hex::encode(dk.encapsulation_key().to_bytes().as_slice()),
            exp["mlkem_ek_hex"].as_str().unwrap()
        );

        let alice_x = hex32(inp["alice_x25519_secret_hex"].as_str().unwrap());
        let bob_x = hex32(inp["bob_x25519_secret_hex"].as_str().unwrap());
        let bob_pk = hex32(exp["bob_x25519_public_hex"].as_str().unwrap());
        let z_x = x25519_shared(&alice_x, &bob_pk);
        assert_eq!(hex::encode(z_x), exp["z_x_hex"].as_str().unwrap());
        let th = transcript_hash(inp["transcript_material_utf8"].as_str().unwrap().as_bytes());
        assert_eq!(
            hex::encode(th),
            exp["transcript_hash_hex"].as_str().unwrap()
        );
        let root = derive_root(&z_x, &z_pq, &th);
        assert_eq!(hex::encode(root), exp["k_root_hex"].as_str().unwrap());

        // Decap of deterministic CT via seed
        let root_b = respond_hybrid_root(
            &bob_x,
            &hex32(exp["alice_x25519_public_hex"].as_str().unwrap()),
            &seed,
            &ct,
            &th,
        )
        .unwrap();
        assert_eq!(root_b, root);
    }

    #[test]
    fn shared_vector_rust_decaps_cryptokit_ciphertext() {
        let v = load_kat();
        let inp = &v["input"];
        let exp = &v["expected"];
        let seed = hex64(inp["mlkem_seed_hex"].as_str().unwrap());
        let ct = hex::decode(exp["cryptokit_ct_hex"].as_str().unwrap()).unwrap();
        let dk_seed = Seed::try_from(seed.as_slice()).unwrap();
        let dk = DecapsulationKey::<MlKem768>::from_seed(dk_seed);
        let ct_arr = ct.as_slice().try_into().expect("ct");
        let ss = dk.decapsulate(&ct_arr);
        assert_eq!(
            hex::encode(ss.as_slice()),
            exp["cryptokit_z_pq_hex"].as_str().unwrap()
        );
    }
}
