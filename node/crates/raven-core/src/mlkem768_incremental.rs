//! ML-KEM-768 incremental encapsulation (lab-only, libcrux backend).
//!
//! Gated behind `mlkem768-incremental-lab`. Production builds must not enable this feature.
//! The standard 1088-byte FIPS ciphertext is reconstructed as `ct1 || ct2`:
//! the 960-byte first chunk followed by the 128-byte second chunk, in that order.

#[cfg(not(debug_assertions))]
compile_error!(
    "mlkem768-incremental-lab is forbidden in release builds; lab-only incremental ML-KEM"
);

// Second layer: `debug_assertions` is only a proxy for the build profile and a
// release profile can switch it on. `RAVEN_BUILD_PROFILE` is Cargo's `PROFILE`
// as emitted by `build.rs`. `full-braid-lab` and both lab FFI crates pull this
// module in, so they inherit the gate.
const _: () = assert!(
    !matches!(env!("RAVEN_BUILD_PROFILE").as_bytes(), b"release"),
    "mlkem768-incremental-lab is forbidden in release builds; lab-only incremental ML-KEM"
);

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Libcrux compressed incremental private key length; not the ATSAM 64-byte seed.
pub const DK_LEN: usize = 2400;

/// ML-KEM key-generation seed length.
pub const SEED_LEN: usize = 64;

/// Incremental encaps header length.
pub const HEADER_LEN: usize = 64;

/// Encapsulation key vector length (libcrux incremental wire form).
pub const EK_VECTOR_LEN: usize = 1152;

/// Incremental encaps state length.
pub const STATE_LEN: usize = 2080;

/// First ciphertext chunk length (incremental encaps).
pub const CT1_LEN: usize = 960;

/// Second ciphertext chunk length (incremental encaps).
pub const CT2_LEN: usize = 128;

/// Shared secret length (ML-KEM-768).
pub const SS_LEN: usize = 32;

/// Encapsulation randomness length (ML-KEM-768).
pub const COINS_LEN: usize = 32;

// Compressed layout (libcrux 0.0.10): s | t | ρ | H(ek) | z
//   ek_vector (t) @ COMPRESSED_EK_VECTOR_OFFSET
//   header (ρ||H) @ COMPRESSED_HEADER_OFFSET, len HEADER_LEN (64) — ends at 2368; z follows
const COMPRESSED_EK_VECTOR_OFFSET: usize = 1152;
const COMPRESSED_HEADER_OFFSET: usize = 2304; // 2 * 1152

/// Errors returned by the lab-only incremental ML-KEM adapter.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The incremental public-key parts are inconsistent or malformed.
    #[error("invalid incremental ML-KEM-768 public key")]
    InvalidPublicKey,

    /// Libcrux rejected the fixed-size Encaps1 inputs or outputs.
    #[error("incremental ML-KEM-768 encapsulation failed")]
    EncapsulationFailed,
}

/// Raven-owned compressed decapsulation key that is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DkCompressed([u8; DK_LEN]);

impl DkCompressed {
    /// Copy a fixed-size compressed decapsulation key into zeroizing storage.
    pub fn from_bytes(bytes: &[u8; DK_LEN]) -> Self {
        let mut dk = Self([0u8; DK_LEN]);
        dk.0.copy_from_slice(bytes);
        dk
    }
}

impl AsRef<[u8]> for DkCompressed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Raven-owned incremental encapsulation state that is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncapsState([u8; STATE_LEN]);

impl EncapsState {
    /// Copy a fixed-size retained encapsulation state into zeroizing storage.
    pub fn from_bytes(bytes: &[u8; STATE_LEN]) -> Self {
        let mut state = Self([0u8; STATE_LEN]);
        state.0.copy_from_slice(bytes);
        state
    }
}

impl AsRef<[u8]> for EncapsState {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Raven-owned ML-KEM shared secret that is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; SS_LEN]);

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Generate a compressed key pair and split out its incremental public-key parts.
pub fn keygen_split(
    seed: &[u8; SEED_LEN],
) -> (DkCompressed, [u8; HEADER_LEN], [u8; EK_VECTOR_LEN]) {
    let mut dk = DkCompressed([0u8; DK_LEN]);
    libcrux_ml_kem::mlkem768::incremental::generate_key_pair_compressed(*seed, &mut dk.0);

    let mut vector = [0u8; EK_VECTOR_LEN];
    vector.copy_from_slice(
        &dk.0[COMPRESSED_EK_VECTOR_OFFSET..COMPRESSED_EK_VECTOR_OFFSET + EK_VECTOR_LEN],
    );

    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&dk.0[COMPRESSED_HEADER_OFFSET..COMPRESSED_HEADER_OFFSET + HEADER_LEN]);

    (dk, header, vector)
}

/// Validate that the incremental public-key header and vector belong together.
pub fn validate(header: &[u8; HEADER_LEN], vector: &[u8; EK_VECTOR_LEN]) -> Result<(), Error> {
    libcrux_ml_kem::mlkem768::incremental::validate_pk_bytes(header, vector)
        .map_err(|_| Error::InvalidPublicKey)
}

/// Produce the first ciphertext chunk, retained state, and shared secret.
///
/// Does not validate the public key: the vector may not be available yet.
/// Call [`validate`] when both parts are present, or rely on [`encaps2`].
pub fn encaps1(
    header: &[u8; HEADER_LEN],
    coins: &[u8; COINS_LEN],
) -> Result<(EncapsState, [u8; CT1_LEN], SharedSecret), Error> {
    let mut state = EncapsState([0u8; STATE_LEN]);
    let mut shared_secret = SharedSecret([0u8; SS_LEN]);
    let ciphertext = libcrux_ml_kem::mlkem768::incremental::encapsulate1(
        header,
        *coins,
        &mut state.0,
        &mut shared_secret.0,
    )
    .map_err(|_| Error::EncapsulationFailed)?;

    Ok((state, ciphertext.value, shared_secret))
}

/// Validate the public-key parts and produce the second ciphertext chunk.
///
/// `header` must be the same value passed to [`encaps1`]; it is used only for
/// binding/`validate` before libcrux `encapsulate2` (which takes the vector).
pub fn encaps2(
    state: &EncapsState,
    header: &[u8; HEADER_LEN],
    vector: &[u8; EK_VECTOR_LEN],
) -> Result<[u8; CT2_LEN], Error> {
    validate(header, vector)?;
    let ciphertext = libcrux_ml_kem::mlkem768::incremental::encapsulate2(&state.0, vector);
    Ok(ciphertext.value)
}

/// Decapsulate the two ciphertext chunks with the compressed decapsulation key.
///
/// Always returns a shared secret (ML-KEM implicit rejection): tampered or
/// invalid ciphertexts yield a pseudorandom secret, not an error. The shared
/// secret is only considered authentic after upstream AEAD or protocol
/// verification succeeds.
pub fn decaps(dk: &DkCompressed, ct1: &[u8; CT1_LEN], ct2: &[u8; CT2_LEN]) -> SharedSecret {
    let ciphertext1 = libcrux_ml_kem::mlkem768::incremental::Ciphertext1 { value: *ct1 };
    let ciphertext2 = libcrux_ml_kem::mlkem768::incremental::Ciphertext2 { value: *ct2 };
    let shared_secret = libcrux_ml_kem::mlkem768::incremental::decapsulate_compressed_key(
        &dk.0,
        &ciphertext1,
        &ciphertext2,
    );

    SharedSecret(shared_secret)
}

#[cfg(test)]
mod feature_smoke {
    use ml_kem::kem::{Decapsulate, Key, KeyExport};
    use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768, Seed, B32};
    use serde::{Deserialize, Serialize};
    use sha3::{Digest, Sha3_256};
    use std::path::PathBuf;

    const FIXTURE_ID: &str = "mlkem768_incremental_encaps_001";
    const FIXTURE_NOTES: &str = "lab-only; dk_hex must not ship to production clients";
    const FIPS_EK_LEN: usize = 1184;
    const FIPS_CT_LEN: usize = super::CT1_LEN + super::CT2_LEN;

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct Fixture {
        vector_id: String,
        seed_hex: String,
        coins_hex: String,
        dk_hex: String,
        header_hex: String,
        ek_vector_hex: String,
        fips_ek_hex: String,
        encaps_state_hex: String,
        ct1_hex: String,
        ct2_hex: String,
        ss_hex: String,
        atomic_libcrux_ct_hex: String,
        atomic_libcrux_ss_hex: String,
        atomic_rustcrypto_ct_hex: String,
        atomic_rustcrypto_ss_hex: String,
        #[serde(default)]
        lab_only: bool,
        notes: String,
    }

    fn fixture_path() -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.pop();
        path.join("shared-vectors")
            .join("rvn1")
            .join("atsam")
            .join(format!("{FIXTURE_ID}.json"))
    }

    fn load_fixture() -> Fixture {
        let path = fixture_path();
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{error}: {}", path.display()));
        serde_json::from_str(&raw).expect("incremental ML-KEM fixture JSON")
    }

    fn hex_array<const N: usize>(field: &str, value: &str) -> [u8; N] {
        let decoded = hex::decode(value).unwrap_or_else(|error| panic!("{field}: {error}"));
        decoded.try_into().unwrap_or_else(|value: Vec<u8>| {
            panic!("{field}: expected {N} bytes, got {}", value.len())
        })
    }

    fn regenerate_fixture(seed: [u8; super::SEED_LEN], coins: [u8; super::COINS_LEN]) -> Fixture {
        let (dk, header, vector) = super::keygen_split(&seed);
        super::validate(&header, &vector).expect("generated public key must validate");
        let (state, ct1, ss) = super::encaps1(&header, &coins).expect("encaps1");
        let ct2 = super::encaps2(&state, &header, &vector).expect("encaps2");

        let mut fips_ek = [0u8; FIPS_EK_LEN];
        fips_ek[..super::EK_VECTOR_LEN].copy_from_slice(&vector);
        fips_ek[super::EK_VECTOR_LEN..].copy_from_slice(&header[..32]);

        let mut fips_ct = [0u8; FIPS_CT_LEN];
        fips_ct[..super::CT1_LEN].copy_from_slice(&ct1);
        fips_ct[super::CT1_LEN..].copy_from_slice(&ct2);

        let public_key = libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(fips_ek);
        let (libcrux_ct, libcrux_ss) = libcrux_ml_kem::mlkem768::encapsulate(&public_key, coins);
        assert_eq!(libcrux_ct.as_ref(), fips_ct.as_slice());
        assert_eq!(libcrux_ss, *ss.as_ref());

        let seed_rc = Seed::try_from(seed.as_slice()).expect("RustCrypto seed");
        let dk_rc = DecapsulationKey::<MlKem768>::from_seed(seed_rc);
        assert_eq!(
            dk_rc.encapsulation_key().to_bytes().as_slice(),
            fips_ek.as_slice()
        );
        let encoded_ek: Key<EncapsulationKey<MlKem768>> =
            fips_ek.as_slice().try_into().expect("RustCrypto EK bytes");
        let ek = EncapsulationKey::<MlKem768>::new(&encoded_ek).expect("RustCrypto EK decode");
        let deterministic_coins = B32::try_from(coins.as_slice()).expect("RustCrypto coins");
        let (rustcrypto_ct, rustcrypto_ss) = ek.encapsulate_deterministic(&deterministic_coins);
        assert_eq!(rustcrypto_ct.as_slice(), fips_ct.as_slice());
        assert_eq!(rustcrypto_ss.as_slice(), ss.as_ref());

        Fixture {
            vector_id: FIXTURE_ID.into(),
            seed_hex: hex::encode(seed),
            coins_hex: hex::encode(coins),
            dk_hex: hex::encode(dk.as_ref()),
            header_hex: hex::encode(header),
            ek_vector_hex: hex::encode(vector),
            fips_ek_hex: hex::encode(fips_ek),
            encaps_state_hex: hex::encode(state.as_ref()),
            ct1_hex: hex::encode(ct1),
            ct2_hex: hex::encode(ct2),
            ss_hex: hex::encode(ss.as_ref()),
            atomic_libcrux_ct_hex: hex::encode(libcrux_ct.as_ref()),
            atomic_libcrux_ss_hex: hex::encode(libcrux_ss),
            atomic_rustcrypto_ct_hex: hex::encode(rustcrypto_ct.as_slice()),
            atomic_rustcrypto_ss_hex: hex::encode(rustcrypto_ss.as_slice()),
            lab_only: true,
            notes: FIXTURE_NOTES.into(),
        }
    }

    fn fixture_fips_ek(fixture: &Fixture) -> [u8; FIPS_EK_LEN] {
        let header = hex_array::<{ super::HEADER_LEN }>("header_hex", &fixture.header_hex);
        let vector = hex_array::<{ super::EK_VECTOR_LEN }>("ek_vector_hex", &fixture.ek_vector_hex);
        let mut fips_ek = [0u8; FIPS_EK_LEN];
        fips_ek[..super::EK_VECTOR_LEN].copy_from_slice(&vector);
        fips_ek[super::EK_VECTOR_LEN..].copy_from_slice(&header[..32]);
        fips_ek
    }

    fn fixture_fips_ct(fixture: &Fixture) -> [u8; FIPS_CT_LEN] {
        let ct1 = hex_array::<{ super::CT1_LEN }>("ct1_hex", &fixture.ct1_hex);
        let ct2 = hex_array::<{ super::CT2_LEN }>("ct2_hex", &fixture.ct2_hex);
        let mut ciphertext = [0u8; FIPS_CT_LEN];
        ciphertext[..super::CT1_LEN].copy_from_slice(&ct1);
        ciphertext[super::CT1_LEN..].copy_from_slice(&ct2);
        ciphertext
    }

    fn sha3_256(input: &[u8]) -> [u8; 32] {
        let digest = Sha3_256::digest(input);
        let mut output = [0u8; 32];
        output.copy_from_slice(&digest);
        output
    }

    fn deterministic_seed() -> [u8; super::SEED_LEN] {
        core::array::from_fn(|index| index as u8)
    }

    #[test]
    fn frozen_fixture_regenerates_from_seed_and_coins() {
        let frozen = load_fixture();
        let seed = hex_array::<{ super::SEED_LEN }>("seed_hex", &frozen.seed_hex);
        let coins = hex_array::<{ super::COINS_LEN }>("coins_hex", &frozen.coins_hex);

        assert_eq!(seed, deterministic_seed());
        assert_eq!(coins, [7u8; super::COINS_LEN]);
        assert_eq!(regenerate_fixture(seed, coins), frozen);
    }

    #[test]
    fn incremental_fixture_decaps_with_adapter() {
        let fixture = load_fixture();
        let dk = super::DkCompressed(hex_array::<{ super::DK_LEN }>("dk_hex", &fixture.dk_hex));
        let ct1 = hex_array::<{ super::CT1_LEN }>("ct1_hex", &fixture.ct1_hex);
        let ct2 = hex_array::<{ super::CT2_LEN }>("ct2_hex", &fixture.ct2_hex);
        let expected_ss = hex_array::<{ super::SS_LEN }>("ss_hex", &fixture.ss_hex);

        let decapsulated = super::decaps(&dk, &ct1, &ct2);

        assert_eq!(decapsulated.as_ref(), expected_ss.as_slice());
    }

    #[test]
    fn incremental_fixture_libcrux_atomic_interop() {
        let fixture = load_fixture();
        let dk = hex_array::<{ super::DK_LEN }>("dk_hex", &fixture.dk_hex);
        let fips_ek = fixture_fips_ek(&fixture);
        let ciphertext = fixture_fips_ct(&fixture);
        let expected_ss = hex_array::<{ super::SS_LEN }>("ss_hex", &fixture.ss_hex);
        let frozen_fips_ek = hex_array::<FIPS_EK_LEN>("fips_ek_hex", &fixture.fips_ek_hex);
        let frozen_libcrux_ct =
            hex_array::<FIPS_CT_LEN>("atomic_libcrux_ct_hex", &fixture.atomic_libcrux_ct_hex);
        let frozen_libcrux_ss =
            hex_array::<{ super::SS_LEN }>("atomic_libcrux_ss_hex", &fixture.atomic_libcrux_ss_hex);

        assert_eq!(fips_ek, frozen_fips_ek);
        assert_eq!(ciphertext, frozen_libcrux_ct);
        assert_eq!(expected_ss, frozen_libcrux_ss);

        // Compressed layout interop: incremental dk embeds the FIPS EK at a fixed offset.
        assert_eq!(
            &dk[super::EK_VECTOR_LEN..super::EK_VECTOR_LEN + FIPS_EK_LEN],
            &fips_ek
        );
        let public_key = libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(fips_ek);
        assert!(libcrux_ml_kem::mlkem768::validate_public_key(&public_key));

        let private_key = libcrux_ml_kem::mlkem768::MlKem768PrivateKey::from(dk);
        let ciphertext = libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from(ciphertext);
        let decapsulated = libcrux_ml_kem::mlkem768::decapsulate(&private_key, &ciphertext);

        assert_eq!(decapsulated, expected_ss);
    }

    #[test]
    fn incremental_fixture_decapsulates_with_rustcrypto_oracle() {
        let fixture = load_fixture();
        let seed_bytes = hex_array::<{ super::SEED_LEN }>("seed_hex", &fixture.seed_hex);
        let coins = hex_array::<{ super::COINS_LEN }>("coins_hex", &fixture.coins_hex);
        let fips_ek = fixture_fips_ek(&fixture);
        let ciphertext = fixture_fips_ct(&fixture);
        let expected_ss = hex_array::<{ super::SS_LEN }>("ss_hex", &fixture.ss_hex);
        let frozen_rustcrypto_ct = hex_array::<FIPS_CT_LEN>(
            "atomic_rustcrypto_ct_hex",
            &fixture.atomic_rustcrypto_ct_hex,
        );
        let frozen_rustcrypto_ss = hex_array::<{ super::SS_LEN }>(
            "atomic_rustcrypto_ss_hex",
            &fixture.atomic_rustcrypto_ss_hex,
        );

        assert_eq!(ciphertext, frozen_rustcrypto_ct);
        assert_eq!(expected_ss, frozen_rustcrypto_ss);

        let seed = Seed::try_from(seed_bytes.as_slice()).expect("RustCrypto seed");
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        assert_eq!(
            dk.encapsulation_key().to_bytes().as_slice(),
            fips_ek.as_slice()
        );

        let encoded_ek: Key<EncapsulationKey<MlKem768>> =
            fips_ek.as_slice().try_into().expect("RustCrypto EK bytes");
        let ek = EncapsulationKey::<MlKem768>::new(&encoded_ek).expect("RustCrypto EK decode");
        let deterministic_coins = B32::try_from(coins.as_slice()).expect("RustCrypto coins");
        let (atomic_ct, atomic_ss) = ek.encapsulate_deterministic(&deterministic_coins);
        assert_eq!(atomic_ct.as_slice(), ciphertext.as_slice());
        assert_eq!(atomic_ss.as_slice(), expected_ss.as_slice());

        let encoded_ct = ciphertext
            .as_slice()
            .try_into()
            .expect("RustCrypto ciphertext bytes");
        let decapsulated = dk.decapsulate(&encoded_ct);
        assert_eq!(decapsulated.as_slice(), expected_ss.as_slice());
    }

    #[test]
    #[ignore = "writes the frozen lab fixture only with the explicit environment gate"]
    fn write_mlkem768_incremental_fixture() {
        assert_eq!(
            std::env::var("RAVEN_WRITE_MLKEM_INCREMENTAL_FIXTURE").as_deref(),
            Ok("1"),
            "set RAVEN_WRITE_MLKEM_INCREMENTAL_FIXTURE=1"
        );

        // Deterministic lab inputs: seed = 00..3f and coins = 07 repeated 32 times.
        let fixture = regenerate_fixture(deterministic_seed(), [7u8; super::COINS_LEN]);
        let encoded = serde_json::to_string_pretty(&fixture).expect("serialize fixture");
        let path = fixture_path();
        std::fs::write(&path, format!("{encoded}\n"))
            .unwrap_or_else(|error| panic!("{error}: {}", path.display()));
        println!("wrote {}", path.display());
    }

    #[test]
    #[ignore = "writes deterministic Encaps1 state only with the explicit environment gate"]
    fn dump_mlkem768_incremental_encaps1_state() {
        assert_eq!(
            std::env::var("RAVEN_DUMP_ENCAPS1_STATE").as_deref(),
            Ok("1"),
            "set RAVEN_DUMP_ENCAPS1_STATE=1"
        );
        let path = std::env::var_os("RAVEN_DUMP_ENCAPS1_STATE_PATH")
            .map(PathBuf::from)
            .expect("set RAVEN_DUMP_ENCAPS1_STATE_PATH");
        assert!(
            !path.as_os_str().is_empty(),
            "RAVEN_DUMP_ENCAPS1_STATE_PATH must not be empty"
        );

        // Frozen-fixture inputs: seed = 00..3f and coins = 07 repeated 32 times.
        let (_dk, header, _vector) = super::keygen_split(&deterministic_seed());
        let (state, _ct1, _ss) =
            super::encaps1(&header, &[7u8; super::COINS_LEN]).expect("encaps1");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|error| {
                panic!("{error}: {}", parent.display());
            });
        }
        std::fs::write(&path, format!("{}\n", hex::encode(state.as_ref())))
            .unwrap_or_else(|error| panic!("{error}: {}", path.display()));
        println!("wrote {}", path.display());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn require_avx2_when_gated() {
        if std::env::var("RAVEN_REQUIRE_AVX2").as_deref() != Ok("1") {
            return;
        }
        assert!(
            std::is_x86_feature_detected!("avx2"),
            "RAVEN_REQUIRE_AVX2=1 requires a host with runtime AVX2"
        );
    }

    #[test]
    fn feature_compiles_and_exports_sizes() {
        assert_eq!(super::DK_LEN, 2400);
        assert_eq!(super::HEADER_LEN, 64);
        assert_eq!(super::EK_VECTOR_LEN, 1152);
        assert_eq!(super::STATE_LEN, 2080);
        assert_eq!(super::CT1_LEN, 960);
        assert_eq!(super::CT2_LEN, 128);
        assert_eq!(super::SS_LEN, 32);
        assert_eq!(super::COINS_LEN, 32);
    }

    #[test]
    fn keygen_split_lengths_and_header_layout() {
        let mut seed = [0u8; 64];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = index as u8;
        }

        let (dk, header, vector) = super::keygen_split(&seed);

        assert_eq!(dk.as_ref().len(), 2400);
        assert_eq!(header.len(), 64);
        assert_eq!(vector.len(), 1152);

        // The header is rho || H(FIPS_EK), where FIPS_EK is vector || rho.
        let rho = &header[..32];
        let mut fips_ek = [0u8; 1184];
        fips_ek[..1152].copy_from_slice(&vector);
        fips_ek[1152..].copy_from_slice(rho);
        assert_eq!(&header[32..], &sha3_256(&fips_ek));
    }

    #[test]
    fn keygen_does_not_call_from_seed_path() {
        let source = include_str!("mlkem768_incremental.rs");
        let forbidden = ["KeyPairCompressedBytes", "::from_seed"].concat();

        assert!(!source.contains(&forbidden));
        assert!(source.contains("incremental::generate_key_pair_compressed"));
    }

    #[test]
    fn encaps1_encaps2_decaps_roundtrip() {
        let (dk, header, vector) = super::keygen_split(&deterministic_seed());
        super::validate(&header, &vector).expect("generated public key must validate");

        let coins = [7u8; 32];
        let (state, ct1, encapsulated_ss) = super::encaps1(&header, &coins).expect("encaps1");
        let ct2 = super::encaps2(&state, &header, &vector).expect("encaps2");
        let decapsulated_ss = super::decaps(&dk, &ct1, &ct2);

        assert_eq!(encapsulated_ss.as_ref(), decapsulated_ss.as_ref());
    }

    #[test]
    fn encaps2_rejects_tampered_vector() {
        let (_dk, header, mut vector) = super::keygen_split(&deterministic_seed());
        let coins = [7u8; 32];
        let (state, _ct1, _ss) = super::encaps1(&header, &coins).expect("encaps1");

        vector[0] ^= 1;

        assert!(super::encaps2(&state, &header, &vector).is_err());
    }

    #[test]
    fn tampered_ct_yields_ss_ne_honest_not_necessarily_err() {
        let (dk, header, vector) = super::keygen_split(&deterministic_seed());
        let coins = [7u8; 32];
        let (state, mut ct1, encapsulated_ss) = super::encaps1(&header, &coins).expect("encaps1");
        let ct2 = super::encaps2(&state, &header, &vector).expect("encaps2");
        let honest_ss = super::decaps(&dk, &ct1, &ct2);
        assert_eq!(encapsulated_ss.as_ref(), honest_ss.as_ref());

        ct1[0] ^= 1;
        let tampered_ss = super::decaps(&dk, &ct1, &ct2);

        assert_ne!(tampered_ss.as_ref(), honest_ss.as_ref());
    }
}
