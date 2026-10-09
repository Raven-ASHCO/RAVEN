//! Interim authenticated sealed payload for Phase B DM + opaque ATSAM bridge.
//!
//! Wire prefix uses RVNA1 magic so Mesh/iOS dispatchers recognize an ATSAM-family
//! frame. Protocol byte `0x7F` marks this **interim stub** (not shipping ATSAM v1/v2).
//! ATSAM v1 (`0x01`) / v2 (`0x02`) bodies are classified as **opaque**: relays and
//! terminal nodes without a portable hybrid ratchet MUST NOT decrypt them — they
//! may verify the outer `RavenEnvelopeV1` and ACK/forward only.
//! Migration: replace seal/unseal bodies with full ATSAM hybrid root + chain ratchet
//! per `protocol/ATSAM_PRIMITIVE_MAPPING_V1.md` without changing RavenEnvelopeV1.

#[cfg(all(feature = "unsafe-demo-crypto", not(debug_assertions)))]
compile_error!(
    "unsafe-demo-crypto is forbidden in release builds; establish an authenticated ATSAM session"
);

// Second layer: `debug_assertions` is only a proxy for the build profile (a
// release profile can switch it on, e.g. `CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true`
// or `RUSTFLAGS=-Cdebug-assertions=on`). `RAVEN_BUILD_PROFILE` is Cargo's own
// `PROFILE`, emitted by `build.rs` (the same signal as the durable-lab release hold).
#[cfg(feature = "unsafe-demo-crypto")]
const _: () = assert!(
    !matches!(env!("RAVEN_BUILD_PROFILE").as_bytes(), b"release"),
    "unsafe-demo-crypto is forbidden in release builds; establish an authenticated ATSAM session"
);

#[cfg(feature = "unsafe-demo-crypto")]
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
#[cfg(feature = "unsafe-demo-crypto")]
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
#[cfg(feature = "unsafe-demo-crypto")]
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Same 8-byte magic as ATSAMMessageSealer (`RVNA1\0\0\0`).
pub const SEAL_MAGIC_RVNA1: [u8; 8] = [0x52, 0x56, 0x4E, 0x41, 0x31, 0x00, 0x00, 0x00];
/// Back-compat alias.
pub const SEAL_MAGIC_RVNA1_STUB: [u8; 8] = SEAL_MAGIC_RVNA1;

/// Interim protocol byte — MUST NOT collide with ATSAM v1 (0x01) or v2 (0x02).
pub const STUB_PROTO: u8 = 0x7F;
pub const ATSAM_PROTO_V1: u8 = 0x01;
pub const ATSAM_PROTO_V2: u8 = 0x02;
pub const STUB_SUITE: u8 = 0x01; // ChaCha20-Poly1305

const INFO: &[u8] = b"raven/rvn1/interim-seal/v0";

/// Stable error returned when a production build encounters the lab-only
/// public-key-derived cipher.
pub const UNSAFE_INTERIM_DISABLED: &str =
    "UNSAFE_INTERIM_DISABLED: establish an authenticated ATSAM session";

/// How a `message_ciphertext` body should be handled by a terminal node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealClass {
    /// Local interim AEAD (`proto=0x7F`) — node can unseal with pairwise demo key.
    InterimStub,
    /// Shipping ATSAM frame — treat as opaque unless full ratchet is available.
    OpaqueAtsam { proto: u8 },
    /// Noise / other / unknown — not decrypted by raven-node Phase B.
    Other,
}

/// Parsed RVNA1 header fields (no AEAD verify). Used to harden classification
/// and reject truncated / malformed opaque frames before ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rvna1Header {
    pub proto: u8,
    pub suite: u8,
    /// Present for ATSAM v2 (`proto=0x02`).
    pub index: Option<u32>,
    /// Byte offset where nonce begins.
    pub nonce_offset: usize,
    /// Minimum total wire length for a well-formed frame (header + empty CT + tag).
    pub min_wire_len: usize,
}

/// Classify sealed content by the 8-byte magic + protocol byte (no decrypt).
pub fn classify_sealed_body(wire: &[u8]) -> SealClass {
    if wire.len() < 10 {
        return SealClass::Other;
    }
    if wire[..8] != SEAL_MAGIC_RVNA1 {
        return SealClass::Other;
    }
    match wire[8] {
        STUB_PROTO => SealClass::InterimStub,
        p @ (ATSAM_PROTO_V1 | ATSAM_PROTO_V2) => SealClass::OpaqueAtsam { proto: p },
        _ => SealClass::Other,
    }
}

/// Parse RVNA1 / interim header layout. Returns `None` if truncated or unknown.
pub fn parse_rvna1_header(wire: &[u8]) -> Option<Rvna1Header> {
    if wire.len() < 10 || wire[..8] != SEAL_MAGIC_RVNA1 {
        return None;
    }
    let proto = wire[8];
    let suite = wire[9];
    match proto {
        ATSAM_PROTO_V1 | STUB_PROTO => {
            // magic(8) || proto || suite || nonce(12) || ct+tag(≥16)
            Some(Rvna1Header {
                proto,
                suite,
                index: None,
                nonce_offset: 10,
                min_wire_len: 8 + 2 + 12 + 16,
            })
        }
        ATSAM_PROTO_V2 => {
            // magic(8) || proto || suite || index_be32(4) || nonce(12) || ct+tag(≥16)
            if wire.len() < 14 {
                return None;
            }
            let index = u32::from_be_bytes([wire[10], wire[11], wire[12], wire[13]]);
            Some(Rvna1Header {
                proto,
                suite,
                index: Some(index),
                nonce_offset: 14,
                min_wire_len: 8 + 2 + 4 + 12 + 16,
            })
        }
        _ => None,
    }
}

/// True when the body is long enough for its declared RVNA1 layout (opaque-safe).
pub fn rvna1_wire_plausible(wire: &[u8]) -> bool {
    match parse_rvna1_header(wire) {
        Some(h) => wire.len() >= h.min_wire_len && h.suite == STUB_SUITE,
        None => false,
    }
}

/// Derive the lab-only pre-ATSAM key from two public identity keys.
///
/// # Security
///
/// This is intentionally available only to compatibility code.  **It is not a
/// shared secret**: every observer that knows the public keys can derive it.
/// [`seal_message`] refuses to use it in default/production builds.
pub fn derive_pairwise_key(local_pub: &[u8; 32], peer_pub: &[u8; 32]) -> [u8; 32] {
    let (a, b) = if local_pub.as_slice() <= peer_pub.as_slice() {
        (local_pub, peer_pub)
    } else {
        (peer_pub, local_pub)
    };
    let mut ikm = Vec::with_capacity(64 + 24);
    ikm.extend_from_slice(b"raven/rvn1/interim-psk");
    ikm.extend_from_slice(a);
    ikm.extend_from_slice(b"|");
    ikm.extend_from_slice(b);
    let hash = Sha256::digest(&ikm);
    let hk = Hkdf::<Sha256>::new(None, &hash);
    let mut okm = [0u8; 32];
    hk.expand(INFO, &mut okm).expect("hkdf");
    okm
}

pub fn seal_message(
    key: &[u8; 32],
    plaintext: &[u8],
    sender_addr: &str,
    recipient_addr: &str,
    msg_id: &[u8; 16],
) -> Result<Vec<u8>, String> {
    #[cfg(not(feature = "unsafe-demo-crypto"))]
    {
        let _ = (key, plaintext, sender_addr, recipient_addr, msg_id);
        Err(UNSAFE_INTERIM_DISABLED.into())
    }

    #[cfg(feature = "unsafe-demo-crypto")]
    {
        let aad = build_aad(sender_addr, recipient_addr, msg_id);
        let cipher = ChaCha20Poly1305::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| "seal failed".to_string())?;

        let mut wire = Vec::with_capacity(8 + 2 + 12 + ct.len());
        wire.extend_from_slice(&SEAL_MAGIC_RVNA1);
        wire.push(STUB_PROTO);
        wire.push(STUB_SUITE);
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ct);
        Ok(wire)
    }
}

pub fn unseal_message(
    key: &[u8; 32],
    wire: &[u8],
    sender_addr: &str,
    recipient_addr: &str,
    msg_id: &[u8; 16],
) -> Result<Vec<u8>, String> {
    if wire.len() < 8 + 2 + 12 + 16 {
        return Err("truncated seal".into());
    }
    if wire[..8] != SEAL_MAGIC_RVNA1 {
        return Err("bad seal magic".into());
    }
    match classify_sealed_body(wire) {
        SealClass::InterimStub => {}
        SealClass::OpaqueAtsam { proto } => {
            return Err(format!(
                "opaque ATSAM proto={proto:#x} — cannot unseal without hybrid ratchet"
            ));
        }
        SealClass::Other => {
            return Err("unsupported seal version (await ATSAM migration)".into());
        }
    }
    if wire[9] != STUB_SUITE {
        return Err("unsupported seal suite".into());
    }

    #[cfg(not(feature = "unsafe-demo-crypto"))]
    {
        let _ = (key, sender_addr, recipient_addr, msg_id);
        Err(UNSAFE_INTERIM_DISABLED.into())
    }

    #[cfg(feature = "unsafe-demo-crypto")]
    {
        let nonce = Nonce::from_slice(&wire[10..22]);
        let ct = &wire[22..];
        let aad = build_aad(sender_addr, recipient_addr, msg_id);
        let cipher = ChaCha20Poly1305::new(key.into());
        cipher
            .decrypt(nonce, Payload { msg: ct, aad: &aad })
            .map_err(|_| "unseal failed".to_string())
    }
}

#[cfg(feature = "unsafe-demo-crypto")]
fn build_aad(sender: &str, recipient: &str, msg_id: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"raven/rvn1/interim-seal/aad");
    h.update([0]);
    h.update(sender.as_bytes());
    h.update([0]);
    h.update(recipient.as_bytes());
    h.update([0]);
    h.update(msg_id);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "unsafe-demo-crypto")]
    #[test]
    fn roundtrip() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let key = derive_pairwise_key(&a, &b);
        let mid = [9u8; 16];
        let wire = seal_message(&key, b"hello", "rvn1aaa", "rvn1bbb", &mid).unwrap();
        let pt = unseal_message(&key, &wire, "rvn1aaa", "rvn1bbb", &mid).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn rejects_truncated() {
        let key = [0u8; 32];
        assert!(unseal_message(&key, &[0u8; 5], "a", "b", &[0u8; 16]).is_err());
    }

    #[cfg(feature = "unsafe-demo-crypto")]
    #[test]
    fn pairwise_key_fixed_vector() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let key = derive_pairwise_key(&a, &b);
        assert_eq!(
            hex::encode(key),
            "23b797ecf9085621051a0ac973c8906ec4d5b32de76d02ec10e659ebff66e9d3"
        );
    }

    #[test]
    fn classifies_interim_and_opaque_atsam() {
        let mut interim = SEAL_MAGIC_RVNA1.to_vec();
        interim.push(STUB_PROTO);
        interim.push(STUB_SUITE);
        assert_eq!(classify_sealed_body(&interim), SealClass::InterimStub);

        let mut v2 = SEAL_MAGIC_RVNA1.to_vec();
        v2.extend_from_slice(&[ATSAM_PROTO_V2, STUB_SUITE, 0, 0, 0, 1]);
        v2.extend_from_slice(&[0u8; 28]); // nonce+tag placeholder
        assert_eq!(
            classify_sealed_body(&v2),
            SealClass::OpaqueAtsam {
                proto: ATSAM_PROTO_V2
            }
        );

        assert_eq!(classify_sealed_body(b"RVNS1\0\0\0xxxx"), SealClass::Other);
    }

    #[test]
    fn unseal_refuses_opaque_atsam() {
        let key = [0u8; 32];
        let mut v2 = SEAL_MAGIC_RVNA1.to_vec();
        v2.extend_from_slice(&[ATSAM_PROTO_V2, STUB_SUITE]);
        v2.extend_from_slice(&[0u8; 40]);
        let err = unseal_message(&key, &v2, "a", "b", &[0u8; 16]).unwrap_err();
        assert!(err.contains("opaque ATSAM"));
    }

    #[cfg(not(feature = "unsafe-demo-crypto"))]
    #[test]
    fn production_build_refuses_public_key_demo_cipher() {
        let key = derive_pairwise_key(&[1u8; 32], &[2u8; 32]);
        let mid = [9u8; 16];
        let err = seal_message(&key, b"secret", "rvn1aaa", "rvn1bbb", &mid).unwrap_err();
        assert_eq!(err, UNSAFE_INTERIM_DISABLED);

        let mut wire = SEAL_MAGIC_RVNA1.to_vec();
        wire.extend_from_slice(&[STUB_PROTO, STUB_SUITE]);
        wire.extend_from_slice(&[0u8; 28]);
        let err = unseal_message(&key, &wire, "rvn1aaa", "rvn1bbb", &mid).unwrap_err();
        assert_eq!(err, UNSAFE_INTERIM_DISABLED);
    }

    #[test]
    fn parses_v1_v2_and_interim_headers() {
        let mut interim = SEAL_MAGIC_RVNA1.to_vec();
        interim.extend_from_slice(&[STUB_PROTO, STUB_SUITE]);
        interim.extend_from_slice(&[0u8; 28]);
        let h = parse_rvna1_header(&interim).unwrap();
        assert_eq!(h.proto, STUB_PROTO);
        assert!(h.index.is_none());
        assert!(rvna1_wire_plausible(&interim));

        let mut v2 = SEAL_MAGIC_RVNA1.to_vec();
        v2.extend_from_slice(&[ATSAM_PROTO_V2, STUB_SUITE, 0, 0, 0, 7]);
        v2.extend_from_slice(&[0u8; 28]);
        let h2 = parse_rvna1_header(&v2).unwrap();
        assert_eq!(h2.index, Some(7));
        assert!(rvna1_wire_plausible(&v2));

        assert!(!rvna1_wire_plausible(&SEAL_MAGIC_RVNA1));
    }
}
