//! Noise XX over the existing `u32_be || payload` LAN frame.
//!
//! Static X25519 is HKDF-derived from the identity seed and is never the
//! prekey X25519. After handshake each side binds `ed25519_pub` with
//! `sig("rvn1/lan-noise/v1" || noise_static_pub)`.

use hkdf::Hkdf;
use sha2::Sha256;
use snow::{Builder, HandshakeState, TransportState};

pub use snow::TransportState as NoiseTransport;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::identity::Identity;

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
pub const BIND_DOMAIN: &[u8] = b"rvn1/lan-noise/v1";
pub const BIND_LEN: usize = 32 + 64;
pub const HKDF_SALT: &[u8] = b"rvn1/lan-noise/v1";
pub const HKDF_INFO: &[u8] = b"static-x25519";
/// Largest Noise message snow will read or write (handshake or transport).
/// LAN/Internet framers reject longer `u32_be` lengths before allocating.
pub const MAX_NOISE_MSG: usize = 65535;
/// ChaChaPoly tag is 16 bytes; snow rejects larger transport plaintexts.
pub const MAX_TRANSPORT_PLAINTEXT: usize = MAX_NOISE_MSG - 16;
/// Conservative application text cap so the packed RVN1 envelope still fits.
pub const MAX_LAN_ENDPOINT_TEXT: usize = 48 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LanNoiseError {
    #[error("noise handshake failed")]
    Handshake,
    #[error("noise transport failed")]
    Transport,
    #[error("identity bind missing or truncated")]
    BindTruncated,
    #[error("identity bind signature invalid")]
    BindBadSignature,
    #[error("identity bind does not match expected pub")]
    BindMismatch,
    #[error("noise key derivation failed")]
    KeyDerive,
    #[error("noise plaintext exceeds transport limit")]
    PlaintextTooLarge,
}

/// HKDF-SHA256 static X25519 private key from the identity seed.
///
/// Knowing this key is equivalent to impersonating the identity on LAN, so it
/// is returned in a wrapper that wipes it on drop.
pub fn derive_noise_static(identity: &Identity) -> Result<Zeroizing<[u8; 32]>, LanNoiseError> {
    let mut seed = identity.seed_bytes();
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &seed);
    seed.zeroize();
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, okm.as_mut_slice())
        .map_err(|_| LanNoiseError::KeyDerive)?;
    Ok(okm)
}

pub fn noise_static_public(static_priv: &[u8; 32]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(*static_priv);
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}

pub fn bind_signing_bytes(noise_static_pub: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BIND_DOMAIN.len() + 32);
    out.extend_from_slice(BIND_DOMAIN);
    out.extend_from_slice(noise_static_pub);
    out
}

pub fn encode_bind(identity: &Identity, noise_static_pub: &[u8; 32]) -> [u8; BIND_LEN] {
    let mut out = [0u8; BIND_LEN];
    out[..32].copy_from_slice(&identity.public_key_bytes());
    let sig = identity.sign(&bind_signing_bytes(noise_static_pub));
    out[32..].copy_from_slice(&sig);
    out
}

pub fn verify_bind(
    bind: &[u8],
    noise_static_pub: &[u8; 32],
    expected_ed25519: Option<&[u8; 32]>,
) -> Result<[u8; 32], LanNoiseError> {
    if bind.len() != BIND_LEN {
        return Err(LanNoiseError::BindTruncated);
    }
    let mut ed = [0u8; 32];
    ed.copy_from_slice(&bind[..32]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bind[32..]);
    if !Identity::verify(&ed, &bind_signing_bytes(noise_static_pub), &sig) {
        return Err(LanNoiseError::BindBadSignature);
    }
    if let Some(expected) = expected_ed25519 {
        if &ed != expected {
            return Err(LanNoiseError::BindMismatch);
        }
    }
    Ok(ed)
}

fn builder<'a>(
    static_priv: &'a [u8; 32],
    prologue: Option<&'a [u8]>,
) -> Result<Builder<'a>, LanNoiseError> {
    let params = NOISE_PATTERN
        .parse()
        .map_err(|_| LanNoiseError::Handshake)?;
    let mut b = Builder::new(params).local_private_key(static_priv);
    // LAN never sets a prologue (wire-frozen); other carriers use one for
    // domain separation so a LAN transcript can never complete against them.
    if let Some(p) = prologue {
        b = b.prologue(p);
    }
    Ok(b)
}

pub fn build_initiator(static_priv: &[u8; 32]) -> Result<HandshakeState, LanNoiseError> {
    builder(static_priv, None)?
        .build_initiator()
        .map_err(|_| LanNoiseError::Handshake)
}

pub fn build_responder(static_priv: &[u8; 32]) -> Result<HandshakeState, LanNoiseError> {
    builder(static_priv, None)?
        .build_responder()
        .map_err(|_| LanNoiseError::Handshake)
}

/// Known-answer-test builder. A caller-chosen ephemeral key voids forward
/// secrecy and makes the handshake keys predictable, so this exists only for
/// tests and the `test-helpers` feature and never in a default/release build.
#[cfg(any(test, feature = "test-helpers"))]
fn builder_with_fixed_ephemeral<'a>(
    static_priv: &'a [u8; 32],
    fixed_ephemeral: Option<&'a [u8; 32]>,
) -> Result<Builder<'a>, LanNoiseError> {
    let mut b = builder(static_priv, None)?;
    if let Some(eph) = fixed_ephemeral {
        b = b.fixed_ephemeral_key_for_testing_only(eph);
    }
    Ok(b)
}

/// Test/KAT-only (see [`builder_with_fixed_ephemeral`]).
#[cfg(any(test, feature = "test-helpers"))]
pub fn build_initiator_with_ephemeral(
    static_priv: &[u8; 32],
    fixed_ephemeral: Option<&[u8; 32]>,
) -> Result<HandshakeState, LanNoiseError> {
    builder_with_fixed_ephemeral(static_priv, fixed_ephemeral)?
        .build_initiator()
        .map_err(|_| LanNoiseError::Handshake)
}

/// Test/KAT-only (see [`builder_with_fixed_ephemeral`]).
#[cfg(any(test, feature = "test-helpers"))]
pub fn build_responder_with_ephemeral(
    static_priv: &[u8; 32],
    fixed_ephemeral: Option<&[u8; 32]>,
) -> Result<HandshakeState, LanNoiseError> {
    builder_with_fixed_ephemeral(static_priv, fixed_ephemeral)?
        .build_responder()
        .map_err(|_| LanNoiseError::Handshake)
}

/// Same XX pattern and static key, with a carrier-specific Noise prologue.
/// Not used by LAN (its transcript has no prologue).
pub fn build_initiator_with_prologue(
    static_priv: &[u8; 32],
    prologue: &[u8],
) -> Result<HandshakeState, LanNoiseError> {
    builder(static_priv, Some(prologue))?
        .build_initiator()
        .map_err(|_| LanNoiseError::Handshake)
}

pub fn build_responder_with_prologue(
    static_priv: &[u8; 32],
    prologue: &[u8],
) -> Result<HandshakeState, LanNoiseError> {
    builder(static_priv, Some(prologue))?
        .build_responder()
        .map_err(|_| LanNoiseError::Handshake)
}

pub fn handshake_hash(state: &HandshakeState) -> [u8; 32] {
    let raw = state.get_handshake_hash();
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

pub fn handshake_write(
    state: &mut HandshakeState,
    payload: &[u8],
) -> Result<Vec<u8>, LanNoiseError> {
    let mut buf = vec![0u8; MAX_NOISE_MSG];
    let n = state
        .write_message(payload, &mut buf)
        .map_err(|_| LanNoiseError::Handshake)?;
    buf.truncate(n);
    Ok(buf)
}

pub fn handshake_read(
    state: &mut HandshakeState,
    message: &[u8],
) -> Result<Vec<u8>, LanNoiseError> {
    let mut buf = vec![0u8; MAX_NOISE_MSG];
    let n = state
        .read_message(message, &mut buf)
        .map_err(|_| LanNoiseError::Handshake)?;
    buf.truncate(n);
    Ok(buf)
}

pub fn into_transport(state: HandshakeState) -> Result<TransportState, LanNoiseError> {
    state
        .into_transport_mode()
        .map_err(|_| LanNoiseError::Handshake)
}

pub fn transport_encrypt(
    state: &mut TransportState,
    plaintext: &[u8],
) -> Result<Vec<u8>, LanNoiseError> {
    if plaintext.len() > MAX_TRANSPORT_PLAINTEXT {
        return Err(LanNoiseError::PlaintextTooLarge);
    }
    let mut buf = vec![0u8; plaintext.len().saturating_add(32).max(64)];
    if buf.len() < plaintext.len() + 16 {
        buf.resize(plaintext.len() + 64, 0);
    }
    let n = state
        .write_message(plaintext, &mut buf)
        .map_err(|_| LanNoiseError::Transport)?;
    buf.truncate(n);
    Ok(buf)
}

pub fn transport_decrypt(
    state: &mut TransportState,
    ciphertext: &[u8],
) -> Result<Vec<u8>, LanNoiseError> {
    let mut buf = vec![0u8; ciphertext.len()];
    let n = state
        .read_message(ciphertext, &mut buf)
        .map_err(|_| LanNoiseError::Transport)?;
    buf.truncate(n);
    Ok(buf)
}

pub fn get_remote_static(state: &HandshakeState) -> Result<[u8; 32], LanNoiseError> {
    let raw = state.get_remote_static().ok_or(LanNoiseError::Handshake)?;
    if raw.len() != 32 {
        return Err(LanNoiseError::Handshake);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Ok(out)
}

/// Complete XX in memory (tests / dispatch fixtures). Returns initiator then responder transport.
pub fn handshake_pair(
    initiator_id: &Identity,
    responder_id: &Identity,
) -> Result<(TransportState, TransportState, [u8; 32], [u8; 32]), LanNoiseError> {
    let init_priv = derive_noise_static(initiator_id)?;
    let resp_priv = derive_noise_static(responder_id)?;
    let init_pub = noise_static_public(&init_priv);
    let resp_pub = noise_static_public(&resp_priv);
    let mut initiator = build_initiator(&init_priv)?;
    let mut responder = build_responder(&resp_priv)?;

    let m1 = handshake_write(&mut initiator, &[])?;
    handshake_read(&mut responder, &m1)?;
    let m2 = handshake_write(&mut responder, &[])?;
    handshake_read(&mut initiator, &m2)?;
    let m3 = handshake_write(&mut initiator, &[])?;
    handshake_read(&mut responder, &m3)?;

    let mut init_t = into_transport(initiator)?;
    let mut resp_t = into_transport(responder)?;

    let bind_i = encode_bind(initiator_id, &init_pub);
    let ct = transport_encrypt(&mut init_t, &bind_i)?;
    let pt = transport_decrypt(&mut resp_t, &ct)?;
    verify_bind(&pt, &init_pub, Some(&initiator_id.public_key_bytes()))?;

    let bind_r = encode_bind(responder_id, &resp_pub);
    let ct = transport_encrypt(&mut resp_t, &bind_r)?;
    let pt = transport_decrypt(&mut init_t, &ct)?;
    verify_bind(&pt, &resp_pub, Some(&responder_id.public_key_bytes()))?;

    Ok((init_t, resp_t, init_pub, resp_pub))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Identity {
        Identity::from_seed(&[0x11; 32])
    }
    fn bob() -> Identity {
        Identity::from_seed(&[0x22; 32])
    }

    #[test]
    fn handshake_and_frame_round_trip() {
        let (mut a, mut b, _, _) = handshake_pair(&alice(), &bob()).unwrap();
        let ct = transport_encrypt(&mut a, b"hello-lan").unwrap();
        let pt = transport_decrypt(&mut b, &ct).unwrap();
        assert_eq!(pt, b"hello-lan");
    }

    #[test]
    fn wrong_bind_identity_fails() {
        let alice = alice();
        let bob = bob();
        let mallory = Identity::from_seed(&[0x33; 32]);
        let init_priv = derive_noise_static(&alice).unwrap();
        let resp_priv = derive_noise_static(&bob).unwrap();
        let init_pub = noise_static_public(&init_priv);
        let mut initiator = build_initiator(&init_priv).unwrap();
        let mut responder = build_responder(&resp_priv).unwrap();
        let m1 = handshake_write(&mut initiator, &[]).unwrap();
        handshake_read(&mut responder, &m1).unwrap();
        let m2 = handshake_write(&mut responder, &[]).unwrap();
        handshake_read(&mut initiator, &m2).unwrap();
        let m3 = handshake_write(&mut initiator, &[]).unwrap();
        handshake_read(&mut responder, &m3).unwrap();
        let mut init_t = into_transport(initiator).unwrap();
        let mut resp_t = into_transport(responder).unwrap();
        let forged = encode_bind(&mallory, &init_pub);
        let ct = transport_encrypt(&mut init_t, &forged).unwrap();
        let pt = transport_decrypt(&mut resp_t, &ct).unwrap();
        assert_eq!(
            verify_bind(&pt, &init_pub, Some(&alice.public_key_bytes())),
            Err(LanNoiseError::BindMismatch)
        );
    }

    #[test]
    fn bind_signed_over_wrong_static_fails() {
        let alice = alice();
        let other_static = [0x44; 32];
        let bind = encode_bind(&alice, &noise_static_public(&[0x55; 32]));
        assert_eq!(
            verify_bind(&bind, &other_static, None),
            Err(LanNoiseError::BindBadSignature)
        );
    }

    #[test]
    fn ciphertext_is_not_readable_plaintext() {
        let (mut a, _b, _, _) = handshake_pair(&alice(), &bob()).unwrap();
        let secret = b"RVPI1 PairInit cert plaintext must not leak";
        let ct = transport_encrypt(&mut a, secret).unwrap();
        assert!(!ct.windows(secret.len()).any(|w| w == secret));
        assert!(!ct.windows(5).any(|w| w == b"RVPI1"));
        assert_ne!(ct, secret);
    }

    #[test]
    fn oversized_plaintext_is_rejected() {
        let (mut a, _, _, _) = handshake_pair(&alice(), &bob()).unwrap();
        let too_big = vec![0u8; MAX_TRANSPORT_PLAINTEXT + 1];
        assert_eq!(
            transport_encrypt(&mut a, &too_big),
            Err(LanNoiseError::PlaintextTooLarge)
        );
    }

    #[test]
    fn noise_static_is_not_identity_seed() {
        let id = alice();
        let noise = derive_noise_static(&id).unwrap();
        assert_ne!(*noise, id.seed_bytes());
        assert_ne!(*noise, [0u8; 32]);
    }

    #[test]
    fn noise_static_is_wiped_on_drop() {
        // The derived key is identity-equivalent; it must not be a bare array
        // that callers leave on the stack.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let noise = derive_noise_static(&alice()).unwrap();
        assert_zeroize_on_drop(&noise);
    }

    #[test]
    fn max_noise_msg_matches_snow_limit() {
        // Framers cap `u32_be` lengths at this value before allocating; it must
        // equal snow's own limit so no valid Noise message is ever rejected.
        let (mut a, mut b, _, _) = handshake_pair(&alice(), &bob()).unwrap();
        let ct = transport_encrypt(&mut a, &vec![0u8; MAX_TRANSPORT_PLAINTEXT]).unwrap();
        assert_eq!(ct.len(), MAX_NOISE_MSG);
        let too_long = vec![0u8; MAX_NOISE_MSG + 1];
        assert!(b
            .read_message(&too_long, &mut vec![0u8; MAX_NOISE_MSG + 1])
            .is_err());
    }

    #[test]
    fn prologue_mismatch_fails_handshake() {
        // A LAN (no prologue) initiator must not complete XX against a
        // responder that uses a carrier prologue.
        let a = derive_noise_static(&alice()).unwrap();
        let b = derive_noise_static(&bob()).unwrap();
        let mut initiator = build_initiator(&a).unwrap();
        let mut responder = build_responder_with_prologue(&b, b"raven/internet/v1").unwrap();
        let m1 = handshake_write(&mut initiator, &[]).unwrap();
        handshake_read(&mut responder, &m1).unwrap();
        let m2 = handshake_write(&mut responder, &[]).unwrap();
        assert_eq!(
            handshake_read(&mut initiator, &m2),
            Err(LanNoiseError::Handshake)
        );
    }
}
