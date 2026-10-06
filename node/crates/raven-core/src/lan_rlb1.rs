//! RLB1 — LAN bundle offer (device cert + signed prekey).
//!
//! Replaces `ash lab import-peer-cert` / import-prekey on the direct LAN path.
//! The payload is JSON of already-signed public records; confidentiality comes
//! from the Noise XX session that carries the frame.

use crate::device_cert::DeviceCertificate;
use crate::prekey_bundle::{PrekeyBundle, PrekeyBundleJson};

pub const RLB1_MAGIC: &[u8; 4] = b"RLB1";
pub const RLB1_VERSION: u8 = 1;
pub const RLB1_KIND_OFFER: u8 = 2;
/// `6 + u32 cert_len + u32 prekey_len` header bytes before JSON payloads.
pub const RLB1_HEADER_LEN: usize = 14;
/// Whole offer must fit in one Noise transport plaintext (`65535 − 16` tag).
pub const MAX_OFFER_WIRE: usize = 65519;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanBundle {
    pub cert: DeviceCertificate,
    pub prekey: PrekeyBundle,
}

pub fn encode_offer(bundle: &LanBundle) -> Result<Vec<u8>, String> {
    let cert = serde_json::to_vec(&bundle.cert).map_err(|e| format!("rlb1 cert: {e}"))?;
    let prekey =
        serde_json::to_vec(&bundle.prekey.to_json()).map_err(|e| format!("rlb1 prekey: {e}"))?;
    if cert.len() > 64 * 1024 || prekey.len() > 64 * 1024 {
        return Err("rlb1 offer too large".into());
    }
    if RLB1_HEADER_LEN + cert.len() + prekey.len() > MAX_OFFER_WIRE {
        return Err("rlb1 offer exceeds transport plaintext".into());
    }
    let mut out = Vec::with_capacity(RLB1_HEADER_LEN + cert.len() + prekey.len());
    out.extend_from_slice(RLB1_MAGIC);
    out.push(RLB1_VERSION);
    out.push(RLB1_KIND_OFFER);
    out.extend_from_slice(&(cert.len() as u32).to_be_bytes());
    out.extend_from_slice(&cert);
    out.extend_from_slice(&(prekey.len() as u32).to_be_bytes());
    out.extend_from_slice(&prekey);
    Ok(out)
}

pub fn decode_offer(bytes: &[u8]) -> Result<LanBundle, String> {
    if bytes.len() < 10 || bytes[..4] != *RLB1_MAGIC {
        return Err("rlb1 magic".into());
    }
    if bytes[4] != RLB1_VERSION {
        return Err("rlb1 version".into());
    }
    if bytes[5] != RLB1_KIND_OFFER {
        return Err("rlb1 kind".into());
    }
    if bytes.len() > MAX_OFFER_WIRE {
        return Err("rlb1 offer exceeds transport plaintext".into());
    }
    // Attacker-chosen u32 lengths: every offset below is checked, so a length
    // near u32::MAX cannot wrap `usize` on 32-bit targets (armv7, wasm32).
    let cert_len = u32::from_be_bytes(bytes[6..10].try_into().unwrap()) as usize;
    let cert_start: usize = 10;
    let cert_end = cert_start
        .checked_add(cert_len)
        .ok_or_else(|| "rlb1 cert overflow".to_string())?;
    let prekey_start = cert_end
        .checked_add(4)
        .filter(|&end| end <= bytes.len())
        .ok_or_else(|| "rlb1 cert truncated".to_string())?;
    let prekey_len = u32::from_be_bytes(bytes[cert_end..prekey_start].try_into().unwrap()) as usize;
    let prekey_end = prekey_start
        .checked_add(prekey_len)
        .ok_or_else(|| "rlb1 prekey overflow".to_string())?;
    if prekey_end != bytes.len() {
        return Err("rlb1 trailing bytes".into());
    }
    let cert: DeviceCertificate = serde_json::from_slice(&bytes[cert_start..cert_end])
        .map_err(|e| format!("rlb1 cert json: {e}"))?;
    let prekey_json: PrekeyBundleJson = serde_json::from_slice(&bytes[prekey_start..prekey_end])
        .map_err(|e| format!("rlb1 prekey json: {e}"))?;
    let prekey = PrekeyBundle::from_json(&prekey_json)?;
    let bundle = LanBundle { cert, prekey };
    // Structural bind only here — callers verify signatures/expiry with a clock.
    bundle.require_identity_bound()?;
    Ok(bundle)
}

impl LanBundle {
    /// Cert and prekey must name the same user identity and device_id.
    pub fn require_identity_bound(&self) -> Result<(), String> {
        if self.prekey.identity_ed25519_pub != self.cert.user_ed_pub {
            return Err("lan bundle prekey/cert identity mismatch".into());
        }
        if self.prekey.device_id != self.cert.device_id {
            return Err("lan bundle prekey/cert device_id mismatch".into());
        }
        Ok(())
    }

    pub fn verify_bound(&self, now_ms: u64) -> Result<(), String> {
        self.require_identity_bound()?;
        self.cert.verify(now_ms)?;
        self.prekey.verify(now_ms)?;
        Ok(())
    }
}

pub fn is_rlb1(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == *RLB1_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::prekey_bundle::PrekeyBundle;

    #[test]
    fn offer_roundtrip() {
        let user = Identity::from_seed(&[0x51; 32]);
        let now = 1_700_000_000_000u64;
        let cert = crate::device_cert::DeviceCertificate::issue(
            &user,
            user.public_key_bytes(),
            [0x61; 32],
            "ash-primary",
            now - 60_000,
            now + 86_400_000,
            0,
        )
        .unwrap();
        let bundle = PrekeyBundle::from_hybrid_public(
            "ash-primary",
            [0x61; 32],
            vec![0x02; crate::prekey_bundle::MLKEM768_EK_LEN],
            1,
            now,
            now + 86_400_000,
        )
        .unwrap()
        .sign(&user)
        .unwrap();
        let offer = LanBundle {
            cert,
            prekey: bundle,
        };
        let wire = encode_offer(&offer).unwrap();
        assert!(is_rlb1(&wire));
        let back = decode_offer(&wire).unwrap();
        assert_eq!(back.cert, offer.cert);
        assert_eq!(back.prekey, offer.prekey);
    }

    #[test]
    fn hostile_lengths_are_rejected_without_panic() {
        // Header-only frames whose u32 lengths point past the buffer. On a
        // 32-bit target `cert_end + 4` used to overflow for these values.
        for cert_len in [u32::MAX, u32::MAX - 3, u32::MAX - 13, 0x7fff_ffff, 5] {
            let mut wire = RLB1_MAGIC.to_vec();
            wire.extend_from_slice(&[RLB1_VERSION, RLB1_KIND_OFFER]);
            wire.extend_from_slice(&cert_len.to_be_bytes());
            wire.extend_from_slice(&[0u8; 8]);
            assert!(decode_offer(&wire).is_err(), "cert_len={cert_len:#x}");
        }
        // Valid cert length, hostile prekey length.
        for prekey_len in [u32::MAX, u32::MAX - 13, 1] {
            let mut wire = RLB1_MAGIC.to_vec();
            wire.extend_from_slice(&[RLB1_VERSION, RLB1_KIND_OFFER]);
            wire.extend_from_slice(&0u32.to_be_bytes());
            wire.extend_from_slice(&prekey_len.to_be_bytes());
            assert!(decode_offer(&wire).is_err(), "prekey_len={prekey_len:#x}");
        }
    }

    #[test]
    fn combined_offer_cap_rejects_oversize() {
        let user = Identity::from_seed(&[0x51; 32]);
        let now = 1_700_000_000_000u64;
        let huge_id = "x".repeat(60_000);
        let cert = crate::device_cert::DeviceCertificate::issue(
            &user,
            user.public_key_bytes(),
            [0x61; 32],
            &huge_id,
            now - 60_000,
            now + 86_400_000,
            0,
        )
        .unwrap();
        let prekey = PrekeyBundle::from_hybrid_public(
            &huge_id,
            [0x61; 32],
            vec![0x02; crate::prekey_bundle::MLKEM768_EK_LEN],
            1,
            now,
            now + 86_400_000,
        )
        .unwrap()
        .sign(&user)
        .unwrap();
        let offer = LanBundle { cert, prekey };
        let cert_json = serde_json::to_vec(&offer.cert).unwrap();
        let prekey_json = serde_json::to_vec(&offer.prekey.to_json()).unwrap();
        assert!(RLB1_HEADER_LEN + cert_json.len() + prekey_json.len() > MAX_OFFER_WIRE);
        assert_eq!(
            encode_offer(&offer),
            Err("rlb1 offer exceeds transport plaintext".into())
        );
        let mut wire = encode_offer(&LanBundle {
            cert: crate::device_cert::DeviceCertificate::issue(
                &user,
                user.public_key_bytes(),
                [0x61; 32],
                "ok-device",
                now - 60_000,
                now + 86_400_000,
                0,
            )
            .unwrap(),
            prekey: PrekeyBundle::from_hybrid_public(
                "ok-device",
                [0x61; 32],
                vec![0x02; crate::prekey_bundle::MLKEM768_EK_LEN],
                1,
                now,
                now + 86_400_000,
            )
            .unwrap()
            .sign(&user)
            .unwrap(),
        })
        .unwrap();
        wire.resize(MAX_OFFER_WIRE + 1, 0);
        assert_eq!(
            decode_offer(&wire),
            Err("rlb1 offer exceeds transport plaintext".into())
        );
    }
}
