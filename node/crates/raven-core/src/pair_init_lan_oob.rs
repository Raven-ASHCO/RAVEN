//! LAN OOB carrier for PairInit / PairResponse (Test A).
//!
//! Protocol §7 allows PairInit on an already confidential/OOB channel. Same
//! Wi‑Fi LAN with signed RVN1 framing is that carrier for lab Test A — not a
//! public relay claim. Raw RVPI1/RVPR1 cannot ride IPC/LAN alone (strict RVN1
//! unpack); this module wraps them as `EnvType::Message` ciphertext so
//! existing u32-BE length frames and forward queues work unchanged.
//!
//! Classifiers sniff the inner magic. Live networking remains gated by
//! `lab_test_a_enabled()` / production tripwires at the callsite.
//!
//! The wrapped body is the *plaintext* PairInit/PairResponse (both addresses,
//! device keys, cert and prekey digests). §7 forbids placing it in an
//! observable relay body, so the wrapper is direct-only: `hop_limit` and
//! `replication_budget` are 0 (a cooperative relay drops it in
//! `bridge::prepare_forward`) and the outer TTL is short.

use rand::{CryptoRng, RngCore};

use crate::envelope::{EnvType, Envelope};
use crate::identity::Identity;
use crate::pair_init::{INIT_MAGIC, INIT_WIRE_LEN, RESPONSE_MAGIC, RESPONSE_WIRE_LEN};

/// Env flag bit reserved for PairInit OOB (not in ALLOWED_FLAGS yet).
/// Do not set on the wire until the envelope flag registry is extended;
/// classifiers sniff RVPI1/RVPR1 magic in message_ciphertext instead.
pub const FLAG_PAIR_INIT_OOB: u16 = 1 << 8;

/// Outer RVN1 lifetime of an OOB pairing envelope. The carrier is a live,
/// direct exchange and consumers enforce the inner record's own validity
/// window, so this only bounds how long any store/bridge that sees the frame
/// may retain it.
pub const PAIR_INIT_OOB_TTL_MS: u64 = 10 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairInitOobKind {
    PairInit,
    PairResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairInitOobClassify {
    PairInit(Vec<u8>),
    PairResponse(Vec<u8>),
    NotPairInitOob,
}

/// Best-effort body sniff (ignores outer flag; flag is advisory).
pub fn classify_message_ciphertext(body: &[u8]) -> PairInitOobClassify {
    if body.len() == INIT_WIRE_LEN && body.starts_with(&INIT_MAGIC) {
        return PairInitOobClassify::PairInit(body.to_vec());
    }
    if body.len() == RESPONSE_WIRE_LEN && body.starts_with(&RESPONSE_MAGIC) {
        return PairInitOobClassify::PairResponse(body.to_vec());
    }
    PairInitOobClassify::NotPairInitOob
}

pub fn classify_packed_envelope(packed: &[u8]) -> PairInitOobClassify {
    let Some(env) = Envelope::unpack(packed) else {
        return PairInitOobClassify::NotPairInitOob;
    };
    if env.env_type != EnvType::Message as u8 {
        return PairInitOobClassify::NotPairInitOob;
    }
    classify_message_ciphertext(&env.message_ciphertext)
}

/// Pack PairInit or PairResponse wire as a signed RVN1 Message for LAN/IPC.
pub fn wrap_oob_wire<R: RngCore + CryptoRng>(
    wire: &[u8],
    kind: PairInitOobKind,
    identity: &Identity,
    routing_tag: [u8; 16],
    now_ms: u64,
    rng: &mut R,
) -> Result<Vec<u8>, String> {
    match kind {
        PairInitOobKind::PairInit => {
            if wire.len() != INIT_WIRE_LEN || !wire.starts_with(&INIT_MAGIC) {
                return Err("PAIR_INIT_OOB_BAD_INIT_WIRE".into());
            }
        }
        PairInitOobKind::PairResponse => {
            if wire.len() != RESPONSE_WIRE_LEN || !wire.starts_with(&RESPONSE_MAGIC) {
                return Err("PAIR_INIT_OOB_BAD_RESPONSE_WIRE".into());
            }
        }
    }
    let mut message_id = [0u8; 16];
    rng.fill_bytes(&mut message_id);
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let mut env = Envelope {
        env_type: EnvType::Message as u8,
        flags: 0, // magic-sniff only; FLAG_PAIR_INIT_OOB not in ALLOWED_FLAGS yet
        message_id,
        routing_tag,
        dest_device_hint: 0,
        created_at: now_ms,
        expires_at: now_ms.saturating_add(PAIR_INIT_OOB_TTL_MS),
        // Direct-only (§7): never relay-, spray- or store-forward eligible.
        hop_limit: 0,
        replication_budget: 0,
        anti_replay_nonce: nonce,
        ratchet_header_ciphertext: vec![],
        message_ciphertext: wire.to_vec(),
        sender_authentication: vec![],
    };
    env.sign_with(identity);
    Ok(env.pack())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pair_init::{decode_init, INIT_WIRE_LEN};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use serde_json::Value;
    use std::path::PathBuf;

    fn pair_init_wire() -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../shared-vectors/rvn1/atsam/pair_init_v1_001.json");
        let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        hex::decode(vector["expected"]["pair_init_wire_hex"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn wrap_and_classify_round_trip() {
        let wire = pair_init_wire();
        assert_eq!(wire.len(), INIT_WIRE_LEN);
        let id = Identity::from_seed(&[0x42; 32]);
        let mut rng = StdRng::seed_from_u64(9);
        let packed = wrap_oob_wire(
            &wire,
            PairInitOobKind::PairInit,
            &id,
            [0x11; 16],
            1_700_000_000_000,
            &mut rng,
        )
        .unwrap();
        let env = Envelope::unpack(&packed).expect("unpack");
        assert_eq!(env.flags, 0);
        assert_eq!(env.message_ciphertext.len(), wire.len());
        match classify_packed_envelope(&packed) {
            PairInitOobClassify::PairInit(body) => {
                assert_eq!(body, wire);
                assert!(decode_init(&body).is_ok());
            }
            other => panic!("expected PairInit, got {other:?}"),
        }
    }

    #[test]
    fn oob_wrapper_is_direct_only() {
        use crate::bridge::{decide, BridgeAction, BridgeRole, DropReason};

        let wire = pair_init_wire();
        let id = Identity::from_seed(&[0x42; 32]);
        let mut rng = StdRng::seed_from_u64(10);
        let now = 1_700_000_000_000;
        let packed = wrap_oob_wire(
            &wire,
            PairInitOobKind::PairInit,
            &id,
            [0x11; 16],
            now,
            &mut rng,
        )
        .unwrap();
        let env = Envelope::unpack(&packed).expect("unpack");
        assert_eq!(env.hop_limit, 0);
        assert_eq!(env.replication_budget, 0);
        assert_eq!(env.expires_at, now + PAIR_INIT_OOB_TTL_MS);
        assert!(env.verify(&id.public_key_bytes()));
        assert_eq!(
            decide(&packed, BridgeRole::Relay, now, false),
            BridgeAction::Drop {
                reason: DropReason::HopExhausted
            }
        );
        assert_eq!(
            decide(&packed, BridgeRole::Endpoint, now, false),
            BridgeAction::DeliverLocal
        );
    }
}
