//! RVFI1 init parse + post-init state bootstrap (design §4.2).

use std::fmt;

use zeroize::Zeroize;

use crate::hybrid_ratchet_v2::{ratchet_init_alice_scka, ratchet_init_bob_scka, SckaInitOut};
use crate::hybrid_ratchet_v2_full_braid::authenticator::AuthState;
use crate::hybrid_ratchet_v2_full_braid::constants::{
    AGENT_KEYS_UNSAMPLED, AGENT_NO_HEADER_RECEIVED, ERR_PARSE,
};
use crate::hybrid_ratchet_v2_full_braid::state_codec::{
    bob_empty_hdr_inbound_set, encode_rvfb1, Rvfb1Prefix, Rvfb1State,
};
use crate::hybrid_ratchet_v2_full_braid::wire_rvft1::{Rvft1, SckaChainEntry};
use crate::hybrid_ratchet_v2_full_braid::wire_util::{
    expect_magic, read_array32, read_bytes, read_u8, reject_trailing, WireResult,
};
use crate::hybrid_ratchet_v2_tr::{ec_dr_init_alice, ec_dr_init_bob, x25519_public, EcDrState};

pub const RVFI1_MAGIC: &[u8; 8] = b"RVFI1\0\0\0";
pub const RVFI1_LEN: usize = 176;
pub const RVFI1_SCHEMA: u16 = 1;

pub const ROLE_ALICE: u8 = 0;
pub const ROLE_BOB: u8 = 1;

/// Session roots and the role DH private key: wiped on drop, redacted from Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct Rvfi1 {
    pub session_id: [u8; 32],
    pub role: u8,
    pub sk_ec: [u8; 32],
    pub sk_scka: [u8; 32],
    pub bob_spk_pub: [u8; 32],
    pub role_material: [u8; 32],
}

impl fmt::Debug for Rvfi1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rvfi1")
            .field("session_id", &self.session_id)
            .field("role", &self.role)
            .field("bob_spk_pub", &self.bob_spk_pub)
            .field("secrets", &"<redacted>")
            .finish()
    }
}

impl Drop for Rvfi1 {
    fn drop(&mut self) {
        self.sk_ec.zeroize();
        self.sk_scka.zeroize();
        self.role_material.zeroize();
    }
}

pub fn decode_rvfi1(data: &[u8]) -> WireResult<Rvfi1> {
    if data.len() != RVFI1_LEN {
        return Err("rvfi1 bad length".into());
    }
    expect_magic(data, RVFI1_MAGIC)?;
    let mut off = 8;
    let schema = crate::hybrid_ratchet_v2_full_braid::wire_util::read_u16be(data, &mut off)?;
    if schema != RVFI1_SCHEMA {
        return Err("rvfi1 bad schema".into());
    }
    let session_id = read_array32(data, &mut off)?;
    let role = read_u8(data, &mut off)?;
    if role > ROLE_BOB {
        return Err("rvfi1 role".into());
    }
    let reserved0 = read_u8(data, &mut off)?;
    if reserved0 != 0 {
        return Err("rvfi1 reserved0".into());
    }
    let sk_ec = read_array32(data, &mut off)?;
    let sk_scka = read_array32(data, &mut off)?;
    let bob_spk_pub = read_array32(data, &mut off)?;
    let role_material = read_array32(data, &mut off)?;
    let reserved_tail = read_bytes(data, &mut off, 4)?;
    if reserved_tail != [0u8; 4] {
        return Err("rvfi1 reserved_tail".into());
    }
    reject_trailing(data, off)?;
    Ok(Rvfi1 {
        session_id,
        role,
        sk_ec,
        sk_scka,
        bob_spk_pub,
        role_material,
    })
}

fn auth_init(sk_scka: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Design §4.2: auth ← Authenticator.Init(1, SK_scka) (SPQR pin).
    let auth = AuthState::init(1, sk_scka);
    (auth.root_key, auth.mac_key)
}

fn zero_pending(prefix: &mut Rvfb1Prefix) {
    prefix.pending_phase = 0;
    prefix.pending_transition_id = [0u8; 32];
    prefix.pending_before_digest = [0u8; 32];
    prefix.pending_output_digest = [0u8; 32];
    prefix.pending_execution_digest = [0u8; 32];
    prefix.terminal_reason = 0;
    prefix.generation = 0;
    prefix.flags = 0;
    prefix.braid_agent_epoch = 1;
    prefix.braid_send_epoch = 0;
    prefix.braid_recv_epoch = 0;
}

fn scka_init_chain(ck: [u8; 32]) -> Vec<SckaChainEntry> {
    vec![SckaChainEntry { epoch: 0, ck, n: 0 }]
}

/// Copy an initialised EC Double Ratchet into RVFT1 (no skipped keys at init).
fn rvft1_from_ec(ec: &EcDrState, scka: &SckaInitOut) -> Rvft1 {
    Rvft1 {
        scka_rk: scka.rk,
        scka_sending_epoch: 0,
        scka_receiving_epoch: 0,
        scka_send_chain: scka_init_chain(scka.ck_send),
        scka_recv_chain: scka_init_chain(scka.ck_recv),
        scka_send_pn: 0,
        scka_skipped: Vec::new(),
        ec_rk: ec.rk,
        ec_dhs_priv: ec.dhs_priv,
        ec_dhs_pub: ec.dhs_pub,
        ec_dhr_present: ec.dhr_pub.is_some() as u8,
        ec_dhr_pub: ec.dhr_pub.unwrap_or([0u8; 32]),
        ec_ck_send_present: ec.cks.is_some() as u8,
        ec_ck_recv_present: ec.ckr.is_some() as u8,
        ec_ck_send: ec.cks.unwrap_or([0u8; 32]),
        ec_ck_recv: ec.ckr.unwrap_or([0u8; 32]),
        ec_ns: ec.ns,
        ec_nr: ec.nr,
        ec_pn: ec.pn,
        ec_skipped: Vec::new(),
    }
}

/// Alice: `SK_ec` is the EC root only; her ratchet key is the ephemeral
/// `role_material`, whose DH with Bob's SPK seeds her first sending chain.
fn rvft1_alice_init(
    sk_ec: &[u8; 32],
    sk_scka: &[u8; 32],
    bob_spk_pub: &[u8; 32],
    alice_dh_priv: &[u8; 32],
) -> WireResult<Rvft1> {
    let ec = ec_dr_init_alice(sk_ec, alice_dh_priv, bob_spk_pub).map_err(|e| e.to_string())?;
    Ok(rvft1_from_ec(&ec, &ratchet_init_alice_scka(sk_scka)))
}

/// Bob: his ratchet key is the SPK private key (`role_material`); `SK_ec` is
/// the EC root only and is never used as a DH private key.
fn rvft1_bob_init(
    sk_ec: &[u8; 32],
    sk_scka: &[u8; 32],
    bob_spk_priv: &[u8; 32],
) -> WireResult<Rvft1> {
    let ec = ec_dr_init_bob(sk_ec, bob_spk_priv).map_err(|e| e.to_string())?;
    Ok(rvft1_from_ec(&ec, &ratchet_init_bob_scka(sk_scka)))
}

pub fn init_state_from_rvfi1(init: &Rvfi1) -> WireResult<Rvfb1State> {
    let (auth_root, auth_mac_key) = auth_init(&init.sk_scka);
    let mut prefix = Rvfb1Prefix {
        session_id: init.session_id,
        role: init.role,
        generation: 0,
        agent: 0,
        terminal_reason: 0,
        auth_root,
        auth_mac_key,
        braid_agent_epoch: 1,
        braid_send_epoch: 0,
        braid_recv_epoch: 0,
        flags: 0,
        pending_phase: 0,
        pending_transition_id: [0u8; 32],
        pending_before_digest: [0u8; 32],
        pending_output_digest: [0u8; 32],
        pending_execution_digest: [0u8; 32],
    };
    zero_pending(&mut prefix);

    match init.role {
        ROLE_ALICE => {
            prefix.agent = AGENT_KEYS_UNSAMPLED;
            let tr = rvft1_alice_init(
                &init.sk_ec,
                &init.sk_scka,
                &init.bob_spk_pub,
                &init.role_material,
            )?;
            Ok(Rvfb1State {
                prefix,
                inbound_sets: Vec::new(),
                active_send: None,
                objects: Vec::new(),
                replays: Vec::new(),
                tlvs: Vec::new(),
                tr,
            })
        }
        ROLE_BOB => {
            let derived_spk = x25519_public(&init.role_material).map_err(|e| e.to_string())?;
            if derived_spk != init.bob_spk_pub {
                return Err("rvfi1 bob spk mismatch".into());
            }
            prefix.agent = AGENT_NO_HEADER_RECEIVED;
            Ok(Rvfb1State {
                prefix,
                inbound_sets: vec![bob_empty_hdr_inbound_set()],
                active_send: None,
                objects: Vec::new(),
                replays: Vec::new(),
                tlvs: Vec::new(),
                tr: rvft1_bob_init(&init.sk_ec, &init.sk_scka, &init.role_material)?,
            })
        }
        _ => Err("rvfi1 role".into()),
    }
}

/// Parse RVFI1 and produce initial canonical RVFB1 bytes.
pub fn init_write(init_bytes: &[u8]) -> Result<Vec<u8>, i32> {
    let init = decode_rvfi1(init_bytes).map_err(|_| ERR_PARSE)?;
    let state = init_state_from_rvfi1(&init).map_err(|_| ERR_PARSE)?;
    encode_rvfb1(&state).map_err(|_| ERR_PARSE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_ratchet_v2_full_braid::constants::RVFB1_PREFIX;
    use crate::hybrid_ratchet_v2_full_braid::state_codec::{
        decode_rvfb1, DIR_A2B, SOURCE_KIND_HDR,
    };
    use crate::hybrid_ratchet_v2_full_braid::wire_rvft1::encode_rvft1;
    use crate::hybrid_ratchet_v2_full_braid::wire_util::{
        write_array32, write_bytes, write_u16be, write_u32be, write_u8,
    };
    use crate::hybrid_ratchet_v2_tr::x25519_public;

    fn sample_rvfi1(
        role: u8,
        sk_ec: [u8; 32],
        sk_scka: [u8; 32],
        bob_spk_priv: [u8; 32],
    ) -> Vec<u8> {
        let bob_spk_pub = x25519_public(&bob_spk_priv).unwrap();
        let role_material = if role == ROLE_ALICE {
            [0xA1u8; 32]
        } else {
            bob_spk_priv
        };
        let mut out = Vec::with_capacity(RVFI1_LEN);
        write_bytes(&mut out, RVFI1_MAGIC);
        write_u16be(&mut out, RVFI1_SCHEMA);
        write_array32(&mut out, &[0x53; 32]); // session_id
        write_u8(&mut out, role);
        write_u8(&mut out, 0);
        write_array32(&mut out, &sk_ec);
        write_array32(&mut out, &sk_scka);
        write_array32(&mut out, &bob_spk_pub);
        write_array32(&mut out, &role_material);
        write_u32be(&mut out, 0);
        assert_eq!(out.len(), RVFI1_LEN);
        out
    }

    #[test]
    fn rvfi1_exact_176() {
        let wire = sample_rvfi1(ROLE_ALICE, [0x01; 32], [0x02; 32], [0x03; 32]);
        assert_eq!(wire.len(), RVFI1_LEN);
        assert_eq!(decode_rvfi1(&wire).unwrap().role, ROLE_ALICE);
    }

    #[test]
    fn alice_post_init_fields() {
        let sk_ec = [0x11; 32];
        let sk_scka = [0x22; 32];
        let bob_priv = [0x33; 32];
        let init = decode_rvfi1(&sample_rvfi1(ROLE_ALICE, sk_ec, sk_scka, bob_priv)).unwrap();
        let state = init_state_from_rvfi1(&init).unwrap();
        assert_eq!(state.prefix.agent, AGENT_KEYS_UNSAMPLED);
        assert_eq!(state.prefix.flags, 0);
        assert_eq!(state.prefix.braid_agent_epoch, 1);
        assert!(state.inbound_sets.is_empty());
        assert!(state.active_send.is_none());
        assert!(state.objects.is_empty());
        let tr_wire = encode_rvft1(&state.tr).unwrap();
        assert_eq!(&tr_wire[..8], b"RVFT1\0\0\0");
        assert_eq!(state.tr.ec_dhr_present, 1);
        assert_eq!(state.tr.scka_send_chain.len(), 1);
        let wire = encode_rvfb1(&state).unwrap();
        assert!(wire.len() > RVFB1_PREFIX);
        assert_eq!(decode_rvfb1(&wire).unwrap(), state);
    }

    #[test]
    fn bob_post_init_hdr_inbound() {
        let sk_ec = [0x41; 32];
        let sk_scka = [0x42; 32];
        let bob_priv = [0x43; 32];
        let init = decode_rvfi1(&sample_rvfi1(ROLE_BOB, sk_ec, sk_scka, bob_priv)).unwrap();
        let state = init_state_from_rvfi1(&init).unwrap();
        assert_eq!(state.prefix.agent, AGENT_NO_HEADER_RECEIVED);
        assert_eq!(state.inbound_sets.len(), 1);
        assert_eq!(state.inbound_sets[0].source_kind, SOURCE_KIND_HDR);
        assert_eq!(state.inbound_sets[0].direction, DIR_A2B);
        assert_eq!(state.inbound_sets[0].epoch, 1);
        assert_eq!(
            state.inbound_sets[0].max_index,
            crate::hybrid_ratchet_v2_full_braid::spqr_codec::BRAID_MAX_CHUNK_INDEX
        );
        assert_eq!(state.inbound_sets[0].bitmap.len(), 8);
        assert!(state.inbound_sets[0].bitmap.iter().all(|&b| b == 0));
        assert!(state.inbound_sets[0].chunks.is_empty());
        let wire = init_write(&sample_rvfi1(ROLE_BOB, sk_ec, sk_scka, bob_priv)).unwrap();
        let decoded = decode_rvfb1(&wire).unwrap();
        assert_eq!(decoded.prefix.agent, AGENT_NO_HEADER_RECEIVED);
        assert_eq!(decoded.inbound_sets, state.inbound_sets);
    }

    #[test]
    fn root_key_is_never_a_dh_private_key_and_bob_derives_alice_chain() {
        use crate::hybrid_ratchet_v2_tr::{ec_dr_decrypt, ec_dr_encrypt, EcDrHeader};

        let sk_ec = [0x61; 32];
        let sk_scka = [0x62; 32];
        let bob_priv = [0x63; 32];
        let alice = init_state_from_rvfi1(
            &decode_rvfi1(&sample_rvfi1(ROLE_ALICE, sk_ec, sk_scka, bob_priv)).unwrap(),
        )
        .unwrap();
        let bob = init_state_from_rvfi1(
            &decode_rvfi1(&sample_rvfi1(ROLE_BOB, sk_ec, sk_scka, bob_priv)).unwrap(),
        )
        .unwrap();

        // Alice ratchets with her ephemeral role_material; Bob with his SPK.
        assert_eq!(alice.tr.ec_dhs_priv, [0xA1; 32]);
        assert_eq!(alice.tr.ec_dhs_pub, x25519_public(&[0xA1; 32]).unwrap());
        assert_eq!(bob.tr.ec_dhs_priv, bob_priv);
        assert_eq!(bob.tr.ec_dhs_pub, x25519_public(&bob_priv).unwrap());
        assert_eq!(alice.tr.ec_dhr_pub, bob.tr.ec_dhs_pub);
        assert_ne!(alice.tr.ec_dhs_priv, sk_ec);
        assert_ne!(bob.tr.ec_dhs_priv, sk_ec);
        assert_ne!(alice.tr.ec_dhs_pub, bob.tr.ec_dhs_pub);
        assert_eq!(bob.tr.ec_rk, sk_ec);
        assert_eq!(bob.tr.ec_ck_send_present, 0);

        // Bob's first receive reproduces Alice's first message key.
        let to_ec = |tr: &Rvft1| crate::hybrid_ratchet_v2_tr::EcDrState {
            rk: tr.ec_rk,
            dhs_priv: tr.ec_dhs_priv,
            dhs_pub: tr.ec_dhs_pub,
            dhr_pub: (tr.ec_dhr_present == 1).then_some(tr.ec_dhr_pub),
            cks: (tr.ec_ck_send_present == 1).then_some(tr.ec_ck_send),
            ckr: (tr.ec_ck_recv_present == 1).then_some(tr.ec_ck_recv),
            ns: tr.ec_ns,
            nr: tr.ec_nr,
            pn: tr.ec_pn,
            mkskipped: Default::default(),
        };
        let (_, header, alice_mk) = ec_dr_encrypt(&to_ec(&alice.tr)).unwrap();
        assert_eq!(
            header,
            EcDrHeader {
                dh_pub: alice.tr.ec_dhs_pub,
                pn: 0,
                n: 0
            }
        );
        let (_, bob_mk) = ec_dr_decrypt(
            &to_ec(&bob.tr),
            &header,
            crate::hybrid_ratchet_v2::MAX_SKIP,
            Some(&[0x64; 32]),
            16,
        )
        .unwrap();
        assert_eq!(bob_mk, alice_mk);
    }

    #[test]
    fn alice_zero_dh_rejected_at_init() {
        let init = decode_rvfi1(&sample_rvfi1(
            ROLE_ALICE, [0x51; 32], [0x52; 32], [0x53; 32],
        ))
        .unwrap();
        let mut bad = init.clone();
        bad.role_material = [0u8; 32];
        assert!(init_state_from_rvfi1(&bad).is_err());
    }
}
