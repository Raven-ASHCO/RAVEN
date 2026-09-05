//! ATSAM adversarial battery — attacks an active adversary may mount against
//! the sealed-message path. Every test encodes one attack; the assertion is the
//! defense. Green here means the attack failed.
//!
//! Class A (Double Ratchet replay / reorder) requires `--features full-braid-lab`.
//! Classes B–F run on default builds.

use std::collections::HashSet;

use raven_core::ack::Ack;
use raven_core::atsam_aead::{seal_rvna1_v2, unseal_rvna1_v2};
use raven_core::atsam_indexed_session::{
    derive_route_tag, encode_signed_ack, message_key_at_index, open_ack,
    open_indexed_message_with_key, route_coordinates, seal_ack, seal_indexed_message_with_key,
    Direction, SignedAck,
};
use raven_core::atsam_root::{derive_root, transcript_hash, x25519_shared_checked};
use raven_core::envelope::{EnvType, Envelope};
#[cfg(feature = "full-braid-lab")]
use raven_core::hybrid_ratchet_v2_tr::{
    ec_dr_decrypt, ec_dr_encrypt, ec_dr_init_alice, ec_dr_init_bob, EcDrHeader,
};
use raven_core::identity::Identity;
#[cfg(feature = "full-braid-lab")]
use x25519_dalek::{PublicKey, StaticSecret};

fn addr(seed: u8) -> String {
    Identity::from_seed(&[seed; 32]).address()
}

#[cfg(feature = "full-braid-lab")]
fn dr_setup() -> (Identity, Identity, [u8; 32]) {
    let alice = Identity::from_seed(&[0xA1; 32]);
    let bob = Identity::from_seed(&[0xB0; 32]);
    let rk0 = [0x07; 32];
    (alice, bob, rk0)
}

// ---------------------------------------------------------------------------
// Class A — replay / reorder against the Double Ratchet
// Requires `--features full-braid-lab` (`hybrid_ratchet_v2_tr` is lab-only).
// ---------------------------------------------------------------------------

#[cfg(feature = "full-braid-lab")]
#[test]
fn a1_replayed_consumed_message_is_rejected() {
    let (_alice, bob, rk0) = dr_setup();
    let a_priv = [0x11; 32];
    let b_priv = [0x22; 32];
    let b_pub = PublicKey::from(&StaticSecret::from(b_priv)).to_bytes();

    let alice = ec_dr_init_alice(&rk0, &a_priv, &b_pub).unwrap();
    let (alice, hdr0, _mk0) = ec_dr_encrypt(&alice).unwrap();

    let bob_st = ec_dr_init_bob(&rk0, &b_priv).unwrap();
    let b_ratchet_priv = [0x33; 32];
    let (bob_st, _) = ec_dr_decrypt(&bob_st, &hdr0, 100, Some(&b_ratchet_priv), 2000).unwrap();

    let replay = ec_dr_decrypt(&bob_st, &hdr0, 100, None, 2000);
    assert!(replay.is_err(), "replayed message must not decrypt twice");
}

#[cfg(feature = "full-braid-lab")]
#[test]
fn a2_replayed_skipped_message_cannot_open_twice() {
    let (_alice, _bob, rk0) = dr_setup();
    let a_priv = [0x11; 32];
    let b_priv = [0x22; 32];
    let b_pub = PublicKey::from(&StaticSecret::from(b_priv)).to_bytes();
    let b_ratchet_priv = [0x33; 32];

    let mut alice = ec_dr_init_alice(&rk0, &a_priv, &b_pub).unwrap();
    let mut sealed = Vec::new();
    for _ in 0..3 {
        let (st, hdr, _mk) = ec_dr_encrypt(&alice).unwrap();
        alice = st;
        sealed.push(hdr);
    }

    let bob = ec_dr_init_bob(&rk0, &b_priv).unwrap();
    // Attacker holds back m0/m1; m2 arrives first.
    let (bob, _) = ec_dr_decrypt(&bob, &sealed[2], 10, Some(&b_ratchet_priv), 2000).unwrap();
    // Delayed m0 opens once via the skipped-key store…
    let (bob, _) = ec_dr_decrypt(&bob, &sealed[0], 10, None, 2000).unwrap();
    // …and the replayed copy must never open again.
    let replay = ec_dr_decrypt(&bob, &sealed[0], 10, None, 2000);
    assert!(replay.is_err(), "skipped-key replay must fail");
}

#[cfg(feature = "full-braid-lab")]
#[test]
fn a3_adversarial_reordering_is_fully_recoverable() {
    let (_alice, _bob, rk0) = dr_setup();
    let a_priv = [0x11; 32];
    let b_priv = [0x22; 32];
    let b_pub = PublicKey::from(&StaticSecret::from(b_priv)).to_bytes();
    let b_ratchet_priv = [0x33; 32];

    let mut alice = ec_dr_init_alice(&rk0, &a_priv, &b_pub).unwrap();
    let mut sealed = Vec::new();
    for i in 0..5 {
        let (st, hdr, _mk) = ec_dr_encrypt(&alice).unwrap();
        alice = st;
        sealed.push((hdr, i));
    }

    let mut bob = ec_dr_init_bob(&rk0, &b_priv).unwrap();
    let mut delivered = Vec::new();
    for order in [3usize, 1, 4, 0, 2] {
        let (st, _mk) = ec_dr_decrypt(
            &bob,
            &sealed[order].0,
            10,
            if order == 3 {
                Some(&b_ratchet_priv)
            } else {
                None
            },
            2000,
        )
        .expect("reordered delivery must succeed");
        bob = st;
        delivered.push(sealed[order].1);
    }
    delivered.sort_unstable();
    assert_eq!(delivered, vec![0, 1, 2, 3, 4]);
    assert_eq!(bob.nr, 5, "receive head must reach the last index");
}

#[cfg(feature = "full-braid-lab")]
#[test]
fn a4_max_skip_flood_leaves_state_usable() {
    let (_alice, _bob, rk0) = dr_setup();
    let a_priv = [0x11; 32];
    let b_priv = [0x22; 32];
    let b_pub = PublicKey::from(&StaticSecret::from(b_priv)).to_bytes();
    let b_ratchet_priv = [0x33; 32];

    let mut alice = ec_dr_init_alice(&rk0, &a_priv, &b_pub).unwrap();
    let (alice, hdr0, _) = ec_dr_encrypt(&alice).unwrap();
    let (mut alice, hdr1) = {
        let (st, h, _) = ec_dr_encrypt(&alice).unwrap();
        (st, h)
    };
    let _ = hdr1;

    let bob = ec_dr_init_bob(&rk0, &b_priv).unwrap();
    let (bob, _) = ec_dr_decrypt(&bob, &hdr0, 100, Some(&b_ratchet_priv), 2000).unwrap();

    // Attack: fabricated far-ahead sequence number.
    let flood = EcDrHeader {
        dh_pub: hdr0.dh_pub,
        pn: hdr0.pn,
        n: 100_000,
    };
    let attacked = ec_dr_decrypt(&bob, &flood, 50, None, 2000);
    assert!(attacked.is_err(), "far-ahead n must trip MAX_SKIP");

    // The failed attack must not corrupt state — the real next message opens.
    let (_bob, _) = ec_dr_decrypt(&bob, &hdr1, 50, None, 2000).unwrap();
}

#[cfg(feature = "full-braid-lab")]
#[test]
fn a5_skipped_store_exhaustion_is_bounded_and_recovers() {
    let (_alice, _bob, rk0) = dr_setup();
    let a_priv = [0x11; 32];
    let b_priv = [0x22; 32];
    let b_pub = PublicKey::from(&StaticSecret::from(b_priv)).to_bytes();
    let b_ratchet_priv = [0x33; 32];

    let mut alice = ec_dr_init_alice(&rk0, &a_priv, &b_pub).unwrap();
    let (alice, hdr0, _) = ec_dr_encrypt(&alice).unwrap();
    let (alice, hdr1) = {
        let (st, h, _) = ec_dr_encrypt(&alice).unwrap();
        (st, h)
    };
    let _ = hdr1;

    let bob = ec_dr_init_bob(&rk0, &b_priv).unwrap();
    let (bob, _) = ec_dr_decrypt(&bob, &hdr0, 100, Some(&b_ratchet_priv), 2000).unwrap();

    // Attack: force more skipped-key material than the configured budget.
    let gap = EcDrHeader {
        dh_pub: hdr0.dh_pub,
        pn: hdr0.pn,
        n: 64,
    };
    let exhausted = ec_dr_decrypt(&bob, &gap, 100, None, 8);
    assert!(
        exhausted.is_err(),
        "skip-store exhaustion must abort decryption"
    );

    // Legitimate traffic continues afterwards.
    let (_bob, _) = ec_dr_decrypt(&bob, &hdr1, 100, None, 8).unwrap();
}

// ---------------------------------------------------------------------------
// Class B — tampering / substitution at the sealed-frame layer
// ---------------------------------------------------------------------------

#[test]
fn b1_ciphertext_bitflip_detected() {
    let root = [0x44; 32];
    let wire = seal_rvna1_v2(&root, "alice", "bob", "m-1", 0, b"payload", &[0xAB; 12]).unwrap();
    let mut tampered = wire.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(unseal_rvna1_v2(&root, &tampered, "alice", "bob", "m-1").is_err());
}

#[test]
fn b2_cross_index_ciphertext_splice_detected() {
    let root = [0x45; 32];
    let frame5 = seal_rvna1_v2(&root, "a", "b", "m-1", 5, b"secret-A", &[0x01; 12]).unwrap();
    let frame6 = seal_rvna1_v2(&root, "a", "b", "m-2", 6, b"secret-B", &[0x02; 12]).unwrap();

    // Splice frame5's ciphertext behind frame6's header (claims index 6).
    let mut spliced = frame6[..26].to_vec();
    spliced.extend_from_slice(&frame5[26..]);
    assert!(unseal_rvna1_v2(&root, &spliced, "a", "b", "m-2").is_err());
}

#[test]
fn b3_wire_index_tamper_detected() {
    let root = [0x46; 32];
    let wire = seal_rvna1_v2(&root, "a", "b", "m-1", 9, b"payload", &[0xAB; 12]).unwrap();
    let mut tampered = wire.clone();
    tampered[13] ^= 0x01; // low byte of the BE chain index
    assert!(unseal_rvna1_v2(&root, &tampered, "a", "b", "m-1").is_err());
}

#[test]
fn b4_outer_msg_id_substitution_detected() {
    let (ia, ra) = (addr(0xA0), addr(0xB0));
    let root = [0x47; 32];
    let dir = Direction::InitiatorToResponder;
    let idx = 4;
    let outer_id = [0x55; 16];
    let key = message_key_at_index(&root, &ia, &ra, dir, idx).unwrap();
    let wire = seal_indexed_message_with_key(
        &key,
        &ia,
        &ra,
        dir,
        idx,
        &outer_id,
        b"attributed payload",
        &[0xCD; 12],
    )
    .unwrap();

    let mut forged_id = outer_id;
    forged_id[0] ^= 0x80;
    let opened = open_indexed_message_with_key(&key, &ia, &ra, dir, &forged_id, &wire);
    assert!(opened.is_err(), "msg-id swap must break AAD binding");
}

#[test]
fn b5_sender_recipient_reflection_detected() {
    let root = [0x48; 32];
    let wire = seal_rvna1_v2(&root, "alice", "bob", "m-1", 0, b"hi", &[0xAB; 12]).unwrap();
    let reflected = unseal_rvna1_v2(&root, &wire, "bob", "alice", "m-1");
    assert!(reflected.is_err(), "role reflection must not authenticate");
}

#[test]
fn b6_direction_flip_confusion_detected() {
    let (ia, ra) = (addr(0xA1), addr(0xB1));
    let root = [0x49; 32];
    let idx = 2;
    let outer_id = [0x66; 16];

    let key_i2r =
        message_key_at_index(&root, &ia, &ra, Direction::InitiatorToResponder, idx).unwrap();
    let wire = seal_indexed_message_with_key(
        &key_i2r,
        &ia,
        &ra,
        Direction::InitiatorToResponder,
        idx,
        &outer_id,
        b"d",
        &[0xEE; 12],
    )
    .unwrap();

    let flipped = open_indexed_message_with_key(
        &key_i2r,
        &ia,
        &ra,
        Direction::ResponderToInitiator,
        &outer_id,
        &wire,
    );
    assert!(flipped.is_err(), "direction confusion must fail");
}

#[test]
fn b7_ack_lane_and_msg_lane_are_isolated() {
    let (ia, ra) = (addr(0xA2), addr(0xB2));
    let root = [0x4A; 32];
    let dir = Direction::ResponderToInitiator;
    let idx = 3;
    let outer_id = [0x77; 16];

    let signed = SignedAck {
        record: Ack {
            acked_message_id: outer_id,
            status: 1,
            ack_nonce: [0x02; 12],
            created_at: 1_700_000_001_000,
        },
        signature: [0x55; 64],
    };
    let plain101 = encode_signed_ack(&signed).unwrap();
    let ack_wire = seal_ack(&root, &ia, &ra, dir, idx, &outer_id, &plain101, &[0x11; 12]).unwrap();
    assert_eq!(
        open_ack(&root, &ia, &ra, dir, &outer_id, &ack_wire).unwrap(),
        plain101
    );

    // Open the ACK frame through the message lane.
    let msg_key = message_key_at_index(&root, &ia, &ra, dir, idx).unwrap();
    let as_msg = open_indexed_message_with_key(&msg_key, &ia, &ra, dir, &outer_id, &ack_wire);
    assert!(
        as_msg.is_err(),
        "ACK frame must not open under message lane"
    );

    // And a message frame (same 101-byte body shape) must not open as an ACK.
    let msg_pt = [0x20; 101];
    let msg_wire = seal_indexed_message_with_key(
        &msg_key,
        &ia,
        &ra,
        dir,
        idx,
        &outer_id,
        &msg_pt,
        &[0x12; 12],
    )
    .unwrap();
    let as_ack = open_ack(&root, &ia, &ra, dir, &outer_id, &msg_wire);
    assert!(
        as_ack.is_err(),
        "message frame must not open under ACK lane"
    );
}

#[test]
fn b8_proto_suite_downgrade_rejected() {
    let root = [0x4B; 32];
    let wire = seal_rvna1_v2(&root, "a", "b", "m", 0, b"x", &[0xAB; 12]).unwrap();

    let mut proto_down = wire.clone();
    proto_down[8] = 0x01; // claim legacy ATSAM v1
    assert!(unseal_rvna1_v2(&root, &proto_down, "a", "b", "m").is_err());

    let mut suite_down = wire.clone();
    suite_down[9] = 0x99; // unknown cipher suite
    assert!(unseal_rvna1_v2(&root, &suite_down, "a", "b", "m").is_err());
}

// ---------------------------------------------------------------------------
// Class C — routing-tag / metadata manipulation
// ---------------------------------------------------------------------------

#[test]
fn c1_route_coordinates_reject_invalid_env_types() {
    for bad in [0u8, 5, 255] {
        assert!(
            route_coordinates(1_700_000_000_000, 0, bad, Direction::InitiatorToResponder).is_err()
        );
    }
}

#[test]
fn c2_route_tags_are_unique_across_all_axes() {
    let root = [0x4C; 32];
    let base_ms: u64 = 1_700_000_000_000;
    let mut seen = HashSet::new();
    for epoch_ms in [base_ms, base_ms + 1_500] {
        for index in [0u32, 1] {
            for env in [1u8, 2] {
                for dir in [
                    Direction::InitiatorToResponder,
                    Direction::ResponderToInitiator,
                ] {
                    let tag = derive_route_tag(&root, epoch_ms, index, env, dir).unwrap();
                    assert!(seen.insert(tag), "route tag collision across axes");
                }
            }
        }
    }
    assert_eq!(seen.len(), 16);
}

// ---------------------------------------------------------------------------
// Class D — hybrid root derivation and transcript binding
// ---------------------------------------------------------------------------

#[test]
fn d1_transcript_binding_separates_sessions() {
    let z_x = [0x51; 32];
    let z_pq = [0x52; 32];
    let th_a = transcript_hash(b"pairing-transcript-alpha");
    let th_b = transcript_hash(b"pairing-transcript-beta");
    let root_a = derive_root(&z_x, &z_pq, &th_a);
    let root_b = derive_root(&z_x, &z_pq, &th_b);
    assert_ne!(root_a, root_b);

    // End-to-end: a frame sealed under session A must not open under session B.
    let wire = seal_rvna1_v2(&root_a, "a", "b", "m", 0, b"session-bound", &[0xAB; 12]).unwrap();
    assert!(unseal_rvna1_v2(&root_b, &wire, "a", "b", "m").is_err());
    assert!(unseal_rvna1_v2(&root_a, &wire, "a", "b", "m").is_ok());
}

#[test]
fn d2_hybrid_root_sensitive_to_single_bit_flips() {
    let z_x = [0x61; 32];
    let z_pq = [0x62; 32];
    let th = transcript_hash(b"t");
    let baseline = derive_root(&z_x, &z_pq, &th);

    let mut z_pq_flip = z_pq;
    z_pq_flip[31] ^= 0x01;
    assert_ne!(baseline, derive_root(&z_x, &z_pq_flip, &th));

    let mut z_x_flip = z_x;
    z_x_flip[0] ^= 0x01;
    assert_ne!(baseline, derive_root(&z_x_flip, &z_pq, &th));

    let th_flip = transcript_hash(b"u");
    assert_ne!(baseline, derive_root(&z_x, &z_pq, &th_flip));
}

#[test]
fn d3_low_order_x25519_peers_are_rejected() {
    let sk = [0x63; 32];
    let zero_point = [0u8; 32];
    assert!(x25519_shared_checked(&sk, &zero_point).is_err());

    let mut one_point = [0u8; 32];
    one_point[0] = 1; // small-order point
    assert!(
        x25519_shared_checked(&sk, &one_point).is_err(),
        "small-order peer keys must not contribute"
    );
}

// ---------------------------------------------------------------------------
// Class E — envelope signature coverage
// ---------------------------------------------------------------------------

#[test]
fn e1_envelope_signature_binds_every_security_field() {
    let id = Identity::from_seed(&[0xE1; 32]);
    let mut env = Envelope {
        env_type: EnvType::Message as u8,
        flags: 0,
        message_id: [0x01; 16],
        routing_tag: [0x02; 16],
        dest_device_hint: 0,
        created_at: 1_700_000_000_000,
        expires_at: 1_700_003_600_000,
        hop_limit: 8,
        replication_budget: 3,
        anti_replay_nonce: [0x09; 12],
        ratchet_header_ciphertext: vec![0xAA; 40],
        message_ciphertext: vec![0xBB; 50],
        sender_authentication: vec![0; 64],
    };
    env.sign_with(&id);
    assert!(env.verify(&id.public_key_bytes()));

    // Ratchet header swap-in (classic header-injection goal) must break the sig.
    let mut hdr_swap = env.clone();
    hdr_swap.ratchet_header_ciphertext[39] ^= 0x01;
    assert!(!hdr_swap.verify(&id.public_key_bytes()));

    let mut tag_swap = env.clone();
    tag_swap.routing_tag[15] ^= 0x01;
    assert!(!tag_swap.verify(&id.public_key_bytes()));

    let mut body_swap = env;
    body_swap.message_ciphertext[0] ^= 0x01;
    assert!(!body_swap.verify(&id.public_key_bytes()));
}

// ---------------------------------------------------------------------------
// Class F — documented determinism hazard (caller contract)
// ---------------------------------------------------------------------------

#[test]
fn f1_nonce_and_index_reuse_is_deterministic_caller_hazard() {
    let root = [0x71; 32];
    let w1 = seal_rvna1_v2(&root, "a", "b", "m", 0, b"p", &[0xAB; 12]).unwrap();
    let w2 = seal_rvna1_v2(&root, "a", "b", "m", 0, b"p", &[0xAB; 12]).unwrap();
    // Documents the hazard: identical (key,index,nonce) yields identical wire.
    // Endpoint actors MUST draw a fresh random nonce per sealed message.
    assert_eq!(w1, w2);

    let w3 = seal_rvna1_v2(&root, "a", "b", "m", 0, b"p", &[0xAC; 12]).unwrap();
    assert_ne!(w1, w3);
    assert!(unseal_rvna1_v2(&root, &w3, "a", "b", "m").is_ok());
}
