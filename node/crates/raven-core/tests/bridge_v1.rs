//! Integration tests for Raven Bridge V1 (cases 1–8). Mock BLE = TCP length-prefix.

use raven_core::ack::{Ack, STATUS_DELIVERED};
use raven_core::atsam_indexed_session::{
    open_indexed_message_with_key, seal_indexed_message_with_key, Direction,
};
use raven_core::bridge::{authenticated_object_digest, DropReason};
use raven_core::envelope::{EnvType, Envelope};
use raven_core::forward_queue::{
    ForwardItem, ForwardQueue, ForwardState, MAX_ENVELOPE_BYTES, MAX_FORWARD_TTL_MS,
    MAX_RELAY_SEEN_OBJECTS,
};
use raven_core::identity::Identity;
use raven_core::message_router::{InboundEnvelope, MessageRouter, RouterOutcome};
use raven_core::transport::TransportKind;
use tempfile::tempdir;

/// A known test message key. This exercises the indexed-session RVNA1 `0x03`
/// wire and AEAD path (the only body custody admits) without pretending that
/// public identity keys are a secret.
const BRIDGE_TEST_ROOT: [u8; 32] = [0x42; 32];

fn now() -> u64 {
    1_700_000_000_000
}

fn make_env(
    signer: &Identity,
    seal_to: &Identity,
    plaintext: &[u8],
    message_id: [u8; 16],
    hop: u8,
    expires_at: u64,
) -> Envelope {
    let message_id_text = hex::encode(message_id);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&message_id[..12]);
    let _ = message_id_text;
    let sealed = seal_indexed_message_with_key(
        &BRIDGE_TEST_ROOT,
        &signer.address(),
        &seal_to.address(),
        Direction::InitiatorToResponder,
        0,
        &message_id,
        plaintext,
        &nonce,
    )
    .unwrap();
    let mut env = Envelope {
        env_type: EnvType::Message as u8,
        flags: 0,
        message_id,
        routing_tag: [7u8; 16],
        dest_device_hint: 0,
        created_at: now(),
        expires_at,
        hop_limit: hop,
        replication_budget: 3,
        anti_replay_nonce: [9u8; 12],
        ratchet_header_ciphertext: vec![],
        message_ciphertext: sealed,
        sender_authentication: vec![],
    };
    env.sign_with(signer);
    env
}

/// 1. BLE→Internet (mock): C-side BLE ingress on B → LAN egress.
#[test]
fn case01_ble_to_internet_forward() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
    let a = Identity::generate();
    let c = Identity::generate();
    let mid = [1u8; 16];
    let env = make_env(&a, &c, b"hello-ac", mid, 8, now() + 60_000);
    let packed = env.pack();
    let router = MessageRouter {
        bridge_enabled: true,
        endpoint_enabled: false,
        local_has_ble: true,
        local_has_internet: true,
        ..Default::default()
    };
    match router.handle_inbound(
        &q,
        InboundEnvelope {
            packed: packed.clone(),
            ingress: TransportKind::MockBle,
            previous_hop: "device-c".into(),
            now_ms: now(),
        },
        true,
    ) {
        RouterOutcome::ForwardNow {
            packed: out,
            egress,
            identity,
        } => {
            assert_eq!(egress, TransportKind::Lan);
            assert_eq!(identity.message_id, mid);
            let fwd = Envelope::unpack(&out).unwrap();
            assert_eq!(fwd.message_id, mid);
            assert_eq!(fwd.message_ciphertext, env.message_ciphertext);
            assert!(fwd.verify(&a.public_key_bytes()));
        }
        other => panic!("case1: {other:?}"),
    }
}

/// 2. Internet→BLE reverse.
#[test]
fn case02_internet_to_ble_forward() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
    let a = Identity::generate();
    let c = Identity::generate();
    let mid = [2u8; 16];
    let env = make_env(&a, &c, b"hello-rev", mid, 8, now() + 60_000);
    let router = MessageRouter {
        bridge_enabled: true,
        endpoint_enabled: false,
        local_has_ble: true,
        local_has_internet: true,
        ..Default::default()
    };
    match router.handle_inbound(
        &q,
        InboundEnvelope {
            packed: env.pack(),
            ingress: TransportKind::Lan,
            previous_hop: "device-a".into(),
            now_ms: now(),
        },
        true,
    ) {
        RouterOutcome::ForwardNow {
            egress, identity, ..
        } => {
            assert_eq!(egress, TransportKind::MockBle);
            assert_eq!(identity.message_id, mid);
        }
        other => panic!("case2: {other:?}"),
    }
}

/// 3. No Internet then later Internet (store-carry-bridge).
#[test]
fn case03_store_carry_bridge() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("f.sqlite");
    let a = Identity::generate();
    let c = Identity::generate();
    let mid = [3u8; 16];
    let env = make_env(&a, &c, b"delayed", mid, 8, now() + 60_000);
    {
        let q = ForwardQueue::open(&path).unwrap();
        let router = MessageRouter {
            bridge_enabled: true,
            store_enabled: true,
            endpoint_enabled: false,
            local_has_ble: true,
            local_has_internet: false,
            ..Default::default()
        };
        match router.handle_inbound(
            &q,
            InboundEnvelope {
                packed: env.pack(),
                ingress: TransportKind::MockBle,
                previous_hop: "c".into(),
                now_ms: now(),
            },
            true,
        ) {
            RouterOutcome::QueuedForForward { message_id, .. } => {
                assert_eq!(message_id, mid);
            }
            other => panic!("case3 queue: {other:?}"),
        }
    }
    // Later: internet up — recover pending.
    let q = ForwardQueue::open(&path).unwrap();
    let router = MessageRouter {
        bridge_enabled: true,
        local_has_internet: true,
        local_has_ble: true,
        ..Default::default()
    };
    let pending = router.recover_pending(&q, now() + 1).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0.message_id, mid);
    assert_eq!(pending[0].0.egress, TransportKind::Lan);
}

/// 4. Dup via BLE+Internet → one delivery (second dropped).
#[test]
fn case04_dup_ble_and_internet() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
    let a = Identity::generate();
    let c = Identity::generate();
    let mid = [4u8; 16];
    let env = make_env(&a, &c, b"once", mid, 8, now() + 60_000);
    let packed = env.pack();
    let router = MessageRouter {
        bridge_enabled: true,
        endpoint_enabled: false,
        ..Default::default()
    };
    let first = router.handle_inbound(
        &q,
        InboundEnvelope {
            packed: packed.clone(),
            ingress: TransportKind::Lan,
            previous_hop: "a".into(),
            now_ms: now(),
        },
        true,
    );
    assert!(matches!(first, RouterOutcome::ForwardNow { .. }));
    let second = router.handle_inbound(
        &q,
        InboundEnvelope {
            packed,
            ingress: TransportKind::MockBle,
            previous_hop: "a-ble".into(),
            now_ms: now() + 1,
        },
        true,
    );
    assert!(matches!(
        second,
        RouterOutcome::Dropped {
            reason: DropReason::Duplicate
        }
    ));
}

/// 5. Tampered ciphertext rejected (signature fails at endpoint verify).
#[test]
fn case05_tampered_ciphertext_rejected() {
    let a = Identity::generate();
    let c = Identity::generate();
    let mid = [5u8; 16];
    let mut env = make_env(&a, &c, b"good", mid, 8, now() + 60_000);
    assert!(env.verify(&a.public_key_bytes()));
    // Flip a ciphertext byte — signing covers hash of ciphertext → verify fails.
    if let Some(b) = env.message_ciphertext.first_mut() {
        *b ^= 0xff;
    }
    assert!(
        !env.verify(&a.public_key_bytes()),
        "tampered body must fail envelope auth"
    );
}

/// 6. Replay rejected.
#[test]
fn case06_replay_rejected() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
    let a = Identity::generate();
    let c = Identity::generate();
    let mid = [6u8; 16];
    let packed = make_env(&a, &c, b"replay", mid, 8, now() + 60_000).pack();
    let router = MessageRouter {
        bridge_enabled: true,
        endpoint_enabled: false,
        ..Default::default()
    };
    let _ = router.handle_inbound(
        &q,
        InboundEnvelope {
            packed: packed.clone(),
            ingress: TransportKind::Lan,
            previous_hop: "a".into(),
            now_ms: now(),
        },
        true,
    );
    let replay = router.handle_inbound(
        &q,
        InboundEnvelope {
            packed,
            ingress: TransportKind::Lan,
            previous_hop: "a".into(),
            now_ms: now() + 5,
        },
        true,
    );
    assert!(matches!(
        replay,
        RouterOutcome::Dropped {
            reason: DropReason::Duplicate
        }
    ));
}

/// 7. Crash after receive → queue recovers.
#[test]
fn case07_crash_recover_queue() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("f.sqlite");
    let a = Identity::generate();
    let c = Identity::generate();
    let mid = [7u8; 16];
    let packed = make_env(&a, &c, b"custody", mid, 8, now() + 60_000).pack();
    {
        let q = ForwardQueue::open(&path).unwrap();
        let env = Envelope::unpack(&packed).unwrap();
        q.enqueue(&ForwardItem {
            object_digest: authenticated_object_digest(&env),
            message_id: mid,
            packed_envelope: packed.clone(),
            ingress: TransportKind::MockBle,
            egress: TransportKind::Lan,
            state: ForwardState::Queued,
            created_at_ms: now(),
            expires_at_ms: now() + 60_000,
            previous_hop: "c".into(),
        })
        .unwrap();
    }
    // Simulate process restart.
    let q = ForwardQueue::open(&path).unwrap();
    let router = MessageRouter::default();
    let recovered = router.recover_pending(&q, now() + 10).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].0.packed_envelope, packed);
    assert_eq!(recovered[0].1.message_id, mid);
}

/// 8. Expired while offline → never forward after expiry.
#[test]
fn case08_expired_never_forward() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("f.sqlite");
    let a = Identity::generate();
    let c = Identity::generate();
    let mid = [8u8; 16];
    let expires = now() + 100;
    let packed = make_env(&a, &c, b"stale", mid, 8, expires).pack();
    {
        let q = ForwardQueue::open(&path).unwrap();
        let router = MessageRouter {
            bridge_enabled: true,
            store_enabled: true,
            endpoint_enabled: false,
            local_has_internet: false,
            local_has_ble: true,
            ..Default::default()
        };
        let _ = router.handle_inbound(
            &q,
            InboundEnvelope {
                packed,
                ingress: TransportKind::MockBle,
                previous_hop: "c".into(),
                now_ms: now(),
            },
            true,
        );
        assert_eq!(q.count_pending().unwrap(), 1);
    }
    let q = ForwardQueue::open(&path).unwrap();
    let router = MessageRouter {
        local_has_internet: true,
        ..Default::default()
    };
    let after_expiry = expires + 1;
    let recovered = router.recover_pending(&q, after_expiry).unwrap();
    assert!(recovered.is_empty(), "expired must not forward");
    let item = q.get(&mid).unwrap().unwrap();
    assert_eq!(item.state, ForwardState::Expired);
}

/// Endpoint can still unseal A↔C after bridge hop (E2EE preserved).
#[test]
fn e2ee_survives_bridge_hop() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
    let a = Identity::generate();
    let c = Identity::generate();
    let mid = [99u8; 16];
    let env = make_env(&a, &c, b"secret-e2ee", mid, 8, now() + 60_000);
    let body_before = env.message_ciphertext.clone();
    let router = MessageRouter {
        bridge_enabled: true,
        endpoint_enabled: false,
        ..Default::default()
    };
    let out = match router.handle_inbound(
        &q,
        InboundEnvelope {
            packed: env.pack(),
            ingress: TransportKind::Lan,
            previous_hop: "a".into(),
            now_ms: now(),
        },
        true,
    ) {
        RouterOutcome::ForwardNow { packed, .. } => packed,
        other => panic!("{other:?}"),
    };
    let fwd = Envelope::unpack(&out).unwrap();
    assert_eq!(fwd.message_ciphertext, body_before);
    let pt = open_indexed_message_with_key(
        &BRIDGE_TEST_ROOT,
        &a.address(),
        &c.address(),
        Direction::InitiatorToResponder,
        &mid,
        &fwd.message_ciphertext,
    )
    .unwrap();
    assert_eq!(pt, b"secret-e2ee");
}

/// 9. Per-peer rate limit drops flood from one hop; other peers still forward.
#[test]
fn case09_per_peer_rate_limit() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open_with_peer_limits(
        &dir.path().join("f.sqlite"),
        512,
        1_048_576,
        64,
        2, // only 2 enqueues / window from same peer
        256_000,
        60_000,
    )
    .unwrap();
    let a = Identity::generate();
    let c = Identity::generate();
    let router = MessageRouter {
        bridge_enabled: true,
        endpoint_enabled: false,
        local_has_ble: true,
        local_has_internet: true,
        ..Default::default()
    };
    let mut outcomes = Vec::new();
    for i in 0u8..3 {
        let mut mid = [10u8; 16];
        mid[15] = i;
        let packed = make_env(&a, &c, b"flood", mid, 8, now() + 60_000).pack();
        outcomes.push(router.handle_inbound(
            &q,
            InboundEnvelope {
                packed,
                ingress: TransportKind::Lan,
                previous_hop: "noisy-peer".into(),
                now_ms: now() + i as u64,
            },
            true,
        ));
    }
    assert!(matches!(outcomes[0], RouterOutcome::ForwardNow { .. }));
    assert!(matches!(outcomes[1], RouterOutcome::ForwardNow { .. }));
    assert!(matches!(
        outcomes[2],
        RouterOutcome::Dropped {
            reason: DropReason::RateLimited
        }
    ));
    // Different peer still accepted.
    let mid = [11u8; 16];
    let packed = make_env(&a, &c, b"other", mid, 8, now() + 60_000).pack();
    match router.handle_inbound(
        &q,
        InboundEnvelope {
            packed,
            ingress: TransportKind::Lan,
            previous_hop: "quiet-peer".into(),
            now_ms: now() + 10,
        },
        true,
    ) {
        RouterOutcome::ForwardNow { .. } => {}
        other => panic!("quiet peer should forward: {other:?}"),
    }
}

fn make_ack(signer: &Identity, recipient: &Identity, acked_message_id: [u8; 16]) -> Envelope {
    let ack = Ack {
        acked_message_id,
        status: STATUS_DELIVERED,
        ack_nonce: [0x11u8; 12],
        created_at: now(),
    };
    let mut plaintext = ack.signing_bytes()[b"rvn1/ack".len()..].to_vec();
    plaintext.extend_from_slice(&ack.sign(signer));
    let mut mid = [0xACu8; 16];
    mid[0] = acked_message_id[0];
    let body = seal_indexed_message_with_key(
        &BRIDGE_TEST_ROOT,
        &signer.address(),
        &recipient.address(),
        Direction::InitiatorToResponder,
        0,
        &mid,
        &plaintext,
        &[0x33u8; 12],
    )
    .unwrap();
    assert_eq!(
        body.len(),
        raven_core::atsam_indexed_session::ACK_SEALED_WIRE_LEN
    );
    let mut env = Envelope {
        env_type: EnvType::Ack as u8,
        flags: 0,
        message_id: mid,
        routing_tag: [8u8; 16],
        dest_device_hint: 0,
        created_at: now(),
        expires_at: now() + 60_000,
        hop_limit: 8,
        replication_budget: 1,
        anti_replay_nonce: [4u8; 12],
        ratchet_header_ciphertext: vec![],
        message_ciphertext: body,
        sender_authentication: vec![],
    };
    env.sign_with(signer);
    env
}

/// 10. Recipient ACK reverse: BLE→LAN on B; sealed body stays opaque and
///
/// Byte-preserved. The relay never parses `acked_message_id`.
#[test]
fn case10_ack_reverse_relay_opaque() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
    let a = Identity::generate();
    let c = Identity::generate();
    let acked = [0x10u8; 16];
    let ack = make_ack(&c, &a, acked);
    let packed = ack.pack();
    assert!(!ack
        .message_ciphertext
        .windows(acked.len())
        .any(|window| window == acked));

    let router = MessageRouter {
        bridge_enabled: true,
        endpoint_enabled: false,
        local_has_ble: true,
        local_has_internet: true,
        ..Default::default()
    };
    match router.handle_inbound(
        &q,
        InboundEnvelope {
            packed: packed.clone(),
            ingress: TransportKind::MockBle,
            previous_hop: "device-c".into(),
            now_ms: now(),
        },
        true,
    ) {
        RouterOutcome::ForwardNow {
            packed: out,
            egress,
            identity,
        } => {
            assert_eq!(egress, TransportKind::Lan);
            assert_eq!(identity.message_id, ack.message_id);
            let fwd = Envelope::unpack(&out).unwrap();
            assert_eq!(fwd.env_type, EnvType::Ack as u8);
            assert_eq!(fwd.message_ciphertext, ack.message_ciphertext);
            assert!(fwd.verify(&c.public_key_bytes()));
            let opened = open_indexed_message_with_key(
                &BRIDGE_TEST_ROOT,
                &c.address(),
                &a.address(),
                Direction::InitiatorToResponder,
                &fwd.message_id,
                &fwd.message_ciphertext,
            )
            .unwrap();
            assert_eq!(&opened[..16], &acked);
            assert_eq!(opened[16], STATUS_DELIVERED);
        }
        other => panic!("case10: {other:?}"),
    }
}

/// Destination ingest: when local is endpoint (not forced bridge), DeliverToEndpoint.
#[test]
fn case10b_destination_deliver_to_endpoint() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
    let a = Identity::generate();
    let c = Identity::generate();
    let mid = [0xCCu8; 16];
    let env = make_env(&a, &c, b"for-c", mid, 8, now() + 60_000);
    let router = MessageRouter {
        bridge_enabled: false,
        endpoint_enabled: true,
        ..Default::default()
    };
    match router.handle_inbound(
        &q,
        InboundEnvelope {
            packed: env.pack(),
            ingress: TransportKind::MockBle,
            previous_hop: "b".into(),
            now_ms: now(),
        },
        false,
    ) {
        RouterOutcome::DeliverToEndpoint { identity, packed } => {
            assert_eq!(identity.message_id, mid);
            let got = Envelope::unpack(&packed).unwrap();
            assert_eq!(got.message_ciphertext, env.message_ciphertext);
        }
        other => panic!("case10b: {other:?}"),
    }
}

fn relay_router() -> MessageRouter {
    MessageRouter {
        bridge_enabled: true,
        endpoint_enabled: false,
        local_has_ble: true,
        local_has_internet: true,
        ..Default::default()
    }
}

fn inbound(packed: Vec<u8>, hop: &str, now_ms: u64) -> InboundEnvelope {
    InboundEnvelope {
        packed,
        ingress: TransportKind::Lan,
        previous_hop: hop.into(),
        now_ms,
    }
}

/// 11. Replay after seen-cache eviction is still a duplicate.
///
/// The forward tombstone outlives the bounded seen cache, so the row is
/// never resurrected (no INSERT OR REPLACE back to Queued).
#[test]
fn case11_replay_after_seen_eviction_is_duplicate() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
    let a = Identity::generate();
    let c = Identity::generate();
    let packed = make_env(&a, &c, b"once-only", [0x11; 16], 8, now() + 60_000).pack();
    let router = relay_router();
    let identity = match router.handle_inbound(&q, inbound(packed.clone(), "a", now()), true) {
        RouterOutcome::ForwardNow { identity, .. } => identity,
        other => panic!("case11 first: {other:?}"),
    };
    q.mark_object_state(&identity.object_digest, ForwardState::Forwarded)
        .unwrap();

    // Attacker floods fresh digests until the original is evicted.
    for i in 0..=MAX_RELAY_SEEN_OBJECTS {
        let mut d = [0u8; 32];
        d[..8].copy_from_slice(&(i as u64).to_be_bytes());
        d[31] = 0xEE;
        q.mark_object_seen(&d, now() + 1 + i as u64, TransportKind::Lan, "flood")
            .unwrap();
    }
    assert!(!q.object_was_seen(&identity.object_digest).unwrap());

    let replay = router.handle_inbound(&q, inbound(packed, "a2", now() + 10_000), true);
    assert!(
        matches!(
            replay,
            RouterOutcome::Dropped {
                reason: DropReason::Duplicate
            }
        ),
        "case11 replay: {replay:?}"
    );
    assert_eq!(
        q.get_object(&identity.object_digest)
            .unwrap()
            .unwrap()
            .state,
        ForwardState::Forwarded
    );
    assert_eq!(q.count_pending().unwrap(), 0);
}

/// 12. Full relay custody is reported as STORE_FULL, not Malformed.
#[test]
fn case12_queue_full_reports_store_full() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open_with_limits(&dir.path().join("f.sqlite"), 1, MAX_ENVELOPE_BYTES)
        .unwrap();
    let a = Identity::generate();
    let c = Identity::generate();
    let router = relay_router();
    let first = make_env(&a, &c, b"first", [0x12; 16], 8, now() + 60_000).pack();
    assert!(matches!(
        router.handle_inbound(&q, inbound(first, "a", now()), true),
        RouterOutcome::ForwardNow { .. }
    ));
    let second = make_env(&a, &c, b"second", [0x13; 16], 8, now() + 60_000).pack();
    let out = router.handle_inbound(&q, inbound(second, "b", now()), true);
    assert!(
        matches!(
            out,
            RouterOutcome::Dropped {
                reason: DropReason::StoreFull
            }
        ),
        "case12: {out:?}"
    );
}

/// 13. Relay custody is capped at MAX_FORWARD_TTL_MS.
///
/// A far-future envelope expiry cannot squat a pending slot forever: the
/// custody allow-list refuses validity beyond 24 h (+ skew) outright, and the
/// queue itself still clamps any row (defence in depth for other writers).
#[test]
fn case13_relay_custody_ttl_is_clamped() {
    use raven_core::carrier_admission::CustodyRefusal;
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
    let a = Identity::generate();
    let c = Identity::generate();
    let mid = [0x14; 16];
    let far = now() + 365 * 24 * 60 * 60 * 1_000;
    let env = make_env(&a, &c, b"long-lived", mid, 8, far);
    let packed = env.pack();
    let router = MessageRouter {
        local_has_internet: false,
        ..relay_router()
    };
    assert_eq!(
        router.handle_inbound(
            &q,
            InboundEnvelope {
                packed: packed.clone(),
                ingress: TransportKind::MockBle,
                previous_hop: "c".into(),
                now_ms: now(),
            },
            true
        ),
        RouterOutcome::Dropped {
            reason: DropReason::NotAdmitted(CustodyRefusal::ValidityTooLong)
        }
    );
    assert_eq!(q.count_all().unwrap(), 0);
    // A writer that bypasses the router still gets a clamped row.
    q.enqueue(&ForwardItem {
        object_digest: authenticated_object_digest(&env),
        message_id: mid,
        packed_envelope: packed,
        ingress: TransportKind::MockBle,
        egress: TransportKind::Lan,
        state: ForwardState::Queued,
        created_at_ms: now(),
        expires_at_ms: far,
        previous_hop: "c".into(),
    })
    .unwrap();
    let row = q.get(&mid).unwrap().unwrap();
    assert_eq!(row.expires_at_ms, now() + MAX_FORWARD_TTL_MS);
    let later = now() + MAX_FORWARD_TTL_MS + 1;
    assert!(router.recover_pending(&q, later).unwrap().is_empty());
    assert_ne!(q.get(&mid).unwrap().unwrap().state, ForwardState::Queued);
    q.maintain(later).unwrap();
    assert_eq!(q.count_pending().unwrap(), 0);
}

/// 14. Forwarded relay rows keep no ciphertext and are garbage-collected.
#[test]
fn case14_forwarded_rows_are_garbage_collected() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
    let a = Identity::generate();
    let c = Identity::generate();
    let router = relay_router();
    for i in 0u8..5 {
        let packed = make_env(&a, &c, b"relay", [0x20 + i; 16], 8, now() + 60_000).pack();
        match router.handle_inbound(&q, inbound(packed, "a", now() + i as u64), true) {
            RouterOutcome::ForwardNow { identity, .. } => {
                q.mark_object_state(&identity.object_digest, ForwardState::Forwarded)
                    .unwrap();
                let row = q.get_object(&identity.object_digest).unwrap().unwrap();
                assert!(row.packed_envelope.is_empty());
            }
            other => panic!("case14: {other:?}"),
        }
    }
    assert_eq!(q.count_pending().unwrap(), 0);
    assert_eq!(q.count_all().unwrap(), 5);
    q.maintain(now() + 60_001).unwrap();
    assert_eq!(q.count_all().unwrap(), 0);
}

/// 15. A replay after the custody period is never re-forwarded.
///
/// Far-future objects are refused at admission (case 13), so the longest an
/// object can live is 24 h: a replay after the custody period arrives
/// expired, and the Forwarded tombstone covers it until then.
#[test]
fn case15_far_future_replay_after_custody_is_duplicate() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
    let a = Identity::generate();
    let c = Identity::generate();
    let day = now() + 24 * 60 * 60 * 1_000;
    let packed = make_env(&a, &c, b"long-lived", [0x15; 16], 8, day).pack();
    let router = relay_router();
    let identity = match router.handle_inbound(&q, inbound(packed.clone(), "a", now()), true) {
        RouterOutcome::ForwardNow { identity, .. } => identity,
        other => panic!("case15 first: {other:?}"),
    };
    q.mark_object_state(&identity.object_digest, ForwardState::Forwarded)
        .unwrap();

    // Before its expiry the tombstone makes a replay a duplicate, even once
    // the bounded seen cache forgot the object.
    let soon = now() + 60 * 60 * 1_000;
    q.prune_seen_objects(soon + MAX_FORWARD_TTL_MS).unwrap();
    let replay = router.handle_inbound(&q, inbound(packed.clone(), "a2", soon), true);
    assert!(
        matches!(
            replay,
            RouterOutcome::Dropped {
                reason: DropReason::Duplicate
            }
        ),
        "case15 replay: {replay:?}"
    );
    // After the custody period the object itself has expired.
    let later = now() + MAX_FORWARD_TTL_MS + 1;
    q.maintain(later).unwrap();
    let replay = router.handle_inbound(&q, inbound(packed, "a3", later), true);
    assert!(
        matches!(
            replay,
            RouterOutcome::Dropped {
                reason: DropReason::Expired
            }
        ),
        "case15 late replay: {replay:?}"
    );
    assert_eq!(q.count_pending().unwrap(), 0);
    q.maintain(day + 1).unwrap();
    assert_eq!(q.count_all().unwrap(), 0);
}

/// 16. Alias-gossip (3) and capabilities (4) envelopes are not relayable.
///
/// `bridge::decide`, `classify_multi_role` and `MessageRouter::handle_inbound`
/// share one policy (`is_relayable_type`): only Message and Ack are carried.
/// The router must also leave no seen-state or custody row behind.
#[test]
fn case16_non_message_ack_types_are_dropped_by_every_entry_point() {
    use raven_core::bridge::{
        classify_multi_role, decide, is_relayable_type, BridgeAction, BridgeRole,
        MultiRoleDisposition,
    };

    assert!(is_relayable_type(EnvType::Message as u8));
    assert!(is_relayable_type(EnvType::Ack as u8));
    let a = Identity::generate();
    let c = Identity::generate();
    for env_type in [EnvType::AliasGossip, EnvType::Capabilities] {
        let ty = env_type as u8;
        assert!(!is_relayable_type(ty));
        let mut env = make_env(&a, &c, b"gossip", [0x16; 16], 8, now() + 60_000);
        env.env_type = ty;
        env.sign_with(&a);
        let packed = env.pack();
        let digest = authenticated_object_digest(&Envelope::unpack(&packed).unwrap());

        for role in [BridgeRole::Relay, BridgeRole::Endpoint] {
            assert_eq!(
                decide(&packed, role, now(), false),
                BridgeAction::Drop {
                    reason: DropReason::UnsupportedType
                },
                "decide type {ty} {role:?}"
            );
        }
        for (local_is_destination, bridge_enabled) in
            [(true, true), (true, false), (false, true), (false, false)]
        {
            assert_eq!(
                classify_multi_role(ty, local_is_destination, bridge_enabled),
                MultiRoleDisposition::Drop,
                "classify type {ty}"
            );
        }

        let relay = relay_router();
        let endpoint_only = MessageRouter {
            bridge_enabled: false,
            endpoint_enabled: true,
            ..Default::default()
        };
        for (router, force_bridge) in [(&relay, true), (&relay, false), (&endpoint_only, false)] {
            let dir = tempdir().unwrap();
            let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
            let out = router.handle_inbound(&q, inbound(packed.clone(), "p", now()), force_bridge);
            assert!(
                matches!(
                    out,
                    RouterOutcome::Dropped {
                        reason: DropReason::UnsupportedType
                    }
                ),
                "router type {ty} force={force_bridge}: {out:?}"
            );
            assert_eq!(q.count_all().unwrap(), 0);
            assert!(!q.object_was_seen(&digest).unwrap());
        }
    }
}
