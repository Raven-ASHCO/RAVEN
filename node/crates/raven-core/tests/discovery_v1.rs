//! Discovery V1 acceptance tests (research §22).
//!
//! Multi-lane search / contact request without central Raven DB.

use raven_core::alias_record::{AliasClaimStore, AliasPublishQuota, AliasRecord};
use raven_core::bootstrap::BootstrapConfig;
use raven_core::chat_history::BlockList;
use raven_core::contact_request::{
    ContactAcceptV1, ContactRequestInbox, ContactRequestInner, RavenContactRequestV1,
    CONTACT_REQ_MAX_PER_SENDER, CONTACT_REQ_SESSION_REQUIRED,
};
use raven_core::discovery_resolver::{
    result_model_schema_keys, DiscoveryContext, DiscoveryResolver, DiscoveryScope, DiscoverySource,
    LocalContactRow, VerificationState,
};
use raven_core::envelope::{EnvType, Envelope};
use raven_core::forward_queue::ForwardQueue;
use raven_core::identity::Identity;
use raven_core::introduction::{IntroductionInbox, RavenIntroductionV1, INTRO_SESSION_REQUIRED};
use raven_core::message_router::{InboundEnvelope, MessageRouter, RouterOutcome};
use raven_core::messaging_path::{assert_no_silent_fastapi, resolve_terminal_messaging_path};
use raven_core::nearby::{NearbyAdvertisement, NearbyRegistry};
use raven_core::profile_record::{ProfileStore, RavenProfileRecordV1};
use raven_core::seal::{classify_sealed_body, SealClass};
use raven_core::transport::TransportKind;
use tempfile::tempdir;

/// Authenticated session root supplied by the test harness. Tests exercise
/// shipping RVNA1 v2 AEAD; public identity keys are never treated as secrets.
const DISCOVERY_TEST_ROOT: [u8; 32] = [0x5D; 32];

fn now() -> u64 {
    1_700_000_000_000
}

fn make_contact_request(
    sender: &Identity,
    recipient: &Identity,
    inner: ContactRequestInner,
) -> RavenContactRequestV1 {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&inner.request_id[..12]);
    RavenContactRequestV1::create_with_atsam_root(
        sender,
        &recipient.public_key_bytes(),
        &recipient.address(),
        inner,
        &DISCOVERY_TEST_ROOT,
        0,
        &nonce,
    )
    .unwrap()
}

/// Product-level contact and introduction APIs never fall back to the
/// publicly-derivable demo cipher, even in a debug build or when the low-level
/// compatibility feature is explicitly enabled.
#[test]
fn rootless_contact_and_introduction_apis_fail_closed() {
    let sender = Identity::from_seed(&[0x21; 32]);
    let recipient = Identity::from_seed(&[0x42; 32]);
    let inner = ContactRequestInner {
        request_id: [0xA5; 16],
        sender_raven_id: sender.address(),
        sender_display_name: "Ada".into(),
        sender_aliases: vec!["ada".into()],
        sender_profile_digest: [0u8; 32],
        optional_message: "private".into(),
        created_at: now(),
        expires_at: now() + 60_000,
    };
    let err = RavenContactRequestV1::create(
        &sender,
        &recipient.public_key_bytes(),
        &recipient.address(),
        inner,
    )
    .unwrap_err();
    assert_eq!(err, CONTACT_REQ_SESSION_REQUIRED);

    let err = RavenIntroductionV1::seal_note(
        &sender,
        &recipient.public_key_bytes(),
        &recipient.address(),
        b"private introduction",
        &[0xC3; 16],
    )
    .unwrap_err();
    assert_eq!(err, INTRO_SESSION_REQUIRED);

    let mut spoofed_intro = RavenIntroductionV1 {
        intro_id: [0xC4; 16],
        introducer_raven_id: recipient.address(),
        subject_raven_id: "subject".into(),
        recipient_raven_id: recipient.address(),
        subject_display_name: "Subject".into(),
        subject_aliases: vec![],
        created_at: now(),
        expires_at: now() + 60_000,
        note_ciphertext: vec![1],
        signature: [0u8; 64],
        introducer_pub: sender.public_key_bytes(),
    };
    spoofed_intro.signature = sender.sign(&spoofed_intro.signing_bytes().unwrap());
    assert_eq!(
        spoofed_intro.verify(now()).unwrap_err(),
        "INTRO_IDENTITY_OR_TIME_MISMATCH"
    );
}

#[test]
fn contact_root_codec_rejects_unbound_or_oversized_inner_fields() {
    let sender = Identity::from_seed(&[0x31; 32]);
    let recipient = Identity::from_seed(&[0x32; 32]);
    let base = ContactRequestInner {
        request_id: [0xB5; 16],
        sender_raven_id: recipient.address(),
        sender_display_name: "Ada".into(),
        sender_aliases: vec![],
        sender_profile_digest: [0u8; 32],
        optional_message: "private".into(),
        created_at: now(),
        expires_at: now() + 60_000,
    };
    let err = RavenContactRequestV1::create_with_atsam_root(
        &sender,
        &recipient.public_key_bytes(),
        &recipient.address(),
        base.clone(),
        &DISCOVERY_TEST_ROOT,
        0,
        &[0x55; 12],
    )
    .unwrap_err();
    assert_eq!(err, "CONTACT_REQ_SENDER_ID_MISMATCH");

    let mut oversized = base;
    oversized.sender_raven_id = sender.address();
    oversized.sender_aliases = vec![String::new(); usize::from(u16::MAX) + 1];
    let err = oversized.encode().unwrap_err();
    assert!(err.contains("too many contact request aliases"));
}

/// Fixed Rust/Swift RVNA1-v2 contact-request ciphertext vector. This covers
/// address encoding, contact-inner canonical bytes, chain KDF, AAD, nonce,
/// ciphertext, and tag without activating product session state.
#[test]
fn contact_request_atsam_root_fixed_vector() {
    let sender = Identity::from_seed(&[0x11; 32]);
    let recipient = Identity::from_seed(&[0x22; 32]);
    let mut request_id = [0u8; 16];
    for (i, byte) in request_id.iter_mut().enumerate() {
        *byte = (i + 1) as u8;
    }
    let req = RavenContactRequestV1::create_with_atsam_root(
        &sender,
        &recipient.public_key_bytes(),
        &recipient.address(),
        ContactRequestInner {
            request_id,
            sender_raven_id: sender.address(),
            sender_display_name: "Ada".into(),
            sender_aliases: vec!["ada".into()],
            sender_profile_digest: [0u8; 32],
            optional_message: "hello".into(),
            created_at: now(),
            expires_at: now() + 86_400_000,
        },
        &DISCOVERY_TEST_ROOT,
        7,
        &[0xA7; 12],
    )
    .unwrap();
    assert_eq!(
        hex::encode(req.ciphertext),
        "52564e4131000000020100000007a7a7a7a7a7a7a7a7a7a7a7a7280fecc70f23af7bcdb9ec51dab82dc364a5b2bf6d8a59daf128f9336594e7710ac2ab955cbeffe1ac435960df222d290fab8eccd38d30b6a162de4f1dbf9edbd49844423e00485180c9e58261cff86a85a015c6b8bf0bd10262c7f3e0e997368e6ed855aacc299921837baa83db0347e53dae544dd8c21488fa0cd46bb9cd213ec759fe36ee5b6219647ddfaf5710f6def129b810464833034274f7c4f5dba7f76cded7f8b215"
    );
}

fn make_profile(
    id: &Identity,
    display: &str,
    aliases: &[&str],
    seq: u64,
    exp: u64,
) -> RavenProfileRecordV1 {
    RavenProfileRecordV1 {
        version: 1,
        raven_id: String::new(),
        display_name: display.into(),
        public_aliases: aliases.iter().map(|s| s.to_string()).collect(),
        profile_image_digest: [0u8; 32],
        device_set_commitment: [3u8; 32],
        prekey_bundle_reference: [4u8; 32],
        sequence: seq,
        issued_at: now(),
        expires_at: exp,
        visibility: 0,
        signature: [0u8; 64],
        ed25519_pub: [0u8; 32],
    }
    .sign(id)
    .unwrap()
}

fn make_alias(id: &Identity, alias: &str, seq: u64, exp: u64) -> AliasRecord {
    AliasRecord {
        alias: alias.into(),
        identity_address: String::new(),
        sequence: seq,
        expires_at: exp,
        signature: [0u8; 64],
        ed25519_pub: [0u8; 32],
    }
    .sign(id)
    .unwrap()
}

fn pack_contact_req_env(sender: &Identity, req: &RavenContactRequestV1) -> Envelope {
    let wire = req.encode_wire().expect("wire");
    let mut env = Envelope {
        env_type: EnvType::Message as u8,
        flags: 0,
        message_id: req.request_id,
        routing_tag: [7u8; 16],
        dest_device_hint: 0,
        created_at: now(),
        expires_at: req.expires_at,
        hop_limit: 8,
        replication_budget: 3,
        anti_replay_nonce: [9u8; 12],
        ratchet_header_ciphertext: vec![],
        message_ciphertext: wire,
        sender_authentication: vec![],
    };
    env.sign_with(sender);
    env
}

/// 1 Exact Raven ID search with no FastAPI
#[test]
fn a01_exact_raven_id_no_fastapi() {
    let path = resolve_terminal_messaging_path();
    assert_no_silent_fastapi(path).unwrap();
    assert!(!path.as_diag_label().contains("fastapi"));

    let id = Identity::generate();
    let mut ctx = DiscoveryContext {
        serverless: true,
        now_ms: now(),
        ..Default::default()
    };
    ctx.profiles
        .put(
            make_profile(&id, "Poline", &["poline"], 1, now() + 60_000),
            now(),
        )
        .unwrap();

    let resolver = DiscoveryResolver::v1();
    let hits = resolver.search(&id.address(), DiscoveryScope::ExactId, &ctx);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].raven_id, id.address());
    assert!(hits[0].source_set.contains(&DiscoverySource::ExactRavenId));
    assert_eq!(
        hits[0].verification_state,
        VerificationState::PublicSignedProfile
    );
}

/// 2 Exact alias via local/signed records (community/manual peers)
#[test]
fn a02_exact_alias_signed_records() {
    let id = Identity::generate();
    let mut ctx = DiscoveryContext {
        serverless: true,
        now_ms: now(),
        ..Default::default()
    };
    ctx.aliases
        .put(make_alias(&id, "poline", 1, now() + 60_000), now())
        .unwrap();
    ctx.profiles
        .put(
            make_profile(&id, "Poline", &["poline"], 1, now() + 60_000),
            now(),
        )
        .unwrap();

    let hits = DiscoveryResolver::v1().search("@poline", DiscoveryScope::ExactAlias, &ctx);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].raven_id, id.address());
    assert!(hits[0].aliases.iter().any(|a| a == "poline"));
}

/// 3 Alias partition conflict displays both
#[test]
fn a03_alias_partition_conflict_both() {
    let a = Identity::generate();
    let b = Identity::generate();
    let mut ctx = DiscoveryContext {
        now_ms: now(),
        ..Default::default()
    };
    ctx.aliases
        .put(make_alias(&a, "alex", 1, now() + 60_000), now())
        .unwrap();
    ctx.aliases
        .put(make_alias(&b, "alex", 1, now() + 60_000), now())
        .unwrap();

    let hits = DiscoveryResolver::v1().search("@alex", DiscoveryScope::ExactAlias, &ctx);
    assert_eq!(hits.len(), 2);
    assert!(hits
        .iter()
        .all(|h| h.verification_state == VerificationState::AliasConflict));
    assert!(hits.iter().all(|h| h.conflict_count >= 2));
    let ids: std::collections::HashSet<_> = hits.iter().map(|h| h.raven_id.clone()).collect();
    assert_eq!(ids.len(), 2);
}

/// 4 Forged alias signature rejected
#[test]
fn a04_forged_alias_rejected() {
    let id = Identity::generate();
    let mut rec = make_alias(&id, "poline", 1, now() + 60_000);
    rec.signature[0] ^= 0xff;
    let mut store = AliasClaimStore::default();
    assert!(store.put(rec, now()).is_err());
}

/// 5 Old sequence replay rejected
#[test]
fn a05_old_sequence_replay_rejected() {
    let id = Identity::generate();
    let mut store = AliasClaimStore::default();
    store
        .put(make_alias(&id, "poline", 42, now() + 60_000), now())
        .unwrap();
    let err = store
        .put(make_alias(&id, "poline", 41, now() + 60_000), now())
        .unwrap_err();
    assert!(err.contains("STALE"));
}

/// 6 Expired profile not current
#[test]
fn a06_expired_profile_not_current() {
    let id = Identity::generate();
    let mut store = ProfileStore::default();
    store
        .put(make_profile(&id, "X", &[], 1, now() + 10), now())
        .unwrap();
    assert!(store.get(&id.address(), now() + 5).is_some());
    assert!(store.get(&id.address(), now() + 11).is_none());

    let ctx = DiscoveryContext {
        now_ms: now() + 11,
        profiles: store,
        ..Default::default()
    };
    // Raw expired still in map but resolver ExactId without live profile returns empty-ish candidate
    // or no PublicSignedProfile with digest — ensure get path treats expired absent.
    assert!(ctx.profiles.get(&id.address(), ctx.now_ms).is_none());
}

/// 7 Alias change doesn't change contact raven_id binding
#[test]
fn a07_alias_change_keeps_raven_id_binding() {
    let id = Identity::generate();
    let mut contacts = vec![LocalContactRow {
        raven_id: id.address(),
        pub_hex: hex::encode(id.public_key_bytes()),
        petname: "Poline Uni".into(),
        public_tag: "poline".into(),
        display_name: "Poline".into(),
        pinned: true,
        directly_verified: true,
    }];
    // Alias rotates
    contacts[0].public_tag = "poline_new".into();
    assert_eq!(contacts[0].raven_id, id.address());
    let mut ctx = DiscoveryContext {
        contacts,
        now_ms: now(),
        ..Default::default()
    };
    ctx.aliases
        .put(make_alias(&id, "poline_new", 2, now() + 60_000), now())
        .unwrap();
    let hits = DiscoveryResolver::v1().search("@poline_new", DiscoveryScope::All, &ctx);
    assert!(hits.iter().any(|h| h.raven_id == id.address()));
}

/// 8 QR/add without internet (local)
#[test]
fn a08_qr_add_without_internet() {
    let id = Identity::generate();
    let ctx = DiscoveryContext {
        serverless: true,
        now_ms: now(),
        contacts: vec![LocalContactRow {
            raven_id: id.address(),
            pub_hex: hex::encode(id.public_key_bytes()),
            petname: "QR Friend".into(),
            public_tag: String::new(),
            display_name: String::new(),
            pinned: true,
            directly_verified: true,
        }],
        ..Default::default()
    };
    // No profiles / aliases / bootstrap needed
    let hits = DiscoveryResolver::v1().search(&id.address(), DiscoveryScope::Local, &ctx);
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].verification_state,
        VerificationState::DirectlyVerified
    );
}

/// 9 Nearby ephemeral pairing mock (no permanent ID in adv)
#[test]
fn a09_nearby_ephemeral_no_permanent_id() {
    let mut near = NearbyRegistry::default();
    let adv = NearbyAdvertisement::mint(now(), 30_000, b"confirm-secret");
    assert!(!adv.contains_permanent_raven_id());
    near.publish_ephemeral(adv.clone()).unwrap();
    assert_eq!(near.scan_live(now()).len(), 1);

    let peer = Identity::generate();
    near.confirm(
        adv.ephemeral_token,
        peer.address(),
        peer.public_key_bytes(),
        now(),
    );
    let ctx = DiscoveryContext {
        nearby: near,
        now_ms: now(),
        ..Default::default()
    };
    let hits = DiscoveryResolver::v1().search("", DiscoveryScope::Nearby, &ctx);
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].verification_state,
        VerificationState::NearbyVerified
    );
}

/// 10 Contact request while recipient offline (store)
#[test]
fn a10_contact_request_offline_store() {
    let dir = tempdir().unwrap();
    let sender = Identity::generate();
    let recipient = Identity::generate();
    let req = make_contact_request(
        &sender,
        &recipient,
        ContactRequestInner {
            request_id: [10u8; 16],
            sender_raven_id: sender.address(),
            sender_display_name: "A".into(),
            sender_aliases: vec!["ahmad".into()],
            sender_profile_digest: [0u8; 32],
            optional_message: "hi".into(),
            created_at: now(),
            expires_at: now() + 60_000,
        },
    );
    let env = pack_contact_req_env(&sender, &req);
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
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
            previous_hop: "phone".into(),
            now_ms: now(),
        },
        true,
    ) {
        RouterOutcome::QueuedForForward { message_id, .. } => {
            assert_eq!(message_id, [10u8; 16]);
        }
        other => panic!("expected store queue: {other:?}"),
    }
}

/// 11 Ciphertext-only store
#[test]
fn a11_ciphertext_only_store() {
    let sender = Identity::generate();
    let recipient = Identity::generate();
    let req = make_contact_request(
        &sender,
        &recipient,
        ContactRequestInner {
            request_id: [11u8; 16],
            sender_raven_id: sender.address(),
            sender_display_name: "A".into(),
            sender_aliases: vec![],
            sender_profile_digest: [0u8; 32],
            optional_message: "secret note".into(),
            created_at: now(),
            expires_at: now() + 60_000,
        },
    );
    assert!(req.is_ciphertext_only());
    let ct = String::from_utf8_lossy(&req.ciphertext);
    assert!(!ct.contains("secret note"));
    assert!(!ct.contains("rvn1/contact-req-inner"));
}

/// 12 BLE→Bridge→Internet path for contact request
#[test]
fn a12_ble_bridge_internet_contact_request() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
    let sender = Identity::generate();
    let recipient = Identity::generate();
    let req = make_contact_request(
        &sender,
        &recipient,
        ContactRequestInner {
            request_id: [12u8; 16],
            sender_raven_id: sender.address(),
            sender_display_name: "A".into(),
            sender_aliases: vec![],
            sender_profile_digest: [0u8; 32],
            optional_message: "via bridge".into(),
            created_at: now(),
            expires_at: now() + 60_000,
        },
    );
    let env = pack_contact_req_env(&sender, &req);
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
            ingress: TransportKind::MockBle,
            previous_hop: "ble-peer".into(),
            now_ms: now(),
        },
        true,
    ) {
        RouterOutcome::ForwardNow {
            packed,
            egress,
            identity,
        } => {
            assert_eq!(egress, TransportKind::Lan);
            assert_eq!(identity.message_id, [12u8; 16]);
            let fwd = Envelope::unpack(&packed).unwrap();
            // Wire body carries outer metadata + opaque ciphertext; plaintext note absent.
            assert!(!String::from_utf8_lossy(&fwd.message_ciphertext).contains("via bridge"));
            let decoded = RavenContactRequestV1::decode_wire(&fwd.message_ciphertext).unwrap();
            assert_eq!(decoded.ciphertext, req.ciphertext);
            assert!(decoded.is_ciphertext_only());
        }
        other => panic!("case12: {other:?}"),
    }
}

/// 13 Bridge cannot decrypt
#[test]
fn a13_bridge_cannot_decrypt() {
    let sender = Identity::generate();
    let recipient = Identity::generate();
    let req = make_contact_request(
        &sender,
        &recipient,
        ContactRequestInner {
            request_id: [13u8; 16],
            sender_raven_id: sender.address(),
            sender_display_name: "A".into(),
            sender_aliases: vec![],
            sender_profile_digest: [0u8; 32],
            optional_message: "bridge opaque".into(),
            created_at: now(),
            expires_at: now() + 60_000,
        },
    );
    // Bridge only classifies seal class — never opens.
    match classify_sealed_body(&req.ciphertext) {
        SealClass::InterimStub | SealClass::OpaqueAtsam { .. } | SealClass::Other => {}
    }
    // Opening requires recipient key — bridge identity cannot.
    let bridge = Identity::generate();
    assert!(req
        .open_with_atsam_root(&bridge, &DISCOVERY_TEST_ROOT)
        .is_err());
    let inner = req
        .open_with_atsam_root(&recipient, &DISCOVERY_TEST_ROOT)
        .unwrap();
    assert_eq!(inner.optional_message, "bridge opaque");
}

/// 14 Multi-transport dedup once
#[test]
fn a14_multi_transport_dedup() {
    let dir = tempdir().unwrap();
    let q = ForwardQueue::open(&dir.path().join("f.sqlite")).unwrap();
    let sender = Identity::generate();
    let recipient = Identity::generate();
    let req = make_contact_request(
        &sender,
        &recipient,
        ContactRequestInner {
            request_id: [14u8; 16],
            sender_raven_id: sender.address(),
            sender_display_name: "A".into(),
            sender_aliases: vec![],
            sender_profile_digest: [0u8; 32],
            optional_message: "once".into(),
            created_at: now(),
            expires_at: now() + 60_000,
        },
    );
    let packed = pack_contact_req_env(&sender, &req).pack();
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
            previous_hop: "b".into(),
            now_ms: now(),
        },
        true,
    );
    match second {
        RouterOutcome::Dropped { .. } => {}
        other => panic!("expected dedup drop: {other:?}"),
    }
}

/// 15 Local block
#[test]
fn a15_local_block() {
    let id = Identity::generate();
    let pub_hex = hex::encode(id.public_key_bytes());
    let mut blocked = BlockList::default();
    blocked.block(&pub_hex);
    let ctx = DiscoveryContext {
        contacts: vec![LocalContactRow {
            raven_id: id.address(),
            pub_hex,
            petname: "Bad".into(),
            public_tag: "bad".into(),
            display_name: "Bad".into(),
            pinned: false,
            directly_verified: false,
        }],
        blocked,
        now_ms: now(),
        ..Default::default()
    };
    let hits = DiscoveryResolver::v1().search("bad", DiscoveryScope::Local, &ctx);
    assert!(hits
        .iter()
        .any(|h| h.verification_state == VerificationState::Blocked));
}

/// 16 Sybil quota / rate limit on alias publish
#[test]
fn a16_sybil_quota_alias_publish() {
    let id = Identity::generate();
    let mut store = AliasClaimStore::with_quota(AliasPublishQuota {
        max_live_claims_per_pub: 2,
        max_publishes_per_window: 100,
        window_ms: 3_600_000,
    });
    store
        .put(make_alias(&id, "a1", 1, now() + 60_000), now())
        .unwrap();
    store
        .put(make_alias(&id, "a2", 1, now() + 60_000), now())
        .unwrap();
    let err = store
        .put(make_alias(&id, "a3", 1, now() + 60_000), now())
        .unwrap_err();
    assert!(err.contains("SYBIL") || err.contains("QUOTA") || err.contains("RATE"));
}

/// 17 Bootstrap disabled + manual peer
#[test]
fn a17_bootstrap_disabled_manual_peer() {
    let mut cfg = BootstrapConfig::default();
    cfg.remove_raven_defaults();
    cfg.manual_peers.push("/ip4/127.0.0.1/tcp/4001".into());
    assert!(cfg.manual_peer_only_ok());
    assert!(cfg
        .effective_peers()
        .iter()
        .any(|p| p.contains("127.0.0.1")));
}

/// 18 No phone/email in DHT fixtures
#[test]
fn a18_no_phone_email_in_dht() {
    let id = Identity::generate();
    let mut store = AliasClaimStore::default();
    store
        .put(make_alias(&id, "poline", 1, now() + 60_000), now())
        .unwrap();
    assert!(!store.contains_phone_or_email_marker());
    // Profile store has no phone fields by schema — digest only.
    let prof = make_profile(&id, "Poline", &["poline"], 1, now() + 60_000);
    let wire = format!("{:?}", prof);
    assert!(!wire.to_lowercase().contains("phone"));
    assert!(!wire.to_lowercase().contains("email"));
}

/// 19 Terminal result model stable
#[test]
fn a19_terminal_result_model_stable() {
    let keys = result_model_schema_keys();
    assert!(keys.contains(&"raven_id"));
    assert!(keys.contains(&"verification_state"));
    assert!(keys.contains(&"conflict_count"));
    assert!(keys.contains(&"source_set"));
    let id = Identity::generate();
    let mut ctx = DiscoveryContext {
        now_ms: now(),
        ..Default::default()
    };
    ctx.aliases
        .put(make_alias(&id, "poline", 1, now() + 60_000), now())
        .unwrap();
    let hits = DiscoveryResolver::v1().search("@poline", DiscoveryScope::ExactAlias, &ctx);
    let json = serde_json::to_value(&hits[0]).unwrap();
    for k in keys {
        assert!(json.get(*k).is_some(), "missing key {k}");
    }
}

/// 20 Provenance + conflict on results
#[test]
fn a20_provenance_and_conflict() {
    let a = Identity::generate();
    let b = Identity::generate();
    let mut ctx = DiscoveryContext {
        now_ms: now(),
        serverless: true,
        ..Default::default()
    };
    ctx.aliases
        .put(make_alias(&a, "poline", 1, now() + 60_000), now())
        .unwrap();
    ctx.aliases
        .put(make_alias(&b, "poline", 1, now() + 60_000), now())
        .unwrap();
    let hits = DiscoveryResolver::v1().search("@poline", DiscoveryScope::All, &ctx);
    assert!(hits.len() >= 2);
    for h in &hits {
        assert!(!h.source_set.is_empty());
        assert_eq!(h.verification_state, VerificationState::AliasConflict);
        assert!(h.conflict_count >= 2);
    }
    // Legacy server not required
    assert!(!hits
        .iter()
        .any(|h| h.source_set.contains(&DiscoverySource::LegacyServer)));
}

/// Contact accept roundtrip + intro lane smoke
#[test]
fn contact_accept_and_intro_lane() {
    let intro = Identity::generate();
    let subject = Identity::generate();
    let recipient = Identity::generate();
    let intro_id = [9u8; 16];
    let intro_nonce = [0x19u8; 12];
    let note = RavenIntroductionV1::seal_note_with_atsam_root(
        &intro,
        &recipient.public_key_bytes(),
        &recipient.address(),
        b"meet poline",
        &intro_id,
        &DISCOVERY_TEST_ROOT,
        0,
        &intro_nonce,
    )
    .unwrap();
    let intro_rec = RavenIntroductionV1 {
        intro_id,
        introducer_raven_id: String::new(),
        subject_raven_id: subject.address(),
        recipient_raven_id: recipient.address(),
        subject_display_name: "Poline".into(),
        subject_aliases: vec!["poline".into()],
        created_at: now(),
        expires_at: now() + 60_000,
        note_ciphertext: note,
        signature: [0u8; 64],
        introducer_pub: [0u8; 32],
    }
    .sign(&intro)
    .unwrap();
    let opened_note = intro_rec
        .open_note_with_atsam_root(&recipient, &intro.public_key_bytes(), &DISCOVERY_TEST_ROOT)
        .unwrap();
    assert_eq!(opened_note, b"meet poline");
    let mut inbox = IntroductionInbox::default();
    inbox.add(intro_rec, now()).unwrap();
    let ctx = DiscoveryContext {
        intros: inbox,
        now_ms: now(),
        ..Default::default()
    };
    let hits = DiscoveryResolver::v1().search("@poline", DiscoveryScope::MyNetwork, &ctx);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].verification_state, VerificationState::Introduced);

    let accept = ContactAcceptV1 {
        request_id: [1u8; 16],
        accepter_raven_id: String::new(),
        requester_raven_id: intro.address(),
        accepted_at: now(),
        signature: [0u8; 64],
        accepter_pub: [0u8; 32],
    }
    .sign(&recipient)
    .unwrap();
    accept.verify().unwrap();
}

/// Contact-request inbox: accept binds petname + raven_id, emits ContactAcceptV1
#[test]
fn contact_inbox_accept_binds() {
    use raven_core::contact_request::ContactRequestInbox;

    // Fixed seeds so this is not a CSPRNG flake. The optional note must stay
    // inside the sealed inner payload; a two-byte canary like "hi" can appear
    // by chance in sender_pub / signature / ciphertext.
    const OPTIONAL_NOTE: &str = "CONTACT_REQ_OPTIONAL_MSG_CANARY";
    let requester = Identity::from_seed(&[0x11; 32]);
    let accepter = Identity::from_seed(&[0x22; 32]);
    let req = make_contact_request(
        &requester,
        &accepter,
        ContactRequestInner {
            request_id: [0xACu8; 16],
            sender_raven_id: requester.address(),
            sender_display_name: "Ada".into(),
            sender_aliases: vec!["ada".into()],
            sender_profile_digest: [0u8; 32],
            optional_message: OPTIONAL_NOTE.into(),
            created_at: now(),
            expires_at: now() + 60_000,
        },
    );
    let wire = req.encode_wire().unwrap();
    assert!(
        !String::from_utf8_lossy(&wire).contains(OPTIONAL_NOTE),
        "optional contact-request note must not appear on the wire"
    );
    assert!(
        !String::from_utf8_lossy(&req.ciphertext).contains(OPTIONAL_NOTE),
        "optional contact-request note must not appear in ciphertext bytes"
    );
    let decoded = RavenContactRequestV1::decode_wire(&wire).unwrap();
    assert_eq!(decoded.request_id, req.request_id);

    let mut inbox = ContactRequestInbox::default();
    inbox
        .ingest_with_atsam_root(decoded, &accepter, &DISCOVERY_TEST_ROOT, now())
        .unwrap();
    assert_eq!(inbox.pending().len(), 1);

    let outcome = inbox
        .accept(&[0xACu8; 16], &accepter, "Ada (work)", now())
        .unwrap();
    outcome.accept.verify().unwrap();
    assert_eq!(outcome.accept.requester_raven_id, requester.address());
    assert_eq!(outcome.binding.raven_id, requester.address());
    assert_eq!(outcome.binding.petname, "Ada (work)");
    assert_eq!(
        outcome.binding.verification_state,
        VerificationState::TrustedContact
    );
    assert_eq!(
        outcome.binding.pub_hex,
        hex::encode(requester.public_key_bytes())
    );
    assert!(inbox.pending().is_empty());
}

/// Decline removes pending without binding
#[test]
fn contact_inbox_decline() {
    use raven_core::contact_request::ContactRequestInbox;

    let requester = Identity::generate();
    let accepter = Identity::generate();
    let req = make_contact_request(
        &requester,
        &accepter,
        ContactRequestInner {
            request_id: [0xDEu8; 16],
            sender_raven_id: requester.address(),
            sender_display_name: "Bob".into(),
            sender_aliases: vec![],
            sender_profile_digest: [0u8; 32],
            optional_message: String::new(),
            created_at: now(),
            expires_at: now() + 60_000,
        },
    );
    let mut inbox = ContactRequestInbox::default();
    inbox
        .ingest_with_atsam_root(req, &accepter, &DISCOVERY_TEST_ROOT, now())
        .unwrap();
    inbox.decline(&[0xDEu8; 16]).unwrap();
    assert!(inbox.pending().is_empty());
}

/// Block removes pending and adds sender pub to local block list
#[test]
fn contact_inbox_block() {
    use raven_core::contact_request::ContactRequestInbox;

    let requester = Identity::generate();
    let accepter = Identity::generate();
    let req = make_contact_request(
        &requester,
        &accepter,
        ContactRequestInner {
            request_id: [0xBBu8; 16],
            sender_raven_id: requester.address(),
            sender_display_name: "Eve".into(),
            sender_aliases: vec![],
            sender_profile_digest: [0u8; 32],
            optional_message: String::new(),
            created_at: now(),
            expires_at: now() + 60_000,
        },
    );
    let mut inbox = ContactRequestInbox::default();
    inbox
        .ingest_with_atsam_root(req, &accepter, &DISCOVERY_TEST_ROOT, now())
        .unwrap();
    let mut blocks = BlockList::default();
    inbox.block(&[0xBBu8; 16], &mut blocks).unwrap();
    assert!(inbox.pending().is_empty());
    assert!(blocks.is_blocked(&hex::encode(requester.public_key_bytes())));
}

/// Contact-request anti-spam: per-sender pending cap.
#[test]
fn contact_inbox_sender_cap_antispam() {
    let requester = Identity::generate();
    let accepter = Identity::generate();
    let mut inbox = ContactRequestInbox::default();
    let t0 = now();
    for i in 0..CONTACT_REQ_MAX_PER_SENDER {
        let mut rid = [0u8; 16];
        rid[0] = 0xA0 + i as u8;
        let req = make_contact_request(
            &requester,
            &accepter,
            ContactRequestInner {
                request_id: rid,
                sender_raven_id: requester.address(),
                sender_display_name: "Spam".into(),
                sender_aliases: vec![],
                sender_profile_digest: [0u8; 32],
                optional_message: String::new(),
                created_at: t0,
                expires_at: t0 + 60_000,
            },
        );
        inbox
            .ingest_with_atsam_root(req, &accepter, &DISCOVERY_TEST_ROOT, t0)
            .unwrap();
    }
    assert_eq!(inbox.pending().len(), CONTACT_REQ_MAX_PER_SENDER);
    let mut rid = [0u8; 16];
    rid[0] = 0xFF;
    let extra = make_contact_request(
        &requester,
        &accepter,
        ContactRequestInner {
            request_id: rid,
            sender_raven_id: requester.address(),
            sender_display_name: "Spam".into(),
            sender_aliases: vec![],
            sender_profile_digest: [0u8; 32],
            optional_message: String::new(),
            created_at: t0,
            expires_at: t0 + 60_000,
        },
    );
    let err = inbox
        .ingest_with_atsam_root(extra, &accepter, &DISCOVERY_TEST_ROOT, t0)
        .unwrap_err();
    assert!(err.contains("CONTACT_REQ_SENDER_CAP"), "got {err}");
}

/// Nearby safety phrase required before confirm-to-bind
#[test]
fn nearby_confirm_requires_safety_phrase() {
    use raven_core::nearby::{nearby_safety_phrase, NearbyRegistry};

    let adv = NearbyAdvertisement::mint(now(), 30_000, b"confirm-secret");
    let phrase = nearby_safety_phrase(&adv.ephemeral_token, &adv.session_commitment);
    assert!(!phrase.is_empty());
    assert!(phrase.contains('-'));

    let peer = Identity::generate();
    let mut near = NearbyRegistry::default();
    near.publish_ephemeral(adv.clone()).unwrap();
    // Wrong phrase must refuse bind
    assert!(near
        .confirm_with_phrase(
            adv.ephemeral_token,
            peer.address(),
            peer.public_key_bytes(),
            now(),
            &adv.session_commitment,
            "wrong-phrase",
        )
        .is_err());
    assert!(near.confirmed.is_empty());
    // Matching phrase binds
    near.confirm_with_phrase(
        adv.ephemeral_token,
        peer.address(),
        peer.public_key_bytes(),
        now(),
        &adv.session_commitment,
        &phrase,
    )
    .unwrap();
    assert_eq!(near.confirmed.len(), 1);
}
