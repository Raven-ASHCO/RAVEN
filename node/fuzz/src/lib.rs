//! Fuzz target bodies for Raven's attacker-facing decoders.
//!
//! Every function takes arbitrary bytes, must never panic, and checks cheap
//! invariants (canonical re-encoding, bounded consumption) on inputs a decoder
//! accepts. The same file is compiled twice:
//!
//! * as the library of the `raven-fuzz` cargo-fuzz crate (`node/fuzz`, outside
//!   the workspace; `fuzz_targets/*.rs` are one-line libFuzzer wrappers), and
//! * as a module of `raven-core`'s `tests/fuzz_smoke.rs`, which runs every
//!   target over seeded pseudo-random inputs on stable Rust in CI — so these
//!   bodies always type-check against the current decoder APIs.
//!
//! Only `raven_core` and `serde_json` may be used here (both crates have them).

use raven_core::ble_adapter::{ble_frame_decode, validate_opaque_rvn1};
use raven_core::bridge::{decide, BridgeRole};
use raven_core::device_cert::DeviceCertificate;
use raven_core::device_revocation::{claim_digest, DeviceRevocationV1};
use raven_core::envelope::Envelope;
use raven_core::internet::{deframe_prefix, frame, unpack_verify_hello, HelloBinding, HelloRole};
use raven_core::ipc::{decode_request, decode_response, encode_request, encode_response};
use raven_core::lan_rlb1::{decode_offer, encode_offer};
use raven_core::pair_init::{
    decode_init, decode_response as decode_pair_response, encode_init,
    encode_response as encode_pair_response,
};
use raven_core::prekey_bundle::{PrekeyBundle, PrekeyBundleJson};
use raven_core::store_object::StoreObject;

/// Fixed validation clock so runs are reproducible (2023-11-14T22:13:20Z).
const NOW_MS: u64 = 1_700_000_000_000;

/// RVN1 envelope — the outer wire every carrier and bridge ingests.
pub fn envelope(data: &[u8]) {
    if let Some(env) = Envelope::unpack(data) {
        // The strict decoder is exact-length, so decoding is canonical: an
        // accepted input must re-encode to the identical bytes.
        assert_eq!(env.pack(), data, "RVN1 envelope re-encode mismatch");
        let _ = env.signing_bytes();
    }
    for role in [BridgeRole::Endpoint, BridgeRole::Relay] {
        let _ = decide(data, role, NOW_MS, false);
        let _ = decide(data, role, NOW_MS, true);
    }
    let _ = validate_opaque_rvn1(data);
}

/// RSO1 store object (store-and-forward custody wrapper).
pub fn store_object(data: &[u8]) {
    if let Ok(obj) = StoreObject::unpack(data) {
        let packed = obj.pack().expect("accepted store object must re-encode");
        let again = StoreObject::unpack(&packed).expect("re-encoded store object must decode");
        assert_eq!(
            again.pack().expect("second re-encode"),
            packed,
            "RSO1 re-encode is not stable"
        );
    }
}

/// RLB1 LAN bundle offer (device cert + prekey bundle, sent in the LAN Noise
/// handshake by an unauthenticated peer).
pub fn rlb1_offer(data: &[u8]) {
    if let Ok(bundle) = decode_offer(data) {
        let wire = encode_offer(&bundle).expect("accepted RLB1 offer must re-encode");
        let again = decode_offer(&wire).expect("re-encoded RLB1 offer must decode");
        assert_eq!(again, bundle, "RLB1 offer round trip changed the bundle");
        let _ = bundle.verify_bound(NOW_MS);
    }
}

/// Length-prefixed carrier frames: Internet/LAN TCP frames, the mock-BLE /
/// bridge frame, and the RIH1 Internet hello.
pub fn carrier_frames(data: &[u8]) {
    if let Some((payload, used)) = deframe_prefix(data) {
        assert!(used <= data.len(), "deframe consumed past the buffer");
        assert_eq!(used, payload.len() + 4, "deframe length accounting");
        let reframed = frame(&payload).expect("accepted frame must re-frame");
        assert_eq!(reframed, &data[..used], "frame re-encode mismatch");
    }
    if let Ok(Some((payload, used))) = ble_frame_decode(data) {
        assert!(used <= data.len(), "BLE frame consumed past the buffer");
        assert_eq!(used, payload.len() + 4, "BLE frame length accounting");
        assert!(
            validate_opaque_rvn1(&payload),
            "BLE frame passed a non-RVN1 payload"
        );
    }
    // The hello signature is channel-bound; a fixed binding still exercises
    // the full decode + verify path on arbitrary bytes.
    let binding = HelloBinding {
        role: HelloRole::Initiator,
        handshake_hash: [0u8; 32],
        noise_static_pub: [0u8; 32],
    };
    let _ = unpack_verify_hello(data, &binding);
}

/// PairInit / PairResponse (fixed-length, signed first-contact messages).
pub fn pair_init(data: &[u8]) {
    if let Ok(init) = decode_init(data) {
        let wire = encode_init(&init).expect("accepted PairInit must re-encode");
        assert_eq!(wire, data, "PairInit re-encode mismatch");
    }
    if let Ok(resp) = decode_pair_response(data) {
        let wire = encode_pair_response(&resp).expect("accepted PairResponse must re-encode");
        assert_eq!(wire, data, "PairResponse re-encode mismatch");
    }
}

/// Device certificate and prekey bundle JSON (peer cert cache, RLB1 bodies).
pub fn device_cert(data: &[u8]) {
    if let Ok(cert) = serde_json::from_slice::<DeviceCertificate>(data) {
        let _ = cert.verify(NOW_MS);
        let _ = raven_core::pair_init::device_certificate_hash(&cert);
    }
    if let Ok(json) = serde_json::from_slice::<PrekeyBundleJson>(data) {
        if let Ok(bundle) = PrekeyBundle::from_json(&json) {
            let _ = bundle.verify(NOW_MS);
        }
    }
}

/// Device revocation claim (`RAVEN_DEVICE_REVOCATION_V1`).
pub fn device_revocation(data: &[u8]) {
    let _ = claim_digest(data);
    if let Ok(rev) = DeviceRevocationV1::decode(data) {
        let wire = rev.encode().expect("accepted revocation must re-encode");
        assert_eq!(wire, data, "device revocation re-encode mismatch");
    }
}

/// Local IPC frames (`ash` ⇄ `raven-node`; reachable by any local process
/// that can open the socket / named pipe).
pub fn ipc_frame(data: &[u8]) {
    if let Ok(req) = decode_request(data) {
        let wire = encode_request(&req).expect("accepted IPC request must re-encode");
        // The re-encode may legitimately be refused (e.g. a JSON escape that
        // spells a forbidden field name once normalised); if it decodes, it
        // must be the same request.
        if let Ok(again) = decode_request(&wire) {
            assert_eq!(again, req, "IPC request round trip changed the request");
        }
    }
    if let Ok(resp) = decode_response(data) {
        let _ = encode_response(&resp);
    }
}

/// ATSAM indexed-session wire pieces and discovery / contact records.
pub fn session_and_records(data: &[u8]) {
    let _ = raven_core::atsam_indexed_session::parse_indexed_message_header(data);
    let _ = raven_core::atsam_indexed_session::decode_signed_ack(data);
    let _ = raven_core::seal::parse_rvna1_header(data);
    let _ = raven_core::alias_record::AliasRecord::decode(data);
    let _ = raven_core::discovery::PeerRecord::decode(data);
    let _ = raven_core::contact_request::RavenContactRequestV1::decode_wire(data);
    let _ = raven_core::contact_request::ContactAcceptV1::decode_wire(data);
}

/// A fuzz target body.
pub type Target = fn(&[u8]);

/// Every target, for smoke drivers that feed one input to all decoders.
pub const ALL_TARGETS: &[(&str, Target)] = &[
    ("envelope", envelope),
    ("store_object", store_object),
    ("rlb1_offer", rlb1_offer),
    ("carrier_frames", carrier_frames),
    ("pair_init", pair_init),
    ("device_cert", device_cert),
    ("device_revocation", device_revocation),
    ("ipc_frame", ipc_frame),
    ("session_and_records", session_and_records),
];
