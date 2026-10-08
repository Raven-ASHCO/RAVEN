//! Custody admission allow-list (design 2026-10 transports §4.1, finding F3).
//!
//! Every path that takes **custody** of an object for someone else (bridge
//! store-and-forward, IPC `EnqueueSealed`, `message_router` relay, mailbox PUT)
//! calls [`admit_relayable`] before it stores or forwards anything. Only the
//! two objects a relay may ever hold pass:
//!
//! - a strict `RavenEnvelopeV1` **message** (`env_type = 1`) whose body is a
//!   sealed RVNA1 indexed-session frame (`RVNA1\0\0\0 || 0x03 || 0x01 || ...`,
//!   at least header + tag long), and
//! - a strict **ACK** (`env_type = 2`) whose body is exactly one sealed indexed
//!   ACK (same header, [`ACK_SEALED_WIRE_LEN`] bytes),
//!
//! both with `flags = 0`, an empty ratchet header, a packed size that fits one
//! Noise transport frame, `created_at` no more than the normative clock skew in
//! the future, and `expires_at` in the future but at most 24 h (+ skew) away.
//!
//! Everything else is refused before custody: PairInit / PairResponse wrapped
//! as a message (addresses and trust material in clear, PairInit §7), the
//! `0x7F` interim demo cipher, RVNA1 v1/v2 frames, plaintext ACK records, alias
//! gossip and capability records. Classification reads the fixed header bytes
//! only, never the ciphertext (umbrella §7.2): an admitted object stays opaque.
//!
//! Lab exception: builds with the `unsafe-demo-crypto` feature (debug only,
//! see `seal.rs`) also admit the interim demo message cipher and demo ACK
//! bodies so the mock-BLE A-B-C demo keeps working. PairInit stays refused
//! there too.

use crate::atsam_indexed_session::{
    ACK_SEALED_WIRE_LEN, INDEXED_SEALED_HEADER_LEN, INDEXED_SEALED_MIN_WIRE_LEN, RVNA1_PROTO,
    RVNA1_SUITE,
};
use crate::envelope::{EnvType, Envelope};
use crate::pair_init_lan_oob::{classify_message_ciphertext, PairInitOobClassify};
use crate::prekey_lifecycle::MAX_PREKEY_FUTURE_SKEW_MS;
use crate::seal::SEAL_MAGIC_RVNA1;

/// Largest object a custody path holds: one Noise transport frame, so every
/// admitted object can still be delivered over any authenticated Raven link.
pub const MAX_CUSTODY_OBJECT_BYTES: usize = crate::lan_noise::MAX_TRANSPORT_PLAINTEXT;

/// `created_at` may be at most this far in the future (the normative
/// `MAX_PEER_CLOCK_SKEW_MS`, PairInit §1).
pub const MAX_CUSTODY_FUTURE_SKEW_MS: u64 = MAX_PREKEY_FUTURE_SKEW_MS;

/// Longest validity a custody path accepts, measured from its own clock: the
/// session lifetime (24 h) plus the clock skew a sender may be ahead by.
pub const MAX_CUSTODY_VALIDITY_MS: u64 = 24 * 60 * 60 * 1000 + MAX_CUSTODY_FUTURE_SKEW_MS;

/// Required `flags` (the indexed-session `OUTBOUND_FLAGS`).
const CUSTODY_FLAGS: u16 = 0;

/// Why an object was refused custody. Local diagnostics only: callers map it
/// to their existing wire codes, so no new byte reaches a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyRefusal {
    /// Over [`MAX_CUSTODY_OBJECT_BYTES`].
    TooLarge,
    /// Not a strict `RavenEnvelopeV1`.
    Malformed,
    /// Neither a message nor an ACK (alias gossip, capabilities, ...).
    UnsupportedType,
    /// Non-zero `flags`.
    Flags,
    /// Non-empty ratchet header (the indexed profile sends none).
    RatchetHeader,
    /// A wrapped PairInit / PairResponse: never relay- or store-readable.
    PairingMaterial,
    /// The body is not a sealed indexed-session frame (demo cipher, RVNA1
    /// v1/v2, plaintext ACK record, anything else).
    NotSealedIndexed,
    /// `created_at` too far in the future.
    FromTheFuture,
    /// Already expired.
    Expired,
    /// Valid for longer than [`MAX_CUSTODY_VALIDITY_MS`].
    ValidityTooLong,
}

/// What custody may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayableKind {
    Message,
    Ack,
}

/// An admitted object: the decoded envelope (for the caller's bookkeeping)
/// plus its kind. The packed bytes the caller holds are what it stores.
#[derive(Debug, Clone)]
pub struct RelayableObject {
    pub kind: RelayableKind,
    pub envelope: Envelope,
}

fn sealed_indexed_header(body: &[u8]) -> bool {
    body.len() >= INDEXED_SEALED_HEADER_LEN
        && body[..8] == SEAL_MAGIC_RVNA1
        && body[8] == RVNA1_PROTO
        && body[9] == RVNA1_SUITE
}

/// Lab-only (`unsafe-demo-crypto`) bodies the mock-BLE demo relays.
#[cfg(feature = "unsafe-demo-crypto")]
fn lab_demo_body(kind: RelayableKind, body: &[u8]) -> bool {
    match kind {
        RelayableKind::Message => matches!(
            crate::seal::classify_sealed_body(body),
            crate::seal::SealClass::InterimStub
        ),
        RelayableKind::Ack => !body.is_empty(),
    }
}

#[cfg(not(feature = "unsafe-demo-crypto"))]
fn lab_demo_body(_kind: RelayableKind, _body: &[u8]) -> bool {
    false
}

/// The custody allow-list. See the module docs for the rule.
pub fn admit_relayable(packed: &[u8], now_ms: u64) -> Result<RelayableObject, CustodyRefusal> {
    if packed.len() > MAX_CUSTODY_OBJECT_BYTES {
        return Err(CustodyRefusal::TooLarge);
    }
    let envelope = Envelope::unpack(packed).ok_or(CustodyRefusal::Malformed)?;
    let kind = match EnvType::from_u8(envelope.env_type) {
        Some(EnvType::Message) => RelayableKind::Message,
        Some(EnvType::Ack) => RelayableKind::Ack,
        _ => return Err(CustodyRefusal::UnsupportedType),
    };
    if envelope.flags != CUSTODY_FLAGS {
        return Err(CustodyRefusal::Flags);
    }
    if !envelope.ratchet_header_ciphertext.is_empty() {
        return Err(CustodyRefusal::RatchetHeader);
    }
    // Before the body-shape rule, so a pairing frame is always reported (and
    // refused) as what it is, in lab builds too.
    if !matches!(
        classify_message_ciphertext(&envelope.message_ciphertext),
        PairInitOobClassify::NotPairInitOob
    ) {
        return Err(CustodyRefusal::PairingMaterial);
    }
    let body = &envelope.message_ciphertext;
    let sealed = sealed_indexed_header(body)
        && match kind {
            RelayableKind::Message => body.len() >= INDEXED_SEALED_MIN_WIRE_LEN,
            RelayableKind::Ack => body.len() == ACK_SEALED_WIRE_LEN,
        };
    if !sealed && !lab_demo_body(kind, body) {
        return Err(CustodyRefusal::NotSealedIndexed);
    }
    if envelope.created_at > now_ms.saturating_add(MAX_CUSTODY_FUTURE_SKEW_MS) {
        return Err(CustodyRefusal::FromTheFuture);
    }
    if envelope.expires_at <= now_ms {
        return Err(CustodyRefusal::Expired);
    }
    if envelope.expires_at > now_ms.saturating_add(MAX_CUSTODY_VALIDITY_MS) {
        return Err(CustodyRefusal::ValidityTooLong);
    }
    Ok(RelayableObject { kind, envelope })
}

/// A body with the fixed sealed indexed-session header and `len` bytes in
/// total (filled with `fill`). For tests and harnesses of custody paths in
/// other crates: it has the *shape* custody admits, not a decryptable frame.
#[doc(hidden)]
pub fn opaque_indexed_body_for_tests(kind: RelayableKind, fill: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(ACK_SEALED_WIRE_LEN);
    body.extend_from_slice(&SEAL_MAGIC_RVNA1);
    body.push(RVNA1_PROTO);
    body.push(RVNA1_SUITE);
    let target = match kind {
        RelayableKind::Message => INDEXED_SEALED_MIN_WIRE_LEN.max(10 + fill.len() + 16),
        RelayableKind::Ack => ACK_SEALED_WIRE_LEN,
    };
    let mut i = 0usize;
    while body.len() < target {
        body.push(if fill.is_empty() {
            0x5a
        } else {
            fill[i % fill.len()]
        });
        i += 1;
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::pair_init::{INIT_MAGIC, INIT_WIRE_LEN, RESPONSE_MAGIC, RESPONSE_WIRE_LEN};

    const NOW: u64 = 1_800_000_000_000;

    fn env(env_type: EnvType, body: Vec<u8>) -> Envelope {
        let mut e = Envelope {
            env_type: env_type as u8,
            flags: 0,
            message_id: [0x11; 16],
            routing_tag: [0x22; 16],
            dest_device_hint: 0,
            created_at: NOW,
            expires_at: NOW + 60 * 60 * 1000,
            hop_limit: 8,
            replication_budget: 2,
            anti_replay_nonce: [0x33; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: body,
            sender_authentication: vec![],
        };
        e.sign_with(&Identity::from_seed(&[0x44; 32]));
        e
    }

    fn msg() -> Envelope {
        env(
            EnvType::Message,
            opaque_indexed_body_for_tests(RelayableKind::Message, b"ct"),
        )
    }

    fn ack() -> Envelope {
        env(
            EnvType::Ack,
            opaque_indexed_body_for_tests(RelayableKind::Ack, b"ack"),
        )
    }

    fn refusal(e: &Envelope) -> CustodyRefusal {
        admit_relayable(&e.pack(), NOW).unwrap_err()
    }

    #[test]
    fn sealed_indexed_message_and_ack_are_admitted() {
        let m = admit_relayable(&msg().pack(), NOW).unwrap();
        assert_eq!(m.kind, RelayableKind::Message);
        let a = admit_relayable(&ack().pack(), NOW).unwrap();
        assert_eq!(a.kind, RelayableKind::Ack);
        // Legacy-hint senders are not refused (a hop rewrites nothing).
        let mut legacy = msg();
        legacy.dest_device_hint = 0x0123_4567_89ab_cdef;
        assert!(admit_relayable(&legacy.pack(), NOW).is_ok());
    }

    #[test]
    fn pairing_material_is_never_admitted() {
        let mut init = INIT_MAGIC.to_vec();
        init.resize(INIT_WIRE_LEN, 0x01);
        let mut resp = RESPONSE_MAGIC.to_vec();
        resp.resize(RESPONSE_WIRE_LEN, 0x02);
        for body in [init, resp] {
            assert_eq!(
                refusal(&env(EnvType::Message, body.clone())),
                CustodyRefusal::PairingMaterial
            );
            assert_eq!(
                refusal(&env(EnvType::Ack, body)),
                CustodyRefusal::PairingMaterial
            );
        }
        // The real wrapper (hop 0 / budget 0, short TTL) is refused as well.
        let wrapped = crate::pair_init_lan_oob::wrap_oob_wire(
            &{
                let mut w = INIT_MAGIC.to_vec();
                w.resize(INIT_WIRE_LEN, 0x07);
                w
            },
            crate::pair_init_lan_oob::PairInitOobKind::PairInit,
            &Identity::from_seed(&[0x45; 32]),
            [0; 16],
            NOW,
            &mut rand::thread_rng(),
        )
        .unwrap();
        assert_eq!(
            admit_relayable(&wrapped, NOW).unwrap_err(),
            CustodyRefusal::PairingMaterial
        );
    }

    #[test]
    fn other_bodies_types_and_shapes_are_refused() {
        // Plaintext / demo / other RVNA1 protocols.
        let mut demo = SEAL_MAGIC_RVNA1.to_vec();
        demo.extend_from_slice(&[crate::seal::STUB_PROTO, 0x01]);
        demo.resize(64, 0);
        let mut v2 = SEAL_MAGIC_RVNA1.to_vec();
        v2.extend_from_slice(&[0x02, 0x01]);
        v2.resize(64, 0);
        for body in [b"hello plaintext".to_vec(), v2, vec![]] {
            assert_eq!(
                refusal(&env(EnvType::Message, body)),
                CustodyRefusal::NotSealedIndexed
            );
        }
        if !cfg!(feature = "unsafe-demo-crypto") {
            assert_eq!(
                refusal(&env(EnvType::Message, demo)),
                CustodyRefusal::NotSealedIndexed
            );
            // A plaintext 101-byte ACK record is not a sealed ACK.
            assert_eq!(
                refusal(&env(EnvType::Ack, vec![0x01; 101])),
                CustodyRefusal::NotSealedIndexed
            );
        }
        // A sealed ACK must be exactly one ACK frame.
        let mut long_ack = opaque_indexed_body_for_tests(RelayableKind::Ack, b"x");
        long_ack.push(0);
        if !cfg!(feature = "unsafe-demo-crypto") {
            assert_eq!(
                refusal(&env(EnvType::Ack, long_ack)),
                CustodyRefusal::NotSealedIndexed
            );
        }
        // Truncated message frame (header without tag).
        let short = opaque_indexed_body_for_tests(RelayableKind::Message, b"")
            [..INDEXED_SEALED_HEADER_LEN]
            .to_vec();
        assert_eq!(
            refusal(&env(EnvType::Message, short)),
            CustodyRefusal::NotSealedIndexed
        );
        for t in [EnvType::AliasGossip, EnvType::Capabilities] {
            let body = opaque_indexed_body_for_tests(RelayableKind::Message, b"c");
            assert_eq!(refusal(&env(t, body)), CustodyRefusal::UnsupportedType);
        }
        let mut flagged = msg();
        flagged.flags = 1;
        flagged.sign_with(&Identity::from_seed(&[0x44; 32]));
        assert_eq!(refusal(&flagged), CustodyRefusal::Flags);
        let mut header = msg();
        header.ratchet_header_ciphertext = vec![1, 2, 3];
        header.sign_with(&Identity::from_seed(&[0x44; 32]));
        assert_eq!(refusal(&header), CustodyRefusal::RatchetHeader);
        assert_eq!(
            admit_relayable(b"RVN1 not an envelope", NOW).unwrap_err(),
            CustodyRefusal::Malformed
        );
        let mut big = msg();
        big.message_ciphertext
            .resize(MAX_CUSTODY_OBJECT_BYTES, 0x00);
        big.sign_with(&Identity::from_seed(&[0x44; 32]));
        assert_eq!(refusal(&big), CustodyRefusal::TooLarge);
    }

    #[test]
    fn time_window_is_bounded() {
        let mut future = msg();
        future.created_at = NOW + MAX_CUSTODY_FUTURE_SKEW_MS + 1;
        future.expires_at = future.created_at + 1000;
        assert_eq!(refusal(&future), CustodyRefusal::FromTheFuture);
        let mut skewed = msg();
        skewed.created_at = NOW + MAX_CUSTODY_FUTURE_SKEW_MS;
        skewed.expires_at = skewed.created_at + 1000;
        assert!(admit_relayable(&skewed.pack(), NOW).is_ok());
        let mut expired = msg();
        expired.created_at = NOW - 10;
        expired.expires_at = NOW;
        assert_eq!(refusal(&expired), CustodyRefusal::Expired);
        let mut long = msg();
        long.expires_at = NOW + MAX_CUSTODY_VALIDITY_MS + 1;
        assert_eq!(refusal(&long), CustodyRefusal::ValidityTooLong);
        let mut day = msg();
        day.expires_at = NOW + 24 * 60 * 60 * 1000;
        assert!(admit_relayable(&day.pack(), NOW).is_ok());
    }

    /// Admission is opaque: it never needs, or touches, a key.
    #[test]
    fn admission_reads_only_the_fixed_header() {
        let mut a = msg();
        let mut b = msg();
        let n = a.message_ciphertext.len();
        a.message_ciphertext[n - 1] = 0x00;
        b.message_ciphertext[n - 1] = 0xff;
        assert!(admit_relayable(&a.pack(), NOW).is_ok());
        assert!(admit_relayable(&b.pack(), NOW).is_ok());
    }
}
