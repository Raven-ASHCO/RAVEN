//! RavenContactRequestV1 + ContactAcceptV1 — root-required ATSAM contact codec.
//!
//! Delivered as opaque RavenEnvelopeV1 message bodies through MessageRouter
//! (direct / relay / store / BLE / Bridge). Bridge never decrypts.
//!
//! Recipient opens locally into `ContactRequestInbox`, then Accept / Decline / Block.

use crate::atsam_aead::{seal_rvna1_v2, unseal_rvna1_v2};
use crate::canon::{lp, u64_be};
use crate::chat_history::BlockList;
use crate::discovery_resolver::VerificationState;
use crate::identity::Identity;
use sha2::{Digest, Sha256};

pub const CONTACT_REQ_DOMAIN: &[u8] = b"rvn1/contact-req";
pub const CONTACT_ACCEPT_DOMAIN: &[u8] = b"rvn1/contact-accept";
pub const CONTACT_REQ_INNER: &[u8] = b"rvn1/contact-req-inner";
pub const CONTACT_REQ_WIRE: &[u8] = b"rvn1/contact-req-wire";
pub const CONTACT_ACCEPT_WIRE: &[u8] = b"rvn1/contact-accept-wire";
/// Rootless contact-request encryption is intentionally unavailable. Public
/// identity keys are not secrets; callers must supply an authenticated ATSAM
/// session root through the explicit `*_with_atsam_root` APIs.
pub const CONTACT_REQ_SESSION_REQUIRED: &str =
    "CONTACT_REQ_SESSION_REQUIRED: authenticated ATSAM root required";
/// Maximum signed lifetime (`expires_at - created_at`). Bounds how long a
/// captured request stays replayable and how long an inbox must remember it.
pub const CONTACT_REQ_MAX_LIFETIME_MS: u64 = 30 * 24 * 3_600_000; // 30 days
/// Tolerated sender clock skew for a `created_at` in the future.
pub const CONTACT_REQ_MAX_FUTURE_SKEW_MS: u64 = 5 * 60 * 1_000;

/// Cleartext fields that live *inside* the sealed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRequestInner {
    pub request_id: [u8; 16],
    pub sender_raven_id: String,
    pub sender_display_name: String,
    pub sender_aliases: Vec<String>,
    pub sender_profile_digest: [u8; 32],
    pub optional_message: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl ContactRequestInner {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut out = CONTACT_REQ_INNER.to_vec();
        out.extend_from_slice(&self.request_id);
        out.extend(lp(self.sender_raven_id.as_bytes())?);
        out.extend(lp(self.sender_display_name.as_bytes())?);
        let alias_count = u16::try_from(self.sender_aliases.len())
            .map_err(|_| "too many contact request aliases".to_string())?;
        out.extend_from_slice(&alias_count.to_be_bytes());
        for a in &self.sender_aliases {
            out.extend(lp(a.as_bytes())?);
        }
        out.extend_from_slice(&self.sender_profile_digest);
        out.extend(lp(self.optional_message.as_bytes())?);
        out.extend_from_slice(&u64_be(self.created_at));
        out.extend_from_slice(&u64_be(self.expires_at));
        Ok(out)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < CONTACT_REQ_INNER.len() + 16 {
            return Err("contact req inner short".into());
        }
        if &raw[..CONTACT_REQ_INNER.len()] != CONTACT_REQ_INNER {
            return Err("contact req inner magic".into());
        }
        let mut off = CONTACT_REQ_INNER.len();
        let mut request_id = [0u8; 16];
        request_id.copy_from_slice(&raw[off..off + 16]);
        off += 16;
        let (sender_raven_id, n) = read_lp_str(raw, off)?;
        off = n;
        let (sender_display_name, n) = read_lp_str(raw, off)?;
        off = n;
        if off + 2 > raw.len() {
            return Err("aliases len".into());
        }
        let n_alias = u16::from_be_bytes([raw[off], raw[off + 1]]) as usize;
        off += 2;
        let mut sender_aliases = Vec::with_capacity(n_alias);
        for _ in 0..n_alias {
            let (a, n) = read_lp_str(raw, off)?;
            off = n;
            sender_aliases.push(a);
        }
        if off + 32 > raw.len() {
            return Err("digest".into());
        }
        let mut sender_profile_digest = [0u8; 32];
        sender_profile_digest.copy_from_slice(&raw[off..off + 32]);
        off += 32;
        let (optional_message, n) = read_lp_str(raw, off)?;
        off = n;
        if off + 16 > raw.len() {
            return Err("timestamps".into());
        }
        let created_at = u64::from_be_bytes(raw[off..off + 8].try_into().unwrap());
        off += 8;
        let expires_at = u64::from_be_bytes(raw[off..off + 8].try_into().unwrap());
        off += 8;
        if off != raw.len() {
            return Err("contact req inner trailing bytes".into());
        }
        Ok(Self {
            request_id,
            sender_raven_id,
            sender_display_name,
            sender_aliases,
            sender_profile_digest,
            optional_message,
            created_at,
            expires_at,
        })
    }
}

fn read_lp_str(raw: &[u8], off: usize) -> Result<(String, usize), String> {
    if off + 2 > raw.len() {
        return Err("lp short".into());
    }
    let len = u16::from_be_bytes([raw[off], raw[off + 1]]) as usize;
    let start = off + 2;
    if start + len > raw.len() {
        return Err("lp trunc".into());
    }
    let s = String::from_utf8(raw[start..start + len].to_vec()).map_err(|_| "utf8".to_string())?;
    Ok((s, start + len))
}

/// Wire object: sealed contact request (ciphertext-only for store/bridge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RavenContactRequestV1 {
    pub request_id: [u8; 16],
    pub recipient_raven_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// Opaque sealed body — Bridge/store MUST NOT decrypt.
    pub ciphertext: Vec<u8>,
    pub sender_authentication: [u8; 64],
    pub sender_pub: [u8; 32],
}

impl RavenContactRequestV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = CONTACT_REQ_DOMAIN.to_vec();
        out.extend_from_slice(&self.request_id);
        out.extend(lp(self.recipient_raven_id.as_bytes())?);
        out.extend_from_slice(&u64_be(self.created_at));
        out.extend_from_slice(&u64_be(self.expires_at));
        out.extend(lp(&self.ciphertext)?);
        Ok(out)
    }

    pub fn create(
        sender: &Identity,
        recipient_pub: &[u8; 32],
        recipient_addr: &str,
        inner: ContactRequestInner,
    ) -> Result<Self, String> {
        let _ = (sender, recipient_pub, recipient_addr, inner);
        Err(CONTACT_REQ_SESSION_REQUIRED.into())
    }

    /// Create a contact request under an already authenticated ATSAM session
    /// root. Session establishment, root persistence, and monotonic index
    /// allocation are the caller's responsibility.
    pub fn create_with_atsam_root(
        sender: &Identity,
        recipient_pub: &[u8; 32],
        recipient_addr: &str,
        inner: ContactRequestInner,
        root: &[u8; 32],
        chain_index: u32,
        nonce: &[u8; 12],
    ) -> Result<Self, String> {
        if crate::address::encode_address(recipient_pub) != recipient_addr {
            return Err("CONTACT_REQ_RECIPIENT_KEY_MISMATCH".into());
        }
        let sender_addr = sender.address();
        if inner.sender_raven_id != sender_addr {
            return Err("CONTACT_REQ_SENDER_ID_MISMATCH".into());
        }
        if inner.expires_at <= inner.created_at {
            return Err("CONTACT_REQ_INVALID_TIME_RANGE".into());
        }
        if inner.expires_at - inner.created_at > CONTACT_REQ_MAX_LIFETIME_MS {
            return Err("CONTACT_REQ_LIFETIME_TOO_LONG".into());
        }
        let plain = inner.encode()?;
        let ciphertext = seal_rvna1_v2(
            root,
            &sender_addr,
            recipient_addr,
            &hex::encode(inner.request_id),
            chain_index,
            &plain,
            nonce,
        )?;
        let mut req = Self {
            request_id: inner.request_id,
            recipient_raven_id: recipient_addr.to_string(),
            created_at: inner.created_at,
            expires_at: inner.expires_at,
            ciphertext,
            sender_authentication: [0u8; 64],
            sender_pub: sender.public_key_bytes(),
        };
        req.sender_authentication = sender.sign(&req.signing_bytes()?);
        Ok(req)
    }

    pub fn verify_outer(&self, now_ms: u64) -> Result<(), String> {
        if self.expires_at <= self.created_at {
            return Err("CONTACT_REQ_INVALID_TIME_RANGE".into());
        }
        if self.expires_at - self.created_at > CONTACT_REQ_MAX_LIFETIME_MS {
            return Err("CONTACT_REQ_LIFETIME_TOO_LONG".into());
        }
        if self.created_at > now_ms.saturating_add(CONTACT_REQ_MAX_FUTURE_SKEW_MS) {
            return Err("CONTACT_REQ_NOT_YET_VALID".into());
        }
        if now_ms > self.expires_at {
            return Err("CONTACT_REQ_EXPIRED".into());
        }
        let sb = self.signing_bytes()?;
        if !Identity::verify(&self.sender_pub, &sb, &self.sender_authentication) {
            return Err("CONTACT_REQ_BAD_SIG".into());
        }
        Ok(())
    }

    pub fn open(&self, recipient: &Identity) -> Result<ContactRequestInner, String> {
        let _ = recipient;
        Err(CONTACT_REQ_SESSION_REQUIRED.into())
    }

    /// Open using the authenticated ATSAM session root paired with the sender.
    pub fn open_with_atsam_root(
        &self,
        recipient: &Identity,
        root: &[u8; 32],
    ) -> Result<ContactRequestInner, String> {
        if self.recipient_raven_id != recipient.address() {
            return Err("CONTACT_REQ_WRONG_RECIPIENT".into());
        }
        let sender_addr = crate::address::encode_address(&self.sender_pub);
        let plain = unseal_rvna1_v2(
            root,
            &self.ciphertext,
            &sender_addr,
            &self.recipient_raven_id,
            &hex::encode(self.request_id),
        )?;
        let inner = ContactRequestInner::decode(&plain)?;
        if inner.request_id != self.request_id
            || inner.sender_raven_id != sender_addr
            || inner.created_at != self.created_at
            || inner.expires_at != self.expires_at
        {
            return Err("CONTACT_REQ_INNER_BINDING_MISMATCH".into());
        }
        Ok(inner)
    }

    /// True when store/bridge only sees ciphertext (no plaintext markers).
    pub fn is_ciphertext_only(&self) -> bool {
        !self.ciphertext.is_empty()
            && !String::from_utf8_lossy(&self.ciphertext).contains("rvn1/contact-req-inner")
    }

    pub fn content_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.request_id);
        h.update(&self.ciphertext);
        h.finalize().into()
    }

    /// Full outer object for MessageRouter body (ciphertext remains opaque to Bridge).
    pub fn encode_wire(&self) -> Result<Vec<u8>, String> {
        let mut out = CONTACT_REQ_WIRE.to_vec();
        out.extend_from_slice(&self.request_id);
        out.extend(lp(self.recipient_raven_id.as_bytes())?);
        out.extend_from_slice(&u64_be(self.created_at));
        out.extend_from_slice(&u64_be(self.expires_at));
        out.extend(lp(&self.ciphertext)?);
        out.extend_from_slice(&self.sender_authentication);
        out.extend_from_slice(&self.sender_pub);
        Ok(out)
    }

    pub fn decode_wire(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < CONTACT_REQ_WIRE.len() + 16 + 64 + 32 {
            return Err("contact req wire short".into());
        }
        if &raw[..CONTACT_REQ_WIRE.len()] != CONTACT_REQ_WIRE {
            return Err("contact req wire magic".into());
        }
        let mut off = CONTACT_REQ_WIRE.len();
        let mut request_id = [0u8; 16];
        request_id.copy_from_slice(&raw[off..off + 16]);
        off += 16;
        let (recipient_raven_id, n) = read_lp_str(raw, off)?;
        off = n;
        if off + 16 > raw.len() {
            return Err("timestamps".into());
        }
        let created_at = u64::from_be_bytes(raw[off..off + 8].try_into().unwrap());
        off += 8;
        let expires_at = u64::from_be_bytes(raw[off..off + 8].try_into().unwrap());
        off += 8;
        if off + 2 > raw.len() {
            return Err("ct lp".into());
        }
        let ct_len = u16::from_be_bytes([raw[off], raw[off + 1]]) as usize;
        off += 2;
        if off + ct_len + 64 + 32 != raw.len() {
            return Err("ct trunc".into());
        }
        let ciphertext = raw[off..off + ct_len].to_vec();
        off += ct_len;
        let mut sender_authentication = [0u8; 64];
        sender_authentication.copy_from_slice(&raw[off..off + 64]);
        off += 64;
        let mut sender_pub = [0u8; 32];
        sender_pub.copy_from_slice(&raw[off..off + 32]);
        Ok(Self {
            request_id,
            recipient_raven_id,
            created_at,
            expires_at,
            ciphertext,
            sender_authentication,
            sender_pub,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactAcceptV1 {
    pub request_id: [u8; 16],
    pub accepter_raven_id: String,
    pub requester_raven_id: String,
    pub accepted_at: u64,
    pub signature: [u8; 64],
    pub accepter_pub: [u8; 32],
}

impl ContactAcceptV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = CONTACT_ACCEPT_DOMAIN.to_vec();
        out.extend_from_slice(&self.request_id);
        out.extend(lp(self.accepter_raven_id.as_bytes())?);
        out.extend(lp(self.requester_raven_id.as_bytes())?);
        out.extend_from_slice(&u64_be(self.accepted_at));
        Ok(out)
    }

    pub fn sign(mut self, accepter: &Identity) -> Result<Self, String> {
        self.accepter_pub = accepter.public_key_bytes();
        self.accepter_raven_id = accepter.address();
        let sb = self.signing_bytes()?;
        self.signature = accepter.sign(&sb);
        Ok(self)
    }

    /// Verify the signature *and* that `accepter_raven_id` is the address of
    /// the signing key, so an accept cannot claim someone else's Raven ID.
    pub fn verify(&self) -> Result<(), String> {
        if crate::address::encode_address(&self.accepter_pub) != self.accepter_raven_id {
            return Err("CONTACT_ACCEPT_ADDR_MISMATCH".into());
        }
        let sb = self.signing_bytes()?;
        if !Identity::verify(&self.accepter_pub, &sb, &self.signature) {
            return Err("CONTACT_ACCEPT_BAD_SIG".into());
        }
        Ok(())
    }

    /// Requester-side check before trusting an inbound accept: it must be a
    /// valid accept (see [`Self::verify`]) for exactly the request this
    /// requester sent — same `request_id`, signed by that request's
    /// recipient, naming this requester.
    pub fn verify_for_request(&self, request: &RavenContactRequestV1) -> Result<(), String> {
        self.verify()?;
        if self.request_id != request.request_id
            || self.accepter_raven_id != request.recipient_raven_id
            || self.requester_raven_id != crate::address::encode_address(&request.sender_pub)
        {
            return Err("CONTACT_ACCEPT_BINDING_MISMATCH".into());
        }
        Ok(())
    }

    pub fn encode_wire(&self) -> Result<Vec<u8>, String> {
        let mut out = CONTACT_ACCEPT_WIRE.to_vec();
        out.extend_from_slice(&self.request_id);
        out.extend(lp(self.accepter_raven_id.as_bytes())?);
        out.extend(lp(self.requester_raven_id.as_bytes())?);
        out.extend_from_slice(&u64_be(self.accepted_at));
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.accepter_pub);
        Ok(out)
    }

    pub fn decode_wire(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < CONTACT_ACCEPT_WIRE.len() + 16 + 64 + 32 {
            return Err("contact accept wire short".into());
        }
        if &raw[..CONTACT_ACCEPT_WIRE.len()] != CONTACT_ACCEPT_WIRE {
            return Err("contact accept wire magic".into());
        }
        let mut off = CONTACT_ACCEPT_WIRE.len();
        let mut request_id = [0u8; 16];
        request_id.copy_from_slice(&raw[off..off + 16]);
        off += 16;
        let (accepter_raven_id, n) = read_lp_str(raw, off)?;
        off = n;
        let (requester_raven_id, n) = read_lp_str(raw, off)?;
        off = n;
        if off + 8 + 64 + 32 != raw.len() {
            return Err("accept trunc or trailing bytes".into());
        }
        let accepted_at = u64::from_be_bytes(raw[off..off + 8].try_into().unwrap());
        off += 8;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&raw[off..off + 64]);
        off += 64;
        let mut accepter_pub = [0u8; 32];
        accepter_pub.copy_from_slice(&raw[off..off + 32]);
        Ok(Self {
            request_id,
            accepter_raven_id,
            requester_raven_id,
            accepted_at,
            signature,
            accepter_pub,
        })
    }
}

/// Opened pending request held locally until Accept / Decline / Block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingContactRequest {
    pub outer: RavenContactRequestV1,
    pub inner: ContactRequestInner,
    pub received_at: u64,
}

/// Local contact row produced on Accept (bound by Raven ID, not alias).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactBinding {
    pub raven_id: String,
    pub pub_hex: String,
    pub petname: String,
    pub verification_state: VerificationState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactAcceptOutcome {
    pub accept: ContactAcceptV1,
    pub binding: ContactBinding,
}

/// Admission record for one `(sender_pub, request_id)`. It outlives Accept /
/// Decline / Block so a replay of an already-resolved request is refused, and
/// it feeds the per-sender rolling ingest window. Pruned only once the signed
/// `expires_at` has passed (after which `verify_outer` rejects the request
/// anyway) *and* it has left the rate-limit window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRequestTombstone {
    pub sender_pub: [u8; 32],
    pub request_id: [u8; 16],
    pub received_at: u64,
    pub expires_at: u64,
}

/// Recipient-side inbox. Opens sealed requests locally; Bridge never sees plaintext.
#[derive(Default)]
pub struct ContactRequestInbox {
    pub pending: Vec<PendingContactRequest>,
    /// Every admitted request (pending or resolved) until it expires. A
    /// caller that persists `pending` MUST persist this alongside it, or
    /// resolved requests become replayable after a reload.
    pub seen: Vec<ContactRequestTombstone>,
    /// Senders blocked through this inbox. Blocking drops the sender's
    /// pending requests *and* tombstones (so a spammer's history can always be
    /// cleared by the user); this one entry then refuses every request from
    /// that key, replays included. Persist it alongside `seen`. Grows only by
    /// explicit user action.
    pub blocked_senders: Vec<[u8; 32]>,
}

/// Anti-spam caps for inbound contact requests (local only — no central moderation).
pub const CONTACT_REQ_MAX_PENDING: usize = 64;
pub const CONTACT_REQ_MAX_PER_SENDER: usize = 3;
/// Rolling window for per-sender ingest rate (ms).
pub const CONTACT_REQ_SENDER_WINDOW_MS: u64 = 3_600_000; // 1h
/// Admissions per sender per window, counting requests already accepted,
/// declined or blocked (not just the ones still pending).
pub const CONTACT_REQ_MAX_PER_SENDER_WINDOW: usize = 5;
/// Remembered admissions (pending or resolved, until expiry) per sender. A
/// sender at this bound is refused (`CONTACT_REQ_SENDER_CAP`) until its own
/// tombstones expire, so one key cannot eat the shared tombstone budget.
pub const CONTACT_REQ_MAX_TOMBSTONES_PER_SENDER: usize = 16;
/// Upper bound on remembered admissions across all senders; the inbox fails
/// closed when full. With the per-sender bound this takes
/// `4096 / 16 = 256` distinct paired senders to reach, and the user can free
/// space by blocking any of them ([`ContactRequestInbox::block_sender`]).
pub const CONTACT_REQ_MAX_TOMBSTONES: usize = 4096;

impl ContactRequestInbox {
    pub fn pending(&self) -> &[PendingContactRequest] {
        &self.pending
    }

    /// Drop pending requests whose signed validity window has ended
    /// (`now_ms > expires_at`, the same boundary as `verify_outer`). Only
    /// `pending` is touched: the replay tombstones in `seen` outlive the
    /// request and keep refusing re-deliveries.
    ///
    /// `ingest*` and `accept*` already call this; a UI that lists requests
    /// should too (or use [`Self::pending_at`]).
    pub fn prune_expired(&mut self, now_ms: u64) {
        self.pending.retain(|p| now_ms <= p.outer.expires_at);
    }

    /// Pending requests that are still inside their signed validity window.
    pub fn pending_at(&self, now_ms: u64) -> impl Iterator<Item = &PendingContactRequest> {
        self.pending
            .iter()
            .filter(move |p| now_ms <= p.outer.expires_at)
    }

    /// Verify outer + open with recipient key; dedup on
    /// `(sender_pub, request_id)`. Rejects replays of resolved requests and
    /// when inbox / per-sender caps are exceeded (anti-spam).
    pub fn ingest(
        &mut self,
        outer: RavenContactRequestV1,
        recipient: &Identity,
        now_ms: u64,
    ) -> Result<ContactRequestInner, String> {
        outer.verify_outer(now_ms)?;
        if outer.recipient_raven_id != recipient.address() {
            return Err("CONTACT_REQ_WRONG_RECIPIENT".into());
        }
        let inner = outer.open(recipient)?;
        self.ingest_opened(outer, inner, now_ms)
    }

    /// Verify, decrypt with an authenticated ATSAM root, then apply inbox
    /// deduplication and anti-spam policy. Failed authentication never inserts
    /// a durable request ID.
    pub fn ingest_with_atsam_root(
        &mut self,
        outer: RavenContactRequestV1,
        recipient: &Identity,
        root: &[u8; 32],
        now_ms: u64,
    ) -> Result<ContactRequestInner, String> {
        outer.verify_outer(now_ms)?;
        if outer.recipient_raven_id != recipient.address() {
            return Err("CONTACT_REQ_WRONG_RECIPIENT".into());
        }
        let inner = outer.open_with_atsam_root(recipient, root)?;
        self.ingest_opened(outer, inner, now_ms)
    }

    fn ingest_opened(
        &mut self,
        outer: RavenContactRequestV1,
        inner: ContactRequestInner,
        now_ms: u64,
    ) -> Result<ContactRequestInner, String> {
        if inner.request_id != outer.request_id {
            return Err("CONTACT_REQ_ID_MISMATCH".into());
        }
        let sender = outer.sender_pub;
        let request_id = outer.request_id;
        // Dead requests must not hold per-sender / global pending slots: an
        // unopened request that has expired could otherwise lock a sender out
        // (or, across many paired senders, the whole inbox) until it was
        // declined by hand.
        self.prune_expired(now_ms);
        // A blocked sender's tombstones were dropped at block time; this
        // entry is what now refuses its replays and new requests.
        if self.blocked_senders.contains(&sender) {
            return Err("CONTACT_REQ_BLOCKED".into());
        }
        // Idempotent multi-transport re-delivery of a request still pending.
        // Keyed on the sender too: a different sender reusing a visible
        // request_id must not shadow (and silently drop) the original.
        if self
            .pending
            .iter()
            .any(|p| p.outer.sender_pub == sender && p.outer.request_id == request_id)
        {
            return Ok(inner);
        }
        self.seen.retain(|t| {
            now_ms <= t.expires_at
                || now_ms.saturating_sub(t.received_at) <= CONTACT_REQ_SENDER_WINDOW_MS
        });
        if self
            .seen
            .iter()
            .any(|t| t.sender_pub == sender && t.request_id == request_id)
        {
            return Err("CONTACT_REQ_REPLAY".into());
        }
        // Per-sender limits first, so a sender over its own budget is told so
        // and never reaches (or consumes) the shared caps below.
        let pending_from_sender = self
            .pending
            .iter()
            .filter(|p| p.outer.sender_pub == sender)
            .count();
        let (seen_from_sender, in_window) = self
            .seen
            .iter()
            .filter(|t| t.sender_pub == sender)
            .fold((0usize, 0usize), |(all, win), t| {
                let recent = now_ms.saturating_sub(t.received_at) <= CONTACT_REQ_SENDER_WINDOW_MS;
                (all + 1, win + usize::from(recent))
            });
        if pending_from_sender >= CONTACT_REQ_MAX_PER_SENDER
            || seen_from_sender >= CONTACT_REQ_MAX_TOMBSTONES_PER_SENDER
        {
            return Err("CONTACT_REQ_SENDER_CAP".into());
        }
        if in_window >= CONTACT_REQ_MAX_PER_SENDER_WINDOW {
            return Err("CONTACT_REQ_RATE_LIMIT".into());
        }
        if self.pending.len() >= CONTACT_REQ_MAX_PENDING
            || self.seen.len() >= CONTACT_REQ_MAX_TOMBSTONES
        {
            return Err("CONTACT_REQ_INBOX_FULL".into());
        }
        self.seen.push(ContactRequestTombstone {
            sender_pub: sender,
            request_id,
            received_at: now_ms,
            expires_at: outer.expires_at,
        });
        self.pending.push(PendingContactRequest {
            outer,
            inner: inner.clone(),
            received_at: now_ms,
        });
        Ok(inner)
    }

    /// Remove one pending request. With `sender_pub == None` the request_id
    /// must be unambiguous; two senders sharing a request_id fail closed so a
    /// UI action can never land on a squatter's request by accident.
    fn take(
        &mut self,
        request_id: &[u8; 16],
        sender_pub: Option<&[u8; 32]>,
    ) -> Result<PendingContactRequest, String> {
        let hits: Vec<usize> = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                &p.outer.request_id == request_id
                    && sender_pub.is_none_or(|s| &p.outer.sender_pub == s)
            })
            .map(|(i, _)| i)
            .collect();
        match hits.as_slice() {
            [] => Err("CONTACT_REQ_NOT_FOUND".into()),
            [i] => Ok(self.pending.remove(*i)),
            _ => Err("CONTACT_REQ_AMBIGUOUS_ID".into()),
        }
    }

    /// Accept → signed ContactAcceptV1 + local binding (raven_id + petname).
    pub fn accept(
        &mut self,
        request_id: &[u8; 16],
        accepter: &Identity,
        petname: &str,
        now_ms: u64,
    ) -> Result<ContactAcceptOutcome, String> {
        self.accept_pending(request_id, None, accepter, petname, now_ms)
    }

    /// [`Self::accept`] for a specific sender (needed when two senders share
    /// a request_id).
    pub fn accept_from(
        &mut self,
        sender_pub: &[u8; 32],
        request_id: &[u8; 16],
        accepter: &Identity,
        petname: &str,
        now_ms: u64,
    ) -> Result<ContactAcceptOutcome, String> {
        self.accept_pending(request_id, Some(sender_pub), accepter, petname, now_ms)
    }

    fn accept_pending(
        &mut self,
        request_id: &[u8; 16],
        sender_pub: Option<&[u8; 32]>,
        accepter: &Identity,
        petname: &str,
        now_ms: u64,
    ) -> Result<ContactAcceptOutcome, String> {
        let pet = petname.trim();
        if pet.is_empty() {
            return Err("CONTACT_ACCEPT_PETNAME_REQUIRED".into());
        }
        let pending = self.take(request_id, sender_pub)?;
        // The sender signed a validity window; accepting after it would mint a
        // trusted binding and a signed accept for a request that no longer
        // exists. The dead entry is removed by `take`; the tombstone stays.
        if now_ms > pending.outer.expires_at {
            return Err("CONTACT_REQ_EXPIRED".into());
        }
        let accept = ContactAcceptV1 {
            request_id: pending.outer.request_id,
            accepter_raven_id: String::new(),
            requester_raven_id: pending.inner.sender_raven_id.clone(),
            accepted_at: now_ms,
            signature: [0u8; 64],
            accepter_pub: [0u8; 32],
        }
        .sign(accepter)?;
        let binding = ContactBinding {
            raven_id: pending.inner.sender_raven_id,
            pub_hex: hex::encode(pending.outer.sender_pub),
            petname: pet.to_string(),
            verification_state: VerificationState::TrustedContact,
        };
        Ok(ContactAcceptOutcome { accept, binding })
    }

    pub fn decline(&mut self, request_id: &[u8; 16]) -> Result<(), String> {
        let _ = self.take(request_id, None)?;
        Ok(())
    }

    pub fn decline_from(
        &mut self,
        sender_pub: &[u8; 32],
        request_id: &[u8; 16],
    ) -> Result<(), String> {
        let _ = self.take(request_id, Some(sender_pub))?;
        Ok(())
    }

    /// Local block — no central moderation. Blocks the sender of this pending
    /// request; see [`Self::block_sender`].
    pub fn block(&mut self, request_id: &[u8; 16], blocks: &mut BlockList) -> Result<(), String> {
        let pending = self.take(request_id, None)?;
        self.block_sender(&pending.outer.sender_pub, blocks);
        Ok(())
    }

    pub fn block_from(
        &mut self,
        sender_pub: &[u8; 32],
        request_id: &[u8; 16],
        blocks: &mut BlockList,
    ) -> Result<(), String> {
        let pending = self.take(request_id, Some(sender_pub))?;
        self.block_sender(&pending.outer.sender_pub, blocks);
        Ok(())
    }

    /// Block a sender key outright (it need not have a request pending — e.g.
    /// a spammer whose requests were all declined). Drops all of its pending
    /// requests and tombstones, freeing shared inbox capacity, records it in
    /// `blocked_senders` (which refuses its future requests and replays) and
    /// adds it to the local block list.
    pub fn block_sender(&mut self, sender_pub: &[u8; 32], blocks: &mut BlockList) {
        self.pending.retain(|p| &p.outer.sender_pub != sender_pub);
        self.seen.retain(|t| &t.sender_pub != sender_pub);
        if !self.blocked_senders.contains(sender_pub) {
            self.blocked_senders.push(*sender_pub);
        }
        blocks.block(&hex::encode(sender_pub));
    }

    /// Undo [`Self::block_sender`] for this inbox. The sender's earlier
    /// tombstones were dropped when it was blocked, so its already-resolved
    /// requests that have not yet expired can be delivered again; that is the
    /// user's explicit choice. (The block-list entry is the caller's to remove.)
    pub fn unblock_sender(&mut self, sender_pub: &[u8; 32]) {
        self.blocked_senders.retain(|s| s != sender_pub);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: [u8; 32] = [0x5D; 32];
    const T0: u64 = 1_700_000_000_000;
    const DAY_MS: u64 = 24 * 3_600_000;

    fn request(
        sender: &Identity,
        recipient: &Identity,
        request_id: [u8; 16],
        created_at: u64,
        expires_at: u64,
    ) -> RavenContactRequestV1 {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&request_id[..12]);
        RavenContactRequestV1::create_with_atsam_root(
            sender,
            &recipient.public_key_bytes(),
            &recipient.address(),
            ContactRequestInner {
                request_id,
                sender_raven_id: sender.address(),
                sender_display_name: "Ada".into(),
                sender_aliases: vec![],
                sender_profile_digest: [0u8; 32],
                optional_message: String::new(),
                created_at,
                expires_at,
            },
            &ROOT,
            0,
            &nonce,
        )
        .unwrap()
    }

    fn rid(n: u8) -> [u8; 16] {
        let mut id = [0x40u8; 16];
        id[0] = n;
        id
    }

    #[test]
    fn rate_window_counts_resolved_requests() {
        let sender = Identity::from_seed(&[0x01; 32]);
        let me = Identity::from_seed(&[0x02; 32]);
        let mut inbox = ContactRequestInbox::default();
        // Three requests, all declined: the pending cap never trips, but the
        // rolling window must still remember them.
        for n in 0..3 {
            let req = request(&sender, &me, rid(n), T0, T0 + DAY_MS);
            inbox.ingest_with_atsam_root(req, &me, &ROOT, T0).unwrap();
            inbox.decline(&rid(n)).unwrap();
        }
        for n in 3..5 {
            let req = request(&sender, &me, rid(n), T0, T0 + DAY_MS);
            inbox.ingest_with_atsam_root(req, &me, &ROOT, T0).unwrap();
        }
        assert_eq!(inbox.pending().len(), 2);
        let sixth = request(&sender, &me, rid(5), T0, T0 + DAY_MS);
        let err = inbox
            .ingest_with_atsam_root(sixth.clone(), &me, &ROOT, T0)
            .unwrap_err();
        assert_eq!(err, "CONTACT_REQ_RATE_LIMIT");
        // Once the window has passed the sender may ask again.
        let later = T0 + CONTACT_REQ_SENDER_WINDOW_MS + 1;
        inbox
            .ingest_with_atsam_root(sixth, &me, &ROOT, later)
            .unwrap();
    }

    #[test]
    fn replay_of_resolved_request_is_refused() {
        let sender = Identity::from_seed(&[0x03; 32]);
        let me = Identity::from_seed(&[0x04; 32]);
        let mut inbox = ContactRequestInbox::default();

        let declined = request(&sender, &me, rid(1), T0, T0 + DAY_MS);
        inbox
            .ingest_with_atsam_root(declined.clone(), &me, &ROOT, T0)
            .unwrap();
        inbox.decline(&rid(1)).unwrap();
        let err = inbox
            .ingest_with_atsam_root(declined, &me, &ROOT, T0 + 1)
            .unwrap_err();
        assert_eq!(err, "CONTACT_REQ_REPLAY");

        let accepted = request(&sender, &me, rid(2), T0, T0 + DAY_MS);
        inbox
            .ingest_with_atsam_root(accepted.clone(), &me, &ROOT, T0)
            .unwrap();
        inbox.accept(&rid(2), &me, "Ada", T0).unwrap();
        let err = inbox
            .ingest_with_atsam_root(accepted, &me, &ROOT, T0 + 1)
            .unwrap_err();
        assert_eq!(err, "CONTACT_REQ_REPLAY");
        assert!(inbox.pending().is_empty());
    }

    #[test]
    fn redelivery_of_pending_request_is_idempotent() {
        let sender = Identity::from_seed(&[0x05; 32]);
        let me = Identity::from_seed(&[0x06; 32]);
        let mut inbox = ContactRequestInbox::default();
        let req = request(&sender, &me, rid(1), T0, T0 + DAY_MS);
        inbox
            .ingest_with_atsam_root(req.clone(), &me, &ROOT, T0)
            .unwrap();
        inbox
            .ingest_with_atsam_root(req, &me, &ROOT, T0 + 5)
            .unwrap();
        assert_eq!(inbox.pending().len(), 1);
        assert_eq!(inbox.seen.len(), 1);
    }

    #[test]
    fn squatted_request_id_does_not_drop_the_original() {
        let squatter = Identity::from_seed(&[0x07; 32]);
        let ada = Identity::from_seed(&[0x08; 32]);
        let me = Identity::from_seed(&[0x09; 32]);
        let mut inbox = ContactRequestInbox::default();
        let shared = rid(9);
        inbox
            .ingest_with_atsam_root(
                request(&squatter, &me, shared, T0, T0 + DAY_MS),
                &me,
                &ROOT,
                T0,
            )
            .unwrap();
        inbox
            .ingest_with_atsam_root(request(&ada, &me, shared, T0, T0 + DAY_MS), &me, &ROOT, T0)
            .unwrap();
        assert_eq!(inbox.pending().len(), 2);
        // An unqualified action must not guess which one the user meant.
        assert_eq!(
            inbox.accept(&shared, &me, "Ada", T0).unwrap_err(),
            "CONTACT_REQ_AMBIGUOUS_ID"
        );
        assert_eq!(inbox.pending().len(), 2);
        let outcome = inbox
            .accept_from(&ada.public_key_bytes(), &shared, &me, "Ada", T0)
            .unwrap();
        assert_eq!(outcome.binding.raven_id, ada.address());
        let mut blocks = BlockList::default();
        inbox.block(&shared, &mut blocks).unwrap();
        assert!(blocks.is_blocked(&hex::encode(squatter.public_key_bytes())));
        assert!(inbox.pending().is_empty());
    }

    #[test]
    fn empty_petname_keeps_request_pending() {
        let sender = Identity::from_seed(&[0x0A; 32]);
        let me = Identity::from_seed(&[0x0B; 32]);
        let mut inbox = ContactRequestInbox::default();
        inbox
            .ingest_with_atsam_root(
                request(&sender, &me, rid(1), T0, T0 + DAY_MS),
                &me,
                &ROOT,
                T0,
            )
            .unwrap();
        assert_eq!(
            inbox.accept(&rid(1), &me, "  ", T0).unwrap_err(),
            "CONTACT_ACCEPT_PETNAME_REQUIRED"
        );
        assert_eq!(inbox.pending().len(), 1);
    }

    #[test]
    fn expired_pending_requests_free_their_slots() {
        // Regression: `pending` was never pruned, so three requests the user
        // never opened locked their sender out (CONTACT_REQ_SENDER_CAP) long
        // after their signed validity window had ended.
        let sender = Identity::from_seed(&[0x14; 32]);
        let me = Identity::from_seed(&[0x15; 32]);
        let mut inbox = ContactRequestInbox::default();
        let short_lived = 60_000;
        for n in 0..CONTACT_REQ_MAX_PER_SENDER as u8 {
            let req = request(&sender, &me, rid(n), T0, T0 + short_lived);
            inbox.ingest_with_atsam_root(req, &me, &ROOT, T0).unwrap();
        }
        let next_id = rid(CONTACT_REQ_MAX_PER_SENDER as u8);
        let fresh_at = |now| request(&sender, &me, next_id, now, now + DAY_MS);
        // Still live at the boundary: the cap still applies.
        let at_boundary = T0 + short_lived;
        assert_eq!(
            inbox
                .ingest_with_atsam_root(fresh_at(at_boundary), &me, &ROOT, at_boundary)
                .unwrap_err(),
            "CONTACT_REQ_SENDER_CAP"
        );
        // One millisecond later the three are dead and release their slots.
        let later = at_boundary + 1;
        assert_eq!(inbox.pending_at(later).count(), 0);
        inbox
            .ingest_with_atsam_root(fresh_at(later), &me, &ROOT, later)
            .unwrap();
        assert_eq!(inbox.pending().len(), 1);
        // Replay tombstones outlive the request they describe.
        assert_eq!(inbox.seen.len(), CONTACT_REQ_MAX_PER_SENDER + 1);
        assert_eq!(inbox.pending_at(later).count(), 1);
    }

    #[test]
    fn expired_pending_request_cannot_be_accepted() {
        let sender = Identity::from_seed(&[0x16; 32]);
        let me = Identity::from_seed(&[0x17; 32]);
        let mut inbox = ContactRequestInbox::default();
        let expires = T0 + 60_000;
        for n in 0..2 {
            let req = request(&sender, &me, rid(n), T0, expires);
            inbox.ingest_with_atsam_root(req, &me, &ROOT, T0).unwrap();
        }
        // The signed window includes its last millisecond...
        inbox.accept(&rid(0), &me, "Ada", expires).unwrap();
        // ...but not the next one: no binding, no signed accept, entry gone.
        assert_eq!(
            inbox.accept(&rid(1), &me, "Ada", expires + 1).unwrap_err(),
            "CONTACT_REQ_EXPIRED"
        );
        assert!(inbox.pending().is_empty());
        assert_eq!(inbox.seen.len(), 2, "tombstones keep replay protection");
        // A dead entry that is never accepted is dropped by an explicit prune.
        let req = request(&sender, &me, rid(2), T0, expires);
        inbox.ingest_with_atsam_root(req, &me, &ROOT, T0).unwrap();
        inbox.prune_expired(expires + 1);
        assert!(inbox.pending().is_empty());
    }

    /// A full tombstone set as the per-sender bound allows it to fill:
    /// `CONTACT_REQ_MAX_TOMBSTONES / CONTACT_REQ_MAX_TOMBSTONES_PER_SENDER`
    /// distinct senders (`[0x80 + k, 0xEE, ..]`), each at its own bound.
    fn full_tombstones(received_at: u64, expires_at: u64) -> Vec<ContactRequestTombstone> {
        (0..CONTACT_REQ_MAX_TOMBSTONES)
            .map(|i| {
                let mut sender_pub = [0xEE; 32];
                sender_pub[..2].copy_from_slice(
                    &((i / CONTACT_REQ_MAX_TOMBSTONES_PER_SENDER) as u16).to_be_bytes(),
                );
                ContactRequestTombstone {
                    sender_pub,
                    request_id: (i as u128).to_be_bytes(),
                    received_at,
                    expires_at,
                }
            })
            .collect()
    }

    #[test]
    fn per_sender_tombstone_bound_contains_a_spammer() {
        // Regression: tombstones were bounded only globally (4096) and live
        // for the sender-chosen lifetime (up to 30 days), so a couple of
        // paired senders pacing requests under the hourly rate limit and
        // getting them declined could fill the set and lock *everyone* out
        // with CONTACT_REQ_INBOX_FULL.
        let spammer = Identity::from_seed(&[0x11; 32]);
        let friend = Identity::from_seed(&[0x12; 32]);
        let me = Identity::from_seed(&[0x13; 32]);
        let mut inbox = ContactRequestInbox::default();
        let step = 20 * 60_000; // three per hour: under the rate window
        let life = CONTACT_REQ_MAX_LIFETIME_MS;
        let mut refused_at = None;
        for n in 0..40u8 {
            let t = T0 + u64::from(n) * step;
            match inbox.ingest_with_atsam_root(
                request(&spammer, &me, rid(n), t, t + life),
                &me,
                &ROOT,
                t,
            ) {
                Ok(_) => inbox.decline(&rid(n)).unwrap(),
                Err(e) => {
                    assert_eq!(e, "CONTACT_REQ_SENDER_CAP");
                    refused_at.get_or_insert(n);
                }
            }
        }
        assert_eq!(
            refused_at,
            Some(CONTACT_REQ_MAX_TOMBSTONES_PER_SENDER as u8)
        );
        assert_eq!(inbox.seen.len(), CONTACT_REQ_MAX_TOMBSTONES_PER_SENDER);
        // Everyone else is unaffected.
        let t = T0 + 40 * step;
        inbox
            .ingest_with_atsam_root(request(&friend, &me, rid(1), t, t + DAY_MS), &me, &ROOT, t)
            .unwrap();
        // The spammer's budget comes back only as its own tombstones expire.
        let after = T0 + life + 1;
        inbox
            .ingest_with_atsam_root(
                request(&spammer, &me, rid(99), after, after + DAY_MS),
                &me,
                &ROOT,
                after,
            )
            .unwrap();
    }

    #[test]
    fn blocking_frees_tombstones_but_still_refuses_replay() {
        let spammer = Identity::from_seed(&[0x14; 32]);
        let friend = Identity::from_seed(&[0x15; 32]);
        let me = Identity::from_seed(&[0x16; 32]);
        let mut inbox = ContactRequestInbox::default();
        let declined = request(&spammer, &me, rid(1), T0, T0 + DAY_MS);
        inbox
            .ingest_with_atsam_root(declined.clone(), &me, &ROOT, T0)
            .unwrap();
        inbox.decline(&rid(1)).unwrap();
        let pending = request(&spammer, &me, rid(2), T0, T0 + DAY_MS);
        inbox
            .ingest_with_atsam_root(pending.clone(), &me, &ROOT, T0)
            .unwrap();
        // Fill the rest of the shared budget with other senders' tombstones.
        let mut filler = full_tombstones(T0, T0 + DAY_MS);
        filler.truncate(CONTACT_REQ_MAX_TOMBSTONES - inbox.seen.len());
        inbox.seen.extend(filler);
        let err = inbox
            .ingest_with_atsam_root(
                request(&friend, &me, rid(3), T0, T0 + DAY_MS),
                &me,
                &ROOT,
                T0,
            )
            .unwrap_err();
        assert_eq!(err, "CONTACT_REQ_INBOX_FULL");

        // The user can clear it: blocking drops the sender's pending requests
        // and tombstones (no pending request is needed to block)...
        let mut blocks = BlockList::default();
        inbox.block_sender(&spammer.public_key_bytes(), &mut blocks);
        assert!(blocks.is_blocked(&hex::encode(spammer.public_key_bytes())));
        assert!(inbox.pending().is_empty());
        assert!(inbox
            .seen
            .iter()
            .all(|t| t.sender_pub != spammer.public_key_bytes()));
        inbox
            .ingest_with_atsam_root(
                request(&friend, &me, rid(3), T0, T0 + DAY_MS),
                &me,
                &ROOT,
                T0,
            )
            .unwrap();
        // ...while its resolved and pending requests stay unreplayable.
        for replay in [declined, pending] {
            let err = inbox
                .ingest_with_atsam_root(replay, &me, &ROOT, T0 + 1)
                .unwrap_err();
            assert_eq!(err, "CONTACT_REQ_BLOCKED");
        }
        assert_eq!(inbox.pending().len(), 1);
        inbox.unblock_sender(&spammer.public_key_bytes());
        assert!(inbox.blocked_senders.is_empty());
    }

    #[test]
    fn block_by_request_purges_that_senders_other_requests() {
        let spammer = Identity::from_seed(&[0x17; 32]);
        let me = Identity::from_seed(&[0x18; 32]);
        let mut inbox = ContactRequestInbox::default();
        for n in 0..3 {
            inbox
                .ingest_with_atsam_root(
                    request(&spammer, &me, rid(n), T0, T0 + DAY_MS),
                    &me,
                    &ROOT,
                    T0,
                )
                .unwrap();
        }
        let mut blocks = BlockList::default();
        inbox.block(&rid(0), &mut blocks).unwrap();
        assert!(inbox.pending().is_empty());
        assert!(inbox.seen.is_empty());
        assert_eq!(inbox.blocked_senders, vec![spammer.public_key_bytes()]);
    }

    #[test]
    fn full_tombstone_set_fails_closed() {
        let sender = Identity::from_seed(&[0x0C; 32]);
        let me = Identity::from_seed(&[0x0D; 32]);
        let mut inbox = ContactRequestInbox {
            seen: full_tombstones(T0, T0 + DAY_MS),
            ..Default::default()
        };
        let err = inbox
            .ingest_with_atsam_root(
                request(&sender, &me, rid(1), T0, T0 + DAY_MS),
                &me,
                &ROOT,
                T0,
            )
            .unwrap_err();
        assert_eq!(err, "CONTACT_REQ_INBOX_FULL");
        // Expired, out-of-window tombstones are pruned and free the space.
        let later = T0 + DAY_MS + CONTACT_REQ_SENDER_WINDOW_MS + 1;
        let req = request(&sender, &me, rid(2), later, later + DAY_MS);
        inbox
            .ingest_with_atsam_root(req, &me, &ROOT, later)
            .unwrap();
        assert_eq!(inbox.seen.len(), 1);
    }

    #[test]
    fn verify_outer_bounds_lifetime_and_future_created_at() {
        let sender = Identity::from_seed(&[0x0E; 32]);
        let me = Identity::from_seed(&[0x0F; 32]);
        let mut long = request(&sender, &me, rid(1), T0, T0 + DAY_MS);
        long.expires_at = T0 + CONTACT_REQ_MAX_LIFETIME_MS + 1;
        long.sender_authentication = sender.sign(&long.signing_bytes().unwrap());
        assert_eq!(
            long.verify_outer(T0).unwrap_err(),
            "CONTACT_REQ_LIFETIME_TOO_LONG"
        );

        let future = T0 + CONTACT_REQ_MAX_FUTURE_SKEW_MS + 1;
        let early = request(&sender, &me, rid(2), future, future + DAY_MS);
        assert_eq!(
            early.verify_outer(T0).unwrap_err(),
            "CONTACT_REQ_NOT_YET_VALID"
        );
        early.verify_outer(future).unwrap();

        let err = RavenContactRequestV1::create_with_atsam_root(
            &sender,
            &me.public_key_bytes(),
            &me.address(),
            ContactRequestInner {
                request_id: rid(3),
                sender_raven_id: sender.address(),
                sender_display_name: String::new(),
                sender_aliases: vec![],
                sender_profile_digest: [0u8; 32],
                optional_message: String::new(),
                created_at: T0,
                expires_at: T0 + CONTACT_REQ_MAX_LIFETIME_MS + 1,
            },
            &ROOT,
            0,
            &[0u8; 12],
        )
        .unwrap_err();
        assert_eq!(err, "CONTACT_REQ_LIFETIME_TOO_LONG");
    }

    #[test]
    fn accept_verify_binds_accepter_address() {
        let victim = Identity::from_seed(&[0x10; 32]);
        let attacker = Identity::from_seed(&[0x11; 32]);
        let requester = Identity::from_seed(&[0x12; 32]);
        let mut spoofed = ContactAcceptV1 {
            request_id: rid(1),
            accepter_raven_id: victim.address(),
            requester_raven_id: requester.address(),
            accepted_at: T0,
            signature: [0u8; 64],
            accepter_pub: attacker.public_key_bytes(),
        };
        spoofed.signature = attacker.sign(&spoofed.signing_bytes().unwrap());
        assert_eq!(
            spoofed.verify().unwrap_err(),
            "CONTACT_ACCEPT_ADDR_MISMATCH"
        );
    }

    #[test]
    fn accept_verify_for_request_binds_request() {
        let requester = Identity::from_seed(&[0x13; 32]);
        let me = Identity::from_seed(&[0x14; 32]);
        let other = Identity::from_seed(&[0x15; 32]);
        let sent = request(&requester, &me, rid(1), T0, T0 + DAY_MS);
        let mut inbox = ContactRequestInbox::default();
        inbox
            .ingest_with_atsam_root(sent.clone(), &me, &ROOT, T0)
            .unwrap();
        let accept = inbox.accept(&rid(1), &me, "Req", T0).unwrap().accept;
        accept.verify_for_request(&sent).unwrap();

        let unrelated = request(&requester, &me, rid(2), T0, T0 + DAY_MS);
        assert_eq!(
            accept.verify_for_request(&unrelated).unwrap_err(),
            "CONTACT_ACCEPT_BINDING_MISMATCH"
        );
        // A validly self-bound accept from someone the request never went to.
        let foreign = ContactAcceptV1 {
            request_id: rid(1),
            accepter_raven_id: String::new(),
            requester_raven_id: requester.address(),
            accepted_at: T0,
            signature: [0u8; 64],
            accepter_pub: [0u8; 32],
        }
        .sign(&other)
        .unwrap();
        foreign.verify().unwrap();
        assert_eq!(
            foreign.verify_for_request(&sent).unwrap_err(),
            "CONTACT_ACCEPT_BINDING_MISMATCH"
        );
    }

    #[test]
    fn accept_decode_wire_is_exact() {
        let me = Identity::from_seed(&[0x16; 32]);
        let accept = ContactAcceptV1 {
            request_id: rid(1),
            accepter_raven_id: String::new(),
            requester_raven_id: "rvn1requester".into(),
            accepted_at: T0,
            signature: [0u8; 64],
            accepter_pub: [0u8; 32],
        }
        .sign(&me)
        .unwrap();
        let mut wire = accept.encode_wire().unwrap();
        assert_eq!(ContactAcceptV1::decode_wire(&wire).unwrap(), accept);
        wire.push(0);
        assert!(ContactAcceptV1::decode_wire(&wire).is_err());
    }
}
