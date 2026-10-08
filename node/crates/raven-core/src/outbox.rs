//! Outbox policy and delivery bookkeeping shared by `raven send` (ash) and the
//! raven-node background outbox worker (transports design 2026-10 §2.4-§2.5).
//!
//! Both processes serialise their work on one peer with the same
//! [`PeerSendLock`], verify a sealed ACK with the same
//! [`finish_outbound_delivered`] (including the check that the ACK confirms
//! *this* message), and give a message up with the same
//! [`mark_outbound_undelivered`]. A message is therefore delivered, expired or
//! failed in exactly the same way whichever of them saw the outcome.
//!
//! Nothing here does network I/O, and nothing runs inside a session-store
//! transaction: the store commits before any callback dials.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::device_cert::DeviceCertificate;
use crate::device_sync::RevocationStore;
use crate::envelope::{EnvType, Envelope};
use crate::indexed_session_store::{
    EndpointAckAcceptance, EndpointDeliveryState, EndpointOutboundKind, IndexedSessionRecordKey,
    IndexedSessionStore,
};
use crate::paths::DataDirLock;

/// How long a sealed message or ACK envelope stays valid: `min(session end,
/// now + ENVELOPE_VALIDITY_MS)` (transports design F2, owner decision Q4: no
/// automatic re-seal after expiry). The frozen profile only requires the
/// envelope to end inside its session and to live at most
/// `MAX_ENDPOINT_ENVELOPE_LIFETIME_MS` (7 days); sessions this node initiates
/// last 24 h, so in practice the session end decides. Was 1 h before P2a
/// (docs/WAIVER_LAN_DIRECT_P2A_AMENDMENT_DRAFT.md).
pub const ENVELOPE_VALIDITY_MS: u64 = 24 * 60 * 60 * 1_000;

const _: () = assert!(
    ENVELOPE_VALIDITY_MS <= crate::indexed_session_store::MAX_ENDPOINT_ENVELOPE_LIFETIME_MS
);

/// Expiry for an envelope sealed at `now_ms` under a session that ends at
/// `session_expires_ms`. `Err` once the session has no time left.
pub fn envelope_expires_at(now_ms: u64, session_expires_ms: u64) -> Result<u64, String> {
    let expires = now_ms
        .saturating_add(ENVELOPE_VALIDITY_MS)
        .min(session_expires_ms);
    if expires <= now_ms {
        return Err("session expired".into());
    }
    Ok(expires)
}

// ── Per-peer send lock ───────────────────────────────────────────────────────

/// Cross-process lock serialising the stateful part of every send to one peer
/// from this profile: pairing (first contact), the retry of an earlier queued
/// message, staging a new one and its dial. `ash send` and the raven-node
/// outbox worker take the very same lock file, so they never dial the same
/// staged bytes at the same time nor race for the one prepared-message slot.
///
/// Without it, concurrent senders interleave in ways the store can only
/// refuse: two first-contact sends each ran PairInit and left two sessions the
/// peer then refused, and a burst of sends fought over the single
/// outstanding-message slot, so some of them lost their text.
pub struct PeerSendLock {
    _lock: DataDirLock,
}

impl PeerSendLock {
    /// The lock file for `peer_device`: dot-prefixed `*.lock.sqlite`, the inert
    /// lock-database shape the first-install check already tolerates.
    pub fn file_name(peer_device: &[u8; 32]) -> String {
        format!(".send_{}.lock.sqlite", hex::encode(peer_device))
    }

    /// Wait at most `wait` for the other holder. The error is the raw lock
    /// text; [`send_lock_busy`] tells "held by someone else" apart.
    pub fn acquire_within(
        data_dir: &Path,
        peer_device: &[u8; 32],
        wait: Duration,
    ) -> Result<Self, String> {
        DataDirLock::acquire_within(data_dir, &Self::file_name(peer_device), wait)
            .map(|_lock| Self { _lock })
    }
}

/// True when a [`PeerSendLock::acquire_within`] error means another sender
/// (ash or the outbox worker) still holds the lock.
pub fn send_lock_busy(err: &str) -> bool {
    err.contains("database is locked") || err.contains("database is busy")
}

// ── ACK acceptance and history ───────────────────────────────────────────────

/// Start of the error [`finish_outbound_delivered`] returns when the ACK that
/// came back belongs to another outstanding message of the session.
pub const ACK_FOR_ANOTHER_MESSAGE: &str = "ACK_FOR_ANOTHER_MESSAGE";

/// History delivery states written for an outbound message that was given up.
pub const HISTORY_FAILED: &str = "failed";
/// Its envelope expired before any ACK came back (shown as "expired, not
/// delivered").
pub const HISTORY_EXPIRED: &str = "expired";
/// The user cancelled it (`raven outbox cancel`).
pub const HISTORY_CANCELLED: &str = "cancelled";

/// Lineage-aware peer denial, the same predicate the receive side uses
/// (`RevocationStore::denies_certificate`): legacy `(user, device_id)` records
/// plus RVDR1 claims covering the device id, either device key or the cert
/// hash.
pub fn peer_lineage_denied(data_dir: &Path, peer_cert: &DeviceCertificate) -> Result<bool, String> {
    RevocationStore::load_checked(data_dir)?.denies_certificate(peer_cert)
}

/// The first packed ACK envelope among dial replies.
pub fn first_ack_frame(frames: &[Vec<u8>]) -> Option<&[u8]> {
    ack_frames(frames).into_iter().next()
}

/// Every packed ACK envelope among dial replies (a dial may carry several
/// objects, each answered by its own ACK).
pub fn ack_frames(frames: &[Vec<u8>]) -> Vec<&[u8]> {
    frames
        .iter()
        .filter(|packed| {
            Envelope::unpack(packed).is_some_and(|env| env.env_type == EnvType::Ack as u8)
        })
        .map(Vec::as_slice)
        .collect()
}

/// Why [`accept_sealed_ack`] did not accept an ACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckRejected {
    /// Not sealed under this session: try the next candidate session.
    OtherSession,
    /// Refused by the store or the revocation check (redacted text).
    Refused(String),
}

/// Verify one sealed ACK under `record_key` (session-bound device, inner and
/// outer signatures, an outstanding row, replay checks, the peer lineage) and
/// return the message it confirms. The one ACK check `raven send` and the
/// outbox worker share; a message is delivered only when an ACK this accepts
/// names *its* id.
pub fn accept_sealed_ack(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    record_key: &IndexedSessionRecordKey,
    peer_cert: &DeviceCertificate,
    ack: &[u8],
) -> Result<[u8; 16], AckRejected> {
    let denied = peer_lineage_denied(data_dir, peer_cert).map_err(AckRejected::Refused)?;
    match store.accept_ack_envelope(record_key, ack, peer_cert, denied, wall_clock_ms()) {
        Ok(
            EndpointAckAcceptance::Committed {
                acked_message_id, ..
            }
            | EndpointAckAcceptance::Duplicate {
                acked_message_id, ..
            },
        ) => Ok(acked_message_id),
        Err(crate::IndexedSessionStoreError::RouteTagMismatch) => Err(AckRejected::OtherSession),
        Err(e) => Err(AckRejected::Refused(e.redacted_display())),
    }
}

/// Record that `message_id` was delivered (an accepted ACK names it): an
/// outbox row still `Prepared` is settled so nothing dials it again, the
/// history row becomes `delivered` (never back again, see
/// `chat_history::delivery_after`) and the staged body is cleared.
pub fn record_outbound_delivered(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    message_id: &[u8; 16],
) -> Result<(), String> {
    store
        .settle_delivered_outbound(session_id, message_id)
        .map_err(|e| e.redacted_display())?;
    record_inbound_ack_delivery(data_dir, peer_pub, session_id, message_id)
}

/// Did an accepted ACK already deliver this message (outstanding row
/// `Delivered` or `Read`)? Checked before every retry, by `raven send` and the
/// worker alike: a delivered message is never dialled again.
pub fn outbound_already_delivered(
    store: &IndexedSessionStore,
    session_id: &[u8; 32],
    message_id: &[u8; 16],
    recipient: &[u8; 32],
) -> Result<bool, String> {
    Ok(matches!(
        store
            .outstanding_delivery_state(session_id, message_id, recipient)
            .map_err(|e| e.redacted_display())?,
        Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)
    ))
}

/// Verify the sealed `ack` for `message_id` and record the delivery: the store
/// accepts the ACK ([`accept_sealed_ack`]), the history row becomes
/// `delivered` and the staged body is cleared.
///
/// An ACK the store accepts for *another* outstanding message of the session
/// marks that one delivered and returns [`ACK_FOR_ANOTHER_MESSAGE`]: it must
/// never make this message read "delivered".
#[allow(clippy::too_many_arguments)]
pub fn finish_outbound_delivered(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    record_key: &IndexedSessionRecordKey,
    peer_cert: &DeviceCertificate,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    ack: &[u8],
    now_ms: u64,
) -> Result<(), String> {
    // History body must exist before Delivered is committed.
    crate::lan_dispatch::ensure_outbound_queued_history(
        data_dir,
        &peer_cert.device_ed_pub,
        session_id,
        object_digest,
        message_id,
        now_ms,
        None,
    )?;
    let acked =
        accept_sealed_ack(data_dir, store, record_key, peer_cert, ack).map_err(|e| match e {
            AckRejected::OtherSession => {
                crate::IndexedSessionStoreError::RouteTagMismatch.redacted_display()
            }
            AckRejected::Refused(text) => text,
        })?;
    if acked != *message_id {
        // A genuine ACK (the store matched it to an outstanding message of this
        // session) but for ANOTHER message: that one is delivered, this one is
        // still unconfirmed.
        let _ = record_outbound_delivered(
            data_dir,
            store,
            &peer_cert.device_ed_pub,
            session_id,
            &acked,
        );
        return Err(format!(
            "{ACK_FOR_ANOTHER_MESSAGE}: the acknowledgement that came back is for message \
             {}…, not for this one",
            hex::encode(&acked[..4])
        ));
    }
    store
        .settle_delivered_outbound(session_id, message_id)
        .map_err(|e| e.redacted_display())?;
    crate::lan_dispatch::mark_lan_chat_history_delivery(
        data_dir,
        "out",
        &peer_cert.device_ed_pub,
        message_id,
        "delivered",
    )?;
    crate::chat_history::clear_staged_outbound_body(data_dir, message_id)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Record an outbound message that will never be delivered: the history row
/// takes `delivery` ([`HISTORY_FAILED`], [`HISTORY_EXPIRED`] or
/// [`HISTORY_CANCELLED`]) with the staged body, and the stage is cleared. The
/// staged binding must match exactly. A row already `delivered` stays so.
pub fn mark_outbound_undelivered(
    data_dir: &Path,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    delivery: &str,
) -> Result<(), String> {
    if let Some(staged) = crate::chat_history::load_staged_outbound_body(data_dir, message_id)
        .map_err(|e| e.to_string())?
    {
        let bound = staged
            .peer_pub_hex
            .eq_ignore_ascii_case(&hex::encode(peer_pub))
            && staged
                .session_id_hex
                .eq_ignore_ascii_case(&hex::encode(session_id))
            && staged
                .object_digest_hex
                .eq_ignore_ascii_case(&hex::encode(object_digest))
            && staged
                .message_id_hex
                .eq_ignore_ascii_case(&hex::encode(message_id));
        if !bound {
            return Err(format!(
                "staged outbound binding mismatch on fail mid={}",
                hex::encode(message_id)
            ));
        }
        crate::lan_dispatch::persist_lan_chat_history(
            data_dir,
            "out",
            peer_pub,
            message_id,
            staged.created_at_ms,
            delivery,
            staged.body.as_bytes(),
        )?;
    } else {
        crate::lan_dispatch::mark_lan_chat_history_delivery(
            data_dir, "out", peer_pub, message_id, delivery,
        )?;
    }
    crate::chat_history::clear_staged_outbound_body(data_dir, message_id)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// What [`give_up_outbound`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GiveUp {
    /// Abandoned; the history says why.
    Abandoned,
    /// An ACK delivered it in the meantime: nothing was abandoned, and the
    /// history now says delivered.
    Delivered,
}

/// Abandon one undelivered message and record why (`delivery`), unless an ACK
/// delivered it in the meantime: then the delivery is recorded instead. The
/// one give-up step `raven send` and the worker share.
#[allow(clippy::too_many_arguments)]
pub fn give_up_outbound(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    record_key: &IndexedSessionRecordKey,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    delivery: &str,
) -> Result<GiveUp, String> {
    let dropped = store
        .abandon_undelivered_outbound(record_key, object_digest)
        .map_err(|e| e.redacted_display())?;
    if dropped {
        mark_outbound_undelivered(
            data_dir,
            peer_pub,
            session_id,
            object_digest,
            message_id,
            delivery,
        )?;
        Ok(GiveUp::Abandoned)
    } else {
        record_outbound_delivered(data_dir, store, peer_pub, session_id, message_id)?;
        Ok(GiveUp::Delivered)
    }
}

/// Abandon every undelivered message to `recipient` (a revoked peer lineage)
/// and mark each [`HISTORY_FAILED`], so it is not retried again. Messages an
/// ACK delivered meanwhile are recorded as delivered instead.
pub fn abandon_undelivered_to_peer(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    recipient: &[u8; 32],
) -> Result<(), String> {
    let mut rows = store
        .pending_endpoint_outbound_for_recipient(Some(recipient))
        .map_err(|e| e.redacted_display())?;
    rows.extend(
        store
            .awaiting_ack_endpoint_outbound_for_recipient(Some(recipient))
            .map_err(|e| e.redacted_display())?,
    );
    for row in rows {
        if row.kind != EndpointOutboundKind::Message {
            continue;
        }
        let Some(key) = store
            .record_key_for_session_id(&row.session_id)
            .map_err(|e| e.redacted_display())?
        else {
            continue;
        };
        give_up_outbound(
            data_dir,
            store,
            &key,
            recipient,
            &row.session_id,
            &row.object_digest,
            &row.message_id,
            HISTORY_FAILED,
        )?;
    }
    Ok(())
}

/// After an ACK that arrived on an inbound link (pushed by the receiver's
/// outbox, transports design F8) was committed: the history row of the message
/// it confirms becomes `delivered` and its staged body is cleared. Best effort
/// by design: the ACK is already committed in the store, and a missing history
/// row is repaired by `reconcile_outbound_stage_history` later.
pub fn record_inbound_ack_delivery(
    data_dir: &Path,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    acked_message_id: &[u8; 16],
) -> Result<(), String> {
    let staged = crate::chat_history::load_staged_outbound_body(data_dir, acked_message_id)
        .map_err(|e| e.to_string())?;
    match staged {
        Some(staged)
            if staged
                .peer_pub_hex
                .eq_ignore_ascii_case(&hex::encode(peer_pub))
                && staged
                    .session_id_hex
                    .eq_ignore_ascii_case(&hex::encode(session_id)) =>
        {
            crate::lan_dispatch::persist_lan_chat_history(
                data_dir,
                "out",
                peer_pub,
                acked_message_id,
                staged.created_at_ms,
                "delivered",
                staged.body.as_bytes(),
            )?;
            crate::chat_history::clear_staged_outbound_body(data_dir, acked_message_id)
                .map_err(|e| e.to_string())
        }
        _ => crate::lan_dispatch::mark_lan_chat_history_delivery(
            data_dir,
            "out",
            peer_pub,
            acked_message_id,
            "delivered",
        ),
    }
}

// ── Routes the worker may use ────────────────────────────────────────────────

/// A carrier the outbox may retry on. Both are endpoint-authenticated Raven
/// Noise links that terminate at the intended contact, so both are
/// confidential to the endpoint (PairInit V1 §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxCarrier {
    Lan,
    Internet,
}

impl OutboxCarrier {
    /// The label `raven send` and the IPC dial ops use.
    pub fn label(self) -> &'static str {
        match self {
            Self::Lan => "lan_dial",
            Self::Internet => "internet_dial",
        }
    }

    /// May this carrier carry PairInit? Only links whose Raven Noise session
    /// ends at the intended contact (transports design §3.3) say yes.
    pub fn confidential_to_endpoint(self) -> bool {
        match self {
            Self::Lan | Self::Internet => true,
        }
    }
}

/// What `raven send --carrier` asked for, stored with each queued object so
/// the worker never widens it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierChoice {
    Auto,
    Lan,
    Internet,
}

impl CarrierChoice {
    pub fn allows(self, carrier: OutboxCarrier) -> bool {
        match self {
            Self::Auto => true,
            Self::Lan => carrier == OutboxCarrier::Lan,
            Self::Internet => carrier == OutboxCarrier::Internet,
        }
    }
}

/// One way to reach a peer: a carrier and its `host:port`. A reachability hint
/// only: every link still proves the pinned key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutboxRoute {
    pub carrier: OutboxCarrier,
    pub dial: String,
}

/// Where `raven send` records, per queued object, the carrier choice and the
/// routes it used, so the worker retries within exactly that (never wider).
/// Hints only: entries expire with their envelope, are cleared on delivery
/// and whenever the contact's addresses change or it is removed.
pub const OUTBOX_ROUTES_FILE: &str = "outbox_routes.json";
const OUTBOX_ROUTES_LOCK: &str = ".outbox_routes.lock.sqlite";
const MAX_ROUTE_OBJECTS: usize = 256;
const MAX_ROUTES_PER_OBJECT: usize = 4;
const MAX_DIAL_CHARS: usize = 300;

/// The record of one queued object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRoutes {
    pub peer_pub_hex: String,
    pub choice: CarrierChoice,
    pub routes: Vec<OutboxRoute>,
    pub expires_at_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RouteFile {
    /// Message id (hex) -> its record. Files from older builds (per peer)
    /// simply hold no objects.
    #[serde(default)]
    objects: BTreeMap<String, ObjectRoutes>,
}

/// A `host:port` the carriers can dial (port 1-65535, no spaces, not an
/// address or the "local listen" placeholder).
pub fn plausible_dial(dial: &str) -> bool {
    let t = dial.trim();
    if t.is_empty()
        || t.len() > MAX_DIAL_CHARS
        || t.contains(char::is_whitespace)
        || t.starts_with("rvn1")
        || t.eq_ignore_ascii_case("local")
        || t.eq_ignore_ascii_case("local-listen")
    {
        return false;
    }
    let Some((host, port)) = t.rsplit_once(':') else {
        return false;
    };
    !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0)
}

fn load_route_file(data_dir: &Path) -> Result<RouteFile, String> {
    let path = data_dir.join(OUTBOX_ROUTES_FILE);
    match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| format!("{OUTBOX_ROUTES_FILE}: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RouteFile::default()),
        Err(e) => Err(format!("{OUTBOX_ROUTES_FILE}: {e}")),
    }
}

/// Rewrite the file under its lock with `edit`, dropping expired entries.
/// An unreadable file is replaced: it holds hints only.
fn edit_route_file(
    data_dir: &Path,
    now_ms: u64,
    edit: impl FnOnce(&mut RouteFile),
) -> Result<(), String> {
    let path = data_dir.join(OUTBOX_ROUTES_FILE);
    let _lock = DataDirLock::acquire(data_dir, OUTBOX_ROUTES_LOCK)?;
    let existed = path.exists();
    let mut file = load_route_file(data_dir).unwrap_or_default();
    let before = file.objects.len();
    file.objects.retain(|_, r| r.expires_at_ms > now_ms);
    let pruned = file.objects.len() != before;
    let snapshot = serde_json::to_vec(&file.objects).unwrap_or_default();
    edit(&mut file);
    while file.objects.len() > MAX_ROUTE_OBJECTS {
        // The entry that expires first goes first.
        let Some(first) = file
            .objects
            .iter()
            .min_by_key(|(_, r)| r.expires_at_ms)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        file.objects.remove(&first);
    }
    let changed = pruned || serde_json::to_vec(&file.objects).unwrap_or_default() != snapshot;
    if !changed || (!existed && file.objects.is_empty()) {
        return Ok(());
    }
    let out = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
    crate::paths::atomic_write_private(&path, &out)
}

/// Remember, for the queued object `message_id`, the carrier choice and routes
/// of the send that queued it, until its envelope expires.
pub fn record_object_routes(
    data_dir: &Path,
    message_id: &[u8; 16],
    peer_device: &[u8; 32],
    choice: CarrierChoice,
    routes: &[OutboxRoute],
    expires_at_ms: u64,
    now_ms: u64,
) -> Result<(), String> {
    if expires_at_ms <= now_ms {
        return Ok(());
    }
    let routes: Vec<OutboxRoute> = routes
        .iter()
        .filter(|r| plausible_dial(&r.dial) && choice.allows(r.carrier))
        .take(MAX_ROUTES_PER_OBJECT)
        .map(|r| OutboxRoute {
            carrier: r.carrier,
            dial: r.dial.trim().to_string(),
        })
        .collect();
    let record = ObjectRoutes {
        peer_pub_hex: hex::encode(peer_device),
        choice,
        routes,
        expires_at_ms,
    };
    edit_route_file(data_dir, now_ms, |file| {
        file.objects.insert(hex::encode(message_id), record);
    })
}

/// The live records, by message id (expired ones are not returned).
pub fn object_route_records(
    data_dir: &Path,
    now_ms: u64,
) -> Result<BTreeMap<[u8; 16], ObjectRoutes>, String> {
    Ok(load_route_file(data_dir)?
        .objects
        .into_iter()
        .filter(|(_, r)| r.expires_at_ms > now_ms)
        .filter_map(|(k, r)| {
            let id: [u8; 16] = hex::decode(k).ok()?.try_into().ok()?;
            Some((id, r))
        })
        .collect())
}

/// Forget the records of these objects (delivered, given up, cancelled).
pub fn clear_object_routes(data_dir: &Path, message_ids: &[[u8; 16]]) -> Result<(), String> {
    if message_ids.is_empty() || !data_dir.join(OUTBOX_ROUTES_FILE).exists() {
        return Ok(());
    }
    edit_route_file(data_dir, wall_clock_ms(), |file| {
        for id in message_ids {
            file.objects.remove(&hex::encode(id));
        }
    })
}

/// Forget every record for `peer_device` (contact removed, or its addresses
/// changed): the worker then plans from the contact book alone.
pub fn clear_peer_routes(data_dir: &Path, peer_device: &[u8; 32]) -> Result<(), String> {
    if !data_dir.join(OUTBOX_ROUTES_FILE).exists() {
        return Ok(());
    }
    let key = hex::encode(peer_device);
    edit_route_file(data_dir, wall_clock_ms(), |file| {
        file.objects
            .retain(|_, r| !r.peer_pub_hex.eq_ignore_ascii_case(&key));
    })
}

// ── Verified contacts only beyond the LAN ───────────────────────────────────

/// Refusal / status code: the carrier needs a verified (pinned) contact.
pub const CONTACT_NOT_VERIFIED: &str = "CONTACT_NOT_VERIFIED";

/// May a contact use `carrier`? Owner decision 2026-10-08 (transports design
/// risk 5, Q15): unverified contacts are LAN only (and only at local-network
/// addresses, [`localize_lan_route`]); Internet delivery (and later p2p, mesh
/// and mailbox) is only for a **verified** contact, one whose fingerprint was
/// confirmed out of band (`pinned`: `--verify-fp` or the interactive verify).
/// The one rule `raven send`, the outbox worker and the listeners apply.
pub fn carrier_allowed_for_contact(carrier: OutboxCarrier, pinned: bool) -> bool {
    match carrier {
        OutboxCarrier::Lan => true,
        OutboxCarrier::Internet => pinned,
    }
}

/// Is `ip` on the local network: loopback, private (10/8, 172.16/12,
/// 192.168/16), link-local (169.254/16, fe80::/10) or unique-local (fc00::/7)?
/// IPv4-mapped IPv6 counts by its IPv4 address. Carrier-grade NAT space
/// (100.64/10), public and unspecified addresses do not count.
pub fn is_local_network_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    let v4_local =
        |v4: std::net::Ipv4Addr| v4.is_loopback() || v4.is_private() || v4.is_link_local();
    match ip {
        IpAddr::V4(v4) => v4_local(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4_local(v4);
            }
            let first = v6.segments()[0];
            v6.is_loopback() || (first & 0xffc0) == 0xfe80 || (first & 0xfe00) == 0xfc00
        }
    }
}

/// Why a LAN route may not be used for an unverified contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteRefusal {
    /// It resolves (at least partly) outside the local network.
    NotLocal,
    /// It could not be resolved; nothing is known, so nothing is dialled.
    Unresolved(String),
}

/// How long [`localize_lan_route`] waits for a name to resolve.
pub const LOCALIZE_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// The LAN route to dial for a contact: unchanged for a verified contact (and
/// for any non-LAN route); for an unverified one, `host:port` must resolve to
/// local-network addresses only ([`is_local_network_ip`]), and the route to
/// dial is the resolved literal, so a later resolution cannot point it
/// elsewhere. A `[v6%zone]:port` literal keeps its zone.
pub fn localize_lan_route(
    route: &OutboxRoute,
    pinned: bool,
    timeout: Duration,
) -> Result<OutboxRoute, RouteRefusal> {
    if pinned || route.carrier != OutboxCarrier::Lan {
        return Ok(route.clone());
    }
    let dial = route.dial.trim();
    if let Ok(addr) = dial.parse::<std::net::SocketAddr>() {
        return if is_local_network_ip(addr.ip()) {
            Ok(route.clone())
        } else {
            Err(RouteRefusal::NotLocal)
        };
    }
    let (host, port) = dial
        .rsplit_once(':')
        .ok_or_else(|| RouteRefusal::Unresolved("not host:port".into()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| RouteRefusal::Unresolved("bad port".into()))?;
    let inner = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Some((ip, _zone)) = inner.split_once('%') {
        // A scoped IPv6 literal (`fe80::1%en0`): local only if link-local / ULA.
        let ip: std::net::Ipv6Addr = ip
            .parse()
            .map_err(|_| RouteRefusal::Unresolved("bad scoped IPv6".into()))?;
        return if is_local_network_ip(ip.into()) {
            Ok(route.clone())
        } else {
            Err(RouteRefusal::NotLocal)
        };
    }
    let name = inner.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::net::ToSocketAddrs;
        let _ = tx.send(
            (name.as_str(), port)
                .to_socket_addrs()
                .map(|it| it.collect::<Vec<_>>()),
        );
    });
    let addrs = match rx.recv_timeout(timeout) {
        Ok(Ok(addrs)) if !addrs.is_empty() => addrs,
        Ok(Ok(_)) => return Err(RouteRefusal::Unresolved("no address".into())),
        Ok(Err(e)) => return Err(RouteRefusal::Unresolved(e.to_string())),
        Err(_) => return Err(RouteRefusal::Unresolved("resolution timed out".into())),
    };
    if !addrs.iter().all(|a| is_local_network_ip(a.ip())) {
        return Err(RouteRefusal::NotLocal);
    }
    Ok(OutboxRoute {
        carrier: OutboxCarrier::Lan,
        dial: addrs[0].to_string(),
    })
}

/// What the local contact book says about one key: its saved routes (LAN
/// first) and whether it is verified.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContactRoutes {
    pub routes: Vec<OutboxRoute>,
    pub pinned: bool,
}

#[derive(Debug, Deserialize)]
struct ContactRouteRow {
    #[serde(default)]
    pub_hex: String,
    #[serde(default)]
    pinned: bool,
    #[serde(default)]
    lan_dial: String,
    #[serde(default)]
    internet_dial: String,
}

/// The contact whose key is `peer_device`, or `None` when there is none. An
/// unreadable or corrupt book is an error (callers fail closed).
pub fn contact_routes(
    data_dir: &Path,
    peer_device: &[u8; 32],
) -> Result<Option<ContactRoutes>, String> {
    let path = data_dir.join("contacts.json");
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("contacts.json: {e}")),
    };
    let rows: Vec<ContactRouteRow> =
        serde_json::from_str(&raw).map_err(|e| format!("contacts.json corrupt: {e}"))?;
    let key = hex::encode(peer_device);
    let mut found: Option<ContactRoutes> = None;
    for row in rows
        .iter()
        .filter(|r| r.pub_hex.trim().eq_ignore_ascii_case(&key))
    {
        let entry = found.get_or_insert_with(|| ContactRoutes {
            routes: Vec::new(),
            pinned: true,
        });
        // Several rows for one key (an old book): verified only if all are.
        entry.pinned &= row.pinned;
        for (carrier, dial) in [
            (OutboxCarrier::Lan, &row.lan_dial),
            (OutboxCarrier::Internet, &row.internet_dial),
        ] {
            if plausible_dial(dial) {
                entry.routes.push(OutboxRoute {
                    carrier,
                    dial: dial.trim().to_string(),
                });
            }
        }
    }
    if let Some(entry) = found.as_mut() {
        entry.routes.sort_by_key(|r| r.carrier);
    }
    Ok(found)
}

/// Whether the contact whose key is `peer_device` is verified (pinned). No
/// such contact is `false`; an unreadable book is an error.
pub fn contact_is_pinned(data_dir: &Path, peer_device: &[u8; 32]) -> Result<bool, String> {
    Ok(contact_routes(data_dir, peer_device)?.is_some_and(|c| c.pinned))
}

/// May anything be exchanged with `peer` at all?
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContactAdmission {
    /// A current, unblocked contact (with its routes and pin).
    Allowed(ContactRoutes),
    NotContact,
    Blocked,
    /// The contact book or block list cannot be read: nobody is admitted.
    Unreadable,
}

/// The contact and block-list check every sender and listener runs first.
/// It always reads both files once, whatever the answer, so refusing a
/// stranger costs the same as refusing a contact.
pub fn contact_admission(data_dir: &Path, peer: &[u8; 32]) -> ContactAdmission {
    let contact = contact_routes(data_dir, peer);
    let blocks = crate::chat_history::BlockList::load_checked(data_dir);
    match (contact, blocks) {
        (Ok(Some(contact)), Ok(blocks)) => {
            if blocks.is_blocked(&hex::encode(peer)) {
                ContactAdmission::Blocked
            } else {
                ContactAdmission::Allowed(contact)
            }
        }
        (Ok(None), Ok(_)) => ContactAdmission::NotContact,
        (Ok(Some(_)), Err(_)) => ContactAdmission::Blocked,
        (Err(_), _) | (Ok(None), Err(_)) => ContactAdmission::Unreadable,
    }
}

/// What the worker may try, in order, and why a route was held back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoutePlan {
    pub routes: Vec<OutboxRoute>,
    /// A route was held back only because the contact is not verified
    /// ([`CONTACT_NOT_VERIFIED`]).
    pub unverified_withheld: bool,
}

/// The routes the worker tries for one object, in order:
/// - the carriers its send allowed (`record.choice`; with no record, the
///   narrowest plan: LAN only), each only while its gate is open
///   (`lan_live`: `lan_direct_live_enabled`, `internet_live`:
///   `internet_direct_live_enabled`), and Internet only for a verified contact;
/// - the contact's **current** addresses first, then the ones the send used
///   (an address changed since the send is still found, the new one first).
///
/// Nothing at all is planned when both gates are off. LAN routes of an
/// unverified contact must still pass [`localize_lan_route`] at dial time.
pub fn plan_object_routes(
    record: Option<&ObjectRoutes>,
    contact: &ContactRoutes,
    lan_live: bool,
    internet_live: bool,
) -> RoutePlan {
    let choice = record.map_or(CarrierChoice::Lan, |r| r.choice);
    let gate = |c: OutboxCarrier| match c {
        OutboxCarrier::Lan => lan_live,
        OutboxCarrier::Internet => internet_live,
    };
    let recorded: &[OutboxRoute] = record.map_or(&[], |r| r.routes.as_slice());
    let mut plan = RoutePlan::default();
    for route in contact.routes.iter().chain(recorded.iter()) {
        if !choice.allows(route.carrier) || !gate(route.carrier) || !plausible_dial(&route.dial) {
            continue;
        }
        if !carrier_allowed_for_contact(route.carrier, contact.pinned) {
            plan.unverified_withheld = true;
            continue;
        }
        let route = OutboxRoute {
            carrier: route.carrier,
            dial: route.dial.trim().to_string(),
        };
        if !plan.routes.contains(&route) {
            plan.routes.push(route);
        }
    }
    plan.routes.truncate(MAX_ROUTES_PER_OBJECT);
    plan
}

// ── Retry timing ─────────────────────────────────────────────────────────────

/// First retry delay (before jitter).
pub const RETRY_BASE: Duration = Duration::from_secs(5);
/// No retry waits longer than this, whatever the jitter.
pub const RETRY_MAX: Duration = Duration::from_secs(10 * 60);

/// Delay before the next attempt after `failures` failed ones (0 = the first
/// failure): `min(RETRY_MAX, RETRY_BASE * 2^failures)` with ±50 % jitter, and
/// never above [`RETRY_MAX`]. `jitter` is a uniform sample from `[0, 1]`;
/// callers supply it so tests stay deterministic (0.5 = no jitter).
pub fn retry_delay(failures: u32, jitter: f64) -> Duration {
    let ceiling = RETRY_BASE
        .saturating_mul(1u32 << failures.min(16))
        .min(RETRY_MAX);
    let jitter = if jitter.is_finite() {
        jitter.clamp(0.0, 1.0)
    } else {
        0.5
    };
    ceiling.mul_f64(0.5 + jitter).min(RETRY_MAX)
}

fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity_is_a_day_capped_by_the_session() {
        let now = 1_000_000;
        assert_eq!(
            envelope_expires_at(now, u64::MAX).unwrap(),
            now + ENVELOPE_VALIDITY_MS
        );
        assert_eq!(envelope_expires_at(now, now + 5_000).unwrap(), now + 5_000);
        assert!(envelope_expires_at(now, now).is_err());
        assert!(envelope_expires_at(now, now - 1).is_err());
        assert_eq!(ENVELOPE_VALIDITY_MS, 24 * 60 * 60 * 1_000);
    }

    #[test]
    fn retry_delay_doubles_from_five_seconds_with_bounded_jitter_and_cap() {
        let secs = |d: Duration| d.as_secs_f64();
        // No jitter: exactly 5 s, 10 s, 20 s ... capped at 10 min.
        assert_eq!(retry_delay(0, 0.5), Duration::from_secs(5));
        assert_eq!(retry_delay(1, 0.5), Duration::from_secs(10));
        assert_eq!(retry_delay(2, 0.5), Duration::from_secs(20));
        assert_eq!(retry_delay(7, 0.5), RETRY_MAX);
        assert_eq!(retry_delay(u32::MAX, 0.5), RETRY_MAX);
        // ±50 % around the ceiling, never above the cap.
        for failures in 0..40 {
            let ceiling = (5.0 * 2f64.powi(failures.min(16) as i32)).min(600.0);
            for jitter in [0.0, 0.25, 0.5, 0.75, 1.0, -3.0, 9.0, f64::NAN] {
                let d = secs(retry_delay(failures, jitter));
                assert!(d >= ceiling * 0.5 - 1e-9, "{failures} {jitter}: {d}");
                assert!(
                    d <= (ceiling * 1.5).min(600.0) + 1e-9,
                    "{failures} {jitter}: {d}"
                );
                assert!(d <= 600.0, "{d}");
            }
        }
        assert_eq!(retry_delay(0, 0.0), Duration::from_millis(2_500));
        assert_eq!(retry_delay(0, 1.0), Duration::from_millis(7_500));
        assert_eq!(retry_delay(10, 0.0), Duration::from_secs(300));
    }

    fn lan(d: &str) -> OutboxRoute {
        OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: d.into(),
        }
    }

    fn inet(d: &str) -> OutboxRoute {
        OutboxRoute {
            carrier: OutboxCarrier::Internet,
            dial: d.into(),
        }
    }

    fn contact(routes: &[OutboxRoute], pinned: bool) -> ContactRoutes {
        ContactRoutes {
            routes: routes.to_vec(),
            pinned,
        }
    }

    fn record(choice: CarrierChoice, routes: &[OutboxRoute]) -> ObjectRoutes {
        ObjectRoutes {
            peer_pub_hex: hex::encode([7u8; 32]),
            choice,
            routes: routes.to_vec(),
            expires_at_ms: u64::MAX,
        }
    }

    fn plan(
        rec: Option<&ObjectRoutes>,
        c: &ContactRoutes,
        lan_live: bool,
        internet_live: bool,
    ) -> Vec<OutboxRoute> {
        plan_object_routes(rec, c, lan_live, internet_live).routes
    }

    #[test]
    fn plan_keeps_the_send_choice_current_addresses_first_and_both_gates() {
        let both = contact(&[lan("10.0.0.9:7420"), inet("203.0.113.7:7422")], true);
        let auto = record(CarrierChoice::Auto, &[lan("10.0.0.2:7420")]);
        // The contact's current addresses first, then the send's own.
        assert_eq!(
            plan(Some(&auto), &both, true, true),
            vec![
                lan("10.0.0.9:7420"),
                inet("203.0.113.7:7422"),
                lan("10.0.0.2:7420")
            ]
        );
        // The Internet gate off: no Internet route, whatever was recorded.
        assert_eq!(
            plan(Some(&auto), &both, true, false),
            vec![lan("10.0.0.9:7420"), lan("10.0.0.2:7420")]
        );
        // The LAN gate off: no LAN route (M); both off: nothing at all.
        assert_eq!(
            plan(Some(&auto), &both, false, true),
            vec![inet("203.0.113.7:7422")]
        );
        assert!(plan(Some(&auto), &both, false, false).is_empty());
        // `--carrier lan` stays LAN-only, `--carrier internet` Internet-only.
        let lan_only = record(CarrierChoice::Lan, &[lan("10.0.0.2:7420")]);
        assert_eq!(
            plan(Some(&lan_only), &both, true, true),
            vec![lan("10.0.0.9:7420"), lan("10.0.0.2:7420")]
        );
        let inet_only = record(CarrierChoice::Internet, &[inet("[::1]:7422")]);
        assert_eq!(
            plan(Some(&inet_only), &both, true, true),
            vec![inet("203.0.113.7:7422"), inet("[::1]:7422")]
        );
        // No record: the narrowest plan, LAN from the contact book only.
        assert_eq!(plan(None, &both, true, true), vec![lan("10.0.0.9:7420")]);
        // Junk is never dialled; duplicates collapse.
        let junk = contact(&[lan("10.0.0.2:7420")], false);
        let rec = record(
            CarrierChoice::Lan,
            &[
                lan("local-listen"),
                lan("10.0.0.2:0"),
                lan(" 10.0.0.2:7420 "),
            ],
        );
        assert_eq!(
            plan(Some(&rec), &junk, true, false),
            vec![lan("10.0.0.2:7420")]
        );
        assert!(OutboxCarrier::Lan.confidential_to_endpoint());
        assert!(OutboxCarrier::Internet.confidential_to_endpoint());
    }

    /// Owner decision 2026-10-08: Internet only for verified (pinned) contacts;
    /// LAN for every contact, at local-network addresses unless verified.
    #[test]
    fn internet_needs_a_verified_contact_and_lan_does_not() {
        assert!(carrier_allowed_for_contact(OutboxCarrier::Lan, false));
        assert!(carrier_allowed_for_contact(OutboxCarrier::Lan, true));
        assert!(!carrier_allowed_for_contact(OutboxCarrier::Internet, false));
        assert!(carrier_allowed_for_contact(OutboxCarrier::Internet, true));
        let auto = record(CarrierChoice::Auto, &[]);
        let unpinned = contact(&[lan("10.0.0.2:7420"), inet("203.0.113.7:7422")], false);
        let p = plan_object_routes(Some(&auto), &unpinned, true, true);
        assert_eq!(p.routes, vec![lan("10.0.0.2:7420")]);
        assert!(p.unverified_withheld);
        let only_inet = contact(&[inet("[::1]:7422")], false);
        let p = plan_object_routes(Some(&auto), &only_inet, true, true);
        assert!(p.routes.is_empty() && p.unverified_withheld);
        // The gate decides first: with it off nothing was withheld for trust.
        let p = plan_object_routes(Some(&auto), &only_inet, true, false);
        assert!(p.routes.is_empty() && !p.unverified_withheld);
        let p = plan_object_routes(
            Some(&auto),
            &contact(&[inet("[::1]:7422")], true),
            true,
            true,
        );
        assert_eq!(p.routes, vec![inet("[::1]:7422")]);
    }

    #[test]
    fn local_network_addresses_are_exactly_the_private_ranges() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        for local in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.20",
            "169.254.3.4",
            "::1",
            "fe80::1",
            "febf::1",
            "fc00::1",
            "fd12:3456::1",
            "::ffff:192.168.1.20",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_local_network_ip(ip(local)), "{local}");
        }
        for remote in [
            "100.64.0.1",
            "100.127.255.255",
            "172.32.0.1",
            "8.8.8.8",
            "203.0.113.7",
            "0.0.0.0",
            "::",
            "2001:db8::1",
            "fec0::1",
            "::ffff:8.8.8.8",
            "::ffff:100.64.0.1",
        ] {
            assert!(!is_local_network_ip(ip(remote)), "{remote}");
        }
    }

    #[test]
    fn an_unverified_contact_is_dialled_only_at_local_resolved_addresses() {
        let t = LOCALIZE_RESOLVE_TIMEOUT;
        // A verified contact is unrestricted (no resolution at all).
        assert_eq!(
            localize_lan_route(&lan("203.0.113.7:7420"), true, t),
            Ok(lan("203.0.113.7:7420"))
        );
        // Literals: local ones as they are, public ones refused.
        for ok in [
            "192.168.1.20:7420",
            "[fe80::1%en0]:7420",
            "[::1]:7420",
            "[fd00::5]:7420",
        ] {
            assert_eq!(localize_lan_route(&lan(ok), false, t), Ok(lan(ok)), "{ok}");
        }
        for bad in ["203.0.113.7:7420", "100.64.0.1:7420", "[2001:db8::1]:7420"] {
            assert_eq!(
                localize_lan_route(&lan(bad), false, t),
                Err(RouteRefusal::NotLocal),
                "{bad}"
            );
        }
        // A name is resolved first and dialled as the resolved literal.
        let got = localize_lan_route(&lan("localhost:7420"), false, t).unwrap();
        let addr: std::net::SocketAddr = got.dial.parse().unwrap();
        assert!(addr.ip().is_loopback() && addr.port() == 7420, "{got:?}");
        // An unresolvable name is not dialled.
        assert!(matches!(
            localize_lan_route(&lan("no-such-host.invalid:7420"), false, t),
            Err(RouteRefusal::Unresolved(_))
        ));
        // Internet routes are not this function's business.
        assert_eq!(
            localize_lan_route(&inet("203.0.113.7:7422"), false, t),
            Ok(inet("203.0.113.7:7422"))
        );
    }

    #[test]
    fn admission_reads_both_files_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (friend, stranger) = ([1u8; 32], [2u8; 32]);
        assert_eq!(
            contact_admission(dir.path(), &friend),
            ContactAdmission::NotContact
        );
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(r#"[{{"pub_hex":"{}","pinned":true}}]"#, hex::encode(friend)),
        )
        .unwrap();
        assert!(matches!(
            contact_admission(dir.path(), &friend),
            ContactAdmission::Allowed(ContactRoutes { pinned: true, .. })
        ));
        assert_eq!(
            contact_admission(dir.path(), &stranger),
            ContactAdmission::NotContact
        );
        let mut blocks = crate::chat_history::BlockList::default();
        blocks.block(&hex::encode(friend));
        blocks.save(dir.path()).unwrap();
        assert_eq!(
            contact_admission(dir.path(), &friend),
            ContactAdmission::Blocked
        );
        std::fs::write(dir.path().join("contacts.json"), b"{not json").unwrap();
        assert_eq!(
            contact_admission(dir.path(), &friend),
            ContactAdmission::Unreadable
        );
    }

    /// Q: a stranger costs the listener the same reads as a contact (the block
    /// list is read for it too: a broken one is noticed), and every refusal,
    /// stranger, unverified or blocked, comes out of that one admission call.
    #[test]
    fn a_stranger_costs_the_same_reads_as_a_contact() {
        let dir = tempfile::tempdir().unwrap();
        let (unverified, stranger) = ([3u8; 32], [4u8; 32]);
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}","pinned":false}}]"#,
                hex::encode(unverified)
            ),
        )
        .unwrap();
        std::fs::write(crate::chat_history::blocked_path(dir.path()), b"{broken").unwrap();
        assert_eq!(
            contact_admission(dir.path(), &stranger),
            ContactAdmission::Unreadable
        );
        assert_eq!(
            contact_admission(dir.path(), &unverified),
            ContactAdmission::Blocked
        );
        std::fs::remove_file(crate::chat_history::blocked_path(dir.path())).unwrap();
        assert_eq!(
            contact_admission(dir.path(), &stranger),
            ContactAdmission::NotContact
        );
        assert!(matches!(
            contact_admission(dir.path(), &unverified),
            ContactAdmission::Allowed(ContactRoutes { pinned: false, .. })
        ));
    }

    #[test]
    fn object_records_expire_clear_and_stay_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let (bob, carol) = ([7u8; 32], [8u8; 32]);
        // The clearing helpers prune by the wall clock.
        let now = wall_clock_ms();
        let mid = |i: u8| [i; 16];
        assert!(object_route_records(dir.path(), now).unwrap().is_empty());
        record_object_routes(
            dir.path(),
            &mid(1),
            &bob,
            CarrierChoice::Lan,
            &[lan("10.0.0.2:7420"), inet("[::1]:7422"), lan("bad")],
            now + 10_000,
            now,
        )
        .unwrap();
        let got = object_route_records(dir.path(), now).unwrap();
        assert_eq!(
            got[&mid(1)].routes,
            vec![lan("10.0.0.2:7420")],
            "only what the choice allows"
        );
        assert_eq!(got[&mid(1)].choice, CarrierChoice::Lan);
        // It expires with the envelope.
        assert!(object_route_records(dir.path(), now + 10_000)
            .unwrap()
            .is_empty());
        // Cleared on delivery, and per peer (contact removed / addresses changed).
        record_object_routes(
            dir.path(),
            &mid(2),
            &bob,
            CarrierChoice::Auto,
            &[],
            now + 10_000,
            now,
        )
        .unwrap();
        record_object_routes(
            dir.path(),
            &mid(3),
            &carol,
            CarrierChoice::Auto,
            &[],
            now + 10_000,
            now,
        )
        .unwrap();
        clear_object_routes(dir.path(), &[mid(2)]).unwrap();
        let got = object_route_records(dir.path(), now).unwrap();
        assert!(!got.contains_key(&mid(2)) && got.contains_key(&mid(1)));
        clear_peer_routes(dir.path(), &bob).unwrap();
        let got = object_route_records(dir.path(), now).unwrap();
        assert_eq!(got.keys().copied().collect::<Vec<_>>(), vec![mid(3)]);
        // A corrupt hint file is replaced, never wedging a send.
        std::fs::write(dir.path().join(OUTBOX_ROUTES_FILE), b"{not json").unwrap();
        assert!(object_route_records(dir.path(), now).is_err());
        record_object_routes(
            dir.path(),
            &mid(4),
            &bob,
            CarrierChoice::Lan,
            &[],
            u64::MAX,
            now,
        )
        .unwrap();
        assert!(object_route_records(dir.path(), now)
            .unwrap()
            .contains_key(&mid(4)));
        // Bounded: the soonest-expiring records go first.
        for i in 0..(MAX_ROUTE_OBJECTS as u64 + 5) {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&i.to_be_bytes());
            record_object_routes(
                dir.path(),
                &id,
                &carol,
                CarrierChoice::Lan,
                &[],
                now + 100 + i,
                now,
            )
            .unwrap();
        }
        let got = object_route_records(dir.path(), now).unwrap();
        assert_eq!(got.len(), MAX_ROUTE_OBJECTS);
        assert!(got.contains_key(&mid(4)), "the longest-lived record stays");
    }

    #[test]
    fn contact_pin_is_read_from_the_book_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (pinned, plain, absent) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        assert!(!contact_is_pinned(dir.path(), &pinned).unwrap());
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}","pinned":true}},{{"pub_hex":"{}"}}]"#,
                hex::encode(pinned),
                hex::encode(plain)
            ),
        )
        .unwrap();
        assert!(contact_is_pinned(dir.path(), &pinned).unwrap());
        assert!(!contact_is_pinned(dir.path(), &plain).unwrap());
        assert!(!contact_is_pinned(dir.path(), &absent).unwrap());
        assert_eq!(contact_routes(dir.path(), &absent).unwrap(), None);
        std::fs::write(dir.path().join("contacts.json"), b"{not json").unwrap();
        assert!(contact_is_pinned(dir.path(), &pinned).is_err());
    }

    #[test]
    fn contact_routes_come_from_the_matching_contact_only() {
        let dir = tempfile::tempdir().unwrap();
        let peer = [9u8; 32];
        assert_eq!(contact_routes(dir.path(), &peer).unwrap(), None);
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}","internet_dial":"203.0.113.7:7422","lan_dial":"10.0.0.2:7420"}},
                    {{"pub_hex":"{}","lan_dial":"10.0.0.8:7420"}}]"#,
                hex::encode(peer).to_uppercase(),
                hex::encode([1u8; 32])
            ),
        )
        .unwrap();
        assert_eq!(
            contact_routes(dir.path(), &peer).unwrap(),
            Some(ContactRoutes {
                routes: vec![lan("10.0.0.2:7420"), inet("203.0.113.7:7422")],
                pinned: false,
            })
        );
        std::fs::write(dir.path().join("contacts.json"), b"{not json").unwrap();
        assert!(contact_routes(dir.path(), &peer).is_err());
    }

    #[test]
    fn send_lock_is_one_file_per_peer_shared_by_every_sender() {
        let dir = tempfile::tempdir().unwrap();
        let (bob, carol) = ([1u8; 32], [2u8; 32]);
        assert_eq!(
            PeerSendLock::file_name(&bob),
            format!(".send_{}.lock.sqlite", hex::encode(bob))
        );
        let held = PeerSendLock::acquire_within(dir.path(), &bob, Duration::ZERO).unwrap();
        let err = PeerSendLock::acquire_within(dir.path(), &bob, Duration::from_millis(50))
            .err()
            .expect("a second holder must wait");
        assert!(send_lock_busy(&err), "{err}");
        // Another peer never waits on Bob's lock.
        let _carol = PeerSendLock::acquire_within(dir.path(), &carol, Duration::ZERO).unwrap();
        drop(held);
        PeerSendLock::acquire_within(dir.path(), &bob, Duration::ZERO).unwrap();
    }

    #[test]
    fn first_ack_frame_skips_messages_and_junk() {
        let env = |kind: EnvType, id: u8| {
            Envelope {
                env_type: kind as u8,
                flags: 0,
                message_id: [id; 16],
                routing_tag: [0x44; 16],
                dest_device_hint: 0,
                created_at: 1,
                expires_at: 2,
                hop_limit: 4,
                replication_budget: 1,
                anti_replay_nonce: [0x55; 12],
                ratchet_header_ciphertext: vec![],
                message_ciphertext: vec![id; 8],
                sender_authentication: vec![0u8; 64],
            }
            .pack()
        };
        let frames = vec![
            b"RLB1junk".to_vec(),
            env(EnvType::Message, 1),
            env(EnvType::Ack, 2),
        ];
        assert_eq!(first_ack_frame(&frames), Some(frames[2].as_slice()));
        assert_eq!(first_ack_frame(&frames[..2]), None);
    }
}
