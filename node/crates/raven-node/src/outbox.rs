//! Background outbox worker (transports design 2026-10 §2.4, phase P2a).
//!
//! `raven send` stages a message durably before it dials. When that dial does
//! not deliver (the peer is asleep, off the network, restarting), this worker
//! keeps retrying the **exact staged bytes** from the session store's outbox
//! until the first verified ACK or the envelope's expiry, so the message
//! arrives when the peer comes back, with no new `raven send`.
//!
//! - **Work source:** `IndexedSessionStore::pending_endpoint_outbound()` (not
//!   yet handed to a carrier) and `awaiting_ack_endpoint_outbound()` (written,
//!   no ACK yet). There is no second queue: the schedule below is in memory
//!   only and rebuilt from the store at every start.
//! - **Schedule:** monotonic (`tokio::time::Instant`), so a wall-clock step
//!   never stalls or rushes a retry; the wall clock decides expiry only. Per
//!   object: 5 s doubling to 10 min, ±50 % jitter, never sooner than 5 s after
//!   a failed attempt. Only due objects are dialled, each with its own count.
//! - **Same rules as `raven send`:** the same per-peer
//!   [`raven_core::outbox::PeerSendLock`], the same store calls and the same
//!   ACK check ([`raven_core::outbox::accept_sealed_ack`]) and history
//!   functions. The lock is held only for store work: one attempt reads and
//!   validates under it, dials without it, and records the result under it
//!   again, so `raven send` never waits behind a dial.
//! - **Routes:** each object's own record (its `--carrier` choice and routes;
//!   no record means LAN from the contact book only), the contact's current
//!   addresses first, the LAN and Internet gates, Internet for verified
//!   contacts only and LAN addresses of unverified ones on the local network
//!   only. A route that answered with the wrong identity or refused this node
//!   is not retried for that object until `raven outbox retry`.
//! - **Triggers:** an IPC `OutboxKick` right after a send stages, the backoff
//!   timer, a listener coming up, and an authenticated inbound link from that
//!   contact (at most once a minute per contact).
//! - **Stops:** a verified ACK (history `delivered`, and never back); expiry
//!   (abandoned, history `expired`); a revoked peer lineage (abandoned, history
//!   `failed`). A removed, blocked or not-verified-enough contact fails closed:
//!   the object is held, nothing is dialled. A row this node holds no message
//!   body for (sealed by `SealUnderSession`) is never touched.
//! - **ACKs we owe (F8):** an ACK whose reply could not be written on the
//!   inbound link is pushed to the sender, in the same dial as our own due
//!   objects to it.
//!
//! Logs carry counts and fixed codes only: no peer key, address or message id.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use raven_core::device_cert::{ensure_local_device_certificate, DeviceCertificate};
use raven_core::envelope::{EnvType, Envelope};
use raven_core::identity::Identity;
use raven_core::indexed_session_store::{
    AuthorizedEndpointDevice, EndpointDeliveryState, EndpointOutbound, EndpointOutboundKind,
    EndpointOutboxState, IndexedSessionRecordKey, IndexedSessionStore, IndexedSessionStoreError,
};
use raven_core::ipc::OutboxItem;
use raven_core::outbox::{
    abandon_undelivered_to_peer, accept_sealed_ack, ack_frames, clear_object_routes,
    contact_admission, give_up_outbound, localize_lan_route, object_route_records,
    outbound_already_delivered, peer_lineage_denied, plan_object_routes, record_outbound_delivered,
    retry_delay, send_lock_busy, AckRejected, CarrierChoice, CarrierGates, ContactAdmission,
    ContactRoutes, GiveUp, ObjectRoutes, OutboxCarrier, OutboxRoute, PeerSendLock, RouteRefusal,
    CONTACT_NOT_VERIFIED, HISTORY_EXPIRED, HISTORY_FAILED, LOCALIZE_RESOLVE_TIMEOUT, RETRY_BASE,
};
use raven_core::paths::PRIMARY_DEVICE_ID;
use tokio::time::Instant;

use crate::netutil;

/// Without a kick or a due object the store is still re-read this often while
/// something is tracked, so a message staged by an older `raven send` (which
/// does not kick) is found.
const IDLE_REFRESH: Duration = Duration::from_secs(60);
/// With nothing tracked the store is re-read only as often as the expiry
/// prune reads it (`lan_direct::DURABLE_PRUNE_INTERVAL`): every send kicks, and
/// on a real install each store open reads the protected session state.
const IDLE_REFRESH_EMPTY: Duration = crate::lan_direct::DURABLE_PRUNE_INTERVAL;
/// After any attempt that did not finish an object, it waits at least this
/// long (no hot loop, even past its expiry when the store keeps failing).
const MIN_RETRY: Duration = RETRY_BASE;
/// How long one attempt waits for `raven send` (or another attempt) to release
/// the peer's send lock before it steps back.
const LOCK_WAIT: Duration = Duration::from_secs(2);
/// When the lock was busy: try again soon, without counting a failure.
const LOCK_BUSY_RETRY: Duration = Duration::from_secs(5);
/// Hard bound on one dial (the carriers have their own 40 s deadline).
const DIAL_DEADLINE: Duration = Duration::from_secs(45);
/// Objects (and owed ACKs) sent in one dial at most; the rest go next round.
const MAX_FRAMES_PER_DIAL: usize = 16;
/// Live objects tracked at most (the store's one-prepared-message-per-session
/// rule keeps the real number small).
const MAX_TRACKED: usize = 1024;
/// Finished objects kept for `OutboxStatus` / `OutboxList`.
const MAX_DONE: usize = 256;
/// ACKs owed to senders whose inbound link dropped before the reply (F8), in
/// all and per sender (one contact cannot push out everybody else's).
const MAX_UNSENT_ACKS: usize = 256;
const MAX_UNSENT_ACKS_PER_PEER: usize = 32;
/// A contact's inbound link triggers a dial-back at most this often.
const DIALBACK_INTERVAL: Duration = Duration::from_secs(60);
/// A refusal of an object sealed under an older session counts as "this
/// session is gone for good" only after this many in a row, over this long:
/// transient receiver errors look the same on the wire.
const SUPERSEDED_REFUSALS: u32 = 3;
const SUPERSEDED_SPAN: Duration = Duration::from_secs(120);
/// One worker attempt per object at a time; `raven send` may hold the other.
/// Transports design §2.3: at most 2 concurrent attempts per object.
pub(crate) const MAX_CONCURRENT_ATTEMPTS_PER_OBJECT: usize = 2;

const _: () = assert!(MAX_CONCURRENT_ATTEMPTS_PER_OBJECT >= 1);
const _: () = assert!(MAX_UNSENT_ACKS_PER_PEER <= MAX_UNSENT_ACKS);

/// Stable codes for `last_error_code` (`raven outbox status`).
pub(crate) mod code {
    pub const NOT_A_CONTACT: &str = "NOT_A_CONTACT";
    pub const CONTACT_BLOCKED: &str = "CONTACT_BLOCKED";
    pub const CONTACTS_UNREADABLE: &str = "CONTACTS_UNREADABLE";
    pub const NO_ROUTE: &str = "NO_ROUTE";
    pub const SEND_IN_PROGRESS: &str = "SEND_IN_PROGRESS";
    pub const LOCK: &str = "LOCK";
    pub const LOCAL_DEVICE: &str = "LOCAL_DEVICE";
    pub const LOCAL_DEVICE_REVOKED: &str = "LOCAL_DEVICE_REVOKED";
    pub const PEER_REVOKED: &str = "PEER_REVOKED";
    pub const NO_PEER_CERT: &str = "NO_PEER_CERT";
    pub const NO_LOCAL_BODY: &str = "NO_LOCAL_BODY";
    pub const HISTORY: &str = "HISTORY";
    pub const CLOCK: &str = "CLOCK";
    pub const STORE: &str = "STORE";
    pub const NO_ACK_YET: &str = "NO_ACK_YET";
    pub const STAGE: &str = "STAGE";
    pub const SUPERSEDED: &str = "SUPERSEDED";
    pub const EXPIRED: &str = "EXPIRED";
    pub const INTERNET_HOLD: &str = "INTERNET_HOLD";
    pub const P2P_HOLD: &str = "P2P_HOLD";
    pub const P2P_NOT_RUNNING: &str = "P2P_NOT_RUNNING";
    pub const LINK_NOT_ACCEPTED: &str = "LINK_NOT_ACCEPTED";
    pub const PEER_REFUSED: &str = "PEER_REFUSED";
    pub const WRONG_IDENTITY: &str = "WRONG_IDENTITY";
    pub const NOT_LISTENING: &str = "NOT_LISTENING";
    pub const NOT_REACHABLE: &str = "NOT_REACHABLE";
    pub const CLOSED_EARLY: &str = "CLOSED_EARLY";
    pub const DIAL_FAILED: &str = "DIAL_FAILED";
}

/// Where an object stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryState {
    /// Staged, not handed to a carrier yet.
    Queued,
    /// Written to the peer at least once, no ACK yet.
    Sent,
    /// Not tried: the contact was removed, blocked or is not verified enough
    /// for the routes left, the send lock was busy, ... (`last_error`).
    Held,
    Delivered,
    Expired,
    Failed,
    /// Left the store without the worker seeing why (`raven send` delivered or
    /// gave it up, `raven outbox cancel`, a prune): the history knows.
    Gone,
}

impl EntryState {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sent => "sent",
            Self::Held => "held",
            Self::Delivered => "delivered",
            Self::Expired => "expired",
            Self::Failed => "failed",
            Self::Gone => "gone",
        }
    }

    fn is_final(self) -> bool {
        matches!(
            self,
            Self::Delivered | Self::Expired | Self::Failed | Self::Gone
        )
    }
}

/// One tracked object (no plaintext, no ciphertext: the bytes stay in the store).
#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub(crate) object_digest: [u8; 32],
    pub(crate) kind: EndpointOutboundKind,
    pub(crate) session_id: [u8; 32],
    pub(crate) message_id: [u8; 16],
    pub(crate) recipient: [u8; 32],
    /// Wall-clock ms: expiry is the only wall-clock decision.
    pub(crate) expires_at_ms: u64,
    pub(crate) state: EntryState,
    /// Attempts the worker made (dials, monotonic).
    pub(crate) attempts: u32,
    /// Consecutive failures: drives the backoff, reset by progress.
    pub(crate) failures: u32,
    /// Monotonic: when the next attempt is due.
    pub(crate) next_due: Instant,
    pub(crate) last_carrier: Option<OutboxCarrier>,
    pub(crate) last_error: &'static str,
    /// Missing from the last store scan: the next attempt finds out why.
    pub(crate) vanished: bool,
    /// Routes that answered with the wrong identity or refused this node: not
    /// retried for this object until an explicit `raven outbox retry`.
    pub(crate) blocked_routes: Vec<OutboxRoute>,
    pub(crate) blocked_code: &'static str,
    /// Consecutive refusals by the peer, and when the first of them came.
    pub(crate) refusals: u32,
    pub(crate) first_refusal: Option<Instant>,
}

impl Entry {
    fn from_row(row: &ScanRow, now: Instant) -> Self {
        Self {
            object_digest: row.object_digest,
            kind: row.kind,
            session_id: row.session_id,
            message_id: row.message_id,
            recipient: row.recipient,
            expires_at_ms: row.expires_at_ms,
            state: row.state,
            attempts: 0,
            failures: 0,
            next_due: now,
            last_carrier: None,
            last_error: "",
            vanished: false,
            blocked_routes: Vec::new(),
            blocked_code: "",
            refusals: 0,
            first_refusal: None,
        }
    }

    /// The IPC view: the next attempt as wall-clock ms (0 when none).
    pub(crate) fn item(&self, now: Instant, wall_ms: u64) -> OutboxItem {
        OutboxItem {
            message_id_hex: hex::encode(self.message_id),
            peer_pub_hex: hex::encode(self.recipient),
            kind: match self.kind {
                EndpointOutboundKind::Message => "message".into(),
                EndpointOutboundKind::Ack => "ack".into(),
            },
            state: self.state.label().into(),
            carrier: self
                .last_carrier
                .map(|c| c.label().to_string())
                .unwrap_or_default(),
            attempts: self.attempts,
            next_attempt_ms: if self.state.is_final() {
                0
            } else {
                wall_ms
                    .saturating_add(self.next_due.saturating_duration_since(now).as_millis() as u64)
            },
            last_error_code: self.last_error.into(),
            expires_at_ms: self.expires_at_ms,
        }
    }
}

/// One outbox row as a store scan sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScanRow {
    pub(crate) object_digest: [u8; 32],
    pub(crate) kind: EndpointOutboundKind,
    pub(crate) session_id: [u8; 32],
    pub(crate) message_id: [u8; 16],
    pub(crate) recipient: [u8; 32],
    pub(crate) expires_at_ms: u64,
    pub(crate) state: EntryState,
}

/// An ACK we sealed for a message from `peer` whose reply was never written
/// on the inbound link (F8). The exact bytes from the store's ACK row.
#[derive(Clone, Debug)]
pub(crate) struct UnsentAck {
    pub(crate) peer: [u8; 32],
    pub(crate) bytes: Vec<u8>,
    pub(crate) expires_at_ms: u64,
    pub(crate) failures: u32,
    pub(crate) next_due: Instant,
}

/// Everything due for one peer, handed to one attempt.
#[derive(Debug)]
pub(crate) struct DueWork {
    pub(crate) peer: [u8; 32],
    pub(crate) entries: Vec<Entry>,
    pub(crate) acks: Vec<([u8; 32], UnsentAck)>,
}

#[derive(Default)]
struct Inner {
    running: bool,
    entries: BTreeMap<[u8; 32], Entry>,
    done: VecDeque<Entry>,
    in_flight: HashSet<[u8; 32]>,
    /// Kicked while an attempt was in flight: due again as soon as it ends.
    kicked: HashSet<[u8; 32]>,
    /// Explicitly kicked while in flight: also forget blocked routes.
    clear_blocks: HashSet<[u8; 32]>,
    unsent_acks: BTreeMap<[u8; 32], UnsentAck>,
    refresh: bool,
    /// Bumped by every applied attempt; a store scan older than a peer's last
    /// attempt is not merged for that peer (it may predate what it finished).
    apply_seq: u64,
    last_apply: HashMap<[u8; 32], u64>,
    last_dialback: HashMap<[u8; 32], Instant>,
}

pub(crate) struct Outbox {
    inner: Mutex<Inner>,
    wake: tokio::sync::Notify,
}

static OUTBOX: OnceLock<Outbox> = OnceLock::new();

fn outbox() -> &'static Outbox {
    OUTBOX.get_or_init(|| Outbox {
        inner: Mutex::new(Inner::default()),
        wake: tokio::sync::Notify::new(),
    })
}

fn lock(m: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn jitter() -> f64 {
    use rand::Rng;
    rand::thread_rng().gen_range(0.0..=1.0)
}

/// The wait after a failed attempt: the backoff, no later than the expiry (so
/// an expiring object is finished promptly), never sooner than [`MIN_RETRY`].
fn retry_wait(failures: u32, expires_at_ms: u64, wall_ms: u64, jitter: f64) -> Duration {
    let mut wait = retry_delay(failures, jitter);
    let to_expiry = expires_at_ms.saturating_sub(wall_ms);
    if to_expiry > 0 {
        wait = wait.min(Duration::from_millis(to_expiry));
    }
    wait.max(MIN_RETRY)
}

/// Is the worker running in this process (`raven-node service`)?
pub(crate) fn is_running() -> bool {
    lock(&outbox().inner).running
}

/// Make the objects to `peer` (or every object) due now and re-read the
/// store. `explicit` (the IPC kick: a send or `raven outbox retry`) also
/// forgets routes blocked for those objects. `false` when no worker runs in
/// this process: nothing is retried in the background then.
pub(crate) fn kick(peer: Option<&[u8; 32]>, explicit: bool) -> bool {
    let ob = outbox();
    let mut inner = lock(&ob.inner);
    if !inner.running {
        return false;
    }
    inner.kick_now(peer, explicit, Instant::now());
    drop(inner);
    ob.wake.notify_one();
    true
}

/// An authenticated contact just connected to us: it is online now. At most
/// one dial-back per contact per [`DIALBACK_INTERVAL`].
pub(crate) fn peer_seen(peer: &[u8; 32]) {
    let ob = outbox();
    let mut inner = lock(&ob.inner);
    if !inner.running || !inner.dialback_allowed(peer, Instant::now()) {
        return;
    }
    inner.kick_now(Some(peer), false, Instant::now());
    drop(inner);
    ob.wake.notify_one();
}

/// A listener came up (start-up, restart, network change).
pub(crate) fn listener_up() {
    let _ = kick(None, false);
}

/// Reply frames for `peer` that the inbound link could not write. The ACKs
/// among them are pushed to the sender later (F8); anything else (an RLB1
/// offer, a PairResponse the initiator retries anyway) is dropped.
pub(crate) fn note_unsent_replies(peer: &[u8; 32], replies: &[Vec<u8>]) {
    let ob = outbox();
    let mut inner = lock(&ob.inner);
    if !inner.running {
        return;
    }
    inner.note_unsent_acks(peer, replies, Instant::now(), now_ms());
    drop(inner);
    ob.wake.notify_one();
}

/// What the worker knows about one of our messages (live or recently done).
pub(crate) fn status(message_id: &[u8; 16]) -> Option<OutboxItem> {
    let inner = lock(&outbox().inner);
    let (now, wall) = (Instant::now(), now_ms());
    inner
        .entries
        .values()
        .find(|e| e.message_id == *message_id)
        .or_else(|| {
            inner
                .done
                .iter()
                .rev()
                .find(|e| e.message_id == *message_id)
        })
        .map(|e| e.item(now, wall))
}

/// Tracked objects (oldest first), then recently finished ones, at most `limit`.
pub(crate) fn list(peer: Option<&[u8; 32]>, limit: usize) -> Vec<OutboxItem> {
    let inner = lock(&outbox().inner);
    let (now, wall) = (Instant::now(), now_ms());
    let wanted = |e: &&Entry| peer.is_none_or(|p| *p == e.recipient);
    let mut live: Vec<&Entry> = inner.entries.values().filter(wanted).collect();
    live.sort_by_key(|e| (e.expires_at_ms, e.message_id));
    live.into_iter()
        .chain(inner.done.iter().rev().filter(wanted))
        .take(limit)
        .map(|e| e.item(now, wall))
        .collect()
}

/// The history's word (`delivered`, `expired`, `failed`, ...) and peer for our
/// outbound messages, by message id hex. Loaded once per IPC call, and only
/// when an answer needs it.
type HistoryStates = HashMap<String, (String, String)>;

fn load_history_states(data_dir: &Path) -> HistoryStates {
    raven_core::ChatHistory::load(data_dir)
        .map(|h| {
            h.entries
                .into_iter()
                .filter(|e| e.direction == "out")
                .map(|e| {
                    (
                        e.message_id_hex.to_ascii_lowercase(),
                        (e.peer_pub_hex, e.delivery),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Fill in what only the history knows about finished objects, loading the
/// history at most once (`load`) and only if some item needs it.
fn resolve_from_history(items: &mut [OutboxItem], load: impl FnOnce() -> HistoryStates) {
    let mut load = Some(load);
    let mut states: Option<HistoryStates> = None;
    for item in items
        .iter_mut()
        .filter(|i| i.state == EntryState::Gone.label())
    {
        let states = states.get_or_insert_with(|| (load.take().expect("loaded once"))());
        if let Some((_, delivery)) = states.get(&item.message_id_hex.to_ascii_lowercase()) {
            item.state = raven_core::sanitize::sanitize_terminal_line(delivery);
        }
    }
}

/// `OutboxStatus`: the worker's view, else the store's, else the history's.
/// Blocking (store, history).
pub(crate) fn status_anywhere(data_dir: &Path, message_id: &[u8; 16]) -> Option<OutboxItem> {
    let (now, wall) = (Instant::now(), now_ms());
    let found = status(message_id).or_else(|| {
        scan_store(data_dir)
            .ok()?
            .iter()
            .find(|r| r.message_id == *message_id)
            .map(|r| {
                let mut item = Entry::from_row(r, now).item(now, wall);
                item.next_attempt_ms = 0;
                item
            })
    });
    let mut items = match found {
        Some(item) => vec![item],
        None => {
            let states = load_history_states(data_dir);
            let (peer, delivery) = states.get(&hex::encode(message_id))?;
            return Some(OutboxItem {
                message_id_hex: hex::encode(message_id),
                peer_pub_hex: peer.to_ascii_lowercase(),
                kind: "message".into(),
                state: raven_core::sanitize::sanitize_terminal_line(delivery),
                ..OutboxItem::default()
            });
        }
    };
    resolve_from_history(&mut items, || load_history_states(data_dir));
    items.pop()
}

/// `OutboxList`: the worker's schedule when it runs, else the store's rows
/// (nothing retries them then). Blocking.
pub(crate) fn list_anywhere(
    data_dir: &Path,
    peer: Option<&[u8; 32]>,
    limit: usize,
) -> Result<(bool, Vec<OutboxItem>), String> {
    let running = is_running();
    let (now, wall) = (Instant::now(), now_ms());
    let mut items = if running {
        list(peer, limit)
    } else {
        scan_store(data_dir)?
            .iter()
            .filter(|r| peer.is_none_or(|p| *p == r.recipient))
            .take(limit)
            .map(|r| {
                let mut item = Entry::from_row(r, now).item(now, wall);
                item.next_attempt_ms = 0;
                item
            })
            .collect()
    };
    resolve_from_history(&mut items, || load_history_states(data_dir));
    Ok((running, items))
}

/// Every row the store still holds for us (no lock, read only).
pub(crate) fn scan_store(data_dir: &Path) -> Result<Vec<ScanRow>, String> {
    let store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let mut rows = Vec::new();
    let pending = store
        .pending_endpoint_outbound()
        .map_err(|e| e.redacted_display())?;
    let awaiting = store
        .awaiting_ack_endpoint_outbound()
        .map_err(|e| e.redacted_display())?;
    for (row, state) in pending
        .iter()
        .map(|r| (r, EntryState::Queued))
        .chain(awaiting.iter().map(|r| (r, EntryState::Sent)))
    {
        rows.push(scan_row(row, state));
    }
    Ok(rows)
}

fn scan_row(row: &EndpointOutbound, state: EntryState) -> ScanRow {
    ScanRow {
        object_digest: row.object_digest,
        kind: row.kind,
        session_id: row.session_id,
        message_id: row.message_id,
        recipient: row.recipient_device,
        expires_at_ms: Envelope::unpack(&row.immutable_envelope_bytes)
            .map(|e| e.expires_at)
            .unwrap_or(0),
        state,
    }
}

impl Inner {
    fn kick_now(&mut self, peer: Option<&[u8; 32]>, explicit: bool, now: Instant) {
        for entry in self.entries.values_mut() {
            if peer.is_none_or(|p| *p == entry.recipient) {
                entry.next_due = entry.next_due.min(now);
                if explicit {
                    entry.blocked_routes.clear();
                    entry.blocked_code = "";
                }
            }
        }
        for ack in self.unsent_acks.values_mut() {
            if peer.is_none_or(|p| *p == ack.peer) {
                ack.next_due = ack.next_due.min(now);
            }
        }
        // An attempt in flight works from what it was given: due again when
        // it ends, so this kick is not lost behind its backoff.
        let in_flight: Vec<[u8; 32]> = self
            .in_flight
            .iter()
            .filter(|p| peer.is_none_or(|k| k == *p))
            .copied()
            .collect();
        for p in in_flight {
            self.kicked.insert(p);
            if explicit {
                self.clear_blocks.insert(p);
            }
        }
        self.refresh = true;
    }

    fn dialback_allowed(&mut self, peer: &[u8; 32], now: Instant) -> bool {
        match self.last_dialback.get(peer) {
            Some(last) if now.saturating_duration_since(*last) < DIALBACK_INTERVAL => false,
            _ => {
                self.last_dialback.insert(*peer, now);
                // Bounded: forget contacts not seen for a while.
                if self.last_dialback.len() > MAX_TRACKED {
                    self.last_dialback
                        .retain(|_, t| now.saturating_duration_since(*t) < DIALBACK_INTERVAL);
                }
                true
            }
        }
    }

    fn note_unsent_acks(&mut self, peer: &[u8; 32], replies: &[Vec<u8>], now: Instant, wall: u64) {
        for reply in replies {
            let Some(env) = Envelope::unpack(reply) else {
                continue;
            };
            if env.env_type != EnvType::Ack as u8 || env.expires_at <= wall {
                continue;
            }
            let digest = raven_core::authenticated_object_digest(&env);
            if self.unsent_acks.contains_key(&digest) {
                continue;
            }
            // Per sender first, then in all: the one that expires first goes.
            let mine = self
                .unsent_acks
                .values()
                .filter(|a| a.peer == *peer)
                .count();
            let full =
                mine >= MAX_UNSENT_ACKS_PER_PEER || self.unsent_acks.len() >= MAX_UNSENT_ACKS;
            if full {
                let victim = self
                    .unsent_acks
                    .iter()
                    .filter(|(_, a)| mine < MAX_UNSENT_ACKS_PER_PEER || a.peer == *peer)
                    .min_by_key(|(_, a)| a.expires_at_ms)
                    .map(|(k, _)| *k);
                if let Some(victim) = victim {
                    self.unsent_acks.remove(&victim);
                }
            }
            self.unsent_acks.insert(
                digest,
                UnsentAck {
                    peer: *peer,
                    bytes: reply.clone(),
                    expires_at_ms: env.expires_at,
                    failures: 0,
                    next_due: now,
                },
            );
        }
        self.refresh = true;
    }

    /// The apply sequence a store scan started at (see [`Self::merge`]).
    fn scan_seq(&self) -> u64 {
        self.apply_seq
    }

    /// Fold a store scan into the schedule: new rows are due now (this is the
    /// rebuild at start-up), known rows take the store's state, and rows the
    /// store no longer holds are flagged for their peer's next attempt. A peer
    /// whose attempt finished after the scan started (`scan_seq`), or is in
    /// flight, is left alone: the scan may predate what that attempt did.
    fn merge(&mut self, rows: Vec<ScanRow>, scan_seq: u64, now: Instant, wall: u64) {
        let fresh = |inner: &Self, peer: &[u8; 32]| {
            !inner.in_flight.contains(peer)
                && inner
                    .last_apply
                    .get(peer)
                    .is_none_or(|seq| *seq <= scan_seq)
        };
        let seen: HashSet<[u8; 32]> = rows.iter().map(|r| r.object_digest).collect();
        for row in rows {
            if !fresh(self, &row.recipient) {
                continue;
            }
            if row.kind == EndpointOutboundKind::Ack && row.expires_at_ms <= wall {
                // Never sendable again; the store retires it.
                self.entries.remove(&row.object_digest);
                continue;
            }
            if let Some(entry) = self.entries.get_mut(&row.object_digest) {
                entry.vanished = false;
                if entry.state != EntryState::Held {
                    entry.state = row.state;
                }
                continue;
            }
            if self.entries.len() >= MAX_TRACKED {
                continue;
            }
            self.entries
                .insert(row.object_digest, Entry::from_row(&row, now));
        }
        let stale: Vec<[u8; 32]> = self
            .entries
            .values()
            .filter(|e| !seen.contains(&e.object_digest) && fresh(self, &e.recipient))
            .map(|e| e.object_digest)
            .collect();
        for digest in stale {
            if let Some(entry) = self.entries.get_mut(&digest) {
                if !entry.vanished {
                    entry.vanished = true;
                    entry.next_due = now;
                }
            }
        }
    }

    /// The work that is due now, by peer, each peer marked in flight (one
    /// attempt per peer at a time, so one per object). Only due objects go.
    fn take_due(&mut self, now: Instant) -> Vec<DueWork> {
        let mut by_peer: BTreeMap<[u8; 32], DueWork> = BTreeMap::new();
        for entry in self.entries.values() {
            if entry.next_due <= now && !self.in_flight.contains(&entry.recipient) {
                by_peer
                    .entry(entry.recipient)
                    .or_insert_with(|| DueWork {
                        peer: entry.recipient,
                        entries: Vec::new(),
                        acks: Vec::new(),
                    })
                    .entries
                    .push(entry.clone());
            }
        }
        for (digest, ack) in &self.unsent_acks {
            if ack.next_due <= now && !self.in_flight.contains(&ack.peer) {
                by_peer
                    .entry(ack.peer)
                    .or_insert_with(|| DueWork {
                        peer: ack.peer,
                        entries: Vec::new(),
                        acks: Vec::new(),
                    })
                    .acks
                    .push((*digest, ack.clone()));
            }
        }
        for peer in by_peer.keys() {
            self.in_flight.insert(*peer);
        }
        by_peer.into_values().collect()
    }

    /// How long until the next due object (`None`: nothing scheduled).
    fn next_due_in(&self, now: Instant) -> Option<Duration> {
        self.entries
            .values()
            .filter(|e| !self.in_flight.contains(&e.recipient))
            .map(|e| e.next_due)
            .chain(
                self.unsent_acks
                    .values()
                    .filter(|a| !self.in_flight.contains(&a.peer))
                    .map(|a| a.next_due),
            )
            .min()
            .map(|t| t.saturating_duration_since(now))
    }

    fn idle_refresh(&self) -> Duration {
        if self.entries.is_empty() && self.unsent_acks.is_empty() {
            IDLE_REFRESH_EMPTY
        } else {
            IDLE_REFRESH
        }
    }

    /// Apply one peer attempt's report.
    fn apply(&mut self, peer: &[u8; 32], report: PeerReport, now: Instant, wall: u64) {
        self.in_flight.remove(peer);
        self.apply_seq += 1;
        self.last_apply.insert(*peer, self.apply_seq);
        for digest in &report.acks_done {
            self.unsent_acks.remove(digest);
        }
        for digest in &report.acks_failed {
            if let Some(ack) = self.unsent_acks.get_mut(digest) {
                let wait = retry_wait(ack.failures, ack.expires_at_ms, wall, jitter());
                ack.failures = ack.failures.saturating_add(1);
                ack.next_due = now + wait;
            }
        }
        self.unsent_acks.retain(|_, a| a.expires_at_ms > wall);
        for digest in &report.attempted {
            let Some(entry) = self.entries.get_mut(digest) else {
                continue;
            };
            if let Some(blocked) = report.blocked.get(digest) {
                for (route, why) in blocked {
                    if !entry.blocked_routes.contains(route) {
                        entry.blocked_routes.push(route.clone());
                    }
                    entry.blocked_code = why;
                }
            }
            let outcome = report
                .outcomes
                .get(digest)
                .cloned()
                .or_else(|| report.held.map(Outcome::Held))
                .unwrap_or(Outcome::Held(code::STORE));
            apply_outcome(entry, outcome, now, wall);
            if entry.state.is_final() {
                let finished = self.entries.remove(digest).expect("entry present");
                self.done.push_back(finished);
                while self.done.len() > MAX_DONE {
                    self.done.pop_front();
                }
            }
        }
        if self.clear_blocks.remove(peer) {
            for entry in self.entries.values_mut().filter(|e| e.recipient == *peer) {
                entry.blocked_routes.clear();
                entry.blocked_code = "";
            }
        }
        if self.kicked.remove(peer) {
            for entry in self.entries.values_mut().filter(|e| e.recipient == *peer) {
                entry.next_due = now;
            }
        }
    }
}

/// What one attempt found for one object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Delivered {
        carrier: Option<OutboxCarrier>,
    },
    /// Written (or already written), no ACK yet.
    Sent {
        carrier: Option<OutboxCarrier>,
        code: &'static str,
    },
    /// A prepared ACK object of ours was handed to a carrier.
    AckSent {
        carrier: OutboxCarrier,
    },
    /// The dial failed: back off.
    Unreachable {
        carrier: Option<OutboxCarrier>,
        code: &'static str,
    },
    /// Not tried (fail closed or busy): back off (or retry soon when busy).
    Held(&'static str),
    Expired,
    Failed(&'static str),
    /// No longer in the store, for a reason the history holds.
    Gone,
}

fn apply_outcome(entry: &mut Entry, outcome: Outcome, now: Instant, wall: u64) {
    let backoff = |entry: &mut Entry| {
        let wait = retry_wait(entry.failures, entry.expires_at_ms, wall, jitter());
        entry.failures = entry.failures.saturating_add(1);
        entry.next_due = now + wait;
    };
    let refused = matches!(
        outcome,
        Outcome::Unreachable {
            code: code::PEER_REFUSED,
            ..
        }
    );
    if refused {
        entry.refusals = entry.refusals.saturating_add(1);
        entry.first_refusal.get_or_insert(now);
    } else if !matches!(outcome, Outcome::Held(_)) {
        entry.refusals = 0;
        entry.first_refusal = None;
    }
    match outcome {
        Outcome::Delivered { carrier } => {
            entry.state = EntryState::Delivered;
            if carrier.is_some() {
                // The attempt that got the ACK counts too.
                entry.attempts = entry.attempts.saturating_add(1);
            }
            entry.last_carrier = carrier.or(entry.last_carrier);
            entry.last_error = "";
        }
        Outcome::Sent { carrier, code } => {
            entry.state = EntryState::Sent;
            if carrier.is_some() {
                entry.attempts = entry.attempts.saturating_add(1);
                entry.last_carrier = carrier;
            }
            entry.last_error = code;
            backoff(entry);
        }
        Outcome::AckSent { carrier } => {
            entry.attempts = entry.attempts.saturating_add(1);
            entry.last_carrier = Some(carrier);
            entry.last_error = "";
            entry.state = EntryState::Delivered;
        }
        Outcome::Unreachable { carrier, code } => {
            if entry.state == EntryState::Held {
                entry.state = EntryState::Queued;
            }
            if carrier.is_some() {
                entry.attempts = entry.attempts.saturating_add(1);
                entry.last_carrier = carrier;
            }
            entry.last_error = code;
            backoff(entry);
        }
        Outcome::Held(why) if why == code::SEND_IN_PROGRESS => {
            // `raven send` is handling this peer right now: no failure.
            entry.last_error = why;
            entry.next_due = now + LOCK_BUSY_RETRY.max(MIN_RETRY);
        }
        Outcome::Held(why) => {
            entry.state = EntryState::Held;
            entry.last_error = why;
            backoff(entry);
        }
        Outcome::Expired => {
            entry.state = EntryState::Expired;
            entry.last_error = code::EXPIRED;
        }
        Outcome::Failed(why) => {
            entry.state = EntryState::Failed;
            entry.last_error = why;
        }
        Outcome::Gone => entry.state = EntryState::Gone,
    }
}

/// The outcome of one attempt on one peer.
#[derive(Debug, Default)]
pub(crate) struct PeerReport {
    /// The objects this attempt was given (the due ones).
    pub(crate) attempted: Vec<[u8; 32]>,
    pub(crate) outcomes: HashMap<[u8; 32], Outcome>,
    /// Applies to every attempted object that has no outcome of its own.
    pub(crate) held: Option<&'static str>,
    /// Owed ACKs that went out, expired, or are owed to a non-contact (F8).
    pub(crate) acks_done: Vec<[u8; 32]>,
    /// Owed ACKs whose push failed: they back off.
    pub(crate) acks_failed: Vec<[u8; 32]>,
    /// Routes no longer to be tried for an object, with why.
    pub(crate) blocked: HashMap<[u8; 32], Vec<(OutboxRoute, &'static str)>>,
}

impl PeerReport {
    fn hold_all(mut self, why: &'static str) -> Self {
        self.held = Some(why);
        self
    }
}

/// How one carrier attempt is made. Production dials over the network
/// (`lan_direct::dial` / `internet_direct::dial`); tests hand the frames to a
/// second profile's dispatcher in process.
pub(crate) trait Dialer: Send + Sync {
    fn dial(
        &self,
        data_dir: &Path,
        route: &OutboxRoute,
        expected_pub_hex: &str,
        frames: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, String>;
}

/// The real carriers. Runs on a blocking-pool thread, so it may block on the
/// runtime.
struct NetDialer {
    handle: tokio::runtime::Handle,
}

impl Dialer for NetDialer {
    fn dial(
        &self,
        data_dir: &Path,
        route: &OutboxRoute,
        expected_pub_hex: &str,
        frames: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, String> {
        self.handle.block_on(async {
            let work = async {
                match route.carrier {
                    OutboxCarrier::Lan => {
                        crate::lan_direct::dial(data_dir, &route.dial, expected_pub_hex, frames)
                            .await
                    }
                    OutboxCarrier::Internet => {
                        crate::internet_direct::dial(
                            data_dir,
                            &route.dial,
                            expected_pub_hex,
                            frames,
                        )
                        .await
                    }
                    OutboxCarrier::P2p => {
                        crate::p2p::dial(data_dir, &route.dial, expected_pub_hex, frames).await
                    }
                }
            };
            tokio::time::timeout(DIAL_DEADLINE, work)
                .await
                .unwrap_or_else(|_| {
                    Err(format!("outbox dial exceeded {}s", DIAL_DEADLINE.as_secs()))
                })
        })
    }
}

/// Everything an attempt needs, shared by all attempts of the worker.
pub(crate) struct AttemptCtx {
    pub(crate) data_dir: PathBuf,
    pub(crate) identity: Arc<Identity>,
    pub(crate) dialer: Arc<dyn Dialer>,
    /// The LAN direct gate (`lan_direct_live_enabled`), read at every attempt.
    pub(crate) lan_live: fn() -> bool,
    /// The Internet direct gate, read at every attempt.
    pub(crate) internet_live: fn() -> bool,
    /// The p2p gate (`p2p_live_enabled`), read at every attempt.
    pub(crate) p2p_live: fn() -> bool,
}

/// Map dial error text to a stable code (no addresses, no ids).
pub(crate) fn dial_error_code(detail: &str) -> &'static str {
    let l = detail.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| l.contains(n));
    if has(&["internet_direct_hold"]) {
        code::INTERNET_HOLD
    } else if has(&["p2p_hold"]) {
        code::P2P_HOLD
    } else if has(&["p2p_not_running"]) {
        code::P2P_NOT_RUNNING
    } else if has(&["contact_not_verified"]) {
        CONTACT_NOT_VERIFIED
    } else if has(&["link_not_accepted"]) {
        code::LINK_NOT_ACCEPTED
    } else if has(&["_dial_peer_closed"]) {
        code::PEER_REFUSED
    } else if has(&[
        "identity bind does not match",
        "rlb1 offer identity mismatch",
        "identity mismatch",
    ]) {
        code::WRONG_IDENTITY
    } else if has(&["blocked peer"]) {
        code::CONTACT_BLOCKED
    } else if has(&["connection refused", "actively refused"]) {
        code::NOT_LISTENING
    } else if has(&[
        "closed the connection during the handshake",
        "peer closed the connection",
        "early eof",
        "connection reset",
        "broken pipe",
    ]) {
        code::CLOSED_EARLY
    } else if has(&[
        "timed out",
        "timeout",
        "exceeded",
        "cannot connect",
        "connect budget",
        "no route",
        "unreachable",
        "host is down",
    ]) {
        code::NOT_REACHABLE
    } else {
        code::DIAL_FAILED
    }
}

/// A route answer that will not change by retrying: the peer at that address
/// is someone else, or it does not accept this node.
fn blocks_route(why: &str) -> bool {
    why == code::WRONG_IDENTITY || why == code::LINK_NOT_ACCEPTED
}

/// One object about to be dialled: its exact bytes and its routes.
struct Candidate {
    digest: [u8; 32],
    kind: EndpointOutboundKind,
    key: IndexedSessionRecordKey,
    session_id: [u8; 32],
    message_id: [u8; 16],
    /// Still `Prepared`: the handoff is recorded once a dial took it.
    pending: bool,
    bytes: Vec<u8>,
    /// (as planned, as dialled): blocking uses the planned form.
    routes: Vec<(OutboxRoute, OutboxRoute)>,
    sent: Option<OutboxCarrier>,
    last_try: Option<(OutboxCarrier, &'static str)>,
    superseded: bool,
    refusals: u32,
    first_refusal: Option<Instant>,
}

/// Message bodies this node holds (staged or in the history), read once per
/// attempt: a row without one was not staged by `raven send` (it was sealed
/// by `SealUnderSession` for another path) and is never touched.
struct LocalBodies {
    staged: Option<HashSet<String>>,
    history: Option<HashSet<String>>,
}

impl LocalBodies {
    fn new() -> Self {
        Self {
            staged: None,
            history: None,
        }
    }

    fn has(&mut self, data_dir: &Path, peer: &[u8; 32], message_id: &[u8; 16]) -> bool {
        let mid = hex::encode(message_id);
        let peer_hex = hex::encode(peer);
        let staged = self.staged.get_or_insert_with(|| {
            raven_core::list_staged_outbound_bodies(data_dir)
                .map(|all| {
                    all.into_iter()
                        .filter(|s| s.peer_pub_hex.eq_ignore_ascii_case(&peer_hex))
                        .map(|s| s.message_id_hex.to_ascii_lowercase())
                        .collect()
                })
                .unwrap_or_default()
        });
        if staged.contains(&mid) {
            return true;
        }
        let history = self.history.get_or_insert_with(|| {
            raven_core::ChatHistory::load(data_dir)
                .map(|h| {
                    h.entries
                        .into_iter()
                        .filter(|e| {
                            e.direction == "out"
                                && !e.body.is_empty()
                                && e.peer_pub_hex.eq_ignore_ascii_case(&peer_hex)
                        })
                        .map(|e| e.message_id_hex.to_ascii_lowercase())
                        .collect()
                })
                .unwrap_or_default()
        });
        history.contains(&mid)
    }
}

/// One attempt on the due objects (and owed ACKs) of `peer`. Blocking (store,
/// history, DNS, dials): run it on the blocking pool. The send lock is taken
/// for the store work before and after the dial, never across it.
pub(crate) fn attempt_peer(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    due: &[Entry],
    owed_acks: &[([u8; 32], UnsentAck)],
) -> PeerReport {
    let mut report = attempt_peer_inner(ctx, peer, due, owed_acks);
    // Every owed ACK ends up in exactly one list; one this attempt could not
    // send (or decide) backs off.
    report.acks_done.sort_unstable();
    report.acks_done.dedup();
    let done: HashSet<[u8; 32]> = report.acks_done.iter().copied().collect();
    report.acks_failed = owed_acks
        .iter()
        .map(|(d, _)| *d)
        .filter(|d| !done.contains(d))
        .collect();
    report
}

fn attempt_peer_inner(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    due: &[Entry],
    owed_acks: &[([u8; 32], UnsentAck)],
) -> PeerReport {
    let mut report = PeerReport {
        attempted: due.iter().map(|e| e.object_digest).collect(),
        ..PeerReport::default()
    };
    let data_dir = ctx.data_dir.as_path();
    let wall = now_ms();
    let mono = Instant::now();
    let peer_hex = hex::encode(peer);

    // Contact and block list first: nothing (not even an owed ACK) goes to a
    // key that is not a current, unblocked contact.
    let contact: Option<ContactRoutes> = match contact_admission(data_dir, peer) {
        ContactAdmission::Allowed(c) => Some(c),
        ContactAdmission::NotContact => {
            report.acks_done = owed_acks.iter().map(|(d, _)| *d).collect();
            report.held = Some(code::NOT_A_CONTACT);
            None
        }
        ContactAdmission::Blocked => {
            report.acks_done = owed_acks.iter().map(|(d, _)| *d).collect();
            report.held = Some(code::CONTACT_BLOCKED);
            None
        }
        ContactAdmission::Unreadable => {
            report.held = Some(code::CONTACTS_UNREADABLE);
            None
        }
    };

    let mut store = match IndexedSessionStore::open(data_dir) {
        Ok(store) => store,
        Err(_) => return report.hold_all(code::STORE),
    };

    // Plans (no lock, no store writes): records, gates, trust, localization.
    let records: BTreeMap<[u8; 16], ObjectRoutes> =
        object_route_records(data_dir, wall).unwrap_or_default();
    let gates = CarrierGates {
        lan: (ctx.lan_live)(),
        internet: (ctx.internet_live)(),
        p2p: (ctx.p2p_live)(),
    };
    let mut localized: HashMap<OutboxRoute, Result<OutboxRoute, RouteRefusal>> = HashMap::new();
    let mut localize = |route: &OutboxRoute, pinned: bool| {
        localized
            .entry(route.clone())
            .or_insert_with(|| localize_lan_route(route, pinned, LOCALIZE_RESOLVE_TIMEOUT))
            .clone()
    };
    // Owed ACKs go over the contact's own routes, any carrier allowed.
    let ack_routes: Vec<(OutboxRoute, OutboxRoute)> = match &contact {
        Some(c) => {
            let any = ObjectRoutes {
                peer_pub_hex: peer_hex.clone(),
                choice: CarrierChoice::Auto,
                routes: Vec::new(),
                expires_at_ms: u64::MAX,
            };
            plan_object_routes(Some(&any), c, gates)
                .routes
                .into_iter()
                .filter_map(|r| localize(&r, c.pinned).ok().map(|d| (r, d)))
                .collect()
        }
        None => Vec::new(),
    };

    // Session-bound peer certificates (revocation, ACK checks). A missing one
    // is fetched by a frame-less probe, which caches the peer's bundle.
    let mut keys: HashMap<[u8; 32], Option<IndexedSessionRecordKey>> = HashMap::new();
    for entry in due {
        keys.entry(entry.session_id).or_insert_with(|| {
            store
                .record_key_for_session_id(&entry.session_id)
                .ok()
                .flatten()
        });
    }
    let cert_for = |store: &mut IndexedSessionStore, key: &IndexedSessionRecordKey| {
        raven_core::lan_dispatch::session_bound_peer_certificate(data_dir, store, key, peer)
            .ok()
            .flatten()
    };
    let mut certs: HashMap<[u8; 32], Option<DeviceCertificate>> = HashMap::new();
    for (sid, key) in &keys {
        let cert = key.as_ref().and_then(|k| cert_for(&mut store, k));
        certs.insert(*sid, cert);
    }
    // Only for messages that can still go out: an expired one needs no dial.
    let missing_cert = contact.is_some()
        && due.iter().any(|e| {
            e.kind == EndpointOutboundKind::Message
                && e.expires_at_ms > wall
                && keys.get(&e.session_id).is_some_and(Option::is_some)
                && certs.get(&e.session_id).is_some_and(Option::is_none)
        });
    if missing_cert {
        if let Some((_, dial)) = ack_routes.first() {
            let _ = ctx.dialer.dial(data_dir, dial, &peer_hex, &[]);
            for (sid, key) in &keys {
                if certs.get(sid).is_some_and(Option::is_none) {
                    let cert = key.as_ref().and_then(|k| cert_for(&mut store, k));
                    certs.insert(*sid, cert);
                }
            }
        }
    }
    // The peer's certificate for the owed-ACK revocation check.
    let any_cert: Option<DeviceCertificate> =
        certs.values().flatten().next().cloned().or_else(|| {
            raven_core::load_cached_peer_bundle(data_dir, peer)
                .ok()
                .flatten()
                .map(|b| b.cert)
        });

    // ── Under the send lock: decide everything local, capture the bytes ──
    let lock = match PeerSendLock::acquire_within(data_dir, peer, LOCK_WAIT) {
        Ok(lock) => lock,
        Err(e) => {
            return report.hold_all(if send_lock_busy(&e) {
                code::SEND_IN_PROGRESS
            } else {
                code::LOCK
            });
        }
    };
    let rows: Vec<EndpointOutbound> = match (
        store.pending_endpoint_outbound_for_recipient(Some(peer)),
        store.awaiting_ack_endpoint_outbound_for_recipient(Some(peer)),
    ) {
        (Ok(mut p), Ok(a)) => {
            p.extend(a);
            p
        }
        _ => return report.hold_all(code::STORE),
    };
    let mut bodies = LocalBodies::new();
    let mut live: Vec<(&Entry, &EndpointOutbound)> = Vec::new();
    let mut finished: Vec<[u8; 16]> = Vec::new();
    for entry in due {
        let Some(row) = rows.iter().find(|r| r.object_digest == entry.object_digest) else {
            // It left the store since the last scan: why? No dial needed.
            let outcome = finalize_vanished(data_dir, &mut store, peer, entry, wall);
            if matches!(
                outcome,
                Outcome::Delivered { .. } | Outcome::Expired | Outcome::Failed(_) | Outcome::Gone
            ) {
                finished.push(entry.message_id);
            }
            report.outcomes.insert(entry.object_digest, outcome);
            continue;
        };
        if let Some(outcome) = settle_locally(
            data_dir,
            &mut store,
            &keys,
            &mut bodies,
            peer,
            entry,
            row,
            wall,
        ) {
            if !matches!(outcome, Outcome::Held(_)) {
                finished.push(entry.message_id);
            }
            report.outcomes.insert(entry.object_digest, outcome);
            continue;
        }
        live.push((entry, row));
    }
    let Some(contact) = contact else {
        drop(lock);
        let _ = clear_object_routes(data_dir, &finished);
        return report;
    };

    // Revocation: never seal to, resend to or push an ACK to a revoked lineage.
    // An unreadable revocation store denies everything and destroys nothing.
    let verdicts: Vec<Result<bool, String>> = certs
        .values()
        .flatten()
        .chain(any_cert.iter())
        .map(|c| peer_lineage_denied(data_dir, c))
        .collect();
    if verdicts.iter().any(Result::is_err) {
        drop(lock);
        let _ = clear_object_routes(data_dir, &finished);
        for (entry, _) in &live {
            report
                .outcomes
                .insert(entry.object_digest, Outcome::Held(code::STORE));
        }
        return report;
    }
    if verdicts.iter().any(|v| matches!(v, Ok(true))) {
        let _ = abandon_undelivered_to_peer(data_dir, &mut store, peer);
        drop(lock);
        report.acks_done = owed_acks.iter().map(|(d, _)| *d).collect();
        for (entry, _) in &live {
            report
                .outcomes
                .insert(entry.object_digest, Outcome::Failed(code::PEER_REVOKED));
            finished.push(entry.message_id);
        }
        let _ = clear_object_routes(data_dir, &finished);
        return report;
    }
    // Without a certificate revocation cannot be checked: owed ACKs wait.
    let owed: Vec<&([u8; 32], UnsentAck)> = match &any_cert {
        Some(_) => owed_acks.iter().collect(),
        None => Vec::new(),
    };

    let (local_cert, registry) =
        match ensure_local_device_certificate(data_dir, &ctx.identity, PRIMARY_DEVICE_ID) {
            Ok(v) => v,
            Err(_) => {
                drop(lock);
                for (entry, _) in &live {
                    report
                        .outcomes
                        .insert(entry.object_digest, Outcome::Held(code::LOCAL_DEVICE));
                }
                return report;
            }
        };
    let local_device =
        match AuthorizedEndpointDevice::authorize(&local_cert, &ctx.identity, &registry, wall) {
            Ok(d) => d,
            Err(_) => {
                drop(lock);
                for (entry, _) in &live {
                    report.outcomes.insert(
                        entry.object_digest,
                        Outcome::Held(code::LOCAL_DEVICE_REVOKED),
                    );
                }
                return report;
            }
        };
    let newest = store.find_confirmed_session_for_peer(peer).ok().flatten();

    let mut candidates: Vec<Candidate> = Vec::new();
    for (entry, row) in live {
        let Some(key) = keys.get(&row.session_id).cloned().flatten() else {
            report.outcomes.insert(entry.object_digest, Outcome::Gone);
            continue;
        };
        let routes: Vec<(OutboxRoute, OutboxRoute)> = if row.kind == EndpointOutboundKind::Ack {
            ack_routes.clone()
        } else {
            let plan = plan_object_routes(records.get(&row.message_id), &contact, gates);
            let mut unlocal = false;
            let mut unresolved = false;
            let routes: Vec<(OutboxRoute, OutboxRoute)> = plan
                .routes
                .iter()
                .filter(|r| !entry.blocked_routes.contains(r))
                .filter_map(|r| match localize(r, contact.pinned) {
                    Ok(d) => Some((r.clone(), d)),
                    Err(RouteRefusal::NotLocal) => {
                        unlocal = true;
                        None
                    }
                    Err(RouteRefusal::Unresolved(_)) => {
                        unresolved = true;
                        None
                    }
                })
                .collect();
            if routes.is_empty() {
                let why = if !entry.blocked_routes.is_empty()
                    && !plan.routes.is_empty()
                    && plan.routes.iter().all(|r| entry.blocked_routes.contains(r))
                {
                    if entry.blocked_code.is_empty() {
                        code::LINK_NOT_ACCEPTED
                    } else {
                        entry.blocked_code
                    }
                } else if plan.unverified_withheld || unlocal {
                    CONTACT_NOT_VERIFIED
                } else if unresolved {
                    code::NOT_REACHABLE
                } else {
                    code::NO_ROUTE
                };
                report
                    .outcomes
                    .insert(entry.object_digest, Outcome::Held(why));
                continue;
            }
            routes
        };
        if row.kind == EndpointOutboundKind::Ack && routes.is_empty() {
            report
                .outcomes
                .insert(entry.object_digest, Outcome::Held(code::NO_ROUTE));
            continue;
        }
        if row.kind == EndpointOutboundKind::Message {
            let Some(cert) = certs.get(&row.session_id).cloned().flatten() else {
                report
                    .outcomes
                    .insert(entry.object_digest, Outcome::Held(code::NO_PEER_CERT));
                continue;
            };
            if raven_core::refuse_if_session_lineage_revoked(data_dir, &local_cert, &cert).is_err()
            {
                report.outcomes.insert(
                    entry.object_digest,
                    Outcome::Held(code::LOCAL_DEVICE_REVOKED),
                );
                continue;
            }
            // History must hold the body before the message can be delivered.
            if let Err(e) = raven_core::ensure_outbound_queued_history(
                data_dir,
                peer,
                &row.session_id,
                &row.object_digest,
                &row.message_id,
                wall,
                None,
            ) {
                let outcome = if e.contains("outbound body unavailable") {
                    Outcome::Held(code::NO_LOCAL_BODY)
                } else if e.contains("binding mismatch") {
                    match give_up_outbound(
                        data_dir,
                        &mut store,
                        &key,
                        peer,
                        &row.session_id,
                        &row.object_digest,
                        &row.message_id,
                        HISTORY_FAILED,
                    ) {
                        Ok(GiveUp::Abandoned) => Outcome::Failed(code::STAGE),
                        Ok(GiveUp::Delivered) => Outcome::Delivered { carrier: None },
                        Err(_) => Outcome::Held(code::STORE),
                    }
                } else {
                    Outcome::Held(code::HISTORY)
                };
                if !matches!(outcome, Outcome::Held(_)) {
                    finished.push(row.message_id);
                }
                report.outcomes.insert(entry.object_digest, outcome);
                continue;
            }
        }
        match capture(&mut store, &key, row, &local_device, wall) {
            Captured::Bytes { bytes, pending } => candidates.push(Candidate {
                digest: row.object_digest,
                kind: row.kind,
                key: key.clone(),
                session_id: row.session_id,
                message_id: row.message_id,
                pending,
                bytes,
                routes,
                sent: None,
                last_try: None,
                superseded: newest.as_ref().is_some_and(|n| *n != key),
                refusals: entry.refusals,
                first_refusal: entry.first_refusal,
            }),
            Captured::Delivered => {
                let _ = record_outbound_delivered(
                    data_dir,
                    &mut store,
                    peer,
                    &row.session_id,
                    &row.message_id,
                );
                finished.push(row.message_id);
                report
                    .outcomes
                    .insert(entry.object_digest, Outcome::Delivered { carrier: None });
            }
            Captured::Gone => {
                report.outcomes.insert(entry.object_digest, Outcome::Gone);
            }
            Captured::NotValid => {
                // Expired by the envelope's own clock: give up. Otherwise the
                // wall clock moved (a step backwards): hold and retry later.
                let outcome = if entry.expires_at_ms <= wall {
                    match give_up_outbound(
                        data_dir,
                        &mut store,
                        &key,
                        peer,
                        &row.session_id,
                        &row.object_digest,
                        &row.message_id,
                        HISTORY_EXPIRED,
                    ) {
                        Ok(GiveUp::Abandoned) => Outcome::Expired,
                        Ok(GiveUp::Delivered) => Outcome::Delivered { carrier: None },
                        Err(_) => Outcome::Held(code::STORE),
                    }
                } else {
                    Outcome::Held(code::CLOCK)
                };
                if !matches!(outcome, Outcome::Held(_)) {
                    finished.push(row.message_id);
                }
                report.outcomes.insert(entry.object_digest, outcome);
            }
            Captured::Failed => {
                report
                    .outcomes
                    .insert(entry.object_digest, Outcome::Held(code::STORE));
            }
        }
    }
    drop(lock);

    // ── Without the lock: one dial per route, every due frame in it ──
    let mut acks_sent: HashSet<[u8; 32]> = HashSet::new();
    let mut replies: Vec<Vec<u8>> = Vec::new();
    let mut order: Vec<(OutboxRoute, OutboxRoute)> = Vec::new();
    let ack_route_count = if owed.is_empty() { 0 } else { ack_routes.len() };
    for route in candidates
        .iter()
        .flat_map(|c| c.routes.iter())
        .chain(ack_routes[..ack_route_count].iter())
    {
        if !order.contains(route) {
            order.push(route.clone());
        }
    }
    for (planned, dial) in &order {
        let mut frames: Vec<Vec<u8>> = Vec::new();
        let mut in_batch: Vec<usize> = Vec::new();
        let mut acks_in_batch: Vec<[u8; 32]> = Vec::new();
        if ack_routes.iter().any(|(p, _)| p == planned) {
            for (digest, ack) in &owed {
                if frames.len() < MAX_FRAMES_PER_DIAL
                    && !acks_sent.contains(digest)
                    && ack.expires_at_ms > wall
                {
                    frames.push(ack.bytes.clone());
                    acks_in_batch.push(*digest);
                }
            }
        }
        for (i, c) in candidates.iter().enumerate() {
            if frames.len() < MAX_FRAMES_PER_DIAL
                && c.sent.is_none()
                && c.routes.iter().any(|(p, _)| p == planned)
            {
                frames.push(c.bytes.clone());
                in_batch.push(i);
            }
        }
        if frames.is_empty() {
            continue;
        }
        match ctx.dialer.dial(data_dir, dial, &peer_hex, &frames) {
            Ok(got) => {
                replies.extend(got);
                acks_sent.extend(acks_in_batch);
                for i in in_batch {
                    candidates[i].sent = Some(planned.carrier);
                }
            }
            Err(e) => {
                let why = dial_error_code(&e);
                for i in in_batch {
                    let c = &mut candidates[i];
                    c.last_try = Some((planned.carrier, why));
                    if blocks_route(why) {
                        report
                            .blocked
                            .entry(c.digest)
                            .or_default()
                            .push((planned.clone(), why));
                    }
                }
            }
        }
    }
    for (digest, ack) in &owed {
        if acks_sent.contains(digest) || ack.expires_at_ms <= wall {
            report.acks_done.push(*digest);
        }
    }
    if candidates.is_empty() {
        let _ = clear_object_routes(data_dir, &finished);
        return report;
    }

    // ── Under the lock again: record handoffs, verify the ACKs ──
    let Ok(_lock) = PeerSendLock::acquire_within(data_dir, peer, LOCK_WAIT * 5) else {
        // `raven send` holds the peer: record nothing now. The next attempt
        // re-sends the same bytes and gets the same ACK back (a duplicate).
        for c in &candidates {
            let outcome = match c.sent {
                Some(carrier) => Outcome::Sent {
                    carrier: Some(carrier),
                    code: code::SEND_IN_PROGRESS,
                },
                None => Outcome::Held(code::SEND_IN_PROGRESS),
            };
            report.outcomes.insert(c.digest, outcome);
        }
        let _ = clear_object_routes(data_dir, &finished);
        return report;
    };
    let wall_after = now_ms();
    for c in candidates.iter().filter(|c| c.sent.is_some() && c.pending) {
        let _ = store.retry_endpoint_outbound(
            &c.key,
            &c.digest,
            &local_device,
            wall_after,
            &mut |d: &[u8; 32], _: &[u8]| Ok(*d),
        );
    }
    let mut delivered: HashSet<[u8; 16]> = HashSet::new();
    let sessions: Vec<(IndexedSessionRecordKey, [u8; 32])> = {
        let mut s: Vec<(IndexedSessionRecordKey, [u8; 32])> = Vec::new();
        for c in &candidates {
            if !s.iter().any(|(k, _)| *k == c.key) {
                s.push((c.key.clone(), c.session_id));
            }
        }
        s
    };
    for ack in ack_frames(&replies) {
        for (key, session_id) in &sessions {
            let Some(cert) = certs.get(session_id).cloned().flatten() else {
                continue;
            };
            match accept_sealed_ack(data_dir, &mut store, key, &cert, ack) {
                Ok(mid) => {
                    // The one rule: a message is delivered only by an ACK
                    // that names it.
                    let _ = record_outbound_delivered(data_dir, &mut store, peer, session_id, &mid);
                    delivered.insert(mid);
                    break;
                }
                Err(AckRejected::OtherSession) => continue,
                Err(AckRejected::Refused(_)) => break,
            }
        }
    }
    for c in &candidates {
        let outcome = match (c.kind, c.sent) {
            (EndpointOutboundKind::Ack, Some(carrier)) => Outcome::AckSent { carrier },
            (_, Some(carrier)) if delivered.contains(&c.message_id) => Outcome::Delivered {
                carrier: Some(carrier),
            },
            (_, Some(carrier)) => Outcome::Sent {
                carrier: Some(carrier),
                code: code::NO_ACK_YET,
            },
            (_, None) => {
                let (carrier, why) = c
                    .last_try
                    .map(|(c, w)| (Some(c), w))
                    .unwrap_or((None, code::NO_ROUTE));
                let routes_left = c
                    .routes
                    .iter()
                    .filter(|(p, _)| {
                        !report
                            .blocked
                            .get(&c.digest)
                            .is_some_and(|b| b.iter().any(|(r, _)| r == p))
                    })
                    .count();
                let span_ok = c
                    .first_refusal
                    .is_some_and(|t| mono.saturating_duration_since(t) >= SUPERSEDED_SPAN);
                if why == code::PEER_REFUSED
                    && c.kind == EndpointOutboundKind::Message
                    && c.superseded
                    && c.refusals + 1 >= SUPERSEDED_REFUSALS
                    && span_ok
                {
                    // Sealed under a session the reachable peer keeps refusing
                    // while a newer one exists: it can never be accepted.
                    match give_up_outbound(
                        data_dir,
                        &mut store,
                        &c.key,
                        peer,
                        &c.session_id,
                        &c.digest,
                        &c.message_id,
                        HISTORY_FAILED,
                    ) {
                        Ok(GiveUp::Abandoned) => Outcome::Failed(code::SUPERSEDED),
                        Ok(GiveUp::Delivered) => Outcome::Delivered { carrier: None },
                        Err(_) => Outcome::Unreachable { carrier, code: why },
                    }
                } else if routes_left == 0 {
                    Outcome::Held(why)
                } else {
                    Outcome::Unreachable { carrier, code: why }
                }
            }
        };
        if matches!(
            outcome,
            Outcome::Delivered { .. } | Outcome::Failed(_) | Outcome::Expired
        ) {
            finished.push(c.message_id);
        }
        report.outcomes.insert(c.digest, outcome);
    }
    drop(_lock);
    let _ = clear_object_routes(data_dir, &finished);
    report
}

/// The decisions that need no network, under the lock: already delivered,
/// not ours to send, expired. `None`: it needs a dial.
#[allow(clippy::too_many_arguments)]
fn settle_locally(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    keys: &HashMap<[u8; 32], Option<IndexedSessionRecordKey>>,
    bodies: &mut LocalBodies,
    peer: &[u8; 32],
    entry: &Entry,
    row: &EndpointOutbound,
    wall: u64,
) -> Option<Outcome> {
    let expired = entry.expires_at_ms <= wall;
    if row.kind == EndpointOutboundKind::Ack {
        // A prepared ACK past its validity is retired by the store itself.
        return expired.then_some(Outcome::Expired);
    }
    // An ACK that came back another way (pushed by the receiver, F8) already
    // delivered it: record that and never dial it again.
    match outbound_already_delivered(store, &row.session_id, &row.message_id, peer) {
        Ok(true) => {
            return Some(
                match record_outbound_delivered(
                    data_dir,
                    store,
                    peer,
                    &row.session_id,
                    &row.message_id,
                ) {
                    Ok(()) => Outcome::Delivered { carrier: None },
                    Err(_) => Outcome::Held(code::HISTORY),
                },
            );
        }
        Ok(false) => {}
        Err(_) => return Some(Outcome::Held(code::STORE)),
    }
    let Some(key) = keys.get(&row.session_id).cloned().flatten() else {
        return Some(Outcome::Gone);
    };
    // Not staged by `raven send` (sealed by `SealUnderSession` for another
    // path): no body to record a delivery against, so never dialled and never
    // abandoned here; its session's prune removes it.
    if !bodies.has(data_dir, peer, &row.message_id) {
        return Some(Outcome::Held(code::NO_LOCAL_BODY));
    }
    if expired {
        return Some(
            match give_up_outbound(
                data_dir,
                store,
                &key,
                peer,
                &row.session_id,
                &row.object_digest,
                &row.message_id,
                HISTORY_EXPIRED,
            ) {
                Ok(GiveUp::Abandoned) => Outcome::Expired,
                Ok(GiveUp::Delivered) => Outcome::Delivered { carrier: None },
                Err(_) => Outcome::Held(code::STORE),
            },
        );
    }
    None
}

/// The exact bytes of one object, validated by the store (session, signer,
/// time window) without handing anything off: the callback refuses, so the
/// store changes nothing.
enum Captured {
    Bytes {
        bytes: Vec<u8>,
        pending: bool,
    },
    /// The store says nothing is left to send (an ACK delivered it).
    Delivered,
    Gone,
    /// `EndpointNotCurrentlyValid`: expired, or the clock moved.
    NotValid,
    Failed,
}

fn capture(
    store: &mut IndexedSessionStore,
    key: &IndexedSessionRecordKey,
    row: &EndpointOutbound,
    local_device: &AuthorizedEndpointDevice<'_>,
    wall: u64,
) -> Captured {
    let taken = RefCell::new(None::<Vec<u8>>);
    let mut grab = |d: &[u8; 32], bytes: &[u8]| {
        if *d == row.object_digest {
            *taken.borrow_mut() = Some(bytes.to_vec());
        }
        Err(())
    };
    let pending = row.state == EndpointOutboxState::Prepared;
    let result = if pending {
        store.retry_endpoint_outbound(key, &row.object_digest, local_device, wall, &mut grab)
    } else {
        store.resend_queued_endpoint_outbound(
            key,
            &row.object_digest,
            local_device,
            wall,
            &mut grab,
        )
    };
    match result {
        Err(IndexedSessionStoreError::OutboundQueueHandoff) => match taken.into_inner() {
            Some(bytes) => Captured::Bytes { bytes, pending },
            None => Captured::Failed,
        },
        // A resend the store skipped: the outstanding row is no longer `Sent`.
        Ok(_) if !pending => Captured::Delivered,
        // A prepared row that is already queued (handed off meanwhile).
        Ok(_) => {
            let again = RefCell::new(None::<Vec<u8>>);
            match store.resend_queued_endpoint_outbound(
                key,
                &row.object_digest,
                local_device,
                wall,
                &mut |d: &[u8; 32], bytes: &[u8]| {
                    if *d == row.object_digest {
                        *again.borrow_mut() = Some(bytes.to_vec());
                    }
                    Err(())
                },
            ) {
                Err(IndexedSessionStoreError::OutboundQueueHandoff) => match again.into_inner() {
                    Some(bytes) => Captured::Bytes {
                        bytes,
                        pending: false,
                    },
                    None => Captured::Failed,
                },
                Ok(_) => Captured::Delivered,
                Err(IndexedSessionStoreError::EndpointNotCurrentlyValid) => Captured::NotValid,
                Err(
                    IndexedSessionStoreError::NotFound | IndexedSessionStoreError::BindingConflict,
                ) => Captured::Gone,
                Err(_) => Captured::Failed,
            }
        }
        Err(IndexedSessionStoreError::EndpointNotCurrentlyValid) => Captured::NotValid,
        Err(IndexedSessionStoreError::NotFound | IndexedSessionStoreError::BindingConflict) => {
            Captured::Gone
        }
        Err(_) => Captured::Failed,
    }
}

/// An object the store no longer holds: delivered (an ACK reached us some
/// other way: the history is repaired too), or given up elsewhere. A message
/// pruned with its expired session still has its staged body: record it as
/// expired, which nobody else would.
fn finalize_vanished(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    gone: &Entry,
    wall: u64,
) -> Outcome {
    match store.outstanding_delivery_state(&gone.session_id, &gone.message_id, peer) {
        Ok(Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)) => {
            let _ = raven_core::outbox::record_inbound_ack_delivery(
                data_dir,
                peer,
                &gone.session_id,
                &gone.message_id,
            );
            return Outcome::Delivered { carrier: None };
        }
        Ok(Some(EndpointDeliveryState::Sent)) => {
            // Still outstanding but no longer listed (a scan race): look
            // again next round.
            return Outcome::Sent {
                carrier: None,
                code: gone.last_error,
            };
        }
        Ok(None) | Err(_) => {}
    }
    if gone.kind != EndpointOutboundKind::Message {
        return Outcome::Gone;
    }
    let staged = raven_core::load_staged_outbound_body(data_dir, &gone.message_id)
        .ok()
        .flatten()
        .filter(|s| {
            s.peer_pub_hex.eq_ignore_ascii_case(&hex::encode(peer))
                && s.session_id_hex
                    .eq_ignore_ascii_case(&hex::encode(gone.session_id))
        });
    if staged.is_none() {
        return Outcome::Gone;
    }
    let (delivery, outcome) = if gone.expires_at_ms <= wall {
        (HISTORY_EXPIRED, Outcome::Expired)
    } else {
        (HISTORY_FAILED, Outcome::Failed(code::STORE))
    };
    match raven_core::outbox::mark_outbound_undelivered(
        data_dir,
        peer,
        &gone.session_id,
        &gone.object_digest,
        &gone.message_id,
        delivery,
    ) {
        Ok(()) => outcome,
        Err(_) => Outcome::Gone,
    }
}

/// A failed or panicking pass is logged once an hour at most.
static WORKER_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(3600));

/// The service's outbox worker (supervised in `main`).
pub async fn run_worker(data_dir: PathBuf) -> Result<(), String> {
    let identity = Arc::new(
        netutil::retry_until_ok("outbox", || {
            let dd = data_dir.clone();
            async move {
                tokio::task::spawn_blocking(move || {
                    raven_core::load_identity_required(&dd).map_err(|e| e.to_string())
                })
                .await
                .map_err(|e| format!("outbox blocking join: {e}"))?
            }
        })
        .await,
    );
    let ctx = Arc::new(AttemptCtx {
        data_dir,
        identity,
        dialer: Arc::new(NetDialer {
            handle: tokio::runtime::Handle::current(),
        }),
        lan_live: raven_core::lan_direct_live_enabled,
        internet_live: raven_core::internet_direct_live_enabled,
        p2p_live: raven_core::p2p_live_enabled,
    });
    run_loop(ctx).await
}

struct RunningGuard;

impl Drop for RunningGuard {
    fn drop(&mut self) {
        let mut inner = lock(&outbox().inner);
        inner.running = false;
        inner.in_flight.clear();
    }
}

async fn run_loop(ctx: Arc<AttemptCtx>) -> Result<(), String> {
    let ob = outbox();
    {
        let mut inner = lock(&ob.inner);
        inner.running = true;
        inner.refresh = true;
    }
    let _running = RunningGuard;
    eprintln!("raven-node outbox: running");
    let mut last_scan = Instant::now();
    loop {
        let (refresh, idle_refresh, scan_seq) = {
            let mut inner = lock(&ob.inner);
            (
                std::mem::take(&mut inner.refresh),
                inner.idle_refresh(),
                inner.scan_seq(),
            )
        };
        if refresh || last_scan.elapsed() >= idle_refresh {
            last_scan = Instant::now();
            let dd = ctx.data_dir.clone();
            match tokio::task::spawn_blocking(move || scan_store(&dd)).await {
                Ok(Ok(rows)) => lock(&ob.inner).merge(rows, scan_seq, Instant::now(), now_ms()),
                Ok(Err(e)) => netutil::log_limited(&WORKER_LOG, "outbox scan failed", e),
                Err(e) => netutil::log_limited(&WORKER_LOG, "outbox scan failed", e),
            }
        }
        let due = lock(&ob.inner).take_due(Instant::now());
        for work in due {
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                let peer = work.peer;
                let attempted: Vec<[u8; 32]> =
                    work.entries.iter().map(|e| e.object_digest).collect();
                let report = tokio::task::spawn_blocking(move || {
                    attempt_peer(&ctx, &work.peer, &work.entries, &work.acks)
                })
                .await
                .unwrap_or_else(|e| {
                    netutil::log_limited(&WORKER_LOG, "outbox attempt failed", e);
                    PeerReport {
                        attempted,
                        held: Some(code::STORE),
                        ..PeerReport::default()
                    }
                });
                let ob = outbox();
                lock(&ob.inner).apply(&peer, report, Instant::now(), now_ms());
                ob.wake.notify_one();
            });
        }
        let wait = {
            let inner = lock(&ob.inner);
            let idle = inner.idle_refresh().saturating_sub(last_scan.elapsed());
            inner
                .next_due_in(Instant::now())
                .map(|d| d.min(idle))
                .unwrap_or(idle)
        };
        tokio::select! {
            _ = tokio::time::sleep(wait.max(Duration::from_millis(50))) => {}
            _ = ob.wake.notified() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::lan_dispatch::{
        cache_peer_bundle, create_initiator_pair_init, dispatch_frame, local_bundle, wrap_pair_init,
    };
    use raven_core::outbox::record_object_routes;
    use raven_core::{classify_packed_envelope, LanBundle, PairInitOobClassify};
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

    /// The lab file backends; these tests never reach an OS keystore. Set once
    /// (a restore would race the other tests, which use the same backends).
    fn lab_backends() -> bool {
        static ONCE: std::sync::Once = std::sync::Once::new();
        if !cfg!(debug_assertions) {
            eprintln!("skipped: the lab locked-file backends need a debug build");
            return false;
        }
        ONCE.call_once(|| {
            for key in [
                "RAVEN_SESSION_BACKEND",
                "RAVEN_PREKEY_BACKEND",
                "RAVEN_CHAT_HISTORY_BACKEND",
                "RAVEN_IDENTITY_BACKEND",
            ] {
                // Edition 2021: a plain call. Set before any store opens.
                std::env::set_var(key, "locked-file");
            }
        });
        true
    }

    const UP: u8 = 0;
    const DOWN: u8 = 1;
    const REFUSE: u8 = 2;
    const WRONG_ID: u8 = 3;
    const NOT_ACCEPTED: u8 = 4;

    /// B's side of a dial, in process: the frames go to B's real dispatcher.
    struct FakeNet {
        b_dir: PathBuf,
        bob: Identity,
        a_bundle: LanBundle,
        alice_pub: [u8; 32],
        mode: AtomicU8,
        dials: AtomicUsize,
        internet_dials: AtomicUsize,
        /// (route dialled, frames) per dial.
        log: Mutex<Vec<(OutboxRoute, usize)>>,
        /// Set by a test: the A data dir whose send lock a dial checks.
        lock_probe: Mutex<Option<(PathBuf, [u8; 32])>>,
        lock_free_during_dial: AtomicBool,
    }

    impl Dialer for FakeNet {
        fn dial(
            &self,
            _data_dir: &Path,
            route: &OutboxRoute,
            _expected: &str,
            frames: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            self.log.lock().unwrap().push((route.clone(), frames.len()));
            if let Some((dir, peer)) = self.lock_probe.lock().unwrap().clone() {
                let free = PeerSendLock::acquire_within(&dir, &peer, Duration::ZERO).is_ok();
                self.lock_free_during_dial.store(free, Ordering::SeqCst);
            }
            if route.carrier == OutboxCarrier::Internet {
                self.internet_dials.fetch_add(1, Ordering::SeqCst);
            }
            match self.mode.load(Ordering::SeqCst) {
                DOWN => {
                    return Err(
                        "lan connect: cannot connect to 127.0.0.1:9 (Connection refused)".into(),
                    )
                }
                REFUSE => {
                    return Err(
                        "LAN_DIAL_PEER_CLOSED: the peer closed the connection without \
                                replying; the frames were sent"
                            .into(),
                    )
                }
                WRONG_ID => return Err("rlb1 offer identity mismatch".into()),
                NOT_ACCEPTED => return Err(crate::netutil::LINK_NOT_ACCEPTED.into()),
                _ => {}
            }
            let mut replies = vec![raven_core::encode_local_offer(&self.b_dir, &self.bob).unwrap()];
            for f in frames {
                if let Ok(more) =
                    dispatch_frame(&self.b_dir, &self.bob, &self.a_bundle, &self.alice_pub, f)
                {
                    replies.extend(more);
                }
            }
            Ok(replies)
        }
    }

    struct Rig {
        a: tempfile::TempDir,
        b: tempfile::TempDir,
        alice: Arc<Identity>,
        bob_pub: [u8; 32],
        b_bundle: LanBundle,
        net: Arc<FakeNet>,
        key: IndexedSessionRecordKey,
    }

    fn contacts(dir: &Path, peer: &[u8; 32], lan: &str, inet: &str, pinned: bool) {
        std::fs::write(
            dir.join("contacts.json"),
            format!(
                r#"[{{"petname":"Peer","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":{pinned},"lan_dial":"{lan}","internet_dial":"{inet}"}}]"#,
                hex::encode(peer)
            ),
        )
        .unwrap();
    }

    fn pair(
        a: &Path,
        alice: &Identity,
        b: &Path,
        bob: &Identity,
        a_bundle: &LanBundle,
        b_bundle: &LanBundle,
    ) -> IndexedSessionRecordKey {
        let (init, key) = create_initiator_pair_init(a, alice, b_bundle).unwrap();
        let replies = dispatch_frame(
            b,
            bob,
            a_bundle,
            &alice.public_key_bytes(),
            &wrap_pair_init(alice, &init).unwrap(),
        )
        .unwrap();
        let response = replies
            .iter()
            .find_map(|f| match classify_packed_envelope(f) {
                PairInitOobClassify::PairResponse(w) => {
                    raven_core::pair_init::decode_response(&w).ok()
                }
                _ => None,
            })
            .expect("PairResponse");
        IndexedSessionStore::open(a)
            .unwrap()
            .confirm_verified_pair_response(&key, &init, &response, now_ms())
            .unwrap();
        key
    }

    impl Rig {
        /// Alice and Bob, mutual contacts with a confirmed session (Alice
        /// initiated), and Bob's bundle in Alice's durable cache.
        fn new(seed: u8) -> Self {
            let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let alice = Identity::from_seed(&[seed; 32]);
            let bob = Identity::from_seed(&[seed.wrapping_add(1); 32]);
            for (dir, id) in [(a.path(), &alice), (b.path(), &bob)] {
                ensure_local_device_certificate(dir, id, PRIMARY_DEVICE_ID).unwrap();
                raven_core::ensure_local_prekey(dir, id).unwrap();
            }
            let (alice_pub, bob_pub) = (alice.public_key_bytes(), bob.public_key_bytes());
            contacts(a.path(), &bob_pub, "127.0.0.1:9", "", false);
            contacts(b.path(), &alice_pub, "", "", false);
            let a_bundle = local_bundle(a.path(), &alice).unwrap();
            let b_bundle = local_bundle(b.path(), &bob).unwrap();
            cache_peer_bundle(a.path(), &b_bundle).unwrap();
            let key = pair(a.path(), &alice, b.path(), &bob, &a_bundle, &b_bundle);
            let net = Arc::new(FakeNet {
                b_dir: b.path().to_path_buf(),
                bob,
                a_bundle,
                alice_pub,
                mode: AtomicU8::new(DOWN),
                dials: AtomicUsize::new(0),
                internet_dials: AtomicUsize::new(0),
                log: Mutex::new(Vec::new()),
                lock_probe: Mutex::new(None),
                lock_free_during_dial: AtomicBool::new(false),
            });
            Self {
                a,
                b,
                alice: Arc::new(alice),
                bob_pub,
                b_bundle,
                net,
                key,
            }
        }

        fn set(&self, mode: u8) {
            self.net.mode.store(mode, Ordering::SeqCst);
        }

        fn dials(&self) -> usize {
            self.net.dials.load(Ordering::SeqCst)
        }

        fn ctx_with(&self, lan_live: fn() -> bool, internet_live: fn() -> bool) -> AttemptCtx {
            AttemptCtx {
                data_dir: self.a.path().to_path_buf(),
                identity: Arc::clone(&self.alice),
                dialer: self.net.clone(),
                lan_live,
                internet_live,
                p2p_live: off,
            }
        }

        fn ctx(&self) -> AttemptCtx {
            self.ctx_with(on, off)
        }

        /// `raven send` while Bob is down: staged (history `queued`, protected
        /// body), its dial failed, so the row stays pending. Sealed at
        /// `created`, valid for `validity_ms` (capped by the session).
        fn stage_at(&self, text: &str, created: u64, validity_ms: u64) -> [u8; 16] {
            let (cert, registry) =
                ensure_local_device_certificate(self.a.path(), &self.alice, PRIMARY_DEVICE_ID)
                    .unwrap();
            let device =
                AuthorizedEndpointDevice::authorize(&cert, &self.alice, &registry, created)
                    .unwrap();
            let mut store = IndexedSessionStore::open(self.a.path()).unwrap();
            let session = store.session_id_for_record_key(&self.key).unwrap();
            let session_end = store.session_expires_at(&self.key).unwrap();
            let staged = std::cell::Cell::new(None::<[u8; 16]>);
            let (a_dir, bob_pub) = (self.a.path().to_path_buf(), self.bob_pub);
            let result = store.send_message_envelope(
                &self.key,
                text,
                &device,
                created,
                (created + validity_ms).min(session_end),
                created,
                &mut rand::rngs::OsRng,
                &mut |digest: &[u8; 32], bytes: &[u8]| {
                    let env = Envelope::unpack(bytes).unwrap();
                    raven_core::ensure_outbound_queued_history(
                        &a_dir,
                        &bob_pub,
                        &session,
                        digest,
                        &env.message_id,
                        created,
                        Some(text),
                    )
                    .unwrap();
                    staged.set(Some(env.message_id));
                    Err(())
                },
            );
            let err = result.expect_err("the dial failed: the row stays pending");
            staged
                .get()
                .unwrap_or_else(|| panic!("not staged: {}", err.redacted_display()))
        }

        fn stage(&self, text: &str, validity_ms: u64) -> [u8; 16] {
            self.stage_at(text, now_ms(), validity_ms)
        }

        fn record(&self, mid: &[u8; 16], choice: CarrierChoice, routes: &[OutboxRoute]) {
            record_object_routes(
                self.a.path(),
                mid,
                &self.bob_pub,
                choice,
                routes,
                now_ms() + DAY,
                now_ms(),
            )
            .unwrap();
        }

        fn due(&self) -> Vec<Entry> {
            let now = Instant::now();
            scan_store(self.a.path())
                .unwrap()
                .iter()
                .map(|r| Entry::from_row(r, now))
                .collect()
        }

        fn attempt_with(&self, ctx: &AttemptCtx) -> PeerReport {
            attempt_peer(ctx, &self.bob_pub, &self.due(), &[])
        }

        fn attempt(&self) -> PeerReport {
            self.attempt_with(&self.ctx())
        }

        fn history(&self, mid: &[u8; 16]) -> Option<String> {
            raven_core::ChatHistory::load(self.a.path())
                .unwrap()
                .entries
                .into_iter()
                .find(|e| e.direction == "out" && e.message_id_hex == hex::encode(mid))
                .map(|e| e.delivery)
        }

        fn bob_inbox(&self) -> Vec<String> {
            IndexedSessionStore::open(self.b.path())
                .unwrap()
                .list_endpoint_inbox()
                .unwrap()
                .into_iter()
                .map(|r| String::from_utf8_lossy(&r.plaintext).into_owned())
                .collect()
        }

        /// The exact staged bytes of the one pending row.
        fn staged_bytes(&self) -> Vec<u8> {
            IndexedSessionStore::open(self.a.path())
                .unwrap()
                .pending_endpoint_outbound()
                .unwrap()
                .remove(0)
                .immutable_envelope_bytes
        }

        /// Bob accepts `bytes` directly (our dial broke before the reply) and
        /// returns his sealed ACK.
        fn bob_accepts(&self, bytes: &[u8]) -> Vec<u8> {
            dispatch_frame(
                self.b.path(),
                &self.net.bob,
                &self.net.a_bundle,
                &self.alice.public_key_bytes(),
                bytes,
            )
            .unwrap()
            .into_iter()
            .find(|f| Envelope::unpack(f).is_some())
            .expect("Bob's ACK")
        }
    }

    fn on() -> bool {
        true
    }

    fn off() -> bool {
        false
    }

    const DAY: u64 = 24 * 60 * 60 * 1000;

    fn only(report: &PeerReport) -> Outcome {
        assert_eq!(report.outcomes.len(), 1, "{:?}", report.outcomes);
        report.outcomes.values().next().unwrap().clone()
    }

    fn lan(d: &str) -> OutboxRoute {
        OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: d.into(),
        }
    }

    fn sched_row(d: u8, peer: u8, expires_at_ms: u64) -> ScanRow {
        ScanRow {
            object_digest: [d; 32],
            kind: EndpointOutboundKind::Message,
            session_id: [9; 32],
            message_id: [d; 16],
            recipient: [peer; 32],
            expires_at_ms,
            state: EntryState::Queued,
        }
    }

    fn report_for(digest: [u8; 32], outcome: Outcome) -> PeerReport {
        let mut r = PeerReport {
            attempted: vec![digest],
            ..PeerReport::default()
        };
        r.outcomes.insert(digest, outcome);
        r
    }

    fn unreachable() -> Outcome {
        Outcome::Unreachable {
            carrier: Some(OutboxCarrier::Lan),
            code: code::NOT_REACHABLE,
        }
    }

    #[test]
    fn a_queued_message_is_retried_until_the_ack_and_then_left_alone() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x81);
        let mid = rig.stage("while you were away", DAY);
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        // Bob is down: one dial, backed off, still queued.
        let outcome = only(&rig.attempt());
        assert_eq!(
            outcome,
            Outcome::Unreachable {
                carrier: Some(OutboxCarrier::Lan),
                code: code::NOT_LISTENING
            }
        );
        assert_eq!(rig.dials(), 1);
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        assert!(rig.bob_inbox().is_empty());
        // Bob is back: the exact staged bytes go out, the sealed ACK verifies.
        rig.set(UP);
        assert_eq!(
            only(&rig.attempt()),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
        assert_eq!(rig.bob_inbox(), vec!["while you were away"]);
        assert!(raven_core::load_staged_outbound_body(rig.a.path(), &mid)
            .unwrap()
            .is_none());
        // Cancel on ACK: nothing is left to send, nothing is dialled again.
        let dials = rig.dials();
        assert!(scan_store(rig.a.path()).unwrap().is_empty());
        assert!(attempt_peer(&rig.ctx(), &rig.bob_pub, &[], &[])
            .outcomes
            .is_empty());
        assert_eq!(rig.dials(), dials);
        assert_eq!(rig.bob_inbox(), vec!["while you were away"], "exactly once");
    }

    #[test]
    fn an_expired_message_is_abandoned_and_the_history_says_expired() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x83);
        rig.set(UP);
        let mid = rig.stage("too late", 1_500);
        std::thread::sleep(Duration::from_millis(1_600));
        assert_eq!(only(&rig.attempt()), Outcome::Expired);
        assert_eq!(rig.dials(), 0, "nothing dialled");
        assert_eq!(rig.history(&mid).as_deref(), Some(HISTORY_EXPIRED));
        assert!(scan_store(rig.a.path()).unwrap().is_empty());
        assert!(rig.bob_inbox().is_empty());
    }

    #[test]
    fn a_removed_or_blocked_contact_fails_closed_and_nothing_is_dialled() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x85);
        rig.set(UP);
        let mid = rig.stage("hold this", DAY);
        let mut blocks = raven_core::BlockList::default();
        blocks.block(&hex::encode(rig.bob_pub));
        blocks.save(rig.a.path()).unwrap();
        assert_eq!(rig.attempt().held, Some(code::CONTACT_BLOCKED));
        assert_eq!(rig.dials(), 0);
        raven_core::BlockList::default().save(rig.a.path()).unwrap();
        std::fs::write(rig.a.path().join("contacts.json"), "[]").unwrap();
        assert_eq!(rig.attempt().held, Some(code::NOT_A_CONTACT));
        assert_eq!(rig.dials(), 0);
        // Held, not destroyed: still queued, and restoring the contact resumes.
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        assert_eq!(scan_store(rig.a.path()).unwrap().len(), 1);
        contacts(rig.a.path(), &rig.bob_pub, "127.0.0.1:9", "", false);
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
        // An unreadable book trusts nobody.
        let mid2 = rig.stage("second", DAY);
        std::fs::write(rig.a.path().join("contacts.json"), "{not json").unwrap();
        let dials = rig.dials();
        assert!(rig.attempt().held.is_some());
        assert_eq!(rig.dials(), dials);
        assert_eq!(rig.history(&mid2).as_deref(), Some("queued"));
    }

    #[test]
    fn a_revoked_peer_lineage_is_abandoned_before_any_dial() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x87);
        rig.set(UP);
        let mid = rig.stage("not to a revoked device", DAY);
        let bob = Identity::from_seed(&[0x88; 32]);
        let mut store = raven_core::RevocationStore::load_checked(rig.a.path()).unwrap();
        let rec =
            raven_core::RevocationRecord::issue(&bob, PRIMARY_DEVICE_ID, 1, 10, "test").unwrap();
        assert!(store.apply(rec).unwrap());
        store.save(rig.a.path()).unwrap();
        assert_eq!(only(&rig.attempt()), Outcome::Failed(code::PEER_REVOKED));
        assert_eq!(rig.dials(), 0);
        assert_eq!(rig.history(&mid).as_deref(), Some(HISTORY_FAILED));
        assert!(rig.bob_inbox().is_empty());
    }

    /// The Internet gate and the verified-contact rule hold for the worker.
    #[test]
    fn the_internet_gate_and_the_verified_contact_rule_hold() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x89);
        rig.set(UP);
        contacts(rig.a.path(), &rig.bob_pub, "", "203.0.113.7:7422", false);
        let mid = rig.stage("over the internet", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(on, off))),
            Outcome::Held(code::NO_ROUTE)
        );
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(on, on))),
            Outcome::Held(CONTACT_NOT_VERIFIED)
        );
        assert_eq!(rig.net.internet_dials.load(Ordering::SeqCst), 0);
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        contacts(rig.a.path(), &rig.bob_pub, "", "203.0.113.7:7422", true);
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(on, off))),
            Outcome::Held(code::NO_ROUTE),
            "the gate still decides"
        );
        assert_eq!(rig.net.internet_dials.load(Ordering::SeqCst), 0);
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(on, on))),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Internet)
            }
        );
    }

    /// M: LAN routes need the LAN gate; with both gates off nothing is planned.
    #[test]
    fn the_lan_gate_is_honoured_and_both_gates_off_plan_nothing() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x8a);
        rig.set(UP);
        rig.stage("gated", DAY);
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(off, off))),
            Outcome::Held(code::NO_ROUTE)
        );
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(off, on))),
            Outcome::Held(code::NO_ROUTE),
            "no record: LAN only, and LAN is gated"
        );
        assert_eq!(rig.dials(), 0);
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
    }

    /// K: the worker takes `raven send`'s lock, steps back while ash holds it,
    /// and never holds it across a dial.
    #[test]
    fn the_send_lock_is_shared_with_raven_send_but_never_held_across_a_dial() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x8b);
        rig.set(UP);
        rig.stage("wait for ash", DAY);
        let ash = PeerSendLock::acquire_within(rig.a.path(), &rig.bob_pub, Duration::ZERO)
            .expect("ash takes the lock");
        assert_eq!(rig.attempt().held, Some(code::SEND_IN_PROGRESS));
        assert_eq!(rig.dials(), 0);
        let t = Instant::now();
        let mut entry = rig.due().remove(0);
        apply_outcome(
            &mut entry,
            Outcome::Held(code::SEND_IN_PROGRESS),
            t,
            now_ms(),
        );
        assert_eq!(entry.failures, 0);
        assert_eq!(entry.next_due, t + LOCK_BUSY_RETRY);
        drop(ash);
        *rig.net.lock_probe.lock().unwrap() = Some((rig.a.path().to_path_buf(), rig.bob_pub));
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
        assert!(
            rig.net.lock_free_during_dial.load(Ordering::SeqCst),
            "`raven send` could take the lock while the worker dialled"
        );
    }

    /// The schedule lives in memory only: a new process rebuilds it from the
    /// store, every object due at once, without a new send.
    #[test]
    fn the_schedule_is_rebuilt_from_the_store_after_a_restart() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x8d);
        rig.stage("survives a restart", DAY);
        let t0 = Instant::now();
        let mut inner = Inner::default();
        inner.merge(scan_store(rig.a.path()).unwrap(), 0, t0, now_ms());
        assert_eq!(inner.entries.len(), 1);
        let entry = inner.entries.values().next().unwrap().clone();
        assert_eq!((entry.state, entry.attempts), (EntryState::Queued, 0));
        assert_eq!(entry.next_due, t0, "due at once");
        let due = inner.take_due(t0);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].peer, rig.bob_pub);
        assert!(inner.take_due(t0).is_empty(), "one attempt per peer");
        inner.apply(
            &rig.bob_pub,
            report_for(entry.object_digest, unreachable()),
            t0,
            now_ms(),
        );
        let after = inner.entries.values().next().unwrap().clone();
        assert_eq!((after.attempts, after.failures), (1, 1));
        let wait = after.next_due - t0;
        assert!(
            (MIN_RETRY..=Duration::from_millis(7_500)).contains(&wait),
            "{wait:?}"
        );
        let seq = inner.scan_seq();
        inner.merge(
            scan_store(rig.a.path()).unwrap(),
            seq,
            t0 + Duration::from_secs(1),
            now_ms(),
        );
        assert_eq!(
            inner.entries.values().next().unwrap().next_due,
            after.next_due
        );
    }

    /// A: an expired object whose finalization fails (store, lock, abandon)
    /// backs off at least 5 s from now: no hot loop past an expiry.
    #[test]
    fn an_expired_object_that_cannot_be_finalized_backs_off() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall - 5_000)], 0, t0, wall);
        let peer = [0xB0; 32];
        let mut now = t0;
        for why in [code::STORE, code::LOCK, code::STORE, code::STORE] {
            let due = inner.take_due(now);
            assert_eq!(due.len(), 1, "due once");
            inner.apply(&peer, report_for([1; 32], Outcome::Held(why)), now, wall);
            let wait = inner.next_due_in(now).unwrap();
            assert!(wait >= MIN_RETRY, "{why}: due again after {wait:?}");
            assert!(inner.take_due(now).is_empty());
            now += wait;
        }
        // And with the real store: a broken session (secret gone) past expiry.
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x8f);
        rig.stage("expires on a broken session", 1_200);
        std::thread::sleep(Duration::from_millis(1_300));
        for e in std::fs::read_dir(rig.a.path().join("indexed-session-secrets")).unwrap() {
            std::fs::remove_file(e.unwrap().path()).unwrap();
        }
        let report = rig.attempt();
        assert!(
            matches!(only(&report), Outcome::Held(_)),
            "{:?}",
            report.outcomes
        );
        let mut entry = rig.due().remove(0);
        let t = Instant::now();
        apply_outcome(&mut entry, only(&report), t, now_ms());
        assert!(entry.next_due >= t + MIN_RETRY);
        assert_eq!(rig.dials(), 0);
    }

    /// H: only due objects are dialled, each with its own failure count.
    #[test]
    fn only_due_objects_are_attempted_each_with_its_own_backoff() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let mut inner = Inner::default();
        inner.merge(
            vec![
                sched_row(1, 0xB0, wall + DAY),
                sched_row(2, 0xB0, wall + DAY),
            ],
            0,
            t0,
            wall,
        );
        inner.entries.get_mut(&[2; 32]).unwrap().next_due = t0 + Duration::from_secs(300);
        inner.entries.get_mut(&[2; 32]).unwrap().failures = 6;
        let due = inner.take_due(t0);
        assert_eq!(due[0].entries.len(), 1, "only the due object goes");
        assert_eq!(due[0].entries[0].object_digest, [1; 32]);
        inner.apply(&[0xB0; 32], report_for([1; 32], unreachable()), t0, wall);
        let one = &inner.entries[&[1; 32]];
        let two = &inner.entries[&[2; 32]];
        assert_eq!((one.failures, two.failures), (1, 6), "own counts");
        assert_eq!(two.next_due, t0 + Duration::from_secs(300), "untouched");
    }

    /// G: a kick that arrives while the peer's attempt is in flight makes its
    /// objects due again as soon as that attempt ends.
    #[test]
    fn a_kick_during_an_in_flight_attempt_is_honoured() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let peer = [0xB0; 32];
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);
        inner.entries.get_mut(&[1; 32]).unwrap().failures = 8;
        assert_eq!(inner.take_due(t0).len(), 1);
        inner.kick_now(Some(&peer), false, t0 + Duration::from_secs(3));
        let end = t0 + Duration::from_secs(6);
        inner.apply(&peer, report_for([1; 32], unreachable()), end, wall);
        assert_eq!(
            inner.entries[&[1; 32]].next_due, end,
            "due at once, not in 10 min"
        );
        assert_eq!(inner.take_due(end).len(), 1);
    }

    /// D(a): the schedule is monotonic: a wall-clock step either way neither
    /// stalls nor rushes a retry.
    #[test]
    fn a_wall_clock_step_does_not_move_the_schedule() {
        let t0 = Instant::now();
        let wall = 1_000_000_000_000u64;
        for stepped in [wall - 3 * 3_600_000, wall + 3 * 3_600_000] {
            let mut e = Entry::from_row(&sched_row(1, 0xB0, wall + DAY), t0);
            apply_outcome(&mut e, unreachable(), t0, stepped);
            let wait = e.next_due - t0;
            assert!(
                (MIN_RETRY..=Duration::from_millis(7_500)).contains(&wait),
                "{wait:?}"
            );
        }
        // The IPC view shows the next try relative to the wall clock now.
        let mut e = Entry::from_row(&sched_row(1, 0xB0, wall + DAY), t0);
        e.next_due = t0 + Duration::from_secs(40);
        assert_eq!(e.item(t0, wall).next_attempt_ms, wall + 40_000);
    }

    /// I: a scan that started before an attempt finished does not re-add what
    /// that attempt finished.
    #[test]
    fn a_stale_scan_does_not_re_add_a_finished_object() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let peer = [0xB0; 32];
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);
        assert_eq!(inner.take_due(t0).len(), 1);
        let seq = inner.scan_seq();
        let stale = vec![sched_row(1, 0xB0, wall + DAY)];
        inner.apply(
            &peer,
            report_for(
                [1; 32],
                Outcome::Delivered {
                    carrier: Some(OutboxCarrier::Lan),
                },
            ),
            t0,
            wall,
        );
        inner.merge(stale, seq, t0, wall);
        assert!(
            inner.entries.is_empty(),
            "the delivered object stays finished"
        );
        assert_eq!(inner.done.len(), 1);
        // A scan started after the attempt is merged as usual.
        let fresh = inner.scan_seq();
        inner.merge(vec![sched_row(2, 0xB0, wall + DAY)], fresh, t0, wall);
        assert_eq!(inner.entries.len(), 1);
    }

    /// B: a row sealed by `SealUnderSession` (no staged body, no history row)
    /// is never dialled and never destroyed by the worker.
    #[test]
    fn rows_without_a_local_body_are_held_not_destroyed() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x91);
        rig.set(UP);
        raven_core::seal_app_payload_under_session(
            rig.a.path(),
            &rig.alice,
            &hex::encode(rig.bob_pub),
            b"sealed by the daemon for the bridge",
        )
        .unwrap();
        assert_eq!(scan_store(rig.a.path()).unwrap().len(), 1);
        assert_eq!(only(&rig.attempt()), Outcome::Held(code::NO_LOCAL_BODY));
        assert_eq!(rig.dials(), 0, "nothing dialled");
        assert_eq!(scan_store(rig.a.path()).unwrap().len(), 1, "row kept");
    }

    /// C: an ACK that arrived on an inbound link (F8) settles the row; and a
    /// row still `Prepared` whose message an ACK already delivered is
    /// recorded, never dialled.
    #[test]
    fn a_message_delivered_by_an_inbound_ack_is_never_dialled_again() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x93);
        let mid = rig.stage("delivered behind our back", DAY);
        let ack = rig.bob_accepts(&rig.staged_bytes());
        // Bob's outbox pushes the owed ACK to Alice's listener.
        dispatch_frame(rig.a.path(), &rig.alice, &rig.b_bundle, &rig.bob_pub, &ack).unwrap();
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
        assert!(
            scan_store(rig.a.path()).unwrap().is_empty(),
            "the row is settled"
        );
        // Without the settle (an ACK accepted elsewhere): the worker records it.
        let mid2 = rig.stage("second", DAY);
        let ack2 = rig.bob_accepts(&rig.staged_bytes());
        IndexedSessionStore::open(rig.a.path())
            .unwrap()
            .accept_ack_envelope(&rig.key, &ack2, &rig.b_bundle.cert, false, now_ms())
            .unwrap();
        assert_eq!(scan_store(rig.a.path()).unwrap().len(), 1, "still listed");
        assert_eq!(only(&rig.attempt()), Outcome::Delivered { carrier: None });
        assert_eq!(rig.dials(), 0, "a delivered message is not dialled");
        assert_eq!(rig.history(&mid2).as_deref(), Some("delivered"));
        assert!(scan_store(rig.a.path()).unwrap().is_empty());
    }

    /// F: an object that left the store delivered (ACK committed, history not
    /// recorded) has its history repaired when the worker finalizes it.
    #[test]
    fn a_vanished_delivered_object_repairs_the_history() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x95);
        let mid = rig.stage("acked, not recorded", DAY);
        let bytes = rig.staged_bytes();
        let (cert, registry) =
            ensure_local_device_certificate(rig.a.path(), &rig.alice, PRIMARY_DEVICE_ID).unwrap();
        let device =
            AuthorizedEndpointDevice::authorize(&cert, &rig.alice, &registry, now_ms()).unwrap();
        let mut store = IndexedSessionStore::open(rig.a.path()).unwrap();
        let digest = scan_store(rig.a.path()).unwrap()[0].object_digest;
        store
            .retry_endpoint_outbound(
                &rig.key,
                &digest,
                &device,
                now_ms(),
                &mut |d: &[u8; 32], _: &[u8]| Ok(*d),
            )
            .unwrap();
        let tracked = rig.due();
        let ack = rig.bob_accepts(&bytes);
        store
            .accept_ack_envelope(&rig.key, &ack, &rig.b_bundle.cert, false, now_ms())
            .unwrap();
        drop(store);
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &tracked, &[]);
        assert_eq!(only(&report), Outcome::Delivered { carrier: None });
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"), "repaired");
    }

    /// D(b): a message the store refuses only because the clock stepped back
    /// (sealed "in the future") is held, not abandoned as expired.
    #[test]
    fn a_backward_clock_step_does_not_abandon_valid_messages() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x97);
        rig.set(UP);
        let mid = rig.stage_at("sealed with a fast clock", now_ms() + 10 * 60_000, DAY);
        assert_eq!(only(&rig.attempt()), Outcome::Held(code::CLOCK));
        assert_eq!(rig.dials(), 0);
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        assert_eq!(scan_store(rig.a.path()).unwrap().len(), 1, "not abandoned");
    }

    fn ack_envelope(id: u8, expires_at: u64) -> Vec<u8> {
        Envelope {
            env_type: EnvType::Ack as u8,
            flags: 0,
            message_id: [id; 16],
            routing_tag: [0x44; 16],
            dest_device_hint: 0,
            created_at: 1,
            expires_at,
            hop_limit: 4,
            replication_budget: 1,
            anti_replay_nonce: [id; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: vec![id; 8],
            sender_authentication: vec![0u8; 64],
        }
        .pack()
    }

    /// E: owed ACKs and the due message go in ONE dial (one per route), after
    /// the contact, block and revocation checks; a failed push backs off; one
    /// sender cannot fill everybody's slots.
    #[test]
    fn owed_acks_ride_one_dial_with_the_due_objects_after_the_checks() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x99);
        rig.stage("plus a message", DAY);
        let t = Instant::now();
        let owed: Vec<([u8; 32], UnsentAck)> = (0..6u8)
            .map(|i| {
                (
                    [i; 32],
                    UnsentAck {
                        peer: rig.bob_pub,
                        bytes: ack_envelope(i, now_ms() + 3_600_000),
                        expires_at_ms: now_ms() + 3_600_000,
                        failures: 0,
                        next_due: t,
                    },
                )
            })
            .collect();
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &rig.due(), &owed);
        assert_eq!(rig.dials(), 1, "one dial for 6 owed ACKs and 1 message");
        assert_eq!(rig.net.log.lock().unwrap()[0].1, 7, "all in it");
        assert_eq!(report.acks_failed.len(), 6, "they back off together");
        // Not a contact any more: no dial, the ACKs are dropped.
        std::fs::write(rig.a.path().join("contacts.json"), "[]").unwrap();
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &[], &owed);
        assert_eq!(rig.dials(), 1);
        assert_eq!(report.acks_done.len(), 6);
        // Revoked: no dial either.
        contacts(rig.a.path(), &rig.bob_pub, "127.0.0.1:9", "", false);
        let bob = Identity::from_seed(&[0x9a; 32]);
        let mut rev = raven_core::RevocationStore::load_checked(rig.a.path()).unwrap();
        assert!(rev
            .apply(
                raven_core::RevocationRecord::issue(&bob, PRIMARY_DEVICE_ID, 1, 10, "t").unwrap()
            )
            .unwrap());
        rev.save(rig.a.path()).unwrap();
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &[], &owed);
        assert_eq!(rig.dials(), 1, "nothing to a revoked lineage");
        assert_eq!(report.acks_done.len(), 6);
        // Per-sender cap: one sender cannot push out another's owed ACKs.
        let mut inner = Inner::default();
        let carol = [0xC0; 32];
        inner.note_unsent_acks(&carol, &[ack_envelope(200, u64::MAX / 2)], t, now_ms());
        let flood: Vec<Vec<u8>> = (0..60u8).map(|i| ack_envelope(i, u64::MAX / 2)).collect();
        inner.note_unsent_acks(&rig.bob_pub, &flood, t, now_ms());
        let bobs = inner
            .unsent_acks
            .values()
            .filter(|a| a.peer == rig.bob_pub)
            .count();
        assert_eq!(bobs, MAX_UNSENT_ACKS_PER_PEER);
        assert_eq!(
            inner
                .unsent_acks
                .values()
                .filter(|a| a.peer == carol)
                .count(),
            1
        );
        // A failed push backs off at least 5 s.
        let digest = *inner.unsent_acks.keys().next().unwrap();
        let peer = inner.unsent_acks[&digest].peer;
        inner.apply(
            &peer,
            PeerReport {
                acks_failed: vec![digest],
                ..PeerReport::default()
            },
            t,
            now_ms(),
        );
        assert!(inner.unsent_acks[&digest].next_due >= t + MIN_RETRY);
    }

    /// J: an object sealed under an older session is given up as superseded
    /// only after repeated refusals spread over two minutes.
    #[test]
    fn a_superseded_session_is_given_up_only_after_repeated_refusals() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x9b);
        let mid = rig.stage("old session", DAY);
        // A newer confirmed session with Bob exists.
        let alice = Identity::from_seed(&[0x9b; 32]);
        let bob = Identity::from_seed(&[0x9c; 32]);
        let a_bundle = local_bundle(rig.a.path(), &alice).unwrap();
        pair(
            rig.a.path(),
            &alice,
            rig.b.path(),
            &bob,
            &a_bundle,
            &rig.b_bundle,
        );
        rig.set(REFUSE);
        let mut entry = rig.due().remove(0);
        // First refusal: never given up.
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, std::slice::from_ref(&entry), &[]);
        assert!(matches!(
            only(&report),
            Outcome::Unreachable {
                code: code::PEER_REFUSED,
                ..
            }
        ));
        // The third refusal within two minutes: still not.
        entry.refusals = 2;
        entry.first_refusal = Some(Instant::now());
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, std::slice::from_ref(&entry), &[]);
        assert!(matches!(
            only(&report),
            Outcome::Unreachable {
                code: code::PEER_REFUSED,
                ..
            }
        ));
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        // The third refusal over more than two minutes: superseded.
        let Some(long_ago) = Instant::now().checked_sub(SUPERSEDED_SPAN + Duration::from_secs(1))
        else {
            return;
        };
        entry.first_refusal = Some(long_ago);
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, std::slice::from_ref(&entry), &[]);
        assert_eq!(only(&report), Outcome::Failed(code::SUPERSEDED));
        assert_eq!(rig.history(&mid).as_deref(), Some(HISTORY_FAILED));
        // The refusal count follows the outcomes.
        let t = Instant::now();
        let mut e = Entry::from_row(&sched_row(1, 0xB0, u64::MAX), t);
        for _ in 0..3 {
            apply_outcome(
                &mut e,
                Outcome::Unreachable {
                    carrier: Some(OutboxCarrier::Lan),
                    code: code::PEER_REFUSED,
                },
                t,
                0,
            );
        }
        assert_eq!((e.refusals, e.first_refusal), (3, Some(t)));
        apply_outcome(&mut e, unreachable(), t, 0);
        assert_eq!((e.refusals, e.first_refusal), (0, None));
    }

    /// N: a route that answered with the wrong identity, or does not accept
    /// this node, is not retried for that object; with no route left it is
    /// held with that code until an explicit retry clears it.
    #[test]
    fn a_wrong_identity_or_refusing_route_is_blocked_until_an_explicit_retry() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x9d);
        rig.stage("to the right Bob only", DAY);
        for (mode, want) in [
            (WRONG_ID, code::WRONG_IDENTITY),
            (NOT_ACCEPTED, code::LINK_NOT_ACCEPTED),
        ] {
            rig.set(mode);
            let t = Instant::now();
            let mut inner = Inner {
                running: true,
                ..Inner::default()
            };
            inner.merge(scan_store(rig.a.path()).unwrap(), 0, t, now_ms());
            let work = inner.take_due(t).remove(0);
            let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &work.entries, &[]);
            assert_eq!(only(&report), Outcome::Held(want), "no route left");
            inner.apply(&rig.bob_pub, report, t, now_ms());
            let entry = inner.entries.values().next().unwrap().clone();
            assert_eq!(entry.blocked_routes, vec![lan("127.0.0.1:9")]);
            let item = entry.item(t, now_ms());
            assert_eq!(
                (item.state.as_str(), item.last_error_code.as_str()),
                ("held", want)
            );
            // Retries leave that route alone: no dial at all.
            let dials = rig.dials();
            let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &[entry], &[]);
            assert_eq!(only(&report), Outcome::Held(want));
            assert_eq!(rig.dials(), dials);
            // `raven outbox retry` (an explicit kick) clears it.
            inner.kick_now(Some(&rig.bob_pub), true, t);
            assert!(inner
                .entries
                .values()
                .next()
                .unwrap()
                .blocked_routes
                .is_empty());
        }
        rig.set(UP);
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
    }

    /// L: an unverified contact is dialled only at local-network addresses
    /// (names resolved first, dialled as the resolved literal); a verified one
    /// anywhere.
    #[test]
    fn an_unverified_contact_is_dialled_only_on_the_local_network() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x9f);
        rig.set(UP);
        let mid = rig.stage("only on the LAN", DAY);
        contacts(rig.a.path(), &rig.bob_pub, "203.0.113.7:7420", "", false);
        assert_eq!(only(&rig.attempt()), Outcome::Held(CONTACT_NOT_VERIFIED));
        assert_eq!(rig.dials(), 0);
        contacts(rig.a.path(), &rig.bob_pub, "100.64.0.9:7420", "", false);
        assert_eq!(only(&rig.attempt()), Outcome::Held(CONTACT_NOT_VERIFIED));
        assert_eq!(rig.dials(), 0, "carrier-grade NAT space is not local");
        contacts(rig.a.path(), &rig.bob_pub, "localhost:7420", "", false);
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
        let (route, _) = rig.net.log.lock().unwrap()[0].clone();
        let addr: std::net::SocketAddr = route.dial.parse().expect("the resolved literal");
        assert!(addr.ip().is_loopback(), "{route:?}");
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
        // A verified contact is dialled at its public address as saved.
        rig.stage("anywhere", DAY);
        contacts(rig.a.path(), &rig.bob_pub, "203.0.113.7:7420", "", true);
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
        assert_eq!(rig.net.log.lock().unwrap()[1].0, lan("203.0.113.7:7420"));
    }

    /// O: the contact's current addresses first; no record means LAN from the
    /// book only; a record is cleared once its object is delivered.
    #[test]
    fn routes_current_first_no_record_lan_only_and_cleared_on_delivery() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xa1);
        let mid = rig.stage("route order", DAY);
        contacts(rig.a.path(), &rig.bob_pub, "127.0.0.2:7420", "", false);
        rig.record(&mid, CarrierChoice::Lan, &[lan("127.0.0.9:7420")]);
        let _ = rig.attempt();
        let dialled: Vec<String> = rig
            .net
            .log
            .lock()
            .unwrap()
            .iter()
            .map(|(r, _)| r.dial.clone())
            .collect();
        assert_eq!(
            dialled,
            vec!["127.0.0.2:7420", "127.0.0.9:7420"],
            "current first"
        );
        rig.set(UP);
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
        let records = object_route_records(rig.a.path(), now_ms()).unwrap();
        assert!(!records.contains_key(&mid), "cleared on delivery");
        // No record: never the Internet, even for a verified contact.
        rig.stage("no record", DAY);
        contacts(rig.a.path(), &rig.bob_pub, "", "203.0.113.7:7422", true);
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(on, on))),
            Outcome::Held(code::NO_ROUTE)
        );
        assert_eq!(rig.net.internet_dials.load(Ordering::SeqCst), 0);
    }

    /// P: an inbound link triggers at most one dial-back per minute per contact.
    #[test]
    fn dial_backs_from_inbound_links_are_rate_limited() {
        let t0 = Instant::now();
        let mut inner = Inner::default();
        let (bob, carol) = ([1u8; 32], [2u8; 32]);
        assert!(inner.dialback_allowed(&bob, t0));
        assert!(!inner.dialback_allowed(&bob, t0 + Duration::from_secs(30)));
        assert!(inner.dialback_allowed(&carol, t0 + Duration::from_secs(30)));
        assert!(inner.dialback_allowed(&bob, t0 + DIALBACK_INTERVAL));
    }

    /// S: one IPC answer loads the history at most once, and only when needed.
    #[test]
    fn an_outbox_list_loads_the_history_at_most_once() {
        let calls = std::cell::Cell::new(0);
        let gone = |i: u8| OutboxItem {
            message_id_hex: hex::encode([i; 16]),
            state: "gone".into(),
            ..OutboxItem::default()
        };
        let mut items = vec![gone(1), gone(2), gone(3)];
        resolve_from_history(&mut items, || {
            calls.set(calls.get() + 1);
            (1..=3u8)
                .map(|i| {
                    (
                        hex::encode([i; 16]),
                        (String::new(), "delivered".to_string()),
                    )
                })
                .collect()
        });
        assert_eq!(calls.get(), 1);
        assert!(items.iter().all(|i| i.state == "delivered"));
        let mut live = vec![OutboxItem {
            state: "queued".into(),
            ..OutboxItem::default()
        }];
        resolve_from_history(&mut live, || {
            calls.set(calls.get() + 1);
            HistoryStates::new()
        });
        assert_eq!(calls.get(), 1, "not loaded when no row needs it");
    }

    #[test]
    fn backoff_has_a_floor_and_never_waits_past_the_expiry() {
        let t = Instant::now();
        let wall = 1_000_000u64;
        let mut e = Entry::from_row(&sched_row(1, 0xB0, wall + 60_000), t);
        for _ in 0..20 {
            apply_outcome(&mut e, unreachable(), t, wall);
            assert!(
                e.next_due <= t + Duration::from_secs(60),
                "not past the expiry"
            );
            assert!(e.next_due >= t + MIN_RETRY);
        }
        assert_eq!(e.attempts, 20);
        apply_outcome(
            &mut e,
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan),
            },
            t,
            wall,
        );
        assert_eq!((e.attempts, e.state), (21, EntryState::Delivered));
        assert_eq!(e.item(t, wall).next_attempt_ms, 0);
        let mut e = Entry::from_row(&sched_row(1, 0xB0, wall + DAY), t);
        apply_outcome(&mut e, Outcome::Held(CONTACT_NOT_VERIFIED), t, wall);
        assert_eq!(e.item(t, wall).state, "held");
        assert_eq!(e.item(t, wall).last_error_code, CONTACT_NOT_VERIFIED);
        assert_eq!(
            retry_wait(0, 0, wall, 0.0),
            MIN_RETRY,
            "past expiry: the floor"
        );
    }

    #[test]
    fn dial_errors_map_to_fixed_codes_without_addresses() {
        for (text, want) in [
            (
                "ipc LAN_DIAL: lan connect: cannot connect to 10.0.0.5:7420 (Connection refused)",
                code::NOT_LISTENING,
            ),
            (
                "lan dial to x:1 timed out after 40s while connecting",
                code::NOT_REACHABLE,
            ),
            (
                "LAN_DIAL_PEER_CLOSED: the peer closed the connection without replying",
                code::PEER_REFUSED,
            ),
            (crate::netutil::LINK_NOT_ACCEPTED, code::LINK_NOT_ACCEPTED),
            (crate::internet_direct::HOLD, code::INTERNET_HOLD),
            (
                "CONTACT_NOT_VERIFIED: Internet delivery needs a verified contact",
                CONTACT_NOT_VERIFIED,
            ),
            ("rlb1 offer identity mismatch", code::WRONG_IDENTITY),
            ("something else", code::DIAL_FAILED),
        ] {
            assert_eq!(dial_error_code(text), want, "{text}");
        }
        assert!(blocks_route(code::WRONG_IDENTITY) && blocks_route(code::LINK_NOT_ACCEPTED));
        assert!(!blocks_route(code::NOT_REACHABLE) && !blocks_route(code::PEER_REFUSED));
    }

    /// Outbox IPC items carry identifiers, states and counts, never content.
    #[test]
    fn outbox_items_carry_no_plaintext() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xa3);
        let secret = "the-secret-words-never-leave-the-store";
        rig.stage(secret, DAY);
        let item = rig.due().remove(0).item(Instant::now(), now_ms());
        let json = serde_json::to_string(&item).unwrap();
        assert!(
            !json.contains(secret) && !json.contains("the-secret"),
            "{json}"
        );
        assert_eq!(
            (item.kind.as_str(), item.state.as_str()),
            ("message", "queued")
        );
        assert_eq!(item.peer_pub_hex, hex::encode(rig.bob_pub));
    }
}
