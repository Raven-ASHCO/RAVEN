//! Bridge runtime V1 — opaque cross-transport forward inside raven-node.
//!
//! LAN + mock BLE are both TCP length-prefix frames (same RavenEnvelopeV1).
//! BridgeSubsystem never decrypts. Closing `ash` does not stop this process.
//!
//! Robustness rules (the listeners are unauthenticated):
//! - The global state lock is never held across an await: fanout uses
//!   `try_send`, and each subscriber's socket is written by its own task.
//! - Connections are admitted against a global and per-source cap (loopback
//!   folded into one source); reads and writes are bounded by timeouts;
//!   frame bodies grow with arriving bytes. Only progress (a newly admitted
//!   envelope or a completed outbound write) keeps a connection open.
//! - Queue items are InFlight while handed to writers and become Forwarded
//!   only after a complete socket write; failed hand-offs are requeued.
//! - Per-source quotas are keyed by IP (IPv6 /64), never the source port.
//!   Loopback sources are keyed per connection: every local process shares
//!   the address, so one bucket would let any local process starve the rest.
//! - An unreadable/unparsable `node_policy.json` disables the bridge.
//! - Background tasks are supervised: if an accept loop or the policy/flush
//!   poller ever ends (a panic), `run_bridge_daemon` returns an error so the
//!   process supervisor restarts the bridge instead of it dying silently.
//! - Settle writes that fail are kept and retried, never dropped, so a row is
//!   not stranded InFlight in SQLite while absent from the in-memory map.
//! - Idle accounting uses a monotonic clock; events any peer can cause at will
//!   (connects, junk frames) are rate limited in the log.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use raven_core::ble_adapter::validate_opaque_rvn1;
use raven_core::envelope::{MAX_WIRE_ENVELOPE_BYTES, PREFIX_LEN};
use raven_core::forward_queue::{ForwardQueue, ForwardState};
use raven_core::message_router::{InboundEnvelope, MessageRouter, RouterOutcome};
use raven_core::node_policy::{policy_path, BridgeStatusSnapshot, NodePolicy};
use raven_core::transport::TransportKind;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

/// Write one line to stderr, ignoring write errors. `eprintln!` panics when
/// stderr fails (EPIPE once the log pipe's reader is gone), which would
/// silently kill the accept loops or the poller; a lost log line must never.
/// (Tests keep `eprintln!` so the harness still captures the output.)
macro_rules! blog {
    ($($arg:tt)*) => {{
        #[cfg(not(test))]
        {
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr(), $($arg)*);
        }
        #[cfg(test)]
        eprintln!($($arg)*);
    }};
}

/// Wall clock for persisted timestamps (queue rows, envelope expiry). Never
/// for idle accounting: see [`mono_ms`].
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// `mono_ms` starts here, so "N ms ago" never underflows near process start.
const MONO_BASE_MS: u64 = 3_600_000;

/// Milliseconds on a monotonic clock (arbitrary origin), for idle accounting.
/// A wall-clock step (NTP after a 1970 boot, a resume with a corrected clock)
/// must neither tear down every connection at once nor keep dead ones open.
fn mono_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    MONO_BASE_MS + START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// At most one log line per window for events a peer can cause at will (the
/// listeners are unauthenticated); the next line says how many were folded in.
struct PeerLogLimiter {
    window: Duration,
    state: std::sync::Mutex<(Option<Instant>, u64)>,
}

impl PeerLogLimiter {
    const fn new(window: Duration) -> Self {
        Self {
            window,
            state: std::sync::Mutex::new((None, 0)),
        }
    }

    /// Count one event. `Some(n)`: write a line now; `n` events happened since
    /// the previous line (this one included).
    fn hit_at(&self, now: Instant) -> Option<u64> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.1 += 1;
        match st.0 {
            Some(last) if now.saturating_duration_since(last) < self.window => None,
            _ => {
                st.0 = Some(now);
                Some(std::mem::take(&mut st.1))
            }
        }
    }

    fn log(&self, what: std::fmt::Arguments<'_>) {
        match self.hit_at(Instant::now()) {
            None => {}
            Some(1) => blog!("{what}"),
            Some(n) => blog!("{what} (and {} more like it since the last line)", n - 1),
        }
    }
}

const PEER_LOG_WINDOW: Duration = Duration::from_secs(10);
static ACCEPT_LOG: PeerLogLimiter = PeerLogLimiter::new(PEER_LOG_WINDOW);
static CAP_LOG: PeerLogLimiter = PeerLogLimiter::new(PEER_LOG_WINDOW);
static PROBE_LOG: PeerLogLimiter = PeerLogLimiter::new(PEER_LOG_WINDOW);
static FRAME_LOG: PeerLogLimiter = PeerLogLimiter::new(PEER_LOG_WINDOW);
static DROP_LOG: PeerLogLimiter = PeerLogLimiter::new(PEER_LOG_WINDOW);
static POLICY_OFF_LOG: PeerLogLimiter = PeerLogLimiter::new(PEER_LOG_WINDOW);
/// Queue write failures repeat every poll tick while the disk is bad.
static DB_LOG: PeerLogLimiter = PeerLogLimiter::new(PEER_LOG_WINDOW);

pub fn forward_queue_path(data_dir: &Path) -> PathBuf {
    data_dir.join("forward_queue.sqlite")
}

/// Optional pull hello a subscriber may send before any frame.
const PULL_HELLO: &[u8; 4] = b"RVNP";
/// Frames waiting for one subscriber's socket writer.
const SUBSCRIBER_QUEUE: usize = 64;
/// Smallest frame that can be a RavenEnvelopeV1 (prefix + Ed25519 auth).
const MIN_FRAME_BYTES: usize = PREFIX_LEN + 64;
const MAX_FRAME_BYTES: usize = MAX_WIRE_ENVELOPE_BYTES;
/// Frame buffers start here and grow only as bytes actually arrive.
const READ_CHUNK_BYTES: usize = 64 * 1024;
const POLICY_POLL: Duration = Duration::from_millis(400);
/// Queue expiry / tombstone pruning cadence, in policy-poll ticks (~30 s).
const MAINTENANCE_EVERY_TICKS: u32 = 75;
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(50);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);
/// Slowest link a frame is still expected to cross: the per-frame timeouts
/// below are a base allowance plus the time `len` bytes need at this rate, so
/// a 1 MiB frame can finish on a slow link instead of timing out for ever.
const MIN_LINK_BYTES_PER_SEC: u64 = 16 * 1024;
/// Outbound frames are written in chunks of this size, each of which must be
/// accepted within the base write timeout (a dead peer is noticed at that
/// speed however large the frame is).
const WRITE_CHUNK_BYTES: usize = 16 * 1024;
/// Pending rows are re-scanned at least this often even when no event asked
/// for it (a safety net; every known source of new work sets a hint).
const FLUSH_RESCAN: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy)]
struct BridgeLimits {
    /// Concurrent connections across both bridge listeners.
    max_conns: usize,
    /// Concurrent connections from one source ([`admission_key`]: IP, IPv6
    /// /64, all of loopback as one). Keeps remote peers on a public bind from
    /// being locked out by local connections and vice versa.
    max_per_ip: usize,
    /// Silence after which a connection counts as a stable silent pull.
    classify_wait: Duration,
    /// A started length prefix must complete within this. A frame body gets
    /// this as its base allowance (see [`frame_budget`]) and as the longest
    /// wait for its next bytes.
    frame_read_timeout: Duration,
    /// Close after this long without progress: no newly admitted inbound
    /// envelope and no completed outbound write. Junk, duplicate or
    /// rate-limited frames do not count, so they cannot pin a slot.
    idle_timeout: Duration,
    /// Base allowance for one outbound frame (length + body + flush; see
    /// [`frame_budget`]) and the longest wait for the peer to accept the
    /// next chunk of it.
    write_timeout: Duration,
}

const PRODUCTION_LIMITS: BridgeLimits = BridgeLimits {
    max_conns: 64,
    max_per_ip: 32,
    classify_wait: Duration::from_millis(400),
    frame_read_timeout: Duration::from_secs(30),
    idle_timeout: Duration::from_secs(600),
    write_timeout: Duration::from_secs(10),
};

/// Per-source quota key (`previous_hop`).
///
/// Remote sources: the IP (IPv4-mapped IPv6 folded to IPv4) or the /64 of a
/// native IPv6 address — never the source port, which a sender picks freely
/// per connection to reset its quotas.
///
/// Loopback sources (127.0.0.0/8, ::1): the address identifies no one — the
/// carriers, ash and any other local process all connect from it — so a
/// shared bucket would let one local process starve every honest local
/// client, while a process that can bind other 127/8 addresses escapes it.
/// Each loopback connection gets its own key instead; the node-wide pending
/// caps (rows, bytes, custody TTL) and the connection cap bound the total.
fn bridge_peer_key(addr: &SocketAddr, conn_id: u64) -> String {
    let ip = addr.ip().to_canonical();
    if ip.is_loopback() {
        return format!("loopback/{:x}.{conn_id}", boot_tag());
    }
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

/// Distinguishes this process's per-connection keys from rows persisted by
/// an earlier run (connection ids restart at zero).
fn boot_tag() -> u64 {
    static BOOT: OnceLock<u64> = OnceLock::new();
    *BOOT.get_or_init(now_ms)
}

fn next_conn_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Connection-admission key: the canonical IP, the /64 of a native IPv6
/// address, and every loopback address (127/8, ::1) folded into one, so
/// binding extra loopback or IPv6 addresses does not multiply the cap.
fn admission_key(ip: IpAddr) -> IpAddr {
    let ip = ip.to_canonical();
    if ip.is_loopback() {
        return IpAddr::V4(Ipv4Addr::LOCALHOST);
    }
    match ip {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

/// Policy for the relay path. A missing file keeps the documented defaults;
/// a file that exists but cannot be read or parsed is an error, and the
/// caller fails closed instead of silently re-enabling a disabled bridge.
fn load_bridge_policy(data_dir: &Path) -> Result<NodePolicy, String> {
    match std::fs::read_to_string(policy_path(data_dir)) {
        Ok(raw) => serde_json::from_str::<NodePolicy>(&raw).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(NodePolicy::default()),
        Err(e) => Err(e.to_string()),
    }
}

fn fail_closed_policy() -> NodePolicy {
    NodePolicy {
        bridge: false,
        store: false,
        relay: false,
        ..NodePolicy::default()
    }
}

/// Global and per-IP connection admission shared by both listeners.
struct Admission {
    slots: Arc<Semaphore>,
    per_ip: std::sync::Mutex<HashMap<IpAddr, usize>>,
    max_per_ip: usize,
}

struct AdmissionSlot {
    admission: Arc<Admission>,
    ip: IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl Drop for AdmissionSlot {
    fn drop(&mut self) {
        let mut map = self
            .admission
            .per_ip
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(n) = map.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

impl Admission {
    fn new(limits: &BridgeLimits) -> Arc<Self> {
        Arc::new(Self {
            slots: Arc::new(Semaphore::new(limits.max_conns)),
            per_ip: std::sync::Mutex::new(HashMap::new()),
            max_per_ip: limits.max_per_ip,
        })
    }

    fn try_admit(self: &Arc<Self>, ip: IpAddr) -> Option<AdmissionSlot> {
        let permit = Arc::clone(&self.slots).try_acquire_owned().ok()?;
        let ip = admission_key(ip);
        let mut map = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        let n = map.entry(ip).or_insert(0);
        if *n >= self.max_per_ip {
            return None;
        }
        *n += 1;
        Some(AdmissionSlot {
            admission: Arc::clone(self),
            ip,
            _permit: permit,
        })
    }
}

/// One frame handed to a subscriber's writer task.
struct Outbound {
    object_digest: [u8; 32],
    frame: Arc<[u8]>,
}

struct Subscriber {
    id: u64,
    tx: mpsc::Sender<Outbound>,
}

struct BridgeState {
    policy: NodePolicy,
    /// True while node_policy.json is unreadable (logged once per episode).
    policy_error: bool,
    queue: ForwardQueue,
    lan_out: Vec<Subscriber>,
    ble_out: Vec<Subscriber>,
    /// Object digest → writer hand-offs not yet settled.
    inflight: HashMap<[u8; 32], usize>,
    next_subscriber_id: u64,
    /// Settle writes (Forwarded, or back to Queued) that failed. Every flush
    /// retries them first, so a row is never left InFlight in the database
    /// while absent from `inflight`, where nothing would ever hand it out.
    settle_retry: HashMap<[u8; 32], ForwardState>,
    /// Per egress group ([`egress_group`]: LAN, BLE): rows may be waiting in
    /// Queued state. Set by every event that can create one (a stored frame,
    /// a requeue, a policy switched on, startup, rows stored by another
    /// writer such as the IPC send path); a flush scans the queue only for a
    /// group that has both waiting rows and a subscriber with room, so an
    /// idle poll tick or a new connection costs no scan.
    waiting: [bool; 2],
    /// Pending (Queued + InFlight) row count as last observed, kept current
    /// by this bridge's own stores and settles: a higher count at the next
    /// flush means someone else stored a row.
    known_pending: usize,
    /// [`mono_ms`] of the last queue scan (for the [`FLUSH_RESCAN`] net).
    scanned_at: u64,
    /// Queue scans so far.
    #[cfg_attr(not(test), allow(dead_code))]
    scans: u64,
}

/// Which subscriber list (0 = LAN, 1 = BLE) an egress is served from.
fn egress_group(egress: TransportKind) -> usize {
    match egress {
        TransportKind::Lan | TransportKind::Internet => 0,
        TransportKind::Ble | TransportKind::MockBle => 1,
    }
}

/// Persist one settle outcome: `Queued` returns an InFlight row to custody
/// (the other states are terminal).
fn apply_settle(
    queue: &ForwardQueue,
    object_digest: &[u8; 32],
    target: ForwardState,
) -> Result<(), String> {
    #[cfg(test)]
    {
        if tests::take_settle_fault() {
            return Err("injected settle fault".into());
        }
    }
    match target {
        ForwardState::Queued => queue.requeue_object(object_digest).map(|_| ()),
        other => queue.mark_object_state(object_digest, other),
    }
    .map_err(|e| e.to_string())
}

impl BridgeState {
    fn new(policy: NodePolicy, queue: ForwardQueue) -> Self {
        Self {
            policy,
            policy_error: false,
            queue,
            lan_out: Vec::new(),
            ble_out: Vec::new(),
            inflight: HashMap::new(),
            next_subscriber_id: 0,
            settle_retry: HashMap::new(),
            // Crash recovery just requeued whatever was in flight.
            waiting: [true; 2],
            known_pending: 0,
            scanned_at: mono_ms(),
            scans: 0,
        }
    }

    fn router(&self) -> MessageRouter {
        MessageRouter {
            bridge_enabled: self.policy.bridge,
            store_enabled: self.policy.store,
            relay_enabled: self.policy.relay,
            endpoint_enabled: false,
            local_has_internet: true,
            local_has_ble: true,
        }
    }

    fn apply_policy(&mut self, loaded: Result<NodePolicy, String>) {
        match loaded {
            Ok(policy) => {
                if self.policy_error {
                    blog!("raven-node: BRIDGE policy readable again");
                    self.policy_error = false;
                }
                if policy.bridge && !self.policy.bridge {
                    // Rows stored while the bridge was off are now due.
                    self.waiting = [true; 2];
                }
                self.policy = policy;
            }
            Err(e) => {
                if !self.policy_error {
                    blog!(
                        "raven-node: BRIDGE policy unreadable ({e}) — bridge disabled (fail closed)"
                    );
                    self.policy_error = true;
                }
                self.policy = fail_closed_policy();
            }
        }
    }

    fn subscribers(&mut self, egress: TransportKind) -> &mut Vec<Subscriber> {
        match egress {
            TransportKind::Lan | TransportKind::Internet => &mut self.lan_out,
            TransportKind::Ble | TransportKind::MockBle => &mut self.ble_out,
        }
    }

    fn subscribe(&mut self, ingress: TransportKind, tx: mpsc::Sender<Outbound>) -> u64 {
        self.next_subscriber_id += 1;
        let id = self.next_subscriber_id;
        self.subscribers(ingress).push(Subscriber { id, tx });
        id
    }

    fn unsubscribe(&mut self, id: u64) {
        self.lan_out.retain(|s| s.id != id);
        self.ble_out.retain(|s| s.id != id);
    }

    /// Hand `packed` to every subscriber on `egress` without waiting. A full
    /// subscriber queue skips that subscriber (the row stays Queued and the
    /// next flush retries); a slow socket is closed by its writer's timeout.
    fn fanout(&mut self, egress: TransportKind, object_digest: &[u8; 32], packed: &[u8]) -> usize {
        // Mock BLE and future GATT share the same opaque RVN1 bytes.
        if matches!(egress, TransportKind::Ble | TransportKind::MockBle)
            && !validate_opaque_rvn1(packed)
        {
            blog!("raven-node: BRIDGE drop non-RVN1 on BLE egress");
            let _ = self
                .queue
                .mark_object_state(object_digest, ForwardState::Failed);
            return 0;
        }
        let frame: Arc<[u8]> = Arc::from(packed);
        let mut handed = 0usize;
        self.subscribers(egress).retain(|sub| {
            match sub.tx.try_send(Outbound {
                object_digest: *object_digest,
                frame: frame.clone(),
            }) {
                Ok(()) => {
                    handed += 1;
                    true
                }
                Err(TrySendError::Full(_)) => true,
                Err(TrySendError::Closed(_)) => false,
            }
        });
        if handed > 0 {
            *self.inflight.entry(*object_digest).or_insert(0) += handed;
            let _ = self
                .queue
                .mark_object_state(object_digest, ForwardState::InFlight);
        }
        handed
    }

    /// Writer report for one hand-off. The first complete write marks the
    /// object Forwarded; when every hand-off failed it returns to Queued. A
    /// failed database write is kept for retry, not dropped.
    fn settle(&mut self, object_digest: &[u8; 32], delivered: bool) {
        let Some(outstanding) = self.inflight.get_mut(object_digest) else {
            return; // already Forwarded via another subscriber
        };
        if delivered {
            self.inflight.remove(object_digest);
            self.write_settled(object_digest, ForwardState::Forwarded);
        } else {
            *outstanding = outstanding.saturating_sub(1);
            if *outstanding == 0 {
                self.inflight.remove(object_digest);
                self.write_settled(object_digest, ForwardState::Queued);
            }
        }
    }

    fn write_settled(&mut self, object_digest: &[u8; 32], target: ForwardState) {
        match apply_settle(&self.queue, object_digest, target) {
            Ok(()) => self.settled(target),
            Err(e) => {
                DB_LOG.log(format_args!(
                    "raven-node: BRIDGE settle write failed ({e}); will retry (digest {})",
                    hex::encode(&object_digest[..4])
                ));
                self.settle_retry.insert(*object_digest, target);
            }
        }
    }

    /// Bookkeeping after a settle write landed: a requeued row is due again;
    /// a forwarded one has left the pending set.
    fn settled(&mut self, target: ForwardState) {
        if target == ForwardState::Queued {
            self.waiting = [true; 2];
        } else {
            self.known_pending = self.known_pending.saturating_sub(1);
        }
    }

    /// Redo settle writes that failed earlier. Runs on every flush, before
    /// anything that could return early (a carrier that just disconnected
    /// leaves no subscribers, which is exactly when a requeue is due).
    fn retry_settles(&mut self) {
        if self.settle_retry.is_empty() {
            return;
        }
        let queue = &self.queue;
        let mut landed = Vec::new();
        self.settle_retry.retain(
            |digest, target| match apply_settle(queue, digest, *target) {
                Ok(()) => {
                    landed.push(*target);
                    false
                }
                Err(e) => {
                    DB_LOG.log(format_args!(
                        "raven-node: BRIDGE settle retry failed ({e}) (digest {})",
                        hex::encode(&digest[..4])
                    ));
                    true
                }
            },
        );
        for target in landed {
            self.settled(target);
        }
    }

    /// Rows for `egress` may be waiting in Queued state.
    fn want_flush(&mut self, egress: TransportKind) {
        self.waiting[egress_group(egress)] = true;
    }

    /// Some subscriber of `group` can take another frame right now. (A closed
    /// one counts: the scan is what removes it.)
    fn group_has_room(&self, group: usize) -> bool {
        let subs = if group == 0 {
            &self.lan_out
        } else {
            &self.ble_out
        };
        subs.iter().any(|s| s.tx.capacity() > 0)
    }

    /// Whether a queue scan could hand anything off. Rows can only be handed
    /// to a subscriber with room on their own egress, so scanning with no
    /// such subscriber (all the rows wait for an offline BLE peer while a LAN
    /// carrier is connected, or every subscriber queue is full) would read
    /// every pending blob for nothing.
    fn flush_wanted(&self) -> bool {
        let rescan_due = mono_ms().saturating_sub(self.scanned_at)
            >= FLUSH_RESCAN.as_millis() as u64
            && !(self.lan_out.is_empty() && self.ble_out.is_empty());
        (0..2).any(|g| self.waiting[g] && self.group_has_room(g)) || rescan_due
    }

    fn flush_pending(&mut self, now: u64) {
        self.retry_settles();
        if !self.policy.bridge || (self.lan_out.is_empty() && self.ble_out.is_empty()) {
            return;
        }
        // One cheap count per tick. More rows than this bridge accounts for
        // were stored by someone else (the IPC send path writes this queue).
        let pending_rows = self.queue.count_pending().ok();
        if let Some(n) = pending_rows {
            if n > self.known_pending {
                self.waiting = [true; 2];
            }
            self.known_pending = n;
        }
        if !self.flush_wanted() {
            return;
        }
        self.scanned_at = mono_ms();
        self.scans += 1;
        // Nothing in custody (the common case): skip the blob scan and the
        // write transaction its expiry sweep opens.
        if pending_rows == Some(0) {
            self.waiting = [false; 2];
            return;
        }
        let pending = match self.router().recover_pending(&self.queue, now) {
            Ok(p) => p,
            Err(e) => {
                DB_LOG.log(format_args!("raven-node: BRIDGE flush failed: {e}"));
                return; // `waiting` stays set: the next tick retries
            }
        };
        let mut waiting = [false; 2];
        for (item, _identity) in pending {
            if item.state != ForwardState::Queued || self.inflight.contains_key(&item.object_digest)
            {
                continue;
            }
            let group = egress_group(item.egress);
            if self.subscribers(item.egress).is_empty() {
                waiting[group] = true;
                continue;
            }
            if self.fanout(item.egress, &item.object_digest, &item.packed_envelope) > 0 {
                blog!(
                    "raven-node: BRIDGE flush → {} (opaque) mid={}",
                    item.egress.as_str(),
                    hex::encode(item.message_id)
                );
            } else {
                // Subscriber queues full: retry once one has room.
                waiting[group] = true;
            }
        }
        self.waiting = waiting;
    }

    fn status_snapshot(&self) -> BridgeStatusSnapshot {
        BridgeStatusSnapshot::from_policy(
            &self.policy,
            &["lan", "mock_ble"],
            self.queue.count_pending().unwrap_or(0),
            self.queue.count_all().unwrap_or(0),
        )
    }
}

/// Lab Test A only (debug build + `RAVEN_LAB_TEST_A`): keep a PairResponse
/// seen on the bridge for the lab harness. A default relay never inspects
/// ciphertext or persists unauthenticated bytes.
fn lab_sniff_pair_response(data_dir: &Path, packed: &[u8]) {
    if !raven_core::pair_init::lab_test_a_enabled() {
        return;
    }
    if let raven_core::pair_init_lan_oob::PairInitOobClassify::PairResponse(wire) =
        raven_core::pair_init_lan_oob::classify_packed_envelope(packed)
    {
        let path = data_dir.join("lab_pair_response.rvpr1");
        match raven_core::atomic_write_private(&path, &wire) {
            Ok(()) => blog!(
                "raven-node: lab PairResponse → {} ({} bytes)",
                path.display(),
                wire.len()
            ),
            Err(e) => blog!("raven-node: lab PairResponse drop write failed: {e}"),
        }
    }
}

/// Route one inbound frame. Returns true when it made progress (a new
/// object was admitted), which is what keeps a connection from idling out.
async fn on_frame(
    state: &Arc<Mutex<BridgeState>>,
    data_dir: &Path,
    packed: Vec<u8>,
    ingress: TransportKind,
    previous_hop: &str,
) -> bool {
    lab_sniff_pair_response(data_dir, &packed);
    let policy = load_bridge_policy(data_dir);

    let mut st = state.lock().await;
    st.apply_policy(policy);
    if !st.policy.bridge {
        // Not under the global lock, and not once per frame a peer sends.
        drop(st);
        POLICY_OFF_LOG.log(format_args!("raven-node: bridge policy off — ignore frame"));
        return false;
    }
    let router = st.router();
    let outcome = router.handle_inbound(
        &st.queue,
        InboundEnvelope {
            packed,
            ingress,
            previous_hop: previous_hop.to_string(),
            now_ms: now_ms(),
        },
        true,
    );
    match outcome {
        RouterOutcome::ForwardNow {
            packed: fwd,
            egress,
            identity,
        } => {
            st.known_pending += 1; // the row just stored
            if st.fanout(egress, &identity.object_digest, &fwd) > 0 {
                blog!(
                    "raven-node: BRIDGE forward {}→{} (opaque) mid={}",
                    ingress.as_str(),
                    egress.as_str(),
                    hex::encode(identity.message_id)
                );
            } else {
                // No subscriber with room: the row stays Queued for a flush.
                st.want_flush(egress);
                blog!(
                    "raven-node: BRIDGE queued waiting {} (opaque) mid={}",
                    egress.as_str(),
                    hex::encode(identity.message_id)
                );
            }
            true
        }
        RouterOutcome::QueuedForForward { egress, .. } => {
            st.known_pending += 1; // the row just stored
            st.want_flush(egress);
            blog!(
                "raven-node: BRIDGE store-carry → {} (opaque)",
                egress.as_str()
            );
            true
        }
        RouterOutcome::DeliverToEndpoint { identity, .. } => {
            // Unreachable with endpoint_enabled=false; never persist here.
            DROP_LOG.log(format_args!(
                "raven-node: BRIDGE drop deliver_to_endpoint mid={} (relay-only)",
                hex::encode(&identity.message_id[..4])
            ));
            false
        }
        RouterOutcome::Dropped { reason } => {
            DROP_LOG.log(format_args!("raven-node: BRIDGE drop {reason:?}"));
            false
        }
        other => {
            // An error may follow a successful enqueue: let a flush look.
            st.waiting = [true; 2];
            DROP_LOG.log(format_args!("raven-node: BRIDGE {other:?}"));
            false
        }
    }
}

enum Opening {
    /// Explicit pull hello.
    Hello,
    /// First four bytes are the length prefix of an inbound frame.
    Frame([u8; 4]),
    /// Connected and quiet for `classify_wait`: a stable silent pull.
    Silent,
    /// Closed, errored, or stalled mid-prefix before classification.
    Closed,
}

/// Classify a new connection before it may receive queued items. Probes
/// (`nc -z`) and half-open connects close before `classify_wait` and never
/// trigger a flush. Uses cancel-safe `read` so no prefix byte is lost.
async fn classify_opening(reader: &mut OwnedReadHalf, limits: &BridgeLimits) -> Opening {
    let mut magic = [0u8; 4];
    let mut got = 0usize;
    let silent = tokio::time::sleep(limits.classify_wait);
    tokio::pin!(silent);
    let give_up = tokio::time::sleep(limits.frame_read_timeout);
    tokio::pin!(give_up);
    while got < magic.len() {
        tokio::select! {
            r = reader.read(&mut magic[got..]) => match r {
                Ok(0) | Err(_) => return Opening::Closed,
                Ok(n) => got += n,
            },
            _ = &mut silent, if got == 0 => return Opening::Silent,
            _ = &mut give_up => return Opening::Closed,
        }
    }
    if &magic == PULL_HELLO {
        Opening::Hello
    } else {
        Opening::Frame(magic)
    }
}

/// Time since the last progress stamp (a [`mono_ms`] value).
fn idle_for(last_io: &AtomicU64) -> Duration {
    Duration::from_millis(mono_ms().saturating_sub(last_io.load(Ordering::Relaxed)))
}

/// Whole-frame time budget: `base` plus what `len` bytes need at
/// [`MIN_LINK_BYTES_PER_SEC`]. A flat budget starves a maximum-size frame on
/// a slow link: it times out, is requeued and fails identically for ever.
fn frame_budget(base: Duration, len: usize) -> Duration {
    base + Duration::from_millis((len as u64).saturating_mul(1000) / MIN_LINK_BYTES_PER_SEC)
}

/// Next length prefix. Waiting for its first byte ends `idle_timeout` after
/// the last progress (`last_io`, also advanced by the writer's completed
/// deliveries), not a fresh full timeout per wait; a started prefix must
/// complete within `frame_read_timeout`.
async fn read_len_prefix(
    reader: &mut OwnedReadHalf,
    limits: &BridgeLimits,
    last_io: &AtomicU64,
) -> Option<[u8; 4]> {
    let mut b = [0u8; 4];
    let mut got = 0usize;
    while got < b.len() {
        let wait = if got == 0 {
            // Checked even when bytes are already waiting: frames that make
            // no progress cannot keep the connection open.
            match limits.idle_timeout.checked_sub(idle_for(last_io)) {
                Some(left) if !left.is_zero() => left,
                _ => return None,
            }
        } else {
            limits.frame_read_timeout
        };
        match tokio::time::timeout(wait, reader.read(&mut b[got..])).await {
            Ok(Ok(0)) | Ok(Err(_)) => return None,
            Ok(Ok(n)) => got += n,
            // Re-check: the writer may have delivered in the meantime.
            Err(_) if got == 0 => continue,
            Err(_) => return None,
        }
    }
    Some(b)
}

/// Read exactly `len` bytes, committing memory only as bytes arrive (a
/// declared 1 MiB length alone allocates one chunk). The body gets
/// [`frame_budget`] in total, but no single wait for more bytes may exceed
/// `frame_read_timeout`: a slow link finishes, a stalled sender is closed at
/// the old speed.
async fn read_frame_body<R: AsyncRead + Unpin>(
    reader: &mut R,
    len: usize,
    limits: &BridgeLimits,
) -> Option<Vec<u8>> {
    let end = tokio::time::Instant::now() + frame_budget(limits.frame_read_timeout, len);
    let mut buf: Vec<u8> = Vec::with_capacity(len.min(READ_CHUNK_BYTES));
    let mut limited = (&mut *reader).take(len as u64);
    while buf.len() < len {
        let wait = end
            .saturating_duration_since(tokio::time::Instant::now())
            .min(limits.frame_read_timeout);
        match tokio::time::timeout(wait, limited.read_buf(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {}
            _ => return None,
        }
    }
    Some(buf)
}

/// Validate a length prefix and read that frame's body.
async fn read_frame(
    reader: &mut OwnedReadHalf,
    prefix: [u8; 4],
    ingress: TransportKind,
    limits: &BridgeLimits,
) -> Option<Vec<u8>> {
    let len = u32::from_be_bytes(prefix) as usize;
    if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&len) {
        FRAME_LOG.log(format_args!(
            "raven-node: BRIDGE close {} (frame length {len})",
            ingress.as_str()
        ));
        return None;
    }
    let body = read_frame_body(reader, len, limits).await;
    if body.is_none() {
        FRAME_LOG.log(format_args!(
            "raven-node: BRIDGE close {} (short/slow frame)",
            ingress.as_str()
        ));
    }
    body
}

#[allow(clippy::too_many_arguments)]
async fn read_frames(
    state: &Arc<Mutex<BridgeState>>,
    data_dir: &Path,
    reader: &mut OwnedReadHalf,
    mut pending_frame: Option<Vec<u8>>,
    ingress: TransportKind,
    peer_key: &str,
    limits: &BridgeLimits,
    last_io: &AtomicU64,
) {
    loop {
        let buf = match pending_frame.take() {
            Some(buf) => buf,
            None => {
                let Some(prefix) = read_len_prefix(reader, limits, last_io).await else {
                    return;
                };
                let Some(buf) = read_frame(reader, prefix, ingress, limits).await else {
                    return;
                };
                buf
            }
        };
        // Only an admitted new object counts as progress: junk, duplicate,
        // rate-limited or refused frames cannot hold a connection slot.
        if on_frame(state, data_dir, buf, ingress, peer_key).await {
            last_io.store(mono_ms(), Ordering::Relaxed);
        }
    }
}

/// Write one length-prefixed frame and flush it; false when it did not
/// complete in time. The whole frame gets [`frame_budget`], and every chunk of
/// it must be accepted within `write_timeout`, so a slow link finishes while
/// a dead peer is still noticed at the base timeout.
async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &[u8],
    limits: &BridgeLimits,
) -> bool {
    let end = tokio::time::Instant::now() + frame_budget(limits.write_timeout, frame.len());
    let wait = || {
        end.saturating_duration_since(tokio::time::Instant::now())
            .min(limits.write_timeout)
    };
    let prefix = (frame.len() as u32).to_be_bytes();
    for part in std::iter::once(&prefix[..]).chain(frame.chunks(WRITE_CHUNK_BYTES)) {
        if !matches!(
            tokio::time::timeout(wait(), writer.write_all(part)).await,
            Ok(Ok(()))
        ) {
            return false;
        }
    }
    matches!(
        tokio::time::timeout(wait(), writer.flush()).await,
        Ok(Ok(()))
    )
}

/// Socket writer for one subscriber. Every hand-off is settled exactly once:
/// delivered after a complete timed write, otherwise failed (requeue). After
/// the first failure or a stop signal the channel is closed and drained.
async fn subscriber_writer(
    state: Arc<Mutex<BridgeState>>,
    mut writer: OwnedWriteHalf,
    mut rx: mpsc::Receiver<Outbound>,
    mut stop: watch::Receiver<bool>,
    limits: BridgeLimits,
    last_io: Arc<AtomicU64>,
) {
    let mut open = true;
    loop {
        let next = if open {
            tokio::select! {
                biased;
                _ = stop.changed() => {
                    open = false;
                    rx.close();
                    continue;
                }
                m = rx.recv() => m,
            }
        } else {
            rx.recv().await
        };
        let Some(out) = next else {
            break;
        };
        let delivered = open && {
            let write = write_frame(&mut writer, &out.frame, &limits);
            tokio::select! {
                biased;
                _ = stop.changed() => false,
                ok = write => ok,
            }
        };
        if delivered {
            last_io.store(mono_ms(), Ordering::Relaxed);
        } else if open {
            open = false;
            rx.close();
        }
        state.lock().await.settle(&out.object_digest, delivered);
    }
}

async fn handle_connection(
    state: Arc<Mutex<BridgeState>>,
    data_dir: PathBuf,
    stream: TcpStream,
    addr: SocketAddr,
    ingress: TransportKind,
    limits: BridgeLimits,
) {
    let peer_key = bridge_peer_key(&addr, next_conn_id());
    let (mut reader, writer) = stream.into_split();

    // Do NOT flush on bare accept: probes (nc -z) and half-open connects
    // used to drain the outbox and mark messages Forwarded forever. Wait for
    // pull hello `RVNP`, a stable silent pull, or a structurally valid inbound
    // RVN1 frame on every transport. Early disconnect or junk → no flush.
    let first_frame = match classify_opening(&mut reader, &limits).await {
        Opening::Closed => {
            PROBE_LOG.log(format_args!("raven-node: BRIDGE drop probe (no flush)"));
            return;
        }
        Opening::Hello | Opening::Silent => None,
        Opening::Frame(prefix) => match read_frame(&mut reader, prefix, ingress, &limits).await {
            Some(buf) if validate_opaque_rvn1(&buf) => Some(buf),
            Some(_) => {
                FRAME_LOG.log(format_args!(
                    "raven-node: BRIDGE drop non-RVN1 opening frame (no flush)"
                ));
                return;
            }
            None => return,
        },
    };

    let (out_tx, out_rx) = mpsc::channel::<Outbound>(SUBSCRIBER_QUEUE);
    let (stop_tx, stop_rx) = watch::channel(false);
    let last_io = Arc::new(AtomicU64::new(mono_ms()));
    let subscriber_id = {
        let mut st = state.lock().await;
        let id = st.subscribe(ingress, out_tx);
        st.flush_pending(now_ms());
        id
    };
    let mut writer_task = tokio::spawn(subscriber_writer(
        state.clone(),
        writer,
        out_rx,
        stop_rx,
        limits,
        last_io.clone(),
    ));

    let writer_done = tokio::select! {
        _ = read_frames(
            &state,
            &data_dir,
            &mut reader,
            first_frame,
            ingress,
            &peer_key,
            &limits,
            &last_io,
        ) => false,
        _ = &mut writer_task => true,
    };
    // Stop first so the writer does not start new writes on a dead link.
    let _ = stop_tx.send(true);
    state.lock().await.unsubscribe(subscriber_id);
    if !writer_done {
        // Let the writer settle (requeue) whatever it still held.
        let _ = writer_task.await;
    }
}

async fn accept_loop(
    listener: TcpListener,
    state: Arc<Mutex<BridgeState>>,
    data_dir: PathBuf,
    ingress: TransportKind,
    admission: Arc<Admission>,
    limits: BridgeLimits,
) {
    let mut backoff = ACCEPT_BACKOFF_MIN;
    // Connection tasks live and die with this loop (dropping the set aborts
    // them), so a restarted bridge never leaves orphans writing on its behalf.
    let mut conns: JoinSet<()> = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            // Reap finished connections so the set stays small.
            Some(done) = conns.join_next(), if !conns.is_empty() => {
                if let Err(e) = done {
                    if e.is_panic() {
                        blog!("raven-node: BRIDGE {} connection task panicked", ingress.as_str());
                    }
                }
                continue;
            }
        };
        let (stream, addr) = match accepted {
            Ok(conn) => {
                backoff = ACCEPT_BACKOFF_MIN;
                conn
            }
            Err(e) => {
                // EMFILE / ENFILE / ECONNABORTED are transient: keep serving.
                blog!("raven-node: BRIDGE accept {} error: {e}", ingress.as_str());
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
                continue;
            }
        };
        let Some(slot) = admission.try_admit(addr.ip()) else {
            CAP_LOG.log(format_args!(
                "raven-node: BRIDGE {} connection cap — refused",
                ingress.as_str()
            ));
            continue;
        };
        ACCEPT_LOG.log(format_args!(
            "raven-node: BRIDGE accept {}",
            ingress.as_str()
        ));
        let st = state.clone();
        let dir = data_dir.clone();
        conns.spawn(async move {
            let _slot = slot;
            handle_connection(st, dir, stream, addr, ingress, limits).await;
        });
    }
}

/// The bridge's long-lived tasks. All are infinite loops, so one ending (a
/// panic, a cancellation) means the bridge is partly dead: [`first_exit`]
/// reports it. Dropping aborts every one, so a restarted bridge can rebind
/// its ports.
///
/// [`first_exit`]: BridgeTasks::first_exit
struct BridgeTasks {
    lan: JoinHandle<()>,
    ble: JoinHandle<()>,
    poll: JoinHandle<()>,
}

impl BridgeTasks {
    /// Resolves when the first of the tasks ends, and says which and how.
    async fn first_exit(&mut self) -> String {
        let (name, res) = tokio::select! {
            r = &mut self.lan => ("lan accept loop", r),
            r = &mut self.ble => ("mock_ble accept loop", r),
            r = &mut self.poll => ("policy/flush poller", r),
        };
        match res {
            Ok(()) => format!("{name} exited"),
            Err(e) => format!("{name} ended abnormally: {e}"),
        }
    }
}

impl Drop for BridgeTasks {
    fn drop(&mut self) {
        self.lan.abort();
        self.ble.abort();
        self.poll.abort();
    }
}

struct BridgeRuntime {
    // Tests drive the running bridge through this handle.
    #[cfg_attr(not(test), allow(dead_code))]
    state: Arc<Mutex<BridgeState>>,
    lan_addr: SocketAddr,
    ble_addr: SocketAddr,
    tasks: BridgeTasks,
}

async fn start_bridge(
    data_dir: PathBuf,
    queue: ForwardQueue,
    lan_listen: &str,
    ble_listen: &str,
    write_status: Option<PathBuf>,
    limits: BridgeLimits,
) -> Result<BridgeRuntime, String> {
    // Bind before touching the queue: a bridge that cannot bind (port taken)
    // must not have reset another instance's in-flight rows or compacted its
    // file. Bound sockets queue connections until the accept loops start.
    let lan = TcpListener::bind(lan_listen)
        .await
        .map_err(|e| e.to_string())?;
    let ble = TcpListener::bind(ble_listen)
        .await
        .map_err(|e| e.to_string())?;
    let lan_addr: SocketAddr = lan.local_addr().map_err(|e| e.to_string())?;
    let ble_addr: SocketAddr = ble.local_addr().map_err(|e| e.to_string())?;

    // Nothing is in flight before this process dispatches it (crash recovery).
    queue.requeue_all_in_flight().map_err(|e| e.to_string())?;
    if let Err(e) = queue.maintain(now_ms()) {
        blog!("raven-node: BRIDGE queue maintenance failed: {e}");
    }
    // One-time rewrite of a pre-GC file (only here, never on status/IPC opens).
    match queue.compact_legacy_file() {
        Ok(true) => blog!("raven-node: BRIDGE forward queue compacted (one-time)"),
        Ok(false) => {}
        Err(e) => blog!("raven-node: BRIDGE forward queue compaction skipped: {e}"),
    }
    let mut initial = BridgeState::new(NodePolicy::default(), queue);
    initial.apply_policy(load_bridge_policy(&data_dir));
    let state = Arc::new(Mutex::new(initial));

    blog!("raven-node: BRIDGE lan listen {lan_addr}");
    blog!("raven-node: BRIDGE mock_ble listen {ble_addr}");
    {
        let snap = state.lock().await.status_snapshot();
        blog!(
            "raven-node: BRIDGE enabled={} store={} pending={}",
            snap.bridge,
            snap.store,
            snap.forward_queue_pending
        );
        if let Some(p) = &write_status {
            let _ = std::fs::write(p, serde_json::to_string_pretty(&snap).unwrap_or_default());
        }
    }

    let admission = Admission::new(&limits);
    let lan_task = tokio::spawn(accept_loop(
        lan,
        state.clone(),
        data_dir.clone(),
        TransportKind::Lan,
        admission.clone(),
        limits,
    ));
    let ble_task = tokio::spawn(accept_loop(
        ble,
        state.clone(),
        data_dir.clone(),
        TransportKind::MockBle,
        admission,
        limits,
    ));

    let st_pol = state.clone();
    let poll_task = tokio::spawn(async move {
        let mut tick: u32 = 0;
        loop {
            tokio::time::sleep(POLICY_POLL).await;
            let policy = load_bridge_policy(&data_dir);
            let mut st = st_pol.lock().await;
            st.apply_policy(policy);
            if tick.is_multiple_of(MAINTENANCE_EVERY_TICKS) {
                if let Err(e) = st.queue.maintain(now_ms()) {
                    blog!("raven-node: BRIDGE queue maintenance failed: {e}");
                }
            }
            tick = tick.wrapping_add(1);
            if let Some(p) = &write_status {
                let snap = st.status_snapshot();
                let _ = std::fs::write(p, serde_json::to_string_pretty(&snap).unwrap_or_default());
            }
            st.flush_pending(now_ms());
        }
    });

    Ok(BridgeRuntime {
        state,
        lan_addr,
        ble_addr,
        tasks: BridgeTasks {
            lan: lan_task,
            ble: ble_task,
            poll: poll_task,
        },
    })
}

/// File that keeps a second bridge off the same data dir for the life of the
/// first. Its own name: `service` runs the IPC server (own lock) and the
/// bridge in one process. The name keeps the `.<x>.lock.sqlite` shape on every
/// platform (the file itself stays zero bytes): `bridge` also runs on a profile
/// with no identity, and the first-install proof in raven-core only accepts a
/// leftover lock file of that shape.
const BRIDGE_LOCK_NAME: &str = ".bridge.lock.sqlite";

/// Exclusive per-data-dir bridge lock, released when dropped (and by the OS if
/// the process dies, so a crash never leaves it stuck).
struct BridgeLock {
    #[cfg(unix)]
    _file: std::fs::File,
    #[cfg(not(unix))]
    _lock: raven_core::DataDirLock,
}

/// Two bridges on one data dir would reset each other's in-flight rows on
/// start and hand the same items to their carriers twice. Fails at once (unix
/// `flock`; elsewhere the cross-platform data-dir lock, which waits up to its
/// busy timeout first).
#[cfg(unix)]
fn acquire_bridge_lock(data_dir: &Path) -> Result<BridgeLock, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let path = data_dir.join(BRIDGE_LOCK_NAME);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    // SAFETY: flock(2) on a descriptor this function owns.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(if e.kind() == std::io::ErrorKind::WouldBlock {
            format!(
                "another raven-node bridge is already running for {} (lock held)",
                data_dir.display()
            )
        } else {
            format!("lock {}: {e}", path.display())
        });
    }
    Ok(BridgeLock { _file: file })
}

#[cfg(not(unix))]
fn acquire_bridge_lock(data_dir: &Path) -> Result<BridgeLock, String> {
    raven_core::DataDirLock::acquire(data_dir, BRIDGE_LOCK_NAME)
        .map(|lock| BridgeLock { _lock: lock })
        .map_err(|e| {
            format!(
                "another raven-node bridge may already be running for {} ({e})",
                data_dir.display()
            )
        })
}

/// Wait for the bridge to end: with `timeout`, Ok once it elapses; otherwise
/// (or earlier) Err as soon as one of its tasks dies, so the process
/// supervisor restarts the bridge instead of leaving it half dead.
async fn run_supervised(
    runtime: &mut BridgeRuntime,
    timeout: Option<Duration>,
) -> Result<(), String> {
    let exit = runtime.tasks.first_exit();
    match timeout {
        Some(limit) => tokio::select! {
            why = exit => Err(format!("bridge task ended: {why}")),
            _ = tokio::time::sleep(limit) => {
                blog!("raven-node: BRIDGE timeout exit");
                Ok(())
            }
        },
        None => Err(format!("bridge task ended: {}", exit.await)),
    }
}

/// Run bridge daemon. `timeout_secs=0` means run until killed (ash exit must NOT stop it
/// when launched as a separate process — ash only edits node_policy.json).
/// Returns an error if the bridge cannot start, or if one of its tasks dies.
pub async fn run_bridge_daemon(
    data_dir: PathBuf,
    lan_listen: String,
    ble_listen: String,
    write_lan_addr: Option<PathBuf>,
    write_ble_addr: Option<PathBuf>,
    write_status: Option<PathBuf>,
    timeout_secs: u64,
) -> Result<(), String> {
    std::fs::create_dir_all(&data_dir).ok();
    // Held until this function returns; declared before `runtime`, so it is
    // released only after the tasks are aborted.
    let _lock = {
        let dir = data_dir.clone();
        tokio::task::spawn_blocking(move || acquire_bridge_lock(&dir))
            .await
            .map_err(|e| format!("bridge lock: {e}"))??
    };
    let queue = ForwardQueue::open(&forward_queue_path(&data_dir)).map_err(|e| e.to_string())?;
    let mut runtime = start_bridge(
        data_dir,
        queue,
        &lan_listen,
        &ble_listen,
        write_status,
        PRODUCTION_LIMITS,
    )
    .await?;
    if let Some(p) = write_lan_addr {
        let _ = std::fs::write(p, runtime.lan_addr.to_string());
    }
    if let Some(p) = write_ble_addr {
        let _ = std::fs::write(p, runtime.ble_addr.to_string());
    }

    run_supervised(
        &mut runtime,
        (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs)),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::atsam_aead::seal_rvna1_v2;
    use raven_core::bridge::authenticated_object_digest;
    use raven_core::envelope::{EnvType, Envelope};
    use raven_core::forward_queue::{ForwardItem, MAX_ENVELOPE_BYTES, MAX_FORWARD_QUEUE};
    use raven_core::identity::Identity;
    use tempfile::tempdir;

    thread_local! {
        /// Settle writes still to fail (per test thread: `#[tokio::test]`
        /// runs everything on its own thread).
        static SETTLE_FAULTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Make the next `n` settle writes fail as a busy or full database would.
    fn fail_next_settle_writes(n: usize) {
        SETTLE_FAULTS.with(|c| c.set(n));
    }

    pub(super) fn take_settle_fault() -> bool {
        SETTLE_FAULTS.with(|c| {
            let n = c.get();
            c.set(n.saturating_sub(1));
            n > 0
        })
    }

    fn test_limits() -> BridgeLimits {
        BridgeLimits {
            max_conns: 8,
            max_per_ip: 8,
            classify_wait: Duration::from_millis(150),
            frame_read_timeout: Duration::from_millis(300),
            idle_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(2),
        }
    }

    fn signed_message(mid: [u8; 16], body: &[u8]) -> Vec<u8> {
        let now = now_ms();
        let mut env = Envelope {
            env_type: EnvType::Message as u8,
            flags: 0,
            message_id: mid,
            routing_tag: [0x18; 16],
            dest_device_hint: 0,
            created_at: now,
            expires_at: now + 60_000,
            hop_limit: 3,
            replication_budget: 2,
            anti_replay_nonce: [0x24; 12],
            ratchet_header_ciphertext: Vec::new(),
            message_ciphertext: body.to_vec(),
            sender_authentication: Vec::new(),
        };
        env.sign_with(&Identity::generate());
        env.pack()
    }

    fn queued_item(packed: &[u8], egress: TransportKind) -> ForwardItem {
        let env = Envelope::unpack(packed).unwrap();
        let now = now_ms();
        ForwardItem {
            object_digest: authenticated_object_digest(&env),
            message_id: env.message_id,
            packed_envelope: packed.to_vec(),
            ingress: TransportKind::Lan,
            egress,
            state: ForwardState::Queued,
            created_at_ms: now,
            expires_at_ms: now + 60_000,
            previous_hop: "127.0.0.1".into(),
        }
    }

    fn state_with(queue: ForwardQueue) -> Arc<Mutex<BridgeState>> {
        Arc::new(Mutex::new(BridgeState::new(NodePolicy::default(), queue)))
    }

    async fn object_state(state: &Arc<Mutex<BridgeState>>, digest: &[u8; 32]) -> ForwardState {
        state
            .lock()
            .await
            .queue
            .get_object(digest)
            .unwrap()
            .unwrap()
            .state
    }

    async fn wait_for_state(
        state: &Arc<Mutex<BridgeState>>,
        digest: &[u8; 32],
        want: ForwardState,
    ) -> ForwardState {
        let mut got = object_state(state, digest).await;
        for _ in 0..100 {
            if got == want {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            got = object_state(state, digest).await;
        }
        got
    }

    async fn wait_for_count(state: &Arc<Mutex<BridgeState>>, want: usize) -> usize {
        for _ in 0..100 {
            let n = state.lock().await.queue.count_all().unwrap();
            if n == want {
                return n;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        state.lock().await.queue.count_all().unwrap()
    }

    async fn read_one_frame(stream: &mut TcpStream) -> Vec<u8> {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).await.unwrap();
        let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut buf).await.unwrap();
        buf
    }

    /// True when the server closed the connection within `within`.
    async fn server_closed(stream: &mut TcpStream, within: Duration) -> bool {
        let mut b = [0u8; 1];
        matches!(
            tokio::time::timeout(within, stream.read(&mut b)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }

    #[tokio::test]
    async fn sealed_ack_is_forwarded_opaquely_and_never_marked_delivered() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let state = state_with(queue);
        let (lan_tx, mut lan_rx) = mpsc::channel(1);
        state.lock().await.subscribe(TransportKind::Lan, lan_tx);

        let sender = Identity::generate();
        let message_id = [0xA5; 16];
        let sealed_ack = seal_rvna1_v2(
            &[0x42; 32],
            "recipient-device",
            "origin-device",
            "ack-envelope-1",
            0,
            &[0x77; 101],
            &[0x24; 12],
        )
        .unwrap();
        let now = now_ms();
        let mut envelope = Envelope {
            env_type: EnvType::Ack as u8,
            flags: 0,
            message_id,
            routing_tag: [0x18; 16],
            dest_device_hint: 0,
            created_at: now,
            expires_at: now + 60_000,
            hop_limit: 3,
            replication_budget: 2,
            anti_replay_nonce: [0x24; 12],
            ratchet_header_ciphertext: Vec::new(),
            message_ciphertext: sealed_ack.clone(),
            sender_authentication: Vec::new(),
        };
        envelope.sign_with(&sender);

        on_frame(
            &state,
            dir.path(),
            envelope.pack(),
            TransportKind::MockBle,
            "test-ble-hop",
        )
        .await;

        let out: Outbound = tokio::time::timeout(Duration::from_secs(1), lan_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let forwarded = Envelope::unpack(&out.frame).unwrap();
        assert_eq!(forwarded.env_type, EnvType::Ack as u8);
        assert_eq!(forwarded.message_id, message_id);
        assert_eq!(forwarded.message_ciphertext, sealed_ack);

        // Handed to a writer is custody in flight, not yet Forwarded.
        let digest = out.object_digest;
        assert_eq!(object_state(&state, &digest).await, ForwardState::InFlight);
        state.lock().await.settle(&digest, true);
        assert_eq!(object_state(&state, &digest).await, ForwardState::Forwarded);
    }

    /// node-swarm#0: a subscriber that never drains its queue must not wedge
    /// on_frame (and with it the global bridge lock).
    #[tokio::test]
    async fn full_subscriber_queue_never_blocks_on_frame() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let state = state_with(queue);
        let (stuck_tx, _stuck_rx) = mpsc::channel(1);
        stuck_tx
            .try_send(Outbound {
                object_digest: [0; 32],
                frame: Arc::from(&b"filler"[..]),
            })
            .unwrap();
        state.lock().await.subscribe(TransportKind::Lan, stuck_tx);

        let packed = signed_message([0x31; 16], b"opaque");
        let digest = authenticated_object_digest(&Envelope::unpack(&packed).unwrap());
        tokio::time::timeout(
            Duration::from_secs(2),
            on_frame(
                &state,
                dir.path(),
                packed,
                TransportKind::MockBle,
                "127.0.0.1",
            ),
        )
        .await
        .expect("on_frame must not await a full subscriber queue");

        // The lock is free and the object stayed in custody for a retry.
        let st = tokio::time::timeout(Duration::from_secs(1), state.lock())
            .await
            .expect("bridge lock must be free");
        assert_eq!(
            st.queue.get_object(&digest).unwrap().unwrap().state,
            ForwardState::Queued
        );
        assert!(st.inflight.is_empty());
    }

    /// node-swarm#7: every hand-off settles; failure requeues, success forwards.
    #[tokio::test]
    async fn failed_handoff_requeues_and_success_forwards() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let packed = signed_message([0x41; 16], b"custody");
        let item = queued_item(&packed, TransportKind::Lan);
        let digest = item.object_digest;
        queue.enqueue(&item).unwrap();
        let state = state_with(queue);
        let (a_tx, mut a_rx) = mpsc::channel(4);
        let (b_tx, mut b_rx) = mpsc::channel(4);
        {
            let mut st = state.lock().await;
            st.subscribe(TransportKind::Lan, a_tx);
            st.subscribe(TransportKind::Lan, b_tx);
            st.flush_pending(now_ms());
        }
        assert!(a_rx.try_recv().is_ok() && b_rx.try_recv().is_ok());
        assert_eq!(object_state(&state, &digest).await, ForwardState::InFlight);

        // One writer fails: still in flight via the other.
        state.lock().await.settle(&digest, false);
        assert_eq!(object_state(&state, &digest).await, ForwardState::InFlight);
        // Last writer fails too: back to Queued, not lost as Forwarded.
        state.lock().await.settle(&digest, false);
        assert_eq!(object_state(&state, &digest).await, ForwardState::Queued);

        // A later flush hands it off again and a complete write forwards it.
        state.lock().await.flush_pending(now_ms());
        assert!(a_rx.try_recv().is_ok());
        state.lock().await.settle(&digest, true);
        assert_eq!(object_state(&state, &digest).await, ForwardState::Forwarded);
        // A straggling failure report cannot resurrect it.
        state.lock().await.settle(&digest, false);
        assert_eq!(object_state(&state, &digest).await, ForwardState::Forwarded);
    }

    /// node-swarm#7: a writer stopped before writing reports failure, so the
    /// object is requeued instead of being counted as delivered.
    #[tokio::test]
    async fn stopped_writer_requeues_undelivered_frames() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let packed = signed_message([0x42; 16], b"custody");
        let item = queued_item(&packed, TransportKind::Lan);
        let digest = item.object_digest;
        queue.enqueue(&item).unwrap();
        let state = state_with(queue);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let (_r, w) = server.into_split();

        let (tx, rx) = mpsc::channel(4);
        state.lock().await.subscribe(TransportKind::Lan, tx);
        state.lock().await.flush_pending(now_ms());
        assert_eq!(object_state(&state, &digest).await, ForwardState::InFlight);

        let (stop_tx, stop_rx) = watch::channel(false);
        stop_tx.send(true).unwrap();
        subscriber_writer(
            state.clone(),
            w,
            rx,
            stop_rx,
            test_limits(),
            Arc::new(AtomicU64::new(mono_ms())),
        )
        .await;
        assert_eq!(object_state(&state, &digest).await, ForwardState::Queued);
        assert!(state.lock().await.inflight.is_empty());
    }

    /// node-swarm#7: a bare connect/close probe on mock BLE must not drain the
    /// store-carry queue; a real puller then receives it and only a complete
    /// write marks it Forwarded.
    #[tokio::test]
    async fn probe_connect_does_not_drain_store_carry_queue() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let packed = signed_message([0x51; 16], b"store-carry");
        let item = queued_item(&packed, TransportKind::MockBle);
        let digest = item.object_digest;
        queue.enqueue(&item).unwrap();
        let rt = start_bridge(
            dir.path().to_path_buf(),
            queue,
            "127.0.0.1:0",
            "127.0.0.1:0",
            None,
            test_limits(),
        )
        .await
        .unwrap();

        for _ in 0..3 {
            drop(TcpStream::connect(rt.ble_addr).await.unwrap());
        }
        // Junk openers (an HTTP probe; a plausible length with a non-RVN1
        // body) are closed before they may pull anything.
        let mut http = TcpStream::connect(rt.ble_addr).await.unwrap();
        http.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
        let mut junk = TcpStream::connect(rt.ble_addr).await.unwrap();
        junk.write_all(&200u32.to_be_bytes()).await.unwrap();
        junk.write_all(&[0x5a; 200]).await.unwrap();
        assert!(server_closed(&mut http, Duration::from_secs(2)).await);
        assert!(server_closed(&mut junk, Duration::from_secs(2)).await);
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(object_state(&rt.state, &digest).await, ForwardState::Queued);

        let mut puller = TcpStream::connect(rt.ble_addr).await.unwrap();
        let frame = tokio::time::timeout(Duration::from_secs(3), read_one_frame(&mut puller))
            .await
            .unwrap();
        assert_eq!(
            authenticated_object_digest(&Envelope::unpack(&frame).unwrap()),
            digest
        );
        assert_eq!(
            wait_for_state(&rt.state, &digest, ForwardState::Forwarded).await,
            ForwardState::Forwarded
        );
    }

    /// node-swarm#6 / storage-durable#1: remote sources are keyed by IP (new
    /// source ports share one quota); loopback is keyed per connection.
    #[test]
    fn quota_key_ignores_source_port_but_loopback_is_per_connection() {
        let a: SocketAddr = "203.0.113.5:40001".parse().unwrap();
        let b: SocketAddr = "203.0.113.5:40002".parse().unwrap();
        assert_eq!(bridge_peer_key(&a, 1), bridge_peer_key(&b, 2));
        assert_eq!(bridge_peer_key(&a, 1), "203.0.113.5");
        let mapped: SocketAddr = "[::ffff:10.0.0.7]:9".parse().unwrap();
        assert_eq!(bridge_peer_key(&mapped, 3), "10.0.0.7");
        let v6a: SocketAddr = "[2001:db8:1:2::10]:1".parse().unwrap();
        let v6b: SocketAddr = "[2001:db8:1:2:ffff::1]:2".parse().unwrap();
        assert_eq!(bridge_peer_key(&v6a, 4), bridge_peer_key(&v6b, 5));
        assert_eq!(bridge_peer_key(&v6a, 4), "2001:db8:1:2::/64");

        // Every local process shares loopback: one key per connection.
        let lo1: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let lo2: SocketAddr = "127.0.0.1:50002".parse().unwrap();
        assert_ne!(bridge_peer_key(&lo1, 6), bridge_peer_key(&lo2, 7));
        assert_eq!(bridge_peer_key(&lo1, 6), bridge_peer_key(&lo1, 6));
        for lo in [
            "127.0.0.1:1",
            "127.9.8.7:1",
            "[::1]:1",
            "[::ffff:127.0.0.1]:1",
        ] {
            let addr: SocketAddr = lo.parse().unwrap();
            assert!(bridge_peer_key(&addr, 8).starts_with("loopback/"), "{lo}");
        }
    }

    /// storage-durable#1: a remote source cannot reset its quota by
    /// reconnecting, and loopback connections do not share one bucket.
    #[tokio::test]
    async fn remote_reconnect_shares_quota_but_loopback_connections_do_not() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open_with_peer_limits(
            &forward_queue_path(dir.path()),
            MAX_FORWARD_QUEUE,
            MAX_ENVELOPE_BYTES,
            64,
            1, // one enqueue per window per source
            256_000,
            3_600_000, // long window: no boundary mid-test
        )
        .unwrap();
        let state = state_with(queue);
        let mut n = 0u8;
        let mut frame = |state: &Arc<Mutex<BridgeState>>, key: String| {
            n += 1;
            let state = state.clone();
            let dir = dir.path().to_path_buf();
            let packed = signed_message([0x60 + n; 16], b"flood");
            async move { on_frame(&state, &dir, packed, TransportKind::Lan, &key).await }
        };
        let remote_a: SocketAddr = "203.0.113.5:40001".parse().unwrap();
        let remote_b: SocketAddr = "203.0.113.5:40002".parse().unwrap();
        assert!(frame(&state, bridge_peer_key(&remote_a, 1)).await);
        assert!(!frame(&state, bridge_peer_key(&remote_b, 2)).await);
        assert_eq!(state.lock().await.queue.count_all().unwrap(), 1);

        let lo_a: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let lo_b: SocketAddr = "127.0.0.1:50002".parse().unwrap();
        assert!(frame(&state, bridge_peer_key(&lo_a, 3)).await);
        assert!(!frame(&state, bridge_peer_key(&lo_a, 3)).await);
        assert!(frame(&state, bridge_peer_key(&lo_b, 4)).await);
        assert_eq!(state.lock().await.queue.count_all().unwrap(), 3);
    }

    /// storage-durable#1 regression: a local process that exhausts its quota
    /// over loopback does not rate-limit another local client.
    #[tokio::test]
    async fn local_flooder_cannot_starve_other_loopback_clients() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open_with_peer_limits(
            &forward_queue_path(dir.path()),
            MAX_FORWARD_QUEUE,
            MAX_ENVELOPE_BYTES,
            64,
            2,
            256_000,
            3_600_000,
        )
        .unwrap();
        let rt = start_bridge(
            dir.path().to_path_buf(),
            queue,
            "127.0.0.1:0",
            "127.0.0.1:0",
            None,
            test_limits(),
        )
        .await
        .unwrap();

        let mut flooder = TcpStream::connect(rt.lan_addr).await.unwrap();
        for i in 0u8..5 {
            let packed = signed_message([0x90 + i; 16], b"flood");
            flooder
                .write_all(&(packed.len() as u32).to_be_bytes())
                .await
                .unwrap();
            flooder.write_all(&packed).await.unwrap();
        }
        assert_eq!(wait_for_count(&rt.state, 2).await, 2);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            rt.state.lock().await.queue.count_all().unwrap(),
            2,
            "flooder is held to its own quota"
        );

        let mut honest = TcpStream::connect(rt.lan_addr).await.unwrap();
        let packed = signed_message([0x9f; 16], b"honest");
        honest
            .write_all(&(packed.len() as u32).to_be_bytes())
            .await
            .unwrap();
        honest.write_all(&packed).await.unwrap();
        assert_eq!(
            wait_for_count(&rt.state, 3).await,
            3,
            "honest local client admitted"
        );
    }

    /// node-swarm#1 regression: loopback (127/8, ::1) is one admission source
    /// and a native IPv6 source is its /64, so extra local or IPv6 addresses
    /// do not multiply the per-source connection cap.
    #[test]
    fn admission_folds_loopback_and_ipv6_prefix() {
        let limits = BridgeLimits {
            max_conns: 16,
            max_per_ip: 2,
            ..test_limits()
        };
        let adm = Admission::new(&limits);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let lo1 = adm.try_admit(ip("127.0.0.1")).expect("first loopback");
        let _lo2 = adm.try_admit(ip("127.0.0.2")).expect("second loopback");
        assert!(adm.try_admit(ip("127.0.0.3")).is_none());
        assert!(adm.try_admit(ip("::1")).is_none());
        assert!(adm.try_admit(ip("::ffff:127.1.2.3")).is_none());
        let _remote = adm.try_admit(ip("10.0.0.1")).expect("remote peer");

        let _v6a = adm.try_admit(ip("2001:db8:1:2::1")).expect("v6 a");
        let _v6b = adm.try_admit(ip("2001:db8:1:2:ffff::9")).expect("v6 b");
        assert!(adm.try_admit(ip("2001:db8:1:2:abcd::1")).is_none());
        let _v6c = adm.try_admit(ip("2001:db8:1:3::1")).expect("other /64");

        drop(lo1);
        let _lo3 = adm.try_admit(ip("127.0.0.9")).expect("slot released");
    }

    /// node-swarm#1 regression: frames that make no progress (here, replays
    /// of an already-admitted envelope) do not keep a connection open.
    #[tokio::test]
    async fn non_progress_frames_do_not_keep_connection_open() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let limits = BridgeLimits {
            idle_timeout: Duration::from_millis(1_000),
            ..test_limits()
        };
        let rt = start_bridge(
            dir.path().to_path_buf(),
            queue,
            "127.0.0.1:0",
            "127.0.0.1:0",
            None,
            limits,
        )
        .await
        .unwrap();
        let packed = signed_message([0xa1; 16], b"once");
        let mut len = (packed.len() as u32).to_be_bytes().to_vec();
        len.extend_from_slice(&packed);
        let started = std::time::Instant::now();
        let mut s = TcpStream::connect(rt.lan_addr).await.unwrap();
        s.write_all(&len).await.unwrap();

        let mut closed = false;
        while started.elapsed() < Duration::from_secs(6) {
            if s.write_all(&len).await.is_err()
                || server_closed(&mut s, Duration::from_millis(150)).await
            {
                closed = true;
                break;
            }
        }
        assert!(closed, "duplicate frames must not hold the connection");
        assert!(started.elapsed() >= Duration::from_millis(900));
        assert_eq!(rt.state.lock().await.queue.count_all().unwrap(), 1);
    }

    /// node-swarm#1: the idle deadline counts from the last progress, not
    /// from the start of each wait (which let a close take up to 2x).
    #[tokio::test]
    async fn idle_deadline_counts_from_last_progress() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let (mut reader, _w) = server.into_split();
        let limits = BridgeLimits {
            idle_timeout: Duration::from_secs(5),
            ..test_limits()
        };
        let last_io = AtomicU64::new(mono_ms() - 4_800);
        let started = std::time::Instant::now();
        let got = tokio::time::timeout(
            Duration::from_secs(10),
            read_len_prefix(&mut reader, &limits, &last_io),
        )
        .await
        .expect("read_len_prefix must return");
        assert!(got.is_none());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "closed after {:?}",
            started.elapsed()
        );

        // Progress reported by the writer extends the wait.
        let last_io = Arc::new(AtomicU64::new(mono_ms() - 4_800));
        let bump = last_io.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            bump.store(mono_ms(), Ordering::Relaxed);
        });
        let r = tokio::time::timeout(
            Duration::from_millis(1_500),
            read_len_prefix(&mut reader, &limits, &last_io),
        )
        .await;
        assert!(r.is_err(), "still waiting after writer progress");
    }

    /// node-swarm#1: connections beyond the cap are refused, not queued.
    #[tokio::test]
    async fn connection_cap_refuses_excess_connections() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let limits = BridgeLimits {
            max_conns: 2,
            ..test_limits()
        };
        let rt = start_bridge(
            dir.path().to_path_buf(),
            queue,
            "127.0.0.1:0",
            "127.0.0.1:0",
            None,
            limits,
        )
        .await
        .unwrap();
        let mut a = TcpStream::connect(rt.lan_addr).await.unwrap();
        let mut b = TcpStream::connect(rt.ble_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut c = TcpStream::connect(rt.lan_addr).await.unwrap();
        assert!(server_closed(&mut c, Duration::from_secs(2)).await);
        assert!(!server_closed(&mut a, Duration::from_millis(200)).await);
        assert!(!server_closed(&mut b, Duration::from_millis(200)).await);
        // A freed slot is reusable.
        drop(a);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut d = TcpStream::connect(rt.lan_addr).await.unwrap();
        assert!(!server_closed(&mut d, Duration::from_millis(300)).await);
    }

    /// node-swarm#1: a declared frame whose body stalls is closed after the
    /// read timeout instead of pinning a task and buffer forever.
    #[tokio::test]
    async fn stalled_frame_body_is_closed() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let rt = start_bridge(
            dir.path().to_path_buf(),
            queue,
            "127.0.0.1:0",
            "127.0.0.1:0",
            None,
            test_limits(),
        )
        .await
        .unwrap();
        let mut s = TcpStream::connect(rt.ble_addr).await.unwrap();
        s.write_all(&(MAX_FRAME_BYTES as u32).to_be_bytes())
            .await
            .unwrap();
        s.write_all(&[0u8; 16]).await.unwrap();
        assert!(server_closed(&mut s, Duration::from_secs(3)).await);

        // Oversized and undersized declarations close immediately.
        for len in [MAX_FRAME_BYTES as u32 + 1, 4] {
            let mut s = TcpStream::connect(rt.lan_addr).await.unwrap();
            s.write_all(&len.to_be_bytes()).await.unwrap();
            assert!(server_closed(&mut s, Duration::from_secs(2)).await);
        }
    }

    /// node-swarm#11 / protocol-reference#6: the default relay never sniffs
    /// ciphertext or writes unauthenticated PairResponse bytes to disk.
    #[tokio::test]
    async fn pair_response_sniff_is_lab_gated() {
        if raven_core::pair_init::lab_test_a_enabled() {
            return; // lab environment explicitly opted in
        }
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let state = state_with(queue);
        let mut wire = vec![0u8; raven_core::pair_init::RESPONSE_WIRE_LEN];
        wire[..8].copy_from_slice(&raven_core::pair_init::RESPONSE_MAGIC);
        let packed = signed_message([0x71; 16], &wire);
        assert!(matches!(
            raven_core::pair_init_lan_oob::classify_packed_envelope(&packed),
            raven_core::pair_init_lan_oob::PairInitOobClassify::PairResponse(_)
        ));
        on_frame(&state, dir.path(), packed, TransportKind::Lan, "127.0.0.1").await;
        assert!(!dir.path().join("lab_pair_response.rvpr1").exists());
        assert!(!dir.path().join("lab_endpoint_inbox").exists());
    }

    /// node-swarm#10: a present but unreadable policy disables the bridge.
    #[tokio::test]
    async fn unreadable_policy_fails_closed() {
        let dir = tempdir().unwrap();
        assert!(load_bridge_policy(dir.path()).unwrap().bridge);
        std::fs::write(policy_path(dir.path()), b"").unwrap();
        assert!(load_bridge_policy(dir.path()).is_err());
        std::fs::write(policy_path(dir.path()), b"{\"bridge\": tru").unwrap();
        assert!(load_bridge_policy(dir.path()).is_err());

        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let state = state_with(queue);
        on_frame(
            &state,
            dir.path(),
            signed_message([0x81; 16], b"opaque"),
            TransportKind::Lan,
            "127.0.0.1",
        )
        .await;
        let st = state.lock().await;
        assert!(!st.policy.bridge);
        assert_eq!(st.queue.count_all().unwrap(), 0);
        drop(st);

        std::fs::write(policy_path(dir.path()), b"{\"bridge\": false}").unwrap();
        assert!(!load_bridge_policy(dir.path()).unwrap().bridge);
    }

    /// node-main-bridge-4: a failed requeue write is kept and retried (even
    /// with no carrier left to send to), not stranded InFlight in the database.
    #[tokio::test]
    async fn failed_requeue_write_is_retried_not_stranded() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let packed = signed_message([0x43; 16], b"custody");
        let item = queued_item(&packed, TransportKind::Lan);
        let digest = item.object_digest;
        queue.enqueue(&item).unwrap();
        let state = state_with(queue);
        let (tx, mut rx) = mpsc::channel(4);
        let id = {
            let mut st = state.lock().await;
            let id = st.subscribe(TransportKind::Lan, tx);
            st.flush_pending(now_ms());
            id
        };
        assert!(rx.try_recv().is_ok());
        assert_eq!(object_state(&state, &digest).await, ForwardState::InFlight);

        // The carrier fails while the database write fails too.
        fail_next_settle_writes(2);
        {
            let mut st = state.lock().await;
            st.settle(&digest, false);
            st.unsubscribe(id); // nobody left to hand it to
            assert!(st.inflight.is_empty());
            assert_eq!(st.settle_retry.get(&digest), Some(&ForwardState::Queued));
        }
        assert_eq!(
            object_state(&state, &digest).await,
            ForwardState::InFlight,
            "the failed write left the row InFlight"
        );

        // The first retry fails again and is kept; the next one lands. Both
        // run with no subscribers at all.
        state.lock().await.flush_pending(now_ms());
        assert_eq!(object_state(&state, &digest).await, ForwardState::InFlight);
        assert!(!state.lock().await.settle_retry.is_empty());
        state.lock().await.flush_pending(now_ms());
        assert_eq!(object_state(&state, &digest).await, ForwardState::Queued);
        assert!(state.lock().await.settle_retry.is_empty());

        // A carrier that reconnects gets the item.
        let (tx2, mut rx2) = mpsc::channel(4);
        {
            let mut st = state.lock().await;
            st.subscribe(TransportKind::Lan, tx2);
            st.flush_pending(now_ms());
        }
        assert!(rx2.try_recv().is_ok());
        assert_eq!(object_state(&state, &digest).await, ForwardState::InFlight);
    }

    /// node-main-bridge-4: a delivered row whose Forwarded write failed is
    /// marked Forwarded by the retry, and is not sent a second time.
    #[tokio::test]
    async fn failed_forwarded_write_is_retried_without_a_resend() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let packed = signed_message([0x46; 16], b"delivered");
        let item = queued_item(&packed, TransportKind::Lan);
        let digest = item.object_digest;
        queue.enqueue(&item).unwrap();
        let state = state_with(queue);
        let (tx, mut rx) = mpsc::channel(4);
        {
            let mut st = state.lock().await;
            st.subscribe(TransportKind::Lan, tx);
            st.flush_pending(now_ms());
        }
        assert!(rx.try_recv().is_ok());

        fail_next_settle_writes(1);
        state.lock().await.settle(&digest, true);
        assert_eq!(object_state(&state, &digest).await, ForwardState::InFlight);
        assert_eq!(
            state.lock().await.settle_retry.get(&digest),
            Some(&ForwardState::Forwarded)
        );

        state.lock().await.flush_pending(now_ms());
        assert_eq!(object_state(&state, &digest).await, ForwardState::Forwarded);
        assert!(rx.try_recv().is_err(), "a delivered item is not re-sent");
    }

    /// node-main-bridge-6: a flush reads the queue only when a subscriber can
    /// take rows that are waiting, not on every tick or new connection.
    #[tokio::test]
    async fn flush_scans_only_when_a_subscriber_can_take_waiting_rows() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let ble_packed = signed_message([0x44; 16], b"for-ble");
        let ble_item = queued_item(&ble_packed, TransportKind::MockBle);
        let ble_digest = ble_item.object_digest;
        queue.enqueue(&ble_item).unwrap();
        let state = state_with(queue);
        let mut st = state.lock().await;
        let (lan_tx, mut lan_rx) = mpsc::channel(4);
        st.subscribe(TransportKind::Lan, lan_tx);

        // Startup: rows may be waiting, so the first flush scans. It finds only
        // a BLE row nobody can take yet.
        st.flush_pending(now_ms());
        assert_eq!(st.scans, 1);
        assert_eq!(st.waiting, [false, true]);

        // Poll ticks and another LAN carrier: no scan.
        let (lan_tx2, _lan_rx2) = mpsc::channel(4);
        st.subscribe(TransportKind::Lan, lan_tx2);
        for _ in 0..5 {
            st.flush_pending(now_ms());
        }
        assert_eq!(st.scans, 1);

        // The safety-net rescan runs once its interval has elapsed.
        st.scanned_at = 0;
        st.flush_pending(now_ms());
        assert_eq!(st.scans, 2);

        // A row stored by someone else (the IPC send path writes this queue)
        // is noticed by its count, at the next tick, and goes out.
        let lan_packed = signed_message([0x45; 16], b"for-lan");
        st.queue
            .enqueue(&queued_item(&lan_packed, TransportKind::Lan))
            .unwrap();
        st.flush_pending(now_ms());
        assert_eq!(st.scans, 3);
        assert!(lan_rx.try_recv().is_ok());

        // A BLE carrier arrives: the waiting row goes out.
        let (ble_tx, mut ble_rx) = mpsc::channel(4);
        st.subscribe(TransportKind::MockBle, ble_tx);
        st.flush_pending(now_ms());
        assert_eq!(st.scans, 4);
        assert!(ble_rx.try_recv().is_ok());
        assert_eq!(st.waiting, [false, false]);
        drop(st);
        assert_eq!(
            object_state(&state, &ble_digest).await,
            ForwardState::InFlight
        );
    }

    /// node-main-bridge-6: this bridge's own stores and settles keep the row
    /// count it expects, so they do not look like someone else's writes.
    #[tokio::test]
    async fn own_stores_and_settles_do_not_cause_scans() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let state = state_with(queue);
        let (tx, mut rx) = mpsc::channel(4);
        {
            let mut st = state.lock().await;
            st.subscribe(TransportKind::Lan, tx);
            st.flush_pending(now_ms()); // startup scan: empty queue
            assert_eq!(st.scans, 1);
        }

        let packed = signed_message([0x49; 16], b"through");
        let digest = authenticated_object_digest(&Envelope::unpack(&packed).unwrap());
        on_frame(&state, dir.path(), packed, TransportKind::MockBle, "peer").await;
        assert!(rx.try_recv().is_ok());
        {
            let mut st = state.lock().await;
            st.flush_pending(now_ms());
            st.settle(&digest, true);
            st.flush_pending(now_ms());
            assert_eq!(st.scans, 1, "a stored and delivered frame needs no scan");

            // A row nobody on this bridge accounted for does.
            let other = signed_message([0x4a; 16], b"ipc");
            st.queue
                .enqueue(&queued_item(&other, TransportKind::Lan))
                .unwrap();
            st.flush_pending(now_ms());
            assert_eq!(st.scans, 2);
        }
        assert!(rx.try_recv().is_ok());
    }

    /// node-main-bridge-6: subscribers with full queues are not worth a scan;
    /// the row goes out once one has room.
    #[tokio::test]
    async fn full_subscribers_do_not_trigger_scans() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let packed = signed_message([0x47; 16], b"waiting");
        let item = queued_item(&packed, TransportKind::Lan);
        let digest = item.object_digest;
        queue.enqueue(&item).unwrap();
        let state = state_with(queue);
        let mut st = state.lock().await;
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(Outbound {
            object_digest: [0; 32],
            frame: Arc::from(&b"filler"[..]),
        })
        .unwrap();
        st.subscribe(TransportKind::Lan, tx);

        for _ in 0..5 {
            st.flush_pending(now_ms());
        }
        assert_eq!(st.scans, 0, "no room anywhere: nothing to scan for");

        assert!(rx.try_recv().is_ok()); // the writer drained its queue
        st.flush_pending(now_ms());
        assert_eq!(st.scans, 1);
        assert!(rx.try_recv().is_ok());
        drop(st);
        assert_eq!(object_state(&state, &digest).await, ForwardState::InFlight);
    }

    /// node-main-bridge-5: a task that dies is reported by name, not silently.
    #[tokio::test]
    async fn dead_task_is_reported_with_its_name() {
        let mut tasks = BridgeTasks {
            lan: tokio::spawn(async { panic!("listener task panic (test)") }),
            ble: tokio::spawn(std::future::pending::<()>()),
            poll: tokio::spawn(std::future::pending::<()>()),
        };
        let why = tokio::time::timeout(Duration::from_secs(5), tasks.first_exit())
            .await
            .expect("a dead task must be reported");
        assert!(
            why.contains("lan accept loop") && why.contains("panic"),
            "{why}"
        );
    }

    /// node-main-bridge-5: dropping the tasks aborts them, so a restarted
    /// bridge can rebind and nothing keeps running unsupervised.
    #[tokio::test]
    async fn dropping_the_tasks_aborts_them() {
        struct Notify(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for Notify {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let guard = Notify(Some(tx));
        let tasks = BridgeTasks {
            lan: tokio::spawn(async move {
                let _guard = guard;
                std::future::pending::<()>().await
            }),
            ble: tokio::spawn(std::future::pending::<()>()),
            poll: tokio::spawn(std::future::pending::<()>()),
        };
        drop(tasks);
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("the task future must be dropped")
            .unwrap();
    }

    /// node-main-bridge-5: the supervising wait fails when a bridge task dies
    /// (so the service's supervisor restarts the bridge) and is Ok at a timeout.
    #[tokio::test]
    async fn supervision_fails_when_a_bridge_task_dies() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let mut rt = start_bridge(
            dir.path().to_path_buf(),
            queue,
            "127.0.0.1:0",
            "127.0.0.1:0",
            None,
            test_limits(),
        )
        .await
        .unwrap();
        assert_eq!(
            run_supervised(&mut rt, Some(Duration::from_millis(50))).await,
            Ok(())
        );
        rt.tasks.poll.abort();
        let err = tokio::time::timeout(Duration::from_secs(5), run_supervised(&mut rt, None))
            .await
            .expect("a dead poller must end the supervision")
            .unwrap_err();
        assert!(err.contains("policy/flush poller"), "{err}");
    }

    /// node-main-bridge-5: dropping a running bridge closes its listeners and
    /// ends its connections (no orphans writing on behalf of a dead instance).
    #[tokio::test]
    async fn dropping_the_runtime_closes_connections() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let rt = start_bridge(
            dir.path().to_path_buf(),
            queue,
            "127.0.0.1:0",
            "127.0.0.1:0",
            None,
            test_limits(),
        )
        .await
        .unwrap();
        let mut client = TcpStream::connect(rt.lan_addr).await.unwrap();
        client.write_all(PULL_HELLO).await.unwrap();
        for _ in 0..200 {
            if rt.state.lock().await.lan_out.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(rt.state.lock().await.lan_out.len(), 1, "connection served");
        drop(rt);
        assert!(server_closed(&mut client, Duration::from_secs(5)).await);
    }

    /// node-main-bridge-10: one bridge per data dir.
    #[cfg(unix)]
    #[test]
    fn second_bridge_on_the_same_data_dir_is_refused() {
        let dir = tempdir().unwrap();
        let first = acquire_bridge_lock(dir.path()).expect("first bridge");
        let err = acquire_bridge_lock(dir.path())
            .err()
            .expect("second bridge must be refused");
        assert!(err.contains("already running"), "{err}");
        let other = tempdir().unwrap();
        let _other = acquire_bridge_lock(other.path()).expect("another data dir is independent");
        drop(first);
        acquire_bridge_lock(dir.path()).expect("released with the first bridge");
    }

    /// `bridge` also runs on a profile with no identity, and its lock stays
    /// behind: it must keep the shape raven-core's first-install proof accepts
    /// (`.<x>.lock.sqlite`, a regular zero-byte file), or the first `init`
    /// fails closed. The end-to-end check is tests/bridge_lock_first_install.rs.
    #[cfg(unix)]
    #[test]
    fn bridge_lock_file_keeps_the_first_install_inert_shape() {
        let dir = tempdir().unwrap();
        drop(acquire_bridge_lock(dir.path()).unwrap());
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, [BRIDGE_LOCK_NAME]);
        assert!(BRIDGE_LOCK_NAME.starts_with('.') && BRIDGE_LOCK_NAME.ends_with(".lock.sqlite"));
        let meta = std::fs::symlink_metadata(dir.path().join(BRIDGE_LOCK_NAME)).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.len(), 0);
    }

    /// node-main-bridge-10: a refused second daemon leaves the queue alone (it
    /// must not reset the live instance's in-flight rows before failing).
    #[cfg(unix)]
    #[tokio::test]
    async fn refused_daemon_does_not_touch_the_queue() {
        let dir = tempdir().unwrap();
        let _live = acquire_bridge_lock(dir.path()).unwrap();
        let err = run_bridge_daemon(
            dir.path().to_path_buf(),
            "127.0.0.1:0".into(),
            "127.0.0.1:0".into(),
            None,
            None,
            None,
            1,
        )
        .await
        .unwrap_err();
        assert!(err.contains("already running"), "{err}");
        assert!(!forward_queue_path(dir.path()).exists());
    }

    /// node-main-bridge-10: a bridge that cannot bind has not yet modified
    /// the queue (in-flight rows stay in-flight for the instance that owns them).
    #[tokio::test]
    async fn failed_bind_leaves_in_flight_rows_alone() {
        let dir = tempdir().unwrap();
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        let packed = signed_message([0x48; 16], b"live");
        let item = queued_item(&packed, TransportKind::Lan);
        let digest = item.object_digest;
        queue.enqueue(&item).unwrap();
        queue
            .mark_object_state(&digest, ForwardState::InFlight)
            .unwrap();
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let taken_addr = taken.local_addr().unwrap().to_string();
        let res = start_bridge(
            dir.path().to_path_buf(),
            queue,
            "127.0.0.1:0",
            &taken_addr,
            None,
            test_limits(),
        )
        .await;
        assert!(res.is_err(), "the BLE port is taken");
        let queue = ForwardQueue::open(&forward_queue_path(dir.path())).unwrap();
        assert_eq!(
            queue.get_object(&digest).unwrap().unwrap().state,
            ForwardState::InFlight
        );
    }

    /// node-main-bridge-7: idle accounting reads a monotonic clock, so a wall
    /// clock step can neither drop every connection nor keep dead ones open.
    #[test]
    fn idle_accounting_ignores_the_wall_clock() {
        // Progress stamped now is not idle, whatever the wall clock says (a
        // wall-clock based idle_for would read ~now_ms() here).
        assert!(idle_for(&AtomicU64::new(mono_ms())) < Duration::from_secs(1));
        let idle = idle_for(&AtomicU64::new(mono_ms() - 5_000));
        assert!(
            idle >= Duration::from_secs(5) && idle < Duration::from_secs(10),
            "{idle:?}"
        );
        let a = mono_ms();
        assert!(mono_ms() >= a && a >= MONO_BASE_MS);
    }

    /// node-main-bridge-8: a storm of peer-caused events is one log line per
    /// window, and the next window says how many were folded in.
    #[test]
    fn peer_log_limiter_folds_a_storm_into_one_line() {
        let limiter = PeerLogLimiter::new(Duration::from_secs(10));
        let t0 = Instant::now();
        let lines = (0..50_000u32)
            .filter(|i| {
                limiter
                    .hit_at(t0 + Duration::from_micros(u64::from(*i) * 180))
                    .is_some()
            })
            .count();
        assert_eq!(lines, 1, "a connect/junk storm is one line, not 50k");
        assert_eq!(limiter.hit_at(t0 + Duration::from_secs(11)), Some(50_000));
    }

    /// node-main-bridge-11: a frame's time budget grows with its length, so a
    /// maximum-size frame can cross a slow link (about 60 KB/s here).
    #[test]
    fn frame_budget_scales_with_frame_length() {
        let base = Duration::from_secs(10);
        assert_eq!(frame_budget(base, 0), base);
        assert!(frame_budget(base, MIN_FRAME_BYTES) < base + Duration::from_millis(50));
        let max = frame_budget(base, MAX_FRAME_BYTES);
        assert!(max >= base + Duration::from_secs(MAX_FRAME_BYTES as u64 / MIN_LINK_BYTES_PER_SEC));
        assert!(max > Duration::from_secs_f64(MAX_FRAME_BYTES as f64 / 60_000.0));
    }

    /// node-main-bridge-11: a link slower than the flat write timeout still
    /// completes the frame within its scaled budget.
    #[tokio::test(start_paused = true)]
    async fn slow_link_finishes_within_the_scaled_write_budget() {
        let limits = BridgeLimits {
            write_timeout: Duration::from_secs(2),
            ..test_limits()
        };
        let frame = vec![0xAB; 64 * 1024];
        let total = frame.len() + 4;
        let (mut tx, mut rx) = tokio::io::duplex(4096);
        // The peer drains 4 KiB every 250 ms: 16 KiB/s, 4 s for this frame.
        let drain = tokio::spawn(async move {
            let (mut got, mut buf) = (0, [0u8; 4096]);
            while got < total {
                got += rx.read(&mut buf).await.unwrap();
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            got
        });
        let started = tokio::time::Instant::now();
        assert!(write_frame(&mut tx, &frame, &limits).await);
        assert!(
            started.elapsed() > limits.write_timeout,
            "slower than the old flat timeout: {:?}",
            started.elapsed()
        );
        assert_eq!(drain.await.unwrap(), total);
    }

    /// node-main-bridge-11: a peer that accepts nothing is still given up on
    /// after the base timeout, however large the frame (and its budget) is.
    #[tokio::test(start_paused = true)]
    async fn stalled_peer_fails_the_write_at_the_base_timeout() {
        let limits = BridgeLimits {
            write_timeout: Duration::from_secs(2),
            ..test_limits()
        };
        let frame = vec![0xAB; 64 * 1024];
        let (mut tx, _rx) = tokio::io::duplex(1024);
        let started = tokio::time::Instant::now();
        assert!(!write_frame(&mut tx, &frame, &limits).await);
        let took = started.elapsed();
        assert!(
            took >= limits.write_timeout && took < limits.write_timeout + Duration::from_secs(1),
            "{took:?}"
        );
    }

    /// node-main-bridge-11: a body spanning several read chunks is read
    /// exactly, leaving the next frame's bytes on the stream.
    #[tokio::test]
    async fn inbound_body_larger_than_a_chunk_is_read_exactly() {
        let limits = test_limits();
        let body: Vec<u8> = (0..(READ_CHUNK_BYTES * 3 + 123) as u32)
            .map(|i| (i % 251) as u8)
            .collect();
        let (mut tx, mut rx) = tokio::io::duplex(8192);
        let sent = body.clone();
        let sender = tokio::spawn(async move {
            tx.write_all(&sent).await.unwrap();
            tx.write_all(b"NEXT-FRAME").await.unwrap();
            tx
        });
        let got = tokio::time::timeout(
            Duration::from_secs(5),
            read_frame_body(&mut rx, body.len(), &limits),
        )
        .await
        .expect("body read")
        .expect("body complete");
        assert_eq!(got, body);
        let mut next = [0u8; 10];
        rx.read_exact(&mut next).await.unwrap();
        assert_eq!(&next, b"NEXT-FRAME");
        let _tx = sender.await.unwrap();
    }

    /// node-main-bridge-11: inbound bodies get the same scaling, while a
    /// sender that goes quiet is still closed at the base timeout.
    #[tokio::test(start_paused = true)]
    async fn slow_inbound_body_finishes_but_a_stalled_one_is_closed() {
        let limits = BridgeLimits {
            frame_read_timeout: Duration::from_secs(2),
            ..test_limits()
        };
        let body: Vec<u8> = (0..64 * 1024u32).map(|i| i as u8).collect();
        let (mut tx, mut rx) = tokio::io::duplex(4096);
        let sent = body.clone();
        let sender = tokio::spawn(async move {
            for chunk in sent.chunks(4096) {
                tx.write_all(chunk).await.unwrap();
                tokio::time::sleep(Duration::from_millis(250)).await; // 16 KiB/s
            }
            tx
        });
        let started = tokio::time::Instant::now();
        let got = read_frame_body(&mut rx, body.len(), &limits)
            .await
            .expect("slow but steady");
        assert_eq!(got, body);
        assert!(started.elapsed() > limits.frame_read_timeout);
        let _tx = sender.await.unwrap();

        let (mut tx, mut rx) = tokio::io::duplex(4096);
        tx.write_all(&[1u8; 100]).await.unwrap();
        let started = tokio::time::Instant::now();
        assert!(read_frame_body(&mut rx, 64 * 1024, &limits).await.is_none());
        let took = started.elapsed();
        assert!(
            took >= limits.frame_read_timeout
                && took < limits.frame_read_timeout + Duration::from_secs(1),
            "{took:?}"
        );
    }
}
