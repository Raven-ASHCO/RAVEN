//! Raven local node — TCP framed RavenEnvelopeV1, persistent queue, ACK/dedup.
//! Bridge V1: opaque cross-transport forward (see `bridge_run`).
//! Frame: u32 BE length || envelope bytes. Never logs private keys or plaintext.

mod bridge_run;
#[cfg(feature = "corebluetooth")]
mod corebluetooth_exp;
mod internet_direct;
#[cfg(any(unix, windows))]
mod ipc_server;
mod lan_direct;

#[cfg(any(unix, windows))]
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
#[cfg(any(unix, windows))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use rand::RngCore;
#[cfg(feature = "unsafe-demo-crypto")]
use raven_core::ack::{Ack, STATUS_DELIVERED};
use raven_core::envelope::{EnvType, Envelope};
use raven_core::forward_queue::ForwardQueue;
use raven_core::identity::Identity;
use raven_core::node_policy::{load_policy, BridgeStatusSnapshot};
use raven_core::queue::{DeliveryState, OutgoingQueue, QueueItem};
#[cfg(feature = "unsafe-demo-crypto")]
use raven_core::routing_tag;
#[cfg(not(feature = "unsafe-demo-crypto"))]
use raven_core::seal::UNSAFE_INTERIM_DISABLED;
use raven_core::seal::{classify_sealed_body, rvna1_wire_plausible, SealClass};
#[cfg(feature = "unsafe-demo-crypto")]
use raven_core::seal::{derive_pairwise_key, seal_message, unseal_message};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinHandle;

const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_CONCURRENT_CONNECTION_HANDLERS: usize = 64;

#[derive(Clone, Copy, Debug)]
struct ConnectionLimits {
    /// Maximum wait for the next frame header. This also bounds idle peers.
    idle_timeout: Duration,
    /// Hard wall-clock budget from the start of a frame through its payload.
    frame_timeout: Duration,
    /// A peer that stops reading cannot retain a handler indefinitely.
    write_timeout: Duration,
    /// Hard lifetime for one TCP handler, including all frames and replies.
    lifetime: Duration,
}

const DEFAULT_CONNECTION_LIMITS: ConnectionLimits = ConnectionLimits {
    idle_timeout: Duration::from_secs(10),
    frame_timeout: Duration::from_secs(30),
    write_timeout: Duration::from_secs(30),
    lifetime: Duration::from_secs(120),
};

/// Longest `--timeout-secs` honoured (also keeps `Instant + Duration` from
/// overflowing on absurd values).
const MAX_RUN_SECS: u64 = 365 * 24 * 60 * 60;

/// Limits for a connection *we* dialed (`run --peer`): it has to survive for as
/// long as the user asked to wait, not the 10 s idle bound that protects the
/// accept side from slow-loris peers. The bridge keeps its side open for 600 s,
/// so a dialed node that stays connected is already supported.
fn client_limits(timeout_secs: u64) -> ConnectionLimits {
    let budget =
        Duration::from_secs(timeout_secs.min(MAX_RUN_SECS)).saturating_add(Duration::from_secs(5));
    ConnectionLimits {
        idle_timeout: budget,
        // The header wait is also capped by this (see read_frame_with_limits).
        frame_timeout: budget,
        write_timeout: DEFAULT_CONNECTION_LIMITS.write_timeout,
        lifetime: budget,
    }
}

/// Resolve and connect to `--peer` (an IP or a name) within a bounded time, or
/// print the reason and exit 1: a dead peer is an error, never a hang or panic.
async fn dial_peer_or_exit(peer: &str, timeout_secs: u64) -> (TcpStream, SocketAddr) {
    let per_addr = Duration::from_secs(timeout_secs.clamp(1, 10));
    netutil::connect_dial(peer, per_addr, per_addr * 2)
        .await
        .unwrap_or_else(|e| {
            eprintln!("connect: {e}");
            std::process::exit(1);
        })
}

/// `forward_queue.sqlite` counts for `status`. A profile without the file
/// reports 0/0 *without creating it*: `ForwardQueue::open` creates the file,
/// and one that exists before the identity breaks the first-install proof
/// (`require_proven_first_install`). Real open/count failures are errors, not
/// an empty queue.
fn forward_queue_counts(data_dir: &Path) -> Result<(usize, usize), String> {
    let path = bridge_run::forward_queue_path(data_dir);
    match path.try_exists() {
        Ok(true) => {}
        Ok(false) => return Ok((0, 0)),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let queue = ForwardQueue::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let pending = queue
        .count_pending()
        .map_err(|e| format!("count pending: {e}"))?;
    let total = queue.count_all().map_err(|e| format!("count total: {e}"))?;
    Ok((pending, total))
}

/// Accept errors are per-connection (ECONNABORTED, a pipe client that went
/// away) or resource pressure (EMFILE, ENFILE, ENOBUFS, ENOMEM). None of them
/// may terminate a listener — and with it the whole `service` process.
pub(crate) const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(50);
pub(crate) const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Delay before the next accept after `e`: zero for errors that belonged to a
/// single peer, exponential (capped) for resource exhaustion so in-flight
/// handlers can release descriptors.
pub(crate) fn accept_error_delay(e: &std::io::Error, previous: Duration) -> Duration {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionRefused
        | ErrorKind::Interrupted
        | ErrorKind::WouldBlock => Duration::ZERO,
        _ => (previous * 2).clamp(ACCEPT_BACKOFF_MIN, ACCEPT_BACKOFF_MAX),
    }
}

/// Run `accept` until it yields a connection. Errors are logged and backed off,
/// never returned: a listener only stops when its task is cancelled.
pub(crate) async fn accept_retrying<T, F, Fut>(what: &str, mut accept: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let mut delay = Duration::ZERO;
    loop {
        match accept().await {
            Ok(conn) => return conn,
            Err(e) => {
                delay = accept_error_delay(&e, delay);
                // Peer-caused errors (zero delay) are not logged: remote
                // peers must not get a log-amplification channel.
                if !delay.is_zero() {
                    eprintln!(
                        "{what}: accept error: {e} (retry in {}ms)",
                        delay.as_millis()
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

/// Transport plumbing shared by the LAN-direct and internet-direct dialers and
/// listeners, so the two carriers cannot drift apart again.
pub(crate) mod netutil {
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::future::Future;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use raven_core::envelope::{EnvType, Envelope};
    use raven_core::pair_init_lan_oob::{classify_packed_envelope, PairInitOobClassify};
    use raven_core::MAX_IPC_FRAME;
    use tokio::net::TcpStream;
    use tokio::sync::Notify;

    // ── Dialing ──────────────────────────────────────────────────────────

    /// One TCP connect attempt (one resolved address).
    pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    /// All connect attempts of one dial together.
    pub(crate) const CONNECT_BUDGET: Duration = Duration::from_secs(20);
    /// Name resolution; mDNS `.local` lookups can be slow.
    const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
    /// Further candidates are never tried.
    const MAX_DIAL_ADDRS: usize = 8;

    // ── Supervision ──────────────────────────────────────────────────────

    /// First delay before a failed transport step is retried; doubles up to the cap.
    pub(crate) const RESTART_BACKOFF_MIN: Duration = Duration::from_secs(1);
    pub(crate) const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(30);
    /// An attempt that stayed up this long resets the backoff.
    pub(crate) const RESTART_STABLE: Duration = Duration::from_secs(60);

    /// Retry `op` until it succeeds, logging each failure (`<name> failed: …`,
    /// which the lab scripts grep for) and backing off up to
    /// [`RESTART_BACKOFF_MAX`]. A transport uses this for each *step* of its
    /// start-up (preflight, bind) so a failed bind retries only the bind:
    /// repeating the heavy preflight would keep re-taking the data-dir locks
    /// that `ash` sends need.
    pub(crate) async fn retry_until_ok<T, F, Fut>(name: &str, mut op: F) -> T
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, String>>,
    {
        let mut backoff = RESTART_BACKOFF_MIN;
        loop {
            match op().await {
                Ok(v) => return v,
                Err(e) => {
                    eprintln!("{name} failed: {e}");
                    eprintln!(
                        "{name}: unavailable; IPC and the other transports keep running; \
                         retrying in {}s",
                        backoff.as_secs()
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(RESTART_BACKOFF_MAX);
                }
            }
        }
    }

    /// A start-up step that runs this long without finishing is announced in
    /// the log (once) while it keeps running.
    pub(crate) const SLOW_STEP_NOTICE: Duration = Duration::from_secs(15);

    /// Await `step`. If it is still running after `after`, call `on_slow` once
    /// and keep waiting. The listener preflight reads the OS keystore, which
    /// can block for as long as an access prompt goes unanswered; without this
    /// the service log stays silent and the daemon looks dead.
    pub(crate) async fn with_slow_notice_then<T>(
        after: Duration,
        step: impl Future<Output = T>,
        on_slow: impl FnOnce(),
    ) -> T {
        tokio::pin!(step);
        tokio::select! {
            out = &mut step => out,
            () = tokio::time::sleep(after) => {
                on_slow();
                step.await
            }
        }
    }

    /// [`with_slow_notice_then`] that writes the standard log line for the
    /// start-up step `what` of transport `name`.
    pub(crate) async fn with_slow_notice<T>(
        name: &str,
        what: &str,
        step: impl Future<Output = T>,
    ) -> T {
        with_slow_notice_then(SLOW_STEP_NOTICE, step, || {
            eprintln!(
                "{name}: {what} is taking longer than {}s and is still running (if the OS \
                 keystore is asking for access, answer its prompt)",
                SLOW_STEP_NOTICE.as_secs()
            );
        })
        .await
    }

    /// What every "the other side hung up" I/O error is reported as: a clean
    /// EOF, a reset, an abort or a broken pipe.
    pub(crate) const PEER_CLOSED: &str = "peer closed the connection";

    /// The dialer's view of a contact-gated responder's refusal: the link closed
    /// after our signed bind/hello and before the peer identified itself. The
    /// responder sends nothing that names it or says why. Never retried: a
    /// refused dialer that repeats only repeats the refusal.
    pub(crate) const LINK_NOT_ACCEPTED: &str = "LINK_NOT_ACCEPTED: the peer closed the \
        connection after our signed hello, before identifying itself: it does not accept this \
        node (this identity is not one of its contacts, or it is blocked), or it is overloaded";

    /// Map a hang-up while waiting for the peer's bind/hello to [`LINK_NOT_ACCEPTED`].
    pub(crate) fn closed_before_peer_identity(e: String) -> String {
        if e == PEER_CLOSED {
            LINK_NOT_ACCEPTED.to_string()
        } else {
            e
        }
    }

    pub(crate) fn io_error_text(e: &std::io::Error) -> String {
        use std::io::ErrorKind;
        match e.kind() {
            ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe => PEER_CLOSED.to_string(),
            _ => e.to_string(),
        }
    }

    /// Attempts at connect + Noise handshake against a peer that hangs up
    /// during it.
    const HANDSHAKE_ATTEMPTS: u32 = 3;

    fn retry_delay() -> Duration {
        use rand::Rng;
        Duration::from_millis(rand::thread_rng().gen_range(100..300))
    }

    /// A listener over its connection cap accepts and immediately drops
    /// the socket, so a burst of dials from one host sees the hang-up in the
    /// middle of the handshake. Nothing but handshake bytes has been sent
    /// then, so retrying (after a short random delay) is always safe. Any other
    /// error, and a hang-up after the last attempt, is returned as is.
    pub(crate) async fn with_handshake_retries<T, F, Fut>(mut attempt: F) -> Result<T, String>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, String>>,
    {
        let mut n = 1;
        loop {
            match attempt().await {
                Err(e) if e == PEER_CLOSED && n < HANDSHAKE_ATTEMPTS => {
                    n += 1;
                    tokio::time::sleep(retry_delay()).await;
                }
                Err(e) if e == PEER_CLOSED => {
                    return Err(format!(
                        "{PEER_CLOSED} during the handshake ({n} attempts); the peer may be at \
                         its connection limit or may not be a RAVEN node"
                    ));
                }
                other => return other,
            }
        }
    }

    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `host:port` / `[v6]:port` into the host (brackets removed) and port.
    fn split_host_port(target: &str) -> Result<(&str, u16), String> {
        let (host, port) = target
            .rsplit_once(':')
            .ok_or_else(|| format!("{target:?} is not host:port"))?;
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| format!("{target:?} has no valid port"))?;
        let (host, bracketed) = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            Some(inner) => (inner, true),
            None => (host, false),
        };
        if host.is_empty() || host.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(format!("{target:?} has an invalid host"));
        }
        if host.contains(':') && !bracketed {
            return Err(format!("{target:?}: an IPv6 address must be in [brackets]"));
        }
        Ok((host, port))
    }

    /// Syntax-only check of a dial target (no DNS).
    pub(crate) fn check_dial_syntax(target: &str) -> Result<(), String> {
        split_host_port(target.trim()).map(|_| ())
    }

    #[cfg(unix)]
    fn interface_index(name: &str) -> Option<u32> {
        let c = std::ffi::CString::new(name).ok()?;
        // SAFETY: `c` is a valid NUL-terminated string for the whole call.
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        (idx != 0).then_some(idx)
    }

    #[cfg(not(unix))]
    fn interface_index(_name: &str) -> Option<u32> {
        None
    }

    /// `fe80::1%en0` (interface name or numeric zone) as a scoped socket
    /// address. `None` when `host` has no zone; std's parser rejects zones.
    fn parse_scoped_v6(host: &str, port: u16) -> Option<Result<SocketAddr, String>> {
        let (ip, zone) = host.split_once('%')?;
        let ip: Ipv6Addr = match ip.parse() {
            Ok(ip) => ip,
            Err(_) => return Some(Err(format!("{host:?}: not an IPv6 address before %"))),
        };
        let scope = zone
            .parse::<u32>()
            .ok()
            .or_else(|| interface_index(zone))
            .ok_or_else(|| format!("{host:?}: unknown network interface {zone:?}"));
        Some(scope.map(|scope| SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope))))
    }

    /// Alternate address families, starting with the resolver's first choice,
    /// so a dead AAAA record cannot use up the whole connect budget.
    pub(crate) fn interleave_families(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let first_is_v6 = addrs.first().is_some_and(SocketAddr::is_ipv6);
        let (lead, other): (Vec<_>, Vec<_>) =
            addrs.into_iter().partition(|a| a.is_ipv6() == first_is_v6);
        let mut out: Vec<SocketAddr> = Vec::new();
        let (mut lead, mut other) = (lead.into_iter(), other.into_iter());
        loop {
            let (a, b) = (lead.next(), other.next());
            if a.is_none() && b.is_none() {
                return out;
            }
            for addr in a.into_iter().chain(b) {
                if !out.contains(&addr) {
                    out.push(addr);
                }
            }
        }
    }

    /// Candidate socket addresses for `host:port`, `[v6]:port` or
    /// `[v6%zone]:port`. Literals never touch DNS; names go through the
    /// system resolver off the async workers.
    pub(crate) async fn resolve_dial_target(target: &str) -> Result<Vec<SocketAddr>, String> {
        let target = target.trim();
        if let Ok(addr) = target.parse::<SocketAddr>() {
            return Ok(vec![addr]);
        }
        let (host, port) = split_host_port(target)?;
        if let Some(scoped) = parse_scoped_v6(host, port) {
            return scoped.map(|a| vec![a]);
        }
        let found = tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| {
                format!(
                    "resolving {host} timed out after {}s",
                    RESOLVE_TIMEOUT.as_secs()
                )
            })?
            .map_err(|e| format!("cannot resolve {host}: {e}"))?;
        let addrs = interleave_families(found.collect());
        if addrs.is_empty() {
            return Err(format!("{host} did not resolve to any address"));
        }
        Ok(addrs)
    }

    /// Resolve `target` and connect to the first address that answers, each
    /// attempt bounded by `per_addr` and all of them by `budget`. The stream
    /// has TCP_NODELAY set (frames are small and strictly request/response).
    pub(crate) async fn connect_dial(
        target: &str,
        per_addr: Duration,
        budget: Duration,
    ) -> Result<(TcpStream, SocketAddr), String> {
        let addrs = resolve_dial_target(target).await?;
        let deadline = tokio::time::Instant::now() + budget;
        let mut failures: Vec<String> = Vec::new();
        for addr in addrs.into_iter().take(MAX_DIAL_ADDRS) {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                failures.push("connect budget exhausted".into());
                break;
            }
            let wait = per_addr.min(left);
            match tokio::time::timeout(wait, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    return Ok((stream, addr));
                }
                Ok(Err(e)) => failures.push(format!("{addr}: {e}")),
                Err(_) => failures.push(format!(
                    "{addr}: no answer within {:.1}s",
                    wait.as_secs_f32()
                )),
            }
        }
        Err(format!(
            "cannot connect to {target} ({})",
            failures.join("; ")
        ))
    }

    // ── Reply collection ─────────────────────────────────────────────────

    /// `dial` replies go back to the IPC client in one `*DialResult` frame;
    /// stop reading once they could no longer fit instead of buffering
    /// without bound.
    const MAX_DIAL_REPLIES: usize = 64;
    /// Base64 bytes (plus per-item JSON quoting) available in one IPC
    /// response; the remainder of `MAX_IPC_FRAME` covers the JSON envelope.
    const DIAL_REPLY_B64_BUDGET: usize = MAX_IPC_FRAME - 1024;

    #[derive(Debug)]
    pub(crate) struct DialReplyBudget {
        carrier: &'static str,
        count: usize,
        b64_bytes: usize,
        /// Set once the caller's frames were written, so an overflow error
        /// tells the client whether they were delivered.
        frames_sent: bool,
    }

    impl DialReplyBudget {
        pub(crate) fn new(carrier: &'static str) -> Self {
            Self {
                carrier,
                count: 0,
                b64_bytes: 0,
                frames_sent: false,
            }
        }

        pub(crate) fn mark_frames_sent(&mut self) {
            self.frames_sent = true;
        }

        pub(crate) fn admit(&mut self, reply: &[u8]) -> Result<(), String> {
            // Standard base64 plus `"` `"` `,` in the JSON array.
            let cost = reply.len().div_ceil(3) * 4 + 3;
            let total = self.b64_bytes.saturating_add(cost);
            if self.count >= MAX_DIAL_REPLIES || total > DIAL_REPLY_B64_BUDGET {
                let sent = if self.frames_sent {
                    "frames were sent"
                } else {
                    "no frames were sent"
                };
                return Err(format!(
                    "{}_DIAL_REPLY_OVERFLOW: peer replies exceed one IPC response ({sent})",
                    self.carrier
                ));
            }
            self.count += 1;
            self.b64_bytes = total;
            Ok(())
        }
    }

    /// Does the responder answer this frame? A PairInit gets a PairResponse
    /// and a Message gets a sealed ACK; RLB1 offers, ACKs and PairResponses
    /// get nothing.
    fn expects_reply(frame: &[u8]) -> bool {
        match classify_packed_envelope(frame) {
            PairInitOobClassify::PairInit(_) => true,
            PairInitOobClassify::PairResponse(_) => false,
            PairInitOobClassify::NotPairInitOob => {
                Envelope::unpack(frame).is_some_and(|e| e.env_type == EnvType::Message as u8)
            }
        }
    }

    /// Is this the reply a dial was waiting for (PairResponse or sealed ACK)?
    fn is_terminal_reply(frame: &[u8]) -> bool {
        match classify_packed_envelope(frame) {
            PairInitOobClassify::PairResponse(_) => true,
            PairInitOobClassify::PairInit(_) => false,
            PairInitOobClassify::NotPairInitOob => {
                Envelope::unpack(frame).is_some_and(|e| e.env_type == EnvType::Ack as u8)
            }
        }
    }

    /// Outcome of one wait for the next reply frame.
    #[derive(Debug)]
    pub(crate) enum ReplyWait {
        Frame(Vec<u8>),
        /// Nothing arrived in time.
        Idle,
        /// The peer closed the connection, or the frame was unreadable.
        Closed(String),
    }

    #[derive(Debug, Clone, Copy)]
    pub(crate) struct ReplyWaits {
        /// Patience for the first reply: the responder may be hitting
        /// Keychain / session persistence.
        pub first: Duration,
        /// Silence after which later replies are given up on.
        pub idle: Duration,
    }

    pub(crate) const PRODUCTION_REPLY_WAITS: ReplyWaits = ReplyWaits {
        first: Duration::from_secs(30),
        idle: Duration::from_secs(2),
    };

    /// Collects the replies of one dial. Ends as soon as every frame that
    /// gets a reply has had its terminal reply; the idle wait is only the
    /// fallback for replies that cannot be classified.
    #[derive(Debug)]
    pub(crate) struct ReplyCollector {
        carrier: &'static str,
        waits: ReplyWaits,
        budget: DialReplyBudget,
        replies: Vec<Vec<u8>>,
        expected: usize,
        seen: usize,
    }

    impl ReplyCollector {
        pub(crate) fn new(carrier: &'static str, waits: ReplyWaits) -> Self {
            Self {
                carrier,
                waits,
                budget: DialReplyBudget::new(carrier),
                replies: Vec::new(),
                expected: 0,
                seen: 0,
            }
        }

        /// Record the peer's offer (already read) and the frames about to be sent.
        pub(crate) fn begin(
            &mut self,
            peer_offer: Vec<u8>,
            frames: &[Vec<u8>],
        ) -> Result<(), String> {
            self.budget.admit(&peer_offer)?;
            self.replies.push(peer_offer);
            self.expected = frames.iter().filter(|f| expects_reply(f)).count();
            Ok(())
        }

        pub(crate) fn mark_frames_sent(&mut self) {
            self.budget.mark_frames_sent();
        }

        /// How long to wait for the first reply.
        pub(crate) fn first_wait(&self) -> Duration {
            if self.expected == 0 {
                self.waits.idle
            } else {
                self.waits.first
            }
        }

        pub(crate) fn idle_wait(&self) -> Duration {
            self.waits.idle
        }

        fn push(&mut self, frame: Vec<u8>) -> Result<bool, String> {
            self.budget.admit(&frame)?;
            if is_terminal_reply(&frame) {
                self.seen += 1;
            }
            self.replies.push(frame);
            Ok(self.expected == 0 || self.seen < self.expected)
        }

        /// Feed the outcome of the first wait; `Ok(true)` = keep reading.
        pub(crate) fn first(&mut self, got: ReplyWait) -> Result<bool, String> {
            match got {
                ReplyWait::Frame(f) => self.push(f),
                // No answer yet: the caller sees only the offer and retries.
                ReplyWait::Idle => Ok(false),
                ReplyWait::Closed(_) if self.expected == 0 => Ok(false),
                ReplyWait::Closed(why) => {
                    let (code, what) = if why == PEER_CLOSED {
                        (
                            "PEER_CLOSED",
                            "the peer closed the connection without replying".to_string(),
                        )
                    } else {
                        (
                            "BAD_REPLY",
                            format!("the peer's reply could not be read ({why})"),
                        )
                    };
                    Err(format!(
                        "{}_DIAL_{code}: {what}; the frames were sent, delivery is \
                         unconfirmed and a retry is safe",
                        self.carrier
                    ))
                }
            }
        }

        /// Feed a later wait; `Ok(true)` = keep reading. Silence or a close
        /// after at least one reply is a normal end.
        pub(crate) fn next(&mut self, got: ReplyWait) -> Result<bool, String> {
            match got {
                ReplyWait::Frame(f) => self.push(f),
                ReplyWait::Idle | ReplyWait::Closed(_) => Ok(false),
            }
        }

        pub(crate) fn into_replies(self) -> Vec<Vec<u8>> {
            self.replies
        }
    }

    /// What a dial has done so far, kept outside the dial future so the
    /// overall deadline can still report precisely.
    #[derive(Debug)]
    pub(crate) struct DialProgress {
        pub(crate) stage: &'static str,
        pub(crate) frames_sent: bool,
        pub(crate) collector: ReplyCollector,
    }

    impl DialProgress {
        pub(crate) fn new(carrier: &'static str, waits: ReplyWaits) -> Self {
            Self {
                stage: "starting",
                frames_sent: false,
                collector: ReplyCollector::new(carrier, waits),
            }
        }

        /// The overall dial deadline fired. Once the frames were written the
        /// replies collected so far are the answer (the caller maps a missing
        /// ACK to "waiting for ACK" and retries); before that it is an error.
        pub(crate) fn on_deadline(
            self,
            carrier: &str,
            target: &str,
            deadline: Duration,
        ) -> Result<Vec<Vec<u8>>, String> {
            if self.frames_sent {
                return Ok(self.collector.into_replies());
            }
            let sent = if self.stage == "sending frames" {
                "; the frames may have been delivered"
            } else {
                ""
            };
            Err(format!(
                "{carrier} dial to {target} timed out after {}s while {}{sent}",
                deadline.as_secs(),
                self.stage
            ))
        }
    }

    // ── Listening ────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy)]
    pub(crate) struct InboundLimits {
        /// Concurrent connections, any phase.
        pub max_conns: usize,
        /// Concurrent connections from one source, handshaking or established.
        pub max_per_ip: usize,
        /// Pre-auth connections from one source. Small: an unauthenticated
        /// peer can hold these slots, nothing more.
        pub max_handshaking_per_ip: usize,
        pub max_frames: u32,
        /// Hard lifetime of one connection.
        pub lifetime: Duration,
        /// Noise handshake, bind and offer exchange: separate from (and much
        /// shorter than) `lifetime`, so an idle connection cannot sit on a slot.
        pub handshake_deadline: Duration,
    }

    pub(crate) const PRODUCTION_INBOUND: InboundLimits = InboundLimits {
        max_conns: 32,
        max_per_ip: 8,
        max_handshaking_per_ip: 4,
        max_frames: 64,
        lifetime: Duration::from_secs(120),
        handshake_deadline: Duration::from_secs(10),
    };

    /// Per-source quota key: IPv4-mapped IPv6 folds to IPv4, a native IPv6
    /// address to its /64 (a host controls the whole /64).
    pub(crate) fn admission_key(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => {
                    let mut octets = v6.octets();
                    octets[8..].fill(0);
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
            },
            v4 => v4,
        }
    }

    #[derive(Debug)]
    struct Conn {
        key: IpAddr,
        /// Still pre-auth: counts against the small per-source cap and may be
        /// displaced by a newcomer.
        handshaking: bool,
        displaced: Arc<Notify>,
    }

    #[derive(Debug, Default)]
    struct AdmissionState {
        next_id: u64,
        /// Live connections, oldest first (ids grow with admission order).
        /// At most `max_conns`, so counting by scan is cheap.
        conns: BTreeMap<u64, Conn>,
    }

    impl AdmissionState {
        /// The pre-auth connection to give up when the listener is full: the
        /// oldest one of the source holding the most pre-auth connections
        /// (a handshake that has had the longest to finish and has not is the
        /// most likely to be silent). `None` when there is no pre-auth
        /// connection, or when the newcomer's own source (`mine` pre-auth
        /// connections) already holds as many as that one: a source at its
        /// fair share cannot push anyone else out.
        fn displaceable(&self, mine: usize) -> Option<u64> {
            let mut best: Option<(u64, usize)> = None;
            for (&id, conn) in self.conns.iter().filter(|(_, c)| c.handshaking) {
                let n = self
                    .conns
                    .values()
                    .filter(|o| o.handshaking && o.key == conn.key)
                    .count();
                match best {
                    Some((_, most)) if n <= most => {}
                    _ => best = Some((id, n)),
                }
            }
            best.filter(|&(_, n)| n > mine).map(|(id, _)| id)
        }
    }

    /// Global and per-source admission for one listener. A slot is released
    /// by dropping it (also on panic or cancellation) and starts out as a
    /// pre-auth "handshaking" connection until [`AdmissionSlot::authenticated`].
    ///
    /// A full listener makes room for a newcomer by displacing a pre-auth
    /// connection of a busier source (see `AdmissionState::displaceable`), so a
    /// pool of silent sockets cannot lock real peers out. Authenticated
    /// sessions are never displaced, and a source over its own caps is simply
    /// refused.
    #[derive(Debug)]
    pub(crate) struct Admission {
        state: Mutex<AdmissionState>,
        limits: InboundLimits,
    }

    #[derive(Debug)]
    pub(crate) struct AdmissionSlot {
        admission: Arc<Admission>,
        id: u64,
        displaced: Arc<Notify>,
    }

    impl Admission {
        pub(crate) fn new(limits: InboundLimits) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(AdmissionState::default()),
                limits,
            })
        }

        pub(crate) fn try_admit(self: &Arc<Self>, ip: IpAddr) -> Option<AdmissionSlot> {
            let key = admission_key(ip);
            let mut st = lock(&self.state);
            let (mut total, mut handshaking) = (0, 0);
            for c in st.conns.values().filter(|c| c.key == key) {
                total += 1;
                handshaking += usize::from(c.handshaking);
            }
            if total >= self.limits.max_per_ip || handshaking >= self.limits.max_handshaking_per_ip
            {
                return None;
            }
            if st.conns.len() >= self.limits.max_conns {
                let victim = st.displaceable(handshaking)?;
                if let Some(conn) = st.conns.remove(&victim) {
                    // Stores a permit, so the wake-up is not lost if the
                    // victim's task has not polled yet.
                    conn.displaced.notify_one();
                }
            }
            let id = st.next_id;
            st.next_id += 1;
            let displaced = Arc::new(Notify::new());
            st.conns.insert(
                id,
                Conn {
                    key,
                    handshaking: true,
                    displaced: Arc::clone(&displaced),
                },
            );
            drop(st);
            Some(AdmissionSlot {
                admission: Arc::clone(self),
                id,
                displaced,
            })
        }
    }

    impl AdmissionSlot {
        /// The peer completed the handshake **and is trusted** (a local
        /// contact): stop counting it against the pre-auth caps and protect it
        /// from displacement. Possessing a key is not trust: anyone can
        /// self-sign an RLB1 bundle, so callers must not promote strangers.
        pub(crate) fn authenticated(&mut self) {
            if let Some(c) = lock(&self.admission.state).conns.get_mut(&self.id) {
                c.handshaking = false;
            }
        }

        /// Fires once a newcomer has taken this (pre-auth) slot over: the
        /// connection must then be dropped.
        pub(crate) fn displaced(&self) -> Arc<Notify> {
            Arc::clone(&self.displaced)
        }
    }

    impl Drop for AdmissionSlot {
        fn drop(&mut self) {
            // Already gone if it was displaced.
            lock(&self.admission.state).conns.remove(&self.id);
        }
    }

    /// At most one log line per window for events a remote peer can cause at
    /// will; the next line says how many were folded into it.
    pub(crate) struct LogLimiter {
        window: Duration,
        state: Mutex<(Option<Instant>, u64)>,
    }

    impl LogLimiter {
        pub(crate) const fn new(window: Duration) -> Self {
            Self {
                window,
                state: Mutex::new((None, 0)),
            }
        }

        /// Count one event. `Some(n)`: write a line now; `n` events happened
        /// since the previous line (this one included).
        pub(crate) fn hit_at(&self, now: Instant) -> Option<u64> {
            let mut st = lock(&self.state);
            st.1 += 1;
            match st.0 {
                Some(last) if now.saturating_duration_since(last) < self.window => None,
                _ => {
                    st.0 = Some(now);
                    Some(std::mem::take(&mut st.1))
                }
            }
        }
    }

    pub(crate) fn log_limited(limiter: &LogLimiter, what: &str, detail: impl std::fmt::Display) {
        match limiter.hit_at(Instant::now()) {
            None => {}
            Some(1) => eprintln!("{what}: {detail}"),
            Some(n) => eprintln!(
                "{what}: {detail} (and {} more like it in the last {}s)",
                n - 1,
                limiter.window.as_secs()
            ),
        }
    }

    static CAP_LOG: LogLimiter = LogLimiter::new(Duration::from_secs(10));
    static INBOUND_LOG: LogLimiter = LogLimiter::new(Duration::from_secs(10));

    /// Log a peer-caused per-connection failure (rate limited).
    pub(crate) fn log_inbound_failure(what: &str, detail: impl std::fmt::Display) {
        log_limited(&INBOUND_LOG, what, detail);
    }

    /// Accept connections for ever. Accept errors are retried
    /// ([`crate::accept_retrying`]), over-cap peers are dropped with a rate
    /// limited log line, and every admitted connection runs `handler` under
    /// `limits.lifetime`; its slot is released when the handler ends, however
    /// it ends (a pre-auth connection displaced by a newcomer ends early).
    pub(crate) async fn serve_connections<A, AFut, H, HFut>(
        name: &'static str,
        mut accept: A,
        limits: InboundLimits,
        handler: H,
    ) -> Infallible
    where
        A: FnMut() -> AFut,
        AFut: Future<Output = std::io::Result<(TcpStream, SocketAddr)>>,
        H: Fn(TcpStream, AdmissionSlot) -> HFut,
        HFut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let admission = Admission::new(limits);
        loop {
            // EMFILE / ECONNABORTED etc. are logged and backed off, never fatal.
            let (stream, addr) = crate::accept_retrying(name, &mut accept).await;
            let Some(slot) = admission.try_admit(addr.ip()) else {
                log_limited(
                    &CAP_LOG,
                    name,
                    // No remote address: this line is persisted in the service log
                    // (`raven-node-service.log`), which users back up and sync, and
                    // any host that connects can trigger it.
                    format_args!("connection cap reached; refused a connection"),
                );
                continue;
            };
            let _ = stream.set_nodelay(true);
            let displaced = slot.displaced();
            let work = handler(stream, slot);
            let lifetime = limits.lifetime;
            tokio::spawn(async move {
                tokio::select! {
                    done = tokio::time::timeout(lifetime, work) => match done {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => log_inbound_failure(&format!("{name} inbound"), e),
                        Err(_) => log_inbound_failure(
                            &format!("{name} inbound"),
                            "connection lifetime exceeded",
                        ),
                    },
                    // Dropping `work` closes the socket.
                    () = displaced.notified() => log_inbound_failure(
                        &format!("{name} inbound"),
                        "unauthenticated connection displaced by a newcomer",
                    ),
                }
            });
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        use tokio::sync::mpsc;

        fn sa(s: &str) -> SocketAddr {
            s.parse().unwrap()
        }

        #[test]
        fn dial_syntax_accepts_names_and_bracketed_v6_only() {
            for ok in [
                "192.168.1.20:7420",
                "mac-mini.local:7420",
                "localhost:1",
                "[::1]:7420",
                "[fe80::1%en0]:7420",
            ] {
                assert!(check_dial_syntax(ok).is_ok(), "{ok}");
            }
            for bad in [
                "mac-mini.local",
                "host:0",
                "host:99999",
                ":7420",
                "ho st:1",
                "::1:7420", // ambiguous: a v6 literal needs brackets
                "bad\0host:1",
            ] {
                assert!(check_dial_syntax(bad).is_err(), "{bad:?}");
            }
        }

        #[tokio::test]
        async fn literals_and_zones_resolve_without_dns() {
            assert_eq!(
                resolve_dial_target(" 10.0.0.5:7420 ").await.unwrap(),
                vec![sa("10.0.0.5:7420")]
            );
            assert_eq!(
                resolve_dial_target("[::1]:7420").await.unwrap(),
                vec![sa("[::1]:7420")]
            );
            // std's parser rejects zones; a numeric one is carried as scope id.
            match resolve_dial_target("[fe80::1%7]:7420").await.unwrap()[..] {
                [SocketAddr::V6(v6)] => {
                    assert_eq!(v6.scope_id(), 7);
                    assert_eq!(v6.port(), 7420);
                    assert_eq!(v6.ip(), &"fe80::1".parse::<Ipv6Addr>().unwrap());
                }
                ref other => panic!("{other:?}"),
            }
            let err = resolve_dial_target("[fe80::1%no-such-if0]:7420")
                .await
                .unwrap_err();
            assert!(err.contains("unknown network interface"), "{err}");
            let err = resolve_dial_target("[not-an-ip%en0]:7420")
                .await
                .unwrap_err();
            assert!(err.contains("IPv6"), "{err}");
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn interface_names_map_to_scope_ids() {
            let lo = if cfg!(target_os = "linux") {
                "lo"
            } else {
                "lo0"
            };
            match resolve_dial_target(&format!("[fe80::1%{lo}]:7420"))
                .await
                .unwrap()[..]
            {
                [SocketAddr::V6(v6)] => assert!(v6.scope_id() > 0),
                ref other => panic!("{other:?}"),
            }
        }

        #[test]
        fn address_families_are_interleaved_and_deduplicated() {
            let (a, b) = (sa("[2001:db8::1]:1"), sa("[2001:db8::2]:1"));
            let (c, d) = (sa("192.0.2.1:1"), sa("192.0.2.2:1"));
            assert_eq!(
                interleave_families(vec![a, b, c, d, c]),
                vec![a, c, b, d],
                "a dead first family must not hold up the other"
            );
            assert_eq!(interleave_families(vec![c, a, d]), vec![c, a, d]);
            assert!(interleave_families(Vec::new()).is_empty());
        }

        #[tokio::test]
        async fn names_resolve_and_connect_with_fallback() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            // `localhost` may list ::1 first; the v4-only listener must still
            // be reached through the fallback.
            let (stream, addr) = connect_dial(
                &format!("localhost:{port}"),
                Duration::from_secs(2),
                Duration::from_secs(5),
            )
            .await
            .expect("dial by name");
            assert!(addr.ip().is_loopback() && addr.port() == port);
            assert!(stream.nodelay().unwrap());
            drop(listener);
        }

        #[tokio::test]
        async fn refused_connect_names_the_address_and_returns_promptly() {
            let port = {
                let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
                l.local_addr().unwrap().port()
            };
            let target = format!("127.0.0.1:{port}");
            let err = connect_dial(&target, Duration::from_secs(2), Duration::from_secs(5))
                .await
                .unwrap_err();
            assert!(err.contains(&target), "{err}");
            assert!(err.contains("cannot connect"), "{err}");
            let err = connect_dial("no-such-host.invalid:1", CONNECT_TIMEOUT, CONNECT_BUDGET)
                .await
                .unwrap_err();
            assert!(err.contains("no-such-host.invalid"), "{err}");
        }

        #[test]
        fn log_limiter_folds_a_storm_into_one_line() {
            let limiter = LogLimiter::new(Duration::from_secs(10));
            let t0 = Instant::now();
            let mut lines = 0;
            for i in 0..50_000u32 {
                // 50k events spread over 9 s: still inside one window.
                if limiter
                    .hit_at(t0 + Duration::from_micros(u64::from(i) * 180))
                    .is_some()
                {
                    lines += 1;
                }
            }
            assert_eq!(lines, 1, "a connect/RST storm is one line, not 50k");
            // The next window reports how many were folded in.
            assert_eq!(limiter.hit_at(t0 + Duration::from_secs(11)), Some(50_000));
        }

        fn limits(max_conns: usize, per_ip: usize, hs_per_ip: usize) -> InboundLimits {
            InboundLimits {
                max_conns,
                max_per_ip: per_ip,
                max_handshaking_per_ip: hs_per_ip,
                ..PRODUCTION_INBOUND
            }
        }

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        impl AdmissionSlot {
            /// Not displaced, not dropped.
            fn is_live(&self) -> bool {
                lock(&self.admission.state).conns.contains_key(&self.id)
            }
        }

        #[test]
        fn admission_enforces_global_and_per_ip_caps() {
            let adm = Admission::new(limits(3, 2, 2));
            let (a, b) = (ip("192.0.2.1"), ip("192.0.2.2"));
            let mut s1 = adm.try_admit(a).expect("first");
            let mut s2 = adm.try_admit(a).expect("second from the same ip");
            assert!(adm.try_admit(a).is_none(), "per-ip cap");
            let mut s3 = adm.try_admit(b).expect("other ip");
            // Authenticated sessions are never displaced: full means full.
            for s in [&mut s1, &mut s2, &mut s3] {
                s.authenticated();
            }
            assert!(adm.try_admit(b).is_none(), "global cap");
            drop(s1);
            assert!(adm.try_admit(b).is_some(), "slot released by drop");
        }

        /// Regression: lingering connections kept the small per-IP cap full, so
        /// a burst of dials from one host (or one NAT) was refused. Only
        /// handshakes count against the small cap; an authenticated session
        /// makes room for the next dial.
        #[test]
        fn authenticated_sessions_do_not_hold_the_handshake_cap() {
            let adm = Admission::new(limits(32, 8, 4));
            let ip: IpAddr = "192.0.2.9".parse().unwrap();
            let mut held: Vec<AdmissionSlot> = (0..4).map(|_| adm.try_admit(ip).unwrap()).collect();
            assert!(adm.try_admit(ip).is_none(), "four handshakes in flight");
            held[0].authenticated();
            held[1].authenticated();
            // Two promoted: two more handshakes fit ...
            for _ in 0..2 {
                held.push(adm.try_admit(ip).expect("room after authentication"));
            }
            assert!(adm.try_admit(ip).is_none(), "handshake cap binds again");
            // ... and once everything is authenticated the total cap (8) is
            // the only limit left.
            for slot in &mut held {
                slot.authenticated();
                slot.authenticated(); // idempotent
            }
            for _ in 0..2 {
                held.push(adm.try_admit(ip).expect("handshake room"));
            }
            assert_eq!(held.len(), 8);
            assert!(adm.try_admit(ip).is_none(), "total per-ip cap still binds");
            // Dropping releases whatever is left.
            held.clear();
            assert!(adm.try_admit(ip).is_some());
        }

        /// Regression: silent pre-auth sockets from a few source addresses
        /// filled the listener and every real peer was refused until they
        /// timed out (and they re-opened at no cost). A newcomer now displaces
        /// the oldest pre-auth connection of the busiest source.
        #[test]
        fn a_pool_full_of_silent_handshakes_still_admits_a_newcomer() {
            // The production shape: 32 slots, 4 pre-auth per source, so 8
            // addresses fill it.
            let adm = Admission::new(limits(32, 8, 4));
            let mut silent: Vec<AdmissionSlot> = (1..=8)
                .flat_map(|host| {
                    let adm = &adm;
                    (0..4).map(move |_| adm.try_admit(ip(&format!("10.0.0.{host}"))).unwrap())
                })
                .collect();
            let stranger = ip("10.0.9.9");
            // A real peer gets in ... and took the oldest silent socket's place.
            let mut peer = adm.try_admit(stranger).expect("newcomer admitted");
            assert!(
                !silent[0].is_live(),
                "the oldest silent socket is displaced"
            );
            assert!(silent[1..].iter().all(AdmissionSlot::is_live));
            // It completes the handshake: its slot is now untouchable.
            peer.authenticated();
            // Silent sockets keep arriving from the attacker's addresses; each
            // one only ever displaces another silent socket.
            for round in 0..64 {
                let host = ip(&format!("10.0.0.{}", 1 + round % 8));
                if let Some(s) = adm.try_admit(host) {
                    silent.push(s);
                }
                assert!(peer.is_live(), "authenticated session survived {round}");
            }
            // And a second real peer is still admitted.
            assert!(adm.try_admit(ip("10.0.9.10")).is_some());
            assert!(peer.is_live());
        }

        /// The victim is the busiest source's oldest pre-auth connection, not
        /// the oldest overall: a lone slow handshake outlives a flood.
        #[test]
        fn displacement_prefers_the_busiest_source() {
            let adm = Admission::new(limits(4, 4, 4));
            let (lone, flood, newcomer) = (ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3"));
            let first = adm.try_admit(lone).unwrap(); // oldest of all
            let f1 = adm.try_admit(flood).unwrap();
            let f2 = adm.try_admit(flood).unwrap();
            let f3 = adm.try_admit(flood).unwrap();
            let _new = adm.try_admit(newcomer).expect("admitted");
            assert!(first.is_live(), "the lone handshake is spared");
            assert!(!f1.is_live(), "the busiest source gives up its oldest");
            assert!(f2.is_live() && f3.is_live());
        }

        /// A source that already holds as many pre-auth connections as the
        /// busiest one cannot push anyone out, and authenticated sessions are
        /// never displaced.
        #[test]
        fn displacement_never_favours_a_greedy_source_or_touches_sessions() {
            let adm = Admission::new(limits(4, 4, 4));
            let (a, b) = (ip("192.0.2.1"), ip("192.0.2.2"));
            let (sa1, sa2) = (adm.try_admit(a).unwrap(), adm.try_admit(a).unwrap());
            let (sb1, sb2) = (adm.try_admit(b).unwrap(), adm.try_admit(b).unwrap());
            assert!(adm.try_admit(a).is_none(), "equally busy: refused");
            assert!(adm.try_admit(b).is_none(), "equally busy: refused");
            assert!(sa1.is_live() && sa2.is_live() && sb1.is_live() && sb2.is_live());
            // Promote everything: nothing is displaceable any more.
            let mut all = [sa1, sa2, sb1, sb2];
            for s in &mut all {
                s.authenticated();
            }
            assert!(
                adm.try_admit(ip("192.0.2.3")).is_none(),
                "only sessions left"
            );
            assert!(all.iter().all(AdmissionSlot::is_live));
        }

        /// A source over its own caps is refused outright; it never gets to
        /// displace connections of other sources, even when the pool is full.
        #[test]
        fn per_source_caps_refuse_instead_of_displacing() {
            let adm = Admission::new(limits(4, 4, 2));
            let (a, b) = (ip("192.0.2.1"), ip("192.0.2.2"));
            let from_b = [adm.try_admit(b).unwrap(), adm.try_admit(b).unwrap()];
            let from_a = [adm.try_admit(a).unwrap(), adm.try_admit(a).unwrap()];
            assert!(adm.try_admit(a).is_none());
            assert!(from_a.iter().chain(&from_b).all(AdmissionSlot::is_live));
        }

        #[test]
        fn admission_keys_fold_mapped_v4_and_v6_prefixes() {
            let k = |s: &str| admission_key(s.parse().unwrap());
            assert_eq!(k("::ffff:192.0.2.1"), k("192.0.2.1"));
            assert_eq!(k("2001:db8:1:2:aaaa::1"), k("2001:db8:1:2:bbbb::2"));
            assert_ne!(k("2001:db8:1:2::1"), k("2001:db8:1:3::1"));
            let adm = Admission::new(limits(32, 1, 1));
            let _s = adm.try_admit("2001:db8::1".parse().unwrap()).unwrap();
            assert!(
                adm.try_admit("2001:db8::2".parse().unwrap()).is_none(),
                "one host cannot dodge the cap with many addresses in its /64"
            );
        }

        #[test]
        fn dial_reply_budget_fits_one_ipc_response() {
            use raven_core::ipc::{encode_response, IpcResponse, IPC_VERSION};
            let mut budget = DialReplyBudget::new("LAN");
            let big = vec![0xA5u8; 40 * 1024];
            let mut admitted = Vec::new();
            while budget.admit(&big).is_ok() {
                admitted.push(big.clone());
            }
            assert!(!admitted.is_empty());
            let err = budget.admit(&big).unwrap_err();
            assert!(err.starts_with("LAN_DIAL_REPLY_OVERFLOW"));
            // Nothing was marked as sent: the error must not claim delivery
            // (e.g. an oversized RLB1 offer, read before any frame is written).
            assert!(err.contains("(no frames were sent)"), "{err}");
            budget.mark_frames_sent();
            let err = budget.admit(&big).unwrap_err();
            assert!(err.ends_with("(frames were sent)"), "{err}");
            // What the budget admitted is bounded by the IPC frame, not the peer.
            assert!(admitted.len() * big.len() < MAX_IPC_FRAME);
            use base64::Engine;
            let resp = IpcResponse::LanDialResult {
                v: IPC_VERSION,
                frames_b64: admitted
                    .iter()
                    .map(|f| base64::engine::general_purpose::STANDARD.encode(f))
                    .collect(),
            };
            assert!(
                encode_response(&resp).is_ok(),
                "admitted replies must encode"
            );

            let mut budget = DialReplyBudget::new("INTERNET");
            for _ in 0..MAX_DIAL_REPLIES {
                budget.admit(b"ack").unwrap();
            }
            let err = budget.admit(b"ack").unwrap_err();
            assert!(
                err.starts_with("INTERNET_DIAL_REPLY_OVERFLOW"),
                "reply count is capped: {err}"
            );
        }

        fn envelope(kind: EnvType) -> Vec<u8> {
            Envelope {
                env_type: kind as u8,
                flags: 0,
                message_id: [7; 16],
                routing_tag: [8; 16],
                dest_device_hint: 0,
                created_at: 1,
                expires_at: 2,
                hop_limit: 1,
                replication_budget: 1,
                anti_replay_nonce: [9; 12],
                ratchet_header_ciphertext: vec![],
                message_ciphertext: vec![1, 2, 3],
                sender_authentication: vec![0u8; 64],
            }
            .pack()
        }

        const WAITS: ReplyWaits = ReplyWaits {
            first: Duration::from_secs(30),
            idle: Duration::from_secs(2),
        };

        #[test]
        fn collector_counts_only_frames_that_get_replies() {
            let message = envelope(EnvType::Message);
            let ack = envelope(EnvType::Ack);
            // A Message gets an ACK; an ACK or an RLB1 refresh gets nothing.
            assert!(expects_reply(&message));
            assert!(!expects_reply(&ack));
            assert!(!expects_reply(b"RLB1-refresh"));
            assert!(is_terminal_reply(&ack));
            assert!(!is_terminal_reply(&message));

            let mut c = ReplyCollector::new("LAN", WAITS);
            c.begin(b"offer".to_vec(), std::slice::from_ref(&message))
                .unwrap();
            assert_eq!(c.first_wait(), WAITS.first);
            // A non-terminal frame keeps the dial reading ...
            assert!(c.first(ReplyWait::Frame(b"noise".to_vec())).unwrap());
            // ... the ACK ends it.
            assert!(!c.next(ReplyWait::Frame(ack.clone())).unwrap());
            assert_eq!(c.into_replies().len(), 3);

            // Two frames that get replies need two terminal replies.
            let mut c = ReplyCollector::new("LAN", WAITS);
            c.begin(b"offer".to_vec(), &[message.clone(), message.clone()])
                .unwrap();
            assert!(c.first(ReplyWait::Frame(ack.clone())).unwrap());
            assert!(!c.next(ReplyWait::Frame(ack)).unwrap());

            // Nothing is answered: the short wait applies, not the patient one.
            let mut c = ReplyCollector::new("LAN", WAITS);
            c.begin(b"offer".to_vec(), &[b"RLB1-refresh".to_vec()])
                .unwrap();
            assert_eq!(c.first_wait(), WAITS.idle);
            assert!(!c.first(ReplyWait::Closed("eof".into())).unwrap());
        }

        #[test]
        fn collector_reports_closed_and_idle_distinctly() {
            let message = envelope(EnvType::Message);
            let mut c = ReplyCollector::new("INTERNET", WAITS);
            c.begin(b"offer".to_vec(), std::slice::from_ref(&message))
                .unwrap();
            c.mark_frames_sent();
            let err = c
                .first(ReplyWait::Closed("peer closed the connection".into()))
                .unwrap_err();
            assert!(err.starts_with("INTERNET_DIAL_PEER_CLOSED"), "{err}");
            assert!(err.contains("retry is safe"), "{err}");
            // An unreadable reply is not "closed".
            let mut c = ReplyCollector::new("LAN", WAITS);
            c.begin(b"offer".to_vec(), std::slice::from_ref(&message))
                .unwrap();
            let err = c
                .first(ReplyWait::Closed("aead: decryption failed".into()))
                .unwrap_err();
            assert!(err.starts_with("LAN_DIAL_BAD_REPLY"), "{err}");
            assert!(err.contains("aead: decryption failed"), "{err}");

            // Silence is "no reply yet", not a failure; after a reply it is a
            // normal end.
            let mut c = ReplyCollector::new("LAN", WAITS);
            c.begin(b"offer".to_vec(), &[message]).unwrap();
            assert!(!c.first(ReplyWait::Idle).unwrap());
            assert_eq!(c.into_replies(), vec![b"offer".to_vec()]);
        }

        #[tokio::test(start_paused = true)]
        async fn handshake_hang_ups_are_retried_but_other_errors_are_not() {
            use std::sync::atomic::{AtomicU32, Ordering};
            // Two hang-ups (a listener at its cap), then success.
            let calls = AtomicU32::new(0);
            let got = with_handshake_retries(|| {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 2 {
                        Err(PEER_CLOSED.to_string())
                    } else {
                        Ok(n)
                    }
                }
            })
            .await;
            assert_eq!(got, Ok(2));

            // Always hanging up: bounded, and the error says what happened.
            let calls = AtomicU32::new(0);
            let err = with_handshake_retries(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(PEER_CLOSED.to_string()) }
            })
            .await
            .unwrap_err();
            assert_eq!(calls.load(Ordering::SeqCst), HANDSHAKE_ATTEMPTS);
            assert!(err.contains("3 attempts"), "{err}");
            assert!(err.contains("connection limit"), "{err}");

            // An authentication failure is final: no retry.
            let calls = AtomicU32::new(0);
            let err = with_handshake_retries(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>("bind: identity mismatch".to_string()) }
            })
            .await
            .unwrap_err();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(err, "bind: identity mismatch");
        }

        /// Regression: the whole listener start-up was restarted after a bind
        /// failure, so a busy port made the daemon re-run the preflight (and
        /// re-take the chat-history / stage locks `ash` sends need) over and
        /// over. Steps are retried on their own: the preflight is not repeated
        /// for a bind that keeps failing.
        #[tokio::test(start_paused = true)]
        async fn each_startup_step_is_retried_on_its_own() {
            use std::sync::atomic::{AtomicU32, Ordering};
            let (preflights, binds) = (AtomicU32::new(0), AtomicU32::new(0));
            let identity = retry_until_ok("test", || {
                preflights.fetch_add(1, Ordering::SeqCst);
                async { Ok::<_, String>("identity") }
            })
            .await;
            let listener = retry_until_ok("test", || {
                let n = binds.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 3 {
                        Err("bind: address in use".to_string())
                    } else {
                        Ok("listener")
                    }
                }
            })
            .await;
            assert_eq!((identity, listener), ("identity", "listener"));
            assert_eq!(preflights.load(Ordering::SeqCst), 1);
            assert_eq!(binds.load(Ordering::SeqCst), 4);
        }

        #[tokio::test(start_paused = true)]
        async fn a_slow_startup_step_is_announced_once_and_still_awaited() {
            use std::sync::atomic::{AtomicU32, Ordering};
            let notices = AtomicU32::new(0);
            let slow = with_slow_notice_then(
                Duration::from_secs(15),
                async {
                    tokio::time::sleep(Duration::from_secs(40)).await;
                    7
                },
                || {
                    notices.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await;
            assert_eq!(slow, 7, "the step's result is not lost");
            assert_eq!(notices.load(Ordering::SeqCst), 1);
            let fast = with_slow_notice_then(Duration::from_secs(15), async { 8 }, || {
                notices.fetch_add(1, Ordering::SeqCst);
            })
            .await;
            assert_eq!(fast, 8);
            assert_eq!(notices.load(Ordering::SeqCst), 1, "a fast step is silent");
        }

        #[test]
        fn hang_up_error_kinds_share_one_text() {
            use std::io::{Error, ErrorKind};
            for kind in [
                ErrorKind::UnexpectedEof,
                ErrorKind::ConnectionReset,
                ErrorKind::ConnectionAborted,
                ErrorKind::BrokenPipe,
            ] {
                assert_eq!(io_error_text(&Error::from(kind)), PEER_CLOSED);
            }
            assert_ne!(
                io_error_text(&Error::from(ErrorKind::PermissionDenied)),
                PEER_CLOSED
            );
        }

        /// A listener whose accept() fails (fd exhaustion, an aborted
        /// connection) keeps serving, caps what it admits, and gives a
        /// finished connection's slot back.
        #[tokio::test]
        async fn serve_connections_survives_accept_errors_and_recycles_slots() {
            use std::io::{Error, ErrorKind};
            let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
            let addr = listener.local_addr().unwrap();
            let mut script = vec![
                Err(Error::from_raw_os_error(24)), // EMFILE
                Err(Error::from(ErrorKind::ConnectionAborted)),
            ]
            .into_iter();
            let accept_from = listener.clone();
            let (started_tx, mut started_rx) = mpsc::unbounded_channel::<()>();
            let (done_tx, mut done_rx) = mpsc::unbounded_channel::<()>();
            let server = tokio::spawn(serve_connections(
                "test",
                move || {
                    let scripted = script.next();
                    let listener = accept_from.clone();
                    async move {
                        match scripted {
                            Some(err) => err,
                            None => listener.accept().await,
                        }
                    }
                },
                limits(2, 2, 2),
                move |mut stream, slot| {
                    let (started, done) = (started_tx.clone(), done_tx.clone());
                    async move {
                        started.send(()).unwrap();
                        // Hold the slot until the dialer hangs up.
                        let mut sink = Vec::new();
                        let _ = stream.read_to_end(&mut sink).await;
                        drop(slot);
                        done.send(()).unwrap();
                        Ok(())
                    }
                },
            ));

            let first = TcpStream::connect(addr).await.unwrap();
            let _second = TcpStream::connect(addr).await.unwrap();
            started_rx.recv().await.unwrap();
            started_rx.recv().await.unwrap();

            // Over the cap: accepted by the kernel, then dropped by the server.
            let mut third = TcpStream::connect(addr).await.unwrap();
            let mut buf = [0u8; 1];
            assert!(matches!(third.read(&mut buf).await, Ok(0) | Err(_)));

            // The dialer is done: its slot comes back and the next dial is served.
            drop(first);
            done_rx.recv().await.unwrap();
            let _fourth = TcpStream::connect(addr).await.unwrap();
            started_rx.recv().await.unwrap();
            assert!(!server.is_finished(), "the accept loop never ends");
            server.abort();
        }

        /// A pre-auth connection displaced by a newcomer is cut (its handler
        /// is dropped, the socket closes) and the newcomer is served.
        #[tokio::test]
        async fn serve_connections_cuts_a_displaced_pre_auth_connection() {
            use std::io::{Error, ErrorKind};
            let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
            let addr = listener.local_addr().unwrap();
            // Loopback is one source address and the quotas are per source, so
            // the accept side stamps each socket with a scripted one.
            let mut sources = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
                .into_iter()
                .map(|s| SocketAddr::new(ip(s), 4000));
            let (started_tx, mut started_rx) = mpsc::unbounded_channel::<()>();
            let server = tokio::spawn(serve_connections(
                "test",
                move || {
                    let (listener, source) = (listener.clone(), sources.next());
                    async move {
                        let (stream, _) = listener.accept().await?;
                        Ok((stream, source.ok_or_else(|| Error::from(ErrorKind::Other))?))
                    }
                },
                limits(2, 2, 2),
                move |mut stream, slot| {
                    let started = started_tx.clone();
                    async move {
                        // Never authenticates: waits for the peer to hang up.
                        let _slot = slot;
                        started.send(()).unwrap();
                        let mut sink = Vec::new();
                        let _ = stream.read_to_end(&mut sink).await;
                        Ok(())
                    }
                },
            ));

            let mut oldest = TcpStream::connect(addr).await.unwrap();
            started_rx.recv().await.unwrap();
            let _second = TcpStream::connect(addr).await.unwrap();
            started_rx.recv().await.unwrap();

            // Full of pre-auth connections: the third dial gets in, and the
            // oldest silent one is hung up on.
            let _third = TcpStream::connect(addr).await.unwrap();
            started_rx.recv().await.unwrap();
            let mut buf = [0u8; 1];
            let cut = tokio::time::timeout(Duration::from_secs(30), oldest.read(&mut buf))
                .await
                .expect("the displaced connection is closed");
            assert!(matches!(cut, Ok(0) | Err(_)), "{cut:?}");
            assert!(!server.is_finished(), "the accept loop never ends");
            server.abort();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameReadError {
    Closed,
    Truncated,
    InvalidLength,
    IdleDeadline,
    FrameDeadline,
}

#[derive(Parser, Debug)]
#[command(name = "raven-node", about = "RAVEN serverless local node")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new identity in --data-dir (prints ADDRESS only, never the seed).
    Init {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
    },
    /// Print public address for this data dir.
    Address {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
    },
    /// Run listener; optionally send one message then wait for ACK.
    Run {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: String,
        /// Optional peer to dial (host:port).
        #[arg(long)]
        peer: Option<String>,
        /// Peer Ed25519 public key hex (32 bytes) for seal + verify.
        #[arg(long)]
        peer_pub_hex: Option<String>,
        /// REMOVED for security: plaintext on argv is refused. Use `--send-stdin`.
        #[arg(long, hide = true)]
        send: Option<String>,
        /// Read one plaintext line from stdin (secure). Never puts body on argv/`ps`.
        #[arg(long, default_value_t = false)]
        send_stdin: bool,
        /// Secure ATSAM session mode. The current daemon refuses origination
        /// until a persisted authenticated session is available. Lab builds
        /// may explicitly request `unsafe-interim`.
        #[arg(long, default_value = "atsam")]
        body_mode: String,
        /// Write bound listen address to this file (for demo scripts).
        #[arg(long)]
        write_addr: Option<PathBuf>,
        /// Write public key hex to this file (safe — public only).
        #[arg(long)]
        write_pub: Option<PathBuf>,
        /// Exit after successful send+ACK or after receiving N messages.
        #[arg(long, default_value_t = 0)]
        exit_after_recv: u32,
        #[arg(long, default_value_t = false)]
        exit_after_ack: bool,
        /// How long to run max (seconds).
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        /// Seal plaintext to this pub (A→C via bridge). Defaults to peer_pub_hex.
        #[arg(long)]
        seal_to_pub_hex: Option<String>,
        /// Verify inbound Message signatures with this pub (C verifies A).
        #[arg(long)]
        origin_pub_hex: Option<String>,
        /// Verify ACK signatures with this pub (A verifies C). Defaults to peer_pub_hex.
        #[arg(long)]
        ack_pub_hex: Option<String>,
    },
    /// Bridge daemon: LAN + mock-BLE opaque forward (survives ash exit).
    Bridge {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:0")]
        lan_listen: String,
        #[arg(long, default_value = "127.0.0.1:0")]
        ble_listen: String,
        #[arg(long)]
        write_lan_addr: Option<PathBuf>,
        #[arg(long)]
        write_ble_addr: Option<PathBuf>,
        #[arg(long)]
        write_status: Option<PathBuf>,
        /// 0 = run until killed (normal daemon).
        #[arg(long, default_value_t = 0)]
        timeout_secs: u64,
    },
    /// Print bridge/policy status (safe fields only).
    Status {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
    },
    /// Replay pending queue items to peer (crash recovery).
    Flush {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        peer_pub_hex: String,
        #[arg(long, default_value_t = 15)]
        timeout_secs: u64,
    },
    /// Always-on local IPC (UDS on Unix, named pipe on Windows) for ash ↔ raven-node.
    #[cfg(any(unix, windows))]
    Ipc {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
        /// Optional forward queue path for status.pending.
        #[arg(long)]
        forward_db: Option<PathBuf>,
    },
    /// Always-on daemon: bridge + IPC together (launchd/systemd/Task Scheduler).
    #[cfg(any(unix, windows))]
    Service {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
        #[arg(long, default_value = raven_core::DEFAULT_LAN_LISTEN)]
        lan_listen: String,
        #[arg(long, default_value = raven_core::DEFAULT_BLE_LISTEN)]
        ble_listen: String,
        /// Optional InternetTransport (RIH1) listen. Empty = disabled.
        /// Lab-only until INTERNET_DIRECT_PRODUCTION_ENABLED. localhost ≠ WAN.
        #[arg(long, default_value = "")]
        internet_listen: String,
        #[arg(long, default_value_t = 0)]
        timeout_secs: u64,
    },
    /// Report BLE adapter selection (mock vs platform). Safe fields only.
    BleStatus,
}

/// Milliseconds since the Unix epoch; a clock set before 1970 reads as 0
/// instead of panicking the daemon.
impl Commands {
    /// The profile directory a subcommand works in, if it takes one.
    fn data_dir(&self) -> Option<&Path> {
        match self {
            Commands::Init { data_dir }
            | Commands::Address { data_dir }
            | Commands::Status { data_dir }
            | Commands::Run { data_dir, .. }
            | Commands::Bridge { data_dir, .. }
            | Commands::Flush { data_dir, .. } => Some(data_dir),
            #[cfg(any(unix, windows))]
            Commands::Ipc { data_dir, .. } | Commands::Service { data_dir, .. } => Some(data_dir),
            Commands::BleStatus => None,
        }
    }
}

fn now_ms() -> u64 {
    system_time_ms(SystemTime::now())
}

fn system_time_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn queue_path(data_dir: &Path) -> PathBuf {
    data_dir.join("queue.sqlite")
}

fn load_or_err(data_dir: &Path) -> Result<Identity, String> {
    raven_core::load_identity_required(data_dir).map_err(|e| e.to_string())
}

fn init_identity(data_dir: &Path) -> Result<Identity, String> {
    raven_core::load_or_create_identity(data_dir)
        .map(|(id, _)| id)
        .map_err(|e| e.to_string())
}

async fn write_frame_with_timeout(
    stream: &mut TcpStream,
    bytes: &[u8],
    write_timeout: Duration,
) -> Result<(), String> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err("frame too large".into());
    }
    // One write per frame (a separate 4-byte prefix segment would wait on the
    // peer's delayed ACK).
    let mut framed = Vec::with_capacity(4 + bytes.len());
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(bytes);
    let write = async {
        stream.write_all(&framed).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        Ok(())
    };
    tokio::time::timeout(write_timeout, write)
        .await
        .map_err(|_| "frame write deadline exceeded".to_string())?
}

async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), String> {
    write_frame_with_timeout(stream, bytes, DEFAULT_CONNECTION_LIMITS.write_timeout).await
}

async fn read_frame_with_limits<R: AsyncRead + Unpin>(
    stream: &mut R,
    limits: ConnectionLimits,
) -> Result<Vec<u8>, FrameReadError> {
    let started = tokio::time::Instant::now();
    let frame_deadline = started + limits.frame_timeout;
    let idle_deadline = started + limits.idle_timeout;
    let header_deadline = if idle_deadline < frame_deadline {
        idle_deadline
    } else {
        frame_deadline
    };

    let mut len_buf = [0u8; 4];
    tokio::time::timeout_at(header_deadline, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| FrameReadError::IdleDeadline)?
        .map_err(|_| FrameReadError::Closed)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    // Incremental: reject absurd sizes before alloc (DoS note from envelope spec).
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(FrameReadError::InvalidLength);
    }
    let mut buf = vec![0u8; len];
    tokio::time::timeout_at(frame_deadline, stream.read_exact(&mut buf))
        .await
        .map_err(|_| FrameReadError::FrameDeadline)?
        .map_err(|_| FrameReadError::Truncated)?;
    Ok(buf)
}

#[cfg(feature = "unsafe-demo-crypto")]
fn fingerprint_of(pub_bytes: &[u8]) -> String {
    let mut k = [0u8; 32];
    let n = pub_bytes.len().min(32);
    k[..n].copy_from_slice(&pub_bytes[..n]);
    raven_core::fingerprint::device_fingerprint_v1(&k)
}

fn parse_pub_hex(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s.trim()).map_err(|e| e.to_string())?;
    if v.len() != 32 {
        return Err("peer_pub_hex must be 32 bytes".into());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

/// A provided-but-malformed key flag is an error, never "not provided":
/// silently dropping `--origin-pub-hex` would verify against `--peer-pub-hex`.
fn parse_pub_flag(flag: &str, value: Option<&String>) -> Result<Option<[u8; 32]>, String> {
    value
        .map(|s| parse_pub_hex(s).map_err(|e| format!("--{flag}: {e}")))
        .transpose()
}

fn build_message_envelope(
    identity: &Identity,
    peer_pub: &[u8; 32],
    plaintext: &[u8],
    message_id: [u8; 16],
    body_mode: &str,
) -> Result<Envelope, String> {
    #[cfg(not(feature = "unsafe-demo-crypto"))]
    {
        let _ = (identity, peer_pub, plaintext, message_id, body_mode);
        Err("ATSAM_SESSION_REQUIRED: no authenticated persisted ATSAM session is available".into())
    }

    #[cfg(feature = "unsafe-demo-crypto")]
    {
        let my_pub = identity.public_key_bytes();
        let my_addr = identity.address();
        let peer_addr = raven_core::encode_address(peer_pub);
        let sealed =
            match body_mode {
                "unsafe-interim" => {
                    let key = derive_pairwise_key(&my_pub, peer_pub);
                    seal_message(&key, plaintext, &my_addr, &peer_addr, &message_id)?
                }
                "atsam" | "" => return Err(
                    "ATSAM_SESSION_REQUIRED: no authenticated persisted ATSAM session is available"
                        .into(),
                ),
                other => {
                    return Err(format!(
                        "unknown body_mode={other} (production: atsam; lab only: unsafe-interim)"
                    ))
                }
            };
        // Lab-only routing material. Production routing tags must be derived from
        // an authenticated session root, never public identity material.
        let k_route = derive_pairwise_key(&my_pub, peer_pub);
        let tag = routing_tag::derive(&k_route, now_ms() / 1000, 0);
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut env = Envelope {
            env_type: EnvType::Message as u8,
            flags: 0,
            message_id,
            routing_tag: tag,
            dest_device_hint: 0,
            created_at: now_ms(),
            expires_at: now_ms() + 86_400_000,
            hop_limit: 8,
            replication_budget: 3,
            anti_replay_nonce: nonce,
            ratchet_header_ciphertext: vec![],
            message_ciphertext: sealed,
            sender_authentication: vec![],
        };
        env.sign_with(identity);
        Ok(env)
    }
}

#[cfg(feature = "unsafe-demo-crypto")]
fn build_ack_envelope(
    identity: &Identity,
    acked_message_id: [u8; 16],
    peer_pub: &[u8; 32],
) -> Envelope {
    let mut ack_nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut ack_nonce);
    let ack = Ack {
        acked_message_id,
        status: STATUS_DELIVERED,
        ack_nonce,
        created_at: now_ms(),
    };
    let sig = ack.sign(identity);
    let body = {
        let mut b = Vec::new();
        b.extend_from_slice(&ack.acked_message_id);
        b.push(ack.status);
        b.extend_from_slice(&ack.ack_nonce);
        b.extend_from_slice(&ack.created_at.to_be_bytes());
        b.extend_from_slice(&sig);
        b
    };
    let mut mid = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut mid);
    let k_route = derive_pairwise_key(&identity.public_key_bytes(), peer_pub);
    let tag = routing_tag::derive(&k_route, now_ms() / 1000, 1);
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut env = Envelope {
        env_type: EnvType::Ack as u8,
        flags: 0,
        message_id: mid,
        routing_tag: tag,
        dest_device_hint: 0,
        created_at: now_ms(),
        expires_at: now_ms() + 86_400_000,
        hop_limit: 8,
        replication_budget: 1,
        anti_replay_nonce: nonce,
        ratchet_header_ciphertext: vec![],
        message_ciphertext: body,
        sender_authentication: vec![],
    };
    env.sign_with(identity);
    env
}

struct NodeState {
    identity: Identity,
    queue: OutgoingQueue,
    /// Default peer pub (legacy two-node).
    peer_pub: Option<[u8; 32]>,
    /// Verify Message env signatures (origin A when C is recipient).
    origin_pub: Option<[u8; 32]>,
    /// Verify ACK signatures (C when A is sender).
    ack_pub: Option<[u8; 32]>,
    recv_count: u32,
    got_ack: bool,
}

/// Envelope verification keys. Immutable after startup, so a connection copies
/// them once and checks signatures (Ed25519 over up to 1 MiB) without holding
/// the `NodeState` lock.
#[derive(Clone, Copy, Debug)]
struct VerifyKeys {
    /// Message signatures: origin (A when C is recipient), else peer.
    msg: Option<[u8; 32]>,
    /// ACK signatures: ack key (C when A is sender), else peer.
    #[cfg_attr(not(feature = "unsafe-demo-crypto"), allow(dead_code))]
    ack: Option<[u8; 32]>,
}

/// Stateless half of inbound handling: parse, expiry and envelope signature.
/// Returns the envelope and the key that authenticated it; `Ok(None)` = ignore.
fn authenticate_inbound(
    raw: &[u8],
    keys: VerifyKeys,
) -> Result<Option<(Envelope, [u8; 32])>, String> {
    let env = Envelope::unpack(raw).ok_or_else(|| "malformed envelope".to_string())?;
    if now_ms() > env.expires_at {
        return Ok(None);
    }
    match env.env_type {
        x if x == EnvType::Message as u8 => {
            let peer_pub = keys
                .msg
                .ok_or_else(|| "origin/peer pub required to verify".to_string())?;
            if !env.verify(&peer_pub) {
                return Err("envelope auth failed".into());
            }
            Ok(Some((env, peer_pub)))
        }
        x if x == EnvType::Ack as u8 => {
            #[cfg(not(feature = "unsafe-demo-crypto"))]
            {
                let _ = env;
                Err("ATSAM_SESSION_REQUIRED: plaintext legacy ACK bodies are disabled".into())
            }

            #[cfg(feature = "unsafe-demo-crypto")]
            {
                let peer_pub = keys
                    .ack
                    .ok_or_else(|| "ack/peer pub required to verify".to_string())?;
                if !env.verify(&peer_pub) {
                    return Err("ack envelope auth failed".into());
                }
                Ok(Some((env, peer_pub)))
            }
        }
        _ => Ok(None),
    }
}

impl NodeState {
    fn verify_keys(&self) -> VerifyKeys {
        VerifyKeys {
            msg: self.origin_pub.or(self.peer_pub),
            ack: self.ack_pub.or(self.peer_pub),
        }
    }

    /// Both halves under one borrow (tests; connections split them so the
    /// signature check runs without the lock).
    #[cfg(test)]
    fn handle_inbound(&mut self, raw: &[u8]) -> Result<Option<Vec<u8>>, String> {
        match authenticate_inbound(raw, self.verify_keys())? {
            Some((env, peer_pub)) => self.handle_authenticated(env, peer_pub),
            None => Ok(None),
        }
    }

    /// Stateful half: queue/dedup work for an envelope that
    /// [`authenticate_inbound`] already verified against `peer_pub`.
    fn handle_authenticated(
        &mut self,
        env: Envelope,
        peer_pub: [u8; 32],
    ) -> Result<Option<Vec<u8>>, String> {
        #[cfg(not(feature = "unsafe-demo-crypto"))]
        let _ = peer_pub;
        match env.env_type {
            x if x == EnvType::Message as u8 => {
                match classify_sealed_body(&env.message_ciphertext) {
                    SealClass::InterimStub => {
                        #[cfg(not(feature = "unsafe-demo-crypto"))]
                        {
                            return Err(UNSAFE_INTERIM_DISABLED.into());
                        }

                        #[cfg(feature = "unsafe-demo-crypto")]
                        {
                            let my_addr = self.identity.address();
                            let peer_addr = raven_core::encode_address(&peer_pub);
                            let key =
                                derive_pairwise_key(&self.identity.public_key_bytes(), &peer_pub);
                            let plaintext = unseal_message(
                                &key,
                                &env.message_ciphertext,
                                &peer_addr,
                                &my_addr,
                                &env.message_id,
                            )?;
                            let dup = self
                                .queue
                                .dedup_check_and_insert(&env.message_id, now_ms())
                                .map_err(|e| e.to_string())?;
                            if dup {
                                return Ok(None);
                            }
                            self.recv_count += 1;
                            // Show the actual message to the human, plus who sent it.
                            let peer_fp = crate::fingerprint_of(&peer_pub);
                            let body = String::from_utf8_lossy(&plaintext);
                            let body = body.trim_end_matches(['\r', '\n']);
                            eprintln!("\n── INCOMING from {} ──", peer_fp);
                            for line in body.lines() {
                                eprintln!("│ {}", line);
                            }
                            eprintln!("────────────────────");
                            eprintln!("DELIVERED bytes={}", env.message_ciphertext.len());
                            let ack = build_ack_envelope(&self.identity, env.message_id, &peer_pub);
                            return Ok(Some(ack.pack()));
                        }
                    }
                    SealClass::OpaqueAtsam { proto } => {
                        if !rvna1_wire_plausible(&env.message_ciphertext) {
                            return Err(format!(
                                "opaque ATSAM proto={proto:#x} truncated or bad suite"
                            ));
                        }
                        return Err(format!(
                            "ATSAM_SESSION_REQUIRED: cannot authenticate/decrypt proto={proto:#x}; no delivery ACK emitted"
                        ));
                    }
                    SealClass::Other => {
                        return Err("unsupported message_ciphertext seal class".into());
                    }
                }
                #[allow(unreachable_code)]
                Ok(None)
            }
            x if x == EnvType::Ack as u8 => {
                #[cfg(not(feature = "unsafe-demo-crypto"))]
                {
                    // authenticate_inbound already refuses these; stay closed.
                    Err("ATSAM_SESSION_REQUIRED: plaintext legacy ACK bodies are disabled".into())
                }

                #[cfg(feature = "unsafe-demo-crypto")]
                {
                    if env.message_ciphertext.len() != 16 + 1 + 12 + 8 + 64 {
                        return Err("invalid ack body length".into());
                    }
                    let mut acked = [0u8; 16];
                    acked.copy_from_slice(&env.message_ciphertext[0..16]);
                    let status = env.message_ciphertext[16];
                    let mut ack_nonce = [0u8; 12];
                    ack_nonce.copy_from_slice(&env.message_ciphertext[17..29]);
                    let created_at = u64::from_be_bytes(
                        env.message_ciphertext[29..37]
                            .try_into()
                            .map_err(|_| "ack ts")?,
                    );
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&env.message_ciphertext[37..101]);
                    let ack = Ack {
                        acked_message_id: acked,
                        status,
                        ack_nonce,
                        created_at,
                    };
                    if !ack.verify(&sig, &peer_pub) {
                        return Err("ack signature failed".into());
                    }
                    if status != STATUS_DELIVERED {
                        return Err("unsupported ack status for delivery queue".into());
                    }
                    if created_at > now_ms().saturating_add(5 * 60 * 1000)
                        || created_at > env.expires_at
                    {
                        return Err("ack timestamp outside accepted bounds".into());
                    }
                    let queued = self
                        .queue
                        .get(&acked)
                        .map_err(|e| e.to_string())?
                        .ok_or_else(|| {
                            "ack does not match a pending outbound message".to_string()
                        })?;
                    if queued.peer_addr != raven_core::encode_address(&peer_pub) {
                        return Err("ack signer is not the queued recipient".into());
                    }
                    if queued.state == DeliveryState::Delivered {
                        return Ok(None);
                    }
                    let dup = self
                        .queue
                        .dedup_check_and_insert(&env.message_id, now_ms())
                        .map_err(|e| e.to_string())?;
                    if dup {
                        return Ok(None);
                    }
                    self.queue
                        .mark_state(&acked, DeliveryState::Delivered)
                        .map_err(|e| e.to_string())?;
                    self.got_ack = true;
                    eprintln!("ACK delivered");
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod security_tests {
    use super::*;
    #[cfg(not(feature = "unsafe-demo-crypto"))]
    use raven_core::seal::{ATSAM_PROTO_V2, SEAL_MAGIC_RVNA1, STUB_PROTO, STUB_SUITE};
    use tempfile::tempdir;

    fn signed_envelope(sender: &Identity, message_id: [u8; 16], body: Vec<u8>) -> Envelope {
        let mut env = Envelope {
            env_type: EnvType::Message as u8,
            flags: 0,
            message_id,
            routing_tag: [0x44; 16],
            dest_device_hint: 0,
            created_at: now_ms(),
            expires_at: now_ms() + 60_000,
            hop_limit: 4,
            replication_budget: 1,
            anti_replay_nonce: [0x55; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: body,
            sender_authentication: vec![],
        };
        env.sign_with(sender);
        env
    }

    fn node_state(path: &Path, recipient: Identity, sender: &Identity) -> NodeState {
        NodeState {
            identity: recipient,
            queue: OutgoingQueue::open(path).unwrap(),
            peer_pub: Some(sender.public_key_bytes()),
            origin_pub: None,
            ack_pub: None,
            recv_count: 0,
            got_ack: false,
        }
    }

    fn short_test_limits() -> ConnectionLimits {
        ConnectionLimits {
            idle_timeout: Duration::from_secs(2),
            frame_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(2),
            lifetime: Duration::from_secs(20),
        }
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        (accepted.unwrap().0, client.unwrap())
    }

    #[cfg(not(feature = "unsafe-demo-crypto"))]
    fn stub_shaped_body() -> Vec<u8> {
        let mut body = SEAL_MAGIC_RVNA1.to_vec();
        body.extend_from_slice(&[STUB_PROTO, STUB_SUITE]);
        body.extend_from_slice(&[0u8; 28]);
        body
    }

    #[cfg(not(feature = "unsafe-demo-crypto"))]
    fn opaque_atsam_shaped_body() -> Vec<u8> {
        let mut body = SEAL_MAGIC_RVNA1.to_vec();
        body.extend_from_slice(&[ATSAM_PROTO_V2, STUB_SUITE]);
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&[0u8; 28]);
        body
    }

    #[cfg(not(feature = "unsafe-demo-crypto"))]
    #[test]
    fn production_origination_requires_authenticated_session() {
        let sender = Identity::from_seed(&[1u8; 32]);
        let recipient = Identity::from_seed(&[2u8; 32]);
        let err = build_message_envelope(
            &sender,
            &recipient.public_key_bytes(),
            b"never queued",
            [3u8; 16],
            "atsam",
        )
        .unwrap_err();
        assert!(err.contains("ATSAM_SESSION_REQUIRED"));
    }

    #[cfg(not(feature = "unsafe-demo-crypto"))]
    #[test]
    fn signed_stub_and_opaque_atsam_get_no_ack_or_dedup_poison() {
        let dir = tempdir().unwrap();
        let sender = Identity::from_seed(&[4u8; 32]);
        let recipient = Identity::from_seed(&[5u8; 32]);
        let mut state = node_state(&dir.path().join("q.sqlite"), recipient, &sender);

        let stub = signed_envelope(&sender, [6u8; 16], stub_shaped_body()).pack();
        for _ in 0..2 {
            let err = state.handle_inbound(&stub).unwrap_err();
            assert!(err.contains("UNSAFE_INTERIM_DISABLED"));
        }

        let opaque = signed_envelope(&sender, [7u8; 16], opaque_atsam_shaped_body()).pack();
        for _ in 0..2 {
            let err = state.handle_inbound(&opaque).unwrap_err();
            assert!(err.contains("ATSAM_SESSION_REQUIRED"));
            assert!(err.contains("no delivery ACK"));
        }
        assert_eq!(state.recv_count, 0);
        assert!(!state.got_ack);
    }

    #[cfg(not(feature = "unsafe-demo-crypto"))]
    #[test]
    fn plaintext_ack_cannot_advance_queue() {
        let dir = tempdir().unwrap();
        let sender = Identity::from_seed(&[8u8; 32]);
        let recipient = Identity::from_seed(&[9u8; 32]);
        let acked = [0xAA; 16];
        let mut state = node_state(&dir.path().join("q.sqlite"), recipient, &sender);
        state
            .queue
            .enqueue(&QueueItem {
                message_id: acked,
                packed_envelope: vec![1],
                peer_addr: sender.address(),
                state: DeliveryState::Sent,
                created_at_ms: now_ms(),
            })
            .unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(&acked);
        body.push(raven_core::ack::STATUS_DELIVERED);
        body.extend_from_slice(&[0x11; 12]);
        body.extend_from_slice(&now_ms().to_be_bytes());
        body.extend_from_slice(&[0u8; 64]);
        let mut ack_env = signed_envelope(&sender, [0xAB; 16], body);
        ack_env.env_type = EnvType::Ack as u8;
        ack_env.sign_with(&sender);

        let err = state.handle_inbound(&ack_env.pack()).unwrap_err();
        assert!(err.contains("plaintext legacy ACK bodies are disabled"));
        assert_eq!(
            state.queue.get(&acked).unwrap().unwrap().state,
            DeliveryState::Sent
        );
        assert!(!state.got_ack);
    }

    #[cfg(feature = "unsafe-demo-crypto")]
    #[test]
    fn lab_invalid_signature_cannot_poison_valid_message_id() {
        let dir = tempdir().unwrap();
        let sender = Identity::from_seed(&[10u8; 32]);
        let recipient = Identity::from_seed(&[11u8; 32]);
        let mid = [12u8; 16];
        let key = derive_pairwise_key(&sender.public_key_bytes(), &recipient.public_key_bytes());
        let wire = seal_message(
            &key,
            b"authenticated",
            &sender.address(),
            &recipient.address(),
            &mid,
        )
        .unwrap();
        let mut forged = signed_envelope(&sender, mid, wire.clone());
        forged.sender_authentication[0] ^= 0x80;

        let mut state = node_state(&dir.path().join("q.sqlite"), recipient, &sender);
        assert!(state
            .handle_inbound(&forged.pack())
            .unwrap_err()
            .contains("auth failed"));

        let valid = signed_envelope(&sender, mid, wire);
        assert!(state.handle_inbound(&valid.pack()).unwrap().is_some());
        assert_eq!(state.recv_count, 1);
    }

    #[tokio::test]
    async fn frame_reader_rejects_zero_and_oversized_lengths_before_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer.write_all(&0u32.to_be_bytes()).await.unwrap();
        assert_eq!(
            read_frame_with_limits(&mut reader, short_test_limits()).await,
            Err(FrameReadError::InvalidLength)
        );

        let oversized = (MAX_FRAME_BYTES as u32) + 1;
        writer.write_all(&oversized.to_be_bytes()).await.unwrap();
        assert_eq!(
            read_frame_with_limits(&mut reader, short_test_limits()).await,
            Err(FrameReadError::InvalidLength)
        );
    }

    #[tokio::test]
    async fn frame_reader_is_exact_and_rejects_truncation() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&3u32.to_be_bytes()).await.unwrap();
        writer.write_all(b"one").await.unwrap();
        writer.write_all(&3u32.to_be_bytes()).await.unwrap();
        writer.write_all(b"two").await.unwrap();

        assert_eq!(
            read_frame_with_limits(&mut reader, short_test_limits())
                .await
                .unwrap(),
            b"one"
        );
        assert_eq!(
            read_frame_with_limits(&mut reader, short_test_limits())
                .await
                .unwrap(),
            b"two"
        );

        let (mut truncated_writer, mut truncated_reader) = tokio::io::duplex(32);
        truncated_writer
            .write_all(&4u32.to_be_bytes())
            .await
            .unwrap();
        truncated_writer.write_all(b"abc").await.unwrap();
        truncated_writer.shutdown().await.unwrap();
        assert_eq!(
            read_frame_with_limits(&mut truncated_reader, short_test_limits()).await,
            Err(FrameReadError::Truncated)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_frame_hits_hard_frame_deadline() {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer.write_all(&8u32.to_be_bytes()).await.unwrap();
        writer.write_all(b"x").await.unwrap();

        let limits = ConnectionLimits {
            idle_timeout: Duration::from_secs(4),
            frame_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(2),
            lifetime: Duration::from_secs(20),
        };
        let read_task =
            tokio::spawn(async move { read_frame_with_limits(&mut reader, limits).await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(read_task.await.unwrap(), Err(FrameReadError::FrameDeadline));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_connection_hits_header_deadline() {
        let (_writer, mut reader) = tokio::io::duplex(32);
        let limits = short_test_limits();
        let read_task =
            tokio::spawn(async move { read_frame_with_limits(&mut reader, limits).await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(read_task.await.unwrap(), Err(FrameReadError::IdleDeadline));
    }

    #[tokio::test]
    async fn connection_permit_is_reused_after_error_and_cancellation() {
        let dir = tempdir().unwrap();
        let sender = Identity::from_seed(&[0x31; 32]);
        let recipient = Identity::from_seed(&[0x32; 32]);
        let state = Arc::new(Mutex::new(node_state(
            &dir.path().join("permits.sqlite"),
            recipient,
            &sender,
        )));
        let limiter = Arc::new(Semaphore::new(1));

        let (server, mut client) = tcp_pair().await;
        let handle =
            spawn_connection_handler(server, state.clone(), limiter.clone(), short_test_limits())
                .unwrap();
        assert_eq!(limiter.available_permits(), 0);
        assert!(limiter.clone().try_acquire_owned().is_err());
        client.write_all(&0u32.to_be_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(handle.await.unwrap().unwrap_err().contains("invalid frame"));
        assert_eq!(limiter.available_permits(), 1);

        let (server, _client) = tcp_pair().await;
        let handle =
            spawn_connection_handler(server, state, limiter.clone(), short_test_limits()).unwrap();
        assert_eq!(limiter.available_permits(), 0);
        abort_handler(&handle);
        assert!(handle.await.unwrap_err().is_cancelled());
        assert_eq!(limiter.available_permits(), 1);
    }

    /// Regression: EMFILE / ECONNABORTED from accept() used to end the accept
    /// loop (and `service` then exited). They must be retried with backoff.
    #[tokio::test(start_paused = true)]
    async fn accept_errors_are_retried_not_fatal() {
        use std::io::{Error, ErrorKind};
        let started = tokio::time::Instant::now();
        let mut script = vec![
            Err(Error::from_raw_os_error(24)), // EMFILE
            Err(Error::from_raw_os_error(24)),
            Err(Error::from(ErrorKind::ConnectionAborted)),
            Err(Error::from(ErrorKind::OutOfMemory)),
            Ok(7u32),
        ]
        .into_iter();
        let got = accept_retrying("test", || {
            let next = script.next().expect("accept polled past script");
            async move { next }
        })
        .await;
        assert_eq!(got, 7);
        // Resource errors back off (50ms, 100ms; ECONNABORTED: none; then 50ms).
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn accept_backoff_is_capped_and_zero_for_peer_errors() {
        use std::io::{Error, ErrorKind};
        let emfile = Error::from_raw_os_error(24);
        let mut d = Duration::ZERO;
        for _ in 0..20 {
            d = accept_error_delay(&emfile, d);
        }
        assert_eq!(d, ACCEPT_BACKOFF_MAX);
        assert_eq!(
            accept_error_delay(&emfile, Duration::ZERO),
            ACCEPT_BACKOFF_MIN
        );
        assert_eq!(
            accept_error_delay(&Error::from(ErrorKind::ConnectionAborted), d),
            Duration::ZERO
        );
    }

    /// Regression: a typo in a key flag silently became `None` and message
    /// verification fell back to a different key.
    #[test]
    fn malformed_pub_flags_are_errors() {
        let good = "ab".repeat(32);
        assert_eq!(parse_pub_flag("origin-pub-hex", None).unwrap(), None);
        assert_eq!(
            parse_pub_flag("origin-pub-hex", Some(&good)).unwrap(),
            Some([0xab; 32])
        );
        for bad in ["zz".repeat(32), "ab".repeat(31), String::new()] {
            let err = parse_pub_flag("origin-pub-hex", Some(&bad)).unwrap_err();
            assert!(err.starts_with("--origin-pub-hex"), "{err}");
        }
    }

    /// Regression: envelope signatures were verified while holding the global
    /// NodeState lock. A frame that fails authentication must be handled
    /// without taking the lock at all.
    #[tokio::test]
    async fn unauthenticated_frames_are_rejected_without_state_lock() {
        let dir = tempdir().unwrap();
        let sender = Identity::from_seed(&[0x61; 32]);
        let recipient = Identity::from_seed(&[0x62; 32]);
        let forger = Identity::from_seed(&[0x63; 32]);
        let state = Arc::new(Mutex::new(node_state(
            &dir.path().join("lockfree.sqlite"),
            recipient,
            &sender,
        )));
        let limiter = Arc::new(Semaphore::new(1));
        let (server, mut client) = tcp_pair().await;
        let handle =
            spawn_connection_handler(server, state.clone(), limiter, short_test_limits()).unwrap();
        // Let the handler copy its verification keys and block on the read.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _held = state.lock().await;
        let forged = signed_envelope(&forger, [0x64; 16], vec![1, 2, 3]).pack();
        write_frame(&mut client, &forged).await.unwrap();
        client.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("handler must not wait for the state lock")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn connection_lifetime_timeout_releases_permit() {
        let dir = tempdir().unwrap();
        let sender = Identity::from_seed(&[0x41; 32]);
        let recipient = Identity::from_seed(&[0x42; 32]);
        let state = Arc::new(Mutex::new(node_state(
            &dir.path().join("lifetime.sqlite"),
            recipient,
            &sender,
        )));
        let limiter = Arc::new(Semaphore::new(1));
        let limits = ConnectionLimits {
            idle_timeout: Duration::from_secs(60),
            frame_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(2),
            lifetime: Duration::from_secs(5),
        };

        let (server, _client) = tcp_pair().await;
        let handle = spawn_connection_handler(server, state, limiter.clone(), limits).unwrap();
        assert_eq!(limiter.available_permits(), 0);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(6)).await;
        assert!(handle
            .await
            .unwrap()
            .unwrap_err()
            .contains("connection lifetime"));
        assert_eq!(limiter.available_permits(), 1);
    }
}

async fn handle_connection_until(
    mut stream: TcpStream,
    state: Arc<Mutex<NodeState>>,
    limits: ConnectionLimits,
    lifetime_deadline: tokio::time::Instant,
) -> Result<(), String> {
    let connection = async {
        let keys = state.lock().await.verify_keys();
        loop {
            let frame = match read_frame_with_limits(&mut stream, limits).await {
                Ok(f) => f,
                Err(FrameReadError::Closed) => break,
                Err(FrameReadError::Truncated) => return Err("truncated frame".to_string()),
                Err(FrameReadError::InvalidLength) => {
                    return Err("invalid frame length".to_string())
                }
                Err(FrameReadError::IdleDeadline) => {
                    return Err("connection idle deadline exceeded".to_string())
                }
                Err(FrameReadError::FrameDeadline) => {
                    return Err("frame read deadline exceeded".to_string())
                }
            };
            // Detailed parser/authentication failures are deliberately not logged:
            // untrusted peers must not create a log-amplification channel.
            // Signatures are checked before (and without) taking the state lock.
            let reply = match authenticate_inbound(&frame, keys) {
                Ok(Some((env, peer_pub))) => {
                    let mut st = state.lock().await;
                    st.handle_authenticated(env, peer_pub).ok().flatten()
                }
                _ => None,
            };
            if let Some(ack_bytes) = reply {
                write_frame_with_timeout(&mut stream, &ack_bytes, limits.write_timeout).await?;
            }
        }
        Ok(())
    };

    tokio::time::timeout_at(lifetime_deadline, connection)
        .await
        .map_err(|_| "connection lifetime exceeded".to_string())?
}

fn spawn_connection_handler(
    stream: TcpStream,
    state: Arc<Mutex<NodeState>>,
    limiter: Arc<Semaphore>,
    limits: ConnectionLimits,
) -> Result<JoinHandle<Result<(), String>>, ()> {
    let permit = limiter.try_acquire_owned().map_err(|_| ())?;
    // Measure lifetime from admission, not from whenever the executor first
    // polls the spawned task.
    let lifetime_deadline = tokio::time::Instant::now() + limits.lifetime;
    Ok(tokio::spawn(async move {
        // The owned permit is released by RAII on normal return, timeout,
        // cancellation, or panic unwinding.
        let _permit = permit;
        handle_connection_until(stream, state, limits, lifetime_deadline).await
    }))
}

fn spawn_default_connection_handler(
    stream: TcpStream,
    state: Arc<Mutex<NodeState>>,
    limiter: Arc<Semaphore>,
) -> Result<JoinHandle<Result<(), String>>, ()> {
    spawn_connection_handler(stream, state, limiter, DEFAULT_CONNECTION_LIMITS)
}

fn abort_handler(handle: &JoinHandle<Result<(), String>>) {
    if !handle.is_finished() {
        handle.abort();
    }
}

/// Opt-in cap on the service's own log. `ash` sets it (to its 1 MiB cap) only
/// when it redirected the daemon's stdout/stderr into `raven-node-service.log`,
/// so a service run by hand, under launchd/systemd, or redirected by the user is
/// never touched.
#[cfg(unix)]
const SERVICE_LOG_MAX_ENV: &str = "RAVEN_SERVICE_LOG_MAX_BYTES";
/// Lower bound for the cap, so a typo cannot make the service thrash its log.
#[cfg(unix)]
const SERVICE_LOG_MIN_BYTES: u64 = 64 * 1024;
#[cfg(unix)]
const SERVICE_LOG_CHECK_EVERY: Duration = Duration::from_secs(30);

/// Truncate the regular file behind `fd` to zero when it is larger than
/// `max_bytes`. The descriptor is `O_APPEND` (ash opens the log that way), so
/// the next write simply lands at the new end. Not a regular file (a terminal, a
/// pipe) or within the cap: nothing happens. `true` when it truncated.
#[cfg(unix)]
fn truncate_log_fd_if_over(fd: std::os::fd::RawFd, max_bytes: u64) -> bool {
    // SAFETY: `fstat` only writes into the zeroed `stat` we own; `ftruncate`
    // takes no memory. Both are plain syscalls on a descriptor number.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return false;
    }
    let regular = (st.st_mode & libc::S_IFMT) == libc::S_IFREG;
    if !regular || u64::try_from(st.st_size).unwrap_or(0) <= max_bytes {
        return false;
    }
    unsafe { libc::ftruncate(fd, 0) == 0 }
}

/// Keep the service log bounded while the daemon runs: `ash` only enforces its
/// cap when it next starts a service, and a detached daemon appends for weeks.
/// A no-op unless `ash` opted in through [`SERVICE_LOG_MAX_ENV`].
#[cfg(unix)]
fn spawn_service_log_bound() {
    let Some(max) = std::env::var(SERVICE_LOG_MAX_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    else {
        return;
    };
    let max = max.max(SERVICE_LOG_MIN_BYTES);
    let _ = std::thread::Builder::new()
        .name("service-log-bound".into())
        .spawn(move || loop {
            std::thread::sleep(SERVICE_LOG_CHECK_EVERY);
            // stdout and stderr normally share one file; either may be the log.
            let mut truncated = false;
            for fd in [1, 2] {
                truncated |= truncate_log_fd_if_over(fd, max);
            }
            if truncated {
                eprintln!("raven-node: service log truncated (it passed {max} bytes)");
            }
        });
}

/// Set while the bridge could not start or keep running; `Status` stops
/// advertising bridge / store / relay then.
#[cfg(any(unix, windows))]
static BRIDGE_DEGRADED: AtomicBool = AtomicBool::new(false);

#[cfg(any(unix, windows))]
pub(crate) fn bridge_degraded() -> bool {
    BRIDGE_DEGRADED.load(Ordering::Relaxed)
}

/// Keep one transport running for the life of the process. Each attempt runs
/// in its own task, so a panic is a failed attempt rather than a dead
/// supervisor; failures are logged (`<name> failed: …`, which the lab scripts
/// grep for) and retried with capped exponential backoff. `degraded`, when
/// given, is true between a failure and the next attempt.
#[cfg(any(unix, windows))]
async fn supervise<F, Fut>(
    name: &'static str,
    degraded: Option<&'static AtomicBool>,
    mut start: F,
) -> Infallible
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    let mut backoff = netutil::RESTART_BACKOFF_MIN;
    loop {
        if let Some(flag) = degraded {
            flag.store(false, Ordering::Relaxed);
        }
        let started = tokio::time::Instant::now();
        match tokio::spawn(start()).await {
            Ok(Ok(())) => eprintln!("{name} failed: exited unexpectedly"),
            Ok(Err(e)) => eprintln!("{name} failed: {e}"),
            Err(e) => eprintln!("{name} failed: task ended abnormally: {e}"),
        }
        if let Some(flag) = degraded {
            flag.store(true, Ordering::Relaxed);
        }
        if started.elapsed() >= netutil::RESTART_STABLE {
            backoff = netutil::RESTART_BACKOFF_MIN;
        }
        eprintln!(
            "{name}: unavailable; IPC and the other transports keep running; retrying in {}s",
            backoff.as_secs()
        );
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(netutil::RESTART_BACKOFF_MAX);
    }
}

/// Why `service` is stopping.
#[cfg(any(unix, windows))]
#[derive(Debug, PartialEq, Eq)]
enum ServiceEnd {
    /// The IPC server ended: without it nothing can reach the daemon.
    IpcStopped,
    /// A transport supervisor itself died (it never returns on its own).
    SupervisorDied(&'static str),
    /// `--timeout-secs` elapsed (lab / CI runs).
    TimedOut,
}

#[cfg(any(unix, windows))]
impl ServiceEnd {
    /// Non-zero for anything a supervisor (launchd, systemd) should restart.
    fn exit_code(&self) -> i32 {
        match self {
            Self::IpcStopped | Self::SupervisorDied(_) => 1,
            Self::TimedOut => 0,
        }
    }
}

/// Wait until the service has to stop. Transport failures never get here:
/// their supervisors absorb them.
#[cfg(any(unix, windows))]
async fn wait_service_end(
    ipc: &mut JoinHandle<()>,
    lan: &mut JoinHandle<Infallible>,
    inet: &mut JoinHandle<Infallible>,
    bridge: &mut JoinHandle<Infallible>,
    prune: &mut JoinHandle<Infallible>,
    timeout: Option<Duration>,
) -> ServiceEnd {
    let timer = async {
        match timeout {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        r = &mut *ipc => {
            if let Err(e) = r {
                eprintln!("ipc join: {e}");
            }
            ServiceEnd::IpcStopped
        }
        r = &mut *lan => {
            eprintln!("lan_direct supervisor ended: {r:?}");
            ServiceEnd::SupervisorDied("lan_direct")
        }
        r = &mut *inet => {
            eprintln!("internet_direct supervisor ended: {r:?}");
            ServiceEnd::SupervisorDied("internet_direct")
        }
        r = &mut *bridge => {
            eprintln!("bridge supervisor ended: {r:?}");
            ServiceEnd::SupervisorDied("bridge")
        }
        r = &mut *prune => {
            eprintln!("durable_prune supervisor ended: {r:?}");
            ServiceEnd::SupervisorDied("durable_prune")
        }
        _ = timer => {
            eprintln!("raven-node: service timeout");
            ServiceEnd::TimedOut
        }
    }
}

#[tokio::main]
async fn main() {
    use raven_core::macos_keychain::{set_hint_mode, HintMode};
    let cli = Cli::parse();
    // A macOS Keychain dialog blocks the call it is raised from: besides the
    // human hint (without Ctrl-C advice: nothing can press it here), print one
    // BLOCKED_ON_KEYCHAIN line to stderr. That lands in raven-node-service.log
    // when `ash` started the service (where `ash` can find it), and in
    // raven-node.err under launchd. Set before any identity or session access.
    let _ = set_hint_mode(HintMode::Daemon);
    // No `--data-dir`, no override and no usable HOME: say so now instead of
    // letting the first store fail with an opaque "Not a directory".
    if let Some(dir) = cli.cmd.data_dir() {
        if let Err(e) = raven_core::paths::require_resolved_data_dir(dir) {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
    match cli.cmd {
        Commands::Init { data_dir } => match init_identity(&data_dir) {
            Ok(id) => {
                println!("address={}", id.address());
                println!("pub_hex={}", hex::encode(id.public_key_bytes()));
                // NEVER print seed.
            }
            Err(e) => {
                eprintln!("init failed: {e}");
                std::process::exit(1);
            }
        },
        Commands::Address { data_dir } => match load_or_err(&data_dir) {
            Ok(id) => {
                println!("address={}", id.address());
                println!("pub_hex={}", hex::encode(id.public_key_bytes()));
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        },
        Commands::Run {
            data_dir,
            listen,
            peer,
            peer_pub_hex,
            send,
            send_stdin,
            body_mode,
            write_addr,
            write_pub,
            exit_after_recv,
            exit_after_ack,
            timeout_secs,
            seal_to_pub_hex,
            origin_pub_hex,
            ack_pub_hex,
        } => {
            let identity = init_identity(&data_dir).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            });
            if let Some(path) = write_pub {
                let _ = std::fs::write(path, hex::encode(identity.public_key_bytes()));
            }
            let queue = OutgoingQueue::open(&queue_path(&data_dir)).unwrap_or_else(|e| {
                eprintln!("queue: {e}");
                std::process::exit(1);
            });
            let pub_flag = |flag: &str, value: Option<&String>| {
                parse_pub_flag(flag, value).unwrap_or_else(|e| {
                    eprintln!("{e}");
                    std::process::exit(2);
                })
            };
            let peer_pub = pub_flag("peer-pub-hex", peer_pub_hex.as_ref());
            let origin_pub = pub_flag("origin-pub-hex", origin_pub_hex.as_ref());
            let ack_pub = pub_flag("ack-pub-hex", ack_pub_hex.as_ref());
            let seal_to = pub_flag("seal-to-pub-hex", seal_to_pub_hex.as_ref()).or(peer_pub);
            let state = Arc::new(Mutex::new(NodeState {
                identity,
                queue,
                peer_pub,
                origin_pub,
                ack_pub,
                recv_count: 0,
                got_ack: false,
            }));
            let connection_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTION_HANDLERS));

            let listener = TcpListener::bind(&listen).await.unwrap_or_else(|e| {
                eprintln!("bind: {e}");
                std::process::exit(1);
            });
            let local = listener.local_addr().unwrap();
            eprintln!("raven-node: listen {local}");
            if let Some(path) = write_addr {
                let _ = std::fs::write(path, local.to_string());
            }

            let state_accept = state.clone();
            let limiter_accept = connection_limiter.clone();
            tokio::spawn(async move {
                loop {
                    // Transient accept errors (EMFILE, ECONNABORTED, ...) are
                    // backed off inside accept_retrying; they never end the loop.
                    let (stream, _) = accept_retrying("raven-node", || listener.accept()).await;
                    let st = state_accept.clone();
                    // Admission is intentionally non-blocking. When full, the
                    // just-accepted socket is dropped without spawning work.
                    let _ = spawn_default_connection_handler(stream, st, limiter_accept.clone());
                }
            });

            let send_body: Option<String> = if send_stdin {
                use std::io::{self, BufRead};
                let mut line = String::new();
                if io::stdin().lock().read_line(&mut line).is_err() {
                    eprintln!("failed to read --send-stdin");
                    std::process::exit(1);
                }
                let t = line.trim_end_matches(['\r', '\n']).to_string();
                if t.is_empty() {
                    eprintln!("empty --send-stdin body");
                    std::process::exit(1);
                }
                Some(t)
            } else if send.is_some() {
                eprintln!(
                    "REFUSE: --send puts plaintext on argv (visible via ps). Use --send-stdin."
                );
                std::process::exit(2);
            } else {
                None
            };

            if let (Some(peer_s), Some(text), Some(pp)) =
                (peer.as_ref(), send_body.as_ref(), seal_to)
            {
                let mut mid = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut mid);
                let env = {
                    let st = state.lock().await;
                    build_message_envelope(&st.identity, &pp, text.as_bytes(), mid, &body_mode)
                        .unwrap_or_else(|e| {
                            eprintln!("{e}");
                            std::process::exit(1);
                        })
                };
                eprintln!("ENVELOPE_FP mid={}", hex::encode(mid));
                let packed = env.pack();
                {
                    let st = state.lock().await;
                    st.queue
                        .enqueue(&QueueItem {
                            message_id: mid,
                            packed_envelope: packed.clone(),
                            peer_addr: raven_core::encode_address(&pp),
                            state: DeliveryState::Queued,
                            created_at_ms: now_ms(),
                        })
                        .unwrap_or_else(|e| {
                            eprintln!("queue: {e}");
                            std::process::exit(1);
                        });
                }
                let (mut stream, _) = dial_peer_or_exit(peer_s, timeout_secs).await;
                if let Err(e) = write_frame(&mut stream, &packed).await {
                    eprintln!("send: {e}");
                    std::process::exit(1);
                }
                {
                    let st = state.lock().await;
                    // The frame is already out; a failed state write must not
                    // abort the wait for the ACK.
                    if let Err(e) = st.queue.mark_state(&mid, DeliveryState::Sent) {
                        eprintln!("queue: mark sent: {e}");
                    }
                }
                let st = state.clone();
                if spawn_connection_handler(
                    stream,
                    st,
                    connection_limiter.clone(),
                    client_limits(timeout_secs),
                )
                .is_err()
                {
                    eprintln!("raven-node: connection handler capacity reached");
                }
            } else if let Some(peer_s) = peer.as_ref() {
                // Dial-only (e.g. C connects to B mock-BLE to receive).
                let (stream, _) = dial_peer_or_exit(peer_s, timeout_secs).await;
                let st = state.clone();
                if spawn_connection_handler(
                    stream,
                    st,
                    connection_limiter.clone(),
                    client_limits(timeout_secs),
                )
                .is_err()
                {
                    eprintln!("raven-node: connection handler capacity reached");
                }
            }

            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_secs(timeout_secs.min(MAX_RUN_SECS));
            loop {
                if tokio::time::Instant::now() > deadline {
                    eprintln!("raven-node: timeout");
                    break;
                }
                {
                    let st = state.lock().await;
                    if exit_after_ack && st.got_ack {
                        eprintln!("raven-node: exit_after_ack");
                        break;
                    }
                    if exit_after_recv > 0 && st.recv_count >= exit_after_recv {
                        eprintln!("raven-node: exit_after_recv");
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
        Commands::Bridge {
            data_dir,
            lan_listen,
            ble_listen,
            write_lan_addr,
            write_ble_addr,
            write_status,
            timeout_secs,
        } => {
            if let Err(e) = bridge_run::run_bridge_daemon(
                data_dir,
                lan_listen,
                ble_listen,
                write_lan_addr,
                write_ble_addr,
                write_status,
                timeout_secs,
            )
            .await
            {
                eprintln!("bridge failed: {e}");
                std::process::exit(1);
            }
        }
        Commands::Status { data_dir } => {
            let policy = load_policy(&data_dir);
            let queue = forward_queue_counts(&data_dir);
            let (pending, total) = queue.as_ref().copied().unwrap_or((0, 0));
            let snap =
                BridgeStatusSnapshot::from_policy(&policy, &["lan", "mock_ble"], pending, total);
            println!("bridge={}", snap.bridge);
            println!("store={}", snap.store);
            println!("relay={}", snap.relay);
            println!("endpoint={}", snap.endpoint);
            println!("auto_policy={}", snap.auto_policy);
            println!("transports={}", snap.transports.join(","));
            match &queue {
                Ok(_) => {
                    println!("forward_queue_pending={}", snap.forward_queue_pending);
                    println!("forward_queue_total={}", snap.forward_queue_total);
                }
                // An unreadable queue is not an empty one: say so, and fail.
                Err(e) => {
                    println!("forward_queue_pending=unknown");
                    println!("forward_queue_total=unknown");
                    println!(
                        "forward_queue_error={}",
                        raven_core::sanitize::sanitize_terminal_line(e)
                    );
                }
            }
            println!("capabilities={}", snap.capabilities.join(","));
            if let Err(e) = queue {
                eprintln!("raven-node status: forward queue unavailable: {e}");
                std::process::exit(1);
            }
        }
        Commands::Flush {
            data_dir,
            peer,
            peer_pub_hex,
            timeout_secs,
        } => {
            let identity = load_or_err(&data_dir).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            });
            let queue = OutgoingQueue::open(&queue_path(&data_dir)).unwrap_or_else(|e| {
                eprintln!("queue: {e}");
                std::process::exit(1);
            });
            let peer_pub = parse_pub_hex(&peer_pub_hex).unwrap_or_else(|e| {
                eprintln!("--peer-pub-hex: {e}");
                std::process::exit(2);
            });
            if let Err(e) = netutil::check_dial_syntax(&peer) {
                eprintln!("--peer: {e}");
                std::process::exit(2);
            }
            let pending = queue.pending().unwrap_or_else(|e| {
                eprintln!("queue: {e}");
                std::process::exit(1);
            });
            eprintln!("raven-node: flushing {} pending", pending.len());
            let state = Arc::new(Mutex::new(NodeState {
                identity,
                queue,
                peer_pub: Some(peer_pub),
                origin_pub: None,
                ack_pub: None,
                recv_count: 0,
                got_ack: false,
            }));
            let connection_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTION_HANDLERS));
            // One dead connect or reset must not strand the items behind it:
            // every item is attempted, and the exit status says if any failed.
            let per_addr = Duration::from_secs(timeout_secs.clamp(1, 10));
            let mut failed = 0usize;
            for item in pending {
                let mid = hex::encode(&item.message_id[..4]);
                let mut stream = match netutil::connect_dial(&peer, per_addr, per_addr * 2).await {
                    Ok((stream, _)) => stream,
                    Err(e) => {
                        eprintln!("raven-node: flush {mid}…: connect: {e}");
                        failed += 1;
                        continue;
                    }
                };
                if let Err(e) = write_frame(&mut stream, &item.packed_envelope).await {
                    eprintln!("raven-node: flush {mid}…: send: {e}");
                    failed += 1;
                    continue;
                }
                {
                    let st = state.lock().await;
                    if let Err(e) = st.queue.mark_state(&item.message_id, DeliveryState::Sent) {
                        // Sent but not recorded: the next flush re-sends it
                        // and the peer's dedup absorbs the repeat.
                        eprintln!("raven-node: flush {mid}…: mark sent: {e}");
                        failed += 1;
                    }
                }
                let st = state.clone();
                let Ok(mut handle) =
                    spawn_default_connection_handler(stream, st, connection_limiter.clone())
                else {
                    eprintln!("raven-node: connection handler capacity reached");
                    continue;
                };
                if tokio::time::timeout(
                    std::time::Duration::from_secs(timeout_secs.min(MAX_RUN_SECS)),
                    &mut handle,
                )
                .await
                .is_err()
                {
                    // Dropping a JoinHandle detaches it. Explicit cancellation is
                    // required so a stalled peer cannot accumulate flush handlers.
                    abort_handler(&handle);
                    let _ = handle.await;
                }
            }
            let got_ack = state.lock().await.got_ack;
            if got_ack {
                eprintln!("raven-node: flush got ACK");
            } else {
                eprintln!("raven-node: flush done (check pending)");
            }
            if failed > 0 {
                eprintln!("raven-node: flush: {failed} item(s) not sent");
                std::process::exit(1);
            }
        }
        #[cfg(any(unix, windows))]
        Commands::Ipc {
            data_dir,
            forward_db,
        } => {
            let fwd = forward_db.or_else(|| {
                let p = bridge_run::forward_queue_path(&data_dir);
                if p.exists() {
                    Some(p)
                } else {
                    None
                }
            });
            if let Err(e) = ipc_server::run_ipc_server(data_dir, fwd).await {
                eprintln!("ipc failed: {e}");
                std::process::exit(1);
            }
        }
        #[cfg(any(unix, windows))]
        Commands::Service {
            data_dir,
            lan_listen,
            ble_listen,
            internet_listen,
            timeout_secs,
        } => {
            #[cfg(unix)]
            spawn_service_log_bound();
            // Identity preflight runs before any other profile-state creation.
            // The first-install proof (raven-core identity_store) tolerates an
            // *empty* forward_queue.sqlite and the IPC socket / instance lock,
            // but nothing that holds state: custody or rate-limit rows (and any
            // other file) that predate the identity would make a fresh profile
            // fail require_proven_first_install and wedge first install. Doing
            // the preflight first means none of that can exist yet.
            init_identity(&data_dir).unwrap_or_else(|e| {
                eprintln!("service identity preflight failed: {e}");
                std::process::exit(1);
            });
            // Pre-create WAL schema so IPC + bridge do not race on first open.
            let fq = bridge_run::forward_queue_path(&data_dir);
            let _warmup = ForwardQueue::open(&fq).map_err(|e| {
                eprintln!("service queue warmup failed: {e}");
                std::process::exit(1);
            });
            drop(_warmup);
            let fwd = Some(fq);
            let data_ipc = data_dir.clone();
            let mut ipc_task = tokio::spawn(async move {
                if let Err(e) = ipc_server::run_ipc_server(data_ipc, fwd).await {
                    eprintln!("ipc failed: {e}");
                }
            });
            // IPC is the one thing the service cannot run without. Every
            // transport is supervised on its own: a busy port, a slow or
            // failed preflight or a crash is logged, shown in Status (the
            // listener is simply not up) and retried with backoff; it never
            // takes IPC or the other transports down, and there is no
            // start-up wait that could mistake "slow" for "failed".
            let data_lan = data_dir.clone();
            let mut lan_task = tokio::spawn(supervise("lan_direct", None, move || {
                lan_direct::run_listener(data_lan.clone(), lan_listen.clone())
            }));
            let mut inet_task = if internet_listen.trim().is_empty() {
                tokio::spawn(std::future::pending::<Infallible>())
            } else {
                let data_inet = data_dir.clone();
                tokio::spawn(supervise("internet_direct", None, move || {
                    internet_direct::run_listener(data_inet.clone(), internet_listen.clone())
                }))
            };
            // Expired sessions (protected K_root, outbox envelopes, inbox
            // rows) are destroyed on a timer, not only when a listener starts
            // or the next PairInit arrives.
            let data_prune = data_dir.clone();
            let mut prune_task = tokio::spawn(supervise("durable_prune", None, move || {
                lan_direct::run_durable_prune(data_prune.clone())
            }));
            // Mock BLE stays on ble_listen. Do not fanout the production LAN port.
            // The service owns --timeout-secs; the bridge itself runs until stopped.
            let mut bridge_task =
                tokio::spawn(supervise("bridge", Some(&BRIDGE_DEGRADED), move || {
                    bridge_run::run_bridge_daemon(
                        data_dir.clone(),
                        "127.0.0.1:0".into(),
                        ble_listen.clone(),
                        None,
                        None,
                        None,
                        0,
                    )
                }));
            let timeout =
                (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs.min(MAX_RUN_SECS)));
            let end = wait_service_end(
                &mut ipc_task,
                &mut lan_task,
                &mut inet_task,
                &mut bridge_task,
                &mut prune_task,
                timeout,
            )
            .await;
            ipc_task.abort();
            lan_task.abort();
            inet_task.abort();
            bridge_task.abort();
            prune_task.abort();
            std::process::exit(end.exit_code());
        }
        Commands::BleStatus => {
            let kind = raven_core::ble_adapter::select_ble_adapter_from_env();
            println!("ble_adapter={}", kind.as_str());
            println!("transport={:?}", kind.transport());
            println!(
                "hint=set RAVEN_BLE_PLATFORM=1 to prefer platform GATT; default mock_ble for CI"
            );
            #[cfg(feature = "corebluetooth")]
            {
                let (k, st) = corebluetooth_exp::probe();
                println!("corebluetooth_feature=on");
                println!("corebluetooth_kind={}", k.as_str());
                println!("corebluetooth_state={}", st.as_str());
                if let Err(e) = corebluetooth_exp::try_start_gatt() {
                    println!("corebluetooth_start={e}");
                }
            }
            #[cfg(not(feature = "corebluetooth"))]
            {
                println!("corebluetooth_feature=off");
                println!("corebluetooth_build=cargo build -p raven-node --features corebluetooth");
            }
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Regression: `unwrap()` on `duration_since(UNIX_EPOCH)` panicked the
    /// daemon on a clock set before 1970.
    #[test]
    fn pre_epoch_clock_reads_as_zero() {
        assert_eq!(system_time_ms(UNIX_EPOCH - Duration::from_secs(5)), 0);
        assert_eq!(
            system_time_ms(UNIX_EPOCH + Duration::from_millis(1234)),
            1234
        );
        assert!(now_ms() > 0);
    }

    /// The daemon bounds its own (append-mode) log in place: past the cap the
    /// file is truncated and later writes land at the new end; a file within the
    /// cap, and anything that is not a regular file, is left alone.
    #[cfg(unix)]
    #[test]
    fn service_log_is_truncated_in_place_only_past_the_cap() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raven-node-service.log");
        // Same flags ash opens the log with.
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        log.write_all(&[b'x'; 100]).unwrap();
        assert!(!truncate_log_fd_if_over(log.as_raw_fd(), 100), "at the cap");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 100);
        log.write_all(b"y").unwrap();
        assert!(
            truncate_log_fd_if_over(log.as_raw_fd(), 100),
            "past the cap"
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        // The same descriptor keeps working: the next line is at the new start.
        log.write_all(b"after\n").unwrap();
        let mut text = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "after\n");
        // A pipe (or terminal) is never truncated.
        let (reader, writer) = std::io::pipe().unwrap();
        assert!(!truncate_log_fd_if_over(writer.as_raw_fd(), 0));
        drop((reader, writer));
        // A bad descriptor is not a panic.
        assert!(!truncate_log_fd_if_over(-1, 0));
    }

    /// Regression: `raven-node status` opened (and so created)
    /// forward_queue.sqlite on a fresh profile, which made the next
    /// `init`/`service` fail require_proven_first_install.
    #[test]
    fn status_never_creates_the_forward_queue() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(forward_queue_counts(dir.path()), Ok((0, 0)));
        assert!(
            !bridge_run::forward_queue_path(dir.path()).exists(),
            "status must not touch a profile that has no queue"
        );
    }

    /// Regression: open / count errors were reported as an empty queue.
    #[test]
    fn status_reports_an_unreadable_queue_instead_of_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = bridge_run::forward_queue_path(dir.path());
        std::fs::write(&path, b"this is not a sqlite database, just 100 bytes of text....................................").unwrap();
        let err = forward_queue_counts(dir.path()).unwrap_err();
        assert!(err.contains("forward_queue.sqlite"), "{err}");

        // A queue that works reports its real counts.
        let ok_dir = tempfile::tempdir().unwrap();
        drop(ForwardQueue::open(&bridge_run::forward_queue_path(ok_dir.path())).unwrap());
        assert_eq!(forward_queue_counts(ok_dir.path()), Ok((0, 0)));
    }

    /// Regression: a dialed `run --peer` connection inherited the accept-side
    /// 10 s idle bound (and the 30 s frame bound caps the header wait), so a
    /// receiver told to wait 35 s was dropped long before. Client limits
    /// cover the whole `--timeout-secs`.
    #[test]
    fn client_limits_cover_the_requested_wait() {
        for secs in [0, 1, 30, 35, 40, 600] {
            let l = client_limits(secs);
            let want = Duration::from_secs(secs);
            assert!(l.idle_timeout >= want, "{secs}: idle {:?}", l.idle_timeout);
            assert!(
                l.frame_timeout >= want,
                "{secs}: frame {:?}",
                l.frame_timeout
            );
            assert!(l.lifetime >= want, "{secs}: lifetime {:?}", l.lifetime);
        }
        // Absurd values are clamped, not an Instant overflow.
        assert!(client_limits(u64::MAX).lifetime <= Duration::from_secs(MAX_RUN_SECS + 5));
        // The accept side keeps its slow-loris bound.
        assert_eq!(
            DEFAULT_CONNECTION_LIMITS.idle_timeout,
            Duration::from_secs(10)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_dialed_connection_survives_a_late_frame_that_default_limits_drop() {
        let late = Duration::from_secs(25);
        let (mut peer, mut mine) = tokio::io::duplex(1 << 12);
        let send = tokio::spawn(async move {
            tokio::time::sleep(late).await;
            peer.write_all(&3u32.to_be_bytes()).await.unwrap();
            peer.write_all(b"abc").await.unwrap();
            peer
        });
        assert_eq!(
            read_frame_with_limits(&mut mine, client_limits(35)).await,
            Ok(b"abc".to_vec()),
            "a frame 25 s into a 35 s wait must arrive"
        );
        let _peer = send.await.unwrap();

        let (_peer2, mut mine2) = tokio::io::duplex(1 << 12);
        assert_eq!(
            read_frame_with_limits(&mut mine2, DEFAULT_CONNECTION_LIMITS).await,
            Err(FrameReadError::IdleDeadline),
            "the accept-side default still idles out at 10 s"
        );
    }

    #[cfg(any(unix, windows))]
    fn counting_failures(
        attempts: Arc<AtomicUsize>,
        err: &'static str,
    ) -> impl FnMut() -> std::future::Ready<Result<(), String>> {
        move || {
            attempts.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err(err.to_string()))
        }
    }

    /// Regression: a busy LAN port (or any listener failure) ended the whole
    /// `service` process. The listener is now retried with backoff and
    /// nothing else notices.
    #[cfg(any(unix, windows))]
    #[tokio::test(start_paused = true)]
    async fn failing_listener_is_retried_and_never_ends_the_service() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut ipc = tokio::spawn(std::future::pending::<()>());
        let mut lan = tokio::spawn(supervise(
            "test_lan",
            None,
            counting_failures(attempts.clone(), "bind: address in use"),
        ));
        let mut inet = tokio::spawn(std::future::pending::<Infallible>());
        let mut bridge = tokio::spawn(std::future::pending::<Infallible>());
        let mut prune = tokio::spawn(std::future::pending::<Infallible>());
        let outcome = tokio::time::timeout(
            Duration::from_secs(3600),
            wait_service_end(&mut ipc, &mut lan, &mut inet, &mut bridge, &mut prune, None),
        )
        .await;
        assert!(
            outcome.is_err(),
            "service must still be running: {outcome:?}"
        );
        // 1 + 2 + 4 + 8 + 16 s, then 30 s steps: well past a handful of tries.
        assert!(attempts.load(Ordering::SeqCst) >= 10);
        assert!(!ipc.is_finished(), "IPC untouched by the listener failure");
        ipc.abort();
        inet.abort();
        bridge.abort();
        prune.abort();
        lan.abort();
    }

    #[cfg(any(unix, windows))]
    #[tokio::test(start_paused = true)]
    async fn retry_backoff_is_capped_and_a_panic_is_just_a_failed_attempt() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let a = attempts.clone();
        let task = tokio::spawn(supervise("test_panic", None, move || {
            let n = a.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    panic!("listener bug");
                }
                Err("still down".to_string())
            }
        }));
        // Attempts at 0 (the panic), 1, 3, 7, 15, 31, 61 and 91 s: the delay
        // stops doubling at 30 s (an uncapped 32 s would push the 8th past 93 s).
        tokio::time::sleep(Duration::from_millis(91_500)).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 8);
        assert!(!task.is_finished());
        task.abort();
    }

    /// The bridge flag is up while an attempt is failing and clear again when
    /// the next one starts (`Status` stops advertising bridge capabilities).
    #[cfg(any(unix, windows))]
    #[tokio::test(start_paused = true)]
    async fn bridge_degraded_flag_follows_the_attempts() {
        static FLAG: AtomicBool = AtomicBool::new(false);
        let attempts = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(supervise(
            "test_bridge",
            Some(&FLAG),
            counting_failures(attempts.clone(), "ble bind: address in use"),
        ));
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(FLAG.load(Ordering::Relaxed), "degraded while retrying");
        task.abort();
    }

    /// Regression: `service` awaited the listener task during start-up, so a
    /// preflight slower than 1 s parked it for ever and the bridge never
    /// started. There is no start-up wait now: a listener that is slow to come
    /// up (here: 120 s) changes nothing, and only IPC ending (or the
    /// timeout) stops the service.
    #[cfg(any(unix, windows))]
    #[tokio::test(start_paused = true)]
    async fn slow_listener_start_does_not_block_or_end_the_service() {
        let mut ipc = tokio::spawn(std::future::pending::<()>());
        let mut lan = tokio::spawn(supervise("slow_lan", None, || async {
            tokio::time::sleep(Duration::from_secs(120)).await;
            std::future::pending::<Result<(), String>>().await
        }));
        let mut inet = tokio::spawn(std::future::pending::<Infallible>());
        let mut bridge = tokio::spawn(std::future::pending::<Infallible>());
        let mut prune = tokio::spawn(std::future::pending::<Infallible>());
        let end = wait_service_end(
            &mut ipc,
            &mut lan,
            &mut inet,
            &mut bridge,
            &mut prune,
            Some(Duration::from_secs(300)),
        )
        .await;
        assert_eq!(end, ServiceEnd::TimedOut);
        assert_eq!(end.exit_code(), 0);
        ipc.abort();
        lan.abort();
        inet.abort();
        bridge.abort();
        prune.abort();
    }

    /// IPC is the one task whose end stops the service, with a non-zero
    /// status so launchd / systemd restart it.
    #[cfg(any(unix, windows))]
    #[tokio::test(start_paused = true)]
    async fn ipc_ending_stops_the_service_with_a_failure_status() {
        let mut ipc = tokio::spawn(async {});
        let mut lan = tokio::spawn(std::future::pending::<Infallible>());
        let mut inet = tokio::spawn(std::future::pending::<Infallible>());
        let mut bridge = tokio::spawn(std::future::pending::<Infallible>());
        let mut prune = tokio::spawn(std::future::pending::<Infallible>());
        let end =
            wait_service_end(&mut ipc, &mut lan, &mut inet, &mut bridge, &mut prune, None).await;
        assert_eq!(end, ServiceEnd::IpcStopped);
        assert_eq!(end.exit_code(), 1);
        assert_eq!(ServiceEnd::SupervisorDied("bridge").exit_code(), 1);
        lan.abort();
        inet.abort();
        bridge.abort();
        prune.abort();
    }
}
