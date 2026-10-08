//! The p2p carrier (transports design 2026-10 §3, phase P3): libp2p as a
//! connectivity substrate for the Raven link.
//!
//! - **Host:** a supervised task in `service` (opt-in like Internet direct:
//!   `--p2p-listen` / `RAVEN_P2P_LISTEN` / `raven node p2p on`). TCP + QUIC,
//!   IPv4 + IPv6 on 7423 by default, or no listener at all (`relay`: reached
//!   only through relays). Every listen address is probe-bound first, so a
//!   port another program holds is reported (and retried) instead of shared
//!   (libp2p-tcp sets SO_REUSEADDR / SO_REUSEPORT). The local preflight runs
//!   once; only the listen step is retried. It keeps reservations on at most
//!   two relays (`--p2p-relay` / `RAVEN_P2P_RELAYS` / node policy; none is
//!   compiled in), which libp2p renews before they expire; a lost or refused
//!   one is re-requested with backoff, a relay named by DNS is re-resolved
//!   before every attempt and its addresses are tried in turn. The service
//!   asks it to shut down cleanly (connections closed) before it exits, so a
//!   restart is not refused by a relay still holding the old reservation.
//! - **Link:** every `/raven/link/1.0.0` stream runs the *same* Raven Noise link
//!   as Internet direct (`internet_direct::P2P_LINK`: prologue
//!   `raven/p2p-link/v1`, the RIH1 identity bind, the contact gate, RLB1, then
//!   `dispatch_frame`). The responder answers verified (pinned) contacts only
//!   and treats everyone else like a stranger, with the same timing. A relay
//!   and any other libp2p peer see only libp2p-Noise(Raven-Noise(...)); the
//!   PeerId is never trusted, the pinned Raven key inside the link is.
//! - **Dial:** direct addresses first, then circuits through the contact's
//!   relays (at most two connection attempts at once: the design's hedge);
//!   libp2p's DCUtR upgrades a circuit to a direct connection where the NATs
//!   allow it. A Raven link never moves: once the upgrade is in, the relayed
//!   connection is closed as soon as no link uses it, so the next attempt opens
//!   a *new* Raven link on the direct connection. Each dial logs (counts only)
//!   when the kind of connection its link uses changes: `link via a direct
//!   connection` / `link via the relay`.
//! - **Relay role** (`service --relay`): the same host relays for the PeerIds
//!   in this profile's `relay_allow.json` (the relay PeerId is then the user's
//!   own PeerId, which everyone who uses the relay learns).
//!
//! Held by `raven_core::p2p_live_enabled` (P2P_PRODUCTION_ENABLED=false or the
//! debug lab unlock): with it closed nothing is built, so nothing listens,
//! dials, reserves or advertises. Logs carry categories and counts only (NAT
//! spec §5): no PeerId, address or key; this node's own PeerId and listen
//! addresses are shown by IPC `Status` (`raven status`).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures::StreamExt;
use raven_core::identity::Identity;
use raven_core::ipc::{P2pStatusInfo, RelayCounts};
use raven_core::outbox::{carrier_allowed_for_contact, OutboxCarrier};
use raven_core::p2p_route::{self, P2pDialTarget, P2pListen, ViaAddr};
use raven_swarm::host::{
    build_endpoint_swarm, listen_port_label, probe_listen_addr, EndpointBehaviour,
    EndpointBehaviourEvent, EndpointConfig, HostGate, ListenProbe, RelayAdvertiser, RelayGuard,
    RelayLimits, RAVEN_LINK_PROTOCOL,
};
use raven_swarm::libp2p::core::transport::ListenerId;
use raven_swarm::libp2p::multiaddr::Protocol;
use raven_swarm::libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use raven_swarm::libp2p::swarm::{ConnectionId, DialError, SwarmEvent};
use raven_swarm::libp2p::{autonat, dcutr, relay, upnp, Multiaddr, PeerId, Swarm};
use raven_swarm::libp2p_stream::{Control, IncomingStreams, OpenStreamError};
use raven_swarm::liveness::{close_if_dead, reconnect_delay, retry_jitter};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use crate::internet_direct::{self, blocking, P2P_LINK};
use crate::netutil::{self, Admission, DialProgress, PRODUCTION_REPLY_WAITS};

/// The whole dial, below the 45 s IPC cap (as Internet direct).
const DIAL_DEADLINE: Duration = Duration::from_secs(40);
/// Connecting to the contact (direct, then circuits), within the dial.
const CONNECT_DEADLINE: Duration = Duration::from_secs(20);
/// How often the host re-reads the relay allow-list and re-publishes status.
const TICK: Duration = Duration::from_secs(1);
const ALLOW_RELOAD: Duration = Duration::from_secs(5);
/// A busy listen port is tried again after this, doubling up to the cap.
const LISTEN_RETRY_MIN: Duration = Duration::from_secs(2);
const LISTEN_RETRY_MAX: Duration = Duration::from_secs(60);
/// How long a clean shutdown waits for the connections to close.
pub(crate) const SHUTDOWN_DRAIN: Duration = Duration::from_millis(1500);
/// How long a dial waits for the relayed connections it closes (to put its
/// link on the direct connection) to be gone.
const PREFER_DIRECT_WAIT: Duration = Duration::from_secs(2);
/// AutoNAT results remembered (one per tested address).
const MAX_NAT_RESULTS: usize = 16;
/// Peer-caused events are logged at most once per window.
static P2P_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(30));
static CAP_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(10));

/// Refusal while no host runs (p2p off, held, or still starting).
pub(crate) const P2P_NOT_RUNNING: &str = "P2P_NOT_RUNNING: the libp2p host of this raven-node is \
    not running (turn it on with `raven node p2p on` and restart raven-node)";
/// No p2p address of the contact answered.
pub(crate) const P2P_UNREACHABLE: &str =
    "P2P_UNREACHABLE: the contact is unreachable on every p2p address it has (direct and relay)";

/// What the service runs (`main::service_p2p_config`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct P2pConfig {
    pub listen: P2pListen,
    /// Relays to keep a reservation on (at most [`p2p_route::MAX_VIA`]).
    pub relays: Vec<ViaAddr>,
    /// `--relay`: also relay for others (`Some(open)`).
    pub relay_server: Option<bool>,
    /// node_policy.json `upnp` (unset behaves as off).
    pub upnp: Option<bool>,
}

/// What the service decided about p2p at start-up, reported by IPC
/// `Status` whether or not a host runs (`raven status`, `raven whoami
/// --card`): the effective setting and where it came from.
pub(crate) enum ServiceP2p<'a> {
    Off {
        source: &'a str,
    },
    Held {
        config: &'a P2pConfig,
        source: &'a str,
    },
    Configured {
        config: &'a P2pConfig,
        source: &'a str,
    },
    Error,
}

/// Publish the start-up decision (before any host runs).
pub(crate) fn publish_service_config(decision: ServiceP2p<'_>) {
    let base = |config: Option<&P2pConfig>, source: &str| P2pStatusInfo {
        listen_setting: config.map(|c| c.listen.policy_text()).unwrap_or_default(),
        source: source.to_string(),
        relays: config
            .map(|c| c.relays.iter().map(|v| v.text.clone()).collect())
            .unwrap_or_default(),
        relays_configured: config.map_or(0, |c| c.relays.len() as u32),
        relay_role: config.is_some_and(|c| c.relay_server.is_some()),
        upnp: config.map_or_else(|| "off".into(), |c| upnp_initial(c.upnp)),
        nat: "unknown".into(),
        ..P2pStatusInfo::default()
    };
    let info = match decision {
        ServiceP2p::Off { source } => base(None, source),
        ServiceP2p::Held { config, source } => P2pStatusInfo {
            held: true,
            ..base(Some(config), source)
        },
        ServiceP2p::Configured { config, source } => base(Some(config), source),
        ServiceP2p::Error => P2pStatusInfo {
            config_error: "the p2p settings could not be used (see raven-node-service.log)".into(),
            ..base(None, "")
        },
    };
    *lock(&CONFIG) = Some(info);
}

// ── The running host, for dials and IPC Status ──────────────────────────────

enum Command {
    Connect {
        peer: PeerId,
        addrs: Vec<Multiaddr>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Before a link: if a direct connection exists, close the relayed ones
    /// (when no link uses them) so the link rides the direct one. Answers
    /// whether the link will use a direct connection.
    PreferDirect {
        peer: PeerId,
        reply: oneshot::Sender<bool>,
    },
    /// A relay name was resolved (index of the relay slot).
    Resolved { slot: usize, addrs: Vec<Multiaddr> },
    /// Close every connection, wait at most [`SHUTDOWN_DRAIN`], then stop.
    Shutdown { done: oneshot::Sender<()> },
}

/// Handle of the running host.
struct HostHandle {
    commands: mpsc::Sender<Command>,
    control: Control,
    /// Raven links in flight per peer (both directions).
    links: Mutex<HashMap<PeerId, usize>>,
}

static HOST: Mutex<Option<Arc<HostHandle>>> = Mutex::new(None);
/// The running host's status (overrides [`CONFIG`] while it runs).
static STATUS: Mutex<Option<P2pStatusInfo>> = Mutex::new(None);
/// The service's start-up decision ([`publish_service_config`]).
static CONFIG: Mutex<Option<P2pStatusInfo>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn current_host() -> Option<Arc<HostHandle>> {
    lock(&HOST).clone()
}

/// What IPC `Status` reports: the running host's state, else the service's
/// start-up decision (with `up: false`), else `None` (no service decision:
/// not `raven-node service`).
pub(crate) fn status_snapshot() -> Option<P2pStatusInfo> {
    lock(&STATUS).clone().or_else(|| lock(&CONFIG).clone())
}

/// Ask a running host to shut down cleanly (close its connections, so a
/// relay frees the reservation at once) and wait at most `wait`.
pub(crate) async fn shutdown(wait: Duration) {
    let Some(host) = current_host() else {
        return;
    };
    let (done, finished) = oneshot::channel();
    if host.commands.send(Command::Shutdown { done }).await.is_ok() {
        let _ = tokio::time::timeout(wait, finished).await;
    }
}

/// Clears the published handle and status when the host task ends.
struct RunningGuard;

impl Drop for RunningGuard {
    fn drop(&mut self) {
        *lock(&HOST) = None;
        // Back to the service's start-up decision (`up: false`).
        *lock(&STATUS) = None;
    }
}

/// One Raven link in flight to or from `peer` (the upgrade waits for it).
struct LinkGuard {
    host: Arc<HostHandle>,
    peer: PeerId,
}

impl HostHandle {
    fn link(self: &Arc<Self>, peer: PeerId) -> LinkGuard {
        *lock(&self.links).entry(peer).or_insert(0) += 1;
        LinkGuard {
            host: Arc::clone(self),
            peer,
        }
    }

    fn links_to(&self, peer: &PeerId) -> usize {
        lock(&self.links).get(peer).copied().unwrap_or(0)
    }

    async fn prefer_direct(&self, peer: PeerId) -> bool {
        let (reply, answer) = oneshot::channel();
        if self
            .commands
            .send(Command::PreferDirect { peer, reply })
            .await
            .is_err()
        {
            return false;
        }
        tokio::time::timeout(PREFER_DIRECT_WAIT + Duration::from_secs(1), answer)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false)
    }

    async fn connect(&self, peer: PeerId, addrs: Vec<Multiaddr>) -> Result<(), String> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Connect { peer, addrs, reply })
            .await
            .map_err(|_| P2P_NOT_RUNNING.to_string())?;
        match tokio::time::timeout(CONNECT_DEADLINE, answer).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(P2P_NOT_RUNNING.to_string()),
            Err(_) => Err(format!(
                "{P2P_UNREACHABLE} (connect timed out after {}s)",
                CONNECT_DEADLINE.as_secs()
            )),
        }
    }
}

impl Drop for LinkGuard {
    fn drop(&mut self) {
        let mut links = lock(&self.host.links);
        if let Some(n) = links.get_mut(&self.peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                links.remove(&self.peer);
            }
        }
    }
}

// ── Dial ─────────────────────────────────────────────────────────────────────

fn open_stream_error(e: OpenStreamError) -> String {
    match e {
        OpenStreamError::UnsupportedProtocol(_) => {
            "p2p stream: the peer does not speak the Raven link (not a RAVEN node, or p2p is off \
             there)"
                .into()
        }
        OpenStreamError::Io(e) => netutil::io_error_text(&e),
        other => format!("p2p stream: {other}"),
    }
}

/// How long one `/dns*/` name may take to resolve.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Addresses one name resolves to that are dialled at most.
const MAX_RESOLVED: usize = 4;

/// The host has no libp2p DNS transport (it would make hickory buildable, see
/// raven-swarm's Cargo.toml): a `/dns|dns4|dns6/<name>/…` address is resolved
/// here with the system resolver into `/ip4|ip6/…` ones (the family the
/// protocol asks for). Anything else is returned unchanged; a name that does
/// not resolve gives nothing (it is then simply not dialled).
async fn resolve_addr(addr: Multiaddr) -> Vec<Multiaddr> {
    let mut parts = addr.iter();
    let (name, family) = match parts.next() {
        Some(Protocol::Dns(n)) => (n.to_string(), None),
        Some(Protocol::Dns4(n)) => (n.to_string(), Some(4)),
        Some(Protocol::Dns6(n)) => (n.to_string(), Some(6)),
        _ => return vec![addr],
    };
    let rest: Vec<Protocol<'static>> = parts.map(Protocol::acquire).collect();
    let port = rest
        .iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) | Protocol::Udp(port) => Some(*port),
            _ => None,
        })
        .unwrap_or(0);
    let Ok(Ok(found)) = tokio::time::timeout(
        RESOLVE_TIMEOUT,
        tokio::net::lookup_host((name.as_str(), port)),
    )
    .await
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for sock in found {
        let host = match (sock.ip(), family) {
            (IpAddr::V4(v4), None | Some(4)) => Protocol::Ip4(v4),
            (IpAddr::V6(v6), None | Some(6)) => Protocol::Ip6(v6),
            _ => continue,
        };
        let mut resolved = Multiaddr::empty().with(host);
        for p in &rest {
            resolved.push(p.clone());
        }
        if !out.contains(&resolved) {
            out.push(resolved);
        }
        if out.len() >= MAX_RESOLVED {
            break;
        }
    }
    out
}

async fn resolve_all(addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    for a in addrs {
        for r in resolve_addr(a).await {
            if !out.contains(&r) {
                out.push(r);
            }
        }
    }
    out
}

/// The libp2p addresses to try for `target`, in plan order (direct, then
/// circuits). `/p2p/<PeerId>` takes the contact book's addresses for that
/// PeerId (none is fine: a connection may already exist, or libp2p may know
/// the contact's addresses from an earlier connection).
fn dial_addrs(
    target: &P2pDialTarget,
    contact: Option<&p2p_route::ContactP2p>,
) -> Result<Vec<Multiaddr>, String> {
    let text: Vec<String> = match target {
        P2pDialTarget::Peer { peer_id } => contact
            .filter(|c| c.peer_id == *peer_id)
            .map(|c| c.dial_addrs())
            .unwrap_or_default(),
        P2pDialTarget::Direct { addr, .. } => vec![addr.text.clone()],
        P2pDialTarget::Circuit { peer_id, relay } => vec![p2p_route::circuit_addr(relay, peer_id)],
    };
    text.iter()
        .map(|t| {
            t.parse::<Multiaddr>()
                .map_err(|e| format!("p2p address: {e}"))
        })
        .collect()
}

/// Dial `multiaddr` (a p2p dial string ending in the target's PeerId, see
/// `raven_core::p2p_route::parse_p2p_dial`), run the Raven link expecting
/// `expected_pub_hex`, send `frames`, collect the replies. Verified contacts
/// only; nothing is dialled otherwise.
pub(crate) async fn dial(
    data_dir: &Path,
    multiaddr: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    P2P_LINK.require_live()?;
    let expected = internet_direct::parse_pub_hex(expected_pub_hex)?;
    let target = p2p_route::parse_p2p_dial(multiaddr).map_err(|e| format!("p2p dial: {e}"))?;
    let dd = data_dir.to_path_buf();
    let contact = blocking(move || raven_core::outbox::contact_routes(&dd, &expected)).await?;
    let pinned = contact.as_ref().is_some_and(|c| c.pinned);
    if !carrier_allowed_for_contact(OutboxCarrier::P2p, pinned) {
        return Err(format!(
            "{}: p2p delivery needs a verified contact (fingerprint pinned); nothing was dialled",
            raven_core::CONTACT_NOT_VERIFIED
        ));
    }
    let addrs = resolve_all(dial_addrs(
        &target,
        contact.as_ref().and_then(|c| c.p2p.as_ref()),
    )?)
    .await;
    let peer: PeerId = target
        .peer_id()
        .parse()
        .map_err(|_| "p2p dial: invalid PeerId".to_string())?;
    let host = current_host().ok_or_else(|| P2P_NOT_RUNNING.to_string())?;
    let mut progress = DialProgress::new(P2P_LINK.wire, PRODUCTION_REPLY_WAITS);
    let outcome = tokio::time::timeout(DIAL_DEADLINE, async {
        progress.stage = "connecting (direct, then through a relay)";
        host.connect(peer, addrs).await?;
        let direct = host.prefer_direct(peer).await;
        note_link_kind(peer, direct);
        let _link = host.link(peer);
        let control = host.control.clone();
        internet_direct::dial_session_on(
            P2P_LINK,
            data_dir,
            move || {
                let mut control = control.clone();
                async move {
                    control
                        .open_stream(peer, RAVEN_LINK_PROTOCOL)
                        .await
                        .map(|s| s.compat())
                        .map_err(open_stream_error)
                }
            },
            &expected,
            frames,
            &mut progress,
        )
        .await
    })
    .await;
    match outcome {
        Ok(Ok(())) => Ok(progress.collector.into_replies()),
        Ok(Err(e)) => Err(e),
        Err(_) => progress.on_deadline("p2p", "the contact", DIAL_DEADLINE),
    }
}

/// The kind of connection the last link to each peer used: a line is logged
/// (counts only) whenever it changes, e.g. after a DCUtR upgrade.
static LINK_KINDS: Mutex<Option<HashMap<PeerId, bool>>> = Mutex::new(None);
const MAX_LINK_KINDS: usize = 256;

fn note_link_kind(peer: PeerId, direct: bool) {
    let mut kinds = lock(&LINK_KINDS);
    let map = kinds.get_or_insert_with(HashMap::new);
    if map.len() >= MAX_LINK_KINDS && !map.contains_key(&peer) {
        map.clear();
    }
    if map.insert(peer, direct) != Some(direct) {
        eprintln!(
            "raven-node p2p: link via {}",
            if direct {
                "a direct connection"
            } else {
                "the relay"
            }
        );
    }
}

// ── Responder ───────────────────────────────────────────────────────────────

/// Admission key of a libp2p peer: a stable per-PeerId address in fd00::/8
/// (one /64 per PeerId), so the shared caps apply per peer. PeerIds are free,
/// so the global cap and pre-auth displacement still bound a flood; contacts
/// leave the pre-auth caps once their link authenticates.
fn admission_ip(peer: &PeerId) -> IpAddr {
    let bytes = peer.to_bytes();
    let mut o = [0u8; 16];
    o[0] = 0xfd;
    let tail = &bytes[bytes.len().saturating_sub(7)..];
    o[1..1 + tail.len()].copy_from_slice(tail);
    IpAddr::V6(Ipv6Addr::from(o))
}

/// Serve every inbound `/raven/link/1.0.0` stream: the Internet direct
/// responder (contact gate first) under the shared inbound limits.
async fn serve_streams(
    mut incoming: IncomingStreams,
    data_dir: PathBuf,
    identity: Arc<Identity>,
    host: Arc<HostHandle>,
) {
    let limits = netutil::PRODUCTION_INBOUND;
    let admission = Admission::new(limits);
    while let Some((peer, stream)) = incoming.next().await {
        let Some(mut slot) = admission.try_admit(admission_ip(&peer)) else {
            netutil::log_limited(
                &CAP_LOG,
                "p2p",
                format_args!("link cap reached; refused a link"),
            );
            continue;
        };
        let displaced = slot.displaced();
        let (dd, id, host) = (data_dir.clone(), Arc::clone(&identity), Arc::clone(&host));
        tokio::spawn(async move {
            let _link = host.link(peer);
            let work = async {
                P2P_LINK.require_live()?;
                internet_direct::serve_inbound_on(
                    P2P_LINK,
                    dd,
                    id,
                    stream.compat(),
                    limits,
                    &mut slot,
                )
                .await
            };
            tokio::select! {
                done = tokio::time::timeout(limits.lifetime, work) => match done {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => netutil::log_inbound_failure("p2p inbound", e),
                    Err(_) => netutil::log_inbound_failure(
                        "p2p inbound",
                        "connection lifetime exceeded",
                    ),
                },
                () = displaced.notified() => netutil::log_inbound_failure(
                    "p2p inbound",
                    "unauthenticated link displaced by a newcomer",
                ),
            }
        });
    }
}

// ── The host task ────────────────────────────────────────────────────────────

/// One configured relay: its (possibly `/dns*`) address, the addresses it
/// resolved to last, the one tried next, and the reservation's state.
struct RelaySlot {
    text: String,
    named: Multiaddr,
    peer: PeerId,
    resolved: Vec<Multiaddr>,
    next: usize,
    listener: Option<ListenerId>,
    active: bool,
    resolving: bool,
    attempt: u32,
    retry_at: Option<Instant>,
}

fn is_dns(addr: &Multiaddr) -> bool {
    matches!(
        addr.iter().next(),
        Some(Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_))
    )
}

impl RelaySlot {
    fn arm_retry(&mut self, now: Instant) {
        let delay = reconnect_delay(self.attempt, retry_jitter());
        self.attempt = self.attempt.saturating_add(1);
        self.retry_at = Some(now + delay);
    }

    /// The next resolved address, in turn.
    fn rotate(&mut self) {
        if !self.resolved.is_empty() {
            self.next = (self.next + 1) % self.resolved.len();
        }
    }
}

/// A listen address and, while it cannot be opened (a busy port), when it
/// is tried again.
struct ListenSlot {
    addr: Multiaddr,
    open: bool,
    failures: u32,
    retry_at: Option<Instant>,
}

struct RelayRole {
    guard: RelayGuard,
    open: bool,
    data_dir: PathBuf,
    circuits: u32,
    circuits_refused: u64,
    reservations_refused: u64,
    last_reload: Instant,
    advertiser: RelayAdvertiser,
}

struct Host {
    swarm: Swarm<EndpointBehaviour>,
    commands: mpsc::Sender<Command>,
    config: P2pConfig,
    source: String,
    slots: Vec<RelaySlot>,
    listens: Vec<ListenSlot>,
    role: Option<RelayRole>,
    pending: HashMap<PeerId, Vec<oneshot::Sender<Result<(), String>>>>,
    connections: HashMap<ConnectionId, (PeerId, bool)>,
    /// Peers DCUtR upgraded whose relayed connections still have to go.
    upgraded: HashSet<PeerId>,
    /// Dials waiting for relayed connections to close (`PreferDirect`).
    preferring: Vec<(PeerId, Instant, oneshot::Sender<bool>)>,
    listen_addrs: Vec<Multiaddr>,
    /// Latest AutoNAT v2 verdict per tested address.
    nat_results: HashMap<Multiaddr, bool>,
    upnp: String,
    peer_id: PeerId,
}

fn upnp_initial(policy: Option<bool>) -> String {
    match policy {
        None => "unset".into(),
        Some(false) => "off".into(),
        Some(true) => "on".into(),
    }
}

fn mapped_port(addr: &Multiaddr) -> Option<u16> {
    addr.iter().find_map(|p| match p {
        Protocol::Tcp(port) | Protocol::Udp(port) => Some(port),
        _ => None,
    })
}

/// The reachability row from the latest AutoNAT verdicts: `public` while any
/// tested address is reachable, `private` when every tested one failed,
/// `unknown` before any test. It follows new verdicts both ways.
fn nat_verdict(results: &HashMap<Multiaddr, bool>) -> &'static str {
    if results.values().any(|ok| *ok) {
        "public"
    } else if results.is_empty() {
        "unknown"
    } else {
        "private"
    }
}

/// Probe, then open, every listen address not open yet whose retry is due.
/// A busy port is retried with backoff (logged with its port only); an
/// address this host cannot have (no IPv6, say) is dropped after one line.
fn open_listeners(
    swarm: &mut Swarm<EndpointBehaviour>,
    listens: &mut Vec<ListenSlot>,
    now: Instant,
) {
    // Every probe before any bind: a dual-stack `[::]` probe would collide
    // with our own `0.0.0.0` listener otherwise.
    let due: Vec<usize> = (0..listens.len())
        .filter(|i| !listens[*i].open && listens[*i].retry_at.is_none_or(|t| t <= now))
        .collect();
    let probes: Vec<(usize, Result<(), ListenProbe>)> = due
        .iter()
        .map(|i| (*i, probe_listen_addr(&listens[*i].addr)))
        .collect();
    let mut dropped = Vec::new();
    for (i, probe) in probes {
        let slot = &mut listens[i];
        let label = listen_port_label(&slot.addr);
        let outcome = match probe {
            Ok(()) => swarm
                .listen_on(slot.addr.clone())
                .map(|_| ())
                .map_err(|_| ListenProbe::Busy),
            Err(e) => Err(e),
        };
        match outcome {
            Ok(()) => {
                slot.open = true;
                slot.retry_at = None;
                if slot.failures > 0 {
                    eprintln!("raven-node p2p: listen port {label} is open now");
                }
            }
            Err(ListenProbe::Busy) => {
                if slot.failures == 0 {
                    eprintln!(
                        "p2p failed: listen port {label} is already in use by another program \
                         (another raven-node?); it is not opened and is retried"
                    );
                }
                let delay = LISTEN_RETRY_MIN
                    .saturating_mul(1u32 << slot.failures.min(5))
                    .min(LISTEN_RETRY_MAX);
                slot.failures = slot.failures.saturating_add(1);
                slot.retry_at = Some(now + delay);
            }
            Err(ListenProbe::Unavailable) => {
                eprintln!(
                    "p2p failed: listen port {label} cannot be opened on this host (no such \
                     address family or interface); skipped"
                );
                dropped.push(i);
            }
        }
    }
    for i in dropped.into_iter().rev() {
        listens.remove(i);
    }
}

impl Host {
    fn publish(&self) {
        let relay = self.role.as_ref().map(|r| {
            let c = r.guard.counts();
            RelayCounts {
                open: r.open,
                allowed_peers: c.allowed_peers,
                allow_list_unreadable: c.unreadable,
                reservations: c.active_reservations,
                circuits: r.circuits,
                reservations_refused: r.reservations_refused,
                circuits_refused: r.circuits_refused,
            }
        });
        let info = P2pStatusInfo {
            up: true,
            peer_id: self.peer_id.to_string(),
            listen_addrs: self.listen_addrs.iter().map(|a| a.to_string()).collect(),
            nat: nat_verdict(&self.nat_results).to_string(),
            reservations: self
                .slots
                .iter()
                .filter(|s| s.active)
                .map(|s| s.text.clone())
                .collect(),
            relays_configured: self.config.relays.len() as u32,
            upnp: self.upnp.clone(),
            relay,
            listen_setting: self.config.listen.policy_text(),
            source: self.source.clone(),
            relays: self.config.relays.iter().map(|v| v.text.clone()).collect(),
            relay_role: self.config.relay_server.is_some(),
            held: false,
            config_error: String::new(),
            listen_retrying: self.listens.iter().filter(|l| !l.open).count() as u32,
        };
        *lock(&STATUS) = Some(info);
    }

    fn connect(
        &mut self,
        peer: PeerId,
        addrs: Vec<Multiaddr>,
        reply: oneshot::Sender<Result<(), String>>,
    ) {
        if self.swarm.is_connected(&peer) {
            let _ = reply.send(Ok(()));
            return;
        }
        let opts = DialOpts::peer_id(peer)
            .addresses(addrs)
            .extend_addresses_through_behaviour()
            .condition(PeerCondition::DisconnectedAndNotDialing)
            .build();
        match self.swarm.dial(opts) {
            Ok(()) | Err(DialError::DialPeerConditionFalse(_)) => {
                self.pending.entry(peer).or_default().push(reply);
            }
            Err(DialError::NoAddresses) => {
                let _ = reply.send(Err(format!("{P2P_UNREACHABLE} (no address known)")));
            }
            Err(_) => {
                let _ = reply.send(Err(P2P_UNREACHABLE.to_string()));
            }
        }
    }

    fn connections_to(&self, peer: &PeerId) -> (Vec<ConnectionId>, Vec<ConnectionId>) {
        let (mut direct, mut relayed) = (Vec::new(), Vec::new());
        for (id, (p, is_relayed)) in &self.connections {
            if p == peer {
                if *is_relayed {
                    relayed.push(*id);
                } else {
                    direct.push(*id);
                }
            }
        }
        (direct, relayed)
    }

    fn prefer_direct(&mut self, peer: PeerId, reply: oneshot::Sender<bool>) {
        let (direct, relayed) = self.connections_to(&peer);
        if direct.is_empty() {
            let _ = reply.send(false);
            return;
        }
        let idle = current_host().is_none_or(|h| h.links_to(&peer) == 0);
        if relayed.is_empty() || !idle {
            // Nothing to close, or a link still rides the relay: the new one
            // may land on either connection.
            let _ = reply.send(relayed.is_empty());
            return;
        }
        for id in relayed {
            self.swarm.close_connection(id);
        }
        self.preferring.push((peer, Instant::now(), reply));
    }

    fn answer_preferring(&mut self, now: Instant) {
        let waiting = std::mem::take(&mut self.preferring);
        for (peer, since, reply) in waiting {
            let (direct, relayed) = self.connections_to(&peer);
            if relayed.is_empty() || now.saturating_duration_since(since) >= PREFER_DIRECT_WAIT {
                let _ = reply.send(!direct.is_empty() && relayed.is_empty());
            } else {
                self.preferring.push((peer, since, reply));
            }
        }
    }

    fn answer_pending(&mut self, peer: &PeerId, result: Result<(), String>) {
        for reply in self.pending.remove(peer).unwrap_or_default() {
            let _ = reply.send(result.clone());
        }
    }

    /// Resolve (when named by DNS) and then request the reservation of
    /// `slot`. Resolution runs off the swarm loop; its answer comes back as
    /// `Command::Resolved`.
    fn start_reservation(&mut self, index: usize) {
        let slot = &mut self.slots[index];
        slot.retry_at = None;
        if !is_dns(&slot.named) {
            slot.resolved = vec![slot.named.clone()];
            self.request_reservation(index);
            return;
        }
        if slot.resolving {
            return;
        }
        slot.resolving = true;
        let named = slot.named.clone();
        let commands = self.commands.clone();
        tokio::spawn(async move {
            let addrs = resolve_addr(named).await;
            let _ = commands
                .send(Command::Resolved { slot: index, addrs })
                .await;
        });
    }

    fn on_resolved(&mut self, index: usize, addrs: Vec<Multiaddr>) {
        let Some(slot) = self.slots.get_mut(index) else {
            return;
        };
        slot.resolving = false;
        if addrs.is_empty() {
            netutil::log_limited(
                &P2P_LOG,
                "p2p failed",
                "a configured relay name does not resolve (yet); retrying",
            );
            slot.arm_retry(Instant::now());
            return;
        }
        if addrs != slot.resolved {
            slot.next = 0;
            slot.resolved = addrs;
        }
        self.request_reservation(index);
    }

    fn request_reservation(&mut self, index: usize) {
        let slot = &mut self.slots[index];
        if slot.resolved.is_empty() {
            slot.arm_retry(Instant::now());
            return;
        }
        slot.next %= slot.resolved.len();
        let addr = slot.resolved[slot.next].clone().with(Protocol::P2pCircuit);
        match self.swarm.listen_on(addr) {
            Ok(id) => slot.listener = Some(id),
            Err(_) => {
                slot.listener = None;
                slot.rotate();
                slot.arm_retry(Instant::now());
            }
        }
    }

    fn on_event(&mut self, event: SwarmEvent<EndpointBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                if let Some(role) = self.role.as_mut() {
                    // A relay must name at least one address in its
                    // reservations: never a LAN / loopback one it was not
                    // told to (`RelayAdvertiser`).
                    role.advertiser
                        .on_new_listen_addr(&mut self.swarm, &address);
                }
                if !self.listen_addrs.contains(&address) {
                    self.listen_addrs.push(address);
                }
            }
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                if let Some(role) = self.role.as_mut() {
                    role.advertiser
                        .on_expired_listen_addr(&mut self.swarm, &address);
                }
                self.listen_addrs.retain(|a| *a != address);
            }
            SwarmEvent::ExternalAddrExpired { address } => {
                self.nat_results.remove(&address);
            }
            SwarmEvent::ListenerClosed { listener_id, .. } => {
                let now = Instant::now();
                let mut lost = false;
                for slot in &mut self.slots {
                    if slot.listener == Some(listener_id) {
                        slot.listener = None;
                        lost |= std::mem::take(&mut slot.active);
                        // Lost or refused: the next address, after a pause.
                        slot.rotate();
                        slot.arm_retry(now);
                    }
                }
                if lost {
                    eprintln!(
                        "raven-node p2p: reservation lost (active={})",
                        self.slots.iter().filter(|s| s.active).count()
                    );
                }
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                self.connections
                    .insert(connection_id, (peer_id, endpoint.is_relayed()));
                self.answer_pending(&peer_id, Ok(()));
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                num_established,
                ..
            } => {
                self.connections.remove(&connection_id);
                if num_established == 0 {
                    if let Some(role) = self.role.as_ref() {
                        role.guard.on_peer_disconnected(&peer_id);
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer),
                ..
            } => {
                if !self.swarm.is_connected(&peer) {
                    self.answer_pending(&peer, Err(P2P_UNREACHABLE.to_string()));
                }
            }
            SwarmEvent::Behaviour(event) => self.on_behaviour(event),
            _ => {}
        }
    }

    fn on_behaviour(&mut self, event: EndpointBehaviourEvent) {
        match event {
            EndpointBehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                renewal,
                ..
            }) => {
                let mut fresh = !renewal;
                for slot in &mut self.slots {
                    if slot.peer == relay_peer_id && slot.listener.is_some() {
                        fresh |= !slot.active;
                        slot.active = true;
                        slot.attempt = 0;
                    }
                }
                if fresh {
                    eprintln!(
                        "raven-node p2p: reservation accepted (active={})",
                        self.slots.iter().filter(|s| s.active).count()
                    );
                }
            }
            EndpointBehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result,
            }) => match result {
                Ok(_) => {
                    eprintln!("raven-node p2p: direct connection upgraded (dcutr)");
                    self.upgraded.insert(remote_peer_id);
                }
                Err(_) => netutil::log_limited(
                    &P2P_LOG,
                    "raven-node p2p",
                    "hole punch failed; staying on the relay",
                ),
            },
            EndpointBehaviourEvent::Autonat(autonat::v2::client::Event {
                tested_addr,
                result,
                ..
            }) => {
                if self.nat_results.len() >= MAX_NAT_RESULTS
                    && !self.nat_results.contains_key(&tested_addr)
                {
                    self.nat_results.clear();
                }
                self.nat_results.insert(tested_addr, result.is_ok());
            }
            EndpointBehaviourEvent::Upnp(event) => {
                let (state, line) = match &event {
                    upnp::Event::NewExternalAddr(addr) => match mapped_port(addr) {
                        Some(port) => (
                            format!("mapped {port}"),
                            format!("raven-node p2p: upnp mapped port {port}"),
                        ),
                        None => ("mapped".into(), "raven-node p2p: upnp mapped a port".into()),
                    },
                    upnp::Event::ExpiredExternalAddr(_) => (
                        "failed".into(),
                        "raven-node p2p: upnp mapping failed (renewal refused)".into(),
                    ),
                    upnp::Event::GatewayNotFound => (
                        "failed".into(),
                        "raven-node p2p: upnp mapping failed (no UPnP/NAT-PMP router found)".into(),
                    ),
                    upnp::Event::NonRoutableGateway => (
                        "failed".into(),
                        "raven-node p2p: upnp mapping failed (the router is behind another NAT)"
                            .into(),
                    ),
                };
                if state != self.upnp {
                    eprintln!("{line}");
                    self.upnp = state;
                }
            }
            EndpointBehaviourEvent::Ping(event) => {
                close_if_dead(&mut self.swarm, &event);
            }
            EndpointBehaviourEvent::RelayServer(event) => {
                if let Some(role) = self.role.as_mut() {
                    role.guard.on_relay_event(&event);
                    match event {
                        relay::Event::CircuitReqAccepted { .. } => role.circuits += 1,
                        relay::Event::CircuitClosed { .. } => {
                            role.circuits = role.circuits.saturating_sub(1)
                        }
                        relay::Event::CircuitReqDenied { .. } => role.circuits_refused += 1,
                        relay::Event::ReservationReqDenied { .. } => role.reservations_refused += 1,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn tick(&mut self) {
        let now = Instant::now();
        open_listeners(&mut self.swarm, &mut self.listens, now);
        for i in 0..self.slots.len() {
            if self.slots[i].retry_at.is_some_and(|t| t <= now) {
                // A DNS name is resolved again before every attempt.
                self.start_reservation(i);
            }
        }
        // After an upgrade: close the relayed connections once no Raven link
        // rides them, so the next link opens on the direct connection.
        let host = current_host();
        let idle: Vec<PeerId> = self
            .upgraded
            .iter()
            .filter(|p| host.as_ref().is_none_or(|h| h.links_to(p) == 0))
            .copied()
            .collect();
        for peer in idle {
            self.upgraded.remove(&peer);
            let (direct, relayed) = self.connections_to(&peer);
            if direct.is_empty() {
                continue;
            }
            for id in relayed {
                self.swarm.close_connection(id);
            }
        }
        self.answer_preferring(now);
        if let Some(role) = self.role.as_mut() {
            role.guard.prune();
            if role.last_reload.elapsed() >= ALLOW_RELOAD {
                role.last_reload = now;
                let policy = crate::relay::allow_policy(&role.data_dir, role.open);
                for peer in role.guard.set_policy(policy) {
                    let _ = self.swarm.disconnect_peer_id(peer);
                }
            }
        }
        self.publish();
    }

    /// Close every connection (QUIC sends its close frame, the relay frees
    /// our reservation at once) and drive the swarm until they are gone or
    /// [`SHUTDOWN_DRAIN`] passed.
    async fn drain(&mut self) {
        let peers: HashSet<PeerId> = self.connections.values().map(|(p, _)| *p).collect();
        for peer in peers {
            let _ = self.swarm.disconnect_peer_id(peer);
        }
        let deadline = Instant::now() + SHUTDOWN_DRAIN;
        while !self.connections.is_empty() {
            match tokio::time::timeout_at(deadline, self.swarm.select_next_some()).await {
                Ok(SwarmEvent::ConnectionClosed { connection_id, .. }) => {
                    self.connections.remove(&connection_id);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }
}

/// The local state the responder needs, loaded once per host start: the
/// identity (also the libp2p key's seed), a current prekey (its RLB1 offer)
/// and the session store opened (so the host is not reported up while every
/// inbound frame would fail). The durable-state upkeep is the LAN listener's
/// (it always runs in the service), so the two never contend at start-up.
fn preflight(data_dir: &Path) -> Result<Identity, String> {
    P2P_LINK.require_live()?;
    let identity = raven_core::load_identity_required(data_dir).map_err(|e| e.to_string())?;
    raven_core::ensure_local_prekey(data_dir, &identity)?;
    let _ = raven_core::IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    Ok(identity)
}

/// The service's libp2p host (supervised in `main`). Never returns `Ok`;
/// after a clean shutdown it parks.
pub(crate) async fn run_host(
    data_dir: PathBuf,
    config: P2pConfig,
    source: String,
) -> Result<(), String> {
    let gate = HostGate::open(raven_core::p2p_live_enabled())
        .map_err(|_| raven_core::P2P_HOLD.to_string())?;
    let identity = Arc::new(
        netutil::retry_until_ok("p2p", || {
            let dd = data_dir.clone();
            async move {
                netutil::with_slow_notice(
                    "p2p",
                    "local state preflight (identity, prekey, session store)",
                    blocking(move || preflight(&dd)),
                )
                .await
            }
        })
        .await,
    );
    let keypair = raven_swarm::kad_node::libp2p_keypair_from_raven(&identity);
    let role = config.relay_server.map(|open| {
        let limits = if open {
            RelayLimits::open()
        } else {
            RelayLimits::friends()
        };
        let guard = RelayGuard::new(crate::relay::allow_policy(&data_dir, open), &limits);
        (limits, guard, open)
    });
    let endpoint = EndpointConfig {
        upnp: config.upnp == Some(true),
        relay_server: role.as_ref().map(|(l, g, _)| (*l, g.clone())),
        ..EndpointConfig::default()
    };
    let mut swarm =
        build_endpoint_swarm(&gate, keypair, endpoint).map_err(|e| format!("p2p host: {e}"))?;
    let peer_id = *swarm.local_peer_id();
    let mut listens = Vec::new();
    for text in config.listen.multiaddrs() {
        let addr: Multiaddr = text.parse().map_err(|e| format!("p2p listen: {e}"))?;
        listens.push(ListenSlot {
            addr,
            open: false,
            failures: 0,
            retry_at: None,
        });
    }
    let listen_is_specific = matches!(config.listen, P2pListen::One(a) if !a.ip().is_unspecified());
    let mut slots = Vec::new();
    for via in config.relays.iter().take(p2p_route::MAX_VIA) {
        let named: Multiaddr = via.text.parse().map_err(|e| format!("p2p relay: {e}"))?;
        let relay: PeerId = via
            .peer_id
            .parse()
            .map_err(|_| "p2p relay: invalid PeerId".to_string())?;
        if relay == peer_id {
            eprintln!("p2p failed: a configured relay is this node itself; skipped");
            continue;
        }
        slots.push(RelaySlot {
            text: via.text.clone(),
            named,
            peer: relay,
            resolved: Vec::new(),
            next: 0,
            listener: None,
            active: false,
            resolving: false,
            attempt: 0,
            retry_at: None,
        });
    }
    let mut control = swarm.behaviour().stream.new_control();
    let incoming = control
        .accept(RAVEN_LINK_PROTOCOL)
        .map_err(|_| "p2p: the Raven link protocol is already registered".to_string())?;
    let (commands, mut command_rx) = mpsc::channel(64);
    let handle = Arc::new(HostHandle {
        commands: commands.clone(),
        control,
        links: Mutex::new(HashMap::new()),
    });
    let role = role.map(|(_, guard, open)| RelayRole {
        guard,
        open,
        data_dir: data_dir.clone(),
        circuits: 0,
        circuits_refused: 0,
        reservations_refused: 0,
        last_reload: Instant::now(),
        advertiser: RelayAdvertiser::new(&mut swarm, listen_is_specific, &[]),
    });
    let mut host = Host {
        swarm,
        commands,
        config,
        source,
        slots,
        listens,
        role,
        pending: HashMap::new(),
        connections: HashMap::new(),
        upgraded: HashSet::new(),
        preferring: Vec::new(),
        listen_addrs: Vec::new(),
        nat_results: HashMap::new(),
        upnp: String::new(),
        peer_id,
    };
    host.upnp = upnp_initial(host.config.upnp);
    open_listeners(&mut host.swarm, &mut host.listens, Instant::now());
    for i in 0..host.slots.len() {
        host.start_reservation(i);
    }
    let _running = RunningGuard;
    *lock(&HOST) = Some(Arc::clone(&handle));
    host.publish();
    let responder = tokio::spawn(serve_streams(
        incoming,
        data_dir.clone(),
        Arc::clone(&identity),
        Arc::clone(&handle),
    ));
    eprintln!(
        "raven-node p2p: host up (listeners={}, relays={}{})",
        host.listens.iter().filter(|l| l.open).count(),
        host.slots.len(),
        match &host.role {
            Some(r) if r.open => ", relaying for anyone (open)",
            Some(_) => ", relaying for the allow-list",
            None => "",
        }
    );
    if host.role.as_ref().is_some_and(|r| r.open) {
        eprintln!(
            "raven-node p2p: OPEN relay: anyone may reserve and relay through this host, and \
             they all learn its PeerId (stricter limits apply)"
        );
    }
    crate::outbox::listener_up();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = loop {
        tokio::select! {
            event = host.swarm.select_next_some() => {
                // Status follows every event (a reservation, a listener), not
                // just the tick, so `raven status` is never a second behind.
                host.on_event(event);
                host.answer_preferring(Instant::now());
                host.publish();
            }
            command = command_rx.recv() => match command {
                Some(Command::Connect { peer, addrs, reply }) => host.connect(peer, addrs, reply),
                Some(Command::PreferDirect { peer, reply }) => host.prefer_direct(peer, reply),
                Some(Command::Resolved { slot, addrs }) => host.on_resolved(slot, addrs),
                Some(Command::Shutdown { done }) => {
                    responder.abort();
                    host.drain().await;
                    drop(host);
                    let _ = done.send(());
                    // The process is about to exit: never restart.
                    return std::future::pending().await;
                }
                None => break Err("p2p host: command channel closed".to_string()),
            },
            _ = tick.tick() => host.tick(),
        }
        if responder.is_finished() {
            break Err("p2p host: the link responder stopped".to_string());
        }
    };
    responder.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> String {
        p2p_route::local_peer_id(&Identity::from_seed(&[seed; 32]))
    }

    #[test]
    fn admission_key_is_stable_and_distinct_per_peer() {
        let a: PeerId = peer(1).parse().unwrap();
        let b: PeerId = peer(2).parse().unwrap();
        assert_eq!(admission_ip(&a), admission_ip(&a));
        assert_ne!(
            netutil::admission_key(admission_ip(&a)),
            netutil::admission_key(admission_ip(&b))
        );
        match admission_ip(&a) {
            IpAddr::V6(v6) => assert_eq!(v6.octets()[0], 0xfd),
            IpAddr::V4(_) => panic!("must be a ULA"),
        }
    }

    #[test]
    fn dial_addresses_follow_the_plan_order_and_the_contact_book() {
        let (bob, relay) = (peer(3), peer(4));
        let relay_via = format!("/ip4/198.51.100.1/tcp/7423/p2p/{relay}");
        let direct = format!("/ip4/203.0.113.9/tcp/7423/p2p/{bob}");
        let contact =
            p2p_route::ContactP2p::from_fields(&bob, &[relay_via.clone(), direct.clone()]).unwrap();
        let target = p2p_route::parse_p2p_dial(&p2p_route::peer_route(&bob)).unwrap();
        let got: Vec<String> = dial_addrs(&target, Some(&contact))
            .unwrap()
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(
            got,
            vec![direct.clone(), format!("{relay_via}/p2p-circuit/p2p/{bob}")]
        );
        // The book entry of another PeerId is never used.
        let other = p2p_route::parse_p2p_dial(&p2p_route::peer_route(&peer(5))).unwrap();
        assert!(dial_addrs(&other, Some(&contact)).unwrap().is_empty());
        // An explicit address is dialled as given, nothing else.
        let explicit = p2p_route::parse_p2p_dial(&direct).unwrap();
        assert_eq!(dial_addrs(&explicit, Some(&contact)).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn dial_is_held_or_refused_before_anything_is_dialled() {
        let dir = tempfile::tempdir().unwrap();
        let expected = hex::encode(Identity::from_seed(&[6; 32]).public_key_bytes());
        let target = p2p_route::peer_route(&peer(6));
        let err = dial(dir.path(), &target, &expected, &[]).await.unwrap_err();
        if !raven_core::p2p_live_enabled() {
            assert_eq!(err, raven_core::P2P_HOLD);
            return;
        }
        // Not a contact (or not verified): refused, nothing dialled.
        assert!(err.starts_with(raven_core::CONTACT_NOT_VERIFIED), "{err}");
        assert!(err.contains("nothing was dialled"), "{err}");
    }

    #[tokio::test]
    async fn dns_route_names_are_resolved_before_libp2p_sees_them() {
        let peer = peer(9);
        let ip: Multiaddr = format!("/ip4/203.0.113.7/tcp/7423/p2p/{peer}")
            .parse()
            .unwrap();
        assert_eq!(resolve_addr(ip.clone()).await, vec![ip]);
        let named: Multiaddr = format!("/dns4/localhost/tcp/7423/p2p/{peer}")
            .parse()
            .unwrap();
        let got = resolve_addr(named).await;
        assert!(!got.is_empty(), "localhost resolves");
        for a in &got {
            let text = a.to_string();
            assert!(text.starts_with("/ip4/127."), "{text}");
            assert!(text.ends_with(&format!("/tcp/7423/p2p/{peer}")), "{text}");
        }
        let v6: Multiaddr = format!("/dns6/localhost/udp/7423/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        for a in resolve_addr(v6).await {
            assert!(a.to_string().starts_with("/ip6/"), "{a}");
        }
        let nowhere: Multiaddr = format!("/dns4/no-such-host.invalid/tcp/7423/p2p/{peer}")
            .parse()
            .unwrap();
        assert!(resolve_addr(nowhere).await.is_empty());
    }

    #[test]
    fn upnp_state_starts_from_the_policy() {
        assert_eq!(upnp_initial(None), "unset");
        assert_eq!(upnp_initial(Some(false)), "off");
        assert_eq!(upnp_initial(Some(true)), "on");
        let addr: Multiaddr = "/ip4/203.0.113.7/tcp/7423".parse().unwrap();
        assert_eq!(mapped_port(&addr), Some(7423));
    }

    /// Review item 8: the service's decision is reported whether or not a
    /// host runs (an installer flag included), and a running host's own
    /// status wins over it.
    #[test]
    fn status_reports_the_service_decision_with_or_without_a_host() {
        if current_host().is_some() {
            return;
        }
        assert_eq!(status_snapshot(), None, "not `raven-node service`: nothing");
        let relay = peer(7);
        let config = P2pConfig {
            listen: P2pListen::All(7423),
            relays: vec![p2p_route::parse_via(&format!(
                "/dns4/relay.example.org/tcp/7423/p2p/{relay}"
            ))
            .unwrap()],
            relay_server: Some(false),
            upnp: None,
        };
        publish_service_config(ServiceP2p::Held {
            config: &config,
            source: "--p2p-listen",
        });
        let held = status_snapshot().unwrap();
        assert!(!held.up && held.held);
        assert_eq!(held.listen_setting, "7423");
        assert_eq!(held.source, "--p2p-listen");
        assert_eq!(held.relays.len(), 1);
        assert!(
            held.relays[0].starts_with("/dns4/relay.example.org/"),
            "{:?}",
            held.relays
        );
        assert_eq!(held.relays_configured, 1);
        assert!(held.relay_role);
        assert_eq!(held.upnp, "unset");
        publish_service_config(ServiceP2p::Off {
            source: "RAVEN_P2P_LISTEN",
        });
        let off = status_snapshot().unwrap();
        assert!(off.listen_setting.is_empty() && !off.held && off.relays.is_empty());
        assert_eq!(off.source, "RAVEN_P2P_LISTEN");
        publish_service_config(ServiceP2p::Error);
        assert!(!status_snapshot().unwrap().config_error.is_empty());
        // A running host's status overrides the decision while it runs.
        *lock(&STATUS) = Some(P2pStatusInfo {
            up: true,
            ..P2pStatusInfo::default()
        });
        assert!(status_snapshot().unwrap().up);
        *lock(&STATUS) = None;
        *lock(&CONFIG) = None;
        assert_eq!(status_snapshot(), None);
    }

    /// Review item 14: the reachability row follows every AutoNAT update,
    /// both ways, and forgets addresses that expired.
    #[test]
    fn reachability_follows_autonat_updates_both_ways() {
        let mut results = HashMap::new();
        assert_eq!(nat_verdict(&results), "unknown");
        let a: Multiaddr = "/ip4/203.0.113.7/tcp/7423".parse().unwrap();
        let b: Multiaddr = "/ip4/203.0.113.7/udp/7423/quic-v1".parse().unwrap();
        results.insert(a.clone(), false);
        assert_eq!(nat_verdict(&results), "private");
        results.insert(b.clone(), true);
        assert_eq!(nat_verdict(&results), "public");
        results.insert(b.clone(), false);
        assert_eq!(nat_verdict(&results), "private", "a later failure counts");
        results.insert(a.clone(), true);
        assert_eq!(nat_verdict(&results), "public");
        results.remove(&a);
        assert_eq!(nat_verdict(&results), "private");
        results.remove(&b);
        assert_eq!(nat_verdict(&results), "unknown");
    }

    /// Review item 5: a named relay keeps its name, rotates through every
    /// address it resolved to, and backs off between attempts.
    #[test]
    fn relay_slots_keep_the_name_rotate_and_back_off() {
        let relay = peer(8);
        let named: Multiaddr = format!("/dns/relay.example.org/tcp/7423/p2p/{relay}")
            .parse()
            .unwrap();
        assert!(is_dns(&named));
        let ip: Multiaddr = format!("/ip4/198.51.100.7/tcp/7423/p2p/{relay}")
            .parse()
            .unwrap();
        assert!(!is_dns(&ip));
        let mut slot = RelaySlot {
            text: named.to_string(),
            named: named.clone(),
            peer: relay.parse().unwrap(),
            resolved: Vec::new(),
            next: 0,
            listener: None,
            active: false,
            resolving: false,
            attempt: 0,
            retry_at: None,
        };
        slot.rotate();
        assert_eq!(slot.next, 0, "nothing resolved: nothing to rotate");
        slot.resolved = vec![ip.clone(), ip.clone(), ip];
        let seen: Vec<usize> = (0..4)
            .map(|_| {
                slot.rotate();
                slot.next
            })
            .collect();
        assert_eq!(seen, vec![1, 2, 0, 1]);
        let now = Instant::now();
        slot.arm_retry(now);
        let first = slot.retry_at.unwrap() - now;
        for _ in 0..6 {
            slot.arm_retry(now);
        }
        let later = slot.retry_at.unwrap() - now;
        assert_eq!(slot.attempt, 7);
        assert!(later > first, "{first:?} then {later:?}");
        assert_eq!(slot.named, named, "the name is kept for the next resolve");
    }
}
