//! The P3 libp2p host (transports design 2026-10 §3.2-§3.6): the substrate a
//! Raven endpoint uses to reach NAT'd contacts, and the relay role.
//!
//! - **Endpoint** ([`build_endpoint_swarm`]): TCP + QUIC (IPv4 and IPv6),
//!   Circuit Relay v2 client, DCUtR, AutoNAT v2 client, Identify
//!   ([`IDENTIFY_PROTOCOL`]), Ping, `connection_limits`, per-IP limits, optional
//!   UPnP / NAT-PMP, and `libp2p-stream` for [`RAVEN_LINK_PROTOCOL`]. With
//!   `service --relay` it also carries the relay server ([`RelayLimits`],
//!   [`RelayGuard`]); its relay PeerId is then the user's own PeerId.
//! - **Relay** ([`build_relay_swarm`], `raven-node relay`): relay server,
//!   optional AutoNAT v2 server, Identify, Ping and the limits; no Raven link
//!   protocol, no Kademlia, no mailbox.
//!
//! libp2p is a substrate only: a PeerId authenticates a libp2p key, never a
//! Raven identity. raven-node runs the Raven Noise link (prologue
//! `raven/p2p-link/v1` + the RIH1 identity bind) inside every
//! `/raven/link/1.0.0` stream, so a relay sees only
//! libp2p-Noise(Raven-Noise(...)).
//!
//! Nothing here is policy-free on its own: every builder takes a [`HostGate`],
//! which the caller can only obtain with its runtime gate open
//! (`raven_core::p2p_live_enabled()` in raven-node). No relay, bootstrap or
//! AutoNAT server address is compiled in.

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU8, NonZeroUsize};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use libp2p::connection_limits::{self, ConnectionLimits};
use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{
    autonat, dcutr, identify, noise, ping, relay, tcp, upnp, yamux, Multiaddr, PeerId,
    StreamProtocol, Swarm, SwarmBuilder,
};
use rand::rngs::OsRng;

use crate::ip_limits::{IpLimitConfig, IpLimits};

/// The Raven link protocol: one Raven Noise link per stream.
pub const RAVEN_LINK_PROTOCOL: StreamProtocol = StreamProtocol::new("/raven/link/1.0.0");
/// Identify protocol name of every Raven libp2p host.
pub const IDENTIFY_PROTOCOL: &str = "/raven/identify/1.0.0";
/// Generic agent string: no version or OS detail for a scanner.
pub const AGENT_VERSION: &str = "raven";

/// Proof that the caller's runtime gate is open. The builders take one, so a
/// host cannot be built (and therefore cannot listen, dial, reserve or
/// advertise) while the gate is closed.
#[derive(Debug)]
pub struct HostGate(());

impl HostGate {
    /// `live`: the caller's runtime gate (raven-node:
    /// `raven_core::p2p_live_enabled()`).
    pub fn open(live: bool) -> Result<Self, HostError> {
        if live {
            Ok(Self(()))
        } else {
            Err(HostError::new(
                "the libp2p host is held: its runtime gate is closed",
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostError {
    message: &'static str,
}

impl HostError {
    const fn new(message: &'static str) -> Self {
        Self { message }
    }

    pub const fn message(self) -> &'static str {
        self.message
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl Error for HostError {}

// ── Relay limits (transports design §3.5) ───────────────────────────────────

/// Relay server limits. Every value is finite and checked against a hard
/// maximum ([`RelayLimits::validate`]); zero is refused.
///
/// libp2p 0.56 knob names (the design's "(verify)" guesses, checked against
/// libp2p-relay 0.21.1): `max_reservations`, `max_reservations_per_peer`,
/// `reservation_duration`, `max_circuits`, `max_circuits_per_peer`,
/// `max_circuit_duration`, `max_circuit_bytes`, and the rate-limiter lists
/// `reservation_rate_limiters` / `circuit_src_rate_limiters`. libp2p has
/// **no** per-IP reservation cap and **no** allow-list: both are
/// [`RelayGuard`], which also does both per-source rates itself, keyed like
/// every other per-source limit (an IPv4 address or an IPv6 /64; libp2p's own
/// `*_per_ip` limiters key on the exact address, a /128 for IPv6, would spend
/// a source's tokens on requests the allow-list then refuses, and cannot
/// exempt loopback). Its per-peer check denies only when a peer already holds
/// *more* than `max_reservations_per_peer`, so [`Self::relay_config`] passes
/// `per_peer - 1` to get exactly `per_peer` (checked against libp2p-relay
/// 0.21.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    pub max_reservations: usize,
    pub max_reservations_per_peer: usize,
    pub max_reservations_per_ip: usize,
    pub reservation_duration: Duration,
    pub max_circuits: usize,
    pub max_circuits_per_peer: usize,
    pub max_circuit_duration: Duration,
    pub max_circuit_bytes: u64,
    /// Reservation requests per source IP per minute.
    pub reservation_rate_per_ip_per_min: u32,
    /// Circuit requests per source (IPv4 address or IPv6 /64) per minute.
    pub circuit_rate_per_ip_per_min: u32,
    pub max_established: u32,
    pub max_established_per_ip: u32,
    /// Exempt loopback from the per-IP caps (same-host tools and harnesses
    /// share one address by construction), as [`IpLimitConfig`] does.
    pub exempt_loopback: bool,
}

/// Hard maxima of [`RelayLimits`].
pub const RELAY_HARD_MAX: RelayLimits = RelayLimits {
    max_reservations: 1024,
    max_reservations_per_peer: 2,
    max_reservations_per_ip: 16,
    reservation_duration: Duration::from_secs(2 * 60 * 60),
    max_circuits: 256,
    max_circuits_per_peer: 8,
    max_circuit_duration: Duration::from_secs(30 * 60),
    max_circuit_bytes: 16 << 20,
    reservation_rate_per_ip_per_min: 60,
    circuit_rate_per_ip_per_min: 600,
    max_established: 1024,
    max_established_per_ip: 32,
    exempt_loopback: true,
};

impl RelayLimits {
    /// Friends-only (allow-list) defaults. Two reservations per peer: after a
    /// restart (or a network change) a friend's new connection reserves at
    /// once while the relay still holds the old, silent one until it times
    /// out.
    pub const fn friends() -> Self {
        Self {
            max_reservations: 128,
            max_reservations_per_peer: 2,
            max_reservations_per_ip: 4,
            reservation_duration: Duration::from_secs(30 * 60),
            max_circuits: 64,
            max_circuits_per_peer: 4,
            max_circuit_duration: Duration::from_secs(5 * 60),
            max_circuit_bytes: 2 << 20,
            reservation_rate_per_ip_per_min: 4,
            circuit_rate_per_ip_per_min: 30,
            max_established: 256,
            max_established_per_ip: 8,
            exempt_loopback: true,
        }
    }

    /// `--open` (anyone may reserve): the stricter defaults.
    pub const fn open() -> Self {
        Self {
            max_reservations: 32,
            max_circuit_bytes: 512 << 10,
            ..Self::friends()
        }
    }

    pub fn validate(&self) -> Result<(), HostError> {
        let h = RELAY_HARD_MAX;
        let counts = [
            (self.max_reservations as u64, h.max_reservations as u64),
            (
                self.max_reservations_per_peer as u64,
                h.max_reservations_per_peer as u64,
            ),
            (
                self.max_reservations_per_ip as u64,
                h.max_reservations_per_ip as u64,
            ),
            (self.max_circuits as u64, h.max_circuits as u64),
            (
                self.max_circuits_per_peer as u64,
                h.max_circuits_per_peer as u64,
            ),
            (self.max_circuit_bytes, h.max_circuit_bytes),
            (
                self.reservation_rate_per_ip_per_min as u64,
                h.reservation_rate_per_ip_per_min as u64,
            ),
            (
                self.circuit_rate_per_ip_per_min as u64,
                h.circuit_rate_per_ip_per_min as u64,
            ),
            (self.max_established as u64, h.max_established as u64),
            (
                self.max_established_per_ip as u64,
                h.max_established_per_ip as u64,
            ),
        ];
        if counts.iter().any(|(v, _)| *v == 0) {
            return Err(HostError::new("relay limits must be nonzero"));
        }
        if counts.iter().any(|(v, max)| v > max) {
            return Err(HostError::new("relay limit exceeds its hard maximum"));
        }
        let durations = [
            (self.reservation_duration, h.reservation_duration),
            (self.max_circuit_duration, h.max_circuit_duration),
        ];
        if durations.iter().any(|(d, _)| d.is_zero()) {
            return Err(HostError::new("relay durations must be nonzero"));
        }
        if durations.iter().any(|(d, max)| d > max) {
            return Err(HostError::new("relay duration exceeds its hard maximum"));
        }
        if self.max_reservations_per_peer > self.max_reservations
            || self.max_reservations_per_ip > self.max_reservations
            || self.max_circuits_per_peer > self.max_circuits
            || self.max_established_per_ip > self.max_established
            || self.max_established <= OUTBOUND_RESERVE
        {
            return Err(HostError::new(
                "per-peer or per-IP relay limit exceeds its total",
            ));
        }
        Ok(())
    }

    /// The libp2p relay configuration, with [`RelayGuard`] as the only
    /// reservation and circuit limiter. libp2p asks it last (after its own
    /// total and per-peer caps), so its "yes" means the request is accepted.
    pub fn relay_config(&self, guard: &RelayGuard) -> relay::Config {
        relay::Config {
            max_reservations: self.max_reservations,
            // libp2p denies only above this count (see the type docs).
            max_reservations_per_peer: self.max_reservations_per_peer.saturating_sub(1),
            reservation_duration: self.reservation_duration,
            reservation_rate_limiters: vec![guard.limiter()],
            max_circuits: self.max_circuits,
            max_circuits_per_peer: self.max_circuits_per_peer,
            max_circuit_duration: self.max_circuit_duration,
            max_circuit_bytes: self.max_circuit_bytes,
            circuit_src_rate_limiters: vec![guard.circuit_limiter()],
        }
    }

    fn connection_limits(&self) -> connection_limits::Behaviour {
        connection_limits::Behaviour::new(
            ConnectionLimits::default()
                .with_max_pending_incoming(Some(64))
                .with_max_pending_outgoing(Some(64))
                .with_max_established(Some(self.max_established))
                // Strangers cannot take the slots our own dials need.
                .with_max_established_incoming(Some(
                    self.max_established.saturating_sub(OUTBOUND_RESERVE).max(1),
                ))
                .with_max_established_per_peer(Some(4)),
        )
    }

    fn ip_limits(&self) -> IpLimits {
        IpLimits::new(IpLimitConfig {
            max_pending_per_ip: 4,
            max_established_per_ip: self.max_established_per_ip,
            exempt_loopback: self.exempt_loopback,
        })
    }
}

/// Established connections every host keeps for its own dials (its relays,
/// contacts, AutoNAT dial-backs): inbound connections can never take them,
/// so a flood of strangers cannot lock a node out of its own relay.
pub const OUTBOUND_RESERVE: u32 = 16;

// ── Relay admission: allow-list and per-IP reservations ─────────────────────

/// Who may reserve on this relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowPolicy {
    /// `--open`: anyone (stricter limits).
    Open,
    /// The allow-list (`relay_allow.json`), the default. Empty = nobody.
    Peers(HashSet<PeerId>),
    /// The allow-list could not be read: nobody (fail closed).
    Unreadable,
}

/// Source bucket of a reservation: the exact IPv4 address or the IPv6 /64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IpBucket {
    V4([u8; 4]),
    V6([u8; 8]),
}

fn ip_bucket(addr: &Multiaddr, exempt_loopback: bool) -> Option<IpBucket> {
    let ip = addr.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })?;
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        ip => ip,
    };
    if exempt_loopback && ip.is_loopback() {
        return None;
    }
    Some(match ip {
        IpAddr::V4(v4) => IpBucket::V4(v4.octets()),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            IpBucket::V6([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
        }
    })
}

/// Why a reservation was refused (counts only, never the peer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationRefusal {
    NotAllowed,
    AllowListUnreadable,
    PerIpCap,
    /// More new reservations from this source than its per-minute rate.
    PerIpRate,
}

/// Sources one rate table remembers at most. Beyond it the oldest source is
/// forgotten first, which only hands that source a fresh, full bucket.
pub const MAX_RATE_SOURCES: usize = 4096;

/// Token buckets per source (an IPv4 address or an IPv6 /64), bounded by
/// [`MAX_RATE_SOURCES`]. Admission is O(1); [`Self::prune`] (on the host's
/// timer, not on every request) drops the buckets that are full again.
#[derive(Debug)]
struct SourceRate {
    per_min: u32,
    buckets: HashMap<IpBucket, (f64, Instant)>,
    /// Insertion order of `buckets` (exactly its keys).
    order: VecDeque<IpBucket>,
}

impl SourceRate {
    fn new(per_min: u32) -> Self {
        Self {
            per_min,
            buckets: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn cap(&self) -> f64 {
        f64::from(self.per_min.max(1))
    }

    fn level(&self, tokens: f64, last: Instant, now: Instant) -> f64 {
        let cap = self.cap();
        (tokens + now.saturating_duration_since(last).as_secs_f64() * cap / 60.0).min(cap)
    }

    /// Take one token for `source`; `false` when its bucket is empty.
    fn try_take(&mut self, source: IpBucket, now: Instant) -> bool {
        let current = match self.buckets.get(&source) {
            Some(&(tokens, last)) => self.level(tokens, last, now),
            None => self.cap(),
        };
        if current < 1.0 {
            self.buckets.insert(source, (current, now));
            return false;
        }
        if !self.buckets.contains_key(&source) {
            while self.buckets.len() >= MAX_RATE_SOURCES {
                match self.order.pop_front() {
                    Some(oldest) => {
                        self.buckets.remove(&oldest);
                    }
                    None => break,
                }
            }
            self.order.push_back(source);
        }
        self.buckets.insert(source, (current - 1.0, now));
        true
    }

    /// Forget every source whose bucket is full again.
    fn prune(&mut self, now: Instant) {
        let cap = self.cap();
        let per_sec = cap / 60.0;
        self.buckets.retain(|_, (tokens, last)| {
            *tokens + now.saturating_duration_since(*last).as_secs_f64() * per_sec < cap
        });
        let kept = &self.buckets;
        self.order.retain(|source| kept.contains_key(source));
    }

    fn len(&self) -> usize {
        self.buckets.len()
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GuardCounts {
    pub allowed_peers: u32,
    pub open: bool,
    pub unreadable: bool,
    pub active_reservations: u32,
    pub refused_not_allowed: u64,
    pub refused_unreadable: u64,
    pub refused_per_ip: u64,
    pub refused_rate: u64,
    pub refused_circuit_rate: u64,
}

#[derive(Debug)]
struct GuardState {
    policy: AllowPolicy,
    max_per_ip: usize,
    exempt_loopback: bool,
    /// Peers holding (or just granted) a reservation, and their bucket.
    active: HashMap<PeerId, Option<IpBucket>>,
    per_ip: HashMap<IpBucket, usize>,
    /// New reservations per source and minute.
    rate: SourceRate,
    /// Circuit requests per source and minute.
    circuit_rate: SourceRate,
    refused_not_allowed: u64,
    refused_unreadable: u64,
    refused_per_ip: u64,
    refused_rate: u64,
    refused_circuit_rate: u64,
}

/// The relay's own admission on top of libp2p: the allow-list (on by
/// default, fail closed), the per-IP reservation cap and the per-IP rate of
/// new reservations, in that order, so a refused peer spends nobody's rate,
/// plus the per-source circuit rate. libp2p-relay has none of them (its own
/// per-IP limiters key on the exact IPv6 address). Plugged in as the only
/// reservation and circuit limiter ([`RelayLimits::relay_config`]); the swarm
/// loop feeds it the relay events ([`Self::on_relay_event`]) and disconnects
/// ([`Self::on_peer_disconnected`]) and prunes it on its timer
/// ([`Self::prune`]). Clones share one state.
#[derive(Debug, Clone)]
pub struct RelayGuard {
    state: Arc<Mutex<GuardState>>,
}

impl RelayGuard {
    pub fn new(policy: AllowPolicy, limits: &RelayLimits) -> Self {
        Self {
            state: Arc::new(Mutex::new(GuardState {
                policy,
                max_per_ip: limits.max_reservations_per_ip,
                exempt_loopback: limits.exempt_loopback,
                active: HashMap::new(),
                per_ip: HashMap::new(),
                rate: SourceRate::new(limits.reservation_rate_per_ip_per_min),
                circuit_rate: SourceRate::new(limits.circuit_rate_per_ip_per_min),
                refused_not_allowed: 0,
                refused_unreadable: 0,
                refused_per_ip: 0,
                refused_rate: 0,
                refused_circuit_rate: 0,
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, GuardState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Decide one reservation request (new or renewal) from `peer` at `addr`.
    pub fn admit(&self, peer: PeerId, addr: &Multiaddr) -> Result<(), ReservationRefusal> {
        self.admit_at(peer, addr, Instant::now())
    }

    /// [`Self::admit`] at a given time (tests).
    pub fn admit_at(
        &self,
        peer: PeerId,
        addr: &Multiaddr,
        now: Instant,
    ) -> Result<(), ReservationRefusal> {
        let mut st = self.lock();
        match &st.policy {
            AllowPolicy::Open => {}
            AllowPolicy::Peers(peers) if peers.contains(&peer) => {}
            AllowPolicy::Peers(_) => {
                st.refused_not_allowed += 1;
                return Err(ReservationRefusal::NotAllowed);
            }
            AllowPolicy::Unreadable => {
                st.refused_unreadable += 1;
                return Err(ReservationRefusal::AllowListUnreadable);
            }
        }
        if st.active.contains_key(&peer) {
            // A renewal (or a second connection: libp2p's per-peer cap).
            return Ok(());
        }
        let bucket = ip_bucket(addr, st.exempt_loopback);
        if let Some(b) = bucket {
            if st.per_ip.get(&b).copied().unwrap_or(0) >= st.max_per_ip {
                st.refused_per_ip += 1;
                return Err(ReservationRefusal::PerIpCap);
            }
            if !st.rate.try_take(b, now) {
                st.refused_rate += 1;
                return Err(ReservationRefusal::PerIpRate);
            }
            *st.per_ip.entry(b).or_insert(0) += 1;
        }
        st.active.insert(peer, bucket);
        Ok(())
    }

    /// Decide one circuit request from the source at `addr` (its per-minute
    /// rate; loopback exempt like everything else).
    pub fn admit_circuit_at(&self, addr: &Multiaddr, now: Instant) -> bool {
        let mut st = self.lock();
        let Some(b) = ip_bucket(addr, st.exempt_loopback) else {
            return true;
        };
        if st.circuit_rate.try_take(b, now) {
            true
        } else {
            st.refused_circuit_rate += 1;
            false
        }
    }

    /// Drop the rate buckets that are full again (call it on a timer).
    pub fn prune(&self) {
        self.prune_at(Instant::now());
    }

    pub fn prune_at(&self, now: Instant) {
        let mut st = self.lock();
        st.rate.prune(now);
        st.circuit_rate.prune(now);
    }

    /// Sources the two rate tables remember (tests, diagnostics).
    pub fn rate_sources(&self) -> (usize, usize) {
        let st = self.lock();
        (st.rate.len(), st.circuit_rate.len())
    }

    fn release(&self, peer: &PeerId) {
        let mut st = self.lock();
        if let Some(Some(b)) = st.active.remove(peer) {
            if let Some(n) = st.per_ip.get_mut(&b) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    st.per_ip.remove(&b);
                }
            }
        }
    }

    /// Feed every relay server event: closed and timed-out reservations free
    /// their slot. (A denial never took one: this guard says yes last.)
    pub fn on_relay_event(&self, event: &relay::Event) {
        match event {
            relay::Event::ReservationClosed { src_peer_id }
            | relay::Event::ReservationTimedOut { src_peer_id } => self.release(src_peer_id),
            _ => {}
        }
    }

    /// The peer has no connection left (`ConnectionClosed` with
    /// `num_established == 0`): whatever it reserved is gone.
    pub fn on_peer_disconnected(&self, peer: &PeerId) {
        self.release(peer);
    }

    /// Replace the policy (an allow-list reload). Returns the peers that hold a
    /// reservation but are no longer allowed: the caller disconnects them.
    pub fn set_policy(&self, policy: AllowPolicy) -> Vec<PeerId> {
        let mut st = self.lock();
        st.policy = policy;
        let allowed = |p: &PeerId, policy: &AllowPolicy| match policy {
            AllowPolicy::Open => true,
            AllowPolicy::Peers(set) => set.contains(p),
            AllowPolicy::Unreadable => false,
        };
        let policy = st.policy.clone();
        st.active
            .keys()
            .filter(|p| !allowed(p, &policy))
            .copied()
            .collect()
    }

    pub fn counts(&self) -> GuardCounts {
        let st = self.lock();
        GuardCounts {
            allowed_peers: match &st.policy {
                AllowPolicy::Peers(p) => p.len() as u32,
                _ => 0,
            },
            open: st.policy == AllowPolicy::Open,
            unreadable: st.policy == AllowPolicy::Unreadable,
            active_reservations: st.active.len() as u32,
            refused_not_allowed: st.refused_not_allowed,
            refused_unreadable: st.refused_unreadable,
            refused_per_ip: st.refused_per_ip,
            refused_rate: st.refused_rate,
            refused_circuit_rate: st.refused_circuit_rate,
        }
    }

    /// This guard as a libp2p reservation rate limiter.
    pub fn limiter(&self) -> Box<dyn relay::RateLimiter> {
        let guard = self.clone();
        Box::new(move |peer: PeerId, addr: &Multiaddr, _now| guard.admit(peer, addr).is_ok())
    }

    /// This guard as a libp2p circuit rate limiter (per source).
    pub fn circuit_limiter(&self) -> Box<dyn relay::RateLimiter> {
        let guard = self.clone();
        Box::new(move |_peer: PeerId, addr: &Multiaddr, _now| {
            guard.admit_circuit_at(addr, Instant::now())
        })
    }
}

// ── Which addresses a host may name ─────────────────────────────────────────

/// Globally routable unicast IPv4 (not private, loopback, link-local,
/// CGNAT 100.64/10, documentation, benchmarking, multicast, reserved,
/// broadcast or unspecified).
pub fn is_global_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] & 0xfe) == 18))
}

/// Globally routable unicast IPv6 (not loopback, unspecified, link-local,
/// unique-local, multicast, documentation 2001:db8::/32, or an IPv4-mapped
/// address whose IPv4 part is not global).
pub fn is_global_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_global_ipv4(v4);
    }
    let s = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] == 0x2001 && s[1] == 0x0db8))
}

pub fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_ipv4(v4),
        IpAddr::V6(v6) => is_global_ipv6(v6),
    }
}

/// The IP of the first `/ip4` / `/ip6` component, if any.
pub fn addr_ip(address: &Multiaddr) -> Option<IpAddr> {
    address.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

/// May a relay name this listen address of its own (in reservations and to
/// Identify)? Circuits never; a globally routable one always; any other only
/// when the operator listens on that specific address (`--listen
/// 10.0.0.1:7423`, a lab's `127.0.0.1:0`): an unspecified listen address
/// (`0.0.0.0`, `::`) must not disclose the host's LAN, link-local or
/// loopback addresses. `/dns*` addresses come only from `--external`.
pub fn relay_may_advertise(address: &Multiaddr, listen_is_specific: bool) -> bool {
    if is_circuit(address) {
        return false;
    }
    match addr_ip(address) {
        Some(ip) => is_global_ip(ip) || listen_is_specific,
        None => false,
    }
}

/// Which own listen addresses a relaying host names as external (in its
/// reservations and to Identify), given how it listens:
/// - `--external` addresses, when the operator gave any: exactly those;
/// - else every listen address [`relay_may_advertise`] admits;
/// - else (an unspecified listen address with no global one) one loopback
///   listen address as a placeholder, which discloses nothing but the port:
///   libp2p clients refuse a reservation that names no address at all, and
///   friends dial the address in their `via=` anyway. A real address replaces
///   it as soon as one appears.
///
/// Expired listen addresses are withdrawn again, so a network change never
/// leaves a stale address advertised.
#[derive(Debug, Default)]
pub struct RelayAdvertiser {
    listen_is_specific: bool,
    explicit: bool,
    advertised: HashSet<Multiaddr>,
    placeholder: Option<Multiaddr>,
}

impl RelayAdvertiser {
    pub fn new<B: NetworkBehaviour>(
        swarm: &mut Swarm<B>,
        listen_is_specific: bool,
        external: &[Multiaddr],
    ) -> Self {
        for addr in external {
            swarm.add_external_address(addr.clone());
        }
        Self {
            listen_is_specific,
            explicit: !external.is_empty(),
            advertised: HashSet::new(),
            placeholder: None,
        }
    }

    /// Feed `SwarmEvent::NewListenAddr`.
    pub fn on_new_listen_addr<B: NetworkBehaviour>(
        &mut self,
        swarm: &mut Swarm<B>,
        addr: &Multiaddr,
    ) {
        if self.explicit || is_circuit(addr) {
            return;
        }
        if relay_may_advertise(addr, self.listen_is_specific) {
            if let Some(old) = self.placeholder.take() {
                swarm.remove_external_address(&old);
            }
            if self.advertised.insert(addr.clone()) {
                swarm.add_external_address(addr.clone());
            }
        } else if self.advertised.is_empty()
            && self.placeholder.is_none()
            && addr_ip(addr).is_some_and(|ip| ip.is_loopback())
        {
            swarm.add_external_address(addr.clone());
            self.placeholder = Some(addr.clone());
        }
    }

    /// Feed `SwarmEvent::ExpiredListenAddr`.
    pub fn on_expired_listen_addr<B: NetworkBehaviour>(
        &mut self,
        swarm: &mut Swarm<B>,
        addr: &Multiaddr,
    ) {
        if self.advertised.remove(addr) || self.placeholder.as_ref() == Some(addr) {
            swarm.remove_external_address(addr);
            if self.placeholder.as_ref() == Some(addr) {
                self.placeholder = None;
            }
        }
    }

    /// Only the loopback placeholder is advertised (no public address known).
    pub fn placeholder_only(&self) -> bool {
        !self.explicit && self.advertised.is_empty() && self.placeholder.is_some()
    }
}

/// Why a listen address cannot be opened, found before libp2p binds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenProbe {
    /// Another program holds the port: libp2p-tcp would still bind it
    /// (`SO_REUSEADDR`, and `SO_REUSEPORT` on Unix) and silently share or
    /// lose the connections, so it must not be opened.
    Busy,
    /// The address cannot be bound here at all (no such interface, no IPv6).
    Unavailable,
}

/// Probe-bind the exact TCP (or, for `/quic-v1`, UDP) address of `addr` with
/// a plain std socket, which sets no `SO_REUSEPORT` (and on Windows no
/// `SO_REUSEADDR`), so a port another socket holds is reported instead of
/// shared. Port 0 and non-IP addresses are not probed. The probe socket is
/// closed before this returns; probe every address before opening any, or a
/// dual-stack `[::]` probe collides with one's own `0.0.0.0` listener.
pub fn probe_listen_addr(addr: &Multiaddr) -> Result<(), ListenProbe> {
    let Some(ip) = addr_ip(addr) else {
        return Ok(());
    };
    let mut port = None;
    let mut udp = false;
    for p in addr.iter() {
        match p {
            Protocol::Tcp(n) => port = Some(n),
            Protocol::Udp(n) => {
                port = Some(n);
                udp = true;
            }
            _ => {}
        }
    }
    let Some(port) = port.filter(|p| *p != 0) else {
        return Ok(());
    };
    let sock = std::net::SocketAddr::new(ip, port);
    let result = if udp {
        std::net::UdpSocket::bind(sock).map(drop)
    } else {
        std::net::TcpListener::bind(sock).map(drop)
    };
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Err(ListenProbe::Busy),
        // Windows reports a port held exclusively as access denied.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && cfg!(windows) => {
            Err(ListenProbe::Busy)
        }
        Err(_) => Err(ListenProbe::Unavailable),
    }
}

/// "tcp" / "udp" and the port of a listen address, for logs that must not
/// name an address (NAT spec §5).
pub fn listen_port_label(addr: &Multiaddr) -> String {
    let mut out = String::from("?");
    for p in addr.iter() {
        match p {
            Protocol::Tcp(n) => out = format!("{n}/tcp"),
            Protocol::Udp(n) => out = format!("{n}/udp"),
            _ => {}
        }
    }
    out
}

/// Refuses every outbound dial to an address that is not globally routable.
/// On the relay-only host the only outbound dials are the AutoNAT v2 server's
/// dial-backs (the relay server dials nobody), whose target a client chooses:
/// without this a client could make the relay connect to its own loopback or
/// LAN services. libp2p-autonat 0.15 has no such filter of its own.
#[derive(Debug, Default)]
pub struct DialBackGuard {
    refused: u64,
}

/// Why [`DialBackGuard`] refused a dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotGloballyRoutable;

impl fmt::Display for NotGloballyRoutable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dial-back target is not a globally routable address")
    }
}

impl Error for NotGloballyRoutable {}

impl DialBackGuard {
    pub fn refused(&self) -> u64 {
        self.refused
    }

    fn allowed(addresses: &[Multiaddr]) -> bool {
        !addresses.is_empty()
            && addresses
                .iter()
                .all(|a| addr_ip(a).is_some_and(is_global_ip) && !is_circuit(a))
    }
}

impl NetworkBehaviour for DialBackGuard {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if Self::allowed(addresses) {
            Ok(Vec::new())
        } else {
            self.refused += 1;
            Err(ConnectionDenied::new(NotGloballyRoutable))
        }
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if Self::allowed(std::slice::from_ref(addr)) {
            Ok(dummy::ConnectionHandler)
        } else {
            self.refused += 1;
            Err(ConnectionDenied::new(NotGloballyRoutable))
        }
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _peer: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        libp2p::core::util::unreachable(event)
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

// ── Endpoint host ────────────────────────────────────────────────────────────

/// What the endpoint host runs besides the always-on parts.
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    /// UPnP / NAT-PMP port mapping (node policy; owner decision Q8).
    pub upnp: bool,
    /// `service --relay`: also relay for others (the user's own PeerId).
    pub relay_server: Option<(RelayLimits, RelayGuard)>,
    pub connection_timeout: Duration,
    pub idle_connection_timeout: Duration,
    pub ping_interval: Duration,
    pub ping_timeout: Duration,
    pub identify_interval: Duration,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            upnp: false,
            relay_server: None,
            connection_timeout: Duration::from_secs(10),
            idle_connection_timeout: Duration::from_secs(60),
            ping_interval: Duration::from_secs(15),
            ping_timeout: Duration::from_secs(5),
            identify_interval: Duration::from_secs(60),
        }
    }
}

/// Connection budget of an endpoint that does not relay: a few contacts,
/// their circuits and our relays. Inbound connections may hold at most
/// `ENDPOINT_MAX_ESTABLISHED - OUTBOUND_RESERVE` of them.
const ENDPOINT_MAX_ESTABLISHED: u32 = 64;
const ENDPOINT_MAX_PENDING: u32 = 16;
/// A direct and a relayed connection to one contact, plus one spare.
const ENDPOINT_MAX_PER_PEER: u32 = 3;

/// The derive asks the fields in declaration order whether to admit a
/// connection and stops at the first denial, so `limits` and `ip_limits` come
/// FIRST: a behaviour listed before them (DCUtR keeps a record of every
/// direct connection it is shown) would otherwise record connections the
/// limits then deny, and those records never see a `ConnectionClosed`.
#[derive(NetworkBehaviour)]
pub struct EndpointBehaviour {
    limits: connection_limits::Behaviour,
    ip_limits: IpLimits,
    pub relay_client: relay::client::Behaviour,
    pub relay_server: Toggle<relay::Behaviour>,
    pub dcutr: dcutr::Behaviour,
    pub autonat: autonat::v2::client::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub upnp: Toggle<upnp::tokio::Behaviour>,
    pub stream: libp2p_stream::Behaviour,
}

/// Identify names only this host's *external* addresses: those a relay
/// reservation, UPnP or AutoNAT confirmed (plus, on a relay, the ones
/// [`relay_may_advertise`] admits). Listen addresses (LAN, link-local,
/// loopback) are never sent, and nothing is pushed unasked. DCUtR and AutoNAT
/// do not need them: both work from the addresses peers *observe*
/// (`NewExternalAddrCandidate`), which Identify still reports.
pub fn identify_config(key: &Keypair, interval: Duration) -> identify::Config {
    identify::Config::new(IDENTIFY_PROTOCOL.to_owned(), key.public())
        .with_agent_version(AGENT_VERSION.to_owned())
        .with_interval(interval)
        .with_hide_listen_addrs(true)
        .with_push_listen_addr_updates(false)
        .with_cache_size(64)
}

/// The endpoint host: direct TCP / QUIC, the relay client transport, and the
/// behaviours above. No DNS transport: callers resolve `/dns*/` names first. At most two concurrent
/// connection attempts per dial (the design's hedge of 2).
pub fn build_endpoint_swarm(
    _gate: &HostGate,
    identity: Keypair,
    config: EndpointConfig,
) -> Result<Swarm<EndpointBehaviour>, Box<dyn Error + Send + Sync>> {
    if let Some((limits, _)) = &config.relay_server {
        limits.validate()?;
    }
    let cfg = config.clone();
    let swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(move |key, relay_client| {
            let local = key.public().to_peer_id();
            let (limits, ip_limits, relay_server) = match &cfg.relay_server {
                Some((relay_limits, guard)) => (
                    relay_limits.connection_limits(),
                    relay_limits.ip_limits(),
                    Some(relay::Behaviour::new(
                        local,
                        relay_limits.relay_config(guard),
                    )),
                ),
                None => (
                    connection_limits::Behaviour::new(
                        ConnectionLimits::default()
                            .with_max_pending_incoming(Some(ENDPOINT_MAX_PENDING))
                            .with_max_pending_outgoing(Some(ENDPOINT_MAX_PENDING))
                            .with_max_established(Some(ENDPOINT_MAX_ESTABLISHED))
                            .with_max_established_incoming(Some(
                                ENDPOINT_MAX_ESTABLISHED - OUTBOUND_RESERVE,
                            ))
                            .with_max_established_per_peer(Some(ENDPOINT_MAX_PER_PEER)),
                    ),
                    IpLimits::new(IpLimitConfig::default()),
                    None,
                ),
            };
            EndpointBehaviour {
                limits,
                ip_limits,
                relay_client,
                relay_server: Toggle::from(relay_server),
                dcutr: dcutr::Behaviour::new(local),
                autonat: autonat::v2::client::Behaviour::new(
                    OsRng,
                    autonat::v2::client::Config::default()
                        .with_max_candidates(8)
                        .with_probe_interval(Duration::from_secs(60)),
                ),
                identify: identify::Behaviour::new(identify_config(key, cfg.identify_interval)),
                // Ping only reports a dead connection; the host loop closes it
                // (`crate::liveness::close_if_dead`).
                ping: ping::Behaviour::new(
                    ping::Config::new()
                        .with_interval(cfg.ping_interval)
                        .with_timeout(cfg.ping_timeout),
                ),
                upnp: Toggle::from(cfg.upnp.then(upnp::tokio::Behaviour::default)),
                stream: libp2p_stream::Behaviour::new(),
            }
        })?
        .with_swarm_config(move |c| {
            c.with_idle_connection_timeout(config.idle_connection_timeout)
                .with_notify_handler_buffer_size(NonZeroUsize::new(32).expect("nonzero"))
                .with_per_connection_event_buffer_size(32)
                .with_dial_concurrency_factor(NonZeroU8::new(2).expect("nonzero"))
                .with_max_negotiating_inbound_streams(64)
        })
        .with_connection_timeout(config.connection_timeout)
        .build();
    Ok(swarm)
}

// ── Relay-only host ──────────────────────────────────────────────────────────

/// `limits` and `ip_limits` first, for the reason given at
/// [`EndpointBehaviour`]; `dial_back_guard` before the AutoNAT server.
#[derive(NetworkBehaviour)]
pub struct RelayBehaviour {
    limits: connection_limits::Behaviour,
    ip_limits: IpLimits,
    pub dial_back_guard: DialBackGuard,
    pub relay: relay::Behaviour,
    pub autonat_server: Toggle<autonat::v2::server::Behaviour>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}

/// `raven-node relay`: the relay server with `limits` and `guard`, an
/// optional AutoNAT v2 server, Identify and Ping. No Raven link protocol.
pub fn build_relay_swarm(
    _gate: &HostGate,
    identity: Keypair,
    limits: RelayLimits,
    guard: &RelayGuard,
    autonat_server: bool,
) -> Result<Swarm<RelayBehaviour>, Box<dyn Error + Send + Sync>> {
    limits.validate()?;
    let guard = guard.clone();
    let swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(move |key| RelayBehaviour {
            limits: limits.connection_limits(),
            ip_limits: limits.ip_limits(),
            dial_back_guard: DialBackGuard::default(),
            relay: relay::Behaviour::new(key.public().to_peer_id(), limits.relay_config(&guard)),
            autonat_server: Toggle::from(
                autonat_server.then(|| autonat::v2::server::Behaviour::new(OsRng)),
            ),
            identify: identify::Behaviour::new(identify_config(key, Duration::from_secs(60))),
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(15))
                    .with_timeout(Duration::from_secs(5)),
            ),
        })?
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(Duration::from_secs(60))
                .with_max_negotiating_inbound_streams(128)
        })
        .with_connection_timeout(Duration::from_secs(10))
        .build();
    Ok(swarm)
}

/// Is `address` a relayed (`/p2p-circuit`) address?
pub fn is_circuit(address: &Multiaddr) -> bool {
    address.iter().any(|p| matches!(p, Protocol::P2pCircuit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
    use libp2p::swarm::SwarmEvent;

    fn key(seed: u8) -> Keypair {
        Keypair::ed25519_from_bytes([seed; 32]).unwrap()
    }

    fn gate() -> HostGate {
        HostGate::open(true).unwrap()
    }

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn the_gate_is_required_to_build_anything() {
        assert_eq!(
            HostGate::open(false).unwrap_err().message(),
            "the libp2p host is held: its runtime gate is closed"
        );
        HostGate::open(true).unwrap();
    }

    #[test]
    fn relay_defaults_match_the_design_and_stay_under_the_hard_max() {
        let f = RelayLimits::friends();
        f.validate().unwrap();
        assert_eq!(
            (
                f.max_reservations,
                f.max_reservations_per_peer,
                f.max_reservations_per_ip
            ),
            (128, 2, 4)
        );
        assert_eq!(f.reservation_duration, Duration::from_secs(1800));
        assert_eq!((f.max_circuits, f.max_circuits_per_peer), (64, 4));
        assert_eq!(f.max_circuit_duration, Duration::from_secs(300));
        assert_eq!(f.max_circuit_bytes, 2 << 20);
        assert_eq!(
            (
                f.reservation_rate_per_ip_per_min,
                f.circuit_rate_per_ip_per_min
            ),
            (4, 30)
        );
        assert_eq!((f.max_established, f.max_established_per_ip), (256, 8));
        let o = RelayLimits::open();
        o.validate().unwrap();
        assert_eq!(o.max_reservations, 32);
        assert_eq!(o.max_circuit_bytes, 512 << 10);
        RELAY_HARD_MAX.validate().unwrap();

        // The libp2p per-peer check is "more than": compensated by one.
        let guard = RelayGuard::new(AllowPolicy::Open, &f);
        let config = f.relay_config(&guard);
        assert_eq!(
            config.max_reservations_per_peer, 1,
            "2 per peer: n - 1 for libp2p"
        );
        assert_eq!(config.max_circuit_bytes, 2 << 20);
        assert_eq!(config.reservation_rate_limiters.len(), 1, "the guard alone");
        assert_eq!(config.circuit_src_rate_limiters.len(), 1, "the guard alone");
    }

    #[test]
    fn relay_limits_refuse_zero_and_anything_above_the_hard_max() {
        let cases: [fn(&mut RelayLimits); 8] = [
            |l| l.max_reservations = RELAY_HARD_MAX.max_reservations + 1,
            |l| l.max_reservations_per_peer = 3,
            |l| l.max_circuit_bytes = (16 << 20) + 1,
            |l| l.max_circuit_duration = Duration::from_secs(30 * 60 + 1),
            |l| l.reservation_duration = Duration::from_secs(2 * 3600 + 1),
            |l| l.max_circuits = 0,
            |l| l.max_circuit_duration = Duration::ZERO,
            |l| l.max_reservations_per_ip = 200,
        ];
        for (i, edit) in cases.iter().enumerate() {
            let mut l = RelayLimits::friends();
            edit(&mut l);
            assert!(l.validate().is_err(), "case {i}");
        }
    }

    /// Per-IP cap tests: the rate is at its maximum so only the cap decides.
    fn strict(per_ip: usize) -> RelayLimits {
        RelayLimits {
            max_reservations_per_ip: per_ip,
            reservation_rate_per_ip_per_min: RELAY_HARD_MAX.reservation_rate_per_ip_per_min,
            exempt_loopback: false,
            ..RelayLimits::friends()
        }
    }

    /// C10: a peer that is not on the allow-list cannot reserve; an
    /// unreadable allow-list admits nobody; `--open` admits anyone.
    #[test]
    fn allow_list_is_on_by_default_and_fails_closed() {
        let (friend, stranger) = (PeerId::random(), PeerId::random());
        let from = addr("/ip4/198.51.100.7/tcp/4001");
        let guard = RelayGuard::new(
            AllowPolicy::Peers([friend].into_iter().collect()),
            &RelayLimits::friends(),
        );
        assert_eq!(guard.admit(friend, &from), Ok(()));
        assert_eq!(
            guard.admit(stranger, &from),
            Err(ReservationRefusal::NotAllowed)
        );
        let empty = RelayGuard::new(AllowPolicy::Peers(HashSet::new()), &RelayLimits::friends());
        assert_eq!(
            empty.admit(friend, &from),
            Err(ReservationRefusal::NotAllowed)
        );
        let broken = RelayGuard::new(AllowPolicy::Unreadable, &RelayLimits::friends());
        assert_eq!(
            broken.admit(friend, &from),
            Err(ReservationRefusal::AllowListUnreadable)
        );
        let open = RelayGuard::new(AllowPolicy::Open, &RelayLimits::open());
        assert_eq!(open.admit(stranger, &from), Ok(()));
        let c = guard.counts();
        assert_eq!(
            (
                c.allowed_peers,
                c.active_reservations,
                c.refused_not_allowed
            ),
            (1, 1, 1)
        );
        assert!(broken.counts().unreadable && broken.counts().refused_unreadable == 1);
        assert!(open.counts().open);
    }

    /// C10: per-IP reservation cap (IPv6 by /64), renewals do not count
    /// twice, and a closed or timed-out reservation frees its slot.
    #[test]
    fn per_ip_reservation_cap_holds_and_frees_on_close() {
        let guard = RelayGuard::new(AllowPolicy::Open, &strict(2));
        let host = addr("/ip4/198.51.100.7/tcp/4001");
        let other_port = addr("/ip4/198.51.100.7/udp/9/quic-v1");
        let (p1, p2, p3) = (PeerId::random(), PeerId::random(), PeerId::random());
        assert_eq!(guard.admit(p1, &host), Ok(()));
        assert_eq!(guard.admit(p2, &other_port), Ok(()));
        assert_eq!(guard.admit(p3, &host), Err(ReservationRefusal::PerIpCap));
        // Renewal of a peer that already holds one is not a new slot.
        assert_eq!(guard.admit(p1, &host), Ok(()));
        // Another address is its own bucket; one /64 is one bucket.
        assert_eq!(guard.admit(p3, &addr("/ip4/203.0.113.9/tcp/1")), Ok(()));
        let v6 = RelayGuard::new(AllowPolicy::Open, &strict(1));
        assert_eq!(
            v6.admit(PeerId::random(), &addr("/ip6/2001:db8:1:2::1/tcp/1")),
            Ok(())
        );
        assert_eq!(
            v6.admit(PeerId::random(), &addr("/ip6/2001:db8:1:2:ffff::9/tcp/1")),
            Err(ReservationRefusal::PerIpCap)
        );
        // Close frees the slot (also a timeout, or the peer going away).
        guard.on_relay_event(&relay::Event::ReservationClosed { src_peer_id: p1 });
        let p4 = PeerId::random();
        assert_eq!(guard.admit(p4, &host), Ok(()));
        guard.on_relay_event(&relay::Event::ReservationTimedOut { src_peer_id: p4 });
        guard.on_relay_event(&relay::Event::ReservationTimedOut { src_peer_id: p4 });
        let p5 = PeerId::random();
        assert_eq!(guard.admit(p5, &host), Ok(()));
        guard.on_peer_disconnected(&p5);
        // A denial libp2p made itself never frees a slot it did not take.
        guard.on_relay_event(&relay::Event::ReservationReqDenied {
            src_peer_id: p2,
            status: relay::StatusCode::ResourceLimitExceeded,
        });
        assert_eq!(guard.admit(PeerId::random(), &host), Ok(()));
        assert_eq!(
            guard.admit(PeerId::random(), &host),
            Err(ReservationRefusal::PerIpCap)
        );
        assert_eq!(guard.counts().refused_per_ip, 2);
        // Loopback is exempt unless configured otherwise.
        let lab = RelayGuard::new(AllowPolicy::Open, &RelayLimits::friends());
        for _ in 0..10 {
            assert_eq!(
                lab.admit(PeerId::random(), &addr("/ip4/127.0.0.1/tcp/1")),
                Ok(())
            );
        }
    }

    /// C10: new reservations per source and minute are capped; renewals and
    /// refused (not allow-listed) requests spend nothing; the bucket refills.
    #[test]
    fn reservation_rate_is_per_source_and_spent_only_on_admissions() {
        let limits = RelayLimits {
            reservation_rate_per_ip_per_min: 2,
            max_reservations_per_ip: 16,
            exempt_loopback: false,
            ..RelayLimits::friends()
        };
        let friends: Vec<PeerId> = (0..4).map(|_| PeerId::random()).collect();
        let guard = RelayGuard::new(
            AllowPolicy::Peers(friends.iter().copied().collect()),
            &limits,
        );
        let from = addr("/ip4/198.51.100.7/tcp/4001");
        let t0 = std::time::Instant::now();
        // Strangers spend nothing.
        for _ in 0..10 {
            assert_eq!(
                guard.admit_at(PeerId::random(), &from, t0),
                Err(ReservationRefusal::NotAllowed)
            );
        }
        assert_eq!(guard.admit_at(friends[0], &from, t0), Ok(()));
        assert_eq!(guard.admit_at(friends[1], &from, t0), Ok(()));
        // Renewal of an active one is free.
        assert_eq!(guard.admit_at(friends[0], &from, t0), Ok(()));
        assert_eq!(
            guard.admit_at(friends[2], &from, t0),
            Err(ReservationRefusal::PerIpRate)
        );
        // Another source has its own bucket; 30 s later one token is back.
        assert_eq!(
            guard.admit_at(friends[3], &addr("/ip4/203.0.113.1/tcp/1"), t0),
            Ok(())
        );
        let later = t0 + Duration::from_secs(31);
        assert_eq!(guard.admit_at(friends[2], &from, later), Ok(()));
        assert_eq!(guard.counts().refused_rate, 1);
        // Loopback is exempt by default (same-host tools and harnesses).
        let lab = RelayGuard::new(AllowPolicy::Open, &RelayLimits::friends());
        for _ in 0..20 {
            assert_eq!(
                lab.admit_at(PeerId::random(), &addr("/ip4/127.0.0.1/tcp/1"), t0),
                Ok(())
            );
        }
    }

    #[test]
    fn reloading_the_allow_list_names_the_peers_to_drop() {
        let (a, b) = (PeerId::random(), PeerId::random());
        let from = addr("/ip4/198.51.100.7/tcp/4001");
        let guard = RelayGuard::new(
            AllowPolicy::Peers([a, b].into_iter().collect()),
            &RelayLimits::friends(),
        );
        guard.admit(a, &from).unwrap();
        guard.admit(b, &addr("/ip4/198.51.100.8/tcp/1")).unwrap();
        let drop = guard.set_policy(AllowPolicy::Peers([a].into_iter().collect()));
        assert_eq!(drop, vec![b]);
        assert_eq!(
            guard.admit(b, &from),
            Err(ReservationRefusal::NotAllowed),
            "a denied peer cannot renew"
        );
        let mut drop = guard.set_policy(AllowPolicy::Unreadable);
        drop.sort();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(drop, want);
    }

    // ── In-process relay + two endpoints over loopback ───────────────────

    struct Lab {
        relay: Swarm<RelayBehaviour>,
        relay_addr: Multiaddr,
        guard: RelayGuard,
    }

    async fn relay_lab(limits: RelayLimits, policy: AllowPolicy) -> Lab {
        let guard = RelayGuard::new(policy, &limits);
        let mut relay = build_relay_swarm(&gate(), key(0xA1), limits, &guard, false).unwrap();
        relay
            .listen_on(addr("/ip4/127.0.0.1/tcp/0"))
            .expect("relay listen");
        let relay_addr = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = relay.select_next_some().await {
                    return address;
                }
            }
        })
        .await
        .expect("relay listen timeout");
        relay.add_external_address(relay_addr.clone());
        let relay_addr = relay_addr.with(Protocol::P2p(*relay.local_peer_id()));
        Lab {
            relay,
            relay_addr,
            guard,
        }
    }

    fn endpoint(seed: u8) -> Swarm<EndpointBehaviour> {
        build_endpoint_swarm(&gate(), key(seed), EndpointConfig::default()).unwrap()
    }

    /// Drive the relay (feeding the guard) and the endpoints until `done`
    /// picks a value: from an endpoint event (`Some((index, event))`), or on a
    /// 50 ms tick (`None`). At most 15 s.
    async fn drive<T>(
        lab: &mut Lab,
        eps: &mut [&mut Swarm<EndpointBehaviour>],
        mut done: impl FnMut(Option<(usize, SwarmEvent<EndpointBehaviourEvent>)>) -> Option<T>,
    ) -> T {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let mut next = futures::future::select_all(
                    eps.iter_mut()
                        .map(|s| Box::pin(s.select_next_some()))
                        .collect::<Vec<_>>(),
                );
                tokio::select! {
                    event = lab.relay.select_next_some() => {
                        if let SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(e)) = &event {
                            lab.guard.on_relay_event(e);
                        }
                    }
                    (event, i, _) = &mut next => {
                        if let Some(v) = done(Some((i, event))) {
                            return v;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {
                        if let Some(v) = done(None) {
                            return v;
                        }
                    }
                }
            }
        })
        .await
        .expect("relay lab timed out")
    }

    fn reserve(ep: &mut Swarm<EndpointBehaviour>, relay: &Multiaddr) {
        ep.listen_on(relay.clone().with(Protocol::P2pCircuit))
            .expect("reservation listen");
    }

    fn accepted(event: &SwarmEvent<EndpointBehaviourEvent>) -> bool {
        matches!(
            event,
            SwarmEvent::Behaviour(EndpointBehaviourEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted { .. }
            ))
        )
    }

    /// C10 end to end: an allow-listed peer gets a reservation; a peer that
    /// is not on the list is refused (its reservation listener closes) and
    /// the relay counts the refusal.
    #[tokio::test]
    async fn a_peer_off_the_allow_list_cannot_reserve() {
        let mut ok = endpoint(0xB1);
        let mut stranger = endpoint(0xB2);
        let policy = AllowPolicy::Peers([*ok.local_peer_id()].into_iter().collect());
        let mut lab = relay_lab(RelayLimits::friends(), policy).await;
        let relay_addr = lab.relay_addr.clone();
        reserve(&mut ok, &relay_addr);
        drive(&mut lab, &mut [&mut ok], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        reserve(&mut stranger, &relay_addr);
        drive(&mut lab, &mut [&mut ok, &mut stranger], |e| {
            let (i, e) = e?;
            assert!(!(i == 1 && accepted(&e)), "stranger got a reservation");
            (i == 1 && matches!(e, SwarmEvent::ListenerClosed { .. })).then_some(())
        })
        .await;
        let c = lab.guard.counts();
        assert_eq!(c.refused_not_allowed, 1);
        assert_eq!(c.active_reservations, 1);
    }

    /// Open a `/raven/link/1.0.0` stream from `b` to `a` (reserved on the
    /// relay) over the circuit, and return both ends.
    async fn circuit_stream(
        lab: &mut Lab,
        a: &mut Swarm<EndpointBehaviour>,
        b: &mut Swarm<EndpointBehaviour>,
    ) -> (libp2p::Stream, libp2p::Stream) {
        let a_peer = *a.local_peer_id();
        let mut incoming = a
            .behaviour()
            .stream
            .new_control()
            .accept(RAVEN_LINK_PROTOCOL)
            .unwrap();
        let mut control = b.behaviour().stream.new_control();
        let circuit = lab
            .relay_addr
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(a_peer));
        b.dial(circuit).unwrap();
        let opened = tokio::spawn(async move {
            control
                .open_stream(a_peer, RAVEN_LINK_PROTOCOL)
                .await
                .map_err(|e| e.to_string())
        });
        let accepted_stream = tokio::spawn(async move { incoming.next().await.map(|(_, s)| s) });
        drive(lab, &mut [a, b], |_| {
            (opened.is_finished() && accepted_stream.is_finished()).then_some(())
        })
        .await;
        let out = opened.await.unwrap().expect("open stream over the circuit");
        let inn = accepted_stream.await.unwrap().expect("inbound stream");
        (out, inn)
    }

    /// C10: a circuit that carries more than `max_circuit_bytes` is cut by
    /// the relay; well below the cap the bytes flow.
    #[tokio::test]
    async fn circuit_byte_cap_cuts_the_circuit() {
        let limits = RelayLimits {
            max_circuit_bytes: 64 << 10,
            ..RelayLimits::friends()
        };
        let mut a = endpoint(0xC1);
        let mut b = endpoint(0xC2);
        let mut lab = relay_lab(limits, AllowPolicy::Open).await;
        let relay_addr = lab.relay_addr.clone();
        reserve(&mut a, &relay_addr);
        drive(&mut lab, &mut [&mut a], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        let (mut out, mut inn) = circuit_stream(&mut lab, &mut a, &mut b).await;
        // Small exchange first: within the cap.
        let pump = tokio::spawn(async move {
            out.write_all(b"ping").await.unwrap();
            out.flush().await.unwrap();
            let mut buf = [0u8; 4];
            inn.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            // Now far beyond the cap: the relay closes the circuit.
            let chunk = vec![0x5a; 16 << 10];
            let writer = async {
                for _ in 0..64 {
                    if out.write_all(&chunk).await.is_err() || out.flush().await.is_err() {
                        return true;
                    }
                }
                false
            };
            let reader = async {
                let mut total = 0usize;
                let mut buf = vec![0u8; 16 << 10];
                loop {
                    match inn.read(&mut buf).await {
                        Ok(0) | Err(_) => return total,
                        Ok(n) => total += n,
                    }
                }
            };
            let (write_failed, received) = futures::join!(writer, reader);
            (write_failed, received)
        });
        drive(&mut lab, &mut [&mut a, &mut b], |_| {
            pump.is_finished().then_some(())
        })
        .await;
        let (write_failed, received) = pump.await.unwrap();
        assert!(received < 64 * (16 << 10), "the whole megabyte got through");
        assert!(received <= (64 << 10) + (16 << 10), "received {received}");
        let _ = write_failed;
    }

    /// C10: a circuit that lives longer than `max_circuit_duration` is closed
    /// by the relay.
    #[tokio::test]
    async fn circuit_duration_cap_closes_the_circuit() {
        let limits = RelayLimits {
            max_circuit_duration: Duration::from_secs(2),
            ..RelayLimits::friends()
        };
        let mut a = endpoint(0xD1);
        let mut b = endpoint(0xD2);
        let mut lab = relay_lab(limits, AllowPolicy::Open).await;
        let relay_addr = lab.relay_addr.clone();
        reserve(&mut a, &relay_addr);
        drive(&mut lab, &mut [&mut a], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        let started = std::time::Instant::now();
        let (_out, mut inn) = circuit_stream(&mut lab, &mut a, &mut b).await;
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                match inn.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        });
        drive(&mut lab, &mut [&mut a, &mut b], |_| {
            reader.is_finished().then_some(())
        })
        .await;
        let lived = started.elapsed();
        assert!(
            lived >= Duration::from_secs(1),
            "closed too early: {lived:?}"
        );
        assert!(lived < Duration::from_secs(12), "not closed: {lived:?}");
    }

    /// Review item 3: the rate table of an `--open` relay is bounded (the
    /// oldest source goes first) and pruned on the timer, not on every
    /// request.
    #[test]
    fn rate_tables_are_bounded_and_pruned_on_the_timer() {
        let limits = RelayLimits {
            reservation_rate_per_ip_per_min: 60,
            circuit_rate_per_ip_per_min: 60,
            max_reservations: 1024,
            max_reservations_per_ip: 16,
            exempt_loopback: false,
            ..RelayLimits::open()
        };
        let guard = RelayGuard::new(AllowPolicy::Open, &limits);
        let t0 = Instant::now();
        let src = |i: usize| {
            addr(&format!(
                "/ip4/10.{}.{}.{}/tcp/1",
                i >> 16,
                (i >> 8) & 0xff,
                i & 0xff
            ))
        };
        for i in 0..(MAX_RATE_SOURCES + 100) {
            let _ = guard.admit_circuit_at(&src(i), t0);
        }
        assert_eq!(guard.rate_sources().1, MAX_RATE_SOURCES, "bounded");
        // The oldest were forgotten: they get a fresh, full bucket again.
        for _ in 0..60 {
            assert!(guard.admit_circuit_at(&src(0), t0));
        }
        assert!(
            !guard.admit_circuit_at(&src(0), t0),
            "now that one is spent"
        );
        // Pruning keeps the buckets that are still refilling, drops full ones.
        guard.prune_at(t0 + Duration::from_secs(1));
        assert!(guard.rate_sources().1 >= 1);
        guard.prune_at(t0 + Duration::from_secs(120));
        assert_eq!(guard.rate_sources(), (0, 0));
        // IPv6: one /64 is one source (libp2p's own limiter keys on /128).
        let small = RelayLimits {
            circuit_rate_per_ip_per_min: 2,
            exempt_loopback: false,
            ..RelayLimits::friends()
        };
        let g = RelayGuard::new(AllowPolicy::Open, &small);
        assert!(g.admit_circuit_at(&addr("/ip6/2001:db8:1:2::1/tcp/1"), t0));
        assert!(g.admit_circuit_at(&addr("/ip6/2001:db8:1:2::2/tcp/1"), t0));
        assert!(!g.admit_circuit_at(&addr("/ip6/2001:db8:1:2:ffff::3/tcp/1"), t0));
        assert!(g.admit_circuit_at(&addr("/ip6/2001:db8:1:3::1/tcp/1"), t0));
        assert_eq!(g.counts().refused_circuit_rate, 1);
    }

    #[test]
    fn global_addresses_and_what_a_relay_may_name() {
        for ip in [
            "8.8.8.8",
            "203.0.114.1",
            "2606:4700::1111",
            "::ffff:8.8.4.4",
        ] {
            assert!(is_global_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "10.0.0.1",
            "192.168.1.2",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "203.0.113.7",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "ff02::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(!is_global_ip(ip.parse().unwrap()), "{ip}");
        }
        let lan = addr("/ip4/192.168.1.5/tcp/7423");
        let public = addr("/ip4/8.8.8.8/tcp/7423");
        assert!(
            !relay_may_advertise(&lan, false),
            "wildcard listen: no LAN address"
        );
        assert!(relay_may_advertise(&lan, true), "the operator chose it");
        assert!(relay_may_advertise(&public, false));
        assert!(!relay_may_advertise(&addr("/ip4/127.0.0.1/tcp/1"), false));
        let circuit = addr(
            "/ip4/8.8.8.8/tcp/1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit",
        );
        assert!(!relay_may_advertise(&circuit, true));
    }

    /// Review item 4: the AutoNAT v2 server's dial-back can only reach
    /// globally routable addresses.
    #[test]
    fn dial_backs_reach_only_global_addresses() {
        let mut guard = DialBackGuard::default();
        let deny = |g: &mut DialBackGuard, a: &str| {
            g.handle_pending_outbound_connection(
                ConnectionId::new_unchecked(1),
                None,
                &[addr(a)],
                Endpoint::Dialer,
            )
            .is_err()
        };
        assert!(deny(&mut guard, "/ip4/127.0.0.1/tcp/22"));
        assert!(deny(&mut guard, "/ip4/192.168.1.1/tcp/80"));
        assert!(deny(&mut guard, "/ip6/::1/udp/53/quic-v1"));
        assert!(deny(&mut guard, "/dns4/localhost/tcp/80"));
        assert!(!deny(&mut guard, "/ip4/8.8.8.8/tcp/7423"));
        assert!(guard
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(2),
                None,
                &[],
                Endpoint::Dialer,
            )
            .is_err());
        assert_eq!(guard.refused(), 5);
    }

    /// Review item 1: Identify never sends a host's listen addresses (here a
    /// loopback one); only confirmed external addresses go out.
    #[tokio::test]
    async fn identify_does_not_publish_listen_addresses() {
        let mut a = endpoint(0xE1);
        let mut b = endpoint(0xE2);
        a.listen_on(addr("/ip4/127.0.0.1/tcp/0")).unwrap();
        let a_addr = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = a.select_next_some().await {
                    return address;
                }
            }
        })
        .await
        .unwrap();
        let confirmed = addr("/ip4/8.8.8.8/tcp/7423");
        a.add_external_address(confirmed.clone());
        b.dial(a_addr.clone().with(Protocol::P2p(*a.local_peer_id())))
            .unwrap();
        let info = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    _ = a.select_next_some() => {}
                    event = b.select_next_some() => {
                        if let SwarmEvent::Behaviour(EndpointBehaviourEvent::Identify(
                            identify::Event::Received { info, .. },
                        )) = event
                        {
                            return info;
                        }
                    }
                }
            }
        })
        .await
        .expect("identify info");
        assert!(
            !info.listen_addrs.contains(&a_addr),
            "listen address leaked: {:?}",
            info.listen_addrs
        );
        assert!(info
            .listen_addrs
            .iter()
            .all(|x| addr_ip(x).is_none_or(|ip| !ip.is_loopback())));
        assert!(
            info.listen_addrs.contains(&confirmed),
            "{:?}",
            info.listen_addrs
        );
        assert_eq!(info.agent_version, AGENT_VERSION);
    }

    /// Review items 10/11: the limits are asked first, and inbound
    /// connections can never take the slots our own dials need.
    #[test]
    fn limits_come_first_and_outbound_keeps_a_reserve() {
        const {
            assert!(ENDPOINT_MAX_ESTABLISHED > OUTBOUND_RESERVE);
        }
        RelayLimits::friends().validate().unwrap();
        let tiny = RelayLimits {
            max_established: OUTBOUND_RESERVE,
            max_established_per_ip: 1,
            ..RelayLimits::friends()
        };
        assert!(tiny.validate().is_err(), "no room left for our own dials");
        // Field order is the admission order of the derive (see the type docs).
        let src = include_str!("host.rs");
        for name in [
            "pub struct EndpointBehaviour {",
            "pub struct RelayBehaviour {",
        ] {
            let at = src.find(name).expect("struct");
            let body = &src[at..at + 200];
            let first = body.lines().nth(1).unwrap_or_default().trim();
            assert_eq!(first, "limits: connection_limits::Behaviour,", "{name}");
        }
    }

    /// Review item 6: a port another program holds is found before libp2p
    /// (which sets SO_REUSEADDR / SO_REUSEPORT) would share it; a free one is
    /// not.
    #[tokio::test]
    async fn a_busy_port_is_found_before_libp2p_binds_it() {
        // Another libp2p host on a fixed port, TCP and QUIC.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let tcp = addr(&format!("/ip4/127.0.0.1/tcp/{port}"));
        let quic = addr(&format!("/ip4/127.0.0.1/udp/{port}/quic-v1"));
        assert_eq!(probe_listen_addr(&tcp), Ok(()));
        let mut other = endpoint(0xF1);
        other.listen_on(tcp.clone()).unwrap();
        other.listen_on(quic.clone()).unwrap();
        let mut seen = 0;
        tokio::time::timeout(Duration::from_secs(5), async {
            while seen < 2 {
                if let SwarmEvent::NewListenAddr { .. } = other.select_next_some().await {
                    seen += 1;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(probe_listen_addr(&tcp), Err(ListenProbe::Busy));
        assert_eq!(probe_listen_addr(&quic), Err(ListenProbe::Busy));
        assert_eq!(listen_port_label(&tcp), format!("{port}/tcp"));
        assert_eq!(listen_port_label(&quic), format!("{port}/udp"));
        // Port 0 and addresses without a port are never probed.
        assert_eq!(probe_listen_addr(&addr("/ip4/127.0.0.1/tcp/0")), Ok(()));
        // An address this host does not have.
        assert_eq!(
            probe_listen_addr(&addr("/ip4/203.0.113.7/tcp/7423")),
            Err(ListenProbe::Unavailable)
        );
    }

    /// Review items 1/14: a relaying host names only global (or explicitly
    /// chosen) addresses, a loopback placeholder otherwise, and withdraws
    /// expired ones.
    #[tokio::test]
    async fn a_relay_advertises_only_what_it_may_and_withdraws_expired() {
        let mut swarm = endpoint(0xF2);
        let ext = |s: &Swarm<EndpointBehaviour>| -> Vec<Multiaddr> {
            s.external_addresses().cloned().collect()
        };
        let mut adv = RelayAdvertiser::new(&mut swarm, false, &[]);
        let lan = addr("/ip4/192.168.1.5/tcp/7423");
        let lo = addr("/ip4/127.0.0.1/tcp/7423");
        let public = addr("/ip4/8.8.8.8/tcp/7423");
        adv.on_new_listen_addr(&mut swarm, &lan);
        assert!(
            ext(&swarm).is_empty(),
            "no LAN address under a wildcard listen"
        );
        adv.on_new_listen_addr(&mut swarm, &lo);
        assert_eq!(ext(&swarm), vec![lo.clone()]);
        assert!(adv.placeholder_only());
        adv.on_new_listen_addr(&mut swarm, &public);
        assert_eq!(
            ext(&swarm),
            vec![public.clone()],
            "the placeholder is replaced"
        );
        adv.on_expired_listen_addr(&mut swarm, &public);
        assert!(ext(&swarm).is_empty(), "expired addresses are withdrawn");
        // A specific listen address (the operator chose it) is advertised.
        let mut specific = endpoint(0xF3);
        let mut adv = RelayAdvertiser::new(&mut specific, true, &[]);
        adv.on_new_listen_addr(&mut specific, &lan);
        assert_eq!(ext(&specific), vec![lan.clone()]);
        // --external wins over everything else.
        let mut explicit = endpoint(0xF4);
        let named = addr("/dns4/relay.example.com/tcp/7423");
        let mut adv = RelayAdvertiser::new(&mut explicit, false, std::slice::from_ref(&named));
        adv.on_new_listen_addr(&mut explicit, &public);
        assert_eq!(ext(&explicit), vec![named]);
        assert!(!adv.placeholder_only());
    }

    #[test]
    fn circuit_addresses_are_recognised() {
        assert!(is_circuit(&addr(
            "/ip4/127.0.0.1/tcp/1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit"
        )));
        assert!(!is_circuit(&addr("/ip4/127.0.0.1/tcp/1")));
    }
}
