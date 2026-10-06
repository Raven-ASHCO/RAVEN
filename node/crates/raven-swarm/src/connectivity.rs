//! Bounded, experimental NAT traversal composition for Raven.
//!
//! This module is not part of default builds. Enabling the Cargo feature only
//! makes the reusable profile available; the companion binary also requires a
//! separate runtime acknowledgement. It never contains a bootstrap, relay, or
//! AutoNAT server address.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::num::{NonZeroU8, NonZeroUsize};
use std::time::Duration;

use libp2p::connection_limits::{self, ConnectionLimits};
use libp2p::core::transport::ListenerId;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{ConnectionId, NetworkBehaviour};
use libp2p::{
    autonat, dcutr, identify, noise, ping, relay, tcp, yamux, Multiaddr, Swarm, SwarmBuilder,
};
use rand::rngs::OsRng;
use tokio::time::Instant;

use crate::ip_limits::{IpLimitConfig, IpLimits};
use crate::liveness::reconnect_delay;

/// Default/release Raven binaries do not instantiate this behaviour.
pub const PRODUCTION_NAT_CONNECTIVITY_ENABLED: bool = false;
pub const IDENTIFY_PROTOCOL_V1: &str = "/raven/connectivity/1.0.0";

pub const MAX_PENDING_CONNECTIONS: u32 = 64;
pub const MAX_ESTABLISHED_CONNECTIONS: u32 = 128;
pub const MAX_CONNECTIONS_PER_PEER: u32 = 4;
pub const MAX_AUTONAT_CANDIDATES: usize = 16;

/// Every dimension is finite. A value of zero deliberately disables that
/// direction, which is useful for a receive-only or dial-only experiment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionBudget {
    pub pending_incoming: u32,
    pub pending_outgoing: u32,
    pub established_incoming: u32,
    pub established_outgoing: u32,
    pub established_total: u32,
    pub established_per_peer: u32,
    /// Inbound connections one source address may still be upgrading. PeerIds
    /// are free, so `established_per_peer` alone does not stop one host.
    pub pending_incoming_per_ip: u32,
    /// Inbound connections one source address may hold open (loopback is
    /// exempt; see [`crate::ip_limits`]).
    pub established_incoming_per_ip: u32,
}

impl Default for ConnectionBudget {
    fn default() -> Self {
        Self {
            pending_incoming: 8,
            pending_outgoing: 8,
            established_incoming: 24,
            established_outgoing: 16,
            established_total: 32,
            established_per_peer: 2,
            pending_incoming_per_ip: 2,
            established_incoming_per_ip: 8,
        }
    }
}

impl ConnectionBudget {
    fn validate(self) -> Result<(), ConnectivityConfigError> {
        if self.pending_incoming > MAX_PENDING_CONNECTIONS
            || self.pending_outgoing > MAX_PENDING_CONNECTIONS
        {
            return Err(ConnectivityConfigError::new(
                "pending connection budget exceeds hard maximum",
            ));
        }
        if self.established_incoming > MAX_ESTABLISHED_CONNECTIONS
            || self.established_outgoing > MAX_ESTABLISHED_CONNECTIONS
            || self.established_total > MAX_ESTABLISHED_CONNECTIONS
        {
            return Err(ConnectivityConfigError::new(
                "established connection budget exceeds hard maximum",
            ));
        }
        if self.pending_incoming_per_ip > MAX_PENDING_CONNECTIONS {
            return Err(ConnectivityConfigError::new(
                "pending connection budget exceeds hard maximum",
            ));
        }
        if self.established_incoming_per_ip > MAX_ESTABLISHED_CONNECTIONS {
            return Err(ConnectivityConfigError::new(
                "established connection budget exceeds hard maximum",
            ));
        }
        if self.established_per_peer > MAX_CONNECTIONS_PER_PEER {
            return Err(ConnectivityConfigError::new(
                "per-peer connection budget exceeds hard maximum",
            ));
        }
        if self.established_per_peer > self.established_total {
            return Err(ConnectivityConfigError::new(
                "per-peer connection budget exceeds total budget",
            ));
        }
        Ok(())
    }

    fn into_behaviour(self) -> connection_limits::Behaviour {
        let limits = ConnectionLimits::default()
            .with_max_pending_incoming(Some(self.pending_incoming))
            .with_max_pending_outgoing(Some(self.pending_outgoing))
            .with_max_established_incoming(Some(self.established_incoming))
            .with_max_established_outgoing(Some(self.established_outgoing))
            .with_max_established(Some(self.established_total))
            .with_max_established_per_peer(Some(self.established_per_peer));
        connection_limits::Behaviour::new(limits)
    }

    fn into_ip_limits(self) -> IpLimits {
        IpLimits::new(IpLimitConfig {
            max_pending_per_ip: self.pending_incoming_per_ip,
            max_established_per_ip: self.established_incoming_per_ip,
            ..IpLimitConfig::default()
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectivityProfile {
    pub connections: ConnectionBudget,
    pub connection_timeout: Duration,
    pub idle_connection_timeout: Duration,
    /// Ping only *reports* a dead connection (an `Err` event after two
    /// consecutive failures); it never closes one, and a relay client keeps
    /// its relay connection alive while a reservation exists, so the idle
    /// timeout does not reap it either. The application must close on the
    /// report: see [`crate::liveness::close_if_dead`].
    pub ping_interval: Duration,
    pub ping_timeout: Duration,
    pub identify_interval: Duration,
    pub autonat_probe_interval: Duration,
    pub autonat_max_candidates: usize,
}

impl Default for ConnectivityProfile {
    fn default() -> Self {
        Self {
            connections: ConnectionBudget::default(),
            connection_timeout: Duration::from_secs(10),
            idle_connection_timeout: Duration::from_secs(90),
            ping_interval: Duration::from_secs(15),
            ping_timeout: Duration::from_secs(5),
            identify_interval: Duration::from_secs(60),
            autonat_probe_interval: Duration::from_secs(30),
            autonat_max_candidates: 8,
        }
    }
}

impl ConnectivityProfile {
    pub fn validate(&self) -> Result<(), ConnectivityConfigError> {
        self.connections.validate()?;
        if self.connection_timeout.is_zero()
            || self.idle_connection_timeout.is_zero()
            || self.ping_interval.is_zero()
            || self.ping_timeout.is_zero()
            || self.identify_interval.is_zero()
            || self.autonat_probe_interval.is_zero()
        {
            return Err(ConnectivityConfigError::new(
                "connectivity durations must be nonzero",
            ));
        }
        if self.ping_timeout >= self.ping_interval {
            return Err(ConnectivityConfigError::new(
                "ping timeout must be shorter than ping interval",
            ));
        }
        if self.autonat_max_candidates == 0 || self.autonat_max_candidates > MAX_AUTONAT_CANDIDATES
        {
            return Err(ConnectivityConfigError::new(
                "AutoNAT candidate budget is outside the hard range",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectivityConfigError {
    message: &'static str,
}

impl ConnectivityConfigError {
    const fn new(message: &'static str) -> Self {
        Self { message }
    }

    pub const fn message(self) -> &'static str {
        self.message
    }
}

impl fmt::Display for ConnectivityConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for ConnectivityConfigError {}

/// The feature gate is intentionally insufficient on its own. Callers that
/// expose the experiment must collect a distinct runtime acknowledgement.
pub fn require_experimental_runtime_opt_in(
    acknowledged: bool,
) -> Result<(), ConnectivityConfigError> {
    if acknowledged {
        Ok(())
    } else {
        Err(ConnectivityConfigError::new(
            "experimental NAT connectivity requires explicit runtime opt-in",
        ))
    }
}

/// Convert an operator-supplied relay address ending in `/p2p/<peer>` into a
/// reservation listener. Raven ships no relay address and never selects one
/// implicitly.
pub fn relay_reservation_address(
    relay_address: &Multiaddr,
) -> Result<Multiaddr, ConnectivityConfigError> {
    let mut peer_components = 0usize;
    let mut last_is_peer = false;
    for component in relay_address.iter() {
        if matches!(component, Protocol::P2pCircuit) {
            return Err(ConnectivityConfigError::new(
                "relay address already contains p2p-circuit",
            ));
        }
        if matches!(component, Protocol::P2p(_)) {
            peer_components += 1;
            last_is_peer = true;
        } else {
            last_is_peer = false;
        }
    }
    if peer_components != 1 || !last_is_peer {
        return Err(ConnectivityConfigError::new(
            "relay address must end in exactly one p2p peer component",
        ));
    }
    let mut reservation = relay_address.clone();
    reservation.push(Protocol::P2pCircuit);
    Ok(reservation)
}

/// An operator-supplied `--dial` address must end in `/p2p/<peer>`: without it
/// libp2p accepts whichever identity completes the handshake, so a path
/// attacker or a wrong host would be treated as the intended peer. This works
/// for direct addresses and for circuit addresses
/// (`.../p2p/<relay>/p2p-circuit/p2p/<target>`), where the last component
/// pins the target.
pub fn require_terminal_peer(address: &Multiaddr) -> Result<(), ConnectivityConfigError> {
    match address.iter().last() {
        Some(Protocol::P2p(_)) => Ok(()),
        _ => Err(ConnectivityConfigError::new(
            "dial address must end in a /p2p/<peer> component",
        )),
    }
}

/// Keeps one operator-supplied relay reservation alive.
///
/// libp2p closes the reservation listener (`SwarmEvent::ListenerClosed`) when
/// the relay connection drops or a renewal fails, and nothing re-requests it:
/// without this the node silently loses its `/p2p-circuit` address for the
/// rest of the run. Only the listener returned by [`Self::request`] counts, so
/// a closing TCP or QUIC listener never triggers a spurious re-reservation,
/// and the retry is armed once per loss (libp2p also reports an expired
/// address and a closed connection for the same drop).
#[derive(Debug)]
pub struct ReservationKeeper {
    address: Multiaddr,
    listener: Option<ListenerId>,
    attempt: u32,
    retry_at: Option<Instant>,
}

impl ReservationKeeper {
    /// `relay_address` is the operator's relay ending in `/p2p/<relay>`.
    pub fn new(relay_address: &Multiaddr) -> Result<Self, ConnectivityConfigError> {
        Ok(Self {
            address: relay_reservation_address(relay_address)?,
            listener: None,
            attempt: 0,
            retry_at: None,
        })
    }

    /// Request (or re-request) the reservation. Returns `false` when the
    /// transport refused the request outright; a retry is then already armed.
    pub fn request<B: NetworkBehaviour>(
        &mut self,
        swarm: &mut Swarm<B>,
        now: Instant,
        jitter: f64,
    ) -> bool {
        self.retry_at = None;
        match swarm.listen_on(self.address.clone()) {
            Ok(listener) => {
                self.listener = Some(listener);
                true
            }
            Err(_) => {
                self.listener = None;
                self.arm_retry(now, jitter);
                false
            }
        }
    }

    /// Feed every `SwarmEvent::ListenerClosed`. Returns the retry delay when
    /// `listener` was the reservation listener, `None` for any other listener.
    pub fn on_listener_closed(
        &mut self,
        listener: ListenerId,
        now: Instant,
        jitter: f64,
    ) -> Option<Duration> {
        if self.listener != Some(listener) {
            return None;
        }
        self.listener = None;
        Some(self.arm_retry(now, jitter))
    }

    /// The relay accepted (or renewed) the reservation: start the backoff over.
    pub fn on_reservation_accepted(&mut self) {
        self.attempt = 0;
    }

    /// When the next [`Self::request`] is due, if one is waiting.
    pub fn retry_at(&self) -> Option<Instant> {
        self.retry_at
    }

    pub fn retry_due(&self, now: Instant) -> bool {
        self.retry_at.is_some_and(|at| at <= now)
    }

    fn arm_retry(&mut self, now: Instant, jitter: f64) -> Duration {
        let delay = reconnect_delay(self.attempt, jitter);
        self.attempt = self.attempt.saturating_add(1);
        self.retry_at = Some(now + delay);
        delay
    }
}

/// Attempts per operator-supplied dial (the first plus its retries).
pub const MAX_DIAL_ATTEMPTS: u32 = 4;

/// What became of a failed operator dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialOutcome {
    /// Not an operator dial (a dial libp2p made itself, e.g. to the relay).
    NotTracked,
    /// A retry is armed after the given delay.
    Retrying(Duration),
    /// Attempts are exhausted; the dial is dropped.
    GaveUp,
}

struct TrackedDial {
    address: Multiaddr,
    /// Failures so far.
    failures: u32,
}

/// Bounded retries for the operator's `--dial` addresses. A failed first dial
/// used to be final; now it is retried with capped, jittered backoff up to
/// [`MAX_DIAL_ATTEMPTS`] times so the connection budget stays a hard limit.
#[derive(Default)]
pub struct OperatorDials {
    in_flight: HashMap<ConnectionId, TrackedDial>,
    waiting: Vec<(Instant, TrackedDial)>,
}

impl OperatorDials {
    /// Start tracking `address` and dial it.
    pub fn start<B: NetworkBehaviour>(
        &mut self,
        swarm: &mut Swarm<B>,
        address: Multiaddr,
    ) -> Result<(), libp2p::swarm::DialError> {
        self.dial(
            swarm,
            TrackedDial {
                address,
                failures: 0,
            },
        )
    }

    fn dial<B: NetworkBehaviour>(
        &mut self,
        swarm: &mut Swarm<B>,
        dial: TrackedDial,
    ) -> Result<(), libp2p::swarm::DialError> {
        let opts = DialOpts::unknown_peer_id()
            .address(dial.address.clone())
            .build();
        let connection = opts.connection_id();
        swarm.dial(opts)?;
        self.in_flight.insert(connection, dial);
        Ok(())
    }

    /// Feed `SwarmEvent::ConnectionEstablished`: the dial succeeded.
    pub fn on_established(&mut self, connection: ConnectionId) {
        self.in_flight.remove(&connection);
    }

    /// Feed `SwarmEvent::OutgoingConnectionError`.
    pub fn on_failed(
        &mut self,
        connection: ConnectionId,
        now: Instant,
        jitter: f64,
    ) -> DialOutcome {
        match self.in_flight.remove(&connection) {
            Some(dial) => self.after_failure(dial, now, jitter),
            None => DialOutcome::NotTracked,
        }
    }

    fn after_failure(&mut self, mut dial: TrackedDial, now: Instant, jitter: f64) -> DialOutcome {
        dial.failures += 1;
        if dial.failures >= MAX_DIAL_ATTEMPTS {
            return DialOutcome::GaveUp;
        }
        let delay = reconnect_delay(dial.failures - 1, jitter);
        self.waiting.push((now + delay, dial));
        DialOutcome::Retrying(delay)
    }

    /// Earliest retry still waiting, if any.
    pub fn next_retry(&self) -> Option<Instant> {
        self.waiting.iter().map(|(at, _)| *at).min()
    }

    /// Re-dial everything whose retry is due. A dial the swarm refuses
    /// synchronously (for example over the connection budget) counts as a
    /// failed attempt. Returns how many dials were started.
    pub fn redial_due<B: NetworkBehaviour>(
        &mut self,
        swarm: &mut Swarm<B>,
        now: Instant,
        jitter: f64,
    ) -> usize {
        let (due, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.waiting)
            .into_iter()
            .partition(|(at, _)| *at <= now);
        self.waiting = waiting;
        let mut started = 0;
        for (_, dial) in due {
            let retry = TrackedDial {
                address: dial.address.clone(),
                failures: dial.failures,
            };
            match self.dial(swarm, dial) {
                Ok(()) => started += 1,
                Err(_) => {
                    self.after_failure(retry, now, jitter);
                }
            }
        }
        started
    }

    pub fn is_idle(&self) -> bool {
        self.in_flight.is_empty() && self.waiting.is_empty()
    }
}

/// Relay is client-only and AutoNAT is the v2 client behaviour. There is no
/// relay service or AutoNAT server in this profile.
#[derive(NetworkBehaviour)]
pub struct RavenConnectivityBehaviour {
    pub relay: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub auto_nat: autonat::v2::client::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    limits: connection_limits::Behaviour,
    ip_limits: IpLimits,
}

/// Compose direct TCP and QUIC transports with the relay client transport.
/// TCP and relay streams both use Noise authentication and Yamux; QUIC uses
/// QUIC's authenticated transport security.
pub fn build_connectivity_swarm(
    identity: Keypair,
    profile: ConnectivityProfile,
) -> Result<Swarm<RavenConnectivityBehaviour>, Box<dyn Error + Send + Sync>> {
    profile.validate()?;

    let behaviour_profile = profile.clone();
    let swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(move |key, relay| {
            let local_peer_id = key.public().to_peer_id();
            let auto_nat_config = autonat::v2::client::Config::default()
                .with_max_candidates(behaviour_profile.autonat_max_candidates)
                .with_probe_interval(behaviour_profile.autonat_probe_interval);
            let identify_config =
                identify::Config::new(IDENTIFY_PROTOCOL_V1.to_owned(), key.public())
                    .with_agent_version("raven-connectivity-experimental/1".to_owned())
                    .with_interval(behaviour_profile.identify_interval)
                    .with_push_listen_addr_updates(true)
                    .with_cache_size(64);
            // Ping only reports a dead connection (an `Err` event after two
            // consecutive failures) and never closes one; the application must
            // act on it. See `crate::liveness::close_if_dead`.
            let ping_config = ping::Config::new()
                .with_interval(behaviour_profile.ping_interval)
                .with_timeout(behaviour_profile.ping_timeout);

            RavenConnectivityBehaviour {
                relay,
                dcutr: dcutr::Behaviour::new(local_peer_id),
                auto_nat: autonat::v2::client::Behaviour::new(OsRng, auto_nat_config),
                identify: identify::Behaviour::new(identify_config),
                ping: ping::Behaviour::new(ping_config),
                limits: behaviour_profile.connections.into_behaviour(),
                ip_limits: behaviour_profile.connections.into_ip_limits(),
            }
        })?
        .with_swarm_config(move |config| {
            config
                .with_idle_connection_timeout(profile.idle_connection_timeout)
                .with_notify_handler_buffer_size(
                    NonZeroUsize::new(32).expect("constant is nonzero"),
                )
                .with_per_connection_event_buffer_size(32)
                .with_dial_concurrency_factor(NonZeroU8::new(4).expect("constant is nonzero"))
                .with_max_negotiating_inbound_streams(64)
        })
        .with_connection_timeout(profile.connection_timeout)
        .build();

    Ok(swarm)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::StreamExt;
    use libp2p::identity::Keypair;
    use libp2p::multiaddr::Protocol;
    use libp2p::swarm::SwarmEvent;
    use libp2p::{identify, noise, relay, tcp, yamux, Multiaddr, SwarmBuilder};

    use super::*;

    fn fixed_identity(seed_byte: u8) -> Keypair {
        Keypair::ed25519_from_bytes([seed_byte; 32]).expect("fixed Ed25519 test seed")
    }

    #[derive(NetworkBehaviour)]
    struct TestRelayBehaviour {
        relay: relay::Behaviour,
        identify: identify::Behaviour,
    }

    fn build_test_relay(identity: Keypair) -> Swarm<TestRelayBehaviour> {
        let local_peer_id = identity.public().to_peer_id();
        SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .expect("relay TCP transport")
            .with_behaviour(move |key| TestRelayBehaviour {
                relay: relay::Behaviour::new(
                    local_peer_id,
                    relay::Config {
                        reservation_duration: Duration::from_secs(60),
                        ..Default::default()
                    },
                ),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/raven/connectivity-test-relay/1.0.0".to_owned(),
                    key.public(),
                )),
            })
            .expect("relay behaviour")
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_secs(30))
            })
            .build()
    }

    async fn tcp_listener_for<B>(swarm: &mut Swarm<B>) -> Multiaddr
    where
        B: NetworkBehaviour,
    {
        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("literal multiaddr"))
            .expect("listen request");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                    if address.iter().any(|part| matches!(part, Protocol::Tcp(_))) {
                        return address;
                    }
                }
            }
        })
        .await
        .expect("listener timeout")
    }

    async fn quic_listener(swarm: &mut Swarm<RavenConnectivityBehaviour>) -> Multiaddr {
        swarm
            .listen_on(
                "/ip4/127.0.0.1/udp/0/quic-v1"
                    .parse()
                    .expect("literal multiaddr"),
            )
            .expect("listen request");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                    if address.iter().any(|part| matches!(part, Protocol::QuicV1)) {
                        return address;
                    }
                }
            }
        })
        .await
        .expect("listener timeout")
    }

    async fn assert_nodes_connect(
        listener: &mut Swarm<RavenConnectivityBehaviour>,
        dialer: &mut Swarm<RavenConnectivityBehaviour>,
        address: Multiaddr,
    ) {
        let listener_peer = *listener.local_peer_id();
        dialer
            .dial(address.with(Protocol::P2p(listener_peer)))
            .expect("dial request");

        let connected = tokio::time::timeout(Duration::from_secs(5), async {
            let mut listener_connected = false;
            let mut dialer_connected = false;
            loop {
                tokio::select! {
                    event = listener.select_next_some() => {
                        if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                            listener_connected = true;
                        }
                    }
                    event = dialer.select_next_some() => {
                        if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                            dialer_connected = true;
                        }
                    }
                }
                if listener_connected && dialer_connected {
                    return true;
                }
            }
        })
        .await
        .expect("connection timeout");
        assert!(connected);
    }

    #[test]
    fn runtime_gate_and_default_budgets_are_fixed() {
        assert_eq!(
            require_experimental_runtime_opt_in(false)
                .expect_err("runtime gate")
                .message(),
            "experimental NAT connectivity requires explicit runtime opt-in"
        );
        require_experimental_runtime_opt_in(true).expect("explicit acknowledgement");
        let profile = ConnectivityProfile::default();
        profile.validate().expect("default profile");
        assert_eq!(profile.connections.established_total, 32);
        assert_eq!(profile.connections.established_per_peer, 2);
        assert_eq!(profile.connections.pending_incoming_per_ip, 2);
        assert_eq!(profile.connections.established_incoming_per_ip, 8);
        assert_eq!(profile.autonat_max_candidates, 8);
    }

    #[test]
    fn operator_dials_must_pin_a_peer_id() {
        let peer = fixed_identity(0x32).public().to_peer_id();
        let relay = fixed_identity(0x33).public().to_peer_id();
        let ok = |text: String| require_terminal_peer(&text.parse().expect("address")).is_ok();

        assert!(ok(format!("/ip4/203.0.113.7/tcp/4001/p2p/{peer}")));
        assert!(ok(format!("/ip4/203.0.113.7/udp/4001/quic-v1/p2p/{peer}")));
        // Circuit dial: the last component pins the target, not the relay.
        assert!(ok(format!(
            "/ip4/203.0.113.7/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{peer}"
        )));

        assert!(!ok("/ip4/203.0.113.7/tcp/4001".to_owned()));
        assert!(!ok(format!("/ip4/203.0.113.7/tcp/4001/p2p/{peer}/tcp/1")));
        // A circuit address that does not name its target is not pinned.
        assert!(!ok(format!(
            "/ip4/203.0.113.7/tcp/4001/p2p/{relay}/p2p-circuit"
        )));
        assert_eq!(
            require_terminal_peer(&Multiaddr::empty())
                .expect_err("empty address")
                .message(),
            "dial address must end in a /p2p/<peer> component"
        );
    }

    #[test]
    fn relay_reservation_is_operator_supplied_and_canonical() {
        let relay_peer = fixed_identity(0x31).public().to_peer_id();
        let relay: Multiaddr = format!("/ip4/127.0.0.1/tcp/41001/p2p/{relay_peer}")
            .parse()
            .expect("relay address");
        let reservation = relay_reservation_address(&relay).expect("reservation address");
        assert!(matches!(
            reservation.iter().last(),
            Some(Protocol::P2pCircuit)
        ));

        assert!(relay_reservation_address(
            &"/ip4/127.0.0.1/tcp/41001"
                .parse()
                .expect("address without peer")
        )
        .is_err());
        assert!(relay_reservation_address(&reservation).is_err());
    }

    #[test]
    fn unsafe_budget_and_timing_are_rejected() {
        let mut profile = ConnectivityProfile::default();
        profile.connections.pending_outgoing = MAX_PENDING_CONNECTIONS + 1;
        assert_eq!(
            profile
                .validate()
                .expect_err("oversized pending budget")
                .message(),
            "pending connection budget exceeds hard maximum"
        );

        let mut profile = ConnectivityProfile::default();
        profile.connections.established_per_peer = MAX_CONNECTIONS_PER_PEER + 1;
        assert_eq!(
            profile
                .validate()
                .expect_err("oversized peer budget")
                .message(),
            "per-peer connection budget exceeds hard maximum"
        );

        let mut profile = ConnectivityProfile::default();
        profile.connections.pending_incoming_per_ip = MAX_PENDING_CONNECTIONS + 1;
        assert_eq!(
            profile
                .validate()
                .expect_err("oversized per-address pending budget")
                .message(),
            "pending connection budget exceeds hard maximum"
        );

        let mut profile = ConnectivityProfile::default();
        profile.connections.established_incoming_per_ip = MAX_ESTABLISHED_CONNECTIONS + 1;
        assert_eq!(
            profile
                .validate()
                .expect_err("oversized per-address established budget")
                .message(),
            "established connection budget exceeds hard maximum"
        );

        let mut profile = ConnectivityProfile::default();
        profile.ping_timeout = profile.ping_interval;
        assert_eq!(
            profile
                .validate()
                .expect_err("invalid ping timing")
                .message(),
            "ping timeout must be shorter than ping interval"
        );
    }

    #[tokio::test]
    async fn fixed_localhost_nodes_connect_over_noise_tcp() {
        let mut listener =
            build_connectivity_swarm(fixed_identity(0x41), ConnectivityProfile::default())
                .expect("listener swarm");
        let mut dialer =
            build_connectivity_swarm(fixed_identity(0x42), ConnectivityProfile::default())
                .expect("dialer swarm");

        let address = tcp_listener_for(&mut listener).await;
        assert_nodes_connect(&mut listener, &mut dialer, address).await;
    }

    #[tokio::test]
    async fn fixed_localhost_nodes_connect_over_authenticated_quic() {
        let mut listener =
            build_connectivity_swarm(fixed_identity(0x45), ConnectivityProfile::default())
                .expect("listener swarm");
        let mut dialer =
            build_connectivity_swarm(fixed_identity(0x46), ConnectivityProfile::default())
                .expect("dialer swarm");

        let address = quic_listener(&mut listener).await;
        assert_nodes_connect(&mut listener, &mut dialer, address).await;
    }

    #[tokio::test]
    async fn operator_supplied_local_relay_accepts_a_client_reservation() {
        let mut relay = build_test_relay(fixed_identity(0x61));
        let relay_peer = *relay.local_peer_id();
        let relay_address = tcp_listener_for(&mut relay).await;
        relay.add_external_address(relay_address.clone());

        let mut client =
            build_connectivity_swarm(fixed_identity(0x62), ConnectivityProfile::default())
                .expect("client swarm");
        let _client_direct_address = tcp_listener_for(&mut client).await;
        let relay_dial_address = relay_address.with(Protocol::P2p(relay_peer));
        let reservation = relay_reservation_address(&relay_dial_address)
            .expect("operator relay reservation address");
        client
            .listen_on(reservation)
            .expect("relay reservation request");

        let accepted = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    _ = relay.select_next_some() => {}
                    event = client.select_next_some() => {
                        if matches!(
                            event,
                            SwarmEvent::Behaviour(RavenConnectivityBehaviourEvent::Relay(
                                relay::client::Event::ReservationReqAccepted {
                                    renewal: false,
                                    ..
                                }
                            ))
                        ) {
                            return true;
                        }
                    }
                }
            }
        })
        .await
        .expect("relay reservation timeout");
        assert!(accepted);
    }

    #[tokio::test]
    async fn zero_pending_inbound_budget_rejects_localhost_dial() {
        let mut listener_profile = ConnectivityProfile::default();
        listener_profile.connections.pending_incoming = 0;
        let mut listener = build_connectivity_swarm(fixed_identity(0x51), listener_profile)
            .expect("listener swarm");
        let mut dialer =
            build_connectivity_swarm(fixed_identity(0x52), ConnectivityProfile::default())
                .expect("dialer swarm");

        let listener_peer = *listener.local_peer_id();
        let address = tcp_listener_for(&mut listener).await;
        dialer
            .dial(address.with(Protocol::P2p(listener_peer)))
            .expect("dial request");

        let rejected = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    event = listener.select_next_some() => {
                        if matches!(event, SwarmEvent::IncomingConnectionError { .. }) {
                            return true;
                        }
                        assert!(!matches!(event, SwarmEvent::ConnectionEstablished { .. }));
                    }
                    event = dialer.select_next_some() => {
                        if matches!(event, SwarmEvent::OutgoingConnectionError { .. }) {
                            return true;
                        }
                        assert!(!matches!(event, SwarmEvent::ConnectionEstablished { .. }));
                    }
                }
            }
        })
        .await
        .expect("rejection timeout");
        assert!(rejected);
    }

    /// Drive both swarms until `pick` returns a value for a client event.
    async fn client_until<T>(
        relay: &mut Swarm<TestRelayBehaviour>,
        client: &mut Swarm<RavenConnectivityBehaviour>,
        mut pick: impl FnMut(SwarmEvent<RavenConnectivityBehaviourEvent>) -> Option<T>,
    ) -> T {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    _ = relay.select_next_some() => {}
                    event = client.select_next_some() => {
                        if let Some(value) = pick(event) {
                            return value;
                        }
                    }
                }
            }
        })
        .await
        .expect("relay scenario timeout")
    }

    fn fresh_reservation(event: &SwarmEvent<RavenConnectivityBehaviourEvent>) -> bool {
        matches!(
            event,
            SwarmEvent::Behaviour(RavenConnectivityBehaviourEvent::Relay(
                relay::client::Event::ReservationReqAccepted { renewal: false, .. }
            ))
        )
    }

    /// Regression: `ListenerClosed` for the reservation was discarded, so a
    /// dropped relay connection left the node without a circuit address for
    /// the rest of the run. The keeper must notice exactly that listener and
    /// get a fresh reservation accepted by the (still running) relay.
    #[tokio::test]
    async fn dropped_relay_connection_leads_to_a_fresh_reservation() {
        let mut relay = build_test_relay(fixed_identity(0x71));
        let relay_peer = *relay.local_peer_id();
        let relay_address = tcp_listener_for(&mut relay).await;
        relay.add_external_address(relay_address.clone());

        let mut client =
            build_connectivity_swarm(fixed_identity(0x72), ConnectivityProfile::default())
                .expect("client swarm");
        let client_peer = *client.local_peer_id();
        let _direct = tcp_listener_for(&mut client).await;
        let mut keeper = ReservationKeeper::new(&relay_address.with(Protocol::P2p(relay_peer)))
            .expect("operator relay");
        assert!(keeper.request(&mut client, Instant::now(), 0.0));
        assert_eq!(keeper.retry_at(), None);

        client_until(&mut relay, &mut client, |event| {
            fresh_reservation(&event).then_some(())
        })
        .await;
        keeper.on_reservation_accepted();

        // The relay drops the connection that carries the reservation.
        relay
            .disconnect_peer_id(client_peer)
            .expect("client is connected to the relay");
        let lost_at = Instant::now();
        let delay = client_until(&mut relay, &mut client, |event| match event {
            SwarmEvent::ListenerClosed { listener_id, .. } => {
                keeper.on_listener_closed(listener_id, lost_at, 0.0)
            }
            _ => None,
        })
        .await;
        assert_eq!(delay, reconnect_delay(0, 0.0));
        assert!(!keeper.retry_due(lost_at));
        assert!(keeper.retry_due(lost_at + delay));
        assert_eq!(keeper.retry_at(), Some(lost_at + delay));
        // A second report for the same loss, or for some other listener (the
        // TCP/QUIC ones), must not arm anything.
        assert_eq!(
            keeper.on_listener_closed(ListenerId::next(), lost_at, 0.0),
            None
        );

        assert!(keeper.request(&mut client, lost_at + delay, 0.0));
        assert_eq!(keeper.retry_at(), None);
        client_until(&mut relay, &mut client, |event| {
            fresh_reservation(&event).then_some(())
        })
        .await;
    }

    #[tokio::test]
    async fn reservation_retries_back_off_and_reset_when_accepted() {
        let relay_peer = fixed_identity(0x34).public().to_peer_id();
        let relay: Multiaddr = format!("/ip4/127.0.0.1/tcp/41001/p2p/{relay_peer}")
            .parse()
            .expect("relay address");
        assert!(ReservationKeeper::new(&"/ip4/127.0.0.1/tcp/41001".parse().unwrap()).is_err());
        let mut keeper = ReservationKeeper::new(&relay).expect("keeper");
        let now = Instant::now();

        // Without a live reservation listener nothing is armed.
        assert_eq!(
            keeper.on_listener_closed(ListenerId::next(), now, 0.0),
            None
        );
        assert_eq!(keeper.retry_at(), None);

        let mut swarm =
            build_connectivity_swarm(fixed_identity(0x35), ConnectivityProfile::default())
                .expect("swarm");
        // Repeated losses lengthen the delay; acceptance starts over.
        let mut delays = Vec::new();
        for _ in 0..3 {
            assert!(keeper.request(&mut swarm, now, 1.0));
            let listener = keeper.listener.expect("requested listener");
            delays.push(keeper.on_listener_closed(listener, now, 1.0).unwrap());
        }
        assert_eq!(
            delays,
            [
                reconnect_delay(0, 1.0),
                reconnect_delay(1, 1.0),
                reconnect_delay(2, 1.0)
            ]
        );
        assert!(delays[0] < delays[1] && delays[1] < delays[2]);
        keeper.on_reservation_accepted();
        assert!(keeper.request(&mut swarm, now, 1.0));
        let listener = keeper.listener.expect("requested listener");
        assert_eq!(
            keeper.on_listener_closed(listener, now, 1.0),
            Some(reconnect_delay(0, 1.0))
        );
    }

    async fn outgoing_error(swarm: &mut Swarm<RavenConnectivityBehaviour>) -> ConnectionId {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::OutgoingConnectionError { connection_id, .. } =
                    swarm.select_next_some().await
                {
                    return connection_id;
                }
            }
        })
        .await
        .expect("dial failure timeout")
    }

    /// Regression: a failed `--dial` was never retried. It is now retried a
    /// bounded number of times, with growing delays, then dropped.
    #[tokio::test]
    async fn failed_operator_dial_is_retried_a_bounded_number_of_times() {
        let closed_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("probe port");
            listener.local_addr().expect("probe address").port()
        };
        let target = fixed_identity(0x73).public().to_peer_id();
        let address: Multiaddr = format!("/ip4/127.0.0.1/tcp/{closed_port}/p2p/{target}")
            .parse()
            .expect("dial address");
        let mut dialer =
            build_connectivity_swarm(fixed_identity(0x74), ConnectivityProfile::default())
                .expect("dialer swarm");
        let mut dials = OperatorDials::default();
        dials.start(&mut dialer, address).expect("queue dial");
        assert!(!dials.is_idle());

        let mut retries = 0u32;
        loop {
            let connection = outgoing_error(&mut dialer).await;
            let now = Instant::now();
            match dials.on_failed(connection, now, 0.0) {
                DialOutcome::Retrying(delay) => {
                    assert_eq!(delay, reconnect_delay(retries, 0.0));
                    retries += 1;
                    assert_eq!(dials.next_retry(), Some(now + delay));
                    // Not due yet, then due: exactly one re-dial starts.
                    assert_eq!(dials.redial_due(&mut dialer, now, 0.0), 0);
                    assert_eq!(dials.redial_due(&mut dialer, now + delay, 0.0), 1);
                    assert_eq!(dials.next_retry(), None);
                }
                DialOutcome::GaveUp => break,
                DialOutcome::NotTracked => panic!("operator dial was not tracked"),
            }
        }
        assert_eq!(retries, MAX_DIAL_ATTEMPTS - 1);
        assert!(dials.is_idle());
        // Dials libp2p makes on its own (e.g. to the relay) are not ours.
        assert_eq!(
            dials.on_failed(ConnectionId::new_unchecked(usize::MAX), Instant::now(), 0.0),
            DialOutcome::NotTracked
        );
    }

    #[tokio::test]
    async fn successful_operator_dial_stops_being_tracked() {
        let mut listener =
            build_connectivity_swarm(fixed_identity(0x75), ConnectivityProfile::default())
                .expect("listener swarm");
        let mut dialer =
            build_connectivity_swarm(fixed_identity(0x76), ConnectivityProfile::default())
                .expect("dialer swarm");
        let listener_peer = *listener.local_peer_id();
        let address = tcp_listener_for(&mut listener).await;

        let mut dials = OperatorDials::default();
        dials
            .start(&mut dialer, address.with(Protocol::P2p(listener_peer)))
            .expect("queue dial");
        let connection = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    _ = listener.select_next_some() => {}
                    event = dialer.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { connection_id, .. } = event {
                            return connection_id;
                        }
                    }
                }
            }
        })
        .await
        .expect("connect timeout");
        dials.on_established(connection);
        assert!(dials.is_idle());
    }
}
