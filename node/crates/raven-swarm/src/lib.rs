//! Reusable pieces of the Raven libp2p transport.
//!
//! The offline mailbox is deliberately feature gated. Default and release
//! builds do not advertise its protocol while the authenticated ATSAM session
//! integration remains on security hold.
//!
//! [`liveness`] and [`ip_limits`] are always compiled: every Raven swarm binary
//! enforces ping-based liveness and per-source-address connection caps itself,
//! because libp2p only reports the former and counts only the latter globally.

/// The libp2p crate this library is built on, for callers (raven-node) that
/// drive a swarm from [`host`] without a second, possibly mismatched,
/// dependency on it.
pub use libp2p;
#[cfg(feature = "p2p-host")]
pub use libp2p_stream;

pub mod liveness {
    //! Liveness policy shared by every Raven swarm binary.
    //!
    //! `libp2p-ping` only *reports* a dead connection (an `Err` event after two
    //! consecutive failures); it never closes anything, and handlers such as the
    //! relay client keep a connection alive on their own while a reservation
    //! exists, so the idle timeout does not reap it either. Enforcing liveness is
    //! the application's job: [`close_if_dead`] turns a ping failure into
    //! `Swarm::close_connection`, and [`reconnect_delay`] spaces out whatever
    //! re-dials or re-reservations follow.

    use std::collections::hash_map::RandomState;
    use std::time::Duration;

    use libp2p::swarm::NetworkBehaviour;
    use libp2p::{ping, Swarm};

    /// First retry delay (before jitter) after a connection or reservation is lost.
    pub const RECONNECT_BASE: Duration = Duration::from_secs(1);
    /// Hard cap on the delay between attempts, however many have failed.
    pub const RECONNECT_MAX: Duration = Duration::from_secs(60);

    /// Whether a ping failure means the connection is dead.
    ///
    /// `Unsupported` is not a liveness signal: a peer that does not run the ping
    /// protocol (a relay, say) is healthy, and closing on it would drop and redial
    /// that peer in a loop. `Timeout` and `Other` already include libp2p's free
    /// first failure, so an `Err` event means two consecutive failures.
    pub fn should_close_on_ping_failure(failure: &ping::Failure) -> bool {
        match failure {
            ping::Failure::Timeout | ping::Failure::Other { .. } => true,
            ping::Failure::Unsupported => false,
        }
    }

    /// Close the connection a failed ping was measured on. Returns `true` when a
    /// close was started; `SwarmEvent::ConnectionClosed` follows once it is done.
    pub fn close_if_dead<B: NetworkBehaviour>(swarm: &mut Swarm<B>, event: &ping::Event) -> bool {
        match &event.result {
            Err(failure) if should_close_on_ping_failure(failure) => {
                swarm.close_connection(event.connection)
            }
            _ => false,
        }
    }

    /// A sample from `[0, 1)` to desynchronise retries ([`reconnect_delay`]'s
    /// `jitter`). Not a secret: it only needs to differ between processes, which
    /// the randomly keyed `RandomState` hasher gives without a new dependency.
    pub fn retry_jitter() -> f64 {
        use std::hash::{BuildHasher, Hasher};

        let bits = RandomState::new().build_hasher().finish();
        (bits >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Delay before retry number `attempt` (0 = first retry): capped exponential
    /// backoff with "equal jitter", i.e. uniformly between half and all of
    /// `min(RECONNECT_MAX, RECONNECT_BASE * 2^attempt)`. `jitter` is a uniform
    /// sample from `[0, 1]`; callers supply it so tests stay deterministic.
    pub fn reconnect_delay(attempt: u32, jitter: f64) -> Duration {
        let ceiling = RECONNECT_BASE
            .saturating_mul(1u32 << attempt.min(16))
            .min(RECONNECT_MAX);
        let jitter = if jitter.is_finite() {
            jitter.clamp(0.0, 1.0)
        } else {
            0.0
        };
        ceiling.mul_f64(0.5 + 0.5 * jitter)
    }

    #[cfg(test)]
    mod tests {
        use std::time::Duration;

        use futures::StreamExt;
        use libp2p::identity::Keypair;
        use libp2p::multiaddr::Protocol;
        use libp2p::swarm::SwarmEvent;
        use libp2p::{noise, tcp, yamux, Multiaddr, SwarmBuilder};

        use super::*;

        fn ping_swarm(seed: u8) -> Swarm<ping::Behaviour> {
            SwarmBuilder::with_existing_identity(Keypair::ed25519_from_bytes([seed; 32]).unwrap())
                .with_tokio()
                .with_tcp(
                    tcp::Config::default().nodelay(true),
                    noise::Config::new,
                    yamux::Config::default,
                )
                .unwrap()
                .with_behaviour(|_| ping::Behaviour::default())
                .unwrap()
                .with_swarm_config(|config| {
                    config.with_idle_connection_timeout(Duration::from_secs(30))
                })
                .build()
        }

        fn failure_event(
            peer: libp2p::PeerId,
            connection: libp2p::swarm::ConnectionId,
            failure: ping::Failure,
        ) -> ping::Event {
            ping::Event {
                peer,
                connection,
                result: Err(failure),
            }
        }

        #[test]
        fn only_timeouts_and_transport_errors_count_as_dead() {
            assert!(should_close_on_ping_failure(&ping::Failure::Timeout));
            assert!(should_close_on_ping_failure(&ping::Failure::Other {
                error: "reset".into()
            }));
            assert!(!should_close_on_ping_failure(&ping::Failure::Unsupported));
        }

        #[test]
        fn retry_jitter_stays_in_unit_range_and_varies() {
            let samples: Vec<f64> = (0..64).map(|_| retry_jitter()).collect();
            assert!(samples.iter().all(|jitter| (0.0..1.0).contains(jitter)));
            assert!(samples.windows(2).any(|pair| pair[0] != pair[1]));
        }

        #[test]
        fn reconnect_delay_is_capped_jittered_and_total() {
            // No jitter: half the ceiling, doubling per attempt until the cap.
            assert_eq!(reconnect_delay(0, 0.0), Duration::from_millis(500));
            assert_eq!(reconnect_delay(1, 0.0), Duration::from_secs(1));
            assert_eq!(reconnect_delay(3, 1.0), Duration::from_secs(8));
            // Full jitter reaches the ceiling; it never exceeds the cap.
            for attempt in [6, 7, 16, 31, 32, u32::MAX] {
                assert_eq!(reconnect_delay(attempt, 1.0), RECONNECT_MAX);
                assert_eq!(reconnect_delay(attempt, 0.0), RECONNECT_MAX / 2);
            }
            // Delays never shrink with more failures and stay within [ceil/2, ceil].
            let mut previous = Duration::ZERO;
            for attempt in 0..40 {
                let low = reconnect_delay(attempt, 0.0);
                let high = reconnect_delay(attempt, 1.0);
                assert!(low >= previous, "attempt {attempt}");
                assert!(low <= high && high <= RECONNECT_MAX);
                previous = low;
            }
            // Out-of-range or non-finite jitter cannot panic or escape the range.
            for jitter in [-1.0, 2.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
                let delay = reconnect_delay(2, jitter);
                assert!(delay >= Duration::from_secs(2) && delay <= Duration::from_secs(4));
            }
        }

        /// A reported ping failure must close that exact connection; an
        /// `Unsupported` report (peer without ping) must leave it alone.
        #[tokio::test]
        async fn dead_connection_is_closed_but_ping_less_peer_is_kept() {
            let mut server = ping_swarm(0x81);
            let mut client = ping_swarm(0x82);
            let server_peer = *server.local_peer_id();
            server
                .listen_on("/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().unwrap())
                .unwrap();
            let address = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let SwarmEvent::NewListenAddr { address, .. } =
                        server.select_next_some().await
                    {
                        return address;
                    }
                }
            })
            .await
            .expect("listen timeout");
            client
                .dial(address.with(Protocol::P2p(server_peer)))
                .unwrap();

            // Wait for the client's established connection id; keep driving the
            // server so the handshake completes.
            let connection = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    tokio::select! {
                        _ = server.select_next_some() => {}
                        event = client.select_next_some() => {
                            if let SwarmEvent::ConnectionEstablished { connection_id, .. } = event {
                                return connection_id;
                            }
                        }
                    }
                }
            })
            .await
            .expect("connect timeout");

            // Unsupported: not a liveness signal.
            let keep = failure_event(server_peer, connection, ping::Failure::Unsupported);
            assert!(!close_if_dead(&mut client, &keep));
            // A successful ping is never a reason to close either.
            let ok = ping::Event {
                peer: server_peer,
                connection,
                result: Ok(Duration::from_millis(1)),
            };
            assert!(!close_if_dead(&mut client, &ok));
            assert!(client.is_connected(&server_peer));

            // Timeout: the connection is closed and the swarm reports it.
            let dead = failure_event(server_peer, connection, ping::Failure::Timeout);
            assert!(close_if_dead(&mut client, &dead));
            let closed = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    tokio::select! {
                        _ = server.select_next_some() => {}
                        event = client.select_next_some() => {
                            if let SwarmEvent::ConnectionClosed { connection_id, .. } = event {
                                return connection_id;
                            }
                        }
                    }
                }
            })
            .await
            .expect("close timeout");
            assert_eq!(closed, connection);
            // The id is gone, so a stale report is a no-op rather than an error.
            assert!(!close_if_dead(&mut client, &dead));
        }
    }
}

pub mod ip_limits {
    //! Per-source-IP caps on inbound connections.
    //!
    //! `libp2p-connection-limits` only keeps global and per-PeerId counts, and a
    //! PeerId costs nothing to generate. One host that opens `max_pending_incoming`
    //! idle sockets (each holds a slot until the upgrade times out) or fills
    //! `max_established` with fresh identities therefore starves every honest
    //! dialer. [`IpLimits`] adds a cap per source address on top of those global
    //! caps: compose it next to `connection_limits::Behaviour`; it speaks no
    //! protocol and never dials.
    //!
    //! The key is the exact IPv4 address or the IPv6 /64 (IPv4-mapped IPv6 counts as
    //! IPv4). Loopback is exempt by default because same-host tools and lab
    //! harnesses share one address by construction. Connections whose remote
    //! address carries no IP (relayed circuits) are not counted here; the global
    //! caps still bound them. Hosts behind one NAT share a bucket, so the defaults
    //! leave room for a handful of them.

    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::fmt;
    use std::net::IpAddr;
    use std::task::{Context, Poll};

    use libp2p::core::transport::PortUse;
    use libp2p::core::{ConnectedPoint, Endpoint};
    use libp2p::multiaddr::Protocol;
    use libp2p::swarm::behaviour::{ConnectionEstablished, ListenFailure};
    use libp2p::swarm::{
        dummy, ConnectionClosed, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour,
        THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
    };
    use libp2p::{Multiaddr, PeerId};

    /// Inbound connections still upgrading (Noise/Yamux) one address may hold.
    pub const DEFAULT_MAX_PENDING_PER_IP: u32 = 4;
    /// Established inbound connections one address may hold.
    pub const DEFAULT_MAX_ESTABLISHED_PER_IP: u32 = 8;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct IpLimitConfig {
        pub max_pending_per_ip: u32,
        pub max_established_per_ip: u32,
        /// Do not count or limit loopback sources (127.0.0.0/8, ::1).
        pub exempt_loopback: bool,
    }

    impl Default for IpLimitConfig {
        fn default() -> Self {
            Self {
                max_pending_per_ip: DEFAULT_MAX_PENDING_PER_IP,
                max_established_per_ip: DEFAULT_MAX_ESTABLISHED_PER_IP,
                exempt_loopback: true,
            }
        }
    }

    /// Which per-address limit denied a connection.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum IpLimitKind {
        PendingIncoming,
        EstablishedIncoming,
    }

    /// Cause carried by `ListenError::Denied` when [`IpLimits`] refuses a
    /// connection (downcast the `ConnectionDenied` to tell it from other limits).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct IpLimitExceeded {
        pub kind: IpLimitKind,
        pub limit: u32,
    }

    impl fmt::Display for IpLimitExceeded {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            let what = match self.kind {
                IpLimitKind::PendingIncoming => "pending incoming",
                IpLimitKind::EstablishedIncoming => "established incoming",
            };
            write!(
                formatter,
                "per-address limit of {} {what} connections exceeded",
                self.limit
            )
        }
    }

    impl std::error::Error for IpLimitExceeded {}

    /// Bucket a connection is charged to.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum IpKey {
        V4([u8; 4]),
        V6([u8; 8]),
    }

    impl IpKey {
        fn from_ip(ip: IpAddr) -> Self {
            let ip = match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
                ip => ip,
            };
            match ip {
                IpAddr::V4(v4) => Self::V4(v4.octets()),
                IpAddr::V6(v6) => {
                    let o = v6.octets();
                    Self::V6([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
                }
            }
        }
    }

    /// First IP in a remote multiaddr, if any.
    fn remote_ip(address: &Multiaddr) -> Option<IpAddr> {
        address.iter().find_map(|protocol| match protocol {
            Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        })
    }

    /// Counted by connection id so every exit path (established, failed, closed)
    /// releases exactly what it took, and ids this behaviour never saw are ignored.
    #[derive(Default)]
    struct Tally {
        by_connection: HashMap<ConnectionId, IpKey>,
        by_ip: HashMap<IpKey, u32>,
    }

    impl Tally {
        fn count(&self, key: IpKey) -> u32 {
            self.by_ip.get(&key).copied().unwrap_or(0)
        }

        fn insert(&mut self, connection: ConnectionId, key: IpKey) {
            if self.by_connection.insert(connection, key).is_none() {
                *self.by_ip.entry(key).or_insert(0) += 1;
            }
        }

        fn release(&mut self, connection: ConnectionId) {
            if let Some(key) = self.by_connection.remove(&connection) {
                if let Some(count) = self.by_ip.get_mut(&key) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.by_ip.remove(&key);
                    }
                }
            }
        }
    }

    /// A [`NetworkBehaviour`] that enforces [`IpLimitConfig`] on inbound connections.
    pub struct IpLimits {
        config: IpLimitConfig,
        pending: Tally,
        established: Tally,
    }

    impl IpLimits {
        pub fn new(config: IpLimitConfig) -> Self {
            Self {
                config,
                pending: Tally::default(),
                established: Tally::default(),
            }
        }

        /// Bucket for a remote address, `None` when it is not subject to limits.
        fn key_for(&self, remote: &Multiaddr) -> Option<IpKey> {
            let ip = remote_ip(remote)?;
            let exempt = self.config.exempt_loopback
                && match ip {
                    IpAddr::V4(v4) => v4.is_loopback(),
                    IpAddr::V6(v6) => {
                        v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v| v.is_loopback())
                    }
                };
            (!exempt).then(|| IpKey::from_ip(ip))
        }

        /// Source addresses currently holding a pending slot (for tests/diagnostics).
        pub fn tracked_pending_addresses(&self) -> usize {
            self.pending.by_ip.len()
        }

        /// Source addresses currently holding an established slot.
        pub fn tracked_established_addresses(&self) -> usize {
            self.established.by_ip.len()
        }
    }

    impl NetworkBehaviour for IpLimits {
        type ConnectionHandler = dummy::ConnectionHandler;
        type ToSwarm = Infallible;

        fn handle_pending_inbound_connection(
            &mut self,
            connection_id: ConnectionId,
            _local_addr: &Multiaddr,
            remote_addr: &Multiaddr,
        ) -> Result<(), ConnectionDenied> {
            if let Some(key) = self.key_for(remote_addr) {
                let limit = self.config.max_pending_per_ip;
                if self.pending.count(key) >= limit {
                    return Err(ConnectionDenied::new(IpLimitExceeded {
                        kind: IpLimitKind::PendingIncoming,
                        limit,
                    }));
                }
                self.pending.insert(connection_id, key);
            }
            Ok(())
        }

        fn handle_established_inbound_connection(
            &mut self,
            connection_id: ConnectionId,
            _peer: PeerId,
            _local_addr: &Multiaddr,
            remote_addr: &Multiaddr,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            // The upgrade is over: it no longer holds a pending slot.
            self.pending.release(connection_id);
            if let Some(key) = self.key_for(remote_addr) {
                let limit = self.config.max_established_per_ip;
                if self.established.count(key) >= limit {
                    return Err(ConnectionDenied::new(IpLimitExceeded {
                        kind: IpLimitKind::EstablishedIncoming,
                        limit,
                    }));
                }
            }
            Ok(dummy::ConnectionHandler)
        }

        fn handle_pending_outbound_connection(
            &mut self,
            _connection_id: ConnectionId,
            _maybe_peer: Option<PeerId>,
            _addresses: &[Multiaddr],
            _effective_role: Endpoint,
        ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
            Ok(Vec::new())
        }

        fn handle_established_outbound_connection(
            &mut self,
            _connection_id: ConnectionId,
            _peer: PeerId,
            _addr: &Multiaddr,
            _role_override: Endpoint,
            _port_use: PortUse,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            Ok(dummy::ConnectionHandler)
        }

        fn on_swarm_event(&mut self, event: FromSwarm) {
            match event {
                FromSwarm::ConnectionEstablished(ConnectionEstablished {
                    connection_id,
                    endpoint: ConnectedPoint::Listener { send_back_addr, .. },
                    ..
                }) => {
                    if let Some(key) = self.key_for(send_back_addr) {
                        self.established.insert(connection_id, key);
                    }
                }
                FromSwarm::ConnectionClosed(ConnectionClosed { connection_id, .. }) => {
                    self.established.release(connection_id);
                }
                // The upgrade failed, or another behaviour denied the connection
                // after this one admitted it.
                FromSwarm::ListenFailure(ListenFailure { connection_id, .. }) => {
                    self.pending.release(connection_id);
                }
                _ => {}
            }
        }

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

    #[cfg(test)]
    mod tests {
        use std::time::Duration;

        use futures::StreamExt;
        use libp2p::identity::Keypair;
        use libp2p::swarm::{ListenError, SwarmEvent};
        use libp2p::{noise, tcp, yamux, Swarm, SwarmBuilder};

        use super::*;

        fn addr(text: &str) -> Multiaddr {
            text.parse().unwrap()
        }

        fn local() -> Multiaddr {
            addr("/ip4/10.0.0.1/tcp/4001")
        }

        fn id(n: usize) -> ConnectionId {
            ConnectionId::new_unchecked(n)
        }

        fn limits(pending: u32, established: u32) -> IpLimits {
            IpLimits::new(IpLimitConfig {
                max_pending_per_ip: pending,
                max_established_per_ip: established,
                exempt_loopback: true,
            })
        }

        fn established(limits: &mut IpLimits, connection: ConnectionId, remote: &Multiaddr) {
            let endpoint = ConnectedPoint::Listener {
                local_addr: local(),
                send_back_addr: remote.clone(),
            };
            limits.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id: PeerId::random(),
                connection_id: connection,
                endpoint: &endpoint,
                failed_addresses: &[],
                other_established: 0,
            }));
        }

        fn closed(limits: &mut IpLimits, connection: ConnectionId, remote: &Multiaddr) {
            let endpoint = ConnectedPoint::Listener {
                local_addr: local(),
                send_back_addr: remote.clone(),
            };
            limits.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id: PeerId::random(),
                connection_id: connection,
                endpoint: &endpoint,
                cause: None,
                remaining_established: 0,
            }));
        }

        fn listen_failed(limits: &mut IpLimits, connection: ConnectionId, remote: &Multiaddr) {
            limits.on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
                local_addr: &local(),
                send_back_addr: remote,
                error: &ListenError::Aborted,
                connection_id: connection,
                peer_id: None,
            }));
        }

        fn denial(result: Result<(), ConnectionDenied>) -> Option<IpLimitExceeded> {
            result
                .err()
                .and_then(|denied| denied.downcast::<IpLimitExceeded>().ok())
        }

        /// Regression: only global pending caps existed, so one host could hold
        /// every pending slot with idle sockets.
        #[test]
        fn one_address_cannot_hold_every_pending_slot() {
            let mut limits = limits(2, 8);
            let attacker = addr("/ip4/198.51.100.7/tcp/50000");
            let honest = addr("/ip4/203.0.113.9/tcp/50000");

            assert!(limits
                .handle_pending_inbound_connection(id(1), &local(), &attacker)
                .is_ok());
            assert!(limits
                .handle_pending_inbound_connection(id(2), &local(), &attacker)
                .is_ok());
            assert_eq!(
                denial(limits.handle_pending_inbound_connection(id(3), &local(), &attacker)),
                Some(IpLimitExceeded {
                    kind: IpLimitKind::PendingIncoming,
                    limit: 2
                })
            );
            // Another address is unaffected, and the same host on another source
            // port is still the same bucket.
            assert!(limits
                .handle_pending_inbound_connection(id(4), &local(), &honest)
                .is_ok());
            assert!(denial(limits.handle_pending_inbound_connection(
                id(5),
                &local(),
                &addr("/ip4/198.51.100.7/udp/1234/quic-v1")
            ))
            .is_some());

            // A failed upgrade (timeout, handshake error, denial elsewhere)
            // releases the slot, and releasing twice or an unknown id is a no-op.
            listen_failed(&mut limits, id(1), &attacker);
            listen_failed(&mut limits, id(1), &attacker);
            listen_failed(&mut limits, id(99), &attacker);
            assert!(limits
                .handle_pending_inbound_connection(id(6), &local(), &attacker)
                .is_ok());
            assert!(
                denial(limits.handle_pending_inbound_connection(id(7), &local(), &attacker))
                    .is_some()
            );

            // A denied connection took nothing, so releasing everyone empties the table.
            for connection in [2, 4, 6] {
                listen_failed(&mut limits, id(connection), &attacker);
            }
            assert_eq!(limits.tracked_pending_addresses(), 0);
        }

        #[test]
        fn established_cap_counts_open_connections_and_frees_on_close() {
            let mut limits = limits(8, 2);
            let host = addr("/ip4/198.51.100.7/tcp/50000");

            for n in 1..=2 {
                limits
                    .handle_pending_inbound_connection(id(n), &local(), &host)
                    .unwrap();
                limits
                    .handle_established_inbound_connection(id(n), PeerId::random(), &local(), &host)
                    .unwrap();
                established(&mut limits, id(n), &host);
            }
            // The upgrade finished, so no pending slot is held any more.
            assert_eq!(limits.tracked_pending_addresses(), 0);

            limits
                .handle_pending_inbound_connection(id(3), &local(), &host)
                .unwrap();
            let denied = limits
                .handle_established_inbound_connection(id(3), PeerId::random(), &local(), &host)
                .err()
                .and_then(|denied| denied.downcast::<IpLimitExceeded>().ok());
            assert_eq!(
                denied,
                Some(IpLimitExceeded {
                    kind: IpLimitKind::EstablishedIncoming,
                    limit: 2
                })
            );
            // The swarm reports the denial as a ListenFailure; it never counted.
            listen_failed(&mut limits, id(3), &host);
            assert_eq!(limits.tracked_established_addresses(), 1);

            closed(&mut limits, id(1), &host);
            closed(&mut limits, id(1), &host);
            limits
                .handle_established_inbound_connection(id(4), PeerId::random(), &local(), &host)
                .unwrap();
            established(&mut limits, id(4), &host);
            closed(&mut limits, id(2), &host);
            closed(&mut limits, id(4), &host);
            assert_eq!(limits.tracked_established_addresses(), 0);
        }

        #[test]
        fn buckets_normalise_ipv4_mapped_and_group_ipv6_by_64() {
            let mut limits = limits(1, 8);
            limits
                .handle_pending_inbound_connection(
                    id(1),
                    &local(),
                    &addr("/ip4/198.51.100.7/tcp/1"),
                )
                .unwrap();
            assert!(denial(limits.handle_pending_inbound_connection(
                id(2),
                &local(),
                &addr("/ip6/::ffff:198.51.100.7/tcp/2")
            ))
            .is_some());

            limits
                .handle_pending_inbound_connection(
                    id(3),
                    &local(),
                    &addr("/ip6/2001:db8:1:2::1/tcp/1"),
                )
                .unwrap();
            assert!(denial(limits.handle_pending_inbound_connection(
                id(4),
                &local(),
                &addr("/ip6/2001:db8:1:2:ffff::9/tcp/2")
            ))
            .is_some());
            // A different /64 is a different bucket.
            assert!(limits
                .handle_pending_inbound_connection(
                    id(5),
                    &local(),
                    &addr("/ip6/2001:db8:1:3::1/tcp/1")
                )
                .is_ok());
        }

        #[test]
        fn loopback_and_ip_less_sources_are_not_counted() {
            let mut limits = limits(1, 1);
            for n in 0..4 {
                for remote in [
                    "/ip4/127.0.0.1/tcp/1",
                    "/ip6/::1/tcp/1",
                    "/ip6/::ffff:127.0.0.1/tcp/1",
                    // Relayed circuit: the source address has no IP at all.
                    "/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
                ] {
                    assert!(limits
                        .handle_pending_inbound_connection(id(n), &local(), &addr(remote))
                        .is_ok());
                }
            }
            assert_eq!(limits.tracked_pending_addresses(), 0);

            // Opting out of the loopback exemption counts loopback like any other.
            let mut strict = IpLimits::new(IpLimitConfig {
                max_pending_per_ip: 1,
                max_established_per_ip: 1,
                exempt_loopback: false,
            });
            let loopback = addr("/ip4/127.0.0.1/tcp/1");
            strict
                .handle_pending_inbound_connection(id(1), &local(), &loopback)
                .unwrap();
            assert!(
                denial(strict.handle_pending_inbound_connection(id(2), &local(), &loopback))
                    .is_some()
            );
        }

        fn limited_swarm(seed: u8, config: IpLimitConfig) -> Swarm<IpLimits> {
            SwarmBuilder::with_existing_identity(Keypair::ed25519_from_bytes([seed; 32]).unwrap())
                .with_tokio()
                .with_tcp(
                    tcp::Config::default().nodelay(true),
                    noise::Config::new,
                    yamux::Config::default,
                )
                .unwrap()
                .with_behaviour(|_| IpLimits::new(config))
                .unwrap()
                .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
                .build()
        }

        /// End to end: the behaviour is wired into a real swarm, a second
        /// connection from the same address is refused at the established stage
        /// with `IpLimitExceeded`, and closing the first frees the slot.
        #[tokio::test]
        async fn swarm_refuses_a_second_connection_from_the_same_address() {
            let config = IpLimitConfig {
                max_pending_per_ip: 4,
                max_established_per_ip: 1,
                exempt_loopback: false,
            };
            let mut server = limited_swarm(0x91, config);
            let mut first = limited_swarm(0x92, IpLimitConfig::default());
            let mut second = limited_swarm(0x93, IpLimitConfig::default());
            let mut retry = limited_swarm(0x94, IpLimitConfig::default());
            let server_peer = *server.local_peer_id();
            server
                .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();
            let address = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let SwarmEvent::NewListenAddr { address, .. } =
                        server.select_next_some().await
                    {
                        return address;
                    }
                }
            })
            .await
            .expect("listen timeout");

            first
                .dial(address.clone().with(Protocol::P2p(server_peer)))
                .unwrap();
            let first_connection = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    tokio::select! {
                        event = server.select_next_some() => {
                            if let SwarmEvent::ConnectionEstablished { connection_id, .. } = event {
                                return connection_id;
                            }
                        }
                        _ = first.select_next_some() => {}
                    }
                }
            })
            .await
            .expect("first connection timeout");

            second
                .dial(address.clone().with(Protocol::P2p(server_peer)))
                .unwrap();
            let denied = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    tokio::select! {
                        event = server.select_next_some() => match event {
                            SwarmEvent::IncomingConnectionError {
                                error: ListenError::Denied { cause }, ..
                            } => return cause.downcast::<IpLimitExceeded>().ok(),
                            SwarmEvent::ConnectionEstablished { .. } => {
                                panic!("second connection from the same address was admitted")
                            }
                            _ => {}
                        },
                        _ = first.select_next_some() => {}
                        _ = second.select_next_some() => {}
                    }
                }
            })
            .await
            .expect("denial timeout");
            assert_eq!(
                denied,
                Some(IpLimitExceeded {
                    kind: IpLimitKind::EstablishedIncoming,
                    limit: 1
                })
            );
            assert_eq!(server.behaviour().tracked_established_addresses(), 1);
            assert_eq!(server.behaviour().tracked_pending_addresses(), 0);

            // Closing the first connection frees the address for a retry.
            assert!(server.close_connection(first_connection));
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    tokio::select! {
                        event = server.select_next_some() => {
                            if matches!(event, SwarmEvent::ConnectionClosed { .. }) {
                                return;
                            }
                        }
                        _ = first.select_next_some() => {}
                        _ = second.select_next_some() => {}
                    }
                }
            })
            .await
            .expect("close timeout");
            assert_eq!(server.behaviour().tracked_established_addresses(), 0);

            retry
                .dial(address.with(Protocol::P2p(server_peer)))
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    tokio::select! {
                        event = server.select_next_some() => {
                            if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                                return;
                            }
                        }
                        _ = first.select_next_some() => {}
                        _ = second.select_next_some() => {}
                        _ = retry.select_next_some() => {}
                    }
                }
            })
            .await
            .expect("retry connection timeout");
            assert_eq!(server.behaviour().tracked_established_addresses(), 1);
        }
    }
}

pub mod kad_node;

#[cfg(feature = "experimental-offline-mailbox")]
pub mod mailbox;

/// NAT traversal building blocks (relay client, DCUtR, AutoNAT v2, operator
/// relay addresses and reservations). Compiled for the separate experiment
/// binary (`experimental-nat-connectivity`) and for the P3 host (`p2p-host`,
/// enabled by raven-node only); neither is in this crate's default features.
#[cfg(any(feature = "experimental-nat-connectivity", feature = "p2p-host"))]
pub mod connectivity;

/// The P3 libp2p host: endpoint (relay client, DCUtR, AutoNAT v2 client,
/// Identify, Ping, limits, `/raven/link/1.0.0` streams) and relay server.
#[cfg(feature = "p2p-host")]
pub mod host;
