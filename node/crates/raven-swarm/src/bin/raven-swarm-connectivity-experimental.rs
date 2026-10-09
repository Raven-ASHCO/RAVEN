//! Operator-only NAT traversal experiment.
//!
//! Compiling this target requires `experimental-nat-connectivity`; running it
//! requires `--enable-experimental-nat-connectivity`. It has no built-in
//! bootstrap, relay, rendezvous, or Raven service address.
//!
//! Liveness is enforced here, not by libp2p: a failed ping closes its
//! connection, a lost relay reservation is re-requested with capped, jittered
//! backoff, and a failed `--dial` is retried a bounded number of times.

use std::error::Error;
use std::time::Duration;

use clap::Parser;
use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::relay::client::Event as RelayEvent;
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;
use raven_swarm::connectivity::{
    build_connectivity_swarm, require_experimental_runtime_opt_in, require_terminal_peer,
    ConnectivityProfile, DialOutcome, OperatorDials, RavenConnectivityBehaviourEvent,
    ReservationKeeper,
};
use raven_swarm::liveness::{close_if_dead, retry_jitter, should_close_on_ping_failure};
use tokio::time::Instant;

const MAX_EXPERIMENT_SECONDS: u64 = 3_600;
const MAX_OPERATOR_DIALS: usize = 8;

#[derive(Debug, Parser)]
#[command(
    name = "raven-swarm-connectivity-experimental",
    about = "Production-disabled Raven NAT traversal experiment"
)]
struct Arguments {
    /// Required runtime acknowledgement in addition to the Cargo feature.
    #[arg(long, default_value_t = false)]
    enable_experimental_nat_connectivity: bool,

    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/0")]
    listen_tcp: String,

    #[arg(long, default_value = "/ip4/0.0.0.0/udp/0/quic-v1")]
    listen_quic: String,

    /// Optional operator-supplied relay ending in `/p2p/<relay-peer>`.
    #[arg(long)]
    relay: Option<String>,

    /// Optional operator-supplied peer multiaddr; no peers are built in.
    #[arg(long)]
    dial: Vec<String>,

    #[arg(long, default_value_t = 60)]
    run_seconds: u64,
}

fn parse_address(raw: &str) -> Result<Multiaddr, Box<dyn Error + Send + Sync>> {
    raw.parse()
        .map_err(|_| "invalid operator-supplied multiaddr".into())
}

/// Earliest instant at which a reservation or dial retry is due.
fn next_retry(reservation: Option<&ReservationKeeper>, dials: &OperatorDials) -> Option<Instant> {
    [
        reservation.and_then(ReservationKeeper::retry_at),
        dials.next_retry(),
    ]
    .into_iter()
    .flatten()
    .min()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = Arguments::parse();
    require_experimental_runtime_opt_in(arguments.enable_experimental_nat_connectivity)?;
    if arguments.run_seconds == 0 || arguments.run_seconds > MAX_EXPERIMENT_SECONDS {
        return Err("experiment duration is outside the bounded range".into());
    }
    if arguments.dial.len() > MAX_OPERATOR_DIALS {
        return Err("too many operator-supplied dial addresses".into());
    }

    let identity = Keypair::generate_ed25519();
    let mut swarm = build_connectivity_swarm(identity, ConnectivityProfile::default())
        .map_err(|_| "failed to build experimental connectivity profile")?;
    swarm
        .listen_on(parse_address(&arguments.listen_tcp)?)
        .map_err(|_| "failed to start TCP listener")?;
    swarm
        .listen_on(parse_address(&arguments.listen_quic)?)
        .map_err(|_| "failed to start QUIC listener")?;

    let mut reservation = match arguments.relay.as_deref() {
        Some(relay) => {
            let mut keeper = ReservationKeeper::new(&parse_address(relay)?)?;
            if !keeper.request(&mut swarm, Instant::now(), retry_jitter()) {
                return Err("failed to request relay reservation".into());
            }
            Some(keeper)
        }
        None => None,
    };
    let mut dials = OperatorDials::default();
    for address in &arguments.dial {
        // An unpinned address would accept whichever identity answers.
        let address = parse_address(address)?;
        require_terminal_peer(&address)?;
        dials
            .start(&mut swarm, address)
            .map_err(|_| "failed to queue operator-supplied dial")?;
    }

    println!("state=experimental_connectivity_enabled");
    println!("transport=tcp_quic_noise_yamux_relay_client");
    println!("discovery=operator_supplied_only");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(arguments.run_seconds);
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                println!("state=experiment_complete");
                return Ok(());
            }
            _ = tokio::signal::ctrl_c() => {
                println!("state=experiment_stopped");
                return Ok(());
            }
            _ = async {
                match next_retry(reservation.as_ref(), &dials) {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let now = Instant::now();
                if let Some(keeper) = reservation.as_mut() {
                    if keeper.retry_due(now) {
                        println!("relay=reservation_retry");
                        keeper.request(&mut swarm, now, retry_jitter());
                    }
                }
                dials.redial_due(&mut swarm, now, retry_jitter());
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { .. } => println!("network=listener_ready"),
                SwarmEvent::ConnectionEstablished { connection_id, .. } => {
                    dials.on_established(connection_id);
                    println!("network=connection_established")
                }
                SwarmEvent::ConnectionClosed { .. } => println!("network=connection_closed"),
                SwarmEvent::IncomingConnectionError { .. } => {
                    println!("network=incoming_rejected")
                }
                SwarmEvent::OutgoingConnectionError { connection_id, .. } => {
                    match dials.on_failed(connection_id, Instant::now(), retry_jitter()) {
                        DialOutcome::Retrying(_) => println!("network=outgoing_failed_retrying"),
                        DialOutcome::GaveUp => println!("network=outgoing_failed_gave_up"),
                        DialOutcome::NotTracked => println!("network=outgoing_failed"),
                    }
                }
                SwarmEvent::ListenerClosed { listener_id, reason, .. } => {
                    let lost = reservation.as_mut().and_then(|keeper| {
                        keeper.on_listener_closed(listener_id, Instant::now(), retry_jitter())
                    });
                    match (lost, reason.is_ok()) {
                        (Some(_), true) => println!("relay=reservation_lost reason=closed"),
                        (Some(_), false) => println!("relay=reservation_lost reason=error"),
                        (None, _) => println!("network=listener_closed"),
                    }
                }
                SwarmEvent::Behaviour(RavenConnectivityBehaviourEvent::AutoNat(event)) => {
                    if event.result.is_ok() {
                        println!("autonat=reachable")
                    } else {
                        println!("autonat=probe_failed")
                    }
                }
                SwarmEvent::Behaviour(RavenConnectivityBehaviourEvent::Dcutr(event)) => {
                    if event.result.is_ok() {
                        println!("dcutr=direct_connection_established")
                    } else {
                        println!("dcutr=upgrade_failed")
                    }
                }
                SwarmEvent::Behaviour(RavenConnectivityBehaviourEvent::Relay(event)) => {
                    match event {
                        RelayEvent::ReservationReqAccepted { renewal, .. } => {
                            if let Some(keeper) = reservation.as_mut() {
                                keeper.on_reservation_accepted();
                            }
                            if renewal {
                                println!("relay=reservation_renewed")
                            } else {
                                println!("relay=reservation_accepted")
                            }
                        }
                        RelayEvent::OutboundCircuitEstablished { .. } => {
                            println!("relay=outbound_circuit_established")
                        }
                        RelayEvent::InboundCircuitEstablished { .. } => {
                            println!("relay=inbound_circuit_established")
                        }
                    }
                }
                SwarmEvent::Behaviour(RavenConnectivityBehaviourEvent::Ping(event)) => {
                    match &event.result {
                        Err(failure) if should_close_on_ping_failure(failure) => {
                            // libp2p only reports the failure; closing is ours to do.
                            println!("health=ping_failed");
                            if close_if_dead(&mut swarm, &event) {
                                println!("health=connection_closed_after_ping_failure");
                            }
                        }
                        Err(_) => println!("health=ping_unsupported"),
                        Ok(_) => {}
                    }
                }
                _ => {}
            }
        }
    }
}
