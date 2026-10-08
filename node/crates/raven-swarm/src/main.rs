//! Two-node libp2p swarm: TCP (+ optional QUIC listen) + Noise/Yamux + Kad put/get
//! of signed `PeerRecord`. Separates libp2p PeerId from Raven Ed25519 identity.
//! No FastAPI / HTTP API in path.
//!
//! The swarm, the Kad record validation and the key derivation live in
//! [`raven_swarm::kad_node`]; this binary is the CLI around them.
//!
//! `serve` re-signs and re-publishes its own record every
//! `SERVE_RECORD_REFRESH`, well inside the `SERVE_RECORD_TTL_MS` validity,
//! so a long run never leaves remote nodes holding only an expired copy.

use std::error::Error;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use futures::StreamExt;
use libp2p::kad::{self, RecordKey};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm};
use raven_core::bootstrap::{load_bootstrap, save_bootstrap, BootstrapConfig};
use raven_core::identity::Identity;
use raven_swarm::kad_node::{
    build_swarm, dht_key_for, on_inbound_put, publish_own_record, verify_found_record,
    RavenBehaviour, RavenBehaviourEvent, SERVE_RECORD_REFRESH,
};
use raven_swarm::liveness::{close_if_dead, reconnect_delay, retry_jitter};

/// Attempts at the one dial `dial` makes (the first plus its retries).
const MAX_PRIMARY_DIAL_ATTEMPTS: u32 = 3;

#[derive(Parser, Debug)]
#[command(
    name = "raven-swarm",
    about = "RAVEN libp2p swarm smoke (TCP/QUIC + Kad)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Listen, publish signed PeerRecord into Kad, wait for inbound dial.
    Serve {
        #[arg(long, default_value = "./raven-swarm-data")]
        data_dir: PathBuf,
        #[arg(long, default_value = "/ip4/127.0.0.1/tcp/0")]
        listen: String,
        /// Also listen QUIC on UDP (same host, port+1 or explicit).
        #[arg(long, default_value_t = true)]
        quic: bool,
        #[arg(long)]
        write_multiaddr: Option<PathBuf>,
        #[arg(long)]
        write_peer_id: Option<PathBuf>,
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        /// Exit after successful Kad put of our peer record.
        #[arg(long, default_value_t = false)]
        exit_after_put: bool,
    },
    /// Dial peer, fetch signed PeerRecord via Kad get, verify Ed25519.
    Dial {
        #[arg(long, default_value = "./raven-swarm-data-b")]
        data_dir: PathBuf,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        peer_id: String,
        /// Raven Ed25519 pub hex whose DHT key we GET.
        #[arg(long)]
        raven_pub_hex: String,
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
    },
    /// Write bootstrap.json for manual-peer-only startup (§30).
    BootstrapInit {
        #[arg(long, default_value = "./raven-swarm-data")]
        data_dir: PathBuf,
        /// Manual multiaddr (required for manual-peer-only proof).
        #[arg(long)]
        manual_peer: String,
        /// Extra custom bootstrap multiaddrs.
        #[arg(long)]
        custom: Vec<String>,
        /// Disable Raven-provided defaults (always empty in V1 anyway).
        #[arg(long, default_value_t = true)]
        no_raven_defaults: bool,
    },
    /// Print effective bootstrap peers from data-dir config.
    BootstrapShow {
        #[arg(long, default_value = "./raven-swarm-data")]
        data_dir: PathBuf,
    },
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn load_or_create_identity(data_dir: &std::path::Path) -> Result<Identity, Box<dyn Error>> {
    Ok(raven_core::load_or_create_identity(data_dir).map(|(id, _)| id)?)
}

/// First TCP listen address, the one `serve` announces.
fn first_tcp(mut addresses: impl Iterator<Item = Multiaddr>) -> Option<Multiaddr> {
    addresses.find(|a| a.iter().any(|p| matches!(p, Protocol::Tcp(_))))
}

async fn cmd_serve(
    data_dir: PathBuf,
    listen: String,
    quic: bool,
    write_multiaddr: Option<PathBuf>,
    write_peer_id: Option<PathBuf>,
    timeout_secs: u64,
    exit_after_put: bool,
) -> Result<(), Box<dyn Error>> {
    let raven_id = load_or_create_identity(&data_dir)?;
    let mut swarm = build_swarm(&raven_id)?;
    let local_peer = *swarm.local_peer_id();
    println!("raven_pub_hex={}", hex::encode(raven_id.public_key_bytes()));
    println!("libp2p_peer_id={local_peer}");
    println!("note=libp2p PeerId is domain-separated from Raven identity");

    let own_key = RecordKey::new(&dht_key_for(&raven_id.public_key_bytes()));
    let listen_maddr: Multiaddr = listen.parse()?;
    swarm.listen_on(listen_maddr.clone())?;
    if quic {
        // Prefer explicit QUIC listen on UDP; derive from TCP listen when possible.
        let quic_addr = if listen.contains("/tcp/") {
            let tcp_port = listen_maddr
                .iter()
                .find_map(|p| match p {
                    Protocol::Tcp(p) => Some(p),
                    _ => None,
                })
                .unwrap_or(0);
            let mut q = Multiaddr::empty();
            for p in listen_maddr.iter() {
                match p {
                    Protocol::Tcp(_) => {
                        q.push(Protocol::Udp(if tcp_port == 0 {
                            0
                        } else {
                            tcp_port.saturating_add(1)
                        }));
                        q.push(Protocol::QuicV1);
                    }
                    other => q.push(other),
                }
            }
            q
        } else {
            "/ip4/127.0.0.1/udp/0/quic-v1".parse()?
        };
        match swarm.listen_on(quic_addr.clone()) {
            Ok(_) => println!("quic_listen_requested={quic_addr}"),
            Err(e) => println!("quic_listen_skip={e}"),
        }
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    // Address our PeerRecord currently announces (the first TCP listener).
    let mut announced: Option<Multiaddr> = None;
    let mut refresh = tokio::time::interval_at(
        tokio::time::Instant::now() + SERVE_RECORD_REFRESH,
        SERVE_RECORD_REFRESH,
    );
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        if tokio::time::Instant::now() > deadline {
            return Err("serve timeout".into());
        }
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("listen_addr={address}");
                        // Prefer TCP for the smoke dial address.
                        if address.iter().any(|p| matches!(p, Protocol::Tcp(_))) {
                            if let Some(ref path) = write_multiaddr {
                                std::fs::write(path, address.to_string())?;
                            }
                            if let Some(ref path) = write_peer_id {
                                std::fs::write(path, local_peer.to_string())?;
                            }
                            if announced.is_none() {
                                let rec = publish_own_record(
                                    &mut swarm,
                                    &raven_id,
                                    &address.to_string(),
                                    now_ms(),
                                )?;
                                announced = Some(address);
                                println!("kad_put_ok key={}", hex::encode(rec.dht_key()));
                                if exit_after_put {
                                    return Ok(());
                                }
                            }
                        }
                    }
                    SwarmEvent::ExpiredListenAddr { address, .. } if announced.as_ref() == Some(&address) => {
                        // The announced interface went away: move the record to
                        // another TCP listener now rather than at the next refresh.
                        announced = first_tcp(swarm.listeners().filter(|a| **a != address).cloned());
                        if let Some(next) = &announced {
                            publish_own_record(&mut swarm, &raven_id, &next.to_string(), now_ms())?;
                            println!("kad_put_readdressed");
                        }
                    }
                    SwarmEvent::Behaviour(RavenBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::PutRecord(Ok(_)),
                        ..
                    })) => {
                        println!("kad_network_put_ok");
                    }
                    SwarmEvent::Behaviour(RavenBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::PutRecord(Err(e)),
                        ..
                    })) => {
                        // Solo listen: network quorum may fail until a peer dials — local put already OK.
                        println!("kad_network_put_pending={e}");
                    }
                    SwarmEvent::Behaviour(RavenBehaviourEvent::Kad(kad::Event::InboundRequest {
                        request: kad::InboundRequest::PutRecord { record: Some(record), .. },
                    })) => {
                        on_inbound_put(&mut swarm, &own_key, record);
                    }
                    SwarmEvent::Behaviour(RavenBehaviourEvent::Ping(event)) => {
                        // libp2p only reports a dead connection; closing it is ours to do.
                        if close_if_dead(&mut swarm, &event) {
                            println!("connection_closed_after_ping_failure");
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("connection_established peer={peer_id}");
                    }
                    SwarmEvent::IncomingConnection { .. } => {
                        println!("incoming_connection");
                    }
                    _ => {}
                }
            }
            _ = refresh.tick() => {
                // Re-sign well before the signature expires; remote nodes
                // reject an expired record, so a one-shot announce would make
                // this node undiscoverable after SERVE_RECORD_TTL_MS.
                if let Some(address) = &announced {
                    publish_own_record(&mut swarm, &raven_id, &address.to_string(), now_ms())?;
                    println!("kad_put_refreshed");
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
}

async fn cmd_dial(
    data_dir: PathBuf,
    peer: String,
    peer_id: String,
    raven_pub_hex: String,
    timeout_secs: u64,
) -> Result<(), Box<dyn Error>> {
    let raven_id = load_or_create_identity(&data_dir)?;
    let mut swarm = build_swarm(&raven_id)?;
    let remote_peer: PeerId = peer_id.parse()?;
    let remote_addr: Multiaddr = peer.parse()?;

    // Report bootstrap.json (manual peers only path). This smoke dialer only
    // dials --peer; bootstrap peers are printed, not dialed.
    let boot = load_bootstrap(&data_dir);
    if boot.manual_peer_only_ok() {
        println!("bootstrap_mode=manual_peer_only");
    } else {
        println!(
            "bootstrap_mode=config_effective count={}",
            boot.effective_peers().len()
        );
    }
    for p in boot.effective_peers() {
        println!("bootstrap_peer={p}");
    }

    swarm
        .behaviour_mut()
        .kad
        .add_address(&remote_peer, remote_addr.clone());
    let dial_addr = remote_addr.with(Protocol::P2p(remote_peer));
    swarm.dial(dial_addr.clone())?;

    let pub_bytes = hex::decode(raven_pub_hex.trim())?;
    if pub_bytes.len() != 32 {
        return Err("raven_pub_hex must be 32 bytes".into());
    }
    let mut raven_pub = [0u8; 32];
    raven_pub.copy_from_slice(&pub_bytes);
    let dht_key = dht_key_for(&raven_pub);
    let own_key = RecordKey::new(&dht_key_for(&raven_id.public_key_bytes()));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    run_dial(
        &mut swarm,
        remote_peer,
        dial_addr,
        &dht_key,
        &raven_pub,
        &own_key,
        deadline,
    )
    .await
}

/// Drive an already-dialed `swarm` until the signed PeerRecord of `raven_pub`
/// has been fetched over Kad and verified, or `deadline` passes.
async fn run_dial(
    swarm: &mut Swarm<RavenBehaviour>,
    remote_peer: PeerId,
    dial_addr: Multiaddr,
    dht_key: &[u8; 32],
    raven_pub: &[u8; 32],
    own_key: &RecordKey,
    deadline: tokio::time::Instant,
) -> Result<(), Box<dyn Error>> {
    let mut connected = false;
    let mut get_started = false;
    let mut verified = false;
    // Failed attempts at the primary dial, and when the next one is due.
    let mut dial_failures = 0u32;
    let mut redial_at: Option<tokio::time::Instant> = None;

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                return Err("dial timeout".into());
            }
            _ = async {
                match redial_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                redial_at = None;
                if !connected && swarm.dial(dial_addr.clone()).is_err() {
                    return Err("dial error: redial refused".into());
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("connection_established peer={peer_id}");
                        connected = true;
                        if !get_started {
                            get_started = true;
                            let key = RecordKey::new(dht_key);
                            swarm.behaviour_mut().kad.get_record(key);
                            println!("kad_get_started key={}", hex::encode(dht_key));
                        }
                    }
                    // Kad also dials peers it learns from GET_VALUE responses, and
                    // one unreachable or hostile one must not end the lookup.
                    // Only a failure of the explicit --peer dial is ours; the
                    // lookup's own 20 s timeout and the deadline end the rest.
                    SwarmEvent::OutgoingConnectionError { peer_id: Some(failed), error, .. }
                        if failed == remote_peer =>
                    {
                        if connected {
                            // Another address of the peer failed; we are already in.
                            println!("kad_outgoing_error_ignored");
                        } else {
                            dial_failures += 1;
                            if dial_failures >= MAX_PRIMARY_DIAL_ATTEMPTS {
                                return Err(format!("dial error: {error}").into());
                            }
                            println!("dial_retry attempt={dial_failures}");
                            redial_at = Some(
                                tokio::time::Instant::now()
                                    + reconnect_delay(dial_failures - 1, retry_jitter()),
                            );
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { .. } => {
                        println!("kad_outgoing_error_ignored");
                    }
                    SwarmEvent::Behaviour(RavenBehaviourEvent::Ping(event)) => {
                        // libp2p only reports a dead connection; closing it is ours to do.
                        if close_if_dead(swarm, &event) {
                            println!("connection_closed_after_ping_failure");
                        }
                    }
                    SwarmEvent::Behaviour(RavenBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_rec))),
                        ..
                    })) => {
                        // One bad (or poisoned) record must not end discovery:
                        // skip it and keep reading the query's other results.
                        match verify_found_record(&peer_rec.record, dht_key, raven_pub, now_ms()) {
                            Ok(rec) => {
                                verified = true;
                                println!("kad_get_ok dial={}", rec.dial);
                                println!("peer_record_verified=1");
                                if connected {
                                    println!("=== LIBP2P SWARM DIAL+KAD OK (no FastAPI) ===");
                                    return Ok(());
                                }
                            }
                            Err(e) => println!("kad_get_skip_invalid_record={e}"),
                        }
                    }
                    SwarmEvent::Behaviour(RavenBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. })),
                        ..
                    })) => {
                        if !verified {
                            return Err("kad get finished without a valid peer record".into());
                        }
                    }
                    SwarmEvent::Behaviour(RavenBehaviourEvent::Kad(kad::Event::InboundRequest {
                        request: kad::InboundRequest::PutRecord { record: Some(record), .. },
                    })) => {
                        on_inbound_put(swarm, own_key, record);
                    }
                    SwarmEvent::Behaviour(RavenBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::GetRecord(Err(e)),
                        ..
                    })) => {
                        return Err(format!("kad get failed: {e}").into());
                    }
                    _ => {}
                }
            }
        }
    }
}

fn cmd_bootstrap_init(
    data_dir: PathBuf,
    manual_peer: String,
    custom: Vec<String>,
    no_raven_defaults: bool,
) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(&data_dir)?;
    let mut cfg = BootstrapConfig::default();
    if no_raven_defaults {
        cfg.remove_raven_defaults();
    }
    cfg.manual_peers.push(manual_peer);
    for c in custom {
        cfg.add_custom(c);
    }
    save_bootstrap(&data_dir, &cfg)?;
    println!(
        "bootstrap_path={}",
        data_dir.join("bootstrap.json").display()
    );
    println!("manual_peer_only={}", cfg.manual_peer_only_ok());
    println!("effective_count={}", cfg.effective_peers().len());
    Ok(())
}

fn cmd_bootstrap_show(data_dir: PathBuf) -> Result<(), Box<dyn Error>> {
    let cfg = load_bootstrap(&data_dir);
    println!("use_raven_defaults={}", cfg.use_raven_defaults);
    println!("raven_defaults_count={}", cfg.raven_defaults.len());
    println!("custom_count={}", cfg.custom.len());
    println!("manual_count={}", cfg.manual_peers.len());
    println!("manual_peer_only={}", cfg.manual_peer_only_ok());
    for p in cfg.effective_peers() {
        println!("peer={p}");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Serve {
            data_dir,
            listen,
            quic,
            write_multiaddr,
            write_peer_id,
            timeout_secs,
            exit_after_put,
        } => {
            cmd_serve(
                data_dir,
                listen,
                quic,
                write_multiaddr,
                write_peer_id,
                timeout_secs,
                exit_after_put,
            )
            .await
        }
        Commands::Dial {
            data_dir,
            peer,
            peer_id,
            raven_pub_hex,
            timeout_secs,
        } => cmd_dial(data_dir, peer, peer_id, raven_pub_hex, timeout_secs).await,
        Commands::BootstrapInit {
            data_dir,
            manual_peer,
            custom,
            no_raven_defaults,
        } => cmd_bootstrap_init(data_dir, manual_peer, custom, no_raven_defaults),
        Commands::BootstrapShow { data_dir } => cmd_bootstrap_show(data_dir),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::kad::store::RecordStore;
    use libp2p::kad::Record;

    async fn listen_tcp(swarm: &mut Swarm<RavenBehaviour>) -> Multiaddr {
        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                    return address;
                }
            }
        })
        .await
        .expect("listen timeout")
    }

    /// Keep a serving swarm answering requests for the rest of the test.
    fn serve_in_background(mut swarm: Swarm<RavenBehaviour>) {
        tokio::spawn(async move {
            loop {
                swarm.select_next_some().await;
            }
        });
    }

    /// Regression: any `OutgoingConnectionError` ended `dial`, including the
    /// failure of a dial Kad made on its own to a peer it learned from a
    /// GET_VALUE answer. Here the first answer is poisoned and points at a
    /// dead peer (whose dial fails at once) and at the real owner of the record.
    #[tokio::test]
    async fn lookup_survives_a_failing_third_party_dial() {
        let owner_id = Identity::from_seed(&[20; 32]);
        let hub_id = Identity::from_seed(&[21; 32]);
        let seeker_id = Identity::from_seed(&[22; 32]);
        let mut owner = build_swarm(&owner_id).unwrap();
        let mut hub = build_swarm(&hub_id).unwrap();
        let mut seeker = build_swarm(&seeker_id).unwrap();
        let (owner_peer, hub_peer) = (*owner.local_peer_id(), *hub.local_peer_id());
        let owner_addr = listen_tcp(&mut owner).await;
        let hub_addr = listen_tcp(&mut hub).await;
        publish_own_record(&mut owner, &owner_id, &owner_addr.to_string(), now_ms()).unwrap();

        let owner_pub = owner_id.public_key_bytes();
        let dht_key = dht_key_for(&owner_pub);
        let closed_port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let dead_peer = PeerId::random();
        let dead_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{closed_port}").parse().unwrap();
        // The hub answers with garbage under the owner's key, plus two hints.
        hub.behaviour_mut()
            .kad
            .store_mut()
            .put(Record {
                key: RecordKey::new(&dht_key),
                value: b"poison".to_vec(),
                publisher: None,
                expires: None,
            })
            .unwrap();
        hub.behaviour_mut().kad.add_address(&dead_peer, dead_addr);
        hub.behaviour_mut().kad.add_address(&owner_peer, owner_addr);
        serve_in_background(owner);
        serve_in_background(hub);

        let dial_addr = hub_addr.clone().with(Protocol::P2p(hub_peer));
        seeker.behaviour_mut().kad.add_address(&hub_peer, hub_addr);
        seeker.dial(dial_addr.clone()).unwrap();
        let own_key = RecordKey::new(&dht_key_for(&seeker_id.public_key_bytes()));
        let result = run_dial(
            &mut seeker,
            hub_peer,
            dial_addr,
            &dht_key,
            &owner_pub,
            &own_key,
            tokio::time::Instant::now() + Duration::from_secs(15),
        )
        .await;
        assert!(result.is_ok(), "lookup aborted: {:?}", result.err());
    }
}
