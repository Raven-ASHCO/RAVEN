//! Two-node libp2p swarm: TCP (+ optional QUIC listen) + Noise/Yamux + Kad put/get
//! of signed `PeerRecord`. Separates libp2p PeerId from Raven Ed25519 identity.
//! No FastAPI / HTTP API in path.
//!
//! Kad runs with `StoreInserts::FilterBoth`: inbound PUTs are stored only after
//! [`validate_inbound_record`] (well-formed, signed, unexpired, keyed by its
//! signer, never our own key, never an older record over a newer one).
//!
//! `serve` re-signs and re-publishes its own record every
//! [`SERVE_RECORD_REFRESH`], well inside the [`SERVE_RECORD_TTL_MS`] validity,
//! so a long run never leaves remote nodes holding only an expired copy.

use std::error::Error;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::kad::store::{MemoryStore, MemoryStoreConfig, RecordStore};
use libp2p::kad::{self, Mode, Quorum, Record, RecordKey};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    connection_limits, identify, noise, ping, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm,
    SwarmBuilder,
};
use raven_core::bootstrap::{load_bootstrap, save_bootstrap, BootstrapConfig};
use raven_core::discovery::PeerRecord;
use raven_core::identity::Identity;
use raven_core::CAP_INTERNET;
use raven_swarm::ip_limits::{IpLimitConfig, IpLimits};
use raven_swarm::liveness::{close_if_dead, reconnect_delay, retry_jitter};

const RAVEN_KAD: StreamProtocol = StreamProtocol::new("/raven/kad/1.0.0");
/// Longest PeerRecord validity accepted from the network (serve signs 1 h).
const MAX_PEER_RECORD_TTL_MS: u64 = 24 * 60 * 60 * 1000;
/// Validity of the PeerRecord `serve` signs for itself.
const SERVE_RECORD_TTL_MS: u64 = 3_600_000;
/// How often `serve` re-signs and re-publishes it (half the validity).
const SERVE_RECORD_REFRESH: Duration = Duration::from_millis(SERVE_RECORD_TTL_MS / 2);
/// Longest dial string accepted in a foreign PeerRecord. The codec allows
/// 64 KiB; real multiaddrs, including circuit addresses, are far shorter.
const MAX_PEER_DIAL_BYTES: usize = 512;
/// Largest encoded foreign PeerRecord: dial plus the fixed 110 bytes
/// (2 length + 32 key + 4 caps + 8 expiry + 64 signature). Also the store's
/// per-value cap, so a full store pins under 1 MiB instead of 64 MiB.
const MAX_PEER_RECORD_BYTES: usize = 110 + MAX_PEER_DIAL_BYTES;
const MAX_ESTABLISHED: u32 = 64;
const MAX_PENDING_INCOMING: u32 = 16;
const MAX_ESTABLISHED_PER_PEER: u32 = 2;
/// Attempts at the one dial `dial` makes (the first plus its retries).
const MAX_PRIMARY_DIAL_ATTEMPTS: u32 = 3;

#[derive(NetworkBehaviour)]
struct RavenBehaviour {
    limits: connection_limits::Behaviour,
    ip_limits: IpLimits,
    kad: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

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

fn libp2p_keypair_from_raven(id: &Identity) -> Keypair {
    // Separate namespaces: derive libp2p key from a domain-separated hash of the
    // Raven seed so PeerId ≠ Raven address, but is stable per data-dir.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"raven/libp2p-peer-key/v1");
    h.update(id.seed_bytes());
    let d = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&d);
    Keypair::ed25519_from_bytes(seed).expect("ed25519 key")
}

fn build_swarm(id: &Identity) -> Result<libp2p::Swarm<RavenBehaviour>, Box<dyn Error>> {
    let kp = libp2p_keypair_from_raven(id);
    let peer_id = kp.public().to_peer_id();
    let swarm = SwarmBuilder::with_existing_identity(kp)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {
            // Records are small and signed; cap the value size so a flood of
            // validly signed junk cannot pin memory (see MAX_PEER_RECORD_BYTES).
            let store = MemoryStore::with_config(
                peer_id,
                MemoryStoreConfig {
                    // The store rejects values *at or above* this size.
                    max_value_bytes: MAX_PEER_RECORD_BYTES + 1,
                    ..Default::default()
                },
            );
            let mut kad_cfg = kad::Config::new(RAVEN_KAD);
            kad_cfg.set_query_timeout(Duration::from_secs(20));
            // Never let a remote PUT reach the store unvalidated (default is
            // Unfiltered: any peer could overwrite any key, including ours).
            kad_cfg.set_record_filtering(kad::StoreInserts::FilterBoth);
            let mut kad = kad::Behaviour::with_config(peer_id, store, kad_cfg);
            kad.set_mode(Some(Mode::Server));
            let identify = identify::Behaviour::new(identify::Config::new(
                "/raven/identify/1.0.0".into(),
                key.public(),
            ));
            let ping = ping::Behaviour::default();
            let limits = connection_limits::Behaviour::new(
                connection_limits::ConnectionLimits::default()
                    .with_max_established(Some(MAX_ESTABLISHED))
                    .with_max_pending_incoming(Some(MAX_PENDING_INCOMING))
                    .with_max_established_per_peer(Some(MAX_ESTABLISHED_PER_PEER)),
            );
            // One source address cannot hold the whole pending/established budget.
            let ip_limits = IpLimits::new(IpLimitConfig::default());
            RavenBehaviour {
                limits,
                ip_limits,
                kad,
                identify,
                ping,
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    Ok(swarm)
}

fn dht_key_for(raven_pub: &[u8; 32]) -> [u8; 32] {
    // Same derivation as PeerRecord::dht_key.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"rvn1/peer-key");
    hasher.update(raven_pub);
    hasher.finalize().into()
}

/// Validate a record another peer asked us to store. Returns the verified
/// PeerRecord; the caller stores it only on `Ok`.
fn validate_inbound_record(
    store: &MemoryStore,
    own_key: &RecordKey,
    record: &Record,
    now_ms: u64,
) -> Result<PeerRecord, String> {
    if &record.key == own_key {
        // We are the only authority for our own record.
        return Err("refusing remote write to own peer record".into());
    }
    // Bounds the dial string (and the verify work) before anything is decoded.
    if record.value.len() > MAX_PEER_RECORD_BYTES {
        return Err("peer record too large".into());
    }
    let rec = PeerRecord::decode(&record.value)?;
    rec.verify(now_ms)?;
    if rec.expires_at_ms > now_ms.saturating_add(MAX_PEER_RECORD_TTL_MS) {
        return Err("peer record validity exceeds maximum".into());
    }
    if record.key != RecordKey::new(&rec.dht_key()) {
        return Err("record key is not the signer's dht key".into());
    }
    if let Some(existing) = store.get(&record.key) {
        if let Ok(old) = PeerRecord::decode(&existing.value) {
            // No sequence number in PeerRecord: expiry is the only freshness
            // signal, so never replace a valid record with an older one.
            if old.verify(now_ms).is_ok() && old.expires_at_ms >= rec.expires_at_ms {
                return Err("stale peer record (not newer than stored)".into());
            }
        }
    }
    Ok(rec)
}

/// Handle inbound Kad PUTs under `StoreInserts::FilterBoth`.
fn on_inbound_put(swarm: &mut libp2p::Swarm<RavenBehaviour>, own_key: &RecordKey, record: Record) {
    let now = now_ms();
    let store = swarm.behaviour_mut().kad.store_mut();
    match validate_inbound_record(store, own_key, &record, now) {
        Ok(rec) => {
            let remaining = Duration::from_millis(rec.expires_at_ms.saturating_sub(now));
            let signed_expiry = std::time::Instant::now() + remaining;
            let expires = Some(
                record
                    .expires
                    .map_or(signed_expiry, |e| e.min(signed_expiry)),
            );
            match store.put(Record { expires, ..record }) {
                Ok(()) => println!("kad_inbound_put_stored"),
                Err(e) => println!("kad_inbound_put_rejected=store:{e}"),
            }
        }
        Err(e) => println!("kad_inbound_put_rejected={e}"),
    }
}

/// Sign our own PeerRecord for `dial` (valid for [`SERVE_RECORD_TTL_MS`] from
/// `now_ms`), store it locally and push it to the network. The local copy
/// expires with its signature, so a record that is no longer being refreshed
/// is purged here instead of being served (and re-replicated) as expired.
/// Calling this again replaces the stored record with a fresher one.
fn publish_own_record(
    swarm: &mut Swarm<RavenBehaviour>,
    raven_id: &Identity,
    dial: &str,
    now_ms: u64,
) -> Result<PeerRecord, Box<dyn Error>> {
    let local_peer = *swarm.local_peer_id();
    let rec = PeerRecord {
        dial: dial.to_owned(),
        ed25519_pub: [0u8; 32],
        // This binary speaks Raven's Internet request/response protocol. It is
        // not a Circuit Relay server.
        caps: CAP_INTERNET,
        expires_at_ms: now_ms + SERVE_RECORD_TTL_MS,
        signature: [0u8; 64],
    }
    .sign(raven_id)?;
    let record = Record {
        key: RecordKey::new(&rec.dht_key()),
        value: rec.encode()?,
        publisher: Some(local_peer),
        expires: Some(std::time::Instant::now() + Duration::from_millis(SERVE_RECORD_TTL_MS)),
    };
    // Local store first (solo-node Quorum put would fail).
    swarm
        .behaviour_mut()
        .kad
        .store_mut()
        .put(record.clone())
        .map_err(|e| format!("local kad put: {e}"))?;
    // Also start a network put (replication); it may fail until a peer dials.
    let _ = swarm.behaviour_mut().kad.put_record(record, Quorum::One);
    Ok(rec)
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

/// Check a record returned by a GET before trusting its dial string.
fn verify_found_record(
    record: &Record,
    dht_key: &[u8; 32],
    raven_pub: &[u8; 32],
    now_ms: u64,
) -> Result<PeerRecord, String> {
    if record.key != RecordKey::new(dht_key) {
        return Err("record key mismatch".into());
    }
    let rec = PeerRecord::decode(&record.value)?;
    rec.verify(now_ms)?;
    if rec.ed25519_pub != *raven_pub {
        return Err("peer record pub mismatch".into());
    }
    Ok(rec)
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

    fn signed(id: &Identity, dial: &str, expires_at_ms: u64) -> PeerRecord {
        PeerRecord {
            dial: dial.into(),
            ed25519_pub: [0u8; 32],
            caps: CAP_INTERNET,
            expires_at_ms,
            signature: [0u8; 64],
        }
        .sign(id)
        .unwrap()
    }

    fn kad_record(rec: &PeerRecord) -> Record {
        Record {
            key: RecordKey::new(&rec.dht_key()),
            value: rec.encode().unwrap(),
            publisher: None,
            expires: None,
        }
    }

    #[test]
    fn inbound_put_filter_accepts_only_valid_newer_foreign_records() {
        let now = 1_000_000;
        let own = Identity::from_seed(&[1; 32]);
        let other = Identity::from_seed(&[2; 32]);
        let own_key = RecordKey::new(&dht_key_for(&own.public_key_bytes()));
        let mut store = MemoryStore::new(PeerId::random());

        let fresh = signed(&other, "/ip4/10.0.0.2/tcp/1", now + 60_000);
        let rec = validate_inbound_record(&store, &own_key, &kad_record(&fresh), now).unwrap();
        assert_eq!(rec, fresh);
        store.put(kad_record(&fresh)).unwrap();

        // Replay of an older (still valid) record cannot roll the address back.
        let older = signed(&other, "/ip4/6.6.6.6/tcp/1", now + 30_000);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&older), now).is_err());
        let newer = signed(&other, "/ip4/10.0.0.3/tcp/1", now + 90_000);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&newer), now).is_ok());

        // Our own key is never writable remotely, even with a valid signature.
        let own_rec = signed(&own, "/ip4/6.6.6.6/tcp/1", now + 90_000);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&own_rec), now).is_err());

        // Garbage, forged, mis-keyed, expired and over-long records are refused.
        let mut garbage = kad_record(&fresh);
        garbage.value = b"not a peer record".to_vec();
        assert!(validate_inbound_record(&store, &own_key, &garbage, now).is_err());
        let mut forged = signed(&other, "/ip4/10.0.0.9/tcp/1", now + 120_000);
        forged.dial = "/ip4/6.6.6.6/tcp/1".into();
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&forged), now).is_err());
        let third = Identity::from_seed(&[3; 32]);
        let mut miskeyed = kad_record(&signed(&third, "/ip4/10.0.0.4/tcp/1", now + 60_000));
        miskeyed.key = RecordKey::new(&fresh.dht_key());
        assert!(validate_inbound_record(&store, &own_key, &miskeyed, now).is_err());
        let expired = signed(&third, "/ip4/10.0.0.4/tcp/1", now - 1);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&expired), now).is_err());
        let forever = signed(&third, "/ip4/10.0.0.4/tcp/1", u64::MAX);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&forever), now).is_err());
    }

    /// Regression: with StoreInserts::Unfiltered any peer could overwrite the
    /// serving node's own signed PeerRecord.
    #[tokio::test]
    async fn remote_put_cannot_replace_own_record() {
        let own = Identity::from_seed(&[4; 32]);
        let mut swarm = build_swarm(&own).unwrap();
        let own_key = RecordKey::new(&dht_key_for(&own.public_key_bytes()));
        let mine = signed(&own, "/ip4/127.0.0.1/tcp/4001", now_ms() + 3_600_000);
        swarm
            .behaviour_mut()
            .kad
            .store_mut()
            .put(kad_record(&mine))
            .unwrap();

        let mut hostile = kad_record(&signed(&own, "/ip4/6.6.6.6/tcp/1", now_ms() + 7_200_000));
        hostile.key = own_key.clone();
        on_inbound_put(&mut swarm, &own_key, hostile);
        let mut garbage = kad_record(&mine);
        garbage.value = vec![0xff; 8];
        on_inbound_put(&mut swarm, &own_key, garbage);

        let stored = swarm
            .behaviour_mut()
            .kad
            .store_mut()
            .get(&own_key)
            .unwrap()
            .into_owned();
        assert_eq!(PeerRecord::decode(&stored.value).unwrap(), mine);

        let other = Identity::from_seed(&[5; 32]);
        let theirs = signed(&other, "/ip4/10.0.0.5/tcp/1", now_ms() + 60_000);
        on_inbound_put(&mut swarm, &own_key, kad_record(&theirs));
        let key = RecordKey::new(&theirs.dht_key());
        let stored = swarm
            .behaviour_mut()
            .kad
            .store_mut()
            .get(&key)
            .unwrap()
            .into_owned();
        assert!(
            stored.expires.is_some(),
            "stored record expires with its signature"
        );
    }

    /// Regression: the first undecodable/forged FoundRecord aborted the dial.
    #[test]
    fn found_record_check_skips_instead_of_failing() {
        let now = 1_000_000;
        let target = Identity::from_seed(&[6; 32]);
        let pub_key = target.public_key_bytes();
        let key = dht_key_for(&pub_key);
        let good = signed(&target, "/ip4/10.0.0.6/tcp/1", now + 60_000);
        assert_eq!(
            verify_found_record(&kad_record(&good), &key, &pub_key, now).unwrap(),
            good
        );
        let mut poisoned = kad_record(&good);
        poisoned.value = b"poison".to_vec();
        assert!(verify_found_record(&poisoned, &key, &pub_key, now).is_err());
        let impostor = Identity::from_seed(&[7; 32]);
        let mut wrong = kad_record(&signed(&impostor, "/ip4/6.6.6.6/tcp/1", now + 60_000));
        wrong.key = RecordKey::new(&key);
        assert!(verify_found_record(&wrong, &key, &pub_key, now).is_err());
    }

    /// Regression: a validly signed record with a 64 KiB dial string passed
    /// validation, so ~1024 throwaway identities could pin ~64 MiB in the store.
    #[test]
    fn inbound_records_are_size_bounded() {
        let now = 1_000_000;
        let own = Identity::from_seed(&[8; 32]);
        let other = Identity::from_seed(&[9; 32]);
        let own_key = RecordKey::new(&dht_key_for(&own.public_key_bytes()));
        let store = MemoryStore::new(PeerId::random());

        let longest = signed(&other, &"x".repeat(MAX_PEER_DIAL_BYTES), now + 60_000);
        assert_eq!(kad_record(&longest).value.len(), MAX_PEER_RECORD_BYTES);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&longest), now).is_ok());

        let too_long = signed(&other, &"x".repeat(MAX_PEER_DIAL_BYTES + 1), now + 60_000);
        assert_eq!(
            validate_inbound_record(&store, &own_key, &kad_record(&too_long), now),
            Err("peer record too large".to_owned())
        );
        let huge = signed(&other, &"x".repeat(60_000), now + 60_000);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&huge), now).is_err());
        // Real dial strings, including circuit addresses, are far below the cap.
        let circuit = "/ip4/203.0.113.7/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        assert!(circuit.len() < MAX_PEER_DIAL_BYTES / 2);
    }

    /// The store itself refuses oversized values, whatever path they take in.
    #[tokio::test]
    async fn store_refuses_values_above_the_record_cap() {
        let mut swarm = build_swarm(&Identity::from_seed(&[12; 32])).unwrap();
        let store = swarm.behaviour_mut().kad.store_mut();
        let record = |len: usize, key: &[u8]| Record {
            key: RecordKey::new(&key),
            value: vec![0; len],
            publisher: None,
            expires: None,
        };
        assert!(store.put(record(MAX_PEER_RECORD_BYTES, b"fits")).is_ok());
        assert!(store
            .put(record(MAX_PEER_RECORD_BYTES + 1, b"too big"))
            .is_err());
    }

    /// Regression: `serve` signed its record once with a 1 h validity and never
    /// refreshed it, so after an hour every GET returned an expired record.
    #[tokio::test]
    async fn own_record_is_refreshed_before_it_expires() {
        let id = Identity::from_seed(&[10; 32]);
        let mut swarm = build_swarm(&id).unwrap();
        let dial = "/ip4/127.0.0.1/tcp/4001";
        let t0 = now_ms();
        let first = publish_own_record(&mut swarm, &id, dial, t0).unwrap();

        // The refresh timer fires at half the validity at the latest.
        assert!(SERVE_RECORD_REFRESH * 2 <= Duration::from_millis(SERVE_RECORD_TTL_MS));
        let refresh_ms = SERVE_RECORD_REFRESH.as_millis() as u64;
        let second = publish_own_record(&mut swarm, &id, dial, t0 + refresh_ms).unwrap();

        // Once the first signature has run out, only the refreshed record is
        // servable; this is exactly what dialers saw before the fix.
        let late = t0 + SERVE_RECORD_TTL_MS + 1;
        assert_eq!(first.verify(late), Err("PEER_EXPIRED".to_owned()));
        assert!(second.verify(late).is_ok());

        // A remote node holding the first copy accepts the refreshed one.
        let remote_own = RecordKey::new(&dht_key_for(
            &Identity::from_seed(&[11; 32]).public_key_bytes(),
        ));
        let mut remote = MemoryStore::new(PeerId::random());
        remote.put(kad_record(&first)).unwrap();
        assert!(validate_inbound_record(
            &remote,
            &remote_own,
            &kad_record(&second),
            t0 + refresh_ms
        )
        .is_ok());

        // Locally the refreshed record replaced the old one, and it expires
        // with its signature instead of being served forever.
        let key = RecordKey::new(&second.dht_key());
        let stored = swarm
            .behaviour_mut()
            .kad
            .store_mut()
            .get(&key)
            .unwrap()
            .into_owned();
        assert_eq!(PeerRecord::decode(&stored.value).unwrap(), second);
        assert!(stored.expires.is_some());
    }

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
