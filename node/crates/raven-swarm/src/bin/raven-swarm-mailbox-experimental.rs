//! Explicitly feature-gated offline mailbox transport harness.
//!
//! This is intentionally a separate binary. Building or running the normal
//! `raven-swarm` does not advertise `/raven/offline-mailbox/1.0.0`.
//!
//! The server bounds connections (globally, per PeerId and per source IP),
//! charges each request to the sending PeerId and to the connection's source
//! network (see `MailboxService::handle_from`), handles requests (parse,
//! quota, fsync'd snapshot) on the blocking pool so the swarm event loop never
//! stalls, and drops requests beyond a fixed in-flight budget, global and per
//! peer.

use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, Subcommand};
use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{Event, Message, OutboundRequestId, ResponseChannel};
use libp2p::swarm::{ConnectionId, NetworkBehaviour, SwarmEvent};
use libp2p::{connection_limits, noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};
use raven_core::identity::Identity;
use raven_core::store_object::StoreObject;
use raven_swarm::ip_limits::{IpLimitConfig, IpLimits};
use raven_swarm::mailbox::{
    mailbox_behaviour, multiaddr_ip, unix_time_ms, InflightLimiter, MailboxBehaviour,
    MailboxReject, MailboxRequest, MailboxResponse, MailboxRole, MailboxService,
    MAX_INFLIGHT_PER_PEER, MAX_INFLIGHT_REQUESTS, MAX_PAGE_OBJECTS, MAX_STORE_OBJECT_WIRE_BYTES,
};

const MAX_ESTABLISHED: u32 = 128;
const MAX_PENDING_INCOMING: u32 = 32;
const MAX_ESTABLISHED_PER_PEER: u32 = 2;

#[derive(NetworkBehaviour)]
struct MailboxNode {
    limits: connection_limits::Behaviour,
    ip_limits: IpLimits,
    mailbox: MailboxBehaviour,
}

#[derive(Parser, Debug)]
#[command(
    name = "raven-swarm-mailbox-experimental",
    about = "EXPERIMENTAL: bounded opaque Raven offline mailbox over libp2p"
)]
struct Cli {
    /// Required runtime acknowledgement in addition to the Cargo feature.
    #[arg(long, global = true, default_value_t = false)]
    allow_experimental_mailbox: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Persist and serve strict StoreObjectV1 rows. Zero timeout runs until SIGINT.
    Serve {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value = "/ip4/127.0.0.1/tcp/0")]
        listen: String,
        #[arg(long)]
        write_multiaddr: Option<PathBuf>,
        #[arg(long)]
        write_peer_id: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        timeout_secs: u64,
    },
    /// Deposit one already-packed, opaque StoreObjectV1.
    Put {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        peer_id: String,
        #[arg(long)]
        object_hex: String,
        #[arg(long, default_value_t = 15)]
        timeout_secs: u64,
    },
    /// Fetch one bounded page by a 16-byte rotating store_tag capability.
    Get {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        peer_id: String,
        #[arg(long)]
        store_tag_hex: String,
        /// Opaque 32-byte continuation token returned by a previous page.
        #[arg(long)]
        after_hex: Option<String>,
        #[arg(long, default_value_t = MAX_PAGE_OBJECTS)]
        limit: u16,
        #[arg(long, default_value_t = 15)]
        timeout_secs: u64,
    },
}

fn load_identity(data_dir: &Path) -> Result<Identity, Box<dyn Error>> {
    Ok(raven_core::load_or_create_identity(data_dir).map(|(identity, _)| identity)?)
}

fn libp2p_keypair(identity: &Identity) -> Keypair {
    use sha2::{Digest, Sha256};

    let mut hash = Sha256::new();
    hash.update(b"raven/libp2p-peer-key/v1");
    hash.update(identity.seed_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash.finalize());
    Keypair::ed25519_from_bytes(seed).expect("domain-separated Ed25519 seed")
}

fn build_swarm(
    identity: &Identity,
    role: MailboxRole,
) -> Result<Swarm<MailboxNode>, Box<dyn Error>> {
    Ok(
        SwarmBuilder::with_existing_identity(libp2p_keypair(identity))
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_behaviour(|_| MailboxNode {
                limits: connection_limits::Behaviour::new(
                    connection_limits::ConnectionLimits::default()
                        .with_max_established(Some(MAX_ESTABLISHED))
                        .with_max_pending_incoming(Some(MAX_PENDING_INCOMING))
                        .with_max_established_per_peer(Some(MAX_ESTABLISHED_PER_PEER)),
                ),
                // PeerIds are free, so also cap what one source address holds.
                ip_limits: IpLimits::new(IpLimitConfig::default()),
                mailbox: mailbox_behaviour(role),
            })?
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_secs(30))
            })
            .build(),
    )
}

fn remote(peer: &str, peer_id: &str) -> Result<(Multiaddr, PeerId), Box<dyn Error>> {
    let address: Multiaddr = peer.parse()?;
    let peer_id: PeerId = peer_id.parse()?;
    Ok((address, peer_id))
}

fn dial_address(address: Multiaddr, peer_id: PeerId) -> Multiaddr {
    if address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2p(_)))
    {
        address
    } else {
        address.with(Protocol::P2p(peer_id))
    }
}

async fn serve(
    data_dir: PathBuf,
    listen: String,
    write_multiaddr: Option<PathBuf>,
    write_peer_id: Option<PathBuf>,
    timeout_secs: u64,
) -> Result<(), Box<dyn Error>> {
    let identity = load_identity(&data_dir)?;
    let service = Arc::new(Mutex::new(MailboxService::open(&data_dir)?));
    let mut swarm = build_swarm(&identity, MailboxRole::Server)?;
    let local_peer = *swarm.local_peer_id();
    swarm.listen_on(listen.parse()?)?;
    // Requests being handled at once, overall and per peer; further requests
    // are dropped (the client sees an outbound failure) instead of queueing
    // without bound or letting one peer take the whole budget.
    let inflight = InflightLimiter::new(MAX_INFLIGHT_REQUESTS, MAX_INFLIGHT_PER_PEER);
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<(
        ResponseChannel<MailboxResponse>,
        MailboxResponse,
    )>(MAX_INFLIGHT_REQUESTS);
    // Remote IP per live connection (bounded by the connection limits), so a
    // deposit is charged to its source network, not only to a free PeerId.
    let mut origins: HashMap<ConnectionId, Option<IpAddr>> = HashMap::new();

    let deadline =
        (timeout_secs > 0).then(|| tokio::time::Instant::now() + Duration::from_secs(timeout_secs));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = async {
                if let Some(deadline) = deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => return Ok(()),
            Some((channel, response)) = done_rx.recv() => {
                let accepted = matches!(response, MailboxResponse::Stored | MailboxResponse::Objects { .. });
                if swarm.behaviour_mut().mailbox.send_response(channel, response).is_err() {
                    eprintln!("mailbox_response_dropped");
                } else {
                    println!("mailbox_request_complete accepted={}", u8::from(accepted));
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("listen_addr={address}");
                        println!("libp2p_peer_id={local_peer}");
                        if let Some(path) = &write_multiaddr {
                            std::fs::write(path, address.to_string())?;
                        }
                        if let Some(path) = &write_peer_id {
                            std::fs::write(path, local_peer.to_string())?;
                        }
                    }
                    SwarmEvent::ConnectionEstablished { connection_id, endpoint, .. } => {
                        origins.insert(connection_id, multiaddr_ip(endpoint.get_remote_address()));
                    }
                    SwarmEvent::ConnectionClosed { connection_id, .. } => {
                        origins.remove(&connection_id);
                    }
                    SwarmEvent::Behaviour(MailboxNodeEvent::Mailbox(Event::Message {
                        peer,
                        connection_id,
                        message: Message::Request { request, channel, .. },
                    })) => {
                        // Unknown connection: charge the shared "no address" bucket.
                        let origin = origins.get(&connection_id).copied().flatten();
                        let Some(permit) = inflight.try_acquire(peer) else {
                            // Dropping the channel fails the request for the client.
                            eprintln!("mailbox_busy_dropped");
                            continue;
                        };
                        let service = service.clone();
                        let done = done_tx.clone();
                        // Parsing, quota checks and the fsync'd snapshot write are
                        // blocking work: keep them off the swarm event loop.
                        tokio::task::spawn_blocking(move || {
                            let response = match service.lock() {
                                Ok(mut service) => {
                                    let was_available = service.is_available();
                                    let response =
                                        service.handle_from(peer, origin, request, unix_time_ms());
                                    // Never a silent latch: report each way in or out.
                                    match (was_available, service.is_available()) {
                                        (true, false) => eprintln!(
                                            "mailbox_unavailable persistence_failures={}",
                                            service.persistence_failures()
                                        ),
                                        (false, true) => eprintln!(
                                            "mailbox_recovered recoveries={}",
                                            service.recoveries()
                                        ),
                                        _ => {}
                                    }
                                    response
                                }
                                Err(_) => MailboxResponse::Rejected(MailboxReject::Persistence),
                            };
                            let _ = done.blocking_send((channel, response));
                            drop(permit);
                        });
                    }
                    SwarmEvent::Behaviour(MailboxNodeEvent::Mailbox(Event::InboundFailure { error, .. })) => {
                        eprintln!("mailbox_inbound_failure error={error}");
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn request(
    data_dir: PathBuf,
    peer: String,
    peer_id: String,
    request: MailboxRequest,
    timeout_secs: u64,
) -> Result<MailboxResponse, Box<dyn Error>> {
    let identity = load_identity(&data_dir)?;
    let mut swarm = build_swarm(&identity, MailboxRole::Client)?;
    let (address, remote_peer) = remote(&peer, &peer_id)?;
    swarm.dial(dial_address(address, remote_peer))?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let mut request_id: Option<OutboundRequestId> = None;

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return Err("mailbox request timeout".into()),
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id: connected, .. }
                        if connected == remote_peer && request_id.is_none() => {
                        request_id = Some(swarm.behaviour_mut().mailbox.send_request(&remote_peer, request.clone()));
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        return Err(format!("mailbox dial failed: {error}").into());
                    }
                    SwarmEvent::Behaviour(MailboxNodeEvent::Mailbox(Event::Message {
                        message: Message::Response { request_id: got, response },
                        ..
                    })) if Some(got) == request_id => return Ok(response),
                    SwarmEvent::Behaviour(MailboxNodeEvent::Mailbox(Event::OutboundFailure { request_id: got, error, .. }))
                        if Some(got) == request_id => {
                        return Err(format!("mailbox request failed: {error}").into());
                    }
                    _ => {}
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    if !cli.allow_experimental_mailbox {
        return Err("security hold: pass --allow-experimental-mailbox explicitly".into());
    }

    match cli.command {
        Command::Serve {
            data_dir,
            listen,
            write_multiaddr,
            write_peer_id,
            timeout_secs,
        } => {
            serve(
                data_dir,
                listen,
                write_multiaddr,
                write_peer_id,
                timeout_secs,
            )
            .await
        }
        Command::Put {
            data_dir,
            peer,
            peer_id,
            object_hex,
            timeout_secs,
        } => {
            if object_hex.len() > MAX_STORE_OBJECT_WIRE_BYTES.saturating_mul(2) {
                return Err("store object exceeds hard limit".into());
            }
            let object = hex::decode(object_hex)?;
            StoreObject::unpack(&object)
                .map_err(|error| format!("invalid StoreObjectV1: {error}"))?;
            match request(
                data_dir,
                peer,
                peer_id,
                MailboxRequest::Put(object),
                timeout_secs,
            )
            .await?
            {
                MailboxResponse::Stored => {
                    println!("stored=1");
                    Ok(())
                }
                MailboxResponse::Rejected(code) => {
                    Err(format!("mailbox rejected put: {code:?}").into())
                }
                _ => Err("unexpected mailbox put response".into()),
            }
        }
        Command::Get {
            data_dir,
            peer,
            peer_id,
            store_tag_hex,
            after_hex,
            limit,
            timeout_secs,
        } => {
            let tag = hex::decode(store_tag_hex)?;
            if tag.len() != 16 {
                return Err("store_tag_hex must be exactly 16 bytes".into());
            }
            let mut store_tag = [0u8; 16];
            store_tag.copy_from_slice(&tag);
            let after = match after_hex {
                Some(value) => {
                    let decoded = hex::decode(value)?;
                    if decoded.len() != 32 {
                        return Err("after_hex must be exactly 32 bytes".into());
                    }
                    let mut token = [0u8; 32];
                    token.copy_from_slice(&decoded);
                    Some(token)
                }
                None => None,
            };
            match request(
                data_dir,
                peer,
                peer_id,
                MailboxRequest::Get {
                    store_tag,
                    after,
                    limit,
                },
                timeout_secs,
            )
            .await?
            {
                MailboxResponse::Objects {
                    next_cursor,
                    objects,
                } => {
                    println!("object_count={}", objects.len());
                    for object in objects {
                        let decoded = StoreObject::unpack(&object)
                            .map_err(|error| format!("store returned invalid object: {error}"))?;
                        if decoded.store_tag != store_tag {
                            return Err("store returned an object for a different store_tag".into());
                        }
                        println!("object_hex={}", hex::encode(object));
                    }
                    match next_cursor {
                        Some(value) => println!("next_cursor={}", hex::encode(value)),
                        None => println!("next_cursor=end"),
                    }
                    Ok(())
                }
                MailboxResponse::Rejected(code) => {
                    Err(format!("mailbox rejected get: {code:?}").into())
                }
                _ => Err("unexpected mailbox get response".into()),
            }
        }
    }
}
