//! Raven local node — TCP framed RavenEnvelopeV1, persistent queue, ACK/dedup.
//! Bridge V1: opaque cross-transport forward (see `bridge_run`).
//! Frame: u32 BE length || envelope bytes. Never logs private keys or plaintext.

mod bridge_run;
#[cfg(feature = "corebluetooth")]
mod corebluetooth_exp;
#[cfg(any(unix, windows))]
mod ipc_server;
mod lan_direct;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
        #[arg(long, default_value = "./raven-data")]
        data_dir: PathBuf,
    },
    /// Print public address for this data dir.
    Address {
        #[arg(long, default_value = "./raven-data")]
        data_dir: PathBuf,
    },
    /// Run listener; optionally send one message then wait for ACK.
    Run {
        #[arg(long, default_value = "./raven-data")]
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
        #[arg(long, default_value = "./raven-data")]
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
        #[arg(long, default_value = "./raven-data")]
        data_dir: PathBuf,
    },
    /// Replay pending queue items to peer (crash recovery).
    Flush {
        #[arg(long, default_value = "./raven-data")]
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
        #[arg(long, default_value = "./raven-data")]
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
        #[arg(long, default_value_t = 0)]
        timeout_secs: u64,
    },
    /// Report BLE adapter selection (mock vs platform). Safe fields only.
    BleStatus,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
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
    let write = async {
        let len = (bytes.len() as u32).to_be_bytes();
        stream.write_all(&len).await.map_err(|e| e.to_string())?;
        stream.write_all(bytes).await.map_err(|e| e.to_string())?;
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
    #[cfg_attr(not(feature = "unsafe-demo-crypto"), allow(dead_code))]
    ack_pub: Option<[u8; 32]>,
    recv_count: u32,
    got_ack: bool,
}

impl NodeState {
    fn msg_verify_pub(&self) -> Option<[u8; 32]> {
        self.origin_pub.or(self.peer_pub)
    }

    #[cfg(feature = "unsafe-demo-crypto")]
    fn ack_verify_pub(&self) -> Option<[u8; 32]> {
        self.ack_pub.or(self.peer_pub)
    }

    fn handle_inbound(&mut self, raw: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let env = Envelope::unpack(raw).ok_or_else(|| "malformed envelope".to_string())?;
        if now_ms() > env.expires_at {
            return Ok(None);
        }

        match env.env_type {
            x if x == EnvType::Message as u8 => {
                let peer_pub = self
                    .msg_verify_pub()
                    .ok_or_else(|| "origin/peer pub required to verify".to_string())?;
                if !env.verify(&peer_pub) {
                    return Err("envelope auth failed".into());
                }
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
                    let _ = env;
                    Err("ATSAM_SESSION_REQUIRED: plaintext legacy ACK bodies are disabled".into())
                }

                #[cfg(feature = "unsafe-demo-crypto")]
                {
                    let peer_pub = self
                        .ack_verify_pub()
                        .ok_or_else(|| "ack/peer pub required to verify".to_string())?;
                    if !env.verify(&peer_pub) {
                        return Err("ack envelope auth failed".into());
                    }
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
            let reply = {
                let mut st = state.lock().await;
                // Detailed parser/authentication failures are deliberately not logged:
                // untrusted peers must not create a log-amplification channel.
                st.handle_inbound(&frame).ok().flatten()
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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
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
            let peer_pub = peer_pub_hex.as_ref().and_then(|s| parse_pub_hex(s).ok());
            let origin_pub = origin_pub_hex.as_ref().and_then(|s| parse_pub_hex(s).ok());
            let ack_pub = ack_pub_hex.as_ref().and_then(|s| parse_pub_hex(s).ok());
            let seal_to = seal_to_pub_hex
                .as_ref()
                .and_then(|s| parse_pub_hex(s).ok())
                .or(peer_pub);
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
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            let st = state_accept.clone();
                            // Admission is intentionally non-blocking. When full, the
                            // just-accepted socket is dropped without spawning work.
                            let _ = spawn_default_connection_handler(
                                stream,
                                st,
                                limiter_accept.clone(),
                            );
                        }
                        Err(e) => {
                            eprintln!("accept err: {e}");
                            break;
                        }
                    }
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
                        .unwrap();
                }
                let addr: SocketAddr = peer_s.parse().unwrap_or_else(|e| {
                    eprintln!("peer parse: {e}");
                    std::process::exit(1);
                });
                let mut stream = TcpStream::connect(addr).await.unwrap_or_else(|e| {
                    eprintln!("connect: {e}");
                    std::process::exit(1);
                });
                write_frame(&mut stream, &packed).await.unwrap();
                {
                    let st = state.lock().await;
                    st.queue.mark_state(&mid, DeliveryState::Sent).unwrap();
                }
                let st = state.clone();
                if spawn_default_connection_handler(stream, st, connection_limiter.clone()).is_err()
                {
                    eprintln!("raven-node: connection handler capacity reached");
                }
            } else if let Some(peer_s) = peer.as_ref() {
                // Dial-only (e.g. C connects to B mock-BLE to receive).
                let addr: SocketAddr = peer_s.parse().unwrap_or_else(|e| {
                    eprintln!("peer parse: {e}");
                    std::process::exit(1);
                });
                let stream = TcpStream::connect(addr).await.unwrap_or_else(|e| {
                    eprintln!("connect: {e}");
                    std::process::exit(1);
                });
                let st = state.clone();
                if spawn_default_connection_handler(stream, st, connection_limiter.clone()).is_err()
                {
                    eprintln!("raven-node: connection handler capacity reached");
                }
            }

            let deadline =
                tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
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
            let (pending, total) =
                match ForwardQueue::open(&bridge_run::forward_queue_path(&data_dir)) {
                    Ok(q) => (q.count_pending().unwrap_or(0), q.count_all().unwrap_or(0)),
                    Err(_) => (0, 0),
                };
            let snap =
                BridgeStatusSnapshot::from_policy(&policy, &["lan", "mock_ble"], pending, total);
            println!("bridge={}", snap.bridge);
            println!("store={}", snap.store);
            println!("relay={}", snap.relay);
            println!("endpoint={}", snap.endpoint);
            println!("auto_policy={}", snap.auto_policy);
            println!("transports={}", snap.transports.join(","));
            println!("forward_queue_pending={}", snap.forward_queue_pending);
            println!("forward_queue_total={}", snap.forward_queue_total);
            println!("capabilities={}", snap.capabilities.join(","));
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
            let queue = OutgoingQueue::open(&queue_path(&data_dir)).unwrap();
            let peer_pub = parse_pub_hex(&peer_pub_hex).unwrap();
            let pending = queue.pending().unwrap();
            eprintln!("raven-node: flushing {} pending", pending.len());
            let addr: SocketAddr = peer.parse().unwrap();
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
            for item in pending {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                write_frame(&mut stream, &item.packed_envelope)
                    .await
                    .unwrap();
                {
                    let st = state.lock().await;
                    st.queue
                        .mark_state(&item.message_id, DeliveryState::Sent)
                        .unwrap();
                }
                let st = state.clone();
                let Ok(mut handle) =
                    spawn_default_connection_handler(stream, st, connection_limiter.clone())
                else {
                    eprintln!("raven-node: connection handler capacity reached");
                    continue;
                };
                if tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), &mut handle)
                    .await
                    .is_err()
                {
                    // Dropping a JoinHandle detaches it. Explicit cancellation is
                    // required so a stalled peer cannot accumulate flush handlers.
                    abort_handler(&handle);
                    let _ = handle.await;
                }
            }
            let st = state.lock().await;
            if st.got_ack {
                eprintln!("raven-node: flush got ACK");
            } else {
                eprintln!("raven-node: flush done (check pending)");
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
            timeout_secs,
        } => {
            // Identity preflight MUST run before any profile-state creation:
            // creating forward_queue.sqlite first would make a fresh profile
            // fail require_proven_first_install (the queue file is not on the
            // first-install allow-list), wedging first install permanently.
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
            let data_lan = data_dir.clone();
            let mut lan_task =
                tokio::spawn(async move { lan_direct::run_listener(data_lan, lan_listen).await });
            for _ in 0..50 {
                if lan_direct::listener_is_up() {
                    break;
                }
                if lan_task.is_finished() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            if !lan_direct::listener_is_up() {
                eprintln!("lan_direct failed to bind");
                match lan_task.await {
                    Ok(Err(e)) => eprintln!("lan_direct failed: {e}"),
                    Ok(Ok(())) => {}
                    Err(e) => eprintln!("lan_direct join: {e}"),
                }
                ipc_task.abort();
                std::process::exit(1);
            }
            // Mock BLE stays on ble_listen. Do not fanout the production LAN port.
            tokio::select! {
                r = &mut lan_task => {
                    match r {
                        Ok(Err(e)) => eprintln!("lan_direct failed: {e}"),
                        Ok(Ok(())) => eprintln!("lan_direct listener exited"),
                        Err(e) => eprintln!("lan_direct join: {e}"),
                    }
                    ipc_task.abort();
                    std::process::exit(1);
                }
                r = &mut ipc_task => {
                    if let Err(e) = r {
                        eprintln!("ipc join: {e}");
                    }
                    lan_task.abort();
                    std::process::exit(1);
                }
                bridge_result = bridge_run::run_bridge_daemon(
                    data_dir,
                    "127.0.0.1:0".into(),
                    ble_listen,
                    None,
                    None,
                    None,
                    timeout_secs,
                ) => {
                    ipc_task.abort();
                    lan_task.abort();
                    if let Err(e) = bridge_result {
                        eprintln!("service bridge failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
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
