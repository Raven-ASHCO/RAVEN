//! Local IPC server — UDS on Unix, named pipe on Windows.
//!
//! Shared request handling and length-prefixed JSON framing live here
//! (`raven_core::ipc`, IPC_VERSION=1). Transport bind/accept is cfg-gated:
//! Unix uses a `0600` socket (bound atomically, single-instance lock, owned
//! data dir) plus peer-cred UID check; Windows binds the per-user pipe
//! `{WINDOWS_NAMED_PIPE}-{SID}` with a current-user DACL (fail-closed).
//! Requests still refuse secret field names (`raven_core::ipc`).
//! `SealUnderSession` is served only after the same peer-cred / pipe-ACL gate.
//! Blocking work (SQLite, identity/secret store, seal) runs on the blocking
//! pool; `Ping` is answered inline so a busy daemon never looks dead.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use raven_core::bridge::authenticated_object_digest;
use raven_core::envelope::Envelope;
use raven_core::forward_queue::{ForwardItem, ForwardQueue, ForwardState};
#[cfg(unix)]
use raven_core::ipc::default_socket_path;
use raven_core::ipc::{
    decode_request_checked, encode_response, IpcRequest, IpcResponse, IPC_VERSION, MAX_IPC_FRAME,
};
use raven_core::load_identity_required;
use raven_core::{seal_app_payload_under_session, ATSAM_LINEAGE_REVOKED, ATSAM_SESSION_REQUIRED};
use tokio::time::Duration;

use crate::internet_direct;
use crate::lan_direct;

const IPC_IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent IPC connections. Accept waits for a slot (kernel backlog holds
/// the rest), so a flood of local clients cannot exhaust the daemon's fds.
pub(crate) const MAX_IPC_CONNECTIONS: usize = 64;
/// How often the UDS server checks that its socket path still points at it.
#[cfg(unix)]
const SOCKET_WATCH_INTERVAL: Duration = Duration::from_secs(1);
const LAN_DIAL_TIMEOUT: Duration = Duration::from_secs(45);
const INTERNET_DIAL_TIMEOUT: Duration = Duration::from_secs(45);
use raven_core::node_policy::{load_policy, save_policy};
use raven_core::queue::{DeliveryState, OutgoingQueue, QueueItem};
use raven_core::transport::TransportKind;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
#[cfg(unix)]
use tokio::sync::Semaphore;

#[cfg(windows)]
#[path = "ipc_server_windows.rs"]
mod windows;

#[cfg(unix)]
pub fn socket_path(data_dir: &Path) -> PathBuf {
    default_socket_path(data_dir)
}

/// Return true iff the connected peer's effective UID matches ours.
/// Denies cross-user local clients even if they somehow open the socket.
#[cfg(unix)]
fn peer_uid_matches_self(stream: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let self_uid = unsafe { libc::geteuid() };

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        let mut euid: libc::uid_t = 0;
        let mut egid: libc::gid_t = 0;
        let rc = unsafe { libc::getpeereid(fd, &mut euid, &mut egid) };
        if rc != 0 {
            return false;
        }
        euid == self_uid
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return false;
        }
        cred.uid == self_uid
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        let _ = (fd, self_uid);
        // Unknown Unix: no peer-cred API wired up. Fail closed rather than
        // trusting socket mode 0600 alone.
        false
    }
}

async fn read_frame<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let read = async {
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| e.to_string())?;
        let n = u32::from_be_bytes(len_buf) as usize;
        if n == 0 || n > raven_core::MAX_IPC_FRAME {
            return Err("IPC_FRAME".into());
        }
        let mut buf = vec![0u8; 4 + n];
        buf[0..4].copy_from_slice(&len_buf);
        stream
            .read_exact(&mut buf[4..])
            .await
            .map_err(|e| e.to_string())?;
        Ok(buf)
    };
    tokio::time::timeout(IPC_IO_TIMEOUT, read)
        .await
        .map_err(|_| "ipc read timeout".to_string())?
}

/// Serializes policy read-modify-write (`SetPolicy`) against policy reads
/// (`Status`) in this process. IPC ops run concurrently on the blocking pool,
/// and `save_policy` truncates before writing, so without this two
/// `SetPolicy` calls could lose an update and `Status` could read a partial
/// file (which parses as the defaults).
static POLICY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn policy_guard() -> std::sync::MutexGuard<'static, ()> {
    POLICY_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn handle_req(req: IpcRequest, data_dir: &Path, forward: &Option<ForwardQueue>) -> IpcResponse {
    match req {
        IpcRequest::Ping { v } => IpcResponse::Pong { v },
        IpcRequest::Status { v } => {
            let policy = {
                let _policy = policy_guard();
                load_policy(data_dir)
            };
            // Transport capabilities do not depend on the forward queue: the
            // listeners are up or not on their own. Bridge / store / relay do
            // (they run on it), and only while the bridge is actually running.
            let mut caps: Vec<String> = vec!["ipc".into()];
            if crate::lan_direct::listener_is_up() {
                caps.push("lan_direct".into());
            }
            if crate::internet_direct::listener_is_up() {
                caps.push("internet_direct".into());
            }
            let pending = match forward {
                Some(q) => {
                    if !crate::bridge_degraded() {
                        if policy.bridge {
                            caps.push("bridge".into());
                        }
                        if policy.store {
                            caps.push("store".into());
                        }
                        if policy.relay {
                            caps.push("relay".into());
                        }
                    }
                    q.count_pending().unwrap_or_else(|e| {
                        eprintln!("raven-node ipc: forward queue count failed: {e}");
                        0
                    }) as u64
                }
                None => 0u64,
            };
            IpcResponse::Status {
                v,
                bridge: policy.bridge,
                store: policy.store,
                relay: policy.relay,
                forward_pending: pending,
                capabilities: caps,
            }
        }
        IpcRequest::SetPolicy {
            v,
            bridge,
            store,
            relay,
        } => {
            let _policy = policy_guard();
            let mut p = load_policy(data_dir);
            if let Some(b) = bridge {
                p.bridge = b;
                p.auto_policy = false;
            }
            if let Some(s) = store {
                p.store = s;
                p.auto_policy = false;
            }
            if let Some(r) = relay {
                p.relay = r;
                p.auto_policy = false;
            }
            match save_policy(data_dir, &p) {
                Ok(()) => IpcResponse::Accepted { v },
                Err(e) => IpcResponse::Error {
                    v,
                    code: "INTERNAL".into(),
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::EnqueueSealed {
            v,
            envelope_b64,
            peer_hint,
        } => {
            // The request frame (MAX_IPC_FRAME) already bounds envelope_b64, so
            // IPC can carry envelopes up to ~190 KiB; MAX_ENVELOPE_BYTES below
            // is the queue's own limit.
            let packed = match base64_decode(&envelope_b64) {
                Ok(b) => b,
                Err(e) => {
                    return IpcResponse::Error {
                        v,
                        code: "IPC_BAD_B64".into(),
                        message: e,
                    };
                }
            };
            if packed.len() > raven_core::forward_queue::MAX_ENVELOPE_BYTES {
                return IpcResponse::Error {
                    v,
                    code: "IPC_FRAME".into(),
                    message: "envelope too large".into(),
                };
            }
            let Some(env) = Envelope::unpack(&packed) else {
                return IpcResponse::Error {
                    v,
                    code: "IPC_BAD_ENVELOPE".into(),
                    message: "not a RavenEnvelopeV1".into(),
                };
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            // Custody allow-list (F3): both queues below hand these bytes to a
            // relay or store, so only a sealed indexed-session message or ACK
            // is accepted, never PairInit / PairResponse, demo or plaintext.
            if let Err(refusal) = raven_core::carrier_admission::admit_relayable(&packed, now) {
                return IpcResponse::Error {
                    v,
                    code: "IPC_NOT_RELAYABLE".into(),
                    message: format!(
                        "not a sealed indexed-session message or ACK; refused before custody \
                         ({refusal:?})"
                    ),
                };
            }
            let peer = peer_hint.unwrap_or_else(|| "ipc".into());
            // Prefer forward queue when available (always-on bridge); also mirror outbox.
            if let Some(q) = forward {
                let item = ForwardItem {
                    object_digest: authenticated_object_digest(&env),
                    message_id: env.message_id,
                    packed_envelope: packed.clone(),
                    ingress: TransportKind::Internet,
                    egress: TransportKind::Internet,
                    state: ForwardState::Queued,
                    created_at_ms: now,
                    expires_at_ms: env.expires_at.max(now.saturating_add(60_000)),
                    previous_hop: peer.clone(),
                };
                if let Err(e) = q.enqueue(&item) {
                    return IpcResponse::Error {
                        v,
                        code: forward_queue_error_code(&e).into(),
                        message: e.to_string(),
                    };
                }
            }
            let outbox_path = data_dir.join("queue.sqlite");
            match OutgoingQueue::open(&outbox_path) {
                Ok(oq) => {
                    let item = QueueItem {
                        message_id: env.message_id,
                        packed_envelope: packed,
                        peer_addr: peer,
                        state: DeliveryState::Queued,
                        created_at_ms: now,
                    };
                    if let Err(e) = oq.enqueue(&item) {
                        return IpcResponse::Error {
                            v,
                            code: "OUTBOX".into(),
                            message: outbox_failed_message(forward.is_some(), &e.to_string()),
                        };
                    }
                }
                Err(e) => {
                    return IpcResponse::Error {
                        v,
                        code: "OUTBOX".into(),
                        message: outbox_failed_message(forward.is_some(), &e.to_string()),
                    };
                }
            }
            IpcResponse::Accepted { v }
        }
        IpcRequest::SealUnderSession {
            v,
            peer_hint,
            app_payload_b64,
        } => {
            // Cheap checks first: never touch the identity lock / secret store
            // for a request that is malformed anyway.
            if !is_device_pub_hex(&peer_hint) {
                return IpcResponse::Error {
                    v,
                    code: "SEAL_PEER_HINT".into(),
                    message: "SEAL_PEER_HINT: peer_hint must be 64 hex chars (device Ed25519)"
                        .into(),
                };
            }
            let payload = match base64_decode(&app_payload_b64) {
                Ok(b) => b,
                Err(e) => {
                    return IpcResponse::Error {
                        v,
                        code: "IPC_BAD_B64".into(),
                        message: e,
                    };
                }
            };
            let identity = match load_identity_required(data_dir) {
                Ok(id) => id,
                Err(_) => {
                    return IpcResponse::Error {
                        v,
                        code: ATSAM_SESSION_REQUIRED.into(),
                        message: format!(
                            "{ATSAM_SESSION_REQUIRED}: local identity missing; session plane unusable"
                        ),
                    };
                }
            };
            match seal_app_payload_under_session(data_dir, &identity, &peer_hint, &payload) {
                Ok(packed) => IpcResponse::SealUnderSessionResult {
                    v,
                    envelope_b64: b64_encode(&packed),
                },
                Err(e) => {
                    let code = if e.starts_with(ATSAM_LINEAGE_REVOKED) {
                        ATSAM_LINEAGE_REVOKED
                    } else if e.starts_with(ATSAM_SESSION_REQUIRED) {
                        ATSAM_SESSION_REQUIRED
                    } else if e.starts_with("SEAL_PEER_HINT") {
                        "SEAL_PEER_HINT"
                    } else if e.starts_with("SEAL_PAYLOAD") {
                        "SEAL_PAYLOAD"
                    } else {
                        "SEAL"
                    };
                    IpcResponse::Error {
                        v,
                        code: code.into(),
                        message: e,
                    }
                }
            }
        }
        IpcRequest::LanDial { v, .. } => IpcResponse::Error {
            v,
            code: "INTERNAL".into(),
            message: "LanDial must be handled asynchronously".into(),
        },
        IpcRequest::InternetDial { v, .. } => IpcResponse::Error {
            v,
            code: "INTERNAL".into(),
            message: "InternetDial must be handled asynchronously".into(),
        },
    }
}

/// IPC error code for a forward-queue enqueue failure: only a full queue is
/// back-pressure a client should retry; bad input and storage faults are not.
fn forward_queue_error_code(e: &raven_core::forward_queue::ForwardQueueError) -> &'static str {
    use raven_core::forward_queue::ForwardQueueError as E;
    match e {
        E::QueueFull(_) => "QUEUE_FULL",
        E::BadId | E::BadObjectDigest => "IPC_BAD_ENVELOPE",
        E::TooLarge(_) => "IPC_FRAME",
        E::Sqlite(_) => "QUEUE_IO",
    }
}

/// The forward row is written before the outbox row. When the outbox step
/// fails the envelope may already be queued for the bridge, so say that: the
/// forward enqueue is idempotent, a retry is safe and a "failed" send may
/// still be delivered.
fn outbox_failed_message(forward_queued: bool, cause: &str) -> String {
    if forward_queued {
        format!("{cause} (the envelope is already in the forward queue and may still be delivered; retrying is safe)")
    } else {
        cause.to_string()
    }
}

fn is_device_pub_hex(s: &str) -> bool {
    let t = s.trim();
    t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Ops that read or write the shared forward queue (serialized by its lock).
fn needs_forward_queue(req: &IpcRequest) -> bool {
    matches!(
        req,
        IpcRequest::Status { .. } | IpcRequest::EnqueueSealed { .. }
    )
}

/// Blocking request work (SQLite, policy files, identity/secret store, seal).
/// Must run on the blocking pool. Only queue ops take the queue lock, so a slow
/// `SealUnderSession` never serializes `Status` / `EnqueueSealed` behind it.
fn handle_req_blocking(
    req: IpcRequest,
    data_dir: &Path,
    forward: &Mutex<Option<ForwardQueue>>,
) -> IpcResponse {
    if needs_forward_queue(&req) {
        let fwd = forward.blocking_lock();
        handle_req(req, data_dir, &fwd)
    } else {
        handle_req(req, data_dir, &None)
    }
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

async fn handle_lan_dial(data_dir: &Path, req: IpcRequest) -> IpcResponse {
    let IpcRequest::LanDial {
        v,
        lan_dial,
        expected_pub_hex,
        frames_b64,
    } = req
    else {
        return IpcResponse::Error {
            v: IPC_VERSION,
            code: "INTERNAL".into(),
            message: "not LanDial".into(),
        };
    };
    let mut frames = Vec::new();
    for item in frames_b64 {
        match base64_decode(&item) {
            Ok(b) => frames.push(b),
            Err(e) => {
                return IpcResponse::Error {
                    v,
                    code: "IPC_BAD_B64".into(),
                    message: e,
                };
            }
        }
    }
    let work = lan_direct::dial(data_dir, &lan_dial, &expected_pub_hex, &frames);
    match tokio::time::timeout(LAN_DIAL_TIMEOUT, work).await {
        Ok(Ok(replies)) => IpcResponse::LanDialResult {
            v,
            frames_b64: replies.iter().map(|f| b64_encode(f)).collect(),
        },
        Ok(Err(e)) => IpcResponse::Error {
            v,
            code: "LAN_DIAL".into(),
            message: e,
        },
        Err(_) => IpcResponse::Error {
            v,
            code: "LAN_DIAL_TIMEOUT".into(),
            message: "lan dial exceeded 45s".into(),
        },
    }
}

async fn handle_internet_dial(data_dir: &Path, req: IpcRequest) -> IpcResponse {
    let IpcRequest::InternetDial {
        v,
        internet_dial,
        expected_pub_hex,
        frames_b64,
    } = req
    else {
        return IpcResponse::Error {
            v: IPC_VERSION,
            code: "INTERNAL".into(),
            message: "not InternetDial".into(),
        };
    };
    let mut frames = Vec::new();
    for item in frames_b64 {
        match base64_decode(&item) {
            Ok(b) => frames.push(b),
            Err(e) => {
                return IpcResponse::Error {
                    v,
                    code: "IPC_BAD_B64".into(),
                    message: e,
                };
            }
        }
    }
    let work = internet_direct::dial(data_dir, &internet_dial, &expected_pub_hex, &frames);
    match tokio::time::timeout(INTERNET_DIAL_TIMEOUT, work).await {
        Ok(Ok(replies)) => IpcResponse::InternetDialResult {
            v,
            frames_b64: replies.iter().map(|f| b64_encode(f)).collect(),
        },
        Ok(Err(e)) => IpcResponse::Error {
            v,
            code: "INTERNET_DIAL".into(),
            message: e,
        },
        Err(_) => IpcResponse::Error {
            v,
            code: "INTERNET_DIAL_TIMEOUT".into(),
            message: "internet dial exceeded 45s".into(),
        },
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim()))
        .map_err(|e| e.to_string())
}

async fn dispatch(
    frame: &[u8],
    data_dir: &Arc<PathBuf>,
    forward: &Arc<Mutex<Option<ForwardQueue>>>,
) -> IpcResponse {
    match decode_request_checked(frame) {
        // Liveness: no lock, no I/O — a busy daemon must still answer Ping.
        Ok(IpcRequest::Ping { v }) => IpcResponse::Pong { v },
        Ok(req @ IpcRequest::LanDial { .. }) => handle_lan_dial(data_dir, req).await,
        Ok(req @ IpcRequest::InternetDial { .. }) => handle_internet_dial(data_dir, req).await,
        Ok(req) => {
            let dd = data_dir.clone();
            let fq = forward.clone();
            tokio::task::spawn_blocking(move || handle_req_blocking(req, &dd, &fq))
                .await
                .unwrap_or_else(|e| IpcResponse::Error {
                    v: IPC_VERSION,
                    code: "INTERNAL".into(),
                    message: format!("ipc worker: {e}"),
                })
        }
        Err(e) => IpcResponse::Error {
            v: IPC_VERSION,
            code: e.code.into(),
            message: e.message,
        },
    }
}

/// Encode `resp`, or an explicit `IPC_FRAME` error if it does not fit in one
/// IPC frame — never leave the client with a bare EOF after side effects.
fn encode_response_or_error(resp: &IpcResponse) -> Vec<u8> {
    encode_response(resp).unwrap_or_else(|e| {
        let fallback = IpcResponse::Error {
            v: IPC_VERSION,
            code: "IPC_FRAME".into(),
            message: format!("{e} (limit {MAX_IPC_FRAME} bytes)"),
        };
        encode_response(&fallback).expect("small error response fits")
    })
}

async fn serve_one<S>(
    mut stream: S,
    data_dir: Arc<PathBuf>,
    forward: Arc<Mutex<Option<ForwardQueue>>>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = match read_frame(&mut stream).await {
        Ok(f) => f,
        Err(_) => return,
    };
    let resp = dispatch(&frame, &data_dir, &forward).await;
    let out = encode_response_or_error(&resp);
    let _ = tokio::time::timeout(IPC_IO_TIMEOUT, async {
        stream.write_all(&out).await.ok()?;
        stream.flush().await.ok()?;
        Some(())
    })
    .await;
}

/// Open the forward queue the IPC server shares with the bridge. `None` path
/// means "no bridge configured". A path that cannot be opened is an error that
/// stops the server: running on would answer `EnqueueSealed` with `Accepted`
/// for envelopes the bridge never sees.
pub(crate) fn open_forward_queue(
    forward_path: Option<PathBuf>,
) -> Result<Arc<Mutex<Option<ForwardQueue>>>, String> {
    let queue = match forward_path {
        Some(p) => Some(
            ForwardQueue::open(&p)
                .map_err(|e| format!("forward queue {} unavailable: {e}", p.display()))?,
        ),
        None => None,
    };
    Ok(Arc::new(Mutex::new(queue)))
}

/// Bind the platform IPC transport and serve until the process exits.
pub async fn run_ipc_server(
    data_dir: PathBuf,
    forward_path: Option<PathBuf>,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        run_uds_server(data_dir, forward_path).await
    }
    #[cfg(windows)]
    {
        windows::run_named_pipe_server(data_dir, forward_path).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (data_dir, forward_path);
        Err("IPC transport not supported on this OS".into())
    }
}

/// Create `data_dir` 0700 if missing and refuse one this user does not own or
/// that anyone may write to: its owner could swap the socket under us. A
/// group-writable dir we own is tightened (group write removed) instead of
/// refused: umask 002 makes that the default on user-private-group systems,
/// and otherwise any group member could replace the socket (Unix clients do
/// not check the server's UID).
#[cfg(unix)]
fn ensure_private_data_dir(data_dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    // Never build the "no profile could be determined" placeholder (a root process
    // on a minimal system could otherwise create its tree).
    raven_core::paths::require_resolved_data_dir(data_dir)?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(data_dir)
        .map_err(|e| format!("create {}: {e}", data_dir.display()))?;
    let meta = std::fs::metadata(data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;
    let me = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != me {
        return Err(format!(
            "ipc: data dir {} is not a directory owned by uid {me}; refusing to serve IPC",
            data_dir.display()
        ));
    }
    if meta.mode() & 0o002 != 0 {
        return Err(format!(
            "ipc: data dir {} is world-writable; refusing to serve IPC",
            data_dir.display()
        ));
    }
    if meta.mode() & 0o020 != 0 {
        let tightened = meta.mode() & 0o7777 & !0o022;
        std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(tightened)).map_err(
            |e| {
                format!(
                    "ipc: data dir {} is group-writable and chmod failed ({e}); refusing to serve IPC",
                    data_dir.display()
                )
            },
        )?;
        eprintln!(
            "raven-node ipc: removed group write permission from data dir {} (now {:o})",
            data_dir.display(),
            tightened
        );
    }
    Ok(())
}

/// Single-instance lock next to the socket, held for the server's lifetime
/// (the kernel drops it on exit, so a crash never leaves it stuck).
#[cfg(unix)]
fn acquire_instance_lock(sock: &Path) -> Result<std::fs::File, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let path = raven_core::ipc::instance_lock_path(sock);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(if e.kind() == std::io::ErrorKind::WouldBlock {
            format!(
                "another raven-node IPC server is running for {} (lock held); not replacing it",
                sock.display()
            )
        } else {
            format!("lock {}: {e}", path.display())
        });
    }
    Ok(file)
}

/// Unlink a leftover socket only if nothing answers on it. Never unlinks a
/// live daemon's endpoint or a non-socket file.
#[cfg(unix)]
fn remove_stale_socket(sock: &Path) -> Result<(), String> {
    use std::io::ErrorKind;
    use std::os::unix::fs::FileTypeExt;
    let meta = match std::fs::symlink_metadata(sock) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", sock.display())),
    };
    if !meta.file_type().is_socket() {
        return Err(format!(
            "{} exists and is not a socket; refusing to replace it",
            sock.display()
        ));
    }
    match std::os::unix::net::UnixStream::connect(sock) {
        Ok(_) => Err(format!(
            "a live IPC server is listening on {}; refusing to unlink it",
            sock.display()
        )),
        Err(e) if matches!(e.kind(), ErrorKind::ConnectionRefused | ErrorKind::NotFound) => {
            match std::fs::remove_file(sock) {
                Err(e) if e.kind() != ErrorKind::NotFound => {
                    Err(format!("remove stale {}: {e}", sock.display()))
                }
                _ => Ok(()),
            }
        }
        Err(e) => Err(format!(
            "probe {}: {e}; refusing to unlink it",
            sock.display()
        )),
    }
}

/// Bind `sock` so it is never reachable with a mode looser than 0600: bind in
/// a fresh 0700 staging dir, chmod (checked), then rename into place. The
/// staging path is shorter than `sock`, so it fits `sun_path` whenever `sock`
/// does.
#[cfg(unix)]
fn bind_private_uds(sock: &Path) -> Result<UnixListener, String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let parent = sock
        .parent()
        .ok_or_else(|| format!("{} has no parent", sock.display()))?;
    let staging = parent.join(format!(".rn{:08x}", rand::random::<u32>()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|e| format!("create {}: {e}", staging.display()))?;
    let tmp = staging.join("s");
    let bound = (|| -> Result<std::os::unix::net::UnixListener, String> {
        let listener = std::os::unix::net::UnixListener::bind(&tmp)
            .map_err(|e| format!("bind {}: {e}", sock.display()))?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {}: {e}", sock.display()))?;
        std::fs::rename(&tmp, sock).map_err(|e| format!("publish {}: {e}", sock.display()))?;
        Ok(listener)
    })();
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_dir(&staging);
    let listener = bound?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    UnixListener::from_std(listener).map_err(|e| e.to_string())
}

/// (dev, inode) of the socket path, to notice when it was unlinked/replaced.
#[cfg(unix)]
fn socket_identity(sock: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(sock)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// Bind UDS with mode 0600 and serve until the process exits.
#[cfg(unix)]
async fn run_uds_server(data_dir: PathBuf, forward_path: Option<PathBuf>) -> Result<(), String> {
    ensure_private_data_dir(&data_dir)?;
    let sock = socket_path(&data_dir);
    let _instance_lock = acquire_instance_lock(&sock)?;
    // Before the endpoint is published: a queue that cannot open must not
    // leave a socket behind that answers and then loses envelopes.
    let forward = open_forward_queue(forward_path)?;
    remove_stale_socket(&sock)?;
    let mut listener = bind_private_uds(&sock)?;
    let mut bound = socket_identity(&sock);
    eprintln!("raven-node ipc: listening {}", sock.display());

    let data_dir = Arc::new(data_dir);
    let slots = Arc::new(Semaphore::new(MAX_IPC_CONNECTIONS));
    let mut watch = tokio::time::interval(SOCKET_WATCH_INTERVAL);
    watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let permit = slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "ipc connection limiter closed".to_string())?;
        let stream = loop {
            tokio::select! {
                (stream, _) = crate::accept_retrying("raven-node ipc", || listener.accept()) => {
                    break stream;
                }
                _ = watch.tick() => {
                    if bound.is_some() && socket_identity(&sock) == bound {
                        continue;
                    }
                    // Our path was unlinked or replaced (e.g. a client "cleaning
                    // up" a socket it wrongly thought stale). We hold the instance
                    // lock, so no other raven-node serves this data dir: publish
                    // our endpoint again instead of running orphaned.
                    match bind_private_uds(&sock) {
                        Ok(fresh) => {
                            listener = fresh;
                            bound = socket_identity(&sock);
                            eprintln!("raven-node ipc: re-bound {}", sock.display());
                        }
                        Err(e) => eprintln!("raven-node ipc: re-bind failed: {e}"),
                    }
                }
            }
        };
        if !peer_uid_matches_self(&stream) {
            eprintln!("raven-node ipc: reject peer (uid mismatch)");
            continue;
        }
        let dd = data_dir.clone();
        let fq = forward.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_one(stream, dd, fq).await;
        });
    }
}

/// Client helper for same-process smoke tests.
#[cfg(unix)]
#[allow(dead_code)]
pub async fn client_ping(sock: &Path) -> Result<IpcResponse, String> {
    let mut stream = UnixStream::connect(sock)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let req = raven_core::encode_request(&IpcRequest::Ping { v: IPC_VERSION })?;
    stream.write_all(&req).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    let frame = read_frame(&mut stream).await?;
    raven_core::decode_response(&frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::ipc::{IpcRequest, IpcResponse, IPC_VERSION};

    #[test]
    fn pipe_name_constant_is_exact() {
        assert_eq!(raven_core::WINDOWS_NAMED_PIPE, r"\\.\pipe\raven-node");
        assert_eq!(
            raven_core::default_pipe_name(),
            raven_core::WINDOWS_NAMED_PIPE
        );
    }

    #[test]
    fn enqueue_sealed_never_seals_app_payload() {
        use base64::Engine;
        let dir = tempfile::tempdir().unwrap();
        let req = IpcRequest::EnqueueSealed {
            v: IPC_VERSION,
            envelope_b64: base64::engine::general_purpose::STANDARD.encode(b"not-a-raven-envelope"),
            peer_hint: Some("peer".into()),
        };
        let resp = handle_req(req, dir.path(), &None);
        match resp {
            IpcResponse::Error { code, .. } => {
                assert_eq!(code, "IPC_BAD_ENVELOPE");
            }
            other => panic!("EnqueueSealed must not seal app bytes: {other:?}"),
        }
        assert!(
            !dir.path().join("queue.sqlite").exists(),
            "EnqueueSealed must not create an outbox from unsealed bytes"
        );
    }

    fn frame(req: &IpcRequest) -> Vec<u8> {
        raven_core::encode_request(req).unwrap()
    }

    fn shared(dir: &Path) -> (Arc<PathBuf>, Arc<Mutex<Option<ForwardQueue>>>) {
        (Arc::new(dir.to_path_buf()), Arc::new(Mutex::new(None)))
    }

    /// Regression: Ping was served under the forward-queue mutex, behind slow
    /// SealUnderSession / SQLite work, so a busy daemon looked dead.
    #[tokio::test]
    async fn ping_and_seal_do_not_wait_for_forward_queue_lock() {
        use base64::Engine;
        let dir = tempfile::tempdir().unwrap();
        let (dd, fq) = shared(dir.path());
        let _held = fq.lock().await;
        let pong = tokio::time::timeout(
            Duration::from_secs(5),
            dispatch(&frame(&IpcRequest::Ping { v: IPC_VERSION }), &dd, &fq),
        )
        .await
        .expect("Ping must not wait for the queue lock");
        assert_eq!(pong, IpcResponse::Pong { v: IPC_VERSION });
        let seal = IpcRequest::SealUnderSession {
            v: IPC_VERSION,
            peer_hint: "ab".repeat(32),
            app_payload_b64: base64::engine::general_purpose::STANDARD.encode(b"hi"),
        };
        let resp = tokio::time::timeout(Duration::from_secs(10), dispatch(&frame(&seal), &dd, &fq))
            .await
            .expect("SealUnderSession must not wait for the queue lock");
        assert!(
            matches!(resp, IpcResponse::Error { ref code, .. } if code == ATSAM_SESSION_REQUIRED)
        );
    }

    /// Regression: base64 values containing a denylisted token were refused
    /// with IPC_FORBIDDEN_FIELD.
    #[tokio::test]
    async fn payload_values_with_secret_words_reach_the_handler() {
        let dir = tempfile::tempdir().unwrap();
        let (dd, fq) = shared(dir.path());
        let req = IpcRequest::EnqueueSealed {
            v: IPC_VERSION,
            envelope_b64: "c2VlZHNlZWRzZWVk".into(), // "seedseedseed", not an envelope
            peer_hint: Some("seed-peer".into()),
        };
        match dispatch(&frame(&req), &dd, &fq).await {
            IpcResponse::Error { code, .. } => assert_eq!(code, "IPC_BAD_ENVELOPE"),
            other => panic!("unexpected {other:?}"),
        }
        let body = br#"{"op":"ping","v":1,"seed":"x"}"#;
        let mut raw = (body.len() as u32).to_be_bytes().to_vec();
        raw.extend_from_slice(body);
        match dispatch(&raw, &dd, &fq).await {
            IpcResponse::Error { code, .. } => assert_eq!(code, "IPC_FORBIDDEN_FIELD"),
            other => panic!("secret key must be refused: {other:?}"),
        }
    }

    /// Regression: an oversized response was silently dropped (client saw EOF
    /// after the side effects had happened).
    #[test]
    fn oversized_response_becomes_explicit_error() {
        let resp = IpcResponse::LanDialResult {
            v: IPC_VERSION,
            frames_b64: vec!["A".repeat(MAX_IPC_FRAME)],
        };
        let out = encode_response_or_error(&resp);
        match raven_core::decode_response(&out).unwrap() {
            IpcResponse::Error { code, message, .. } => {
                assert_eq!(code, "IPC_FRAME");
                assert!(message.contains("too large"), "{message}");
            }
            other => panic!("expected explicit error, got {other:?}"),
        }
    }

    #[test]
    fn seal_rejects_malformed_peer_hint_before_identity_work() {
        let dir = tempfile::tempdir().unwrap();
        let req = IpcRequest::SealUnderSession {
            v: IPC_VERSION,
            peer_hint: "not-hex".into(),
            app_payload_b64: "aGk=".into(),
        };
        match handle_req(req, dir.path(), &None) {
            IpcResponse::Error { code, .. } => assert_eq!(code, "SEAL_PEER_HINT"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[cfg(unix)]
    async fn wait_for_ping(sock: &Path) -> IpcResponse {
        for _ in 0..200 {
            if let Ok(r) = client_ping(sock).await {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no IPC server at {}", sock.display());
    }

    /// Regression: a second `ipc`/`service` unlinked the live daemon's socket.
    #[cfg(unix)]
    #[tokio::test]
    async fn second_server_never_steals_live_socket() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let first = tokio::spawn(run_uds_server(data.clone(), None));
        let sock = socket_path(&data);
        assert_eq!(
            wait_for_ping(&sock).await,
            IpcResponse::Pong { v: IPC_VERSION }
        );
        let before = socket_identity(&sock);

        let err = tokio::time::timeout(Duration::from_secs(5), run_uds_server(data.clone(), None))
            .await
            .expect("second server fails fast")
            .unwrap_err();
        assert!(err.contains("already") || err.contains("lock"), "{err}");
        assert_eq!(
            socket_identity(&sock),
            before,
            "live socket must not be replaced"
        );
        assert_eq!(
            client_ping(&sock).await.unwrap(),
            IpcResponse::Pong { v: IPC_VERSION }
        );

        let sock_mode = std::fs::symlink_metadata(&sock)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(sock_mode & 0o777, 0o600);
        let dir_mode = std::fs::metadata(&data).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700, "fresh data dir is private");
        first.abort();
    }

    /// Stale socket (daemon crashed) is replaced; a non-socket is not touched.
    #[cfg(unix)]
    #[tokio::test]
    async fn stale_socket_is_replaced_but_regular_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().to_path_buf();
        let sock = socket_path(&data);
        drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
        assert!(sock.exists(), "stale socket left behind");
        let server = tokio::spawn(run_uds_server(data.clone(), None));
        assert_eq!(
            wait_for_ping(&sock).await,
            IpcResponse::Pong { v: IPC_VERSION }
        );
        server.abort();
        let _ = server.await;

        let other = tempfile::tempdir().unwrap();
        let sock = socket_path(other.path());
        std::fs::write(&sock, b"not a socket").unwrap();
        let err = run_uds_server(other.path().to_path_buf(), None)
            .await
            .unwrap_err();
        assert!(err.contains("not a socket"), "{err}");
        assert_eq!(std::fs::read(&sock).unwrap(), b"not a socket");
    }

    /// If the socket path is unlinked under a running daemon (e.g. by a client
    /// "cleaning up"), the lock holder re-publishes it instead of running orphaned.
    #[cfg(unix)]
    #[tokio::test]
    async fn unlinked_socket_is_republished() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().to_path_buf();
        let server = tokio::spawn(run_uds_server(data.clone(), None));
        let sock = socket_path(&data);
        wait_for_ping(&sock).await;
        std::fs::remove_file(&sock).unwrap();
        assert_eq!(
            wait_for_ping(&sock).await,
            IpcResponse::Pong { v: IPC_VERSION }
        );
        server.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn world_writable_data_dir_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("open");
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = run_uds_server(data.clone(), None).await.unwrap_err();
        assert!(err.contains("world-writable"), "{err}");
        assert!(!socket_path(&data).exists());
    }

    /// Review residual (node-swarm#17): a group-writable data dir let group
    /// members replace the socket. It is tightened (not refused, since umask
    /// 002 creates such dirs by default) before the socket is published.
    #[cfg(unix)]
    #[test]
    fn group_writable_data_dir_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("shared");
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o775)).unwrap();
        ensure_private_data_dir(&data).expect("owned group-writable dir is tightened");
        let mode = std::fs::metadata(&data).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "group write removed, nothing else changed");
        // Already private: untouched.
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        ensure_private_data_dir(&data).unwrap();
        let mode = std::fs::metadata(&data).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// The "no profile could be determined" placeholder is refused before anything
    /// is created under it.
    #[cfg(unix)]
    #[test]
    fn unresolved_profile_placeholder_is_never_created() {
        let placeholder = raven_core::resolve_raven_data_dir(None, None, None);
        assert!(raven_core::paths::is_unresolved_data_dir(&placeholder));
        let err = ensure_private_data_dir(&placeholder).unwrap_err();
        assert!(
            err.contains("cannot determine the Raven data directory"),
            "{err}"
        );
    }

    /// Regression: moving IPC ops off the forward-queue mutex also removed
    /// the serialization of `SetPolicy` (load, modify, truncate + write).
    /// Concurrent updates to different fields must all survive, and `Status`
    /// must never observe a half-written policy file.
    #[test]
    fn concurrent_set_policy_and_status_are_serialized() {
        let dir = tempfile::tempdir().unwrap();
        let set = |bridge: Option<bool>, store: Option<bool>, relay: Option<bool>| {
            IpcRequest::SetPolicy {
                v: IPC_VERSION,
                bridge,
                store,
                relay,
            }
        };
        for _round in 0..40 {
            let reset = handle_req(
                set(Some(false), Some(false), Some(false)),
                dir.path(),
                &None,
            );
            assert!(matches!(reset, IpcResponse::Accepted { .. }));
            let barrier = std::sync::Barrier::new(3);
            std::thread::scope(|scope| {
                for update in [
                    set(Some(true), None, None),
                    set(None, Some(true), None),
                    set(None, None, Some(true)),
                ] {
                    let barrier = &barrier;
                    let data_dir = dir.path();
                    scope.spawn(move || {
                        barrier.wait();
                        let resp = handle_req(update, data_dir, &None);
                        assert!(matches!(resp, IpcResponse::Accepted { .. }), "{resp:?}");
                    });
                }
            });
            let policy = load_policy(dir.path());
            assert!(
                policy.bridge && policy.store && policy.relay,
                "lost policy update: {policy:?}"
            );
        }

        // Non-default policy; a torn read would parse as the defaults.
        let resp = handle_req(set(Some(false), Some(false), Some(true)), dir.path(), &None);
        assert!(matches!(resp, IpcResponse::Accepted { .. }));
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..300 {
                    let resp = handle_req(set(None, None, Some(true)), dir.path(), &None);
                    assert!(matches!(resp, IpcResponse::Accepted { .. }));
                }
            });
            scope.spawn(|| {
                for _ in 0..300 {
                    match handle_req(IpcRequest::Status { v: IPC_VERSION }, dir.path(), &None) {
                        IpcResponse::Status {
                            bridge,
                            store,
                            relay,
                            ..
                        } => assert!(!bridge && !store && relay, "torn policy read"),
                        other => panic!("{other:?}"),
                    }
                }
            });
        });
    }

    #[test]
    fn seal_under_session_refuses_without_session() {
        use base64::Engine;
        let dir = tempfile::tempdir().unwrap();
        let req = IpcRequest::SealUnderSession {
            v: IPC_VERSION,
            peer_hint: "ab".repeat(32),
            app_payload_b64: base64::engine::general_purpose::STANDARD.encode(b"hello"),
        };
        let resp = handle_req(req, dir.path(), &None);
        match resp {
            IpcResponse::Error { code, message, .. } => {
                assert_eq!(code, ATSAM_SESSION_REQUIRED);
                assert!(
                    !message.contains(ATSAM_LINEAGE_REVOKED),
                    "missing session must not report revoke: {message}"
                );
            }
            other => panic!("expected ATSAM_SESSION_REQUIRED, got {other:?}"),
        }
    }

    fn wall_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// An envelope custody admits: sealed indexed-session shape, valid now.
    fn sealed_envelope(id: u8, body: Vec<u8>) -> Vec<u8> {
        use raven_core::envelope::{EnvType, Envelope};
        Envelope {
            env_type: EnvType::Message as u8,
            flags: 0,
            message_id: [id; 16],
            routing_tag: [0x44; 16],
            dest_device_hint: 0,
            created_at: wall_ms(),
            expires_at: wall_ms() + 60 * 60 * 1000,
            hop_limit: 4,
            replication_budget: 1,
            anti_replay_nonce: [0x55; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: body,
            sender_authentication: vec![0u8; 64],
        }
        .pack()
    }

    fn sealed_envelope_b64(id: u8) -> String {
        use raven_core::carrier_admission::{opaque_indexed_body_for_tests, RelayableKind};
        b64_encode(&sealed_envelope(
            id,
            opaque_indexed_body_for_tests(RelayableKind::Message, &[id; 32]),
        ))
    }

    /// F3: `EnqueueSealed` feeds the bridge custody queue and the legacy
    /// outbox, so a wrapped PairInit or a plaintext body is refused before
    /// either queue exists.
    #[test]
    fn enqueue_sealed_refuses_pairing_and_plaintext_before_custody() {
        use raven_core::pair_init::{INIT_MAGIC, INIT_WIRE_LEN};
        let dir = tempfile::tempdir().unwrap();
        let mut init = INIT_MAGIC.to_vec();
        init.resize(INIT_WIRE_LEN, 0x01);
        for body in [init, b"plaintext hello".to_vec()] {
            let req = IpcRequest::EnqueueSealed {
                v: IPC_VERSION,
                envelope_b64: b64_encode(&sealed_envelope(7, body)),
                peer_hint: Some("peer".into()),
            };
            match handle_req(req, dir.path(), &None) {
                IpcResponse::Error { code, .. } => assert_eq!(code, "IPC_NOT_RELAYABLE"),
                other => panic!("must be refused: {other:?}"),
            }
        }
        assert!(!dir.path().join("queue.sqlite").exists());
        match handle_req(enqueue_req(8), dir.path(), &None) {
            IpcResponse::Accepted { .. } => {}
            other => panic!("a sealed object is accepted: {other:?}"),
        }
    }

    fn enqueue_req(id: u8) -> IpcRequest {
        IpcRequest::EnqueueSealed {
            v: IPC_VERSION,
            envelope_b64: sealed_envelope_b64(id),
            peer_hint: Some("peer".into()),
        }
    }

    /// Regression: a forward queue that failed to open was swallowed (`.ok()`),
    /// so the server ran on, answered `EnqueueSealed` with `Accepted` for
    /// envelopes the bridge never saw, and `Status` hid every capability.
    /// Now the server refuses to start, before it publishes its socket.
    #[cfg(unix)]
    #[tokio::test]
    async fn unopenable_forward_queue_stops_the_server_before_the_socket_exists() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let bad = data.join("forward_queue.sqlite");
        std::fs::write(
            &bad,
            b"not a database, but long enough to be read as one ................",
        )
        .unwrap();
        let err = run_uds_server(data.clone(), Some(bad)).await.unwrap_err();
        assert!(err.contains("forward queue"), "{err}");
        assert!(err.contains("forward_queue.sqlite"), "{err}");
        assert!(
            !socket_path(&data).exists(),
            "no endpoint for a daemon that cannot serve"
        );
        // No path configured is the legitimate no-bridge setup.
        assert!(open_forward_queue(None).unwrap().lock().await.is_none());
    }

    /// Regression: with the forward queue absent `Status` reported only
    /// `["ipc"]`; transport capabilities are independent of it, and the
    /// bridge ones follow the bridge actually running.
    #[test]
    fn status_capabilities_follow_the_bridge_not_just_the_queue() {
        let dir = tempfile::tempdir().unwrap();
        let set = IpcRequest::SetPolicy {
            v: IPC_VERSION,
            bridge: Some(true),
            store: Some(true),
            relay: Some(true),
        };
        assert!(matches!(
            handle_req(set, dir.path(), &None),
            IpcResponse::Accepted { .. }
        ));
        let queue = ForwardQueue::open(&dir.path().join("forward_queue.sqlite")).unwrap();
        let caps = |fwd: &Option<ForwardQueue>| match handle_req(
            IpcRequest::Status { v: IPC_VERSION },
            dir.path(),
            fwd,
        ) {
            IpcResponse::Status { capabilities, .. } => capabilities,
            other => panic!("{other:?}"),
        };
        let fwd = Some(queue);
        assert_eq!(caps(&fwd), ["ipc", "bridge", "store", "relay"]);
        crate::BRIDGE_DEGRADED.store(true, std::sync::atomic::Ordering::Relaxed);
        let degraded = caps(&fwd);
        crate::BRIDGE_DEGRADED.store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            degraded,
            ["ipc"],
            "a bridge that is not running is not advertised"
        );
        assert_eq!(caps(&None), ["ipc"], "no queue, no bridge");
    }

    /// Regression: every forward-queue error was reported as QUEUE_FULL
    /// (retryable back-pressure), including bad input.
    #[test]
    fn forward_queue_errors_get_distinct_codes() {
        use raven_core::forward_queue::ForwardQueueError as E;
        assert_eq!(forward_queue_error_code(&E::QueueFull(512)), "QUEUE_FULL");
        assert_eq!(forward_queue_error_code(&E::BadId), "IPC_BAD_ENVELOPE");
        assert_eq!(
            forward_queue_error_code(&E::BadObjectDigest),
            "IPC_BAD_ENVELOPE"
        );
        assert_eq!(forward_queue_error_code(&E::TooLarge(2)), "IPC_FRAME");
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("q.sqlite");
        std::fs::write(&bad, vec![b'x'; 200]).unwrap();
        let sqlite = ForwardQueue::open(&bad)
            .err()
            .expect("garbage is not a queue");
        assert_eq!(forward_queue_error_code(&sqlite), "QUEUE_IO");

        // End to end: a genuinely full queue is the only QUEUE_FULL.
        let q =
            ForwardQueue::open_with_limits(&dir.path().join("full.sqlite"), 0, 1 << 20).unwrap();
        match handle_req(enqueue_req(1), dir.path(), &Some(q)) {
            IpcResponse::Error { code, .. } => assert_eq!(code, "QUEUE_FULL"),
            other => panic!("{other:?}"),
        }
    }

    /// The forward row is written before the outbox row. When the outbox
    /// step fails the client must be told the envelope is already queued for
    /// the bridge (and that retrying is safe), not just "failed".
    #[test]
    fn outbox_failure_after_forward_enqueue_says_so() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the outbox database should be makes it unopenable.
        std::fs::create_dir(dir.path().join("queue.sqlite")).unwrap();
        let q = ForwardQueue::open(&dir.path().join("forward_queue.sqlite")).unwrap();
        let fwd = Some(q);
        match handle_req(enqueue_req(2), dir.path(), &fwd) {
            IpcResponse::Error { code, message, .. } => {
                assert_eq!(code, "OUTBOX");
                assert!(
                    message.contains("already in the forward queue"),
                    "{message}"
                );
                assert!(message.contains("retrying is safe"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(fwd.as_ref().unwrap().count_pending().unwrap(), 1);
        // Without a forward queue there is nothing to claim.
        assert_eq!(outbox_failed_message(false, "disk full"), "disk full");
    }
}
