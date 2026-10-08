//! Local IPC framing for ash/raven ↔ raven-node (UDS / named pipe payload).
//!
//! Versioned length-prefixed JSON requests. Private keys MUST NOT appear in
//! request/response bodies. Auth is peer-cred at the socket layer (OS-specific).

use serde::{Deserialize, Serialize};

pub const IPC_VERSION: u16 = 1;
pub const MAX_IPC_FRAME: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcRequest {
    Ping {
        v: u16,
    },
    Status {
        v: u16,
    },
    /// Policy toggle — no secrets.
    SetPolicy {
        v: u16,
        bridge: Option<bool>,
        store: Option<bool>,
        relay: Option<bool>,
    },
    /// Enqueue already-sealed RavenEnvelopeV1 (base64). Daemon never seals here.
    EnqueueSealed {
        v: u16,
        envelope_b64: String,
        peer_hint: Option<String>,
    },
    /// Seal application payload bytes inside the daemon under a persisted ATSAM
    /// session (ADR 0004 D4 / M2). NON-RELEASE: does not lift RVN1 HOLD, and is
    /// not O6 E2E / confidential-delivery Proven. Field names must not include
    /// the substring `plaintext` (decode denylist).
    SealUnderSession {
        v: u16,
        /// Peer device Ed25519 as 64 hex chars (same plane as LanDial expected_pub_hex).
        peer_hint: String,
        /// Application payload bytes (standard or URL-safe base64). Not a field
        /// named with substring `plaintext`.
        app_payload_b64: String,
    },
    /// Direct-dial a LAN peer over Noise XX and exchange already-sealed frames.
    LanDial {
        v: u16,
        lan_dial: String,
        expected_pub_hex: String,
        frames_b64: Vec<String>,
    },
    /// Direct-dial an InternetTransport peer (RIH1 hello + framed envelopes).
    /// Lab-only until INTERNET_DIRECT_PRODUCTION_ENABLED. Not a WAN claim.
    InternetDial {
        v: u16,
        internet_dial: String,
        expected_pub_hex: String,
        frames_b64: Vec<String>,
    },
    /// Dial a peer over the libp2p carrier (P3: direct, then a Circuit Relay
    /// v2 circuit, DCUtR upgrade by libp2p) and run the Raven Noise link
    /// (`raven/p2p-link/v1` + RIH1 bind) inside a `/raven/link/1.0.0` stream.
    /// `multiaddr` ends in the target's `/p2p/<PeerId>`: `/p2p/<PeerId>` alone
    /// means "every address the contact book has". Verified contacts only.
    /// Lab-only until P2P_PRODUCTION_ENABLED. Not a WAN claim.
    P2pDial {
        v: u16,
        multiaddr: String,
        expected_pub_hex: String,
        frames_b64: Vec<String>,
    },
    /// Wake the background outbox worker (`raven-node service`): retry the
    /// staged objects to one peer (64 hex Ed25519), or to every peer, now.
    /// Carries no content; answered `Accepted`. A daemon without a worker (or
    /// an older one, which answers `IPC_FRAME`) does not retry in the
    /// background, and the client must say so.
    OutboxKick {
        v: u16,
        #[serde(default)]
        peer_pub_hex: Option<String>,
    },
    /// Delivery state of one of our outbound messages (32 hex message id).
    /// Metadata only, never content.
    OutboxStatus {
        v: u16,
        message_id_hex: String,
    },
    /// Our outbound objects the outbox still tracks, oldest first: at most
    /// `limit` rows ([`MAX_OUTBOX_LIST`] at most; default 50).
    OutboxList {
        v: u16,
        #[serde(default)]
        peer_pub_hex: Option<String>,
        #[serde(default)]
        limit: Option<u16>,
    },
}

/// Hard cap on `OutboxList` rows.
pub const MAX_OUTBOX_LIST: u16 = 200;

/// The libp2p host as `Status` reports it (P3). Public facts about this node
/// only: its own PeerId and listen addresses, counts and states; never a
/// peer's address, a message id or content.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct P2pStatusInfo {
    /// The host is running (listening, or at least dialling out).
    pub up: bool,
    /// This node's libp2p PeerId (the `p2p=` of its card).
    pub peer_id: String,
    /// The addresses the host listens on (and any UPnP / relay addresses).
    pub listen_addrs: Vec<String>,
    /// AutoNAT v2 reachability hint: `public`, `private` or `unknown`.
    pub nat: String,
    /// Configured relays (`/…/p2p/<relay>`) that hold an active reservation.
    pub reservations: Vec<String>,
    /// How many relays are configured (at most 2).
    pub relays_configured: u32,
    /// UPnP / NAT-PMP: `unset` (never asked: off), `off`, `on` (trying),
    /// `mapped <port>` or `failed`.
    pub upnp: String,
    /// Present while this node also relays for others (`service --relay`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayCounts>,
    /// The p2p listen setting the service runs with (`7423`, `relay`,
    /// `IP:PORT`; empty: p2p is off), whatever its `source`. Reported even
    /// while the host is held or not up, so `raven status` and `raven whoami
    /// --card` follow what the service really does (an installer flag beats
    /// node_policy.json).
    #[serde(default)]
    pub listen_setting: String,
    /// Where it came from: `--p2p-listen`, `RAVEN_P2P_LISTEN` or
    /// `node_policy.json`.
    #[serde(default)]
    pub source: String,
    /// The relays the service keeps (or tries to keep) a reservation on.
    #[serde(default)]
    pub relays: Vec<String>,
    /// `service --relay` (or `RAVEN_P2P_RELAY=1`) is set.
    #[serde(default)]
    pub relay_role: bool,
    /// The p2p gate is closed in this build (`P2P_HOLD`): nothing runs.
    #[serde(default)]
    pub held: bool,
    /// The p2p settings could not be used (bad value, unreadable policy):
    /// no host. Fixed text, no addresses.
    #[serde(default)]
    pub config_error: String,
    /// Listen addresses that could not be opened yet (a busy port) and are
    /// retried.
    #[serde(default)]
    pub listen_retrying: u32,
}

/// What a relay reports about itself: counts only (NAT spec §5), shared by
/// `service --relay` (IPC `Status`) and `raven-node relay` (relay_status.json).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayCounts {
    /// `--open`: anyone may reserve (stricter limits).
    pub open: bool,
    /// PeerIds on the allow-list (0 with `open`).
    pub allowed_peers: u32,
    /// The allow-list could not be read: nobody may reserve (fail closed).
    #[serde(default)]
    pub allow_list_unreadable: bool,
    pub reservations: u32,
    pub circuits: u32,
    pub reservations_refused: u64,
    pub circuits_refused: u64,
}

/// One outbound object as the outbox sees it. Identifiers, states and counts
/// only: no plaintext, preview or ciphertext ever travels in it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboxItem {
    pub message_id_hex: String,
    pub peer_pub_hex: String,
    /// `message` or `ack`.
    pub kind: String,
    /// `queued` (not yet handed to a carrier), `sent` (written, no ACK yet),
    /// `held` (not tried: see `last_error_code`), `delivered`, `expired`,
    /// `failed` or `cancelled`.
    pub state: String,
    /// The carrier of the last attempt (`lan_dial` / `internet_dial`), or "".
    pub carrier: String,
    pub attempts: u32,
    /// Unix ms of the next scheduled attempt; 0 when none is scheduled.
    pub next_attempt_ms: u64,
    /// Stable code of the last failure (`NOT_REACHABLE`,
    /// `CONTACT_NOT_VERIFIED`, ...), or "".
    pub last_error_code: String,
    /// Unix ms when the sealed envelope stops being valid (0 = unknown).
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "ok", rename_all = "snake_case")]
pub enum IpcResponse {
    Pong {
        v: u16,
    },
    Status {
        v: u16,
        bridge: bool,
        store: bool,
        relay: bool,
        forward_pending: u64,
        capabilities: Vec<String>,
        /// The libp2p host (P3): `nat`, `reservations`, `listen_addrs`, …
        /// Absent from older daemons and while the host does not run.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        p2p: Option<P2pStatusInfo>,
    },
    Accepted {
        v: u16,
    },
    LanDialResult {
        v: u16,
        frames_b64: Vec<String>,
    },
    InternetDialResult {
        v: u16,
        frames_b64: Vec<String>,
    },
    P2pDialResult {
        v: u16,
        frames_b64: Vec<String>,
    },
    /// Packed RavenEnvelopeV1 produced by in-daemon ATSAM seal (base64).
    SealUnderSessionResult {
        v: u16,
        envelope_b64: String,
    },
    OutboxStatusResult {
        v: u16,
        item: OutboxItem,
    },
    OutboxListResult {
        v: u16,
        /// False when this daemon runs no outbox worker (nothing is retried
        /// in the background); the items then come from the store alone.
        worker_running: bool,
        items: Vec<OutboxItem>,
    },
    Error {
        v: u16,
        code: String,
        message: String,
    },
}

pub fn encode_request(req: &IpcRequest) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    if body.len() > MAX_IPC_FRAME {
        return Err("ipc request too large".into());
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Substrings refused in JSON object *keys* (never in values: base64 ciphertext
/// and dial strings are opaque data and may contain any of these by chance).
pub const FORBIDDEN_FIELD_TOKENS: [&str; 4] = ["seed", "private_key", "plaintext", "recovery"];

/// Why [`decode_request_checked`] refused a frame. `code` is the stable
/// `IPC_*` error code for the response; `message` is diagnostic text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcDecodeError {
    pub code: &'static str,
    pub message: String,
}

impl IpcDecodeError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn json_has_forbidden_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, v)| {
            let key = key.to_ascii_lowercase();
            FORBIDDEN_FIELD_TOKENS.iter().any(|bad| key.contains(bad)) || json_has_forbidden_key(v)
        }),
        serde_json::Value::Array(items) => items.iter().any(json_has_forbidden_key),
        _ => false,
    }
}

pub fn decode_request(frame: &[u8]) -> Result<IpcRequest, String> {
    decode_request_checked(frame).map_err(|e| e.message)
}

/// [`decode_request`] with a typed error code (no substring classification).
pub fn decode_request_checked(frame: &[u8]) -> Result<IpcRequest, IpcDecodeError> {
    if frame.len() < 4 {
        return Err(IpcDecodeError::new("IPC_FRAME", "short frame"));
    }
    let n = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if n > MAX_IPC_FRAME || frame.len() < 4 + n {
        return Err(IpcDecodeError::new("IPC_FRAME", "bad length"));
    }
    let body = &frame[4..4 + n];
    let req: IpcRequest = serde_json::from_slice(body)
        .map_err(|e| IpcDecodeError::new("IPC_FRAME", e.to_string()))?;
    match &req {
        IpcRequest::Ping { v }
        | IpcRequest::Status { v }
        | IpcRequest::SetPolicy { v, .. }
        | IpcRequest::EnqueueSealed { v, .. }
        | IpcRequest::SealUnderSession { v, .. }
        | IpcRequest::LanDial { v, .. }
        | IpcRequest::InternetDial { v, .. }
        | IpcRequest::P2pDial { v, .. }
        | IpcRequest::OutboxKick { v, .. }
        | IpcRequest::OutboxStatus { v, .. }
        | IpcRequest::OutboxList { v, .. } => {
            if *v != IPC_VERSION {
                return Err(IpcDecodeError::new("IPC_VERSION", "ipc version"));
            }
        }
    }
    // Refuse accidental secret field names in JSON (defense in depth). Only
    // object keys are inspected (after JSON unescaping); scanning the raw body
    // would randomly reject base64 payloads (~2^-20 per character for "seed").
    let tree: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| IpcDecodeError::new("IPC_FRAME", e.to_string()))?;
    if json_has_forbidden_key(&tree) {
        return Err(IpcDecodeError::new(
            "IPC_FORBIDDEN_FIELD",
            "forbidden field",
        ));
    }
    Ok(req)
}

pub fn encode_response(resp: &IpcResponse) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(resp).map_err(|e| e.to_string())?;
    if body.len() > MAX_IPC_FRAME {
        return Err("ipc response too large".into());
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode_response(frame: &[u8]) -> Result<IpcResponse, String> {
    if frame.len() < 4 {
        return Err("short frame".into());
    }
    let n = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if n > MAX_IPC_FRAME || frame.len() < 4 + n {
        return Err("bad length".into());
    }
    serde_json::from_slice(&frame[4..4 + n]).map_err(|e| e.to_string())
}

pub(crate) const SOCKET_FILE_NAME: &str = "raven-node.sock";

/// Longest path `bind`/`connect` accept for an `AF_UNIX` socket: `sizeof
/// (sun_path)` minus the NUL (104 on macOS/BSD, 108 elsewhere).
#[cfg(unix)]
const UNIX_SOCKET_PATH_MAX: usize = if cfg!(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)) {
    103
} else {
    107
};

/// Default Unix domain socket path (mode 0600 expected at bind): the daemon
/// and every client call this, so they always agree.
///
/// Normally `<data_dir>/raven-node.sock`. When that would not fit `sun_path`
/// (long `RAVEN_DATA_DIR`, sandbox or CI temp paths) `bind` would fail and the
/// service could never start, so a short deterministic per-user path is used
/// instead: `/tmp/raven-<euid>/raven-<hash of data dir>.sock` in a verified
/// owner-only directory. If no such directory can be made safely the direct
/// path is returned unchanged and bind fails loudly as before.
///
/// Every decision (direct or fallback, the direct path itself, the hash) is a
/// function of one normalized spelling of the data dir ([`normalized_data_dir`]:
/// absolute, symlinks resolved), never of how the caller happened to write it.
/// Otherwise a daemon started with one spelling (a launchd/systemd absolute or
/// symlinked `HOME`, `/tmp/x` vs `/private/tmp/x`, `./data`) and a client using
/// another that falls on the other side of the length limit would talk to
/// different sockets, and to different instance locks (`<sock>.lock`). A
/// consequence: a data dir spelled through a symlink such as macOS `/tmp` or
/// `/var` is measured by its longer canonical form, so it reaches the short
/// fallback a few bytes earlier. Tools should ask [`ipc_endpoint`] (`raven
/// doctor` prints it) instead of assuming `<data_dir>/raven-node.sock`.
///
/// Windows callers must not use this alone — the daemon binds
/// [`WINDOWS_NAMED_PIPE`], not a `.sock` file. Use [`ipc_endpoint`].
pub fn default_socket_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    #[cfg(unix)]
    {
        let base = normalized_data_dir(data_dir);
        let direct = base.join(SOCKET_FILE_NAME);
        if direct.as_os_str().len() > UNIX_SOCKET_PATH_MAX {
            if let Some(short) = short_socket_path(&base) {
                return short;
            }
        }
        direct
    }
    #[cfg(not(unix))]
    {
        data_dir.join(SOCKET_FILE_NAME)
    }
}

/// The single-instance lock file of the IPC server listening on `socket`: the
/// socket path plus `.lock`. `raven-node` takes an exclusive `flock` on it for as
/// long as it serves, and clients (`ash`) probe it to tell a live service that is
/// not answering apart from no service at all. Both sides derive it here so they
/// cannot disagree.
pub fn instance_lock_path(socket: &std::path::Path) -> std::path::PathBuf {
    let mut path = socket.as_os_str().to_owned();
    path.push(".lock");
    std::path::PathBuf::from(path)
}

/// One spelling-independent form of `data_dir`: absolute, with symlinks
/// resolved. A directory that does not exist yet resolves its longest existing
/// ancestor and re-appends the rest, so the answer does not change when the
/// daemon creates the directory afterwards. Falls back to the absolute (then
/// the raw) spelling only when nothing can be resolved.
#[cfg(unix)]
fn normalized_data_dir(data_dir: &std::path::Path) -> std::path::PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(data_dir) {
        return canonical;
    }
    let absolute = std::path::absolute(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    let mut missing = Vec::new();
    let mut cursor = absolute.as_path();
    while let (Some(name), Some(parent)) = (cursor.file_name(), cursor.parent()) {
        missing.push(name.to_os_string());
        cursor = parent;
        if let Ok(mut resolved) = std::fs::canonicalize(cursor) {
            resolved.extend(missing.iter().rev());
            return resolved;
        }
    }
    absolute
}

#[cfg(unix)]
pub(crate) fn current_euid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: `geteuid` takes no arguments, cannot fail and touches no memory.
    unsafe { geteuid() }
}

/// `/tmp/raven-<euid>`, created 0700 and verified: a symlink or a directory
/// owned by someone else in the shared `/tmp` (a squatted name) is never used,
/// since the socket's parent decides who can swap the endpoint under us.
#[cfg(unix)]
fn private_short_socket_dir() -> Option<std::path::PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let uid = current_euid();
    let dir = std::path::PathBuf::from(format!("/tmp/raven-{uid}"));
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    let meta = std::fs::symlink_metadata(&dir).ok()?;
    if !meta.is_dir() || meta.uid() != uid {
        return None;
    }
    if meta.mode() & 0o077 != 0 {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok()?;
    }
    Some(dir)
}

/// `base` must already be [`normalized_data_dir`]: daemon and clients then hash
/// the same bytes whatever spelling they were given.
#[cfg(unix)]
fn short_socket_path(base: &std::path::Path) -> Option<std::path::PathBuf> {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    let dir = private_short_socket_dir()?;
    let mut hasher = Sha256::new();
    hasher.update(b"raven/ipc-socket/v1\0");
    hasher.update(base.as_os_str().as_bytes());
    let digest = hasher.finalize();
    let path = dir.join(format!("raven-{}.sock", hex::encode(&digest[..8])));
    (path.as_os_str().len() <= UNIX_SOCKET_PATH_MAX).then_some(path)
}

/// Prefix of the Windows named pipe. The pipe namespace is machine-wide, so the
/// daemon binds (and clients connect to) the per-user name
/// `{WINDOWS_NAMED_PIPE}-{user SID}` ([`windows_pipe_name_for_sid`]) with a
/// current-user DACL. Clients must also verify the server process owner
/// (`verify_named_pipe_server_is_current_user`) — the name alone is not auth.
pub const WINDOWS_NAMED_PIPE: &str = r"\\.\pipe\raven-node";

/// Alias for [`WINDOWS_NAMED_PIPE`] (per-user pipe name prefix).
pub fn default_pipe_name() -> &'static str {
    WINDOWS_NAMED_PIPE
}

/// Per-user pipe name for a canonical string SID (`S-1-...`). `None` for
/// anything that is not a plain SID string, so it can never inject pipe path
/// components.
pub fn windows_pipe_name_for_sid(sid: &str) -> Option<String> {
    let mut parts = sid.split('-');
    let well_formed =
        sid.len() <= 184 && parts.next() == Some("S") && parts.next() == Some("1") && {
            let rest: Vec<&str> = parts.collect();
            !rest.is_empty()
                && rest
                    .iter()
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        };
    well_formed.then(|| format!("{WINDOWS_NAMED_PIPE}-{sid}"))
}

/// Debug-build lab override: `RAVEN_LAB_IPC_PIPE_SUFFIX=<1-32 of [A-Za-z0-9_-]>`
/// appends `-<suffix>` to this process's per-user pipe name. The Windows pipe
/// is per user, not per data dir (Unix sockets live in the data dir), so
/// without it two `raven-node service` profiles of one account (the portable
/// carrier harness on a CI runner) would share one pipe. Release builds ignore
/// it; a malformed value yields no name at all (fail closed, never the shared
/// default).
pub const LAB_IPC_PIPE_SUFFIX_ENV: &str = "RAVEN_LAB_IPC_PIPE_SUFFIX";

/// Apply [`LAB_IPC_PIPE_SUFFIX_ENV`] to a per-user pipe name (pure, testable
/// on every OS).
pub fn with_lab_pipe_suffix(
    user_pipe: String,
    suffix: Option<&str>,
    lab_build: bool,
) -> Option<String> {
    match suffix {
        Some(s) if lab_build => {
            let ok = (1..=32).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            ok.then(|| format!("{user_pipe}-{s}"))
        }
        _ => Some(user_pipe),
    }
}

/// Per-user pipe name for the current process token user (cached).
/// `None` if the SID cannot be read — callers fail closed.
#[cfg(windows)]
pub fn windows_user_pipe_name() -> Option<&'static str> {
    static NAME: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    NAME.get_or_init(|| {
        let suffix = std::env::var(LAB_IPC_PIPE_SUFFIX_ENV).ok();
        win_pipe::current_user_sid()
            .ok()
            .and_then(|sid| windows_pipe_name_for_sid(&sid))
            .and_then(|name| with_lab_pipe_suffix(name, suffix.as_deref(), cfg!(debug_assertions)))
    })
    .as_deref()
}

/// Refuse a connected pipe whose server process runs as a different user
/// (pipe squatting). Call before writing any request bytes.
#[cfg(windows)]
pub fn verify_named_pipe_server_is_current_user(
    pipe: std::os::windows::io::RawHandle,
) -> Result<(), String> {
    let me = win_pipe::current_user_sid()?;
    let server = win_pipe::pipe_server_user_sid(pipe as windows_sys::Win32::Foundation::HANDLE)?;
    if server != me {
        return Err("named pipe server runs as a different user; refusing (squatted pipe?)".into());
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) mod win_pipe {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    unsafe fn token_user_sid(token: HANDLE) -> Result<String, String> {
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return Err("GetTokenInformation(TokenUser) size failed".into());
        }
        // u64 backing keeps TOKEN_USER (pointer-bearing) suitably aligned.
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        if GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
        {
            return Err("GetTokenInformation(TokenUser) failed".into());
        }
        let sid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        if sid.is_null() {
            return Err("TOKEN_USER SID is null".into());
        }
        let mut wide: windows_sys::core::PWSTR = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut wide) == 0 || wide.is_null() {
            return Err("ConvertSidToStringSidW failed".into());
        }
        let mut len = 0usize;
        while *wide.add(len) != 0 {
            len += 1;
        }
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(wide, len));
        LocalFree(wide as _);
        Ok(out)
    }

    pub(crate) fn current_user_sid() -> Result<String, String> {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err("OpenProcessToken(self) failed".into());
            }
            let token = OwnedHandle(token);
            token_user_sid(token.0)
        }
    }

    pub(super) fn pipe_server_user_sid(pipe: HANDLE) -> Result<String, String> {
        unsafe {
            let mut pid = 0u32;
            if GetNamedPipeServerProcessId(pipe, &mut pid) == 0 || pid == 0 {
                return Err("GetNamedPipeServerProcessId failed".into());
            }
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return Err("OpenProcess(pipe server) failed".into());
            }
            let process = OwnedHandle(process);
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(process.0, TOKEN_QUERY, &mut token) == 0 {
                let os = std::io::Error::last_os_error();
                // Typical cause: the daemon runs elevated and this client does
                // not. Fail closed; the fix is running both at one elevation.
                return Err(format!(
                    "OpenProcessToken(pipe server) failed: {os}; cannot verify the pipe owner \
                     (run raven-node and ash at the same elevation)"
                ));
            }
            let token = OwnedHandle(token);
            token_user_sid(token.0)
        }
    }
}

/// Platform-local IPC connect target.
///
/// Callers must obtain this from [`ipc_endpoint`] so Windows never looks for a
/// UDS path under `data_dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcEndpoint {
    /// Unix domain socket (`<data_dir>/raven-node.sock`, or the short
    /// per-user fallback of [`default_socket_path`] for long data dirs).
    UnixSocket(std::path::PathBuf),
    /// Per-user Windows named pipe (`{WINDOWS_NAMED_PIPE}-{user SID}`).
    NamedPipe(&'static str),
    /// No local IPC transport on this OS. Clients/doctor must fail closed
    /// (`ipc_transport_missing`) — never treat as a pass.
    Unsupported,
}

impl std::fmt::Display for IpcEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcEndpoint::UnixSocket(p) => write!(f, "{}", p.display()),
            IpcEndpoint::NamedPipe(n) => write!(f, "{n}"),
            IpcEndpoint::Unsupported => write!(f, "ipc_transport_missing"),
        }
    }
}

impl IpcEndpoint {
    /// False when this OS has no ash↔raven-node IPC transport.
    pub fn transport_available(&self) -> bool {
        !matches!(self, IpcEndpoint::Unsupported)
    }
}

/// Unix socket path vs Windows named-pipe name.
///
/// Never returns a UDS path on Windows.
pub fn ipc_endpoint(data_dir: &std::path::Path) -> IpcEndpoint {
    #[cfg(unix)]
    {
        IpcEndpoint::UnixSocket(default_socket_path(data_dir))
    }
    #[cfg(windows)]
    {
        let _ = data_dir;
        match windows_user_pipe_name() {
            Some(name) => IpcEndpoint::NamedPipe(name),
            // No user SID → no safe per-user name. Fail closed.
            None => IpcEndpoint::Unsupported,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = data_dir;
        IpcEndpoint::Unsupported
    }
}

/// Alias for [`ipc_endpoint`].
pub fn default_ipc_endpoint(data_dir: &std::path::Path) -> IpcEndpoint {
    ipc_endpoint(data_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ping() {
        let req = IpcRequest::Ping { v: IPC_VERSION };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let resp = IpcResponse::Pong { v: IPC_VERSION };
        let rf = encode_response(&resp).unwrap();
        assert_eq!(decode_response(&rf).unwrap(), resp);
    }

    #[test]
    fn rejects_secret_token_in_json() {
        let body = br#"{"op":"ping","v":1,"seed":"nope"}"#;
        let mut frame = Vec::new();
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(body);
        assert!(decode_request(&frame).is_err());
    }

    #[test]
    fn rejects_oversized() {
        let huge = vec![b'a'; MAX_IPC_FRAME + 10];
        let mut frame = Vec::new();
        frame.extend_from_slice(&(huge.len() as u32).to_be_bytes());
        frame.extend_from_slice(&huge);
        assert!(decode_request(&frame).is_err());
    }

    #[test]
    fn roundtrip_internet_dial() {
        let req = IpcRequest::InternetDial {
            v: IPC_VERSION,
            internet_dial: "127.0.0.1:7421".into(),
            expected_pub_hex: "ab".repeat(32),
            frames_b64: vec!["QUJD".into()],
        };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let resp = IpcResponse::InternetDialResult {
            v: IPC_VERSION,
            frames_b64: vec!["ZGVm".into()],
        };
        let rf = encode_response(&resp).unwrap();
        assert_eq!(decode_response(&rf).unwrap(), resp);
        let raw = std::str::from_utf8(&f[4..]).unwrap().to_ascii_lowercase();
        for bad in ["seed", "private_key", "plaintext", "recovery"] {
            assert!(!raw.contains(bad), "{bad} leaked into InternetDial JSON");
        }
    }

    #[test]
    fn roundtrip_p2p_dial_and_status_have_no_secret_fields() {
        let req = IpcRequest::P2pDial {
            v: IPC_VERSION,
            multiaddr: "/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN".into(),
            expected_pub_hex: "ab".repeat(32),
            frames_b64: vec!["QUJD".into()],
        };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let raw = std::str::from_utf8(&f[4..]).unwrap();
        assert!(raw.contains("\"op\":\"p2p_dial\""), "{raw}");
        assert_json_has_no_secret_tokens(raw);
        let resp = IpcResponse::P2pDialResult {
            v: IPC_VERSION,
            frames_b64: vec!["ZGVm".into()],
        };
        assert_eq!(
            decode_response(&encode_response(&resp).unwrap()).unwrap(),
            resp
        );
        let status = IpcResponse::Status {
            v: IPC_VERSION,
            bridge: true,
            store: true,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into(), "p2p".into()],
            p2p: Some(P2pStatusInfo {
                up: true,
                peer_id: "12D3KooW".into(),
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/7423".into()],
                nat: "private".into(),
                reservations: vec!["/ip4/203.0.113.7/tcp/7423/p2p/x".into()],
                relays_configured: 1,
                upnp: "unset".into(),
                relay: Some(RelayCounts::default()),
                listen_setting: "7423".into(),
                source: "--p2p-listen".into(),
                relays: vec!["/ip4/203.0.113.7/tcp/7423/p2p/x".into()],
                relay_role: true,
                ..P2pStatusInfo::default()
            }),
        };
        let f = encode_response(&status).unwrap();
        assert_json_has_no_secret_tokens(std::str::from_utf8(&f[4..]).unwrap());
        assert_eq!(decode_response(&f).unwrap(), status);
        // An older daemon's Status (no p2p) still decodes.
        let old = br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"]}"#;
        let mut frame = (old.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(old);
        match decode_response(&frame).unwrap() {
            IpcResponse::Status { p2p, .. } => assert_eq!(p2p, None),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn roundtrip_lan_dial() {
        let req = IpcRequest::LanDial {
            v: IPC_VERSION,
            lan_dial: "192.168.1.20:7420".into(),
            expected_pub_hex: "ab".repeat(32),
            frames_b64: vec!["QUJD".into()],
        };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let resp = IpcResponse::LanDialResult {
            v: IPC_VERSION,
            frames_b64: vec!["ZGVm".into()],
        };
        let rf = encode_response(&resp).unwrap();
        assert_eq!(decode_response(&rf).unwrap(), resp);
    }

    #[test]
    fn windows_named_pipe_is_canonical_bind_name() {
        assert_eq!(WINDOWS_NAMED_PIPE, r"\\.\pipe\raven-node");
        assert_eq!(default_pipe_name(), WINDOWS_NAMED_PIPE);
    }

    /// The lab pipe suffix separates two profiles of one Windows account in a
    /// debug build only, and a malformed one fails closed (no shared default).
    #[test]
    fn lab_pipe_suffix_is_debug_only_and_strict() {
        let user = windows_pipe_name_for_sid("S-1-5-21-1-2-3-1001").unwrap();
        assert_eq!(
            with_lab_pipe_suffix(user.clone(), None, true),
            Some(user.clone())
        );
        assert_eq!(
            with_lab_pipe_suffix(user.clone(), Some("alice-1_2"), true),
            Some(format!("{user}-alice-1_2"))
        );
        assert_eq!(
            with_lab_pipe_suffix(user.clone(), Some("alice"), false),
            Some(user.clone()),
            "release ignores the lab override"
        );
        for bad in ["", "a\\b", "../x", "a b", &"x".repeat(33)] {
            assert_eq!(with_lab_pipe_suffix(user.clone(), Some(bad), true), None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn ipc_endpoint_selects_unix_socket() {
        let tmp = tempfile::tempdir().unwrap();
        // Canonical spelling: macOS `/var` and `/tmp` are symlinks.
        let dir = std::fs::canonicalize(tmp.path())
            .unwrap()
            .join("raven-data");
        let ep = ipc_endpoint(&dir);
        assert_eq!(default_ipc_endpoint(&dir), ep);
        assert_eq!(ep, IpcEndpoint::UnixSocket(default_socket_path(&dir)));
        assert_eq!(
            ep.to_string(),
            dir.join("raven-node.sock").display().to_string()
        );
        assert!(ep.transport_available());
        assert!(!matches!(ep, IpcEndpoint::NamedPipe(_)));
        assert!(!matches!(ep, IpcEndpoint::Unsupported));
    }

    #[cfg(unix)]
    #[test]
    fn long_data_dir_gets_short_deterministic_private_socket_path() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // A short canonical data dir keeps `<dir>/raven-node.sock`.
        let tmp = tempfile::tempdir().unwrap();
        let tmp_path = std::fs::canonicalize(tmp.path()).unwrap();
        let short = tmp_path.join("raven-data");
        assert_eq!(default_socket_path(&short), short.join("raven-node.sock"));

        // A data dir whose `<dir>/raven-node.sock` cannot fit sun_path.
        let long_a = tmp_path.join("a".repeat(120));
        let long_b = tmp_path.join("b".repeat(120));
        assert!(long_a.join(SOCKET_FILE_NAME).as_os_str().len() > UNIX_SOCKET_PATH_MAX);
        let sock_a = default_socket_path(&long_a);
        assert_ne!(sock_a, long_a.join(SOCKET_FILE_NAME));
        assert!(sock_a.as_os_str().len() <= UNIX_SOCKET_PATH_MAX);
        // Daemon and clients call the same function: stable per data dir, and
        // distinct data dirs never share an endpoint.
        assert_eq!(default_socket_path(&long_a), sock_a);
        assert_ne!(default_socket_path(&long_b), sock_a);
        assert_eq!(
            ipc_endpoint(&long_a),
            IpcEndpoint::UnixSocket(sock_a.clone())
        );

        // It lives in a verified owner-only directory.
        let parent = sock_a.parent().unwrap();
        let meta = std::fs::symlink_metadata(parent).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.uid(), current_euid());
        assert_eq!(meta.permissions().mode() & 0o077, 0);

        // And it really binds and connects, which the long path cannot.
        let _ = std::fs::remove_file(&sock_a);
        assert!(std::os::unix::net::UnixListener::bind(long_a.join(SOCKET_FILE_NAME)).is_err());
        let listener = std::os::unix::net::UnixListener::bind(&sock_a).unwrap();
        let client = std::os::unix::net::UnixStream::connect(&sock_a).unwrap();
        drop((listener, client));
        std::fs::remove_file(&sock_a).unwrap();
    }

    /// One data dir, several spellings (symlink, `..`, not yet created): the
    /// daemon and a client must reach the same socket, and therefore the same
    /// `<sock>.lock`, even when the spellings fall on different sides of the
    /// `sun_path` limit. The raw-length decision used to give the short
    /// symlink spelling its own direct socket while the long real spelling got
    /// the hashed fallback, so a second daemon could start on one profile.
    #[cfg(unix)]
    #[test]
    fn every_spelling_of_one_data_dir_gets_the_same_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let real = root.join("r".repeat(100));
        std::fs::create_dir(&real).unwrap();
        let link = root.join("l");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // The two spellings are on opposite sides of the limit.
        assert!(link.join(SOCKET_FILE_NAME).as_os_str().len() <= UNIX_SOCKET_PATH_MAX);
        assert!(real.join(SOCKET_FILE_NAME).as_os_str().len() > UNIX_SOCKET_PATH_MAX);

        let via_real = default_socket_path(&real);
        let via_link = default_socket_path(&link);
        assert_eq!(via_link, via_real, "spelling must not pick the socket");
        assert!(via_real.as_os_str().len() <= UNIX_SOCKET_PATH_MAX);
        assert_ne!(via_real, real.join(SOCKET_FILE_NAME));
        // `..` and `.` do not change it either.
        assert_eq!(default_socket_path(&real.join("..").join("l")), via_real);
        assert_eq!(default_socket_path(&real.join(".")), via_real);
        // Nor does the instance lock derived from it.
        let lock = |sock: &std::path::Path| {
            let mut p = sock.as_os_str().to_os_string();
            p.push(".lock");
            std::path::PathBuf::from(p)
        };
        assert_eq!(lock(&via_link), lock(&via_real));

        // A short symlinked spelling of a short dir: also one answer, and a
        // direct socket inside the (resolved) directory.
        let short_real = root.join("s");
        std::fs::create_dir(&short_real).unwrap();
        let short_link = root.join("sl");
        std::os::unix::fs::symlink(&short_real, &short_link).unwrap();
        assert_eq!(
            default_socket_path(&short_link),
            short_real.join(SOCKET_FILE_NAME)
        );
        assert_eq!(
            default_socket_path(&short_link),
            default_socket_path(&short_real)
        );
    }

    #[test]
    fn instance_lock_sits_next_to_the_socket() {
        let sock = std::path::Path::new("/some/dir/raven-node.sock");
        assert_eq!(
            instance_lock_path(sock),
            std::path::PathBuf::from("/some/dir/raven-node.sock.lock")
        );
    }

    /// The answer must not change when the daemon creates the directory after
    /// a client (`ash doctor`, a launcher) already asked for its endpoint.
    #[cfg(unix)]
    #[test]
    fn socket_path_is_stable_across_creation_of_the_data_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let real = root.join("r".repeat(60));
        std::fs::create_dir(&real).unwrap();
        let link = root.join("l");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // `<link>/p/q` does not exist yet; its resolved spelling is under `real`.
        let future_via_link = link.join("p").join("q");
        let future_real = real.join("p").join("q");
        assert!(!future_real.exists());
        assert_eq!(normalized_data_dir(&future_via_link), future_real);
        let before = default_socket_path(&future_via_link);
        assert_eq!(before, default_socket_path(&future_real));
        std::fs::create_dir_all(&future_real).unwrap();
        assert_eq!(default_socket_path(&future_via_link), before);
        assert_eq!(default_socket_path(&future_real), before);
    }

    /// A relative data dir resolves against the working directory (read, never
    /// changed, so this cannot race other tests).
    #[cfg(unix)]
    #[test]
    fn relative_data_dir_is_resolved_against_the_working_directory() {
        let cwd = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        let rel = std::path::Path::new("raven-ipc-test-no-such-dir-42");
        assert!(!cwd.join(rel).exists());
        assert_eq!(normalized_data_dir(rel), cwd.join(rel));
        assert_eq!(
            default_socket_path(rel),
            default_socket_path(&cwd.join(rel)),
            "relative and absolute spellings share one endpoint"
        );
        // `.` is the working directory itself.
        assert_eq!(
            default_socket_path(std::path::Path::new(".")),
            default_socket_path(&cwd)
        );
    }

    #[cfg(windows)]
    #[test]
    fn ipc_endpoint_selects_windows_named_pipe() {
        let dir = std::path::Path::new(r"C:\raven-data");
        let ep = ipc_endpoint(dir);
        assert_eq!(default_ipc_endpoint(dir), ep);
        let name = windows_user_pipe_name().expect("current user SID");
        assert_eq!(ep, IpcEndpoint::NamedPipe(name));
        assert!(ep.to_string().starts_with(r"\\.\pipe\raven-node-S-1-"));
        assert_eq!(default_pipe_name(), r"\\.\pipe\raven-node");
        assert!(ep.transport_available());
        assert!(!matches!(ep, IpcEndpoint::UnixSocket(_)));
        assert!(!matches!(ep, IpcEndpoint::Unsupported));
    }

    #[test]
    fn windows_pipe_name_is_per_user_and_injection_safe() {
        assert_eq!(
            windows_pipe_name_for_sid("S-1-5-21-1004336348-1177238915-682003330-1001").as_deref(),
            Some(r"\\.\pipe\raven-node-S-1-5-21-1004336348-1177238915-682003330-1001")
        );
        assert_ne!(
            windows_pipe_name_for_sid("S-1-5-21-1-2-3-1001"),
            windows_pipe_name_for_sid("S-1-5-21-1-2-3-1002")
        );
        for bad in [
            "",
            "S-1",
            "S-1-",
            "S-1-5-",
            "S-1-5--21",
            "S-2-5-21",
            "s-1-5-21",
            "S-1-5-21-a",
            r"S-1-5\..\raven-node",
            "S-1-5-21-1 ",
        ] {
            assert_eq!(windows_pipe_name_for_sid(bad), None, "{bad:?}");
        }
    }

    fn frame_of(body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(body);
        frame
    }

    /// Regression: the denylist used to scan the whole body, so base64
    /// ciphertext or a dial host containing e.g. "seed" was refused.
    #[test]
    fn forbidden_tokens_inside_values_are_accepted() {
        let envelope_b64 = format!("QUJD{}c2VlZA==", "seedPlainTextRECOVERYprivate_key");
        let req = IpcRequest::EnqueueSealed {
            v: IPC_VERSION,
            envelope_b64,
            peer_hint: Some("seedbox".into()),
        };
        assert_eq!(decode_request(&encode_request(&req).unwrap()).unwrap(), req);
        let req = IpcRequest::LanDial {
            v: IPC_VERSION,
            lan_dial: "seed.local:7420".into(),
            expected_pub_hex: "ab".repeat(32),
            frames_b64: vec!["xxSEEDxx".into(), "plaintext".into()],
        };
        assert_eq!(decode_request(&encode_request(&req).unwrap()).unwrap(), req);
        let req = IpcRequest::SealUnderSession {
            v: IPC_VERSION,
            peer_hint: "cd".repeat(32),
            app_payload_b64: "cmVjb3Zlcnk=Recovery".into(),
        };
        assert_eq!(decode_request(&encode_request(&req).unwrap()).unwrap(), req);
    }

    #[test]
    fn forbidden_keys_are_refused_when_nested_escaped_or_cased() {
        for body in [
            r#"{"op":"ping","v":1,"Seed_Hex":"x"}"#,
            r#"{"op":"ping","v":1,"s\u0065ed":"x"}"#,
            r#"{"op":"ping","v":1,"meta":{"inner":{"recovery_phrase":1}}}"#,
            r#"{"op":"ping","v":1,"list":[{"PRIVATE_KEY":0}]}"#,
            r#"{"op":"enqueue_sealed","v":1,"envelope_b64":"QUJD","plaintext_b64":"eA=="}"#,
        ] {
            let err = decode_request_checked(&frame_of(body.as_bytes())).unwrap_err();
            assert_eq!(err.code, "IPC_FORBIDDEN_FIELD", "{body}");
            assert!(decode_request(&frame_of(body.as_bytes())).is_err());
        }
    }

    #[test]
    fn decode_errors_carry_typed_codes() {
        let err = decode_request_checked(&frame_of(br#"{"op":"ping","v":2}"#)).unwrap_err();
        assert_eq!(err.code, "IPC_VERSION");
        let err = decode_request_checked(&frame_of(b"{not json")).unwrap_err();
        assert_eq!(err.code, "IPC_FRAME");
        let err = decode_request_checked(&[0, 0]).unwrap_err();
        assert_eq!(err.code, "IPC_FRAME");
    }

    fn assert_json_has_no_secret_tokens(raw: &str) {
        let lower = raw.to_ascii_lowercase();
        for bad in ["seed", "private_key", "plaintext", "recovery"] {
            assert!(!lower.contains(bad), "{bad} leaked into IPC JSON: {raw}");
        }
    }

    #[test]
    fn status_json_has_no_private_key_material() {
        let req = IpcRequest::Status { v: IPC_VERSION };
        let resp = IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into()],
            p2p: None,
        };
        let rf = encode_request(&req).unwrap();
        let sf = encode_response(&resp).unwrap();
        let req_json = std::str::from_utf8(&rf[4..]).unwrap();
        let resp_json = std::str::from_utf8(&sf[4..]).unwrap();
        assert_json_has_no_secret_tokens(req_json);
        assert_json_has_no_secret_tokens(resp_json);
        assert!(resp_json.contains("\"ok\":\"status\""));
        assert!(
            !resp_json.contains("rvn1"),
            "Status stays policy-only; whoami is ash CLI"
        );
    }

    /// Serialize existing ops to prove no secret field names.
    /// Encode/decode only — not an O6 E2E / HOLD-lift claim.
    #[test]
    fn all_ipc_variants_json_have_no_private_key_material() {
        let reqs = [
            IpcRequest::Ping { v: IPC_VERSION },
            IpcRequest::Status { v: IPC_VERSION },
            IpcRequest::SetPolicy {
                v: IPC_VERSION,
                bridge: Some(false),
                store: None,
                relay: None,
            },
            IpcRequest::EnqueueSealed {
                v: IPC_VERSION,
                envelope_b64: "QUJD".into(),
                peer_hint: Some("peer".into()),
            },
            IpcRequest::SealUnderSession {
                v: IPC_VERSION,
                peer_hint: "ab".repeat(32),
                app_payload_b64: "aGVsbG8=".into(),
            },
            IpcRequest::LanDial {
                v: IPC_VERSION,
                lan_dial: "127.0.0.1:1".into(),
                expected_pub_hex: "ab".repeat(32),
                frames_b64: vec!["QUJD".into()],
            },
            IpcRequest::InternetDial {
                v: IPC_VERSION,
                internet_dial: "127.0.0.1:1".into(),
                expected_pub_hex: "ab".repeat(32),
                frames_b64: vec!["QUJD".into()],
            },
        ];
        let resps = [
            IpcResponse::Pong { v: IPC_VERSION },
            IpcResponse::Status {
                v: IPC_VERSION,
                bridge: false,
                store: false,
                relay: false,
                forward_pending: 0,
                capabilities: vec!["ipc".into()],
                p2p: None,
            },
            IpcResponse::Accepted { v: IPC_VERSION },
            IpcResponse::LanDialResult {
                v: IPC_VERSION,
                frames_b64: vec!["QUJD".into()],
            },
            IpcResponse::InternetDialResult {
                v: IPC_VERSION,
                frames_b64: vec!["QUJD".into()],
            },
            IpcResponse::SealUnderSessionResult {
                v: IPC_VERSION,
                envelope_b64: "QUJD".into(),
            },
            IpcResponse::Error {
                v: IPC_VERSION,
                code: "X".into(),
                message: "no".into(),
            },
        ];
        for req in &reqs {
            let f = encode_request(req).unwrap();
            assert_json_has_no_secret_tokens(std::str::from_utf8(&f[4..]).unwrap());
        }
        for resp in &resps {
            let f = encode_response(resp).unwrap();
            assert_json_has_no_secret_tokens(std::str::from_utf8(&f[4..]).unwrap());
        }
    }

    #[test]
    fn seal_under_session_roundtrip_has_no_secret_fields() {
        let req = IpcRequest::SealUnderSession {
            v: IPC_VERSION,
            peer_hint: "cd".repeat(32),
            app_payload_b64: "aGVsbG8=".into(),
        };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let raw = std::str::from_utf8(&f[4..]).unwrap();
        assert_json_has_no_secret_tokens(raw);
        assert!(raw.contains("\"op\":\"seal_under_session\""));
        assert!(raw.contains("app_payload_b64"));
        assert!(!raw.to_ascii_lowercase().contains("plaintext"));
        let resp = IpcResponse::SealUnderSessionResult {
            v: IPC_VERSION,
            envelope_b64: "QkFTRTY0".into(),
        };
        let rf = encode_response(&resp).unwrap();
        assert_eq!(decode_response(&rf).unwrap(), resp);
        assert_json_has_no_secret_tokens(std::str::from_utf8(&rf[4..]).unwrap());
    }

    #[test]
    fn enqueue_sealed_roundtrip_has_no_secret_fields() {
        let req = IpcRequest::EnqueueSealed {
            v: IPC_VERSION,
            envelope_b64: "QUJD".into(),
            peer_hint: Some("peer".into()),
        };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let raw = std::str::from_utf8(&f[4..]).unwrap().to_ascii_lowercase();
        for bad in ["seed", "private_key", "plaintext", "recovery"] {
            assert!(!raw.contains(bad), "{bad} leaked into EnqueueSealed JSON");
        }
    }

    /// The outbox ops carry identifiers, states and counts only: no field
    /// (and so no value) can hold message content, and the JSON keys pass the
    /// secret-name denylist both ways.
    #[test]
    fn outbox_ops_roundtrip_and_carry_no_content() {
        let item = OutboxItem {
            message_id_hex: "ab".repeat(16),
            peer_pub_hex: "cd".repeat(32),
            kind: "message".into(),
            state: "queued".into(),
            carrier: "lan_dial".into(),
            attempts: 3,
            next_attempt_ms: 1_700_000_000_000,
            last_error_code: "NOT_REACHABLE".into(),
            expires_at_ms: 1_700_000_086_400,
        };
        let reqs = [
            IpcRequest::OutboxKick {
                v: IPC_VERSION,
                peer_pub_hex: Some("cd".repeat(32)),
            },
            IpcRequest::OutboxKick {
                v: IPC_VERSION,
                peer_pub_hex: None,
            },
            IpcRequest::OutboxStatus {
                v: IPC_VERSION,
                message_id_hex: "ab".repeat(16),
            },
            IpcRequest::OutboxList {
                v: IPC_VERSION,
                peer_pub_hex: None,
                limit: Some(MAX_OUTBOX_LIST),
            },
        ];
        for req in &reqs {
            let f = encode_request(req).unwrap();
            assert_eq!(&decode_request(&f).unwrap(), req);
            assert_json_has_no_secret_tokens(std::str::from_utf8(&f[4..]).unwrap());
        }
        // Optional fields may be absent (and a minimal kick is just the op).
        let kick = decode_request(&frame_of(br#"{"op":"outbox_kick","v":1}"#)).unwrap();
        assert_eq!(
            kick,
            IpcRequest::OutboxKick {
                v: IPC_VERSION,
                peer_pub_hex: None
            }
        );
        let resps = [
            IpcResponse::OutboxStatusResult {
                v: IPC_VERSION,
                item: item.clone(),
            },
            IpcResponse::OutboxListResult {
                v: IPC_VERSION,
                worker_running: true,
                items: vec![item.clone()],
            },
        ];
        for resp in &resps {
            let f = encode_response(resp).unwrap();
            assert_eq!(&decode_response(&f).unwrap(), resp);
            let json = std::str::from_utf8(&f[4..]).unwrap();
            assert_json_has_no_secret_tokens(json);
            for word in ["body", "preview", "text", "envelope", "frames"] {
                assert!(!json.contains(word), "{word} in outbox IPC JSON: {json}");
            }
        }
        // The item has exactly these fields: adding one is a reviewed change.
        let value = serde_json::to_value(&item).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "attempts",
                "carrier",
                "expires_at_ms",
                "kind",
                "last_error_code",
                "message_id_hex",
                "next_attempt_ms",
                "peer_pub_hex",
                "state"
            ]
        );
        // A wrong version is refused like every other op.
        let err = decode_request_checked(&frame_of(br#"{"op":"outbox_list","v":2}"#)).unwrap_err();
        assert_eq!(err.code, "IPC_VERSION");
    }

    /// An op this build does not know (a newer client talking to an older
    /// daemon) is the typed `IPC_FRAME` refusal, never a crash or a guess.
    #[test]
    fn unknown_ops_are_a_typed_frame_error() {
        let err =
            decode_request_checked(&frame_of(br#"{"op":"outbox_frobnicate","v":1}"#)).unwrap_err();
        assert_eq!(err.code, "IPC_FRAME");
    }

    #[test]
    fn rejects_all_secret_field_names() {
        for bad in ["seed", "private_key", "plaintext", "recovery"] {
            let body = format!(r#"{{"op":"ping","v":1,"{bad}":"nope"}}"#);
            let mut frame = Vec::new();
            frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
            frame.extend_from_slice(body.as_bytes());
            assert!(decode_request(&frame).is_err(), "expected refuse for {bad}");
        }
    }
}
