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
    /// Packed RavenEnvelopeV1 produced by in-daemon ATSAM seal (base64).
    SealUnderSessionResult {
        v: u16,
        envelope_b64: String,
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

pub fn decode_request(frame: &[u8]) -> Result<IpcRequest, String> {
    if frame.len() < 4 {
        return Err("short frame".into());
    }
    let n = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if n > MAX_IPC_FRAME || frame.len() < 4 + n {
        return Err("bad length".into());
    }
    let req: IpcRequest = serde_json::from_slice(&frame[4..4 + n]).map_err(|e| e.to_string())?;
    match &req {
        IpcRequest::Ping { v }
        | IpcRequest::Status { v }
        | IpcRequest::SetPolicy { v, .. }
        | IpcRequest::EnqueueSealed { v, .. }
        | IpcRequest::SealUnderSession { v, .. }
        | IpcRequest::LanDial { v, .. }
        | IpcRequest::InternetDial { v, .. } => {
            if *v != IPC_VERSION {
                return Err("ipc version".into());
            }
        }
    }
    // Refuse accidental secret field names in JSON (defense in depth).
    let raw = std::str::from_utf8(&frame[4..4 + n]).unwrap_or("");
    for bad in ["seed", "private_key", "plaintext", "recovery"] {
        if raw.to_ascii_lowercase().contains(bad) {
            return Err("forbidden field".into());
        }
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

/// Default Unix domain socket path under data dir (mode 0600 expected at bind).
///
/// Windows callers must not use this alone — the daemon binds
/// [`WINDOWS_NAMED_PIPE`], not a `.sock` file. Use [`ipc_endpoint`].
pub fn default_socket_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("raven-node.sock")
}

/// Canonical Windows named-pipe bind/connect name.
/// Windows Platform server MUST bind this exact string (user DACL only).
pub const WINDOWS_NAMED_PIPE: &str = r"\\.\pipe\raven-node";

/// Alias for [`WINDOWS_NAMED_PIPE`] (Windows Platform bind name).
pub fn default_pipe_name() -> &'static str {
    WINDOWS_NAMED_PIPE
}

/// Platform-local IPC connect target.
///
/// Callers must obtain this from [`ipc_endpoint`] so Windows never looks for a
/// UDS path under `data_dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcEndpoint {
    /// Unix domain socket (`<data_dir>/raven-node.sock`).
    UnixSocket(std::path::PathBuf),
    /// Canonical Windows named pipe ([`WINDOWS_NAMED_PIPE`]).
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
        IpcEndpoint::NamedPipe(WINDOWS_NAMED_PIPE)
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

    #[cfg(unix)]
    #[test]
    fn ipc_endpoint_selects_unix_socket() {
        let dir = std::path::Path::new("/tmp/raven-data");
        let ep = ipc_endpoint(dir);
        assert_eq!(default_ipc_endpoint(dir), ep);
        assert_eq!(ep, IpcEndpoint::UnixSocket(default_socket_path(dir)));
        assert_eq!(
            ep.to_string(),
            dir.join("raven-node.sock").display().to_string()
        );
        assert!(ep.transport_available());
        assert!(!matches!(ep, IpcEndpoint::NamedPipe(_)));
        assert!(!matches!(ep, IpcEndpoint::Unsupported));
    }

    #[cfg(windows)]
    #[test]
    fn ipc_endpoint_selects_windows_named_pipe() {
        let dir = std::path::Path::new(r"C:\raven-data");
        let ep = ipc_endpoint(dir);
        assert_eq!(default_ipc_endpoint(dir), ep);
        assert_eq!(ep, IpcEndpoint::NamedPipe(WINDOWS_NAMED_PIPE));
        assert_eq!(ep.to_string(), r"\\.\pipe\raven-node");
        assert_eq!(default_pipe_name(), r"\\.\pipe\raven-node");
        assert!(ep.transport_available());
        assert!(!matches!(ep, IpcEndpoint::UnixSocket(_)));
        assert!(!matches!(ep, IpcEndpoint::Unsupported));
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
