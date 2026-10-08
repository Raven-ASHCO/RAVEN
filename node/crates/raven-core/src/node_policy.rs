//! Local node policy config (ash writes; raven-node reads). No secrets.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodePolicy {
    /// AUTO: bridge when both radios; user may force on/off.
    #[serde(default = "default_true")]
    pub bridge: bool,
    #[serde(default = "default_true")]
    pub store: bool,
    #[serde(default = "default_false")]
    pub relay: bool,
    /// When true, node also acts as chat endpoint (separate from BridgeSubsystem).
    #[serde(default = "default_true")]
    pub endpoint: bool,
    /// AUTO policy marker — ash may set false when user overrides.
    #[serde(default = "default_true")]
    pub auto_policy: bool,
    /// Internet direct listen address (`ip:port`) the service binds when it
    /// starts without `--internet-listen` / `RAVEN_INTERNET_LISTEN` (`raven
    /// node internet on|off`). Empty = off, the default: Internet exposure is
    /// opt-in, like LAN exposure in the installers. Omitted from the file while
    /// empty, so older files and older readers are unaffected.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub internet_listen: String,
}

fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}

impl Default for NodePolicy {
    fn default() -> Self {
        Self {
            bridge: true,
            store: true,
            relay: false,
            endpoint: true,
            auto_policy: true,
            internet_listen: String::new(),
        }
    }
}

impl NodePolicy {
    /// Applied when `node_policy.json` exists but cannot be read or parsed:
    /// offer no services to other peers (bridge / store / relay off) and drop
    /// the AUTO marker so nothing re-enables them implicitly. The node stays
    /// the user's own chat endpoint, and opens no Internet listener.
    pub fn fail_closed() -> Self {
        Self {
            bridge: false,
            store: false,
            relay: false,
            endpoint: true,
            auto_policy: false,
            internet_listen: String::new(),
        }
    }
}

/// Normalise an Internet direct listen address: `ip:port`, `[ipv6]:port`, a
/// bare IP (`0.0.0.0`, `::`, `[::]`), which gets
/// [`crate::paths::DEFAULT_INTERNET_PORT`], or `localhost[:port]`. Empty (after
/// trimming) is `Ok(None)`: no Internet listener. Port 0 (OS-assigned) is kept
/// for tests. Anything else is an error that says what is expected.
pub fn normalize_internet_listen(raw: &str) -> Result<Option<String>, String> {
    use std::net::{IpAddr, SocketAddr};
    let s = raw.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let port = crate::paths::DEFAULT_INTERNET_PORT;
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(Some(addr.to_string()));
    }
    let bare = s
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or(s);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(Some(SocketAddr::new(ip, port).to_string()));
    }
    if s.eq_ignore_ascii_case("localhost") {
        return Ok(Some(format!("localhost:{port}")));
    }
    if let Some(p) = s
        .strip_prefix("localhost:")
        .or_else(|| s.strip_prefix("LOCALHOST:"))
    {
        if p.parse::<u16>().is_ok() {
            return Ok(Some(format!("localhost:{p}")));
        }
    }
    Err(format!(
        "Internet listen address must be IP:PORT, e.g. 0.0.0.0:{port} (all IPv4 interfaces), \
         [::]:{port} (IPv6) or 127.0.0.1:{port} (this computer only); got \"{}\"",
        crate::sanitize::sanitize_terminal_line(s)
    ))
}

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("write: {0}")]
    Write(String),
}

pub fn policy_path(data_dir: &Path) -> PathBuf {
    data_dir.join("node_policy.json")
}

/// Missing file → [`NodePolicy::default`]. Unreadable or corrupt → error, so
/// callers that can surface it (status, settings UI) may do so.
pub fn try_load_policy(data_dir: &Path) -> Result<NodePolicy, PolicyError> {
    let raw = match std::fs::read_to_string(policy_path(data_dir)) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(NodePolicy::default()),
        Err(e) => return Err(e.into()),
    };
    Ok(serde_json::from_str(&raw)?)
}

static CORRUPT_POLICY_WARNED: AtomicBool = AtomicBool::new(false);

/// Never fails open: a corrupt or unreadable policy file yields
/// [`NodePolicy::fail_closed`] (warned once per process; raven-node polls this).
pub fn load_policy(data_dir: &Path) -> NodePolicy {
    match try_load_policy(data_dir) {
        Ok(policy) => policy,
        Err(e) => {
            if !CORRUPT_POLICY_WARNED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "raven: node_policy.json unusable ({e}); bridge/store/relay disabled \
                     until the policy is saved again"
                );
            }
            NodePolicy::fail_closed()
        }
    }
}

/// Atomic replace (temp + fsync + rename, owner-only) so a concurrent reader
/// or a crash mid-write never observes a truncated policy.
pub fn save_policy(data_dir: &Path, policy: &NodePolicy) -> Result<(), PolicyError> {
    let raw = serde_json::to_string_pretty(policy)?;
    crate::paths::atomic_write_private(&policy_path(data_dir), raw.as_bytes())
        .map_err(PolicyError::Write)
}

/// Safe status snapshot for ash (never includes keys or packed envelopes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeStatusSnapshot {
    pub bridge: bool,
    pub store: bool,
    pub relay: bool,
    pub endpoint: bool,
    pub auto_policy: bool,
    pub transports: Vec<String>,
    pub forward_queue_pending: usize,
    pub forward_queue_total: usize,
    pub capabilities: Vec<String>,
}

impl BridgeStatusSnapshot {
    pub fn from_policy(
        policy: &NodePolicy,
        transports: &[&str],
        pending: usize,
        total: usize,
    ) -> Self {
        let mut caps = Vec::new();
        if transports.iter().any(|t| *t == "ble" || *t == "mock_ble") {
            caps.push("ble".into());
        }
        if transports.iter().any(|t| *t == "lan" || *t == "internet") {
            caps.push("internet".into());
        }
        if policy.relay {
            caps.push("relay".into());
        }
        if policy.store {
            caps.push("store".into());
        }
        if policy.bridge {
            caps.push("bridge".into());
        }
        Self {
            bridge: policy.bridge,
            store: policy.store,
            relay: policy.relay,
            endpoint: policy.endpoint,
            auto_policy: policy.auto_policy,
            transports: transports.iter().map(|s| (*s).to_string()).collect(),
            forward_queue_pending: pending,
            forward_queue_total: total,
            capabilities: caps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip_policy() {
        let dir = tempdir().unwrap();
        let p = NodePolicy {
            bridge: false,
            auto_policy: false,
            ..Default::default()
        };
        save_policy(dir.path(), &p).unwrap();
        let loaded = load_policy(dir.path());
        assert!(!loaded.bridge);
        assert!(!loaded.auto_policy);
    }

    #[test]
    fn missing_policy_uses_defaults() {
        let dir = tempdir().unwrap();
        assert_eq!(try_load_policy(dir.path()).unwrap(), NodePolicy::default());
        assert_eq!(load_policy(dir.path()), NodePolicy::default());
    }

    #[test]
    fn corrupt_or_truncated_policy_fails_closed() {
        // A torn write (empty / partial JSON) used to fall back to the
        // permissive default (bridge=true, store=true), silently undoing a
        // user's "bridge off".
        let dir = tempdir().unwrap();
        for raw in ["", "{\"bridge\": fal", "not json", "{\"bridge\": \"no\"}"] {
            std::fs::write(policy_path(dir.path()), raw).unwrap();
            assert!(try_load_policy(dir.path()).is_err(), "{raw:?}");
            let loaded = load_policy(dir.path());
            assert_eq!(loaded, NodePolicy::fail_closed(), "{raw:?}");
            assert!(!loaded.bridge && !loaded.store && !loaded.relay);
            assert!(!loaded.auto_policy);
        }
    }

    #[test]
    fn save_replaces_atomically_and_repairs_corrupt_file() {
        let dir = tempdir().unwrap();
        std::fs::write(policy_path(dir.path()), "{\"bridge\": tr").unwrap();
        let p = NodePolicy {
            store: false,
            ..NodePolicy::fail_closed()
        };
        save_policy(dir.path(), &p).unwrap();
        assert_eq!(try_load_policy(dir.path()).unwrap(), p);
        // Only the policy file remains: no temp file left behind.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("node_policy.json")]);
    }

    #[test]
    fn internet_listen_is_opt_in_and_old_files_stay_compatible() {
        let dir = tempdir().unwrap();
        // A file written before the field existed loads with it off.
        std::fs::write(
            policy_path(dir.path()),
            r#"{"bridge":true,"store":true,"relay":false,"endpoint":true,"auto_policy":true}"#,
        )
        .unwrap();
        assert_eq!(try_load_policy(dir.path()).unwrap(), NodePolicy::default());
        // Empty is not written at all (older readers see the same keys).
        save_policy(dir.path(), &NodePolicy::default()).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        assert!(!raw.contains("internet_listen"), "{raw}");
        let on = NodePolicy {
            internet_listen: "0.0.0.0:7422".into(),
            ..NodePolicy::default()
        };
        save_policy(dir.path(), &on).unwrap();
        assert_eq!(try_load_policy(dir.path()).unwrap(), on);
        assert!(NodePolicy::fail_closed().internet_listen.is_empty());
    }

    #[test]
    fn internet_listen_normalises_bare_ips_to_the_default_port() {
        let ok = |s: &str| normalize_internet_listen(s).unwrap();
        assert_eq!(ok(""), None);
        assert_eq!(ok("  "), None);
        assert_eq!(ok("0.0.0.0:7422").as_deref(), Some("0.0.0.0:7422"));
        assert_eq!(ok("0.0.0.0").as_deref(), Some("0.0.0.0:7422"));
        assert_eq!(ok("::").as_deref(), Some("[::]:7422"));
        assert_eq!(ok("[::]").as_deref(), Some("[::]:7422"));
        assert_eq!(ok("[::1]:0").as_deref(), Some("[::1]:0"));
        assert_eq!(ok("127.0.0.1:0").as_deref(), Some("127.0.0.1:0"));
        assert_eq!(ok("localhost").as_deref(), Some("localhost:7422"));
        assert_eq!(ok("localhost:9000").as_deref(), Some("localhost:9000"));
        for bad in [
            "example.com:7422",
            "0.0.0.0:99999",
            "1.2.3.4:x",
            "[::1",
            "on",
        ] {
            assert!(normalize_internet_listen(bad).is_err(), "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_tightens_mode_of_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = policy_path(dir.path());
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        save_policy(dir.path(), &NodePolicy::default()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
