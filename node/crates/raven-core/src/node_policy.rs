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
        }
    }
}

impl NodePolicy {
    /// Applied when `node_policy.json` exists but cannot be read or parsed:
    /// offer no services to other peers (bridge / store / relay off) and drop
    /// the AUTO marker so nothing re-enables them implicitly. The node stays
    /// the user's own chat endpoint.
    pub fn fail_closed() -> Self {
        Self {
            bridge: false,
            store: false,
            relay: false,
            endpoint: true,
            auto_policy: false,
        }
    }
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
