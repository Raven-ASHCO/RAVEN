//! Relay allow-list and status files (P3, transports design §3.5).
//!
//! A relay (`raven-node relay`, or `raven-node service --relay`) accepts
//! reservations only from the PeerIds in `relay_allow.json` in its data dir:
//! on by default, managed with `raven relay allow|deny`. A missing file admits
//! nobody; an unreadable or invalid one admits nobody either (fail closed),
//! and the relay says so in its counts. `relay_status.json` is what a relay
//! reports about itself for `raven relay status|card`: its own PeerId and
//! listen addresses and counts only, never a client's PeerId or address.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ipc::RelayCounts;
use crate::p2p_route::normalize_peer_id;

pub const RELAY_ALLOW_FILE: &str = "relay_allow.json";
pub const RELAY_STATUS_FILE: &str = "relay_status.json";
/// The libp2p key of a dedicated relay (`raven-node relay`): a 32-byte
/// Ed25519 seed, owner-only. A relay holds no Raven identity at all.
pub const RELAY_KEY_FILE: &str = "relay_key.ed25519";
const RELAY_ALLOW_LOCK: &str = ".relay_allow.lock.sqlite";
/// Held by a running `raven-node relay` for its whole life: one relay per
/// folder, and `raven relay status` tells a stopped relay by it.
pub const RELAY_LOCK_FILE: &str = ".relay.lock.sqlite";
/// A running relay rewrites `relay_status.json` at least this often.
pub const RELAY_STATUS_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(10);
/// Older than this, the status file is a stopped (or stuck) relay's.
pub const RELAY_STATUS_STALE_MS: u64 = 35_000;
const ALLOW_VERSION: u32 = 1;
/// PeerIds one allow-list holds at most (the hard max of reservations).
pub const MAX_ALLOW_ENTRIES: usize = 1024;
const MAX_LABEL_CHARS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAllowEntry {
    pub peer_id: String,
    /// The operator's own note (a petname), never shown to the peer.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAllowList {
    pub version: u32,
    #[serde(default)]
    pub peers: Vec<RelayAllowEntry>,
}

impl Default for RelayAllowList {
    fn default() -> Self {
        Self {
            version: ALLOW_VERSION,
            peers: Vec::new(),
        }
    }
}

impl RelayAllowList {
    pub fn contains(&self, peer_id: &str) -> bool {
        self.peers.iter().any(|e| e.peer_id == peer_id)
    }
}

pub fn relay_allow_path(dir: &Path) -> PathBuf {
    dir.join(RELAY_ALLOW_FILE)
}

/// The allow-list: `Ok(None)` when there is none (nobody may reserve), `Err`
/// when it exists but cannot be used (unreadable, not JSON, an unknown
/// version, an invalid or duplicate PeerId, too many entries): the relay then
/// admits nobody. Never "repaired" silently.
pub fn load_relay_allow(dir: &Path) -> Result<Option<RelayAllowList>, String> {
    let path = relay_allow_path(dir);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{RELAY_ALLOW_FILE}: {e}")),
    };
    let list: RelayAllowList =
        serde_json::from_str(&raw).map_err(|e| format!("{RELAY_ALLOW_FILE} corrupt: {e}"))?;
    if list.version != ALLOW_VERSION {
        return Err(format!(
            "{RELAY_ALLOW_FILE}: version {} is not supported",
            list.version
        ));
    }
    if list.peers.len() > MAX_ALLOW_ENTRIES {
        return Err(format!(
            "{RELAY_ALLOW_FILE}: more than {MAX_ALLOW_ENTRIES} peers"
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for entry in &list.peers {
        let canonical = normalize_peer_id(&entry.peer_id)
            .map_err(|e| format!("{RELAY_ALLOW_FILE}: invalid peer_id: {e}"))?;
        if canonical != entry.peer_id || !seen.insert(canonical) {
            return Err(format!(
                "{RELAY_ALLOW_FILE}: non-canonical or duplicate peer_id"
            ));
        }
    }
    Ok(Some(list))
}

fn clean_label(label: &str) -> String {
    crate::sanitize::sanitize_terminal_line(label)
        .chars()
        .take(MAX_LABEL_CHARS)
        .collect()
}

/// Edit the allow-list under its lock. A missing file starts empty; an
/// unreadable one is refused (fix or move it aside first), so a typo never
/// opens or empties the relay behind the operator's back.
fn edit_relay_allow<T>(
    dir: &Path,
    edit: impl FnOnce(&mut RelayAllowList) -> Result<T, String>,
) -> Result<T, String> {
    crate::paths::ensure_private_dir(dir)?;
    let _lock = crate::paths::DataDirLock::acquire(dir, RELAY_ALLOW_LOCK)?;
    let mut list = load_relay_allow(dir)?.unwrap_or_default();
    let out = edit(&mut list)?;
    let raw = serde_json::to_vec_pretty(&list).map_err(|e| e.to_string())?;
    crate::paths::atomic_write_private(&relay_allow_path(dir), &raw)?;
    Ok(out)
}

/// Allow `peer_id` to reserve. `Ok(false)`: it already was (the label is
/// updated when given).
pub fn relay_allow(dir: &Path, peer_id: &str, label: &str) -> Result<bool, String> {
    let peer_id = normalize_peer_id(peer_id)?;
    let label = clean_label(label);
    edit_relay_allow(dir, |list| {
        if let Some(entry) = list.peers.iter_mut().find(|e| e.peer_id == peer_id) {
            if !label.is_empty() {
                entry.label = label;
            }
            return Ok(false);
        }
        if list.peers.len() >= MAX_ALLOW_ENTRIES {
            return Err(format!(
                "{RELAY_ALLOW_FILE} is full ({MAX_ALLOW_ENTRIES} peers)"
            ));
        }
        list.peers.push(RelayAllowEntry { peer_id, label });
        Ok(true)
    })
}

/// Stop allowing `peer_id`. `Ok(false)`: it was not on the list. A running
/// relay drops its reservation at the next reload.
pub fn relay_deny(dir: &Path, peer_id: &str) -> Result<bool, String> {
    let peer_id = normalize_peer_id(peer_id)?;
    edit_relay_allow(dir, |list| {
        let before = list.peers.len();
        list.peers.retain(|e| e.peer_id != peer_id);
        Ok(list.peers.len() != before)
    })
}

/// What a relay process publishes about itself (`relay_status.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayStatusFile {
    pub version: u32,
    /// The relay's own PeerId (what friends put in `via=`).
    pub peer_id: String,
    /// Its own listen addresses (no `/p2p/` suffix).
    pub listen_addrs: Vec<String>,
    pub counts: RelayCounts,
    pub updated_at_ms: u64,
    /// The process that wrote it (a later start replaces the file).
    #[serde(default)]
    pub pid: u32,
}

pub fn relay_status_path(dir: &Path) -> PathBuf {
    dir.join(RELAY_STATUS_FILE)
}

pub fn write_relay_status(dir: &Path, status: &RelayStatusFile) -> Result<(), String> {
    let raw = serde_json::to_vec_pretty(status).map_err(|e| e.to_string())?;
    crate::paths::atomic_write_private(&relay_status_path(dir), &raw)
}

/// `Ok(None)` when no relay has run in `dir`.
pub fn load_relay_status(dir: &Path) -> Result<Option<RelayStatusFile>, String> {
    match std::fs::read_to_string(relay_status_path(dir)) {
        Ok(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|e| format!("{RELAY_STATUS_FILE} corrupt: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{RELAY_STATUS_FILE}: {e}")),
    }
}

/// Is `dir` a dedicated relay folder (it holds a relay key, so no identity)?
pub fn is_relay_dir(dir: &Path) -> bool {
    dir.join(RELAY_KEY_FILE).is_file()
}

/// Does a relay run in `dir` right now? It holds [`RELAY_LOCK_FILE`] for
/// its whole life; taking it (and letting it go at once) means nobody does.
pub fn relay_is_running(dir: &Path) -> bool {
    if !dir.join(RELAY_LOCK_FILE).exists() {
        return false;
    }
    crate::paths::DataDirLock::acquire_within(dir, RELAY_LOCK_FILE, std::time::Duration::ZERO)
        .is_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> String {
        crate::p2p_route::local_peer_id(&crate::Identity::from_seed(&[seed; 32]))
    }

    #[test]
    fn allow_and_deny_round_trip_and_stay_canonical() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_relay_allow(dir.path()).unwrap(), None);
        assert!(relay_allow(dir.path(), &peer(1), "bob").unwrap());
        assert!(!relay_allow(dir.path(), &format!(" {} ", peer(1)), "").unwrap());
        assert!(relay_allow(dir.path(), &peer(2), "carol\u{1b}[31m").unwrap());
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert_eq!(list.peers.len(), 2);
        assert!(list.contains(&peer(1)) && list.contains(&peer(2)));
        assert_eq!(list.peers[0].label, "bob");
        assert!(!list.peers[1].label.contains('\u{1b}'));
        assert!(relay_deny(dir.path(), &peer(1)).unwrap());
        assert!(!relay_deny(dir.path(), &peer(1)).unwrap());
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert!(!list.contains(&peer(1)) && list.contains(&peer(2)));
        assert!(relay_allow(dir.path(), "not-a-peer", "").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(relay_allow_path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// An allow-list that cannot be used admits nobody and is never
    /// silently rewritten by `allow` / `deny`.
    #[test]
    fn an_unusable_allow_list_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        for raw in [
            "{not json".to_string(),
            r#"{"version":2,"peers":[]}"#.to_string(),
            r#"{"version":1,"peers":[{"peer_id":"12D3KooWnope"}]}"#.to_string(),
            format!(
                r#"{{"version":1,"peers":[{{"peer_id":"{p}"}},{{"peer_id":"{p}"}}]}}"#,
                p = peer(3)
            ),
        ] {
            std::fs::write(relay_allow_path(dir.path()), &raw).unwrap();
            assert!(load_relay_allow(dir.path()).is_err(), "{raw}");
            assert!(relay_allow(dir.path(), &peer(4), "").is_err(), "{raw}");
            assert!(relay_deny(dir.path(), &peer(3)).is_err(), "{raw}");
            assert_eq!(
                std::fs::read_to_string(relay_allow_path(dir.path())).unwrap(),
                raw,
                "never repaired silently"
            );
        }
    }

    #[test]
    fn status_file_round_trips_and_holds_counts_only() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_relay_status(dir.path()).unwrap(), None);
        let status = RelayStatusFile {
            version: 1,
            peer_id: peer(5),
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/7423".into()],
            counts: RelayCounts {
                allowed_peers: 2,
                reservations: 1,
                ..RelayCounts::default()
            },
            updated_at_ms: 1,
            pid: 7,
        };
        write_relay_status(dir.path(), &status).unwrap();
        assert_eq!(load_relay_status(dir.path()).unwrap(), Some(status));
        assert!(!is_relay_dir(dir.path()));
        std::fs::write(dir.path().join(RELAY_KEY_FILE), [0u8; 32]).unwrap();
        assert!(is_relay_dir(dir.path()));
    }

    /// Review item 13: a stopped relay is told from a running one by its
    /// lock, not only by the age of its last status.
    #[test]
    fn a_running_relay_is_told_by_its_lock() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!relay_is_running(dir.path()));
        let held = crate::paths::DataDirLock::acquire(dir.path(), RELAY_LOCK_FILE).unwrap();
        assert!(relay_is_running(dir.path()));
        drop(held);
        assert!(!relay_is_running(dir.path()));
        const {
            assert!(RELAY_STATUS_STALE_MS > 3 * RELAY_STATUS_HEARTBEAT.as_millis() as u64);
        }
    }
}
