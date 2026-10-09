//! Bootstrap peer configuration (§30).
//!
//! Raven-provided defaults are optional and empty by default — a user can
//! start with only manually supplied multiaddrs / host:port peers. Bootstrap
//! peers are untrusted relays for dial hints only (no identity authority,
//! no plaintext).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

/// Bootstrap / dial-hint configuration (no secrets).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapConfig {
    /// When false, ignore `raven_defaults` entirely.
    #[serde(default = "default_true")]
    pub use_raven_defaults: bool,
    /// Optional Raven-shipped multiaddrs (may be empty — not required).
    #[serde(default)]
    pub raven_defaults: Vec<String>,
    /// User-supplied bootstrap multiaddrs (community or self-hosted).
    #[serde(default)]
    pub custom: Vec<String>,
    /// Explicit manual peers for direct dial (proves no Raven-owned dependency).
    #[serde(default)]
    pub manual_peers: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            // Defaults list is empty — serverless V1 does not require Raven-owned nodes.
            use_raven_defaults: true,
            raven_defaults: Vec::new(),
            custom: Vec::new(),
            manual_peers: Vec::new(),
        }
    }
}

impl BootstrapConfig {
    /// Effective dial targets: manual + custom + (optional empty Raven defaults).
    pub fn effective_peers(&self) -> Vec<String> {
        let mut out = Vec::new();
        for p in &self.manual_peers {
            push_unique(&mut out, p);
        }
        for p in &self.custom {
            push_unique(&mut out, p);
        }
        if self.use_raven_defaults {
            for p in &self.raven_defaults {
                push_unique(&mut out, p);
            }
        }
        out
    }

    /// True when startup can proceed without any Raven-owned bootstrap entry.
    pub fn manual_peer_only_ok(&self) -> bool {
        !self.manual_peers.is_empty()
            && (self.raven_defaults.is_empty() || !self.use_raven_defaults)
    }

    pub fn add_custom(&mut self, multiaddr: impl Into<String>) {
        let s = multiaddr.into();
        if !self.custom.iter().any(|x| x == &s) {
            self.custom.push(s);
        }
    }

    pub fn remove_raven_defaults(&mut self) {
        self.use_raven_defaults = false;
        self.raven_defaults.clear();
    }

    /// Applied when `bootstrap.json` exists but cannot be read or parsed:
    /// no dial hints at all, and Raven defaults off (a user who opted out of
    /// Raven-provided peers must not be silently opted back in).
    pub fn fail_closed() -> Self {
        Self {
            use_raven_defaults: false,
            raven_defaults: Vec::new(),
            custom: Vec::new(),
            manual_peers: Vec::new(),
        }
    }
}

fn push_unique(out: &mut Vec<String>, p: &str) {
    if !out.iter().any(|x| x == p) {
        out.push(p.to_string());
    }
}

#[derive(Error, Debug)]
pub enum BootstrapError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("write: {0}")]
    Write(String),
}

pub fn bootstrap_path(data_dir: &Path) -> PathBuf {
    data_dir.join("bootstrap.json")
}

/// Missing file → [`BootstrapConfig::default`]. Unreadable or corrupt → error.
pub fn try_load_bootstrap(data_dir: &Path) -> Result<BootstrapConfig, BootstrapError> {
    let raw = match std::fs::read_to_string(bootstrap_path(data_dir)) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BootstrapConfig::default()),
        Err(e) => return Err(e.into()),
    };
    Ok(serde_json::from_str(&raw)?)
}

static CORRUPT_BOOTSTRAP_WARNED: AtomicBool = AtomicBool::new(false);

/// Never fails open: a corrupt or unreadable file yields
/// [`BootstrapConfig::fail_closed`] (warned once per process).
pub fn load_bootstrap(data_dir: &Path) -> BootstrapConfig {
    match try_load_bootstrap(data_dir) {
        Ok(cfg) => cfg,
        Err(e) => {
            if !CORRUPT_BOOTSTRAP_WARNED.swap(true, Ordering::Relaxed) {
                eprintln!("raven: bootstrap.json unusable ({e}); using no bootstrap peers");
            }
            BootstrapConfig::fail_closed()
        }
    }
}

/// Where [`save_bootstrap`] keeps a `bootstrap.json` it found unparsable.
pub fn corrupt_bootstrap_backup_path(data_dir: &Path) -> PathBuf {
    data_dir.join("bootstrap.json.corrupt")
}

/// Atomic replace (temp + fsync + rename, owner-only); never a torn file.
///
/// Read-modify-write callers start from [`load_bootstrap`], which turns a
/// corrupt or hand-edited file into an *empty* fail-closed config; saving that
/// would silently replace the user's peers with just the new entry. So an
/// existing file that does not parse is first moved aside to
/// [`corrupt_bootstrap_backup_path`] (kept, never deleted), and one that cannot
/// even be read is not overwritten at all. A missing or valid file is simply
/// replaced.
pub fn save_bootstrap(data_dir: &Path, cfg: &BootstrapConfig) -> Result<(), BootstrapError> {
    let raw = serde_json::to_string_pretty(cfg)?;
    match try_load_bootstrap(data_dir) {
        Ok(_) => {}
        Err(BootstrapError::Json(e)) => {
            let backup = corrupt_bootstrap_backup_path(data_dir);
            std::fs::rename(bootstrap_path(data_dir), &backup).map_err(|rename_err| {
                BootstrapError::Write(format!(
                    "bootstrap.json is unparsable ({e}) and could not be saved to {}: {rename_err}",
                    backup.display()
                ))
            })?;
            eprintln!(
                "raven: bootstrap.json was unparsable ({e}); the old file was kept as {}",
                backup.display()
            );
        }
        Err(e) => {
            return Err(BootstrapError::Write(format!(
                "bootstrap.json is unreadable ({e}); not overwriting it"
            )));
        }
    }
    crate::paths::atomic_write_private(&bootstrap_path(data_dir), raw.as_bytes())
        .map_err(BootstrapError::Write)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn manual_peer_only_without_raven() {
        let mut cfg = BootstrapConfig::default();
        assert!(cfg.raven_defaults.is_empty());
        cfg.manual_peers.push("/ip4/127.0.0.1/tcp/4001".into());
        assert!(cfg.manual_peer_only_ok());
        assert_eq!(cfg.effective_peers().len(), 1);
    }

    #[test]
    fn disable_raven_defaults() {
        let mut cfg = BootstrapConfig {
            use_raven_defaults: true,
            raven_defaults: vec!["/dnsaddr/bootstrap.example".into()],
            custom: vec![],
            manual_peers: vec!["/ip4/10.0.0.1/tcp/9".into()],
        };
        assert!(!cfg.manual_peer_only_ok());
        cfg.remove_raven_defaults();
        assert!(cfg.manual_peer_only_ok());
        assert_eq!(
            cfg.effective_peers(),
            vec!["/ip4/10.0.0.1/tcp/9".to_string()]
        );
    }

    #[test]
    fn roundtrip_file() {
        let dir = tempdir().unwrap();
        let mut cfg = BootstrapConfig::default();
        cfg.add_custom("/ip4/192.0.2.1/tcp/4001");
        cfg.manual_peers.push("127.0.0.1:9000".into());
        save_bootstrap(dir.path(), &cfg).unwrap();
        let loaded = load_bootstrap(dir.path());
        assert_eq!(loaded.custom.len(), 1);
        assert_eq!(loaded.manual_peers.len(), 1);
    }

    #[test]
    fn missing_file_uses_defaults() {
        let dir = tempdir().unwrap();
        assert_eq!(
            try_load_bootstrap(dir.path()).unwrap(),
            BootstrapConfig::default()
        );
    }

    #[test]
    fn corrupt_or_truncated_file_fails_closed() {
        // A torn write used to revert to defaults (use_raven_defaults=true),
        // silently opting a user back into Raven-provided peers.
        let dir = tempdir().unwrap();
        for raw in ["", "{\"use_raven_defaults\": fa", "null"] {
            std::fs::write(bootstrap_path(dir.path()), raw).unwrap();
            assert!(try_load_bootstrap(dir.path()).is_err(), "{raw:?}");
            let loaded = load_bootstrap(dir.path());
            assert_eq!(loaded, BootstrapConfig::fail_closed(), "{raw:?}");
            assert!(!loaded.use_raven_defaults);
            assert!(loaded.effective_peers().is_empty());
        }
    }

    /// Read-modify-write callers load with the fail-closed `load_bootstrap`
    /// (empty on a parse error). Saving that must not silently destroy the
    /// user's existing peers: the unparsable file is kept.
    #[test]
    fn saving_over_an_unparsable_file_keeps_the_original() {
        let dir = tempdir().unwrap();
        let original =
            "{\"manual_peers\": [\"10.0.0.1:9\",], \"custom\": [\"/ip4/1.1.1.1/tcp/1\"]}";
        std::fs::write(bootstrap_path(dir.path()), original).unwrap();

        let mut cfg = load_bootstrap(dir.path());
        assert_eq!(cfg, BootstrapConfig::fail_closed());
        cfg.add_custom("/ip4/1.2.3.4/tcp/4001");
        save_bootstrap(dir.path(), &cfg).unwrap();

        assert_eq!(try_load_bootstrap(dir.path()).unwrap(), cfg);
        assert_eq!(
            std::fs::read_to_string(corrupt_bootstrap_backup_path(dir.path())).unwrap(),
            original
        );
        // A later valid save does not touch the kept backup.
        cfg.add_custom("/ip4/5.6.7.8/tcp/4001");
        save_bootstrap(dir.path(), &cfg).unwrap();
        assert_eq!(
            std::fs::read_to_string(corrupt_bootstrap_backup_path(dir.path())).unwrap(),
            original
        );
    }

    #[test]
    fn saving_does_not_overwrite_an_unreadable_file() {
        let dir = tempdir().unwrap();
        // A directory where the file belongs: read fails with an I/O error that
        // is not "not found", so the (unknowable) contents must not be replaced.
        std::fs::create_dir(bootstrap_path(dir.path())).unwrap();
        let err = save_bootstrap(dir.path(), &BootstrapConfig::default()).unwrap_err();
        assert!(matches!(err, BootstrapError::Write(_)), "{err}");
        assert!(bootstrap_path(dir.path()).is_dir());
    }

    #[test]
    fn save_is_atomic_and_owner_only() {
        let dir = tempdir().unwrap();
        let path = bootstrap_path(dir.path());
        std::fs::write(&path, "{\"custom\": [").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let mut cfg = BootstrapConfig::fail_closed();
        cfg.manual_peers.push("127.0.0.1:9000".into());
        save_bootstrap(dir.path(), &cfg).unwrap();
        assert_eq!(try_load_bootstrap(dir.path()).unwrap(), cfg);
        // No temp file is left behind; the torn original is kept aside.
        let mut names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                std::ffi::OsString::from("bootstrap.json"),
                std::ffi::OsString::from("bootstrap.json.corrupt"),
            ]
        );
        assert_eq!(
            std::fs::read_to_string(corrupt_bootstrap_backup_path(dir.path())).unwrap(),
            "{\"custom\": ["
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
