//! Per-profile keystore choice for GNU/Linux and other non-macOS Unix release
//! builds: the desktop keyring (Secret Service) when it is reachable, else the
//! passphrase vault ([`crate::keystore_vault`]). The choice is recorded in
//! `<data-dir>/keystore.backend` and never changes silently afterwards
//! (`docs/design/2026-10-linux-keystore.md` §2).
//!
//! The decision logic is platform-neutral and unit-tested everywhere; only
//! the Secret Service probe is GNU/Linux code. macOS and Windows never call
//! [`resolve`].

use std::path::Path;
#[cfg(all(unix, not(target_os = "macos")))]
use std::time::Duration;

/// Non-secret marker naming the profile's keystore.
pub const KEYSTORE_MARKER_NAME: &str = "keystore.backend";
/// Explicit choice for a new profile: `vault` or `secret-service`.
pub const KEYSTORE_BACKEND_ENV: &str = "RAVEN_KEYSTORE_BACKEND";
/// How long the Secret Service probe may take before the vault is chosen.
#[cfg(all(unix, not(target_os = "macos")))]
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

const LEGACY_IDENTITY_MARKER: &str = "identity.backend";
const LEGACY_SECRET_SERVICE_IDENTITY: &str = "linux-secret-service\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreBackend {
    SecretService,
    PassphraseVault,
}

impl KeystoreBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecretService => "secret-service",
            Self::PassphraseVault => "passphrase-vault",
        }
    }

    fn parse_env(value: &str) -> Option<Self> {
        match value {
            "vault" | "passphrase-vault" => Some(Self::PassphraseVault),
            "secret-service" => Some(Self::SecretService),
            _ => None,
        }
    }

    fn parse_marker(raw: &str) -> Option<Self> {
        match raw {
            "secret-service\n" => Some(Self::SecretService),
            "passphrase-vault\n" => Some(Self::PassphraseVault),
            _ => None,
        }
    }
}

const SECRET_SERVICE_UNREACHABLE: &str = "this profile keeps its keys in the desktop keyring (Secret Service), but no unlocked keyring answered on the session bus. Log in to the desktop session or unlock the keyring (GNOME Keyring / KWallet) and try again; RAVEN does not fall back to a passphrase file for a keyring profile";

/// The recorded marker only (no legacy inference). Malformed is an error.
pub fn read_marker(data_dir: &Path) -> Result<Option<KeystoreBackend>, String> {
    let path = data_dir.join(KEYSTORE_MARKER_NAME);
    match std::fs::read_to_string(&path) {
        Ok(raw) => KeystoreBackend::parse_marker(&raw).map(Some).ok_or_else(|| {
            format!(
                "{} is not a valid keystore marker (expected `secret-service` or `passphrase-vault`)",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// The profile's keystore as far as its files say: the marker, else a
/// pre-R1 Secret Service identity, else an existing vault file.
pub fn recorded_backend(data_dir: &Path) -> Result<Option<KeystoreBackend>, String> {
    if let Some(recorded) = read_marker(data_dir)? {
        return Ok(Some(recorded));
    }
    match std::fs::read_to_string(data_dir.join(LEGACY_IDENTITY_MARKER)) {
        Ok(raw) if raw == LEGACY_SECRET_SERVICE_IDENTITY => {
            return Ok(Some(KeystoreBackend::SecretService))
        }
        _ => {}
    }
    match std::fs::symlink_metadata(data_dir.join(crate::keystore_vault::VAULT_FILE_NAME)) {
        Ok(_) => Ok(Some(KeystoreBackend::PassphraseVault)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Write the marker add-only. A concurrent writer that got there first wins
/// and its choice is returned.
fn record_marker(data_dir: &Path, choice: KeystoreBackend) -> Result<KeystoreBackend, String> {
    crate::paths::ensure_private_dir(data_dir)?;
    let path = data_dir.join(KEYSTORE_MARKER_NAME);
    match crate::paths::create_new_private(&path, format!("{}\n", choice.as_str()).as_bytes()) {
        Ok(()) => Ok(choice),
        Err(error) => read_marker(data_dir)?.ok_or(error),
    }
}

/// The selection rule with every input injected. `record` writes the marker
/// for a profile that has none (callers about to store a secret pass true).
pub fn resolve_with(
    data_dir: &Path,
    env_override: Option<&str>,
    secret_service_supported: bool,
    probe: &dyn Fn() -> bool,
    record: bool,
) -> Result<KeystoreBackend, String> {
    let requested = match env_override.map(str::trim).filter(|v| !v.is_empty()) {
        None => None,
        Some(value) => Some(KeystoreBackend::parse_env(value).ok_or_else(|| {
            format!("{KEYSTORE_BACKEND_ENV}={value} is not valid; use `vault` or `secret-service`")
        })?),
    };
    if requested == Some(KeystoreBackend::SecretService) && !secret_service_supported {
        return Err(format!(
            "{KEYSTORE_BACKEND_ENV}=secret-service: this build has no Secret Service client (musl/static); use the passphrase vault"
        ));
    }
    if let Some(recorded) = recorded_backend(data_dir)? {
        if let Some(requested) = requested.filter(|r| *r != recorded) {
            return Err(format!(
                "{KEYSTORE_BACKEND_ENV} asks for {} but this profile's keys are in {}; RAVEN never moves keys between keystores silently. Unset {KEYSTORE_BACKEND_ENV} or use a new --data-dir",
                requested.as_str(),
                recorded.as_str()
            ));
        }
        if recorded == KeystoreBackend::SecretService {
            if !secret_service_supported {
                return Err(
                    "this profile keeps its keys in the desktop keyring (Secret Service), which this build cannot use"
                        .into(),
                );
            }
            if !probe() {
                return Err(SECRET_SERVICE_UNREACHABLE.into());
            }
        }
        if record && read_marker(data_dir)?.is_none() {
            return record_marker(data_dir, recorded);
        }
        return Ok(recorded);
    }
    let choice = match requested {
        Some(KeystoreBackend::SecretService) => {
            if !probe() {
                return Err(format!(
                    "{KEYSTORE_BACKEND_ENV}=secret-service, but no unlocked desktop keyring answered on the session bus"
                ));
            }
            KeystoreBackend::SecretService
        }
        Some(KeystoreBackend::PassphraseVault) => KeystoreBackend::PassphraseVault,
        None if secret_service_supported && probe() => KeystoreBackend::SecretService,
        None => KeystoreBackend::PassphraseVault,
    };
    if record {
        let recorded = record_marker(data_dir, choice)?;
        if requested.is_some_and(|r| r != recorded) {
            return Err(format!(
                "another RAVEN process recorded {} for this profile at the same time",
                recorded.as_str()
            ));
        }
        return Ok(recorded);
    }
    Ok(choice)
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const SECRET_SERVICE_SUPPORTED: bool = true;
#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(all(target_os = "linux", target_env = "gnu"))
))]
const SECRET_SERVICE_SUPPORTED: bool = false;

/// Production entry point for the non-macOS Unix stores. A recorded choice is
/// cached per data dir for the life of the process (the Secret Service calls
/// themselves still fail closed if the keyring goes away later).
#[cfg(all(unix, not(target_os = "macos")))]
pub fn resolve(data_dir: &Path, record: bool) -> Result<KeystoreBackend, String> {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    static RESOLVED: OnceLock<Mutex<HashMap<PathBuf, KeystoreBackend>>> = OnceLock::new();
    let cache = RESOLVED.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(found) = cache.lock().ok().and_then(|c| c.get(data_dir).copied()) {
        return Ok(found);
    }
    let env = std::env::var_os(KEYSTORE_BACKEND_ENV).map(|v| v.to_string_lossy().into_owned());
    let resolved = resolve_with(
        data_dir,
        env.as_deref(),
        SECRET_SERVICE_SUPPORTED,
        &|| secret_service_reachable(PROBE_TIMEOUT),
        record,
    )?;
    if read_marker(data_dir)?.is_some() {
        if let Ok(mut c) = cache.lock() {
            c.insert(data_dir.to_path_buf(), resolved);
        }
    }
    Ok(resolved)
}

/// Whether this profile's secrets live in the passphrase vault.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn uses_vault(data_dir: &Path, record: bool) -> Result<bool, String> {
    Ok(resolve(data_dir, record)? == KeystoreBackend::PassphraseVault)
}

/// A session bus exists and the Secret Service default collection answers,
/// unlocked, within `timeout`. Runs on a helper thread: a hung D-Bus call is
/// abandoned, never waited for. Never calls `Unlock` (no prompt).
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn secret_service_reachable(timeout: Duration) -> bool {
    let bus_address = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some_and(|v| !v.is_empty());
    let runtime_bus =
        std::env::var_os("XDG_RUNTIME_DIR").is_some_and(|dir| Path::new(&dir).join("bus").exists());
    if !bus_address && !runtime_bus {
        return false;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("raven-secret-service-probe".into())
        .spawn(move || {
            use secret_service::{EncryptionType, SecretService};
            let reachable = SecretService::new(EncryptionType::Dh)
                .ok()
                .is_some_and(|service| {
                    service
                        .get_default_collection()
                        .ok()
                        .is_some_and(|collection| matches!(collection.is_locked(), Ok(false)))
                });
            let _ = tx.send(reachable);
        });
    if spawned.is_err() {
        return false;
    }
    rx.recv_timeout(timeout).unwrap_or(false)
}

/// Non-glibc Unix builds have no Secret Service client.
#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(all(target_os = "linux", target_env = "gnu"))
))]
pub fn secret_service_reachable(_timeout: Duration) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use tempfile::TempDir;

    fn resolve_t(
        dir: &Path,
        env: Option<&str>,
        supported: bool,
        reachable: bool,
        record: bool,
    ) -> (Result<KeystoreBackend, String>, u32) {
        let probes = Cell::new(0u32);
        let probe = || {
            probes.set(probes.get() + 1);
            reachable
        };
        let result = resolve_with(dir, env, supported, &probe, record);
        (result, probes.get())
    }

    #[test]
    fn fresh_profile_prefers_a_reachable_keyring_else_the_vault() {
        let tmp = TempDir::new().unwrap();
        let (r, _) = resolve_t(tmp.path(), None, true, true, false);
        assert_eq!(r.unwrap(), KeystoreBackend::SecretService);
        let (r, _) = resolve_t(tmp.path(), None, true, false, false);
        assert_eq!(r.unwrap(), KeystoreBackend::PassphraseVault);
        let (r, probes) = resolve_t(tmp.path(), None, false, true, false);
        assert_eq!(r.unwrap(), KeystoreBackend::PassphraseVault);
        assert_eq!(probes, 0, "musl never probes");
        assert!(
            read_marker(tmp.path()).unwrap().is_none(),
            "record=false writes nothing"
        );
    }

    #[test]
    fn explicit_vault_override_skips_the_probe_and_is_recorded() {
        let tmp = TempDir::new().unwrap();
        let (r, probes) = resolve_t(tmp.path(), Some("vault"), true, true, true);
        assert_eq!(r.unwrap(), KeystoreBackend::PassphraseVault);
        assert_eq!(probes, 0);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(KEYSTORE_MARKER_NAME)).unwrap(),
            "passphrase-vault\n"
        );
        assert!(resolve_t(tmp.path(), Some("plaintext"), true, true, false)
            .0
            .is_err());
        // musl: secret-service cannot be requested.
        let other = TempDir::new().unwrap();
        assert!(
            resolve_t(other.path(), Some("secret-service"), false, true, true)
                .0
                .is_err()
        );
        // glibc: requested secret-service must actually answer.
        assert!(
            resolve_t(other.path(), Some("secret-service"), true, false, true)
                .0
                .is_err()
        );
        assert!(read_marker(other.path()).unwrap().is_none());
    }

    #[test]
    fn recorded_choice_is_never_silently_changed() {
        // Vault profile: stays on the vault even when a keyring appears.
        let vault = TempDir::new().unwrap();
        resolve_t(vault.path(), None, true, false, true).0.unwrap();
        let (r, probes) = resolve_t(vault.path(), None, true, true, true);
        assert_eq!(r.unwrap(), KeystoreBackend::PassphraseVault);
        assert_eq!(probes, 0);
        let conflict = resolve_t(vault.path(), Some("secret-service"), true, true, true)
            .0
            .unwrap_err();
        assert!(conflict.contains("never moves keys"), "{conflict}");

        // Keyring profile: fails closed (no downgrade) when the keyring is gone.
        let ss = TempDir::new().unwrap();
        resolve_t(ss.path(), None, true, true, true).0.unwrap();
        let gone = resolve_t(ss.path(), None, true, false, true).0.unwrap_err();
        assert!(gone.contains("does not fall back"), "{gone}");
        assert!(resolve_t(ss.path(), Some("vault"), true, true, true)
            .0
            .is_err());
        assert!(!ss
            .path()
            .join(crate::keystore_vault::VAULT_FILE_NAME)
            .exists());
    }

    #[test]
    fn legacy_profiles_are_recognised_and_malformed_markers_refused() {
        let legacy = TempDir::new().unwrap();
        std::fs::write(
            legacy.path().join(LEGACY_IDENTITY_MARKER),
            LEGACY_SECRET_SERVICE_IDENTITY,
        )
        .unwrap();
        assert!(resolve_t(legacy.path(), None, true, false, true).0.is_err());
        assert_eq!(
            resolve_t(legacy.path(), None, true, true, true).0.unwrap(),
            KeystoreBackend::SecretService
        );
        assert_eq!(
            read_marker(legacy.path()).unwrap(),
            Some(KeystoreBackend::SecretService)
        );

        let vault_only = TempDir::new().unwrap();
        std::fs::write(
            vault_only
                .path()
                .join(crate::keystore_vault::VAULT_FILE_NAME),
            b"x",
        )
        .unwrap();
        assert_eq!(
            resolve_t(vault_only.path(), None, true, true, false)
                .0
                .unwrap(),
            KeystoreBackend::PassphraseVault
        );

        let bad = TempDir::new().unwrap();
        std::fs::write(bad.path().join(KEYSTORE_MARKER_NAME), "vault").unwrap();
        assert!(resolve_t(bad.path(), None, true, true, true).0.is_err());
    }

    #[test]
    fn a_concurrently_recorded_marker_wins() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(KEYSTORE_MARKER_NAME), "passphrase-vault\n").unwrap();
        assert_eq!(
            record_marker(tmp.path(), KeystoreBackend::SecretService).unwrap(),
            KeystoreBackend::PassphraseVault
        );
    }
}
