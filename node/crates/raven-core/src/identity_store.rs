//! Secure persistence for the 32-byte Ed25519 identity seed.
//!
//! Platform backends (never log or print seed bytes):
//! - macOS: Keychain (generic password)
//! - Windows: DPAPI-protected `identity.seed` file
//! - GNU/Linux: Secret Service (glibc) when an unlocked keyring answers,
//!   created add-only and prompt-free through the Raven fork
//!   (`create_item_no_prompt`, R1 2026-10-08); otherwise the passphrase vault
//!   (`keystore_vault`). The per-profile choice is recorded and never changes
//!   silently (`keystore_select`, docs/design/2026-10-linux-keystore.md).
//! - musl / other non-macOS Unix: the passphrase vault only
//! - locked-file mode is an explicit lab/CI override only (debug builds).
//!   First-install and unmarked-seed load require proven platform absence
//!   (`Ok(None)`). macOS `SecureStore` (locked/denied Keychain) is Continuity.
//!   Linux debug/lab may treat `secret-service connect:` / `ServiceUnknown`
//!   (no session bus or no `org.freedesktop.secrets`) as no store.
//!
//! Legacy plaintext `identity.seed` (exactly 32 raw bytes) is migrated on first load.
//! Removing the plaintext file afterwards is **best-effort**: it is overwritten
//! in place, fsynced and unlinked, but copy-on-write filesystems (APFS, btrfs,
//! ZFS), snapshots, backups and SSD wear levelling can retain the old bytes.
//! Treat a seed that ever sat on disk in plaintext as exposed to disk forensics.
//!
//! In memory the seed is zeroized on a best-effort basis only: the loaders hand
//! it back as a plain `[u8; 32]`, so copies can linger in dead stack frames
//! until overwritten, and a core dump or swap page may still contain it.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use zeroize::Zeroize;

use crate::identity::Identity;

/// Legacy / locked-file / DPAPI blob path under `data_dir`.
pub const SEED_FILE_NAME: &str = "identity.seed";

/// Non-secret marker naming the active backend.
pub const BACKEND_MARKER_NAME: &str = "identity.backend";
pub const IDENTITY_BINDING_NAME: &str = "identity.binding";

const IDENTITY_STORE_LOCK_NAME: &str = ".identity_store.lock.sqlite";
const IDENTITY_BINDING_MAGIC: &[u8; 8] = b"RVNIDB1\0";
const IDENTITY_BINDING_VERSION: u8 = 1;
const IDENTITY_ADDRESS_LEN: usize = 44;
const IDENTITY_BINDING_PREFIX_LEN: usize = 8 + 1 + 1 + 2 + 32 + 32 + IDENTITY_ADDRESS_LEN;
const IDENTITY_BINDING_LEN: usize = IDENTITY_BINDING_PREFIX_LEN + 32;

const DPAPI_MAGIC: &[u8] = b"RVNDPAPI";
#[cfg_attr(not(windows), allow(dead_code))]
const DPAPI_VERSION: u8 = 1;

#[cfg_attr(
    not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))),
    allow(dead_code)
)]
const KEYCHAIN_SERVICE: &str = "app.raven.node.identity";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityStoreBackend {
    MacosKeychain,
    WindowsDpapiFile,
    LinuxSecretService,
    LockedFile,
    /// Passphrase vault (`keystore.vault`, entry `identity-seed`): non-macOS
    /// Unix without a reachable Secret Service.
    PassphraseVault,
}

impl IdentityStoreBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MacosKeychain => "macos-keychain",
            Self::WindowsDpapiFile => "windows-dpapi-file",
            Self::LinuxSecretService => "linux-secret-service",
            Self::LockedFile => "locked-file",
            Self::PassphraseVault => "passphrase-vault",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "macos-keychain" => Some(Self::MacosKeychain),
            "windows-dpapi-file" => Some(Self::WindowsDpapiFile),
            "linux-secret-service" => Some(Self::LinuxSecretService),
            "locked-file" => Some(Self::LockedFile),
            "passphrase-vault" => Some(Self::PassphraseVault),
            _ => None,
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::MacosKeychain => 1,
            Self::WindowsDpapiFile => 2,
            Self::LinuxSecretService => 3,
            Self::LockedFile => 4,
            Self::PassphraseVault => 5,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::MacosKeychain),
            2 => Some(Self::WindowsDpapiFile),
            3 => Some(Self::LinuxSecretService),
            4 => Some(Self::LockedFile),
            5 => Some(Self::PassphraseVault),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityStoreStatus {
    pub backend: Option<IdentityStoreBackend>,
    pub has_identity: bool,
    /// True when a legacy plaintext seed file still sits on disk (should be rare after load).
    pub legacy_plaintext_present: bool,
}

/// Env vs recorded-marker check for `ash doctor` (no seed material).
///
/// Aligns with the fail-closed conflict rules in `load_seed_with_migrate`.
/// A hard mismatch means identity is **not usable** for `daemon_ready` —
/// this is not a separate green light beside presence / ready / send_path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityBackendConsistency {
    pub recorded: Option<IdentityStoreBackend>,
    pub env_locked_file_requested: bool,
    pub ok: bool,
    /// Redacted operator issue; never contains seed bytes.
    pub issue: Option<String>,
}

impl IdentityBackendConsistency {
    /// Env/marker conflict (or Release locked-file forbid). Fold into
    /// identity-not-usable / `daemon_ready` fail — do not treat as a
    /// standalone doctor green.
    pub fn blocks_identity_use(&self) -> bool {
        !self.ok
    }
}

/// Combined identity input for CLI DX `daemon_ready`: present **and**
/// backend-consistent. Doctor should print FAIL on mismatch, not a new
/// top-level OK status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityUsable {
    pub usable: bool,
    pub has_identity: bool,
    pub consistency: IdentityBackendConsistency,
    /// Redacted; set when `usable` is false.
    pub reason: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityStoreError {
    #[error("identity store I/O: {0}")]
    Io(String),
    #[error("identity seed corrupt or wrong length")]
    Corrupt,
    #[error("secure store unavailable: {0}")]
    SecureStore(String),
    #[error("identity continuity violation: {0}")]
    Continuity(&'static str),
}

impl IdentityStoreError {
    /// Errors must never embed seed material.
    pub fn redacted_display(&self) -> String {
        self.to_string()
    }
}

fn seed_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SEED_FILE_NAME)
}

fn marker_path(data_dir: &Path) -> PathBuf {
    data_dir.join(BACKEND_MARKER_NAME)
}

fn binding_path(data_dir: &Path) -> PathBuf {
    data_dir.join(IDENTITY_BINDING_NAME)
}

fn account_for_data_dir(data_dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let canon = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    let mut h = Sha256::new();
    h.update(b"raven/identity-store/v1/");
    h.update(canon.to_string_lossy().as_bytes());
    hex::encode(h.finalize())
}

fn account_digest_for_data_dir(data_dir: &Path) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let account = account_for_data_dir(data_dir);
    Sha256::digest(account.as_bytes()).into()
}

fn binding_checksum(prefix: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"raven/identity-binding/v1/");
    h.update(prefix);
    h.finalize().into()
}

fn encode_binding(
    data_dir: &Path,
    backend: IdentityStoreBackend,
    identity: &Identity,
) -> Result<Vec<u8>, IdentityStoreError> {
    let address = identity.address();
    if address.len() != IDENTITY_ADDRESS_LEN || !address.is_ascii() {
        return Err(IdentityStoreError::Corrupt);
    }
    let mut out = Vec::with_capacity(IDENTITY_BINDING_LEN);
    out.extend_from_slice(IDENTITY_BINDING_MAGIC);
    out.push(IDENTITY_BINDING_VERSION);
    out.push(backend.code());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&account_digest_for_data_dir(data_dir));
    out.extend_from_slice(&identity.public_key_bytes());
    out.extend_from_slice(address.as_bytes());
    let checksum = binding_checksum(&out);
    out.extend_from_slice(&checksum);
    debug_assert_eq!(out.len(), IDENTITY_BINDING_LEN);
    Ok(out)
}

fn verify_or_install_binding(
    data_dir: &Path,
    backend: IdentityStoreBackend,
    identity: &Identity,
) -> Result<(), IdentityStoreError> {
    let expected = encode_binding(data_dir, backend, identity)?;
    let path = binding_path(data_dir);
    let existing = match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(IdentityStoreError::Io(e.to_string())),
    };
    if let Some(bytes) = existing {
        if bytes.len() != IDENTITY_BINDING_LEN
            || bytes[..8] != IDENTITY_BINDING_MAGIC[..]
            || bytes[8] != IDENTITY_BINDING_VERSION
            || IdentityStoreBackend::from_code(bytes[9]) != Some(backend)
            || bytes[10..12] != [0, 0]
            || binding_checksum(&bytes[..IDENTITY_BINDING_PREFIX_LEN])
                != bytes[IDENTITY_BINDING_PREFIX_LEN..]
            || bytes != expected
        {
            return Err(IdentityStoreError::Continuity(
                "identity binding does not match protected seed",
            ));
        }
        return Ok(());
    }
    crate::paths::atomic_write_private(&path, &expected).map_err(IdentityStoreError::Io)
}

fn binding_exists_checked(data_dir: &Path) -> Result<bool, IdentityStoreError> {
    match std::fs::metadata(binding_path(data_dir)) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(IdentityStoreError::Continuity(
            "identity binding is not a regular file",
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(IdentityStoreError::Io(e.to_string())),
    }
}

/// Profile entries that may exist before the first identity is created, by
/// exact name: files that read-only commands (`status`, `bridge`, the ash menus,
/// `bootstrap`/policy setup) or the OS leave behind in a fresh profile and that
/// carry no identity-bound state.
const FIRST_INSTALL_INERT_FILES: [&str; 9] = [
    IDENTITY_STORE_LOCK_NAME,
    // Non-secret keystore choice (non-macOS Unix); the vault itself is not inert.
    crate::keystore_select::KEYSTORE_MARKER_NAME,
    ".identity_store.lock.sqlite-wal",
    ".identity_store.lock.sqlite-shm",
    ".identity_store.lock.sqlite-journal",
    "bootstrap.json",
    // `save_bootstrap` keeps an unreadable bootstrap.json here before replacing it.
    "bootstrap.json.corrupt",
    "node_policy.json",
    // Finder metadata.
    ".DS_Store",
];
/// Relay custody database opened (and so created) by `raven-node status` /
/// `bridge` on a profile with no identity. Inert only while it holds no rows.
const FIRST_INSTALL_EMPTY_DB: &str = "forward_queue.sqlite";

fn sqlite_base_name(name: &str) -> &str {
    ["-wal", "-shm", "-journal"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .unwrap_or(name)
}

/// `DataDirLock` files (`.<name>.lock.sqlite`): a lock is `BEGIN EXCLUSIVE`
/// on a database that never gets a schema, so a genuine one is a 0-byte file.
fn is_lock_database_name(base: &str) -> bool {
    base.starts_with('.') && base.ends_with(".lock.sqlite")
}

/// True when every user table of the SQLite database at `path` is empty.
/// Fail-closed: any open or query error counts as "not empty".
fn sqlite_database_has_no_rows(path: &Path) -> bool {
    use rusqlite::{Connection, OpenFlags};
    let Ok(conn) = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        return false;
    };
    let _ = conn.busy_timeout(Duration::from_secs(5));
    let tables: Result<Vec<String>, _> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .and_then(|mut stmt| {
            stmt.query_map([], |row| row.get::<_, String>(0))
                .and_then(|rows| rows.collect())
        });
    let Ok(tables) = tables else {
        return false;
    };
    tables.iter().all(|table| {
        let sql = format!(
            "SELECT EXISTS(SELECT 1 FROM \"{}\")",
            table.replace('"', "\"\"")
        );
        matches!(conn.query_row(&sql, [], |row| row.get::<_, i64>(0)), Ok(0))
    })
}

/// The IPC server's own artifacts, which `raven-node ipc` (and an auto-started
/// `service` whose preflight failed) leave in a profile that has no identity
/// yet: the endpoint socket, its instance lock and the service log. `None` for
/// every other name. Each is judged by what it really is (`symlink_metadata`,
/// so a symlink or a directory under the name is never accepted).
fn ipc_leftover_is_inert(data_dir: &Path, name: &str) -> Option<bool> {
    let socket = crate::ipc::SOCKET_FILE_NAME;
    let path = data_dir.join(name);
    let meta = || std::fs::symlink_metadata(&path).ok();
    if name == socket {
        // Windows serves a named pipe: there is no socket file to tolerate.
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            return Some(meta().is_some_and(|m| m.file_type().is_socket()));
        }
        #[cfg(not(unix))]
        return Some(false);
    }
    if name.strip_prefix(socket) == Some(".lock") {
        // `flock` target created with O_CREAT and never written to.
        return Some(meta().is_some_and(|m| m.file_type().is_file() && m.len() == 0));
    }
    if name == crate::paths::SERVICE_LOG_NAME {
        // Daemon stdout/stderr: diagnostics, no identity-bound state (a daemon
        // cannot get past its identity preflight on a profile without one).
        return Some(meta().is_some_and(|m| m.file_type().is_file()));
    }
    None
}

/// Whether one profile entry is derived or empty bookkeeping that cannot
/// indicate an established profile. Everything else (contacts, chat history,
/// the outbound queue, device keys, ...) must keep failing closed: allowing it
/// would let a deleted or locked secure store mint a second identity.
fn first_install_entry_is_inert(data_dir: &Path, name: &str) -> bool {
    if FIRST_INSTALL_INERT_FILES.contains(&name) {
        return true;
    }
    if let Some(inert) = ipc_leftover_is_inert(data_dir, name) {
        return inert;
    }
    let base = sqlite_base_name(name);
    let is_lock = is_lock_database_name(base);
    if !is_lock && base != FIRST_INSTALL_EMPTY_DB {
        return false;
    }
    let is_sidecar = base != name;
    let regular = |p: &Path| {
        std::fs::symlink_metadata(p)
            .map(|m| m.file_type().is_file())
            .unwrap_or(false)
    };
    let base_path = data_dir.join(base);
    if !regular(&data_dir.join(name)) || !regular(&base_path) {
        // Symlinks, directories, and sidecars whose database is missing.
        return false;
    }
    if is_sidecar {
        // The database entry is judged on its own turn through the directory.
        return true;
    }
    if is_lock {
        std::fs::metadata(&base_path).is_ok_and(|m| m.len() == 0)
    } else {
        sqlite_database_has_no_rows(&base_path)
    }
}

fn require_proven_first_install(
    data_dir: &Path,
    marker: Option<IdentityStoreBackend>,
) -> Result<(), IdentityStoreError> {
    if marker.is_some() || binding_exists_checked(data_dir)? {
        return Err(IdentityStoreError::Continuity(
            "recorded identity is missing from its protected backend",
        ));
    }
    // A missing root inside an established profile is identity loss, not first
    // install. Keep the allow-list deliberately small and future-proof:
    // unknown state must be reviewed/recovered, never silently rebound. Only
    // inert, derived or empty files pass (see `first_install_entry_is_inert`).
    let entries = std::fs::read_dir(data_dir).map_err(|e| IdentityStoreError::Io(e.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|e| IdentityStoreError::Io(e.to_string()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| IdentityStoreError::Continuity("profile entry name is not canonical"))?;
        if !first_install_entry_is_inert(data_dir, &name) {
            return Err(IdentityStoreError::Continuity(
                "profile contains state but has no identity continuity record; if this profile was never initialised, move the stray files out of the data dir, otherwise restore the missing identity",
            ));
        }
    }
    Ok(())
}

fn acquire_identity_store_lock(
    data_dir: &Path,
) -> Result<crate::paths::DataDirLock, IdentityStoreError> {
    const MAX_WAIT: Duration = Duration::from_secs(60);
    acquire_identity_store_lock_with(
        data_dir,
        crate::macos_keychain::FIRST_HINT_AFTER,
        MAX_WAIT,
        |waited| {
            use std::io::Write;
            // A closed stderr must not fail the load.
            let notice = crate::macos_keychain::lock_wait_notice(waited.as_secs());
            let _ = std::io::stderr().write_all(notice.as_bytes());
        },
    )
}

/// [`acquire_identity_store_lock`] with its timings and the notice injected.
/// Every attempt waits `notice_after` for the lock. The holder may itself be
/// blocked in a macOS Keychain dialog (it keeps this lock until the dialog is
/// answered), and a silent wait behind it looks like a freeze: the first attempt
/// that finds the lock held calls `on_wait` once with the time waited so far.
/// Attempts then continue until `max_wait` has passed.
fn acquire_identity_store_lock_with(
    data_dir: &Path,
    notice_after: Duration,
    max_wait: Duration,
    mut on_wait: impl FnMut(Duration),
) -> Result<crate::paths::DataDirLock, IdentityStoreError> {
    const RETRY_DELAY: Duration = Duration::from_millis(50);
    let started = Instant::now();
    let mut announced = false;
    loop {
        match crate::paths::DataDirLock::acquire_within(
            data_dir,
            IDENTITY_STORE_LOCK_NAME,
            notice_after,
        ) {
            Ok(lock) => return Ok(lock),
            Err(e) if e.contains("database is locked") || e.contains("database is busy") => {
                if !announced {
                    announced = true;
                    on_wait(started.elapsed());
                }
                if started.elapsed() >= max_wait {
                    return Err(IdentityStoreError::Io(e));
                }
                std::thread::sleep(RETRY_DELAY);
            }
            Err(e) => return Err(IdentityStoreError::Io(e)),
        }
    }
}

fn finish_loaded_identity(
    data_dir: &Path,
    mut seed: [u8; 32],
    backend: IdentityStoreBackend,
) -> Result<(Identity, IdentityStoreBackend), IdentityStoreError> {
    let id = Identity::from_seed(&seed);
    seed.zeroize();
    verify_or_install_binding(data_dir, backend, &id)?;
    match read_marker_checked(data_dir)? {
        Some(recorded) if recorded != backend => {
            return Err(IdentityStoreError::Continuity(
                "identity backend marker conflicts with protected seed",
            ));
        }
        Some(_) => {}
        None => write_marker(data_dir, backend)?,
    }
    Ok((id, backend))
}

fn write_marker(data_dir: &Path, backend: IdentityStoreBackend) -> Result<(), IdentityStoreError> {
    crate::paths::ensure_private_dir(data_dir).map_err(IdentityStoreError::Io)?;
    crate::paths::atomic_write_private(
        &marker_path(data_dir),
        format!("{}\n", backend.as_str()).as_bytes(),
    )
    .map_err(IdentityStoreError::Io)
}

fn read_marker_checked(
    data_dir: &Path,
) -> Result<Option<IdentityStoreBackend>, IdentityStoreError> {
    let path = marker_path(data_dir);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(IdentityStoreError::Io(e.to_string())),
    };
    let backend = IdentityStoreBackend::parse(raw.strip_suffix('\n').ok_or(
        IdentityStoreError::Continuity("identity backend marker is not canonical"),
    )?)
    .ok_or(IdentityStoreError::Continuity(
        "identity backend marker is unknown",
    ))?;
    if raw != format!("{}\n", backend.as_str()) {
        return Err(IdentityStoreError::Continuity(
            "identity backend marker is not canonical",
        ));
    }
    Ok(Some(backend))
}

#[cfg_attr(not(windows), allow(dead_code))]
fn is_dpapi_blob(bytes: &[u8]) -> bool {
    bytes.len() > DPAPI_MAGIC.len() + 1 && bytes.starts_with(DPAPI_MAGIC)
}

fn is_legacy_plaintext(bytes: &[u8]) -> bool {
    bytes.len() == 32 && !bytes.starts_with(DPAPI_MAGIC)
}

/// When `RAVEN_IDENTITY_BACKEND=locked-file`, demos/CI use a 0600 seed file
/// shared by ash and raven-node (avoids macOS Keychain ACL hangs across binaries).
fn locked_file_backend_requested() -> bool {
    std::env::var_os("RAVEN_IDENTITY_BACKEND")
        .map(|v| v == "locked-file")
        .unwrap_or(false)
}

fn locked_file_backend_enabled() -> Result<bool, IdentityStoreError> {
    if !locked_file_backend_requested() {
        return Ok(false);
    }
    if !cfg!(debug_assertions) {
        return Err(IdentityStoreError::SecureStore(
            "locked-file identity backend is forbidden in Release builds".into(),
        ));
    }
    Ok(true)
}

#[cfg_attr(
    not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))),
    allow(dead_code)
)]
fn wipe_seed_file(path: &Path) -> Result<(), IdentityStoreError> {
    let io = |e: std::io::Error| IdentityStoreError::Io(e.to_string());
    match std::fs::symlink_metadata(path) {
        // Scrubbing is best-effort (see the module docs on copy-on-write
        // storage), removal is not. A failed scrub, such as a read-only or
        // non-writable legacy file or ENOSPC on a copy-on-write volume, must
        // never keep the plaintext name around: that leaves the seed fully
        // readable and makes every later identity load fail in reconcile.
        Ok(metadata) if metadata.file_type().is_file() => {
            let _ = scrub_seed_file_in_place(path, &metadata);
        }
        // Never write through a symlink or into a special file; just drop the name.
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io(e)),
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io(e)),
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(io)?;
    }
    Ok(())
}

/// Overwrite the seed file's bytes in place and force them out. No truncate:
/// a truncating write lets the filesystem free the old blocks untouched. A
/// legacy file the user made read-only is made owner-writable first (it is
/// Raven's own file and is about to be deleted).
#[cfg_attr(
    not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))),
    allow(dead_code)
)]
fn scrub_seed_file_in_place(path: &Path, metadata: &std::fs::Metadata) -> std::io::Result<()> {
    use std::io::Write;
    let open = || std::fs::OpenOptions::new().write(true).open(path);
    let mut file = match open() {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            make_owner_writable(path, metadata)?;
            open()?
        }
        Err(e) => return Err(e),
    };
    let zeros = [0u8; 4096];
    let mut remaining = file.metadata()?.len();
    while remaining > 0 {
        let chunk = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }
    file.sync_all()
}

#[cfg(unix)]
#[cfg_attr(
    not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))),
    allow(dead_code)
)]
fn make_owner_writable(path: &Path, _metadata: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn make_owner_writable(path: &Path, metadata: &std::fs::Metadata) -> std::io::Result<()> {
    let mut permissions = metadata.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    std::fs::set_permissions(path, permissions)
}

/// Finish a just-created (`create_new`) seed file. When writing or syncing it
/// failed (ENOSPC, a kill between create and fsync is the same hazard) remove
/// the partial file: `create_new` forbids re-creating it, and a short
/// `identity.seed` is `Corrupt` on every later load, which would wedge the
/// profile until the user deleted it by hand.
fn finish_new_seed_file(
    path: &Path,
    written: std::io::Result<()>,
) -> Result<(), IdentityStoreError> {
    written.map_err(|e| {
        let _ = std::fs::remove_file(path);
        IdentityStoreError::Io(e.to_string())
    })
}

#[cfg(unix)]
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn write_locked_seed_file(path: &Path, seed: &[u8; 32]) -> Result<(), IdentityStoreError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        crate::paths::ensure_private_dir(parent).map_err(IdentityStoreError::Io)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| IdentityStoreError::Io(e.to_string()))?;
    finish_new_seed_file(path, f.write_all(seed).and_then(|_| f.sync_all()))
}

#[cfg(not(unix))]
fn write_locked_seed_file(path: &Path, seed: &[u8; 32]) -> Result<(), IdentityStoreError> {
    if let Some(parent) = path.parent() {
        crate::paths::ensure_private_dir(parent).map_err(IdentityStoreError::Io)?;
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| IdentityStoreError::Io(e.to_string()))?;
    finish_new_seed_file(path, file.write_all(seed).and_then(|_| file.sync_all()))
}

fn read_raw_seed_file(path: &Path) -> Result<Option<Vec<u8>>, IdentityStoreError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(IdentityStoreError::Io(e.to_string())),
    }
}

#[cfg_attr(
    not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))),
    allow(dead_code)
)]
fn reconcile_secure_and_raw_seed(
    path: &Path,
    secure_seed: &[u8; 32],
) -> Result<(), IdentityStoreError> {
    let Some(mut bytes) = read_raw_seed_file(path)? else {
        return Ok(());
    };
    if !is_legacy_plaintext(&bytes) {
        bytes.zeroize();
        return Err(IdentityStoreError::Corrupt);
    }
    let mut raw_seed = bytes_to_seed(&bytes)?;
    bytes.zeroize();
    if raw_seed != *secure_seed {
        raw_seed.zeroize();
        return Err(IdentityStoreError::Continuity(
            "protected and file identity seeds conflict",
        ));
    }
    raw_seed.zeroize();
    wipe_seed_file(path)
}

// --- macOS Keychain ---------------------------------------------------------

#[cfg(target_os = "macos")]
fn keychain_set(account: &str, seed: &[u8; 32]) -> Result<(), IdentityStoreError> {
    use crate::macos_keychain::{guarded, KeychainWhat};
    use security_framework::os::macos::keychain::SecKeychain;
    guarded(KeychainWhat::IdentitySeed, || {
        let keychain = SecKeychain::default()
            .map_err(|e| IdentityStoreError::SecureStore(format!("keychain default: {e}")))?;
        // Add-only is essential: a create race or unexpected pre-existing item
        // must fail and be reconciled by strict readback, never overwrite a root.
        keychain
            .add_generic_password(KEYCHAIN_SERVICE, account, seed)
            .map_err(|e| IdentityStoreError::SecureStore(format!("keychain add: {e}")))
    })
}

#[cfg(target_os = "macos")]
fn keychain_get(account: &str) -> Result<Option<[u8; 32]>, IdentityStoreError> {
    use crate::macos_keychain::{guarded, KeychainWhat};
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
    use security_framework::passwords::get_generic_password;
    use security_framework_sys::base::errSecItemNotFound;
    use zeroize::Zeroizing;

    // Search and read are both Keychain round trips; either can sit behind a
    // macOS access dialog, so one guard covers the pair.
    guarded(KeychainWhat::IdentitySeed, || {
        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::generic_password())
            .service(KEYCHAIN_SERVICE)
            .account(account)
            .load_attributes(true)
            .limit(Limit::All);
        match query.search() {
            Ok(results) => {
                if results.len() != 1 {
                    return Err(IdentityStoreError::Continuity(
                        "duplicate Keychain identity items",
                    ));
                }
                let bytes = Zeroizing::new(
                    get_generic_password(KEYCHAIN_SERVICE, account).map_err(|e| {
                        IdentityStoreError::SecureStore(format!(
                            "keychain read status {}",
                            e.code()
                        ))
                    })?,
                );
                if bytes.len() != 32 {
                    return Err(IdentityStoreError::Corrupt);
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                Ok(Some(seed))
            }
            // `get_generic_password` documents this exact OSStatus as the only
            // proof that no matching item exists. Locked/denied/unavailable must
            // never be reinterpreted as first install.
            Err(e) if e.code() == errSecItemNotFound => Ok(None),
            Err(e) => Err(IdentityStoreError::SecureStore(format!(
                "keychain get status {}",
                e.code()
            ))),
        }
    })
}

#[cfg(all(target_os = "macos", test))]
fn keychain_status_is_proven_absent(status: i32) -> bool {
    use security_framework_sys::base::errSecItemNotFound;
    status == errSecItemNotFound
}

#[cfg(all(target_os = "macos", any(test, feature = "test-helpers")))]
fn keychain_delete(account: &str) {
    use crate::macos_keychain::{guarded, KeychainWhat};
    use security_framework::passwords::delete_generic_password;
    let _ = guarded(KeychainWhat::IdentitySeed, || {
        delete_generic_password(KEYCHAIN_SERVICE, account)
    });
}

// --- Windows DPAPI ----------------------------------------------------------

#[cfg(windows)]
fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, IdentityStoreError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let data_in = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &data_in,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        )
    };
    if ok == 0 || data_out.pbData.is_null() || data_out.cbData == 0 {
        return Err(IdentityStoreError::SecureStore(
            "CryptProtectData failed".into(),
        ));
    }
    let slice = unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize) };
    let out = slice.to_vec();
    unsafe {
        LocalFree(data_out.pbData as _);
    }
    Ok(out)
}

#[cfg(windows)]
fn dpapi_unprotect(blob: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, IdentityStoreError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let data_in = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &data_in,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        )
    };
    if ok == 0 || data_out.pbData.is_null() || data_out.cbData == 0 {
        return Err(IdentityStoreError::SecureStore(
            "CryptUnprotectData failed".into(),
        ));
    }
    let slice = unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize) };
    let out = zeroize::Zeroizing::new(slice.to_vec());
    unsafe {
        // The plaintext seed must not survive in freed heap (SecureZeroMemory
        // equivalent: zeroize uses volatile writes).
        std::slice::from_raw_parts_mut(data_out.pbData, data_out.cbData as usize).zeroize();
        LocalFree(data_out.pbData as _);
    }
    Ok(out)
}

#[cfg(windows)]
fn dpapi_seed_blob(seed: &[u8; 32]) -> Result<Vec<u8>, IdentityStoreError> {
    use zeroize::Zeroizing;
    let protected = Zeroizing::new(dpapi_protect(seed)?);
    let mut out = Vec::with_capacity(DPAPI_MAGIC.len() + 1 + protected.len());
    out.extend_from_slice(DPAPI_MAGIC);
    out.push(DPAPI_VERSION);
    out.extend_from_slice(&protected);
    Ok(out)
}

/// First-install creation. Create-only (`CREATE_NEW` semantics): a fresh
/// identity must never be able to overwrite pre-existing profile state.
#[cfg(windows)]
fn create_dpapi_seed_file(path: &Path, seed: &[u8; 32]) -> Result<(), IdentityStoreError> {
    crate::paths::create_new_private(path, &dpapi_seed_blob(seed)?).map_err(IdentityStoreError::Io)
}

/// Verified atomic replacement protocol for legacy-plaintext migration:
/// temp → sync → decrypt/compare → atomic replace → reopen/decrypt/compare.
#[cfg(windows)]
fn replace_dpapi_seed_file_verified(
    path: &Path,
    seed: &[u8; 32],
) -> Result<(), IdentityStoreError> {
    use zeroize::Zeroizing;
    let blob = Zeroizing::new(dpapi_seed_blob(seed)?);
    let parent = path
        .parent()
        .ok_or_else(|| IdentityStoreError::Io("dpapi migrate: missing parent".into()))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    let tmp = parent.join(format!(
        ".{}.migrate.{nanos:016x}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("raven"),
    ));
    let result = (|| -> Result<(), IdentityStoreError> {
        use std::io::Write;
        // 1. Write the candidate blob to an exclusive temp file and force it out.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| IdentityStoreError::Io(e.to_string()))?;
        f.write_all(&blob)
            .and_then(|_| f.sync_all())
            .map_err(|e| IdentityStoreError::Io(e.to_string()))?;
        drop(f);
        // 2. Decrypt the temp file back and compare before it becomes canonical.
        let mut round_trip = load_dpapi_seed_file(&tmp)?.ok_or(IdentityStoreError::Continuity(
            "DPAPI migration temp file did not decrypt",
        ))?;
        let matched = round_trip == *seed;
        round_trip.zeroize();
        if !matched {
            return Err(IdentityStoreError::Continuity(
                "DPAPI migration temp decrypt mismatch",
            ));
        }
        // 3. Atomic same-volume replacement (MoveFileEx REPLACE_EXISTING).
        std::fs::rename(&tmp, path).map_err(|e| IdentityStoreError::Io(e.to_string()))?;
        // 4. Reopen the final path and prove the durable bytes decrypt to the seed.
        let mut stored = load_dpapi_seed_file(path)?.ok_or(IdentityStoreError::Continuity(
            "DPAPI migration readback missing",
        ))?;
        let verified = stored == *seed;
        stored.zeroize();
        if !verified {
            return Err(IdentityStoreError::Continuity(
                "DPAPI migration changed identity",
            ));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(windows)]
fn load_dpapi_seed_file(path: &Path) -> Result<Option<[u8; 32]>, IdentityStoreError> {
    let Some(bytes) = read_raw_seed_file(path)? else {
        return Ok(None);
    };
    if !is_dpapi_blob(&bytes) {
        return Ok(None);
    }
    if bytes[DPAPI_MAGIC.len()] != DPAPI_VERSION {
        return Err(IdentityStoreError::Corrupt);
    }
    let plain = dpapi_unprotect(&bytes[DPAPI_MAGIC.len() + 1..])?;
    if plain.len() != 32 {
        return Err(IdentityStoreError::Corrupt);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plain);
    Ok(Some(seed))
}

// --- Linux Secret Service (glibc / desktop session) -------------------------

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const SECRET_SERVICE_IDENTITY_LABEL: &str = "RAVEN node identity seed";

/// R1 (owner decision 2026-10-08): add-only, prompt-free identity creation
/// through the frozen Raven fork. `create_item_no_prompt` requires the DH
/// session, hard-wires the D-Bus `replace` flag to false, refuses a provider
/// prompt (`PromptRequired`) and a locked collection (`Locked`); Raven never
/// calls `Unlock`. Exclusion comes from the identity-store lock plus the
/// proven-absent search before this call, and the strict readback after it
/// (exactly one item) catches a duplicate created behind our back.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn secret_service_set(account: &str, seed: &[u8; 32]) -> Result<(), IdentityStoreError> {
    use secret_service::{EncryptionType, SecretService};
    use std::collections::HashMap;
    let ss = SecretService::new(EncryptionType::Dh)
        .map_err(|e| IdentityStoreError::SecureStore(format!("secret-service connect: {e}")))?;
    let collection = ss
        .get_default_collection()
        .map_err(|e| IdentityStoreError::SecureStore(format!("secret-service collection: {e}")))?;
    collection
        .create_item_no_prompt(
            SECRET_SERVICE_IDENTITY_LABEL,
            HashMap::from([("service", KEYCHAIN_SERVICE), ("account", account)]),
            seed,
            "application/octet-stream",
        )
        .map(|_| ())
        .map_err(|e| IdentityStoreError::SecureStore(format!("secret-service create: {e}")))
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn secret_service_get(account: &str) -> Result<Option<[u8; 32]>, IdentityStoreError> {
    use secret_service::{EncryptionType, SecretService};
    use zeroize::Zeroizing;
    let ss = SecretService::new(EncryptionType::Dh)
        .map_err(|e| IdentityStoreError::SecureStore(format!("secret-service connect: {e}")))?;
    let mut items = ss
        .search_items(vec![("service", KEYCHAIN_SERVICE), ("account", account)])
        .map_err(|e| IdentityStoreError::SecureStore(format!("secret-service search: {e}")))?;
    if items.is_empty() {
        return Ok(None);
    }
    if items.len() != 1 {
        return Err(IdentityStoreError::Continuity(
            "duplicate Secret Service identity items",
        ));
    }
    let item = items.pop().expect("one Secret Service item");
    match item.is_locked() {
        Ok(false) => {}
        Ok(true) => {
            return Err(IdentityStoreError::SecureStore(
                "secret-service identity item locked".into(),
            ));
        }
        Err(e) => {
            return Err(IdentityStoreError::SecureStore(format!(
                "secret-service item state: {e}"
            )));
        }
    }
    let attributes = item
        .get_attributes()
        .map_err(|e| IdentityStoreError::SecureStore(format!("secret-service attrs: {e}")))?;
    let allowed_attribute_shape = attributes.len() == 2
        || (attributes.len() == 3
            && attributes.get("xdg:schema").map(String::as_str)
                == Some("org.freedesktop.Secret.Generic"));
    if !allowed_attribute_shape
        || attributes.get("service").map(String::as_str) != Some(KEYCHAIN_SERVICE)
        || attributes.get("account").map(String::as_str) != Some(account)
        || item
            .get_label()
            .map_err(|e| IdentityStoreError::SecureStore(format!("secret-service label: {e}")))?
            != SECRET_SERVICE_IDENTITY_LABEL
        // R1 content-type policy: Raven creates `application/octet-stream`;
        // GNOME Keyring reports it back as `text/plain` (R0 observation).
        || !matches!(
            item.get_secret_content_type()
                .map_err(|e| {
                    IdentityStoreError::SecureStore(format!("secret-service content type: {e}"))
                })?
                .as_str(),
            "text/plain" | "application/octet-stream"
        )
    {
        return Err(IdentityStoreError::Corrupt);
    }
    let secret = Zeroizing::new(
        item.get_secret()
            .map_err(|e| IdentityStoreError::SecureStore(format!("secret-service get: {e}")))?,
    );
    if secret.len() != 32 {
        return Err(IdentityStoreError::Corrupt);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&secret);
    Ok(Some(seed))
}

#[cfg(all(
    target_os = "linux",
    target_env = "gnu",
    any(test, feature = "test-helpers")
))]
fn secret_service_delete(account: &str) {
    use secret_service::{EncryptionType, SecretService};
    use std::collections::HashMap;
    let Ok(ss) = SecretService::new(EncryptionType::Dh) else {
        return;
    };
    let Ok(collection) = ss.get_default_collection() else {
        return;
    };
    if let Ok(items) = collection.search_items(HashMap::from([
        ("service", KEYCHAIN_SERVICE),
        ("account", account),
    ])) {
        for item in items {
            let _ = item.delete();
        }
    }
}

/// Persist seed using the best available platform backend.
#[allow(clippy::needless_return)]
fn store_seed(
    data_dir: &Path,
    seed: &[u8; 32],
) -> Result<IdentityStoreBackend, IdentityStoreError> {
    crate::paths::ensure_private_dir(data_dir).map_err(IdentityStoreError::Io)?;
    let path = seed_path(data_dir);
    #[cfg(not(windows))]
    let account = account_for_data_dir(data_dir);

    // Demo/CI override: keep seed in mode-0600 file so ash ↔ raven-node share
    // the same data_dir without macOS Keychain per-binary ACL prompts.
    // Set RAVEN_IDENTITY_BACKEND=locked-file (ephemeral mktemp dirs only).
    if locked_file_backend_enabled()? {
        write_locked_seed_file(&path, seed)?;
        write_marker(data_dir, IdentityStoreBackend::LockedFile)?;
        return Ok(IdentityStoreBackend::LockedFile);
    }

    #[cfg(target_os = "macos")]
    {
        keychain_set(&account, seed)?;
        wipe_seed_file(&path)?;
        write_marker(data_dir, IdentityStoreBackend::MacosKeychain)?;
        return Ok(IdentityStoreBackend::MacosKeychain);
    }

    #[cfg(windows)]
    {
        create_dpapi_seed_file(&path, seed)?;
        write_marker(data_dir, IdentityStoreBackend::WindowsDpapiFile)?;
        return Ok(IdentityStoreBackend::WindowsDpapiFile);
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        let keystore = crate::keystore_select::resolve(data_dir, true)
            .map_err(IdentityStoreError::SecureStore)?;
        if keystore == crate::keystore_select::KeystoreBackend::PassphraseVault {
            let vault = crate::keystore_vault::Vault::for_data_dir(data_dir);
            return store_vault_seed(data_dir, &vault, &path, seed);
        }
        secret_service_set(&account, seed)?;
        let mut stored = secret_service_get(&account)?.ok_or(IdentityStoreError::Continuity(
            "Secret Service create had no readable result",
        ))?;
        if stored != *seed {
            stored.zeroize();
            return Err(IdentityStoreError::Continuity(
                "Secret Service readback changed identity",
            ));
        }
        stored.zeroize();
        wipe_seed_file(&path)?;
        write_marker(data_dir, IdentityStoreBackend::LinuxSecretService)?;
        return Ok(IdentityStoreBackend::LinuxSecretService);
    }

    #[cfg(all(
        unix,
        not(target_os = "macos"),
        not(all(target_os = "linux", target_env = "gnu"))
    ))]
    {
        // musl / other Unix: no Secret Service client, the passphrase vault only.
        let _ = account;
        crate::keystore_select::resolve(data_dir, true).map_err(IdentityStoreError::SecureStore)?;
        let vault = crate::keystore_vault::Vault::for_data_dir(data_dir);
        return store_vault_seed(data_dir, &vault, &path, seed);
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, account, seed);
        Err(IdentityStoreError::SecureStore(
            "unsupported platform for identity store".into(),
        ))
    }
}

fn bytes_to_seed(bytes: &[u8]) -> Result<[u8; 32], IdentityStoreError> {
    if bytes.len() != 32 {
        return Err(IdentityStoreError::Corrupt);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(bytes);
    Ok(seed)
}

// --- Passphrase vault (non-macOS Unix without Secret Service) ---------------
//
// Compiled into every test build so the vault-backed identity logic is
// exercised on macOS / Windows CI hosts as well.

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
fn vault_error(error: crate::keystore_vault::VaultError) -> IdentityStoreError {
    IdentityStoreError::SecureStore(format!("passphrase vault: {error}"))
}

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
fn vault_get_seed(
    vault: &crate::keystore_vault::Vault,
) -> Result<Option<[u8; 32]>, IdentityStoreError> {
    vault
        .get(crate::keystore_vault::IDENTITY_SEED_ENTRY)
        .map_err(vault_error)?
        .map(|bytes| bytes_to_seed(&bytes))
        .transpose()
}

/// First-install (or migration) write: add-only, verified by readback.
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
fn store_vault_seed(
    data_dir: &Path,
    vault: &crate::keystore_vault::Vault,
    path: &Path,
    seed: &[u8; 32],
) -> Result<IdentityStoreBackend, IdentityStoreError> {
    vault
        .insert_new(crate::keystore_vault::IDENTITY_SEED_ENTRY, seed)
        .map_err(vault_error)?;
    let mut stored = vault_get_seed(vault)?.ok_or(IdentityStoreError::Continuity(
        "passphrase vault create had no readable result",
    ))?;
    if stored != *seed {
        stored.zeroize();
        return Err(IdentityStoreError::Continuity(
            "passphrase vault readback changed identity",
        ));
    }
    stored.zeroize();
    wipe_seed_file(path)?;
    write_marker(data_dir, IdentityStoreBackend::PassphraseVault)?;
    Ok(IdentityStoreBackend::PassphraseVault)
}

/// Same continuity rules as the Keychain / Secret Service loaders: a recorded
/// vault identity that is missing never becomes a first install, and a wrong
/// passphrase or damaged vault is an error, not absence.
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
fn load_vault_seed_with_migrate(
    data_dir: &Path,
    vault: &crate::keystore_vault::Vault,
    path: &Path,
    marker: Option<IdentityStoreBackend>,
) -> Result<Option<([u8; 32], IdentityStoreBackend)>, IdentityStoreError> {
    if marker.is_some() && marker != Some(IdentityStoreBackend::PassphraseVault) {
        return Err(IdentityStoreError::Continuity(
            "identity backend marker conflicts with the profile's passphrase vault",
        ));
    }
    if let Some(seed) = vault_get_seed(vault)? {
        reconcile_secure_and_raw_seed(path, &seed)?;
        return Ok(Some((seed, IdentityStoreBackend::PassphraseVault)));
    }
    if marker == Some(IdentityStoreBackend::PassphraseVault) {
        return Err(IdentityStoreError::Continuity(
            "recorded passphrase-vault identity is missing",
        ));
    }
    if let Some(mut bytes) = read_raw_seed_file(path)? {
        if !is_legacy_plaintext(&bytes) {
            bytes.zeroize();
            return Err(IdentityStoreError::Corrupt);
        }
        let seed = bytes_to_seed(&bytes)?;
        bytes.zeroize();
        // Verified migration: add-only insert, readback, then wipe + marker.
        let backend = store_vault_seed(data_dir, vault, path, &seed)?;
        return Ok(Some((seed, backend)));
    }
    require_proven_first_install(data_dir, marker)?;
    Ok(None)
}

/// Locked-file lab/CI (debug only) may proceed only when Keychain is
/// **proven absent** (`Ok(None)` / `errSecItemNotFound`).
///
/// Used for first-install *and* unmarked planted/legacy seed load. It is
/// **not Release-safe** to treat `SecureStore` as absence: a locked
/// Keychain *with* an existing item often surfaces as `SecureStore`
/// (search hits, then `get_generic_password` fails), which would fork a
/// locked-file identity beside the Keychain root.
#[cfg(target_os = "macos")]
fn locked_file_after_keychain_probe(
    result: Result<Option<[u8; 32]>, IdentityStoreError>,
) -> Result<(), IdentityStoreError> {
    match result {
        Ok(Some(_)) => Err(IdentityStoreError::Continuity(
            "locked-file override conflicts with existing Keychain identity",
        )),
        Ok(None) => Ok(()),
        Err(IdentityStoreError::SecureStore(_)) => Err(IdentityStoreError::Continuity(
            "locked-file path requires proven-absent Keychain; unavailable or locked is not absence",
        )),
        Err(e) => Err(e),
    }
}

#[cfg(target_os = "macos")]
fn refuse_locked_file_if_keychain_not_proven_absent(
    account: &str,
) -> Result<(), IdentityStoreError> {
    locked_file_after_keychain_probe(keychain_get(account))
}

/// Headless Linux CI has no session bus and no `org.freedesktop.secrets`.
/// `secret-service connect:` (including zbus `ServiceUnknown`) is the
/// documented lab-only exception ("no provider"), not "item exists but
/// locked". This soft path is debug only. Locked/search/get stay Continuity.
///
/// Creating or loading a locked-file identity still requires explicit
/// `RAVEN_IDENTITY_BACKEND=locked-file`. It is **not Release-safe** to treat
/// other `SecureStore` errors as absence.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn linux_secret_service_is_session_bus_missing(err: &IdentityStoreError) -> bool {
    matches!(
        err,
        IdentityStoreError::SecureStore(msg)
            if msg.starts_with("secret-service connect:")
                || msg.contains("ServiceUnknown")
    )
}

/// Test/lab helper: request the debug locked-file identity backend.
///
/// **GNU/Linux only.** Headless Ubuntu has no Secret Service. Once set, the
/// env stays set so parallel tests cannot race (do not clear a CI job
/// override). macOS Keychain and Windows DPAPI tests stay on the platform
/// store — forcing locked-file there regresses migrate / tamper / conflict.
#[cfg(test)]
pub(crate) fn test_enable_locked_file_identity_backend() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        use std::sync::Once;
        static ENABLE: Once = Once::new();
        ENABLE.call_once(|| {
            if locked_file_backend_requested() {
                return;
            }
            // SAFETY: test-only process env for the documented lab/CI backend.
            unsafe { std::env::set_var("RAVEN_IDENTITY_BACKEND", "locked-file") }
        });
    }
}

/// Same unmarked locked-file probe as macOS, plus one lab-only exception:
/// session-bus connect-fail. Never Release; never without locked-file env.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn locked_file_after_secret_service_probe(
    result: Result<Option<[u8; 32]>, IdentityStoreError>,
) -> Result<(), IdentityStoreError> {
    match result {
        Ok(Some(_)) => Err(IdentityStoreError::Continuity(
            "locked-file override conflicts with existing Secret Service identity",
        )),
        Ok(None) => Ok(()),
        Err(e) if linux_secret_service_is_session_bus_missing(&e) => Ok(()),
        Err(IdentityStoreError::SecureStore(_)) => Err(IdentityStoreError::Continuity(
            "locked-file path requires proven-absent Secret Service or a missing session bus; a locked item is not absence",
        )),
        Err(e) => Err(e),
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn refuse_locked_file_if_secret_service_not_proven_absent(
    account: &str,
) -> Result<(), IdentityStoreError> {
    locked_file_after_secret_service_probe(secret_service_get(account))
}

/// Load from platform store or locked file; migrate legacy plaintext when needed.
#[allow(clippy::needless_return)]
fn load_seed_with_migrate(
    data_dir: &Path,
) -> Result<Option<([u8; 32], IdentityStoreBackend)>, IdentityStoreError> {
    let path = seed_path(data_dir);
    let marker = read_marker_checked(data_dir)?;
    #[cfg(not(windows))]
    let account = account_for_data_dir(data_dir);

    // The raw seed backend is an explicit lab/CI mode. It may not override an
    // already-recorded protected backend, because that would fork one profile
    // into two permanent Raven identities.
    if locked_file_backend_enabled()? {
        if marker.is_some() && marker != Some(IdentityStoreBackend::LockedFile) {
            return Err(IdentityStoreError::Continuity(
                "locked-file override conflicts with recorded protected backend",
            ));
        }
        return match read_raw_seed_file(&path)? {
            Some(mut bytes) if is_legacy_plaintext(&bytes) => {
                // Planted CI / leftover plaintext seed. Same proven-absent
                // rule as first-install: macOS only Ok(None); Linux only
                // Ok(None) or session-bus connect-fail. SecureStore is not
                // absence (locked item with a file seed would fork).
                if marker.is_none() {
                    #[cfg(target_os = "macos")]
                    refuse_locked_file_if_keychain_not_proven_absent(&account)?;
                    #[cfg(all(target_os = "linux", target_env = "gnu"))]
                    refuse_locked_file_if_secret_service_not_proven_absent(&account)?;
                }
                let seed = bytes_to_seed(&bytes)?;
                bytes.zeroize();
                Ok(Some((seed, IdentityStoreBackend::LockedFile)))
            }
            Some(mut bytes) => {
                bytes.zeroize();
                Err(IdentityStoreError::Corrupt)
            }
            None => {
                // Locked-file first-install (debug CI/lab only). Unavailable ≠
                // proven absent. macOS: only Ok(None)/errSecItemNotFound.
                // A locked or denied Keychain (SecureStore) must not mint a
                // second root beside an existing item. Linux: only a session-bus
                // *connect* failure is treated as no store (headless ubuntu).
                // require_proven_first_install still refuses non-empty profiles.
                if marker.is_none() {
                    #[cfg(target_os = "macos")]
                    refuse_locked_file_if_keychain_not_proven_absent(&account)?;
                    #[cfg(all(target_os = "linux", target_env = "gnu"))]
                    refuse_locked_file_if_secret_service_not_proven_absent(&account)?;
                }
                require_proven_first_install(data_dir, marker)?;
                Ok(None)
            }
        };
    }
    if marker == Some(IdentityStoreBackend::LockedFile) {
        return Err(IdentityStoreError::SecureStore(
            "locked-file identity requires explicit RAVEN_IDENTITY_BACKEND=locked-file".into(),
        ));
    }

    #[cfg(target_os = "macos")]
    {
        if marker.is_some() && marker != Some(IdentityStoreBackend::MacosKeychain) {
            return Err(IdentityStoreError::Continuity(
                "identity backend marker is not valid on macOS",
            ));
        }
        if let Some(seed) = keychain_get(&account)? {
            reconcile_secure_and_raw_seed(&path, &seed)?;
            return Ok(Some((seed, IdentityStoreBackend::MacosKeychain)));
        }
        if marker == Some(IdentityStoreBackend::MacosKeychain) {
            return Err(IdentityStoreError::Continuity(
                "recorded Keychain identity is missing",
            ));
        }
        // Legacy plaintext file → Keychain (unless demo override already handled).
        if let Some(mut bytes) = read_raw_seed_file(&path)? {
            if is_legacy_plaintext(&bytes) {
                let mut seed = bytes_to_seed(&bytes)?;
                bytes.zeroize();
                let backend = store_seed(data_dir, &seed)?;
                let mut stored = keychain_get(&account)?.ok_or(IdentityStoreError::Continuity(
                    "Keychain migration readback missing",
                ))?;
                if stored != seed {
                    stored.zeroize();
                    seed.zeroize();
                    return Err(IdentityStoreError::Continuity(
                        "Keychain migration changed identity",
                    ));
                }
                stored.zeroize();
                return Ok(Some((seed, backend)));
            }
            bytes.zeroize();
            return Err(IdentityStoreError::Corrupt);
        }
        require_proven_first_install(data_dir, marker)?;
        return Ok(None);
    }

    #[cfg(windows)]
    {
        if marker.is_some() && marker != Some(IdentityStoreBackend::WindowsDpapiFile) {
            return Err(IdentityStoreError::Continuity(
                "identity backend marker is not valid on Windows",
            ));
        }
        if let Some(seed) = load_dpapi_seed_file(&path)? {
            return Ok(Some((seed, IdentityStoreBackend::WindowsDpapiFile)));
        }
        if marker == Some(IdentityStoreBackend::WindowsDpapiFile) {
            return Err(IdentityStoreError::Continuity(
                "recorded DPAPI identity is missing or unprotected",
            ));
        }
        if let Some(mut bytes) = read_raw_seed_file(&path)? {
            if is_legacy_plaintext(&bytes) {
                let seed = bytes_to_seed(&bytes)?;
                bytes.zeroize();
                // Verified protocol: temp → sync → decrypt/compare → atomic
                // replace → reopen/decrypt/compare (inside the call).
                replace_dpapi_seed_file_verified(&path, &seed)?;
                return Ok(Some((seed, IdentityStoreBackend::WindowsDpapiFile)));
            }
            bytes.zeroize();
            return Err(IdentityStoreError::Corrupt);
        }
        require_proven_first_install(data_dir, marker)?;
        return Ok(None);
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        let keystore = crate::keystore_select::resolve(data_dir, false)
            .map_err(IdentityStoreError::SecureStore)?;
        if keystore == crate::keystore_select::KeystoreBackend::PassphraseVault {
            let vault = crate::keystore_vault::Vault::for_data_dir(data_dir);
            return load_vault_seed_with_migrate(data_dir, &vault, &path, marker);
        }
        if marker.is_some() && marker != Some(IdentityStoreBackend::LinuxSecretService) {
            return Err(IdentityStoreError::Continuity(
                "identity backend marker is not valid on GNU/Linux",
            ));
        }
        // Debug/lab only: no session bus / ServiceUnknown is "no store", not
        // Continuity. Release still fail-closes on connect. Locked/search/get
        // stay hard errors. Locked-file create/load still needs the explicit env.
        let existing = match secret_service_get(&account) {
            Ok(seed) => seed,
            Err(e) if cfg!(debug_assertions) && linux_secret_service_is_session_bus_missing(&e) => {
                None
            }
            Err(e) => return Err(e),
        };
        if let Some(seed) = existing {
            reconcile_secure_and_raw_seed(&path, &seed)?;
            return Ok(Some((seed, IdentityStoreBackend::LinuxSecretService)));
        }
        if marker == Some(IdentityStoreBackend::LinuxSecretService) {
            return Err(IdentityStoreError::Continuity(
                "recorded Secret Service identity is missing",
            ));
        }
        if let Some(mut bytes) = read_raw_seed_file(&path)? {
            if !is_legacy_plaintext(&bytes) {
                bytes.zeroize();
                return Err(IdentityStoreError::Corrupt);
            }
            let mut seed = bytes_to_seed(&bytes)?;
            bytes.zeroize();
            secret_service_set(&account, &seed)?;
            let mut stored = secret_service_get(&account)?.ok_or(
                IdentityStoreError::Continuity("Secret Service migration readback missing"),
            )?;
            if stored != seed {
                stored.zeroize();
                seed.zeroize();
                return Err(IdentityStoreError::Continuity(
                    "Secret Service migration changed identity",
                ));
            }
            stored.zeroize();
            wipe_seed_file(&path)?;
            write_marker(data_dir, IdentityStoreBackend::LinuxSecretService)?;
            return Ok(Some((seed, IdentityStoreBackend::LinuxSecretService)));
        }
        require_proven_first_install(data_dir, marker)?;
        return Ok(None);
    }

    #[cfg(all(
        unix,
        not(target_os = "macos"),
        not(all(target_os = "linux", target_env = "gnu"))
    ))]
    {
        // musl / other Unix: the passphrase vault only.
        let _ = account;
        crate::keystore_select::resolve(data_dir, false)
            .map_err(IdentityStoreError::SecureStore)?;
        let vault = crate::keystore_vault::Vault::for_data_dir(data_dir);
        return load_vault_seed_with_migrate(data_dir, &vault, &path, marker);
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, account);
        Ok(None)
    }
}

/// Load identity if present (migrating legacy plaintext seed files).
///
/// **Blocking.** Every call takes the cross-process identity-store lock (a
/// SQLite `BEGIN EXCLUSIVE` with a 3 s busy wait inside a retry loop of up to
/// 60 s; a holder blocked in a macOS Keychain dialog keeps it, so a wait of 3 s
/// prints a one-time notice on stderr) and does a Keychain / Secret Service
/// round trip; nothing is cached.
/// Async code must not call this on a runtime worker thread (a tokio worker
/// stuck here cannot be pre-empted by `tokio::time::timeout`): run it on a
/// blocking thread such as `tokio::task::spawn_blocking`, and prefer loading
/// the identity once at listener start-up over once per inbound connection.
pub fn load_identity(data_dir: &Path) -> Result<Option<Identity>, IdentityStoreError> {
    let _lock = acquire_identity_store_lock(data_dir)?;
    load_identity_under_lock(data_dir)
}

fn load_identity_under_lock(data_dir: &Path) -> Result<Option<Identity>, IdentityStoreError> {
    load_seed_with_migrate(data_dir)?
        .map(|(seed, backend)| finish_loaded_identity(data_dir, seed, backend).map(|v| v.0))
        .transpose()
}

/// Load existing identity or generate + securely persist a new one.
/// Blocking, like [`load_identity`].
pub fn load_or_create_identity(
    data_dir: &Path,
) -> Result<(Identity, IdentityStoreBackend), IdentityStoreError> {
    let _lock = acquire_identity_store_lock(data_dir)?;
    if let Some((seed, backend)) = load_seed_with_migrate(data_dir)? {
        return finish_loaded_identity(data_dir, seed, backend);
    }
    let id = Identity::generate();
    let mut seed = id.seed_bytes();
    let backend = match store_seed(data_dir, &seed) {
        Ok(backend) => backend,
        Err(e) => {
            seed.zeroize();
            return Err(e);
        }
    };
    let (mut stored, readback_backend) = load_seed_with_migrate(data_dir)?.ok_or(
        IdentityStoreError::Continuity("identity create had no readable result"),
    )?;
    if readback_backend != backend || stored != seed {
        stored.zeroize();
        seed.zeroize();
        return Err(IdentityStoreError::Continuity(
            "identity store readback mismatch",
        ));
    }
    stored.zeroize();
    seed.zeroize();
    verify_or_install_binding(data_dir, backend, &id)?;
    Ok((id, backend))
}

/// Require an existing identity (no create). Blocking, like [`load_identity`].
pub fn load_identity_required(data_dir: &Path) -> Result<Identity, IdentityStoreError> {
    load_identity(data_dir)?.ok_or_else(|| {
        IdentityStoreError::Io("identity missing — run init / ash init first".into())
    })
}

/// Env vs `identity.backend` marker, without loading seed bytes.
///
/// Malformed markers propagate [`IdentityStoreError::Continuity`] (fail-closed).
/// Hard mismatches return `ok: false` with a redacted `issue` — they do not
/// invent backends or print secrets.
pub fn backend_consistency(
    data_dir: &Path,
) -> Result<IdentityBackendConsistency, IdentityStoreError> {
    backend_consistency_with(data_dir, locked_file_backend_requested())
}

fn backend_consistency_with(
    data_dir: &Path,
    env_locked_file_requested: bool,
) -> Result<IdentityBackendConsistency, IdentityStoreError> {
    let recorded = read_marker_checked(data_dir)?;
    let mut ok = true;
    let mut issue = None;

    // Same order as `load_seed_with_migrate`: Release forbid, then env vs
    // recorded protected backend, then recorded locked-file without override.
    if env_locked_file_requested {
        if !cfg!(debug_assertions) {
            ok = false;
            issue = Some("locked-file identity backend is forbidden in Release builds".into());
        } else if matches!(
            recorded,
            Some(
                IdentityStoreBackend::MacosKeychain
                    | IdentityStoreBackend::WindowsDpapiFile
                    | IdentityStoreBackend::LinuxSecretService
                    | IdentityStoreBackend::PassphraseVault
            )
        ) {
            ok = false;
            issue = Some("locked-file override conflicts with recorded protected backend".into());
        }
    } else if recorded == Some(IdentityStoreBackend::LockedFile) {
        ok = false;
        issue = Some(
            "locked-file identity requires explicit RAVEN_IDENTITY_BACKEND=locked-file".into(),
        );
    }

    Ok(IdentityBackendConsistency {
        recorded,
        env_locked_file_requested,
        ok,
        issue,
    })
}

/// Identity is usable for daemon/send only when the backend is consistent
/// and a seed can be loaded. Intended as the Core hook for CLI DX
/// `daemon_ready` (mismatch ⇒ not usable ⇒ ready fails).
///
/// Does not invent backends. Never embeds seed material in `reason`.
pub fn identity_usable(data_dir: &Path) -> Result<IdentityUsable, IdentityStoreError> {
    let consistency = backend_consistency(data_dir)?;
    if consistency.blocks_identity_use() {
        let reason = consistency.issue.clone();
        return Ok(IdentityUsable {
            usable: false,
            has_identity: false,
            consistency,
            reason,
        });
    }
    let has_identity = load_identity(data_dir)?.is_some();
    Ok(IdentityUsable {
        usable: has_identity,
        has_identity,
        consistency,
        reason: if has_identity {
            None
        } else {
            Some("identity missing — run init / ash init first".into())
        },
    })
}

/// Non-secret status for `ash doctor` and operators. Store failures remain
/// distinguishable from a proven-empty first install. Does not report env vs
/// marker conflict — call [`backend_consistency`] for that diagnostic.
pub fn store_status(data_dir: &Path) -> Result<IdentityStoreStatus, IdentityStoreError> {
    let path = seed_path(data_dir);
    let has_identity = load_identity(data_dir)?.is_some();
    let backend = read_marker_checked(data_dir)?;
    // After a successful load/migrate, plaintext should be gone on macOS / DPAPI hosts.
    let legacy_after = match read_raw_seed_file(&path)? {
        Some(mut bytes) => {
            let legacy = is_legacy_plaintext(&bytes);
            bytes.zeroize();
            legacy
        }
        None => false,
    };
    Ok(IdentityStoreStatus {
        backend,
        has_identity,
        legacy_plaintext_present: legacy_after
            && !matches!(backend, Some(IdentityStoreBackend::LockedFile)),
    })
}

/// Test helper: remove platform credentials for this data_dir (best-effort).
///
/// Irreversibly destroys the root identity, so it only exists in unit tests
/// and `test-helpers` builds — never in the default production API.
#[cfg(any(test, feature = "test-helpers"))]
pub fn test_cleanup(data_dir: &Path) {
    let account = account_for_data_dir(data_dir);
    #[cfg(target_os = "macos")]
    keychain_delete(&account);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    secret_service_delete(&account);
    let _ = account;
    let _ = std::fs::remove_file(seed_path(data_dir));
    let _ = std::fs::remove_file(marker_path(data_dir));
    let _ = std::fs::remove_file(binding_path(data_dir));
    let _ = std::fs::remove_file(data_dir.join(IDENTITY_STORE_LOCK_NAME));
    let _ = std::fs::remove_file(data_dir.join(crate::keystore_vault::VAULT_FILE_NAME));
    let _ = std::fs::remove_file(data_dir.join(crate::keystore_select::KEYSTORE_MARKER_NAME));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn wipe_seed_file_overwrites_in_place_before_unlinking() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(SEED_FILE_NAME);
        let alias = tmp.path().join("seed-alias");
        std::fs::write(&path, [0xA5u8; 32]).unwrap();
        // A second name for the same inode observes what happened to the bytes.
        std::fs::hard_link(&path, &alias).unwrap();
        wipe_seed_file(&path).unwrap();
        assert!(!path.exists());
        assert_eq!(std::fs::read(&alias).unwrap(), vec![0u8; 32]);
        // Missing file is not an error.
        wipe_seed_file(&path).unwrap();
    }

    /// A legacy seed the user made read-only must still be scrubbed and removed:
    /// refusing would keep the plaintext on disk and make every later load fail.
    #[cfg(unix)]
    #[test]
    fn wipe_seed_file_scrubs_and_removes_a_read_only_legacy_seed() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(SEED_FILE_NAME);
        let alias = tmp.path().join("seed-alias");
        std::fs::write(&path, [0xA5u8; 32]).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        wipe_seed_file(&path).unwrap();
        assert!(!path.exists());
        assert_eq!(std::fs::read(&alias).unwrap(), vec![0u8; 32]);
    }

    /// Scrubbing is best-effort, removal is not: when the bytes cannot be
    /// overwritten the name still goes, and only a failed unlink is an error.
    #[cfg(unix)]
    #[test]
    fn wipe_seed_file_removal_is_mandatory_and_scrub_is_best_effort() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        // Unscrubbable: a symlink is never written through, only unlinked.
        let target = tmp.path().join("user-file");
        std::fs::write(&target, b"not raven's").unwrap();
        let link = tmp.path().join(SEED_FILE_NAME);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        wipe_seed_file(&link).unwrap();
        assert!(link.symlink_metadata().is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"not raven's");

        // Unremovable (read-only directory): the error propagates.
        let locked = tmp.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let path = locked.join(SEED_FILE_NAME);
        std::fs::write(&path, [0xA5u8; 32]).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = wipe_seed_file(&path);
        let still_there = path.exists();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Running as root bypasses the directory mode; nothing to assert then.
        if still_there {
            assert!(result.is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn reconcile_accepts_a_read_only_legacy_seed_that_matches() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(SEED_FILE_NAME);
        let seed = [0x5Au8; 32];
        std::fs::write(&path, seed).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        reconcile_secure_and_raw_seed(&path, &seed).unwrap();
        assert!(!path.exists());
        // Idempotent once the plaintext file is gone.
        reconcile_secure_and_raw_seed(&path, &seed).unwrap();
    }

    #[test]
    fn create_load_round_trip() {
        test_enable_locked_file_identity_backend();
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let (id, backend) = load_or_create_identity(dir).expect("create");
        assert!(matches!(
            backend,
            IdentityStoreBackend::MacosKeychain
                | IdentityStoreBackend::WindowsDpapiFile
                | IdentityStoreBackend::LinuxSecretService
                | IdentityStoreBackend::LockedFile
        ));
        let loaded = load_identity(dir).unwrap().expect("loaded");
        assert_eq!(id.public_key_bytes(), loaded.public_key_bytes());
        assert_eq!(id.address(), loaded.address());
        let (again, _) = load_or_create_identity(dir).unwrap();
        assert_eq!(again.public_key_bytes(), id.public_key_bytes());
        test_cleanup(dir);
    }

    #[test]
    fn migrates_legacy_plaintext_seed_file() {
        test_enable_locked_file_identity_backend();
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        std::fs::create_dir_all(dir).unwrap();
        let original = Identity::generate();
        let seed = original.seed_bytes();
        let path = seed_path(dir);
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            f.write_all(&seed).unwrap();
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&path, seed).unwrap();
        }

        let loaded = load_identity(dir).unwrap().expect("migrate+load");
        assert_eq!(loaded.public_key_bytes(), original.public_key_bytes());

        #[cfg(target_os = "macos")]
        {
            if locked_file_backend_requested() {
                test_cleanup(dir);
                return;
            }
            assert!(
                !path.exists(),
                "plaintext identity.seed must be removed after Keychain migrate"
            );
            assert_eq!(
                read_marker_checked(dir).unwrap(),
                Some(IdentityStoreBackend::MacosKeychain)
            );
        }

        #[cfg(windows)]
        {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                is_dpapi_blob(&bytes),
                "Windows migrate must rewrite as DPAPI blob"
            );
            assert!(!is_legacy_plaintext(&bytes));
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        {
            if path.exists() {
                let meta = std::fs::metadata(&path).unwrap();
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            }
        }

        test_cleanup(dir);
    }

    #[cfg(windows)]
    #[test]
    fn fresh_dpapi_creation_never_overwrites_existing_state() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        std::fs::create_dir_all(dir).unwrap();
        let path = seed_path(dir);
        std::fs::write(&path, b"pre-existing profile state").unwrap();
        let id = Identity::generate();
        let mut seed = id.seed_bytes();
        let err = store_seed(dir, &seed)
            .expect_err("fresh creation must fail closed on an existing seed file");
        seed.zeroize();
        assert!(matches!(err, IdentityStoreError::Io(_)));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"pre-existing profile state",
            "existing bytes must be preserved byte-for-byte"
        );
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_migration_is_verified_and_replaces_plaintext() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        std::fs::create_dir_all(dir).unwrap();
        let original = Identity::generate();
        let seed = original.seed_bytes();
        let path = seed_path(dir);
        std::fs::write(&path, seed).unwrap();

        let loaded = load_identity(dir).unwrap().expect("migrate+load");
        assert_eq!(loaded.public_key_bytes(), original.public_key_bytes());
        let bytes = std::fs::read(&path).unwrap();
        assert!(is_dpapi_blob(&bytes));
        // Final decrypt of the durable blob must reproduce the original seed.
        let mut decrypted = load_dpapi_seed_file(&path).unwrap().unwrap();
        assert_eq!(decrypted, seed);
        decrypted.zeroize();
        test_cleanup(dir);
    }

    #[test]
    fn error_display_never_embeds_seed_hex() {
        let seed = [0xabu8; 32];
        let hex = hex::encode(seed);
        let err = IdentityStoreError::SecureStore("keychain locked".into());
        let s = err.redacted_display();
        assert!(!s.contains(&hex));
        assert!(!s.contains("private"));
    }

    #[test]
    fn store_status_reports_backend_without_secrets() {
        test_enable_locked_file_identity_backend();
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let _ = load_or_create_identity(dir).unwrap();
        let st = store_status(dir).unwrap();
        assert!(st.has_identity);
        assert!(st.backend.is_some());
        let label = st.backend.unwrap().as_str();
        assert!(!label.is_empty());
        assert!(!label.contains("seed"));
        test_cleanup(dir);
    }

    #[test]
    fn malformed_marker_never_becomes_first_install() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        std::fs::write(marker_path(dir), b"macos-keychain\nextra\n").unwrap();
        let err = match load_or_create_identity(dir) {
            Err(e) => e,
            Ok(_) => panic!("marker must fail"),
        };
        assert!(matches!(err, IdentityStoreError::Continuity(_)));
        assert!(!seed_path(dir).exists());
        assert!(!binding_path(dir).exists());
        assert!(store_status(dir).is_err());
        test_cleanup(dir);
    }

    #[test]
    fn recorded_locked_file_missing_never_regenerates() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        write_marker(dir, IdentityStoreBackend::LockedFile).unwrap();
        assert!(load_or_create_identity(dir).is_err());
        assert!(!seed_path(dir).exists());
        assert!(!binding_path(dir).exists());
        test_cleanup(dir);
    }

    #[test]
    fn binding_tamper_refuses_the_original_protected_seed() {
        test_enable_locked_file_identity_backend();
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let (id, _) = load_or_create_identity(dir).unwrap();
        let original_pub = id.public_key_bytes();
        let mut binding = std::fs::read(binding_path(dir)).unwrap();
        assert_eq!(binding.len(), IDENTITY_BINDING_LEN);
        binding[44] ^= 0x80;
        std::fs::write(binding_path(dir), binding).unwrap();
        let err = match load_identity(dir) {
            Err(e) => e,
            Ok(_) => panic!("tamper must fail"),
        };
        assert!(matches!(err, IdentityStoreError::Continuity(_)));

        #[cfg(target_os = "macos")]
        {
            if locked_file_backend_requested() {
                test_cleanup(dir);
                return;
            }
            let seed = keychain_get(&account_for_data_dir(dir)).unwrap().unwrap();
            assert_eq!(Identity::from_seed(&seed).public_key_bytes(), original_pub);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = original_pub;
        }
        test_cleanup(dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_only_item_not_found_is_proven_absence() {
        use security_framework_sys::base::errSecItemNotFound;
        assert!(keychain_status_is_proven_absent(errSecItemNotFound));
        assert!(!keychain_status_is_proven_absent(-25_293));
        assert!(!keychain_status_is_proven_absent(-25_308));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn locked_file_maps_keychain_securestore_to_continuity() {
        // Locked/denied (`SecureStore`) must not soft-succeed as first-install
        // *or* as unmarked planted-seed load. Search-hit + get fail is the
        // locked-with-item case Core flagged.
        for msg in [
            "keychain get status -25308",
            "keychain read status -25293",
            "keychain get status -25393",
        ] {
            let err =
                locked_file_after_keychain_probe(Err(IdentityStoreError::SecureStore(msg.into())))
                    .expect_err("locked Keychain is not proven absent");
            assert!(matches!(err, IdentityStoreError::Continuity(_)), "{msg}");
        }
        locked_file_after_keychain_probe(Ok(None)).expect("item-not-found is absence");
        let visible = locked_file_after_keychain_probe(Ok(Some([0x11; 32])))
            .expect_err("visible Keychain identity conflicts");
        assert!(matches!(visible, IdentityStoreError::Continuity(_)));
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn linux_ss_connect_fail_is_lab_absent_but_locked_item_is_not() {
        let connect = IdentityStoreError::SecureStore(
            "secret-service connect: zbus error: I/O error: No such file or directory (os error 2)"
                .into(),
        );
        let service_unknown = IdentityStoreError::SecureStore(
            "secret-service connect: zbus error: org.freedesktop.DBus.Error.ServiceUnknown: \
             The name org.freedesktop.secrets was not provided by any .service files"
                .into(),
        );
        let locked = IdentityStoreError::SecureStore("secret-service identity item locked".into());
        let search = IdentityStoreError::SecureStore("secret-service search: denied".into());
        let get = IdentityStoreError::SecureStore("secret-service get: denied".into());
        assert!(linux_secret_service_is_session_bus_missing(&connect));
        assert!(linux_secret_service_is_session_bus_missing(
            &service_unknown
        ));
        assert!(!linux_secret_service_is_session_bus_missing(&locked));
        assert!(!linux_secret_service_is_session_bus_missing(&search));
        assert!(!linux_secret_service_is_session_bus_missing(&get));
        locked_file_after_secret_service_probe(Ok(None)).expect("empty collection is absence");
        locked_file_after_secret_service_probe(Err(connect))
            .expect("session-bus connect-fail is the lab-only exception");
        locked_file_after_secret_service_probe(Err(service_unknown))
            .expect("ServiceUnknown is the same no-provider exception");
        for err in [locked, search, get] {
            let mapped = locked_file_after_secret_service_probe(Err(err))
                .expect_err("locked/search/get is not absence");
            assert!(matches!(mapped, IdentityStoreError::Continuity(_)));
        }
        let visible = locked_file_after_secret_service_probe(Ok(Some([0x22; 32])))
            .expect_err("visible Secret Service identity conflicts");
        assert!(matches!(visible, IdentityStoreError::Continuity(_)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn recorded_keychain_item_missing_never_regenerates() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        test_cleanup(dir);
        write_marker(dir, IdentityStoreBackend::MacosKeychain).unwrap();
        let err = match load_or_create_identity(dir) {
            Err(e) => e,
            Ok(_) => panic!("missing recorded Keychain item must fail"),
        };
        assert!(matches!(err, IdentityStoreError::Continuity(_)));
        assert!(keychain_get(&account_for_data_dir(dir)).unwrap().is_none());
        assert!(!binding_path(dir).exists());
        test_cleanup(dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn secure_and_raw_seed_conflict_is_never_winner_picked() {
        if locked_file_backend_requested() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let (id, _) = load_or_create_identity(dir).unwrap();
        let mut other = Identity::generate().seed_bytes();
        write_locked_seed_file(&seed_path(dir), &other).unwrap();
        other.zeroize();
        let err = match load_identity(dir) {
            Err(e) => e,
            Ok(_) => panic!("conflict must fail"),
        };
        assert!(matches!(err, IdentityStoreError::Continuity(_)));
        assert!(
            seed_path(dir).exists(),
            "conflict evidence must be preserved"
        );
        let seed = keychain_get(&account_for_data_dir(dir)).unwrap().unwrap();
        assert_eq!(
            Identity::from_seed(&seed).public_key_bytes(),
            id.public_key_bytes()
        );
        test_cleanup(dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn concurrent_first_init_converges_to_one_identity() {
        use std::sync::{Arc, Barrier};

        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        test_cleanup(&dir);
        let barrier = Arc::new(Barrier::new(6));
        let mut workers = Vec::new();
        for _ in 0..6 {
            let dir = dir.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                load_or_create_identity(&dir)
                    .map(|(id, _)| id.public_key_bytes())
                    .unwrap()
            }));
        }
        let keys: Vec<[u8; 32]> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert!(keys.windows(2).all(|pair| pair[0] == pair[1]));
        test_cleanup(&dir);
    }

    #[test]
    fn locked_file_first_install_when_platform_store_unavailable() {
        test_enable_locked_file_identity_backend();
        if !locked_file_backend_requested() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let (id, backend) = load_or_create_identity(dir).expect("locked-file first install");
        assert_eq!(backend, IdentityStoreBackend::LockedFile);
        let loaded = load_identity(dir).unwrap().expect("loaded");
        assert_eq!(id.public_key_bytes(), loaded.public_key_bytes());
        test_cleanup(dir);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn locked_file_permissions_are_0600_when_used() {
        test_enable_locked_file_identity_backend();
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let id = Identity::generate();
        let seed = id.seed_bytes();
        write_locked_seed_file(&seed_path(dir), &seed).unwrap();
        write_marker(dir, IdentityStoreBackend::LockedFile).unwrap();
        let meta = std::fs::metadata(seed_path(dir)).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let loaded = load_identity(dir).unwrap().unwrap();
        assert_eq!(loaded.public_key_bytes(), id.public_key_bytes());
        test_cleanup(dir);
    }

    #[test]
    fn backend_consistency_env_locked_file_conflicts_with_protected_marker() {
        for backend in [
            IdentityStoreBackend::MacosKeychain,
            IdentityStoreBackend::WindowsDpapiFile,
            IdentityStoreBackend::LinuxSecretService,
        ] {
            let tmp = TempDir::new().unwrap();
            let dir = tmp.path();
            write_marker(dir, backend).unwrap();
            let c = backend_consistency_with(dir, true).unwrap();
            assert!(!c.ok, "{backend:?}");
            assert!(c.blocks_identity_use());
            assert_eq!(c.recorded, Some(backend));
            assert!(c.env_locked_file_requested);
            let issue = c.issue.as_deref().expect("issue");
            if cfg!(debug_assertions) {
                assert!(
                    issue.contains("conflicts with recorded protected backend"),
                    "{issue}"
                );
            } else {
                assert!(issue.contains("forbidden in Release"), "{issue}");
            }
            assert!(!issue.contains("seed"));
            test_cleanup(dir);
        }
    }

    #[test]
    fn backend_consistency_recorded_locked_file_requires_explicit_env() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        write_marker(dir, IdentityStoreBackend::LockedFile).unwrap();
        let c = backend_consistency_with(dir, false).unwrap();
        assert!(!c.ok);
        assert!(c.blocks_identity_use());
        let issue = c.issue.as_deref().expect("issue");
        assert!(
            issue.contains("RAVEN_IDENTITY_BACKEND=locked-file"),
            "{issue}"
        );
        assert!(!issue.contains("seed"));
        test_cleanup(dir);
    }

    #[test]
    fn backend_consistency_locked_file_with_env_ok_in_debug() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        write_marker(dir, IdentityStoreBackend::LockedFile).unwrap();
        let c = backend_consistency_with(dir, true).unwrap();
        assert!(c.env_locked_file_requested);
        if cfg!(debug_assertions) {
            assert!(c.ok);
            assert!(!c.blocks_identity_use());
            assert!(c.issue.is_none());
        } else {
            assert!(!c.ok);
            assert!(c.issue.as_deref().unwrap().contains("forbidden in Release"));
        }
        test_cleanup(dir);
    }

    #[test]
    fn backend_consistency_matching_protected_marker_without_env_ok() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        write_marker(dir, IdentityStoreBackend::MacosKeychain).unwrap();
        let c = backend_consistency_with(dir, false).unwrap();
        assert!(c.ok);
        assert!(!c.blocks_identity_use());
        assert_eq!(c.recorded, Some(IdentityStoreBackend::MacosKeychain));
        assert!(c.issue.is_none());
        test_cleanup(dir);
    }

    #[test]
    fn backend_consistency_empty_dir_is_consistent() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let c = backend_consistency_with(dir, false).unwrap();
        assert!(c.ok);
        assert!(c.recorded.is_none());
        assert!(!c.env_locked_file_requested);
        test_cleanup(dir);
    }

    #[test]
    fn backend_consistency_malformed_marker_is_continuity() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        std::fs::write(marker_path(dir), b"macos-keychain\nextra\n").unwrap();
        let err = backend_consistency_with(dir, false).expect_err("malformed marker");
        assert!(matches!(err, IdentityStoreError::Continuity(_)));
        assert!(!err.redacted_display().contains("seed"));
        test_cleanup(dir);
    }

    #[test]
    fn identity_usable_false_on_recorded_locked_file_without_env() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        write_marker(dir, IdentityStoreBackend::LockedFile).unwrap();
        // Public API reads process env. This VM leaves the override unset;
        // if a harness exports locked-file, skip rather than flake.
        if locked_file_backend_requested() {
            test_cleanup(dir);
            return;
        }
        let u = identity_usable(dir).unwrap();
        assert!(!u.usable);
        assert!(!u.has_identity);
        assert!(u.consistency.blocks_identity_use());
        let reason = u.reason.as_deref().expect("reason");
        assert!(
            reason.contains("RAVEN_IDENTITY_BACKEND=locked-file"),
            "{reason}"
        );
        assert!(!reason.contains("seed"));
        test_cleanup(dir);
    }

    #[test]
    fn identity_usable_empty_dir_is_not_ready_but_consistent() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        if locked_file_backend_requested() && !cfg!(debug_assertions) {
            test_cleanup(dir);
            return;
        }
        // Headless GNU/Linux may fail closed while proving first-install
        // absence (no Secret Service bus). That is not a backend mismatch.
        match identity_usable(dir) {
            Ok(u) => {
                assert!(!u.usable);
                assert!(!u.has_identity);
                assert!(u.consistency.ok);
                assert!(!u.consistency.blocks_identity_use());
            }
            Err(e) => {
                assert!(matches!(e, IdentityStoreError::SecureStore(_)));
                assert!(!e.redacted_display().contains("seed"));
                let c = backend_consistency(dir).unwrap();
                assert!(c.ok);
                assert!(!c.blocks_identity_use());
            }
        }
        test_cleanup(dir);
    }

    fn is_continuity(result: Result<(), IdentityStoreError>) -> bool {
        matches!(result, Err(IdentityStoreError::Continuity(_)))
    }

    /// `raven-node status` / `bridge` open the forward queue and the ash menus
    /// take the history lock on a profile that has no identity yet. Those files
    /// used to trip the first-install tripwire permanently.
    #[test]
    fn first_install_tolerates_inert_files_created_by_read_only_commands() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        require_proven_first_install(dir, None).unwrap();

        // `raven-node status`: an empty relay-custody database.
        drop(crate::forward_queue::ForwardQueue::open(&dir.join("forward_queue.sqlite")).unwrap());
        // ash Messages / outbound-stage / key-init locks and Finder metadata.
        for lock in [
            ".chat_history.lock.sqlite",
            ".outbound_body_stage.lock.sqlite",
            ".chat_history_key.lock.sqlite",
        ] {
            drop(crate::paths::DataDirLock::acquire(dir, lock).unwrap());
        }
        std::fs::write(dir.join(".DS_Store"), b"finder").unwrap();
        std::fs::write(dir.join("bootstrap.json.corrupt"), b"{ not json").unwrap();
        require_proven_first_install(dir, None).unwrap();

        // The recorded-identity tripwires are untouched.
        assert!(is_continuity(require_proven_first_install(
            dir,
            Some(IdentityStoreBackend::LockedFile)
        )));
    }

    /// Anything that indicates an established profile still fails closed, so a
    /// deleted or locked secure store can never mint a second identity.
    #[test]
    fn first_install_still_refuses_established_or_hostile_profile_state() {
        let case = |setup: &dyn Fn(&Path)| {
            let tmp = TempDir::new().unwrap();
            setup(tmp.path());
            require_proven_first_install(tmp.path(), None)
        };
        for stray in [
            "queue.sqlite",
            "contacts.json",
            "chat_history.json",
            "outbound_body_stage.bin",
            "device_x25519.secret",
            "identity.seed",
            "somefile.lock.sqlite",
        ] {
            assert!(
                is_continuity(case(&|d| std::fs::write(d.join(stray), b"x").unwrap())),
                "{stray}"
            );
        }
        // A lock database that actually holds data is not a lock.
        assert!(is_continuity(case(&|d| std::fs::write(
            d.join(".chat_history.lock.sqlite"),
            b"SQLite format 3\0not empty"
        )
        .unwrap())));
        // A relay queue that holds rows is state, not a stray empty file.
        assert!(is_continuity(case(&|d| {
            let path = d.join("forward_queue.sqlite");
            drop(crate::forward_queue::ForwardQueue::open(&path).unwrap());
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "INSERT INTO bridge_seen_objects_v2 (object_digest, seen_at_ms, ingress)
                 VALUES (x'01', 1, 'lan')",
                [],
            )
            .unwrap();
        })));
        // An unreadable or non-SQLite "queue" fails closed too.
        assert!(is_continuity(case(&|d| std::fs::write(
            d.join("forward_queue.sqlite"),
            b"definitely not sqlite, long enough to be a header......"
        )
        .unwrap())));
        // A sidecar without its database is not inert.
        assert!(is_continuity(case(&|d| std::fs::write(
            d.join("forward_queue.sqlite-wal"),
            b"x"
        )
        .unwrap())));
    }

    /// `raven-node ipc --data-dir <new profile>` (the documented dedicated-IPC
    /// start) binds its socket and instance lock before any identity exists;
    /// they used to make the first `ash init` fail the continuity check until
    /// they were removed by hand. Only the real artifacts are tolerated.
    #[cfg(unix)]
    #[test]
    fn first_install_tolerates_the_ipc_servers_socket_lock_and_log() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        // A real bound socket (an unlinked-on-exit file would be left behind
        // by a killed server: the file type is what matters, not liveness).
        let sock = dir.join("raven-node.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        drop(listener);
        assert!(sock.exists(), "a dropped listener leaves its socket file");
        // The instance lock exactly as `acquire_instance_lock` creates it.
        std::fs::write(dir.join("raven-node.sock.lock"), b"").unwrap();
        std::fs::write(dir.join("raven-node-service.log"), b"ipc: listening\n").unwrap();
        require_proven_first_install(dir, None).unwrap();
        assert!(is_continuity(require_proven_first_install(
            dir,
            Some(IdentityStoreBackend::LockedFile)
        )));
    }

    #[cfg(unix)]
    #[test]
    fn first_install_still_refuses_look_alike_ipc_names() {
        let case = |setup: &dyn Fn(&Path)| {
            let tmp = TempDir::new().unwrap();
            setup(tmp.path());
            require_proven_first_install(tmp.path(), None)
        };
        // A regular file named like the socket is state, not a socket.
        assert!(is_continuity(case(&|d| std::fs::write(
            d.join("raven-node.sock"),
            b""
        )
        .unwrap())));
        // So are a symlink and a directory under the socket, lock or log name.
        assert!(is_continuity(case(&|d| {
            std::fs::write(d.join("elsewhere"), b"").unwrap();
            std::os::unix::fs::symlink(d.join("elsewhere"), d.join("raven-node.sock")).unwrap();
        })));
        assert!(is_continuity(case(&|d| {
            std::fs::create_dir(d.join("raven-node.sock.lock")).unwrap()
        })));
        assert!(is_continuity(case(&|d| {
            std::fs::write(d.join("elsewhere"), b"").unwrap();
            std::os::unix::fs::symlink(d.join("elsewhere"), d.join("raven-node-service.log"))
                .unwrap();
        })));
        // A lock file that holds data is not the O_CREAT-and-flock file.
        assert!(is_continuity(case(&|d| std::fs::write(
            d.join("raven-node.sock.lock"),
            b"not empty"
        )
        .unwrap())));
        // Other names that merely share the prefix stay refused.
        for stray in [
            "raven-node.sock.bak",
            "raven-node.sock.lock2",
            "raven-node.log",
        ] {
            assert!(
                is_continuity(case(&|d| std::fs::write(d.join(stray), b"").unwrap())),
                "{stray}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn first_install_refuses_a_symlinked_inert_name() {
        let tmp = TempDir::new().unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::write(&elsewhere, b"").unwrap();
        let profile = tmp.path().join("profile");
        std::fs::create_dir(&profile).unwrap();
        std::os::unix::fs::symlink(&elsewhere, profile.join(".chat_history.lock.sqlite")).unwrap();
        assert!(is_continuity(require_proven_first_install(&profile, None)));
    }

    /// End to end: files a read-only command left behind must not stop the
    /// first identity from being created (lab backend; skipped when the
    /// harness has not selected it, to stay clear of the real secure store).
    #[test]
    fn first_install_succeeds_after_read_only_commands_touched_the_profile() {
        test_enable_locked_file_identity_backend();
        if !locked_file_backend_requested() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        drop(crate::forward_queue::ForwardQueue::open(&dir.join("forward_queue.sqlite")).unwrap());
        drop(crate::paths::DataDirLock::acquire(dir, ".chat_history.lock.sqlite").unwrap());
        let (id, _) = load_or_create_identity(dir).expect("first install after status/menus");
        let loaded = load_identity(dir).unwrap().expect("loaded");
        assert_eq!(id.public_key_bytes(), loaded.public_key_bytes());
        test_cleanup(dir);
    }

    #[test]
    fn failed_seed_write_removes_the_partial_file_but_never_a_preexisting_one() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(SEED_FILE_NAME);
        // create_new on an existing profile file must fail and leave it intact.
        std::fs::write(&path, b"existing profile state").unwrap();
        assert!(write_locked_seed_file(&path, &[7u8; 32]).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"existing profile state");
        std::fs::remove_file(&path).unwrap();

        // A write/sync failure after the create leaves no short identity.seed.
        std::fs::write(&path, [1u8; 5]).unwrap();
        let enospc = std::io::Error::other("no space left on device");
        assert!(finish_new_seed_file(&path, Err(enospc)).is_err());
        assert!(!path.exists());

        // The success path keeps the seed, and a retry can then proceed.
        write_locked_seed_file(&path, &[7u8; 32]).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), [7u8; 32]);
    }

    /// Another raven process (blocked in a macOS Keychain dialog, say) keeps the
    /// identity-store lock: a waiter says so once and carries on by itself when
    /// the holder lets go.
    #[test]
    fn waiting_for_a_held_identity_lock_announces_itself_once_then_gets_it() {
        let tmp = TempDir::new().unwrap();
        let mut holder =
            Some(crate::paths::DataDirLock::acquire(tmp.path(), IDENTITY_STORE_LOCK_NAME).unwrap());
        let mut notices = 0;
        // The notice is the clock: it fires while the lock is still held, and
        // the holder lets go inside it, so the next attempt must win.
        let lock = acquire_identity_store_lock_with(
            tmp.path(),
            Duration::from_millis(20),
            Duration::from_secs(60),
            |_| {
                notices += 1;
                assert!(holder.take().is_some(), "a second notice for one wait");
            },
        )
        .expect("the lock once its holder let go");
        drop(lock);
        assert_eq!(notices, 1);
    }

    /// The bounded wait still ends in the old lock error (ash recognises the
    /// "database is locked" text), after exactly one notice.
    #[test]
    fn a_never_released_identity_lock_times_out_with_the_lock_text_after_one_notice() {
        let tmp = TempDir::new().unwrap();
        let _holder =
            crate::paths::DataDirLock::acquire(tmp.path(), IDENTITY_STORE_LOCK_NAME).unwrap();
        let mut notices = 0;
        let started = Instant::now();
        let err = match acquire_identity_store_lock_with(
            tmp.path(),
            Duration::from_millis(10),
            Duration::from_millis(300),
            |_| notices += 1,
        ) {
            Ok(_) => panic!("the lock is held"),
            Err(e) => e,
        };
        assert!(started.elapsed() < Duration::from_secs(30));
        assert!(
            matches!(&err, IdentityStoreError::Io(text) if text.contains("database is locked")),
            "{err}"
        );
        assert_eq!(notices, 1, "one notice per wait, not one per retry");
    }

    /// Only a held lock is waited for and announced: any other failure to take
    /// it is reported at once.
    #[test]
    fn a_failure_that_is_not_a_held_lock_is_neither_retried_nor_announced() {
        let tmp = TempDir::new().unwrap();
        // A file where the data dir should be: the lock file cannot be created.
        let not_a_dir = tmp.path().join("not-a-dir");
        std::fs::write(&not_a_dir, b"x").unwrap();
        let mut notices = 0;
        let started = Instant::now();
        let result = acquire_identity_store_lock_with(
            &not_a_dir,
            Duration::from_millis(50),
            Duration::from_secs(5),
            |_| notices += 1,
        );
        assert!(matches!(result, Err(IdentityStoreError::Io(_))));
        assert_eq!(notices, 0);
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "it kept retrying"
        );
    }

    fn test_identity_vault(dir: &Path, passphrase: &str) -> crate::keystore_vault::Vault {
        crate::keystore_vault::test_support::test_vault(dir, passphrase).0
    }

    #[test]
    fn vault_identity_create_load_add_only_and_continuity() {
        const PASS: &str = "identity vault passphrase";
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let vault = test_identity_vault(dir, PASS);
        let path = seed_path(dir);
        assert!(load_vault_seed_with_migrate(dir, &vault, &path, None)
            .unwrap()
            .is_none());
        let id = Identity::generate();
        let seed = id.seed_bytes();
        assert_eq!(
            store_vault_seed(dir, &vault, &path, &seed).unwrap(),
            IdentityStoreBackend::PassphraseVault
        );
        let marker = read_marker_checked(dir).unwrap();
        assert_eq!(marker, Some(IdentityStoreBackend::PassphraseVault));
        let (loaded, backend) = load_vault_seed_with_migrate(dir, &vault, &path, marker)
            .unwrap()
            .unwrap();
        assert_eq!(loaded, seed);
        let (loaded_id, _) = finish_loaded_identity(dir, loaded, backend).unwrap();
        assert_eq!(loaded_id.public_key_bytes(), id.public_key_bytes());
        assert!(
            store_vault_seed(dir, &vault, &path, &[9u8; 32]).is_err(),
            "add-only: a second create never replaces the root"
        );
        let reopened = test_identity_vault(dir, PASS);
        let (again, _) = load_vault_seed_with_migrate(dir, &reopened, &path, marker)
            .unwrap()
            .unwrap();
        assert_eq!(again, seed);
        let wrong = test_identity_vault(dir, "not the identity passphrase");
        assert!(matches!(
            load_vault_seed_with_migrate(dir, &wrong, &path, marker),
            Err(IdentityStoreError::SecureStore(_))
        ));
        assert!(matches!(
            load_vault_seed_with_migrate(
                dir,
                &vault,
                &path,
                Some(IdentityStoreBackend::LinuxSecretService)
            ),
            Err(IdentityStoreError::Continuity(_))
        ));
        vault
            .delete(crate::keystore_vault::IDENTITY_SEED_ENTRY)
            .unwrap();
        assert!(matches!(
            load_vault_seed_with_migrate(dir, &vault, &path, marker),
            Err(IdentityStoreError::Continuity(_))
        ));
    }

    #[test]
    fn vault_identity_migrates_legacy_plaintext_and_refuses_unmarked_vault_state() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let original = Identity::generate().seed_bytes();
        let path = seed_path(dir);
        crate::paths::create_new_private(&path, &original).unwrap();
        let vault = test_identity_vault(dir, "migration passphrase");
        let (seed, backend) = load_vault_seed_with_migrate(dir, &vault, &path, None)
            .unwrap()
            .unwrap();
        assert_eq!(seed, original);
        assert_eq!(backend, IdentityStoreBackend::PassphraseVault);
        assert!(!path.exists(), "plaintext seed is wiped after migration");
        assert_eq!(
            read_marker_checked(dir).unwrap(),
            Some(IdentityStoreBackend::PassphraseVault)
        );

        // A vault that holds other secrets but no identity is established
        // state, never a first install.
        let other = TempDir::new().unwrap();
        let other_vault = test_identity_vault(other.path(), "other passphrase");
        other_vault
            .put(crate::keystore_vault::CHAT_HISTORY_KEY_ENTRY, &[1u8; 32])
            .unwrap();
        assert!(matches!(
            load_vault_seed_with_migrate(
                other.path(),
                &other_vault,
                &seed_path(other.path()),
                None
            ),
            Err(IdentityStoreError::Continuity(_))
        ));
        // The keystore marker and the vault lock alone are inert.
        std::fs::write(
            other
                .path()
                .join(crate::keystore_select::KEYSTORE_MARKER_NAME),
            "passphrase-vault\n",
        )
        .unwrap();
        assert!(first_install_entry_is_inert(
            other.path(),
            crate::keystore_select::KEYSTORE_MARKER_NAME
        ));
        assert!(first_install_entry_is_inert(
            other.path(),
            crate::keystore_vault::VAULT_LOCK_NAME
        ));
        assert!(!first_install_entry_is_inert(
            other.path(),
            crate::keystore_vault::VAULT_FILE_NAME
        ));
    }
}
