//! Shared Raven data-dir and LAN bind defaults for ash and raven-node.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default LAN listener for `raven-node service` (reachable from other LAN hosts).
pub const DEFAULT_LAN_LISTEN: &str = "0.0.0.0:7420";
/// Mock BLE stays loopback-only.
pub const DEFAULT_BLE_LISTEN: &str = "127.0.0.1:7421";
/// Shared device_id for the local cert + prekey on this node.
pub const PRIMARY_DEVICE_ID: &str = "ash-primary";
/// Per-profile log the auto-started `raven-node service` writes its stdout and
/// stderr to (0600, in the data dir; `ash` creates it).
pub const SERVICE_LOG_NAME: &str = "raven-node-service.log";

/// Final path component of the placeholder returned by the infallible
/// resolvers when no profile directory can be determined.
pub const UNRESOLVED_DATA_DIR_NAME: &str = "RAVEN_DATA_DIR-unresolved-set-HOME-or-RAVEN_DATA_DIR";

/// Placeholder for "no profile directory could be determined". It is absolute
/// and sits under a path that no process can create (a child of `/dev/null`,
/// or of the NUL device on Windows), so using it can only fail. It must never
/// degrade into a working-directory-relative profile, which would silently give
/// every working directory its own identity, history and queue.
fn unresolved_data_dir() -> PathBuf {
    #[cfg(unix)]
    let base = PathBuf::from("/dev/null");
    #[cfg(not(unix))]
    let base = PathBuf::from(r"\\.\NUL");
    base.join(UNRESOLVED_DATA_DIR_NAME)
}

/// True for the placeholder returned when the profile directory is unresolved.
pub fn is_unresolved_data_dir(dir: &Path) -> bool {
    dir.components()
        .any(|c| c.as_os_str() == UNRESOLVED_DATA_DIR_NAME)
}

fn unresolved_data_dir_error() -> String {
    "cannot determine the Raven data directory: set RAVEN_DATA_DIR (or ASH_DATA_DIR), \
     pass --data-dir, or set HOME"
        .to_string()
}

/// Only an absolute home is usable. An empty or relative `HOME` would make the
/// default profile depend on the working directory.
fn usable_home(p: Option<PathBuf>) -> Option<PathBuf> {
    p.filter(|p| p.is_absolute())
}

/// Home directory from the environment: `HOME`, then on Windows `USERPROFILE`,
/// then `HOMEDRIVE` + `HOMEPATH` (plain `cmd` / PowerShell sessions set no `HOME`).
fn home_dir_from_env() -> Option<PathBuf> {
    let var = |key: &str| std::env::var_os(key).map(PathBuf::from);
    #[cfg(not(windows))]
    {
        usable_home(var("HOME"))
    }
    #[cfg(windows)]
    {
        usable_home(var("HOME"))
            .or_else(|| usable_home(var("USERPROFILE")))
            .or_else(|| {
                let (drive, path) = (var("HOMEDRIVE")?, var("HOMEPATH")?);
                usable_home(Some(PathBuf::from(format!(
                    "{}{}",
                    drive.display(),
                    path.display()
                ))))
            })
    }
}

/// Resolve the shared Raven profile directory.
///
/// Order: `RAVEN_DATA_DIR`, else `ASH_DATA_DIR`, else if `~/.raven-ash` exists
/// and `~/.raven` does not keep the legacy ash dir, else `~/.raven`.
///
/// When none of those can be determined (no override and no usable home) the
/// result is an unusable placeholder (see [`is_unresolved_data_dir`]) so the
/// first use fails with a clear error instead of creating a working-directory
/// relative profile. Callers that can report an error up front should use
/// [`try_default_raven_data_dir`].
pub fn default_raven_data_dir() -> PathBuf {
    try_default_raven_data_dir().unwrap_or_else(|_| unresolved_data_dir())
}

/// [`default_raven_data_dir`], but an undeterminable directory is an error.
pub fn try_default_raven_data_dir() -> Result<PathBuf, String> {
    try_resolve_raven_data_dir(
        std::env::var_os("RAVEN_DATA_DIR").map(PathBuf::from),
        std::env::var_os("ASH_DATA_DIR").map(PathBuf::from),
        home_dir_from_env(),
    )
}

/// Infallible form of [`try_resolve_raven_data_dir`]; the unresolved case
/// yields the unusable placeholder (see [`default_raven_data_dir`]).
pub fn resolve_raven_data_dir(
    raven_data_dir: Option<PathBuf>,
    ash_data_dir: Option<PathBuf>,
    home: Option<PathBuf>,
) -> PathBuf {
    try_resolve_raven_data_dir(raven_data_dir, ash_data_dir, home)
        .unwrap_or_else(|_| unresolved_data_dir())
}

pub fn try_resolve_raven_data_dir(
    raven_data_dir: Option<PathBuf>,
    ash_data_dir: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Result<PathBuf, String> {
    if let Some(p) = nonempty(raven_data_dir) {
        return Ok(p);
    }
    if let Some(p) = nonempty(ash_data_dir) {
        return Ok(p);
    }
    let Some(home) = usable_home(home) else {
        return Err(unresolved_data_dir_error());
    };
    let raven = home.join(".raven");
    let raven_ash = home.join(".raven-ash");
    if raven_ash.is_dir() && !raven.exists() {
        return Ok(raven_ash);
    }
    Ok(raven)
}

fn nonempty(p: Option<PathBuf>) -> Option<PathBuf> {
    p.filter(|p| !p.as_os_str().is_empty())
}

/// Refuse the unresolved-profile placeholder before anything is created.
///
/// Entry points that resolved their profile through the infallible resolvers
/// (a clap default, say) call this once up front, so the user gets the
/// explanatory error instead of whichever store happens to fail first with
/// `Not a directory`.
pub fn require_resolved_data_dir(dir: &Path) -> Result<(), String> {
    if is_unresolved_data_dir(dir) {
        return Err(unresolved_data_dir_error());
    }
    Ok(())
}

fn reject_unresolved_dir(dir: &Path) -> Result<(), String> {
    require_resolved_data_dir(dir)
}

/// Create the Raven data directory (and any missing parents) owner-only
/// (0700) on Unix, and strip group/other access from an existing one.
///
/// Only for the data directory itself (and directories Raven owns inside it);
/// never for caller-chosen locations such as export destinations or a
/// `--forward-db` parent. Fails closed when the mode cannot be restricted,
/// rather than keeping private state in a shared dir.
pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    reject_unresolved_dir(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| e.to_string())?;
        let metadata = std::fs::metadata(dir).map_err(|e| e.to_string())?;
        if !metadata.is_dir() {
            return Err(format!("{} is not a directory", dir.display()));
        }
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode & 0o7700))
                .map_err(|e| format!("cannot restrict {} to owner-only: {e}", dir.display()))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())
    }
}

/// Create missing parents of a private file owner-only, without touching the
/// mode of directories that already exist (they may be user-chosen).
fn create_private_parents(parent: &Path) -> Result<(), String> {
    reject_unresolved_dir(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())
    }
}

#[cfg(unix)]
fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

/// Prepare a SQLite database at a path the caller may have chosen
/// (`raven-node ipc --forward-db <path>`): missing parent directories are
/// created owner-only (0700), but an existing parent is never chmod-ed (it may
/// be `~/Documents`, a shared project dir or `/tmp`, and tightening it would
/// break whatever else lives there). The database plus any existing `-wal` /
/// `-shm` / `-journal` sidecars become 0600 on Unix, and the database file is
/// created 0600 *before* SQLite opens it, so SQLite (which gives new sidecars
/// the database file's mode) never creates world-readable files.
///
/// A database that lives directly in the Raven data dir uses
/// [`prepare_private_data_dir_sqlite_file`], which also locks the directory.
pub fn prepare_private_sqlite_file(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_private_parents(parent)?;
    }
    restrict_private_sqlite_files(path)
}

/// [`prepare_private_sqlite_file`] for a database inside the Raven data dir
/// (its parent *is* the profile directory): the data dir is created 0700 or, if
/// it already exists, stripped of group/other access, failing closed when that
/// is not possible.
pub fn prepare_private_data_dir_sqlite_file(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        ensure_private_dir(parent)?;
    }
    restrict_private_sqlite_files(path)
}

fn restrict_private_sqlite_files(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let candidate = sqlite_sidecar(path, suffix);
            let metadata = match std::fs::symlink_metadata(&candidate) {
                Ok(metadata) => metadata,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.to_string()),
            };
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "{} is not a regular file; refusing to open private database",
                    candidate.display()
                ));
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                match std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600)) {
                    Ok(()) => {}
                    // A sidecar SQLite removed concurrently needs no chmod.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn open_prepared_sqlite(
    path: &Path,
    prepare: fn(&Path) -> Result<(), String>,
) -> rusqlite::Result<rusqlite::Connection> {
    prepare(path).map_err(|message| {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
            Some(message),
        )
    })?;
    rusqlite::Connection::open(path)
}

/// [`prepare_private_sqlite_file`] then `Connection::open`.
pub fn open_private_sqlite(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    open_prepared_sqlite(path, prepare_private_sqlite_file)
}

/// [`prepare_private_data_dir_sqlite_file`] then `Connection::open`.
pub fn open_private_data_dir_sqlite(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    open_prepared_sqlite(path, prepare_private_data_dir_sqlite_file)
}

/// Cross-process exclusive lock via a small SQLite file (BEGIN EXCLUSIVE).
/// Holds until dropped. Used for peer-cache / registry RMW that must not race.
pub struct DataDirLock {
    _connection: rusqlite::Connection,
}

/// How long [`DataDirLock::acquire`] waits for another holder.
const DATA_DIR_LOCK_WAIT: Duration = Duration::from_secs(10);

impl DataDirLock {
    pub fn acquire(data_dir: &Path, lock_file_name: &str) -> Result<Self, String> {
        Self::acquire_within(data_dir, lock_file_name, DATA_DIR_LOCK_WAIT)
    }

    /// [`Self::acquire`] with a caller-chosen wait, for locks whose holders
    /// legitimately keep them longer than the 10 s default (a send that is
    /// waiting on the network, say). Same lock file and same failure text.
    pub fn acquire_within(
        data_dir: &Path,
        lock_file_name: &str,
        wait: Duration,
    ) -> Result<Self, String> {
        // Creates/tightens the owner-only data dir, then a 0600 lock file.
        let path = data_dir.join(lock_file_name);
        let connection = open_private_data_dir_sqlite(&path).map_err(|e| e.to_string())?;
        connection.busy_timeout(wait).map_err(|e| e.to_string())?;
        connection
            .execute_batch("BEGIN EXCLUSIVE")
            .map_err(|e| format!("data-dir lock {lock_file_name}: {e}"))?;
        Ok(Self {
            _connection: connection,
        })
    }
}

/// Temp name for [`atomic_write_private`]. It must never depend on the file
/// contents (often secret key material): a directory listing would otherwise
/// leak secret bits. The suffix is 64 bits from the OS CSPRNG.
fn private_temp_path(parent: &Path, path: &Path) -> PathBuf {
    use rand::RngCore;
    parent.join(format!(
        ".{}.tmp.{:016x}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("raven"),
        rand::rngs::OsRng.next_u64()
    ))
}

/// Flush a directory entry after a rename or create has already committed.
///
/// Best effort on purpose, and the single policy for every atomic writer: the
/// new file is complete and in place by now, so a failing directory fsync (a
/// filesystem that cannot fsync a directory, such as some SMB / exFAT / FUSE
/// mounts) must not turn a finished write into a reported failure that callers
/// then retry forever. The file's own contents were fsynced before the rename,
/// so the worst case after a crash is the previous complete file, never a torn
/// one. A no-op on non-Unix targets.
pub fn sync_dir_best_effort(dir: &Path) {
    #[cfg(unix)]
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Atomically replace `path` (temp + rename) with owner-only mode on Unix.
/// On Windows the temp file is created exclusively, synced, then renamed over
/// the destination (MoveFileEx REPLACE_EXISTING) — never a torn partial write.
pub fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "atomic write: missing parent".to_string())?;
    create_private_parents(parent)?;
    let tmp = private_temp_path(parent, path);

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let write = (|| -> Result<(), String> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| e.to_string())?;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
            f.write_all(contents).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            Ok(())
        })();
        if let Err(e) = write {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.to_string());
        }
        sync_dir_best_effort(parent);
        Ok(())
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let write = (|| -> Result<(), String> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| e.to_string())?;
            f.write_all(contents).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            Ok(())
        })();
        if let Err(e) = write {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.to_string());
        }
        Ok(())
    }
}

/// Create `path` exclusively with owner-only mode on Unix. Fails when the file
/// already exists. First-install writes of secret material must use this —
/// never a replace-capable write.
pub fn create_new_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "create-new write: missing parent".to_string())?;
    create_private_parents(parent)?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        if let Err(e) = (|| -> Result<(), String> {
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
            f.write_all(contents).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            Ok(())
        })() {
            let _ = std::fs::remove_file(path);
            return Err(e);
        }
        sync_dir_best_effort(parent);
        Ok(())
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        if let Err(e) = (|| -> Result<(), String> {
            f.write_all(contents).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            Ok(())
        })() {
            let _ = std::fs::remove_file(path);
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raven_env_wins_over_ash_and_home() {
        let p = resolve_raven_data_dir(
            Some(PathBuf::from("/explicit/raven")),
            Some(PathBuf::from("/explicit/ash")),
            Some(PathBuf::from("/home/u")),
        );
        assert_eq!(p, PathBuf::from("/explicit/raven"));
    }

    #[test]
    fn ash_env_wins_when_raven_env_absent() {
        let p = resolve_raven_data_dir(
            None,
            Some(PathBuf::from("/explicit/ash")),
            Some(PathBuf::from("/home/u")),
        );
        assert_eq!(p, PathBuf::from("/explicit/ash"));
    }

    #[test]
    fn empty_env_values_are_ignored() {
        let home = tempfile::tempdir().unwrap();
        let p = resolve_raven_data_dir(
            Some(PathBuf::from("")),
            Some(PathBuf::from("")),
            Some(home.path().to_path_buf()),
        );
        assert_eq!(p, home.path().join(".raven"));
    }

    #[test]
    fn keeps_existing_raven_ash_when_raven_absent() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".raven-ash")).unwrap();
        let p = resolve_raven_data_dir(None, None, Some(home.path().to_path_buf()));
        assert_eq!(p, home.path().join(".raven-ash"));
    }

    #[test]
    fn prefers_raven_when_both_exist() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".raven-ash")).unwrap();
        std::fs::create_dir(home.path().join(".raven")).unwrap();
        let p = resolve_raven_data_dir(None, None, Some(home.path().to_path_buf()));
        assert_eq!(p, home.path().join(".raven"));
    }

    #[test]
    fn defaults_to_raven_when_neither_exists() {
        let home = tempfile::tempdir().unwrap();
        let p = resolve_raven_data_dir(None, None, Some(home.path().to_path_buf()));
        assert_eq!(p, home.path().join(".raven"));
    }

    /// A missing HOME used to resolve to the working-directory-relative
    /// `./raven-data`, silently giving every working directory its own
    /// identity, history and queue.
    #[test]
    fn missing_home_is_never_a_cwd_relative_profile() {
        let p = resolve_raven_data_dir(None, None, None);
        assert!(p.is_absolute(), "{p:?}");
        assert!(is_unresolved_data_dir(&p), "{p:?}");
        let err = try_resolve_raven_data_dir(None, None, None).unwrap_err();
        assert!(
            err.contains("HOME") && err.contains("RAVEN_DATA_DIR"),
            "{err}"
        );
        // The placeholder can never be created or written into.
        let err = ensure_private_dir(&p).unwrap_err();
        assert!(err.contains("RAVEN_DATA_DIR"), "{err}");
        assert!(atomic_write_private(&p.join("x.json"), b"{}").is_err());
        assert!(open_private_sqlite(&p.join("q.sqlite")).is_err());
        assert!(DataDirLock::acquire(&p, ".probe.lock.sqlite").is_err());
    }

    #[test]
    fn empty_or_relative_home_counts_as_missing() {
        for home in [
            PathBuf::from(""),
            PathBuf::from("."),
            PathBuf::from("rel/home"),
        ] {
            let p = resolve_raven_data_dir(None, None, Some(home.clone()));
            assert!(is_unresolved_data_dir(&p), "{home:?} -> {p:?}");
            assert!(try_resolve_raven_data_dir(None, None, Some(home)).is_err());
        }
    }

    #[test]
    fn explicit_data_dir_does_not_need_home() {
        let p = try_resolve_raven_data_dir(Some(PathBuf::from("/explicit/raven")), None, None);
        assert_eq!(p.unwrap(), PathBuf::from("/explicit/raven"));
        let p = try_resolve_raven_data_dir(None, Some(PathBuf::from("/explicit/ash")), None);
        assert_eq!(p.unwrap(), PathBuf::from("/explicit/ash"));
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contacts.json");
        atomic_write_private(&path, b"[]").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"[]");
    }

    #[test]
    fn create_new_private_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.seed");
        create_new_private(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert!(create_new_private(&path, b"second").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn atomic_temp_names_come_from_csprng_not_contents() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("device_x25519.secret");
        let names: std::collections::HashSet<PathBuf> = (0..64)
            .map(|_| private_temp_path(dir.path(), &target))
            .collect();
        assert_eq!(names.len(), 64, "temp suffixes must be random per call");
        // Same secret written twice leaves no content-derived temp behind.
        atomic_write_private(&target, &[0x42; 32]).unwrap();
        atomic_write_private(&target, &[0x42; 32]).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn data_dir_is_created_and_tightened_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let fresh = root.path().join("a").join("raven");
        ensure_private_dir(&fresh).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&fresh), 0o700);

        let legacy = root.path().join("legacy");
        std::fs::create_dir(&legacy).unwrap();
        std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _lock = DataDirLock::acquire(&legacy, ".probe.lock.sqlite").unwrap();
        assert_eq!(
            mode(&legacy),
            0o700,
            "existing data dir must lose group/other access"
        );
        assert_eq!(mode(&legacy.join(".probe.lock.sqlite")), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_never_chmods_an_existing_user_chosen_parent() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let export_dir = root.path().join("Desktop");
        std::fs::create_dir(&export_dir).unwrap();
        std::fs::set_permissions(&export_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        atomic_write_private(&export_dir.join("prekey.json"), b"{}").unwrap();
        assert_eq!(
            std::fs::metadata(&export_dir).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let created = root.path().join("new").join("nested");
        atomic_write_private(&created.join("x.json"), b"{}").unwrap();
        assert_eq!(
            std::fs::metadata(&created).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_sqlite_database_and_sidecars_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.sqlite");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        {
            let conn = open_private_sqlite(&path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=WAL; CREATE TABLE t(x); INSERT INTO t VALUES (1);",
            )
            .unwrap();
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(&sqlite_sidecar(&path, "-wal")), 0o600);
            assert_eq!(mode(&sqlite_sidecar(&path, "-shm")), 0o600);
        }
        // Files left world-readable by an older build are tightened on open.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let stale_wal = sqlite_sidecar(&path, "-wal");
        if stale_wal.exists() {
            std::fs::set_permissions(&stale_wal, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let _conn = open_private_sqlite(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        if stale_wal.exists() {
            assert_eq!(mode(&stale_wal), 0o600);
        }
    }

    /// A database path chosen by the caller (`--forward-db`) must never cost an
    /// existing directory its permissions: not a shared scratch dir (root would
    /// turn /tmp from 1777 into 1700), not a user dir such as `~/Documents` or
    /// a group project dir. Only the data-dir flavour locks its directory.
    #[cfg(unix)]
    #[test]
    fn private_sqlite_never_chmods_an_existing_caller_chosen_parent() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        let chmod = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
        };

        for (name, dir_mode) in [
            ("scratch", 0o1777),
            ("Documents", 0o755),
            ("project", 0o775),
        ] {
            let dir = root.path().join(name);
            std::fs::create_dir(&dir).unwrap();
            chmod(&dir, dir_mode);
            drop(open_private_sqlite(&dir.join("fwd.sqlite")).unwrap());
            assert_eq!(mode(&dir), dir_mode, "{name} must be left alone");
            assert_eq!(mode(&dir.join("fwd.sqlite")), 0o600, "{name}");
        }

        // Missing parents are still created owner-only.
        let nested = root.path().join("new").join("dir");
        drop(open_private_sqlite(&nested.join("fwd.sqlite")).unwrap());
        assert_eq!(mode(&nested), 0o700);
        assert_eq!(mode(&root.path().join("new")), 0o700);

        // The data-dir flavour tightens an existing directory, even a shared
        // one: private state must not be kept in a shared directory.
        let shared = root.path().join("scratch");
        chmod(&shared, 0o1777);
        drop(open_private_data_dir_sqlite(&shared.join("lock.sqlite")).unwrap());
        assert_eq!(mode(&shared) & 0o777, 0o700);
        let profile = root.path().join("Documents");
        chmod(&profile, 0o755);
        drop(open_private_data_dir_sqlite(&profile.join("queue.sqlite")).unwrap());
        assert_eq!(mode(&profile), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn private_sqlite_refuses_symlinked_database() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("elsewhere.sqlite");
        std::fs::write(&real, b"").unwrap();
        let link = dir.path().join("queue.sqlite");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(open_private_sqlite(&link).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_replaces_existing_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        atomic_write_private(&path, b"v1").unwrap();
        atomic_write_private(&path, b"v2-longer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"v2-longer");
    }
}
