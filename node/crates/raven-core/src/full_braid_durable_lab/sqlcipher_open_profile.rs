//! Frozen SQLCipher open profile for Full Braid Slice 3 Task 0A.4.
//!
//! This module remains lab-only and does not wire a production store. It owns
//! the order in which a connection is opened, hardened, keyed, verified, and
//! made available to the caller. No schema byte is interpreted before the
//! cipher and integrity gates succeed.

use rusqlite::config::DbConfig;
use rusqlite::{ffi, Connection, OpenFlags};
use std::ffi::{c_int, c_void};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

use super::{EXPECTED_CIPHER_VERSION, EXPECTED_CIPHER_VERSION_COMMUNITY, EXPECTED_SQLITE_VERSION};

pub const RAVEN_SQLCIPHER_PAGE_SIZE: i64 = 4096;
pub const RAVEN_SQLCIPHER_KDF_ITER: i64 = 256_000;
pub const RAVEN_SQLCIPHER_APP_GROUP_PLAINTEXT_HEADER_SIZE: i64 = 32;
pub const RAVEN_SQLCIPHER_TERMINAL_PLAINTEXT_HEADER_SIZE: i64 = 0;
pub const RAVEN_SQLCIPHER_RESERVED_BYTES: u8 = 80;
pub const RAVEN_SQLCIPHER_BUSY_TIMEOUT_MS: i64 = 5_000;
pub const RAVEN_SQLCIPHER_HMAC_ALGORITHM: &str = "HMAC_SHA512";
pub const RAVEN_SQLCIPHER_KDF_ALGORITHM: &str = "PBKDF2_HMAC_SHA512";
pub const RAVEN_SQLCIPHER_SOURCE_SHA256: &str =
    "8adaff6b464052a74e7adaa3cfa2725400f48eca68f47856fa806eaf30bdf2c9";
/// `PRAGMA fullfsync` / `checkpoint_fullfsync` are set and verified on Apple
/// targets only (macOS and iOS share this profile).
const APPLE_FULLFSYNC: bool = cfg!(target_vendor = "apple");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RavenSqlCipherProfileV1 {
    pub cipher_version: String,
    pub sqlite_version: String,
    pub sqlite_source_id: String,
    pub provider_name: String,
    pub provider_version: String,
    pub compile_options: Vec<String>,
    pub cipher_page_size: i64,
    pub cipher_hmac_algorithm: String,
    pub cipher_kdf_algorithm: String,
    pub cipher_use_hmac: bool,
    pub cipher_plaintext_header_size: i64,
    pub cipher_memory_security: bool,
    pub journal_mode: String,
    pub synchronous: i64,
    pub foreign_keys: bool,
    pub temp_store: i64,
    pub mmap_size: i64,
    pub locking_mode: String,
    pub busy_timeout_ms: i64,
    pub target_triple: String,
    pub build_mode: String,
    pub source_digest_sha256: String,
    pub consumer_sqlite_has_codec: bool,
    pub final_image_owner: String,
}

enum RavenSqlCipherHeaderProfile {
    IosAppGroup { salt: [u8; 16] },
    Terminal,
}

/// Raw SQLCipher material with an explicit platform profile.
///
/// It deliberately implements neither `Debug` nor `Clone` and wipes on drop.
pub struct RavenSqlCipherRawKey {
    key: [u8; 32],
    profile: RavenSqlCipherHeaderProfile,
}

impl RavenSqlCipherRawKey {
    /// Takes the key by reference: the only copy made is the one this value
    /// owns and wipes on drop (a by-value `[u8; 32]` would leave the caller's
    /// copy behind).
    pub fn ios_app_group(key: &[u8; 32], salt: [u8; 16]) -> Self {
        Self {
            key: *key,
            profile: RavenSqlCipherHeaderProfile::IosAppGroup { salt },
        }
    }

    /// See [`Self::ios_app_group`] on why the key is borrowed.
    pub fn terminal(key: &[u8; 32]) -> Self {
        Self {
            key: *key,
            profile: RavenSqlCipherHeaderProfile::Terminal,
        }
    }

    fn plaintext_header_size(&self) -> i64 {
        match self.profile {
            RavenSqlCipherHeaderProfile::IosAppGroup { .. } => {
                RAVEN_SQLCIPHER_APP_GROUP_PLAINTEXT_HEADER_SIZE
            }
            RavenSqlCipherHeaderProfile::Terminal => RAVEN_SQLCIPHER_TERMINAL_PLAINTEXT_HEADER_SIZE,
        }
    }

    fn uses_public_header(&self) -> bool {
        matches!(
            self.profile,
            RavenSqlCipherHeaderProfile::IosAppGroup { .. }
        )
    }

    fn raw_key_literal(&self) -> Zeroizing<Vec<u8>> {
        let salt_len = match self.profile {
            RavenSqlCipherHeaderProfile::IosAppGroup { .. } => 16,
            RavenSqlCipherHeaderProfile::Terminal => 0,
        };
        let mut out = Zeroizing::new(Vec::with_capacity(3 + 2 * (32 + salt_len)));
        out.extend_from_slice(b"x'");
        for byte in &self.key {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.push(HEX[(byte >> 4) as usize]);
            out.push(HEX[(byte & 0x0f) as usize]);
        }
        if let RavenSqlCipherHeaderProfile::IosAppGroup { salt } = &self.profile {
            for byte in salt {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.push(HEX[(byte >> 4) as usize]);
                out.push(HEX[(byte & 0x0f) as usize]);
            }
        }
        out.push(b'\'');
        out
    }
}

impl Drop for RavenSqlCipherRawKey {
    fn drop(&mut self) {
        self.key.zeroize();
        if let RavenSqlCipherHeaderProfile::IosAppGroup { salt } = &mut self.profile {
            salt.zeroize();
        }
    }
}

/// Proof that a CREATE open is operating on an absent final component under
/// an already-existing, canonical directory. The proof is rechecked at open.
pub struct RavenSqlCipherFirstInstallProof {
    canonical_path: PathBuf,
}

impl RavenSqlCipherFirstInstallProof {
    pub fn acquire(path: &Path) -> Result<Self, RavenSqlCipherOpenError> {
        let canonical_path = validate_new_path(path)?;
        Ok(Self { canonical_path })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RavenSqlCipherOpenError {
    #[error("SQLCIPHER_PATH_REJECTED:{0}")]
    PathRejected(&'static str),
    #[error("SQLCIPHER_FIRST_INSTALL_PROOF_STALE")]
    FirstInstallProofStale,
    #[error("SQLCIPHER_SQLITE_ERROR:{stage}:{code}")]
    Sqlite { stage: &'static str, code: i32 },
    #[error("SQLCIPHER_PROFILE_MISMATCH:{0}")]
    ProfileMismatch(&'static str),
    #[error("SQLCIPHER_INTEGRITY_FAILED:{0}")]
    IntegrityFailed(&'static str),
    #[error("SQLCIPHER_TEMP_DIRECTORY_REJECTED")]
    TempDirectoryRejected,
    #[error("SQLCIPHER_TEMP_FILE_CREATED")]
    TempFileCreated,
    #[error("SQLCIPHER_PLAINTEXT_SENTINEL_FOUND")]
    PlaintextSentinelFound,
}

pub struct RavenSqlCipherConnection {
    connection: Connection,
    report: RavenSqlCipherProfileV1,
    canonical_path: PathBuf,
}

impl RavenSqlCipherConnection {
    pub fn create(
        proof: RavenSqlCipherFirstInstallProof,
        key: &RavenSqlCipherRawKey,
    ) -> Result<Self, RavenSqlCipherOpenError> {
        // Exclusive, owner-only pre-creation closes the exists()→open window:
        // a file planted in between fails `create_new` instead of SQLite
        // adopting a foreign inode or mode. SQLite gives new -wal/-shm files
        // the database file's mode, so the whole triplet ends up 0600.
        precreate_private_database(&proof.canonical_path)?;
        let opened = open_profile(proof.canonical_path.clone(), key);
        if opened.is_err() {
            remove_if_still_empty(&proof.canonical_path);
        }
        opened
    }

    pub fn open_existing(
        path: &Path,
        key: &RavenSqlCipherRawKey,
    ) -> Result<Self, RavenSqlCipherOpenError> {
        let path = validate_existing_path(path, key.uses_public_header())?;
        open_profile(path, key)
    }

    pub fn report(&self) -> &RavenSqlCipherProfileV1 {
        &self.report
    }

    /// Lab-only access after the complete open-profile gate has passed.
    pub fn connection_for_lab(&self) -> &Connection {
        &self.connection
    }

    pub fn canonical_path_for_lab(&self) -> &Path {
        &self.canonical_path
    }

    /// `PRAGMA wal_checkpoint(TRUNCATE)` reports a blocked checkpoint as a
    /// `busy=1` result row, not as an error. Fail closed on it: callers hash
    /// or snapshot the main file after this returns, and a checkpoint that a
    /// concurrent reader blocked left that file behind the WAL. The busy
    /// timeout already retried, so there is no retry loop here.
    pub fn checkpoint_truncate(&self) -> Result<(), RavenSqlCipherOpenError> {
        let busy: i64 = self
            .connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .map_err(|error| sqlite_error("checkpoint", error))?;
        if busy != 0 {
            return Err(RavenSqlCipherOpenError::Sqlite {
                stage: "checkpoint_busy",
                code: ffi::SQLITE_BUSY,
            });
        }
        Ok(())
    }

    pub fn reverify_profile_for_lab(
        &self,
    ) -> Result<RavenSqlCipherProfileV1, RavenSqlCipherOpenError> {
        let verified = verify_cipher_profile_and_integrity(
            &self.connection,
            self.report.cipher_plaintext_header_size,
        )?;
        verify_runtime_and_build_report(&self.connection, verified)
    }
}

/// Never passes SQLITE_OPEN_CREATE: first install pre-creates the file
/// exclusively (see `RavenSqlCipherConnection::create`), so SQLite never
/// creates a database file itself.
fn open_profile(
    canonical_path: PathBuf,
    key: &RavenSqlCipherRawKey,
) -> Result<RavenSqlCipherConnection, RavenSqlCipherOpenError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_FULL_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_EXRESCODE;
    let connection = Connection::open_with_flags(&canonical_path, flags)
        .map_err(|error| sqlite_error("open", error))?;

    harden_connection_before_key(&connection)?;
    apply_raw_key_and_cipher_profile(&connection, key)?;
    let verified_cipher =
        verify_cipher_profile_and_integrity(&connection, key.plaintext_header_size())?;
    configure_post_integrity_security(&connection)?;
    configure_runtime_profile(&connection)?;
    let report = verify_runtime_and_build_report(&connection, verified_cipher)?;

    Ok(RavenSqlCipherConnection {
        connection,
        report,
        canonical_path,
    })
}

fn harden_connection_before_key(connection: &Connection) -> Result<(), RavenSqlCipherOpenError> {
    // ENABLE_LOAD_EXTENSION is intentionally not exposed by rusqlite's safe
    // DbConfig enum. Use sqlite3_db_config directly and verify the readback.
    let mut load_extensions = -1;
    let rc = unsafe {
        ffi::sqlite3_db_config(
            connection.handle(),
            ffi::SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION,
            0,
            &mut load_extensions,
        )
    };
    require_ffi_ok("disable_extensions", rc)?;
    if load_extensions != 0 {
        return Err(RavenSqlCipherOpenError::ProfileMismatch("load_extension"));
    }

    set_and_require_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA,
        false,
        "trusted_schema",
    )?;
    set_and_require_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_DEFENSIVE,
        true,
        "defensive",
    )?;
    set_and_require_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_DQS_DDL,
        false,
        "dqs_ddl",
    )?;
    set_and_require_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_DQS_DML,
        false,
        "dqs_dml",
    )?;

    // The flag is process-global, sticky, and off by default in SQLCipher
    // 4.17.0. Turn it on before the key is applied, so the page decryption
    // and the full integrity scan in the open path already run with
    // mlock-on-allocate and wipe-on-free. The pragma needs no keyed database;
    // verify_runtime_and_build_report still reads it back.
    connection
        .execute_batch("PRAGMA cipher_memory_security=ON;")
        .map_err(|error| sqlite_error("memory_security", error))?;
    Ok(())
}

fn set_and_require_db_config(
    connection: &Connection,
    config: DbConfig,
    expected: bool,
    field: &'static str,
) -> Result<(), RavenSqlCipherOpenError> {
    let applied = connection
        .set_db_config(config, expected)
        .map_err(|error| sqlite_error("db_config", error))?;
    let readback = connection
        .db_config(config)
        .map_err(|error| sqlite_error("db_config_read", error))?;
    if applied != expected || readback != expected {
        return Err(RavenSqlCipherOpenError::ProfileMismatch(field));
    }
    Ok(())
}

fn apply_raw_key_and_cipher_profile(
    connection: &Connection,
    key: &RavenSqlCipherRawKey,
) -> Result<(), RavenSqlCipherOpenError> {
    let literal = key.raw_key_literal();
    let rc = unsafe {
        extern "C" {
            fn sqlite3_key(db: *mut c_void, key: *const c_void, key_len: c_int) -> c_int;
        }
        sqlite3_key(
            connection.handle().cast::<c_void>(),
            literal.as_ptr().cast::<c_void>(),
            literal.len() as c_int,
        )
    };
    require_ffi_ok("key", rc)?;

    // Fixed statements only. Dynamic key bytes never enter SQL text.
    let profile = format!(
        "PRAGMA cipher_page_size=4096;
         PRAGMA kdf_iter=256000;
         PRAGMA cipher_hmac_algorithm=HMAC_SHA512;
         PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512;
         PRAGMA cipher_use_hmac=ON;
         PRAGMA cipher_plaintext_header_size={};",
        key.plaintext_header_size()
    );
    connection
        .execute_batch(&profile)
        .map_err(|error| sqlite_error("cipher_profile", error))?;
    Ok(())
}

fn configure_post_integrity_security(
    connection: &Connection,
) -> Result<(), RavenSqlCipherOpenError> {
    connection
        .execute_batch(
            "PRAGMA cipher_log='off';
             PRAGMA cipher_log_level='NONE';",
        )
        .map_err(|error| sqlite_error("post_integrity_security", error))?;
    Ok(())
}

fn configure_runtime_profile(connection: &Connection) -> Result<(), RavenSqlCipherOpenError> {
    connection
        .busy_timeout(Duration::from_millis(
            RAVEN_SQLCIPHER_BUSY_TIMEOUT_MS as u64,
        ))
        .map_err(|error| sqlite_error("busy_timeout", error))?;
    connection
        .execute_batch(
            "PRAGMA temp_store=MEMORY;
             PRAGMA mmap_size=0;
             PRAGMA locking_mode=NORMAL;
             PRAGMA foreign_keys=ON;
             PRAGMA synchronous=FULL;",
        )
        .map_err(|error| sqlite_error("runtime_profile", error))?;
    // Profile revision (additive, Apple only): `synchronous=FULL` alone does
    // not make a commit power-loss durable on macOS/iOS. Plain fsync does not
    // flush the drive cache there, and SQLite issues F_FULLFSYNC only for
    // `fullfsync` (commits) / `checkpoint_fullfsync` (checkpoints). The anchor
    // update is ordered after the SQLite commit, so an unflushed commit would
    // leave the container behind its anchor. No-ops elsewhere, so not set.
    if APPLE_FULLFSYNC {
        connection
            .execute_batch("PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON;")
            .map_err(|error| sqlite_error("fullfsync", error))?;
    }
    // Last: the journal-mode switch commits through the settings above.
    connection
        .execute_batch("PRAGMA journal_mode=WAL;")
        .map_err(|error| sqlite_error("journal_mode", error))?;
    Ok(())
}

struct VerifiedCipherProfile {
    cipher_version: String,
    sqlite_version: String,
    sqlite_source_id: String,
    provider_name: String,
    provider_version: String,
    compile_options: Vec<String>,
    cipher_page_size: i64,
    cipher_hmac_algorithm: String,
    cipher_kdf_algorithm: String,
    cipher_plaintext_header_size: i64,
}

fn verify_cipher_profile_and_integrity(
    connection: &Connection,
    expected_plaintext_header_size: i64,
) -> Result<VerifiedCipherProfile, RavenSqlCipherOpenError> {
    let cipher_version = pragma_string(connection, "cipher_version", "cipher_version")?;
    if cipher_version != EXPECTED_CIPHER_VERSION
        && cipher_version != EXPECTED_CIPHER_VERSION_COMMUNITY
    {
        return Err(RavenSqlCipherOpenError::ProfileMismatch("cipher_version"));
    }
    let sqlite_version: String = connection
        .query_row("SELECT sqlite_version()", [], |row| row.get(0))
        .map_err(|error| sqlite_error("sqlite_version", error))?;
    if sqlite_version != EXPECTED_SQLITE_VERSION {
        return Err(RavenSqlCipherOpenError::ProfileMismatch("sqlite_version"));
    }
    let sqlite_source_id: String = connection
        .query_row("SELECT sqlite_source_id()", [], |row| row.get(0))
        .map_err(|error| sqlite_error("sqlite_source_id", error))?;
    let provider_name = pragma_string(connection, "cipher_provider", "provider")?.to_lowercase();
    if provider_name != "openssl" {
        return Err(RavenSqlCipherOpenError::ProfileMismatch("provider"));
    }
    let provider_version =
        pragma_string(connection, "cipher_provider_version", "provider_version")?;
    let status = pragma_i64(connection, "cipher_status", "cipher_status")?;
    if status != 1 {
        return Err(RavenSqlCipherOpenError::ProfileMismatch("cipher_status"));
    }

    let cipher_page_size = pragma_i64(connection, "cipher_page_size", "page_size")?;
    require_i64(
        "cipher_page_size",
        cipher_page_size,
        RAVEN_SQLCIPHER_PAGE_SIZE,
    )?;
    let kdf_iter = pragma_i64(connection, "kdf_iter", "kdf_iter")?;
    require_i64("kdf_iter", kdf_iter, RAVEN_SQLCIPHER_KDF_ITER)?;
    let cipher_hmac_algorithm =
        pragma_string(connection, "cipher_hmac_algorithm", "hmac_algorithm")?;
    require_string(
        "cipher_hmac_algorithm",
        &cipher_hmac_algorithm,
        RAVEN_SQLCIPHER_HMAC_ALGORITHM,
    )?;
    let cipher_kdf_algorithm = pragma_string(connection, "cipher_kdf_algorithm", "kdf_algorithm")?;
    require_string(
        "cipher_kdf_algorithm",
        &cipher_kdf_algorithm,
        RAVEN_SQLCIPHER_KDF_ALGORITHM,
    )?;
    let cipher_use_hmac = pragma_i64(connection, "cipher_use_hmac", "use_hmac")?;
    require_i64("cipher_use_hmac", cipher_use_hmac, 1)?;
    let cipher_plaintext_header_size = pragma_i64(
        connection,
        "cipher_plaintext_header_size",
        "plaintext_header",
    )?;
    require_i64(
        "cipher_plaintext_header_size",
        cipher_plaintext_header_size,
        expected_plaintext_header_size,
    )?;

    let mut compile_options = pragma_rows(connection, "compile_options", "compile_options")?;
    compile_options.sort();
    if !compile_options
        .iter()
        .any(|option| option == "TEMP_STORE=2" || option == "SQLITE_TEMP_STORE=2")
    {
        return Err(RavenSqlCipherOpenError::ProfileMismatch(
            "temp_store_compile",
        ));
    }

    let cipher_integrity = pragma_rows(connection, "cipher_integrity_check", "cipher_integrity")?;
    if !cipher_integrity.is_empty() {
        return Err(RavenSqlCipherOpenError::IntegrityFailed("cipher"));
    }
    // This is the first deliberate schema interpretation in the open path.
    let _: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .map_err(|error| sqlite_error("schema_gate", error))?;
    let integrity = pragma_rows(connection, "integrity_check", "integrity")?;
    if integrity.as_slice() != ["ok"] {
        return Err(RavenSqlCipherOpenError::IntegrityFailed("sqlite"));
    }

    Ok(VerifiedCipherProfile {
        cipher_version,
        sqlite_version,
        sqlite_source_id,
        provider_name,
        provider_version,
        compile_options,
        cipher_page_size,
        cipher_hmac_algorithm,
        cipher_kdf_algorithm,
        cipher_plaintext_header_size,
    })
}

fn verify_runtime_and_build_report(
    connection: &Connection,
    verified: VerifiedCipherProfile,
) -> Result<RavenSqlCipherProfileV1, RavenSqlCipherOpenError> {
    let cipher_memory_security =
        pragma_i64(connection, "cipher_memory_security", "memory_security")?;
    require_i64("cipher_memory_security", cipher_memory_security, 1)?;
    let journal_mode = pragma_string(connection, "journal_mode", "journal_mode")?.to_lowercase();
    require_string("journal_mode", &journal_mode, "wal")?;
    let synchronous = pragma_i64(connection, "synchronous", "synchronous")?;
    require_i64("synchronous", synchronous, 2)?;
    if APPLE_FULLFSYNC {
        let fullfsync = pragma_i64(connection, "fullfsync", "fullfsync")?;
        require_i64("fullfsync", fullfsync, 1)?;
        let checkpoint_fullfsync =
            pragma_i64(connection, "checkpoint_fullfsync", "checkpoint_fullfsync")?;
        require_i64("checkpoint_fullfsync", checkpoint_fullfsync, 1)?;
    }
    let foreign_keys = pragma_i64(connection, "foreign_keys", "foreign_keys")?;
    require_i64("foreign_keys", foreign_keys, 1)?;
    let temp_store = pragma_i64(connection, "temp_store", "temp_store")?;
    require_i64("temp_store", temp_store, 2)?;
    let mmap_size = pragma_i64(connection, "mmap_size", "mmap_size")?;
    require_i64("mmap_size", mmap_size, 0)?;
    let locking_mode = pragma_string(connection, "locking_mode", "locking_mode")?.to_lowercase();
    require_string("locking_mode", &locking_mode, "normal")?;
    let busy_timeout_ms = pragma_i64(connection, "busy_timeout", "busy_timeout")?;
    require_i64(
        "busy_timeout",
        busy_timeout_ms,
        RAVEN_SQLCIPHER_BUSY_TIMEOUT_MS,
    )?;

    Ok(RavenSqlCipherProfileV1 {
        cipher_version: verified.cipher_version,
        sqlite_version: verified.sqlite_version,
        sqlite_source_id: verified.sqlite_source_id,
        provider_name: verified.provider_name,
        provider_version: verified.provider_version,
        compile_options: verified.compile_options,
        cipher_page_size: verified.cipher_page_size,
        cipher_hmac_algorithm: verified.cipher_hmac_algorithm,
        cipher_kdf_algorithm: verified.cipher_kdf_algorithm,
        cipher_use_hmac: true,
        cipher_plaintext_header_size: verified.cipher_plaintext_header_size,
        cipher_memory_security: true,
        journal_mode,
        synchronous,
        foreign_keys: true,
        temp_store,
        mmap_size,
        locking_mode,
        busy_timeout_ms,
        target_triple: env!("RAVEN_BUILD_TARGET").to_owned(),
        build_mode: env!("RAVEN_BUILD_PROFILE").to_owned(),
        source_digest_sha256: RAVEN_SQLCIPHER_SOURCE_SHA256.to_owned(),
        consumer_sqlite_has_codec: true,
        final_image_owner: "libsqlite3-sys-raven".to_owned(),
    })
}

pub fn run_temp_store_probe(
    opened: &RavenSqlCipherConnection,
    dedicated_empty_dir: &Path,
) -> Result<(), RavenSqlCipherOpenError> {
    let canonical = validate_empty_temp_dir(dedicated_empty_dir)?;
    let quoted = canonical
        .to_str()
        .ok_or(RavenSqlCipherOpenError::TempDirectoryRejected)?
        .replace('\'', "''");
    opened
        .connection
        .execute_batch(&format!("PRAGMA temp_store_directory='{quoted}';"))
        .map_err(|error| sqlite_error("temp_directory", error))?;
    opened
        .connection
        .execute_batch(
            "CREATE TEMP TABLE raven_temp_probe(v BLOB NOT NULL);
             WITH RECURSIVE seq(x) AS (
               VALUES(1) UNION ALL SELECT x+1 FROM seq WHERE x < 4096
             ) INSERT INTO raven_temp_probe(v) SELECT randomblob(1024) FROM seq;
             SELECT length(v) FROM raven_temp_probe ORDER BY v;
             DROP TABLE raven_temp_probe;",
        )
        .map_err(|error| sqlite_error("temp_workload", error))?;
    if fs::read_dir(&canonical)
        .map_err(|_| RavenSqlCipherOpenError::TempDirectoryRejected)?
        .next()
        .is_some()
    {
        return Err(RavenSqlCipherOpenError::TempFileCreated);
    }
    Ok(())
}

pub fn scan_profile_files_for_plaintext(
    database_path: &Path,
    temp_directory: &Path,
    sentinel: &[u8],
) -> Result<(), RavenSqlCipherOpenError> {
    if sentinel.len() < 32 {
        return Err(RavenSqlCipherOpenError::PathRejected("sentinel"));
    }
    // Fail closed: a scan that inspected nothing must not read as "no
    // plaintext". The main file must be readable; only the sidecars (gone
    // after a TRUNCATE checkpoint) and temp entries that vanish mid-scan may
    // be absent. Any other read error, or an unreadable temp directory, fails.
    let mut candidates = vec![(database_path.to_path_buf(), true)];
    for suffix in ["-wal", "-shm"] {
        candidates.push((sidecar_path(database_path, suffix), false));
    }
    let mut directories = vec![temp_directory.to_path_buf()];
    while let Some(directory) = directories.pop() {
        let entries =
            fs::read_dir(&directory).map_err(|_| RavenSqlCipherOpenError::TempDirectoryRejected)?;
        for entry in entries {
            let entry = entry.map_err(|_| RavenSqlCipherOpenError::TempDirectoryRejected)?;
            match entry.file_type() {
                Ok(file_type) if file_type.is_dir() => directories.push(entry.path()),
                Ok(_) => candidates.push((entry.path(), false)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(RavenSqlCipherOpenError::TempDirectoryRejected),
            }
        }
    }
    for (candidate, required) in candidates {
        match fs::read(&candidate) {
            Ok(bytes) => {
                if bytes
                    .windows(sentinel.len())
                    .any(|window| window == sentinel)
                {
                    return Err(RavenSqlCipherOpenError::PlaintextSentinelFound);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if required {
                    return Err(RavenSqlCipherOpenError::PathRejected("scan_missing"));
                }
            }
            Err(_) => return Err(RavenSqlCipherOpenError::PathRejected("scan_read")),
        }
    }
    Ok(())
}

fn precreate_private_database(path: &Path) -> Result<(), RavenSqlCipherOpenError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(RavenSqlCipherOpenError::FirstInstallProofStale)
        }
        Err(_) => Err(RavenSqlCipherOpenError::PathRejected("create")),
    }
}

/// Undo our own pre-creation after a failed first open, never anything else.
fn remove_if_still_empty(path: &Path) {
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file() && metadata.len() == 0)
        .unwrap_or(false)
    {
        let _ = fs::remove_file(path);
    }
}

fn validate_new_path(path: &Path) -> Result<PathBuf, RavenSqlCipherOpenError> {
    reject_unsafe_path_shape(path)?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(RavenSqlCipherOpenError::PathRejected("exists"));
    }
    for suffix in ["-wal", "-shm"] {
        if fs::symlink_metadata(sidecar_path(path, suffix)).is_ok() {
            return Err(RavenSqlCipherOpenError::PathRejected("stale_sidecar"));
        }
    }
    canonicalize_parent(path)
}

fn validate_existing_path(
    path: &Path,
    require_public_header: bool,
) -> Result<PathBuf, RavenSqlCipherOpenError> {
    reject_unsafe_path_shape(path)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RavenSqlCipherOpenError::PathRejected("missing"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(RavenSqlCipherOpenError::PathRejected("metadata"));
    }
    // Only `create` may initialise an empty file. `open_profile` is that same
    // code path, so on a zero-byte file `open_existing` would key it, pass the
    // (trivially true) integrity gate and switch it to WAL: a truncated store
    // becomes a valid, empty, correctly keyed one and the evidence of the
    // loss is overwritten. Every store this profile wrote holds at least its
    // first full page, because the journal-mode switch commits page 1 to the
    // main file before the WAL exists.
    if metadata.len() == 0 {
        return Err(RavenSqlCipherOpenError::PathRejected("empty"));
    }
    if metadata.len() < RAVEN_SQLCIPHER_PAGE_SIZE as u64 {
        return Err(RavenSqlCipherOpenError::PathRejected("short"));
    }
    let canonical = canonicalize_parent(path)?;
    if require_public_header {
        validate_public_plaintext_header(&canonical)?;
    }
    validate_sidecar_binding(&canonical)?;
    Ok(canonical)
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

/// WAL header bytes the binding check reads (magic, version, page size, salts).
const WAL_HEAD_LEN: usize = 32;
/// Both 48-byte wal-index header copies at the start of `-shm`.
const SHM_HEAD_LEN: usize = 96;

/// First `max_len` bytes of a regular sidecar (all of it when shorter), so
/// `len() < max_len` means the sidecar's length is exactly `len()`.
fn read_regular_sidecar_head(
    path: &Path,
    max_len: usize,
) -> Result<Option<Vec<u8>>, RavenSqlCipherOpenError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(RavenSqlCipherOpenError::PathRejected("sidecar_metadata")),
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(RavenSqlCipherOpenError::PathRejected("sidecar_metadata"));
    }
    // Bounded: a WAL can be large and only its header is inspected.
    let mut head = Vec::with_capacity(max_len);
    fs::File::open(path)
        .and_then(|file| file.take(max_len as u64).read_to_end(&mut head))
        .map_err(|_| RavenSqlCipherOpenError::PathRejected("sidecar_read"))?;
    Ok(Some(head))
}

/// `-shm` is volatile: SQLite rebuilds the wal-index from the WAL whenever
/// its header is not valid. A file too short for both header copies, or
/// zero-filled there, has no header to bind. That is the state after power
/// loss before the mapped first page reached disk, or a crash right after
/// the file was created, and it cannot be a swapped foreign `-shm`.
fn shm_header_initialised(head: &[u8]) -> bool {
    head.len() >= SHM_HEAD_LEN && head.iter().any(|byte| *byte != 0)
}

/// A live writer in another process (`ash` and `raven-node` share these
/// files) can checkpoint-truncate or restart the WAL between the two sidecar
/// reads and produce a spurious mismatch. One immediate re-read separates
/// that from a sidecar pair that really disagrees.
fn validate_sidecar_binding(path: &Path) -> Result<(), RavenSqlCipherOpenError> {
    match check_sidecar_binding(path) {
        Err(RavenSqlCipherOpenError::ProfileMismatch(_)) => check_sidecar_binding(path),
        other => other,
    }
}

fn check_sidecar_binding(path: &Path) -> Result<(), RavenSqlCipherOpenError> {
    let wal = read_regular_sidecar_head(&sidecar_path(path, "-wal"), WAL_HEAD_LEN)?;
    let shm = read_regular_sidecar_head(&sidecar_path(path, "-shm"), SHM_HEAD_LEN)?;
    if shm.is_some() && wal.is_none() {
        return Err(RavenSqlCipherOpenError::ProfileMismatch("orphan_shm"));
    }
    let Some(wal) = wal else { return Ok(()) };
    let shm = shm.filter(|head| shm_header_initialised(head));
    if wal.is_empty() {
        let Some(shm) = shm else { return Ok(()) };
        for base in [0usize, 48] {
            if read_ne_u32(&shm, base) != 3_007_000
                || shm[base + 12] != 1
                || read_ne_u32(&shm, base + 16) != 0
            {
                return Err(RavenSqlCipherOpenError::ProfileMismatch(
                    "empty_wal_shm_binding",
                ));
            }
        }
        return Ok(());
    }
    if wal.len() < WAL_HEAD_LEN {
        return Err(RavenSqlCipherOpenError::ProfileMismatch("wal_header"));
    }
    let magic = read_be_u32(&wal, 0);
    let version = read_be_u32(&wal, 4);
    let page_size = read_be_u32(&wal, 8);
    if !matches!(magic, 0x377f_0682 | 0x377f_0683)
        || version != 3_007_000
        || page_size != RAVEN_SQLCIPHER_PAGE_SIZE as u32
    {
        return Err(RavenSqlCipherOpenError::ProfileMismatch("wal_header"));
    }
    let Some(shm) = shm else { return Ok(()) };
    for base in [0usize, 48] {
        let shm_version = read_ne_u32(&shm, base);
        let shm_page_size = read_ne_u16(&shm, base + 14) as u32;
        if shm_version != 3_007_000
            || shm[base + 12] != 1
            || shm_page_size != RAVEN_SQLCIPHER_PAGE_SIZE as u32
            || shm[base + 32..base + 40] != wal[16..24]
        {
            return Err(RavenSqlCipherOpenError::ProfileMismatch("wal_shm_binding"));
        }
    }
    Ok(())
}

fn read_be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from(bytes[offset]) << 24
        | u32::from(bytes[offset + 1]) << 16
        | u32::from(bytes[offset + 2]) << 8
        | u32::from(bytes[offset + 3])
}

fn read_ne_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_ne_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes([bytes[offset], bytes[offset + 1]])
}

fn validate_public_plaintext_header(path: &Path) -> Result<(), RavenSqlCipherOpenError> {
    let mut file =
        fs::File::open(path).map_err(|_| RavenSqlCipherOpenError::PathRejected("header"))?;
    let mut header = [0u8; RAVEN_SQLCIPHER_APP_GROUP_PLAINTEXT_HEADER_SIZE as usize];
    file.read_exact(&mut header)
        .map_err(|_| RavenSqlCipherOpenError::PathRejected("header"))?;
    if &header[..16] != b"SQLite format 3\0" {
        return Err(RavenSqlCipherOpenError::ProfileMismatch(
            "plaintext_header_magic",
        ));
    }
    let page_size = u16::from_be_bytes([header[16], header[17]]) as i64;
    if page_size != RAVEN_SQLCIPHER_PAGE_SIZE {
        return Err(RavenSqlCipherOpenError::ProfileMismatch(
            "plaintext_header_page_size",
        ));
    }
    if header[20] != RAVEN_SQLCIPHER_RESERVED_BYTES {
        return Err(RavenSqlCipherOpenError::ProfileMismatch(
            "plaintext_header_reserved",
        ));
    }
    if header[21..24] != [64, 32, 32] {
        return Err(RavenSqlCipherOpenError::ProfileMismatch(
            "plaintext_header_fractions",
        ));
    }
    Ok(())
}

fn reject_unsafe_path_shape(path: &Path) -> Result<(), RavenSqlCipherOpenError> {
    if !path.is_absolute() {
        return Err(RavenSqlCipherOpenError::PathRejected("relative"));
    }
    let value = path.to_string_lossy();
    if value.starts_with("file:") || value.contains('\0') {
        return Err(RavenSqlCipherOpenError::PathRejected("uri"));
    }
    if path.file_name().is_none() {
        return Err(RavenSqlCipherOpenError::PathRejected("filename"));
    }
    Ok(())
}

fn canonicalize_parent(path: &Path) -> Result<PathBuf, RavenSqlCipherOpenError> {
    let parent = path
        .parent()
        .ok_or(RavenSqlCipherOpenError::PathRejected("parent"))?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|_| RavenSqlCipherOpenError::PathRejected("parent"))?;
    let metadata = fs::symlink_metadata(&canonical_parent)
        .map_err(|_| RavenSqlCipherOpenError::PathRejected("parent"))?;
    if !metadata.is_dir() {
        return Err(RavenSqlCipherOpenError::PathRejected("parent"));
    }
    Ok(canonical_parent.join(
        path.file_name()
            .ok_or(RavenSqlCipherOpenError::PathRejected("filename"))?,
    ))
}

fn validate_empty_temp_dir(path: &Path) -> Result<PathBuf, RavenSqlCipherOpenError> {
    if !path.is_absolute() {
        return Err(RavenSqlCipherOpenError::TempDirectoryRejected);
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| RavenSqlCipherOpenError::TempDirectoryRejected)?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|_| RavenSqlCipherOpenError::TempDirectoryRejected)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(RavenSqlCipherOpenError::TempDirectoryRejected);
    }
    if fs::read_dir(&canonical)
        .map_err(|_| RavenSqlCipherOpenError::TempDirectoryRejected)?
        .next()
        .is_some()
    {
        return Err(RavenSqlCipherOpenError::TempDirectoryRejected);
    }
    Ok(canonical)
}

fn pragma_string(
    connection: &Connection,
    name: &'static str,
    stage: &'static str,
) -> Result<String, RavenSqlCipherOpenError> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(|error| sqlite_error(stage, error))
}

fn pragma_i64(
    connection: &Connection,
    name: &'static str,
    stage: &'static str,
) -> Result<i64, RavenSqlCipherOpenError> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| {
            use rusqlite::types::ValueRef;
            match row.get_ref(0)? {
                ValueRef::Integer(value) => Ok(value),
                ValueRef::Text(value) => std::str::from_utf8(value)
                    .ok()
                    .and_then(|text| text.parse::<i64>().ok())
                    .ok_or_else(|| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            "expected decimal pragma value".into(),
                        )
                    }),
                other => Err(rusqlite::Error::InvalidColumnType(
                    0,
                    name.to_owned(),
                    other.data_type(),
                )),
            }
        })
        .map_err(|error| sqlite_error(stage, error))
}

fn pragma_rows(
    connection: &Connection,
    name: &'static str,
    stage: &'static str,
) -> Result<Vec<String>, RavenSqlCipherOpenError> {
    let mut statement = connection
        .prepare(&format!("PRAGMA {name}"))
        .map_err(|error| sqlite_error(stage, error))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| sqlite_error(stage, error))?;
    let mut values = Vec::new();
    for row in rows {
        values.push(row.map_err(|error| sqlite_error(stage, error))?);
    }
    Ok(values)
}

fn require_i64(
    field: &'static str,
    actual: i64,
    expected: i64,
) -> Result<(), RavenSqlCipherOpenError> {
    if actual != expected {
        return Err(RavenSqlCipherOpenError::ProfileMismatch(field));
    }
    Ok(())
}

fn require_string(
    field: &'static str,
    actual: &str,
    expected: &str,
) -> Result<(), RavenSqlCipherOpenError> {
    if actual != expected {
        return Err(RavenSqlCipherOpenError::ProfileMismatch(field));
    }
    Ok(())
}

fn require_ffi_ok(stage: &'static str, code: c_int) -> Result<(), RavenSqlCipherOpenError> {
    if code != ffi::SQLITE_OK {
        return Err(RavenSqlCipherOpenError::Sqlite { stage, code });
    }
    Ok(())
}

fn sqlite_error(stage: &'static str, error: rusqlite::Error) -> RavenSqlCipherOpenError {
    let code = match error {
        rusqlite::Error::SqliteFailure(ref failure, _) => failure.extended_code,
        _ => -1,
    };
    RavenSqlCipherOpenError::Sqlite { stage, code }
}
