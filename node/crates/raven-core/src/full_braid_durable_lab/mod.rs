//! Task 0A.2 — Full Braid durable lab (SQLCipher linkage foundation only).
//!
//! Enabled only with `full-braid-durable-lab`. This module proves the frozen
//! SQLCipher 4.17.0 provider can be linked as the single SQLite symbol owner.
//! Full open/key/WAL/integrity profile work belongs to Task 0A.4.

#![cfg(feature = "full-braid-durable-lab")]

// Second release-hold layer. build.rs only sees `PROFILE`; a custom or
// tweaked profile that turns debug assertions off is treated as release too.
// (libsqlite3-sys-raven additionally holds `bundled-sqlcipher*` release builds
// for dependents that enable it without this feature.)
#[cfg(not(debug_assertions))]
compile_error!("FULL_BRAID_SQLCIPHER_NOT_APPROVED");

pub mod protected_anchor;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub mod protected_anchor_linux;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod protected_anchor_linux_ss;
pub mod sqlcipher_open_profile;
pub mod sqlcipher_profile;

pub use protected_anchor::{
    apple_scope_id, classify_append, decode_rvfa1, derive_store_keys, encode_rvfa1,
    k_stage_transition, k_state_record, open_rollback_class, record_key, scope_id,
    terminal_scope_id, AppendDecision, DerivedKeys, ProtectedAnchorError, Rvfa1, Rvfa1Status,
    APPLE_ANCHOR_SERVICE, APPLE_APP_ID, APPLE_LOGICAL_ROOT, APPLE_SEED_SERVICE, ERROR_CODES,
    INITIAL_ANCHOR_SEQ, LINUX_APPLICATION, LINUX_PROTOCOL, MAX_FULL_BRAID_SESSIONS, RELEASE_HOLD,
    RVFA1_LEN, SEED_LEN, TERMINAL_APP_ID, WINDOWS_CRED_MAX_BLOB, WINDOWS_TARGET_PREFIX,
};
pub use sqlcipher_open_profile::{
    run_temp_store_probe, scan_profile_files_for_plaintext, RavenSqlCipherConnection,
    RavenSqlCipherFirstInstallProof, RavenSqlCipherOpenError, RavenSqlCipherProfileV1,
    RavenSqlCipherRawKey, RAVEN_SQLCIPHER_APP_GROUP_PLAINTEXT_HEADER_SIZE,
    RAVEN_SQLCIPHER_BUSY_TIMEOUT_MS, RAVEN_SQLCIPHER_HMAC_ALGORITHM, RAVEN_SQLCIPHER_KDF_ALGORITHM,
    RAVEN_SQLCIPHER_KDF_ITER, RAVEN_SQLCIPHER_PAGE_SIZE, RAVEN_SQLCIPHER_RESERVED_BYTES,
    RAVEN_SQLCIPHER_SOURCE_SHA256, RAVEN_SQLCIPHER_TERMINAL_PLAINTEXT_HEADER_SIZE,
};
pub use sqlcipher_profile::{
    probe_sqlcipher_lab_linkage, SqlCipherLabLinkageError, SqlCipherLabLinkageReport,
    EXPECTED_CIPHER_VERSION, EXPECTED_CIPHER_VERSION_COMMUNITY, EXPECTED_SQLITE_VERSION,
};
