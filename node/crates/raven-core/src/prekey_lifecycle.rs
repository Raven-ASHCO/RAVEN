//! Durable lifecycle for Raven hybrid signed prekeys.
//!
//! This actor is deliberately production-disabled and has no live call sites.
//! It closes the local secret-retention and one-time-prekey race model for
//! `RavenPrekeyBundleV1` / `PairInitV1`; it does **not** define a confidential
//! PairInit carrier or activate indexed-session messaging.
//!
//! Private X25519 material, ML-KEM seeds, accepted-but-not-handed-off roots,
//! and the mutation journal are serialized only into a platform-protected
//! backend. SQLite is used solely as a secret-free, cross-process writer lock.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use ml_kem::kem::KeyExport;
use ml_kem::{DecapsulationKey, MlKem768, Seed};
use rusqlite::{Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::atsam_mlkem::{respond_hybrid_root, DK_SEED_LEN};
use crate::pair_init::{
    decode_init, encode_init, init_hash, prekey_bundle_hash, session_id_from_init_hash,
    transcript_hash, verify_init, PairInit, PairInitError, PairInitTrust, INIT_WIRE_LEN,
};
use crate::prekey_bundle::{PrekeyBundle, MLKEM768_EK_LEN};

/// No live endpoint may instantiate this actor until the remaining PairInit
/// carrier, cross-language transition, and review gates are complete.
pub const PREKEY_LIFECYCLE_PRODUCTION_ENABLED: bool = false;

pub fn live_enabled() -> bool {
    PREKEY_LIFECYCLE_PRODUCTION_ENABLED || crate::pair_init::lab_test_a_enabled()
}

pub const PREKEY_LIFECYCLE_LOCK_FILE: &str = "prekey_lifecycle.sqlite";
pub const MAX_PREKEY_GENERATIONS: usize = 4;
pub const MAX_BUNDLES_PER_GENERATION: usize = 32;
pub const MAX_ACCEPTED_PREKEY_CLAIMS: usize = 512;
pub const MAX_PREKEY_DEVICE_ID_BYTES: usize = 64;
pub const MAX_PREKEY_BUNDLE_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
pub const MAX_PAIR_INIT_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
pub const PREKEY_RETENTION_GRACE_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
pub const PREKEY_ROOT_HANDOFF_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1_000;
pub const MAX_PREKEY_FUTURE_SKEW_MS: u64 = 5 * 60 * 1_000;
pub const MAX_PROTECTED_PREKEY_STATE_BYTES: usize = 2 * 1024 * 1024;

const STATE_MAGIC: &str = "RVNPKL01";
const STATE_VERSION: u8 = 1;
const CLAIM_ID_DOMAIN: &[u8] = b"rvn1/prekey-lifecycle/claim/v1";
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
const PLATFORM_SERVICE: &str = "app.raven.node.prekey-lifecycle";
#[cfg(not(any(
    target_os = "macos",
    windows,
    all(target_os = "linux", target_env = "gnu")
)))]
const PROTECTED_STORE_UNAVAILABLE: &str = "no supported platform-protected prekey backend";

#[derive(Error)]
pub enum PrekeyLifecycleError {
    #[error("protected prekey store unavailable")]
    ProtectedStoreUnavailable,
    #[error("protected prekey store operation failed")]
    ProtectedStore,
    #[error("protected prekey state is corrupt")]
    CorruptProtectedState,
    #[error("prekey lifecycle lock failed")]
    LockFailed,
    #[error("prekey lifecycle metadata database failed")]
    Database,
    #[error("prekey generation material is invalid")]
    InvalidGeneration,
    #[error("signed prekey id is not strictly monotonic")]
    NonMonotonicSignedPrekeyId,
    #[error("prekey generation does not match the actor lineage")]
    ActorLineageMismatch,
    #[error("prekey lifecycle resource limit reached")]
    ResourceLimit,
    #[error("PairInit validation failed: {0}")]
    PairInit(#[from] PairInitError),
    #[error("PairInit exceeds the lifecycle time limit")]
    PairInitLifetime,
    #[error("PairInit is outside the retained prekey grace window")]
    PairInitOutsideGrace,
    #[error("PairInit creation time exceeds allowed clock skew")]
    PairInitClockSkew,
    #[error("PairInit does not bind retained prekey material")]
    UnknownPrekey,
    #[error("PairInit init_id collides with a different signed transcript")]
    InitIdConflict,
    #[error("accepted prekey claim was not found")]
    ClaimNotFound,
    #[error("accepted prekey claim binding mismatch")]
    ClaimBindingMismatch,
    #[error("accepted prekey root handoff expired")]
    ClaimHandoffExpired,
    #[cfg(test)]
    #[error("injected prekey lifecycle crash after {0}")]
    InjectedCrash(&'static str),
}

impl fmt::Debug for PrekeyLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl PrekeyLifecycleError {
    /// Stable diagnostics never include identity, device, key, transcript, or
    /// session bytes.
    pub fn redacted_display(&self) -> String {
        self.to_string()
    }
}

/// One one-time X25519 private key supplied with a signed generation.
pub struct OneTimePrekeyPrivate {
    id: u32,
    secret: [u8; 32],
}

impl OneTimePrekeyPrivate {
    pub fn new(id: u32, mut secret: [u8; 32]) -> Result<Self, PrekeyLifecycleError> {
        if id == 0 || secret.iter().all(|byte| *byte == 0) {
            secret.zeroize();
            return Err(PrekeyLifecycleError::InvalidGeneration);
        }
        Ok(Self { id, secret })
    }

    pub fn id(&self) -> u32 {
        self.id
    }
}

impl fmt::Debug for OneTimePrekeyPrivate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OneTimePrekeyPrivate")
            .field("id", &"[redacted]")
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl Drop for OneTimePrekeyPrivate {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.id.zeroize();
    }
}

/// Private half corresponding to all signed bundles in one generation.
///
/// The bundles themselves are signed outside this actor. This type merely
/// proves that the supplied private material exactly matches them before a
/// protected rotation is committed.
pub struct PrekeyGenerationPrivate {
    signed_x25519_secret: [u8; 32],
    mlkem768_seed: Vec<u8>,
    one_time: Vec<OneTimePrekeyPrivate>,
}

impl PrekeyGenerationPrivate {
    pub fn new(
        signed_x25519_secret: [u8; 32],
        mlkem768_seed: [u8; DK_SEED_LEN],
        one_time: Vec<OneTimePrekeyPrivate>,
    ) -> Self {
        Self {
            signed_x25519_secret,
            mlkem768_seed: mlkem768_seed.to_vec(),
            one_time,
        }
    }
}

impl fmt::Debug for PrekeyGenerationPrivate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrekeyGenerationPrivate")
            .field("signed_x25519_secret", &"[redacted]")
            .field("mlkem768_seed", &"[redacted]")
            .field(
                "one_time",
                &format_args!("{} redacted keys", self.one_time.len()),
            )
            .finish()
    }
}

impl Drop for PrekeyGenerationPrivate {
    fn drop(&mut self) {
        self.signed_x25519_secret.zeroize();
        self.mlkem768_seed.zeroize();
    }
}

/// Root handoff returned after a fully verified PairInit claim is durable.
/// Debug output is intentionally redacted. A pending duplicate returns the
/// same root without performing another accepted decapsulation.
pub struct PrekeyClaim {
    claim_id: [u8; 32],
    session_id: [u8; 32],
    provisional_root: Option<[u8; 32]>,
}

impl PrekeyClaim {
    pub fn claim_id(&self) -> [u8; 32] {
        self.claim_id
    }

    pub fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Moves the caller copy out for immediate protected session-store
    /// persistence. The actor retains its independent protected copy until
    /// [`PrekeyLifecycleActor::complete_claim`].
    pub fn take_provisional_root(&mut self) -> Option<Zeroizing<[u8; 32]>> {
        self.provisional_root.take().map(Zeroizing::new)
    }
}

impl fmt::Debug for PrekeyClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrekeyClaim")
            .field("claim_id", &"[redacted]")
            .field("session_id", &"[redacted]")
            .field("provisional_root", &"[redacted]")
            .finish()
    }
}

impl Drop for PrekeyClaim {
    fn drop(&mut self) {
        self.provisional_root.zeroize();
    }
}

pub enum PrekeyClaimOutcome {
    Accepted(PrekeyClaim),
    DuplicatePending(PrekeyClaim),
    DuplicateCompleted {
        claim_id: [u8; 32],
        session_id: [u8; 32],
    },
    DuplicateAbandoned {
        claim_id: [u8; 32],
        session_id: [u8; 32],
    },
}

impl fmt::Debug for PrekeyClaimOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted(_) => formatter.write_str("Accepted([redacted])"),
            Self::DuplicatePending(_) => formatter.write_str("DuplicatePending([redacted])"),
            Self::DuplicateCompleted { .. } => {
                formatter.write_str("DuplicateCompleted([redacted])")
            }
            Self::DuplicateAbandoned { .. } => {
                formatter.write_str("DuplicateAbandoned([redacted])")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompleteClaimOutcome {
    Completed,
    AlreadyCompleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrekeyLifecycleStatus {
    pub highest_signed_prekey_id: u32,
    pub active_signed_prekey_id: Option<u32>,
    pub retained_generations: usize,
    pub accepted_claims: usize,
    pub pending_handoffs: usize,
    /// Numeric only. No identity, device, OTP, key, or transcript identifier
    /// is exposed by the anomaly API.
    pub one_time_reuse_anomalies: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrekeyPruneOutcome {
    pub destroyed_generations: usize,
    pub destroyed_claim_tombstones: usize,
    pub expired_pending_handoffs: usize,
}

#[derive(Serialize, Deserialize)]
struct BundleBinding {
    bundle_digest: [u8; 32],
    one_time_prekey_id: u32,
    one_time_x25519_pub: [u8; 32],
    created_at_ms: u64,
    expires_at_ms: u64,
    destroy_after_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct OneTimeSecret {
    id: u32,
    secret: [u8; 32],
}

impl Drop for OneTimeSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.id.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
enum GenerationStatus {
    Active,
    Retired { retired_at_ms: u64 },
}

#[derive(Serialize, Deserialize)]
struct SecretGeneration {
    identity_ed25519_pub: [u8; 32],
    device_id: String,
    signed_prekey_id: u32,
    signed_x25519_pub: [u8; 32],
    mlkem768_ek: Vec<u8>,
    signed_x25519_secret: [u8; 32],
    mlkem768_seed: Vec<u8>,
    one_time: Vec<OneTimeSecret>,
    bundles: Vec<BundleBinding>,
    destroy_after_ms: u64,
    status: GenerationStatus,
}

impl Drop for SecretGeneration {
    fn drop(&mut self) {
        self.signed_x25519_secret.zeroize();
        self.mlkem768_seed.zeroize();
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
enum ClaimState {
    PendingHandoff,
    Completed,
    Abandoned,
}

#[derive(Serialize, Deserialize)]
struct AcceptedClaim {
    claim_id: [u8; 32],
    responder_identity: [u8; 32],
    responder_device: [u8; 32],
    signed_prekey_id: u32,
    one_time_prekey_id: u32,
    init_id: [u8; 16],
    init_hash: [u8; 32],
    session_id: [u8; 32],
    accepted_at_ms: u64,
    handoff_deadline_ms: u64,
    retain_until_ms: u64,
    state: ClaimState,
    provisional_root: Option<[u8; 32]>,
}

impl Drop for AcceptedClaim {
    fn drop(&mut self) {
        self.provisional_root.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
enum PendingMutation {
    Rotate {
        generation: Box<SecretGeneration>,
        rotate_at_ms: u64,
    },
    Claim {
        pair_init_wire: Vec<u8>,
        accepted_at_ms: u64,
    },
}

#[derive(Serialize, Deserialize)]
struct ProtectedPrekeyState {
    magic: String,
    version: u8,
    identity_ed25519_pub: Option<[u8; 32]>,
    device_id: Option<String>,
    highest_signed_prekey_id: u32,
    one_time_reuse_anomalies: u64,
    generations: Vec<SecretGeneration>,
    claims: Vec<AcceptedClaim>,
    pending: Option<PendingMutation>,
}

impl Default for ProtectedPrekeyState {
    fn default() -> Self {
        Self {
            magic: STATE_MAGIC.into(),
            version: STATE_VERSION,
            identity_ed25519_pub: None,
            device_id: None,
            highest_signed_prekey_id: 0,
            one_time_reuse_anomalies: 0,
            generations: Vec::new(),
            claims: Vec::new(),
            pending: None,
        }
    }
}

trait ProtectedPrekeyBackend: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, PrekeyLifecycleError>;
    fn put(&self, account: &str, value: &[u8]) -> Result<(), PrekeyLifecycleError>;
}

fn force_locked_file_prekey_backend() -> bool {
    for key in ["RAVEN_PREKEY_BACKEND", "RAVEN_IDENTITY_BACKEND"] {
        if std::env::var_os(key).is_some_and(|v| v == "locked-file") {
            return true;
        }
    }
    false
}

/// Test/lab helper: request the debug locked-file prekey backend.
///
/// Headless Linux CI has no Secret Service. `PrekeyLifecycleActor::open`
/// requires the explicit lab override. Once set, the env stays set so
/// parallel tests cannot race on process env (do not clear a CI job override).
/// Uses `RAVEN_PREKEY_BACKEND` only — identity doctor tests read
/// `RAVEN_IDENTITY_BACKEND` and must stay independent.
#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
pub(crate) fn test_enable_locked_file_prekey_backend() {
    use std::sync::Once;
    static ENABLE: Once = Once::new();
    ENABLE.call_once(|| {
        if force_locked_file_prekey_backend() {
            return;
        }
        // SAFETY: test-only process env for the documented lab/CI backend.
        unsafe { std::env::set_var("RAVEN_PREKEY_BACKEND", "locked-file") }
    });
}

fn locked_file_get(path: &Path) -> Result<Option<Vec<u8>>, PrekeyLifecycleError> {
    if !path.exists() {
        return Ok(None);
    }
    std::fs::read(path)
        .map(Some)
        .map_err(|_| PrekeyLifecycleError::ProtectedStore)
}

fn locked_file_put(path: &Path, value: &[u8]) -> Result<(), PrekeyLifecycleError> {
    crate::paths::atomic_write_private(path, value)
        .map_err(|_| PrekeyLifecycleError::ProtectedStore)
}

struct PlatformProtectedPrekeyBackend {
    locked_file: Option<PathBuf>,
    #[cfg(windows)]
    secret_dir: PathBuf,
}

impl PlatformProtectedPrekeyBackend {
    #[cfg(any(
        target_os = "macos",
        windows,
        all(target_os = "linux", target_env = "gnu")
    ))]
    fn new(data_dir: &Path) -> Result<Self, PrekeyLifecycleError> {
        std::fs::create_dir_all(data_dir).map_err(|_| PrekeyLifecycleError::ProtectedStore)?;
        let locked_file =
            force_locked_file_prekey_backend().then(|| data_dir.join("prekey_lifecycle.protected"));

        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if locked_file.is_none() {
            ensure_secret_service_available()?;
        }

        Ok(Self {
            locked_file,
            #[cfg(windows)]
            secret_dir: data_dir.join("prekey-lifecycle-secrets"),
        })
    }

    #[cfg(not(any(
        target_os = "macos",
        windows,
        all(target_os = "linux", target_env = "gnu")
    )))]
    fn new(data_dir: &Path) -> Result<Self, PrekeyLifecycleError> {
        if force_locked_file_prekey_backend() {
            std::fs::create_dir_all(data_dir).map_err(|_| PrekeyLifecycleError::ProtectedStore)?;
            return Ok(Self {
                locked_file: Some(data_dir.join("prekey_lifecycle.protected")),
            });
        }
        Err(PrekeyLifecycleError::ProtectedStoreUnavailable)
    }
}

#[cfg(not(any(
    target_os = "macos",
    windows,
    all(target_os = "linux", target_env = "gnu")
)))]
impl ProtectedPrekeyBackend for PlatformProtectedPrekeyBackend {
    fn get(&self, _account: &str) -> Result<Option<Vec<u8>>, PrekeyLifecycleError> {
        if let Some(path) = &self.locked_file {
            return locked_file_get(path);
        }
        let _ = PROTECTED_STORE_UNAVAILABLE;
        Err(PrekeyLifecycleError::ProtectedStoreUnavailable)
    }

    fn put(&self, _account: &str, _value: &[u8]) -> Result<(), PrekeyLifecycleError> {
        if let Some(path) = &self.locked_file {
            return locked_file_put(path, _value);
        }
        let _ = PROTECTED_STORE_UNAVAILABLE;
        Err(PrekeyLifecycleError::ProtectedStoreUnavailable)
    }
}

#[cfg(target_os = "macos")]
impl ProtectedPrekeyBackend for PlatformProtectedPrekeyBackend {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, PrekeyLifecycleError> {
        if let Some(path) = &self.locked_file {
            return locked_file_get(path);
        }
        use security_framework::passwords::get_generic_password;
        match get_generic_password(PLATFORM_SERVICE, account) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.code() == -25_300 => Ok(None),
            Err(_) => Err(PrekeyLifecycleError::ProtectedStore),
        }
    }

    fn put(&self, account: &str, value: &[u8]) -> Result<(), PrekeyLifecycleError> {
        if let Some(path) = &self.locked_file {
            return locked_file_put(path, value);
        }
        use security_framework::passwords::set_generic_password;
        set_generic_password(PLATFORM_SERVICE, account, value)
            .map_err(|_| PrekeyLifecycleError::ProtectedStore)
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn ensure_secret_service_available() -> Result<(), PrekeyLifecycleError> {
    use secret_service::{EncryptionType, SecretService};

    let service = SecretService::new(EncryptionType::Dh)
        .map_err(|_| PrekeyLifecycleError::ProtectedStoreUnavailable)?;
    let collection = service
        .get_default_collection()
        .map_err(|_| PrekeyLifecycleError::ProtectedStoreUnavailable)?;
    match collection.is_locked() {
        Ok(false) => Ok(()),
        Ok(true) | Err(_) => Err(PrekeyLifecycleError::ProtectedStoreUnavailable),
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
impl ProtectedPrekeyBackend for PlatformProtectedPrekeyBackend {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, PrekeyLifecycleError> {
        if let Some(path) = &self.locked_file {
            return locked_file_get(path);
        }
        use secret_service::{EncryptionType, SecretService};
        use std::collections::HashMap;
        let service = SecretService::new(EncryptionType::Dh)
            .map_err(|_| PrekeyLifecycleError::ProtectedStoreUnavailable)?;
        let collection = service
            .get_default_collection()
            .map_err(|_| PrekeyLifecycleError::ProtectedStoreUnavailable)?;
        match collection.is_locked() {
            Ok(false) => {}
            Ok(true) | Err(_) => return Err(PrekeyLifecycleError::ProtectedStoreUnavailable),
        }
        let items = collection
            .search_items(HashMap::from([
                ("service", PLATFORM_SERVICE),
                ("account", account),
            ]))
            .map_err(|_| PrekeyLifecycleError::ProtectedStore)?;
        let Some(item) = items.into_iter().next() else {
            return Ok(None);
        };
        item.get_secret()
            .map(Some)
            .map_err(|_| PrekeyLifecycleError::ProtectedStore)
    }

    fn put(&self, account: &str, value: &[u8]) -> Result<(), PrekeyLifecycleError> {
        if let Some(path) = &self.locked_file {
            return locked_file_put(path, value);
        }
        use secret_service::{EncryptionType, SecretService};
        use std::collections::HashMap;
        let service = SecretService::new(EncryptionType::Dh)
            .map_err(|_| PrekeyLifecycleError::ProtectedStoreUnavailable)?;
        let collection = service
            .get_default_collection()
            .map_err(|_| PrekeyLifecycleError::ProtectedStoreUnavailable)?;
        match collection.is_locked() {
            Ok(false) => {}
            Ok(true) | Err(_) => return Err(PrekeyLifecycleError::ProtectedStoreUnavailable),
        }
        collection
            .create_item(
                "RAVEN hybrid prekey lifecycle",
                HashMap::from([("service", PLATFORM_SERVICE), ("account", account)]),
                value,
                true,
                "application/octet-stream",
            )
            .map_err(|_| PrekeyLifecycleError::ProtectedStore)?;
        Ok(())
    }
}

#[cfg(windows)]
impl ProtectedPrekeyBackend for PlatformProtectedPrekeyBackend {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, PrekeyLifecycleError> {
        if let Some(path) = &self.locked_file {
            return locked_file_get(path);
        }
        let path = self.secret_dir.join(format!("{account}.dpapi"));
        if !path.exists() {
            return Ok(None);
        }
        let mut protected =
            std::fs::read(path).map_err(|_| PrekeyLifecycleError::ProtectedStore)?;
        let result = dpapi_unprotect(&protected);
        protected.zeroize();
        result.map(Some)
    }

    fn put(&self, account: &str, value: &[u8]) -> Result<(), PrekeyLifecycleError> {
        if let Some(path) = &self.locked_file {
            return locked_file_put(path, value);
        }
        use std::io::Write;

        std::fs::create_dir_all(&self.secret_dir)
            .map_err(|_| PrekeyLifecycleError::ProtectedStore)?;
        let target = self.secret_dir.join(format!("{account}.dpapi"));
        let temp = self
            .secret_dir
            .join(format!(".{account}.{:016x}.tmp", rand::random::<u64>()));
        let mut protected = dpapi_protect(value)?;
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)
                .map_err(|_| PrekeyLifecycleError::ProtectedStore)?;
            file.write_all(&protected)
                .and_then(|_| file.sync_all())
                .map_err(|_| PrekeyLifecycleError::ProtectedStore)?;
            replace_file_windows(&temp, &target)
        })();
        protected.zeroize();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }
}

#[cfg(windows)]
fn dpapi_protect(value: &[u8]) -> Result<Vec<u8>, PrekeyLifecycleError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: value
            .len()
            .try_into()
            .map_err(|_| PrekeyLifecycleError::ResourceLimit)?,
        pbData: value.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() {
        return Err(PrekeyLifecycleError::ProtectedStoreUnavailable);
    }
    let bytes = unsafe { std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize) };
    let result = bytes.to_vec();
    bytes.zeroize();
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(result)
}

#[cfg(windows)]
fn dpapi_unprotect(value: &[u8]) -> Result<Vec<u8>, PrekeyLifecycleError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: value
            .len()
            .try_into()
            .map_err(|_| PrekeyLifecycleError::CorruptProtectedState)?,
        pbData: value.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() {
        return Err(PrekeyLifecycleError::CorruptProtectedState);
    }
    let bytes = unsafe { std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize) };
    let result = bytes.to_vec();
    bytes.zeroize();
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(result)
}

#[cfg(windows)]
fn replace_file_windows(temp: &Path, target: &Path) -> Result<(), PrekeyLifecycleError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let mut from: Vec<u16> = temp.as_os_str().encode_wide().collect();
    from.push(0);
    let mut to: Vec<u16> = target.as_os_str().encode_wide().collect();
    to.push(0);
    let ok = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        return Err(PrekeyLifecycleError::ProtectedStore);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FaultPoint {
    RotationJournal,
    RotationCommit,
    ClaimJournal,
    ClaimCommit,
}

/// Serialized prekey lifecycle actor. The protected blob is reloaded under a
/// SQLite `BEGIN IMMEDIATE` writer lock for every operation, so independently
/// opened processes cannot silently lose a monotonic rotation or OTP claim.
pub struct PrekeyLifecycleActor {
    connection: Mutex<Connection>,
    backend: Arc<dyn ProtectedPrekeyBackend>,
    account: String,
    #[cfg(test)]
    fault: Mutex<Option<FaultPoint>>,
}

impl fmt::Debug for PrekeyLifecycleActor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrekeyLifecycleActor")
            .field("protected_state", &"[redacted]")
            .finish()
    }
}

impl PrekeyLifecycleActor {
    /// Opens the only supported platform backend. macOS uses Keychain,
    /// GNU/Linux uses Secret Service, Windows uses an atomically replaced
    /// DPAPI blob, and every other target fails closed.
    pub fn open(data_dir: &Path) -> Result<Self, PrekeyLifecycleError> {
        // rust-linux has no org.freedesktop.secrets. Production `open` is
        // unchanged: this hook is test-only and GNU/Linux-only.
        #[cfg(all(test, target_os = "linux", target_env = "gnu"))]
        test_enable_locked_file_prekey_backend();
        let backend = Arc::new(PlatformProtectedPrekeyBackend::new(data_dir)?);
        Self::open_with_backend(data_dir, backend)
    }

    fn open_with_backend(
        data_dir: &Path,
        backend: Arc<dyn ProtectedPrekeyBackend>,
    ) -> Result<Self, PrekeyLifecycleError> {
        std::fs::create_dir_all(data_dir).map_err(|_| PrekeyLifecycleError::ProtectedStore)?;
        let canonical = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
        let account = hex::encode(hash_parts(&[
            b"raven/prekey-lifecycle/account/v1",
            canonical.to_string_lossy().as_bytes(),
        ]));
        let lock_path = data_dir.join(PREKEY_LIFECYCLE_LOCK_FILE);
        let connection =
            Connection::open(&lock_path).map_err(|_| PrekeyLifecycleError::Database)?;
        connection
            .busy_timeout(Duration::from_secs(10))
            .map_err(|_| PrekeyLifecycleError::Database)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS prekey_actor_lock (
                   singleton INTEGER PRIMARY KEY CHECK(singleton = 1)
                 );
                 INSERT OR IGNORE INTO prekey_actor_lock(singleton) VALUES(1);",
            )
            .map_err(|_| PrekeyLifecycleError::Database)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&lock_path, permissions)
                .map_err(|_| PrekeyLifecycleError::ProtectedStore)?;
        }
        let actor = Self {
            connection: Mutex::new(connection),
            backend,
            account,
            #[cfg(test)]
            fault: Mutex::new(None),
        };
        actor.recover()?;
        Ok(actor)
    }

    /// Installs a strictly newer signed-prekey generation. All bundles must
    /// share the same identity, device, signed X25519 key, ML-KEM key, and
    /// signed-prekey id. They may bind distinct OTP ids/keys.
    pub fn install_generation(
        &self,
        bundles: &[PrekeyBundle],
        private: PrekeyGenerationPrivate,
        now_ms: u64,
    ) -> Result<u32, PrekeyLifecycleError> {
        let generation = build_generation(bundles, private, now_ms)?;
        let signed_prekey_id = generation.signed_prekey_id;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrekeyLifecycleError::Database)?;
        let mut state = self.load_and_recover()?;
        if signed_prekey_id <= state.highest_signed_prekey_id {
            return Err(PrekeyLifecycleError::NonMonotonicSignedPrekeyId);
        }
        if let (Some(identity), Some(device_id)) =
            (state.identity_ed25519_pub, state.device_id.as_deref())
        {
            if generation.identity_ed25519_pub != identity || generation.device_id != device_id {
                return Err(PrekeyLifecycleError::ActorLineageMismatch);
            }
        } else if state.identity_ed25519_pub.is_some() || state.device_id.is_some() {
            return Err(PrekeyLifecycleError::CorruptProtectedState);
        }
        if state.generations.len() >= MAX_PREKEY_GENERATIONS {
            return Err(PrekeyLifecycleError::ResourceLimit);
        }
        state.pending = Some(PendingMutation::Rotate {
            generation: Box::new(generation),
            rotate_at_ms: now_ms,
        });
        self.store_state(&state)?;
        self.maybe_fault(FaultPoint::RotationJournal)?;
        recover_pending_mutation(&mut state)?;
        self.store_state(&state)?;
        self.maybe_fault(FaultPoint::RotationCommit)?;
        transaction
            .commit()
            .map_err(|_| PrekeyLifecycleError::Database)?;
        Ok(signed_prekey_id)
    }

    /// Atomically claims an exact, fully signed PairInit and derives its
    /// responder root. Exact duplicates are idempotent. A different valid
    /// PairInit that reuses one OTP receives a distinct session/root and only
    /// increments the bounded numeric anomaly counter.
    pub fn claim_pair_init(
        &self,
        value: &PairInit,
        trust: &PairInitTrust<'_>,
        now_ms: u64,
    ) -> Result<PrekeyClaimOutcome, PrekeyLifecycleError> {
        if value.expires_at_ms <= value.created_at_ms
            || value.expires_at_ms.saturating_sub(value.created_at_ms) > MAX_PAIR_INIT_LIFETIME_MS
        {
            return Err(PrekeyLifecycleError::PairInitLifetime);
        }
        if value.created_at_ms > now_ms.saturating_add(MAX_PREKEY_FUTURE_SKEW_MS) {
            return Err(PrekeyLifecycleError::PairInitClockSkew);
        }
        if now_ms >= value.expires_at_ms {
            return Err(PrekeyLifecycleError::PairInit(
                PairInitError::NotCurrentlyValid,
            ));
        }
        // Trust records and the PairInit were valid when signed. A distributed
        // stale bundle copy remains processable only inside the explicit
        // retention grace, so verification uses the signed creation instant
        // and the actor separately bounds current acceptance below.
        verify_init(value, trust, value.created_at_ms)?;
        let wire = encode_init(value)?;
        if wire.len() != INIT_WIRE_LEN {
            return Err(PrekeyLifecycleError::PairInitLifetime);
        }
        let digest = init_hash(value)?;
        let expected_session_id = session_id_from_init_hash(&digest);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrekeyLifecycleError::Database)?;
        let mut state = self.load_and_recover()?;

        if let Some(existing) = state.claims.iter().find(|claim| {
            claim.responder_identity == trust.responder_prekey.identity_ed25519_pub
                && claim.responder_device == value.responder_device_ed_pub
                && claim.signed_prekey_id == value.signed_prekey_id
                && claim.one_time_prekey_id == value.one_time_prekey_id
                && claim.init_id == value.init_id
                && claim.init_hash == digest
        }) {
            let outcome = claim_outcome(existing, true);
            transaction
                .commit()
                .map_err(|_| PrekeyLifecycleError::Database)?;
            return Ok(outcome);
        }

        if state.claims.iter().any(|claim| {
            claim.responder_identity == trust.responder_prekey.identity_ed25519_pub
                && claim.responder_device == value.responder_device_ed_pub
                && claim.init_id == value.init_id
                && claim.init_hash != digest
        }) {
            return Err(PrekeyLifecycleError::InitIdConflict);
        }
        if state.claims.len() >= MAX_ACCEPTED_PREKEY_CLAIMS {
            return Err(PrekeyLifecycleError::ResourceLimit);
        }
        let generation =
            find_generation_for_init(&state, value).ok_or(PrekeyLifecycleError::UnknownPrekey)?;
        let binding = generation
            .bundles
            .iter()
            .find(|binding| binding.bundle_digest == value.responder_prekey_bundle_hash)
            .ok_or(PrekeyLifecycleError::UnknownPrekey)?;
        if value.created_at_ms > binding.expires_at_ms
            || now_ms > binding.destroy_after_ms
            || prekey_bundle_hash(trust.responder_prekey)? != binding.bundle_digest
        {
            return Err(PrekeyLifecycleError::PairInitOutsideGrace);
        }

        state.pending = Some(PendingMutation::Claim {
            pair_init_wire: wire,
            accepted_at_ms: now_ms,
        });
        self.store_state(&state)?;
        self.maybe_fault(FaultPoint::ClaimJournal)?;
        recover_pending_mutation(&mut state)?;
        self.store_state(&state)?;
        self.maybe_fault(FaultPoint::ClaimCommit)?;
        let accepted = state
            .claims
            .iter()
            .find(|claim| claim.init_hash == digest && claim.session_id == expected_session_id)
            .ok_or(PrekeyLifecycleError::CorruptProtectedState)?;
        let outcome = claim_outcome(accepted, false);
        transaction
            .commit()
            .map_err(|_| PrekeyLifecycleError::Database)?;
        Ok(outcome)
    }

    /// Marks the protected root handoff complete only after the indexed
    /// session actor has durably committed the same session. This operation is
    /// itself idempotent.
    pub fn complete_claim(
        &self,
        claim_id: &[u8; 32],
        session_id: &[u8; 32],
    ) -> Result<CompleteClaimOutcome, PrekeyLifecycleError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrekeyLifecycleError::Database)?;
        let mut state = self.load_and_recover()?;
        let claim = state
            .claims
            .iter_mut()
            .find(|claim| &claim.claim_id == claim_id)
            .ok_or(PrekeyLifecycleError::ClaimNotFound)?;
        if &claim.session_id != session_id {
            return Err(PrekeyLifecycleError::ClaimBindingMismatch);
        }
        let outcome = match claim.state {
            ClaimState::Completed => CompleteClaimOutcome::AlreadyCompleted,
            ClaimState::Abandoned => return Err(PrekeyLifecycleError::ClaimHandoffExpired),
            ClaimState::PendingHandoff => {
                claim.provisional_root.zeroize();
                claim.provisional_root = None;
                claim.state = ClaimState::Completed;
                self.store_state(&state)?;
                CompleteClaimOutcome::Completed
            }
        };
        transaction
            .commit()
            .map_err(|_| PrekeyLifecycleError::Database)?;
        Ok(outcome)
    }

    /// Explicitly retires the active generation. Retirement stops selection
    /// for new publication but does not destroy any private key.
    pub fn retire_active(&self, now_ms: u64) -> Result<Option<u32>, PrekeyLifecycleError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrekeyLifecycleError::Database)?;
        let mut state = self.load_and_recover()?;
        let mut retired = None;
        for generation in &mut state.generations {
            if generation.status == GenerationStatus::Active {
                generation.status = GenerationStatus::Retired {
                    retired_at_ms: now_ms,
                };
                retired = Some(generation.signed_prekey_id);
            }
        }
        if retired.is_some() {
            self.store_state(&state)?;
        }
        transaction
            .commit()
            .map_err(|_| PrekeyLifecycleError::Database)?;
        Ok(retired)
    }

    /// Explicit destruction pass. Retired generation secrets are removed only
    /// after every bound bundle's expiry plus grace and only when no accepted
    /// root still awaits durable session handoff.
    pub fn prune_expired(&self, now_ms: u64) -> Result<PrekeyPruneOutcome, PrekeyLifecycleError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrekeyLifecycleError::Database)?;
        let mut state = self.load_and_recover()?;
        // This explicit maintenance operation is also the bounded handoff
        // timeout. Only after PairInit expiry plus grace may an unclaimed root
        // stop blocking private-generation destruction.
        let mut expired_pending_handoffs = 0;
        for claim in &mut state.claims {
            if claim.state == ClaimState::PendingHandoff && now_ms > claim.handoff_deadline_ms {
                claim.provisional_root.zeroize();
                claim.provisional_root = None;
                claim.state = ClaimState::Abandoned;
                expired_pending_handoffs += 1;
            }
        }
        let claims_before = state.claims.len();
        state.claims.retain(|claim| {
            claim.state == ClaimState::PendingHandoff || now_ms <= claim.retain_until_ms
        });
        let tombstones = claims_before - state.claims.len();
        let generations_before = state.generations.len();
        state.generations.retain(|generation| {
            let expired = now_ms > generation.destroy_after_ms;
            let retired = matches!(generation.status, GenerationStatus::Retired { .. });
            let pending = state.claims.iter().any(|claim| {
                claim.signed_prekey_id == generation.signed_prekey_id
                    && claim.state == ClaimState::PendingHandoff
            });
            !(expired && retired && !pending)
        });
        let generations = generations_before - state.generations.len();
        if tombstones != 0 || generations != 0 || expired_pending_handoffs != 0 {
            self.store_state(&state)?;
        }
        transaction
            .commit()
            .map_err(|_| PrekeyLifecycleError::Database)?;
        Ok(PrekeyPruneOutcome {
            destroyed_generations: generations,
            destroyed_claim_tombstones: tombstones,
            expired_pending_handoffs,
        })
    }

    pub fn status(&self) -> Result<PrekeyLifecycleStatus, PrekeyLifecycleError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrekeyLifecycleError::Database)?;
        let state = self.load_and_recover()?;
        let status = PrekeyLifecycleStatus {
            highest_signed_prekey_id: state.highest_signed_prekey_id,
            active_signed_prekey_id: state.generations.iter().find_map(|generation| {
                (generation.status == GenerationStatus::Active)
                    .then_some(generation.signed_prekey_id)
            }),
            retained_generations: state.generations.len(),
            accepted_claims: state.claims.len(),
            pending_handoffs: state
                .claims
                .iter()
                .filter(|claim| claim.state == ClaimState::PendingHandoff)
                .count(),
            one_time_reuse_anomalies: state.one_time_reuse_anomalies,
        };
        transaction
            .commit()
            .map_err(|_| PrekeyLifecycleError::Database)?;
        Ok(status)
    }

    fn recover(&self) -> Result<(), PrekeyLifecycleError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrekeyLifecycleError::Database)?;
        let _ = self.load_and_recover()?;
        transaction
            .commit()
            .map_err(|_| PrekeyLifecycleError::Database)
    }

    fn load_and_recover(&self) -> Result<ProtectedPrekeyState, PrekeyLifecycleError> {
        let mut state = self.load_state()?;
        if state.pending.is_some() {
            recover_pending_mutation(&mut state)?;
            self.store_state(&state)?;
        }
        Ok(state)
    }

    fn load_state(&self) -> Result<ProtectedPrekeyState, PrekeyLifecycleError> {
        let Some(mut encoded) = self.backend.get(&self.account)? else {
            return Ok(ProtectedPrekeyState::default());
        };
        if encoded.len() > MAX_PROTECTED_PREKEY_STATE_BYTES {
            encoded.zeroize();
            return Err(PrekeyLifecycleError::CorruptProtectedState);
        }
        let decoded = serde_json::from_slice(&encoded)
            .map_err(|_| PrekeyLifecycleError::CorruptProtectedState);
        encoded.zeroize();
        let state: ProtectedPrekeyState = decoded?;
        validate_state(&state)?;
        Ok(state)
    }

    fn store_state(&self, state: &ProtectedPrekeyState) -> Result<(), PrekeyLifecycleError> {
        validate_state(state)?;
        let mut encoded =
            serde_json::to_vec(state).map_err(|_| PrekeyLifecycleError::CorruptProtectedState)?;
        if encoded.len() > MAX_PROTECTED_PREKEY_STATE_BYTES {
            encoded.zeroize();
            return Err(PrekeyLifecycleError::ResourceLimit);
        }
        let result = self.backend.put(&self.account, &encoded);
        encoded.zeroize();
        result
    }

    fn lock_connection(&self) -> Result<MutexGuard<'_, Connection>, PrekeyLifecycleError> {
        self.connection
            .lock()
            .map_err(|_| PrekeyLifecycleError::LockFailed)
    }

    #[cfg(test)]
    fn maybe_fault(&self, point: FaultPoint) -> Result<(), PrekeyLifecycleError> {
        let mut fault = self
            .fault
            .lock()
            .map_err(|_| PrekeyLifecycleError::LockFailed)?;
        if *fault == Some(point) {
            *fault = None;
            let label = match point {
                FaultPoint::RotationJournal => "rotation journal",
                FaultPoint::RotationCommit => "rotation commit",
                FaultPoint::ClaimJournal => "claim journal",
                FaultPoint::ClaimCommit => "claim commit",
            };
            return Err(PrekeyLifecycleError::InjectedCrash(label));
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn maybe_fault(&self, _point: FaultPoint) -> Result<(), PrekeyLifecycleError> {
        Ok(())
    }

    #[cfg(test)]
    fn inject_fault(&self, point: FaultPoint) -> Result<(), PrekeyLifecycleError> {
        *self
            .fault
            .lock()
            .map_err(|_| PrekeyLifecycleError::LockFailed)? = Some(point);
        Ok(())
    }
}

fn build_generation(
    bundles: &[PrekeyBundle],
    mut private: PrekeyGenerationPrivate,
    now_ms: u64,
) -> Result<SecretGeneration, PrekeyLifecycleError> {
    if bundles.is_empty() || bundles.len() > MAX_BUNDLES_PER_GENERATION {
        return Err(PrekeyLifecycleError::ResourceLimit);
    }
    let first = &bundles[0];
    if first.signed_prekey_id == 0
        || first.device_id.is_empty()
        || first.device_id.len() > MAX_PREKEY_DEVICE_ID_BYTES
        || private.mlkem768_seed.len() != DK_SEED_LEN
        || private.signed_x25519_secret.iter().all(|byte| *byte == 0)
        || private.mlkem768_seed.iter().all(|byte| *byte == 0)
    {
        return Err(PrekeyLifecycleError::InvalidGeneration);
    }
    let signed_public =
        X25519PublicKey::from(&StaticSecret::from(private.signed_x25519_secret)).to_bytes();
    if signed_public != first.x25519_pub {
        return Err(PrekeyLifecycleError::InvalidGeneration);
    }
    let mut mlkem_seed: [u8; DK_SEED_LEN] = private
        .mlkem768_seed
        .as_slice()
        .try_into()
        .map_err(|_| PrekeyLifecycleError::InvalidGeneration)?;
    let seed = Seed::try_from(mlkem_seed.as_slice())
        .map_err(|_| PrekeyLifecycleError::InvalidGeneration)?;
    let derived_ek = DecapsulationKey::<MlKem768>::from_seed(seed)
        .encapsulation_key()
        .to_bytes();
    mlkem_seed.zeroize();
    if derived_ek.as_slice() != first.mlkem768_ek.as_slice() {
        return Err(PrekeyLifecycleError::InvalidGeneration);
    }

    let mut one_time = Vec::with_capacity(private.one_time.len());
    for item in private.one_time.drain(..) {
        if one_time
            .iter()
            .any(|stored: &OneTimeSecret| stored.id == item.id)
        {
            return Err(PrekeyLifecycleError::InvalidGeneration);
        }
        one_time.push(OneTimeSecret {
            id: item.id,
            secret: item.secret,
        });
    }
    let mut bindings = Vec::with_capacity(bundles.len());
    let mut maximum_destroy_after = 0;
    for bundle in bundles {
        bundle
            .verify(now_ms)
            .map_err(|_| PrekeyLifecycleError::InvalidGeneration)?;
        let lifetime = bundle.expires_at_ms.saturating_sub(bundle.created_at_ms);
        let destroy_after_ms = bundle
            .expires_at_ms
            .checked_add(PREKEY_RETENTION_GRACE_MS)
            .ok_or(PrekeyLifecycleError::InvalidGeneration)?;
        if now_ms >= bundle.expires_at_ms
            || lifetime == 0
            || lifetime > MAX_PREKEY_BUNDLE_LIFETIME_MS
            || bundle.identity_ed25519_pub != first.identity_ed25519_pub
            || bundle.device_id != first.device_id
            || bundle.signed_prekey_id != first.signed_prekey_id
            || bundle.x25519_pub != signed_public
            || bundle.mlkem768_ek != first.mlkem768_ek
        {
            return Err(PrekeyLifecycleError::InvalidGeneration);
        }
        let one_time_public = bundle.one_time_x25519_pub.unwrap_or([0u8; 32]);
        if bundle.one_time_prekey_id == 0 {
            if bindings
                .iter()
                .any(|binding: &BundleBinding| binding.one_time_prekey_id == 0)
            {
                return Err(PrekeyLifecycleError::InvalidGeneration);
            }
        } else {
            let secret = one_time
                .iter()
                .find(|secret| secret.id == bundle.one_time_prekey_id)
                .ok_or(PrekeyLifecycleError::InvalidGeneration)?;
            let derived = X25519PublicKey::from(&StaticSecret::from(secret.secret)).to_bytes();
            if derived != one_time_public {
                return Err(PrekeyLifecycleError::InvalidGeneration);
            }
        }
        let digest = prekey_bundle_hash(bundle)?;
        if bindings.iter().any(|binding| {
            binding.bundle_digest == digest || {
                binding.one_time_prekey_id != 0
                    && binding.one_time_prekey_id == bundle.one_time_prekey_id
            }
        }) {
            return Err(PrekeyLifecycleError::InvalidGeneration);
        }
        maximum_destroy_after = maximum_destroy_after.max(destroy_after_ms);
        bindings.push(BundleBinding {
            bundle_digest: digest,
            one_time_prekey_id: bundle.one_time_prekey_id,
            one_time_x25519_pub: one_time_public,
            created_at_ms: bundle.created_at_ms,
            expires_at_ms: bundle.expires_at_ms,
            destroy_after_ms,
        });
    }
    if one_time.iter().any(|secret| {
        !bindings
            .iter()
            .any(|binding| binding.one_time_prekey_id == secret.id)
    }) {
        return Err(PrekeyLifecycleError::InvalidGeneration);
    }

    Ok(SecretGeneration {
        identity_ed25519_pub: first.identity_ed25519_pub,
        device_id: first.device_id.clone(),
        signed_prekey_id: first.signed_prekey_id,
        signed_x25519_pub: signed_public,
        mlkem768_ek: first.mlkem768_ek.clone(),
        signed_x25519_secret: private.signed_x25519_secret,
        mlkem768_seed: private.mlkem768_seed.clone(),
        one_time,
        bundles: bindings,
        destroy_after_ms: maximum_destroy_after,
        status: GenerationStatus::Active,
    })
}

fn recover_pending_mutation(state: &mut ProtectedPrekeyState) -> Result<(), PrekeyLifecycleError> {
    let pending = state
        .pending
        .take()
        .ok_or(PrekeyLifecycleError::CorruptProtectedState)?;
    match pending {
        PendingMutation::Rotate {
            generation,
            rotate_at_ms,
        } => {
            if generation.signed_prekey_id <= state.highest_signed_prekey_id
                || state.generations.len() >= MAX_PREKEY_GENERATIONS
            {
                return Err(PrekeyLifecycleError::CorruptProtectedState);
            }
            for existing in &mut state.generations {
                if existing.status == GenerationStatus::Active {
                    existing.status = GenerationStatus::Retired {
                        retired_at_ms: rotate_at_ms,
                    };
                }
            }
            if let (Some(identity), Some(device_id)) =
                (state.identity_ed25519_pub, state.device_id.as_deref())
            {
                if generation.identity_ed25519_pub != identity || generation.device_id != device_id
                {
                    return Err(PrekeyLifecycleError::CorruptProtectedState);
                }
            } else if state.identity_ed25519_pub.is_none() && state.device_id.is_none() {
                state.identity_ed25519_pub = Some(generation.identity_ed25519_pub);
                state.device_id = Some(generation.device_id.clone());
            } else {
                return Err(PrekeyLifecycleError::CorruptProtectedState);
            }
            state.highest_signed_prekey_id = generation.signed_prekey_id;
            state.generations.push(*generation);
        }
        PendingMutation::Claim {
            mut pair_init_wire,
            accepted_at_ms,
        } => {
            let value = decode_init(&pair_init_wire)?;
            pair_init_wire.zeroize();
            let digest = init_hash(&value)?;
            if state.claims.iter().any(|claim| {
                claim.responder_identity == responder_identity_for_init(state, &value)
                    && claim.responder_device == value.responder_device_ed_pub
                    && claim.init_id == value.init_id
                    && claim.init_hash != digest
            }) {
                return Err(PrekeyLifecycleError::CorruptProtectedState);
            }
            if state.claims.iter().any(|claim| claim.init_hash == digest) {
                return Ok(());
            }
            let generation = find_generation_for_init(state, &value)
                .ok_or(PrekeyLifecycleError::CorruptProtectedState)?;
            let responder_identity = generation.identity_ed25519_pub;
            let bundle_destroy_after_ms = generation
                .bundles
                .iter()
                .find(|binding| binding.bundle_digest == value.responder_prekey_bundle_hash)
                .ok_or(PrekeyLifecycleError::CorruptProtectedState)?
                .destroy_after_ms;
            let mut selected_secret = if value.one_time_prekey_id == 0 {
                generation.signed_x25519_secret
            } else {
                generation
                    .one_time
                    .iter()
                    .find(|secret| secret.id == value.one_time_prekey_id)
                    .ok_or(PrekeyLifecycleError::CorruptProtectedState)?
                    .secret
            };
            let mut mlkem_seed: [u8; DK_SEED_LEN] = generation
                .mlkem768_seed
                .as_slice()
                .try_into()
                .map_err(|_| PrekeyLifecycleError::CorruptProtectedState)?;
            let transcript = transcript_hash(&value)?;
            let root_result = respond_hybrid_root(
                &selected_secret,
                &value.initiator_ephemeral_x25519_pub,
                &mlkem_seed,
                &value.mlkem768_ciphertext,
                &transcript,
            );
            selected_secret.zeroize();
            mlkem_seed.zeroize();
            let root = root_result.map_err(|_| PrekeyLifecycleError::CorruptProtectedState)?;
            let reused = value.one_time_prekey_id != 0
                && state.claims.iter().any(|claim| {
                    claim.responder_identity == responder_identity
                        && claim.responder_device == value.responder_device_ed_pub
                        && claim.signed_prekey_id == value.signed_prekey_id
                        && claim.one_time_prekey_id == value.one_time_prekey_id
                        && claim.init_hash != digest
                });
            if reused {
                state.one_time_reuse_anomalies = state.one_time_reuse_anomalies.saturating_add(1);
            }
            let handoff_deadline_ms = accepted_at_ms
                .checked_add(PREKEY_ROOT_HANDOFF_TIMEOUT_MS)
                .ok_or(PrekeyLifecycleError::CorruptProtectedState)?;
            let replay_deadline_ms = bundle_destroy_after_ms;
            let retain_until_ms = handoff_deadline_ms.max(replay_deadline_ms);
            let session_id = session_id_from_init_hash(&digest);
            let claim_id = claim_id(
                &responder_identity,
                &value.responder_device_ed_pub,
                value.signed_prekey_id,
                value.one_time_prekey_id,
                &value.init_id,
                &digest,
            );
            state.claims.push(AcceptedClaim {
                claim_id,
                responder_identity,
                responder_device: value.responder_device_ed_pub,
                signed_prekey_id: value.signed_prekey_id,
                one_time_prekey_id: value.one_time_prekey_id,
                init_id: value.init_id,
                init_hash: digest,
                session_id,
                accepted_at_ms,
                handoff_deadline_ms,
                retain_until_ms,
                state: ClaimState::PendingHandoff,
                provisional_root: Some(root),
            });
        }
    }
    Ok(())
}

fn responder_identity_for_init(state: &ProtectedPrekeyState, value: &PairInit) -> [u8; 32] {
    find_generation_for_init(state, value)
        .map(|generation| generation.identity_ed25519_pub)
        .unwrap_or([0u8; 32])
}

fn find_generation_for_init<'a>(
    state: &'a ProtectedPrekeyState,
    value: &PairInit,
) -> Option<&'a SecretGeneration> {
    state.generations.iter().find(|generation| {
        generation.signed_prekey_id == value.signed_prekey_id
            && generation.signed_x25519_pub == value.responder_signed_x25519_pub
            && generation.mlkem768_ek == value.responder_mlkem768_ek
            && generation.bundles.iter().any(|binding| {
                binding.bundle_digest == value.responder_prekey_bundle_hash
                    && binding.one_time_prekey_id == value.one_time_prekey_id
                    && binding.one_time_x25519_pub == value.responder_one_time_x25519_pub
            })
    })
}

fn claim_outcome(claim: &AcceptedClaim, duplicate: bool) -> PrekeyClaimOutcome {
    match claim.state {
        ClaimState::Completed => {
            return PrekeyClaimOutcome::DuplicateCompleted {
                claim_id: claim.claim_id,
                session_id: claim.session_id,
            };
        }
        ClaimState::Abandoned => {
            return PrekeyClaimOutcome::DuplicateAbandoned {
                claim_id: claim.claim_id,
                session_id: claim.session_id,
            };
        }
        ClaimState::PendingHandoff => {}
    }
    let value = PrekeyClaim {
        claim_id: claim.claim_id,
        session_id: claim.session_id,
        provisional_root: claim.provisional_root,
    };
    if duplicate {
        PrekeyClaimOutcome::DuplicatePending(value)
    } else {
        PrekeyClaimOutcome::Accepted(value)
    }
}

fn claim_id(
    responder_identity: &[u8; 32],
    responder_device: &[u8; 32],
    signed_prekey_id: u32,
    one_time_prekey_id: u32,
    init_id: &[u8; 16],
    init_hash: &[u8; 32],
) -> [u8; 32] {
    hash_parts(&[
        CLAIM_ID_DOMAIN,
        responder_identity,
        responder_device,
        &signed_prekey_id.to_be_bytes(),
        &one_time_prekey_id.to_be_bytes(),
        init_id,
        init_hash,
    ])
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn validate_state(state: &ProtectedPrekeyState) -> Result<(), PrekeyLifecycleError> {
    if state.magic != STATE_MAGIC
        || state.version != STATE_VERSION
        || state.generations.len() > MAX_PREKEY_GENERATIONS
        || state.claims.len() > MAX_ACCEPTED_PREKEY_CLAIMS
    {
        return Err(PrekeyLifecycleError::CorruptProtectedState);
    }
    match (state.identity_ed25519_pub, state.device_id.as_deref()) {
        (None, None) if state.generations.is_empty() && state.highest_signed_prekey_id == 0 => {}
        (Some(identity), Some(device_id))
            if identity.iter().any(|byte| *byte != 0)
                && !device_id.is_empty()
                && device_id.len() <= MAX_PREKEY_DEVICE_ID_BYTES => {}
        _ => return Err(PrekeyLifecycleError::CorruptProtectedState),
    }
    let active = state
        .generations
        .iter()
        .filter(|generation| generation.status == GenerationStatus::Active)
        .count();
    if active > 1 {
        return Err(PrekeyLifecycleError::CorruptProtectedState);
    }
    for (index, generation) in state.generations.iter().enumerate() {
        if generation.signed_prekey_id == 0
            || generation.signed_prekey_id > state.highest_signed_prekey_id
            || generation.device_id.is_empty()
            || generation.device_id.len() > MAX_PREKEY_DEVICE_ID_BYTES
            || generation
                .signed_x25519_secret
                .iter()
                .all(|byte| *byte == 0)
            || generation.mlkem768_ek.len() != MLKEM768_EK_LEN
            || generation.mlkem768_seed.len() != DK_SEED_LEN
            || generation.mlkem768_seed.iter().all(|byte| *byte == 0)
            || generation.bundles.is_empty()
            || generation.bundles.len() > MAX_BUNDLES_PER_GENERATION
            || state.generations[..index]
                .iter()
                .any(|other| other.signed_prekey_id == generation.signed_prekey_id)
        {
            return Err(PrekeyLifecycleError::CorruptProtectedState);
        }
        if state.identity_ed25519_pub != Some(generation.identity_ed25519_pub)
            || state.device_id.as_deref() != Some(generation.device_id.as_str())
        {
            return Err(PrekeyLifecycleError::CorruptProtectedState);
        }
        let signed_public =
            X25519PublicKey::from(&StaticSecret::from(generation.signed_x25519_secret)).to_bytes();
        if signed_public != generation.signed_x25519_pub {
            return Err(PrekeyLifecycleError::CorruptProtectedState);
        }
        let seed = Seed::try_from(generation.mlkem768_seed.as_slice())
            .map_err(|_| PrekeyLifecycleError::CorruptProtectedState)?;
        let derived = DecapsulationKey::<MlKem768>::from_seed(seed)
            .encapsulation_key()
            .to_bytes();
        if derived.as_slice() != generation.mlkem768_ek.as_slice() {
            return Err(PrekeyLifecycleError::CorruptProtectedState);
        }
        let computed_destroy = generation
            .bundles
            .iter()
            .map(|binding| binding.destroy_after_ms)
            .max()
            .ok_or(PrekeyLifecycleError::CorruptProtectedState)?;
        if computed_destroy != generation.destroy_after_ms {
            return Err(PrekeyLifecycleError::CorruptProtectedState);
        }
        for (binding_index, binding) in generation.bundles.iter().enumerate() {
            if binding.expires_at_ms <= binding.created_at_ms
                || binding.expires_at_ms.saturating_sub(binding.created_at_ms)
                    > MAX_PREKEY_BUNDLE_LIFETIME_MS
                || binding.destroy_after_ms
                    != binding
                        .expires_at_ms
                        .checked_add(PREKEY_RETENTION_GRACE_MS)
                        .ok_or(PrekeyLifecycleError::CorruptProtectedState)?
                || generation.bundles[..binding_index]
                    .iter()
                    .any(|other| other.bundle_digest == binding.bundle_digest)
            {
                return Err(PrekeyLifecycleError::CorruptProtectedState);
            }
            if binding.one_time_prekey_id == 0 {
                if binding.one_time_x25519_pub != [0u8; 32] {
                    return Err(PrekeyLifecycleError::CorruptProtectedState);
                }
            } else {
                let secret = generation
                    .one_time
                    .iter()
                    .find(|secret| secret.id == binding.one_time_prekey_id)
                    .ok_or(PrekeyLifecycleError::CorruptProtectedState)?;
                if secret.secret.iter().all(|byte| *byte == 0) {
                    return Err(PrekeyLifecycleError::CorruptProtectedState);
                }
                let public = X25519PublicKey::from(&StaticSecret::from(secret.secret)).to_bytes();
                if public != binding.one_time_x25519_pub {
                    return Err(PrekeyLifecycleError::CorruptProtectedState);
                }
            }
        }
    }
    for (index, claim) in state.claims.iter().enumerate() {
        if claim.claim_id
            != claim_id(
                &claim.responder_identity,
                &claim.responder_device,
                claim.signed_prekey_id,
                claim.one_time_prekey_id,
                &claim.init_id,
                &claim.init_hash,
            )
            || claim.session_id != session_id_from_init_hash(&claim.init_hash)
            || claim.handoff_deadline_ms
                != claim
                    .accepted_at_ms
                    .checked_add(PREKEY_ROOT_HANDOFF_TIMEOUT_MS)
                    .ok_or(PrekeyLifecycleError::CorruptProtectedState)?
            || claim.retain_until_ms < claim.accepted_at_ms
            || claim.retain_until_ms < claim.handoff_deadline_ms
            || (claim.state == ClaimState::PendingHandoff) != claim.provisional_root.is_some()
            || state.claims[..index]
                .iter()
                .any(|other| other.claim_id == claim.claim_id)
        {
            return Err(PrekeyLifecycleError::CorruptProtectedState);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Barrier;
    use std::thread;

    use crate::atsam_mlkem::encapsulate_deterministic;
    use crate::device_cert::DeviceCertificate;
    use crate::identity::Identity;
    use crate::pair_init::{
        device_certificate_hash, init_signing_bytes, prekey_bundle_hash, PairInitTrust,
    };
    use tempfile::TempDir;

    #[derive(Default)]
    struct MemoryProtectedBackend {
        values: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl ProtectedPrekeyBackend for MemoryProtectedBackend {
        fn get(&self, account: &str) -> Result<Option<Vec<u8>>, PrekeyLifecycleError> {
            Ok(self
                .values
                .lock()
                .map_err(|_| PrekeyLifecycleError::LockFailed)?
                .get(account)
                .cloned())
        }

        fn put(&self, account: &str, value: &[u8]) -> Result<(), PrekeyLifecycleError> {
            self.values
                .lock()
                .map_err(|_| PrekeyLifecycleError::LockFailed)?
                .insert(account.into(), value.to_vec());
            Ok(())
        }
    }

    struct FailFinalProtectedWrite {
        inner: Arc<MemoryProtectedBackend>,
        allow_one_then_fail: AtomicBool,
        allowed_write_consumed: AtomicBool,
    }

    impl FailFinalProtectedWrite {
        fn new(inner: Arc<MemoryProtectedBackend>) -> Self {
            Self {
                inner,
                allow_one_then_fail: AtomicBool::new(false),
                allowed_write_consumed: AtomicBool::new(false),
            }
        }

        fn fail_after_one_success(&self) {
            self.allowed_write_consumed.store(false, Ordering::SeqCst);
            self.allow_one_then_fail.store(true, Ordering::SeqCst);
        }
    }

    impl ProtectedPrekeyBackend for FailFinalProtectedWrite {
        fn get(&self, account: &str) -> Result<Option<Vec<u8>>, PrekeyLifecycleError> {
            self.inner.get(account)
        }

        fn put(&self, account: &str, value: &[u8]) -> Result<(), PrekeyLifecycleError> {
            if self.allow_one_then_fail.load(Ordering::SeqCst)
                && self.allowed_write_consumed.swap(true, Ordering::SeqCst)
            {
                self.allow_one_then_fail.store(false, Ordering::SeqCst);
                return Err(PrekeyLifecycleError::ProtectedStore);
            }
            self.inner.put(account, value)
        }
    }

    struct Fixture {
        data_dir: TempDir,
        backend: Arc<MemoryProtectedBackend>,
        actor: Arc<PrekeyLifecycleActor>,
        initiator_user: Identity,
        responder_user: Identity,
        initiator_device: Identity,
        responder_device: Identity,
        initiator_cert: DeviceCertificate,
        responder_cert: DeviceCertificate,
        bundle: PrekeyBundle,
        otp_secret: [u8; 32],
        mlkem_seed: [u8; DK_SEED_LEN],
        created_at_ms: u64,
    }

    impl Fixture {
        fn new() -> Self {
            let created_at_ms = 1_700_000_000_000;
            let data_dir = tempfile::tempdir().unwrap();
            let backend = Arc::new(MemoryProtectedBackend::default());
            let actor = Arc::new(
                PrekeyLifecycleActor::open_with_backend(data_dir.path(), backend.clone()).unwrap(),
            );
            let initiator_user = Identity::from_seed(&[0x11; 32]);
            let responder_user = Identity::from_seed(&[0x22; 32]);
            let initiator_device = Identity::from_seed(&[0x33; 32]);
            let responder_device = Identity::from_seed(&[0x44; 32]);
            let signed_secret = [0x52; 32];
            let signed_public =
                X25519PublicKey::from(&StaticSecret::from(signed_secret)).to_bytes();
            let otp_secret: [u8; 32] = std::array::from_fn(|index| 2 + index as u8 * 5);
            let otp_public = X25519PublicKey::from(&StaticSecret::from(otp_secret)).to_bytes();
            let mlkem_seed: [u8; DK_SEED_LEN] =
                std::array::from_fn(|index| 3u8.wrapping_add((index as u8).wrapping_mul(17)));
            let seed = Seed::try_from(mlkem_seed.as_slice()).unwrap();
            let mlkem_ek = DecapsulationKey::<MlKem768>::from_seed(seed)
                .encapsulation_key()
                .to_bytes()
                .as_slice()
                .to_vec();
            let initiator_cert = DeviceCertificate::issue(
                &initiator_user,
                initiator_device.public_key_bytes(),
                [0x61; 32],
                "alice-device",
                created_at_ms - 60_000,
                created_at_ms + 3 * MAX_PREKEY_BUNDLE_LIFETIME_MS,
                0,
            )
            .unwrap();
            let responder_cert = DeviceCertificate::issue(
                &responder_user,
                responder_device.public_key_bytes(),
                signed_public,
                "bob-device",
                created_at_ms - 60_000,
                created_at_ms + 3 * MAX_PREKEY_BUNDLE_LIFETIME_MS,
                0,
            )
            .unwrap();
            let bundle = PrekeyBundle {
                identity_ed25519_pub: responder_user.public_key_bytes(),
                device_id: "bob-device".into(),
                x25519_pub: signed_public,
                mlkem768_ek: mlkem_ek,
                signed_prekey_id: 1,
                one_time_prekey_id: 7,
                one_time_x25519_pub: Some(otp_public),
                created_at_ms: created_at_ms - 60_000,
                expires_at_ms: created_at_ms + MAX_PAIR_INIT_LIFETIME_MS,
                signature: [0u8; 64],
            }
            .sign(&responder_user)
            .unwrap();
            actor
                .install_generation(
                    std::slice::from_ref(&bundle),
                    PrekeyGenerationPrivate::new(
                        signed_secret,
                        mlkem_seed,
                        vec![OneTimePrekeyPrivate::new(7, otp_secret).unwrap()],
                    ),
                    created_at_ms,
                )
                .unwrap();
            Self {
                data_dir,
                backend,
                actor,
                initiator_user,
                responder_user,
                initiator_device,
                responder_device,
                initiator_cert,
                responder_cert,
                bundle,
                otp_secret,
                mlkem_seed,
                created_at_ms,
            }
        }

        fn pair(&self, discriminator: u8) -> PairInit {
            let mut ephemeral_secret = [0u8; 32];
            ephemeral_secret.fill(0x70u8.wrapping_add(discriminator));
            let ephemeral_public =
                X25519PublicKey::from(&StaticSecret::from(ephemeral_secret)).to_bytes();
            let m = [0x80u8.wrapping_add(discriminator); 32];
            let (ciphertext, _) = encapsulate_deterministic(&self.bundle.mlkem768_ek, &m).unwrap();
            let mut init_id = [0u8; 16];
            init_id.fill(discriminator.max(1));
            let mut pairing_nonce = [0u8; 32];
            pairing_nonce.fill(discriminator.wrapping_add(9));
            let mut value = PairInit {
                initiator_address: self.initiator_user.address(),
                responder_address: self.responder_user.address(),
                init_id,
                pairing_nonce,
                initiator_device_ed_pub: self.initiator_device.public_key_bytes(),
                responder_device_ed_pub: self.responder_device.public_key_bytes(),
                initiator_ephemeral_x25519_pub: ephemeral_public,
                responder_signed_x25519_pub: self.bundle.x25519_pub,
                responder_one_time_x25519_pub: self.bundle.one_time_x25519_pub.unwrap(),
                initiator_device_cert_hash: device_certificate_hash(&self.initiator_cert).unwrap(),
                responder_device_cert_hash: device_certificate_hash(&self.responder_cert).unwrap(),
                responder_prekey_bundle_hash: prekey_bundle_hash(&self.bundle).unwrap(),
                signed_prekey_id: self.bundle.signed_prekey_id,
                one_time_prekey_id: self.bundle.one_time_prekey_id,
                responder_mlkem768_ek: self.bundle.mlkem768_ek.clone(),
                mlkem768_ciphertext: ciphertext,
                created_at_ms: self.created_at_ms + u64::from(discriminator),
                expires_at_ms: self.created_at_ms + MAX_PAIR_INIT_LIFETIME_MS,
                signature: [0u8; 64],
            };
            value.signature = self
                .initiator_device
                .sign(&init_signing_bytes(&value).unwrap());
            value
        }

        fn trust(&self) -> PairInitTrust<'_> {
            PairInitTrust {
                initiator_certificate: &self.initiator_cert,
                responder_certificate: &self.responder_cert,
                responder_prekey: &self.bundle,
                initiator_revoked: false,
                responder_revoked: false,
            }
        }

        fn reopen(&self) -> PrekeyLifecycleActor {
            PrekeyLifecycleActor::open_with_backend(self.data_dir.path(), self.backend.clone())
                .unwrap()
        }
    }

    fn take_claim(outcome: PrekeyClaimOutcome) -> PrekeyClaim {
        match outcome {
            PrekeyClaimOutcome::Accepted(claim) | PrekeyClaimOutcome::DuplicatePending(claim) => {
                claim
            }
            PrekeyClaimOutcome::DuplicateCompleted { .. }
            | PrekeyClaimOutcome::DuplicateAbandoned { .. } => panic!("expected pending claim"),
        }
    }

    #[test]
    fn actor_is_production_disabled_and_debug_is_redacted() {
        const { assert!(!PREKEY_LIFECYCLE_PRODUCTION_ENABLED) };
        let private = PrekeyGenerationPrivate::new([7; 32], [8; DK_SEED_LEN], Vec::new());
        let debug = format!("{private:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains(&hex::encode([7; 32])));
        let error = PrekeyLifecycleError::ProtectedStore;
        assert!(!format!("{error:?}").contains(&hex::encode([7; 32])));
    }

    #[test]
    fn exact_duplicate_is_idempotent_and_root_matches_exact_transcript() {
        let fixture = Fixture::new();
        let pair = fixture.pair(1);
        let mut first = take_claim(
            fixture
                .actor
                .claim_pair_init(&pair, &fixture.trust(), fixture.created_at_ms + 100)
                .unwrap(),
        );
        let first_root = first.take_provisional_root().unwrap();
        let expected = respond_hybrid_root(
            &fixture.otp_secret,
            &pair.initiator_ephemeral_x25519_pub,
            &fixture.mlkem_seed,
            &pair.mlkem768_ciphertext,
            &transcript_hash(&pair).unwrap(),
        )
        .unwrap();
        assert_eq!(*first_root, expected);
        let mut duplicate = take_claim(
            fixture
                .actor
                .claim_pair_init(&pair, &fixture.trust(), fixture.created_at_ms + 101)
                .unwrap(),
        );
        assert_eq!(duplicate.claim_id(), first.claim_id());
        assert_eq!(
            duplicate.take_provisional_root().map(|root| *root),
            Some(expected)
        );
        let status = fixture.actor.status().unwrap();
        assert_eq!(status.accepted_claims, 1);
        assert_eq!(status.one_time_reuse_anomalies, 0);
    }

    #[test]
    fn same_otp_distinct_signed_pairinit_creates_distinct_sessions() {
        let fixture = Fixture::new();
        let first = take_claim(
            fixture
                .actor
                .claim_pair_init(
                    &fixture.pair(1),
                    &fixture.trust(),
                    fixture.created_at_ms + 100,
                )
                .unwrap(),
        );
        let second = take_claim(
            fixture
                .actor
                .claim_pair_init(
                    &fixture.pair(2),
                    &fixture.trust(),
                    fixture.created_at_ms + 100,
                )
                .unwrap(),
        );
        assert_ne!(first.claim_id(), second.claim_id());
        assert_ne!(first.session_id(), second.session_id());
        let status = fixture.actor.status().unwrap();
        assert_eq!(status.accepted_claims, 2);
        assert_eq!(status.one_time_reuse_anomalies, 1);
    }

    #[test]
    fn valid_pairinit_uses_retained_generation_but_expired_pairinit_is_rejected() {
        let fixture = Fixture::new();
        let pair = fixture.pair(1);
        let now = pair.expires_at_ms - 1;
        let claim = take_claim(
            fixture
                .actor
                .claim_pair_init(&pair, &fixture.trust(), now)
                .unwrap(),
        );
        assert!(claim.session_id().iter().any(|byte| *byte != 0));

        let fresh = Fixture::new();
        assert!(matches!(
            fresh.actor.claim_pair_init(
                &fresh.pair(1),
                &fresh.trust(),
                fresh.pair(1).expires_at_ms
            ),
            Err(PrekeyLifecycleError::PairInit(
                PairInitError::NotCurrentlyValid
            ))
        ));
    }

    #[test]
    fn init_id_collision_with_different_signed_hash_is_rejected() {
        let fixture = Fixture::new();
        let first = fixture.pair(1);
        fixture
            .actor
            .claim_pair_init(&first, &fixture.trust(), fixture.created_at_ms + 100)
            .unwrap();
        let mut conflict = fixture.pair(2);
        conflict.init_id = first.init_id;
        conflict.signature = fixture
            .initiator_device
            .sign(&init_signing_bytes(&conflict).unwrap());
        assert!(matches!(
            fixture
                .actor
                .claim_pair_init(&conflict, &fixture.trust(), fixture.created_at_ms + 100),
            Err(PrekeyLifecycleError::InitIdConflict)
        ));
        assert_eq!(fixture.actor.status().unwrap().accepted_claims, 1);
    }

    #[test]
    fn claim_journal_recovers_both_crash_boundaries_idempotently() {
        for point in [FaultPoint::ClaimJournal, FaultPoint::ClaimCommit] {
            let fixture = Fixture::new();
            let pair = fixture.pair(1);
            fixture.actor.inject_fault(point).unwrap();
            assert!(matches!(
                fixture
                    .actor
                    .claim_pair_init(&pair, &fixture.trust(), fixture.created_at_ms + 100),
                Err(PrekeyLifecycleError::InjectedCrash(_))
            ));
            let reopened = fixture.reopen();
            let mut recovered = take_claim(
                reopened
                    .claim_pair_init(&pair, &fixture.trust(), fixture.created_at_ms + 101)
                    .unwrap(),
            );
            assert!(recovered.take_provisional_root().is_some());
            assert_eq!(reopened.status().unwrap().accepted_claims, 1);
            assert_eq!(reopened.status().unwrap().one_time_reuse_anomalies, 0);
        }
    }

    #[test]
    fn protected_final_write_failure_recovers_durable_claim_journal() {
        let fixture = Fixture::new();
        let failing = Arc::new(FailFinalProtectedWrite::new(fixture.backend.clone()));
        let actor =
            PrekeyLifecycleActor::open_with_backend(fixture.data_dir.path(), failing.clone())
                .unwrap();
        let pair = fixture.pair(1);
        failing.fail_after_one_success();
        assert!(matches!(
            actor.claim_pair_init(&pair, &fixture.trust(), fixture.created_at_ms + 100),
            Err(PrekeyLifecycleError::ProtectedStore)
        ));
        let mut recovered = take_claim(
            actor
                .claim_pair_init(&pair, &fixture.trust(), fixture.created_at_ms + 101)
                .unwrap(),
        );
        assert!(recovered.take_provisional_root().is_some());
        let status = actor.status().unwrap();
        assert_eq!(status.accepted_claims, 1);
        assert_eq!(status.one_time_reuse_anomalies, 0);
    }

    #[test]
    fn rotation_journal_recovers_monotonic_head() {
        for point in [FaultPoint::RotationJournal, FaultPoint::RotationCommit] {
            let fixture = Fixture::new();
            let mut second = fixture.bundle.clone();
            second.signed_prekey_id = 2;
            second.one_time_prekey_id = 0;
            second.one_time_x25519_pub = None;
            second.signature = [0u8; 64];
            second = second.sign(&fixture.responder_user).unwrap();
            fixture.actor.inject_fault(point).unwrap();
            assert!(matches!(
                fixture.actor.install_generation(
                    std::slice::from_ref(&second),
                    PrekeyGenerationPrivate::new([0x52; 32], fixture.mlkem_seed, Vec::new()),
                    fixture.created_at_ms + 1
                ),
                Err(PrekeyLifecycleError::InjectedCrash(_))
            ));
            let reopened = fixture.reopen();
            let status = reopened.status().unwrap();
            assert_eq!(status.highest_signed_prekey_id, 2);
            assert_eq!(status.active_signed_prekey_id, Some(2));
            assert_eq!(status.retained_generations, 2);
            assert!(matches!(
                reopened.install_generation(
                    std::slice::from_ref(&second),
                    PrekeyGenerationPrivate::new([0x52; 32], fixture.mlkem_seed, Vec::new()),
                    fixture.created_at_ms + 2
                ),
                Err(PrekeyLifecycleError::NonMonotonicSignedPrekeyId)
            ));
        }
    }

    #[test]
    fn rotation_rejects_wrong_identity_and_wrong_device_lineage() {
        let fixture = Fixture::new();
        let mut wrong_identity = fixture.bundle.clone();
        wrong_identity.signed_prekey_id = 2;
        wrong_identity.identity_ed25519_pub = [0u8; 32];
        wrong_identity.signature = [0u8; 64];
        let other_identity = Identity::from_seed(&[0x99; 32]);
        wrong_identity = wrong_identity.sign(&other_identity).unwrap();
        assert!(matches!(
            fixture.actor.install_generation(
                std::slice::from_ref(&wrong_identity),
                PrekeyGenerationPrivate::new(
                    [0x52; 32],
                    fixture.mlkem_seed,
                    vec![OneTimePrekeyPrivate::new(7, fixture.otp_secret).unwrap()],
                ),
                fixture.created_at_ms + 1
            ),
            Err(PrekeyLifecycleError::ActorLineageMismatch)
        ));

        let mut wrong_device = fixture.bundle.clone();
        wrong_device.signed_prekey_id = 2;
        wrong_device.device_id = "other-device".into();
        wrong_device.signature = [0u8; 64];
        wrong_device = wrong_device.sign(&fixture.responder_user).unwrap();
        assert!(matches!(
            fixture.actor.install_generation(
                std::slice::from_ref(&wrong_device),
                PrekeyGenerationPrivate::new(
                    [0x52; 32],
                    fixture.mlkem_seed,
                    vec![OneTimePrekeyPrivate::new(7, fixture.otp_secret).unwrap()],
                ),
                fixture.created_at_ms + 1
            ),
            Err(PrekeyLifecycleError::ActorLineageMismatch)
        ));
        let status = fixture.actor.status().unwrap();
        assert_eq!(status.highest_signed_prekey_id, 1);
        assert_eq!(status.retained_generations, 1);
    }

    #[test]
    fn expiry_never_destroys_pending_before_bounded_handoff_deadline() {
        let fixture = Fixture::new();
        let pair = fixture.pair(1);
        let claim = take_claim(
            fixture
                .actor
                .claim_pair_init(&pair, &fixture.trust(), fixture.created_at_ms + 100)
                .unwrap(),
        );
        fixture.actor.retire_active(fixture.created_at_ms).unwrap();
        let at_deadline = fixture.created_at_ms + 100 + PREKEY_ROOT_HANDOFF_TIMEOUT_MS;
        let retained = fixture.actor.prune_expired(at_deadline).unwrap();
        assert_eq!(retained.destroyed_generations, 0);
        assert_eq!(retained.expired_pending_handoffs, 0);
        let pruned = fixture.actor.prune_expired(at_deadline + 1).unwrap();
        assert_eq!(pruned.expired_pending_handoffs, 1);
        assert_eq!(pruned.destroyed_generations, 0);
        assert_eq!(fixture.actor.status().unwrap().pending_handoffs, 0);
        assert!(matches!(
            fixture
                .actor
                .complete_claim(&claim.claim_id(), &claim.session_id()),
            Err(PrekeyLifecycleError::ClaimHandoffExpired)
        ));
        let destroyed = fixture
            .actor
            .prune_expired(fixture.bundle.expires_at_ms + PREKEY_RETENTION_GRACE_MS + 1)
            .unwrap();
        assert_eq!(destroyed.destroyed_generations, 1);
        assert_eq!(destroyed.destroyed_claim_tombstones, 1);
    }

    #[test]
    fn completed_handoff_is_idempotent_and_allows_explicit_destruction() {
        let fixture = Fixture::new();
        let pair = fixture.pair(1);
        let claim = take_claim(
            fixture
                .actor
                .claim_pair_init(&pair, &fixture.trust(), fixture.created_at_ms + 100)
                .unwrap(),
        );
        let mut wrong_session = claim.session_id();
        wrong_session[0] ^= 1;
        assert!(matches!(
            fixture
                .actor
                .complete_claim(&claim.claim_id(), &wrong_session),
            Err(PrekeyLifecycleError::ClaimBindingMismatch)
        ));
        assert_eq!(fixture.actor.status().unwrap().pending_handoffs, 1);
        assert_eq!(
            fixture
                .actor
                .complete_claim(&claim.claim_id(), &claim.session_id())
                .unwrap(),
            CompleteClaimOutcome::Completed
        );
        assert_eq!(
            fixture
                .actor
                .complete_claim(&claim.claim_id(), &claim.session_id())
                .unwrap(),
            CompleteClaimOutcome::AlreadyCompleted
        );
        assert!(matches!(
            fixture
                .actor
                .claim_pair_init(&pair, &fixture.trust(), fixture.created_at_ms + 101)
                .unwrap(),
            PrekeyClaimOutcome::DuplicateCompleted { .. }
        ));
        fixture.actor.retire_active(fixture.created_at_ms).unwrap();
        let outcome = fixture
            .actor
            .prune_expired(pair.expires_at_ms + PREKEY_RETENTION_GRACE_MS + 1)
            .unwrap();
        assert_eq!(outcome.destroyed_generations, 1);
        assert_eq!(outcome.destroyed_claim_tombstones, 1);
    }

    #[test]
    fn concurrent_exact_claim_has_one_record_and_no_anomaly() {
        let fixture = Arc::new(Fixture::new());
        let second_actor = Arc::new(fixture.reopen());
        let barrier = Arc::new(Barrier::new(3));
        let mut joins = Vec::new();
        for index in 0..2 {
            let fixture = fixture.clone();
            let barrier = barrier.clone();
            let actor = if index == 0 {
                fixture.actor.clone()
            } else {
                second_actor.clone()
            };
            joins.push(thread::spawn(move || {
                let pair = fixture.pair(1);
                barrier.wait();
                actor
                    .claim_pair_init(&pair, &fixture.trust(), fixture.created_at_ms + 100)
                    .unwrap()
            }));
        }
        barrier.wait();
        let outcomes: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PrekeyClaimOutcome::Accepted(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PrekeyClaimOutcome::DuplicatePending(_)))
                .count(),
            1
        );
        let status = fixture.actor.status().unwrap();
        assert_eq!(status.accepted_claims, 1);
        assert_eq!(status.one_time_reuse_anomalies, 0);
    }

    #[test]
    fn protected_blob_has_secrets_but_secret_free_lock_database_does_not() {
        let fixture = Fixture::new();
        let protected_values = fixture.backend.values.lock().unwrap();
        let protected = protected_values.values().next().unwrap();
        let otp_encoding = serde_json::to_vec(&fixture.otp_secret).unwrap();
        let mlkem_encoding = serde_json::to_vec(&fixture.mlkem_seed.as_slice()).unwrap();
        assert!(protected
            .windows(otp_encoding.len())
            .any(|window| window == otp_encoding));
        drop(protected_values);
        let lock = std::fs::read(fixture.data_dir.path().join(PREKEY_LIFECYCLE_LOCK_FILE)).unwrap();
        assert!(!lock
            .windows(otp_encoding.len())
            .any(|window| window == otp_encoding));
        assert!(!lock
            .windows(mlkem_encoding.len())
            .any(|window| window == mlkem_encoding));
    }

    #[test]
    fn corrupt_and_oversized_protected_state_fail_closed() {
        let data_dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(MemoryProtectedBackend::default());
        let actor =
            PrekeyLifecycleActor::open_with_backend(data_dir.path(), backend.clone()).unwrap();
        backend.values.lock().unwrap().insert(
            actor.account.clone(),
            vec![0u8; MAX_PROTECTED_PREKEY_STATE_BYTES + 1],
        );
        assert!(matches!(
            actor.status(),
            Err(PrekeyLifecycleError::CorruptProtectedState)
        ));
        backend
            .values
            .lock()
            .unwrap()
            .insert(actor.account.clone(), b"not-json".to_vec());
        assert!(matches!(
            actor.status(),
            Err(PrekeyLifecycleError::CorruptProtectedState)
        ));
    }

    #[test]
    fn resource_and_time_limits_fail_without_mutation() {
        let fixture = Fixture::new();
        let mut too_long = fixture.pair(1);
        too_long.expires_at_ms = too_long.created_at_ms + MAX_PAIR_INIT_LIFETIME_MS + 1;
        too_long.signature = fixture
            .initiator_device
            .sign(&init_signing_bytes(&too_long).unwrap());
        assert!(matches!(
            fixture
                .actor
                .claim_pair_init(&too_long, &fixture.trust(), fixture.created_at_ms + 100),
            Err(PrekeyLifecycleError::PairInitLifetime)
        ));
        let future = fixture.pair(2);
        assert!(matches!(
            fixture.actor.claim_pair_init(
                &future,
                &fixture.trust(),
                fixture
                    .created_at_ms
                    .saturating_sub(MAX_PREKEY_FUTURE_SKEW_MS)
                    .saturating_sub(1)
            ),
            Err(PrekeyLifecycleError::PairInitClockSkew)
        ));
        assert_eq!(fixture.actor.status().unwrap().accepted_claims, 0);

        let empty = PrekeyGenerationPrivate::new([9; 32], [8; DK_SEED_LEN], Vec::new());
        assert!(matches!(
            build_generation(&[], empty, fixture.created_at_ms),
            Err(PrekeyLifecycleError::ResourceLimit)
        ));
        assert!(matches!(
            OneTimePrekeyPrivate::new(7, [0u8; 32]),
            Err(PrekeyLifecycleError::InvalidGeneration)
        ));
        assert!(matches!(
            build_generation(
                std::slice::from_ref(&fixture.bundle),
                PrekeyGenerationPrivate::new(
                    [0u8; 32],
                    fixture.mlkem_seed,
                    vec![OneTimePrekeyPrivate::new(7, fixture.otp_secret).unwrap()],
                ),
                fixture.created_at_ms,
            ),
            Err(PrekeyLifecycleError::InvalidGeneration)
        ));
        assert!(matches!(
            build_generation(
                std::slice::from_ref(&fixture.bundle),
                PrekeyGenerationPrivate::new(
                    [0x52; 32],
                    [0u8; DK_SEED_LEN],
                    vec![OneTimePrekeyPrivate::new(7, fixture.otp_secret).unwrap()],
                ),
                fixture.created_at_ms,
            ),
            Err(PrekeyLifecycleError::InvalidGeneration)
        ));
    }

    #[test]
    fn lock_file_is_owner_only_on_unix() {
        let fixture = Fixture::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(fixture.data_dir.path().join(PREKEY_LIFECYCLE_LOCK_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn reference_vector_private_material_derives_expected_root() {
        let mut pair_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pair_path.pop();
        pair_path.pop();
        pair_path.pop();
        let hybrid_path = pair_path.join("shared-vectors/rvn1/atsam/mlkem768_hybrid_kat_001.json");
        let init_path = pair_path.join("shared-vectors/rvn1/atsam/pair_init_v1_001.json");
        let hybrid: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(hybrid_path).unwrap()).unwrap();
        let init_vector: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(init_path).unwrap()).unwrap();
        let init = decode_init(
            &hex::decode(
                init_vector["expected"]["pair_init_wire_hex"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let otp_secret: [u8; 32] =
            hex::decode(hybrid["input"]["bob_x25519_secret_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let mlkem_seed: [u8; DK_SEED_LEN] =
            hex::decode(hybrid["input"]["mlkem_seed_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let root = respond_hybrid_root(
            &otp_secret,
            &init.initiator_ephemeral_x25519_pub,
            &mlkem_seed,
            &init.mlkem768_ciphertext,
            &transcript_hash(&init).unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(root),
            init_vector["expected"]["provisional_k_root_hex"]
                .as_str()
                .unwrap()
        );
    }
}
