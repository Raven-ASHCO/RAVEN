//! Protected local chat-history metadata (petname-first).
//!
//! The durable history file is always authenticated ciphertext. On macOS and
//! GNU/Linux its random encryption key lives in Keychain / Secret Service; on
//! Windows the payload is protected directly with user-scoped DPAPI. There is
//! deliberately no plaintext or mode-0600-key fallback.
//!
//! Headless GNU/Linux CI has no session bus. Debug lab/CI (and `cfg(test)`)
//! may derive a per-`data_dir` key when Secret Service **connect** fails and
//! an explicit locked-file override is set (`RAVEN_CHAT_HISTORY_BACKEND` or
//! `RAVEN_IDENTITY_BACKEND`). Locked/search/get stay fail-closed. Release
//! never takes this path.

use crate::sanitize::sanitize_terminal_text;
#[cfg(any(
    test,
    target_os = "macos",
    all(target_os = "linux", target_env = "gnu")
))]
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
#[cfg(any(
    test,
    target_os = "macos",
    all(target_os = "linux", target_env = "gnu")
))]
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
#[cfg(any(
    test,
    target_os = "macos",
    windows,
    all(target_os = "linux", target_env = "gnu")
))]
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChatHistoryEntry {
    pub message_id_hex: String,
    pub direction: String, // "out" | "in"
    pub peer_petname: String,
    pub peer_tag: String,
    pub peer_pub_hex: String,
    pub created_at_ms: u64,
    pub delivery: String,
    /// Short sanitized preview for list UIs.
    pub preview: String,
    /// Full sanitized plaintext body (LAN endpoint size). Empty on legacy rows.
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatHistory {
    pub entries: Vec<ChatHistoryEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChatHistoryError {
    #[error("chat history I/O failed: {0}")]
    Io(String),
    #[error("protected chat-history backend unavailable: {0}")]
    ProtectedStoreUnavailable(String),
    #[error("protected chat-history key is missing")]
    MissingProtectedKey,
    #[error("protected chat-history key is corrupt")]
    CorruptProtectedKey,
    #[error("chat history is corrupt")]
    Corrupt,
    #[error("chat history authentication failed (wrong key or tampered file)")]
    AuthenticationFailed,
    #[error("chat history exceeds the local size limit")]
    TooLarge,
    #[error("legacy plaintext chat history is malformed; original file was preserved")]
    MalformedLegacyPlaintext,
    #[error("chat history has unsafe file metadata")]
    UnsafeFileMetadata,
}

/// Injectable protection boundary. Production callers use
/// [`PlatformChatHistoryProtector`]; deterministic in-memory implementations
/// let headless CI exercise all file semantics without weakening production.
trait ChatHistoryProtector: Send + Sync {
    fn protect(&self, data_dir: &Path, plaintext: &[u8]) -> Result<Vec<u8>, ChatHistoryError>;
    fn unprotect(&self, data_dir: &Path, ciphertext: &[u8]) -> Result<Vec<u8>, ChatHistoryError>;
    /// Stage ciphertext may still be sealed under the pre-split history AAD.
    /// Returns `(plaintext, needs_rewrite_with_stage_aad)`.
    fn unprotect_stage(
        &self,
        data_dir: &Path,
        ciphertext: &[u8],
    ) -> Result<(Vec<u8>, bool), ChatHistoryError> {
        Ok((self.unprotect(data_dir, ciphertext)?, false))
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct PlatformChatHistoryProtector;

const MAX_ENTRIES: usize = 2_000;
const MAX_HISTORY_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_HISTORY_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
/// Serialized JSON budget before AEAD (12+16) and MAGIC (8) so saves stay under
/// both plaintext and on-disk caps. Eviction uses this, not entry count alone.
/// Equals min(MAX_HISTORY_PLAINTEXT_BYTES, MAX_HISTORY_FILE_BYTES - 36).
const MAX_HISTORY_SERIALIZED_BYTES: usize = 4 * 1024 * 1024 - 36;
const HISTORY_MAGIC: &[u8; 8] = b"RVNHIST1";
#[cfg(any(
    test,
    target_os = "macos",
    windows,
    all(target_os = "linux", target_env = "gnu")
))]
const HISTORY_AAD_DOMAIN: &[u8] = b"raven/chat-history/v1";
#[cfg(any(
    test,
    target_os = "macos",
    windows,
    all(target_os = "linux", target_env = "gnu")
))]
const STAGE_AAD_DOMAIN: &[u8] = b"raven/outbound-stage/v1";
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
const HISTORY_KEY_SERVICE: &str = "app.raven.node.chat-history.v1";
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const HISTORY_KEY_LABEL: &str = "RAVEN protected local chat history";
const MAX_MESSAGE_ID_CHARS: usize = 128;
const MAX_DIRECTION_CHARS: usize = 8;
const MAX_PETNAME_CHARS: usize = 512;
const MAX_TAG_CHARS: usize = 512;
const MAX_PUBLIC_KEY_CHARS: usize = 256;
const MAX_DELIVERY_CHARS: usize = 64;
const MAX_PREVIEW_CHARS: usize = 120;
/// Full message body retained for durable history (matches LAN endpoint text cap).
const MAX_BODY_CHARS: usize = 48 * 1024;

pub fn history_path(data_dir: &Path) -> PathBuf {
    // Retain the historical path for compatibility. Its contents are binary,
    // authenticated ciphertext after the first protected save/migration.
    data_dir.join("chat_history.json")
}

pub fn blocked_path(data_dir: &Path) -> PathBuf {
    data_dir.join("blocked_pubs.json")
}

fn history_lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join(".chat_history.lock.sqlite")
}

struct HistoryLock {
    _connection: rusqlite::Connection,
}

impl HistoryLock {
    fn acquire(data_dir: &Path) -> Result<Self, ChatHistoryError> {
        std::fs::create_dir_all(data_dir).map_err(|e| ChatHistoryError::Io(e.to_string()))?;
        let connection = rusqlite::Connection::open(history_lock_path(data_dir))
            .map_err(|e| ChatHistoryError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                history_lock_path(data_dir),
                std::fs::Permissions::from_mode(0o600),
            )
            .map_err(|e| ChatHistoryError::Io(e.to_string()))?;
        }
        connection
            .busy_timeout(Duration::from_secs(10))
            .map_err(|e| ChatHistoryError::Io(e.to_string()))?;
        connection
            .execute_batch("BEGIN EXCLUSIVE")
            .map_err(|e| ChatHistoryError::Io(format!("history lock: {e}")))?;
        Ok(Self {
            _connection: connection,
        })
    }
}

impl ChatHistory {
    /// Load protected history. Missing files are an empty history; existing
    /// files never degrade to empty on keychain, parse, or authentication error.
    pub fn load(data_dir: &Path) -> Result<Self, ChatHistoryError> {
        Self::load_with_protector(data_dir, &PlatformChatHistoryProtector)
    }

    fn load_with_protector(
        data_dir: &Path,
        protector: &dyn ChatHistoryProtector,
    ) -> Result<Self, ChatHistoryError> {
        let _lock = HistoryLock::acquire(data_dir)?;
        Self::load_unlocked(data_dir, protector)
    }

    pub fn save(&self, data_dir: &Path) -> Result<(), ChatHistoryError> {
        self.save_with_protector(data_dir, &PlatformChatHistoryProtector)
    }

    fn save_with_protector(
        &self,
        data_dir: &Path,
        protector: &dyn ChatHistoryProtector,
    ) -> Result<(), ChatHistoryError> {
        let _lock = HistoryLock::acquire(data_dir)?;
        self.save_unlocked(data_dir, protector)
    }

    /// Append and persist under one inter-process lock, avoiding lost updates
    /// when ash and another local process write concurrently.
    pub fn append_persisted(
        data_dir: &Path,
        entry: ChatHistoryEntry,
    ) -> Result<(), ChatHistoryError> {
        Self::append_persisted_with_protector(data_dir, entry, &PlatformChatHistoryProtector)
    }

    fn append_persisted_with_protector(
        data_dir: &Path,
        entry: ChatHistoryEntry,
        protector: &dyn ChatHistoryProtector,
    ) -> Result<(), ChatHistoryError> {
        let _lock = HistoryLock::acquire(data_dir)?;
        let mut history = Self::load_unlocked(data_dir, protector)?;
        history.upsert(entry);
        history.save_unlocked(data_dir, protector)
    }

    /// Upgrade delivery on an existing `(peer, direction, message_id)` row.
    /// Returns `Ok(true)` when updated, `Ok(false)` when no matching row exists.
    pub fn set_delivery_persisted(
        data_dir: &Path,
        peer_pub_hex: &str,
        direction: &str,
        message_id_hex: &str,
        delivery: &str,
    ) -> Result<bool, ChatHistoryError> {
        Self::set_delivery_persisted_with_protector(
            data_dir,
            peer_pub_hex,
            direction,
            message_id_hex,
            delivery,
            &PlatformChatHistoryProtector,
        )
    }

    fn set_delivery_persisted_with_protector(
        data_dir: &Path,
        peer_pub_hex: &str,
        direction: &str,
        message_id_hex: &str,
        delivery: &str,
        protector: &dyn ChatHistoryProtector,
    ) -> Result<bool, ChatHistoryError> {
        let _lock = HistoryLock::acquire(data_dir)?;
        let mut history = Self::load_unlocked(data_dir, protector)?;
        let want_peer = peer_pub_hex.trim().to_lowercase();
        let want_dir = truncate_sanitized(direction, MAX_DIRECTION_CHARS);
        let want_mid = truncate_sanitized(message_id_hex, MAX_MESSAGE_ID_CHARS);
        let want_delivery = truncate_sanitized(delivery, MAX_DELIVERY_CHARS);
        if let Some(entry) = history.entries.iter_mut().find(|e| {
            !want_mid.is_empty()
                && e.message_id_hex.eq_ignore_ascii_case(&want_mid)
                && e.peer_pub_hex.eq_ignore_ascii_case(&want_peer)
                && e.direction == want_dir
        }) {
            entry.delivery = want_delivery;
            history.save_unlocked(data_dir, protector)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// True when a history row exists with a non-empty body for that key.
    pub fn has_body_persisted(
        data_dir: &Path,
        peer_pub_hex: &str,
        direction: &str,
        message_id_hex: &str,
    ) -> Result<bool, ChatHistoryError> {
        let history = Self::load(data_dir)?;
        let want_peer = peer_pub_hex.trim().to_lowercase();
        let want_dir = truncate_sanitized(direction, MAX_DIRECTION_CHARS);
        let want_mid = truncate_sanitized(message_id_hex, MAX_MESSAGE_ID_CHARS);
        Ok(history.entries.iter().any(|e| {
            !want_mid.is_empty()
                && e.message_id_hex.eq_ignore_ascii_case(&want_mid)
                && e.peer_pub_hex.eq_ignore_ascii_case(&want_peer)
                && e.direction == want_dir
                && !e.body.is_empty()
        }))
    }

    /// Clear one peer and persist under the same lock used by append/migration.
    pub fn clear_peer_persisted(data_dir: &Path, pub_hex: &str) -> Result<(), ChatHistoryError> {
        Self::clear_peer_persisted_with_protector(data_dir, pub_hex, &PlatformChatHistoryProtector)
    }

    fn clear_peer_persisted_with_protector(
        data_dir: &Path,
        pub_hex: &str,
        protector: &dyn ChatHistoryProtector,
    ) -> Result<(), ChatHistoryError> {
        let _lock = HistoryLock::acquire(data_dir)?;
        let mut history = Self::load_unlocked(data_dir, protector)?;
        history.clear_peer(pub_hex);
        history.save_unlocked(data_dir, protector)
    }

    fn load_unlocked(
        data_dir: &Path,
        protector: &dyn ChatHistoryProtector,
    ) -> Result<Self, ChatHistoryError> {
        let path = history_path(data_dir);
        let Some(bytes) = read_history_file(&path)? else {
            return Ok(Self::default());
        };
        let mut bytes = Zeroizing::new(bytes);

        if bytes.starts_with(HISTORY_MAGIC) {
            validate_private_file_metadata(&path)?;
            let plaintext = protector.unprotect(data_dir, &bytes[HISTORY_MAGIC.len()..])?;
            let plaintext = Zeroizing::new(plaintext);
            if plaintext.len() > MAX_HISTORY_PLAINTEXT_BYTES {
                return Err(ChatHistoryError::TooLarge);
            }
            let history: Self =
                serde_json::from_slice(&plaintext).map_err(|_| ChatHistoryError::Corrupt)?;
            history.validate()?;
            return Ok(history);
        }

        // One-time, crash-safe migration from the old JSON file. The old file
        // remains untouched unless encryption, protected-key persistence,
        // ciphertext fsync, and atomic replacement all succeed.
        let first = bytes
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace());
        if first == Some(b'{') {
            let mut history: Self = serde_json::from_slice(&bytes)
                .map_err(|_| ChatHistoryError::MalformedLegacyPlaintext)?;
            history.normalize_all();
            history.validate()?;
            history.save_unlocked(data_dir, protector)?;
            bytes.zeroize();
            return Ok(history);
        }

        Err(ChatHistoryError::Corrupt)
    }

    fn save_unlocked(
        &self,
        data_dir: &Path,
        protector: &dyn ChatHistoryProtector,
    ) -> Result<(), ChatHistoryError> {
        self.validate()?;
        let plaintext = serde_json::to_vec(self).map_err(|_| ChatHistoryError::Corrupt)?;
        let plaintext = Zeroizing::new(plaintext);
        if plaintext.len() > MAX_HISTORY_PLAINTEXT_BYTES {
            return Err(ChatHistoryError::TooLarge);
        }
        let protected = protector.protect(data_dir, &plaintext)?;
        let total_len = HISTORY_MAGIC
            .len()
            .checked_add(protected.len())
            .ok_or(ChatHistoryError::TooLarge)?;
        if total_len as u64 > MAX_HISTORY_FILE_BYTES {
            return Err(ChatHistoryError::TooLarge);
        }
        let mut encoded = Vec::with_capacity(total_len);
        encoded.extend_from_slice(HISTORY_MAGIC);
        encoded.extend_from_slice(&protected);
        atomic_write_private(&history_path(data_dir), &encoded)
    }

    pub fn append(&mut self, entry: ChatHistoryEntry) {
        self.upsert(entry);
    }

    /// Insert or update by `(peer_pub, direction, message_id)`. Updates refresh
    /// delivery (and body when provided) so outbound can go `queued` → `delivered`.
    pub fn upsert(&mut self, mut entry: ChatHistoryEntry) {
        normalize_entry(&mut entry);
        if let Some(existing) = self.entries.iter_mut().find(|e| {
            !entry.message_id_hex.is_empty()
                && e.message_id_hex.eq_ignore_ascii_case(&entry.message_id_hex)
                && e.peer_pub_hex.eq_ignore_ascii_case(&entry.peer_pub_hex)
                && e.direction == entry.direction
        }) {
            if !entry.body.is_empty() {
                existing.body = entry.body;
                existing.preview = entry.preview;
            }
            if !entry.delivery.is_empty() {
                existing.delivery = entry.delivery;
            }
            if entry.created_at_ms > 0 {
                existing.created_at_ms = entry.created_at_ms;
            }
            if !entry.peer_petname.is_empty() {
                existing.peer_petname = entry.peer_petname;
            }
            if !entry.peer_tag.is_empty() {
                existing.peer_tag = entry.peer_tag;
            }
            self.enforce_capacity();
            return;
        }
        self.entries.push(entry);
        self.enforce_capacity();
    }

    /// Drop oldest entries until count and serialized JSON fit the durable caps.
    fn enforce_capacity(&mut self) {
        if self.entries.len() > MAX_ENTRIES {
            let drop = self.entries.len() - MAX_ENTRIES;
            self.entries.drain(0..drop);
        }
        while !self.entries.is_empty() {
            let Ok(serialized) = serde_json::to_vec(self) else {
                break;
            };
            if serialized.len() <= MAX_HISTORY_SERIALIZED_BYTES {
                break;
            }
            self.entries.remove(0);
        }
    }

    pub fn for_peer<'a>(&'a self, pub_hex: &str) -> Vec<&'a ChatHistoryEntry> {
        let want = pub_hex.trim().to_lowercase();
        self.entries
            .iter()
            .filter(|e| e.peer_pub_hex.eq_ignore_ascii_case(&want))
            .collect()
    }

    pub fn clear_peer(&mut self, pub_hex: &str) {
        let want = pub_hex.trim().to_lowercase();
        self.entries
            .retain(|e| !e.peer_pub_hex.eq_ignore_ascii_case(&want));
    }

    fn normalize_all(&mut self) {
        for entry in &mut self.entries {
            normalize_entry(entry);
        }
        self.enforce_capacity();
    }

    fn validate(&self) -> Result<(), ChatHistoryError> {
        if self.entries.len() > MAX_ENTRIES {
            return Err(ChatHistoryError::TooLarge);
        }
        for entry in &self.entries {
            let fields = [
                (&entry.message_id_hex, MAX_MESSAGE_ID_CHARS),
                (&entry.direction, MAX_DIRECTION_CHARS),
                (&entry.peer_petname, MAX_PETNAME_CHARS),
                (&entry.peer_tag, MAX_TAG_CHARS),
                (&entry.peer_pub_hex, MAX_PUBLIC_KEY_CHARS),
                (&entry.delivery, MAX_DELIVERY_CHARS),
                (&entry.preview, MAX_PREVIEW_CHARS),
                (&entry.body, MAX_BODY_CHARS),
            ];
            if fields
                .iter()
                .any(|(value, maximum)| value.chars().count() > *maximum)
            {
                return Err(ChatHistoryError::TooLarge);
            }
            if truncate_sanitized(&entry.message_id_hex, MAX_MESSAGE_ID_CHARS)
                != entry.message_id_hex
                || truncate_sanitized(&entry.direction, MAX_DIRECTION_CHARS) != entry.direction
                || truncate_sanitized(&entry.peer_petname, MAX_PETNAME_CHARS) != entry.peer_petname
                || truncate_sanitized(&entry.peer_tag, MAX_TAG_CHARS) != entry.peer_tag
                || truncate_sanitized(&entry.peer_pub_hex, MAX_PUBLIC_KEY_CHARS)
                    != entry.peer_pub_hex
                || truncate_sanitized(&entry.delivery, MAX_DELIVERY_CHARS) != entry.delivery
                || truncate_sanitized(&entry.preview, MAX_PREVIEW_CHARS) != entry.preview
                || truncate_sanitized(&entry.body, MAX_BODY_CHARS) != entry.body
            {
                return Err(ChatHistoryError::Corrupt);
            }
        }
        Ok(())
    }
}

fn normalize_entry(entry: &mut ChatHistoryEntry) {
    entry.message_id_hex = truncate_sanitized(&entry.message_id_hex, MAX_MESSAGE_ID_CHARS);
    entry.direction = truncate_sanitized(&entry.direction, MAX_DIRECTION_CHARS);
    entry.peer_petname = truncate_sanitized(&entry.peer_petname, MAX_PETNAME_CHARS);
    entry.peer_tag = truncate_sanitized(&entry.peer_tag, MAX_TAG_CHARS);
    entry.peer_pub_hex =
        truncate_sanitized(&entry.peer_pub_hex, MAX_PUBLIC_KEY_CHARS).to_lowercase();
    entry.delivery = truncate_sanitized(&entry.delivery, MAX_DELIVERY_CHARS);
    entry.preview = truncate_sanitized(&entry.preview, MAX_PREVIEW_CHARS);
    entry.body = truncate_sanitized(&entry.body, MAX_BODY_CHARS);
    if entry.body.is_empty() && !entry.preview.is_empty() {
        // Legacy rows: preview was the only payload.
        entry.body = entry.preview.clone();
    } else if entry.preview.is_empty() && !entry.body.is_empty() {
        entry.preview = entry.body.chars().take(MAX_PREVIEW_CHARS).collect();
    }
}

fn truncate_sanitized(value: &str, maximum: usize) -> String {
    sanitize_terminal_text(value)
        .chars()
        .map(|character| match character {
            '\t' | '\n' | '\r' => ' ',
            other => other,
        })
        .take(maximum)
        .collect()
}

fn read_history_file(path: &Path) -> Result<Option<Vec<u8>>, ChatHistoryError> {
    let path_metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ChatHistoryError::Io(error.to_string())),
    };
    validate_regular_history_file(path)?;
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) => return Err(ChatHistoryError::Io(error.to_string())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| ChatHistoryError::Io(error.to_string()))?;
    if !metadata.is_file() {
        return Err(ChatHistoryError::UnsafeFileMetadata);
    }
    if metadata.len() != path_metadata.len() {
        return Err(ChatHistoryError::UnsafeFileMetadata);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.dev() != path_metadata.dev() || metadata.ino() != path_metadata.ino() {
            return Err(ChatHistoryError::UnsafeFileMetadata);
        }
    }
    if metadata.len() > MAX_HISTORY_FILE_BYTES {
        return Err(ChatHistoryError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| ChatHistoryError::Io(error.to_string()))?;
    if bytes.len() as u64 > MAX_HISTORY_FILE_BYTES {
        return Err(ChatHistoryError::TooLarge);
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn validate_regular_history_file(path: &Path) -> Result<(), ChatHistoryError> {
    use std::os::unix::fs::MetadataExt;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| ChatHistoryError::Io(error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1
    {
        return Err(ChatHistoryError::UnsafeFileMetadata);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_regular_history_file(path: &Path) -> Result<(), ChatHistoryError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| ChatHistoryError::Io(error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ChatHistoryError::UnsafeFileMetadata);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file_metadata(path: &Path) -> Result<(), ChatHistoryError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| ChatHistoryError::Io(error.to_string()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ChatHistoryError::UnsafeFileMetadata);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file_metadata(path: &Path) -> Result<(), ChatHistoryError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| ChatHistoryError::Io(error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ChatHistoryError::UnsafeFileMetadata);
    }
    Ok(())
}

fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<(), ChatHistoryError> {
    let parent = path
        .parent()
        .ok_or_else(|| ChatHistoryError::Io("history path has no parent".into()))?;
    std::fs::create_dir_all(parent).map_err(|error| ChatHistoryError::Io(error.to_string()))?;

    let (temporary, mut file) = loop {
        let candidate = parent.join(format!(".chat_history.tmp.{:016x}", rand::random::<u64>()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(ChatHistoryError::Io(error.to_string())),
        }
    };

    let prepared = file.write_all(contents).and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = prepared {
        let _ = std::fs::remove_file(&temporary);
        return Err(ChatHistoryError::Io(error.to_string()));
    }

    if let Err(error) = replace_file(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }

    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| ChatHistoryError::Io(error.to_string()))?;
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(temporary: &Path, destination: &Path) -> Result<(), ChatHistoryError> {
    std::fs::rename(temporary, destination).map_err(|error| ChatHistoryError::Io(error.to_string()))
}

#[cfg(windows)]
fn replace_file(temporary: &Path, destination: &Path) -> Result<(), ChatHistoryError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let mut from: Vec<u16> = temporary.as_os_str().encode_wide().collect();
    from.push(0);
    let mut to: Vec<u16> = destination.as_os_str().encode_wide().collect();
    to.push(0);
    let ok = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        return Err(ChatHistoryError::Io(
            "atomic history replacement failed".into(),
        ));
    }
    Ok(())
}

#[cfg(any(
    test,
    target_os = "macos",
    windows,
    all(target_os = "linux", target_env = "gnu")
))]
fn scoped_aad(data_dir: &Path, domain: &[u8]) -> [u8; 32] {
    let canonical = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(b"/");
    hasher.update(canonical.to_string_lossy().as_bytes());
    hasher.finalize().into()
}

#[cfg(any(
    test,
    target_os = "macos",
    all(target_os = "linux", target_env = "gnu")
))]
fn history_scope(data_dir: &Path) -> [u8; 32] {
    scoped_aad(data_dir, HISTORY_AAD_DOMAIN)
}

#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
fn history_account(data_dir: &Path) -> String {
    hex::encode(history_scope(data_dir))
}

#[cfg(any(
    test,
    target_os = "macos",
    all(target_os = "linux", target_env = "gnu")
))]
fn aead_protect(
    key: &[u8; 32],
    data_dir: &Path,
    domain: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ChatHistoryError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| ChatHistoryError::CorruptProtectedKey)?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let aad = scoped_aad(data_dir, domain);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| ChatHistoryError::AuthenticationFailed)?;
    let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

#[cfg(any(
    test,
    target_os = "macos",
    all(target_os = "linux", target_env = "gnu")
))]
fn aead_unprotect(
    key: &[u8; 32],
    data_dir: &Path,
    domain: &[u8],
    protected: &[u8],
) -> Result<Vec<u8>, ChatHistoryError> {
    if protected.len() < 12 + 16 {
        return Err(ChatHistoryError::Corrupt);
    }
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| ChatHistoryError::CorruptProtectedKey)?;
    let aad = scoped_aad(data_dir, domain);
    cipher
        .decrypt(
            Nonce::from_slice(&protected[..12]),
            Payload {
                msg: &protected[12..],
                aad: &aad,
            },
        )
        .map_err(|_| ChatHistoryError::AuthenticationFailed)
}

#[cfg(target_os = "macos")]
fn platform_get_key(data_dir: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, ChatHistoryError> {
    use security_framework::passwords::get_generic_password;
    let account = history_account(data_dir);
    match get_generic_password(HISTORY_KEY_SERVICE, &account) {
        Ok(mut bytes) => {
            if bytes.len() != 32 {
                bytes.zeroize();
                return Err(ChatHistoryError::CorruptProtectedKey);
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&bytes);
            bytes.zeroize();
            Ok(Some(key))
        }
        Err(error) if error.code() == -25_300 => Ok(None),
        Err(error) => Err(ChatHistoryError::ProtectedStoreUnavailable(format!(
            "keychain read failed: {error}"
        ))),
    }
}

#[cfg(target_os = "macos")]
fn platform_set_key(data_dir: &Path, key: &[u8; 32]) -> Result<(), ChatHistoryError> {
    use security_framework::passwords::set_generic_password;
    let account = history_account(data_dir);
    set_generic_password(HISTORY_KEY_SERVICE, &account, key).map_err(|error| {
        ChatHistoryError::ProtectedStoreUnavailable(format!("keychain update failed: {error}"))
    })
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn platform_get_key(data_dir: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, ChatHistoryError> {
    use secret_service::{EncryptionType, SecretService};
    use std::collections::HashMap;
    let service = SecretService::new(EncryptionType::Dh).map_err(|error| {
        ChatHistoryError::ProtectedStoreUnavailable(format!(
            "secret-service connection failed: {error}"
        ))
    })?;
    let collection = service.get_default_collection().map_err(|error| {
        ChatHistoryError::ProtectedStoreUnavailable(format!(
            "secret-service collection failed: {error}"
        ))
    })?;
    match collection.is_locked() {
        Ok(false) => {}
        Ok(true) => {
            return Err(ChatHistoryError::ProtectedStoreUnavailable(
                "secret-service collection locked".into(),
            ));
        }
        Err(error) => {
            return Err(ChatHistoryError::ProtectedStoreUnavailable(format!(
                "secret-service is_locked failed: {error}"
            )));
        }
    }
    let account = history_account(data_dir);
    let items = collection
        .search_items(HashMap::from([
            ("service", HISTORY_KEY_SERVICE),
            ("account", account.as_str()),
        ]))
        .map_err(|error| {
            ChatHistoryError::ProtectedStoreUnavailable(format!(
                "secret-service search failed: {error}"
            ))
        })?;
    let Some(item) = items.into_iter().next() else {
        return Ok(None);
    };
    let mut bytes = item.get_secret().map_err(|error| {
        ChatHistoryError::ProtectedStoreUnavailable(format!("secret-service read failed: {error}"))
    })?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(ChatHistoryError::CorruptProtectedKey);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(Some(key))
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn platform_set_key(data_dir: &Path, key: &[u8; 32]) -> Result<(), ChatHistoryError> {
    use secret_service::{EncryptionType, SecretService};
    use std::collections::HashMap;
    let service = SecretService::new(EncryptionType::Dh).map_err(|error| {
        ChatHistoryError::ProtectedStoreUnavailable(format!(
            "secret-service connection failed: {error}"
        ))
    })?;
    let collection = service.get_default_collection().map_err(|error| {
        ChatHistoryError::ProtectedStoreUnavailable(format!(
            "secret-service collection failed: {error}"
        ))
    })?;
    match collection.is_locked() {
        Ok(false) => {}
        Ok(true) => {
            return Err(ChatHistoryError::ProtectedStoreUnavailable(
                "secret-service collection locked".into(),
            ));
        }
        Err(error) => {
            return Err(ChatHistoryError::ProtectedStoreUnavailable(format!(
                "secret-service is_locked failed: {error}"
            )));
        }
    }
    let account = history_account(data_dir);
    collection
        .create_item(
            HISTORY_KEY_LABEL,
            HashMap::from([
                ("service", HISTORY_KEY_SERVICE),
                ("account", account.as_str()),
            ]),
            key,
            true,
            "application/octet-stream",
        )
        .map_err(|error| {
            ChatHistoryError::ProtectedStoreUnavailable(format!(
                "secret-service update failed: {error}"
            ))
        })?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn linux_secret_service_connect_failed(err: &ChatHistoryError) -> bool {
    matches!(
        err,
        ChatHistoryError::ProtectedStoreUnavailable(msg)
            if msg.contains("secret-service connection failed:")
                || msg.contains("ServiceUnknown")
    )
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn chat_history_lab_backend_requested() -> bool {
    for key in ["RAVEN_CHAT_HISTORY_BACKEND", "RAVEN_IDENTITY_BACKEND"] {
        if std::env::var_os(key).is_some_and(|v| v == "locked-file") {
            return true;
        }
    }
    false
}

/// Same GNU/Linux SS connect-fail lab path as identity/prekey.
///
/// `cfg(test)` keeps `cargo test -p raven-core` green. Debug ash/raven-node
/// (CI smokes) also take this path when an explicit locked-file env is set.
/// Never Release; never a 0600-key fallback.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn chat_history_lab_key_allowed() -> bool {
    cfg!(test) || (cfg!(debug_assertions) && chat_history_lab_backend_requested())
}

/// Headless rust-linux has no session bus. This is **not** a production
/// 0600-key fallback — lab/CI only, per-`data_dir` derived key so send and
/// lan_dispatch can exercise history/stage without org.freedesktop.secrets.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn lab_history_key(data_dir: &Path) -> Zeroizing<[u8; 32]> {
    let canonical = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(b"raven/chat-history/test-lab-key/v1");
    hasher.update(canonical.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest);
    key
}

#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
fn load_platform_key(
    data_dir: &Path,
    create: bool,
) -> Result<Zeroizing<[u8; 32]>, ChatHistoryError> {
    match platform_get_key(data_dir) {
        Ok(Some(key)) => return Ok(key),
        Ok(None) => {}
        Err(e) => {
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            if linux_secret_service_connect_failed(&e) && chat_history_lab_key_allowed() {
                return Ok(lab_history_key(data_dir));
            }
            return Err(e);
        }
    }
    if !create {
        return Err(ChatHistoryError::MissingProtectedKey);
    }
    let mut generated = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *generated);
    platform_set_key(data_dir, &generated)?;
    let confirmed = platform_get_key(data_dir)?.ok_or(ChatHistoryError::MissingProtectedKey)?;
    if *confirmed != *generated {
        return Err(ChatHistoryError::ProtectedStoreUnavailable(
            "concurrent protected-key initialization".into(),
        ));
    }
    Ok(confirmed)
}

impl ChatHistoryProtector for PlatformChatHistoryProtector {
    fn protect(&self, data_dir: &Path, plaintext: &[u8]) -> Result<Vec<u8>, ChatHistoryError> {
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            let key = load_platform_key(data_dir, true)?;
            aead_protect(&key, data_dir, HISTORY_AAD_DOMAIN, plaintext)
        }
        #[cfg(windows)]
        {
            dpapi_protect_blob(data_dir, HISTORY_AAD_DOMAIN, plaintext)
        }
        #[cfg(not(any(
            target_os = "macos",
            windows,
            all(target_os = "linux", target_env = "gnu")
        )))]
        {
            let _ = (data_dir, plaintext);
            Err(ChatHistoryError::ProtectedStoreUnavailable(
                "no supported platform-protected backend".into(),
            ))
        }
    }

    fn unprotect(&self, data_dir: &Path, ciphertext: &[u8]) -> Result<Vec<u8>, ChatHistoryError> {
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            let key = load_platform_key(data_dir, false)?;
            aead_unprotect(&key, data_dir, HISTORY_AAD_DOMAIN, ciphertext)
        }
        #[cfg(windows)]
        {
            dpapi_unprotect_blob(data_dir, HISTORY_AAD_DOMAIN, ciphertext)
        }
        #[cfg(not(any(
            target_os = "macos",
            windows,
            all(target_os = "linux", target_env = "gnu")
        )))]
        {
            let _ = (data_dir, ciphertext);
            Err(ChatHistoryError::ProtectedStoreUnavailable(
                "no supported platform-protected backend".into(),
            ))
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct PlatformOutboundStageProtector;

impl ChatHistoryProtector for PlatformOutboundStageProtector {
    fn protect(&self, data_dir: &Path, plaintext: &[u8]) -> Result<Vec<u8>, ChatHistoryError> {
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            let key = load_platform_key(data_dir, true)?;
            aead_protect(&key, data_dir, STAGE_AAD_DOMAIN, plaintext)
        }
        #[cfg(windows)]
        {
            dpapi_protect_blob(data_dir, STAGE_AAD_DOMAIN, plaintext)
        }
        #[cfg(not(any(
            target_os = "macos",
            windows,
            all(target_os = "linux", target_env = "gnu")
        )))]
        {
            let _ = (data_dir, plaintext);
            Err(ChatHistoryError::ProtectedStoreUnavailable(
                "no supported platform-protected backend".into(),
            ))
        }
    }

    fn unprotect(&self, data_dir: &Path, ciphertext: &[u8]) -> Result<Vec<u8>, ChatHistoryError> {
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            let key = load_platform_key(data_dir, false)?;
            aead_unprotect(&key, data_dir, STAGE_AAD_DOMAIN, ciphertext)
        }
        #[cfg(windows)]
        {
            dpapi_unprotect_blob(data_dir, STAGE_AAD_DOMAIN, ciphertext)
        }
        #[cfg(not(any(
            target_os = "macos",
            windows,
            all(target_os = "linux", target_env = "gnu")
        )))]
        {
            let _ = (data_dir, ciphertext);
            Err(ChatHistoryError::ProtectedStoreUnavailable(
                "no supported platform-protected backend".into(),
            ))
        }
    }

    fn unprotect_stage(
        &self,
        data_dir: &Path,
        ciphertext: &[u8],
    ) -> Result<(Vec<u8>, bool), ChatHistoryError> {
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            let key = load_platform_key(data_dir, false)?;
            unprotect_stage_aead_with_legacy_fallback(&key, data_dir, ciphertext)
        }
        #[cfg(windows)]
        {
            unprotect_stage_dpapi_with_legacy_fallback(data_dir, ciphertext)
        }
        #[cfg(not(any(
            target_os = "macos",
            windows,
            all(target_os = "linux", target_env = "gnu")
        )))]
        {
            let _ = (data_dir, ciphertext);
            Err(ChatHistoryError::ProtectedStoreUnavailable(
                "no supported platform-protected backend".into(),
            ))
        }
    }
}

/// Prefer stage AAD; accept one prior generation sealed under chat-history AAD.
/// `true` means the blob used history AAD and must be rewritten.
#[cfg(any(
    test,
    target_os = "macos",
    all(target_os = "linux", target_env = "gnu")
))]
fn unprotect_stage_aead_with_legacy_fallback(
    key: &[u8; 32],
    data_dir: &Path,
    ciphertext: &[u8],
) -> Result<(Vec<u8>, bool), ChatHistoryError> {
    match aead_unprotect(key, data_dir, STAGE_AAD_DOMAIN, ciphertext) {
        Ok(plaintext) => Ok((plaintext, false)),
        Err(ChatHistoryError::AuthenticationFailed) => {
            let plaintext = aead_unprotect(key, data_dir, HISTORY_AAD_DOMAIN, ciphertext)?;
            Ok((plaintext, true))
        }
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn unprotect_stage_dpapi_with_legacy_fallback(
    data_dir: &Path,
    ciphertext: &[u8],
) -> Result<(Vec<u8>, bool), ChatHistoryError> {
    match dpapi_unprotect_blob(data_dir, STAGE_AAD_DOMAIN, ciphertext) {
        Ok(plaintext) => Ok((plaintext, false)),
        Err(ChatHistoryError::AuthenticationFailed) => {
            let plaintext = dpapi_unprotect_blob(data_dir, HISTORY_AAD_DOMAIN, ciphertext)?;
            Ok((plaintext, true))
        }
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn dpapi_protect_blob(
    data_dir: &Path,
    domain: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ChatHistoryError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext
            .len()
            .try_into()
            .map_err(|_| ChatHistoryError::TooLarge)?,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let scope = scoped_aad(data_dir, domain);
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: scope.len() as u32,
        pbData: scope.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            &entropy,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() || output.cbData == 0 {
        return Err(ChatHistoryError::ProtectedStoreUnavailable(
            "CryptProtectData failed".into(),
        ));
    }
    let protected =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(protected)
}

#[cfg(windows)]
fn dpapi_unprotect_blob(
    data_dir: &Path,
    domain: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ChatHistoryError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext
            .len()
            .try_into()
            .map_err(|_| ChatHistoryError::TooLarge)?,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let scope = scoped_aad(data_dir, domain);
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: scope.len() as u32,
        pbData: scope.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &entropy,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() {
        return Err(ChatHistoryError::AuthenticationFailed);
    }
    let plaintext =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(plaintext)
}

// ── Protected outbound body stage (pre-History durability) ────────────────

const STAGE_MAGIC: &[u8; 8] = b"RVNOSTG1";
const MAX_STAGE_ENTRIES: usize = 256;
const MAX_STAGE_BODY_CHARS: usize = 48 * 1024;
const MAX_STAGE_HEX_CHARS: usize = 128;
/// Must match `read_history_file` / on-disk loader cap (MAGIC + AEAD overhead).
const MAX_STAGE_FILE_BYTES: u64 = MAX_HISTORY_FILE_BYTES;
const MAX_STAGE_SERIALIZED_BYTES: usize = MAX_HISTORY_SERIALIZED_BYTES;

/// Durable outbound plaintext staged before ChatHistory `queued` / dial.
/// On-disk encoding is authenticated ciphertext with a *separate* AAD domain
/// (`raven/outbound-stage/v1`) from ChatHistory. Bindings prevent retry from
/// attaching the body to the wrong recipient/session/object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StagedOutboundBody {
    pub peer_pub_hex: String,
    pub session_id_hex: String,
    pub object_digest_hex: String,
    pub message_id_hex: String,
    pub body: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OutboundBodyStageFile {
    entries: Vec<StagedOutboundBody>,
}

pub fn outbound_body_stage_path(data_dir: &Path) -> PathBuf {
    data_dir.join("outbound_body_stage.bin")
}

fn outbound_body_stage_legacy_path(data_dir: &Path) -> PathBuf {
    data_dir.join("outbound_body_stage.json")
}

fn normalize_stage_body(body: &str) -> String {
    sanitize_terminal_text(body)
        .chars()
        .map(|c| match c {
            '\t' | '\n' | '\r' => ' ',
            other => other,
        })
        .take(MAX_STAGE_BODY_CHARS)
        .collect()
}

fn normalize_stage_hex(value: &str) -> String {
    truncate_sanitized(value, MAX_STAGE_HEX_CHARS).to_lowercase()
}

fn stage_lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join(".outbound_body_stage.lock.sqlite")
}

struct StageLock {
    _connection: rusqlite::Connection,
}

impl StageLock {
    fn acquire(data_dir: &Path) -> Result<Self, ChatHistoryError> {
        std::fs::create_dir_all(data_dir).map_err(|e| ChatHistoryError::Io(e.to_string()))?;
        let connection = rusqlite::Connection::open(stage_lock_path(data_dir))
            .map_err(|e| ChatHistoryError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                stage_lock_path(data_dir),
                std::fs::Permissions::from_mode(0o600),
            );
        }
        connection
            .busy_timeout(Duration::from_secs(10))
            .map_err(|e| ChatHistoryError::Io(e.to_string()))?;
        connection
            .execute_batch("BEGIN EXCLUSIVE")
            .map_err(|e| ChatHistoryError::Io(format!("outbound stage lock: {e}")))?;
        Ok(Self {
            _connection: connection,
        })
    }
}

fn stage_serialized_len(file: &OutboundBodyStageFile) -> Result<usize, ChatHistoryError> {
    serde_json::to_vec(file)
        .map(|v| v.len())
        .map_err(|_| ChatHistoryError::Corrupt)
}

/// Fail-closed capacity: never silently drop active staged bodies.
fn stage_within_budget(file: &OutboundBodyStageFile) -> Result<(), ChatHistoryError> {
    if file.entries.len() > MAX_STAGE_ENTRIES {
        return Err(ChatHistoryError::TooLarge);
    }
    let serialized = stage_serialized_len(file)?;
    if serialized > MAX_STAGE_SERIALIZED_BYTES {
        return Err(ChatHistoryError::TooLarge);
    }
    Ok(())
}

fn probe_stage_capacity_for_body(
    file: &OutboundBodyStageFile,
    body: &str,
    created_at_ms: u64,
) -> Result<(), ChatHistoryError> {
    let mut probe = file.clone();
    // Always size created_at_ms at u64::MAX JSON width so preflight cannot
    // under-count wall-clock stamps (0 is 1 digit; u64::MAX is 20).
    let _ = created_at_ms;
    let probe_created_at = u64::MAX;
    probe.entries.push(StagedOutboundBody {
        peer_pub_hex: normalize_stage_hex(&hex::encode([0u8; 32])),
        session_id_hex: normalize_stage_hex(&hex::encode([0u8; 32])),
        object_digest_hex: normalize_stage_hex(&hex::encode([0u8; 32])),
        message_id_hex: normalize_stage_hex(&hex::encode([0u8; 16])),
        body: normalize_stage_body(body),
        created_at_ms: probe_created_at,
    });
    stage_within_budget(&probe)?;
    let plaintext = serde_json::to_vec(&probe).map_err(|_| ChatHistoryError::Corrupt)?;
    if plaintext.len() > MAX_STAGE_SERIALIZED_BYTES {
        return Err(ChatHistoryError::TooLarge);
    }
    let total = STAGE_MAGIC
        .len()
        .checked_add(12)
        .and_then(|n| n.checked_add(16))
        .and_then(|n| n.checked_add(plaintext.len()))
        .ok_or(ChatHistoryError::TooLarge)?;
    if total as u64 > MAX_STAGE_FILE_BYTES {
        return Err(ChatHistoryError::TooLarge);
    }
    Ok(())
}

/// Exclusive stage lock held from capacity preflight until the new outbound body
/// is staged (or the send is abandoned). Must be dropped before network I/O.
pub struct OutboundStageSendGuard {
    data_dir: PathBuf,
    _lock: StageLock,
}

impl OutboundStageSendGuard {
    /// Acquire the stage lock and refuse if one more body of `body` would not fit.
    /// `created_at_ms` must match the timestamp that will be staged.
    pub fn acquire(
        data_dir: &Path,
        body: &str,
        created_at_ms: u64,
    ) -> Result<Self, ChatHistoryError> {
        let lock = StageLock::acquire(data_dir)?;
        let guard = Self {
            data_dir: data_dir.to_path_buf(),
            _lock: lock,
        };
        let file =
            load_stage_file_with_protector(&guard.data_dir, &PlatformOutboundStageProtector)?;
        probe_stage_capacity_for_body(&file, body, created_at_ms)?;
        Ok(guard)
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Stage under the already-held lock (no nested StageLock acquire).
    #[allow(clippy::too_many_arguments)]
    pub fn stage_outbound_body(
        &self,
        peer_pub: &[u8; 32],
        session_id: &[u8; 32],
        object_digest: &[u8; 32],
        message_id: &[u8; 16],
        created_at_ms: u64,
        body: &str,
    ) -> Result<(), ChatHistoryError> {
        stage_outbound_body_locked(
            &self.data_dir,
            peer_pub,
            session_id,
            object_digest,
            message_id,
            created_at_ms,
            body,
            &PlatformOutboundStageProtector,
        )
    }

    pub fn load_staged_outbound_body(
        &self,
        message_id: &[u8; 16],
    ) -> Result<Option<StagedOutboundBody>, ChatHistoryError> {
        let file = load_stage_file_with_protector(&self.data_dir, &PlatformOutboundStageProtector)?;
        let mid = hex::encode(message_id);
        Ok(file
            .entries
            .into_iter()
            .find(|e| e.message_id_hex.eq_ignore_ascii_case(&mid)))
    }
}

/// Preflight-only helper for tests: acquire+probe then drop (does not hold lock).
#[cfg(test)]
fn ensure_outbound_stage_capacity_with_protector(
    data_dir: &Path,
    body: &str,
    created_at_ms: u64,
    protector: &dyn ChatHistoryProtector,
) -> Result<(), ChatHistoryError> {
    let _lock = StageLock::acquire(data_dir)?;
    let file = load_stage_file_with_protector(data_dir, protector)?;
    probe_stage_capacity_for_body(&file, body, created_at_ms)
}

fn remove_legacy_plaintext_stage(data_dir: &Path) -> Result<(), ChatHistoryError> {
    let legacy = outbound_body_stage_legacy_path(data_dir);
    match std::fs::symlink_metadata(&legacy) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ChatHistoryError::Io(format!(
            "legacy outbound stage audit failed: {e}"
        ))),
        Ok(_) => {
            // Same hardlink/symlink policy as chat-history migration: nlink must
            // be exactly 1 so deleting this path cannot leave a plaintext alias.
            validate_regular_history_file(&legacy)?;
            std::fs::remove_file(&legacy).map_err(|e| {
                ChatHistoryError::Io(format!("legacy outbound stage delete failed: {e}"))
            })?;
            if legacy.exists() {
                return Err(ChatHistoryError::Io(
                    "legacy outbound stage still present after delete".into(),
                ));
            }
            Ok(())
        }
    }
}

fn load_stage_file_with_protector(
    data_dir: &Path,
    protector: &dyn ChatHistoryProtector,
) -> Result<OutboundBodyStageFile, ChatHistoryError> {
    let path = outbound_body_stage_path(data_dir);
    let legacy = outbound_body_stage_legacy_path(data_dir);
    let file = if let Some(bytes) = read_history_file(&path)? {
        let (file, needs_rewrite) = decode_stage_bytes(data_dir, protector, &path, bytes)?;
        stage_within_budget(&file)?;
        if needs_rewrite {
            save_stage_file_with_protector(data_dir, &file, protector)?;
        }
        file
    } else if let Some(bytes) = read_history_file(&legacy)? {
        let (file, _) = decode_stage_bytes(data_dir, protector, &legacy, bytes)?;
        stage_within_budget(&file)?;
        save_stage_file_with_protector(data_dir, &file, protector)?;
        file
    } else {
        OutboundBodyStageFile::default()
    };
    remove_legacy_plaintext_stage(data_dir)?;
    Ok(file)
}

fn decode_stage_bytes(
    data_dir: &Path,
    protector: &dyn ChatHistoryProtector,
    path: &Path,
    bytes: Vec<u8>,
) -> Result<(OutboundBodyStageFile, bool), ChatHistoryError> {
    if bytes.starts_with(STAGE_MAGIC) {
        validate_private_file_metadata(path)?;
        let (plaintext, needs_rewrite) =
            protector.unprotect_stage(data_dir, &bytes[STAGE_MAGIC.len()..])?;
        let plaintext = Zeroizing::new(plaintext);
        if plaintext.len() > MAX_STAGE_SERIALIZED_BYTES {
            return Err(ChatHistoryError::TooLarge);
        }
        let file = serde_json::from_slice(&plaintext).map_err(|_| ChatHistoryError::Corrupt)?;
        return Ok((file, needs_rewrite));
    }
    let first = bytes.iter().copied().find(|b| !b.is_ascii_whitespace());
    if first == Some(b'{') {
        if let Ok(file) = serde_json::from_slice::<OutboundBodyStageFile>(&bytes) {
            return Ok((file, true));
        }
        #[derive(Deserialize)]
        struct LegacyMap {
            entries: std::collections::BTreeMap<String, StagedOutboundBody>,
        }
        if let Ok(legacy) = serde_json::from_slice::<LegacyMap>(&bytes) {
            return Ok((
                OutboundBodyStageFile {
                    entries: legacy.entries.into_values().collect(),
                },
                true,
            ));
        }
        return Err(ChatHistoryError::Corrupt);
    }
    Err(ChatHistoryError::Corrupt)
}

fn save_stage_file_with_protector(
    data_dir: &Path,
    file: &OutboundBodyStageFile,
    protector: &dyn ChatHistoryProtector,
) -> Result<(), ChatHistoryError> {
    stage_within_budget(file)?;
    let plaintext = serde_json::to_vec(file).map_err(|_| ChatHistoryError::Corrupt)?;
    let plaintext = Zeroizing::new(plaintext);
    if plaintext.len() > MAX_STAGE_SERIALIZED_BYTES {
        return Err(ChatHistoryError::TooLarge);
    }
    let protected = protector.protect(data_dir, &plaintext)?;
    let total_len = STAGE_MAGIC
        .len()
        .checked_add(protected.len())
        .ok_or(ChatHistoryError::TooLarge)?;
    if total_len as u64 > MAX_STAGE_FILE_BYTES {
        return Err(ChatHistoryError::TooLarge);
    }
    let mut encoded = Vec::with_capacity(total_len);
    encoded.extend_from_slice(STAGE_MAGIC);
    encoded.extend_from_slice(&protected);
    atomic_write_private(&outbound_body_stage_path(data_dir), &encoded)?;
    remove_legacy_plaintext_stage(data_dir)
}

/// Persist outbound plaintext before ChatHistory / dial. Idempotent per message_id.
/// Fail-closed when count/byte budget would be exceeded (never drops other active stages).
pub fn stage_outbound_body(
    data_dir: &Path,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    created_at_ms: u64,
    body: &str,
) -> Result<(), ChatHistoryError> {
    let _lock = StageLock::acquire(data_dir)?;
    stage_outbound_body_locked(
        data_dir,
        peer_pub,
        session_id,
        object_digest,
        message_id,
        created_at_ms,
        body,
        &PlatformOutboundStageProtector,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn stage_outbound_body_with_protector(
    data_dir: &Path,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    created_at_ms: u64,
    body: &str,
    protector: &dyn ChatHistoryProtector,
) -> Result<(), ChatHistoryError> {
    let _lock = StageLock::acquire(data_dir)?;
    stage_outbound_body_locked(
        data_dir,
        peer_pub,
        session_id,
        object_digest,
        message_id,
        created_at_ms,
        body,
        protector,
    )
}

#[allow(clippy::too_many_arguments)]
fn stage_outbound_body_locked(
    data_dir: &Path,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    created_at_ms: u64,
    body: &str,
    protector: &dyn ChatHistoryProtector,
) -> Result<(), ChatHistoryError> {
    let mut file = load_stage_file_with_protector(data_dir, protector)?;
    let mid = hex::encode(message_id);
    file.entries
        .retain(|e| !e.message_id_hex.eq_ignore_ascii_case(&mid));
    file.entries.push(StagedOutboundBody {
        peer_pub_hex: normalize_stage_hex(&hex::encode(peer_pub)),
        session_id_hex: normalize_stage_hex(&hex::encode(session_id)),
        object_digest_hex: normalize_stage_hex(&hex::encode(object_digest)),
        message_id_hex: normalize_stage_hex(&mid),
        body: normalize_stage_body(body),
        created_at_ms,
    });
    stage_within_budget(&file)?;
    save_stage_file_with_protector(data_dir, &file, protector)
}

/// Load a staged body (does not remove). Missing is `Ok(None)`.
pub fn load_staged_outbound_body(
    data_dir: &Path,
    message_id: &[u8; 16],
) -> Result<Option<StagedOutboundBody>, ChatHistoryError> {
    load_staged_outbound_body_with_protector(data_dir, message_id, &PlatformOutboundStageProtector)
}

fn load_staged_outbound_body_with_protector(
    data_dir: &Path,
    message_id: &[u8; 16],
    protector: &dyn ChatHistoryProtector,
) -> Result<Option<StagedOutboundBody>, ChatHistoryError> {
    let _lock = StageLock::acquire(data_dir)?;
    let file = load_stage_file_with_protector(data_dir, protector)?;
    let mid = hex::encode(message_id);
    Ok(file
        .entries
        .into_iter()
        .find(|e| e.message_id_hex.eq_ignore_ascii_case(&mid)))
}

/// All staged outbound bodies (for post-ACK / abandon reconciliation).
pub fn list_staged_outbound_bodies(
    data_dir: &Path,
) -> Result<Vec<StagedOutboundBody>, ChatHistoryError> {
    let _lock = StageLock::acquire(data_dir)?;
    Ok(load_stage_file_with_protector(data_dir, &PlatformOutboundStageProtector)?.entries)
}

/// Remove staged body after delivered / abandoned.
pub fn clear_staged_outbound_body(
    data_dir: &Path,
    message_id: &[u8; 16],
) -> Result<(), ChatHistoryError> {
    clear_staged_outbound_body_with_protector(data_dir, message_id, &PlatformOutboundStageProtector)
}

fn clear_staged_outbound_body_with_protector(
    data_dir: &Path,
    message_id: &[u8; 16],
    protector: &dyn ChatHistoryProtector,
) -> Result<(), ChatHistoryError> {
    let _lock = StageLock::acquire(data_dir)?;
    let mut file = load_stage_file_with_protector(data_dir, protector)?;
    let mid = hex::encode(message_id);
    let before = file.entries.len();
    file.entries
        .retain(|e| !e.message_id_hex.eq_ignore_ascii_case(&mid));
    if file.entries.len() != before {
        if file.entries.is_empty() {
            let path = outbound_body_stage_path(data_dir);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(ChatHistoryError::Io(e.to_string())),
            }
            remove_legacy_plaintext_stage(data_dir)?;
        } else {
            save_stage_file_with_protector(data_dir, &file, protector)?;
        }
    } else {
        remove_legacy_plaintext_stage(data_dir)?;
    }
    Ok(())
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BlockList {
    pub pub_hex: Vec<String>,
}

impl BlockList {
    pub fn load(data_dir: &Path) -> Self {
        Self::load_checked(data_dir).unwrap_or_default()
    }

    /// Missing file → empty list. Corrupt JSON → error (fail-closed for policy).
    pub fn load_checked(data_dir: &Path) -> Result<Self, String> {
        let path = blocked_path(data_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path).map_err(|e| format!("block list read: {e}"))?;
        serde_json::from_str(&raw).map_err(|e| format!("block list corrupt: {e}"))
    }

    pub fn save(&self, data_dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
        let raw = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::paths::atomic_write_private(&blocked_path(data_dir), raw.as_bytes())
    }

    pub fn is_blocked(&self, pub_hex: &str) -> bool {
        let want = pub_hex.trim().to_lowercase();
        self.pub_hex.iter().any(|p| p.eq_ignore_ascii_case(&want))
    }

    pub fn block(&mut self, pub_hex: &str) {
        let h = pub_hex.trim().to_lowercase();
        if !self.is_blocked(&h) {
            self.pub_hex.push(h);
        }
    }

    pub fn unblock(&mut self, pub_hex: &str) {
        let want = pub_hex.trim().to_lowercase();
        self.pub_hex.retain(|p| !p.eq_ignore_ascii_case(&want));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn linux_ss_connect_fail_classifier_is_narrow() {
        let connect = ChatHistoryError::ProtectedStoreUnavailable(
            "secret-service connection failed: zbus error: I/O error: No such file or directory (os error 2)"
                .into(),
        );
        let service_unknown = ChatHistoryError::ProtectedStoreUnavailable(
            "secret-service connection failed: zbus error: org.freedesktop.DBus.Error.ServiceUnknown: \
             The name org.freedesktop.secrets was not provided by any .service files"
                .into(),
        );
        let locked =
            ChatHistoryError::ProtectedStoreUnavailable("secret-service collection locked".into());
        let search = ChatHistoryError::ProtectedStoreUnavailable(
            "secret-service search failed: denied".into(),
        );
        let read = ChatHistoryError::ProtectedStoreUnavailable(
            "secret-service read failed: denied".into(),
        );
        assert!(linux_secret_service_connect_failed(&connect));
        assert!(linux_secret_service_connect_failed(&service_unknown));
        assert!(!linux_secret_service_connect_failed(&locked));
        assert!(!linux_secret_service_connect_failed(&search));
        assert!(!linux_secret_service_connect_failed(&read));
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn linux_lab_history_key_is_stable_per_data_dir() {
        let dir = tempdir().unwrap();
        let a = lab_history_key(dir.path());
        let b = lab_history_key(dir.path());
        assert_eq!(*a, *b);
        let other = tempdir().unwrap();
        let c = lab_history_key(other.path());
        assert_ne!(*a, *c);
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn linux_platform_protector_roundtrips_without_secret_service() {
        let dir = tempdir().unwrap();
        let protector = PlatformChatHistoryProtector;
        let plain = b"{\"entries\":[]}";
        let ct = protector
            .protect(dir.path(), plain)
            .expect("lab or Secret Service protect");
        let back = protector
            .unprotect(dir.path(), &ct)
            .expect("lab or Secret Service unprotect");
        assert_eq!(back, plain);
    }

    struct TestProtector {
        key: [u8; 32],
        available: bool,
    }

    impl TestProtector {
        fn new(byte: u8) -> Self {
            Self {
                key: [byte; 32],
                available: true,
            }
        }
    }

    impl ChatHistoryProtector for TestProtector {
        fn protect(&self, data_dir: &Path, plaintext: &[u8]) -> Result<Vec<u8>, ChatHistoryError> {
            if !self.available {
                return Err(ChatHistoryError::ProtectedStoreUnavailable("test".into()));
            }
            aead_protect(&self.key, data_dir, HISTORY_AAD_DOMAIN, plaintext)
        }

        fn unprotect(
            &self,
            data_dir: &Path,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, ChatHistoryError> {
            if !self.available {
                return Err(ChatHistoryError::ProtectedStoreUnavailable("test".into()));
            }
            aead_unprotect(&self.key, data_dir, HISTORY_AAD_DOMAIN, ciphertext)
        }
    }

    /// Stage tests must use the outbound-stage AAD domain (not chat-history).
    struct TestStageProtector {
        key: [u8; 32],
        available: bool,
    }

    impl TestStageProtector {
        fn new(byte: u8) -> Self {
            Self {
                key: [byte; 32],
                available: true,
            }
        }
    }

    impl ChatHistoryProtector for TestStageProtector {
        fn protect(&self, data_dir: &Path, plaintext: &[u8]) -> Result<Vec<u8>, ChatHistoryError> {
            if !self.available {
                return Err(ChatHistoryError::ProtectedStoreUnavailable("test".into()));
            }
            aead_protect(&self.key, data_dir, STAGE_AAD_DOMAIN, plaintext)
        }

        fn unprotect(
            &self,
            data_dir: &Path,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, ChatHistoryError> {
            if !self.available {
                return Err(ChatHistoryError::ProtectedStoreUnavailable("test".into()));
            }
            aead_unprotect(&self.key, data_dir, STAGE_AAD_DOMAIN, ciphertext)
        }

        fn unprotect_stage(
            &self,
            data_dir: &Path,
            ciphertext: &[u8],
        ) -> Result<(Vec<u8>, bool), ChatHistoryError> {
            if !self.available {
                return Err(ChatHistoryError::ProtectedStoreUnavailable("test".into()));
            }
            unprotect_stage_aead_with_legacy_fallback(&self.key, data_dir, ciphertext)
        }
    }

    fn sample_entry() -> ChatHistoryEntry {
        ChatHistoryEntry {
            message_id_hex: "aabbccdd00112233".into(),
            direction: "out".into(),
            peer_petname: "Alice Secret Label\x1b[31m".into(),
            peer_tag: "alice-private-tag".into(),
            peer_pub_hex: "abcdef0123456789".into(),
            created_at_ms: 1,
            delivery: "queued".into(),
            preview: "confidential hello\nthere".into(),
            body: "confidential hello\nthere".into(),
        }
    }

    #[test]
    fn protected_roundtrip_sanitizes_and_disk_has_no_plaintext_identifiers() {
        let dir = tempdir().unwrap();
        let protector = TestProtector::new(7);
        let mut history = ChatHistory::default();
        history.append(sample_entry());
        history.save_with_protector(dir.path(), &protector).unwrap();
        let disk = std::fs::read(history_path(dir.path())).unwrap();
        assert!(disk.starts_with(HISTORY_MAGIC));
        for forbidden in [
            b"Alice Secret Label".as_slice(),
            b"alice-private-tag".as_slice(),
            b"abcdef0123456789".as_slice(),
            b"aabbccdd00112233".as_slice(),
            b"confidential hello".as_slice(),
        ] {
            assert!(!disk
                .windows(forbidden.len())
                .any(|window| window == forbidden));
        }

        let loaded = ChatHistory::load_with_protector(dir.path(), &protector).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert!(!loaded.entries[0].peer_petname.contains('\x1b'));
        assert_eq!(loaded.entries[0].preview, "confidential hello there");
    }

    #[cfg(unix)]
    #[test]
    fn protected_file_is_owner_only_and_atomically_replaced() {
        use std::io::{Read, Seek, SeekFrom};
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let protector = TestProtector::new(8);
        let mut first = ChatHistory::default();
        first.append(sample_entry());
        first.save_with_protector(dir.path(), &protector).unwrap();
        let path = history_path(dir.path());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut old_handle = File::open(&path).unwrap();
        let old_disk = std::fs::read(&path).unwrap();

        let mut second = first.clone();
        let mut entry = sample_entry();
        entry.preview = "replacement text".into();
        second.append(entry);
        second.save_with_protector(dir.path(), &protector).unwrap();

        old_handle.seek(SeekFrom::Start(0)).unwrap();
        let mut old_handle_bytes = Vec::new();
        old_handle.read_to_end(&mut old_handle_bytes).unwrap();
        assert_eq!(
            old_handle_bytes, old_disk,
            "rename replaced the inode atomically"
        );
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".chat_history.tmp.")
        }));
    }

    #[test]
    fn tamper_and_corrupt_files_fail_closed_without_reset() {
        let dir = tempdir().unwrap();
        let protector = TestProtector::new(9);
        let mut history = ChatHistory::default();
        history.append(sample_entry());
        history.save_with_protector(dir.path(), &protector).unwrap();
        let path = history_path(dir.path());
        let mut tampered = std::fs::read(&path).unwrap();
        *tampered.last_mut().unwrap() ^= 0x80;
        std::fs::write(&path, &tampered).unwrap();
        let error = ChatHistory::load_with_protector(dir.path(), &protector).unwrap_err();
        assert!(matches!(error, ChatHistoryError::AuthenticationFailed));
        assert_eq!(std::fs::read(&path).unwrap(), tampered);

        let corrupt = b"not-json-and-not-protected";
        std::fs::write(&path, corrupt).unwrap();
        let error = ChatHistory::load_with_protector(dir.path(), &protector).unwrap_err();
        assert!(matches!(error, ChatHistoryError::Corrupt));
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    }

    #[test]
    fn legacy_plaintext_migrates_only_after_protected_write_succeeds() {
        let dir = tempdir().unwrap();
        let path = history_path(dir.path());
        let mut legacy = ChatHistory::default();
        legacy.append(sample_entry());
        let plaintext = serde_json::to_vec_pretty(&legacy).unwrap();
        std::fs::write(&path, &plaintext).unwrap();

        let unavailable = TestProtector {
            key: [10; 32],
            available: false,
        };
        assert!(matches!(
            ChatHistory::load_with_protector(dir.path(), &unavailable).unwrap_err(),
            ChatHistoryError::ProtectedStoreUnavailable(_)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), plaintext);

        let protector = TestProtector::new(10);
        let loaded = ChatHistory::load_with_protector(dir.path(), &protector).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        let migrated = std::fs::read(&path).unwrap();
        assert!(migrated.starts_with(HISTORY_MAGIC));
        assert!(!migrated
            .windows(b"Alice Secret Label".len())
            .any(|window| window == b"Alice Secret Label"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn legacy_hardlink_is_refused_so_no_plaintext_alias_is_left_behind() {
        let dir = tempdir().unwrap();
        let path = history_path(dir.path());
        let alias = dir.path().join("legacy-alias.json");
        let mut legacy = ChatHistory::default();
        legacy.append(sample_entry());
        let plaintext = serde_json::to_vec_pretty(&legacy).unwrap();
        std::fs::write(&path, &plaintext).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();

        let error =
            ChatHistory::load_with_protector(dir.path(), &TestProtector::new(15)).unwrap_err();
        assert!(matches!(error, ChatHistoryError::UnsafeFileMetadata));
        assert_eq!(std::fs::read(&path).unwrap(), plaintext);
        assert_eq!(std::fs::read(&alias).unwrap(), plaintext);
    }

    #[test]
    fn malformed_legacy_plaintext_is_preserved() {
        let dir = tempdir().unwrap();
        let path = history_path(dir.path());
        let malformed = b"{\"entries\":[";
        std::fs::write(&path, malformed).unwrap();
        let error =
            ChatHistory::load_with_protector(dir.path(), &TestProtector::new(11)).unwrap_err();
        assert!(matches!(error, ChatHistoryError::MalformedLegacyPlaintext));
        assert_eq!(std::fs::read(&path).unwrap(), malformed);
    }

    #[test]
    fn unavailable_backend_never_writes_plaintext_or_overwrites_ciphertext() {
        let dir = tempdir().unwrap();
        let unavailable = TestProtector {
            key: [12; 32],
            available: false,
        };
        let mut history = ChatHistory::default();
        history.append(sample_entry());
        assert!(history
            .save_with_protector(dir.path(), &unavailable)
            .is_err());
        assert!(!history_path(dir.path()).exists());

        let good = TestProtector::new(12);
        history.save_with_protector(dir.path(), &good).unwrap();
        let original = std::fs::read(history_path(dir.path())).unwrap();
        let error =
            ChatHistory::append_persisted_with_protector(dir.path(), sample_entry(), &unavailable)
                .unwrap_err();
        assert!(matches!(
            error,
            ChatHistoryError::ProtectedStoreUnavailable(_)
        ));
        assert_eq!(std::fs::read(history_path(dir.path())).unwrap(), original);
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let dir = tempdir().unwrap();
        let mut history = ChatHistory::default();
        history.append(sample_entry());
        history
            .save_with_protector(dir.path(), &TestProtector::new(13))
            .unwrap();
        let error =
            ChatHistory::load_with_protector(dir.path(), &TestProtector::new(14)).unwrap_err();
        assert!(matches!(error, ChatHistoryError::AuthenticationFailed));
    }

    #[test]
    fn block_list() {
        let dir = tempdir().unwrap();
        let mut blocklist = BlockList::default();
        blocklist.block("AABB");
        assert!(blocklist.is_blocked("aabb"));
        blocklist.save(dir.path()).unwrap();
        assert!(BlockList::load(dir.path()).is_blocked("aabb"));
    }

    #[test]
    fn block_list_corrupt_is_fail_closed() {
        let dir = tempdir().unwrap();
        std::fs::write(blocked_path(dir.path()), b"{not-json").unwrap();
        assert!(BlockList::load_checked(dir.path()).is_err());
        // Legacy load still returns empty for non-LAN callers.
        assert!(BlockList::load(dir.path()).pub_hex.is_empty());
    }

    #[test]
    fn size_budget_evicts_oldest_before_too_large() {
        let mut history = ChatHistory::default();
        let body = "x".repeat(40 * 1024);
        for i in 0..120 {
            let mut entry = sample_entry();
            entry.message_id_hex = format!("{i:032x}");
            entry.body = body.clone();
            entry.preview = body.chars().take(120).collect();
            history.append(entry);
        }
        assert!(history.entries.len() < 120);
        assert!(!history.entries.is_empty());
        let serialized = serde_json::to_vec(&history).unwrap();
        assert!(serialized.len() <= MAX_HISTORY_SERIALIZED_BYTES);
        history.validate().unwrap();
        // Newest large messages should survive FIFO eviction.
        assert_eq!(
            history.entries.last().unwrap().message_id_hex,
            format!("{:032x}", 119)
        );
    }

    #[test]
    fn upsert_upgrades_delivery_without_duplicating() {
        let mut history = ChatHistory::default();
        let mut queued = sample_entry();
        queued.delivery = "queued".into();
        history.append(queued);
        let mut delivered = sample_entry();
        delivered.delivery = "delivered".into();
        delivered.body = "confidential hello\nthere".into();
        history.upsert(delivered);
        assert_eq!(history.entries.len(), 1);
        assert_eq!(history.entries[0].delivery, "delivered");
    }

    #[test]
    fn protected_stage_survives_history_failure_restart_without_plaintext_on_disk() {
        let dir = tempdir().unwrap();
        let stage = TestStageProtector::new(42);
        let history_ok = TestProtector::new(42);
        let peer = [0x11; 32];
        let session = [0x22; 32];
        let digest = [0x33; 32];
        let mid = [0x44; 16];
        let body = "preserve-exact-outbound-body-v2";

        stage_outbound_body_with_protector(
            dir.path(),
            &peer,
            &session,
            &digest,
            &mid,
            99,
            body,
            &stage,
        )
        .unwrap();

        let unavailable = TestProtector {
            key: [9; 32],
            available: false,
        };
        assert!(ChatHistory::append_persisted_with_protector(
            dir.path(),
            ChatHistoryEntry {
                message_id_hex: hex::encode(mid),
                direction: "out".into(),
                peer_petname: String::new(),
                peer_tag: String::new(),
                peer_pub_hex: hex::encode(peer),
                created_at_ms: 99,
                delivery: "queued".into(),
                preview: body.chars().take(120).collect(),
                body: body.into(),
            },
            &unavailable,
        )
        .is_err());

        let disk = std::fs::read(outbound_body_stage_path(dir.path())).unwrap();
        assert!(disk.starts_with(STAGE_MAGIC));
        assert!(!disk.windows(body.len()).any(|w| w == body.as_bytes()));

        let staged = load_staged_outbound_body_with_protector(dir.path(), &mid, &stage)
            .unwrap()
            .expect("stage body");
        assert_eq!(staged.body, body);
        assert_eq!(staged.created_at_ms, 99);
        assert_eq!(staged.session_id_hex, hex::encode(session));
        assert_eq!(staged.object_digest_hex, hex::encode(digest));

        ChatHistory::append_persisted_with_protector(
            dir.path(),
            ChatHistoryEntry {
                message_id_hex: hex::encode(mid),
                direction: "out".into(),
                peer_petname: String::new(),
                peer_tag: String::new(),
                peer_pub_hex: hex::encode(peer),
                created_at_ms: staged.created_at_ms,
                delivery: "queued".into(),
                preview: body.chars().take(120).collect(),
                body: body.into(),
            },
            &history_ok,
        )
        .unwrap();
        assert!(ChatHistory::set_delivery_persisted_with_protector(
            dir.path(),
            &hex::encode(peer),
            "out",
            &hex::encode(mid),
            "delivered",
            &history_ok,
        )
        .unwrap());
        clear_staged_outbound_body_with_protector(dir.path(), &mid, &stage).unwrap();
        assert!(!outbound_body_stage_path(dir.path()).exists());
        let history = ChatHistory::load_with_protector(dir.path(), &history_ok).unwrap();
        assert_eq!(history.entries[0].delivery, "delivered");
        assert_eq!(history.entries[0].body, body);
        let hist_disk = std::fs::read(history_path(dir.path())).unwrap();
        assert!(!hist_disk.windows(body.len()).any(|w| w == body.as_bytes()));
    }

    #[test]
    fn stage_byte_budget_is_fail_closed_and_matches_loader_cap() {
        let dir = tempdir().unwrap();
        let protector = TestStageProtector::new(44);
        let body = "y".repeat(40 * 1024);
        let mut file = OutboundBodyStageFile::default();
        let mut accepted = 0usize;
        for i in 0..200 {
            file.entries.push(StagedOutboundBody {
                peer_pub_hex: hex::encode([1u8; 32]),
                session_id_hex: hex::encode([2u8; 32]),
                object_digest_hex: format!("{i:064x}"),
                message_id_hex: format!("{i:032x}"),
                body: body.clone(),
                created_at_ms: i as u64,
            });
            match stage_within_budget(&file) {
                Ok(()) => accepted += 1,
                Err(ChatHistoryError::TooLarge) => {
                    file.entries.pop();
                    break;
                }
                Err(e) => panic!("unexpected: {e}"),
            }
        }
        assert!(accepted >= 1);
        assert!(accepted < 200, "must refuse before unbounded growth");
        assert!(file.entries.iter().any(|e| e.created_at_ms == 0));
        save_stage_file_with_protector(dir.path(), &file, &protector).unwrap();
        let disk = std::fs::read(outbound_body_stage_path(dir.path())).unwrap();
        assert!(disk.len() as u64 <= MAX_STAGE_FILE_BYTES);
        let loaded = load_stage_file_with_protector(dir.path(), &protector).unwrap();
        assert_eq!(loaded.entries.len(), accepted);
        // Over-budget push must fail closed without dropping active rows.
        let err = stage_outbound_body_with_protector(
            dir.path(),
            &[1u8; 32],
            &[2u8; 32],
            &[0xee; 32],
            &[0xff; 16],
            9_999,
            &body,
            &protector,
        )
        .unwrap_err();
        assert!(matches!(err, ChatHistoryError::TooLarge));
        let still = load_stage_file_with_protector(dir.path(), &protector).unwrap();
        assert_eq!(still.entries.len(), accepted);
        assert!(still.entries.iter().any(|e| e.created_at_ms == 0));
    }

    #[test]
    fn legacy_plaintext_stage_is_migrated_and_deleted_even_if_bin_exists() {
        let dir = tempdir().unwrap();
        let protector = TestStageProtector::new(45);
        let peer = [3; 32];
        let session = [4; 32];
        let digest = [5; 32];
        let mid = [6; 16];
        stage_outbound_body_with_protector(
            dir.path(),
            &peer,
            &session,
            &digest,
            &mid,
            7,
            "secret-stage-body",
            &protector,
        )
        .unwrap();
        assert!(outbound_body_stage_path(dir.path()).exists());
        // Plant leftover plaintext beside bin.
        let legacy = outbound_body_stage_legacy_path(dir.path());
        std::fs::write(&legacy, br#"{"entries":[]}"#).unwrap();
        assert!(legacy.exists());
        // Any load/save path must delete legacy successfully.
        let _ = load_staged_outbound_body_with_protector(dir.path(), &mid, &protector)
            .unwrap()
            .unwrap();
        assert!(!legacy.exists(), "legacy plaintext must be removed");
    }

    #[test]
    fn stage_aad_rejects_chat_history_domain_ciphertext() {
        let dir = tempdir().unwrap();
        let key = [0x5a; 32];
        let plain = b"{\"entries\":[]}";
        let history_blob = aead_protect(&key, dir.path(), HISTORY_AAD_DOMAIN, plain).unwrap();
        let err = aead_unprotect(&key, dir.path(), STAGE_AAD_DOMAIN, &history_blob).unwrap_err();
        assert!(matches!(err, ChatHistoryError::AuthenticationFailed));
        let stage_blob = aead_protect(&key, dir.path(), STAGE_AAD_DOMAIN, plain).unwrap();
        let round = aead_unprotect(&key, dir.path(), STAGE_AAD_DOMAIN, &stage_blob).unwrap();
        assert_eq!(round, plain);
    }

    #[test]
    fn prior_rvnostg1_history_aad_migrates_to_stage_aad() {
        let dir = tempdir().unwrap();
        let key_byte = 0x46u8;
        let protector = TestStageProtector::new(key_byte);
        let plain = serde_json::to_vec(&OutboundBodyStageFile {
            entries: vec![StagedOutboundBody {
                peer_pub_hex: hex::encode([9u8; 32]),
                session_id_hex: hex::encode([8u8; 32]),
                object_digest_hex: hex::encode([7u8; 32]),
                message_id_hex: hex::encode([6u8; 16]),
                body: "pre-domain-split-body".into(),
                created_at_ms: 42,
            }],
        })
        .unwrap();
        // Simulate previous release: same MAGIC, chat-history AAD.
        let legacy_ct =
            aead_protect(&[key_byte; 32], dir.path(), HISTORY_AAD_DOMAIN, &plain).unwrap();
        let mut encoded = Vec::with_capacity(STAGE_MAGIC.len() + legacy_ct.len());
        encoded.extend_from_slice(STAGE_MAGIC);
        encoded.extend_from_slice(&legacy_ct);
        atomic_write_private(&outbound_body_stage_path(dir.path()), &encoded).unwrap();

        let loaded = load_stage_file_with_protector(dir.path(), &protector).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].body, "pre-domain-split-body");
        // Rewritten ciphertext must authenticate under STAGE AAD only.
        let disk = std::fs::read(outbound_body_stage_path(dir.path())).unwrap();
        assert!(disk.starts_with(STAGE_MAGIC));
        let ct = &disk[STAGE_MAGIC.len()..];
        assert!(aead_unprotect(&[key_byte; 32], dir.path(), STAGE_AAD_DOMAIN, ct).is_ok());
        assert!(matches!(
            aead_unprotect(&[key_byte; 32], dir.path(), HISTORY_AAD_DOMAIN, ct),
            Err(ChatHistoryError::AuthenticationFailed)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn legacy_stage_hardlink_is_refused_when_bin_exists() {
        let dir = tempdir().unwrap();
        let protector = TestStageProtector::new(0x47);
        stage_outbound_body_with_protector(
            dir.path(),
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            &[4u8; 16],
            1,
            "keep-me",
            &protector,
        )
        .unwrap();
        let legacy = outbound_body_stage_legacy_path(dir.path());
        let alias = dir.path().join("stage-alias.json");
        std::fs::write(&legacy, br#"{"entries":[{"peer_pub_hex":"aa","session_id_hex":"bb","object_digest_hex":"cc","message_id_hex":"dd","body":"plaintext-leak","created_at_ms":1}]}"#).unwrap();
        std::fs::hard_link(&legacy, &alias).unwrap();
        let err = load_stage_file_with_protector(dir.path(), &protector).unwrap_err();
        assert!(matches!(err, ChatHistoryError::UnsafeFileMetadata));
        assert!(std::fs::read_to_string(&alias)
            .unwrap()
            .contains("plaintext-leak"));
        assert!(alias.exists());
        assert!(legacy.exists());
    }

    #[test]
    fn stage_capacity_preflight_matches_fail_closed_budget() {
        let dir = tempdir().unwrap();
        let protector = TestStageProtector::new(0x48);
        let body = "z".repeat(40 * 1024);
        let mut file = OutboundBodyStageFile::default();
        for i in 0..200 {
            file.entries.push(StagedOutboundBody {
                peer_pub_hex: hex::encode([1u8; 32]),
                session_id_hex: hex::encode([2u8; 32]),
                object_digest_hex: format!("{i:064x}"),
                message_id_hex: format!("{i:032x}"),
                body: body.clone(),
                created_at_ms: i as u64,
            });
            if stage_within_budget(&file).is_err() {
                file.entries.pop();
                break;
            }
        }
        save_stage_file_with_protector(dir.path(), &file, &protector).unwrap();
        let err = ensure_outbound_stage_capacity_with_protector(
            dir.path(),
            &body,
            1_720_000_000_000,
            &protector,
        )
        .unwrap_err();
        assert!(matches!(err, ChatHistoryError::TooLarge));
        // Preflight must not mutate staged entries.
        let still = load_stage_file_with_protector(dir.path(), &protector).unwrap();
        assert_eq!(still.entries.len(), file.entries.len());
    }

    #[test]
    fn stage_capacity_probe_uses_worst_case_timestamp_json_width() {
        let file = OutboundBodyStageFile::default();
        let body = "hi";
        let len_with = |ts: u64| {
            let mut p = file.clone();
            p.entries.push(StagedOutboundBody {
                peer_pub_hex: normalize_stage_hex(&hex::encode([0u8; 32])),
                session_id_hex: normalize_stage_hex(&hex::encode([0u8; 32])),
                object_digest_hex: normalize_stage_hex(&hex::encode([0u8; 32])),
                message_id_hex: normalize_stage_hex(&hex::encode([0u8; 16])),
                body: normalize_stage_body(body),
                created_at_ms: ts,
            });
            serde_json::to_vec(&p).unwrap().len()
        };
        assert!(len_with(u64::MAX) >= len_with(0) + 19);
        // Even when the caller passes a small stamp, probe sizes at u64::MAX width.
        let mut near_full = OutboundBodyStageFile::default();
        let pad = "p".repeat(32 * 1024);
        loop {
            let mut next = near_full.clone();
            next.entries.push(StagedOutboundBody {
                peer_pub_hex: hex::encode([1u8; 32]),
                session_id_hex: hex::encode([2u8; 32]),
                object_digest_hex: format!("{:064x}", next.entries.len()),
                message_id_hex: format!("{:032x}", next.entries.len()),
                body: pad.clone(),
                created_at_ms: 1,
            });
            if stage_within_budget(&next).is_err() {
                break;
            }
            near_full = next;
        }
        // Craft remaining room: zero-width ts might fit while MAX-width must be what we check.
        let mut zero_probe = near_full.clone();
        zero_probe.entries.push(StagedOutboundBody {
            peer_pub_hex: normalize_stage_hex(&hex::encode([0u8; 32])),
            session_id_hex: normalize_stage_hex(&hex::encode([0u8; 32])),
            object_digest_hex: normalize_stage_hex(&hex::encode([0u8; 32])),
            message_id_hex: normalize_stage_hex(&hex::encode([0u8; 16])),
            body: normalize_stage_body("edge"),
            created_at_ms: 0,
        });
        let mut max_probe = near_full.clone();
        max_probe.entries.push(StagedOutboundBody {
            peer_pub_hex: normalize_stage_hex(&hex::encode([0u8; 32])),
            session_id_hex: normalize_stage_hex(&hex::encode([0u8; 32])),
            object_digest_hex: normalize_stage_hex(&hex::encode([0u8; 32])),
            message_id_hex: normalize_stage_hex(&hex::encode([0u8; 16])),
            body: normalize_stage_body("edge"),
            created_at_ms: u64::MAX,
        });
        if stage_within_budget(&zero_probe).is_ok() && stage_within_budget(&max_probe).is_err() {
            assert!(matches!(
                probe_stage_capacity_for_body(&near_full, "edge", 0),
                Err(ChatHistoryError::TooLarge)
            ));
        }
    }
}
