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
//!
//! macOS has no "connect failed" signal: a Keychain read can block for as long
//! as an access prompt goes unanswered. There the same explicit debug-only
//! override (and `cfg(test)`) selects the derived per-`data_dir` lab key
//! *instead of* touching the Keychain at all, so lab harnesses and tests never
//! wait on, or leave items in, the login Keychain. Release never takes this
//! path either.
//!
//! No cross-process data-dir lock is held across a keystore read: every
//! operation first warms its key (`ChatHistoryProtector::prepare`) and only
//! then takes the history / stage lock, so a stalled keystore prompt in one
//! process can no longer starve the other processes' sends and ACKs.
//!
//! Message bodies are stored exactly as sent/received (length-capped only);
//! terminal sanitisation is a display-time concern. Structural fields and the
//! list-UI `preview` stay sanitised at rest.

use crate::sanitize::sanitize_terminal_text;
#[cfg(any(test, unix))]
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
#[cfg(any(test, unix))]
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
#[cfg(any(test, unix, windows))]
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
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
    /// Exact plaintext body (LAN endpoint size cap only). Not sanitised at
    /// rest: renderers must sanitise for their terminal/UI. Legacy rows may
    /// hold a sanitised copy of `preview`.
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
    #[error(
        "chat history file has unsafe metadata: it must be a regular file (not a symlink) with a single hard link; remove the extra link or restore the file in the data dir"
    )]
    UnsafeFileMetadata,
    #[error(
        "plaintext chat history found after protected history was established; it was not imported and was moved aside to chat_history.json.untrusted-plaintext.* in the data dir (history restarts empty)"
    )]
    LegacyPlaintextAfterProtection,
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
    /// True once a protected history key exists for `data_dir`. Legacy
    /// plaintext is only importable before that point: afterwards a plaintext
    /// file can only be a replacement written behind our back.
    fn protected_key_exists(&self, data_dir: &Path) -> Result<bool, ChatHistoryError> {
        let _ = data_dir;
        Ok(false)
    }
    /// Warm whatever the protector needs from a slow keystore **before** the
    /// caller takes a cross-process data-dir lock, so no lock is ever held
    /// across a keystore round trip (a Keychain access prompt blocks it for as
    /// long as nobody answers, and every other process then fails on the held
    /// lock instead of on the real cause). Best effort and read-only: a key
    /// that does not exist yet is minted later, under the locks, as before, and
    /// a failure here is reported by the operation itself, which stays
    /// fail-closed.
    fn prepare(&self, data_dir: &Path) {
        let _ = data_dir;
    }
}

/// Keeps the unwrapped key for one locked load+save so a mutation costs one
/// keystore round-trip instead of two. Never outlives the operation.
#[derive(Default)]
#[cfg_attr(not(unix), allow(dead_code))]
struct OperationKeyCache {
    cached: std::sync::Mutex<Option<(PathBuf, Zeroizing<[u8; 32]>)>>,
}

#[cfg(unix)]
impl OperationKeyCache {
    fn key(&self, data_dir: &Path, create: bool) -> Result<Zeroizing<[u8; 32]>, ChatHistoryError> {
        let mut cached = self.cached.lock().map_err(|_| {
            ChatHistoryError::ProtectedStoreUnavailable("key cache poisoned".into())
        })?;
        if let Some((dir, key)) = cached.as_ref() {
            if dir == data_dir {
                return Ok(key.clone());
            }
        }
        let key = load_platform_key(data_dir, create)?;
        *cached = Some((data_dir.to_path_buf(), key.clone()));
        Ok(key)
    }

    /// Read the existing key into the cache (never mints one). Errors are not
    /// cached and not reported here: the locked operation that follows asks
    /// again and fails closed on its own.
    fn warm(&self, data_dir: &Path) {
        let _ = self.key(data_dir, false);
    }
}

#[derive(Default)]
struct PlatformChatHistoryProtector {
    #[cfg_attr(not(unix), allow(dead_code))]
    keys: OperationKeyCache,
}

const MAX_ENTRIES: usize = 2_000;
const MAX_HISTORY_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_HISTORY_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
/// Serialized JSON budget before AEAD (12+16) and MAGIC (8) so saves stay under
/// both plaintext and on-disk caps. Eviction uses this, not entry count alone.
/// Equals min(MAX_HISTORY_PLAINTEXT_BYTES, MAX_HISTORY_FILE_BYTES - 36).
const MAX_HISTORY_SERIALIZED_BYTES: usize = 4 * 1024 * 1024 - 36;
/// `{"entries":[` + `]}` around the comma-separated compact entries.
const HISTORY_JSON_OVERHEAD: usize = 14;
const HISTORY_MAGIC: &[u8; 8] = b"RVNHIST1";
#[cfg(any(test, unix, windows))]
const HISTORY_AAD_DOMAIN: &[u8] = b"raven/chat-history/v1";
#[cfg(any(test, unix, windows))]
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

/// The delivery state an outbound row moves to when `next` is written over
/// `current`. A confirmed delivery (`delivered`, `read`) is final: a retry
/// that re-stages the row (`queued`) or a late give-up (`failed`, `expired`,
/// `cancelled`) never turns it back into "not delivered". `read` may still
/// follow `delivered`. Inbound rows take `next` as is.
pub fn delivery_after(direction: &str, current: &str, next: &str) -> String {
    let confirmed = |d: &str| matches!(d, "delivered" | "read");
    if direction == "out" && confirmed(current) && !confirmed(next) {
        return current.to_string();
    }
    if direction == "out" && current == "read" && next == "delivered" {
        return current.to_string();
    }
    next.to_string()
}

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

/// Shared by history and outbound stage: both use one keystore item.
#[cfg_attr(not(any(test, unix)), allow(dead_code))]
fn key_init_lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join(".chat_history_key.lock.sqlite")
}

/// Cross-process `BEGIN EXCLUSIVE` lock on a private SQLite file in the
/// (owner-only) data dir. Lock order is stage → history → key-init; nothing
/// may take them in the opposite order.
struct DataDirSqliteLock {
    _connection: rusqlite::Connection,
}

/// How long a lock waiter is blocked by another holder before it gives up.
const LOCK_WAIT: Duration = Duration::from_secs(10);

impl DataDirSqliteLock {
    fn acquire(path: PathBuf, what: &str) -> Result<Self, ChatHistoryError> {
        Self::acquire_within(path, what, LOCK_WAIT)
    }

    fn acquire_within(path: PathBuf, what: &str, wait: Duration) -> Result<Self, ChatHistoryError> {
        // Also creates/tightens the (owner-only) data dir that holds `path`.
        let connection = crate::paths::open_private_data_dir_sqlite(&path)
            .map_err(|e| ChatHistoryError::Io(e.to_string()))?;
        connection
            .busy_timeout(wait)
            .map_err(|e| ChatHistoryError::Io(e.to_string()))?;
        connection.execute_batch("BEGIN EXCLUSIVE").map_err(|e| {
            let text = e.to_string();
            if text.contains("database is locked") || text.contains("database is busy") {
                // The wait is bounded; say what a stuck holder usually is
                // instead of the bare SQLite text.
                ChatHistoryError::Io(format!(
                    "{what}: still held by another raven process after {}s (database is \
                     locked); if the raven-node service is waiting on an OS keystore \
                     prompt, answer it, or see raven-node-service.log in the data dir",
                    wait.as_secs()
                ))
            } else {
                ChatHistoryError::Io(format!("{what}: {text}"))
            }
        })?;
        Ok(Self {
            _connection: connection,
        })
    }
}

struct HistoryLock {
    _lock: DataDirSqliteLock,
}

impl HistoryLock {
    fn acquire(data_dir: &Path) -> Result<Self, ChatHistoryError> {
        Ok(Self {
            _lock: DataDirSqliteLock::acquire(history_lock_path(data_dir), "history lock")?,
        })
    }
}

impl ChatHistory {
    /// Load protected history. Missing files are an empty history; existing
    /// files never degrade to empty on keychain, parse, or authentication error.
    pub fn load(data_dir: &Path) -> Result<Self, ChatHistoryError> {
        Self::load_with_protector(data_dir, &PlatformChatHistoryProtector::default())
    }

    fn load_with_protector(
        data_dir: &Path,
        protector: &dyn ChatHistoryProtector,
    ) -> Result<Self, ChatHistoryError> {
        // No history file: nothing to decrypt, so no keystore round trip either.
        if history_path(data_dir).exists() {
            protector.prepare(data_dir);
        }
        let _lock = HistoryLock::acquire(data_dir)?;
        Self::load_unlocked(data_dir, protector)
    }

    pub fn save(&self, data_dir: &Path) -> Result<(), ChatHistoryError> {
        self.save_with_protector(data_dir, &PlatformChatHistoryProtector::default())
    }

    fn save_with_protector(
        &self,
        data_dir: &Path,
        protector: &dyn ChatHistoryProtector,
    ) -> Result<(), ChatHistoryError> {
        protector.prepare(data_dir);
        let _lock = HistoryLock::acquire(data_dir)?;
        self.save_unlocked(data_dir, protector)
    }

    /// Append and persist under one inter-process lock, avoiding lost updates
    /// when ash and another local process write concurrently.
    pub fn append_persisted(
        data_dir: &Path,
        entry: ChatHistoryEntry,
    ) -> Result<(), ChatHistoryError> {
        Self::append_persisted_with_protector(
            data_dir,
            entry,
            &PlatformChatHistoryProtector::default(),
        )
    }

    fn append_persisted_with_protector(
        data_dir: &Path,
        entry: ChatHistoryEntry,
        protector: &dyn ChatHistoryProtector,
    ) -> Result<(), ChatHistoryError> {
        protector.prepare(data_dir);
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
            &PlatformChatHistoryProtector::default(),
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
        if history_path(data_dir).exists() {
            protector.prepare(data_dir);
        }
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
            // A confirmed delivery is final (see [`delivery_after`]); the row
            // still counts as found.
            let next = delivery_after(&entry.direction, &entry.delivery, &want_delivery);
            if next != entry.delivery {
                entry.delivery = next;
                history.save_unlocked(data_dir, protector)?;
            }
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
        Self::clear_peer_persisted_with_protector(
            data_dir,
            pub_hex,
            &PlatformChatHistoryProtector::default(),
        )
    }

    fn clear_peer_persisted_with_protector(
        data_dir: &Path,
        pub_hex: &str,
        protector: &dyn ChatHistoryProtector,
    ) -> Result<(), ChatHistoryError> {
        protector.prepare(data_dir);
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
        // ciphertext fsync, and atomic replacement all succeed. Once a
        // protected key exists, plaintext here is not a pre-protection file
        // but a replacement (forged history) or, rarely, a legacy file that
        // an older build stranded by minting the key first. Either way it is
        // never imported: it is moved aside once (kept for manual recovery)
        // and reported, and the next operation starts a fresh authenticated
        // history instead of failing forever.
        let first = bytes
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace());
        if first == Some(b'{') {
            if protector.protected_key_exists(data_dir)? {
                bytes.zeroize();
                quarantine_untrusted_plaintext_history(&path)?;
                return Err(ChatHistoryError::LegacyPlaintextAfterProtection);
            }
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

    /// Import a pre-protection plaintext history before the first protected
    /// key is minted by another path (the outbound stage shares the key).
    /// Otherwise the legacy file would later be refused as a post-protection
    /// replacement. No-op unless the history file is legacy plaintext.
    #[cfg(unix)]
    fn import_legacy_plaintext_before_first_key(data_dir: &Path) -> Result<(), ChatHistoryError> {
        let _lock = HistoryLock::acquire(data_dir)?;
        let Some(bytes) = read_history_file(&history_path(data_dir))? else {
            return Ok(());
        };
        let bytes = Zeroizing::new(bytes);
        if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) != Some(b'{') {
            return Ok(());
        }
        Self::load_unlocked(data_dir, &PlatformChatHistoryProtector::default()).map(|_| ())
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
        if let Some(position) = self.entries.iter().position(|e| {
            !entry.message_id_hex.is_empty()
                && e.message_id_hex.eq_ignore_ascii_case(&entry.message_id_hex)
                && e.peer_pub_hex.eq_ignore_ascii_case(&entry.peer_pub_hex)
                && e.direction == entry.direction
        }) {
            let existing = &mut self.entries[position];
            if !entry.body.is_empty() {
                existing.body = entry.body;
                existing.preview = entry.preview;
            }
            if !entry.delivery.is_empty() {
                existing.delivery =
                    delivery_after(&existing.direction, &existing.delivery, &entry.delivery);
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
            self.enforce_capacity(Some(position));
            return;
        }
        self.entries.push(entry);
        self.enforce_capacity(Some(self.entries.len() - 1));
    }

    /// Fit the durable row-count and serialized-byte caps with per-conversation
    /// fairness: while over budget, drop the oldest row of the *largest*
    /// conversation (by bytes when over the byte cap, by rows otherwise), so
    /// one chatty or hostile contact only ever evicts its own history.
    /// `keep` (the row just written) is never evicted. Sizes are computed once
    /// per call, not by re-serializing the whole history per eviction.
    fn enforce_capacity(&mut self, keep: Option<usize>) {
        #[derive(Default)]
        struct Conversation {
            rows: VecDeque<usize>,
            bytes: usize,
        }
        let sizes: Vec<usize> = self.entries.iter().map(entry_serialized_len).collect();
        let mut count = self.entries.len();
        let mut sum: usize = sizes.iter().sum();
        let total =
            |count: usize, sum: usize| HISTORY_JSON_OVERHEAD + sum + count.saturating_sub(1);
        if count <= MAX_ENTRIES && total(count, sum) <= MAX_HISTORY_SERIALIZED_BYTES {
            return;
        }
        let mut conversations: HashMap<&str, Conversation> = HashMap::new();
        for (index, entry) in self.entries.iter().enumerate() {
            if Some(index) == keep {
                continue;
            }
            let conversation = conversations
                .entry(entry.peer_pub_hex.as_str())
                .or_default();
            conversation.rows.push_back(index);
            conversation.bytes += sizes[index];
        }
        let mut evict = vec![false; count];
        while count > MAX_ENTRIES || total(count, sum) > MAX_HISTORY_SERIALIZED_BYTES {
            let by_bytes = count <= MAX_ENTRIES;
            let victim = conversations
                .values_mut()
                .filter(|c| !c.rows.is_empty())
                .max_by(|a, b| {
                    let (size_a, size_b) = if by_bytes {
                        (a.bytes, b.bytes)
                    } else {
                        (a.rows.len(), b.rows.len())
                    };
                    // Equal size: the conversation holding the older row loses.
                    size_a.cmp(&size_b).then_with(|| b.rows[0].cmp(&a.rows[0]))
                });
            let Some(victim) = victim else {
                break;
            };
            let Some(index) = victim.rows.pop_front() else {
                break;
            };
            victim.bytes -= sizes[index];
            evict[index] = true;
            count -= 1;
            sum -= sizes[index];
        }
        let mut index = 0;
        self.entries.retain(|_| {
            let retained = !evict[index];
            index += 1;
            retained
        });
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
        self.enforce_capacity(None);
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
    // The body is user content: keep it exact (newlines, RTL marks, ...),
    // capped by length only. Renderers sanitise at display time.
    entry.body = truncate_chars(&entry.body, MAX_BODY_CHARS);
    if entry.body.is_empty() && !entry.preview.is_empty() {
        // Legacy rows: preview was the only payload.
        entry.body = entry.preview.clone();
    } else if entry.preview.is_empty() && !entry.body.is_empty() {
        entry.preview = truncate_sanitized(&entry.body, MAX_PREVIEW_CHARS);
    }
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

/// Compact JSON length of one entry, as `serde_json::to_vec(history)` lays it out.
fn entry_serialized_len(entry: &ChatHistoryEntry) -> usize {
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    match serde_json::to_writer(&mut counter, entry) {
        Ok(()) => counter.0,
        // Unserialisable rows cannot be saved anyway; make them evict first.
        Err(_) => MAX_HISTORY_SERIALIZED_BYTES,
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

/// Move a plaintext history that appeared after protection out of the history
/// path without importing it. The file is kept, owner-only, next to the
/// history for manual inspection or recovery; the history path is freed so
/// later operations work on a fresh authenticated history.
fn quarantine_untrusted_plaintext_history(path: &Path) -> Result<PathBuf, ChatHistoryError> {
    let parent = path
        .parent()
        .ok_or_else(|| ChatHistoryError::Io("history path has no parent".into()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("chat_history.json");
    let quarantined = loop {
        let candidate = parent.join(format!(
            "{name}.untrusted-plaintext.{:016x}",
            rand::random::<u64>()
        ));
        match std::fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == ErrorKind::NotFound => break candidate,
            Err(error) => return Err(ChatHistoryError::Io(error.to_string())),
            Ok(_) => continue,
        }
    };
    std::fs::rename(path, &quarantined).map_err(|error| ChatHistoryError::Io(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&quarantined, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| ChatHistoryError::Io(error.to_string()))?;
    }
    // The rename has committed; see `sync_dir_best_effort`.
    crate::paths::sync_dir_best_effort(parent);
    Ok(quarantined)
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

/// Metadata gate for an AEAD-protected (MAGIC-prefixed) history or stage file.
///
/// Group/other permission bits are repaired, not fatal: the contents are
/// authenticated ciphertext, so the mode adds neither confidentiality nor
/// integrity, and tools that do not preserve modes (a umask-022 `cp -r`, some
/// sync clients) would otherwise wedge history and the send path until the user
/// ran `chmod 600` by hand. Symlinks, special files and extra hard links stay
/// refused (they could alias the file from outside the profile).
#[cfg(unix)]
fn validate_private_file_metadata(path: &Path) -> Result<(), ChatHistoryError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| ChatHistoryError::Io(error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1
    {
        return Err(ChatHistoryError::UnsafeFileMetadata);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |error| {
                ChatHistoryError::Io(format!(
                    "protected history file {} is accessible to group/other and cannot be restricted to owner-only: {error}",
                    path.display()
                ))
            },
        )?;
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
    crate::paths::ensure_private_dir(parent).map_err(ChatHistoryError::Io)?;

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

    // The replacement has committed. A directory fsync that fails (filesystems
    // that cannot fsync a directory) must not be reported as a failed save: the
    // caller would retry a write that already took effect, forever.
    crate::paths::sync_dir_best_effort(parent);
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

#[cfg(any(test, unix, windows))]
fn scoped_aad(data_dir: &Path, domain: &[u8]) -> [u8; 32] {
    let canonical = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(b"/");
    hasher.update(canonical.to_string_lossy().as_bytes());
    hasher.finalize().into()
}

#[cfg(any(test, unix))]
// Only the OS-keystore `history_account` (macOS / GNU Linux) calls this; the other
// targets compile it for the unit-test build alone, where it is unused.
#[cfg_attr(
    not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))),
    allow(dead_code)
)]
fn history_scope(data_dir: &Path) -> [u8; 32] {
    scoped_aad(data_dir, HISTORY_AAD_DOMAIN)
}

#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
fn history_account(data_dir: &Path) -> String {
    hex::encode(history_scope(data_dir))
}

#[cfg(any(test, unix))]
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

#[cfg(any(test, unix))]
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
    use crate::macos_keychain::{guarded, KeychainWhat};
    use security_framework::passwords::get_generic_password;
    let account = history_account(data_dir);
    match guarded(KeychainWhat::ChatHistoryKey, || {
        get_generic_password(HISTORY_KEY_SERVICE, &account)
    }) {
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

/// Add-only: `Ok(false)` when an item already exists (errSecDuplicateItem).
/// Never replaces a key another process may already have sealed data under.
#[cfg(target_os = "macos")]
fn platform_add_key(data_dir: &Path, key: &[u8; 32]) -> Result<bool, ChatHistoryError> {
    use crate::macos_keychain::{guarded, KeychainWhat};
    use security_framework::os::macos::keychain::SecKeychain;
    const ERR_SEC_DUPLICATE_ITEM: i32 = -25_299;
    let account = history_account(data_dir);
    guarded(KeychainWhat::ChatHistoryKey, || {
        let keychain = SecKeychain::default().map_err(|error| {
            ChatHistoryError::ProtectedStoreUnavailable(format!("keychain default failed: {error}"))
        })?;
        match keychain.add_generic_password(HISTORY_KEY_SERVICE, &account, key) {
            Ok(()) => Ok(true),
            Err(error) if error.code() == ERR_SEC_DUPLICATE_ITEM => Ok(false),
            Err(error) => Err(ChatHistoryError::ProtectedStoreUnavailable(format!(
                "keychain add failed: {error}"
            ))),
        }
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

/// Secret Service has no add-only CreateItem (`replace=false` silently adds a
/// duplicate item). Exclusion comes from [`init_protected_key`]: this runs
/// only under the key-init lock after a fresh lookup found no item.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn platform_add_key(data_dir: &Path, key: &[u8; 32]) -> Result<bool, ChatHistoryError> {
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
    Ok(true)
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

#[cfg(unix)]
fn chat_history_lab_backend_requested() -> bool {
    for key in ["RAVEN_CHAT_HISTORY_BACKEND", "RAVEN_IDENTITY_BACKEND"] {
        if std::env::var_os(key).is_some_and(|v| v == "locked-file") {
            return true;
        }
    }
    false
}

/// The lab key is permitted: `cfg(test)`, or a debug build with an explicit
/// locked-file env.
///
/// GNU/Linux uses it only on the Secret Service connect-fail lab path shared
/// with identity/prekey; macOS uses it *instead of* the Keychain (see
/// [`load_platform_key`]). `cfg(test)` keeps `cargo test -p raven-core` green.
/// Debug ash/raven-node (CI smokes) also take this path when an explicit
/// locked-file env is set. Never Release; never a 0600-key fallback.
#[cfg(unix)]
fn chat_history_lab_key_allowed() -> bool {
    cfg!(test) || (cfg!(debug_assertions) && chat_history_lab_backend_requested())
}

/// Headless rust-linux has no session bus, and a macOS Keychain read can block
/// on an access prompt nobody answers. This is **not** a production 0600-key
/// fallback — lab/CI only, per-`data_dir` derived key so send and
/// lan_dispatch can exercise history/stage without org.freedesktop.secrets or
/// the login Keychain.
#[cfg(unix)]
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

/// Keystore primitives behind first-use key initialisation (test seam).
#[cfg(any(test, unix))]
trait ProtectedKeyStore {
    fn get(&self, data_dir: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, ChatHistoryError>;
    /// `Ok(false)` when an item already exists; must never replace one.
    fn add(&self, data_dir: &Path, key: &[u8; 32]) -> Result<bool, ChatHistoryError>;
}

#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
struct PlatformKeyStore;

#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
impl ProtectedKeyStore for PlatformKeyStore {
    fn get(&self, data_dir: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, ChatHistoryError> {
        platform_get_key(data_dir)
    }

    fn add(&self, data_dir: &Path, key: &[u8; 32]) -> Result<bool, ChatHistoryError> {
        platform_add_key(data_dir, key)
    }
}

/// Mint the shared history/stage key exactly once per data dir. History and
/// stage writers (e.g. ash sending while raven-node receives) serialise on
/// one cross-process lock and re-check under it, and creation is add-only,
/// so no writer can seal a file under a key that another writer replaces.
#[cfg(any(test, unix))]
fn init_protected_key(
    store: &dyn ProtectedKeyStore,
    data_dir: &Path,
) -> Result<Zeroizing<[u8; 32]>, ChatHistoryError> {
    let _lock = DataDirSqliteLock::acquire(key_init_lock_path(data_dir), "key init lock")?;
    if let Some(existing) = store.get(data_dir)? {
        return Ok(existing);
    }
    let mut generated = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *generated);
    if !store.add(data_dir, &generated)? {
        // A writer outside this lock (older build) won the race: adopt its key.
        return store
            .get(data_dir)?
            .ok_or(ChatHistoryError::MissingProtectedKey);
    }
    let confirmed = store
        .get(data_dir)?
        .ok_or(ChatHistoryError::MissingProtectedKey)?;
    if *confirmed != *generated {
        return Err(ChatHistoryError::ProtectedStoreUnavailable(
            "concurrent protected-key initialization".into(),
        ));
    }
    Ok(confirmed)
}

/// History key in the profile's passphrase vault (non-macOS Unix without a
/// reachable Secret Service; docs/design/2026-10-linux-keystore.md). Add-only
/// like the Keychain item. Every test build compiles it.
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
struct VaultKeyStore {
    vault: crate::keystore_vault::Vault,
}

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
fn vault_history_error(error: crate::keystore_vault::VaultError) -> ChatHistoryError {
    ChatHistoryError::ProtectedStoreUnavailable(format!("passphrase vault: {error}"))
}

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
impl ProtectedKeyStore for VaultKeyStore {
    fn get(&self, _data_dir: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, ChatHistoryError> {
        let Some(bytes) = self
            .vault
            .get(crate::keystore_vault::CHAT_HISTORY_KEY_ENTRY)
            .map_err(vault_history_error)?
        else {
            return Ok(None);
        };
        if bytes.len() != 32 {
            return Err(ChatHistoryError::CorruptProtectedKey);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes);
        Ok(Some(key))
    }

    fn add(&self, _data_dir: &Path, key: &[u8; 32]) -> Result<bool, ChatHistoryError> {
        match self
            .vault
            .insert_new(crate::keystore_vault::CHAT_HISTORY_KEY_ENTRY, key)
        {
            Ok(()) => Ok(true),
            Err(crate::keystore_vault::VaultError::EntryExists(_)) => Ok(false),
            Err(error) => Err(vault_history_error(error)),
        }
    }
}

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
fn load_vault_history_key(
    store: &VaultKeyStore,
    data_dir: &Path,
    create: bool,
) -> Result<Zeroizing<[u8; 32]>, ChatHistoryError> {
    if let Some(key) = store.get(data_dir)? {
        return Ok(key);
    }
    if !create {
        return Err(ChatHistoryError::MissingProtectedKey);
    }
    init_protected_key(store, data_dir)
}

/// Release (non-lab) non-macOS Unix: does this profile keep its history key
/// in the passphrase vault? The debug locked-file lab path and unit tests
/// keep their existing behaviour (Secret Service, else the derived lab key).
#[cfg(all(unix, not(target_os = "macos")))]
fn vault_history_key_selected(data_dir: &Path, record: bool) -> Result<bool, ChatHistoryError> {
    if chat_history_lab_key_allowed() {
        return Ok(false);
    }
    crate::keystore_select::uses_vault(data_dir, record)
        .map_err(ChatHistoryError::ProtectedStoreUnavailable)
}

#[cfg(unix)]
fn load_platform_key(
    data_dir: &Path,
    create: bool,
) -> Result<Zeroizing<[u8; 32]>, ChatHistoryError> {
    // macOS never reports "keystore unreachable": a Keychain read just blocks
    // on an unanswered access prompt. The explicit debug lab override (and
    // unit tests) therefore skip the Keychain entirely, the same way the
    // identity, prekey and session backends honour their locked-file override.
    #[cfg(target_os = "macos")]
    if chat_history_lab_key_allowed() {
        return Ok(lab_history_key(data_dir));
    }
    #[cfg(not(target_os = "macos"))]
    if vault_history_key_selected(data_dir, create)? {
        let store = VaultKeyStore {
            vault: crate::keystore_vault::Vault::for_data_dir(data_dir),
        };
        return load_vault_history_key(&store, data_dir, create);
    }
    #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
    {
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
        init_protected_key(&PlatformKeyStore, data_dir)
    }
    // musl / other Unix without a Secret Service client: only the debug lab
    // key remains here (release builds took the vault branch above).
    #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
    {
        let _ = create;
        if chat_history_lab_key_allowed() {
            return Ok(lab_history_key(data_dir));
        }
        Err(ChatHistoryError::ProtectedStoreUnavailable(
            "no protected chat-history keystore on this target".into(),
        ))
    }
}

/// Whether a real (keystore-held) history key exists. The debug Linux lab
/// key is not a protected key and never blocks legacy import.
#[cfg(unix)]
fn platform_key_exists(data_dir: &Path) -> Result<bool, ChatHistoryError> {
    // The lab key is not a protected key and never blocks legacy import.
    #[cfg(target_os = "macos")]
    if chat_history_lab_key_allowed() {
        return Ok(false);
    }
    #[cfg(not(target_os = "macos"))]
    if vault_history_key_selected(data_dir, false)? {
        let store = VaultKeyStore {
            vault: crate::keystore_vault::Vault::for_data_dir(data_dir),
        };
        return Ok(store.get(data_dir)?.is_some());
    }
    #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
    {
        match platform_get_key(data_dir) {
            Ok(key) => Ok(key.is_some()),
            Err(e) => {
                #[cfg(all(target_os = "linux", target_env = "gnu"))]
                if linux_secret_service_connect_failed(&e) && chat_history_lab_key_allowed() {
                    return Ok(false);
                }
                Err(e)
            }
        }
    }
    #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
    {
        let _ = data_dir;
        Ok(false)
    }
}

impl ChatHistoryProtector for PlatformChatHistoryProtector {
    fn protect(&self, data_dir: &Path, plaintext: &[u8]) -> Result<Vec<u8>, ChatHistoryError> {
        #[cfg(unix)]
        {
            let key = self.keys.key(data_dir, true)?;
            aead_protect(&key, data_dir, HISTORY_AAD_DOMAIN, plaintext)
        }
        #[cfg(windows)]
        {
            dpapi_protect_blob(data_dir, HISTORY_AAD_DOMAIN, plaintext)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (data_dir, plaintext);
            Err(ChatHistoryError::ProtectedStoreUnavailable(
                "no supported platform-protected backend".into(),
            ))
        }
    }

    fn unprotect(&self, data_dir: &Path, ciphertext: &[u8]) -> Result<Vec<u8>, ChatHistoryError> {
        #[cfg(unix)]
        {
            let key = self.keys.key(data_dir, false)?;
            aead_unprotect(&key, data_dir, HISTORY_AAD_DOMAIN, ciphertext)
        }
        #[cfg(windows)]
        {
            dpapi_unprotect_blob(data_dir, HISTORY_AAD_DOMAIN, ciphertext)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (data_dir, ciphertext);
            Err(ChatHistoryError::ProtectedStoreUnavailable(
                "no supported platform-protected backend".into(),
            ))
        }
    }

    fn protected_key_exists(&self, data_dir: &Path) -> Result<bool, ChatHistoryError> {
        #[cfg(unix)]
        {
            platform_key_exists(data_dir)
        }
        // DPAPI (user scope) has no key item and offers no integrity against
        // same-user processes anyway; other targets cannot save at all.
        #[cfg(not(unix))]
        {
            let _ = data_dir;
            Ok(false)
        }
    }

    fn prepare(&self, data_dir: &Path) {
        #[cfg(unix)]
        self.keys.warm(data_dir);
        #[cfg(not(unix))]
        let _ = data_dir;
    }
}

#[derive(Default)]
struct PlatformOutboundStageProtector {
    #[cfg_attr(not(unix), allow(dead_code))]
    keys: OperationKeyCache,
}

#[cfg(unix)]
impl PlatformOutboundStageProtector {
    /// The stage may be the first writer to need the shared key. Import any
    /// legacy plaintext history *before* minting it, so that file is not later
    /// refused as a post-protection replacement. Lock order: stage → history.
    fn key_for_protect(&self, data_dir: &Path) -> Result<Zeroizing<[u8; 32]>, ChatHistoryError> {
        match self.keys.key(data_dir, false) {
            Ok(key) => Ok(key),
            Err(ChatHistoryError::MissingProtectedKey) => {
                ChatHistory::import_legacy_plaintext_before_first_key(data_dir)?;
                self.keys.key(data_dir, true)
            }
            Err(error) => Err(error),
        }
    }
}

impl ChatHistoryProtector for PlatformOutboundStageProtector {
    fn protect(&self, data_dir: &Path, plaintext: &[u8]) -> Result<Vec<u8>, ChatHistoryError> {
        #[cfg(unix)]
        {
            let key = self.key_for_protect(data_dir)?;
            aead_protect(&key, data_dir, STAGE_AAD_DOMAIN, plaintext)
        }
        #[cfg(windows)]
        {
            dpapi_protect_blob(data_dir, STAGE_AAD_DOMAIN, plaintext)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (data_dir, plaintext);
            Err(ChatHistoryError::ProtectedStoreUnavailable(
                "no supported platform-protected backend".into(),
            ))
        }
    }

    fn unprotect(&self, data_dir: &Path, ciphertext: &[u8]) -> Result<Vec<u8>, ChatHistoryError> {
        #[cfg(unix)]
        {
            let key = self.keys.key(data_dir, false)?;
            aead_unprotect(&key, data_dir, STAGE_AAD_DOMAIN, ciphertext)
        }
        #[cfg(windows)]
        {
            dpapi_unprotect_blob(data_dir, STAGE_AAD_DOMAIN, ciphertext)
        }
        #[cfg(not(any(unix, windows)))]
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
        #[cfg(unix)]
        {
            let key = self.keys.key(data_dir, false)?;
            unprotect_stage_aead_with_legacy_fallback(&key, data_dir, ciphertext)
        }
        #[cfg(windows)]
        {
            unprotect_stage_dpapi_with_legacy_fallback(data_dir, ciphertext)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (data_dir, ciphertext);
            Err(ChatHistoryError::ProtectedStoreUnavailable(
                "no supported platform-protected backend".into(),
            ))
        }
    }

    fn prepare(&self, data_dir: &Path) {
        #[cfg(unix)]
        self.keys.warm(data_dir);
        #[cfg(not(unix))]
        let _ = data_dir;
    }
}

/// Prefer stage AAD; accept one prior generation sealed under chat-history AAD.
/// `true` means the blob used history AAD and must be rewritten.
#[cfg(any(test, unix))]
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
        // Decrypted history must not linger in freed heap (SecureZeroMemory
        // equivalent: zeroize uses volatile writes).
        std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize).zeroize();
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

/// Staged bodies are the exact outbound text (length cap only), so retry and
/// post-ACK history hold what was actually sent.
fn normalize_stage_body(body: &str) -> String {
    truncate_chars(body, MAX_STAGE_BODY_CHARS)
}

fn normalize_stage_hex(value: &str) -> String {
    truncate_sanitized(value, MAX_STAGE_HEX_CHARS).to_lowercase()
}

fn stage_lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join(".outbound_body_stage.lock.sqlite")
}

/// Whether any stage file exists. Without one there is nothing to decrypt, so
/// a read-only stage operation needs no key (and no keystore round trip).
fn stage_file_present(data_dir: &Path) -> bool {
    outbound_body_stage_path(data_dir).exists()
        || outbound_body_stage_legacy_path(data_dir).exists()
}

struct StageLock {
    _lock: DataDirSqliteLock,
}

impl StageLock {
    fn acquire(data_dir: &Path) -> Result<Self, ChatHistoryError> {
        Ok(Self {
            _lock: DataDirSqliteLock::acquire(stage_lock_path(data_dir), "outbound stage lock")?,
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
    /// One protector for the guard's whole life, so the key read *before* the
    /// lock is reused by the capacity probe and the stage write instead of
    /// being fetched again while the lock is held.
    protector: PlatformOutboundStageProtector,
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
        let protector = PlatformOutboundStageProtector::default();
        if stage_file_present(data_dir) {
            protector.prepare(data_dir);
        }
        let lock = StageLock::acquire(data_dir)?;
        let guard = Self {
            data_dir: data_dir.to_path_buf(),
            protector,
            _lock: lock,
        };
        let file = load_stage_file_with_protector(&guard.data_dir, &guard.protector)?;
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
            &self.protector,
        )
    }

    pub fn load_staged_outbound_body(
        &self,
        message_id: &[u8; 16],
    ) -> Result<Option<StagedOutboundBody>, ChatHistoryError> {
        let file = load_stage_file_with_protector(&self.data_dir, &self.protector)?;
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
    protector.prepare(data_dir);
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
    let protector = PlatformOutboundStageProtector::default();
    protector.prepare(data_dir);
    let _lock = StageLock::acquire(data_dir)?;
    stage_outbound_body_locked(
        data_dir,
        peer_pub,
        session_id,
        object_digest,
        message_id,
        created_at_ms,
        body,
        &protector,
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
    protector.prepare(data_dir);
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
    load_staged_outbound_body_with_protector(
        data_dir,
        message_id,
        &PlatformOutboundStageProtector::default(),
    )
}

fn load_staged_outbound_body_with_protector(
    data_dir: &Path,
    message_id: &[u8; 16],
    protector: &dyn ChatHistoryProtector,
) -> Result<Option<StagedOutboundBody>, ChatHistoryError> {
    if stage_file_present(data_dir) {
        protector.prepare(data_dir);
    }
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
    let protector = PlatformOutboundStageProtector::default();
    if stage_file_present(data_dir) {
        protector.prepare(data_dir);
    }
    let _lock = StageLock::acquire(data_dir)?;
    Ok(load_stage_file_with_protector(data_dir, &protector)?.entries)
}

/// Remove staged body after delivered / abandoned.
pub fn clear_staged_outbound_body(
    data_dir: &Path,
    message_id: &[u8; 16],
) -> Result<(), ChatHistoryError> {
    clear_staged_outbound_body_with_protector(
        data_dir,
        message_id,
        &PlatformOutboundStageProtector::default(),
    )
}

fn clear_staged_outbound_body_with_protector(
    data_dir: &Path,
    message_id: &[u8; 16],
    protector: &dyn ChatHistoryProtector,
) -> Result<(), ChatHistoryError> {
    if stage_file_present(data_dir) {
        protector.prepare(data_dir);
    }
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

/// Far above any real block list; bounds the read of a hostile/corrupt file.
const MAX_BLOCK_LIST_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BlockList {
    pub pub_hex: Vec<String>,
}

impl BlockList {
    /// Missing file → empty list. Unreadable, oversized or corrupt → error.
    /// There is deliberately no lossy loader: every caller (policy checks and
    /// read-modify-write alike) must fail closed instead of treating a broken
    /// file as "nobody is blocked".
    pub fn load_checked(data_dir: &Path) -> Result<Self, String> {
        let path = blocked_path(data_dir);
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("block list read: {e}")),
        };
        let mut raw = String::new();
        file.take(MAX_BLOCK_LIST_BYTES + 1)
            .read_to_string(&mut raw)
            .map_err(|e| format!("block list read: {e}"))?;
        if raw.len() as u64 > MAX_BLOCK_LIST_BYTES {
            return Err("block list exceeds the local size limit".into());
        }
        serde_json::from_str(&raw).map_err(|e| format!("block list corrupt: {e}"))
    }

    /// Replace the persisted list. Refuses to overwrite an existing list that
    /// does not load cleanly: that would silently unblock everyone in it.
    pub fn save(&self, data_dir: &Path) -> Result<(), String> {
        Self::load_checked(data_dir).map_err(|e| {
            format!(
                "refusing to overwrite unreadable block list ({e}); repair or remove {}",
                blocked_path(data_dir).display()
            )
        })?;
        crate::paths::ensure_private_dir(data_dir)?;
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
        let protector = PlatformChatHistoryProtector::default();
        let plain = b"{\"entries\":[]}";
        let ct = protector
            .protect(dir.path(), plain)
            .expect("lab or Secret Service protect");
        let back = protector
            .unprotect(dir.path(), &ct)
            .expect("lab or Secret Service unprotect");
        assert_eq!(back, plain);
    }

    /// macOS: unit tests (and the explicit debug lab override) derive a lab key
    /// instead of reading or creating a login-Keychain item, which can block on
    /// an access prompt nobody answers. Asserts first, so a regression fails the
    /// test instead of reaching the Keychain.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_lab_key_replaces_the_keychain_in_test_builds() {
        assert!(chat_history_lab_key_allowed());
        let dir = tempdir().unwrap();
        let protector = PlatformChatHistoryProtector::default();
        let plain = b"{\"entries\":[]}";
        let ct = protector
            .protect(dir.path(), plain)
            .expect("lab-key protect");
        assert_eq!(
            protector
                .unprotect(dir.path(), &ct)
                .expect("lab-key unprotect"),
            plain
        );
        // The lab key is not a protected key: it never blocks legacy import.
        assert!(!protector.protected_key_exists(dir.path()).unwrap());
        let other = tempdir().unwrap();
        assert_eq!(*lab_history_key(dir.path()), *lab_history_key(dir.path()));
        assert_ne!(*lab_history_key(dir.path()), *lab_history_key(other.path()));
        // The stage shares the same key source.
        let stage = PlatformOutboundStageProtector::default();
        let ct = stage
            .protect(dir.path(), plain)
            .expect("lab-key stage protect");
        assert_eq!(
            stage
                .unprotect(dir.path(), &ct)
                .expect("lab-key stage unprotect"),
            plain
        );
    }

    /// `true` while another connection cannot take the exclusive lock at `path`.
    fn lock_is_held(path: &Path) -> bool {
        let conn = crate::paths::open_private_data_dir_sqlite(path).unwrap();
        conn.busy_timeout(Duration::from_millis(0)).unwrap();
        match conn.execute_batch("BEGIN EXCLUSIVE") {
            Ok(()) => {
                let _ = conn.execute_batch("ROLLBACK");
                false
            }
            Err(_) => true,
        }
    }

    /// Wraps a protector and records, per call, whether the cross-process lock
    /// at `lock_path` was held at that instant.
    struct LockProbeProtector {
        inner: Box<dyn ChatHistoryProtector>,
        lock_path: PathBuf,
        events: std::sync::Mutex<Vec<(&'static str, bool)>>,
    }

    impl LockProbeProtector {
        fn new(inner: impl ChatHistoryProtector + 'static, lock_path: PathBuf) -> Self {
            Self {
                inner: Box::new(inner),
                lock_path,
                events: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn note(&self, what: &'static str) {
            let held = lock_is_held(&self.lock_path);
            self.events.lock().unwrap().push((what, held));
        }

        fn events(&self) -> Vec<(&'static str, bool)> {
            self.events.lock().unwrap().clone()
        }
    }

    impl ChatHistoryProtector for LockProbeProtector {
        fn protect(&self, data_dir: &Path, plaintext: &[u8]) -> Result<Vec<u8>, ChatHistoryError> {
            self.note("protect");
            self.inner.protect(data_dir, plaintext)
        }

        fn unprotect(
            &self,
            data_dir: &Path,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, ChatHistoryError> {
            self.note("unprotect");
            self.inner.unprotect(data_dir, ciphertext)
        }

        fn unprotect_stage(
            &self,
            data_dir: &Path,
            ciphertext: &[u8],
        ) -> Result<(Vec<u8>, bool), ChatHistoryError> {
            self.note("unprotect");
            self.inner.unprotect_stage(data_dir, ciphertext)
        }

        fn prepare(&self, _data_dir: &Path) {
            self.note("prepare");
        }
    }

    /// No cross-process lock may be held across a keystore round trip: the key
    /// is warmed first, and only the (cached) use happens under the lock.
    #[test]
    fn history_key_is_warmed_before_the_history_lock_not_under_it() {
        let dir = tempdir().unwrap();
        let probe = LockProbeProtector::new(TestProtector::new(3), history_lock_path(dir.path()));

        ChatHistory::append_persisted_with_protector(dir.path(), sample_entry(), &probe).unwrap();
        let ev = probe.events();
        assert_eq!(ev.first(), Some(&("prepare", false)), "{ev:?}");
        assert!(
            ev.iter()
                .filter(|(w, _)| *w != "prepare")
                .all(|(_, held)| *held),
            "key use must happen under the lock: {ev:?}"
        );
        assert!(ev.iter().any(|(w, _)| *w == "protect"), "{ev:?}");

        // An existing file is read the same way.
        let probe = LockProbeProtector::new(TestProtector::new(3), history_lock_path(dir.path()));
        let loaded = ChatHistory::load_with_protector(dir.path(), &probe).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(
            probe.events(),
            vec![("prepare", false), ("unprotect", true)]
        );

        // Read-modify-write paths too.
        let probe = LockProbeProtector::new(TestProtector::new(3), history_lock_path(dir.path()));
        ChatHistory::set_delivery_persisted_with_protector(
            dir.path(),
            "abcdef0123456789",
            "out",
            "aabbccdd00112233",
            "delivered",
            &probe,
        )
        .unwrap();
        let ev = probe.events();
        assert_eq!(ev.first(), Some(&("prepare", false)), "{ev:?}");
        let probe = LockProbeProtector::new(TestProtector::new(3), history_lock_path(dir.path()));
        ChatHistory::clear_peer_persisted_with_protector(dir.path(), "abcdef0123456789", &probe)
            .unwrap();
        assert_eq!(probe.events().first(), Some(&("prepare", false)));
    }

    /// Nothing to decrypt means nothing to ask the keystore for: a fresh profile
    /// pays no keystore round trip for a read.
    #[test]
    fn reading_a_missing_history_or_stage_asks_the_keystore_for_nothing() {
        let dir = tempdir().unwrap();
        let probe = LockProbeProtector::new(TestProtector::new(3), history_lock_path(dir.path()));
        assert!(ChatHistory::load_with_protector(dir.path(), &probe)
            .unwrap()
            .entries
            .is_empty());
        assert!(!ChatHistory::set_delivery_persisted_with_protector(
            dir.path(),
            "abcdef0123456789",
            "out",
            "aabbccdd00112233",
            "delivered",
            &probe,
        )
        .unwrap());
        assert!(probe.events().is_empty(), "{:?}", probe.events());

        let probe =
            LockProbeProtector::new(TestStageProtector::new(4), stage_lock_path(dir.path()));
        assert!(
            load_staged_outbound_body_with_protector(dir.path(), &[1u8; 16], &probe)
                .unwrap()
                .is_none()
        );
        clear_staged_outbound_body_with_protector(dir.path(), &[1u8; 16], &probe).unwrap();
        assert!(probe.events().is_empty(), "{:?}", probe.events());
    }

    #[test]
    fn stage_key_is_warmed_before_the_stage_lock_not_under_it() {
        let dir = tempdir().unwrap();
        let probe =
            LockProbeProtector::new(TestStageProtector::new(4), stage_lock_path(dir.path()));
        stage_outbound_body_with_protector(
            dir.path(),
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            &[4u8; 16],
            10,
            "hello",
            &probe,
        )
        .unwrap();
        let ev = probe.events();
        assert_eq!(ev.first(), Some(&("prepare", false)), "{ev:?}");
        assert!(
            ev.iter()
                .filter(|(w, _)| *w != "prepare")
                .all(|(_, held)| *held),
            "{ev:?}"
        );

        let probe =
            LockProbeProtector::new(TestStageProtector::new(4), stage_lock_path(dir.path()));
        let got = load_staged_outbound_body_with_protector(dir.path(), &[4u8; 16], &probe)
            .unwrap()
            .expect("staged");
        assert_eq!(got.body, "hello");
        assert_eq!(
            probe.events(),
            vec![("prepare", false), ("unprotect", true)]
        );

        let probe =
            LockProbeProtector::new(TestStageProtector::new(4), stage_lock_path(dir.path()));
        clear_staged_outbound_body_with_protector(dir.path(), &[4u8; 16], &probe).unwrap();
        assert_eq!(probe.events().first(), Some(&("prepare", false)));
    }

    /// A stuck lock holder is reported as such (bounded wait), not as a bare
    /// SQLite "database is locked".
    #[test]
    fn lock_wait_timeout_names_the_holder_not_just_sqlite() {
        let dir = tempdir().unwrap();
        let path = history_lock_path(dir.path());
        let _held = DataDirSqliteLock::acquire(path.clone(), "history lock").unwrap();
        let started = std::time::Instant::now();
        let err = match DataDirSqliteLock::acquire_within(
            path,
            "history lock",
            Duration::from_millis(60),
        ) {
            Ok(_) => panic!("the lock is held"),
            Err(e) => e.to_string(),
        };
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(err.contains("history lock"), "{err}");
        assert!(err.contains("still held by another raven process"), "{err}");
        assert!(err.contains("keystore"), "{err}");
        assert!(err.contains("raven-node-service.log"), "{err}");
    }

    struct TestProtector {
        key: [u8; 32],
        available: bool,
        key_exists: bool,
    }

    impl TestProtector {
        fn new(byte: u8) -> Self {
            Self {
                key: [byte; 32],
                available: true,
                key_exists: false,
            }
        }

        fn unavailable(byte: u8) -> Self {
            Self {
                available: false,
                ..Self::new(byte)
            }
        }

        /// A protected key was already minted for this data dir.
        fn established(byte: u8) -> Self {
            Self {
                key_exists: true,
                ..Self::new(byte)
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

        fn protected_key_exists(&self, _data_dir: &Path) -> Result<bool, ChatHistoryError> {
            if !self.available {
                return Err(ChatHistoryError::ProtectedStoreUnavailable("test".into()));
            }
            Ok(self.key_exists)
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
        // The durable body is the exact message; only display fields are sanitized.
        assert_eq!(loaded.entries[0].body, "confidential hello\nthere");
    }

    #[test]
    fn body_is_stored_exactly_including_newlines_and_rtl_marks() {
        let dir = tempdir().unwrap();
        let protector = TestProtector::new(0x21);
        let exact =
            "\u{200F}\u{633}\u{644}\u{627}\u{645} \u{200E}v2\nline two\r\n\tindented \x1b[31mred";
        let mut entry = sample_entry();
        entry.body = exact.into();
        entry.preview = String::new();
        ChatHistory::append_persisted_with_protector(dir.path(), entry, &protector).unwrap();
        let loaded = ChatHistory::load_with_protector(dir.path(), &protector).unwrap();
        assert_eq!(loaded.entries[0].body, exact);
        let preview = &loaded.entries[0].preview;
        assert!(!preview.contains('\n') && !preview.contains('\x1b'));
        assert!(!preview.contains('\u{200F}'));

        // Bodies over the cap are truncated by characters, never rejected.
        let mut long = sample_entry();
        long.message_id_hex = "ff".repeat(8);
        long.body = "\u{627}".repeat(MAX_BODY_CHARS + 10);
        ChatHistory::append_persisted_with_protector(dir.path(), long, &protector).unwrap();
        let loaded = ChatHistory::load_with_protector(dir.path(), &protector).unwrap();
        assert_eq!(loaded.entries[1].body.chars().count(), MAX_BODY_CHARS);
    }

    #[test]
    fn staged_outbound_body_is_stored_exactly() {
        let dir = tempdir().unwrap();
        let stage = TestStageProtector::new(0x22);
        let exact = "first line\nsecond \u{200F}\u{645}\u{631}\u{62D}\u{628}\u{627}";
        stage_outbound_body_with_protector(
            dir.path(),
            &[1; 32],
            &[2; 32],
            &[3; 32],
            &[4; 16],
            5,
            exact,
            &stage,
        )
        .unwrap();
        let staged = load_staged_outbound_body_with_protector(dir.path(), &[4; 16], &stage)
            .unwrap()
            .unwrap();
        assert_eq!(staged.body, exact);
    }

    fn quarantined_history_files(dir: &Path) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("chat_history.json.untrusted-plaintext."))
            })
            .collect();
        found.sort();
        found
    }

    /// Forged (or stranded) plaintext after protection is never imported. It
    /// is moved aside once, reported, and the history keeps working: the
    /// honest stranded-legacy case no longer needs manual repair.
    #[test]
    fn plaintext_history_after_protection_is_quarantined_not_imported() {
        let dir = tempdir().unwrap();
        let path = history_path(dir.path());
        let protector = TestProtector::established(0x23);
        let mut forged = ChatHistory::default();
        let mut entry = sample_entry();
        entry.body = "forged message".into();
        forged.append(entry);
        let plaintext = serde_json::to_vec(&forged).unwrap();
        std::fs::write(&path, &plaintext).unwrap();

        let error = ChatHistory::load_with_protector(dir.path(), &protector).unwrap_err();
        assert!(matches!(
            error,
            ChatHistoryError::LegacyPlaintextAfterProtection
        ));
        assert!(!path.exists(), "history path must be freed");
        let quarantined = quarantined_history_files(dir.path());
        assert_eq!(quarantined.len(), 1);
        assert_eq!(std::fs::read(&quarantined[0]).unwrap(), plaintext);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&quarantined[0])
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "quarantined plaintext must be owner-only");
        }

        // Later operations work on a fresh authenticated history; the forged
        // row never appears.
        assert!(ChatHistory::load_with_protector(dir.path(), &protector)
            .unwrap()
            .entries
            .is_empty());
        let mut genuine = sample_entry();
        genuine.body = "genuine message".into();
        ChatHistory::append_persisted_with_protector(dir.path(), genuine, &protector).unwrap();
        let loaded = ChatHistory::load_with_protector(dir.path(), &protector).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].body, "genuine message");
        assert!(std::fs::read(&path).unwrap().starts_with(HISTORY_MAGIC));

        // A second planted file is quarantined too (from a mutation path) and
        // does not clobber the first one.
        std::fs::write(&path, &plaintext).unwrap();
        let error =
            ChatHistory::append_persisted_with_protector(dir.path(), sample_entry(), &protector)
                .unwrap_err();
        assert!(matches!(
            error,
            ChatHistoryError::LegacyPlaintextAfterProtection
        ));
        assert_eq!(quarantined_history_files(dir.path()).len(), 2);
        assert!(!path.exists());
    }

    fn peer_entry(peer_byte: u8, index: usize, body: &str) -> ChatHistoryEntry {
        ChatHistoryEntry {
            message_id_hex: format!("{index:032x}"),
            direction: "in".into(),
            // Fixed-width fields: same-body rows serialize to the same size.
            peer_petname: format!("peer-{peer_byte:03}"),
            peer_tag: String::new(),
            peer_pub_hex: hex::encode([peer_byte; 32]),
            created_at_ms: 1_000_000 + index as u64,
            delivery: "received".into(),
            preview: body.chars().take(MAX_PREVIEW_CHARS).collect(),
            body: body.into(),
        }
    }

    #[test]
    fn serialized_length_accounting_matches_serde_json() {
        let mut history = ChatHistory::default();
        assert_eq!(
            HISTORY_JSON_OVERHEAD,
            serde_json::to_vec(&history).unwrap().len()
        );
        for (i, body) in [
            "plain",
            "quote\" and \\ slash",
            "\u{0}\u{1f}ctl",
            "\u{645}\u{1F600}",
            "",
        ]
        .iter()
        .enumerate()
        {
            history.entries.push(peer_entry(i as u8, i, body));
        }
        let expected = serde_json::to_vec(&history).unwrap().len();
        let n = history.entries.len();
        let computed = HISTORY_JSON_OVERHEAD
            + history
                .entries
                .iter()
                .map(entry_serialized_len)
                .sum::<usize>()
            + (n - 1);
        assert_eq!(computed, expected);
    }

    #[test]
    fn row_flood_from_one_contact_cannot_evict_other_conversations() {
        let mut history = ChatHistory::default();
        let bob = hex::encode([0xbb; 32]);
        for i in 0..5 {
            history.append(peer_entry(0xbb, i, "hi from bob"));
        }
        // Mallory fills the table (direct push keeps the test fast) ...
        for i in 5..MAX_ENTRIES {
            history.entries.push(peer_entry(0xee, i, "spam"));
        }
        // ... then keeps sending past the global cap.
        for i in MAX_ENTRIES..MAX_ENTRIES + 20 {
            history.append(peer_entry(0xee, i, "spam"));
        }
        assert_eq!(history.entries.len(), MAX_ENTRIES);
        assert_eq!(history.for_peer(&bob).len(), 5, "bob's rows must survive");
        assert_eq!(
            history.entries.last().unwrap().message_id_hex,
            format!("{:032x}", MAX_ENTRIES + 19)
        );
        // Mallory's oldest rows went first.
        assert!(!history
            .entries
            .iter()
            .any(|e| e.message_id_hex == format!("{:032x}", 5)));
    }

    #[test]
    fn byte_flood_from_one_contact_only_evicts_its_own_rows() {
        let mut history = ChatHistory::default();
        let bob = hex::encode([0xbb; 32]);
        let small = "b".repeat(1024);
        for i in 0..5 {
            history.append(peer_entry(0xbb, i, &small));
        }
        let big = "x".repeat(40 * 1024);
        for i in 5..125 {
            history.append(peer_entry(0xee, i, &big));
        }
        assert_eq!(history.for_peer(&bob).len(), 5);
        assert!(serde_json::to_vec(&history).unwrap().len() <= MAX_HISTORY_SERIALIZED_BYTES);
        history.validate().unwrap();
        assert_eq!(
            history.entries.last().unwrap().message_id_hex,
            format!("{:032x}", 124)
        );
    }

    #[test]
    fn eviction_never_drops_the_row_being_written() {
        let mut history = ChatHistory::default();
        let bulk = "p".repeat(40_000);
        let row = entry_serialized_len(&peer_entry(0, 0, &bulk));
        let mut total = HISTORY_JSON_OVERHEAD;
        let mut peer = 0u8;
        // Fill with equal-sized one-row conversations until the next would not fit.
        while total + row < MAX_HISTORY_SERIALIZED_BYTES {
            history.entries.push(peer_entry(peer, peer as usize, &bulk));
            total += row + usize::from(peer > 0);
            peer += 1;
        }
        assert_eq!(serde_json::to_vec(&history).unwrap().len(), total);
        let last = peer - 1;
        // A new contact's single message is now the largest conversation.
        let newcomer = hex::encode([0xfe; 32]);
        history.append(peer_entry(0xfe, 1_000, &"n".repeat(48_000)));
        assert_eq!(history.for_peer(&newcomer).len(), 1);
        // Equal-sized conversations: the one holding the oldest row pays.
        assert!(history.for_peer(&hex::encode([0u8; 32])).is_empty());
        assert_eq!(history.for_peer(&hex::encode([last; 32])).len(), 1);
        assert!(serde_json::to_vec(&history).unwrap().len() <= MAX_HISTORY_SERIALIZED_BYTES);
    }

    /// Upserting keystore, like `set_generic_password` / `create_item(replace=true)`.
    struct RacyUpsertKeyStore {
        key: std::sync::Mutex<Option<[u8; 32]>>,
    }

    impl ProtectedKeyStore for RacyUpsertKeyStore {
        fn get(&self, _: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, ChatHistoryError> {
            std::thread::yield_now();
            Ok(self.key.lock().unwrap().map(Zeroizing::new))
        }

        fn add(&self, _: &Path, key: &[u8; 32]) -> Result<bool, ChatHistoryError> {
            std::thread::yield_now();
            *self.key.lock().unwrap() = Some(*key);
            std::thread::yield_now();
            Ok(true)
        }
    }

    #[test]
    fn concurrent_first_use_key_init_converges_on_one_key() {
        use std::sync::{Arc, Barrier};
        let dir = tempdir().unwrap();
        let store = Arc::new(RacyUpsertKeyStore {
            key: std::sync::Mutex::new(None),
        });
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                let data_dir = dir.path().to_path_buf();
                std::thread::spawn(move || {
                    barrier.wait();
                    init_protected_key(&*store, &data_dir).map(|key| *key)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let stored = store.key.lock().unwrap().expect("key minted");
        for result in results {
            assert_eq!(
                result.expect("no writer may fail or diverge"),
                stored,
                "every writer must seal under the surviving key"
            );
        }
    }

    /// An item appears between our lookup and our add (writer outside the lock).
    struct AddOnlyLateItemStore {
        existing: [u8; 32],
        gets: std::sync::atomic::AtomicUsize,
    }

    impl ProtectedKeyStore for AddOnlyLateItemStore {
        fn get(&self, _: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, ChatHistoryError> {
            let n = self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((n > 0).then(|| Zeroizing::new(self.existing)))
        }

        fn add(&self, _: &Path, _: &[u8; 32]) -> Result<bool, ChatHistoryError> {
            Ok(false)
        }
    }

    #[test]
    fn key_init_adopts_an_existing_item_instead_of_replacing_it() {
        let dir = tempdir().unwrap();
        let store = AddOnlyLateItemStore {
            existing: [0x5c; 32],
            gets: Default::default(),
        };
        assert_eq!(*init_protected_key(&store, dir.path()).unwrap(), [0x5c; 32]);
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

        let unavailable = TestProtector::unavailable(10);
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

    /// A history/stage file whose mode drifted (a umask-022 restore, a sync
    /// client) is authenticated ciphertext: loading repairs it to owner-only
    /// instead of failing history and the send path until a manual chmod.
    #[cfg(unix)]
    #[test]
    fn group_readable_ciphertext_is_repaired_not_fatal() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempdir().unwrap();
        let protector = TestProtector::new(0x31);
        let mut history = ChatHistory::default();
        history.append(sample_entry());
        history.save_with_protector(dir.path(), &protector).unwrap();
        let path = history_path(dir.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let loaded = ChatHistory::load_with_protector(dir.path(), &protector).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(mode(&path), 0o600);

        let stage_protector = TestStageProtector::new(0x32);
        stage_outbound_body_with_protector(
            dir.path(),
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            &[4u8; 16],
            1,
            "keep-me",
            &stage_protector,
        )
        .unwrap();
        let stage = outbound_body_stage_path(dir.path());
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o664)).unwrap();
        let file = load_stage_file_with_protector(dir.path(), &stage_protector).unwrap();
        assert_eq!(file.entries.len(), 1);
        assert_eq!(mode(&stage), 0o600);
    }

    /// A hard-linked ciphertext file is still refused, and the error says what
    /// to fix instead of a bare "unsafe file metadata".
    #[cfg(unix)]
    #[test]
    fn hard_linked_ciphertext_is_refused_with_an_actionable_message() {
        let dir = tempdir().unwrap();
        let protector = TestProtector::new(0x33);
        let mut history = ChatHistory::default();
        history.append(sample_entry());
        history.save_with_protector(dir.path(), &protector).unwrap();
        let alias = dir.path().join("snapshot-alias");
        std::fs::hard_link(history_path(dir.path()), &alias).unwrap();
        let error = ChatHistory::load_with_protector(dir.path(), &protector).unwrap_err();
        assert!(matches!(error, ChatHistoryError::UnsafeFileMetadata));
        let text = error.to_string();
        assert!(
            text.contains("hard link") && text.contains("symlink"),
            "{text}"
        );
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
        let unavailable = TestProtector::unavailable(12);
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
        assert!(BlockList::load_checked(dir.path())
            .unwrap()
            .is_blocked("aabb"));
    }

    #[test]
    fn block_list_corrupt_is_fail_closed_and_never_overwritten() {
        let dir = tempdir().unwrap();
        let path = blocked_path(dir.path());
        let corrupt = b"{\"pub_hex\":[\"aa\",\"bb\"";
        std::fs::write(&path, corrupt).unwrap();
        assert!(BlockList::load_checked(dir.path()).is_err());
        // A caller that ignored the error and started from an empty list must
        // not be able to replace (i.e. unblock) the existing entries.
        let mut fresh = BlockList::default();
        fresh.block("cc");
        assert!(fresh.save(dir.path()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    }

    #[test]
    fn block_list_oversized_file_is_rejected() {
        let dir = tempdir().unwrap();
        let mut huge = b"{\"pub_hex\":[".to_vec();
        huge.extend(std::iter::repeat_n(b' ', MAX_BLOCK_LIST_BYTES as usize));
        huge.extend_from_slice(b"]}");
        std::fs::write(blocked_path(dir.path()), &huge).unwrap();
        let error = BlockList::load_checked(dir.path()).unwrap_err();
        assert!(error.contains("size limit"), "{error}");
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
    fn a_confirmed_delivery_is_never_downgraded() {
        for (current, next, want) in [
            ("queued", "delivered", "delivered"),
            ("delivered", "queued", "delivered"),
            ("delivered", "failed", "delivered"),
            ("delivered", "expired", "delivered"),
            ("delivered", "cancelled", "delivered"),
            ("delivered", "read", "read"),
            ("read", "delivered", "read"),
            ("read", "queued", "read"),
            ("queued", "expired", "expired"),
            ("failed", "queued", "queued"),
        ] {
            assert_eq!(
                delivery_after("out", current, next),
                want,
                "{current} -> {next}"
            );
        }
        // Inbound rows are not outbound delivery states.
        assert_eq!(delivery_after("in", "delivered", "received"), "received");
        // Through upsert too (the retry path re-stages `queued`).
        let mut history = ChatHistory::default();
        let mut row = ChatHistoryEntry {
            message_id_hex: "aa".repeat(16),
            direction: "out".into(),
            peer_petname: String::new(),
            peer_tag: String::new(),
            peer_pub_hex: "bb".repeat(32),
            created_at_ms: 1,
            delivery: "delivered".into(),
            preview: "hi".into(),
            body: "hi".into(),
        };
        history.upsert(row.clone());
        row.delivery = "queued".into();
        history.upsert(row);
        assert_eq!(history.entries[0].delivery, "delivered");
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

        let unavailable = TestProtector::unavailable(9);
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

    #[test]
    fn passphrase_vault_history_key_is_minted_once_and_add_only() {
        use crate::keystore_vault::test_support::test_vault;
        let dir = tempfile::tempdir().unwrap();
        let store = VaultKeyStore {
            vault: test_vault(dir.path(), "history vault passphrase").0,
        };
        assert!(matches!(
            load_vault_history_key(&store, dir.path(), false),
            Err(ChatHistoryError::MissingProtectedKey)
        ));
        assert!(!dir
            .path()
            .join(crate::keystore_vault::VAULT_FILE_NAME)
            .exists());
        let key = load_vault_history_key(&store, dir.path(), true).unwrap();
        let again = load_vault_history_key(&store, dir.path(), false).unwrap();
        assert_eq!(*key, *again);
        assert!(!store.add(dir.path(), &[0x55; 32]).unwrap(), "add-only");
        let reopened = VaultKeyStore {
            vault: test_vault(dir.path(), "history vault passphrase").0,
        };
        assert_eq!(*reopened.get(dir.path()).unwrap().unwrap(), *key);
        let sealed = aead_protect(&key, dir.path(), HISTORY_AAD_DOMAIN, b"hello").unwrap();
        assert_eq!(
            aead_unprotect(&again, dir.path(), HISTORY_AAD_DOMAIN, &sealed).unwrap(),
            b"hello"
        );
        let wrong = VaultKeyStore {
            vault: test_vault(dir.path(), "a wrong passphrase").0,
        };
        assert!(matches!(
            wrong.get(dir.path()),
            Err(ChatHistoryError::ProtectedStoreUnavailable(_))
        ));
    }
}
