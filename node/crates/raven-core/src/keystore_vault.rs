//! Passphrase-protected secret vault: the GNU/Linux (and other non-macOS Unix)
//! keystore when no Secret Service is reachable (R1, owner decision
//! 2026-10-08). Format, threat model, passphrase sources and selection rules:
//! `docs/design/2026-10-linux-keystore.md`.
//!
//! Platform-neutral on purpose: every CI host (macOS and Windows included)
//! runs the unit tests, although only non-macOS Unix release builds use it.
//!
//! One vault file per profile (`<data-dir>/keystore.vault`) holds every secret
//! kind as a named entry. Layout (64-byte header, AAD = header):
//! `magic "RVNVLT01" | version 1 | kdf 1 (Argon2id v0x13) | aead 1
//! (XChaCha20-Poly1305) | reserved 0 | m KiB, t, p (u32 LE) | salt[16] |
//! nonce[24] | ciphertext+tag`. A fresh random nonce is used on every write.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

/// Vault file inside the profile (data) directory.
pub const VAULT_FILE_NAME: &str = "keystore.vault";
/// Cross-process writer lock (`DataDirLock`); inert for first-install checks.
pub const VAULT_LOCK_NAME: &str = ".keystore_vault.lock.sqlite";
/// Names a file that holds the passphrase (mode 0400/0600, owned by the user).
pub const PASSPHRASE_FILE_ENV: &str = "RAVEN_KEYSTORE_PASSPHRASE_FILE";
/// Refused on sight: a passphrase in the environment leaks to other processes.
pub const FORBIDDEN_PASSPHRASE_ENV: &str = "RAVEN_KEYSTORE_PASSPHRASE";
/// systemd `LoadCredential=raven-keystore-passphrase:<file>` name.
pub const SYSTEMD_CREDENTIAL_NAME: &str = "raven-keystore-passphrase";

/// Entry holding the 32-byte identity seed.
pub const IDENTITY_SEED_ENTRY: &str = "identity-seed";
/// Entry holding the 32-byte chat-history / outbound-stage key.
pub const CHAT_HISTORY_KEY_ENTRY: &str = "chat-history-key";
/// Prefix of indexed-session secret entries.
pub const SESSION_ENTRY_PREFIX: &str = "indexed-session/";
/// Prefix of the prekey lifecycle entry.
pub const PREKEY_ENTRY_PREFIX: &str = "prekey-lifecycle/";

const MAGIC: &[u8; 8] = b"RVNVLT01";
const FORMAT_VERSION: u8 = 1;
const KDF_ARGON2ID_V13: u8 = 1;
const AEAD_XCHACHA20_POLY1305: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
/// Bytes covered by the AEAD as associated data.
pub const HEADER_LEN: usize = 64;
const TAG_LEN: usize = 16;
/// Decrypted vault size cap (prekey state alone may reach 2 MiB).
pub const MAX_PLAINTEXT_BYTES: usize = 32 * 1024 * 1024;
const MAX_FILE_BYTES: usize = HEADER_LEN + MAX_PLAINTEXT_BYTES + TAG_LEN;
/// Entry names are printable ASCII without spaces, at most this long.
pub const MAX_ENTRY_NAME_BYTES: usize = 160;
const MAX_ENTRIES: usize = 100_000;
/// Longest accepted passphrase, in bytes.
pub const MAX_PASSPHRASE_BYTES: usize = 1024;
/// Shortest accepted *new* passphrase, in characters.
pub const MIN_NEW_PASSPHRASE_CHARS: usize = 8;
const INTERACTIVE_UNLOCK_ATTEMPTS: u32 = 3;
const MUTATE_ATTEMPTS: usize = 3;

/// Argon2id cost parameters as stored in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// Parameters every production vault is created with.
    pub const DEFAULT: Self = Self {
        m_kib: 64 * 1024,
        t: 3,
        p: 1,
    };
}

/// Accepted parameter range when *reading* a header. A planted file outside it
/// is refused before the KDF runs (no memory / CPU bomb, no silent weakening).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfBounds {
    pub min_m_kib: u32,
    pub max_m_kib: u32,
    pub min_t: u32,
    pub max_t: u32,
    pub min_p: u32,
    pub max_p: u32,
}

/// Bounds for every production vault.
pub const PRODUCTION_BOUNDS: KdfBounds = KdfBounds {
    min_m_kib: 19 * 1024,
    max_m_kib: 1024 * 1024,
    min_t: 1,
    max_t: 16,
    min_p: 1,
    max_p: 8,
};

impl KdfBounds {
    pub fn check(&self, params: KdfParams) -> Result<(), VaultError> {
        let ok = (self.min_m_kib..=self.max_m_kib).contains(&params.m_kib)
            && (self.min_t..=self.max_t).contains(&params.t)
            && (self.min_p..=self.max_p).contains(&params.p)
            && params.m_kib >= 8 * params.p;
        if ok {
            Ok(())
        } else {
            Err(VaultError::UnsafeParams(format!(
                "Argon2id m={} KiB t={} p={} is outside the accepted range m={}..={} KiB t={}..={} p={}..={}",
                params.m_kib,
                params.t,
                params.p,
                self.min_m_kib,
                self.max_m_kib,
                self.min_t,
                self.max_t,
                self.min_p,
                self.max_p
            )))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("keystore vault I/O: {0}")]
    Io(String),
    #[error(
        "the keystore passphrase is wrong, or the vault file was changed or damaged (it could not be decrypted)"
    )]
    WrongPassphraseOrTampered,
    #[error("keystore vault is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("keystore vault refused: {0}")]
    UnsafeParams(String),
    #[error("keystore vault file refused: {0}")]
    UnsafeFile(String),
    #[error("keystore passphrase unavailable: {0}")]
    PassphraseUnavailable(String),
    #[error("keystore vault entry already exists: {0}")]
    EntryExists(String),
    #[error("keystore vault limit exceeded: {0}")]
    TooLarge(&'static str),
    #[error("invalid keystore vault entry name")]
    InvalidName,
}

/// Why a passphrase is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphrasePurpose {
    /// A new vault (or a new passphrase) is being created.
    Create,
    /// An existing vault is being opened.
    Unlock,
}

/// Where passphrases come from. Production uses [`DefaultPassphraseSource`].
pub trait PassphraseSource: Send + Sync {
    fn passphrase(
        &self,
        purpose: PassphrasePurpose,
        vault_path: &Path,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError>;

    /// How many unlock passphrases may be tried (more than one only when a
    /// person is typing).
    fn unlock_attempts(&self) -> u32 {
        1
    }

    /// Called after a wrong unlock passphrase when another attempt follows.
    fn wrong_passphrase(&self) {}
}

static TERMINAL_PROMPT_ENABLED: AtomicBool = AtomicBool::new(false);

/// Let this process ask for the passphrase on its controlling terminal
/// (`ash` / `raven` only; `raven-node` never calls this). Prompts still need
/// stdin to be a terminal.
pub fn enable_terminal_prompt() {
    TERMINAL_PROMPT_ENABLED.store(true, Ordering::SeqCst);
}

fn terminal_prompt_enabled() -> bool {
    TERMINAL_PROMPT_ENABLED.load(Ordering::SeqCst)
}

/// Which passphrase source applies, decided from the environment only.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SourceChoice {
    Refused(String),
    File(PathBuf),
    Credential(PathBuf),
    Terminal,
    Unavailable,
}

fn choose_source(
    env: &dyn Fn(&str) -> Option<OsString>,
    terminal_enabled: bool,
    credential_exists: &dyn Fn(&Path) -> bool,
) -> SourceChoice {
    if env(FORBIDDEN_PASSPHRASE_ENV).is_some() {
        return SourceChoice::Refused(format!(
            "{FORBIDDEN_PASSPHRASE_ENV} is set; RAVEN never takes the passphrase itself from the environment (other processes can read it). Put it in a file only you can read (chmod 600) and set {PASSPHRASE_FILE_ENV}=<path> instead"
        ));
    }
    if let Some(path) = env(PASSPHRASE_FILE_ENV).filter(|v| !v.is_empty()) {
        return SourceChoice::File(PathBuf::from(path));
    }
    if let Some(dir) = env("CREDENTIALS_DIRECTORY").filter(|v| !v.is_empty()) {
        let candidate = Path::new(&dir).join(SYSTEMD_CREDENTIAL_NAME);
        if credential_exists(&candidate) {
            return SourceChoice::Credential(candidate);
        }
    }
    if terminal_enabled {
        return SourceChoice::Terminal;
    }
    SourceChoice::Unavailable
}

fn no_source_message(vault_path: &Path) -> String {
    format!(
        "this profile's keys are in a passphrase-protected vault ({}) and this program cannot ask for the passphrase. Set {PASSPHRASE_FILE_ENV}=<file> (a file owned by you, mode 0600 or 0400, holding only the passphrase), or run the service under systemd with LoadCredential={SYSTEMD_CREDENTIAL_NAME}:<file>, or run `raven` on a terminal",
        vault_path.display()
    )
}

/// The production passphrase source: passphrase file, then systemd
/// credential, then (when enabled and stdin is a terminal) an interactive
/// no-echo prompt. Never argv, never an environment value.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultPassphraseSource;

impl DefaultPassphraseSource {
    fn choice(&self) -> SourceChoice {
        choose_source(
            &|key| std::env::var_os(key),
            terminal_prompt_enabled(),
            &|path| std::fs::symlink_metadata(path).is_ok(),
        )
    }
}

impl PassphraseSource for DefaultPassphraseSource {
    fn passphrase(
        &self,
        purpose: PassphrasePurpose,
        vault_path: &Path,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        match self.choice() {
            SourceChoice::Refused(message) => Err(VaultError::PassphraseUnavailable(message)),
            SourceChoice::File(path) => read_passphrase_file(&path, purpose, false),
            SourceChoice::Credential(path) => read_passphrase_file(&path, purpose, true),
            SourceChoice::Terminal => terminal::prompt(purpose, vault_path),
            SourceChoice::Unavailable => Err(VaultError::PassphraseUnavailable(no_source_message(
                vault_path,
            ))),
        }
    }

    fn unlock_attempts(&self) -> u32 {
        if self.choice() == SourceChoice::Terminal {
            INTERACTIVE_UNLOCK_ATTEMPTS
        } else {
            1
        }
    }

    fn wrong_passphrase(&self) {
        terminal::notice("Wrong passphrase, try again.\n");
    }
}

/// Read a passphrase file. It must be a regular file (not a symlink), owned
/// by the current user (or root for a systemd credential when
/// `systemd_credential`), and mode exactly 0400/0600 (a credential: no
/// group/other bits). One trailing newline is stripped.
pub fn read_passphrase_file(
    path: &Path,
    purpose: PassphrasePurpose,
    systemd_credential: bool,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let unavailable =
        |what: String| VaultError::PassphraseUnavailable(format!("{}: {what}", path.display()));
    let link = std::fs::symlink_metadata(path)
        .map_err(|e| unavailable(format!("cannot read the passphrase file ({e})")))?;
    if !link.file_type().is_file() {
        return Err(unavailable(
            "the passphrase file must be a regular file (not a symlink or directory)".into(),
        ));
    }
    let mut file = std::fs::File::open(path)
        .map_err(|e| unavailable(format!("cannot open the passphrase file ({e})")))?;
    let meta = file
        .metadata()
        .map_err(|e| unavailable(format!("cannot stat the passphrase file ({e})")))?;
    if !meta.file_type().is_file() {
        return Err(unavailable(
            "the passphrase file must be a regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if (meta.dev(), meta.ino()) != (link.dev(), link.ino()) {
            return Err(unavailable(
                "the passphrase file changed while it was being opened".into(),
            ));
        }
        let euid = crate::ipc::current_euid();
        let owner_ok = meta.uid() == euid || (systemd_credential && meta.uid() == 0);
        if !owner_ok {
            return Err(unavailable(
                "the passphrase file must be owned by the user running RAVEN".into(),
            ));
        }
        let mode = meta.permissions().mode() & 0o777;
        let mode_ok = if systemd_credential {
            mode & 0o077 == 0
        } else {
            mode == 0o400 || mode == 0o600
        };
        if !mode_ok {
            return Err(unavailable(format!(
                "the passphrase file has mode {mode:04o}; it must be 0600 or 0400 (run: chmod 600 {})",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = systemd_credential;
    if meta.len() > (MAX_PASSPHRASE_BYTES + 2) as u64 {
        return Err(unavailable(format!(
            "the passphrase file is longer than {MAX_PASSPHRASE_BYTES} bytes"
        )));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PASSPHRASE_BYTES + 3));
    (&mut file)
        .take((MAX_PASSPHRASE_BYTES + 3) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| unavailable(format!("cannot read the passphrase file ({e})")))?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    finish_passphrase(bytes, purpose)
}

/// Length / emptiness rules shared by every source.
fn finish_passphrase(
    bytes: Zeroizing<Vec<u8>>,
    purpose: PassphrasePurpose,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if bytes.is_empty() {
        return Err(VaultError::PassphraseUnavailable(
            "the keystore passphrase is empty".into(),
        ));
    }
    if bytes.len() > MAX_PASSPHRASE_BYTES {
        return Err(VaultError::PassphraseUnavailable(format!(
            "the keystore passphrase is longer than {MAX_PASSPHRASE_BYTES} bytes"
        )));
    }
    if purpose == PassphrasePurpose::Create {
        let chars = std::str::from_utf8(&bytes)
            .map(|s| s.chars().count())
            .unwrap_or(bytes.len());
        if chars < MIN_NEW_PASSPHRASE_CHARS {
            return Err(VaultError::PassphraseUnavailable(format!(
                "a new keystore passphrase must have at least {MIN_NEW_PASSPHRASE_CHARS} characters"
            )));
        }
    }
    Ok(bytes)
}

#[cfg(unix)]
mod terminal {
    use super::{
        finish_passphrase, PassphrasePurpose, VaultError, MAX_PASSPHRASE_BYTES,
        MIN_NEW_PASSPHRASE_CHARS, PASSPHRASE_FILE_ENV,
    };
    use std::fs::File;
    use std::io::{IsTerminal, Read, Write};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use zeroize::Zeroizing;

    const CREATE_ATTEMPTS: usize = 3;

    fn open_tty() -> Result<File, VaultError> {
        if !std::io::stdin().is_terminal() {
            return Err(VaultError::PassphraseUnavailable(format!(
                "stdin is not a terminal, so RAVEN will not ask for the keystore passphrase; set {PASSPHRASE_FILE_ENV}=<file> (mode 0600, owned by you)"
            )));
        }
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|e| {
                VaultError::PassphraseUnavailable(format!(
                    "cannot open the terminal for the passphrase prompt ({e}); set {PASSPHRASE_FILE_ENV}=<file>"
                ))
            })
    }

    /// Restores terminal echo when dropped (also on an early `?` return).
    struct EchoOff {
        tty: File,
    }

    impl EchoOff {
        fn new(tty: &File) -> Result<Self, VaultError> {
            let refuse = || {
                VaultError::PassphraseUnavailable(format!(
                    "cannot turn off terminal echo, so the passphrase would be visible; set {PASSPHRASE_FILE_ENV}=<file> instead"
                ))
            };
            let tty = tty.try_clone().map_err(|_| refuse())?;
            let stdin = tty.try_clone().map_err(|_| refuse())?;
            let ok = Command::new("stty")
                .arg("-echo")
                .stdin(Stdio::from(stdin))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
            if !ok {
                return Err(refuse());
            }
            Ok(Self { tty })
        }
    }

    impl Drop for EchoOff {
        fn drop(&mut self) {
            if let Ok(stdin) = self.tty.try_clone() {
                let _ = Command::new("stty")
                    .arg("echo")
                    .stdin(Stdio::from(stdin))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }

    fn read_hidden(tty: &mut File, prompt: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let io = |e: std::io::Error| VaultError::PassphraseUnavailable(format!("terminal: {e}"));
        tty.write_all(prompt.as_bytes()).map_err(io)?;
        tty.flush().map_err(io)?;
        let echo = EchoOff::new(tty)?;
        let mut line = Zeroizing::new(Vec::with_capacity(64));
        let mut byte = [0u8; 1];
        loop {
            match tty.read(&mut byte) {
                Ok(0) => break,
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) => {
                    if line.len() <= MAX_PASSPHRASE_BYTES {
                        line.push(byte[0]);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io(e)),
            }
        }
        drop(echo);
        let _ = tty.write_all(b"\n");
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(line)
    }

    pub(super) fn notice(text: &str) {
        if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
            let _ = tty.write_all(text.as_bytes());
        }
    }

    pub(super) fn prompt(
        purpose: PassphrasePurpose,
        vault_path: &Path,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let mut tty = open_tty()?;
        if purpose == PassphrasePurpose::Unlock {
            let line = read_hidden(
                &mut tty,
                &format!("RAVEN keystore passphrase ({}): ", vault_path.display()),
            )?;
            return finish_passphrase(line, purpose);
        }
        let explanation = format!(
            "\nRAVEN needs a passphrase to protect this profile's keys.\n\
             No unlocked desktop keyring (Secret Service) is available here, so RAVEN keeps\n\
             your identity and message keys in an encrypted file:\n  {}\n\
             The passphrase is what protects that file. RAVEN asks for it whenever it starts.\n\
             If you forget it, the keys cannot be recovered. Use at least {MIN_NEW_PASSPHRASE_CHARS} characters.\n\
             For the background service, put it in a file only you can read and set\n\
             {PASSPHRASE_FILE_ENV} (see docs/INSTALL_Linux.md).\n\n",
            vault_path.display()
        );
        let _ = tty.write_all(explanation.as_bytes());
        for _ in 0..CREATE_ATTEMPTS {
            let first = read_hidden(&mut tty, "New keystore passphrase: ")?;
            let first = match finish_passphrase(first, purpose) {
                Ok(first) => first,
                Err(VaultError::PassphraseUnavailable(why)) => {
                    let _ = tty.write_all(format!("{why}.\n").as_bytes());
                    continue;
                }
                Err(e) => return Err(e),
            };
            let second = read_hidden(&mut tty, "Repeat the passphrase: ")?;
            if *first == *second {
                return Ok(first);
            }
            let _ = tty.write_all(b"The two passphrases did not match.\n");
        }
        Err(VaultError::PassphraseUnavailable(
            "no matching passphrase was entered".into(),
        ))
    }
}

#[cfg(not(unix))]
mod terminal {
    use super::{PassphrasePurpose, VaultError, PASSPHRASE_FILE_ENV};
    use std::path::Path;
    use zeroize::Zeroizing;

    pub(super) fn notice(_text: &str) {}

    pub(super) fn prompt(
        _purpose: PassphrasePurpose,
        _vault_path: &Path,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Err(VaultError::PassphraseUnavailable(format!(
            "interactive passphrase prompts are not supported on this platform; set {PASSPHRASE_FILE_ENV}"
        )))
    }
}

// --- key cache ---------------------------------------------------------------

struct CachedKey {
    path: PathBuf,
    salt: [u8; SALT_LEN],
    params: KdfParams,
    key: Zeroizing<[u8; 32]>,
}

/// Derived keys of vaults this process already unlocked, so one process asks
/// for the passphrase (and runs Argon2id) once per vault.
#[derive(Default)]
pub struct KeyCache {
    keys: Mutex<Vec<CachedKey>>,
}

impl KeyCache {
    fn get(
        &self,
        path: &Path,
        salt: &[u8; SALT_LEN],
        params: KdfParams,
    ) -> Option<Zeroizing<[u8; 32]>> {
        let keys = self.keys.lock().ok()?;
        keys.iter()
            .find(|k| k.path == path && k.salt == *salt && k.params == params)
            .map(|k| k.key.clone())
    }

    fn put(&self, path: &Path, salt: [u8; SALT_LEN], params: KdfParams, key: &[u8; 32]) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.retain(|k| k.path != path);
            keys.push(CachedKey {
                path: path.to_path_buf(),
                salt,
                params,
                key: Zeroizing::new(*key),
            });
        }
    }

    fn forget(&self, path: &Path) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.retain(|k| k.path != path);
        }
    }
}

fn process_key_cache() -> Arc<KeyCache> {
    static CACHE: OnceLock<Arc<KeyCache>> = OnceLock::new();
    CACHE.get_or_init(|| Arc::new(KeyCache::default())).clone()
}

// --- format ------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..8].copy_from_slice(MAGIC);
        out[8] = FORMAT_VERSION;
        out[9] = KDF_ARGON2ID_V13;
        out[10] = AEAD_XCHACHA20_POLY1305;
        out[11] = 0;
        out[12..16].copy_from_slice(&self.params.m_kib.to_le_bytes());
        out[16..20].copy_from_slice(&self.params.t.to_le_bytes());
        out[20..24].copy_from_slice(&self.params.p.to_le_bytes());
        out[24..40].copy_from_slice(&self.salt);
        out[40..64].copy_from_slice(&self.nonce);
        out
    }

    fn decode(raw: &[u8], bounds: &KdfBounds) -> Result<Self, VaultError> {
        if raw.len() < HEADER_LEN + TAG_LEN {
            return Err(VaultError::Corrupt("vault file is truncated"));
        }
        if &raw[..8] != MAGIC {
            return Err(VaultError::Corrupt("not a RAVEN keystore vault"));
        }
        if raw[8] != FORMAT_VERSION {
            return Err(VaultError::Corrupt("unsupported vault version"));
        }
        if raw[9] != KDF_ARGON2ID_V13 || raw[10] != AEAD_XCHACHA20_POLY1305 || raw[11] != 0 {
            return Err(VaultError::Corrupt("unsupported vault algorithms"));
        }
        let u32_at =
            |at: usize| u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]);
        let params = KdfParams {
            m_kib: u32_at(12),
            t: u32_at(16),
            p: u32_at(20),
        };
        bounds.check(params)?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[24..40]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&raw[40..64]);
        Ok(Self {
            params,
            salt,
            nonce,
        })
    }
}

type Entries = BTreeMap<String, Zeroizing<Vec<u8>>>;

fn validate_name(name: &str) -> Result<(), VaultError> {
    if name.is_empty()
        || name.len() > MAX_ENTRY_NAME_BYTES
        || !name.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(VaultError::InvalidName);
    }
    Ok(())
}

fn encode_entries(entries: &Entries) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if entries.len() > MAX_ENTRIES {
        return Err(VaultError::TooLarge("too many vault entries"));
    }
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (name, value) in entries {
        validate_name(name)?;
        let len = u32::try_from(value.len()).map_err(|_| VaultError::TooLarge("vault entry"))?;
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(value);
        if out.len() > MAX_PLAINTEXT_BYTES {
            return Err(VaultError::TooLarge("vault contents"));
        }
    }
    Ok(out)
}

struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.rest.len() < n {
            return None;
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Some(head)
    }

    fn u16(&mut self) -> Option<usize> {
        self.take(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
    }

    fn u32(&mut self) -> Option<usize> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }
}

fn decode_entries(plaintext: &[u8]) -> Result<Entries, VaultError> {
    let mut cursor = Cursor { rest: plaintext };
    let count = cursor
        .u32()
        .filter(|c| *c <= MAX_ENTRIES)
        .ok_or(VaultError::Corrupt("vault contents are malformed"))?;
    let mut entries = Entries::new();
    let mut previous: Option<String> = None;
    for _ in 0..count {
        let name = cursor
            .u16()
            .and_then(|len| cursor.take(len))
            .and_then(|b| std::str::from_utf8(b).ok())
            .map(str::to_owned)
            .ok_or(VaultError::Corrupt("vault entry name is malformed"))?;
        validate_name(&name).map_err(|_| VaultError::Corrupt("vault entry name is malformed"))?;
        // Strictly increasing: canonical, no duplicates.
        if previous.as_deref().is_some_and(|p| p >= name.as_str()) {
            return Err(VaultError::Corrupt("vault entries are not canonical"));
        }
        let value = cursor
            .u32()
            .and_then(|len| cursor.take(len))
            .ok_or(VaultError::Corrupt("vault entry value is truncated"))?;
        entries.insert(name.clone(), Zeroizing::new(value.to_vec()));
        previous = Some(name);
    }
    if !cursor.rest.is_empty() {
        return Err(VaultError::Corrupt("vault contents have trailing bytes"));
    }
    Ok(entries)
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let argon_params = argon2::Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| VaultError::UnsafeParams(format!("Argon2id parameters: {e}")))?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, &mut key[..])
        .map_err(|e| VaultError::UnsafeParams(format!("Argon2id: {e}")))?;
    Ok(key)
}

fn decrypt_entries(key: &[u8; 32], raw: &[u8], header: &Header) -> Result<Entries, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| VaultError::Corrupt("vault key has the wrong length"))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&header.nonce),
                Payload {
                    msg: &raw[HEADER_LEN..],
                    aad: &raw[..HEADER_LEN],
                },
            )
            .map_err(|_| VaultError::WrongPassphraseOrTampered)?,
    );
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(VaultError::TooLarge("vault contents"));
    }
    decode_entries(&plaintext)
}

/// Key material obtained before the writer lock is taken.
struct Unlocked {
    key: Zeroizing<[u8; 32]>,
    salt: [u8; SALT_LEN],
    params: KdfParams,
    /// Kept only when typed/read in this call, so a vault that changed
    /// meanwhile can be re-derived without asking again.
    passphrase: Option<Zeroizing<Vec<u8>>>,
}

/// A profile's passphrase vault. Cheap to construct; holds no secret until
/// used (derived keys live in the shared [`KeyCache`]).
pub struct Vault {
    path: PathBuf,
    dir: PathBuf,
    create_params: KdfParams,
    bounds: KdfBounds,
    source: Arc<dyn PassphraseSource>,
    cache: Arc<KeyCache>,
}

impl Vault {
    /// The production vault of a profile: default Argon2id parameters,
    /// production bounds, [`DefaultPassphraseSource`], process-wide key cache.
    pub fn for_data_dir(data_dir: &Path) -> Self {
        Self::with_options(
            data_dir,
            KdfParams::DEFAULT,
            PRODUCTION_BOUNDS,
            Arc::new(DefaultPassphraseSource),
            process_key_cache(),
        )
    }

    /// Fully injected vault (tests, tools).
    pub fn with_options(
        data_dir: &Path,
        create_params: KdfParams,
        bounds: KdfBounds,
        source: Arc<dyn PassphraseSource>,
        cache: Arc<KeyCache>,
    ) -> Self {
        Self {
            path: data_dir.join(VAULT_FILE_NAME),
            dir: data_dir.to_path_buf(),
            create_params,
            bounds,
            source,
            cache,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the vault file exists (a symlink or other non-file is refused).
    pub fn exists(&self) -> Result<bool, VaultError> {
        Ok(self.read_raw()?.is_some())
    }

    /// One entry, or `None` when the entry or the whole vault is absent. An
    /// absent vault never asks for a passphrase.
    pub fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        validate_name(name)?;
        let Some(raw) = self.read_raw()? else {
            return Ok(None);
        };
        let header = Header::decode(&raw, &self.bounds)?;
        let (_unlocked, mut entries) = self.unlock(&raw, &header, None)?;
        Ok(entries.remove(name))
    }

    /// Names of all entries (no values).
    pub fn entry_names(&self) -> Result<Vec<String>, VaultError> {
        let Some(raw) = self.read_raw()? else {
            return Ok(Vec::new());
        };
        let header = Header::decode(&raw, &self.bounds)?;
        let (_unlocked, entries) = self.unlock(&raw, &header, None)?;
        Ok(entries.into_keys().collect())
    }

    /// Insert or replace an entry (creates the vault on first use).
    pub fn put(&self, name: &str, value: &[u8]) -> Result<(), VaultError> {
        validate_name(name)?;
        self.mutate(true, &|entries| {
            entries.insert(name.to_owned(), Zeroizing::new(value.to_vec()));
            Ok(())
        })
    }

    /// Add-only insert: fails with [`VaultError::EntryExists`] and changes
    /// nothing when the entry is already present.
    pub fn insert_new(&self, name: &str, value: &[u8]) -> Result<(), VaultError> {
        validate_name(name)?;
        self.mutate(true, &|entries| {
            if entries.contains_key(name) {
                return Err(VaultError::EntryExists(name.to_owned()));
            }
            entries.insert(name.to_owned(), Zeroizing::new(value.to_vec()));
            Ok(())
        })
    }

    /// Remove an entry. A missing entry or vault is not an error, and an
    /// absent vault is never created.
    pub fn delete(&self, name: &str) -> Result<(), VaultError> {
        validate_name(name)?;
        self.mutate(false, &|entries| {
            entries.remove(name);
            Ok(())
        })
    }

    /// Re-encrypt every entry under a new passphrase (from `new_source`, with
    /// [`PassphrasePurpose::Create`]), a new salt and this vault's creation
    /// parameters.
    pub fn change_passphrase(&self, new_source: &dyn PassphraseSource) -> Result<(), VaultError> {
        let raw = self.read_raw()?.ok_or(VaultError::Io(
            "there is no keystore vault to re-key".into(),
        ))?;
        let header = Header::decode(&raw, &self.bounds)?;
        let (unlocked, _) = self.unlock(&raw, &header, None)?;
        let new_passphrase = new_source.passphrase(PassphrasePurpose::Create, &self.path)?;
        self.bounds.check(self.create_params)?;
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(&new_passphrase, &salt, self.create_params)?;
        let _lock = crate::paths::DataDirLock::acquire(&self.dir, VAULT_LOCK_NAME)
            .map_err(VaultError::Io)?;
        let current = self
            .read_raw()?
            .ok_or(VaultError::Io("the keystore vault disappeared".into()))?;
        let current_header = Header::decode(&current, &self.bounds)?;
        if (current_header.salt, current_header.params) != (unlocked.salt, unlocked.params) {
            return Err(VaultError::Io(
                "the keystore passphrase was changed concurrently; try again".into(),
            ));
        }
        let entries = decrypt_entries(&unlocked.key, &current, &current_header)?;
        self.write(salt, self.create_params, &key, &entries)?;
        self.cache.forget(&self.path);
        self.cache.put(&self.path, salt, self.create_params, &key);
        Ok(())
    }

    fn read_raw(&self) -> Result<Option<Vec<u8>>, VaultError> {
        let meta = match std::fs::symlink_metadata(&self.path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(VaultError::Io(e.to_string())),
        };
        if !meta.file_type().is_file() {
            return Err(VaultError::UnsafeFile(format!(
                "{} is not a regular file (symlinks are refused)",
                self.path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if meta.uid() != crate::ipc::current_euid() {
                return Err(VaultError::UnsafeFile(format!(
                    "{} is not owned by the user running RAVEN",
                    self.path.display()
                )));
            }
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(VaultError::UnsafeFile(format!(
                    "{} has mode {mode:04o}; other users must not be able to read it (run: chmod 600 {})",
                    self.path.display(),
                    self.path.display()
                )));
            }
        }
        if meta.len() > MAX_FILE_BYTES as u64 {
            return Err(VaultError::TooLarge("vault file"));
        }
        let bytes = std::fs::read(&self.path).map_err(|e| VaultError::Io(e.to_string()))?;
        if bytes.len() > MAX_FILE_BYTES {
            return Err(VaultError::TooLarge("vault file"));
        }
        Ok(Some(bytes))
    }

    /// Key for `header` (cache, carried passphrase, or the source) proven by
    /// decrypting `raw`.
    fn unlock(
        &self,
        raw: &[u8],
        header: &Header,
        carried: Option<&[u8]>,
    ) -> Result<(Unlocked, Entries), VaultError> {
        let unlocked = |key: Zeroizing<[u8; 32]>, passphrase| Unlocked {
            key,
            salt: header.salt,
            params: header.params,
            passphrase,
        };
        if let Some(key) = self.cache.get(&self.path, &header.salt, header.params) {
            return match decrypt_entries(&key, raw, header) {
                Ok(entries) => Ok((unlocked(key, None), entries)),
                Err(e) => {
                    self.cache.forget(&self.path);
                    Err(e)
                }
            };
        }
        if let Some(passphrase) = carried {
            let key = derive_key(passphrase, &header.salt, header.params)?;
            let entries = decrypt_entries(&key, raw, header)?;
            self.cache.put(&self.path, header.salt, header.params, &key);
            return Ok((
                unlocked(key, Some(Zeroizing::new(passphrase.to_vec()))),
                entries,
            ));
        }
        let attempts = self.source.unlock_attempts().max(1);
        for attempt in 1..=attempts {
            let passphrase = self
                .source
                .passphrase(PassphrasePurpose::Unlock, &self.path)?;
            let key = derive_key(&passphrase, &header.salt, header.params)?;
            match decrypt_entries(&key, raw, header) {
                Ok(entries) => {
                    self.cache.put(&self.path, header.salt, header.params, &key);
                    return Ok((unlocked(key, Some(passphrase)), entries));
                }
                Err(VaultError::WrongPassphraseOrTampered) if attempt < attempts => {
                    self.source.wrong_passphrase();
                }
                Err(e) => return Err(e),
            }
        }
        Err(VaultError::WrongPassphraseOrTampered)
    }

    fn new_material(&self) -> Result<Unlocked, VaultError> {
        self.bounds.check(self.create_params)?;
        let passphrase = self
            .source
            .passphrase(PassphrasePurpose::Create, &self.path)?;
        self.material_from(passphrase)
    }

    fn material_from(&self, passphrase: Zeroizing<Vec<u8>>) -> Result<Unlocked, VaultError> {
        self.bounds.check(self.create_params)?;
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(&passphrase, &salt, self.create_params)?;
        Ok(Unlocked {
            key,
            salt,
            params: self.create_params,
            passphrase: Some(passphrase),
        })
    }

    /// Read-modify-write under the cross-process writer lock. Passphrases and
    /// Argon2id run *before* the lock is taken (a prompt may take minutes);
    /// if the file changed meanwhile, the key is re-derived from the
    /// passphrase still held in memory.
    fn mutate(
        &self,
        create_if_missing: bool,
        apply: &dyn Fn(&mut Entries) -> Result<(), VaultError>,
    ) -> Result<(), VaultError> {
        let mut carried: Option<Zeroizing<Vec<u8>>> = None;
        for _ in 0..MUTATE_ATTEMPTS {
            // Phase 1, no lock: key material for the file as it is now.
            let (mut prepared, fresh) = match self.read_raw()? {
                Some(raw) => {
                    let header = Header::decode(&raw, &self.bounds)?;
                    let carried_bytes = carried.as_deref().map(|p| &p[..]);
                    (self.unlock(&raw, &header, carried_bytes)?.0, false)
                }
                None if !create_if_missing => return Ok(()),
                None => match carried.take() {
                    Some(passphrase) => (self.material_from(passphrase)?, true),
                    None => (self.new_material()?, true),
                },
            };
            // Phase 2, locked: re-read and apply only if nothing moved.
            let lock = crate::paths::DataDirLock::acquire(&self.dir, VAULT_LOCK_NAME)
                .map_err(VaultError::Io)?;
            let current = self.read_raw()?;
            let mut entries = match &current {
                None if !create_if_missing => return Ok(()),
                None if fresh => Entries::new(),
                Some(raw) => {
                    let header = Header::decode(raw, &self.bounds)?;
                    if !fresh && (header.salt, header.params) == (prepared.salt, prepared.params) {
                        decrypt_entries(&prepared.key, raw, &header)?
                    } else {
                        drop(lock);
                        carried = prepared.passphrase.take().or(carried);
                        continue;
                    }
                }
                // The vault vanished after it was unlocked: prepare again.
                None => {
                    drop(lock);
                    carried = prepared.passphrase.take().or(carried);
                    continue;
                }
            };
            apply(&mut entries)?;
            self.write(prepared.salt, prepared.params, &prepared.key, &entries)?;
            if fresh {
                self.cache
                    .put(&self.path, prepared.salt, prepared.params, &prepared.key);
            }
            drop(lock);
            return Ok(());
        }
        Err(VaultError::Io(
            "the keystore vault kept changing while it was being updated; try again".into(),
        ))
    }

    fn write(
        &self,
        salt: [u8; SALT_LEN],
        params: KdfParams,
        key: &[u8; 32],
        entries: &Entries,
    ) -> Result<(), VaultError> {
        let plaintext = encode_entries(entries)?;
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let header = Header {
            params,
            salt,
            nonce,
        }
        .encode();
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| VaultError::Corrupt("vault key has the wrong length"))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| VaultError::Io("vault encryption failed".into()))?;
        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        crate::paths::ensure_private_dir(&self.dir).map_err(VaultError::Io)?;
        crate::paths::atomic_write_private(&self.path, &out).map_err(VaultError::Io)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Cheap parameters so debug-build tests stay fast. Never production.
    pub(crate) const TEST_PARAMS: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };
    pub(crate) const TEST_BOUNDS: KdfBounds = KdfBounds {
        min_m_kib: 8,
        max_m_kib: 1024 * 1024,
        min_t: 1,
        max_t: 16,
        min_p: 1,
        max_p: 8,
    };

    /// Fixed passphrase; counts how often it was asked for.
    pub(crate) struct FixedSource {
        pub(crate) passphrase: Vec<u8>,
        pub(crate) asked: Mutex<Vec<PassphrasePurpose>>,
    }

    impl FixedSource {
        pub(crate) fn new(passphrase: &str) -> Arc<Self> {
            Arc::new(Self {
                passphrase: passphrase.as_bytes().to_vec(),
                asked: Mutex::new(Vec::new()),
            })
        }

        pub(crate) fn asked(&self) -> Vec<PassphrasePurpose> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl PassphraseSource for FixedSource {
        fn passphrase(
            &self,
            purpose: PassphrasePurpose,
            _vault_path: &Path,
        ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
            self.asked.lock().unwrap().push(purpose);
            finish_passphrase(Zeroizing::new(self.passphrase.clone()), purpose)
        }
    }

    /// Vault with test parameters, its own key cache and a fixed passphrase.
    pub(crate) fn test_vault(dir: &Path, passphrase: &str) -> (Vault, Arc<FixedSource>) {
        let source = FixedSource::new(passphrase);
        let vault = Vault::with_options(
            dir,
            TEST_PARAMS,
            TEST_BOUNDS,
            source.clone(),
            Arc::new(KeyCache::default()),
        );
        (vault, source)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use tempfile::TempDir;

    const PASS: &str = "correct horse battery";

    fn raw(dir: &Path) -> Vec<u8> {
        std::fs::read(dir.join(VAULT_FILE_NAME)).unwrap()
    }

    fn write_raw(dir: &Path, bytes: &[u8]) {
        crate::paths::atomic_write_private(&dir.join(VAULT_FILE_NAME), bytes).unwrap();
    }

    #[test]
    fn create_open_read_write_rotate_and_delete_entries() {
        let tmp = TempDir::new().unwrap();
        let (vault, source) = test_vault(tmp.path(), PASS);
        assert!(!vault.exists().unwrap());
        assert!(vault.get("identity-seed").unwrap().is_none());
        assert!(source.asked().is_empty(), "absent vault never prompts");
        vault.delete("identity-seed").unwrap();
        assert!(!vault.exists().unwrap(), "delete never creates a vault");

        vault.put("identity-seed", &[7u8; 32]).unwrap();
        vault.put("indexed-session/abc", b"state-1").unwrap();
        assert_eq!(source.asked(), vec![PassphrasePurpose::Create]);
        assert_eq!(&**vault.get("identity-seed").unwrap().unwrap(), &[7u8; 32]);

        // Rotate an entry: the newest value wins, the old one is gone.
        vault.put("indexed-session/abc", b"state-2").unwrap();
        assert_eq!(
            &**vault.get("indexed-session/abc").unwrap().unwrap(),
            b"state-2"
        );
        assert_eq!(
            vault.entry_names().unwrap(),
            vec![
                "identity-seed".to_string(),
                "indexed-session/abc".to_string()
            ]
        );
        vault.delete("indexed-session/abc").unwrap();
        assert!(vault.get("indexed-session/abc").unwrap().is_none());
        assert_eq!(source.asked().len(), 1, "one process asks once");

        // A fresh handle (new cache) must unlock with the passphrase.
        let (reopened, reopened_source) = test_vault(tmp.path(), PASS);
        assert_eq!(
            &**reopened.get("identity-seed").unwrap().unwrap(),
            &[7u8; 32]
        );
        assert_eq!(reopened_source.asked(), vec![PassphrasePurpose::Unlock]);
    }

    #[test]
    fn every_write_uses_a_fresh_nonce_and_keeps_the_salt() {
        let tmp = TempDir::new().unwrap();
        let (vault, _) = test_vault(tmp.path(), PASS);
        vault.put("a", b"1").unwrap();
        let first = raw(tmp.path());
        vault.put("a", b"1").unwrap();
        let second = raw(tmp.path());
        assert_eq!(first[24..40], second[24..40], "salt is per vault");
        assert_ne!(first[40..64], second[40..64], "nonce is per write");
        assert_eq!(&first[..8], MAGIC);
    }

    #[test]
    fn insert_new_is_add_only() {
        let tmp = TempDir::new().unwrap();
        let (vault, _) = test_vault(tmp.path(), PASS);
        vault.insert_new("identity-seed", &[1u8; 32]).unwrap();
        assert!(matches!(
            vault.insert_new("identity-seed", &[2u8; 32]),
            Err(VaultError::EntryExists(_))
        ));
        assert_eq!(&**vault.get("identity-seed").unwrap().unwrap(), &[1u8; 32]);
    }

    #[test]
    fn wrong_passphrase_is_refused_with_the_documented_text() {
        let tmp = TempDir::new().unwrap();
        let (vault, _) = test_vault(tmp.path(), PASS);
        vault.put("k", b"v").unwrap();
        let (wrong, _) = test_vault(tmp.path(), "not the passphrase");
        let error = wrong.get("k").unwrap_err();
        assert!(matches!(error, VaultError::WrongPassphraseOrTampered));
        assert!(error.to_string().contains("passphrase is wrong"));
        // A wrong passphrase must not be able to overwrite the vault either.
        assert!(matches!(
            wrong.put("k", b"evil"),
            Err(VaultError::WrongPassphraseOrTampered)
        ));
        assert_eq!(&**vault.get("k").unwrap().unwrap(), b"v");
    }

    #[test]
    fn tampered_header_or_ciphertext_never_decrypts() {
        let tmp = TempDir::new().unwrap();
        let (vault, _) = test_vault(tmp.path(), PASS);
        vault.put("k", b"value").unwrap();
        let good = raw(tmp.path());
        // (offset, expect a parse refusal rather than an AEAD failure)
        let cases: [(usize, bool); 7] = [
            (0, true),               // magic
            (8, true),               // version
            (11, true),              // reserved
            (16, false),             // Argon2id t: 1 -> 3 (still in bounds)
            (30, false),             // salt
            (50, false),             // nonce
            (HEADER_LEN + 3, false), // ciphertext
        ];
        for (offset, parse_refusal) in cases {
            let mut bad = good.clone();
            bad[offset] ^= if offset == 16 { 0x02 } else { 0x01 }; // t: 1 -> 3
            write_raw(tmp.path(), &bad);
            let (fresh, _) = test_vault(tmp.path(), PASS);
            let error = fresh.get("k").unwrap_err();
            let ok = if parse_refusal {
                matches!(error, VaultError::Corrupt(_))
            } else {
                matches!(error, VaultError::WrongPassphraseOrTampered)
            };
            assert!(ok, "offset {offset}: {error}");
        }
        // The cached key of the original handle must not accept tampering either.
        let mut bad = good.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x80;
        write_raw(tmp.path(), &bad);
        assert!(matches!(
            vault.get("k"),
            Err(VaultError::WrongPassphraseOrTampered)
        ));
        write_raw(tmp.path(), &good);
        let (fresh, _) = test_vault(tmp.path(), PASS);
        assert_eq!(&**fresh.get("k").unwrap().unwrap(), b"value");
    }

    #[test]
    fn truncated_files_are_corrupt_or_unauthenticated() {
        let tmp = TempDir::new().unwrap();
        let (vault, _) = test_vault(tmp.path(), PASS);
        vault.put("k", b"value").unwrap();
        let good = raw(tmp.path());
        for len in [0, 7, HEADER_LEN, HEADER_LEN + TAG_LEN - 1] {
            write_raw(tmp.path(), &good[..len]);
            let (fresh, _) = test_vault(tmp.path(), PASS);
            assert!(
                matches!(fresh.get("k"), Err(VaultError::Corrupt(_))),
                "len {len}"
            );
        }
        write_raw(tmp.path(), &good[..good.len() - 1]);
        let (fresh, _) = test_vault(tmp.path(), PASS);
        assert!(matches!(
            fresh.get("k"),
            Err(VaultError::WrongPassphraseOrTampered)
        ));
    }

    #[test]
    fn parameter_bounds_refuse_absurd_or_weak_headers_before_the_kdf() {
        let ok = KdfParams::DEFAULT;
        PRODUCTION_BOUNDS.check(ok).unwrap();
        for bad in [
            KdfParams {
                m_kib: 8 * 1024,
                ..ok
            }, // weaker than the floor
            KdfParams {
                m_kib: u32::MAX,
                ..ok
            }, // memory bomb
            KdfParams { t: 0, ..ok },
            KdfParams { t: 1_000_000, ..ok }, // CPU bomb
            KdfParams { p: 0, ..ok },
            KdfParams { p: 64, ..ok },
        ] {
            assert!(
                matches!(
                    PRODUCTION_BOUNDS.check(bad),
                    Err(VaultError::UnsafeParams(_))
                ),
                "{bad:?}"
            );
        }
        // A planted header with a 4 GiB memory cost is refused on read.
        let tmp = TempDir::new().unwrap();
        let (vault, _) = test_vault(tmp.path(), PASS);
        vault.put("k", b"v").unwrap();
        let mut bad = raw(tmp.path());
        bad[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        write_raw(tmp.path(), &bad);
        let (fresh, source) = test_vault(tmp.path(), PASS);
        assert!(matches!(fresh.get("k"), Err(VaultError::UnsafeParams(_))));
        assert!(source.asked().is_empty(), "refused before asking/deriving");
        // Production vaults refuse to be created with test-strength parameters.
        let other = TempDir::new().unwrap();
        let weak = Vault::with_options(
            other.path(),
            TEST_PARAMS,
            PRODUCTION_BOUNDS,
            FixedSource::new(PASS),
            Arc::new(KeyCache::default()),
        );
        assert!(matches!(
            weak.put("k", b"v"),
            Err(VaultError::UnsafeParams(_))
        ));
        assert!(!other.path().join(VAULT_FILE_NAME).exists());
    }

    #[test]
    fn entry_codec_is_strict_and_canonical() {
        let mut entries = Entries::new();
        entries.insert("b".into(), Zeroizing::new(b"2".to_vec()));
        entries.insert("a".into(), Zeroizing::new(b"1".to_vec()));
        let encoded = encode_entries(&entries).unwrap();
        let decoded = decode_entries(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(decode_entries(&trailing).is_err());
        assert!(decode_entries(&encoded[..encoded.len() - 1]).is_err());
        // Swap the two entries: not canonical.
        let swapped = [
            &2u32.to_le_bytes()[..],
            &1u16.to_le_bytes(),
            b"b",
            &1u32.to_le_bytes(),
            b"2",
            &1u16.to_le_bytes(),
            b"a",
            &1u32.to_le_bytes(),
            b"1",
        ]
        .concat();
        assert!(decode_entries(&swapped).is_err());
        for bad in [
            "",
            "has space",
            "tab\t",
            &"x".repeat(MAX_ENTRY_NAME_BYTES + 1),
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
        validate_name("indexed-session/ab:cd").unwrap();
    }

    #[test]
    fn concurrent_writers_are_serialised_and_lose_nothing() {
        let tmp = TempDir::new().unwrap();
        let (vault, _) = test_vault(tmp.path(), PASS);
        vault.put("seed", b"0").unwrap();
        let dir = tmp.path().to_path_buf();
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let (vault, _) = test_vault(&dir, PASS);
                    for j in 0..5 {
                        vault
                            .put(&format!("w{i}/{j}"), &[i as u8, j as u8])
                            .unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let names = vault.entry_names().unwrap();
        assert_eq!(names.len(), 1 + 8 * 5, "{names:?}");
    }

    #[test]
    fn concurrent_first_creation_converges_on_one_vault() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let threads: Vec<_> = (0..4)
            .map(|i| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let (vault, _) = test_vault(&dir, PASS);
                    vault.put(&format!("first/{i}"), b"x").unwrap();
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let (vault, _) = test_vault(tmp.path(), PASS);
        assert_eq!(vault.entry_names().unwrap().len(), 4);
    }

    #[test]
    fn change_passphrase_rekeys_everything() {
        let tmp = TempDir::new().unwrap();
        let (vault, _) = test_vault(tmp.path(), PASS);
        vault.put("k", b"v").unwrap();
        let before = raw(tmp.path());
        vault
            .change_passphrase(&*FixedSource::new("a brand new passphrase"))
            .unwrap();
        let after = raw(tmp.path());
        assert_ne!(before[24..40], after[24..40], "new salt");
        let (old, _) = test_vault(tmp.path(), PASS);
        assert!(matches!(
            old.get("k"),
            Err(VaultError::WrongPassphraseOrTampered)
        ));
        let (new, _) = test_vault(tmp.path(), "a brand new passphrase");
        assert_eq!(&**new.get("k").unwrap().unwrap(), b"v");
        assert!(matches!(
            vault.change_passphrase(&*FixedSource::new("short")),
            Err(VaultError::PassphraseUnavailable(_))
        ));
    }

    #[test]
    fn new_passphrases_must_be_long_enough() {
        let tmp = TempDir::new().unwrap();
        let (vault, _) = test_vault(tmp.path(), "seven77");
        assert!(matches!(
            vault.put("k", b"v"),
            Err(VaultError::PassphraseUnavailable(_))
        ));
        assert!(!vault.exists().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_and_dir_are_private_and_unsafe_files_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("profile");
        let (vault, _) = test_vault(&dir, PASS);
        vault.put("k", b"v").unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join(VAULT_FILE_NAME)), 0o600);
        assert_eq!(mode(&dir), 0o700);

        std::fs::set_permissions(
            dir.join(VAULT_FILE_NAME),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let error = vault.get("k").unwrap_err();
        assert!(matches!(error, VaultError::UnsafeFile(_)), "{error}");
        assert!(error.to_string().contains("chmod 600"));
        std::fs::set_permissions(
            dir.join(VAULT_FILE_NAME),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        // A symlinked vault is refused.
        let elsewhere = TempDir::new().unwrap();
        std::fs::rename(dir.join(VAULT_FILE_NAME), elsewhere.path().join("v")).unwrap();
        std::os::unix::fs::symlink(elsewhere.path().join("v"), dir.join(VAULT_FILE_NAME)).unwrap();
        assert!(matches!(vault.get("k"), Err(VaultError::UnsafeFile(_))));
    }

    #[cfg(unix)]
    #[test]
    fn passphrase_files_must_be_private_regular_files() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("pass");
        std::fs::write(&file, b"a long passphrase\n").unwrap();
        let set_mode =
            |m: u32| std::fs::set_permissions(&file, std::fs::Permissions::from_mode(m)).unwrap();
        for bad in [0o644, 0o640, 0o604, 0o700] {
            set_mode(bad);
            let error = read_passphrase_file(&file, PassphrasePurpose::Unlock, false).unwrap_err();
            assert!(error.to_string().contains("chmod 600"), "{bad:o}: {error}");
        }
        for good in [0o600, 0o400] {
            set_mode(good);
            let value = read_passphrase_file(&file, PassphrasePurpose::Create, false).unwrap();
            assert_eq!(
                &**value, b"a long passphrase",
                "one trailing newline stripped"
            );
        }
        // systemd credential: no group/other bits is enough.
        set_mode(0o440);
        assert!(read_passphrase_file(&file, PassphrasePurpose::Unlock, true).is_err());
        set_mode(0o400);
        read_passphrase_file(&file, PassphrasePurpose::Unlock, true).unwrap();

        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_passphrase_file(&link, PassphrasePurpose::Unlock, false).is_err());

        set_mode(0o600);
        std::fs::write(&file, b"\n").unwrap();
        assert!(read_passphrase_file(&file, PassphrasePurpose::Unlock, false).is_err());
        std::fs::write(&file, b"short\n").unwrap();
        read_passphrase_file(&file, PassphrasePurpose::Unlock, false).unwrap();
        assert!(read_passphrase_file(&file, PassphrasePurpose::Create, false).is_err());
        std::fs::write(&file, vec![b'x'; MAX_PASSPHRASE_BYTES + 10]).unwrap();
        assert!(read_passphrase_file(&file, PassphrasePurpose::Unlock, false).is_err());
        assert!(read_passphrase_file(
            &tmp.path().join("missing"),
            PassphrasePurpose::Unlock,
            false
        )
        .is_err());
    }

    #[test]
    fn passphrase_source_order_never_takes_the_value_from_the_environment() {
        fn env_of(
            pairs: &'static [(&'static str, &'static str)],
        ) -> impl Fn(&str) -> Option<OsString> {
            move |key| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| OsString::from(*v))
            }
        }
        let yes = |_: &Path| true;
        let no = |_: &Path| false;
        assert!(matches!(
            choose_source(
                &env_of(&[
                    (FORBIDDEN_PASSPHRASE_ENV, "hunter2"),
                    (PASSPHRASE_FILE_ENV, "/p")
                ]),
                true,
                &yes
            ),
            SourceChoice::Refused(_)
        ));
        assert_eq!(
            choose_source(
                &env_of(&[(PASSPHRASE_FILE_ENV, "/p"), ("CREDENTIALS_DIRECTORY", "/c")]),
                true,
                &yes
            ),
            SourceChoice::File(PathBuf::from("/p"))
        );
        assert_eq!(
            choose_source(&env_of(&[("CREDENTIALS_DIRECTORY", "/c")]), true, &yes),
            SourceChoice::Credential(Path::new("/c").join(SYSTEMD_CREDENTIAL_NAME))
        );
        assert_eq!(
            choose_source(&env_of(&[("CREDENTIALS_DIRECTORY", "/c")]), true, &no),
            SourceChoice::Terminal
        );
        assert_eq!(
            choose_source(&env_of(&[]), false, &no),
            SourceChoice::Unavailable
        );
        let message = no_source_message(Path::new("/d/keystore.vault"));
        assert!(message.contains(PASSPHRASE_FILE_ENV) && message.contains("LoadCredential"));
    }
}
