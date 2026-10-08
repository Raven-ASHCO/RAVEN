# Linux keystore: Secret Service, else a passphrase vault (R1)

| | |
|---|---|
| **Status** | Owner decision 2026-10-08; R1 authorized. Implemented on `fix/code-review-2026-09-29` (uncommitted at time of writing). |
| **Scope** | GNU/Linux and other non-macOS Unix release builds: identity seed, indexed-session secrets, prekey lifecycle state, chat-history key. macOS (Keychain) and Windows (DPAPI) are unchanged. |
| **Code** | `node/crates/raven-core/src/keystore_vault.rs` (vault, platform-neutral), `keystore_select.rs` (backend choice), call sites in `identity_store.rs`, `indexed_session_store.rs`, `prekey_lifecycle.rs`, `chat_history.rs`. |

## 1. Threat model

Protects key material **at rest** against: a copied or backed-up data dir (`~/.raven`), a stolen
disk image, another *local user* (0700 dir / 0600 files / owner checks), and accidental
world-readable permissions (refused, not repaired silently).

**Not protected** (same as every software keystore):
- malware running as the same user: it can read the passphrase file, ptrace the daemon, read the
  unlocked key from memory, or talk to an unlocked Secret Service;
- `root` / the kernel;
- offline guessing of a copied vault protected by a **weak passphrase** (Argon2id only slows it);
- a passphrase *file* stored next to the data dir in the same backup: that backup is unprotected;
- rollback: restoring an older `keystore.vault` restores older session state (the vault lives in the
  data dir, like Windows' DPAPI files; the macOS Keychain head does not have this exposure).

## 2. Backend selection (per profile, recorded, never silently changed)

The debug-only `locked-file` lab backend is checked first and is unchanged (refused in Release).
Otherwise, for a profile (`--data-dir`):

1. **Recorded choice wins.** `<data-dir>/keystore.backend` (`secret-service\n` or
   `passphrase-vault\n`, canonical, 0600). Legacy: `identity.backend = linux-secret-service` counts
   as `secret-service`; an existing `keystore.vault` counts as `passphrase-vault`.
   - recorded `secret-service` but the service is not reachable/unlocked: **fail closed** with
     instructions (log in / unlock the keyring). No fallback to the vault.
   - recorded `passphrase-vault`: always the vault, even when a keyring is reachable.
   - `RAVEN_KEYSTORE_BACKEND` set and different from the recorded choice: fail closed.
2. **Explicit override** for a new profile: `RAVEN_KEYSTORE_BACKEND=vault` (or `secret-service`).
3. **Probe:** a session bus exists (`DBUS_SESSION_BUS_ADDRESS` or `$XDG_RUNTIME_DIR/bus`) and the
   Secret Service default collection answers *unlocked* within **3 s** (probe runs on a helper
   thread; a hung D-Bus call is abandoned) → `secret-service`; otherwise → `passphrase-vault`.
4. The choice is written to `keystore.backend` before the first secret is stored. The marker is
   inert for first-install detection; the vault file is not.

musl and other non-glibc Unix builds have no Secret Service client: the vault only.

## 3. Secret Service path

All Secret Service code links the frozen Raven fork `third_party/secret-service-2.0.2-raven-noprompt`
(API superset of crates.io 2.0.2; upstream client removed from the graph). Identity creation uses
`Collection::create_item_no_prompt` (DH session required, add-only: D-Bus `replace=false`
hard-wired, a provider prompt is refused as `PromptRequired`, a locked collection is `Locked`) after
a search proved absence under the identity-store lock, then strict readback (exactly one item,
label, attributes, 32 bytes). Raven never calls `Unlock`. Content type: created as
`application/octet-stream`; on read `text/plain` (GNOME Keyring normalisation observed in R0) or
`application/octet-stream` is accepted. Session/prekey/chat-history keep their existing calls.
`node/scripts/linux_secret_service_r0_hard_stop.sh` now enforces: fork in the default Linux graph,
crates.io client absent, no-prompt APIs only in `identity_store.rs`, no `.unlock(` anywhere.

## 4. Vault format (`<data-dir>/keystore.vault`, one file per profile)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `RVNVLT01` |
| 8 | 1 | version `1` |
| 9 | 1 | KDF id `1` = Argon2id v0x13 |
| 10 | 1 | AEAD id `1` = XChaCha20-Poly1305 |
| 11 | 1 | reserved `0` |
| 12 | 12 | Argon2id `m` (KiB), `t`, `p` — u32 little-endian each |
| 24 | 16 | salt (random per vault / per passphrase change) |
| 40 | 24 | nonce (fresh random on **every** write) |
| 64 | n+16 | ciphertext + tag; **AAD = bytes 0..64** |

Key = Argon2id(passphrase, salt, m, t, p) → 32 bytes. Plaintext = `u32 count` then sorted, unique
entries `u16 name_len | name (printable ASCII ≤ 160) | u32 len | value`; ≤ 32 MiB; trailing bytes
are corruption. Entries: `identity-seed`, `indexed-session/<account>`, `prekey-lifecycle/<account>`,
`chat-history-key`.

**One vault per profile, not one file per kind:** one passphrase and one Argon2 run per process
(64 MiB is expensive), one atomic unit (identity and the session state it signs for cannot drift to
different passphrases or generations), one lock, one file to back up. Cost: every write re-encrypts
the whole vault (KBs to a few hundred KB in practice; bounded by the 32 MiB cap).

**Parameters:** created with m = 64 MiB, t = 3, p = 1. On read, anything outside m ∈ [19 MiB, 1 GiB],
t ∈ [1, 16], p ∈ [1, 8] is refused before running the KDF (no memory/CPU bomb from a planted file).
Header tampering also fails authentication (AAD), and the key depends on the parameters.

**Writes:** under `<data-dir>/.keystore_vault.lock.sqlite` (the existing `DataDirLock`): re-read,
decrypt, modify, encrypt with a new nonce, `atomic_write_private` (0600 temp, fsync, rename,
directory fsync). The passphrase/KDF runs *before* the lock is taken; if the file changed meanwhile
the key is re-derived from the passphrase still held in memory. Reads need no lock (rename is atomic).

**Files:** data dir 0700 (`ensure_private_dir`), vault 0600. Opening refuses a symlink, a file not
owned by the current user, or any group/other bit (`chmod 600 …` in the message).

**Zeroization:** passphrase, derived key, plaintext and per-entry values are `Zeroizing`; argon2's
`zeroize` feature wipes its working memory. The derived key is cached in process memory (keyed by
vault path, salt and parameters) so a process asks once. Best effort: copies may linger in freed
pages, swap or core dumps.

**Wrong passphrase:** AEAD failure is reported as "the keystore passphrase is wrong, or the vault
file was changed or damaged (it could not be decrypted)" — the two are indistinguishable by design.
Interactive prompts allow 3 attempts.

## 5. Passphrase sources (first match wins)

1. `RAVEN_KEYSTORE_PASSPHRASE_FILE=<path>`: regular file (not a symlink), owned by the current user,
   mode exactly 0400 or 0600, ≤ 1024 bytes; one trailing newline is stripped.
2. systemd credential: `$CREDENTIALS_DIRECTORY/raven-keystore-passphrase` (`LoadCredential=`), owned
   by the user or root, no group/other mode bits.
3. Interactive terminal, only in `ash`/`raven` and only when stdin is a TTY: no echo, no line
   discipline and no signal keys while typing (`stty -echo -icanon -isig` on `/dev/tty`; the saved
   `stty -g` settings are restored on drop, on every return path). Ctrl-C / Ctrl-\ therefore cancel
   the prompt with an error instead of killing the process with echo off; backspace and Ctrl-U edit
   the line. On creation a plain-words explanation, then the passphrase twice (≥ 8 characters, must
   match). An external `kill` during the prompt can still leave echo off (`stty sane` restores it).
4. Otherwise fail with instructions. `raven-node` never prompts.

The passphrase itself is never accepted from argv or an environment variable: a set
`RAVEN_KEYSTORE_PASSPHRASE` is refused (create and unlock, `raven` and `raven-node`, whatever else is
set) with a message saying it "is refused". New passphrases (any source) must be ≥ 8 characters.

**Locks while a person types (2026-10-08).** Loading the identity unlocks an existing vault
(`Vault::preload_key`) *before* the identity-store lock is taken; the derived key stays in the
process cache, so the vault reads under that lock and in later session-store transactions never
prompt. Remaining limit: the very first `init` of a vault profile asks for the *new* passphrase while
it holds the identity-store lock (the vault does not exist before that write); a daemon started at
that moment waits on the lock with its "waiting" notice.

## 6. Verification

Unit tests (platform-neutral, run on macOS too): create/open/read/write/rotate, add-only insert,
passphrase change, wrong passphrase, tampered header/ciphertext/params, truncation, parameter bounds,
concurrent writers, permissions, passphrase-file checks, backend selection and conflicts, vault-backed
identity create/load/continuity. Linux glue (Secret Service probe, fork calls, cfg wiring) is first
compiled and run by CI `rust-linux` and the release-build smoke job (`linux-release-keystore`).
