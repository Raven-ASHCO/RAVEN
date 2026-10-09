# Identity seed storage (raven-node / ash)

The Ed25519 **identity seed** for desktop `raven-node`, `ash`, and `raven-swarm` is persisted through `raven_core::identity_store`. Callers must never log, print, or put the seed in argv/env.

## Backends

| Platform | Backend | Notes |
|----------|---------|--------|
| macOS | **Keychain** (generic password, service `app.raven.node.identity`) | Account = SHA-256 of canonical `data_dir`. Marker file `identity.backend` = `macos-keychain`. |
| Windows | **DPAPI** file (`CryptProtectData`, `CRYPTPROTECT_UI_FORBIDDEN`) | Blob in `identity.seed` with magic `RVNDPAPI` + version. Bound to the Windows user. |
| Linux (glibc), unlocked desktop keyring | **Secret Service** (GNOME Keyring / KWallet) | Same service/account attributes as Keychain. Created add-only and prompt-free through the Raven fork (`create_item_no_prompt`, R1 2026-10-08); Raven never unlocks a keyring. Marker `identity.backend` = `linux-secret-service`, profile keystore `keystore.backend` = `secret-service`. |
| Linux (glibc) without a reachable keyring, musl and other Unix | **Passphrase vault** `keystore.vault` (Argon2id + XChaCha20-Poly1305) | Entry `identity-seed`; marker `identity.backend` = `passphrase-vault`, `keystore.backend` = `passphrase-vault`. Passphrase from `RAVEN_KEYSTORE_PASSPHRASE_FILE`, systemd `LoadCredential=raven-keystore-passphrase:…`, or (ash/raven on a terminal) a no-echo prompt. Format: [`design/2026-10-linux-keystore.md`](design/2026-10-linux-keystore.md). |
| Any OS, **debug / lab / CI only** | **Locked file** mode `0600` (`RAVEN_IDENTITY_BACKEND=locked-file`) | Explicit override honoured only in debug builds; **refused in Release builds** (`locked-file identity backend is forbidden in Release builds`). **Not** an approved production fallback — see below. |

`ash doctor` reports `secure_keystore: backend=…` only (no seed bytes).

## Legacy migration

If a legacy **plaintext** `identity.seed` (exactly 32 raw bytes, no DPAPI magic) is present:

1. Load the seed
2. Re-store via the platform backend above
3. Wipe/remove the plaintext file (macOS / Secret Service) or rewrite as DPAPI (Windows)

Migration runs automatically on first `load_identity` / `load_or_create_identity`.

## Linux: Secret Service, else the passphrase vault (R1, 2026-10-08)

Source of truth is `raven_core::keystore_select`, `raven_core::keystore_vault`
and `raven_core::identity_store`; the design is
[`design/2026-10-linux-keystore.md`](design/2026-10-linux-keystore.md).

- **One keystore per profile, recorded.** On the first secret write RAVEN picks
  Secret Service when an *unlocked* default collection answers on the session
  bus within 3 s, else the passphrase vault, and records the choice in
  `keystore.backend`. `RAVEN_KEYSTORE_BACKEND=vault` forces the vault for a new
  profile. A recorded choice never changes silently: a keyring profile whose
  keyring is unreachable fails closed (no fallback to a file), a vault profile
  stays on the vault, and a conflicting `RAVEN_KEYSTORE_BACKEND` is an error.
- **All four secret kinds follow the choice:** identity seed, indexed-session
  secrets, prekey lifecycle state and the chat-history key.
- **Passphrase:** never argv or an environment *value* (`RAVEN_KEYSTORE_PASSPHRASE`
  is refused). `RAVEN_KEYSTORE_PASSPHRASE_FILE` must name a regular file owned by
  you, mode `0600`/`0400`. `ash`/`raven` on a terminal explain and ask (twice on
  creation, at least 8 characters, no echo); on a non-TTY they refuse unless the
  file is set. `raven-node` never prompts. A wrong passphrase reads: *the keystore
  passphrase is wrong, or the vault file was changed or damaged*.
- **Not protected:** same-user malware (it can read the passphrase file or the
  daemon's memory), root, a copied vault with a weak passphrase, and rollback to
  an older copy of `keystore.vault`.
- **Debug / lab / CI builds:** `RAVEN_IDENTITY_BACKEND=locked-file` stores the
  seed in a mode `0600` file under `--data-dir`. This exists so CI and lab
  scripts can run headless; it is refused in Release builds and must **not** be
  presented or used as a production keystore. Do not build a debug/lab binary
  just to get around the Release limitation for real conversations: the file is
  only as safe as the host account and disk encryption.

Treat a locked-file seed like any plaintext-at-rest secret: file owner
read/write only, not world-readable, never copy `data_dir` to untrusted
machines.

## Operator reminders

- Use ephemeral `--data-dir` for demos; never commit `identity.seed` or `identity.backend`
- `ash` still never prints private keys (public address / fingerprint / pub hex only)
- Locked / missing Keychain or Secret Service: operations that need the identity fail closed with a redacted error (no seed in the message)
