# Identity seed storage (raven-node / ash)

The Ed25519 **identity seed** for desktop `raven-node`, `ash`, and `raven-swarm` is persisted through `raven_core::identity_store`. Callers must never log, print, or put the seed in argv/env.

## Backends

| Platform | Backend | Notes |
|----------|---------|--------|
| macOS | **Keychain** (generic password, service `app.raven.node.identity`) | Account = SHA-256 of canonical `data_dir`. Marker file `identity.backend` = `macos-keychain`. |
| Windows | **DPAPI** file (`CryptProtectData`, `CRYPTPROTECT_UI_FORBIDDEN`) | Blob in `identity.seed` with magic `RVNDPAPI` + version. Bound to the Windows user. |
| Linux (glibc desktop) | **Secret Service** — *loading existing identities only* | Same service/account attributes as Keychain. **Creating a new identity is disabled in Release builds until R1** (`GNU/Linux Secret Service identity creation is disabled before R1`); an existing Secret Service identity still loads, verifies and deletes. Without a session bus the error is a `secret-service connect:` failure instead. |
| Linux (musl and other Unix targets) | **None** | No protected identity backend: creation fails closed (`no protected identity backend on this Unix target`). |
| Any OS, **debug / lab / CI only** | **Locked file** mode `0600` (`RAVEN_IDENTITY_BACKEND=locked-file`) | Explicit override honoured only in debug builds; **refused in Release builds** (`locked-file identity backend is forbidden in Release builds`). **Not** an approved production fallback — see below. |

`ash doctor` reports `secure_keystore: backend=…` only (no seed bytes).

## Legacy migration

If a legacy **plaintext** `identity.seed` (exactly 32 raw bytes, no DPAPI magic) is present:

1. Load the seed
2. Re-store via the platform backend above
3. Wipe/remove the plaintext file (macOS / Secret Service) or rewrite as DPAPI (Windows)

Migration runs automatically on first `load_identity` / `load_or_create_identity`.

## Linux: identity creation is disabled in Release builds (R1 pending)

Source of truth is `raven_core::identity_store` (`secret_service_set` and the
locked-file gate), not older prose in this document.

- **Release builds:** a new identity cannot be created on Linux. On glibc,
  Secret Service *creation* is hard-disabled until R1 authorizes an add-only,
  prompt-free backend; existing Secret Service identities still load. On musl and
  other Unix targets there is no protected backend at all. `ash init`, `raven
  init` and `raven-node service` therefore fail closed on a fresh Linux Release
  install — see the limitation note in [`INSTALL_Linux.md`](INSTALL_Linux.md).
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
