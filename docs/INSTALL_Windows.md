# Install Raven Serverless (Windows)

Also see [`node/WINDOWS.md`](../node/WINDOWS.md) and [`node/scripts/install/WINDOWS_SERVICE.md`](../node/scripts/install/WINDOWS_SERVICE.md).

Unix `node/scripts/install.sh` is **not** an installer (fail-closed). It never
was a Windows path. Use the release-build steps below.

## Native build

```powershell
cd node
cargo build -p raven-core -p raven-node -p ash --release
.\target\release\ash.exe --data-dir $env:TEMP\raven-data init
.\target\release\ash.exe --data-dir $env:TEMP\raven-data doctor
```

Task Scheduler / service helper: `scripts/install/windows_service.ps1`
(builds with `--locked`). Its default `-DataDir` is the profile `raven.exe` /
`ash.exe` use without `--data-dir` (`RAVEN_DATA_DIR`, then `ASH_DATA_DIR`, then
`%USERPROFILE%\.raven`); binaries go to `%LOCALAPPDATA%\RavenNode` (`-BinDir`).
The named pipe is per user, not per profile, so a daemon installed with any other
`-DataDir` must be addressed with `--data-dir <that dir>` on every CLI command, or
the CLI would ping a daemon that serves a different profile. **LAN exposure is
opt-in with this helper (same default on every OS):** the task listens on `127.0.0.1:7420`; pass `-LanListen <LAN-IP>:7420`
and allow TCP 7420 for the local subnet in Windows Firewall to accept LAN peers.
A bare `raven-node.exe service` without `--lan-listen` binds `0.0.0.0:7420`, so
always pass an explicit address when you start it by hand.

**Toolchain:** install Rust with [rustup](https://rustup.rs) (current stable);
older compilers fail at dependency resolution (rustc 1.83.0: the locked graph
needs edition 2024; its highest declared `rust-version` is 1.88). CI is validated
on rustc 1.98.0 only; the exact minimum is not yet verified.

## Unsigned layout from macOS/Linux host

Cross-compile notes in `node/WINDOWS.md`. Prefer native Windows CI for release binaries you will Authenticode-sign.

## Signing

MSI / Authenticode steps: [`SIGNING_NOTARIZATION_CHECKLIST.md`](SIGNING_NOTARIZATION_CHECKLIST.md). This repo ships **unsigned** artifacts only.

## Identity seed

Windows stores the node seed as a **DPAPI**-protected `identity.seed` blob (user-bound). Legacy plaintext 32-byte files are migrated automatically. See [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md).
