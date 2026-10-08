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

**Internet direct is opt-in too (off by default).** It lets contacts who have
your Internet address (`raven whoami --card --inet <public-ip-or-name>:7422`)
reach this computer over TCP port **7422** (7421 is mock BLE's, 7423 is
reserved for libp2p). Only your contacts get an answer: anyone else completes
the Noise handshake and is disconnected before this node names itself, but a
scanner still learns that something listens on that port. A build with
Internet direct off (`INTERNET_DIRECT_PRODUCTION_ENABLED = false`, the state
until its waiver is signed) keeps the port closed and logs `internet_direct
failed: INTERNET_DIRECT_HOLD ...`; the debug lab unlock is `RAVEN_LAB_TEST_A=1`.
`raven status` shows an `internet` row: `YES` only while the running service
really has the listener up.

```powershell
# at install time
.\node\scripts\install\windows_service.ps1 -InternetListen 0.0.0.0:7422
# or later (saved in node_policy.json, applied when the task restarts)
raven.exe node internet on --listen 0.0.0.0:7422
Stop-ScheduledTask -TaskName RavenNodeBridge; Start-ScheduledTask -TaskName RavenNodeBridge
raven.exe node internet off      # closes it again at the next restart
```

Firewall: on the first non-loopback listen Defender Firewall may show "Windows
Security Alert"; allowing needs an administrator and dismissing it creates a
block rule. The installer prints, and never runs, the rule to add in an
elevated PowerShell (Private profile only, never Public; outbound needs no rule):

```powershell
New-NetFirewallRule -DisplayName "Raven node" -Direction Inbound `
  -Program "$env:LOCALAPPDATA\RavenNode\raven-node.exe" -Protocol TCP -LocalPort 7422 -Profile Private
```

Forward TCP 7422 on your router if the PC is behind NAT. The logon task runs only
while you are signed in, so a Windows PC is reachable only then. Contacts:
`raven contact add --card "<their card line>"`, `raven contact set-addr <name>
--internet HOST:PORT`, then `raven send --contact <name>` (LAN address first,
then Internet; `--carrier lan|internet` forces one). Internet delivery is for
verified contacts only. A contact whose fingerprint you have not confirmed
(`--verify-fp` when adding) is reached over the LAN carrier only, and only when
every address its LAN route resolves to is on your local network: loopback,
private (10/8, 172.16/12, 192.168/16), link-local (169.254/16, fe80::/10) or
unique-local IPv6 (fc00::/7); a public or CGNAT (100.64/10) address is refused
and nothing is dialled. Your Internet listener treats an unverified contact like
a stranger, and so does your LAN listener when it connects from outside those
ranges.

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
