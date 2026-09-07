# Windows — always-on raven-node + named-pipe IPC notes

**Do not** replace system shells. Prefer `raven.exe` as the unambiguous CLI; `ash.exe` is an alternate name for the same binary.

## Install script

```powershell
# From repo:
#   powershell -ExecutionPolicy Bypass -File node/scripts/install/windows_service.ps1
# CI / layout-only (no RavenNodeBridge logon task):
#   powershell -ExecutionPolicy Bypass -File node/scripts/install/windows_service.ps1 -SkipScheduledTask
```

See `windows_service.ps1` for build + Task Scheduler registration. This is a **per-user Task Scheduler** task (not an SCM service flip).

CI (`rust-windows` in `raven-serverless.yml`) exercises this helper beyond parse-only: it runs the script with `-DataDir` / `-BinDir` under `$env:RUNNER_TEMP` and `-SkipScheduledTask` so release binaries are built and copied (`raven-node.exe`, `raven.exe`, `ash.exe`) without registering a persistent per-user logon task on the runner. Leave `-SkipScheduledTask` off for a real local install. LAN bind stays `127.0.0.1:7420` (B12 hold).

## Per-user background process (V1)

`raven-node service` is the always-on command: named-pipe IPC + LAN + bridge (parity with Unix `service`).

```powershell
$Data = Join-Path $env:LOCALAPPDATA "RavenNode"
Start-Process -FilePath "$env:LOCALAPPDATA\RavenNode\raven-node.exe" `
  -ArgumentList @("service","--data-dir",$Data,"--lan-listen","127.0.0.1:7420","--ble-listen","127.0.0.1:7421","--timeout-secs","0") `
  -WindowStyle Hidden
```

Dedicated IPC only: `raven-node ipc --data-dir $Data`.

## Named pipe IPC

- Server binds `WINDOWS_NAMED_PIPE` (`\\.\pipe\raven-node`) with a **current-user DACL** (no World/Everyone ACE). DACL setup is **fail-closed**: if the descriptor cannot be built, the process does not bind.
- Framing is the same length-prefixed JSON as Unix UDS (`raven-core::ipc`, IPC_VERSION=1): Ping, Status, SetPolicy, EnqueueSealed, LanDial. Secrets (`seed` / `private_key` / `plaintext` / `recovery`) are refused; EnqueueSealed is already-sealed only.
- `ipc_endpoint(data_dir)` selects the Unix socket vs this pipe so callers cannot UDS-only on Windows. ash, `ash ipc-ping`, and `ash doctor` use `ipc_client::ipc_ping` / `ipc_endpoint` (never a UDS-only probe). Successful Ping prints `daemon_presence: present` (not `up`). Connect fail is `down`. `IpcEndpoint::Unsupported` is `blocked (reason=ipc_transport_missing)` — never a soft pass / ✓. Ping ≠ ready ≠ send_path.
- Software path: framing + refuse-secret-fields are shared; OS bind is platform-specific.

## Try / Proven

`rust-windows` (MSVC) must compile `raven-node` including this server. Unit tests cover the exact pipe name and current-user DACL construction.

**Proven** for named-pipe bind/DACL requires a Windows CI cite after merge (`rust-windows` job: `cargo test -p raven-node` / `cargo build -p raven-node`). Do not claim Proven from Linux/macOS CI alone.

## Uninstall

Stop the scheduled task / process; delete `$env:LOCALAPPDATA\RavenNode`. Never delete unrelated `ash.exe` on PATH that is not Raven's.
