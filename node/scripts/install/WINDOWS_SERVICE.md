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

**Profile.** `-DataDir` defaults to the profile `raven.exe` / `ash.exe` use without `--data-dir` (`RAVEN_DATA_DIR`, then `ASH_DATA_DIR`, then `%USERPROFILE%\.raven`), so a plain `raven.exe doctor` talks to the daemon that serves your profile. Binaries go to `-BinDir` (default `%LOCALAPPDATA%\RavenNode`). The named pipe is **per user, not per profile** (`ipc_endpoint` ignores the data dir on Windows): with any other `-DataDir`, pass `--data-dir <that dir>` to every `raven.exe` / `ash.exe` command, otherwise the CLI pings (and dials through) a daemon that serves a different profile; do not run two profiles' daemons as the same user.

**Upgrade = re-run the installer.** After the release build succeeds it stops the running daemon (the task's instance, plus any hand-started `raven-node.exe` from the same `-BinDir`), replaces the binaries (a locked `raven.exe`/`ash.exe` is renamed to `*.old` first), re-registers the task and starts it. The task has no execution time limit (`PT0S`; the Task Scheduler default of 72h would otherwise stop the always-on daemon after three days), restarts on failure, and ignores a second start while one instance runs. A task registered by an older copy of the script keeps the 72h limit until the installer is re-run. `-TaskName <name> -NoStart` registers a differently named task without launching it (used by CI to assert the settings). Keep `windows_service.ps1` ASCII-only: `powershell.exe` 5.1 reads a BOM-less file as ANSI and an em dash then breaks a string literal.

CI (`rust-windows` in `raven-serverless.yml`) exercises this helper beyond parse-only: it runs the script with `-DataDir` / `-BinDir` under `$env:RUNNER_TEMP` and `-SkipScheduledTask` so release binaries are built and copied (`raven-node.exe`, `raven.exe`, `ash.exe`) without registering a persistent per-user logon task on the runner. Leave `-SkipScheduledTask` off for a real local install. LAN bind defaults to `127.0.0.1:7420` (B12 hold) — the same opt-in default as the Linux/macOS installers; `-LanListen <addr>:7420` is the explicit opt-in.

## Per-user background process (V1)

`raven-node service` is the always-on command: named-pipe IPC + LAN + bridge (parity with Unix `service`).

```powershell
$Data = Join-Path $env:USERPROFILE ".raven"   # the CLI default profile
Start-Process -FilePath "$env:LOCALAPPDATA\RavenNode\raven-node.exe" `
  -ArgumentList @("service","--data-dir",$Data,"--lan-listen","127.0.0.1:7420","--ble-listen","127.0.0.1:7421","--timeout-secs","0") `
  -WindowStyle Hidden
```

Dedicated IPC only: `raven-node ipc --data-dir $Data`.

## Named pipe IPC

- Server binds the per-user pipe `\\.\pipe\raven-node-<user SID>` (`WINDOWS_NAMED_PIPE` prefix) with a **current-user DACL** (no World/Everyone ACE) and `FILE_FLAG_FIRST_PIPE_INSTANCE`. DACL setup is **fail-closed**: if the descriptor cannot be built, the process does not bind. Clients open the pipe with `SECURITY_IDENTIFICATION` and refuse a server process owned by another user (squatted pipe). The owner check reads the server process token, so run `raven-node` and `ash` at the same elevation: a non-elevated `ash` cannot read an elevated daemon's token and refuses to talk to it (fail closed). The logon task above runs non-elevated.
- Framing is the same length-prefixed JSON as Unix UDS (`raven-core::ipc`, IPC_VERSION=1): Ping, Status, SetPolicy, EnqueueSealed, LanDial. JSON keys naming secrets (`seed` / `private_key` / `plaintext` / `recovery`) are refused; EnqueueSealed is already-sealed only.
- `ipc_endpoint(data_dir)` selects the Unix socket vs this pipe so callers cannot UDS-only on Windows. ash, `ash ipc-ping`, and `ash doctor` use `ipc_client::ipc_ping` / `ipc_endpoint` (never a UDS-only probe). Successful Ping prints `daemon_presence: present` (not `up`). Connect fail is `down`. `IpcEndpoint::Unsupported` is `blocked (reason=ipc_transport_missing)` — never a soft pass / ✓. Ping ≠ ready ≠ send_path.
- Software path: framing + refuse-secret-fields are shared; OS bind is platform-specific.

## Try / Proven

`rust-windows` (MSVC) must compile `raven-node` including this server. Unit tests cover the exact pipe name and current-user DACL construction.

**Proven** for named-pipe bind/DACL requires a Windows CI cite after merge (`rust-windows` job: `cargo test -p raven-node` / `cargo build -p raven-node`). Do not claim Proven from Linux/macOS CI alone.

## Uninstall

Stop the scheduled task / process; delete the binaries in `-BinDir` (`$env:LOCALAPPDATA\RavenNode` by default). The profile (`$env:USERPROFILE\.raven` by default) holds your identity, contacts and history: keep or back it up unless you really want to discard them. Never delete unrelated `ash.exe` on PATH that is not Raven's.
