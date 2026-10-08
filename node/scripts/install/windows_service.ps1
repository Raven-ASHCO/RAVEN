# Install always-on raven-node for the current Windows user (no MSI / no system ash overwrite).
# -SkipScheduledTask: build + copy binaries only (CI / no persistent logon task). See WINDOWS_SERVICE.md.
# -LanListen: LAN exposure is opt-in and identical on every OS installer
#   (default 127.0.0.1:7420; pass e.g. -LanListen 192.168.1.20:7420 to accept LAN peers).
# -InternetListen: Internet direct exposure is opt-in too (default: no listener; pass e.g.
#   -InternetListen 0.0.0.0:7422, a bare IP gets port 7422). Without it,
#   `raven node internet on --listen 0.0.0.0:7422` turns it on later (applied at the next
#   task start). The installer never changes the firewall: it prints the rule to run elevated.
# -TaskName / -NoStart: CI hooks (register a uniquely named task without launching the daemon).
# Re-running is the upgrade path: the running daemon is stopped before its binaries are
# replaced and the task is re-registered with the current settings.
# Keep this file ASCII-only: Windows PowerShell 5.1 reads a BOM-less file as ANSI, where the
# UTF-8 bytes of an em dash contain a smart double quote and break the string literal.
param(
    # Default = the profile raven.exe / ash.exe use without --data-dir (raven-core
    # resolve_raven_data_dir): RAVEN_DATA_DIR, ASH_DATA_DIR, a legacy ~\.raven-ash while
    # ~\.raven does not exist, else ~\.raven. The IPC pipe is per user, not per profile, so
    # a daemon serving any other directory would answer the CLI's pings for a profile it
    # does not serve.
    [string]$DataDir = $(& {
        if ($env:RAVEN_DATA_DIR) { return $env:RAVEN_DATA_DIR }
        if ($env:ASH_DATA_DIR) { return $env:ASH_DATA_DIR }
        $homeDir = $env:HOME
        if (-not $homeDir) { $homeDir = $env:USERPROFILE }
        if (-not $homeDir) { $homeDir = "$($env:HOMEDRIVE)$($env:HOMEPATH)" }
        $current = Join-Path $homeDir ".raven"
        $legacy = Join-Path $homeDir ".raven-ash"
        if ((Test-Path -LiteralPath $legacy -PathType Container) -and -not (Test-Path -LiteralPath $current)) { return $legacy }
        return $current
    }),
    [string]$BinDir = $(Join-Path $env:LOCALAPPDATA "RavenNode"),
    [string]$LanListen = "127.0.0.1:7420",
    [string]$InternetListen = "",
    [string]$TaskName = "RavenNodeBridge",
    [switch]$SkipScheduledTask,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"
# IP[:port] / [IPv6][:port] characters only (it lands on the task's command line);
# raven-node validates the rest.
if ($InternetListen -and ($InternetListen -notmatch '^[\[\]0-9A-Za-z.:]+$')) {
    throw "-InternetListen must look like 0.0.0.0:7422 or [::]:7422"
}
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
# Task Scheduler runs with another working directory: register absolute paths only.
$DataDir = (Resolve-Path -LiteralPath $DataDir).Path
$BinDir = (Resolve-Path -LiteralPath $BinDir).Path

Push-Location $Root
# --locked: build exactly the audited Cargo.lock.
cargo build --locked -p raven-node -p ash --release
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "cargo build failed" }
Pop-Location

$exe = Join-Path $BinDir "raven-node.exe"

# Windows cannot overwrite a running image. Stop the daemon only now (after the build
# succeeded, so a failed build leaves the old daemon up): the task's own instance, then any
# hand-started copy of THIS exe (path-filtered so other installs/users are left alone).
try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch { }
$running = @(Get-Process -Name "raven-node" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe })
foreach ($proc in $running) {
    Write-Host "stopping running raven-node (pid $($proc.Id)) so its binary can be replaced"
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Wait-Process -Id $proc.Id -Timeout 15 -ErrorAction SilentlyContinue
}

function Install-Binary([string]$Src, [string]$Dst) {
    try {
        Copy-Item -LiteralPath $Src -Destination $Dst -Force
    } catch {
        # ash.exe / raven.exe can be held open by a running CLI session: Windows refuses to
        # overwrite a running image but allows renaming it. Move the old copy aside and retry.
        if (-not (Test-Path -LiteralPath $Dst)) { throw }
        $old = "$Dst.old"
        Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $Dst -Destination $old -Force
        Copy-Item -LiteralPath $Src -Destination $Dst -Force
    }
}

Install-Binary "$Root\target\release\raven-node.exe" $exe
Install-Binary "$Root\target\release\ash.exe" (Join-Path $BinDir "raven.exe")
# Optional product alias - never touches system ash
Install-Binary "$Root\target\release\ash.exe" (Join-Path $BinDir "ash.exe")

# Do not use $args - automatic/read-only in pwsh 7.
$serviceArgs = "service --data-dir `"$DataDir`" --lan-listen $LanListen --ble-listen 127.0.0.1:7421 --timeout-secs 0"
if ($InternetListen) {
    $serviceArgs = "$serviceArgs --internet-listen $InternetListen"
}

if ($SkipScheduledTask) {
    Write-Host "SkipScheduledTask: binaries copied; logon task not registered"
    if ($running.Count -gt 0) {
        Write-Host "NOTE: the raven-node that was running was stopped and NOT restarted (-SkipScheduledTask)."
    }
} else {
    # Register a per-user logon task (survives reboot; no admin service required for V1 software path).
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute $exe -Argument $serviceArgs
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    # ExecutionTimeLimit 0 (PT0S) = no limit: the default is 72h, after which Task Scheduler
    # force-stops the always-on daemon and nothing relaunches it until the next logon.
    # Restart-on-failure covers crashes; IgnoreNew keeps a single daemon per task.
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -StartWhenAvailable -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "RAVEN raven-node bridge (serverless)" | Out-Null
    if ($NoStart) {
        Write-Host "NoStart: task registered, not started"
    } else {
        Start-ScheduledTask -TaskName $TaskName
    }
    Write-Host "installed task $TaskName"
}

Write-Host "data-dir=$DataDir"
Write-Host "CLI: raven.exe / ash.exe find this profile by default (RAVEN_DATA_DIR, else ~\.raven); for any other -DataDir pass --data-dir `"$DataDir`" to every command"
Write-Host "lan-listen=$LanListen"
if ($LanListen -like "127.*" -or $LanListen -like "localhost:*") {
    Write-Host "LAN peers cannot reach this node (loopback only). Re-run with -LanListen <LAN-IP>:7420 and allow TCP 7420 in Windows Firewall to accept LAN peers."
}
if ($InternetListen) {
    $inetPort = "7422"
    # "[v6]:port" or "v4:port"; a bare IP (IPv6 included) means the default port.
    if (($InternetListen -match '^\[[^\]]*\]:(\d+)$') -or ($InternetListen -match '^[^:\[\]]+:(\d+)$')) {
        $inetPort = $Matches[1]
    }
    Write-Host "internet-listen=$InternetListen (only your contacts get an answer; anyone can see that the port is open)"
    Write-Host "To let contacts reach it, run in an ELEVATED PowerShell yourself (Private profile only, never Public):"
    Write-Host "  New-NetFirewallRule -DisplayName `"Raven node`" -Direction Inbound -Program `"$exe`" -Protocol TCP -LocalPort $inetPort -Profile Private"
    Write-Host "and forward TCP $inetPort on your router if this PC is behind NAT. Outbound needs no rule."
    Write-Host "A build with Internet direct off (INTERNET_DIRECT_PRODUCTION_ENABLED=false) keeps the port closed and logs INTERNET_DIRECT_HOLD; check: raven.exe status (internet row)."
} else {
    Write-Host "internet-listen=off (opt-in: re-run with -InternetListen 0.0.0.0:7422, or run 'raven node internet on' and restart the task)"
}
Write-Host "bin-dir=$BinDir (raven.exe / ash.exe)"
$userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Write-Host "Named-pipe IPC: \\.\pipe\raven-node-$userSid (per-user pipe, current-user DACL; ash refuses a pipe served by another user) - see WINDOWS_SERVICE.md"
