# Install always-on raven-node for the current Windows user (no MSI / no system ash overwrite).
# -SkipScheduledTask: build + copy binaries only (CI / no persistent logon task). See WINDOWS_SERVICE.md.
# -LanListen: LAN exposure is opt-in and identical on every OS installer
#   (default 127.0.0.1:7420; pass e.g. -LanListen 192.168.1.20:7420 to accept LAN peers).
# -InternetListen: Internet direct exposure is opt-in too (default: no listener; pass e.g.
#   -InternetListen 0.0.0.0:7422, a bare IP gets port 7422). Without it,
#   `raven node internet on --listen 0.0.0.0:7422` turns it on later (applied at the next
#   task start). The installer never changes the firewall: it prints the rule to run elevated.
# -P2pListen: libp2p (relay + hole punching, TCP and UDP 7423) is opt-in the same way (default:
#   no flag; pass e.g. -P2pListen 7423 = every interface, IPv4 + IPv6; IP:PORT = that address
#   only; off = off even if `raven node p2p on` saved it). -P2pRelays <multiaddr>[,<multiaddr>]
#   (at most 2, each ending in /p2p/<relay PeerId>) keeps a reservation on those relays;
#   -P2pRelay also relays for the PeerIds in relay_allow.json; -Upnp 1|0 saves the router
#   port-mapping choice (`raven node upnp on|off`). Without -Upnp, an interactive install that
#   turns -P2pListen on asks once (Enter = no); a non-interactive one never asks (stays unset).
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
    [string]$P2pListen = "",
    # -P2pRelays a,b (an array) and -P2pRelays "a,b" (one comma separated string) both work.
    [string[]]$P2pRelays = @(),
    [switch]$P2pRelay,
    [string]$Upnp = "",
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
# libp2p settings: empty = no flag (node_policy.json decides, as today). PORT / IP:PORT /
# [IPv6]:PORT / on / off characters only; raven-node validates the rest.
if ($P2pListen -and ($P2pListen -notmatch '^[\[\]0-9A-Za-z.:]+$')) {
    throw "-P2pListen must look like 7423, 0.0.0.0:7423, [::]:7423 or off"
}
$p2pListenOn = [bool]$P2pListen -and ($P2pListen -ne "off")
# The libp2p port of -P2pListen: "[v6]:port", "v4:port", a bare port or "on" (the default
# port); empty for "relay" (no listening port) and off.
$p2pPort = ""
if ($p2pListenOn -and ($P2pListen -ne "relay")) {
    $p2pPort = "7423"
    if (($P2pListen -match '^\[[^\]]*\]:(\d+)$') -or ($P2pListen -match '^[^:\[\]]+:(\d+)$')) {
        $p2pPort = $Matches[1]
    } elseif ($P2pListen -match '^\d+$') {
        $p2pPort = $P2pListen
    }
}
$p2pRelayList = @()
foreach ($item in $P2pRelays) {
    foreach ($entry in ([string]$item -split ',')) {
        $entry = $entry.Trim()
        if (-not $entry) { continue }
        if (($entry -notmatch '^/[0-9A-Za-z./:_-]+$') -or ($entry -notlike '*/p2p/?*')) {
            throw "-P2pRelays entries must look like /ip4/203.0.113.7/tcp/7423/p2p/<relay PeerId>"
        }
        $p2pRelayList += $entry
    }
}
if ($p2pRelayList.Count -gt 2) {
    throw "-P2pRelays takes at most 2 relays"
}
if ($Upnp -and ($Upnp -notmatch '^[01]$')) {
    throw "-Upnp must be 1 (map the p2p port on the router) or 0"
}
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
# Task Scheduler runs with another working directory: register absolute paths only.
$DataDir = (Resolve-Path -LiteralPath $DataDir).Path
$BinDir = (Resolve-Path -LiteralPath $BinDir).Path

# UPnP / NAT-PMP (owner decision Q8, "ask once at setup"): -Upnp decides. Without it, an
# interactive install (console input not redirected) that opens a p2p port asks the same
# one-time question as `raven node p2p on`, unless node_policy.json already holds an answer
# ("upnp": true|false). Enter = no. A host that cannot prompt leaves it unset. Asked before
# the build so nobody waits for cargo to answer it; saved after install below.
$upnpMode = ""
if ($Upnp -eq "1") {
    $upnpMode = "on"
} elseif ($Upnp -eq "0") {
    $upnpMode = "off"
} elseif ($p2pPort -and [Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
    $policyPath = Join-Path $DataDir "node_policy.json"
    $upnpAnswered = $false
    if (Test-Path -LiteralPath $policyPath) {
        $policyText = [string](Get-Content -Raw -LiteralPath $policyPath -ErrorAction SilentlyContinue)
        $upnpAnswered = $policyText -match '"upnp"\s*:\s*(true|false)'
    }
    if (-not $upnpAnswered) {
        $asked = $true
        $answer = $null
        try {
            $answer = Read-Host "Open TCP/UDP $p2pPort on your router automatically (UPnP/NAT-PMP) so friends can reach this node and it can relay for them? [y/N]"
        } catch {
            $asked = $false
        }
        if ($asked) {
            if ([string]$answer -match '^\s*(y|yes)\s*$') { $upnpMode = "on" } else { $upnpMode = "off" }
        }
    }
}

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
# libp2p flags: only the ones asked for (none = the task's arguments stay as before).
if ($P2pListen) {
    $serviceArgs = "$serviceArgs --p2p-listen $P2pListen"
}
foreach ($relayAddr in $p2pRelayList) {
    $serviceArgs = "$serviceArgs --p2p-relay $relayAddr"
}
if ($P2pRelay) {
    $serviceArgs = "$serviceArgs --relay"
}

$ravenExe = Join-Path $BinDir "raven.exe"
# The same p2p settings go into node_policy.json too, so `raven whoami --card` and
# `raven status` agree with the task even while it is not running (its arguments above still
# decide while it runs). Input comes from a pipe: it never asks.
if ($P2pListen) {
    if ($p2pListenOn) {
        $p2pSaveArgs = @("node", "p2p", "on", "--listen", $P2pListen)
        foreach ($relayAddr in $p2pRelayList) { $p2pSaveArgs += @("--relay", $relayAddr) }
    } else {
        $p2pSaveArgs = @("node", "p2p", "off")
    }
    $null | & $ravenExe --data-dir $DataDir @p2pSaveArgs | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "WARN: could not save the p2p settings in node_policy.json (the task still uses its arguments); run '$ravenExe --data-dir `"$DataDir`" $($p2pSaveArgs -join ' ')'"
    }
}

# Saved in node_policy.json before the task (re)starts below, which applies it.
$upnpSaved = ""
if ($upnpMode) {
    & $ravenExe --data-dir $DataDir node upnp $upnpMode
    if ($LASTEXITCODE -eq 0) {
        $upnpSaved = $upnpMode
    } else {
        Write-Host "WARN: could not save the UPnP choice; run '$ravenExe --data-dir `"$DataDir`" node upnp $upnpMode' and restart the task"
    }
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
if ($p2pListenOn -and -not $p2pPort) {
    Write-Host "p2p-listen=relay (no listening port: contacts reach this node only through its relays, -P2pRelays)"
} elseif ($p2pListenOn) {
    Write-Host "p2p-listen=$P2pListen (libp2p TCP+UDP $p2pPort; only your contacts get a Raven link; anyone can see that the port is open)"
    Write-Host "To let contacts reach it, run in an ELEVATED PowerShell yourself (Private profile only, never Public):"
    Write-Host "  New-NetFirewallRule -DisplayName `"Raven node p2p`" -Direction Inbound -Program `"$exe`" -Protocol TCP -LocalPort $p2pPort -Profile Private"
    Write-Host "  New-NetFirewallRule -DisplayName `"Raven node p2p`" -Direction Inbound -Program `"$exe`" -Protocol UDP -LocalPort $p2pPort -Profile Private"
    Write-Host "and forward TCP+UDP $p2pPort on your router if this PC is behind NAT (or -Upnp 1); without that a relay (-P2pRelays) still lets contacts reach you. Outbound needs no rule."
    Write-Host "A build with p2p off (P2P_PRODUCTION_ENABLED=false) never listens and logs P2P_HOLD; check: raven.exe status (p2p row)."
} elseif ($P2pListen) {
    Write-Host "p2p-listen=off (-P2pListen $P2pListen overrides 'raven node p2p on')"
} else {
    Write-Host "p2p-listen=off (opt-in: re-run with -P2pListen 7423, or run 'raven node p2p on' and restart the task)"
}
if ($p2pRelayList.Count -gt 0) {
    Write-Host "p2p-relays=$($p2pRelayList -join ',') (a reservation is kept on each; a relay sees both PeerIds and IPs of every circuit, never your messages)"
}
if ($P2pRelay) {
    Write-Host "relay=on for the PeerIds in $(Join-Path $DataDir 'relay_allow.json') (add a friend with 'raven relay allow @friend')"
    Write-Host "  Its relay PeerId is your own libp2p PeerId (the one in your card): friends who use it can link it to your card."
    Write-Host "  The logon task runs only while you are logged in, so this PC is a poor always-on relay."
}
if ((($p2pRelayList.Count -gt 0) -or $P2pRelay) -and -not $p2pListenOn) {
    Write-Host "NOTE: -P2pRelays and -P2pRelay take effect only while p2p listen is on (-P2pListen 7423 or 'raven node p2p on')."
}
if ($upnpSaved -eq "on") {
    $upnpPortText = if ($p2pPort) { $p2pPort } else { "of the p2p port, when one is open" }
    Write-Host "upnp=on (raven-node asks the router to map TCP/UDP $upnpPortText; it logs only the mapped port and success or failure)"
} elseif ($upnpSaved -eq "off") {
    Write-Host "upnp=off ('raven node upnp on' changes it; applied when the task restarts)"
}
Write-Host "bin-dir=$BinDir (raven.exe / ash.exe)"
$userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Write-Host "Named-pipe IPC: \\.\pipe\raven-node-$userSid (per-user pipe, current-user DACL; ash refuses a pipe served by another user) - see WINDOWS_SERVICE.md"
