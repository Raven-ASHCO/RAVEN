# Windows terminal-path smoke: ash init → doctor → send teach / fail-closed.
# Sibling of ash_menu_smoke.sh (Unix CI landing: PR #16 rust-linux + rust-macos).
# Not an install helper — do not put under scripts/install/.
# Do NOT call node/scripts/install.sh (B11 fail-closed, PR #17; still Blocked/non-evidence).
#
# Doctor axes stay distinct (Core gate / PR #22):
#   daemon_presence / daemon_ready / send_path (default not_ready / unchecked)
#   doctor exit 0 = report completed, ≠ send Proven
#   IPC-up / presence alone is NOT enough — this script requires identity + serverless_rvn1
#   Never require daemon_presence: present (would greenwash Windows blocked).
#   Never require daemon_ready: ready (do not greenwash ready from presence / Ping).
#   Named-pipe client is on this tree — do NOT require ipc_transport_missing.
#   Try-phase (Windows): start raven-node ipc --data-dir, assert daemon_presence: present
#     (Ping→Pong over the per-user pipe \\.\pipe\raven-node-<user SID>), then kill and assert presence down
#     (fail-closed connect — not a soft skip / blocked transport).
#
# Operator (from node/, Windows / pwsh host):
#   pwsh -File scripts/ash_doctor_send_smoke.ps1
#   (script cargo-builds -p ash -p raven-node if needed, then
#    init → whoami → raven-node ipc → doctor up → stop → doctor down → menu send)
#
# CI (job rust-windows, working-directory: node, shell: pwsh):
#   Fail-loud if this file is missing, then:
#     & scripts/ash_doctor_send_smoke.ps1
#   Wired in .github/workflows/raven-serverless.yml
#     step "ash doctor→send smoke (Windows terminal path)"
#
# Split A: script content = CLI DX; rust-windows job glue = Windows Platform.
#   Debug ash.exe is intentional (locked-file is debug_assertions-only; refused
#   in Release — same as ash_menu_smoke.sh / PR #16). Do not switch this smoke
#   to target\release\ash.exe. No step-order change requested.
#
# Fail-closed:
#   Exit 0 only when every required string is present (smoke passed).
#   If target\debug\ash.exe is missing after cargo build -p ash: exit 1 with
#     "MSVC ash binary missing — blocked on Windows Platform PR1"
#   No silent skip. RAVEN_ALLOW_ASH_SMOKE_SKIP is not honored.
#
# Do not invent Proven. This file existing (or a local green) is not
# terminal-path Proven (Windows). That label waits for the named CI step
# green on main. wine / lima ash --help is PASS_SOFTWARE_SUBSTITUTE only.

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Fail([string]$Message) {
    Write-Host "FAIL: $Message" -ForegroundColor Red
    exit 1
}

function Require-Match([string]$Haystack, [string]$Pattern, [string]$What) {
    if ($Haystack -notmatch $Pattern) {
        Write-Host "----- captured output -----" -ForegroundColor Yellow
        Write-Host $Haystack
        Write-Host "----- end output -----" -ForegroundColor Yellow
        Fail "$What (pattern: $Pattern)"
    }
}

# ash emits no colour escapes with NO_COLOR=1 / redirected stdout; stripping any
# stray SGR codes stays as a belt-and-braces guard for older binaries.
function Get-PlainText([string]$Text) {
    return [regex]::Replace($Text, '\x1b\[[0-9;]*m', '')
}

function Stop-SmokeRavenNode {
    if ($null -eq $script:NodeProc) { return }
    $proc = $script:NodeProc
    $script:NodeProc = $null
    if ($proc.HasExited) { return }
    Write-Host "stopping raven-node ipc pid=$($proc.Id)"
    try { $proc.Kill() } catch { }
    if (-not $proc.WaitForExit(10000)) {
        Fail "raven-node ipc pid=$($proc.Id) did not exit — fail-loud cleanup"
    }
}

function Assert-DoctorIdentity([string]$Text) {
    if ($Text -notmatch "serverless_rvn1") {
        Write-Host $Text
        Fail "ash doctor must show messaging path serverless_rvn1 (IPC-up alone is not Proven)"
    }
    if ($Text -notmatch "identity:\s*present" -and $Text -notmatch "identity present") {
        Write-Host $Text
        Fail "ash doctor must show identity present (IPC-up / daemon_state alone is not Proven)"
    }
}

function Assert-NoMissingTransport([string]$Plain, [string]$Phase) {
    if ($Plain -match "ipc_transport_missing" -or
        $Plain -match "daemon_presence:\s*blocked") {
        Write-Host $Plain
        Fail "named-pipe client is on this tree — $Phase must not skip as ipc_transport_missing / blocked"
    }
}

$NodeRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $NodeRoot

$Ash = Join-Path $NodeRoot "target\debug\ash.exe"
$Node = Join-Path $NodeRoot "target\debug\raven-node.exe"

if (-not (Test-Path -LiteralPath $Ash)) {
    Write-Host "ash.exe missing — cargo build -p ash -p raven-node (debug)"
    & cargo build -p ash -p raven-node
    if ($LASTEXITCODE -ne 0) {
        Fail "cargo build -p ash -p raven-node failed (exit $LASTEXITCODE)"
    }
}

if (-not (Test-Path -LiteralPath $Ash)) {
    Fail "MSVC ash binary missing — blocked on Windows Platform PR1"
}
if (-not (Test-Path -LiteralPath $Node)) {
    Write-Host "raven-node.exe missing — cargo build -p raven-node (debug)"
    & cargo build -p raven-node
    if ($LASTEXITCODE -ne 0) {
        Fail "cargo build -p raven-node failed (exit $LASTEXITCODE)"
    }
}
if (-not (Test-Path -LiteralPath $Node)) {
    Fail "MSVC raven-node.exe missing after cargo build — blocked on Windows Platform PR1"
}

$env:RAVEN_IDENTITY_BACKEND = "locked-file"
$env:NO_COLOR = "1"
$env:TERM = "dumb"

$Work = Join-Path ([System.IO.Path]::GetTempPath()) ("raven-ash-win-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $Work | Out-Null
$Data = Join-Path $Work "data"
New-Item -ItemType Directory -Force -Path $Data | Out-Null
$script:NodeProc = $null
$nodeOut = Join-Path $Work "raven-node-ipc.out.log"
$nodeErr = Join-Path $Work "raven-node-ipc.err.log"

function Invoke-AshCapture {
    param(
        [string[]]$AshArgs,
        [string]$StdinText = $null,
        [int]$TimeoutSec = 90
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Ash
    $psi.Arguments = ($AshArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join " "
    $psi.WorkingDirectory = $NodeRoot
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true
    # Inherit $env:RAVEN_IDENTITY_BACKEND / NO_COLOR from this process.
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    # Drain stdout AND stderr concurrently from the start: a child that writes more than
    # the pipe buffer blocks in write(), WaitForExit then times out and the smoke fails
    # with a misleading "hang" diagnostic. Separate tasks, because draining only one
    # stream can still deadlock on the other.
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if ($null -ne $StdinText) {
        $p.StandardInput.Write($StdinText)
        $p.StandardInput.Close()
    } else {
        $p.StandardInput.Close()
    }
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch { }
        Fail "ash $($AshArgs -join ' ') exceeded ${TimeoutSec}s — refusing hang-as-pass"
    }
    # Parameterless WaitForExit() also waits for the redirected streams to reach EOF.
    $p.WaitForExit()
    $stdout = $outTask.GetAwaiter().GetResult()
    $stderr = $errTask.GetAwaiter().GetResult()
    return @{ ExitCode = $p.ExitCode; Text = ($stdout + "`n" + $stderr) }
}

try {
    Write-Host "=== ash doctor→send smoke workdir=$Work ==="
    Write-Host "ash=$Ash"

    $init = Invoke-AshCapture -AshArgs @("--data-dir", $Data, "init")
    if ($init.ExitCode -ne 0) {
        Fail "ash init exited $($init.ExitCode)"
    }
    Require-Match $init.Text "address=" "ash init must print address="
    Require-Match $init.Text "pub_hex=" "ash init must print pub_hex="
    Require-Match $init.Text "fingerprint=" "ash init must print fingerprint="

    $who = Invoke-AshCapture -AshArgs @("--data-dir", $Data, "whoami")
    if ($who.ExitCode -ne 0) {
        Fail "ash whoami exited $($who.ExitCode)"
    }
    Require-Match $who.Text "address" "ash whoami must show address"
    Require-Match $who.Text "pub_hex" "ash whoami must show pub_hex"

    Write-Host "starting raven-node ipc --data-dir $Data"
    $script:NodeProc = Start-Process -FilePath $Node `
        -ArgumentList "ipc --data-dir `"$Data`"" `
        -WorkingDirectory $NodeRoot `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput $nodeOut `
        -RedirectStandardError $nodeErr
    if ($null -eq $script:NodeProc) {
        Fail "Start-Process raven-node ipc returned no process"
    }
    Write-Host "raven-node ipc pid=$($script:NodeProc.Id)"
    Start-Sleep -Seconds 2
    if ($script:NodeProc.HasExited) {
        $errTxt = ""
        if (Test-Path -LiteralPath $nodeErr) { $errTxt = Get-Content -LiteralPath $nodeErr -Raw }
        Fail "raven-node ipc exited $($script:NodeProc.ExitCode) before doctor ping`n$errTxt"
    }

    $doc = Invoke-AshCapture -AshArgs @("--data-dir", $Data, "doctor")
    # doctor is diagnostic; require identity + messaging_path even if exit != 0
    Assert-DoctorIdentity $doc.Text
    $docPlain = Get-PlainText $doc.Text
    Assert-NoMissingTransport $docPlain "doctor (daemon up)"
    Require-Match $docPlain "daemon_presence:" "ash doctor must print daemon_presence:"
    Require-Match $docPlain "daemon_presence:\s*present" `
        "ash doctor must show daemon_presence: present after raven-node ipc start (named-pipe Ping)"
    # Presence/Ping ≠ ready ≠ send. Do not require daemon_ready: ready.
    if ($docPlain -match "daemon_ready:\s*ready") {
        Write-Host "doctor printed daemon_ready: ready — not used as a pass (presence ≠ ready)"
    }
    Write-Host "doctor (daemon up): daemon_presence: present (named-pipe ping); identity + serverless_rvn1 OK"

    Stop-SmokeRavenNode
    Start-Sleep -Seconds 1

    $docDown = Invoke-AshCapture -AshArgs @("--data-dir", $Data, "doctor")
    $downPlain = Get-PlainText $docDown.Text
    Assert-NoMissingTransport $downPlain "doctor (daemon down)"
    Require-Match $downPlain "daemon_presence:" "ash doctor must print daemon_presence: after raven-node stop"
    if ($downPlain -match "daemon_presence:\s*present") {
        Write-Host $downPlain
        Fail "ash doctor still shows daemon_presence: present after raven-node stop — pipe must fail-closed"
    }
    Require-Match $downPlain "daemon_presence:\s*down" `
        "ash doctor must show daemon_presence: down after raven-node stop (fail-closed connect, not a skip)"
    Write-Host "doctor (daemon down): presence fail-closed after raven-node stop"

    # Interactive line-menu send teach path (Windows uses line_menu_loop).
    # clap `ash send` / `ash contact add` are not dispatched in ash run() today;
    # the wired path is the numbered menu. Empty book → fail-closed teach.
    # 1 = Send; n = do not add a contact now; q = quit.
    $menu = Invoke-AshCapture -AshArgs @("--data-dir", $Data) -StdinText "1`nn`nq`n" -TimeoutSec 90
    $teach = ($menu.Text -match "no pinned contacts") -or
             ($menu.Text -match "Add a contact first") -or
             ($menu.Text -match "empty message")
    if (-not $teach) {
        Write-Host $menu.Text
        Fail "send teach / fail-closed path missing (need no-contact or empty-message evidence)"
    }
    if ($menu.Text -notmatch "fly safe") {
        Write-Host $menu.Text
        Fail "interactive ash did not reach quit (fly safe) — refusing partial menu"
    }
    Write-Host "send teach / fail-closed OK"

    Write-Host "=== ASH DOCTOR SEND SMOKE PASSED ==="
    exit 0
}
finally {
    Stop-SmokeRavenNode
    if (Test-Path -LiteralPath $Work) {
        Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
