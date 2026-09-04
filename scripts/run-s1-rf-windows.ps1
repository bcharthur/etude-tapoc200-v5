param(
    [ValidateSet("list-usb", "probe", "observe", "deauth", "disassoc")]
    [string]$Mode = "probe",

    [string]$Distro = "Ubuntu",
    [string]$BusId = "",
    [string]$Interface = "wlan0",
    [int]$Channel = 0,
    [string]$CameraMac = "dc:62:79:8b:3a:da",
    [string]$ApBssid = "",

    [ValidateRange(1, 3)]
    [int]$Count = 1,

    [ValidateRange(10, 300)]
    [int]$ObserveSeconds = 45,

    [switch]$InstallDeps,
    [switch]$RestoreManaged
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-SafeToken([string]$Value, [string]$Name) {
    if ($Value -notmatch '^[A-Za-z0-9_.-]+$') {
        throw "$Name contains unsupported characters: $Value"
    }
}

function Assert-Mac([string]$Value, [string]$Name) {
    if ($Value -notmatch '^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$') {
        throw "$Name is not a valid MAC address: $Value"
    }
}

function Quote-Bash([string]$Value) {
    # Keep shell construction deliberately strict instead of trying to support
    # arbitrary shell metacharacters in local paths.
    if ($Value.Contains("'")) {
        throw "Single quotes are not supported in WSL paths/arguments: $Value"
    }
    return "'" + $Value + "'"
}

function Invoke-WslBash([string]$Command) {
    & wsl.exe -d $Distro -- bash -lc $Command
    if ($LASTEXITCODE -ne 0) {
        throw "WSL command failed with exit code $LASTEXITCODE`n$Command"
    }
}

function Ensure-UsbAttached {
    if (-not $BusId) {
        return
    }

    if (-not (Get-Command usbipd.exe -ErrorAction SilentlyContinue)) {
        throw @"
usbipd-win is not installed.
Install it from an elevated PowerShell with:
  winget install --interactive --exact dorssel.usbipd-win
Then reconnect the USB Wi-Fi adapter and retry.
"@
    }

    # Keep the WSL VM alive before attaching the USB device.
    & wsl.exe -d $Distro -- true | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to start WSL distribution '$Distro'."
    }

    $list = (& usbipd.exe list) -join "`n"
    $escaped = [regex]::Escape($BusId)
    $line = ($list -split "`n" | Where-Object { $_ -match "^\s*$escaped\s+" } | Select-Object -First 1)
    if (-not $line) {
        throw "USB BUSID '$BusId' was not found. Run: .\scripts\run-s1-rf-windows.ps1 -Mode list-usb"
    }

    if ($line -notmatch '(?i)Shared|Attached') {
        if (-not (Test-IsAdministrator)) {
            throw @"
USB device $BusId is not shared yet. Binding is a one-time administrator action.
Re-open PowerShell as Administrator and run:
  usbipd bind --busid $BusId
Then retry this script normally.
"@
        }
        Write-Host "[+] Sharing USB device $BusId with usbipd"
        & usbipd.exe bind --busid $BusId
        if ($LASTEXITCODE -ne 0) { throw "usbipd bind failed" }
    }

    $list = (& usbipd.exe list) -join "`n"
    $line = ($list -split "`n" | Where-Object { $_ -match "^\s*$escaped\s+" } | Select-Object -First 1)
    if ($line -notmatch '(?i)Attached') {
        Write-Host "[+] Attaching USB device $BusId to WSL"
        & usbipd.exe attach --wsl --busid $BusId
        if ($LASTEXITCODE -ne 0) { throw "usbipd attach failed" }
    }
}

if ($Mode -eq "list-usb") {
    if (-not (Get-Command usbipd.exe -ErrorAction SilentlyContinue)) {
        Write-Host "[-] usbipd-win is not installed."
        Write-Host "    winget install --interactive --exact dorssel.usbipd-win"
        exit 2
    }
    & usbipd.exe list
    exit $LASTEXITCODE
}

Assert-SafeToken $Distro "Distro"
Assert-SafeToken $Interface "Interface"
Assert-Mac $CameraMac "CameraMac"
if ($ApBssid) { Assert-Mac $ApBssid "ApBssid" }
if ($BusId -and $BusId -notmatch '^\d+-\d+$') { throw "BusId must look like 4-4 or 1-7" }

if ($Mode -in @("observe", "deauth", "disassoc") -and ($Channel -lt 1 -or $Channel -gt 196)) {
    throw "-Channel is required for radio trials (example: -Channel 6)."
}
if ($Mode -in @("deauth", "disassoc") -and -not $ApBssid) {
    throw "-$Mode requires -ApBssid with the BSSID of the camera's legitimate AP."
}

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "WSL is not installed or wsl.exe is not in PATH."
}

Ensure-UsbAttached

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$repoRootWsl = (& wsl.exe -d $Distro -- wslpath -a $repoRoot).Trim()
if ($LASTEXITCODE -ne 0 -or -not $repoRootWsl) {
    throw "Unable to translate repository path into WSL."
}

if ($InstallDeps) {
    Write-Host "[+] Installing WSL radio dependencies"
    Invoke-WslBash "sudo apt-get update && sudo apt-get install -y iw usbutils python3-scapy"
}

$requirementsCheck = "command -v ip >/dev/null && command -v iw >/dev/null && command -v python3 >/dev/null && sudo python3 -c 'import scapy.all'"
try {
    Invoke-WslBash $requirementsCheck
}
catch {
    throw @"
Missing WSL dependencies. Run once:
  .\scripts\run-s1-rf-windows.ps1 -Mode probe -BusId $BusId -Distro $Distro -InstallDeps
"@
}

if ($Mode -eq "probe") {
    Write-Host "[+] USB devices visible from WSL"
    Invoke-WslBash "command -v lsusb >/dev/null && lsusb || true"
    Write-Host ""
    Write-Host "[+] Wireless interfaces"
    Invoke-WslBash "iw dev || true; echo; iw phy || true"
    Write-Host ""
    Write-Host "[i] Choose the wireless interface reported above and rerun with -Interface <name>."
    exit 0
}

$ifaceQ = Quote-Bash $Interface
Write-Host "[+] Configuring $Interface in monitor mode on channel $Channel"
$monitorCmd = @"
sudo ip link set $ifaceQ down &&
sudo iw dev $ifaceQ set type monitor &&
sudo ip link set $ifaceQ up &&
sudo iw dev $ifaceQ set channel $Channel &&
iw dev $ifaceQ info
"@
Invoke-WslBash $monitorCmd

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$outWin = Join-Path $repoRoot "evidence\runs\$timestamp-s1-rf-$Mode"
New-Item -ItemType Directory -Force -Path $outWin | Out-Null
$outWsl = (& wsl.exe -d $Distro -- wslpath -a $outWin).Trim()
$trialWsl = "$repoRootWsl/scripts/s1_rf_trial.py"

$args = @(
    "sudo", "python3", (Quote-Bash $trialWsl),
    "--iface", (Quote-Bash $Interface),
    "--camera-mac", (Quote-Bash $CameraMac),
    "--action", (Quote-Bash $Mode),
    "--count", $Count,
    "--observe-seconds", $ObserveSeconds,
    "--out", (Quote-Bash $outWsl)
)
if ($Mode -in @("deauth", "disassoc")) {
    $args += @("--ap-bssid", (Quote-Bash $ApBssid))
}

$trialCmd = $args -join " "
Write-Host "[+] Starting bounded S1 trial"
Write-Host "    action=$Mode count=$Count camera=$CameraMac channel=$Channel"
Invoke-WslBash $trialCmd

if ($RestoreManaged) {
    Write-Host "[+] Restoring $Interface to managed mode"
    $restoreCmd = "sudo ip link set $ifaceQ down && sudo iw dev $ifaceQ set type managed && sudo ip link set $ifaceQ up"
    Invoke-WslBash $restoreCmd
}

Write-Host ""
Write-Host "[+] Evidence written to: $outWin"
Write-Host "[i] Inspect summary.json first. softap_seen=true is the interesting S1 signal."
