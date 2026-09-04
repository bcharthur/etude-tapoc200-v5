param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^\d+-\d+$')]
    [string]$BusId,

    [string]$Distro = 'Ubuntu'
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-UsbipdExe {
    $cmd = Get-Command usbipd.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidate = "$env:ProgramFiles\usbipd-win\usbipd.exe"
    if (Test-Path $candidate) { return $candidate }
    throw 'usbipd.exe not found. Install usbipd-win first.'
}

$usbipd = Get-UsbipdExe

Write-Host '[+] Starting target WSL distro'
& wsl.exe -d $Distro -- true | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Unable to start WSL distro '$Distro'." }

$list = (& $usbipd list) -join "`n"
$escaped = [regex]::Escape($BusId)
$line = ($list -split "`n" | Where-Object { $_ -match "^\s*$escaped\s+" } | Select-Object -First 1)
if (-not $line) {
    Write-Host $list
    throw "BUSID $BusId not found. Plug the Alfa adapter in and rerun usbipd list."
}

Write-Host "[+] Device: $line"

if ($line -notmatch '(?i)Shared|Attached') {
    if (-not (Test-IsAdministrator)) {
        throw "BUSID $BusId is not shared. Re-run this script once from an elevated PowerShell."
    }
    Write-Host "[+] Sharing $BusId"
    & $usbipd bind --busid $BusId
    if ($LASTEXITCODE -ne 0) { throw 'usbipd bind failed.' }
}

$list = (& $usbipd list) -join "`n"
$line = ($list -split "`n" | Where-Object { $_ -match "^\s*$escaped\s+" } | Select-Object -First 1)
if ($line -notmatch '(?i)Attached') {
    Write-Host "[+] Attaching $BusId to WSL"
    & $usbipd attach --wsl --busid $BusId
    if ($LASTEXITCODE -ne 0) { throw 'usbipd attach failed.' }
}

Write-Host ''
Write-Host '[+] USB visible from WSL:'
& wsl.exe -d $Distro -- bash -lc 'lsusb || true'
Write-Host ''
Write-Host '[+] Wireless interfaces visible from WSL:'
& wsl.exe -d $Distro -- bash -lc 'iw dev || true; echo; iw phy || true'
Write-Host ''
Write-Host '[i] If lsusb sees the Alfa but iw dev is empty, the WSL kernel lacks the adapter driver.'
