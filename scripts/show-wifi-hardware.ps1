$ErrorActionPreference = "Continue"

Write-Host "=== Windows Wi-Fi adapters ===" -ForegroundColor Cyan
try {
    Get-NetAdapter -Physical |
        Where-Object { $_.InterfaceDescription -match '(?i)wi-?fi|wireless|802\.11|WLAN|MediaTek|Intel|Realtek|Qualcomm|RZ608' } |
        Format-Table -Auto Name, InterfaceDescription, Status, MacAddress, LinkSpeed
}
catch {
    Write-Warning "Get-NetAdapter failed: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "=== WLAN interfaces ===" -ForegroundColor Cyan
netsh wlan show interfaces

Write-Host ""
Write-Host "=== WLAN driver capabilities ===" -ForegroundColor Cyan
netsh wlan show drivers

Write-Host ""
Write-Host "=== USB devices exposed by usbipd ===" -ForegroundColor Cyan
$usbipd = $null
$cmd = Get-Command usbipd.exe -ErrorAction SilentlyContinue
if ($cmd) {
    $usbipd = $cmd.Source
}
elseif (Test-Path "$env:ProgramFiles\usbipd-win\usbipd.exe") {
    $usbipd = "$env:ProgramFiles\usbipd-win\usbipd.exe"
}

if ($usbipd) {
    & $usbipd list
}
else {
    Write-Warning "usbipd.exe not found"
}

Write-Host ""
Write-Host "Interpretation:" -ForegroundColor Yellow
Write-Host "- A Wi-Fi adapter must appear in the usbipd list to be passed directly to WSL by this lab."
Write-Host "- A Bluetooth-only entry (for example RZ608 Bluetooth Adapter) is not the Wi-Fi radio interface."
Write-Host "- If Windows sees Wi-Fi but usbipd does not list a Wi-Fi device, the radio is probably an internal PCIe/CNVi device rather than USB."
Write-Host "- In that case, use a dedicated USB Wi-Fi adapter supported by Linux monitor mode/injection for the RF trial."
