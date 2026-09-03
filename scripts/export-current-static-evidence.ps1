param(
    [string]$Main = ".\analysis\c200v5-142\main-1.4.2",
    [string]$Out = ".\evidence\static-1.4.2"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

$mainResolved = (Resolve-Path $Main).Path
$mainWsl = (wsl.exe --exec wslpath -a -u $mainResolved).Trim()

wsl bash -lc "readelf -h '$mainWsl'" | Out-File -Encoding utf8 "$Out\readelf-h.txt"
wsl bash -lc "readelf -SW '$mainWsl'" | Out-File -Encoding utf8 "$Out\readelf-sections.txt"
wsl bash -lc "readelf -sW '$mainWsl' | grep -Ei 'spake|rtsp|onvif|soap|decrypt|auth|reset|wifi|wlan|hostapd|wpa|p2p|wps|gpio'" | Out-File -Encoding utf8 "$Out\symbols-security-radio.txt"
wsl bash -lc "strings -a -t x '$mainWsl' | grep -Ei 'factory|reset|restore|softap|Tapo_Cam|provision|deauth|disassoc|disconnect|reconnect|wpa|hostapd|nl80211|p2p|wps|dpp|gpio|button|recovery'" | Out-File -Encoding utf8 "$Out\strings-s1-radio.txt"
wsl bash -lc "mipsel-linux-gnu-objdump -d '$mainWsl' --start-address=0x4cef98 --stop-address=0x4cf104" | Out-File -Encoding utf8 "$Out\spake2p-mac-verify.txt"
wsl bash -lc "mipsel-linux-gnu-objdump -d '$mainWsl' --start-address=0x4d0640 --stop-address=0x4d0788" | Out-File -Encoding utf8 "$Out\spake2p-confirm-wrapper.txt"
wsl bash -lc "mipsel-linux-gnu-objdump -d '$mainWsl' --start-address=0x4d3098 --stop-address=0x4d30f4" | Out-File -Encoding utf8 "$Out\base64-decode-upper.txt"
wsl bash -lc "mipsel-linux-gnu-objdump -d '$mainWsl' --start-address=0x4d194c --stop-address=0x4d19b8" | Out-File -Encoding utf8 "$Out\base64-decode-lower.txt"

Get-FileHash -Algorithm SHA256 $Main | Format-List | Out-File -Encoding utf8 "$Out\main-sha256.txt"
Write-Host "Evidence written to $Out"
