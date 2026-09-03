param(
    [string]$Main = ".\analysis\c200v5-142\main-1.4.2",
    [string]$Out = ".\evidence\s1-onboarding-controlflow"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

$mainResolved = (Resolve-Path $Main).Path
$mainWsl = (wsl.exe --exec wslpath -a -u $mainResolved).Trim()

$targets = @(
    "onboarding_phy_link_status_change_handle",
    "wlan_manager_onboarding_start",
    "onboarding_restart",
    "wlan_manager_init_reconnect_ctx",
    "wlan_manual_reconnect",
    "wlan_manager_sta_disconnect",
    "wlan_sta_disconnect",
    "is_reonboarding",
    "get_cur_onboarding_mode",
    "set_exit_softap_fast_flag",
    "stop_exit_softap",
    "wlan_manager_reboot",
    "wlan_manager_reboot_thread"
)

$symbols = wsl bash -lc "readelf -sW '$mainWsl'"
$symbols | Out-File -Encoding utf8 "$Out\readelf-symbols-full.txt"

$targetRegex = ($targets | ForEach-Object { [regex]::Escape($_) }) -join "|"
$symbols | Select-String -Pattern $targetRegex | ForEach-Object { $_.Line } |
    Out-File -Encoding utf8 "$Out\symbols-s1-targets.txt"

foreach ($name in $targets) {
    $line = ($symbols | Select-String -Pattern "\s$([regex]::Escape($name))$" | Select-Object -First 1).Line
    if (-not $line) {
        "NOT FOUND: $name" | Out-File -Encoding utf8 -Append "$Out\missing-symbols.txt"
        continue
    }

    if ($line -notmatch '^\s*\d+:\s+([0-9A-Fa-f]+)\s+(\d+)\s+FUNC\s+') {
        "UNPARSED: $line" | Out-File -Encoding utf8 -Append "$Out\unparsed-symbols.txt"
        continue
    }

    $start = [Convert]::ToInt64($Matches[1], 16)
    $size = [Int64]$Matches[2]
    if ($size -le 0) {
        "ZERO SIZE: $line" | Out-File -Encoding utf8 -Append "$Out\unparsed-symbols.txt"
        continue
    }
    $stop = $start + $size
    $startHex = ('0x{0:x}' -f $start)
    $stopHex = ('0x{0:x}' -f $stop)

    "${name}: start=$startHex size=$size stop=$stopHex" |
        Out-File -Encoding utf8 -Append "$Out\symbol-ranges.txt"

    wsl bash -lc "mipsel-linux-gnu-objdump -d '$mainWsl' --start-address=$startHex --stop-address=$stopHex" |
        Out-File -Encoding utf8 "$Out\$name.disasm.txt"

    # Direct-call/label references only. PIC jalr/GOT callers require Ghidra or a
    # dedicated data-flow pass and are intentionally not claimed here.
    wsl bash -lc "mipsel-linux-gnu-objdump -d '$mainWsl' | grep -n -B16 -A28 -E '<$name>|(bal|jal).*<$name>'" |
        Out-File -Encoding utf8 "$Out\$name.direct-refs.txt"
}

wsl bash -lc "strings -a -t x '$mainWsl' | grep -Ei 'onboarding_phy_link_status_change_handle|is_reonboarding|softap|reset button|recovery_mode|DONOT WRITE CONFIG|wlan_manager_(onboarding|reboot|sta_disconnect|init_reconnect)|wlan_manual_reconnect'" |
    Out-File -Encoding utf8 "$Out\strings-s1-junctions.txt"

Get-FileHash -Algorithm SHA256 $Main | Format-List |
    Out-File -Encoding utf8 "$Out\main-sha256.txt"

Write-Host "S1 onboarding control-flow evidence written to $Out"
