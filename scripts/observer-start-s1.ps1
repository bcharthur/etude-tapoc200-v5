param(
    [string]$Label = "S1-WLAN-LOSS",
    [int]$Seconds = 180,
    [string]$PcapInterface = ""
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
$argsList = @(".\observerlab.py", "observe", "--label", $Label, "--seconds", "$Seconds")
if ($PcapInterface) {
    $argsList += @("--pcap-interface", $PcapInterface)
}
python @argsList
