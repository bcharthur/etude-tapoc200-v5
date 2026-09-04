param(
  [int]$Seconds = 900,
  [string]$Label = "S1-PASSIVE",
  [ValidateSet("auto","wireshark","pktmon","none")]
  [string]$CaptureBackend = "auto",
  [string]$PcapInterface = ""
)

$Args = @(
  ".\observerlab.py", "passive",
  "--label", $Label,
  "--seconds", "$Seconds",
  "--capture-backend", $CaptureBackend
)
if ($PcapInterface) {
  $Args += @("--pcap-interface", $PcapInterface)
}
python @Args
