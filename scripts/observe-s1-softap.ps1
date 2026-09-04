param(
    [double]$Seconds = 180,
    [double]$Interval = 2,
    [string]$Out = ".\evidence\s1-rf-observe"
)

$ErrorActionPreference = "Stop"
Write-Host "[v1.0.16] Passive S1 SoftAP observer"
Write-Host "This script does NOT inject 802.11 frames."
Write-Host "Watching for Tapo_Cam_* for $Seconds seconds..."

python .\v5patchlab.py s1-observe-softap `
  --seconds $Seconds `
  --interval $Interval `
  --out $Out
