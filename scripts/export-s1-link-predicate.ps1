param(
    [string]$Main = ".\analysis\c200v5-142\main-1.4.2",
    [string]$Out = ".\analysis\s1-link-predicate"
)

$ErrorActionPreference = "Stop"

Write-Host "[v1.0.17] S1 link-status -> onboarding predicate slice"
Write-Host "main: $Main"
Write-Host "out : $Out"

python .\v5patchlab.py s1-predicate-slice `
  $Main `
  --out $Out

Write-Host ""
Write-Host "Priority files:"
Write-Host "  $Out\s1-link-predicate.md"
Write-Host "  $Out\s1-link-predicate.json"
Write-Host "  $Out\onboarding_phy_link_status_change_handle.disasm.txt"
Write-Host "  $Out\context-functions\wlan_manager_onboarding_start.disasm.txt"
Write-Host "  $Out\context-functions\wlan_manager_start.disasm.txt"
