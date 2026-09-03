param(
    [string]$Main = ".\analysis\c200v5-142\main-1.4.2",
    [string]$Rootfs = "",
    [string]$Out = ".\analysis\s1-static-map",
    [switch]$Xrefs
)

$ErrorActionPreference = "Stop"
$argsList = @(".\v5patchlab.py", "s1-static-map", $Main, "--out", $Out)
if ($Rootfs) { $argsList += @("--rootfs", $Rootfs) }
if ($Xrefs) { $argsList += "--xrefs" }
python @argsList
