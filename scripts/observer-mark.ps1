param(
    [Parameter(Mandatory=$true)][string]$Text,
    [string]$Kind = "MARK"
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
python .\observerlab.py mark $Text --kind $Kind
