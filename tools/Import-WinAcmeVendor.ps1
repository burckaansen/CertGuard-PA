# Import win-acme runtime into CertGuard-PA vendor folder
# Copies the complete working win-acme distribution, including plugins.
# ASCII only

param(
    [Parameter(Mandatory=$true)]
    [string]$SourcePath
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Target = Join-Path $RepoRoot "vendor\win-acme"

if (-not (Test-Path $SourcePath)) {
    throw "Source path not found: $SourcePath"
}

$Source = (Resolve-Path $SourcePath).Path
$Wacs = Join-Path $Source "wacs.exe"
if (-not (Test-Path $Wacs)) {
    throw "wacs.exe not found in source directory: $Source"
}

if (Test-Path $Target) {
    Remove-Item $Target -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $Target | Out-Null

Write-Host "[INFO] Importing complete win-acme runtime..."
Copy-Item (Join-Path $Source "*") $Target -Recurse -Force

if (-not (Test-Path (Join-Path $Target "wacs.exe"))) {
    throw "Vendor import failed: wacs.exe missing after copy."
}

$Files = Get-ChildItem $Target -File -Recurse
$TotalBytes = ($Files | Measure-Object Length -Sum).Sum
Write-Host "[INFO] win-acme vendor runtime imported: $Target"
Write-Host "[INFO] Files: $($Files.Count)"
Write-Host "[INFO] Size: $([math]::Round($TotalBytes / 1MB, 2)) MB"
Write-Host "[INFO] Next: .\tools\Build-StandaloneRelease.ps1"
