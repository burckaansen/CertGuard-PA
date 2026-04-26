param(
    [ValidateSet("Install","Uninstall","Debug")]
    [string]$Action = "Install"
)

$InstallDir = "C:\ProgramData\CertGuard-PA"
$Agent = Join-Path $InstallDir "certguard_agent.py"

function Install-App {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item "..\src\certguard_agent.py" $Agent -Force
    Write-Host "Files deployed"
}

function Uninstall-App {
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Files removed"
}

switch ($Action) {
    "Install" { Install-App }
    "Uninstall" { Uninstall-App }
    "Debug" { python ..\src\certguard_agent.py debug }
}
