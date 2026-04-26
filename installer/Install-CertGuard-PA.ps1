param(
    [ValidateSet("Install","Uninstall","Debug","Gui","Deploy")]
    [string]$Action = "Install"
)

$InstallDir = "C:\ProgramData\CertGuard-PA"

function Install-App {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item "..\src\*.py" $InstallDir -Force
    Write-Host "Files deployed"
}

function Uninstall-App {
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Files removed"
}

switch ($Action) {
    "Install" { Install-App }
    "Uninstall" { Uninstall-App }
    "Debug" { python "$InstallDir\certguard_agent.py" debug }
    "Deploy" { python "$InstallDir\certguard_agent.py" deploy }
    "Gui" { python "$InstallDir\certguard_gui.py" }
}
