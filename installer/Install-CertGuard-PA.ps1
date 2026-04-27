param(
    [ValidateSet("Install","InstallSilent","Uninstall","Start","Stop","Restart","Status","Gui","GuiLegacy","Debug","Deploy","ForceDeploy","Policy","Compare","InspectPfx","TestApi","TestWacs","RenewWacs","Health","Repair")]
    [string]$Action = "Install"
)

$ErrorActionPreference = "Stop"

$ServiceName = "CertGuard-PA"
$DisplayName = "CertGuard-PA Certificate Monitor"
$InstallDir = "C:\ProgramData\CertGuard-PA"
$LogDir = Join-Path $InstallDir "logs"
$SrcDir = Join-Path (Split-Path -Parent $PSScriptRoot) "src"
$Agent = Join-Path $InstallDir "certguard_agent.py"
$Gui = Join-Path $InstallDir "certguard_gui_qt.py"
$GuiLegacy = Join-Path $InstallDir "certguard_gui.py"
$RuntimeInstaller = Join-Path $InstallDir "Install-CertGuard-PA.ps1"
$EventSource = "CertGuard-PA"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator."
    }
}

function Get-PythonCommand {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) { return "python" }
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) { return "py" }
    throw "Python 3 was not found in PATH."
}

function Get-PythonPrefix {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) { return @() }
    return @("-3")
}

function Invoke-PythonChecked {
    param([string[]]$Arguments)
    $py = Get-PythonCommand
    $prefix = Get-PythonPrefix
    & $py @prefix @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed with exit code $LASTEXITCODE: $($Arguments -join ' ')"
    }
}

function Test-PythonImport {
    param([string]$ModuleName)
    $py = Get-PythonCommand
    $prefix = Get-PythonPrefix
    & $py @prefix -c "import $ModuleName" *> $null
    return ($LASTEXITCODE -eq 0)
}

function Ensure-Package {
    param([string]$ModuleName, [string]$PackageName)
    if (Test-PythonImport $ModuleName) {
        Write-Host "[INFO] Python package already available: $PackageName"
        return
    }
    Write-Host "[INFO] Python package missing: $PackageName. Installing..."
    Invoke-PythonChecked @("-m", "pip", "install", "--upgrade", $PackageName)
}

function Ensure-Dependencies {
    Ensure-Package "cryptography" "cryptography"
}

function Ensure-GuiDependencies {
    Ensure-Dependencies
    Ensure-Package "PySide6" "PySide6"
}

function Ensure-EventSource {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            New-EventLog -LogName Application -Source $EventSource
            Write-Host "[INFO] Event Log source registered: $EventSource"
        }
    } catch { Write-Warning "Event source registration failed: $($_.Exception.Message)" }
}

function Deploy-Files {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    if (-not (Test-Path $SrcDir)) { throw "Source directory was not found: $SrcDir" }
    Copy-Item (Join-Path $SrcDir "*.py") $InstallDir -Force
    $sourcePath = [System.IO.Path]::GetFullPath($PSCommandPath)
    $targetPath = [System.IO.Path]::GetFullPath($RuntimeInstaller)
    if ($sourcePath -ne $targetPath) { Copy-Item $PSCommandPath $RuntimeInstaller -Force }
    try {
        icacls $InstallDir /inheritance:e | Out-Null
        icacls $InstallDir /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null
    } catch { Write-Warning "ACL update failed: $($_.Exception.Message)" }
    Write-Host "[INFO] Files deployed to $InstallDir"
}

function Invoke-Agent {
    param([string]$Command)
    Deploy-Files
    Ensure-Dependencies
    Invoke-PythonChecked @($Agent, $Command)
}

function Install-Service {
    Deploy-Files
    Ensure-Dependencies
    Ensure-EventSource
    $py = Get-PythonCommand
    $prefix = Get-PythonPrefix
    $pythonArgs = ($prefix + @($Agent, "service-loop")) -join " "
    $binPath = "`"$py`" $pythonArgs"
    sc.exe query $ServiceName *> $null
    if ($LASTEXITCODE -eq 0) {
        sc.exe stop $ServiceName *> $null
        Start-Sleep -Seconds 2
        sc.exe delete $ServiceName *> $null
        Start-Sleep -Seconds 2
    }
    sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= $DisplayName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed." }
    sc.exe description $ServiceName "CertGuard-PA automated Palo Alto certificate lifecycle monitor." | Out-Null
    sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/120000/restart/300000 | Out-Null
    sc.exe failureflag $ServiceName 1 | Out-Null
    sc.exe start $ServiceName | Out-Null
    Write-Host "[INFO] Service installed and started: $ServiceName"
}

function Remove-ServiceIfExists {
    sc.exe query $ServiceName *> $null
    if ($LASTEXITCODE -eq 0) {
        sc.exe stop $ServiceName *> $null
        Start-Sleep -Seconds 2
        sc.exe delete $ServiceName *> $null
        Start-Sleep -Seconds 2
        Write-Host "[INFO] Service removed: $ServiceName"
    } else { Write-Host "[INFO] Service does not exist: $ServiceName" }
}

function Uninstall-App {
    Remove-ServiceIfExists
    if (-not (Test-Path $InstallDir)) { Write-Host "[INFO] ProgramData directory does not exist."; return }
    Write-Host ""
    Write-Host "ProgramData cleanup options:"
    Write-Host "  1 - Remove everything: config, state, logs and runtime files"
    Write-Host "  2 - Keep config/state, remove runtime files only"
    Write-Host "  3 - Remove logs only"
    Write-Host "  4 - Keep everything"
    $choice = Read-Host "Select cleanup option (1/2/3/4)"
    switch ($choice) {
        "1" { Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue; Write-Host "[INFO] Removed all ProgramData: $InstallDir" }
        "2" { Get-ChildItem $InstallDir -File -Filter "*.py" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue; Write-Host "[INFO] Runtime files removed; config/state/logs preserved." }
        "3" { Remove-Item $LogDir -Recurse -Force -ErrorAction SilentlyContinue; Write-Host "[INFO] Logs removed." }
        default { Write-Host "[INFO] ProgramData preserved." }
    }
}

function Show-Status {
    sc.exe query $ServiceName
    $statePath = Join-Path $InstallDir "state.json"
    if (Test-Path $statePath) { Write-Host ""; Write-Host "[STATE]"; Get-Content $statePath }
}

Assert-Admin
switch ($Action) {
    "Install" { Deploy-Files; Ensure-GuiDependencies; Ensure-EventSource; Invoke-PythonChecked @($Gui) }
    "InstallSilent" { Install-Service }
    "Repair" { Install-Service }
    "Uninstall" { Uninstall-App }
    "Start" { sc.exe start $ServiceName }
    "Stop" { sc.exe stop $ServiceName }
    "Restart" { sc.exe stop $ServiceName; Start-Sleep -Seconds 2; sc.exe start $ServiceName }
    "Status" { Show-Status }
    "Gui" { Deploy-Files; Ensure-GuiDependencies; Invoke-PythonChecked @($Gui) }
    "GuiLegacy" { Deploy-Files; Ensure-Dependencies; Invoke-PythonChecked @($GuiLegacy) }
    "Debug" { Invoke-Agent "debug" }
    "Deploy" { Invoke-Agent "deploy" }
    "ForceDeploy" { Invoke-Agent "force-deploy" }
    "Policy" { Invoke-Agent "policy" }
    "Compare" { Invoke-Agent "compare" }
    "InspectPfx" { Invoke-Agent "inspect-pfx" }
    "TestApi" { Invoke-Agent "test-pa" }
    "TestWacs" { Invoke-Agent "test-wacs" }
    "RenewWacs" { Invoke-Agent "renew-wacs" }
    "Health" { Invoke-Agent "health" }
}
