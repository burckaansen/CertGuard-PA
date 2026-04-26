# CertGuard-PA

Automated certificate lifecycle monitoring and deployment for Palo Alto Networks firewalls.

CertGuard-PA is a Windows service package that monitors local win-acme PFX output, compares it with the certificate installed on Palo Alto, and imports the certificate only when policy conditions are met.

## Baseline

This repository starts from the clean rebuild baseline formerly tracked as **PA-LE Service v3.4-clean**.

Baseline principles:

- Single clean embedded Python worker plus PowerShell wrapper
- Step-by-step setup wizard
- `Debug` as a separate action
- Optional `Import if certificate does not exist on Palo Alto`
- Uninstall asks whether to remove ProgramData
- Windows Event Log plus file log
- Windows service created with `sc.exe`, not pywin32

## Repository layout

```text
installer/
  Install-CertGuard-PA.ps1      # distributable installer
src/
  certguard_agent.py            # raw Python worker source
docs/
  OPERATIONS.md                 # setup and operations notes
  DEVELOPMENT.md                # build/development notes
```

## Quick install

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer\Install-CertGuard-PA.ps1 -Action Install
```

## Useful actions

```powershell
.\installer\Install-CertGuard-PA.ps1 -Action Debug
.\installer\Install-CertGuard-PA.ps1 -Action TestApi
.\installer\Install-CertGuard-PA.ps1 -Action TestWacs
.\installer\Install-CertGuard-PA.ps1 -Action CompareCert
.\installer\Install-CertGuard-PA.ps1 -Action CheckExpiry
.\installer\Install-CertGuard-PA.ps1 -Action PolicyDeploy
.\installer\Install-CertGuard-PA.ps1 -Action Status
```

## Runtime paths

```text
C:\ProgramData\CertGuard-PA\config.json
C:\ProgramData\CertGuard-PA\state.json
C:\ProgramData\CertGuard-PA\logs\certguard-pa.log
```

Secrets are stored with Windows DPAPI machine scope.

## Windows Event Log

```text
Windows Logs > Application
Source: CertGuard-PA
```
