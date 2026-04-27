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
- Standalone release generated from repository source, not patched old zip files

## Repository layout

```text
installer/
  Install-CertGuard-PA.ps1      # main installer and service wrapper
src/
  certguard_agent.py            # raw Python worker source
  certguard_gui_qt.py           # primary PySide6 GUI
  certguard_gui.py              # legacy tkinter fallback
  certguard_eventlog.py         # Windows Event Log helper
  certguard_secrets.py          # DPAPI secret helper
tools/
  Build-StandaloneRelease.ps1   # generates standalone installer into releases/
docs/
  OPERATIONS.md                 # setup and operations notes
  DEVELOPMENT.md                # build/development notes
  V1_BASELINE_CHECKLIST.md      # protected baseline checklist
```

## Quick install

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer\Install-CertGuard-PA.ps1 -Action Install
```

## Build standalone release

Run from the repository root:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\tools\Build-StandaloneRelease.ps1
```

The generated file will be written to:

```text
releases\Install-CertGuard-PA-Standalone.ps1
```

Run it as Administrator:

```powershell
.\releases\Install-CertGuard-PA-Standalone.ps1 -Action Install
```

Important: if `tools/Build-StandaloneRelease.ps1` changes, regenerate the standalone file. Do not keep using an older generated standalone script.

## Useful actions

```powershell
.\installer\Install-CertGuard-PA.ps1 -Action Install
.\installer\Install-CertGuard-PA.ps1 -Action InstallSilent
.\installer\Install-CertGuard-PA.ps1 -Action Gui
.\installer\Install-CertGuard-PA.ps1 -Action Debug
.\installer\Install-CertGuard-PA.ps1 -Action Health
.\installer\Install-CertGuard-PA.ps1 -Action TestApi
.\installer\Install-CertGuard-PA.ps1 -Action TestWacs
.\installer\Install-CertGuard-PA.ps1 -Action InspectPfx
.\installer\Install-CertGuard-PA.ps1 -Action Compare
.\installer\Install-CertGuard-PA.ps1 -Action Policy
.\installer\Install-CertGuard-PA.ps1 -Action Deploy
.\installer\Install-CertGuard-PA.ps1 -Action ForceDeploy
.\installer\Install-CertGuard-PA.ps1 -Action RenewWacs
.\installer\Install-CertGuard-PA.ps1 -Action Status
.\installer\Install-CertGuard-PA.ps1 -Action Repair
.\installer\Install-CertGuard-PA.ps1 -Action Uninstall
```

The same action names are supported by the generated standalone installer.

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

## Current active workstream

```text
Base: PA-LE Service v3.4-clean -> CertGuard-PA v1 baseline
Active workstream: feature/qt-gui-polish
Protected areas:
- Do not patch old generated zip packages as source.
- Do not reintroduce pywin32 service model.
- Keep sc.exe service creation.
- Keep DPAPI-backed secret storage.
- Keep standalone build generated from repository source.
```
