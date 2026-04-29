# CertGuard-PA

<p align="center">
  <img src="docs/assets/certguard-pa-logo.png" alt="CertGuard-PA logo" width="520">
</p>

<p align="center">
  <strong>Automated certificate lifecycle monitoring and deployment for Palo Alto Networks firewalls.</strong>
</p>

CertGuard-PA is a Windows service package that monitors local win-acme PFX output, compares it with the certificate installed on Palo Alto, and imports the certificate only when policy conditions are met.

## Branding

The primary project logo is the premium chrome/silver shield-and-certificate design with the `CertGuard-PA` wordmark.

Canonical asset path:

```text
docs/assets/certguard-pa-logo.png
```

Protected branding rules:

- Preserve the current logo/icon design direction.
- Keep the shield, certificate/document, checkmark/seal, and subtle circuit motifs.
- Keep the premium silver/chrome style on dark background for README, splash, and documentation visuals.
- Do not add third-party vendor logos or trademarks into the project logo.
- For Windows application icons, derive `.ico` files from the approved logo/icon artwork.

## Current validated baseline

Validated on Windows customer test machine:

```text
Health      OK
TestWacs    OK - path/file validation only
RenewWacs   OK - wacs.exe --renew --baseuri completed with returncode 0
Service     OK - RUNNING
Startup     AUTO_START
Host        pythonservice.exe via pywin32
Policy      OK - skip when Palo Alto certificate is above threshold
```

## Baseline

This repository starts from the clean rebuild baseline formerly tracked as **PA-LE Service v3.4-clean**.

Baseline principles:

- Single clean embedded Python worker plus PowerShell wrapper
- Step-by-step setup wizard
- `Debug` as a separate action
- Optional `Import if certificate does not exist on Palo Alto`
- Optional `Block Private Key Export on Palo Alto import`
- Uninstall asks whether to remove ProgramData
- Windows Event Log plus file log
- Real Windows service host based on pywin32 `ServiceFramework`
- Windows service is installed with `python certguard_windows_service.py install/start`
- Do not create the service by pointing `sc.exe binPath` directly to `python certguard_agent.py service-loop`
- Standalone release generated from repository source, not patched old zip files
- Current logo/icon design must be preserved in future UI/package work

## Python Windows service rule

Do not use this model:

```text
sc.exe create CertGuard-PA binPath= "python C:\ProgramData\CertGuard-PA\certguard_agent.py service-loop"
```

Correct model, aligned with the working Cloudflare-DDNS-Windows project:

```text
certguard_windows_service.py
  win32serviceutil.ServiceFramework
  SvcDoRun
  SvcStop
  main_loop
  win32event.WaitForSingleObject

InstallSilent
  deploy embedded files
  ensure pywin32
  python certguard_windows_service.py install
  sc.exe config CertGuard-PA start= auto
  sc.exe failure ...
  python certguard_windows_service.py start
```

Expected service configuration:

```text
STATE            : RUNNING
START_TYPE       : AUTO_START
BINARY_PATH_NAME : "C:\Program Files\Python314\pythonservice.exe"
```

## win-acme behavior

`TestWacs` is intentionally a safe path/file validation only. It does not run `wacs.exe --verbose`.

```text
TestWacs:
- verifies win-acme path is configured
- verifies wacs.exe exists
- records file name and file size
- does not start renewal
```

`RenewWacs` performs the real win-acme renewal command:

```powershell
wacs.exe --renew --baseuri "https://acme-v02.api.letsencrypt.org/"
```

The Python subprocess wrapper captures output as bytes, merges stdout/stderr, and decodes safely to avoid Windows codepage errors.

## Repository layout

```text
installer/
  Install-CertGuard-PA.ps1      # main installer and service wrapper
src/
  certguard_agent.py            # raw Python worker source
  certguard_windows_service.py  # pywin32 Windows Service host
  certguard_gui_qt.py           # primary PySide6 GUI
  certguard_gui.py              # legacy tkinter fallback
  certguard_eventlog.py         # Windows Event Log helper
  certguard_secrets.py          # DPAPI secret helper
tools/
  Build-StandaloneRelease.ps1   # generates standalone installer into releases/
  Apply-WacsSubprocessHotfix-v2.ps1 # idempotent WACS subprocess/path-test hotfix
docs/
  BRANDING.md                   # logo and visual identity notes
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
.\tools\Apply-WacsSubprocessHotfix-v2.ps1
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
Base: PA-LE Service v3.4-clean -> CertGuard-PA v1 validated baseline
Active workstream: feature/qt-gui-polish
Protected areas:
- Do not patch old generated zip packages as source.
- Do not reintroduce direct sc.exe -> python script service-loop model.
- Keep pywin32 ServiceFramework / pythonservice.exe Windows service model.
- Keep WACS Test as path validation only.
- Keep RenewWacs as real renewal action.
- Keep DPAPI-backed secret storage.
- Keep standalone build generated from repository source.
- Preserve current logo/icon design.
```
