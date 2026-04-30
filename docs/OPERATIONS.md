# CertGuard-PA Operations Guide

## Purpose

CertGuard-PA monitors the local win-acme PFX output, compares it with the certificate installed on Palo Alto, and imports the certificate only when policy conditions are met.

Validated v1 baseline:

```text
Health      OK
TestWacs    OK - path/file validation only
RenewWacs   OK - wacs.exe --renew --baseuri completed with returncode 0
Service     OK - RUNNING
Startup     AUTO_START
Host        pythonservice.exe via pywin32
Policy      OK - skip when Palo Alto certificate is above threshold
Event Log   OK - pywin32 servicemanager model, CloudDNS-aligned
```

## Palo Alto API key

Open this URL in a browser or call it from a secure admin workstation:

```text
https://<PA-HOST>/api/?type=keygen&user=<USERNAME>&password=<PASSWORD>
```

Copy the value inside `<key>...</key>` and store it through the CertGuard-PA GUI so it is protected with DPAPI.

## Basic GUI flow

1. Configure win-acme and verify that the PFX file is generated.
2. Run the CertGuard-PA setup GUI.
3. Configure Palo Alto host, API key, certificate name, expected FQDN and PFX path.
4. Configure policy options.
5. Save the configuration.
6. Run `Health`.
7. Run `TestApi`.
8. Run `TestWacs` if win-acme fallback is enabled.
9. Run `Compare`.
10. Run `Policy`.
11. Run `Deploy` when the policy decision is correct.
12. Install the Windows service with `InstallSilent` or the GUI Install Service action.

## Main installer

Run PowerShell as Administrator from the repository root:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer\Install-CertGuard-PA.ps1 -Action Install
```

## Standalone release build

Run from the repository root:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\tools\Build-StandaloneRelease.ps1
```

Generated output:

```text
releases\Install-CertGuard-PA-Standalone.ps1
```

Run the generated standalone installer as Administrator:

```powershell
.\releases\Install-CertGuard-PA-Standalone.ps1 -Action Install
```

Important: after any fix in the installer, builder template, GUI, service host or backend source, regenerate the standalone script. Do not reuse an older generated standalone file.

## Versioned release file

Recommended v1.0.0 release copy:

```powershell
Copy-Item `
  ".\releases\Install-CertGuard-PA-Standalone.ps1" `
  ".\releases\CertGuard-PA-v1.0.0-Standalone.ps1" `
  -Force

Get-FileHash ".\releases\CertGuard-PA-v1.0.0-Standalone.ps1" -Algorithm SHA256
```

Record the SHA256 hash in the release notes before publishing.

## Post-build validation commands

Run as Administrator:

```powershell
.\releases\Install-CertGuard-PA-Standalone.ps1 -Action Health
.\releases\Install-CertGuard-PA-Standalone.ps1 -Action TestWacs
.\releases\Install-CertGuard-PA-Standalone.ps1 -Action RenewWacs
.\releases\Install-CertGuard-PA-Standalone.ps1 -Action Status
sc.exe qc CertGuard-PA
```

Expected service state:

```text
STATE              : 4  RUNNING
START_TYPE         : 2  AUTO_START
BINARY_PATH_NAME   : "C:\Program Files\Python314\pythonservice.exe"
SERVICE_START_NAME : LocalSystem
```

## Supported actions

```powershell
.\installer\Install-CertGuard-PA.ps1 -Action Install
.\installer\Install-CertGuard-PA.ps1 -Action InstallSilent
.\installer\Install-CertGuard-PA.ps1 -Action Gui
.\installer\Install-CertGuard-PA.ps1 -Action GuiLegacy
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
.\installer\Install-CertGuard-PA.ps1 -Action Start
.\installer\Install-CertGuard-PA.ps1 -Action Stop
.\installer\Install-CertGuard-PA.ps1 -Action Restart
.\installer\Install-CertGuard-PA.ps1 -Action Repair
.\installer\Install-CertGuard-PA.ps1 -Action Uninstall
```

The generated standalone installer supports the same action names.

## Python Windows service model

Correct model:

```text
certguard_windows_service.py
  win32serviceutil.ServiceFramework
  SvcDoRun
  SvcStop
  main_loop
  win32event.WaitForSingleObject
```

The service is installed by pywin32 and runs through:

```text
C:\Program Files\Python314\pythonservice.exe
```

Do not create the service by pointing `sc.exe binPath` directly to a Python script.

Wrong model:

```text
sc.exe create CertGuard-PA binPath= "python C:\ProgramData\CertGuard-PA\certguard_agent.py service-loop"
```

`sc.exe` is still used for service configuration, status checks, failure actions and cleanup, but not as the runtime host for the Python script.

## Service behavior

- Service name: `CertGuard-PA`
- Display name: `CertGuard-PA Certificate Monitor`
- Service host: pywin32 `pythonservice.exe`
- Startup type: automatic
- Failure actions: restart on failure, three attempts
- Runtime loop: health -> policy -> deploy when needed
- Default interval: 3600 seconds

## win-acme behavior

`TestWacs` is intentionally safe and does not run `wacs.exe --verbose`.

```text
TestWacs:
- verifies win-acme path is configured
- verifies wacs.exe exists
- records file name and file size
- does not start renewal
```

`RenewWacs` performs the real renewal command:

```powershell
wacs.exe --renew --baseuri "https://acme-v02.api.letsencrypt.org/"
```

WACS output is captured as bytes, stdout/stderr are merged, and output is decoded safely to avoid Windows codepage errors.

## Policy logic

- Import if the Palo Alto certificate is missing and `import_if_pa_cert_missing` is enabled.
- Block import if expected-domain mismatch is detected and `block_on_domain_mismatch` is enabled.
- Import only when the Palo Alto certificate is expiring if `auto_import_only_if_expiring` is enabled.
- Require the local certificate to be newer or different if `require_local_newer_or_different` is enabled.
- Optionally run win-acme renewal before deployment if the local certificate is not newer and `use_win_acme_fallback` is enabled.
- Optionally block private key export during Palo Alto import with `block_private_key_export_on_import`.
- Optionally commit after import.
- Optionally verify after import.

## Runtime paths

```text
C:\ProgramData\CertGuard-PA\config.json
C:\ProgramData\CertGuard-PA\state.json
C:\ProgramData\CertGuard-PA\logs\certguard-pa.log
C:\ProgramData\CertGuard-PA\logs\certguard-pa-eventlog-error.log
```

Secrets are protected with Windows DPAPI machine scope when saved through the GUI.

## Windows Event Log

Final v1 Event Log model is aligned with the working Cloudflare-DDNS-Windows project.

```text
Windows Logs > Application
Writer: pywin32 servicemanager
Message prefix: [CertGuard-PA]
Detailed event name: EVENT=<name>
```

CertGuard-PA does not use these anymore:

```text
Write-EventLog
EventCreate.exe
eventcreate CLI
custom EventMessageFile registry mapping
custom Windows message DLL
```

Recommended query:

```powershell
Get-EventLog -LogName Application -Newest 50 |
  Where-Object { $_.Message -like "*[CertGuard-PA]*" } |
  Select-Object TimeGenerated, Source, EntryType, EventID, Message |
  Format-List
```

Typical no-change event:

```text
[CertGuard-PA] EVENT=NoCertificateChangeRequired STATUS=OK ORIGINAL_EVENT_ID=351 MESSAGE=No certificate change required: Palo Alto certificate has 155 days left; threshold is 7
```

Typical certificate comparison event:

```text
[CertGuard-PA] EVENT=CertificateComparisonSummary STATUS=OK ORIGINAL_EVENT_ID=341 MESSAGE=Certificate comparison summary: local_days_left=83 remote_days_left=155 remote_found=True same_fingerprint=False
```

Typical import-required event:

```text
[CertGuard-PA] EVENT=CertificateImportRequired STATUS=WARN ORIGINAL_EVENT_ID=353 MESSAGE=Certificate import required: Palo Alto certificate is missing and first import is enabled
```

The detailed operational event name is carried in the message instead of relying on custom Windows Event IDs. The file log remains the authoritative detailed runtime log.

## Service deletion-pending state

Windows SCM can keep a deleted service in `marked for deletion` state while an MMC snap-in, Services console, Event Viewer, PowerShell session, or process still holds a service handle.

Symptoms:

```text
DeleteService FAILED 1072: The specified service has been marked for deletion.
Error installing service: The specified service has been marked for deletion. (1072)
```

Recommended cleanup:

```powershell
sc.exe stop CertGuard-PA
sc.exe delete CertGuard-PA
```

Then close all Services/Event Viewer/MMC windows and any old PowerShell windows that interacted with the service. Open a new elevated PowerShell window and retry install/repair. If the service remains deletion-pending, reboot the machine.

## Uninstall cleanup options

`-Action Uninstall` removes the Windows service first and then asks what to do with ProgramData:

```text
1 - Remove everything: config, state, logs and runtime files
2 - Keep config/state, remove runtime files only
3 - Remove logs only
4 - Keep everything
```
