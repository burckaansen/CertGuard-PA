# CertGuard-PA v1.0.0 Release Notes

## Release identity

```text
Product      : CertGuard-PA
Version      : 1.0.0
Platform     : Windows Server / Windows 10 / Windows 11
Runtime      : Python 3.x
Service host : pywin32 pythonservice.exe
Release type : Standalone PowerShell installer
Status       : Validated baseline
```

## Release artifact

Expected versioned artifact:

```text
releases\CertGuard-PA-v1.0.0-Standalone.ps1
```

SHA256:

```text
8FB6B2ED66720ED24EFF9876FBF19AF780AE7FF9A3EB5E48561B8FA3E2EE3149
```

## What is included

- Windows service-based certificate lifecycle monitoring.
- Palo Alto API connectivity and certificate inspection.
- Local PFX certificate inspection.
- Certificate comparison and policy decision engine.
- Optional first import if the certificate is missing on Palo Alto.
- Optional import only when Palo Alto certificate is below expiry threshold.
- Optional block private key export on Palo Alto import.
- Optional commit after certificate import.
- win-acme fallback renewal support.
- Safe WACS test behavior that validates path/file only.
- DPAPI-backed secret storage for sensitive values.
- PySide6 GUI and legacy tkinter fallback GUI.
- Windows Application Event Log support through pywin32 servicemanager.
- Detailed file logging under ProgramData.

## Validated baseline

Validated on Windows customer test machine:

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

## Windows service model

The service uses the same pattern validated in Cloudflare-DDNS-Windows:

```text
win32serviceutil.ServiceFramework
SvcDoRun
SvcStop
main_loop
win32event.WaitForSingleObject
pythonservice.exe
```

Do not use the old direct `sc.exe -> python script service-loop` model.

## Event Log model

CertGuard-PA uses pywin32 `servicemanager` for Windows Application Event Log writing.

```text
No Write-EventLog runtime writer
No eventcreate runtime writer
No custom EventMessageFile registry mapping
Message prefix: [CertGuard-PA]
Structured field: EVENT=<name>
```

Recommended query:

```powershell
Get-EventLog -LogName Application -Newest 50 |
  Where-Object { $_.Message -like "*[CertGuard-PA]*" } |
  Select-Object TimeGenerated, Source, EntryType, EventID, Message |
  Format-List
```

## WACS model

`TestWacs` is intentionally safe and does not run `wacs.exe --verbose`.

`RenewWacs` runs:

```powershell
wacs.exe --renew --baseuri "https://acme-v02.api.letsencrypt.org/"
```

The subprocess wrapper captures bytes, merges stdout/stderr and decodes safely for Windows codepages.

## Known post-v1 polish

The following items can move to a post-v1 GUI polish branch:

- Dashboard auto-refresh.
- Live service status polling.
- Visible progress indicator.
- Standardized error popups.
- Stricter GUI input validation.

## Release validation commands

Run as Administrator after producing the standalone release:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\releases\CertGuard-PA-v1.0.0-Standalone.ps1 -Action Health
.\releases\CertGuard-PA-v1.0.0-Standalone.ps1 -Action TestWacs
.\releases\CertGuard-PA-v1.0.0-Standalone.ps1 -Action RenewWacs
.\releases\CertGuard-PA-v1.0.0-Standalone.ps1 -Action Status
sc.exe qc CertGuard-PA
```
