# Changelog

All notable changes to CertGuard-PA will be documented in this file.

## [1.0.0] - 2026-04-30

### Added

- Initial validated v1 baseline for CertGuard-PA.
- Windows service package for Palo Alto certificate lifecycle monitoring.
- pywin32 `ServiceFramework` service host using `pythonservice.exe`.
- Standalone release builder that embeds source files into a single PowerShell installer.
- PySide6 primary GUI and legacy tkinter fallback GUI.
- DPAPI machine-scope secret storage for Palo Alto API key and PFX password.
- Local PFX inspection with certificate expiry, SAN/CN and fingerprint extraction.
- Palo Alto API connectivity test and certificate inspection.
- Policy engine for certificate comparison, expiry threshold and first import behavior.
- Palo Alto PFX import with optional private key export blocking.
- Optional commit after certificate import.
- win-acme fallback integration with safe `RenewWacs` execution.
- Safe `TestWacs` path/file validation that does not run `wacs.exe --verbose`.
- Windows Application Event Log integration aligned with the Cloudflare-DDNS-Windows pywin32 servicemanager model.
- Structured Event Log messages using `[CertGuard-PA] EVENT=<name> STATUS=<status> ...` format.
- File log under `C:\ProgramData\CertGuard-PA\logs\certguard-pa.log`.
- Branding assets and premium chrome/silver project logo.

### Changed

- Removed runtime/source hotfix dependency from the normal release flow.
- Moved WACS subprocess safety fixes directly into `src/certguard_agent.py`.
- Replaced earlier Event Log attempts using `Write-EventLog`, `eventcreate` and custom EventMessageFile mapping with pywin32 `servicemanager` logging.
- Aligned Python Windows service behavior with the working Cloudflare-DDNS-Windows pattern.

### Validated

- Health check completed successfully.
- TestWacs validates configured `wacs.exe` path and file metadata.
- RenewWacs runs `wacs.exe --renew --baseuri` and returns success.
- Windows service runs as `AUTO_START` through `pythonservice.exe`.
- Policy correctly skips deployment when Palo Alto certificate is above threshold.
- Event Log entries are written cleanly through pywin32 servicemanager.

### Known limitations / post-v1 polish

- GUI dashboard auto-refresh still needs polish.
- Live service status polling still needs polish.
- Visible progress indicator still needs polish.
- Error popup standardization still needs polish.
- GUI input validation can be stricter.
