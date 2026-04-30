# CertGuard-PA v1 Baseline Checklist

This checklist preserves all requirements from the working PA-LE v3.4-clean baseline and records the current source-of-truth state for CertGuard-PA.

Status legend:

- [x] Implemented and validated
- [ ] Not implemented or needs verification/fix
- [~] Implemented but needs polish or documentation refinement

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
Event Log   OK - pywin32 servicemanager model, CloudDNS-aligned
```

Expected Windows service configuration:

```text
STATE              : RUNNING
START_TYPE         : AUTO_START
BINARY_PATH_NAME   : "C:\Program Files\Python314\pythonservice.exe"
SERVICE_START_NAME : LocalSystem
```

## Branch model

Use this structure for future development conversations and repository work:

```text
main
  Stable baseline branch. Only verified clean structure should live here.

feature/qt-gui-polish
  Current active workstream for GUI polish and live UX improvements.

hotfix/<short-issue-name>
  Emergency bug fixes only. Merge back after validation.
```

Current conversation baseline:

```text
Base: PA-LE Service v3.4-clean -> CertGuard-PA v1 validated baseline
Active workstream: feature/qt-gui-polish
Protected areas:
- Do not patch old generated zip packages as source.
- Do not rely on runtime/source patch scripts for normal release builds.
- Do not reintroduce direct sc.exe -> python script service-loop model.
- Keep pywin32 ServiceFramework / pythonservice.exe Windows service model.
- Follow the Cloudflare-DDNS-Windows service pattern for Python Windows services.
- Keep Windows Event Log writing aligned with pywin32 servicemanager model.
- Do not reintroduce Write-EventLog, eventcreate, or custom EventMessageFile registry mapping.
- Keep WACS Test as path/file validation only.
- Keep RenewWacs as the real win-acme renewal action.
- Keep DPAPI-backed secret storage.
- Keep standalone build generated from repository source.
- Keep src/certguard_agent.py as the raw backend source of truth.
- Preserve current logo/icon design.
```

## Runtime architecture

- [x] Python worker is the backend runtime engine.
- [x] Real Windows service host exists as `src/certguard_windows_service.py`.
- [x] Windows service uses pywin32 `win32serviceutil.ServiceFramework`.
- [x] Windows service runs through `pythonservice.exe`.
- [x] Service install/start follows the working Cloudflare-DDNS-Windows pattern.
- [x] Direct `sc.exe -> python certguard_agent.py service-loop` service model is prohibited.
- [x] PowerShell wrapper deploys, installs, starts, stops, restarts and removes the service.
- [x] `sc.exe` is still used for service config, failure actions, query/status and cleanup.
- [x] Installer can deploy all required runtime files into `C:\ProgramData\CertGuard-PA`.
- [x] Runtime paths use `C:\ProgramData\CertGuard-PA` for config, state, logs and deployed scripts.

## Setup and GUI

- [x] Primary GUI exists as `src/certguard_gui_qt.py` using PySide6.
- [x] Legacy tkinter GUI remains available as fallback only.
- [x] Dark theme and sidebar navigation are implemented.
- [x] Dashboard page exists with health, policy, deploy and service cards.
- [x] Setup/config pages collect configuration step-by-step.
- [x] Wizard/layout is designed for lower-resolution Windows test machines.
- [x] PFX path can be selected with a file picker.
- [x] win-acme `wacs.exe` path can be selected with a file picker.
- [x] Final/dashboard/operations flow includes an Install Service action through `InstallSilent`.
- [x] Deploy action is available from dashboard and operations pages.
- [x] Installation/action output is visible in the GUI log panel.
- [x] Debug is available as a separate installer action.
- [x] Debug-related workflow is available from GUI operations/log flow.
- [~] Dashboard card refresh is partial; full auto-refresh/live polling still needs polish.
- [~] Service status live check still needs polish.
- [~] Progress indicator still needs polish.
- [~] Error popup standardization still needs polish.
- [~] GUI input validation still needs polish.

## Branding and assets

- [x] Primary logo concept is approved.
- [x] README references the committed logo asset.
- [x] Branding guide exists as `docs/BRANDING.md`.
- [x] Canonical SVG logo asset exists as `docs/assets/certguard-pa-logo.svg`.
- [x] Logo direction is protected: premium chrome/silver shield, certificate, checkmark/seal, circuit cues.
- [x] Future Windows `.ico` assets should be derived from the approved logo/icon artwork.

## Configuration and secrets

- [x] Config is stored under `C:\ProgramData\CertGuard-PA\config.json`.
- [x] State is stored under `C:\ProgramData\CertGuard-PA\state.json`.
- [x] Palo Alto API key is not stored as plaintext in the production build when saved through GUI.
- [x] PFX password is not stored as plaintext in the production build when saved through GUI.
- [x] Secrets are protected with Windows DPAPI machine scope.
- [x] Backward compatibility exists for old plaintext config keys.
- [x] Secure config write removes plaintext secret keys before writing config.

## Certificate intelligence

- [x] Local PFX parsing.
- [x] PFX password/corruption error separation.
- [x] Local certificate fingerprint extraction.
- [x] Local certificate expiry calculation.
- [x] SAN/CN extraction.
- [x] Wildcard and expected-domain match.
- [x] Palo Alto API connectivity test.
- [x] Palo Alto certificate lookup by name.
- [x] Palo Alto certificate expiry extraction.
- [x] Local vs Palo Alto compare engine.

## Policy

- [x] Same fingerprint -> skip.
- [x] Local newer/different logic.
- [x] Expiry threshold logic.
- [x] Domain mismatch -> block.
- [x] Palo Alto cert missing -> optional first import.
- [x] Clear JSON policy decision output.
- [x] `import_if_pa_cert_missing` policy option exists.
- [x] `block_on_domain_mismatch` policy option exists.
- [x] `auto_import_only_if_expiring` policy option exists.
- [x] `auto_import_expiry_threshold_days` policy option exists.
- [x] `require_local_newer_or_different` policy option exists.
- [x] `use_win_acme_fallback` policy option exists.

## Deployment

- [x] PFX import to Palo Alto.
- [x] Optional block private key export during Palo Alto import.
- [x] Verify after import.
- [x] Retry support.
- [x] Optional commit after import.
- [x] State update after deploy.
- [x] Force deploy action exists.

## win-acme fallback

- [x] GUI collects `wacs.exe` path.
- [x] Config stores win-acme path/base URI/timeout.
- [x] `TestWacs` is path/file validation only and does not run `wacs.exe --verbose`.
- [x] `RenewWacs` runs the real renewal command: `wacs.exe --renew --baseuri ...`.
- [x] Agent exposes `test-wacs` and `renew-wacs` commands.
- [x] Installer exposes `TestWacs` and `RenewWacs` actions.
- [x] Safe subprocess capture is built directly into `src/certguard_agent.py`.
- [x] No external hotfix/source patch script is required for normal builds.
- [x] Policy can trigger win-acme renewal before deploy when local PFX is not newer.

## Logging

- [x] File log under `C:\ProgramData\CertGuard-PA\logs`.
- [x] Windows Application Event Log integration in agent runtime.
- [x] Windows Event Log writer uses pywin32 `servicemanager`, aligned with Cloudflare-DDNS-Windows.
- [x] Windows Event Log messages include `[CertGuard-PA]` prefix.
- [x] Windows Event Log messages include structured `EVENT=<name>` details.
- [x] No `Write-EventLog` runtime writer.
- [x] No `eventcreate` runtime writer.
- [x] No custom `EventMessageFile` registry mapping.
- [x] Events for service start.
- [x] Events for service stop.
- [x] Events for health check success/failure.
- [x] Events for certificate checked.
- [x] Events for comparison summary.
- [x] Events for no certificate change required.
- [x] Events for certificate import required.
- [x] Events for import needed / deploy attempt.
- [x] Events for import success.
- [x] Events for import failure.
- [x] Events for commit submitted.
- [x] GUI log panel displays command output.

## Service behavior

- [x] Interval-based service loop exists.
- [x] Default service interval is 3600 seconds.
- [x] Service tick runs health -> policy -> deploy when needed.
- [x] Service failure actions restart the service three times using `sc.exe failure`.
- [x] Service starts automatically after installation.
- [x] Service verified as `RUNNING` on Windows customer test machine.
- [x] Service verified with `AUTO_START`.
- [x] Service verified with `pythonservice.exe` host.

## Uninstall

- [x] Uninstall asks whether to remove ProgramData.
- [x] Options include remove everything, keep config/state and remove runtime files, remove logs only, or keep everything.
- [x] Option exists to keep config/state while removing runtime files.
- [x] Deletion-pending Windows service state is documented in operations notes.

## Packaging

- [x] Build script creates distributable standalone installer package from source.
- [x] Build script is the only required release generation step.
- [x] Standalone installer embeds Python runtime files as Base64.
- [x] Standalone installer includes backend, pywin32 service host, Qt GUI, legacy GUI, event log module and secrets module.
- [x] Standalone installer can deploy embedded files into ProgramData.
- [x] Standalone action set matches the main installer action set.
- [x] README matches current baseline and release flow.
- [x] Branding documentation exists.
- [x] Operations document matches final service/WACS/Event Log/release behavior.
- [ ] Versioned standalone release file should be generated and hashed before publishing.

## Current repository status

- Backend: complete for v1 baseline.
- Service layer: complete and Windows validated for v1 baseline.
- Installer: complete and Windows validated for v1 baseline.
- Standalone builder: complete for v1 baseline.
- Build flow: normalized; no external hotfix/source patch script required.
- Event Log: complete and aligned with CloudDNS pywin32 servicemanager model.
- Branding: primary logo and branding guide are present.
- Qt GUI: functional, approximately 85-90 percent complete; polish remains.

## Open items before v1.0 release

1. Generate versioned standalone release file:
   - `releases/CertGuard-PA-v1.0.0-Standalone.ps1`
2. Record SHA256 hash of the versioned release file.
3. Optional: export PNG logo render to `docs/assets/certguard-pa-logo.png`.
4. Optional GUI polish items can move to post-v1:
   - dashboard auto-refresh
   - live service status polling
   - visible progress indicator
   - standardized error popups
   - stricter GUI input validation

## Next phase after v1.0

- Multi-firewall support.
- Central management web UI.
- Auto-update.
- Reporting.
- SaaS-style management option.
