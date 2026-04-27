# CertGuard-PA v1 Baseline Checklist

This checklist preserves all requirements from the working PA-LE v3.4-clean baseline and records the current source-of-truth state for CertGuard-PA.

Status legend:

- [x] Implemented in repository
- [ ] Not implemented or needs verification/fix
- [~] Implemented but needs polish, documentation update, or Windows validation

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
Base: PA-LE Service v3.4-clean -> CertGuard-PA v1 baseline
Active workstream: feature/qt-gui-polish
Protected areas:
- Do not patch old generated zip packages as source.
- Do not reintroduce pywin32 service model.
- Keep sc.exe service creation.
- Keep DPAPI-backed secret storage.
- Keep standalone build generated from repository source.
- Keep src/certguard_agent.py as the raw backend source of truth.
```

## Runtime architecture

- [x] Windows service uses `sc.exe`, not pywin32.
- [x] PowerShell wrapper installs, starts, stops, restarts and removes the service.
- [x] Python worker is the runtime engine.
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
- [x] Verify after import.
- [x] Retry support.
- [x] Optional commit after import.
- [x] State update after deploy.
- [x] Force deploy action exists.

## win-acme fallback

- [x] GUI collects `wacs.exe` path.
- [x] Config stores win-acme path/base URI/timeout.
- [x] Agent can run `wacs.exe --renew --baseuri ...` as fallback.
- [x] Agent exposes `test-wacs` and `renew-wacs` commands.
- [x] Installer exposes `TestWacs` and `RenewWacs` actions.
- [x] Policy can trigger win-acme renewal before deploy when local PFX is not newer.

## Logging

- [x] File log under `C:\ProgramData\CertGuard-PA\logs`.
- [x] Windows Application Event Log integration in agent runtime.
- [x] Event log source registration from installer.
- [x] Events for service start.
- [x] Events for health check success/failure.
- [x] Events for certificate checked.
- [x] Events for no import needed / deploy skipped.
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

## Uninstall

- [x] Uninstall asks whether to remove ProgramData.
- [x] Options include remove everything, keep config/state and remove runtime files, remove logs only, or keep everything.
- [x] Option exists to keep config/state while removing runtime files.

## Packaging

- [x] Build script creates distributable standalone installer package from source.
- [x] Standalone installer embeds Python runtime files as Base64.
- [x] Standalone installer includes Qt GUI, legacy GUI, event log module and secrets module.
- [x] Standalone installer can deploy embedded files into ProgramData.
- [x] Standalone action set matches the main installer action set.
- [ ] README and operations docs fully match current command names and standalone release flow.

## Current repository status

- Backend: complete for v1 baseline.
- Service layer: complete for v1 baseline.
- Installer: complete for v1 baseline.
- Standalone builder: complete for v1 baseline.
- Qt GUI: functional, approximately 85-90 percent complete; polish remains.

## Open items before v1.0 release

1. Polish Qt dashboard auto-refresh.
2. Add live service status polling in the dashboard/service page.
3. Add visible progress indicator while async commands are running.
4. Standardize error popups and validation messages.
5. Harden GUI validation for integer fields and required paths.
6. Update `README.md` and `docs/OPERATIONS.md` to match current action names:
   - `Compare`, not `CompareCert`
   - `Policy`, not `PolicyDeploy`
   - `Health`, `InspectPfx`, `ForceDeploy`, `RenewWacs` should be documented
7. Document standalone release generation and usage:
   - `tools/Build-StandaloneRelease.ps1`
   - `releases/Install-CertGuard-PA-Standalone.ps1`
8. Generate and test `releases/Install-CertGuard-PA-Standalone.ps1` on Windows.

## Next phase after v1.0

- Multi-firewall support.
- Central management web UI.
- Auto-update.
- Reporting.
- SaaS-style management option.
