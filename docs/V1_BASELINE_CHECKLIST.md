# CertGuard-PA v1 Baseline Checklist

This checklist preserves all requirements from the working PA-LE v3.4-clean baseline.

Status legend:

- [x] Implemented in repository
- [ ] Not implemented or needs verification/fix

## Runtime architecture

- [x] Windows service uses `sc.exe`, not pywin32.
- [x] PowerShell wrapper installs, starts, stops, restarts and removes the service.
- [x] Python worker is the runtime engine.
- [x] Installer can deploy all required runtime files into `C:\ProgramData\CertGuard-PA`.

## Setup and GUI

- [x] Setup wizard collects configuration step-by-step.
- [x] Wizard works on low-resolution Windows test machines.
- [x] PFX path can be selected with a file picker.
- [ ] win-acme `wacs.exe` path can be selected with a file picker.
- [ ] Final wizard page has an Install Service button.
- [x] Final wizard page has a Deploy button.
- [x] Installation/action output is visible to the user.
- [x] Debug is available as a separate action.
- [x] Debug folder is available from GUI.

## Configuration and secrets

- [x] Config is stored under `C:\ProgramData\CertGuard-PA\config.json`.
- [x] State is stored under `C:\ProgramData\CertGuard-PA\state.json`.
- [x] Palo Alto API key is not stored as plaintext in the production build when saved through GUI.
- [x] PFX password is not stored as plaintext in the production build when saved through GUI.
- [x] Secrets are protected with Windows DPAPI machine scope.
- [x] Backward compatibility exists for old plaintext config keys.

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

## Deployment

- [x] PFX import to Palo Alto.
- [x] Verify after import.
- [x] Retry support.
- [x] Optional commit after import.
- [x] State update after deploy.

## win-acme fallback

- [ ] GUI collects `wacs.exe` path.
- [ ] Config stores win-acme path/base URI/timeout.
- [ ] Agent can run `wacs.exe --renew --baseuri ...` as fallback.
- [ ] Policy can trigger win-acme renewal before deploy when local PFX is not newer.

## Logging

- [x] File log under `C:\ProgramData\CertGuard-PA\logs`.
- [x] Windows Application Event Log integration in agent runtime.
- [x] Event log source registration from installer.
- [x] Events for service start.
- [ ] Events for health check.
- [x] Events for certificate checked.
- [x] Events for no import needed / deploy skipped.
- [x] Events for import needed / deploy attempt.
- [x] Events for import success.
- [x] Events for import failure.
- [x] Events for commit submitted.

## Uninstall

- [x] Uninstall asks whether to remove ProgramData.
- [x] Options include remove all, keep everything, and remove logs only.
- [x] Option exists to keep config/state while removing runtime files.

## Packaging

- [x] Build script creates distributable standalone installer package from source.
- [x] Standalone installer embeds Python runtime files as Base64.
- [x] Standalone installer can deploy embedded files into ProgramData.
- [ ] README and operations docs match current commands.

## Open items before v1.0 release

1. Add win-acme fallback support back into the clean architecture.
2. Add an Install Service button/action to the final GUI page, or clearly document that service installation is done through `-Action InstallSilent` / `-Action Repair`.
3. Add explicit health-check command and Event Log entry.
4. Update README and `docs/OPERATIONS.md` to match the current action names and standalone release flow.
5. Generate and test `releases/Install-CertGuard-PA-Standalone.ps1` on Windows.
