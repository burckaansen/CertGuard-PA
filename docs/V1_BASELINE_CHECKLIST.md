# CertGuard-PA v1 Baseline Checklist

This checklist preserves all requirements from the working PA-LE v3.4-clean baseline.

## Runtime architecture

- [ ] Windows service uses `sc.exe`, not pywin32.
- [ ] PowerShell wrapper installs, starts, stops, restarts and removes the service.
- [ ] Python worker is the runtime engine.
- [ ] Installer can deploy all required runtime files into `C:\ProgramData\CertGuard-PA`.

## Setup and GUI

- [ ] Setup wizard collects configuration step-by-step.
- [ ] Wizard works on low-resolution Windows test machines.
- [ ] PFX path can be selected with a file picker.
- [ ] win-acme `wacs.exe` path can be selected with a file picker.
- [ ] Final wizard page has an Install/Deploy button.
- [ ] Installation output is visible to the user.
- [ ] Debug is available as a separate action and from GUI.

## Configuration and secrets

- [ ] Config is stored under `C:\ProgramData\CertGuard-PA\config.json`.
- [ ] State is stored under `C:\ProgramData\CertGuard-PA\state.json`.
- [ ] Palo Alto API key is not stored as plaintext in the production build.
- [ ] PFX password is not stored as plaintext in the production build.
- [ ] Secrets are protected with Windows DPAPI machine scope.

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

## Logging

- [x] File log under `C:\ProgramData\CertGuard-PA\logs`.
- [ ] Windows Application Event Log integration in agent runtime.
- [ ] Event log source registration from installer.
- [ ] Events for: service start, health check, cert checked, no import needed, import needed, import success, import failure, commit submitted.

## Uninstall

- [ ] Uninstall asks whether to remove ProgramData.
- [ ] Options: remove all, keep all, remove logs only.

## Packaging

- [ ] Build script creates distributable installer package from source.
- [ ] README and operations docs match current commands.
