# Operations Guide

## Palo Alto API key

```text
https://<PA-HOST>/api/?type=keygen&user=<USERNAME>&password=<PASSWORD>
```

Copy the value inside `<key>...</key>`.

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

Important: after any fix in the installer or builder template, regenerate the standalone script. Do not reuse an older generated standalone file.

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

## Policy logic

- Import if the Palo Alto certificate is missing and `import_if_pa_cert_missing` is enabled.
- Block import if expected-domain mismatch is detected and `block_on_domain_mismatch` is enabled.
- Import only when the Palo Alto certificate is expiring if `auto_import_only_if_expiring` is enabled.
- Require the local certificate to be newer or different if `require_local_newer_or_different` is enabled.
- Optionally run win-acme renewal before deployment if the local certificate is not newer and `use_win_acme_fallback` is enabled.

## Runtime paths

```text
C:\ProgramData\CertGuard-PA\config.json
C:\ProgramData\CertGuard-PA\state.json
C:\ProgramData\CertGuard-PA\logs\certguard-pa.log
```

## Windows Event Log

```text
Windows Logs > Application
Source: CertGuard-PA
```

## Service behavior

- Service name: `CertGuard-PA`
- Display name: `CertGuard-PA Certificate Monitor`
- Service creation model: `sc.exe`
- Startup type: automatic
- Failure actions: restart on failure, three attempts
- Runtime loop: health -> policy -> deploy when needed

## Uninstall cleanup options

`-Action Uninstall` removes the Windows service first and then asks what to do with ProgramData:

```text
1 - Remove everything: config, state, logs and runtime files
2 - Keep config/state, remove runtime files only
3 - Remove logs only
4 - Keep everything
```
