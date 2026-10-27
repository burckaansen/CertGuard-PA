# ASCII only
# Ensures scheduled service ticks enter the win-acme renewal fallback path
# when policy returns "not newer" or "expired".
# Safe to run multiple times.

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Targets = @(
    (Join-Path $RepoRoot "src\certguard_agent.py"),
    "C:\ProgramData\CertGuard-PA\certguard_agent.py",
    "C:\Program Files\CertGuard-PA\certguard_agent.py"
) | Select-Object -Unique

$ServiceTickBlock = @'
def service_tick():
    log("Service tick executed", "INFO", 301)
    try:
        health_check()
        result = policy_decision()
        decision = result["decision"]
        action = decision["action"]
        reason = decision.get("reason", "")
        log(f"Policy tick completed: action={action}", "INFO", 302)

        if decision.get("should_import"):
            log(
                f"Certificate import required by scheduled service tick: {reason or 'policy matched'}",
                "WARN",
                354,
            )
            deploy_certificate(force=False)
            return

        config = load_config()
        use_wacs = bool(config.get("policy", {}).get("use_win_acme_fallback", True))
        reason_lower = reason.lower()
        renewal_needed = "not newer" in reason_lower or "expired" in reason_lower

        if use_wacs and renewal_needed:
            log(
                f"Scheduled renewal fallback required: {reason}",
                "WARN",
                355,
            )
            deploy_certificate(force=False)
    except Exception as exc:
        log(f"Policy tick failed: {exc}", "ERROR", 303)


'@

$Patched = $false

foreach ($Target in $Targets) {
    if (-not (Test-Path $Target)) {
        continue
    }

    $Text = Get-Content -Path $Target -Raw

    if ($Text -like "*Scheduled renewal fallback required:*") {
        Write-Host "[INFO] Scheduled renewal hotfix already present: $Target"
        $Patched = $true
        continue
    }

    $Pattern = "(?s)def service_tick\(\):.*?(?=\r?\ndef service_loop\(\):)"
    if (-not [regex]::IsMatch($Text, $Pattern)) {
        throw "service_tick function range was not found in $Target"
    }

    $Text = [regex]::Replace($Text, $Pattern, $ServiceTickBlock, 1)
    Set-Content -Path $Target -Value $Text -Encoding UTF8

    python -m py_compile $Target
    if ($LASTEXITCODE -ne 0) {
        throw "Python compile failed: $Target"
    }

    Write-Host "[INFO] Scheduled renewal hotfix patched: $Target"
    Write-Host "[INFO] Python compile OK: $Target"
    $Patched = $true
}

if (-not $Patched) {
    throw "No CertGuard-PA certguard_agent.py target was found."
}

Write-Host "[INFO] Scheduled renewal hotfix completed."
Write-Host "[INFO] Next: .\tools\Build-StandaloneRelease.ps1"
