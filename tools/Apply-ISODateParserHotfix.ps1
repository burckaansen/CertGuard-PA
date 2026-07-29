# ASCII only
# Applies only the ISO-8601 datetime parser fix to CertGuard-PA source.
# Safe to run multiple times.

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Targets = @(
    (Join-Path $RepoRoot "src\certguard_agent.py"),
    "C:\ProgramData\CertGuard-PA\src\certguard_agent.py",
    "C:\Program Files\CertGuard-PA\src\certguard_agent.py"
) | Select-Object -Unique

$DateParserBlock = @'
def parse_datetime_guess(text):
    if not text:
        return None
    raw = str(text).strip().replace("  ", " ")

    # CertGuard stores parsed certificate dates as ISO-8601 strings.
    # Parse these first so compare_certificates can evaluate local_newer.
    try:
        iso_raw = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        parsed = datetime.fromisoformat(iso_raw)
        return cert_dt_to_utc(parsed)
    except Exception:
        pass

    for fmt in [
        "%b %d %H:%M:%S %Y GMT",
        "%b %d %H:%M:%S %Y",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d",
        "%Y-%m-%d",
    ]:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            pass
    try:
        return cert_dt_to_utc(parsedate_to_datetime(raw))
    except Exception:
        return None


'@

$Patched = $false

foreach ($Target in $Targets) {
    if (-not (Test-Path $Target)) {
        continue
    }

    $Text = Get-Content -Path $Target -Raw

    if ($Text -like "*datetime.fromisoformat(iso_raw)*") {
        Write-Host "[INFO] ISO datetime parser already patched: $Target"
        $Patched = $true
        continue
    }

    $Pattern = "(?s)def parse_datetime_guess\(text\):.*?(?=\r?\ndef normalize_fingerprint\()"
    if (-not [regex]::IsMatch($Text, $Pattern)) {
        throw "parse_datetime_guess function range was not found in $Target"
    }

    $Text = [regex]::Replace($Text, $Pattern, $DateParserBlock, 1)
    Set-Content -Path $Target -Value $Text -Encoding UTF8

    python -m py_compile $Target
    if ($LASTEXITCODE -ne 0) {
        throw "Python compile failed: $Target"
    }

    Write-Host "[INFO] ISO datetime parser patched: $Target"
    Write-Host "[INFO] Python compile OK: $Target"
    $Patched = $true
}

if (-not $Patched) {
    throw "No CertGuard-PA certguard_agent.py target was found."
}

Write-Host "[INFO] ISO datetime parser hotfix completed."
Write-Host "[INFO] Next: .\tools\Build-StandaloneRelease.ps1"
