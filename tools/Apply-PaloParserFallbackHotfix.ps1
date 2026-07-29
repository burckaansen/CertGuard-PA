# ASCII only
# Applies safe Palo Alto certificate parser fallback hotfix to CertGuard-PA source.
# This is idempotent and intended for systems that already pulled the XML-entry parser fix.

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Targets = @(
    (Join-Path $RepoRoot "src\certguard_agent.py"),
    "C:\ProgramData\CertGuard-PA\src\certguard_agent.py",
    "C:\Program Files\CertGuard-PA\src\certguard_agent.py"
) | Select-Object -Unique

$Old = @'
def find_pa_cert_element(root, certificate_name):
    if not certificate_name:
        raise PaloApiError("certificate_name is required")
    candidates = []
    for element in root.iter():
        if element_contains_exact_cert_name(element, certificate_name):
            tag = local_tag(element)
            if tag == "entry":
                return element
            candidates.append(element)
    if candidates:
        return sorted(candidates, key=lambda item: len(element_xml(item)))[0]
    return None
'@

$New = @'
def find_pa_cert_element(root, certificate_name):
    if not certificate_name:
        raise PaloApiError("certificate_name is required")

    exact_candidates = []
    for element in root.iter():
        if element_contains_exact_cert_name(element, certificate_name):
            tag = local_tag(element)
            if tag == "entry":
                return element
            exact_candidates.append(element)

    if exact_candidates:
        return sorted(exact_candidates, key=lambda item: len(element_xml(item)))[0]

    # Safe fallback:
    # Palo can return the certificate name inside nested text instead of an entry name.
    # Search only for the smallest XML element containing the exact certificate name,
    # then require that the same element also contains a parseable expiry date.
    name_lower = certificate_name.strip().lower()
    fallback_candidates = []
    for element in root.iter():
        xml = element_xml(element)
        if name_lower in xml.lower():
            expiry_raw = extract_pa_date_from_element(element)
            if parse_datetime_guess(expiry_raw):
                fallback_candidates.append(element)

    if fallback_candidates:
        return sorted(fallback_candidates, key=lambda item: len(element_xml(item)))[0]

    return None
'@

$Patched = $false

foreach ($Target in $Targets) {
    if (-not (Test-Path $Target)) {
        continue
    }

    $Text = Get-Content -Path $Target -Raw

    if ($Text -like "*Safe fallback:*") {
        Write-Host "[INFO] Already patched: $Target"
        $Patched = $true
        continue
    }

    if ($Text -notlike "*def find_pa_cert_element(root, certificate_name):*") {
        Write-Host "[WARN] Parser function not found, skipping: $Target"
        continue
    }

    if ($Text -notlike "*$Old*") {
        throw "Expected parser block was not found in $Target. Source may differ; inspect manually."
    }

    $Text = $Text.Replace($Old, $New)
    Set-Content -Path $Target -Value $Text -Encoding UTF8
    Write-Host "[INFO] Patched: $Target"
    $Patched = $true

    try {
        python -m py_compile $Target
        Write-Host "[INFO] Python compile OK: $Target"
    } catch {
        throw "Python compile failed for $Target : $_"
    }
}

if (-not $Patched) {
    throw "No CertGuard-PA certguard_agent.py target was patched."
}

Write-Host "[INFO] Palo parser fallback hotfix completed."
Write-Host "[INFO] Next: .\tools\Build-StandaloneRelease.ps1"
