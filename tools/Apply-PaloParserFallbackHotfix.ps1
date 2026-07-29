# ASCII only
# Applies robust Palo Alto certificate parser hotfix to CertGuard-PA source.
# Model:
# 1. Try exact config API XPath and parse the PEM certificate locally.
# 2. Only if that fails, use a narrow XML parser fallback.
# 3. Never read dates from a broad multi-certificate XML block.

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Targets = @(
    (Join-Path $RepoRoot "src\certguard_agent.py"),
    "C:\ProgramData\CertGuard-PA\src\certguard_agent.py",
    "C:\Program Files\CertGuard-PA\src\certguard_agent.py"
) | Select-Object -Unique

$FindFunction = @'
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

    # Narrow fallback only. Do not accept large multi-certificate blocks.
    name_lower = certificate_name.strip().lower()
    fallback_candidates = []
    for element in root.iter():
        xml = element_xml(element)
        xml_lower = xml.lower()
        if name_lower not in xml_lower:
            continue
        if len(xml) > 6000:
            continue
        expiry_raw = extract_pa_date_from_element(element)
        if parse_datetime_guess(expiry_raw):
            fallback_candidates.append(element)

    if fallback_candidates:
        return sorted(fallback_candidates, key=lambda item: len(element_xml(item)))[0]

    return None


'@

$InspectBlock = @'
def xpath_literal(value):
    value = str(value)
    if "'" not in value:
        return "'" + value + "'"
    if '"' not in value:
        return '"' + value + '"'
    raise PaloApiError("certificate_name contains unsupported quote characters")


def palo_config_get(config, xpath):
    xml_text = palo_request(config, {"type": "config", "action": "get", "xpath": xpath})
    return parse_palo_response(xml_text), xml_text


def extract_pem_certificate_from_root(root):
    for element in root.iter():
        if local_tag(element) == "certificate":
            value = element_text(element)
            if "BEGIN CERTIFICATE" in value:
                return value
    return ""


def inspect_palo_pem_certificate(config, cert_name):
    require_crypto()
    literal = xpath_literal(cert_name)
    xpaths = [
        f"/config/shared/certificate/entry[@name={literal}]",
        f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/certificate/entry[@name={literal}]",
        f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys2']/certificate/entry[@name={literal}]",
    ]
    last_error = ""
    for xpath in xpaths:
        try:
            root, _ = palo_config_get(config, xpath)
            pem = extract_pem_certificate_from_root(root)
            if not pem:
                continue
            cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
            try:
                not_after = cert_dt_to_utc(cert.not_valid_after_utc)
            except AttributeError:
                not_after = cert_dt_to_utc(cert.not_valid_after)
            return {
                "certificate_name": cert_name,
                "found": True,
                "not_after_raw": not_after.strftime("%b %d %H:%M:%S %Y GMT") if not_after else "",
                "not_after_utc": not_after.isoformat() if not_after else "",
                "days_left": int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400) if not_after else None,
                "fingerprint_sha256": format_fingerprint(cert.fingerprint(hashes.SHA256())),
                "serial_number_hex": format(cert.serial_number, "X"),
                "subject": cert.subject.rfc4514_string(),
                "parser": "config_api_pem",
                "xpath": xpath,
            }
        except Exception as exc:
            last_error = str(exc)
            continue
    if last_error:
        log(f"Config API PEM inspection did not find certificate by exact XPath: {last_error}", "WARN", 332)
    return None


def inspect_pa_certificate():
    config = load_config()
    cert_name = config.get("certificate_name", "")

    config_result = inspect_palo_pem_certificate(config, cert_name)
    if config_result is not None:
        state = load_state()
        state["last_pa_certificate_inspection"] = config_result
        state["last_pa_certificate_inspection_time"] = utc_now_text()
        save_state(state)
        log(f"Palo Alto certificate inspected: name={cert_name} days_left={config_result['days_left']} parser={config_result['parser']}", "INFO", 331)
        return config_result

    root, _ = palo_op(config, "<show><sslmgr-store><config-certificate-info></config-certificate-info></sslmgr-store></show>")
    cert_element = find_pa_cert_element(root, cert_name)
    if cert_element is None:
        log(f"Certificate not found on Palo Alto: {cert_name}", "WARN", 330)
        raise PaloCertificateNotFound(f"Certificate not found on Palo Alto: {cert_name}")
    expiry_raw = extract_pa_date_from_element(cert_element)
    expiry_dt = parse_datetime_guess(expiry_raw)
    result = {
        "certificate_name": cert_name,
        "found": True,
        "not_after_raw": expiry_raw,
        "not_after_utc": expiry_dt.isoformat() if expiry_dt else "",
        "days_left": int((expiry_dt - datetime.now(timezone.utc)).total_seconds() // 86400) if expiry_dt else None,
        "fingerprint_sha256": extract_pa_fingerprint_from_element(cert_element),
        "serial_number_hex": extract_pa_serial_from_element(cert_element),
        "subject": extract_pa_subject_from_element(cert_element),
        "parser": "op_xml_narrow_fallback",
    }
    state = load_state()
    state["last_pa_certificate_inspection"] = result
    state["last_pa_certificate_inspection_time"] = utc_now_text()
    save_state(state)
    log(f"Palo Alto certificate inspected: name={cert_name} days_left={result['days_left']} parser={result['parser']}", "INFO", 331)
    return result


'@

function Replace-FunctionBlock {
    param(
        [Parameter(Mandatory=$true)][string]$Text,
        [Parameter(Mandatory=$true)][string]$StartPattern,
        [Parameter(Mandatory=$true)][string]$EndPattern,
        [Parameter(Mandatory=$true)][string]$Replacement
    )
    $Pattern = "(?s)$StartPattern.*?(?=$EndPattern)"
    $NewText = [regex]::Replace($Text, $Pattern, $Replacement, 1)
    if ($NewText -eq $Text) {
        throw "Replacement failed for pattern: $StartPattern"
    }
    return $NewText
}

$Patched = $false

foreach ($Target in $Targets) {
    if (-not (Test-Path $Target)) {
        continue
    }

    $Text = Get-Content -Path $Target -Raw

    $Text = Replace-FunctionBlock `
        -Text $Text `
        -StartPattern "def find_pa_cert_element\(root, certificate_name\):" `
        -EndPattern "\r?\ndef first_child_text\(" `
        -Replacement $FindFunction

    $Text = Replace-FunctionBlock `
        -Text $Text `
        -StartPattern "def inspect_pa_certificate\(\):" `
        -EndPattern "\r?\ndef compare_certificates\(\):" `
        -Replacement $InspectBlock

    Set-Content -Path $Target -Value $Text -Encoding UTF8
    Write-Host "[INFO] Patched: $Target"
    $Patched = $true

    python -m py_compile $Target
    Write-Host "[INFO] Python compile OK: $Target"
}

if (-not $Patched) {
    throw "No CertGuard-PA certguard_agent.py target was patched."
}

Write-Host "[INFO] Palo parser hotfix completed."
Write-Host "[INFO] Next: .\tools\Build-StandaloneRelease.ps1"
