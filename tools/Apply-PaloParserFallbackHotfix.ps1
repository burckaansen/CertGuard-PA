# ASCII only
# Applies robust Palo Alto certificate parser hotfix to CertGuard-PA source.
# The Palo operational response is a text certificate database, not structured
# certificate XML. Multiple records may share the same CN, so the parser must
# match the exact db-name and then disambiguate by certificate serial number.
# Also fixes ISO-8601 parsing so local_newer is calculated correctly.

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

$ParserBlock = @'
def normalize_serial(value):
    normalized = re.sub(r"[^A-Fa-f0-9]", "", str(value or "")).upper()
    normalized = normalized.lstrip("0")
    return normalized or "0"


def parse_pa_certificate_db_records(result_text):
    text = str(result_text or "").replace("\r\n", "\n")
    header_pattern = re.compile(r"(?m)^([A-Fa-f0-9]+:[A-Fa-f0-9]+)\s*$")
    matches = list(header_pattern.finditer(text))
    records = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[start:end].strip()
        fields = {}
        for line in block.splitlines()[1:]:
            field_match = re.match(r"\s*([A-Za-z0-9_-]+):\s*(.*)$", line)
            if field_match:
                fields[field_match.group(1).lower()] = field_match.group(2).strip()
        expiry_match = re.search(r"db-exp-date:\s*\d{12}Z\(([^)]+)\)", block, re.IGNORECASE)
        records.append({
            "record_key": match.group(1),
            "block": block,
            "db_name": fields.get("db-name", ""),
            "db_serialno": fields.get("db-serialno", ""),
            "db_status": fields.get("db-status", ""),
            "issuer": fields.get("issuer", ""),
            "expiry_raw": expiry_match.group(1).strip() if expiry_match else "",
        })
    return records


def select_pa_certificate_db_record(records, cert_name, preferred_serials):
    expected_names = {
        f"/CN={cert_name}".lower(),
        cert_name.lower(),
    }
    candidates = [
        record for record in records
        if (record.get("db_name") or "").strip().lower() in expected_names
    ]
    if not candidates:
        return None, "not_found"

    preferred = [normalize_serial(value) for value in preferred_serials if value]
    for serial in preferred:
        matches = [
            record for record in candidates
            if normalize_serial(record.get("db_serialno")) == serial
        ]
        if len(matches) == 1:
            return matches[0], "serial_match"

    if len(candidates) == 1:
        return candidates[0], "single_cn_match"

    return None, "ambiguous_cn"


def inspect_pa_certificate():
    config = load_config()
    cert_name = (config.get("certificate_name") or "").strip()
    root, _ = palo_op(config, "<show><sslmgr-store><config-certificate-info></config-certificate-info></sslmgr-store></show>")
    result_text = root.findtext(".//result", default="")
    records = parse_pa_certificate_db_records(result_text)

    local_serial = ""
    try:
        local_info = inspect_pfx(
            config.get("pfx_path", ""),
            get_pfx_password(config),
            config.get("expected_domain", ""),
        )
        local_serial = local_info.get("serial_number_hex", "")
    except Exception as exc:
        log(f"Local PFX serial was unavailable during Palo inspection: {exc}", "WARN", 332)

    state = load_state()
    previous_remote = state.get("last_pa_certificate_inspection", {})
    previous_serial = previous_remote.get("serial_number_hex", "")

    record, match_mode = select_pa_certificate_db_record(
        records,
        cert_name,
        [previous_serial, local_serial],
    )

    if record is None:
        if match_mode == "ambiguous_cn":
            log(f"Multiple Palo Alto certificate DB records have CN={cert_name}; no trusted serial match was available", "ERROR", 333)
            raise PaloApiError(f"Multiple Palo Alto certificates share CN={cert_name}; serial match is required")
        log(f"Certificate not found on Palo Alto: {cert_name}", "WARN", 330)
        raise PaloCertificateNotFound(f"Certificate not found on Palo Alto: {cert_name}")

    expiry_raw = record.get("expiry_raw", "")
    expiry_dt = parse_datetime_guess(expiry_raw)
    if expiry_dt is None:
        raise PaloApiError(f"Palo Alto certificate expiry could not be parsed for {cert_name}")

    serial_number = record.get("db_serialno", "")
    result = {
        "certificate_name": cert_name,
        "found": True,
        "not_after_raw": expiry_raw,
        "not_after_utc": expiry_dt.isoformat(),
        "days_left": int((expiry_dt - datetime.now(timezone.utc)).total_seconds() // 86400),
        "fingerprint_sha256": "",
        "serial_number_hex": serial_number,
        "subject": record.get("db_name", ""),
        "issuer": record.get("issuer", ""),
        "db_status": record.get("db_status", ""),
        "record_key": record.get("record_key", ""),
        "parser": "op_db_record_serial_match",
        "match_mode": match_mode,
    }
    state["last_pa_certificate_inspection"] = result
    state["last_pa_certificate_inspection_time"] = utc_now_text()
    save_state(state)
    log(
        f"Palo Alto certificate inspected: name={cert_name} days_left={result['days_left']} "
        f"parser={result['parser']} match_mode={match_mode} serial={serial_number}",
        "INFO",
        331,
    )
    return result


'@

function Replace-FunctionRange {
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

    $Text = Replace-FunctionRange `
        -Text $Text `
        -StartPattern "def parse_datetime_guess\(text\):" `
        -EndPattern "\r?\ndef normalize_fingerprint\(" `
        -Replacement $DateParserBlock

    $StartPatterns = @(
        "def normalize_serial\(value\):",
        "def xpath_literal\(value\):",
        "def inspect_pa_certificate\(\):"
    )

    $StartPattern = $null
    foreach ($Candidate in $StartPatterns) {
        if ([regex]::IsMatch($Text, $Candidate)) {
            $StartPattern = $Candidate
            break
        }
    }

    if (-not $StartPattern) {
        throw "Palo parser start function was not found in $Target"
    }

    $Text = Replace-FunctionRange `
        -Text $Text `
        -StartPattern $StartPattern `
        -EndPattern "\r?\ndef compare_certificates\(\):" `
        -Replacement $ParserBlock

    Set-Content -Path $Target -Value $Text -Encoding UTF8
    Write-Host "[INFO] Patched: $Target"
    python -m py_compile $Target
    if ($LASTEXITCODE -ne 0) {
        throw "Python compile failed: $Target"
    }
    Write-Host "[INFO] Python compile OK: $Target"
    $Patched = $true
}

if (-not $Patched) {
    throw "No CertGuard-PA certguard_agent.py target was patched."
}

Write-Host "[INFO] Palo parser and ISO datetime hotfix completed."
Write-Host "[INFO] Next: .\tools\Build-StandaloneRelease.ps1"
