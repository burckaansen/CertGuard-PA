#!/usr/bin/env python3
# ASCII only

import argparse
import json
import logging
import re
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
import warnings
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from xml.etree import ElementTree as ET

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtensionOID, NameOID
except Exception:
    x509 = None
    hashes = None
    pkcs12 = None
    ExtensionOID = None
    NameOID = None

try:
    from certguard_eventlog import write_event
except Exception:
    def write_event(message, level="INFO", event_id=255):
        return None

try:
    from certguard_secrets import get_secret
except Exception:
    def get_secret(config, plaintext_key, dpapi_key):
        return config.get(plaintext_key, "")

APP_NAME = "CertGuard-PA"
BASE_DIR = Path(r"C:\ProgramData\CertGuard-PA")
CONFIG_PATH = BASE_DIR / "config.json"
STATE_PATH = BASE_DIR / "state.json"
LOG_PATH = BASE_DIR / "logs" / "certguard-pa.log"
MANAGED_WACS_PATH = BASE_DIR / "win-acme" / "wacs.exe"

DEFAULT_CONFIG = {
    "firewall_host": "",
    "palo_api_key": "",
    "palo_api_key_dpapi": "",
    "skip_tls_validation": True,
    "certificate_name": "",
    "pfx_path": "",
    "pfx_password": "",
    "pfx_password_dpapi": "",
    "cloudflare_api_token": "",
    "cloudflare_api_token_dpapi": "",
    "cloudflare_zone": "",
    "expected_domain": "",
    "commit_after_import": False,
    "policy": {
        "import_if_pa_cert_missing": True,
        "block_on_domain_mismatch": True,
        "auto_import_only_if_expiring": True,
        "auto_import_expiry_threshold_days": 7,
        "require_local_newer_or_different": True,
        "use_win_acme_fallback": True,
        "block_private_key_export_on_import": True
    },
    "deploy": {
        "retry_count": 3,
        "retry_delay_seconds": 5,
        "verify_after_import": True
    },
    "win_acme": {
        "path": r"C:\ProgramData\CertGuard-PA\win-acme\wacs.exe",
        "base_uri": "https://acme-v02.api.letsencrypt.org/",
        "renew_timeout_seconds": 900
    },
    "service": {
        "interval_seconds": 3600
    }
}

class CertGuardError(Exception):
    pass

class DependencyError(CertGuardError):
    pass

class PfxParseError(CertGuardError):
    pass

class PfxPasswordError(PfxParseError):
    pass

class PaloApiError(CertGuardError):
    pass

class PaloCertificateNotFound(PaloApiError):
    pass


def ensure_dirs():
    (BASE_DIR / "logs").mkdir(parents=True, exist_ok=True)


def setup_logging():
    ensure_dirs()
    if logging.getLogger().handlers:
        return
    logging.basicConfig(filename=str(LOG_PATH), level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def log(message, level="INFO", event_id=255, event=True):
    setup_logging()
    print(f"{level}: {message}")
    if level == "ERROR":
        logging.error(message)
    elif level == "WARN":
        logging.warning(message)
    else:
        logging.info(message)
    if event:
        write_event(message, level, event_id)


def deep_merge(base, override):
    result = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config():
    if not CONFIG_PATH.exists():
        return DEFAULT_CONFIG.copy()
    return deep_merge(DEFAULT_CONFIG, json.loads(CONFIG_PATH.read_text(encoding="utf-8")))


def load_state():
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state):
    ensure_dirs()
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def utc_now_text():
    return datetime.now(timezone.utc).isoformat()


def cert_dt_to_utc(value):
    if value is None:
        return None
    if getattr(value, "tzinfo", None) is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_datetime_guess(text):
    if not text:
        return None
    raw = str(text).strip().replace("  ", " ")
    for fmt in ["%b %d %H:%M:%S %Y GMT", "%b %d %H:%M:%S %Y", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d", "%Y-%m-%d"]:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            pass
    try:
        return cert_dt_to_utc(parsedate_to_datetime(raw))
    except Exception:
        return None


def normalize_fingerprint(value):
    return (value or "").replace(":", "").replace(" ", "").upper()


def format_fingerprint(raw_bytes):
    return ":".join(f"{b:02X}" for b in raw_bytes)


def require_crypto():
    if pkcs12 is None or hashes is None or x509 is None:
        raise DependencyError("Python package 'cryptography' is required")


def wildcard_match(pattern, hostname):
    pattern = (pattern or "").lower().strip()
    hostname = (hostname or "").lower().strip()
    if not pattern or not hostname:
        return False
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")
    return False


def domain_matches_certificate(expected_domain, common_name, san_dns_names):
    expected_domain = (expected_domain or "").lower().strip()
    if not expected_domain:
        return True
    names = san_dns_names or ([common_name] if common_name else [])
    return any(wildcard_match(name, expected_domain) for name in names)


def get_common_name(cert):
    try:
        values = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return values[0].value if values else ""
    except Exception:
        return ""


def get_san_dns_names(cert):
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        return []


def get_pfx_password(config):
    return get_secret(config, "pfx_password", "pfx_password_dpapi")


def get_palo_api_key(config):
    return get_secret(config, "palo_api_key", "palo_api_key_dpapi")


def get_cloudflare_api_token(config):
    return get_secret(config, "cloudflare_api_token", "cloudflare_api_token_dpapi")


def inspect_pfx(pfx_path, password, expected_domain=""):
    require_crypto()
    pfx_file = Path(pfx_path)
    if not pfx_file.exists():
        raise FileNotFoundError(f"PFX file not found: {pfx_file}")
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="PKCS#12 bundle could not be parsed as DER.*", category=UserWarning)
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                pfx_file.read_bytes(),
                None if password is None else str(password).encode("utf-8"),
            )
    except ValueError as exc:
        raise PfxPasswordError("Unable to parse PFX. The file may be corrupt or the password may be incorrect.") from exc
    except Exception as exc:
        raise PfxParseError(f"Unable to parse PFX: {exc}") from exc
    if cert is None:
        raise PfxParseError("PFX does not contain a leaf certificate")
    try:
        not_before = cert_dt_to_utc(cert.not_valid_before_utc)
        not_after = cert_dt_to_utc(cert.not_valid_after_utc)
    except AttributeError:
        not_before = cert_dt_to_utc(cert.not_valid_before)
        not_after = cert_dt_to_utc(cert.not_valid_after)
    days_left = int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400) if not_after else None
    common_name = get_common_name(cert)
    san_dns_names = get_san_dns_names(cert)
    return {
        "pfx_path": str(pfx_file),
        "has_private_key": private_key is not None,
        "additional_cert_count": len(additional_certs or []),
        "fingerprint_sha256": format_fingerprint(cert.fingerprint(hashes.SHA256())),
        "serial_number_hex": format(cert.serial_number, "X"),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "common_name": common_name,
        "san_dns_names": san_dns_names,
        "not_before_utc": not_before.isoformat() if not_before else "",
        "not_after_utc": not_after.isoformat() if not_after else "",
        "days_left": days_left,
        "expected_domain": expected_domain,
        "domain_match": domain_matches_certificate(expected_domain, common_name, san_dns_names),
    }


def inspect_configured_pfx():
    config = load_config()
    result = inspect_pfx(config.get("pfx_path", ""), get_pfx_password(config), config.get("expected_domain", ""))
    state = load_state()
    state["last_pfx_inspection"] = result
    state["last_pfx_inspection_time"] = utc_now_text()
    save_state(state)
    log(f"Local PFX inspected: days_left={result.get('days_left')} domain_match={result.get('domain_match')}", "INFO", 310)
    return result


def ssl_context(skip_tls_validation):
    return ssl._create_unverified_context() if skip_tls_validation else ssl.create_default_context()


def palo_request(config, params, timeout=180):
    host = (config.get("firewall_host") or "").strip()
    key = get_palo_api_key(config).strip()
    if not host:
        raise PaloApiError("firewall_host is required")
    if not key:
        raise PaloApiError("palo_api_key is required")
    query = dict(params)
    query["key"] = key
    url = f"https://{host}/api/?{urllib.parse.urlencode(query)}"
    try:
        with urllib.request.urlopen(url, context=ssl_context(bool(config.get("skip_tls_validation", True))), timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except Exception as exc:
        raise PaloApiError(f"Palo Alto API request failed: {exc}") from exc


def palo_multipart_import(config, params, file_path, timeout=240):
    key = get_palo_api_key(config).strip()
    if not key:
        raise PaloApiError("palo_api_key is required")
    boundary = "----certguard-pa-" + uuid.uuid4().hex
    file_path = Path(file_path)
    body = bytearray()
    body.extend(f"--{boundary}\r\n".encode("ascii"))
    body.extend(f'Content-Disposition: form-data; name="file"; filename="{file_path.name}"\r\n'.encode("ascii"))
    body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
    body.extend(file_path.read_bytes())
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("ascii"))
    query = dict(params)
    query["key"] = key
    url = f"https://{config['firewall_host']}/api/?{urllib.parse.urlencode(query)}"
    request = urllib.request.Request(url=url, data=bytes(body), method="POST", headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "Content-Length": str(len(body))})
    try:
        with urllib.request.urlopen(request, context=ssl_context(bool(config.get("skip_tls_validation", True))), timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except Exception as exc:
        raise PaloApiError(f"Palo Alto import request failed: {exc}") from exc


def parse_palo_response(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise PaloApiError(f"Invalid XML response from Palo Alto: {exc}") from exc
    status = root.attrib.get("status", "")
    if status != "success":
        msg_node = root.find(".//msg")
        msg = msg_node.text.strip() if msg_node is not None and msg_node.text else ""
        raise PaloApiError(f"Palo Alto API returned status={status} {msg}".strip())
    return root


def palo_op(config, cmd_xml):
    xml_text = palo_request(config, {"type": "op", "cmd": cmd_xml})
    return parse_palo_response(xml_text), xml_text


def palo_commit(config):
    xml_text = palo_request(config, {"type": "commit", "cmd": "<commit></commit>"}, timeout=240)
    root = parse_palo_response(xml_text)
    job_node = root.find(".//job")
    job_id = job_node.text.strip() if job_node is not None and job_node.text else ""
    log(f"Commit request submitted job={job_id}", "INFO", 370)
    return {"submitted": True, "job_id": job_id}


def test_palo_api():
    config = load_config()
    root, _ = palo_op(config, "<show><system><info></info></system></show>")
    result = {"connected": True, "hostname": root.findtext(".//hostname", default="").strip(), "sw_version": root.findtext(".//sw-version", default="").strip()}
    state = load_state()
    state["last_pa_test"] = result
    state["last_pa_test_time"] = utc_now_text()
    save_state(state)
    log(f"Palo Alto API connected: hostname={result['hostname']} sw_version={result['sw_version']}", "INFO", 320)
    return result


def extract_first(patterns, text):
    for pattern in patterns:
        match = pattern.search(text or "")
        if match:
            return match.group(1).strip()
    return ""


def local_tag(element):
    return str(element.tag).split("}", 1)[-1].lower()


def element_text(element):
    if element is None or element.text is None:
        return ""
    return str(element.text).strip()


def element_xml(element):
    try:
        return ET.tostring(element, encoding="unicode", method="xml")
    except Exception:
        return ""


def text_matches_cert_name(value, cert_name):
    return (value or "").strip().lower() == (cert_name or "").strip().lower()


def element_contains_exact_cert_name(element, cert_name):
    if text_matches_cert_name(element.attrib.get("name", ""), cert_name):
        return True
    if text_matches_cert_name(element_text(element), cert_name):
        return True
    for child in list(element):
        if local_tag(child) in ["name", "certificate-name", "cert-name", "common-name", "cn"]:
            if text_matches_cert_name(element_text(child), cert_name):
                return True
    return False


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


def first_child_text(element, names):
    normalized = {name.lower() for name in names}
    for child in element.iter():
        if child is element:
            continue
        if local_tag(child) in normalized:
            value = element_text(child)
            if value:
                return value
    return ""


def extract_pa_date_from_element(element):
    date_fields = [
        "not-after", "not_after", "notafter",
        "not-valid-after", "not_valid_after",
        "valid-to", "valid_to", "validto",
        "expiry", "expires", "expire", "expiration",
    ]
    value = first_child_text(element, date_fields)
    if value:
        return value
    text = element_xml(element)
    return extract_first([
        re.compile(r"(?:not-after|not_after|notafter|not-valid-after|not_valid_after|expiry|expires|expire|expiration|valid-to|valid_to|validto)[^A-Za-z0-9]{0,30}([^<\r\n]+)", re.IGNORECASE),
        re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+GMT)"),
        re.compile(r"(\d{4}[/-]\d{2}[/-]\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)"),
    ], text)


def extract_pa_fingerprint_from_element(element):
    value = first_child_text(element, ["sha256", "sha-256", "fingerprint", "fingerprint-sha256", "fingerprint_sha256"])
    if value:
        return value
    return extract_first([re.compile(r"(?:sha256|sha-256|fingerprint)[^A-Fa-f0-9]*([A-Fa-f0-9:]{40,})", re.IGNORECASE)], element_xml(element))


def extract_pa_serial_from_element(element):
    value = first_child_text(element, ["serial", "serial-number", "serial_number"])
    if value:
        return value
    return extract_first([re.compile(r"(?:serial|serial-number|serial_number)[^A-Fa-f0-9]*([A-Fa-f0-9:]+)", re.IGNORECASE)], element_xml(element))


def extract_pa_subject_from_element(element):
    value = first_child_text(element, ["subject", "subject-name", "subject_name"])
    if value:
        return value
    return extract_first([re.compile(r"(?:subject|subject-name|subject_name)[^\r\n<]*[:=]\s*([^\r\n<]+)", re.IGNORECASE)], element_xml(element))


def inspect_pa_certificate():
    config = load_config()
    cert_name = config.get("certificate_name", "")
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
        "parser": "matched_xml_entry",
    }
    state = load_state()
    state["last_pa_certificate_inspection"] = result
    state["last_pa_certificate_inspection_time"] = utc_now_text()
    save_state(state)
    log(f"Palo Alto certificate inspected: name={cert_name} days_left={result['days_left']} parser={result['parser']}", "INFO", 331)
    return result


def compare_certificates():
    config = load_config()
    local = inspect_configured_pfx()
    try:
        remote = inspect_pa_certificate()
    except PaloCertificateNotFound as exc:
        remote = {"found": False, "error": str(exc), "certificate_name": config.get("certificate_name", "")}
    local_fp = normalize_fingerprint(local.get("fingerprint_sha256"))
    remote_fp = normalize_fingerprint(remote.get("fingerprint_sha256"))
    local_dt = parse_datetime_guess(local.get("not_after_utc"))
    remote_dt = parse_datetime_guess(remote.get("not_after_utc"))
    result = {
        "local": local,
        "remote": remote,
        "remote_found": bool(remote.get("found")),
        "same_fingerprint": bool(local_fp and remote_fp and local_fp == remote_fp),
        "local_newer": bool(local_dt and remote_dt and local_dt > remote_dt),
        "local_days_left": local.get("days_left"),
        "remote_days_left": remote.get("days_left"),
        "domain_match": bool(local.get("domain_match")),
    }
    state = load_state()
    state["last_compare"] = result
    state["last_compare_time"] = utc_now_text()
    save_state(state)
    log(f"Compare completed: remote_found={result['remote_found']} same={result['same_fingerprint']} local_newer={result['local_newer']} domain_match={result['domain_match']}", "INFO", 340)
    log(f"Certificate comparison summary: local_days_left={result.get('local_days_left')} remote_days_left={result.get('remote_days_left')} remote_found={result.get('remote_found')} same_fingerprint={result.get('same_fingerprint')}", "INFO", 341)
    return result


def decode_process_output(data):
    if not data:
        return ""
    for encoding in ["utf-8", "cp850", "cp1252"]:
        try:
            return data.decode(encoding, errors="replace")
        except Exception:
            pass
    return data.decode("utf-8", errors="replace")


def run_process_capture(args, timeout):
    proc = subprocess.run(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    return proc.returncode, decode_process_output(proc.stdout)


def get_wacs_path(config):
    if MANAGED_WACS_PATH.exists():
        return str(MANAGED_WACS_PATH)
    return (config.get("win_acme", {}).get("path") or "").strip()


def run_win_acme_renew():
    config = load_config()
    win_acme = config.get("win_acme", {})
    wacs_path = get_wacs_path(config)
    base_uri = win_acme.get("base_uri", "https://acme-v02.api.letsencrypt.org/")
    timeout = int(win_acme.get("renew_timeout_seconds", 900))
    if not wacs_path:
        raise CertGuardError("win-acme path is not configured")
    if not Path(wacs_path).exists():
        raise FileNotFoundError(f"wacs.exe not found: {wacs_path}")
    log("win-acme fallback renewal started", "WARN", 380)
    returncode, output = run_process_capture([wacs_path, "--renew", "--baseuri", base_uri], timeout)
    output = output[-6000:]
    state = load_state()
    state["last_wacs_renew_time"] = utc_now_text()
    state["last_wacs_renew_returncode"] = returncode
    state["last_wacs_renew_output"] = output
    save_state(state)
    if returncode != 0:
        log(f"win-acme fallback renewal failed: {output[-900:]}", "ERROR", 381)
        raise CertGuardError(f"win-acme renew failed with code {returncode}")
    log("win-acme fallback renewal completed successfully", "INFO", 382)
    return {"renewed": True, "returncode": returncode}


def test_cloudflare():
    config = load_config()
    token = get_cloudflare_api_token(config).strip()
    zone = (config.get("cloudflare_zone") or "").strip()
    if not token:
        raise CertGuardError("Cloudflare API token is not configured")
    if not zone:
        raise CertGuardError("cloudflare_zone is not configured")
    url = "https://api.cloudflare.com/client/v4/zones?" + urllib.parse.urlencode({"name": zone})
    request = urllib.request.Request(
        url=url,
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "CertGuard-PA/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        raise CertGuardError(f"Cloudflare API request failed: {exc}") from exc
    if not payload.get("success"):
        errors = payload.get("errors") or []
        raise CertGuardError(f"Cloudflare API rejected the token: {errors}")
    zones = payload.get("result") or []
    exact = [item for item in zones if str(item.get("name", "")).lower() == zone.lower()]
    if not exact:
        raise CertGuardError(f"Cloudflare zone not visible to token: {zone}")
    result = {
        "connected": True,
        "zone": zone,
        "zone_id": exact[0].get("id", ""),
        "status": exact[0].get("status", ""),
    }
    state = load_state()
    state["last_cloudflare_test"] = result
    state["last_cloudflare_test_time"] = utc_now_text()
    save_state(state)
    log(f"Cloudflare API connected: zone={zone} status={result['status']}", "INFO", 384)
    return result


def provision_win_acme_renewal():
    config = load_config()
    win_acme = config.get("win_acme", {})
    wacs_path = get_wacs_path(config)
    base_uri = win_acme.get("base_uri", "https://acme-v02.api.letsencrypt.org/")
    timeout = int(win_acme.get("renew_timeout_seconds", 900))
    domain = (config.get("expected_domain") or "").strip()
    pfx_path = Path(config.get("pfx_path", ""))
    token = get_cloudflare_api_token(config).strip()
    pfx_password = get_pfx_password(config)

    if not wacs_path:
        raise CertGuardError("win-acme path is not configured")
    if not Path(wacs_path).exists():
        raise FileNotFoundError(f"wacs.exe not found: {wacs_path}")
    if not domain:
        raise CertGuardError("expected_domain is required for WACS provisioning")
    if not token:
        raise CertGuardError("Cloudflare API token is not configured")
    if not pfx_password:
        raise CertGuardError("PFX password is not configured")
    if not pfx_path.parent:
        raise CertGuardError("PFX path is invalid")

    pfx_path.parent.mkdir(parents=True, exist_ok=True)

    args = [
        wacs_path,
        "--source", "manual",
        "--host", domain,
        "--validation", "cloudflare",
        "--cloudflareapitoken", token,
        "--order", "single",
        "--csr", "rsa",
        "--store", "pfxfile",
        "--pfxfilepath", str(pfx_path.parent),
        "--pfxfilename", pfx_path.stem,
        "--pfxpassword", str(pfx_password),
        "--installation", "none",
        "--baseuri", base_uri,
        "--accepttos",
        "--notaskscheduler",
    ]

    log(f"Provisioning win-acme renewal for {domain} using Cloudflare DNS-01", "WARN", 385)
    returncode, output = run_process_capture(args, timeout)
    output = output[-12000:]
    state = load_state()
    state["last_wacs_provision_time"] = utc_now_text()
    state["last_wacs_provision_returncode"] = returncode
    state["last_wacs_provision_output"] = output
    save_state(state)
    if returncode != 0:
        log(f"win-acme renewal provisioning failed: {output[-1200:]}", "ERROR", 386)
        raise CertGuardError(f"win-acme provisioning failed with code {returncode}")
    log("win-acme renewal provisioned successfully; Task Scheduler creation was disabled", "INFO", 387)
    return {
        "provisioned": True,
        "returncode": returncode,
        "domain": domain,
        "pfx_path": str(pfx_path),
        "task_scheduler_disabled": True,
    }


def test_win_acme():
    config = load_config()
    wacs_path = get_wacs_path(config)
    if not wacs_path:
        raise CertGuardError("win-acme path is not configured")
    path_obj = Path(wacs_path)
    if not path_obj.exists():
        raise FileNotFoundError(f"wacs.exe not found: {wacs_path}")
    result = {
        "exists": True,
        "path": str(path_obj),
        "file_name": path_obj.name,
        "size_bytes": path_obj.stat().st_size,
        "note": "Path check only. Use renew-wacs for actual win-acme renewal."
    }
    state = load_state()
    state["last_wacs_test"] = result
    state["last_wacs_test_time"] = utc_now_text()
    save_state(state)
    log("win-acme path test completed", "INFO", 383)
    return result


def evaluate_policy(compare_result):
    policy = load_config().get("policy", {})
    reasons = []
    local_days_left = compare_result.get("local_days_left")
    if local_days_left is not None and local_days_left < 0:
        return {"action": "skip", "should_import": False, "reason": f"Local PFX certificate is expired ({local_days_left} days left); run renew-wacs before import"}
    if policy.get("block_on_domain_mismatch", True) and not compare_result.get("domain_match", False):
        return {"action": "block", "should_import": False, "reason": "Local PFX certificate does not match expected domain"}
    if not compare_result.get("remote_found", False):
        if policy.get("import_if_pa_cert_missing", True):
            return {"action": "import", "should_import": True, "reason": "Palo Alto certificate is missing and first import is enabled"}
        return {"action": "skip", "should_import": False, "reason": "Palo Alto certificate is missing and first import is disabled"}
    if policy.get("require_local_newer_or_different", True):
        if compare_result.get("same_fingerprint", False):
            return {"action": "skip", "should_import": False, "reason": "Local and Palo Alto certificates have the same fingerprint"}
        if not compare_result.get("local_newer", False):
            reasons.append("local certificate is not newer")
    if policy.get("auto_import_only_if_expiring", True):
        threshold = int(policy.get("auto_import_expiry_threshold_days", 7))
        remote_days_left = compare_result.get("remote_days_left")
        if remote_days_left is None:
            return {"action": "skip", "should_import": False, "reason": "Palo Alto certificate expiry could not be determined"}
        if remote_days_left > threshold:
            return {"action": "skip", "should_import": False, "reason": f"Palo Alto certificate has {remote_days_left} days left; threshold is {threshold}"}
    if reasons:
        return {"action": "skip", "should_import": False, "reason": "; ".join(reasons)}
    return {"action": "import", "should_import": True, "reason": "Policy matched"}


def policy_decision():
    compare_result = compare_certificates()
    decision = evaluate_policy(compare_result)
    result = {"compare": compare_result, "decision": decision}
    state = load_state()
    state["last_policy_decision"] = result
    state["last_policy_decision_time"] = utc_now_text()
    save_state(state)
    level = "WARN" if decision["action"] in ["import", "block"] else "INFO"
    log(f"Policy decision: action={decision['action']} reason={decision['reason']}", level, 350)
    if decision.get("should_import"):
        log(f"Certificate import required: {decision.get('reason', 'policy matched')}", "WARN", 353)
    else:
        log(f"No certificate change required: {decision.get('reason', 'policy skipped')}", "INFO", 351)
    return result


def import_certificate_once():
    config = load_config()
    policy = config.get("policy", {})
    block_private_key_export = bool(policy.get("block_private_key_export_on_import", True))
    local = inspect_configured_pfx()
    params = {
        "type": "import",
        "category": "keypair",
        "certificate-name": config.get("certificate_name", ""),
        "format": "pkcs12",
        "passphrase": get_pfx_password(config),
    }
    if block_private_key_export:
        params["block-private-key"] = "yes"
    xml_text = palo_multipart_import(config, params, Path(config.get("pfx_path", "")))
    parse_palo_response(xml_text)
    log(f"Certificate import completed: {config.get('certificate_name')} block_private_key_export={block_private_key_export}", "INFO", 360)
    return {"imported": True, "local_fingerprint_sha256": local.get("fingerprint_sha256"), "block_private_key_export": block_private_key_export}


def verify_import(expected_fingerprint):
    try:
        remote = inspect_pa_certificate()
    except PaloCertificateNotFound:
        return {"verified": False, "reason": "certificate not found after import"}
    expected = normalize_fingerprint(expected_fingerprint)
    actual = normalize_fingerprint(remote.get("fingerprint_sha256"))
    if expected and actual and expected == actual:
        return {"verified": True, "reason": "fingerprint matched", "remote": remote}
    if not actual:
        return {"verified": True, "reason": "certificate found but Palo fingerprint was not available", "remote": remote}
    return {"verified": False, "reason": "fingerprint mismatch", "remote": remote}


def deploy_certificate(force=False):
    config = load_config()
    state = load_state()
    deploy_config = config.get("deploy", {})
    retry_count = int(deploy_config.get("retry_count", 3))
    retry_delay = int(deploy_config.get("retry_delay_seconds", 5))
    verify_after_import = bool(deploy_config.get("verify_after_import", True))
    decision_result = policy_decision()
    decision = decision_result.get("decision", {})
    if not force and not decision.get("should_import", False):
        reason_text = decision.get("reason", "").lower()
        if config.get("policy", {}).get("use_win_acme_fallback", True) and ("not newer" in reason_text or "expired" in reason_text):
            run_win_acme_renew()
            decision_result = policy_decision()
            decision = decision_result.get("decision", {})
        if not decision.get("should_import", False):
            result = {"deployed": False, "skipped": True, "reason": decision.get("reason", "policy skipped")}
            state["last_deploy"] = result
            state["last_deploy_time"] = utc_now_text()
            save_state(state)
            log(f"Deploy skipped: {result['reason']}", "INFO", 351)
            return result
    last_error = ""
    for attempt in range(1, retry_count + 1):
        try:
            log(f"Deployment attempt {attempt}/{retry_count}", "WARN", 352)
            import_result = import_certificate_once()
            verify_result = {"verified": True, "reason": "verification disabled"}
            if verify_after_import:
                verify_result = verify_import(import_result.get("local_fingerprint_sha256"))
                if not verify_result.get("verified"):
                    raise PaloApiError(f"Import verification failed: {verify_result.get('reason')}")
            commit_result = {"submitted": False, "reason": "commit disabled"}
            if bool(config.get("commit_after_import", False)):
                commit_result = palo_commit(config)
            result = {"deployed": True, "skipped": False, "attempt": attempt, "import": import_result, "verify": verify_result, "commit": commit_result}
            state["last_deploy"] = result
            state["last_deploy_time"] = utc_now_text()
            state["last_deploy_error"] = ""
            save_state(state)
            log("Deployment completed successfully", "INFO", 361)
            return result
        except Exception as exc:
            last_error = str(exc)
            log(f"Deployment attempt {attempt} failed: {last_error}", "ERROR", 362)
            if attempt < retry_count:
                time.sleep(retry_delay)
    state["last_deploy"] = {"deployed": False, "skipped": False, "error": last_error}
    state["last_deploy_time"] = utc_now_text()
    state["last_deploy_error"] = last_error
    save_state(state)
    raise CertGuardError(f"Deployment failed after {retry_count} attempts: {last_error}")


def health_check():
    issues = []
    config = load_config()
    if not config.get("firewall_host"):
        issues.append("firewall_host missing")
    if not get_palo_api_key(config):
        issues.append("palo_api_key missing")
    if not config.get("certificate_name"):
        issues.append("certificate_name missing")
    if not config.get("pfx_path") or not Path(config.get("pfx_path", "")).exists():
        issues.append("pfx_path missing or not found")
    if not get_pfx_password(config):
        issues.append("pfx_password missing")
    if config.get("policy", {}).get("use_win_acme_fallback", True):
        if not get_cloudflare_api_token(config):
            issues.append("cloudflare_api_token missing")
        if not config.get("cloudflare_zone"):
            issues.append("cloudflare_zone missing")
    result = {"ok": not issues, "issues": issues, "time": utc_now_text()}
    state = load_state()
    state["last_health_check"] = result
    save_state(state)
    if issues:
        log("Health check failed: " + "; ".join(issues), "ERROR", 305)
    else:
        log("Health check completed successfully", "INFO", 306)
    return result


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

        # deploy_certificate() owns the win-acme fallback path. A scheduled tick
        # must still enter it when the local certificate is not newer/has
        # expired, otherwise renewal is never attempted and the service can
        # watch both certificates expire while repeatedly returning action=skip.
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


def service_loop():
    setup_logging()
    log("Service started", "INFO", 300)
    while True:
        try:
            service_tick()
        except Exception as exc:
            log(f"Service loop error: {exc}", "ERROR", 304)
        time.sleep(int(load_config().get("service", {}).get("interval_seconds", 60)))


def run_debug():
    log("Debug mode", "INFO", 390)
    service_tick()


def print_json(data):
    print(json.dumps(data, indent=2))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    for command in ["service-loop", "debug", "health", "inspect-pfx", "test-pa", "inspect-pa-cert", "compare", "policy", "deploy", "force-deploy", "test-wacs", "test-cloudflare", "provision-wacs", "renew-wacs"]:
        sub.add_parser(command)
    args = parser.parse_args()
    try:
        if args.cmd == "service-loop":
            service_loop()
        elif args.cmd == "debug":
            run_debug()
        elif args.cmd == "health":
            print_json(health_check())
        elif args.cmd == "inspect-pfx":
            print_json(inspect_configured_pfx())
        elif args.cmd == "test-pa":
            print_json(test_palo_api())
        elif args.cmd == "inspect-pa-cert":
            print_json(inspect_pa_certificate())
        elif args.cmd == "compare":
            print_json(compare_certificates())
        elif args.cmd == "policy":
            print_json(policy_decision())
        elif args.cmd == "deploy":
            print_json(deploy_certificate(force=False))
        elif args.cmd == "force-deploy":
            print_json(deploy_certificate(force=True))
        elif args.cmd == "test-wacs":
            print_json(test_win_acme())
        elif args.cmd == "test-cloudflare":
            print_json(test_cloudflare())
        elif args.cmd == "provision-wacs":
            print_json(provision_win_acme_renewal())
        elif args.cmd == "renew-wacs":
            print_json(run_win_acme_renew())
    except CertGuardError as exc:
        log(f"Command failed: {exc}", "ERROR", 399)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        log(f"File not found: {exc}", "ERROR", 398)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        log(f"Unexpected failure: {exc}", "ERROR", 399)
        print(f"ERROR: unexpected failure: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
