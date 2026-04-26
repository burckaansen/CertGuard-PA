#!/usr/bin/env python3
# ASCII only

import argparse
import json
import logging
import ssl
import sys
import time
import urllib.parse
import urllib.request
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

APP_NAME = "CertGuard-PA"
BASE_DIR = Path(r"C:\ProgramData\CertGuard-PA")
CONFIG_PATH = BASE_DIR / "config.json"
STATE_PATH = BASE_DIR / "state.json"
LOG_PATH = BASE_DIR / "logs" / "certguard-pa.log"

DEFAULT_CONFIG = {
    "firewall_host": "",
    "palo_api_key": "",
    "skip_tls_validation": True,
    "certificate_name": "",
    "pfx_path": "",
    "pfx_password": "",
    "expected_domain": "",
    "policy": {
        "import_if_pa_cert_missing": True,
        "block_on_domain_mismatch": True,
        "auto_import_only_if_expiring": True,
        "auto_import_expiry_threshold_days": 7,
        "require_local_newer_or_different": True
    },
    "service": {
        "interval_seconds": 60
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
    logging.basicConfig(filename=str(LOG_PATH), level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def merge_config(base, override):
    cfg = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            cfg[key] = merge_config(cfg[key], value)
        else:
            cfg[key] = value
    return cfg


def load_config():
    if not CONFIG_PATH.exists():
        return DEFAULT_CONFIG.copy()
    data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return merge_config(DEFAULT_CONFIG, data)


def save_config(cfg):
    ensure_dirs()
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


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


def log(msg):
    setup_logging()
    print(msg)
    logging.info(msg)


def utc_now_text():
    return datetime.now(timezone.utc).isoformat()


def cert_dt_to_utc(dt):
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


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
        dt = parsedate_to_datetime(raw)
        return cert_dt_to_utc(dt)
    except Exception:
        return None


def format_fingerprint(raw_bytes):
    return ":".join(f"{b:02X}" for b in raw_bytes)


def normalize_fingerprint(value):
    return (value or "").replace(":", "").replace(" ", "").upper()


def get_first_name_attribute(cert, oid):
    try:
        values = cert.subject.get_attributes_for_oid(oid)
        if values:
            return values[0].value
    except Exception:
        pass
    return ""


def get_san_dns_names(cert):
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        return []


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
    candidates = san_dns_names or ([common_name] if common_name else [])
    return any(wildcard_match(candidate, expected_domain) for candidate in candidates)


def require_crypto():
    if pkcs12 is None or hashes is None or x509 is None:
        raise DependencyError("Python package 'cryptography' is required")


def inspect_pfx(pfx_path, password, expected_domain=""):
    require_crypto()
    pfx_file = Path(pfx_path)
    if not pfx_file.exists():
        raise FileNotFoundError(f"PFX file not found: {pfx_file}")
    try:
        pfx_bytes = pfx_file.read_bytes()
    except OSError as exc:
        raise PfxParseError(f"Unable to read PFX file: {exc}") from exc
    password_bytes = None if password is None else str(password).encode("utf-8")
    try:
        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(pfx_bytes, password_bytes)
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
    now = datetime.now(timezone.utc)
    days_left = int((not_after - now).total_seconds() // 86400) if not_after else None
    common_name = get_first_name_attribute(cert, NameOID.COMMON_NAME)
    san_dns_names = get_san_dns_names(cert)
    domain_match = domain_matches_certificate(expected_domain, common_name, san_dns_names)
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
        "domain_match": domain_match,
    }


def inspect_configured_pfx():
    cfg = load_config()
    result = inspect_pfx(cfg.get("pfx_path", ""), cfg.get("pfx_password", ""), cfg.get("expected_domain", ""))
    state = load_state()
    state["last_pfx_inspection"] = result
    state["last_pfx_inspection_time"] = utc_now_text()
    save_state(state)
    return result


def ssl_context(skip_tls_validation):
    if skip_tls_validation:
        return ssl._create_unverified_context()
    return ssl.create_default_context()


def palo_request(config, params, timeout=180):
    host = (config.get("firewall_host") or "").strip()
    key = (config.get("palo_api_key") or "").strip()
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


def parse_palo_response(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise PaloApiError(f"Invalid XML response from Palo Alto: {exc}") from exc
    status = root.attrib.get("status", "")
    if status != "success":
        msg = ""
        msg_node = root.find(".//msg")
        if msg_node is not None and msg_node.text:
            msg = msg_node.text.strip()
        raise PaloApiError(f"Palo Alto API returned status={status} {msg}".strip())
    return root


def palo_op(config, cmd_xml):
    xml_text = palo_request(config, {"type": "op", "cmd": cmd_xml})
    return parse_palo_response(xml_text), xml_text


def test_palo_api():
    cfg = load_config()
    root, _ = palo_op(cfg, "<show><system><info></info></system></show>")
    hostname = ""
    sw_version = ""
    host_node = root.find(".//hostname")
    version_node = root.find(".//sw-version")
    if host_node is not None and host_node.text:
        hostname = host_node.text.strip()
    if version_node is not None and version_node.text:
        sw_version = version_node.text.strip()
    result = {"connected": True, "hostname": hostname, "sw_version": sw_version}
    state = load_state()
    state["last_pa_test"] = result
    state["last_pa_test_time"] = utc_now_text()
    save_state(state)
    log(f"Palo Alto API connected: hostname={hostname} sw_version={sw_version}")
    return result


def find_pa_cert_block(xml_text, certificate_name):
    if not certificate_name:
        raise PaloApiError("certificate_name is required")
    idx = xml_text.find(certificate_name)
    if idx < 0:
        return ""
    return xml_text[max(0, idx - 1200): idx + 5000]


def extract_first(patterns, text):
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match.group(1).strip()
    return ""


def inspect_pa_certificate():
    cfg = load_config()
    cert_name = cfg.get("certificate_name", "")
    _, xml_text = palo_op(cfg, "<show><sslmgr-store><config-certificate-info></config-certificate-info></sslmgr-store></show>")
    block = find_pa_cert_block(xml_text, cert_name)
    if not block:
        raise PaloCertificateNotFound(f"Certificate not found on Palo Alto: {cert_name}")
    expiry_raw = extract_first([
        re.compile(r"(?:not-after|not_after|expiry|expires|expire|valid-to|valid_to)[^A-Za-z0-9]{0,30}([^<\r\n]+)", re.IGNORECASE),
        re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+GMT)"),
        re.compile(r"(\d{4}[/-]\d{2}[/-]\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)"),
    ], block)
    expiry_dt = parse_datetime_guess(expiry_raw)
    days_left = int((expiry_dt - datetime.now(timezone.utc)).total_seconds() // 86400) if expiry_dt else None
    fingerprint = extract_first([
        re.compile(r"(?:sha256|sha-256|fingerprint)[^A-Fa-f0-9]*([A-Fa-f0-9:]{40,})", re.IGNORECASE),
    ], block)
    serial = extract_first([
        re.compile(r"(?:serial|serial-number)[^A-Fa-f0-9]*([A-Fa-f0-9:]+)", re.IGNORECASE),
    ], block)
    subject = extract_first([
        re.compile(r"(?:subject|subject-name)[^\r\n<]*[:=]\s*([^\r\n<]+)", re.IGNORECASE),
    ], block)
    result = {
        "certificate_name": cert_name,
        "found": True,
        "not_after_raw": expiry_raw,
        "not_after_utc": expiry_dt.isoformat() if expiry_dt else "",
        "days_left": days_left,
        "fingerprint_sha256": fingerprint,
        "serial_number_hex": serial,
        "subject": subject,
    }
    state = load_state()
    state["last_pa_certificate_inspection"] = result
    state["last_pa_certificate_inspection_time"] = utc_now_text()
    save_state(state)
    log(f"Palo Alto certificate inspected: name={cert_name} days_left={days_left}")
    return result


def compare_certificates():
    cfg = load_config()
    local = inspect_configured_pfx()
    try:
        remote = inspect_pa_certificate()
    except PaloCertificateNotFound as exc:
        remote = {"found": False, "error": str(exc), "certificate_name": cfg.get("certificate_name", "")}

    local_fp = normalize_fingerprint(local.get("fingerprint_sha256"))
    remote_fp = normalize_fingerprint(remote.get("fingerprint_sha256"))
    same_fingerprint = bool(local_fp and remote_fp and local_fp == remote_fp)

    local_dt = parse_datetime_guess(local.get("not_after_utc"))
    remote_dt = parse_datetime_guess(remote.get("not_after_utc"))
    local_newer = bool(local_dt and remote_dt and local_dt > remote_dt)

    result = {
        "local": local,
        "remote": remote,
        "remote_found": bool(remote.get("found")),
        "same_fingerprint": same_fingerprint,
        "local_newer": local_newer,
        "local_days_left": local.get("days_left"),
        "remote_days_left": remote.get("days_left"),
        "domain_match": bool(local.get("domain_match")),
    }

    state = load_state()
    state["last_compare"] = result
    state["last_compare_time"] = utc_now_text()
    save_state(state)
    log(f"Compare completed: remote_found={result['remote_found']} same={same_fingerprint} local_newer={local_newer} domain_match={result['domain_match']}")
    return result


def evaluate_policy(compare_result):
    cfg = load_config()
    policy = cfg.get("policy", {})
    reasons = []

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
    log(f"Policy decision: action={decision['action']} reason={decision['reason']}")
    return result


def service_tick():
    log("Service tick executed")
    try:
        result = policy_decision()
        log(f"Policy tick completed: action={result['decision']['action']}")
    except Exception as exc:
        log(f"Policy tick failed: {exc}")


def service_loop():
    setup_logging()
    log("Service started")
    while True:
        try:
            service_tick()
        except Exception as exc:
            log(f"Error: {exc}")
        time.sleep(load_config().get("service", {}).get("interval_seconds", 60))


def print_json(data):
    print(json.dumps(data, indent=2))


def run_debug():
    log("Debug mode")
    service_tick()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("service-loop")
    sub.add_parser("debug")
    sub.add_parser("inspect-pfx")
    sub.add_parser("test-pa")
    sub.add_parser("inspect-pa-cert")
    sub.add_parser("compare")
    sub.add_parser("policy")
    args = parser.parse_args()
    try:
        if args.cmd == "service-loop":
            service_loop()
        elif args.cmd == "debug":
            run_debug()
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
    except CertGuardError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"ERROR: unexpected failure: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
