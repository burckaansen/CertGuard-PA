#!/usr/bin/env python3
# ASCII only

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

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
    "certificate_name": "",
    "pfx_path": "",
    "pfx_password": "",
    "expected_domain": "",
    "service": {
        "interval_seconds": 60
    }
}


class CertGuardError(Exception):
    """Base exception for CertGuard errors."""


class DependencyError(CertGuardError):
    """Raised when a required Python package is missing."""


class PfxParseError(CertGuardError):
    """Raised when the PFX cannot be parsed."""


class PfxPasswordError(PfxParseError):
    """Raised when the PFX password is wrong or the file is unreadable."""


def ensure_dirs():
    (BASE_DIR / "logs").mkdir(parents=True, exist_ok=True)


def setup_logging():
    ensure_dirs()
    logging.basicConfig(
        filename=str(LOG_PATH),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )


def load_config():
    if not CONFIG_PATH.exists():
        return DEFAULT_CONFIG.copy()
    data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    cfg = DEFAULT_CONFIG.copy()
    cfg.update(data)
    return cfg


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


def cert_dt_to_utc(dt):
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_fingerprint(raw_bytes):
    return ":".join(f"{b:02X}" for b in raw_bytes)


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
    days_left = None
    if not_after is not None:
        days_left = int((not_after - now).total_seconds() // 86400)

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
    result = inspect_pfx(
        cfg.get("pfx_path", ""),
        cfg.get("pfx_password", ""),
        cfg.get("expected_domain", ""),
    )

    state = load_state()
    state["last_pfx_inspection"] = result
    state["last_pfx_inspection_time"] = datetime.now(timezone.utc).isoformat()
    save_state(state)

    return result


def service_tick():
    log("Service tick executed")
    try:
        result = inspect_configured_pfx()
        log(f"Local PFX inspected: days_left={result.get('days_left')} domain_match={result.get('domain_match')}")
    except Exception as exc:
        log(f"Local PFX inspection failed: {exc}")


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

    args = parser.parse_args()

    try:
        if args.cmd == "service-loop":
            service_loop()
        elif args.cmd == "debug":
            run_debug()
        elif args.cmd == "inspect-pfx":
            print_json(inspect_configured_pfx())
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
