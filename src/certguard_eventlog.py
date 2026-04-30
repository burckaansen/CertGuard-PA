# ASCII only

import subprocess
from datetime import datetime, timezone
from pathlib import Path

APP_SOURCE = "CertGuard-PA"
BASE_DIR = Path(r"C:\ProgramData\CertGuard-PA")
EVENTLOG_ERROR_PATH = BASE_DIR / "logs" / "certguard-pa-eventlog-error.log"

# Final v1 Windows Event Log model:
# Source stays CertGuard-PA.
# Event IDs are severity based to avoid a large custom message table.
# 100 = Information
# 200 = Warning
# 300 = Error
SEVERITY_EVENT_IDS = {
    "INFO": 100,
    "WARN": 200,
    "WARNING": 200,
    "ERROR": 300,
}

EVENT_NAMES = {
    300: "ServiceLifecycle",
    301: "ServiceTickExecuted",
    302: "PolicyTickCompleted",
    303: "PolicyTickFailed",
    304: "ServiceLoopError",
    305: "HealthCheckFailed",
    306: "HealthCheckSucceeded",
    310: "LocalPfxInspected",
    320: "PaloAltoApiConnected",
    330: "PaloAltoCertificateNotFound",
    331: "PaloAltoCertificateInspected",
    340: "CertificateCompareCompleted",
    341: "CertificateComparisonSummary",
    350: "PolicyDecision",
    351: "NoCertificateChangeRequired",
    352: "DeploymentAttempt",
    353: "CertificateImportRequired",
    354: "ScheduledTickImportRequired",
    360: "CertificateImportCompleted",
    361: "DeploymentCompleted",
    362: "DeploymentAttemptFailed",
    370: "CommitSubmitted",
    380: "WinAcmeRenewalStarted",
    381: "WinAcmeRenewalFailed",
    382: "WinAcmeRenewalCompleted",
    383: "WinAcmePathTestCompleted",
    390: "DebugMode",
    398: "FileNotFound",
    399: "CommandFailed",
}


def normalize_level(level):
    return str(level or "INFO").upper()


def severity_event_id(level):
    return SEVERITY_EVENT_IDS.get(normalize_level(level), 100)


def entry_type_for_powershell(level):
    return {
        "INFO": "Information",
        "WARN": "Warning",
        "WARNING": "Warning",
        "ERROR": "Error",
    }.get(normalize_level(level), "Information")


def event_name(original_event_id):
    try:
        value = int(original_event_id)
    except Exception:
        value = 399
    return EVENT_NAMES.get(value, "CertGuardEvent")


def safe_message_text(message, level="INFO", original_event_id=0):
    name = event_name(original_event_id)
    status = "ERROR" if normalize_level(level) == "ERROR" else ("WARN" if normalize_level(level) in ["WARN", "WARNING"] else "OK")
    safe_message = f"[{APP_SOURCE}] EVENT={name} STATUS={status} ORIGINAL_EVENT_ID={original_event_id} MESSAGE={message}"
    return safe_message.replace("\r", " ").replace("\n", " ")[:1200]


def write_eventlog_error(message):
    try:
        EVENTLOG_ERROR_PATH.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        with EVENTLOG_ERROR_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"{timestamp} {message}\n")
    except Exception:
        pass


def write_event_powershell(message, level="INFO", event_id=399):
    final_event_id = severity_event_id(level)
    entry_type = entry_type_for_powershell(level)
    safe_message = safe_message_text(message, level, event_id)
    script = (
        "$msg = [Console]::In.ReadToEnd(); "
        f"Write-EventLog -LogName Application -Source '{APP_SOURCE}' -EventId {final_event_id} "
        f"-EntryType {entry_type} -Message $msg"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        input=safe_message,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Write-EventLog failed returncode={result.returncode} output={result.stdout[-500:]}")


def write_event(message, level="INFO", event_id=399):
    try:
        write_event_powershell(message, level, event_id)
    except Exception as exc:
        write_eventlog_error(f"Write-EventLog failed event_id={event_id} level={level}: {exc}")
