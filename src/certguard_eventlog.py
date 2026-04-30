# ASCII only

from datetime import datetime, timezone
from pathlib import Path

APP_SOURCE = "CertGuard-PA"
BASE_DIR = Path(r"C:\ProgramData\CertGuard-PA")
EVENTLOG_ERROR_PATH = BASE_DIR / "logs" / "certguard-pa-eventlog-error.log"

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


def event_name(original_event_id):
    try:
        value = int(original_event_id)
    except Exception:
        value = 399
    return EVENT_NAMES.get(value, "CertGuardEvent")


def safe_message_text(message, level="INFO", original_event_id=0):
    status = "ERROR" if normalize_level(level) == "ERROR" else ("WARN" if normalize_level(level) in ["WARN", "WARNING"] else "OK")
    text = f"[{APP_SOURCE}] EVENT={event_name(original_event_id)} STATUS={status} ORIGINAL_EVENT_ID={original_event_id} MESSAGE={message}"
    return text.replace("\r", " ").replace("\n", " ")[:1200]


def write_eventlog_error(message):
    try:
        EVENTLOG_ERROR_PATH.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        with EVENTLOG_ERROR_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"{timestamp} {message}\n")
    except Exception:
        pass


def write_event(message, level="INFO", event_id=399):
    try:
        import servicemanager
        text = safe_message_text(message, level, event_id)
        normalized = normalize_level(level)
        if normalized == "ERROR":
            servicemanager.LogErrorMsg(text)
        elif normalized in ["WARN", "WARNING"]:
            servicemanager.LogWarningMsg(text)
        else:
            servicemanager.LogInfoMsg(text)
    except Exception as exc:
        write_eventlog_error(f"servicemanager event log failed event_id={event_id} level={level}: {exc}")
