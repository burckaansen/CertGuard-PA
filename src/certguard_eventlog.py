# ASCII only

import subprocess
from datetime import datetime, timezone
from pathlib import Path

APP_SOURCE = "CertGuard-PA"
BASE_DIR = Path(r"C:\ProgramData\CertGuard-PA")
EVENTLOG_ERROR_PATH = BASE_DIR / "logs" / "certguard-pa-eventlog-error.log"

EVENT_INFO = "INFORMATION"
EVENT_WARN = "WARNING"
EVENT_ERROR = "ERROR"

# Clean v1 event ID blocks:
# 100-199 service
# 200-299 health/API
# 300-399 certificate/policy
# 400-499 deploy/commit
# 500-599 win-acme
# 900-999 command/error/debug
LEGACY_TO_V1_EVENT_ID = {
    300: 100,  # service started/stopped
    301: 110,  # service tick executed
    302: 111,  # policy tick completed
    303: 901,  # policy tick failed
    304: 902,  # service loop error
    305: 201,  # health failed
    306: 200,  # health ok
    310: 300,  # local PFX inspected
    320: 210,  # Palo Alto API connected
    330: 302,  # cert not found on PA
    331: 301,  # PA certificate inspected
    340: 310,  # compare completed
    341: 311,  # comparison summary
    350: 320,  # policy decision
    351: 321,  # no change / deploy skipped
    352: 400,  # deployment attempt
    353: 322,  # import required
    354: 323,  # scheduled tick import required
    360: 401,  # import completed
    361: 402,  # deployment completed
    362: 403,  # deployment attempt failed
    370: 404,  # commit submitted
    380: 501,  # win-acme renewal started
    381: 503,  # win-acme renewal failed
    382: 502,  # win-acme renewal completed
    383: 500,  # win-acme path test completed
    390: 910,  # debug mode
    398: 900,  # file not found
    399: 901,  # command failed / unexpected failure
}


def normalize_event_id(event_id):
    try:
        value = int(event_id)
    except Exception:
        value = 900
    value = LEGACY_TO_V1_EVENT_ID.get(value, value)
    if value < 1 or value > 1000:
        return 900
    return value


def normalize_level(level):
    return str(level or "INFO").upper()


def safe_message_text(message):
    safe_message = f"[{APP_SOURCE}] {message}"
    return safe_message.replace("\r", " ").replace("\n", " ")[:900]


def write_eventlog_error(message):
    try:
        EVENTLOG_ERROR_PATH.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        with EVENTLOG_ERROR_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"{timestamp} {message}\n")
    except Exception:
        pass


def write_event_eventcreate(message, level="INFO", event_id=900):
    event_type = {
        "INFO": EVENT_INFO,
        "WARN": EVENT_WARN,
        "WARNING": EVENT_WARN,
        "ERROR": EVENT_ERROR,
    }.get(normalize_level(level), EVENT_INFO)

    safe_message = safe_message_text(message)
    event_id = normalize_event_id(event_id)

    result = subprocess.run(
        [
            "eventcreate",
            "/L", "APPLICATION",
            "/T", event_type,
            "/ID", str(event_id),
            "/SO", APP_SOURCE,
            "/D", safe_message,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"eventcreate failed returncode={result.returncode} output={result.stdout[-500:]}")


def write_event_pywin32(message, level="INFO", event_id=900):
    try:
        import win32evtlogutil
        import win32evtlog
    except Exception as exc:
        raise RuntimeError(f"pywin32 event log modules unavailable: {exc}") from exc

    level = normalize_level(level)
    event_type = {
        "INFO": win32evtlog.EVENTLOG_INFORMATION_TYPE,
        "WARN": win32evtlog.EVENTLOG_WARNING_TYPE,
        "WARNING": win32evtlog.EVENTLOG_WARNING_TYPE,
        "ERROR": win32evtlog.EVENTLOG_ERROR_TYPE,
    }.get(level, win32evtlog.EVENTLOG_INFORMATION_TYPE)

    win32evtlogutil.ReportEvent(
        APP_SOURCE,
        normalize_event_id(event_id),
        eventCategory=0,
        eventType=event_type,
        strings=[safe_message_text(message)],
        data=b"",
    )


def write_event(message, level="INFO", event_id=900):
    # Prefer eventcreate because the installer maps the CertGuard-PA source
    # to EventCreate.exe, which supports simple custom Event IDs 1-1000.
    try:
        write_event_eventcreate(message, level, event_id)
        return
    except Exception as exc:
        write_eventlog_error(f"eventcreate failed event_id={event_id} level={level}: {exc}")

    try:
        write_event_pywin32(message, level, event_id)
        return
    except Exception as exc:
        write_eventlog_error(f"pywin32 fallback failed event_id={event_id} level={level}: {exc}")
