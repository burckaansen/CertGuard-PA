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


def normalize_event_id(event_id):
    try:
        value = int(event_id)
    except Exception:
        value = 900
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
