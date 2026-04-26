# ASCII only

import subprocess

APP_SOURCE = "CertGuard-PA"

EVENT_INFO = "INFORMATION"
EVENT_WARN = "WARNING"
EVENT_ERROR = "ERROR"


def normalize_event_id(event_id):
    try:
        value = int(event_id)
    except Exception:
        value = 255
    if value < 1 or value > 1000:
        return 255
    return value


def write_event(message, level="INFO", event_id=255):
    event_type = {
        "INFO": EVENT_INFO,
        "WARN": EVENT_WARN,
        "ERROR": EVENT_ERROR,
    }.get(str(level).upper(), EVENT_INFO)

    safe_message = f"[{APP_SOURCE}] {message}"
    safe_message = safe_message.replace("\r", " ").replace("\n", " ")[:900]
    event_id = normalize_event_id(event_id)

    try:
        subprocess.run(
            [
                "eventcreate",
                "/L", "APPLICATION",
                "/T", event_type,
                "/ID", str(event_id),
                "/SO", APP_SOURCE,
                "/D", safe_message,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        pass
