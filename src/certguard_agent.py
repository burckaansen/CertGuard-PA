#!/usr/bin/env python3
# ASCII only

import argparse
import json
import logging
import os
import time
from pathlib import Path

APP_NAME = "CertGuard-PA"
BASE_DIR = Path(r"C:\ProgramData\CertGuard-PA")
CONFIG_PATH = BASE_DIR / "config.json"
STATE_PATH = BASE_DIR / "state.json"
LOG_PATH = BASE_DIR / "logs" / "certguard-pa.log"

DEFAULT_CONFIG = {
    "firewall_host": "",
    "certificate_name": "",
    "pfx_path": "",
    "expected_domain": "",
    "service": {
        "interval_seconds": 60
    }
}


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
    return json.loads(CONFIG_PATH.read_text())


def save_config(cfg):
    ensure_dirs()
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def log(msg):
    setup_logging()
    print(msg)
    logging.info(msg)


def service_tick():
    cfg = load_config()
    log("Service tick executed")
    # TODO: compare cert, policy logic, deploy


def service_loop():
    setup_logging()
    log("Service started")
    while True:
        try:
            service_tick()
        except Exception as e:
            log(f"Error: {e}")
        time.sleep(load_config().get("service", {}).get("interval_seconds", 60))


def run_debug():
    log("Debug mode")
    service_tick()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("service-loop")
    sub.add_parser("debug")

    args = parser.parse_args()

    if args.cmd == "service-loop":
        service_loop()
    elif args.cmd == "debug":
        run_debug()


if __name__ == "__main__":
    main()
