#!/usr/bin/env python3
# backend/integrations/cowrie_connector.py
"""
Tail Cowrie JSON logfile and POST events to backend honeypot API.
Robust, verbose, reads config from env, never crashes on transient errors.
"""

import time
import json
import logging
import os
import sys
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter, Retry
from argparse import ArgumentParser

# Config via env (compose sets API / API_KEY or HONEY_API_KEY)
API = os.getenv("API", "http://hacktrap_backend:8000/api/honeypot/capture")
ENV_KEY_1 = os.getenv("API_KEY")
ENV_KEY_2 = os.getenv("HONEY_API_KEY")
API_KEY = ENV_KEY_1 or ENV_KEY_2 or "honeypot-secure-key"

# Logfile path inside the connector container (mounted from host ./cowrie-data)
LOGFILE = os.getenv("COWRIE_LOGFILE", "/home/cowrie/cowrie/var/cowrie.json")
# Fallback public beacon (optional)
FALLBACK_BEACON = os.getenv("FALLBACK_BEACON", "http://hacktrap_backend:8000/api/honeypot/beacon")

# Logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger("cowrie-connector")

# requests session with retries/backoff
session = requests.Session()
retries = Retry(total=3, backoff_factor=0.6, status_forcelist=[429, 500, 502, 503, 504])
session.mount("http://", HTTPAdapter(max_retries=retries))
session.mount("https://", HTTPAdapter(max_retries=retries))


def send_event_to_protected_api(payload):
    headers = {"Content-Type": "application/json", "X-API-KEY": API_KEY}
    try:
        r = session.post(API, json=payload, headers=headers, timeout=8)
        logger.info("POST -> %s [%s] %s", API, r.status_code, (r.text or "")[:300])
        return r.status_code, r.text
    except Exception as e:
        logger.exception("POST to protected API failed")
        return None, str(e)


def send_event_to_beacon(payload):
    try:
        r = session.post(FALLBACK_BEACON, json=payload, timeout=8)
        logger.info("POST beacon -> %s [%s] %s", FALLBACK_BEACON, r.status_code, (r.text or "")[:300])
        return r.status_code, r.text
    except Exception:
        logger.exception("POST to beacon failed")
        return None, None


def send_event(payload):
    code, text = send_event_to_protected_api(payload)
    # If backend rejects API Key explicitly, fallback to beacon.
    if code == 403:
        logger.warning("Protected API rejected key (403). Falling back to beacon.")
        send_event_to_beacon(payload)
    elif code is None:
        logger.warning("Network error posting to protected API, trying beacon.")
        send_event_to_beacon(payload)
    return code


def tail_file(path):
    p = Path(path)
    logger.info("tail_file waiting for log file: %s", p)
    while not p.exists():
        logger.info("log file not present yet: %s — sleeping 2s", p)
        time.sleep(2)

    # Open in text mode, read lines as they are appended
    with p.open("r", encoding="utf-8", errors="replace") as f:
        # move to EOF (but allow reading older lines in `--once` mode)
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def map_cowrie_to_payload(j: dict):
    # Minimal mapping — keep original JSON in payload field too.
    return {
        "timestamp": j.get("timestamp"),
        "source_ip": j.get("src_ip") or (j.get("sensor") or {}).get("src_ip"),
        "userAgent": j.get("user_agent") or j.get("user-agent") or "",
        "payload": json.dumps(j, ensure_ascii=False),
        "cookies": "",
        "localStorage": "",
        "sessionStorage": ""
    }


def process_once(line):
    """Process a single line; returns True on success."""
    try:
        j = json.loads(line)
    except Exception:
        logger.exception("invalid json line (skipping): %s", (line or "")[:400])
        return False
    try:
        payload = map_cowrie_to_payload(j)
        code = send_event(payload)
        logger.info("Processed one event; API returned: %s", code)
        return True
    except Exception:
        logger.exception("failed to process mapped payload")
        return False


def run_forever():
    logger.info("cowrie_connector started, API=%s, LOGFILE=%s", API, LOGFILE)
    for line in tail_file(LOGFILE):
        try:
            # protect the loop from unexpected crashes — log and continue
            process_once(line)
        except Exception:
            logger.exception("unexpected error in main loop (continuing)")
            time.sleep(1)


def main():
    parser = ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Process one line and exit (useful for debugging)")
    parser.add_argument("--file", type=str, help="Alternative logfile path (for quick testing)")
    args = parser.parse_args()

    global LOGFILE
    if args.file:
        LOGFILE = args.file

    logger.info("Starting cowrie_connector (once=%s)", args.once)
    if args.once:
        # open file (or read from stdin) and process a single line then exit
        p = Path(LOGFILE)
        if not p.exists():
            logger.error("File does not exist for --once: %s", p)
            return 2
        with p.open("r", encoding="utf-8", errors="replace") as f:
            # read last non-empty line
            last = None
            for line in f:
                if line.strip():
                    last = line
            if not last:
                logger.error("No non-empty lines found in %s", p)
                return 3
            ok = process_once(last)
            return 0 if ok else 4

    # normal long-running mode
    try:
        run_forever()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception:
        logger.exception("Unhandled exception (exiting)")
        return 5


if __name__ == "__main__":
    sys.exit(main() or 0)
