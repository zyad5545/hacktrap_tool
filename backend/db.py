# backend/db.py
"""
Database helper for HackTrap backend.

Provides:
 - get_connection()
 - init_db()
 - ensure_honeypot_schema()
 - log_honeypot_event(obj: dict) -> int | None
 - log_attack(obj: dict) -> int
 - update_honeypot_anchor(event_id, tx_hash) -> bool

Safe, resilient, uses WAL mode and returns useful values.
"""
import sqlite3
import json
import os
import logging
from pathlib import Path
from typing import Optional, Any, Dict, Tuple

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

DB_PATH = os.getenv("DB_PATH", "data/app.db")


def ensure_data_dir() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    """
    Return a sqlite3 connection with sensible defaults.
    check_same_thread=False because Flask/Gunicorn may use threads.
    """
    ensure_data_dir()
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        # Not fatal; continue
        logger.debug("Could not set PRAGMAs (non-fatal).")
    return conn


def init_db() -> None:
    """
    Create main tables if missing.
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            attack_type TEXT,
            source_ip TEXT,
            target_resource TEXT,
            user_agent TEXT,
            payload TEXT,
            severity TEXT,
            details TEXT,
            blockchain_tx_hash TEXT,
            status TEXT DEFAULT 'new',
            anomaly_score REAL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS honeypot_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            user_agent TEXT,
            form TEXT,
            json_payload TEXT,
            headers TEXT,
            raw TEXT,
            anchored_tx TEXT,
            cookies TEXT,
            localStorage TEXT,
            sessionStorage TEXT,
            payload TEXT,
            referringUrl TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)
        conn.commit()
        logger.info("Database initialized (tables ensured).")
    except Exception:
        logger.exception("init_db failed")
        raise
    finally:
        conn.close()


def ensure_honeypot_schema() -> None:
    """
    Ensure columns exist (safe ALTERs if schema evolved).
    Non-destructive; ignores errors if column already exists.
    """
    required_cols = {
        "timestamp": "TEXT", "source_ip": "TEXT", "user_agent": "TEXT",
        "cookies": "TEXT", "localStorage": "TEXT", "sessionStorage": "TEXT",
        "payload": "TEXT", "referringUrl": "TEXT", "anchored_tx": "TEXT",
        "json_payload": "TEXT", "headers": "TEXT", "raw": "TEXT", "form": "TEXT",
    }
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("PRAGMA table_info(honeypot_events);")
        existing = {r["name"] for r in cur.fetchall()}
        for col, col_def in required_cols.items():
            if col not in existing:
                try:
                    cur.execute(f"ALTER TABLE honeypot_events ADD COLUMN {col} {col_def};")
                    conn.commit()
                    logger.info("Added column %s to honeypot_events", col)
                except Exception:
                    logger.exception("Failed adding column %s (ignored)", col)
    finally:
        conn.close()


def _safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        try:
            return json.dumps(str(obj), ensure_ascii=False)
        except Exception:
            return "{}"


def log_honeypot_event(obj: Dict[str, Any]) -> Optional[int]:
    """
    Insert a honeypot event. Returns lastrowid or None on failure.
    Accepts keys: timestamp, source_ip, user_agent, cookies, localStorage, sessionStorage,
                  payload, referringUrl, anchored_tx, raw, json_payload, headers, form
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
        INSERT INTO honeypot_events (
            timestamp, source_ip, user_agent, cookies,
            localStorage, sessionStorage, payload, referringUrl,
            anchored_tx, raw, json_payload, headers, form
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            obj.get("timestamp"),
            obj.get("source_ip"),
            obj.get("user_agent"),
            obj.get("cookies"),
            obj.get("localStorage"),
            obj.get("sessionStorage"),
            obj.get("payload"),
            obj.get("referringUrl"),
            obj.get("anchored_tx") or obj.get("anchoredTx") or obj.get("anchored_tx"),
            obj.get("raw"),
            _safe_json(obj.get("json_payload") or obj.get("jsonPayload") or obj.get("data")),
            _safe_json(obj.get("headers") or obj.get("request_headers")),
            _safe_json(obj.get("form")),
        ))
        conn.commit()
        event_id = cur.lastrowid
        logger.info("Logged honeypot_event id=%s payload=%s", event_id, (obj.get("payload") or "")[:80])
        return event_id
    except Exception:
        logger.exception("log_honeypot_event failed")
        return None
    finally:
        conn.close()


def log_attack(obj: Dict[str, Any]) -> int:
    """
    Insert an attack record. Returns inserted id.
    Fields: timestamp, attack_type, source_ip, target_resource, user_agent, payload,
            severity, details (dict), anomaly_score
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
        INSERT INTO attacks (timestamp, attack_type, source_ip, target_resource, user_agent,
                             payload, severity, details, anomaly_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            obj.get("timestamp"),
            obj.get("attack_type"),
            obj.get("source_ip"),
            obj.get("target_resource"),
            obj.get("user_agent"),
            obj.get("payload"),
            obj.get("severity"),
            _safe_json(obj.get("details", {})),
            obj.get("anomaly_score"),
        ))
        conn.commit()
        aid = cur.lastrowid
        logger.info("Logged attack id=%s type=%s score=%s", aid, obj.get("attack_type"), obj.get("anomaly_score"))
        return aid
    except Exception:
        logger.exception("log_attack failed")
        raise
    finally:
        conn.close()


def update_honeypot_anchor(event_id: int, tx_hash: str) -> bool:
    """
    Store blockchain tx hash for an event. Returns True on success.
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE honeypot_events SET anchored_tx = ? WHERE id = ?", (tx_hash, event_id))
        conn.commit()
        logger.info("Updated honeypot event %s with tx %s", event_id, tx_hash)
        return True
    except Exception:
        logger.exception("update_honeypot_anchor failed")
        return False
    finally:
        conn.close()


# optional convenience helpers used by some debugging flows
def fetch_recent_honeypot_events(limit: int = 50) -> Tuple[Dict, ...]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM honeypot_events ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        return tuple(rows)
    finally:
        conn.close()


def fetch_recent_attacks(limit: int = 50) -> Tuple[Dict, ...]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM attacks ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        return tuple(rows)
    finally:
        conn.close()
