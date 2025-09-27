# backend/db.py
import sqlite3
import json
import os
from pathlib import Path

DB_PATH = os.getenv("DB_PATH", "data/app.db")

def ensure_data_dir():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

def get_connection():
    ensure_data_dir()
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
    except Exception:
        pass
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()
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
    conn.close()

def ensure_honeypot_schema():
    required_cols = {
        "timestamp": "TEXT", "source_ip": "TEXT", "user_agent": "TEXT",
        "cookies": "TEXT", "localStorage": "TEXT", "sessionStorage": "TEXT",
        "payload": "TEXT", "referringUrl": "TEXT", "anchored_tx": "TEXT",
        "json_payload": "TEXT", "headers": "TEXT", "raw": "TEXT", "form": "TEXT",
    }
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(honeypot_events);")
    existing = {r[1] for r in cur.fetchall()}
    for col, col_def in required_cols.items():
        if col not in existing:
            try:
                cur.execute(f"ALTER TABLE honeypot_events ADD COLUMN {col} {col_def};")
                conn.commit()
            except Exception:
                pass
    conn.close()

def log_honeypot_event(obj: dict):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
        INSERT INTO honeypot_events (
            timestamp, source_ip, user_agent, cookies,
            localStorage, sessionStorage, payload, referringUrl, anchored_tx, raw, json_payload, headers, form
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
            obj.get("anchored_tx"),
            obj.get("raw"),
            obj.get("json_payload"),
            obj.get("headers"),
            obj.get("form"),
        ))
        conn.commit()
        return cur.lastrowid
    except Exception:
        return None
    finally:
        conn.close()

def log_attack(obj: dict):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO attacks (timestamp, attack_type, source_ip, target_resource, user_agent, payload, severity, details, anomaly_score)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        obj.get("timestamp"),
        obj.get("attack_type"),
        obj.get("source_ip"),
        obj.get("target_resource"),
        obj.get("user_agent"),
        obj.get("payload"),
        obj.get("severity"),
        json.dumps(obj.get("details", {}), ensure_ascii=False),
        obj.get("anomaly_score"),
    ))
    conn.commit()
    aid = cur.lastrowid
    conn.close()
    return aid

def update_honeypot_anchor(event_id, tx_hash):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE honeypot_events SET anchored_tx = ? WHERE id = ?", (tx_hash, event_id))
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()
