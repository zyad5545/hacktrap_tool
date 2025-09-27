# backend/db.py
import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path

DB_PATH = os.getenv("DB_PATH", "./data/app.db")

def ensure_data_dir():
    data_dir = Path(DB_PATH).parent
    data_dir.mkdir(parents=True, exist_ok=True)

def get_connection():
    ensure_data_dir()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        attack_type TEXT,
        source_ip TEXT,
        target_resource TEXT,
        severity TEXT,
        details TEXT,
        blockchain_tx_hash TEXT,
        status TEXT DEFAULT 'new',
        anomaly_score REAL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS honeypot_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        source_ip TEXT,
        user_agent TEXT,
        form TEXT,
        json_payload TEXT,
        headers TEXT,
        raw TEXT,
        anchored_tx TEXT
    )
    ''')

    conn.commit()
    conn.close()

def log_attack(
    attack_type,
    source_ip,
    severity=None,
    details=None,
    target_resource=None,
    blockchain_tx_hash=None,
    status="new",
    anomaly_score=None
):
    import sqlite3
    conn = sqlite3.connect("/app/data/app.db")
    c = conn.cursor()
    c.execute("""
        INSERT INTO attacks (
            attack_type, source_ip, severity, details, target_resource,
            blockchain_tx_hash, status, anomaly_score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        attack_type, source_ip, severity, details, target_resource,
        blockchain_tx_hash, status, anomaly_score
    ))
    conn.commit()
    conn.close()


def get_recent_attacks(limit=10):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT id, timestamp, attack_type, source_ip, target_resource, severity, details, blockchain_tx_hash, status, anomaly_score
    FROM attacks
    ORDER BY timestamp DESC
    LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    attacks = []
    for r in rows:
        d = dict(r)
        # attempt to parse details
        try:
            d["details"] = json.loads(d.get("details") or "{}")
        except Exception:
            pass
        attacks.append(d)
    conn.close()
    return attacks

def update_attack_status(attack_id, status, tx_hash=None):
    conn = get_connection()
    cursor = conn.cursor()
    if tx_hash:
        cursor.execute('UPDATE attacks SET status = ?, blockchain_tx_hash = ? WHERE id = ?', (status, tx_hash, attack_id))
    else:
        cursor.execute('UPDATE attacks SET status = ? WHERE id = ?', (status, attack_id))
    conn.commit()
    conn.close()
    return True

def log_honeypot_event(event_data: dict):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO honeypot_events (source_ip, user_agent, form, json_payload, headers, raw)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        event_data.get('source_ip'),
        event_data.get('user_agent'),
        json.dumps(event_data.get('form', {})),
        json.dumps(event_data.get('json', {})),
        json.dumps(event_data.get('headers', {})),
        event_data.get('raw')
    ))
    ev_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return ev_id