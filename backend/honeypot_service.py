# backend/honeypot_service.py
import os
import json
import sqlite3
import time
import hashlib
from typing import Optional

DB_PATH = os.getenv("DB_PATH", "/app/data/app.db")
ANCHOR_RECORD_DIR = os.getenv("ANCHOR_RECORD_DIR", "/app/anchor_records")

# إذا لديك خدمة anchor_service.py داخل backend يمكنك استيرادها
try:
    from anchor_service import AnchorService, MockKMSSigner
    anchor_available = True
except Exception:
    anchor_available = False

def get_db_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS honeypot_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        source_ip TEXT,
        user_agent TEXT,
        cookies TEXT,
        payload TEXT,
        headers TEXT,
        json_payload TEXT,
        anchored_tx TEXT
    );
    """)
    conn.commit()
    conn.close()

def log_honeypot_event(data: dict) -> int:
    """
    Store event in SQLite and return row id
    data expected keys: source_ip, user_agent, cookies, payload, headers, json_payload
    """
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO honeypot_events (source_ip, user_agent, cookies, payload, headers, json_payload)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        data.get("source_ip"),
        data.get("user_agent"),
        data.get("cookies"),
        data.get("payload"),
        json.dumps(data.get("headers", {})),
        json.dumps(data.get("json_payload", {}))
    ))
    conn.commit()
    rowid = cur.lastrowid
    conn.close()
    return rowid

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def anchor_event_if_possible(event_id: int) -> Optional[str]:
    """
    Try to anchor the event to blockchain.
    Implementation: build a digest from event JSON, call anchor_service.anchor_batch
    Returns tx_hash or None
    """
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM honeypot_events WHERE id = ?", (event_id,))
        row = cur.fetchone()
        conn.close()
        if row is None:
            return None

        # canonicalize event as JSON string
        event_obj = {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "source_ip": row["source_ip"],
            "user_agent": row["user_agent"],
            "payload": row["payload"],
            "json_payload": json.loads(row["json_payload"]) if row["json_payload"] else {}
        }
        event_json = json.dumps(event_obj, sort_keys=True, separators=(",", ":"))
        digest_hex = "0x" + _sha256_hex(event_json)

        # If anchor service available, call it
        if anchor_available:
            # create signer (Mock for dev)
            signer = MockKMSSigner()  # environment RELAYER_PRIVATE_KEY must exist for real signing
            svc = AnchorService(signer)
            batch_id = f"honeypot-{int(time.time())}-{event_id}"
            tx = svc.anchor_batch(batch_id, [digest_hex])
            # store tx hash
            conn = get_db_conn()
            cur = conn.cursor()
            cur.execute("UPDATE honeypot_events SET anchored_tx = ? WHERE id = ?", (tx, event_id))
            conn.commit()
            conn.close()
            return tx
        else:
            # fallback: write a local anchor record (no blockchain)
            os.makedirs(ANCHOR_RECORD_DIR, exist_ok=True)
            record = {
                "id": event_id,
                "digest": digest_hex,
                "timestamp": int(time.time())
            }
            path = os.path.join(ANCHOR_RECORD_DIR, f"local-anchor-{event_id}.json")
            with open(path, "w") as f:
                json.dump(record, f, indent=2)
            return None
    except Exception as e:
        # لا تفشل التسجيل لو فشل الـ anchoring
        print("anchor_event_if_possible error:", e)
        return None
