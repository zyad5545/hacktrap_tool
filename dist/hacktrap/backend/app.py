import os
import logging
import sqlite3
from flask import Flask, request, jsonify, redirect
from datetime import datetime
import requests
import json
import glob

# ---------------- CONFIG ----------------
DB_PATH = "./data/app.db"
AI_ENABLED = os.getenv("AI_ENABLED", "true").lower() == "true"
AI_ENDPOINT = os.getenv("AI_ENDPOINT", "http://ai_engine:5000/predict")

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("hacktrap-backend")

# ---------------- DB INIT ----------------
def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
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
        """
    )
    conn.commit()
    conn.close()
    logger.info("Database initialized at %s", DB_PATH)

# ---------------- HELPERS ----------------
def log_attack(attack_type, source_ip, severity, details, target_resource=None):
    score = 0.0
    if AI_ENABLED:
        try:
            resp = requests.post(AI_ENDPOINT, json={
                "attack_type": attack_type,
                "source_ip": source_ip,
                "details": details
            }, timeout=3)
            if resp.status_code == 200:
                score = resp.json().get("anomaly_score", 0.0)
        except Exception as e:
            logger.error("AI engine error: %s", e)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO attacks (attack_type, source_ip, severity, details, target_resource, anomaly_score)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (attack_type, source_ip, severity, details, target_resource, score)
    )
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()

    logger.info("Attack logged: %s from %s score=%.2f", attack_type, source_ip, score)
    return score, row_id


def anchor_attack(row_id: int, payload: dict):
    try:
        from .blockchain import anchor_data  # local import to avoid hard dependency
    except Exception:
        try:
            # fallback absolute import if running as script
            from blockchain import anchor_data
        except Exception:
            anchor_data = None

    if not anchor_data:
        return None

    tx_hash = anchor_data(payload)
    if not tx_hash:
        return None

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE attacks SET blockchain_tx_hash = ? WHERE id = ?",
        (tx_hash, row_id),
    )
    conn.commit()
    conn.close()
    return tx_hash

# ---------------- ROUTES ----------------
@app.route("/health")
def health():
    return jsonify({"service": "hacktrap-backend", "status": "healthy"})

@app.route("/api/attacks", methods=["GET"])
def get_attacks():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attacks ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()

    keys = ["id", "timestamp", "attack_type", "source_ip", "target_resource", "severity",
            "details", "blockchain_tx_hash", "status", "anomaly_score"]

    return jsonify({"attacks": [dict(zip(keys, row)) for row in rows]})

@app.route("/api/logs", methods=["POST"])
def api_logs():
    data = request.get_json(force=True)
    log_attack(
        attack_type=data.get("attack_type", "unknown"),
        source_ip=data.get("source_ip", request.remote_addr),
        severity=data.get("severity", "low"),
        details=data.get("details", "")
    )
    return jsonify({"status": "success", "message": "Log processed"})

@app.route("/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    # support form submissions
    if not payload and request.form:
        payload = request.form.to_dict()
    username = payload.get("username") or payload.get("email")
    password = payload.get("password")

    if username == "admin" and password == "password":
        # سجل نجاح الدخول كمان
        score, row_id = log_attack(
            attack_type="brute_force",
            source_ip=request.remote_addr,
            severity="medium",
            details=f"Valid login attempt {username}/{password}"
        )
        anchor_attack(row_id, {
            "type": "brute_force",
            "source_ip": request.remote_addr,
            "details": f"valid login {username}",
            "score": score,
        })
        return jsonify({"message": "Login successful"}), 200
    else:
        # سجل فشل الدخول
        score, row_id = log_attack(
            attack_type="brute_force",
            source_ip=request.remote_addr,
            severity="high",
            details=f"Invalid login attempt {username}/{password}"
        )
        anchor_attack(row_id, {
            "type": "brute_force",
            "source_ip": request.remote_addr,
            "details": f"invalid login {username}",
            "score": score,
        })
        # redirect attacker to fake login honeypot page
        return redirect("/fake_login.html", code=302)


@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("q", "")
    source_ip = request.remote_addr

    # simple XSS heuristic
    lower_q = query.lower()
    is_xss = any(token in lower_q for token in ["<script", "onerror=", "onload=", "javascript:", "<img", "</script>"])
    severity = "high" if is_xss else "low"

    score, row_id = log_attack(
        attack_type="xss" if is_xss else "search",
        source_ip=source_ip,
        severity=severity,
        details=f"search q={query}",
        target_resource="/search",
    )

    if is_xss:
        anchor_attack(row_id, {
            "type": "xss",
            "source_ip": source_ip,
            "details": query,
            "score": score,
        })
        return redirect("/honeypot", code=302)

    return jsonify({"results": [], "q": query})


@app.route("/id", methods=["GET"])
def get_by_id():
    item_id = request.args.get("id", "")
    source_ip = request.remote_addr
    lower = (item_id or "").lower()
    # naive SQLi detection
    sqli_markers = ["' or ", '" or ', " or 1=1", " union ", "--", ";--", "/*", "*/", "@@", "char("]
    is_sqli = any(marker in lower for marker in sqli_markers)
    severity = "critical" if is_sqli else "low"

    score, row_id = log_attack(
        attack_type="sqli" if is_sqli else "visit",
        source_ip=source_ip,
        severity=severity,
        details=f"id param: {item_id}",
        target_resource="/id",
    )

    if is_sqli:
        anchor_attack(row_id, {
            "type": "sqli",
            "source_ip": source_ip,
            "details": item_id,
            "score": score,
        })
        return redirect("/honeypot", code=302)

    return jsonify({"item": {"id": item_id}})

@app.route("/honeypot", methods=["POST"])
def honeypot():
    data = request.get_json(force=True, silent=True) or {}
    log_attack(
        attack_type="honeypot",
        source_ip=request.remote_addr,
        severity="medium",
        details=f"Honeypot interaction {data}"
    )
    return jsonify({"status": "honeypot logged"}), 200


@app.route("/api/honeypot/sessions", methods=["GET"])
def honeypot_sessions():
    base = os.getenv("COWRIE_LOG_DIR", "./cowrie-data/var/log")
    entries = []
    try:
        for path in glob.glob(os.path.join(base, "cowrie.json*")):
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        try:
                            evt = json.loads(line.strip())
                            entries.append(evt)
                        except Exception:
                            continue
            except Exception:
                continue
    except Exception:
        pass
    return jsonify({"sessions": entries[-200:]})

@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "backend running"}), 200

# ---------------- MAIN ----------------
def create_app():
    init_db()
    return app

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000)
