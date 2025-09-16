import os
import logging
import sqlite3
from flask import Flask, request, jsonify
from datetime import datetime
import requests

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
    conn.commit()
    conn.close()

    logger.info("Attack logged: %s from %s score=%.2f", attack_type, source_ip, score)
    return score

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

    return jsonify([dict(zip(keys, row)) for row in rows])

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
    payload = request.get_json(force=True)
    username = payload.get("username")
    password = payload.get("password")

    if username == "admin" and password == "password":
        # سجل نجاح الدخول كمان
        log_attack(
            attack_type="brute_force",
            source_ip=request.remote_addr,
            severity="medium",
            details=f"Valid login attempt {username}/{password}"
        )
        return jsonify({"message": "Login successful"}), 200
    else:
        # سجل فشل الدخول
        log_attack(
            attack_type="brute_force",
            source_ip=request.remote_addr,
            severity="high",
            details=f"Invalid login attempt {username}/{password}"
        )
        return jsonify({"message": "Invalid credentials"}), 401

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
