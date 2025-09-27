#!/usr/bin/env python3
# backend/app.py — updated to show message instead of redirect

import os
import joblib
import urllib.parse
import logging
import traceback
from functools import wraps
from flask import Flask, request, jsonify, current_app
from flask_cors import CORS
import requests
from werkzeug.exceptions import HTTPException

# local DB helpers
from db import init_db, ensure_honeypot_schema, log_attack, log_honeypot_event, update_honeypot_anchor, get_connection

# optional blockchain anchoring
try:
    from blockchain import anchor_data
except Exception:
    anchor_data = None

# ===== APP SETUP =====
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===== CONFIG =====
MODEL_PATHS = [
    os.getenv("MODEL_PATH", "data/model.joblib"),
    "ai_agent/data/model.joblib",
    "ai_agent/data/attack_model.joblib",
    "data/model.joblib",
    "/app/data/model.joblib",
]
XSS_MODEL_PATHS = [
    os.getenv("XSS_MODEL_PATH", "data/xss_model.joblib"),
    "ai_agent/data/xss_model.joblib",
    "./ai_agent/data/xss_model.joblib",
    "/app/data/xss_model.joblib",
]
AI_ENDPOINT = os.getenv("AI_ENDPOINT", None)
HONEY_API_KEY = os.getenv("HONEY_API_KEY", "honeypot-secure-key")
DETECT_THRESHOLD = float(os.getenv("DETECT_THRESHOLD", "0.5"))
PREFER_REMOTE_AI = os.getenv("PREFER_REMOTE_AI", "0") == "1"
FORCE_AI_ONLY = os.getenv("FORCE_AI_ONLY", "0") == "1"

attack_model = None
attack_model_path = None
xss_model = None
xss_model_path = None

# ===== Model loading =====
def try_load_model(paths):
    for p in paths:
        if not p:
            continue
        try:
            if os.path.exists(p):
                try:
                    m = joblib.load(p)
                    logger.info("Loaded model: %s", p)
                    return m, p
                except Exception:
                    logger.exception("Failed loading model %s", p)
        except Exception:
            logger.exception("Error checking model %s", p)
    return None, None

def load_local_models():
    global attack_model, attack_model_path, xss_model, xss_model_path
    attack_model, attack_model_path = try_load_model(MODEL_PATHS)
    xss_model, xss_model_path = try_load_model(XSS_MODEL_PATHS)

load_local_models()

# ===== Utilities =====
def sanitize_string(s, max_length=2000):
    if not s:
        return ""
    return str(s)[:max_length].replace("\x00", "").strip()

def call_ai_endpoint(text):
    if not AI_ENDPOINT:
        return {"malicious": False, "attack_type": "normal", "score": 0.0}
    try:
        r = requests.post(AI_ENDPOINT, json={"query": text}, timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        logger.exception("AI endpoint call failed")
    return {"malicious": False, "attack_type": "normal", "score": 0.0}

def detect_attack_ai(text):
    if not text.strip():
        return "normal", 0.0

    # Force AI only mode
    if FORCE_AI_ONLY and AI_ENDPOINT:
        res = call_ai_endpoint(text)
        return res.get("attack_type", "normal"), float(res.get("score", 0.0))

    # Prefer remote AI if configured
    if PREFER_REMOTE_AI and AI_ENDPOINT:
        res = call_ai_endpoint(text)
        return res.get("attack_type", "normal"), float(res.get("score", 0.0))

    # Local model detection
    try:
        if attack_model and hasattr(attack_model, "predict_proba"):
            probs = attack_model.predict_proba([text])[0]
            idx = probs.argmax()
            cls = getattr(attack_model, "classes_", [])[idx] if hasattr(attack_model, "classes_") else "normal"
            return str(cls), float(probs[idx])
    except Exception:
        logger.exception("Local attack_model detection failed")

    try:
        if xss_model and hasattr(xss_model, "predict_proba"):
            prob = float(xss_model.predict_proba([text])[0][1])
            return ("xss" if prob >= DETECT_THRESHOLD else "normal"), prob
    except Exception:
        logger.exception("Local xss_model detection failed")

    # Fallback to remote AI
    if AI_ENDPOINT:
        res = call_ai_endpoint(text)
        return res.get("attack_type", "normal"), float(res.get("score", 0.0))

    # Fallback heuristics
    if any(h in text.lower() for h in ["<script", "javascript:", "onerror=", "onload=", "alert("]):
        return "xss", 1.0

    return "normal", 0.0

# ===== Decorators =====
def require_api_key(f):
    @wraps(f)
    def wrapper(*a, **kw):
        api_key = request.headers.get("X-API-KEY") or request.args.get("api_key")
        if api_key != HONEY_API_KEY:
            return jsonify({"error": "Invalid API key"}), 403
        return f(*a, **kw)
    return wrapper

# ===== Routes =====
@app.route("/health")
def health():
    return jsonify({"status": "ok", "ai_endpoint": bool(AI_ENDPOINT)})

@app.route("/search", methods=["POST"])
def search_endpoint():
    data = request.get_json() or {}
    query = sanitize_string(data.get("query", ""))

    attack_type, score = detect_attack_ai(query)
    logger.info("Search: %s -> %s (%.2f)", query, attack_type, score)

    if attack_type != "normal" and score >= DETECT_THRESHOLD:
        log_attack({
            "attack_type": attack_type,
            "source_ip": request.remote_addr,
            "target_resource": "/search",
            "user_agent": request.headers.get("User-Agent", ""),
            "payload": query,
            "severity": "high" if score >= 0.8 else "medium",
            "details": {"ai_score": score},
            "anomaly_score": score
        })
        log_honeypot_event({
            "source_ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            "payload": query,
            "referringUrl": request.referrer or ""
        })
        return jsonify({"show_message": True, "message": "لقد تم خداع الهاكر"}), 200

    # Normal results
    results = [f"عنصر مرتبط بـ {query} - مثال {i}" for i in range(1, 4)]
    return jsonify({"query": query, "results": results})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = sanitize_string(data.get("username", ""))
    password = sanitize_string(data.get("password", ""))
    payload = f"username:{username} password:{password}"

    if not username or not password:
        return jsonify({"success": False, "message": "Missing credentials"}), 400

    attack_type, score = detect_attack_ai(payload)
    logger.info("Login: %s -> %s (%.2f)", username, attack_type, score)

    if attack_type != "normal" and score >= DETECT_THRESHOLD:
        log_attack({
            "attack_type": attack_type,
            "source_ip": request.remote_addr,
            "target_resource": "/login",
            "user_agent": request.headers.get("User-Agent", ""),
            "payload": payload,
            "severity": "high" if score >= 0.8 else "medium",
            "details": {"ai_score": score},
            "anomaly_score": score
        })
        log_honeypot_event({
            "source_ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            "payload": payload,
            "referringUrl": request.referrer or ""
        })
        return jsonify({"show_message": True, "message": "لقد تم خداع الهاكر"}), 200

    # Demo login
    if username == "demo" and password == "demo123":
        return jsonify({"success": True, "message": "Logged in"}), 200

    return jsonify({"success": False, "message": "Invalid credentials"}), 401

# Honeypot endpoints remain same
@app.route("/api/honeypot/capture", methods=["POST"])
@require_api_key
def capture_honeypot():
    data = request.get_json() or {}
    data["source_ip"] = data.get("source_ip") or request.remote_addr
    event_id = log_honeypot_event(data)
    tx_hash = anchor_data(data) if anchor_data else None
    if tx_hash and event_id:
        update_honeypot_anchor(event_id, tx_hash)
    return jsonify({"event_id": event_id, "tx_hash": tx_hash})

@app.route("/api/honeypot/events", methods=["GET"])
@require_api_key
def list_events():
    conn = get_connection()
    rows = [dict(r) for r in conn.execute("SELECT * FROM honeypot_events ORDER BY id DESC LIMIT 50")]
    conn.close()
    return jsonify(rows)

# Init DB
try:
    init_db()
    ensure_honeypot_schema()
except Exception:
    logger.exception("DB init failed")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
