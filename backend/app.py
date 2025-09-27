#!/usr/bin/env python3
# backend/app.py — final: AI-only detection (no heuristic fallback). Honeypot redirect only for XSS.

import os
import joblib
import urllib.parse
import logging
import json
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

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

# ===== Model loading helpers =====
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
    """
    Call the remote AI endpoint. Expect JSON response with keys:
      - attack_type (string: e.g. "xss" / "normal" / other)
      - score (float 0..1)
    Returns a dict fallbacking to normal.
    """
    if not AI_ENDPOINT:
        return {"attack_type": "normal", "score": 0.0}
    try:
        r = requests.post(AI_ENDPOINT, json={"query": text}, timeout=5)
        if r.status_code == 200:
            j = r.json()
            # Normalize
            return {
                "attack_type": str(j.get("attack_type", "normal")) if j else "normal",
                "score": float(j.get("score", 0.0) if j and j.get("score") is not None else 0.0)
            }
        else:
            logger.warning("AI endpoint returned status %s", r.status_code)
    except Exception:
        logger.exception("AI endpoint call failed")
    return {"attack_type": "normal", "score": 0.0}

def detect_attack_ai(text):
    """
    AI-only detection logic (no heuristic).
    Priority:
      1) FORCE_AI_ONLY -> remote AI (must have AI_ENDPOINT)
      2) PREFER_REMOTE_AI -> remote AI (if configured)
      3) Local xss_model (binary) -> if reports XSS above threshold => xss
      4) Local generic attack_model -> return predicted class (but won't be used to classify XSS unless class == 'xss')
      5) Remote AI fallback (if configured)
      6) Default: normal
    Returns (attack_type (str), score (float))
    """
    t = (text or "").strip()
    if not t:
        return "normal", 0.0

    # 1) Forced remote AI
    if FORCE_AI_ONLY and AI_ENDPOINT:
        res = call_ai_endpoint(t)
        logger.info("detect_attack_ai: forced remote -> %s (%.4f)", res.get("attack_type"), res.get("score"))
        return res.get("attack_type", "normal"), float(res.get("score", 0.0))

    # 2) Prefer remote AI
    if PREFER_REMOTE_AI and AI_ENDPOINT:
        res = call_ai_endpoint(t)
        logger.info("detect_attack_ai: prefer remote -> %s (%.4f)", res.get("attack_type"), res.get("score"))
        return res.get("attack_type", "normal"), float(res.get("score", 0.0))

    # 3) Local XSS model (binary detector) — highest priority for XSS decision
    try:
        if xss_model is not None:
            # Support two common patterns of saved model:
            # - a dict with 'xss_vect' and 'xss_clf' (custom pipeline)
            # - a scikit-learn estimator with predict_proba
            if isinstance(xss_model, dict) and "xss_vect" in xss_model and "xss_clf" in xss_model:
                X = xss_model["xss_vect"].transform([t])
                prob = float(xss_model["xss_clf"].predict_proba(X)[0][1])
                logger.info("detect_attack_ai: xss_model(dict) prob=%.4f", prob)
                return ("xss" if prob >= DETECT_THRESHOLD else "normal"), prob
            elif hasattr(xss_model, "predict_proba"):
                prob = float(xss_model.predict_proba([t])[0][1])
                logger.info("detect_attack_ai: xss_model prob=%.4f", prob)
                return ("xss" if prob >= DETECT_THRESHOLD else "normal"), prob
    except Exception:
        logger.exception("Local xss_model detection failed")

    # 4) Local generic attack model
    try:
        if attack_model is not None and hasattr(attack_model, "predict_proba"):
            probs = attack_model.predict_proba([t])[0]
            idx = int(probs.argmax())
            score = float(probs[idx])
            cls = None
            try:
                cls_val = getattr(attack_model, "classes_", [None])[idx]
                cls = str(cls_val) if cls_val is not None else None
            except Exception:
                cls = None
            logger.info("detect_attack_ai: attack_model predicted=%s (score=%.4f)", cls, score)
            # Only treat as XSS if the model's class explicitly names 'xss'
            if cls and str(cls).lower() == "xss":
                return "xss", score
            return (str(cls) if cls else "normal"), score
    except Exception:
        logger.exception("Local attack_model detection failed")

    # 5) Remote AI fallback
    if AI_ENDPOINT:
        res = call_ai_endpoint(t)
        logger.info("detect_attack_ai: remote fallback -> %s (%.4f)", res.get("attack_type"), res.get("score"))
        return res.get("attack_type", "normal"), float(res.get("score", 0.0))

    # 6) Default
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
    return jsonify({
        "status": "ok",
        "ai_endpoint": bool(AI_ENDPOINT),
        "have_attack_model": bool(attack_model),
        "have_xss_model": bool(xss_model)
    })

@app.route("/search", methods=["POST"])
def search_endpoint():
    data = request.get_json() or {}
    query = sanitize_string(data.get("query", ""))

    attack_type, score = detect_attack_ai(query)
    logger.info("Search: query(len=%d) -> %s (score=%.4f)", len(query), attack_type, score)

    # If AI considers malicious, log. Only redirect to honeypot if XSS.
    if attack_type != "normal" and score >= DETECT_THRESHOLD:
        try:
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
        except Exception:
            logger.exception("log_attack failed")

        try:
            log_honeypot_event({
                "source_ip": request.remote_addr,
                "user_agent": request.headers.get("User-Agent", ""),
                "payload": query,
                "referringUrl": request.referrer or ""
            })
        except Exception:
            logger.exception("log_honeypot_event failed")

        # Redirect only when the AI indicates XSS specifically
        if str(attack_type).lower() == "xss":
            redirect_url = "/fake_search.html?p=" + urllib.parse.quote_plus(query)
            logger.info("Search: routing attacker to honeypot: %s", redirect_url)
            return jsonify({
                "action": "honeypot",
                "redirect": redirect_url,
                "show_message": True,
                "message": "لقد تم خداع الهاكر"
            }), 200

        # Non-XSS detections => keep UX normal (still logged)
        results = [f"عنصر مرتبط بـ {query} - مثال {i}" for i in range(1, 4)]
        return jsonify({"query": query, "results": results})

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
    logger.info("Login: %s -> %s (%.4f)", username, attack_type, score)

    if attack_type != "normal" and score >= DETECT_THRESHOLD:
        try:
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
        except Exception:
            logger.exception("log_attack failed")

        try:
            log_honeypot_event({
                "source_ip": request.remote_addr,
                "user_agent": request.headers.get("User-Agent", ""),
                "payload": payload,
                "referringUrl": request.referrer or ""
            })
        except Exception:
            logger.exception("log_honeypot_event failed")

        # For login attacks show the "trapped" banner only (no redirect)
        return jsonify({"show_message": True, "message": "لقد تم خداع الهاكر"}), 200

    # Demo login
    if username == "demo" and password == "demo123":
        return jsonify({"success": True, "message": "Logged in"}), 200

    return jsonify({"success": False, "message": "Invalid credentials"}), 401

# ----- Honeypot endpoints -----
@app.route("/api/honeypot/capture", methods=["POST"])
@require_api_key
def capture_honeypot():
    data = request.get_json() or {}
    data["source_ip"] = data.get("source_ip") or request.remote_addr
    # normalize some fields
    data["user_agent"] = data.get("user_agent") or request.headers.get("User-Agent", "")
    payload_text = data.get("payload") or data.get("query") or ""
    payload_text = sanitize_string(payload_text, max_length=5000)

    # 1) store honeypot event (raw)
    try:
        event_id = log_honeypot_event(data)
    except Exception:
        logger.exception("log_honeypot_event failed in capture_honeypot")
        event_id = None

    # 2) decide whether to also create an attack record (AI-only)
    attack_id = None
    try:
        attack_type, score = detect_attack_ai(payload_text)
        # create attack record only if AI flags it and score >= threshold
        if attack_type != "normal" and score >= DETECT_THRESHOLD:
            severity = "high" if score >= 0.8 else "medium"
            try:
                attack_id = log_attack({
                    "attack_type": attack_type,
                    "source_ip": data.get("source_ip"),
                    "target_resource": "/fake_search",
                    "user_agent": data.get("user_agent"),
                    "payload": sanitize_string(payload_text),
                    "severity": severity,
                    "details": {"honeypot_event_id": event_id, "telemetry": data},
                    "anomaly_score": score
                })
            except Exception:
                logger.exception("log_attack failed from capture_honeypot (AI-only)")
    except Exception:
        logger.exception("Failed to run AI detection for capture_honeypot")

    # 3) anchoring (if available)
    tx_hash = None
    try:
        if anchor_data and event_id:
            tx_hash = anchor_data(data)
            if tx_hash:
                update_honeypot_anchor(event_id, tx_hash)
                # also update attack record blockchain hash if applicable
                if attack_id:
                    try:
                        conn = get_connection()
                        conn.execute("UPDATE attacks SET blockchain_tx_hash = ? WHERE id = ?", (tx_hash, attack_id))
                        conn.commit()
                        conn.close()
                    except Exception:
                        logger.exception("Failed updating attack with blockchain hash")
    except Exception:
        logger.exception("Anchoring failed in capture_honeypot")

    return jsonify({"event_id": event_id, "attack_id": attack_id, "tx_hash": tx_hash})

@app.route("/honeypot/submit", methods=["POST"])
def honeypot_submit():
    """
    Endpoint used by the fake honeypot page to submit telemetry (payload exec results).
    Does NOT require the X-API-KEY header because the page is same-origin.
    """
    data = request.get_json() or {}
    data["source_ip"] = data.get("source_ip") or request.remote_addr
    data["user_agent"] = data.get("user_agent") or request.headers.get("User-Agent", "")
    data["referringUrl"] = data.get("referringUrl") or request.referrer or ""
    payload_text = sanitize_string(data.get("payload") or data.get("alert_message") or "", max_length=5000)

    # 1) store raw honeypot event (for timeline / anchoring)
    try:
        event_id = log_honeypot_event(data)
    except Exception:
        logger.exception("log_honeypot_event failed")
        event_id = None

    # 2) AI-only decision for attack creation
    attack_id = None
    try:
        attack_type, score = detect_attack_ai(payload_text)
        if attack_type != "normal" and score >= DETECT_THRESHOLD:
            severity = "high" if score >= 0.8 else "medium"
            try:
                attack_id = log_attack({
                    "attack_type": attack_type,
                    "source_ip": data.get("source_ip"),
                    "target_resource": "/fake_search",
                    "user_agent": data.get("user_agent"),
                    "payload": payload_text,
                    "severity": severity,
                    "details": {"honeypot_event_id": event_id, "telemetry": data},
                    "anomaly_score": score
                })
            except Exception:
                logger.exception("log_attack failed from honeypot_submit (AI-only)")
    except Exception:
        logger.exception("Failed to run AI detection for honeypot_submit")

    # 3) Anchor the honeypot_event (if anchoring available)
    tx_hash = None
    try:
        if anchor_data and event_id:
            tx_hash = anchor_data(data)
            if tx_hash:
                update_honeypot_anchor(event_id, tx_hash)
    except Exception:
        logger.exception("Anchoring failed")

    return jsonify({"ok": True, "event_id": event_id, "attack_id": attack_id, "tx_hash": tx_hash}), 200

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
