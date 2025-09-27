#!/usr/bin/env python3
# backend/app.py — AI-only detection (no heuristic fallback). Honeypot redirect only for XSS.

import os
import joblib
import urllib.parse
import logging
import time
import json
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

# local DB helpers
from db import init_db, ensure_honeypot_schema, log_attack, log_honeypot_event, update_honeypot_anchor, get_connection

# optional blockchain anchoring helper (if available)
try:
    from blockchain import anchor_data
except Exception:
    anchor_data = None

# ===== APP SETUP =====
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app_start = time.time()

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
DB_PATH = os.getenv("DB_PATH", "data/app.db")
ANCHOR_DIR = os.getenv("ANCHOR_DIR", "anchor_records")
BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))  # threshold for failed login -> brute force

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
    Call remote AI endpoint. Return normalized dict with attack_type and score.
    """
    if not AI_ENDPOINT:
        return {"attack_type": "normal", "score": 0.0}
    try:
        r = requests.post(AI_ENDPOINT, json={"query": text}, timeout=5)
        if r.status_code == 200:
            j = r.json()
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
    Returns (attack_type, score).
    AI-only detection (no heuristic fallback).
    Priority:
      1) FORCE_AI_ONLY -> remote AI
      2) PREFER_REMOTE_AI -> remote AI
      3) Local xss_model -> binary XSS detector
      4) Local attack_model -> generic classification
      5) Remote AI fallback
      6) Default normal
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

    # 3) Local XSS model (binary detector)
    try:
        if xss_model is not None:
            # two common saved-model formats supported
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
            # Only treat as XSS if the model's predicted class explicitly equals 'xss'
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
        "have_xss_model": bool(xss_model),
        "uptime_seconds": int(time.time() - app_start)
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
            # NOTE: remove show_message/message to avoid displaying "لقد تم خداع الهاكر" banner on client.
            return jsonify({
                "action": "honeypot",
                "redirect": redirect_url
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

    # If AI detected something (e.g., brute force signature from model), log + honeypot event
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

        # For login, instruct client to show trapped banner (legacy). We keep this for login flow.
        return jsonify({"show_message": True, "message": "لقد تم خداع الهاكر"}), 200

    # Demo login success
    if username == "demo" and password == "demo123":
        return jsonify({"success": True, "message": "Logged in"}), 200

    # --- Invalid credentials branch: record failure and escalate to brute-force if repeated ---
    try:
        log_attack({
            "attack_type": "login_failure",
            "source_ip": request.remote_addr,
            "target_resource": "/login",
            "user_agent": request.headers.get("User-Agent", ""),
            "payload": payload,
            "severity": "low",
            "details": {"note": "failed credential attempt"},
            "anomaly_score": 0.0
        })
    except Exception:
        logger.exception("Failed logging login_failure")

    # Count recent login_failure attempts from this IP (simple count across attacks table)
    try:
        conn = get_connection()
        row = conn.execute(
            "SELECT COUNT(*) FROM attacks WHERE source_ip = ? AND target_resource = ? AND attack_type = ?",
            (request.remote_addr, "/login", "login_failure")
        ).fetchone()
        conn.close()
        failure_count = int(row[0]) if row and row[0] is not None else 0
    except Exception:
        logger.exception("Failed counting login failures")
        failure_count = 0

    logger.info("Login failures from %s: %d", request.remote_addr, failure_count)

    # If failure_count >= threshold, escalate to brute_force and instruct to honeypot (try ssh)
    if failure_count >= BRUTE_FORCE_THRESHOLD:
        try:
            # Log a proper brute_force attack record
            log_attack({
                "attack_type": "brute_force",
                "source_ip": request.remote_addr,
                "target_resource": "/login",
                "user_agent": request.headers.get("User-Agent", ""),
                "payload": f"brute-force detected after {failure_count} failures",
                "severity": "high",
                "details": {"failures": failure_count},
                "anomaly_score": 1.0
            })
        except Exception:
            logger.exception("Failed logging brute_force escalation")

        # Attempt to craft an SSH URI to cowrie (note: browsers may not open ssh:// URIs)
        try:
            host = request.host.split(':')[0] if request.host else request.remote_addr
            ssh_uri = f"ssh://{host}:2222"
            # Also provide a human-readable fallback page we host
            fallback = f"/ssh_honeypot.html?host={urllib.parse.quote_plus(host)}"
            # Also log a honeypot event
            try:
                log_honeypot_event({
                    "source_ip": request.remote_addr,
                    "user_agent": request.headers.get("User-Agent", ""),
                    "payload": payload,
                    "note": "escalated to ssh honeypot",
                    "referringUrl": request.referrer or ""
                })
            except Exception:
                logger.exception("log_honeypot_event failed")
            logger.info("Escalating %s to SSH honeypot: %s (fallback %s)", request.remote_addr, ssh_uri, fallback)
            return jsonify({
                "action": "honeypot",
                "redirect": ssh_uri,         # client may attempt to open this
                "fallback": fallback,        # fallback in case ssh:// not handled
                "show_message": True,
                "message": "لقد تم خداع الهاكر"
            }), 200
        except Exception:
            logger.exception("Failed to build ssh honeypot redirect")

    # Default invalid credentials response
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
    payload_lower = (payload_text or "").lower()

    # 1) store honeypot event (raw)
    try:
        event_id = log_honeypot_event(data)
    except Exception:
        logger.exception("log_honeypot_event failed in capture_honeypot")
        event_id = None

    # 2) decide whether to also create an attack record (link telemetry -> attacks)
    try:
        # simple heuristics to mark as xss if likely
        likely_xss = ("<script" in payload_lower) or ("alert(" in payload_lower) or ("onerror=" in payload_lower)
        attack_type = data.get("attack_type") or ("xss" if likely_xss else "honeypot_event")
        executed = bool(data.get("executed")) or bool(data.get("alert_message"))
        severity = "high" if executed or likely_xss else "medium"

        payload_summary = sanitize_string(payload_text or data.get("alert_message") or "")

        # Log an attack so it appears in attacks table & dashboard
        try:
            log_attack({
                "attack_type": attack_type,
                "source_ip": data.get("source_ip"),
                "target_resource": "/fake_search",
                "user_agent": data.get("user_agent"),
                "payload": payload_summary,
                "severity": severity,
                "details": {"honeypot_event_id": event_id, "telemetry": data},
                "anomaly_score": 0.95 if executed else (0.9 if likely_xss else 0.6)
            })
        except Exception:
            logger.exception("log_attack failed from capture_honeypot")
    except Exception:
        logger.exception("Failed to build attack record from capture_honeypot")

    # 3) anchoring (if available)
    tx_hash = None
    try:
        if anchor_data and event_id:
            tx_hash = anchor_data(data)
            if tx_hash:
                update_honeypot_anchor(event_id, tx_hash)
    except Exception:
        logger.exception("Anchoring failed in capture_honeypot")

    return jsonify({"event_id": event_id, "tx_hash": tx_hash})


@app.route("/honeypot/submit", methods=["POST"])
def honeypot_submit():
    """
    Endpoint used by the fake honeypot page to submit telemetry (payload exec results).
    Does NOT require the X-API-KEY header because the page is same-origin.
    """
    data = request.get_json() or {}
    # normalize fields and sanity-check
    data["source_ip"] = data.get("source_ip") or request.remote_addr
    data["user_agent"] = data.get("user_agent") or request.headers.get("User-Agent", "")
    data["referringUrl"] = data.get("referringUrl") or request.referrer or ""

    # 1) store raw honeypot event (for timeline / anchoring)
    try:
        event_id = log_honeypot_event(data)
    except Exception:
        logger.exception("log_honeypot_event failed")
        event_id = None

    # 2) If the payload appears to be an attack (or attack_type provided), also write an attacks record
    try:
        # determine attack_type and severity from incoming telemetry
        attack_type = data.get("attack_type") or "xss" if ("<script" in (data.get("payload") or "").lower() or "alert(" in (data.get("payload") or "").lower()) else "honeypot_event"
        executed = bool(data.get("executed")) or bool(data.get("alert_message"))
        severity = "high" if executed else "medium"

        # Build a payload string safe for DB (sanitize length)
        payload_summary = sanitize_string(data.get("payload") or data.get("alert_message") or "")

        # Log attack record so it shows in dashboard/attacks table
        try:
            log_attack({
                "attack_type": attack_type,
                "source_ip": data.get("source_ip"),
                "target_resource": "/fake_search",
                "user_agent": data.get("user_agent"),
                "payload": payload_summary,
                "severity": severity,
                "details": {"honeypot_event_id": event_id, "telemetry": data},
                "anomaly_score": 0.9 if executed else 0.6
            })
        except Exception:
            logger.exception("log_attack failed from honeypot_submit")
    except Exception:
        logger.exception("Failed to build attack record from honeypot telemetry")

    # 3) Anchor the honeypot_event (if anchoring available)
    tx_hash = None
    try:
        if anchor_data and event_id:
            tx_hash = anchor_data(data)
            if tx_hash:
                update_honeypot_anchor(event_id, tx_hash)
    except Exception:
        logger.exception("Anchoring failed")

    return jsonify({"ok": True, "event_id": event_id, "tx_hash": tx_hash}), 200

@app.route("/api/action", methods=["POST"])
@require_api_key
def api_action():
    """
    Simple operator actions endpoint.
    Supported:
      - block_ip : logs a manual_block attack record for operator action
    """
    data = request.get_json() or {}
    action = data.get("action")
    if not action:
        return jsonify({"ok": False, "message": "missing action"}), 400

    if action == "block_ip":
        ip = data.get("ip")
        if not ip:
            return jsonify({"ok": False, "message": "missing ip"}), 400
        try:
            # Log a manual action as an attack record (non-destructive)
            log_attack({
                "attack_type": "manual_block",
                "source_ip": ip,
                "target_resource": "operator_action",
                "user_agent": request.headers.get("User-Agent", ""),
                "payload": f"blocked by operator {ip}",
                "severity": "low",
                "details": {"source": "operator"},
                "anomaly_score": 0.0
            })
            logger.info("Operator blocked IP: %s", ip)
            return jsonify({"ok": True, "message": f"blocked {ip}"}), 200
        except Exception:
            logger.exception("Failed to log manual_block")
            return jsonify({"ok": False, "message": "internal error"}), 500

    return jsonify({"ok": False, "message": "unknown action"}), 400

@app.route("/api/honeypot/events", methods=["GET"])
@require_api_key
def list_events():
    conn = get_connection()
    rows = [dict(r) for r in conn.execute("SELECT * FROM honeypot_events ORDER BY id DESC LIMIT 200")]
    conn.close()
    return jsonify(rows)

# ----- New monitoring endpoints for dashboard -----
@app.route("/api/attacks", methods=["GET"])
@require_api_key
def api_attacks():
    conn = get_connection()
    rows = [dict(r) for r in conn.execute("SELECT * FROM attacks ORDER BY id DESC LIMIT 200")]
    conn.close()
    return jsonify({"attacks": rows})

@app.route("/api/blockchain", methods=["GET"])
@require_api_key
def api_blockchain():
    records = []
    # 1) collect txs from attacks table
    try:
        conn = get_connection()
        for r in conn.execute("SELECT DISTINCT blockchain_tx_hash FROM attacks WHERE blockchain_tx_hash IS NOT NULL"):
            tx = r[0]
            if tx:
                records.append({"id": tx, "source": "attacks_table"})
        # anchored txs from honeypot_events
        for r in conn.execute("SELECT DISTINCT anchored_tx FROM honeypot_events WHERE anchored_tx IS NOT NULL"):
            tx = r[0]
            if tx:
                records.append({"id": tx, "source": "honeypot_events"})
        conn.close()
    except Exception:
        logger.exception("Failed to read DB for blockchain records")

    # 2) also scan anchor_records directory if present
    try:
        if os.path.isdir(ANCHOR_DIR):
            for fname in sorted(os.listdir(ANCHOR_DIR), reverse=True)[:100]:
                path = os.path.join(ANCHOR_DIR, fname)
                mtime = None
                try:
                    mtime = os.path.getmtime(path)
                except Exception:
                    pass
                records.append({"id": fname, "source": "anchor_dir", "mtime": mtime})
    except Exception:
        logger.exception("Failed to scan anchor records directory")

    return jsonify({"records": records})

@app.route("/api/alerts", methods=["GET"])
@require_api_key
def api_alerts():
    alerts = []
    try:
        conn = get_connection()
        # consider recent high/critical attacks as alerts
        rows = conn.execute("SELECT id, timestamp, attack_type, source_ip, severity, payload FROM attacks WHERE severity IN ('high','critical') ORDER BY id DESC LIMIT 50").fetchall()
        conn.close()
        for r in rows:
            rr = dict(r)
            alerts.append({
                "id": f"atk-{rr.get('id')}",
                "title": f"{rr.get('attack_type') or 'attack'} from {rr.get('source_ip')}",
                "description": (rr.get("payload") or "")[:200],
                "time": rr.get("timestamp") or None,
                "severity": rr.get("severity") or "high",
                "recorded": True
            })
    except Exception:
        logger.exception("Failed to fetch alerts")
    return jsonify({"alerts": alerts})

@app.route("/api/attack_analysis", methods=["GET"])
@require_api_key
def api_attack_analysis():
    try:
        conn = get_connection()
        types = {r[0]: r[1] for r in conn.execute("SELECT attack_type, COUNT(*) as cnt FROM attacks GROUP BY attack_type").fetchall()}
        severities = {r[0]: r[1] for r in conn.execute("SELECT severity, COUNT(*) as cnt FROM attacks GROUP BY severity").fetchall()}
        total = conn.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        conn.close()
        return jsonify({"total_attacks": total, "by_type": types, "by_severity": severities})
    except Exception:
        logger.exception("Failed to compute attack analysis")
        return jsonify({"total_attacks": 0, "by_type": {}, "by_severity": {}})

@app.route("/api/system_health", methods=["GET"])
@require_api_key
def api_system_health():
    # lightweight health: DB size, counts, uptime
    info = {"uptime_seconds": int(time.time() - app_start)}
    try:
        db_path = DB_PATH
        if os.path.exists(db_path):
            info["db_bytes"] = os.path.getsize(db_path)
        else:
            info["db_bytes"] = None
        conn = get_connection()
        info["attacks_count"] = conn.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        info["honeypot_events_count"] = conn.execute("SELECT COUNT(*) FROM honeypot_events").fetchone()[0]
        conn.close()
    except Exception:
        logger.exception("Failed to compute system health")
    return jsonify(info)

@app.route("/api/overview", methods=["GET"])
@require_api_key
def api_overview():
    # combined small summary for dashboard
    try:
        attacks_resp = api_attack_analysis().get_json()
        events_resp = api_attacks().get_json()  # will be dict {"attacks": [...]}
        blockchain_resp = api_blockchain().get_json()
        alerts_resp = api_alerts().get_json()
        health_resp = api_system_health().get_json()
        return jsonify({
            "summary": attacks_resp,
            "recent_attacks": events_resp.get("attacks", [])[:20],
            "blockchain": blockchain_resp.get("records", []),
            "alerts": alerts_resp.get("alerts", []),
            "system_health": health_resp
        })
    except Exception:
        logger.exception("Failed to build overview")
        return jsonify({})

# ----- New endpoint: Clear logs -----
@app.route("/api/clear_logs", methods=["POST"])
@require_api_key
def api_clear_logs():
    """مسح هجمات و honeypot_events وملفات anchor_records -> إعادة تعيين العدادات."""
    try:
        conn = get_connection()
        conn.execute("DELETE FROM attacks")
        conn.execute("DELETE FROM honeypot_events")
        conn.commit()
        conn.close()
        # محاولة حذف ملفات anchor_records إن وُجدت
        try:
            if os.path.isdir(ANCHOR_DIR):
                for fname in os.listdir(ANCHOR_DIR):
                    path = os.path.join(ANCHOR_DIR, fname)
                    try:
                        os.remove(path)
                    except Exception:
                        logger.exception("Failed to remove anchor file %s", path)
        except Exception:
            logger.exception("Failed clearing anchor_records directory")
        logger.info("Cleared logs: attacks & honeypot_events & anchor_records")
        return jsonify({"ok": True, "message": "Cleared logs"}), 200
    except Exception:
        logger.exception("Failed to clear logs")
        return jsonify({"ok": False, "message": "Failed to clear logs"}), 500

# Init DB
try:
    init_db()
    ensure_honeypot_schema()
    logger.info("DB initialized (tables ensured).")
except Exception:
    logger.exception("DB init failed")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
