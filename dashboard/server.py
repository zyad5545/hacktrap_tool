#!/usr/bin/env python3
# dashboard/server.py — proxy + live monitoring for HackTrap (final)

from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
import os, requests, logging
from pathlib import Path

app = Flask(__name__, static_folder='static', template_folder='.')
CORS(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("server")

BASE_DIR = Path(__file__).resolve().parent

# Backend URL + API key (container service name + port)
BACKEND_URL = os.getenv("BACKEND_URL", "http://hacktrap_backend:8000").rstrip("/")
HONEY_API_KEY = os.getenv("HONEY_API_KEY", "honeypot-secure-key")

@app.route('/')
def index():
    return send_from_directory(str(BASE_DIR), 'login.html')

# Generic helper to forward GET requests with X-API-KEY
def proxy_get(endpoint):
    url = f"{BACKEND_URL}{endpoint}"
    headers = {"X-API-KEY": HONEY_API_KEY}
    logger.info("Proxy GET -> %s (params=%s)", url, dict(request.args))
    try:
        r = requests.get(url, headers=headers, params=request.args, timeout=8)
    except requests.exceptions.RequestException as e:
        logger.exception("Error contacting backend for GET %s", endpoint)
        return jsonify({"success": False, "message": "Backend unreachable", "error": str(e)}), 502

    content_type = r.headers.get("Content-Type", "")
    if "application/json" in content_type:
        try:
            return jsonify(r.json()), r.status_code
        except Exception:
            pass
    return Response(r.text, status=r.status_code, content_type=content_type or "text/plain")

# Generic helper to forward POST requests with X-API-KEY
def proxy_post(endpoint):
    url = f"{BACKEND_URL}{endpoint}"
    headers = {"X-API-KEY": HONEY_API_KEY}
    # preserve JSON or form/body
    data = None
    json_body = None
    try:
        if request.is_json:
            json_body = request.get_json(silent=True)
        else:
            # form or raw
            data = request.form.to_dict() or request.get_data()
    except Exception:
        data = request.get_data()

    logger.info("Proxy POST -> %s (json=%s, keys=%s)", url, bool(json_body), (list(json_body.keys()) if isinstance(json_body, dict) else None))
    try:
        r = requests.post(url, headers=headers, params=request.args, json=json_body, data=None if json_body is not None else data, timeout=12)
    except requests.exceptions.RequestException as e:
        logger.exception("Error contacting backend for POST %s", endpoint)
        return jsonify({"success": False, "message": "Backend unreachable", "error": str(e)}), 502

    content_type = r.headers.get("Content-Type", "")
    if "application/json" in content_type:
        try:
            return jsonify(r.json()), r.status_code
        except Exception:
            pass
    return Response(r.text, status=r.status_code, content_type=content_type or "text/plain")

# Proxy GET endpoints
@app.route('/api/attacks', methods=['GET'])
def proxy_attacks():
    return proxy_get("/api/attacks")

@app.route('/api/events', methods=['GET'])
def proxy_events():
    return proxy_get("/api/events")

@app.route('/api/honeypot/events', methods=['GET'])
def proxy_honeypot_events():
    return proxy_get("/api/honeypot/events")

@app.route('/api/blockchain', methods=['GET'])
def proxy_blockchain():
    return proxy_get("/api/blockchain")

@app.route('/api/alerts', methods=['GET'])
def proxy_alerts():
    return proxy_get("/api/alerts")

@app.route('/api/attack_analysis', methods=['GET'])
def proxy_attack_analysis():
    return proxy_get("/api/attack_analysis")

@app.route('/api/system_health', methods=['GET'])
def proxy_system_health():
    return proxy_get("/api/system_health")

@app.route('/api/overview', methods=['GET'])
def proxy_overview():
    return proxy_get("/api/overview")

# Proxy POST endpoints needed by UI
@app.route('/api/clear_logs', methods=['POST'])
def proxy_clear_logs():
    return proxy_post("/api/clear_logs")

@app.route('/api/action', methods=['POST'])
def proxy_action():
    # forward operator actions (block_ip, etc.)
    return proxy_post("/api/action")

@app.route('/api/generate', methods=['POST'])
def proxy_generate():
    # forward to backend AI endpoint if exists
    return proxy_post("/api/generate")

# Proxy honeypot submit/capture endpoints (static pages POST here)
@app.route('/honeypot/submit', methods=['POST'])
def proxy_honeypot_submit():
    try:
        payload = request.get_json(silent=True) or request.form.to_dict() or request.data.decode('utf-8')
        backend_endpoint = f"{BACKEND_URL}/honeypot/submit"
        logger.info("Proxy honeypot submit -> %s", backend_endpoint)
        r = requests.post(backend_endpoint, json=payload, headers={"X-API-KEY": HONEY_API_KEY}, timeout=8)
        try:
            return jsonify(r.json()), r.status_code
        except Exception:
            return Response(r.text, status=r.status_code, content_type=r.headers.get("Content-Type", "text/plain"))
    except requests.exceptions.RequestException as e:
        logger.exception("Error contacting backend honeypot/submit")
        return jsonify({"success": False, "message": "Backend unreachable", "error": str(e)}), 502

@app.route('/honeypot/capture', methods=['POST'])
def proxy_honeypot_capture():
    try:
        payload = request.get_json(silent=True) or request.form.to_dict() or request.data.decode('utf-8')
        backend_endpoint = f"{BACKEND_URL}/honeypot/capture"
        logger.info("Proxy honeypot capture -> %s", backend_endpoint)
        r = requests.post(backend_endpoint, json=payload, headers={"X-API-KEY": HONEY_API_KEY}, timeout=8)
        try:
            return jsonify(r.json()), r.status_code
        except Exception:
            return Response(r.text, status=r.status_code, content_type=r.headers.get("Content-Type", "text/plain"))
    except requests.exceptions.RequestException as e:
        logger.exception("Error contacting backend honeypot/capture")
        return jsonify({"success": False, "message": "Backend unreachable", "error": str(e)}), 502

# Health
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"health": "ok"})

# Serve static UI assets from dashboard dir
@app.route('/<path:path>')
def serve_file(path):
    file_path = BASE_DIR / path
    if file_path.exists() and file_path.is_file():
        return send_from_directory(str(BASE_DIR), path)
    return "File not found", 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
