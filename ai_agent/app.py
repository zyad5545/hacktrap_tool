#!/usr/bin/env python3
# ai_agent/app.py — simple microservice that serves attack_model / xss_model predictions
import os
import joblib
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ai_agent")

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
ATTACK_MODEL = os.path.join(DATA_DIR, "attack_model.joblib")
XSS_MODEL = os.path.join(DATA_DIR, "xss_model.joblib")

attack_model = None
xss_model = None

def try_load(path):
    try:
        if os.path.exists(path):
            m = joblib.load(path)
            logger.info("Loaded model: %s (type=%s)", path, type(m))
            return m
    except Exception:
        logger.exception("Failed loading model %s", path)
    return None

attack_model = try_load(ATTACK_MODEL)
xss_model = try_load(XSS_MODEL)

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True) or {}
    text = str(data.get("query") or data.get("text") or "")
    response = {"malicious": False, "score": 0.0, "attack_type": "normal", "results": []}

    if not text.strip():
        return jsonify(response)

    # 1) multi-class attack_model (dict shape)
    try:
        if attack_model and isinstance(attack_model, dict):
            X = attack_model["vect"].transform([text])
            probs = attack_model["clf"].predict_proba(X)[0]
            classes = attack_model["clf"].classes_
            idx = int(probs.argmax())
            attack_type = str(classes[idx])
            score = float(probs[idx])
            response.update({"attack_type": attack_type, "score": score, "malicious": attack_type != "normal" and score >= 0.5})
            if response["malicious"]:
                response["results"].append(f"{attack_type} detected by attack_model")
            return jsonify(response)
    except Exception:
        logger.exception("attack_model prediction error (continuing)")

    # 2) binary xss model
    try:
        if xss_model and isinstance(xss_model, dict):
            X = xss_model["xss_vect"].transform([text])
            prob = float(xss_model["xss_clf"].predict_proba(X)[0][1])
            attack_type = "xss" if prob >= 0.5 else "normal"
            response.update({"attack_type": attack_type, "score": prob, "malicious": attack_type == "xss"})
            if response["malicious"]:
                response["results"].append("xss detected by xss_model")
            return jsonify(response)
    except Exception:
        logger.exception("xss_model prediction error (continuing)")

    # no model matched
    return jsonify(response)

@app.route("/health")
def health():
    return jsonify({
        "health": "ok",
        "attack_model": os.path.exists(ATTACK_MODEL),
        "xss_model": os.path.exists(XSS_MODEL)
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    logger.info("Starting ai_agent on port %s", port)
    app.run(host="0.0.0.0", port=port)
