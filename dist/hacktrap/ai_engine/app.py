# ai_engine/app.py
import os
import joblib
import numpy as np
from flask import Flask, request, jsonify

MODEL_PATH = os.getenv("MODEL_PATH", "/data/model.pkl")  # نفذ mount ./data:/data في docker-compose

app = Flask(__name__)
model = None

def load_model():
    global model
    try:
        model = joblib.load(MODEL_PATH)
        print("Model loaded:", MODEL_PATH)
    except Exception as e:
        print("Failed to load model:", e)
        model = None

def make_json_serializable(v):
    # يحول numpy types وغيرها لأنواع Python الأصلية
    if isinstance(v, (np.generic,)):
        try:
            return v.item()
        except Exception:
            pass
    # لو لسه bool numpy
    if isinstance(v, (np.bool_,)):
        return bool(v)
    # لو list/tuple -> convert عناصرها
    if isinstance(v, (list, tuple)):
        return [make_json_serializable(x) for x in v]
    return v


@app.route("/predict", methods=["POST"])
def predict():
    payload = request.json or {}
    text = payload.get("details", "") or payload.get("text", "")
    attack_type = payload.get("attack_type", "")
    # fallback logic
    if model is None:
        # simple rule: brute_force -> high anomaly
        score = 0.9 if attack_type == "brute_force" else 0.0
        return jsonify({"anomaly_score": score})

    vect = model['vect']
    clf = model['clf']
    X = vect.transform([text])
    prob = clf.predict_proba(X)[0]
    # نفترض الفئة 1 هي anomaly
    score = float(prob[1]) if len(prob) > 1 else float(prob[0])
    return jsonify({"anomaly_score": score})
    
if __name__ == "__main__":
    load_model()
    app.run(host="0.0.0.0", port=5000)