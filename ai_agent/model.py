# ai_engine/model.py
import os
import joblib
import numpy as np

MODEL_PATH = os.getenv("MODEL_PATH", "/app/model.joblib")

class AnomalyModel:
    def __init__(self, model_path=MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self.load()

    def load(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            print("Loaded model:", self.model_path)
        else:
            print("Model file not found at", self.model_path)
            self.model = None

    def predict_score(self, sample: dict):
        """
        sample: dict with numeric keys:
        cpu_percent, memory_percent, disk_usage, network_connections, process_count
        returns anomaly_score in range [0.0, 1.0] as float
        """
        if self.model is None:
            # fallback: heuristic simple score (0.0 normal)
            return 0.0

        # build feature array in correct order
        features = [
            float(sample.get("cpu_percent", 0.0)),
            float(sample.get("memory_percent", 0.0)),
            float(sample.get("disk_usage", 0.0)),
            float(sample.get("network_connections", 0.0)),
            float(sample.get("process_count", 0.0)),
        ]
        arr = np.array(features).reshape(1, -1)
        try:
            if hasattr(self.model, "predict_proba"):
                score = float(self.model.predict_proba(arr)[0, 1])
            else:
                score = float(self.model.predict(arr)[0])
        except Exception:
            score = 0.0
        # ensure native python float (not numpy.float64)
        return float(score)
