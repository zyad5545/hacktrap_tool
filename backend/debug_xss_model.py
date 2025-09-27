# debug_xss_model.py
import os, joblib, traceback
m = joblib.load("data/xss_model.joblib")
clf = m["xss_clf"]
print("classes:", clf.classes_)

MODEL_PATHS = [
    "/app/data/xss_model.joblib",
    "ai_agent/data/xss_model.joblib",
    "./ai_agent/data/xss_model.joblib",
    "data/xss_model.joblib",
    "ai_agent/data/model.joblib",
    "./xss_model.joblib",
]

def try_load(p):
    try:
        m = joblib.load(p)
        return m
    except Exception as e:
        return e

for p in MODEL_PATHS:
    exists = os.path.exists(p)
    print("PATH:", p, "exists:", exists)
    if not exists:
        continue
    res = try_load(p)
    if isinstance(res, Exception):
        print("  load error:", type(res).__name__, str(res))
        traceback.print_exception(res, res, res.__traceback__)
        continue
    model = res
    print("  loaded type:", type(model))
    # if dict-like
    try:
        if isinstance(model, dict):
            print("  dict keys:", list(model.keys()))
            if "xss_vect" in model:
                vect = model["xss_vect"]
                clf = model["xss_clf"]
                X = vect.transform(["<script>alert(1)</script>"])
                prob = clf.predict_proba(X)[0]
                print("  vectorized clf.predict_proba =>", prob)
        else:
            # Try common cases: pipeline with predict_proba, or classifier needing transform
            if hasattr(model, "predict_proba"):
                try:
                    prob = model.predict_proba(["<script>alert(1)</script>"])[0]
                    print("  model.predict_proba(raw) =>", prob)
                except Exception as e:
                    print("  model.predict_proba(raw) failed:", e)
            if hasattr(model, "transform") and hasattr(model, "predict_proba"):
                try:
                    X = model.transform(["<script>alert(1)</script>"])
                    prob = model.predict_proba(X)[0]
                    print("  model.transform + predict_proba =>", prob)
                except Exception as e:
                    print("  model.transform/predict_proba failed:", e)
    except Exception:
        traceback.print_exc()
    print("-" * 60)
