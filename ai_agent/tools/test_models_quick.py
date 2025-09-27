# tools/test_models_quick.py
import joblib, os
for p in ["ai_agent/data/attack_model.joblib","ai_agent/data/xss_model.joblib","ai_agent/data/model.joblib"]:
    print("Checking:", p, "->", os.path.exists(p))
    if os.path.exists(p):
        try:
            m = joblib.load(p)
            print(" Loaded:", type(m))
            # try a sample predict if possible
            if isinstance(m, dict):
                print(" dict keys:", list(m.keys()))
            else:
                print(" has predict?", hasattr(m,"predict"))
        except Exception as e:
            print(" load failed:", e)
print("Done")
