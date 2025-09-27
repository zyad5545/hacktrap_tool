# create_simple_model.py
import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

DATA_DIR = "ai_agent/data"
os.makedirs(DATA_DIR, exist_ok=True)
OUT = os.path.join(DATA_DIR, "xss_model.joblib")

xss_examples = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "onerror=alert('XSS')"
]
normal_examples = [
    "hello", "search query", "normal text", "user input"
]

texts = xss_examples + normal_examples
labels = [1]*len(xss_examples) + [0]*len(normal_examples)

vect = TfidfVectorizer()
X = vect.fit_transform(texts)
clf = RandomForestClassifier(n_estimators=20, random_state=42)
clf.fit(X, labels)

joblib.dump({"xss_vect": vect, "xss_clf": clf}, OUT)
print("Simple XSS model created at", OUT)
