import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import pandas as pd

# Load existing data
xss_payloads = pd.read_csv('/app/xss_payloads.csv')['payload'].tolist()
normal_texts = pd.read_csv('/app/normal_texts.csv')['text'].tolist()

# Enhanced XSS examples
enhanced_xss = [
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "onerror=alert('XSS')",
    "onload=alert('XSS')",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "alert('XSS')",
    "prompt('XSS')",
    "confirm('XSS')",
    "eval('alert(\"XSS\")')",
    "document.cookie",
    "window.location",
    "javascript:void(0)",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>"
]

# Combine all XSS examples
all_xss = list(set(xss_payloads + enhanced_xss))
all_normal = normal_texts + [
    "hello world", "search query", "normal text", "testing",
    "example.com", "login page", "user input", "form data"
]

# Create labels
xss_labels = [1] * len(all_xss)
normal_labels = [0] * len(all_normal)

# Combine data
all_texts = all_xss + all_normal
all_labels = xss_labels + normal_labels

# Create and train model
vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=2000)
X = vectorizer.fit_transform(all_texts)

clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=15)
clf.fit(X, all_labels)

# Save the model
model = {
    "xss_vect": vectorizer,
    "xss_clf": clf
}

joblib.dump(model, "/app/xss_model.joblib")
print("Enhanced XSS model created and saved!")
