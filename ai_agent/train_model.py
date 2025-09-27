#!/usr/bin/env python3
# train_model.py — نسخة محسّنة نهائية من مدرّب النماذج

import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight
import numpy as np

# --- إعدادات ملفات البيانات ---
TEXT_CSV_FILENAMES = [
    "xss_payloads.csv",
    "sqli_payloads.csv",
    "bruteforce_payloads.csv",
    "normal_texts.csv",
]

NUMERIC_CSV = "training_sample.csv"

CANDIDATE_DATA_DIRS = [
    "./ai_agent/data",
    "./ai_agent",
    "./data",
    "../ai_agent/data",
    os.path.join(os.path.dirname(__file__), "ai_agent", "data"),
    os.path.join(os.path.dirname(__file__), "data"),
]

def find_data_dir():
    for d in CANDIDATE_DATA_DIRS:
        try:
            if os.path.isdir(d):
                for f in TEXT_CSV_FILENAMES + [NUMERIC_CSV]:
                    if os.path.exists(os.path.join(d, f)):
                        print(f"✅ تم العثور على مجلد البيانات: {d}")
                        return os.path.abspath(d)
        except Exception:
            pass
    fallback = os.path.abspath(os.path.join(os.path.dirname(__file__), "ai_agent", "data"))
    os.makedirs(fallback, exist_ok=True)
    print(f"⚠ لم يتم العثور على مجلد بيانات جاهز — سيتم استخدام: {fallback}")
    return fallback

DATA_DIR = find_data_dir()
ATTACK_MODEL_PATH = os.path.join(DATA_DIR, "attack_model.joblib")
XSS_MODEL_PATH = os.path.join(DATA_DIR, "xss_model.joblib")
NUMERIC_MODEL_PATH = os.path.join(DATA_DIR, "model.joblib")

# --- بناء إطار البيانات للنصوص ---
def build_text_dataframe():
    parts = []
    for csvname in TEXT_CSV_FILENAMES:
        path = os.path.join(DATA_DIR, csvname)
        if not os.path.exists(path):
            print(f"⚠ skip (not found): {path}")
            continue
        try:
            df = pd.read_csv(path, dtype=str, na_filter=False)
            if df.shape[1] == 0:
                continue
            if "text" not in df.columns:
                df = df.rename(columns={df.columns[0]: "text"})
            if "label" not in df.columns:
                label = os.path.basename(csvname).replace(".csv","").split("_")[0]
                df["label"] = label
            df = df[["text","label"]]
            df["text"] = df["text"].fillna("").astype(str).str.strip()
            df = df[df["text"] != ""].reset_index(drop=True)
            parts.append(df)
            print(f" + loaded {csvname} rows={len(df)}")
        except Exception as e:
            print(f" ! failed reading {path}: {e}")
    if not parts:
        return None
    df_all = pd.concat(parts, ignore_index=True)
    df_all["text"] = df_all["text"].fillna("").astype(str).str.strip()
    df_all = df_all[df_all["text"] != ""].reset_index(drop=True)
    return df_all if not df_all.empty else None

# --- تدريب نموذج النصوص ---
def train_text_model():
    df = build_text_dataframe()
    if df is None or df.empty:
        print(f"❌ No text data found in {DATA_DIR}. Place CSVs at least.")
        return

    # إزالة أي صفوف بدون label
    df = df[df["label"].astype(str).str.strip() != ""].reset_index(drop=True)
    if df.empty:
        print("❌ No valid labeled text rows found.")
        return

    # حذف أي فئات بها صف واحد فقط
    counts = df['label'].value_counts()
    valid_labels = counts[counts >= 2].index
    df = df[df['label'].isin(valid_labels)].reset_index(drop=True)
    if df.empty:
        print("❌ Not enough data after removing tiny classes.")
        return

    print("✅ text label counts:")
    print(df["label"].value_counts().to_string())

    X = df["text"].values
    y = df["label"].values
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    # حساب class_weight
    class_weights = compute_class_weight(
        "balanced",
        classes=np.array(range(len(le.classes_))),
        y=y_enc
    )
    clf = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight=dict(zip(range(len(le.classes_)), class_weights)),
        n_jobs=-1
    )

    vect = TfidfVectorizer(min_df=1, max_df=0.95, max_features=20000, ngram_range=(1,2))
    X_vec = vect.fit_transform(X)

    # stratify فقط إذا كل فئة ≥2
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X_vec, y_enc, test_size=0.2, random_state=42, stratify=y_enc
        )
    except ValueError:
        print("⚠ Not enough samples for stratified split — using unstratified split instead.")
        X_train, X_test, y_train, y_test = train_test_split(
            X_vec, y_enc, test_size=0.2, random_state=42
        )

    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    print("=== multiclass text model report ===")
    print(classification_report(y_test, preds, target_names=le.inverse_transform(sorted(set(y_enc)))))

    joblib.dump({"vect": vect, "clf": clf, "label_encoder": le}, ATTACK_MODEL_PATH)
    print(f"✅ saved multiclass attack model: {ATTACK_MODEL_PATH}")

    # --- نموذج XSS ثنائي ---
    if "xss" in df["label"].unique() and "normal" in df["label"].unique():
        df_x = df[df["label"].isin(["xss","normal"])].copy()
        df_x["text"] = df_x["text"].fillna("").astype(str).str.strip()
        df_x = df_x[df_x["text"] != ""]
        if len(df_x) >= 6:
            vx = TfidfVectorizer(min_df=1, max_df=0.95, max_features=10000, ngram_range=(1,2))
            Xvx = vx.fit_transform(df_x["text"].values)
            yx = (df_x["label"] == "xss").astype(int).values
            clf_x = RandomForestClassifier(n_estimators=100, random_state=42)
            clf_x.fit(Xvx, yx)
            joblib.dump({"xss_vect": vx, "xss_clf": clf_x}, XSS_MODEL_PATH)
            print(f"✅ saved binary XSS model: {XSS_MODEL_PATH}")
        else:
            print("⚠ not enough xss/normal rows for binary XSS model (need >=6).")

# --- تدريب نموذج البيانات الرقمية ---
def train_numeric_model():
    csv_file = os.path.join(DATA_DIR, NUMERIC_CSV)
    if not os.path.exists(csv_file):
        print(f" - numeric sample {csv_file} not found — skipping numeric model.")
        return
    try:
        df = pd.read_csv(csv_file)
        NUMERIC_FEATURES = ["cpu_percent","memory_percent","disk_usage","network_connections","process_count"]
        df = df.dropna(subset=NUMERIC_FEATURES + ["anomaly"])
        if df.empty:
            print("⚠ numeric dataset empty after dropping NaNs.")
            return
        X = df[NUMERIC_FEATURES].astype(float)
        y = df["anomaly"].astype(int)
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X, y)
        joblib.dump(clf, NUMERIC_MODEL_PATH)
        print(f"✅ saved numeric model: {NUMERIC_MODEL_PATH}")
    except Exception as e:
        print("⚠ failed to train numeric model:", e)

if __name__ == "__main__":
    print("Starting training — DATA_DIR:", DATA_DIR)
    train_text_model()
    train_numeric_model()
    print("Done.")
