#!/usr/bin/env python3
# ai_engine/train_model.py — robust trainer (handles NaN, auto-detects data dir)

import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder

CANDIDATE_DATA_DIRS = [
    "./data",
    "./ai_agent/data",
    "./ai_agent",
    "../data",
    "../ai_agent/data",
    os.path.join(os.path.dirname(__file__), "data"),
]

TEXT_CSV_FILENAMES = [
    "xss_payloads.csv",
    "sqli_payloads.csv",
    "bruteforce_payloads.csv",
    "normal_texts.csv"
]

NUMERIC_CSV = "training_sample.csv"

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
    fallback = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
    os.makedirs(fallback, exist_ok=True)
    print(f"⚠ لم يتم العثور على مجلد بيانات جاهز — سيتم استخدام: {fallback}")
    return fallback

DATA_DIR = find_data_dir()
ATTACK_MODEL_PATH = os.path.join(DATA_DIR, "attack_model.joblib")
XSS_MODEL_PATH = os.path.join(DATA_DIR, "xss_model.joblib")
NUMERIC_MODEL_PATH = os.path.join(DATA_DIR, "model.joblib")

def build_text_dataframe():
    parts = []
    for csvname in TEXT_CSV_FILENAMES:
        p = os.path.join(DATA_DIR, csvname)
        if not os.path.exists(p):
            print(f" - مفقود: {csvname} (تخطي)")
            continue
        try:
            # اقرأ كسلاسل ونمنع NaN عبر na_filter=False
            df = pd.read_csv(p, dtype=str, na_filter=False)
            if df.shape[1] == 0:
                continue
            # إذا لا يوجد عمود "text" نعيد تسمية العمود الأول
            if "text" not in df.columns:
                df = df.rename(columns={df.columns[0]: "text"})
            if "label" not in df.columns:
                # افترض اسم الملف كتصنيف (sqli, bruteforce, xss, normal)
                name = os.path.basename(csvname).replace(".csv","")
                label = name.split("_")[0]
                df["label"] = label
            df = df[["text","label"]]
            parts.append(df)
            print(f" + تم تحميل {csvname} (rows={len(df)})")
        except Exception as e:
            print(f" ! خطأ بقراءة {csvname}: {e}")
    if not parts:
        return None
    df_all = pd.concat(parts, ignore_index=True)
    # تنظيف: املأ القيم الفارغة ثم احذف السطور الفارغة
    df_all["text"] = df_all["text"].fillna("").astype(str).str.strip()
    df_all = df_all[df_all["text"] != ""].reset_index(drop=True)
    if df_all.empty:
        return None
    return df_all

def train_text_model():
    df = build_text_dataframe()
    if df is None or df.empty:
        print("❌ لا توجد بيانات نصية كافية لبناء نموذج النص.")
        return
    print("✅ إحصاء الفئات النصية:")
    print(df["label"].value_counts().to_string())

    X = df["text"].astype(str).values
    y = df["label"].astype(str).values
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    if len(X) < 2 or len(set(y_enc)) < 2:
        print("⚠ بيانات النص قليلة جداً أو كلها لفئة واحدة — لا يمكن تدريب نموذج تصنيف متعدد بشكل موثوق.")
        return

    vect = TfidfVectorizer(min_df=1, max_df=0.95, max_features=20000, ngram_range=(1,2))
    try:
        X_vec = vect.fit_transform(X)
    except Exception as e:
        print("❌ فشل تحويل النصوص إلى سمات TF-IDF:", e)
        return

    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)

    try:
        X_train, X_test, y_train, y_test = train_test_split(X_vec, y_enc, test_size=0.2, random_state=42, stratify=y_enc)
    except Exception:
        X_train, X_test, y_train, y_test = train_test_split(X_vec, y_enc, test_size=0.2, random_state=42)

    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    try:
        print("=== تقرير نموذج النص ===")
        print(classification_report(y_test, preds, target_names=le.classes_))
    except Exception:
        print(classification_report(y_test, preds))

    # نحفظ النموذج متعدد الفئات كـ attack_model.joblib (vect+clf+label_encoder)
    joblib.dump({"vect": vect, "clf": clf, "label_encoder": le}, ATTACK_MODEL_PATH)
    print(f"✅ حفظ نموذج الهجوم النصّي: {ATTACK_MODEL_PATH}")

    # بناء نموذج ثنائي XSS إذا متوفر عدد عينات كافٍ
    if "xss" in list(le.classes_):
        try:
            df_x = df[df["label"].isin(["xss","normal"])].copy()
            df_x["text"] = df_x["text"].fillna("").astype(str).str.strip()
            df_x = df_x[df_x["text"] != ""]
            if len(df_x) >= 10 and df_x["label"].nunique() == 2:
                vx = TfidfVectorizer(min_df=1, max_df=0.95, max_features=10000, ngram_range=(1,2))
                Xvx = vx.fit_transform(df_x["text"])
                yx = (df_x["label"] == "xss").astype(int)
                clf_x = RandomForestClassifier(n_estimators=100, random_state=42)
                clf_x.fit(Xvx, yx)
                joblib.dump({"xss_vect": vx, "xss_clf": clf_x}, XSS_MODEL_PATH)
                print(f"✅ حفظ نموذج XSS الثنائي: {XSS_MODEL_PATH}")
            else:
                print("⚠ بيانات XSS غير كافية لبناء نموذج ثنائي (تأكد أن لديك ≥10 عينات لكل من xss و normal).")
        except Exception as e:
            print("⚠ فشل بناء نموذج XSS الثنائي:", e)

def train_numeric_model():
    p = os.path.join(DATA_DIR, NUMERIC_CSV)
    if not os.path.exists(p):
        print(f" - ملف {NUMERIC_CSV} غير موجود — سيتم تخطي النموذج الرقمي.")
        return
    try:
        df = pd.read_csv(p)
        NUMERIC_FEATURES = ["cpu_percent", "memory_percent", "disk_usage", "network_connections", "process_count"]
        df = df.dropna(subset=NUMERIC_FEATURES + ["anomaly"])
        if df.empty:
            print("⚠ بيانات عددية فارغة بعد تنظيف القيم الناقصة.")
            return
        X = df[NUMERIC_FEATURES].astype(float)
        y = df["anomaly"].astype(int)
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X, y)
        joblib.dump(clf, NUMERIC_MODEL_PATH)
        print(f"✅ حفظ النموذج الرقمي: {NUMERIC_MODEL_PATH}")
    except Exception as e:
        print("⚠ فشل تدريب النموذج الرقمي:", e)

if __name__ == "__main__":
    print("بدء التدريب — مجلد البيانات:", DATA_DIR)
    train_text_model()
    train_numeric_model()
    print("انتهى التدريب.")
