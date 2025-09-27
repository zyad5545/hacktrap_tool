# ai_engine/train_model.py
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

DATA_CSV = "../data/training_sample.csv"  # عدل المسار لو لازم
MODEL_OUT = "../data/model.pkl"

def load_data(path):
    df = pd.read_csv(path)
    # افتراض أن عندك أعمدة: text, label (label: 0 normal, 1 anomaly)
    return df['text'].fillna(''), df['label'].fillna(0).astype(int)

def train():
    X_text, y = load_data(DATA_CSV)
    vect = TfidfVectorizer(max_features=2000, ngram_range=(1,2))
    X = vect.fit_transform(X_text)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    # نحفظ الـ pipeline (vectorizer + clf)
    joblib.dump({'vect': vect, 'clf': clf}, MODEL_OUT)
    print("Model saved to", MODEL_OUT)

if __name__ == "__main__":
    os.makedirs(os.path.dirname(MODEL_OUT), exist_ok=True)
    train()