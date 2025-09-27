# scripts/train_dummy_model.py
import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression

# بيانات عشوائية (100 عينة × 5 خصائص)
X = np.random.rand(100, 5)
y = np.random.randint(0, 2, 100)

model = LogisticRegression()
model.fit(X, y)

# حفظ الموديل
joblib.dump(model, "data/model.pkl")
print("✅ Dummy model saved to data/model.pkl")
