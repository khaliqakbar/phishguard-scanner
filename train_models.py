import time
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier

# 1. Load Data Fitur
print("1. Membaca dataset_features.csv...")
df = pd.read_csv("dataset_features.csv")

X = df.drop(columns=["label"])
y = df["label"]

# 2. Train-Test Split (80% Train, 20% Test)
print("2. Membagi data (Train: 80%, Test: 20%)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Standarisasi fitur (sangat penting untuk SVM)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Simpan scaler agar bisa dipakai saat deploy ke web
joblib.dump(scaler, "scaler.pkl")

# 3. Definisi Model
models = {
    "Random Forest": RandomForestClassifier(
        n_estimators=100, random_state=42, n_jobs=-1
    ),
    "XGBoost": XGBClassifier(
        n_estimators=100,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    ),
    "SVM (Linear)": CalibratedClassifierCV(
        LinearSVC(dual=False, random_state=42, max_iter=2000)
    )
}

# 4. Training & Evaluasi
results = {}

for name, model in models.items():
    print(f"\n================ Melatih {name} ================")
    start_time = time.time()
    
    # Model tree (RF & XGBoost) bisa pakai data unscaled/scaled, SVM wajib scaled
    if name == "SVM (Linear)":
        model.fit(X_train_scaled, y_train)
        y_pred = model.predict(X_test_scaled)
    else:
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        
    train_time = time.time() - start_time
    
    acc = accuracy_score(y_test, y_pred)
    print(f"Selesai dalam {train_time:.2f} detik")
    print(f"Akurasi: {acc * 100:.2f}%")
    print("\nLaporan Klasifikasi:")
    print(classification_report(y_test, y_pred, digits=4))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Simpan model terlatih ke file .pkl
    filename = f"{name.lower().replace(' ', '_').replace('(', '').replace(')', '')}_model.pkl"
    joblib.dump(model, filename)
    print(f"Model disimpan ke: {filename}")

print("\nSemua model berhasil dilatih dan dievaluasi!")