"""
Quick prediction test — loads a random sample from the dataset
and shows what the model predicts vs the real label.

Run: python ml/predict.py
"""

import random
import joblib
import numpy as np
import pyarrow.parquet as pq
from pathlib import Path

ML_DIR    = Path(__file__).parent
MODELS    = ML_DIR / "models"

model       = joblib.load(MODELS / "rf_model.joblib")
scaler      = joblib.load(MODELS / "scaler.joblib")
feat_cols   = joblib.load(MODELS / "feature_cols.joblib")

table = pq.read_table(ML_DIR / "Obfuscated-MalMem2022.parquet")
df    = table.to_pydict()
n     = len(df["Category"])

# Pick 5 random samples and predict each one
print("\nTesting model on 5 random samples from the dataset:\n")
print(f"{'#':<4} {'Actual':<25} {'Predicted':<15} {'Confidence':<12} {'Correct?'}")
print("-" * 70)

for i in range(5):
    idx     = random.randint(0, n - 1)
    cat     = str(df["Category"][idx])
    actual  = 1 if cat.startswith("Ransomware") else 0

    features = np.array([[df[col][idx] for col in feat_cols]])
    scaled   = scaler.transform(features)
    pred     = model.predict(scaled)[0]
    proba    = model.predict_proba(scaled)[0][1]

    actual_label = "Ransomware" if actual == 1 else "Not Ransomware"
    pred_label   = "Ransomware" if pred == 1 else "Not Ransomware"
    correct      = "✅" if pred == actual else "❌"

    short_cat = cat.split("-")[0] + "-" + cat.split("-")[1] if "-" in cat else cat
    print(f"{i+1:<4} {short_cat:<25} {pred_label:<15} {proba:.2%}        {correct}")
