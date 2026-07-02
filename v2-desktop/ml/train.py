"""
CyberShield v2 — ML Training Pipeline
---------------------------------------
Trains a Random Forest classifier to detect ransomware from memory
forensics features extracted by the Volatility framework.

Dataset: CIC-MalMem-2022 (Obfuscated variant)
Source:  Canadian Institute for Cybersecurity / Kaggle
File:    Obfuscated-MalMem2022.parquet

WHAT WE'RE TRAINING:
  Binary classification — Ransomware (1) vs Everything Else (0)
  "Everything else" includes Benign, Spyware, and Trojan samples.
  This means the model learns specifically what makes ransomware
  different from ALL other kinds of activity, not just benign.

WHY BINARY AND NOT MULTI-CLASS?
  Our tool has one job: detect ransomware. We don't need to know if
  something is a Trojan or Spyware — we just need to know if it's
  ransomware. Binary keeps the model focused and the output simple:
  a single probability score between 0.0 and 1.0.

HOW TO RUN:
  cd v2-desktop
  python ml/train.py
"""

import os
import sys
import time
import joblib
import pyarrow.parquet as pq
import numpy as np
from pathlib import Path
from collections import Counter

# ---------------------------------------------------------------------------
# We need scikit-learn — install it if missing
# ---------------------------------------------------------------------------
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    from sklearn.metrics import (
        classification_report, confusion_matrix,
        roc_auc_score, accuracy_score
    )
except ImportError:
    print("Installing scikit-learn...")
    os.system(f"{sys.executable} -m pip install scikit-learn --break-system-packages -q")
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    from sklearn.metrics import (
        classification_report, confusion_matrix,
        roc_auc_score, accuracy_score
    )

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ML_DIR     = Path(__file__).parent
DATA_FILE  = ML_DIR / "Obfuscated-MalMem2022.parquet"
MODELS_DIR = ML_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Step 1 — Load the dataset
# ---------------------------------------------------------------------------
def load_data():
    print("\n[1/6] Loading dataset...")
    table = pq.read_table(DATA_FILE)
    df = table.to_pydict()

    # Pull the Category column and all feature columns
    categories = df["Category"]
    feature_cols = [
        col for col in table.schema.names
        if col not in ("Category", "Class")
    ]

    X = np.array([[df[col][i] for col in feature_cols] for i in range(len(categories))])

    # Binary label: Ransomware=1, everything else=0
    y = np.array([1 if str(c).startswith("Ransomware") else 0 for c in categories])

    label_counts = Counter(y)
    print(f"    Rows loaded:        {len(y):,}")
    print(f"    Features per row:   {X.shape[1]}")
    print(f"    Ransomware (1):     {label_counts[1]:,}  ({label_counts[1]/len(y)*100:.1f}%)")
    print(f"    Not ransomware (0): {label_counts[0]:,}  ({label_counts[0]/len(y)*100:.1f}%)")

    return X, y, feature_cols


# ---------------------------------------------------------------------------
# Step 2 — Split into training and test sets
# ---------------------------------------------------------------------------
def split_data(X, y):
    """
    WHY DO WE SPLIT?
    We train on 80% of the data and hold back 20% as a test set.
    The model never sees the test set during training — it's used only
    to measure how well the model generalises to data it hasn't seen.
    If we tested on the same data we trained on, we'd get 99%+ accuracy
    that means nothing in the real world (the model just memorised answers).

    stratify=y ensures both splits have the same % of ransomware samples.
    """
    print("\n[2/6] Splitting data (80% train / 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,    # fixed seed = reproducible results
        stratify=y          # keep class balance in both splits
    )
    print(f"    Training samples:  {len(X_train):,}")
    print(f"    Test samples:      {len(X_test):,}")
    return X_train, X_test, y_train, y_test


# ---------------------------------------------------------------------------
# Step 3 — Scale features
# ---------------------------------------------------------------------------
def scale_features(X_train, X_test):
    """
    WHY SCALE?
    Our features have very different ranges:
      pslist.nproc might be 50–200
      handles.nhandles might be 5,000–50,000
      malfind.ninjections might be 0–5

    Without scaling, the model gives too much weight to large-valued
    features just because they're bigger numbers.
    StandardScaler transforms every feature to have mean=0, std=1.
    """
    print("\n[3/6] Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)  # learn mean/std from train only
    X_test_scaled  = scaler.transform(X_test)       # apply same transform to test
    print("    Done.")
    return scaler, X_train_scaled, X_test_scaled


# ---------------------------------------------------------------------------
# Step 4 — Train the Random Forest
# ---------------------------------------------------------------------------
def train_model(X_train, y_train):
    """
    WHY RANDOM FOREST?
    A Random Forest builds many decision trees (n_estimators=200), each
    trained on a random subset of the data and features. The final
    prediction is a vote across all trees.

    Benefits for security:
    - Handles mixed feature types (counts, averages, booleans) well
    - Gives probability scores (not just yes/no)
    - Resistant to overfitting
    - Fast to train and predict

    class_weight='balanced' tells the model to pay extra attention to
    the minority class (Ransomware at 16%) so it doesn't get lazy and
    just predict "not ransomware" all the time.
    """
    print("\n[4/6] Training Random Forest (200 trees)...")
    print("    This may take a minute...")

    start = time.time()
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,         # let trees grow fully
        min_samples_leaf=2,     # prevents overfitting on tiny leaf nodes
        class_weight="balanced",
        random_state=42,
        n_jobs=-1               # use all CPU cores
    )
    model.fit(X_train, y_train)
    elapsed = time.time() - start

    print(f"    Trained in {elapsed:.1f}s")
    return model


# ---------------------------------------------------------------------------
# Step 5 — Evaluate
# ---------------------------------------------------------------------------
def evaluate(model, scaler, X_test, y_test):
    """
    WHY THESE METRICS AND NOT JUST ACCURACY?

    Accuracy = "how often are we right overall?"
    Bad metric for security because if 90% of samples are benign,
    a model that always says "benign" gets 90% accuracy while being useless.

    Precision = "when we say ransomware, how often are we right?"
      High precision = few false alarms (important for user trust)

    Recall = "of all actual ransomware, how many did we catch?"
      High recall = few missed threats (important for actual protection)

    F1 Score = balance between precision and recall (0–1, higher is better)

    ROC-AUC = overall discrimination ability (0.5 = random, 1.0 = perfect)

    In security tools we generally prefer HIGH RECALL over high precision:
    better to have a false alarm than to miss a real attack.
    """
    print("\n[5/6] Evaluating model...")

    X_test_scaled = scaler.transform(X_test)
    y_pred  = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]

    print(f"\n    Accuracy:  {accuracy_score(y_test, y_pred)*100:.2f}%")
    print(f"    ROC-AUC:   {roc_auc_score(y_test, y_proba):.4f}")

    print("\n    Classification Report:")
    print("    " + "-"*55)
    report = classification_report(
        y_test, y_pred,
        target_names=["Not Ransomware", "Ransomware"]
    )
    for line in report.strip().split("\n"):
        print(f"    {line}")

    print("\n    Confusion Matrix:")
    print("    (rows=actual, cols=predicted)")
    cm = confusion_matrix(y_test, y_pred)
    labels = ["Not Ransom", "Ransomware"]
    col_w = 14
    print("    " + " " * 12 + "".join(f"{l:>{col_w}}" for l in labels))
    for i, row in enumerate(cm):
        print(f"    {labels[i]:>12}" + "".join(f"{v:>{col_w},}" for v in row))

    # Top features
    print("\n    Top 10 most important features:")
    importances = model.feature_importances_
    return y_pred, y_proba, importances


# ---------------------------------------------------------------------------
# Step 6 — Save
# ---------------------------------------------------------------------------
def save_models(model, scaler, feature_cols, importances):
    print("\n[6/6] Saving models...")

    joblib.dump(model,       MODELS_DIR / "rf_model.joblib")
    joblib.dump(scaler,      MODELS_DIR / "scaler.joblib")
    joblib.dump(feature_cols, MODELS_DIR / "feature_cols.joblib")

    # Save feature importance ranking for reference
    ranked = sorted(zip(feature_cols, importances), key=lambda x: -x[1])
    with open(MODELS_DIR / "feature_importance.txt", "w") as f:
        f.write("Feature Importance Ranking\n")
        f.write("=" * 40 + "\n")
        for name, score in ranked:
            f.write(f"{score:.4f}  {name}\n")

    print(f"    rf_model.joblib     → {MODELS_DIR / 'rf_model.joblib'}")
    print(f"    scaler.joblib       → {MODELS_DIR / 'scaler.joblib'}")
    print(f"    feature_cols.joblib → {MODELS_DIR / 'feature_cols.joblib'}")
    print(f"    feature_importance.txt saved")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 55)
    print("  CyberShield v2 — ML Training Pipeline")
    print("  Dataset: CIC-MalMem-2022 (Obfuscated)")
    print("=" * 55)

    if not DATA_FILE.exists():
        print(f"\nERROR: Dataset not found at {DATA_FILE}")
        print("Place Obfuscated-MalMem2022.parquet in the ml/ folder.")
        sys.exit(1)

    X, y, feature_cols          = load_data()
    X_train, X_test, y_train, y_test = split_data(X, y)
    scaler, X_train_s, X_test_s = scale_features(X_train, X_test)
    model                       = train_model(X_train_s, y_train)
    _, _, importances           = evaluate(model, scaler, X_test, y_test)
    save_models(model, scaler, feature_cols, importances)

    print("\n✅ Training complete. Models saved to ml/models/")
    print("   Next step: run  python ml/predict.py  to test a prediction.")


if __name__ == "__main__":
    main()
