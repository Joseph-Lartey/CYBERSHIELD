"""
ML Classifier
-------------
Clean wrapper around the trained Random Forest model.

Accepts a dict of system features → returns a ransomware probability (0.0–1.0).

FEATURE COVERAGE:
  The model was trained on 55 Volatility memory forensics features.
  Our agent collects ~15 of those using psutil (the process/service ones).
  The rest are zeroed out — features that require deep Windows memory
  inspection (DLL lists, handle types, kernel callbacks).

  This means our live score is a conservative estimate — the model only
  sees a subset of what it was trained on.  It will still fire on clear
  ransomware behaviour (high process counts, abnormal service patterns)
  but the threshold to alert is set higher to compensate.

  When Phase 4 (desktop app) adds deeper Windows API monitoring,
  more features will be filled in and the score will become more precise.
"""

import logging
import numpy as np
import joblib
from pathlib import Path

logger = logging.getLogger("cybershield.classifier")

MODELS_DIR = Path(__file__).parent / "models"

# Confidence threshold above which we raise a threat event.
# Set higher than default (0.5) because we're working with partial features.
THREAT_THRESHOLD = 0.65


class RansomwareClassifier:
    """
    Loads the trained model and provides a single predict() method.

    Usage:
        clf = RansomwareClassifier()
        clf.load()
        score = clf.predict(feature_dict)
        if score >= THREAT_THRESHOLD:
            # raise threat
    """

    def __init__(self):
        self.model       = None
        self.scaler      = None
        self.feature_cols = None
        self._loaded     = False

    def load(self):
        """Load model files from ml/models/. Call once at startup."""
        try:
            self.model        = joblib.load(MODELS_DIR / "rf_model.joblib")
            self.scaler       = joblib.load(MODELS_DIR / "scaler.joblib")
            self.feature_cols = joblib.load(MODELS_DIR / "feature_cols.joblib")
            self._loaded      = True
            logger.info(
                "ML model loaded. Features: %d, Trees: %d",
                len(self.feature_cols),
                self.model.n_estimators,
            )
        except FileNotFoundError as e:
            logger.error("Model file not found: %s — run ml/train.py first", e)
            self._loaded = False

    def predict(self, features: dict) -> float:
        """
        Takes a dict of feature_name → value and returns ransomware probability.

        Missing features default to 0. The dict does NOT need to contain all
        55 features — just fill in what you have and the rest are zeroed.

        Returns:
            float between 0.0 and 1.0
            0.0 = definitely not ransomware
            1.0 = definitely ransomware
        """
        if not self._loaded:
            logger.warning("Model not loaded — returning 0.0")
            return 0.0

        # Build the feature vector in the exact order the model expects
        vector = np.array(
            [[features.get(col, 0.0) for col in self.feature_cols]]
        )

        scaled = self.scaler.transform(vector)
        proba  = self.model.predict_proba(scaled)[0][1]

        return float(proba)

    @property
    def is_loaded(self) -> bool:
        return self._loaded
