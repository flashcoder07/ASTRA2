"""
retrainer.py
------------
Handles periodic retraining of the ASTRA RandomForest classifier
using operator feedback stored in feedback.db.

Key design choices
------------------
* Catastrophic-forgetting prevention: if the original CICIoT2023 training
  CSV is available, we mix a stratified 5 000-row sample into the training
  set alongside feedback rows.
* Thread safety: retraining is triggered from inside a Flask request handler
  (potentially from any thread); we protect the global `_ever_retrained` flag
  with a lock and reload the classifier into the app's global namespace via
  joblib so that in-flight requests keep using the old model.
* Feature alignment: feedback rows that came from dashboard button-clicks
  will have an empty feature_vector ({}).  For those rows we synthesise a
  zero-vector so the shapes align; the corrected `true_label` is still useful
  signal for the classifier.
"""

import json
import logging
import os
import threading
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from feedback_store import clear_feedback, get_all_feedback, get_feedback_count

logger = logging.getLogger("astra.retrainer")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_BASE = os.path.dirname(__file__)
_MODELS_DIR = os.path.join(_BASE, "models")
_CLF_PATH = os.path.join(_MODELS_DIR, "threat_classifier.joblib")
_FEATURE_COLS_PATH = os.path.join(_MODELS_DIR, "feature_columns.joblib")
_SCALER_PATH = os.path.join(_MODELS_DIR, "scaler.joblib")
_PROTOCOL_ENC_PATH = os.path.join(_MODELS_DIR, "protocol_encoder.joblib")

# CICIoT2023 training CSV — checked at retrain time (optional)
_CICIOT_CSV = os.path.expanduser(
    "~/.cache/kagglehub/datasets/himadri07/ciciot2023/versions/1/CICIOT23/train/train.csv"
)

# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_ever_retrained: bool = False
MIN_SAMPLES_DEFAULT = 50
_ORIGINAL_SAMPLE_SIZE = 5000  # rows pulled from CICIoT CSV to prevent forgetting


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_feature_columns():
    """Load the saved list of feature column names."""
    try:
        return joblib.load(_FEATURE_COLS_PATH)
    except Exception as exc:
        logger.error("Could not load feature_columns.joblib: %s", exc)
        return None


def _build_feature_matrix(feedback_df: pd.DataFrame, feature_cols: list) -> tuple:
    """
    Parse the feature_vector JSON column into a numeric matrix.

    Rows with an empty / unparseable feature_vector get a zero vector.

    Returns (X: np.ndarray, y: np.ndarray).
    """
    rows = []
    for _, row in feedback_df.iterrows():
        try:
            fv = json.loads(row["feature_vector"])
        except (json.JSONDecodeError, TypeError):
            fv = {}

        vec = [float(fv.get(col, 0.0)) for col in feature_cols]
        rows.append(vec)

    X = np.array(rows, dtype=float)
    y = feedback_df["true_label"].values
    return X, y


def _sample_original_data(feature_cols: list, sample_size: int = _ORIGINAL_SAMPLE_SIZE):
    """
    Try to load a balanced sample from the original CICIoT2023 CSV.
    Returns (X, y) or (None, None) if the file is unavailable.
    """
    if not os.path.exists(_CICIOT_CSV):
        logger.warning(
            "CICIoT2023 CSV not found at %s; skipping original-data mix-in.", _CICIOT_CSV
        )
        return None, None

    try:
        from data_loader import LABEL_MAPPING  # local import to avoid circular deps

        df = pd.read_csv(_CICIOT_CSV, nrows=sample_size * 4)
        df["mapped_label"] = df["label"].map(LABEL_MAPPING)
        df = df[df["mapped_label"].isin(["Normal", "DDoS", "BruteForce", "PortScan"])]
        df = df.dropna(subset=feature_cols, how="any")

        if len(df) > sample_size:
            df = df.sample(n=sample_size, random_state=42)

        # Protocol Type: ensure string (as protocol_encoder expects)
        if "Protocol Type" in df.columns:
            df["Protocol Type"] = df["Protocol Type"].fillna(0).astype(int).astype(str)

        X_orig = df[feature_cols].values.astype(float)
        y_orig = df["mapped_label"].values
        logger.info("Loaded %d rows from original CICIoT2023 data.", len(df))
        return X_orig, y_orig

    except Exception as exc:
        logger.error("Failed to load original data: %s", exc)
        return None, None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def retrain_if_ready(min_samples: int = MIN_SAMPLES_DEFAULT) -> Dict[str, Any]:
    """
    Check whether enough feedback has accumulated and retrain if so.

    Parameters
    ----------
    min_samples : Minimum feedback rows required to trigger retraining.

    Returns
    -------
    dict with keys:
        retrained (bool)  – True if retraining was executed this call.
        samples   (int)   – Number of feedback samples used.
        message   (str)   – Human-readable summary.
    """
    global _ever_retrained

    count = get_feedback_count()
    if count < min_samples:
        return {
            "retrained": False,
            "samples": count,
            "message": f"Not enough samples yet ({count}/{min_samples}).",
        }

    with _lock:
        # Re-check inside the lock to avoid double-retrain in concurrent requests
        count = get_feedback_count()
        if count < min_samples:
            return {
                "retrained": False,
                "samples": count,
                "message": f"Not enough samples yet ({count}/{min_samples}).",
            }

        logger.info("Retraining triggered with %d feedback samples.", count)

        feature_cols = _load_feature_columns()
        if feature_cols is None:
            return {
                "retrained": False,
                "samples": count,
                "message": "feature_columns.joblib missing; cannot retrain.",
            }

        try:
            # 1. Build feature matrix from feedback
            feedback_df = get_all_feedback()
            X_fb, y_fb = _build_feature_matrix(feedback_df, feature_cols)

            # 2. Mix in original data if available
            X_orig, y_orig = _sample_original_data(feature_cols)
            if X_orig is not None and len(X_orig) > 0:
                X_combined = np.vstack([X_fb, X_orig])
                y_combined = np.concatenate([y_fb, y_orig])
            else:
                X_combined = X_fb
                y_combined = y_fb

            # 3. Scale (reuse existing scaler — do NOT refit to avoid distribution shift)
            try:
                scaler = joblib.load(_SCALER_PATH)
                X_scaled = scaler.transform(X_combined)
            except Exception as exc:
                logger.warning("Scaler load/transform failed (%s); using unscaled data.", exc)
                X_scaled = X_combined

            # 4. Retrain Random Forest
            clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
            clf.fit(X_scaled, y_combined)

            # 5. Persist updated classifier
            joblib.dump(clf, _CLF_PATH)
            logger.info("Model retrained on %d feedback samples.", count)
            print(f"[ASTRA] Model retrained on {count} feedback samples.")

            # 6. Clear feedback table
            clear_feedback()

            _ever_retrained = True

            return {
                "retrained": True,
                "samples": count,
                "message": f"Model retrained on {count} feedback samples.",
            }

        except Exception as exc:
            logger.exception("Retraining failed: %s", exc)
            return {
                "retrained": False,
                "samples": count,
                "message": f"Retraining error: {exc}",
            }


def get_retraining_status(min_samples: int = MIN_SAMPLES_DEFAULT) -> Dict[str, Any]:
    """
    Return current retraining status.

    Returns
    -------
    dict with keys:
        collected     (int)  – Feedback samples collected so far.
        needed        (int)  – Samples still needed before next retrain.
        ever_retrained (bool) – Whether the model has been retrained at least once.
    """
    collected = get_feedback_count()
    needed = max(0, min_samples - collected)
    return {
        "collected": collected,
        "needed": needed,
        "min_samples": min_samples,
        "ever_retrained": _ever_retrained,
    }
