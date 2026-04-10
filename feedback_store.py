"""
feedback_store.py
-----------------
Manages the SQLite feedback database for ASTRA's Active Learning loop.

Operators mark detections as True / False Positives from the dashboard;
each mark is stored here and used to periodically retrain the classifier.
"""

import sqlite3
import json
import os
import logging
from datetime import datetime

import pandas as pd

logger = logging.getLogger("astra.feedback_store")

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(os.path.dirname(__file__), "feedback.db")

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS feedback (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    source_ip       TEXT    NOT NULL,
    predicted_label TEXT    NOT NULL,
    true_label      TEXT    NOT NULL,
    feature_vector  TEXT    NOT NULL DEFAULT '{}',
    confidence      REAL    NOT NULL DEFAULT 0.0
);
"""


def _get_conn() -> sqlite3.Connection:
    """Return a new connection to the feedback database."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the feedback table if it does not already exist."""
    with _get_conn() as conn:
        conn.execute(_CREATE_TABLE_SQL)
        conn.commit()
    logger.info("feedback.db initialised at %s", DB_PATH)


# Initialise on import so the DB is always ready when this module is used.
init_db()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def save_feedback(
    source_ip: str,
    predicted_label: str,
    true_label: str,
    feature_vector: dict,
    confidence: float,
) -> None:
    """
    Persist one operator feedback entry.

    Parameters
    ----------
    source_ip       : IP address of the traffic source.
    predicted_label : Label the model originally predicted.
    true_label      : Corrected label supplied by the operator.
    feature_vector  : Dict of feature name → value (may be empty {}).
    confidence      : Model confidence score at prediction time.
    """
    timestamp = datetime.utcnow().isoformat()
    fv_json = json.dumps(feature_vector) if isinstance(feature_vector, dict) else str(feature_vector)

    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO feedback
                (timestamp, source_ip, predicted_label, true_label, feature_vector, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (timestamp, source_ip, predicted_label, true_label, fv_json, float(confidence)),
        )
        conn.commit()

    logger.info(
        "Feedback saved: %s predicted=%s true=%s confidence=%.2f",
        source_ip, predicted_label, true_label, confidence,
    )


def get_all_feedback() -> pd.DataFrame:
    """
    Return every row in the feedback table as a DataFrame.

    Columns: id, timestamp, source_ip, predicted_label, true_label,
             feature_vector (raw JSON string), confidence.
    """
    with _get_conn() as conn:
        rows = conn.execute("SELECT * FROM feedback ORDER BY id ASC").fetchall()

    if not rows:
        return pd.DataFrame(
            columns=["id", "timestamp", "source_ip", "predicted_label",
                     "true_label", "feature_vector", "confidence"]
        )

    return pd.DataFrame([dict(r) for r in rows])


def get_feedback_count() -> int:
    """Return the total number of feedback entries stored so far."""
    with _get_conn() as conn:
        count = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
    return int(count)


def clear_feedback() -> None:
    """Delete all rows from the feedback table (called after retraining)."""
    with _get_conn() as conn:
        conn.execute("DELETE FROM feedback")
        conn.commit()
    logger.info("Feedback table cleared after retraining.")
