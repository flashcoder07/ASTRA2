"""
response_engine.py
------------------
Tiered automated response system for ASTRA.

Four tiers are defined purely on model confidence score:

  TIER 1 — MONITOR      (confidence < 0.65)   watch-only, no action
  TIER 2 — THROTTLE     (0.65 ≤ confidence < 0.75)
  TIER 3 — BLOCK_IP     (0.75 ≤ confidence < 0.85)
  TIER 4 — ISOLATE_HOST (confidence ≥ 0.85)

Normal traffic always returns a no-action response regardless of score.
"""

import json
import logging
import os
from datetime import datetime

logger = logging.getLogger("astra.response_engine")

# ---------------------------------------------------------------------------
# Tier definitions
# ---------------------------------------------------------------------------

TIERS = {
    1: {
        "tier":        1,
        "action":      "MONITOR",
        "description": "Flagged for observation. No action taken.",
        "color":       "yellow",
        "emoji":       "🟡",
        "threshold":   0.0,   # lower bound (inclusive)
    },
    2: {
        "tier":        2,
        "action":      "THROTTLE",
        "description": "Traffic rate-limited. Connection deprioritized.",
        "color":       "orange",
        "emoji":       "🟠",
        "threshold":   0.65,
    },
    3: {
        "tier":        3,
        "action":      "BLOCK_IP",
        "description": "IP blocked at firewall level.",
        "color":       "red",
        "emoji":       "🔴",
        "threshold":   0.75,
    },
    4: {
        "tier":        4,
        "action":      "ISOLATE_HOST",
        "description": "Host fully isolated from network. Incident report generated.",
        "color":       "darkred",
        "emoji":       "⛔",
        "threshold":   0.85,
    },
}

# No-action response for Normal / unknown traffic
_NORMAL_RESPONSE = {
    "tier":        0,
    "action":      "ALLOW",
    "description": "Normal traffic. No action required.",
    "color":       "green",
    "emoji":       "✅",
}

# Incidents folder
INCIDENTS_DIR = os.path.join(os.path.dirname(__file__), "incidents")
os.makedirs(INCIDENTS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def decide_response(predicted_label: str, confidence: float) -> dict:
    """
    Determine the appropriate response tier for a detection.

    Parameters
    ----------
    predicted_label : str   Label from the classifier (e.g. 'DDoS', 'Normal').
    confidence      : float Model confidence score in [0, 1].

    Returns
    -------
    dict with keys: tier, action, description, color, emoji
    """
    # Normal traffic → no action regardless of confidence
    if predicted_label in ("Normal", "Unknown", None):
        logger.debug("ALLOW: Normal traffic (label=%s)", predicted_label)
        return dict(_NORMAL_RESPONSE)

    confidence = float(confidence)

    # Walk tiers from highest to lowest threshold
    for tier_num in (4, 3, 2, 1):
        tier = TIERS[tier_num]
        if confidence >= tier["threshold"]:
            response = dict(tier)
            logger.info(
                "TIER %d — %s | label=%s confidence=%.3f | %s",
                tier_num, response["action"], predicted_label, confidence, response["description"],
            )
            return response

    # Fallback (should never reach here)
    return dict(TIERS[1])


def generate_incident_report(event: dict, response: dict, explanation: dict = None) -> str:
    """
    Generate a timestamped JSON incident report for TIER 4 (ISOLATE_HOST) events.

    Parameters
    ----------
    event       : dict   The processed event dict (source_ip, threat_type, etc.).
    response    : dict   The response tier dict from decide_response().
    explanation : dict   Optional SHAP explanation dict.

    Returns
    -------
    str : Absolute path to the saved incident file.
    """
    if response.get("tier") != 4:
        return None

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    source_ip_safe = (event.get("source_ip") or "unknown").replace(".", "-")
    filename = f"incident_{ts}_{source_ip_safe}.json"
    filepath = os.path.join(INCIDENTS_DIR, filename)

    report = {
        "schema_version":  "1.0",
        "generated_at":    datetime.utcnow().isoformat() + "Z",
        "tier":            4,
        "action":          response["action"],
        "description":     response["description"],
        "source_ip":       event.get("source_ip"),
        "destination_ip":  event.get("destination_ip"),
        "threat_type":     event.get("threat_type"),
        "confidence":      event.get("confidence"),
        "protocol":        event.get("protocol"),
        "packets":         event.get("packets"),
        "bytes":           event.get("bytes"),
        "duration":        event.get("duration"),
        "failed_logins":   event.get("failed_logins"),
        "shap_explanation": explanation or {},
        "timestamp_event":  event.get("timestamp"),
    }

    try:
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        logger.info("Incident report saved: %s", filepath)
    except Exception as exc:
        logger.error("Failed to write incident report: %s", exc)
        return None

    return filepath
