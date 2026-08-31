"""Anomaly detection — IsolationForest calibrated against benign traffic.

Distinguishes:
  * KNOWN attack patterns   -> RandomForest classification
  * UNKNOWN unusual traffic -> anomaly detector score

The raw IsolationForest score (-decision_function) is mapped to a 0..1
score using percentiles measured on held-out BENIGN windows at training
time (stored in ml/models/benign_baselines.json):

    raw <= p50        -> 0.00 .. 0.20   (typical benign)
    p50   .. p95      -> 0.20 .. 0.80   (unusual)
    p95   .. p99      -> 0.80 .. 1.00   (highly anomalous)
    raw  > p99        -> 1.00           (extreme outlier)
"""
from __future__ import annotations

from typing import Dict

from app.core import model_registry


def _interp(v: float, lo: float, hi: float, out_lo: float, out_hi: float) -> float:
    if hi <= lo:
        return out_hi if v >= hi else out_lo
    t = (v - lo) / (hi - lo)
    t = max(0.0, min(1.0, t))
    return out_lo + (out_hi - out_lo) * t


def score(features: Dict[str, float]) -> float:
    """Calibrated anomaly score in [0, 1] — higher = more anomalous."""
    raw = model_registry.anomaly_raw(features)
    cal = model_registry.baselines().get("anomaly_raw_scores", {})
    p50 = cal.get("p50", 0.15)
    p95 = cal.get("p95", 0.30)
    p99 = cal.get("p99", 0.40)

    if raw <= p50:
        return _interp(raw, p50 - 0.5, p50, 0.0, 0.20)
    if raw <= p95:
        return _interp(raw, p50, p95, 0.20, 0.80)
    if raw <= p99:
        return _interp(raw, p95, p99, 0.80, 1.00)
    return 1.0
