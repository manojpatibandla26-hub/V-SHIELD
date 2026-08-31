"""Model registry — loads artifacts, guarantees a trained model exists.

If ml/models/ artifacts are missing (fresh clone), the first server start
triggers a synchronous training run (a few seconds) so the prototype is
ALWAYS runnable out of the box. No fake predictions, ever.
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
import threading
from typing import Dict, List, Tuple

import joblib

from app.config import (ANOMALY_MODEL_PATH, BASELINES_PATH, METADATA_PATH,
                        MODEL_PATH, MODEL_VERSION)
from app.core.feature_schema import FEATURES, feature_row
from app.core.preprocess import sanitize_vector

log = logging.getLogger("sentinel.model")

_lock = threading.Lock()
_rf = None
_iso = None
_metadata: dict | None = None
_baselines: dict | None = None


def ensure_model() -> bool:
    """Load model artifacts; train first if they don't exist. Thread-safe."""
    global _rf, _iso, _metadata, _baselines
    with _lock:
        if _rf is not None and _iso is not None:
            return True
        if not MODEL_PATH.exists() or not ANOMALY_MODEL_PATH.exists():
            log.warning("Model artifacts missing — training now "
                        "(documented synthetic dataset, ~10s)…")
            train_script = MODEL_PATH.parent.parent / "train.py"
            proc = subprocess.run(
                [sys.executable, str(train_script)],
                capture_output=True, text=True, timeout=300,
            )
            if proc.returncode != 0:
                log.error("Training failed: %s", proc.stderr[-800:])
                return False
            log.info("Training complete.")
        _rf = joblib.load(MODEL_PATH)
        _iso = joblib.load(ANOMALY_MODEL_PATH)
        _metadata = json.loads(METADATA_PATH.read_text())
        _baselines = json.loads(BASELINES_PATH.read_text())
        log.info("Model loaded: RandomForest %s (%d classes, %d features)",
                 MODEL_VERSION, len(_rf.classes_), len(FEATURES))
        log.info("Anomaly detector loaded: IsolationForest")
        return True


def is_ready() -> bool:
    return _rf is not None


def predict(features: Dict[str, float]) -> Tuple[str, Dict[str, float], float]:
    """Run the RandomForest on one canonical feature dict.

    Returns (label, per-class probabilities, confidence).
    """
    if _rf is None:
        raise RuntimeError("model not loaded — call ensure_model() first")
    x = sanitize_vector(feature_row(features))
    probs = _rf.predict_proba([x])[0]
    idx = int(probs.argmax())
    label = str(_rf.classes_[idx])
    per_class = {str(c): float(p) for c, p in zip(_rf.classes_, probs)}
    return label, per_class, float(probs[idx])


def anomaly_raw(features: Dict[str, float]) -> float:
    """Raw IsolationForest score (higher = more anomalous)."""
    if _iso is None:
        raise RuntimeError("anomaly model not loaded")
    x = sanitize_vector(feature_row(features))
    return float(-_iso.decision_function([x])[0])


def metadata() -> dict:
    if _metadata is None:
        ensure_model()
    return dict(_metadata or {})


def baselines() -> dict:
    if _baselines is None:
        ensure_model()
    return dict(_baselines or {})


def feature_importances() -> List[dict]:
    return list(metadata().get("feature_importances", []))


def model_version() -> str:
    return MODEL_VERSION
