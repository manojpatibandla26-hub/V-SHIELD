"""Evaluate the trained AI Sentinel models and write a readable report.

Usage:
    python ml/evaluate.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import (ANOMALY_MODEL_PATH, DATA_DIR, METADATA_PATH,
                        MODEL_PATH, MODELS_DIR)
from app.core.feature_schema import FEATURES

REPORT_PATH = MODELS_DIR / "evaluation_report.md"


def main() -> None:
    if not MODEL_PATH.exists():
        print("[evaluate] no trained model found — run ml/train.py first")
        sys.exit(1)

    rf = joblib.load(MODEL_PATH)
    iso = joblib.load(ANOMALY_MODEL_PATH)
    metadata = json.loads(METADATA_PATH.read_text())
    eval_df = pd.read_csv(DATA_DIR / "eval.csv")

    X = eval_df[FEATURES].astype(float).values
    y = eval_df["label"].values
    pred = rf.predict(X)
    probs = rf.predict_proba(X)

    classes = list(rf.classes_)
    lines = ["# AI Sentinel — Model Evaluation Report", ""]

    m = metadata["metrics"]
    lines += [
        f"* Model: RandomForestClassifier ({metadata['model_version']})",
        f"* Evaluated on {len(y)} held-out windows (generator seed 1337, "
        f"disjoint from training seed 42)",
        f"* Dataset: **synthetic, documented distributions** — metrics "
        f"reflect synthetic separability, not real-world generalization",
        "",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Accuracy | {m['accuracy']:.4f} |",
        f"| Precision (macro) | {m['precision_macro']:.4f} |",
        f"| Recall (macro) | {m['recall_macro']:.4f} |",
        f"| F1 (macro) | {m['f1_macro']:.4f} |",
        f"| Mean confidence | {m['mean_confidence']:.4f} |",
        "",
        "## Per-class metrics",
        "",
        "| Class | Precision | Recall | F1 | Support |",
        "|---|---|---|---|---|",
    ]
    for cls in classes:
        c = m["per_class"][cls]
        lines.append(
            f"| {cls} | {c['precision']:.3f} | {c['recall']:.3f} | "
            f"{c['f1']:.3f} | {c['support']} |")

    lines += ["", "## Confusion matrix (rows = true, cols = predicted)", "",
              "| true\\pred | " + " | ".join(classes) + " |",
              "|---" * (len(classes) + 1) + "|"]
    for i, cls in enumerate(classes):
        row = m["confusion_matrix"]["matrix"][i]
        lines.append(f"| {cls} | " + " | ".join(str(v) for v in row) + " |")

    # Anomaly detector behaviour on known classes
    lines += ["", "## IsolationForest anomaly score by true class", ""]
    raw = -iso.decision_function(X)
    lines.append("| Class | mean raw score (higher = more anomalous) |")
    lines.append("|---|---|")
    import numpy as np
    for cls in classes:
        v = raw[y == cls]
        lines.append(f"| {cls} | {float(np.mean(v)):.4f} |")

    lines += [
        "",
        "## Top-10 feature importances (RandomForest)",
        "",
        "| Feature | Importance |",
        "|---|---|",
    ]
    for item in metadata["feature_importances"][:10]:
        lines.append(f"| {item['feature']} | {item['importance']:.4f} |")

    lines += [
        "",
        "## Honest interpretation",
        "",
        "- These numbers are REAL measurements on the bundled synthetic "
        "evaluation set (fresh samples, seed 1337, never used in training).",
        "- They are high because the synthetic class distributions are "
        "separable by design. This is a property of the demo dataset, and "
        "we state it openly.",
        "- For real-world performance, retrain with real captures using "
        "`ml/train_real.py` (CIC-IDS2017) — expect lower, more sober numbers.",
        "",
    ]

    report = "\n".join(lines)
    REPORT_PATH.write_text(report)
    print(report)
    print(f"\n[evaluate] report saved -> {REPORT_PATH}")


if __name__ == "__main__":
    main()
