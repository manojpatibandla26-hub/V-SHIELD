"""Train the AI Sentinel detection models (RandomForest + IsolationForest).

Pipeline:
    train.csv ──> RandomForestClassifier (supervised, 6 classes)
    benign rows ─> IsolationForest       (unsupervised anomaly detector)
    benign rows ─> baseline statistics   (risk engine + explanations)

Artifacts written to ml/models/:
    random_forest.joblib      trained classifier
    isolation_forest.joblib   anomaly detector
    metadata.json             model card (metrics, classes, features, importances)
    benign_baselines.json     benign percentiles + anomaly-score calibration

Usage:
    python ml/train.py            (auto-generates dataset if missing)
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import (BASELINES_PATH, DATA_DIR, METADATA_PATH,
                        ANOMALY_MODEL_PATH, MODEL_PATH, MODEL_VERSION,
                        MODELS_DIR)
from app.core.feature_schema import CLASSES, FEATURES  # noqa: E402

N_TREES = 220
RF_SEED = 42
IF_SEED = 42
IF_CONTAMINATION = 0.12


def _ensure_dataset() -> None:
    if (DATA_DIR / "train.csv").exists() and (DATA_DIR / "eval.csv").exists():
        return
    print("[train] dataset missing — generating (documented synthetic)…")
    import subprocess
    subprocess.run([sys.executable, str(Path(__file__).parent / "generate_dataset.py")],
                   check=True)


def _baselines(df_benign: pd.DataFrame) -> dict:
    """Percentile statistics of benign traffic used by risk/explanation."""
    keys = ["pkt_rate", "byte_rate", "syn_pct", "avg_pkt_size", "flow_count",
            "avg_flow_packets", "distinct_dst_ports", "auth_port_pct",
            "avg_flow_duration_s", "rst_pct", "syn_ack_ratio"]
    out = {}
    for k in keys:
        v = df_benign[k].astype(float).values
        out[k] = {
            "p50": float(np.percentile(v, 50)),
            "p90": float(np.percentile(v, 90)),
            "p99": float(np.percentile(v, 99)),
            "max": float(np.max(v)),
        }
    return out


def _class_magnitude(df: pd.DataFrame) -> dict:
    """Per-class pkt_rate percentiles -> 'attack strength' scaling for risk."""
    out = {}
    for cls in CLASSES:
        v = df[df.label == cls]["pkt_rate"].astype(float).values
        out[cls] = {
            "p10": float(np.percentile(v, 10)),
            "p50": float(np.percentile(v, 50)),
            "p90": float(np.percentile(v, 90)),
        }
    return out


def train() -> dict:
    _ensure_dataset()

    train_df = pd.read_csv(DATA_DIR / "train.csv")
    eval_df = pd.read_csv(DATA_DIR / "eval.csv")

    X_train = train_df[FEATURES].astype(float).values
    y_train = train_df["label"].values
    X_eval = eval_df[FEATURES].astype(float).values
    y_eval = eval_df["label"].values

    # ---------------------------------------------------------------- RF
    rf = RandomForestClassifier(
        n_estimators=N_TREES,
        max_depth=16,
        min_samples_leaf=1,
        class_weight="balanced",
        n_jobs=-1,
        random_state=RF_SEED,
    )
    rf.fit(X_train, y_train)

    pred = rf.predict(X_eval)
    probs = rf.predict_proba(X_eval)
    confidence = probs.max(axis=1)
    report = classification_report(y_eval, pred, output_dict=True,
                                   zero_division=0)
    cm = confusion_matrix(y_eval, pred, labels=CLASSES)

    metrics = {
        "accuracy": float(accuracy_score(y_eval, pred)),
        "precision_macro": float(report.get("macro avg", {}).get("precision", 0.0)),
        "recall_macro": float(report.get("macro avg", {}).get("recall", 0.0)),
        "f1_macro": float(report.get("macro avg", {}).get("f1-score", 0.0)),
        "mean_confidence": float(np.mean(confidence)),
        "min_confidence": float(np.min(confidence)),
        "per_class": {
            cls: {
                "precision": float(report.get(cls, {}).get("precision", 0.0)),
                "recall": float(report.get(cls, {}).get("recall", 0.0)),
                "f1": float(report.get(cls, {}).get("f1-score", 0.0)),
                "support": int(report.get(cls, {}).get("support", 0)),
            } for cls in CLASSES
        },
        "confusion_matrix": {
            "labels": CLASSES,
            "matrix": cm.tolist(),
        },
        "eval_samples": int(len(y_eval)),
    }

    # ------------------------------------------------- IsolationForest
    benign_mask = y_train == "BENIGN"
    X_benign = X_train[benign_mask]
    iso = IsolationForest(
        n_estimators=150,
        contamination=IF_CONTAMINATION,
        random_state=IF_SEED,
        n_jobs=-1,
    )
    iso.fit(X_benign)

    # Calibrate raw anomaly scores against benign distribution:
    #   raw = -decision_function  (higher == more anomalous)
    raw_eval_benign = -iso.decision_function(
        eval_df[eval_df.label == "BENIGN"][FEATURES].astype(float).values)
    anomaly_calibration = {
        "p50": float(np.percentile(raw_eval_benign, 50)),
        "p95": float(np.percentile(raw_eval_benign, 95)),
        "p99": float(np.percentile(raw_eval_benign, 99)),
    }

    # ------------------------------------------------- Baselines
    baselines = {
        "feature_percentiles": _baselines(train_df[train_df.label == "BENIGN"]),
        "class_pkt_rate": _class_magnitude(train_df),
        "anomaly_raw_scores": anomaly_calibration,
    }

    # ------------------------------------------------- Persist artifacts
    joblib.dump(rf, MODEL_PATH)
    joblib.dump(iso, ANOMALY_MODEL_PATH)

    importances = sorted(
        ({"feature": f, "importance": float(i)} for f, i in
         zip(FEATURES, rf.feature_importances_)),
        key=lambda d: d["importance"], reverse=True,
    )

    metadata = {
        "model_version": MODEL_VERSION,
        "algorithm": "RandomForestClassifier",
        "algorithm_params": {
            "n_estimators": N_TREES, "max_depth": 16,
            "class_weight": "balanced", "random_state": RF_SEED,
        },
        "anomaly_detector": {
            "algorithm": "IsolationForest",
            "contamination": IF_CONTAMINATION,
            "trained_on": "benign windows only",
        },
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "classes": CLASSES,
        "features": FEATURES,
        "n_features": len(FEATURES),
        "train_samples": int(len(y_train)),
        "eval_samples": int(len(y_eval)),
        "dataset": {
            "source": "synthetic (documented per-class distributions, "
                      "CIC-IDS2017-inspired; see ml/generate_dataset.py)",
            "generator_seed_train": 42,
            "generator_seed_eval": 1337,
            "honesty_note": (
                "Metrics below are measured on held-out samples of the "
                "synthetic distribution. High scores reflect separable "
                "synthetic classes, NOT real-world generalization. "
                "Train on real data with ml/train_real.py for production."
            ),
        },
        "metrics": metrics,
        "feature_importances": importances,
        "label_mapping": [
            {"dataset_label": "BENIGN",                    "app_class": "BENIGN"},
            {"dataset_label": "DDoS (LOIC/HOIC)",           "app_class": "DOS_DDOS"},
            {"dataset_label": "DoS Hulk / GoldenEye",       "app_class": "DOS_DDOS"},
            {"dataset_label": "DoS Slowloris / Slowhttptest", "app_class": "DOS_DDOS"},
            {"dataset_label": "PortScan",                   "app_class": "PORT_SCAN"},
            {"dataset_label": "FTP-Patator / SSH-Patator",  "app_class": "BRUTE_FORCE"},
            {"dataset_label": "Bot / Infiltration / Heartbleed / Web Attack",
             "app_class": "ANOMALY"},
            {"dataset_label": "(no direct label — modelled from half-open "
                             "connection behaviour literature)",
             "app_class": "SYN_FLOOD"},
        ],
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2))
    BASELINES_PATH.write_text(json.dumps(baselines, indent=2))

    print("[train] RandomForest:  accuracy={:.4f}  f1_macro={:.4f}".format(
        metrics["accuracy"], metrics["f1_macro"]))
    print("[train] artifacts ->", MODELS_DIR)
    return metadata


if __name__ == "__main__":
    train()
