"""Detection pipeline — the SINGLE orchestration point for every input.

    raw counters ──> derive() ──> RandomForest ──> IsolationForest
                                          │              │
                                          ▼              ▼
                                    risk engine ──> severity ──> explanation

Used identically by: background traffic, all 5 simulations, PCAP analysis
and POST /api/analyze. The frontend NEVER decides attack types.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Dict, Optional

from app.core import anomaly, model_registry, risk_engine
from app.core.explanation import build as build_explanation
from app.core.feature_schema import CLASS_DISPLAY, derive

log = logging.getLogger("sentinel.pipeline")

# If the supervised classifier votes BENIGN but the unsupervised detector
# is extremely alarmed, we surface an ANOMALY (unknown behaviour) instead.
ANOMALY_OVERRIDE_THRESHOLD = 0.90


def analyze_window(raw: Dict[str, float], source: str = "unknown",
                   target: str = "unknown",
                   sim_id: Optional[str] = None) -> Dict:
    """Run the full ML + risk + explanation pipeline on one traffic window."""
    t0 = time.perf_counter()

    feats = derive(raw)
    rf_label, probabilities, confidence = model_registry.predict(feats)
    anomaly_score = anomaly.score(feats)
    label = rf_label
    override_note = None

    if rf_label == "BENIGN" and anomaly_score >= ANOMALY_OVERRIDE_THRESHOLD:
        label = "ANOMALY"
        override_note = (
            "The supervised classifier voted BENIGN, but the unsupervised "
            "anomaly detector scored this traffic as an extreme outlier "
            f"({anomaly_score:.2f}/1.00), so it is surfaced as an anomaly."
        )
        log.info("anomaly-override: RF=BENIGN conf=%.2f anomaly=%.2f",
                 confidence, anomaly_score)

    risk, breakdown = risk_engine.compute(label, confidence, anomaly_score, feats)
    severity = risk_engine.severity_of(risk)

    extra_note = override_note
    explanation = build_explanation(label, feats, confidence, anomaly_score,
                                    extra_note)

    elapsed_ms = (time.perf_counter() - t0) * 1000
    log.info("prediction: label=%s conf=%.3f anomaly=%.2f risk=%d (%s) "
             "src=%s %.1fms",
             label, confidence, anomaly_score, risk, severity, source,
             elapsed_ms)

    result = {
        "event_id": str(uuid.uuid4()),
        "label": label,
        "rf_label": rf_label,
        "classification": CLASS_DISPLAY.get(label, label),
        "confidence": round(confidence, 4),
        "probabilities": {k: round(v, 4) for k, v in probabilities.items()},
        "anomaly_score": round(anomaly_score, 3),
        "risk": risk,
        "severity": severity,
        "risk_breakdown": breakdown,
        "explanation": explanation,
        "features": {k: round(float(v), 4) for k, v in feats.items()},
        "observed": {
            "pkt_rate": round(float(feats["pkt_rate"]), 1),
            "flow_count": int(float(feats["flow_count"])),
            "total_packets": int(float(feats["total_packets"])),
            "syn_count": int(float(feats["syn_count"])),
            "ack_count": int(float(feats["ack_count"])),
            "duration_s": round(float(feats["duration_s"]), 2),
            "distinct_dst_ports": int(float(feats["distinct_dst_ports"])),
            "avg_pkt_size": round(float(feats["avg_pkt_size"]), 1),
        },
        "source": source,
        "target": target,
        "sim_id": sim_id,
        "inference_ms": round(elapsed_ms, 1),
    }
    return result
