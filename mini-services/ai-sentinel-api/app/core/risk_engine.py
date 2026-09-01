"""Risk engine — documented, deterministic 0–100 score (NEVER random).

Severity bands:
    0–24   LOW
    25–49  MEDIUM
    50–74  HIGH
    75–100 CRITICAL

FORMULA (documented, weight rationale):

For detected threats:
    strength   = percentile of pkt_rate inside the *attack class's own*
                 training distribution  -> how strong this instance is
                 compared to typical attacks of that class
    impact_eff = CLASS_IMPACT * (0.30 + 0.70 * strength)
    deviation  = percentile of pkt_rate against the *benign* baseline
    risk = round( 0.40*impact_eff            <- attack potential damage
                + 0.25*anomaly_score*100     <- deviation from normal
                + 0.20*confidence*100        <- model certainty
                + 0.15*deviation*100 )       <- traffic abnormality
    clamped to [0, 100]

For BENIGN windows (no attack -> no impact term):
    risk = round( 0.30*anomaly_score*100 + 0.10*deviation*100 ), capped at 24

Weights chosen so that: a weak/early attack with moderate confidence lands
in MEDIUM, a full-strength flood with high confidence & anomaly lands
90–97 (CRITICAL), and normal traffic stays under ~15.
"""
from __future__ import annotations

from typing import Dict, Tuple

from app.core import model_registry

CLASS_IMPACT = {
    "BENIGN": 2,
    "ANOMALY": 50,
    "PORT_SCAN": 45,
    "BRUTE_FORCE": 72,
    "DOS_DDOS": 85,
    "SYN_FLOOD": 90,
}

SEVERITY_BANDS = [(24, "LOW"), (49, "MEDIUM"), (74, "HIGH"), (100, "CRITICAL")]


def severity_of(risk: int) -> str:
    for cap, name in SEVERITY_BANDS:
        if risk <= cap:
            return name
    return "CRITICAL"


def _percentile(value: float, marks: Dict[str, float]) -> float:
    """Piecewise-linear percentile-ish position (0..1) of value vs marks."""
    p50, p90, p99, mx = (marks.get(k, 0.0) for k in ("p50", "p90", "p99", "max"))
    if value <= 0:
        return 0.0
    if value <= p50:
        return 0.15 * (value / p50) if p50 > 0 else 0.15
    if value <= p90:
        return 0.15 + 0.35 * ((value - p50) / max(p90 - p50, 1e-9))
    if value <= p99:
        return 0.50 + 0.35 * ((value - p90) / max(p99 - p90, 1e-9))
    if value <= mx:
        return 0.85 + 0.15 * ((value - p99) / max(mx - p99, 1e-9))
    return 1.0


def deviation(feats: Dict[str, float]) -> float:
    """0..1 — how far pkt_rate is above the benign baseline."""
    base = model_registry.baselines().get("feature_percentiles", {})
    marks = base.get("pkt_rate", {})
    return max(0.0, min(1.0, _percentile(float(feats.get("pkt_rate", 0.0)), marks)))


def strength(label: str, feats: Dict[str, float]) -> float:
    """0..1 — percentile of pkt_rate within the class's own distribution."""
    cls = model_registry.baselines().get("class_pkt_rate", {}).get(label)
    if not cls:
        return 0.5
    v = float(feats.get("pkt_rate", 0.0))
    p10, p50, p90 = cls["p10"], cls["p50"], cls["p90"]
    if v <= p10:
        return max(0.05, 0.5 * v / max(p10, 1e-9))
    if v <= p50:
        return 0.05 + 0.45 * ((v - p10) / max(p50 - p10, 1e-9))
    if v <= p90:
        return 0.50 + 0.40 * ((v - p50) / max(p90 - p50, 1e-9))
    return 1.0


def compute(label: str, confidence: float, anomaly_score: float,
            feats: Dict[str, float]) -> Tuple[int, Dict[str, float]]:
    """Return (risk 0..100, transparent breakdown for the UI)."""
    dev = deviation(feats)
    strg = strength(label, feats)
    impact = CLASS_IMPACT.get(label, 50)

    if label == "BENIGN":
        risk = round(0.30 * anomaly_score * 100 + 0.10 * dev * 100)
        risk = min(risk, 24)
        breakdown = {
            "anomaly_score": round(anomaly_score, 3),
            "traffic_deviation": round(dev, 3),
            "impact": 0,
            "strength": 0.0,
            "confidence": round(confidence, 3),
        }
        return max(0, risk), breakdown

    impact_eff = impact * (0.30 + 0.70 * strg)
    risk = (0.40 * impact_eff
            + 0.25 * anomaly_score * 100
            + 0.20 * confidence * 100
            + 0.15 * dev * 100)
    risk = int(max(1, min(100, round(risk))))
    breakdown = {
        "impact_effective": round(impact_eff, 1),
        "class_impact": impact,
        "attack_strength": round(strg, 3),
        "anomaly_score": round(anomaly_score, 3),
        "confidence": round(confidence, 3),
        "traffic_deviation": round(dev, 3),
        "weights": {"impact": 0.40, "anomaly": 0.25,
                    "confidence": 0.20, "deviation": 0.15},
    }
    return risk, breakdown


RISK_FORMULA_DOC = {
    "benign": "risk = 0.30*anomaly + 0.10*deviation, capped at 24",
    "threat": "risk = 0.40*impact_eff + 0.25*anomaly*100 + 0.20*confidence*100 "
              "+ 0.15*deviation*100, where impact_eff = class_impact * "
              "(0.30 + 0.70*attack_strength)",
    "severity_bands": {"LOW": "0-24", "MEDIUM": "25-49",
                       "HIGH": "50-74", "CRITICAL": "75-100"},
    "class_impact": CLASS_IMPACT,
}
