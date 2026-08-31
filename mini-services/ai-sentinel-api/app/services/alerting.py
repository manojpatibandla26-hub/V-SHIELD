"""Alerting — persists threats, broadcasts escalation-aware events.

Rules:
  * every non-benign window is stored (upsert) and broadcast as
    `threat_detected` (frontend silently refreshes the detail panel)
  * an `alert` (toast-worthy) is broadcast only when the event is NEW or
    its severity INCREASES — this is what produces the demo's escalating
    Low -> Medium -> High -> Critical alert sequence without spam.
"""
from __future__ import annotations

import logging
import time
from typing import Dict, Optional

from app.core import model_registry
from app.services import events, store

log = logging.getLogger("sentinel.alerting")

_SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_last_severity: Dict[str, str] = {}


def _now() -> float:
    return time.time()


async def publish_threat(result: Dict, origin: str = "simulation",
                         sim_id: Optional[str] = None,
                         event_id: Optional[str] = None) -> Optional[Dict]:
    """Store + broadcast one detected threat window. Returns stored event."""
    label = result.get("label", "BENIGN")
    if label == "BENIGN":
        return None

    eid = event_id or result["event_id"]
    sim_id = sim_id or result.get("sim_id")
    ts = _now()
    severity = result["severity"]

    stored = store.upsert_event(
        event_id=eid, ts=ts, attack=label,
        confidence=result["confidence"], risk=result["risk"],
        severity=severity, status="ACTIVE",
        source=result.get("source", "unknown"),
        target=result.get("target", "unknown"),
        explanation=result["explanation"], observed=result["observed"],
        probabilities=result["probabilities"],
        anomaly_score=result.get("anomaly_score", 0.0),
        model_version=model_registry.model_version(),
        sim_id=sim_id, origin=origin,
    )

    threat_msg = {
        "type": "threat_detected",
        "ts": ts,
        "event_id": eid,
        "sim_id": sim_id,
        "attack": label,
        "classification": result["classification"],
        "confidence": result["confidence"],
        "risk": result["risk"],
        "severity": severity,
        "anomaly_score": result["anomaly_score"],
        "source": result.get("source", "unknown"),
        "target": result.get("target", "unknown"),
        "explanation": result["explanation"],
        "observed": result["observed"],
        "features": result["features"],
        "probabilities": result["probabilities"],
        "origin": origin,
        "model_version": model_registry.model_version(),
    }
    await events.broadcast(threat_msg)

    prev = _last_severity.get(eid)
    escalate = prev is None or _SEV_RANK[severity] > _SEV_RANK.get(prev, -1)
    _last_severity[eid] = severity
    if escalate:
        log.warning("Threat detected: %s risk=%d (%s) conf=%.3f src=%s",
                    label, result["risk"], severity, result["confidence"],
                    result.get("source"))
        await events.broadcast({
            "type": "alert",
            "ts": ts,
            "event_id": eid,
            "attack": label,
            "classification": result["classification"],
            "severity": severity,
            "risk": result["risk"],
            "confidence": result["confidence"],
            "source": result.get("source", "unknown"),
            "message": (f"{result['classification']} detected — "
                        f"risk {result['risk']}/100"),
        })
    return stored


def reset_event(event_id: str) -> None:
    _last_severity.pop(event_id, None)
