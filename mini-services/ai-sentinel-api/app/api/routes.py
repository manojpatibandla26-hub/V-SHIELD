"""REST API routes — every detection decision is made HERE, in Python."""
from __future__ import annotations

import logging
import shutil
import tempfile
import time
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app.core import model_registry, pipeline, risk_engine
from app.core.feature_schema import FEATURES, missing_features
from app.pcap import parser as pcap_parser
from app.pcap import samples as pcap_samples
from app.services import alerting, events, state, store
from app.simulation import generators, service as sim_service

log = logging.getLogger("sentinel.api")
router = APIRouter(prefix="/api")


# ------------------------------------------------------------------ models
class AnalyzeRequest(BaseModel):
    features: dict = Field(
        ..., description="Full canonical feature vector (see /api/model-info)")


# ------------------------------------------------------------------ health
@router.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "ai-sentinel-api",
        "backend": "online",
        "model": "online" if model_registry.is_ready() else "loading",
        "model_version": model_registry.model_version()
        if model_registry.is_ready() else None,
        "uptime_s": round(state.uptime_s(), 1),
        "websocket_clients": events.client_count(),
    }


# ------------------------------------------------------------------ model
@router.get("/model-info")
async def model_info():
    if not model_registry.is_ready():
        model_registry.ensure_model()
    meta = model_registry.metadata()
    return {
        "algorithm": meta["algorithm"],
        "model_version": meta["model_version"],
        "trained_at": meta["trained_at"],
        "classes": meta["classes"],
        "features": meta["features"],
        "n_features": meta["n_features"],
        "train_samples": meta["train_samples"],
        "eval_samples": meta["eval_samples"],
        "dataset": meta["dataset"],
        "metrics": meta["metrics"],
        "feature_importances": meta["feature_importances"][:12],
        "label_mapping": meta["label_mapping"],
        "anomaly_detector": meta["anomaly_detector"],
        "risk_model": risk_engine.RISK_FORMULA_DOC,
        "honesty_notes": [
            "Trained on a documented SYNTHETIC dataset modelled on "
            "CIC-IDS2017 attack characteristics (no real data bundled).",
            "Metrics are measured on held-out synthetic samples — they do "
            "NOT represent real-world generalization.",
            "Train on real data via ml/train_real.py for production use.",
        ],
    }


# ------------------------------------------------------------------ simulation
@router.get("/simulation/types")
async def simulation_types():
    return [
        {"type": k, "name": v["name"], "tagline": v["tagline"],
         "description": v["description"], "expected": v["expected"],
         "safety": "synthetic-only"}
        for k, v in generators.SCENARIOS.items()
    ]


@router.post("/simulation/{attack_type}", status_code=202)
async def run_simulation(attack_type: str):
    if attack_type not in generators.SCENARIOS:
        raise HTTPException(
            400, detail=f"Unknown simulation type '{attack_type}'. "
                        f"Available: {list(generators.SCENARIOS.keys())}")
    if not model_registry.is_ready():
        model_registry.ensure_model()
    info = sim_service.start(attack_type)
    scenario = generators.SCENARIOS[attack_type]
    return {
        "sim_id": info["sim_id"],
        "attack_type": attack_type,
        "scenario": scenario["name"],
        "windows_total": info["windows_total"],
        "status": "started",
        "note": "Synthetic data will stream through the ML pipeline and "
                "results arrive over WebSocket (/).",
    }


# ------------------------------------------------------------------ analyze
@router.post("/analyze")
async def analyze(req: AnalyzeRequest):
    if not model_registry.is_ready():
        model_registry.ensure_model()
    missing = missing_features(req.features)
    if missing:
        raise HTTPException(
            400, detail={"message": "Feature vector is missing canonical "
                                    "features (see /api/model-info).",
                         "missing": missing})
    result = pipeline.analyze_window(
        {k: float(v) for k, v in req.features.items()},
        source="api-client", target="manual-window")
    return result


# ------------------------------------------------------------------ pcap
@router.get("/pcap/samples")
async def list_pcap_samples():
    return pcap_samples.list_samples()


@router.post("/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)):
    suffix = Path(file.filename or "").suffix.lower()
    tmp = Path(tempfile.mkstemp(suffix=suffix or ".pcap")[1])
    try:
        with tmp.open("wb") as fh:
            total = 0
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > pcap_parser.PCAP_MAX_BYTES:
                    raise HTTPException(
                        400, detail="File too large — limit is 25 MB.")
                fh.write(chunk)
        return await pcap_parser.analyze_file(tmp, file.filename or "upload.pcap")
    except pcap_parser.PcapError as exc:
        raise HTTPException(400, detail=str(exc))
    finally:
        shutil.os.unlink(tmp)


@router.post("/pcap/samples/{name}/analyze")
async def analyze_sample(name: str):
    path = pcap_samples.sample_path(name)
    if path is None:
        raise HTTPException(
            404, detail=f"Sample '{name}' not found. See /api/pcap/samples.")
    try:
        return await pcap_parser.analyze_file(path, path.name)
    except pcap_parser.PcapError as exc:
        raise HTTPException(400, detail=str(exc))


# ------------------------------------------------------------------ events
@router.get("/events")
async def get_events(limit: int = 50, status: str | None = None):
    limit = max(1, min(limit, 500))
    return {"events": store.list_events(limit=limit, status=status)}


@router.post("/events/{event_id}/resolve")
async def resolve_event(event_id: str):
    ev = store.update_status(event_id, "RESOLVED")
    if not ev:
        raise HTTPException(404, detail=f"Event {event_id} not found.")
    await events.broadcast({
        "type": "event_resolved", "ts": time.time(),
        "event_id": event_id, "status": "RESOLVED",
    })
    return {"ok": True, "event": ev}


@router.post("/events/{event_id}/simulate-mitigation")
async def simulate_mitigation(event_id: str):
    ev = store.get_event(event_id)
    if not ev:
        raise HTTPException(404, detail=f"Event {event_id} not found.")
    source = ev.get("source", "unknown")
    state.block_source(source)
    sim = sim_service.active_for_source(source)

    if sim:
        # A running simulation owns this source: its loop will notice the
        # block within ~1s, emit recovery windows and the mitigation event.
        return {"ok": True, "event": ev,
                "handled_by": "active-simulation",
                "note": "Recovery will stream over WebSocket."}

    # No live simulation: show the before/after effect immediately.
    before = float((ev.get("observed") or {}).get("pkt_rate", 3000))
    after = before * 0.22
    store.update_status(event_id, "MITIGATED")
    ev = store.get_event(event_id) or ev
    await events.broadcast({
        "type": "mitigation", "ts": time.time(),
        "event_id": event_id, "action": "block_source", "target": source,
        "before_pkt_rate": round(before, 1),
        "after_pkt_rate": round(after, 1), "status": "MITIGATED",
        "note": "Simulated block only — no real firewall or host was "
                "modified.",
    })
    # one synthetic post-mitigation traffic window
    import random as _r
    rng = _r.Random()
    raw = sim_service._recovery_window(rng, after)
    result = pipeline.analyze_window(raw, source=source,
                                     target=ev.get("target", "unknown"))
    await events.broadcast({
        "type": "traffic_update", "ts": time.time(), "source": source,
        "prediction": result["label"], "confidence": result["confidence"],
        "risk": result["risk"], "severity": result["severity"],
        "pkt_rate": result["observed"]["pkt_rate"],
        "byte_rate": round(result["features"]["byte_rate"], 1),
        "flows": result["observed"]["flow_count"],
        "total_packets": result["observed"]["total_packets"],
        "syn_count": result["observed"]["syn_count"],
        "ack_count": result["observed"]["ack_count"],
        "duration_s": result["observed"]["duration_s"],
        "mitigated": True,
    })
    return {"ok": True, "event": ev, "handled_by": "immediate",
            "before_pkt_rate": round(before, 1),
            "after_pkt_rate": round(after, 1)}


# ------------------------------------------------------------------ reset
@router.post("/reset")
async def reset_demo():
    """Reset ALL demo state safely (between demo runs / before judging):

    * cancels any running simulation
    * deletes every stored threat event (audit DB)
    * clears alert escalation memory, blocked sources, last traffic window

    The ML models, trained artifacts, PCAP files and the background benign
    traffic engine are untouched. Connected dashboards receive a
    `demo_reset` WebSocket event and return to the clean PROTECTED baseline.
    """
    cancelled_sims = sim_service.cancel_all()
    events_cleared = store.clear_events()
    alerting.reset_all()
    state.reset_runtime()
    stats = state.statistics()
    await events.broadcast({
        "type": "demo_reset", "ts": time.time(),
        "message": ("Demo state reset — events cleared, blocked sources "
                    "released. Baseline traffic continues."),
    })
    return {
        "ok": True,
        "cleared": {
            "events": events_cleared,
            "cancelled_simulations": cancelled_sims,
        },
        "statistics": stats,
    }


# ------------------------------------------------------------------ statistics
@router.get("/statistics")
async def statistics():
    return state.statistics()


# ------------------------------------------------------------------ live capture
class StartCaptureRequest(BaseModel):
    interface: str | None = Field(default=None, description="Interface name/id to sniff on")


@router.get("/capture/interfaces")
async def capture_interfaces():
    from app.services import live_capture
    return {"interfaces": live_capture.get_interfaces()}


@router.get("/capture/status")
async def capture_status():
    from app.services import live_capture
    return live_capture.get_status()


@router.post("/capture/start")
async def start_live_capture(req: StartCaptureRequest | None = None):
    from app.services import live_capture
    iface = req.interface if req else None
    res = live_capture.start_capture(iface=iface)
    await events.broadcast({
        "type": "capture_status_change",
        "ts": time.time(),
        "status": res.get("status"),
        "interface": res.get("interface"),
    })
    return res


@router.post("/capture/stop")
async def stop_live_capture():
    from app.services import live_capture
    res = live_capture.stop_capture()
    await events.broadcast({
        "type": "capture_status_change",
        "ts": time.time(),
        "status": res.get("status"),
    })
    return res

