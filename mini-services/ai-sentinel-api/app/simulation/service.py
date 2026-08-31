"""Simulation service — runs one scenario end-to-end through the pipeline.

Sequence per window (all broadcast over WebSocket):
    sim_started
    traffic_update (with live prediction)
    threat_detected / alert (when the model detects, severity-aware)
    sim_progress
    … (escalating windows, ~1.15s apart)
    sim_complete

If the simulated source gets "blocked" (demo mitigation), the scenario
switches to recovery windows, marks the event MITIGATED and emits a
`mitigation` event. No real blocking ever happens — this is a demo of
what a response WOULD look like.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
import uuid
from typing import Dict, Optional

from app.config import SIM_INTENSITIES, SIM_WINDOW_INTERVAL
from app.core import pipeline
from app.services import alerting, events, state
from app.services.state import set_last_window
from app.simulation import generators

log = logging.getLogger("sentinel.sim")

# sim_id -> {"attack_type", "source", "event_id", "task"}
ACTIVE_SIMS: Dict[str, Dict] = {}


def _now() -> float:
    return time.time()


async def _traffic_msg(result: Dict, sim_id: str) -> Dict:
    return {
        "type": "traffic_update",
        "ts": _now(),
        "source": result["source"],
        "sim_id": sim_id,
        "prediction": result["label"],
        "confidence": result["confidence"],
        "risk": result["risk"],
        "severity": result["severity"],
        "pkt_rate": result["observed"]["pkt_rate"],
        "byte_rate": round(result["features"]["byte_rate"], 1),
        "flows": result["observed"]["flow_count"],
        "total_packets": result["observed"]["total_packets"],
        "syn_count": result["observed"]["syn_count"],
        "ack_count": result["observed"]["ack_count"],
        "duration_s": result["observed"]["duration_s"],
    }


def _recovery_window(rng: random.Random, pkt_rate: float) -> Dict:
    """A benign-shaped window at the given (reduced) rate."""
    packets = int(pkt_rate * 6)
    flows = rng.randint(3, 10)
    return {
        "duration_s": 6.0,
        "flow_count": flows,
        "total_packets": packets,
        "total_bytes": int(packets * rng.uniform(350, 900)),
        "syn_count": rng.randint(2, 12),
        "ack_count": int(packets * 0.6),
        "fin_count": rng.randint(1, 6),
        "rst_count": 0,
        "distinct_dst_ports": rng.randint(1, 4),
        "distinct_dst_ips": 1,
        "distinct_src_ips": 1,
        "avg_flow_duration_s": rng.uniform(1, 6),
        "avg_flow_packets": packets / flows,
        "auth_flows": 0,
        "tcp_packets": int(packets * 0.95),
        "udp_packets": int(packets * 0.05),
        "icmp_packets": 0,
    }


async def _emit_mitigation(event_id: str, source: str, before: float,
                           after: float) -> None:
    from app.services import store
    store.update_status(event_id, "MITIGATED")
    alerting.reset_event(event_id)
    await events.broadcast({
        "type": "mitigation",
        "ts": _now(),
        "event_id": event_id,
        "action": "block_source",
        "target": source,
        "before_pkt_rate": round(before, 1),
        "after_pkt_rate": round(after, 1),
        "status": "MITIGATED",
        "note": ("Simulated block only — no real firewall or host was "
                 "modified. This demonstrates what an automated response "
                 "would look like in production."),
    })
    log.info("Mitigation (simulated): %s %.0f -> %.0f pkt/s",
             source, before, after)


async def run_simulation(attack_type: str, sim_id: str) -> None:
    scenario = generators.SCENARIOS[attack_type]
    source = scenario["source"]
    target = scenario["target"]
    rng = random.Random()
    event_id = str(uuid.uuid4())
    peak_pkt_rate = 0.0
    detected = False
    final_risk, final_severity = 0, "LOW"
    mitigated = False

    ACTIVE_SIMS.setdefault(sim_id, {}).update(
        {"attack_type": attack_type, "source": source, "event_id": event_id})
    log.info("Simulation started: %s (sim_id=%s)", attack_type, sim_id)
    await events.broadcast({
        "type": "sim_started", "ts": _now(), "sim_id": sim_id,
        "attack_type": attack_type, "scenario": scenario["name"],
        "windows_total": len(SIM_INTENSITIES),
        "message": f"Safe synthetic simulation started: {scenario['name']}",
    })

    try:
        for i, intensity in enumerate(SIM_INTENSITIES):
            # Demo mitigation: if the source was "blocked", recover instead
            if state.is_blocked(source):
                mitigated = await _recover(sim_id, event_id, source, target,
                                           peak_pkt_rate)
                break

            raw = generators.generate(attack_type, intensity, rng)
            result = pipeline.analyze_window(raw, source=source, target=target,
                                             sim_id=sim_id)
            result["event_id"] = event_id

            msg = await _traffic_msg(result, sim_id)
            set_last_window(msg)
            await events.broadcast(msg)
            peak_pkt_rate = max(peak_pkt_rate, result["observed"]["pkt_rate"])

            if result["label"] != "BENIGN":
                await alerting.publish_threat(result, origin="simulation",
                                              sim_id=sim_id, event_id=event_id)
                detected = True
                final_risk, final_severity = result["risk"], result["severity"]

            await events.broadcast({
                "type": "sim_progress", "ts": _now(), "sim_id": sim_id,
                "attack_type": attack_type, "phase": "running",
                "windows_done": i + 1,
                "windows_total": len(SIM_INTENSITIES),
                "intensity": round(intensity, 2),
                "current_risk": result["risk"],
            })
            await asyncio.sleep(SIM_WINDOW_INTERVAL)
    except asyncio.CancelledError:
        log.info("Simulation cancelled: %s", sim_id)
        raise
    finally:
        ACTIVE_SIMS.pop(sim_id, None)

    await events.broadcast({
        "type": "sim_complete", "ts": _now(), "sim_id": sim_id,
        "attack_type": attack_type,
        "phase": "mitigated" if mitigated else "complete",
        "detected": detected,
        "final_risk": final_risk, "final_severity": final_severity,
        "peak_pkt_rate": round(peak_pkt_rate, 1),
        "message": ("Scenario complete — model response streamed live."
                    if not mitigated else
                    "Source was blocked during simulation — traffic recovered."),
    })
    log.info("Simulation finished: %s detected=%s mitigated=%s",
             sim_id, detected, mitigated)


async def _recover(sim_id: str, event_id: str, source: str, target: str,
                   before_pkt_rate: float) -> bool:
    """Emit post-mitigation recovery windows and close the event."""
    rng = random.Random()
    after = 0.0
    for step, factor in enumerate((0.45, 0.18, 0.06)):
        base = max((before_pkt_rate or 3000) * factor, 120.0)
        raw = _recovery_window(rng, base)
        result = pipeline.analyze_window(raw, source=source, target=target,
                                         sim_id=sim_id)
        result["event_id"] = event_id
        msg = await _traffic_msg(result, sim_id)
        msg["mitigated"] = True
        set_last_window(msg)
        await events.broadcast(msg)
        after = result["observed"]["pkt_rate"]
        await events.broadcast({
            "type": "sim_progress", "ts": _now(), "sim_id": sim_id,
            "phase": "mitigating", "windows_done": step + 1,
            "windows_total": 3,
        })
        await asyncio.sleep(0.9)

    await _emit_mitigation(event_id, source, before_pkt_rate, after)
    return True


def start(attack_type: str) -> Dict:
    sim_id = str(uuid.uuid4())
    task = asyncio.get_event_loop().create_task(
        run_simulation(attack_type, sim_id))
    ACTIVE_SIMS[sim_id] = {"attack_type": attack_type, "task": task}
    return {"sim_id": sim_id, "attack_type": attack_type,
            "windows_total": len(SIM_INTENSITIES), "status": "started"}


def active_for_source(source: str) -> Optional[Dict]:
    for sim in ACTIVE_SIMS.values():
        if sim.get("source") == source:
            return sim
    return None


def cancel_all() -> int:
    """Cancel every running simulation (demo reset). Returns count."""
    n = 0
    for sim in list(ACTIVE_SIMS.values()):
        task = sim.get("task")
        if task is not None and not task.done():
            task.cancel()
            n += 1
    return n
