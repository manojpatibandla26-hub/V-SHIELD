"""Background benign traffic engine.

Generates a steady stream of NORMAL traffic windows (synthetic, same
canonical schema), runs each through the real ML pipeline and broadcasts
the result — so the dashboard is alive and shows the Protected baseline
before any simulation is started.

NOTE: an 'odd window' injector exists (traffic that is unusual but not an
attack) but is DISABLED by default (ODD_WINDOW_CHANCE = 0.0) so the demo
baseline stays quiet. The anomaly-detection path is demonstrated via the
"Network Anomaly" scenario in the Security Test Lab instead. Set the
chance > 0 to see organic anomaly alerts on the live stream.
"""
from __future__ import annotations

import asyncio
import logging
import random

from app.config import SIM_WINDOW_SECONDS, TRAFFIC_INTERVAL_S
from app.core import pipeline
from app.services import events, state
from app.services.state import set_last_window

log = logging.getLogger("sentinel.traffic")

_task: asyncio.Task | None = None

ODD_WINDOW_CHANCE = 0.0    # keep baseline quiet (see module docstring)

CLIENTS = ["10.0.1.11", "10.0.1.24", "10.0.1.37", "10.0.1.42", "10.0.1.55"]
SERVERS = ["10.0.0.1", "10.0.0.2"]


def _benign_window(rng: random.Random) -> dict:
    duration = SIM_WINDOW_SECONDS
    pkt_rate = rng.uniform(80, 1200)
    flows = rng.randint(2, 12)
    packets = int(pkt_rate * duration)
    syn = int(flows * rng.uniform(1.8, 2.6))
    ack = int(packets * rng.uniform(0.55, 0.9))
    return {
        "duration_s": duration,
        "flow_count": flows,
        "total_packets": packets,
        "total_bytes": int(packets * rng.uniform(200, 900)),
        "syn_count": syn,
        "ack_count": ack,
        "fin_count": int(flows * rng.uniform(1.0, 2.2)),
        "rst_count": rng.choice([0, 0, 0, 1, 2]),
        "distinct_dst_ports": rng.randint(1, 6),
        "distinct_dst_ips": rng.randint(1, 3),
        "distinct_src_ips": rng.choice([1, 1, 1, 2, 3]),
        "avg_flow_duration_s": rng.uniform(0.2, 4.5),
        "avg_flow_packets": packets / max(flows, 1),
        "auth_flows": rng.choice([0, 0, 0, 1]),
        "tcp_packets": int(packets * rng.uniform(0.8, 1.0)),
        "udp_packets": int(packets * 0.1),
        "icmp_packets": rng.choice([0, 0, 0, 1]),
    }


def _odd_window(rng: random.Random) -> dict:
    """Weak anomaly: unusual but NOT an attack (e.g. sudden ICMP ping burst)."""
    duration = SIM_WINDOW_SECONDS
    packets = int(rng.uniform(120, 400))
    icmp = int(packets * rng.uniform(0.5, 0.8))
    return {
        "duration_s": duration,
        "flow_count": rng.randint(3, 10),
        "total_packets": packets,
        "total_bytes": int(packets * rng.uniform(64, 160)),
        "syn_count": rng.randint(0, 6),
        "ack_count": rng.randint(0, 10),
        "fin_count": 0,
        "rst_count": 0,
        "distinct_dst_ports": rng.randint(1, 3),
        "distinct_dst_ips": 1,
        "distinct_src_ips": 1,
        "avg_flow_duration_s": rng.uniform(0.05, 0.5),
        "avg_flow_packets": packets / 8,
        "auth_flows": 0,
        "tcp_packets": packets - icmp,
        "udp_packets": 0,
        "icmp_packets": icmp,
    }


async def _loop() -> None:
    rng = random.Random()
    log.info("background traffic engine started (benign baseline)")
    while True:
        try:
            from app.services import live_capture
            live_result = live_capture.aggregate_and_analyze_window()
            is_live = live_result is not None

            if is_live:
                result = live_result
                source = result.get("source", "local-interface")
                odd = False
            else:
                source = rng.choice(CLIENTS)
                target = rng.choice(SERVERS)
                odd = ODD_WINDOW_CHANCE > 0 and rng.random() < ODD_WINDOW_CHANCE
                raw = _odd_window(rng) if odd else _benign_window(rng)
                result = pipeline.analyze_window(raw, source=source, target=target)

            msg = {
                "type": "traffic_update",
                "ts": _now(),
                "source": source,
                "capture_mode": "LIVE" if is_live else "SYNTHETIC_BASELINE",
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
            set_last_window(msg)
            await events.broadcast(msg)

            # If live threat or odd anomaly detected, trigger alert
            if (is_live or odd) and result["label"] != "BENIGN":
                from app.services import alerting
                await alerting.publish_threat(result, origin="live_capture" if is_live else "background")

            await asyncio.sleep(TRAFFIC_INTERVAL_S)
        except asyncio.CancelledError:
            raise
        except Exception:  # keep the engine alive no matter what
            log.exception("traffic engine iteration failed")
            await asyncio.sleep(TRAFFIC_INTERVAL_S)


def _now() -> float:
    import time
    return time.time()


def start() -> None:
    global _task
    if _task is None or _task.done():
        _task = asyncio.get_event_loop().create_task(_loop())


def stop() -> None:
    global _task
    if _task is not None:
        _task.cancel()
        _task = None
