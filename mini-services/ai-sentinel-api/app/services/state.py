"""In-memory runtime state: blocked sources, live traffic, network status."""
from __future__ import annotations

import time
from typing import Dict, List, Optional

from app.config import BLOCK_DURATION_S
from app.core import risk_engine
from app.services import store

_start_ts = time.time()
_blocked: Dict[str, float] = {}      # source -> expiry epoch seconds
_last_window: Dict = {}              # last traffic_update payload


def uptime_s() -> float:
    return time.time() - _start_ts


def block_source(source: str, duration: float = BLOCK_DURATION_S) -> float:
    """Simulated block (demo only — never touches a real firewall)."""
    expiry = time.time() + duration
    _blocked[source] = expiry
    return expiry


def is_blocked(source: str) -> bool:
    exp = _blocked.get(source)
    if exp is None:
        return False
    if time.time() > exp:
        _blocked.pop(source, None)
        return False
    return True


def blocked_sources() -> List[Dict]:
    now = time.time()
    return [
        {"source": s, "blocked_at": round(exp - BLOCK_DURATION_S),
         "expires_at": round(exp)}
        for s, exp in sorted(_blocked.items()) if exp > now
    ]


def set_last_window(window: Dict) -> None:
    _last_window.update(window)


def statistics() -> Dict:
    """Aggregated dashboard statistics (network status + totals)."""
    db_stats = store.statistics()
    blocked = blocked_sources()
    active = db_stats["active_threats"]

    # Network status from live events
    events = store.list_events(limit=100, status="ACTIVE")
    critical_active = any(e.get("severity") == "CRITICAL" for e in events)
    high_active = any(e.get("severity") == "HIGH" for e in events)
    if critical_active or high_active:
        status = "UNDER_ATTACK"
    elif active > 0:
        status = "MONITORING"
    else:
        status = "PROTECTED"

    current_risk = 5
    if active:
        current_risk = max(int(e.get("risk", 0)) for e in events) or 5

    last = _last_window
    return {
        "network_status": status,
        "current_risk": current_risk,
        "totals": db_stats,
        "traffic": {
            "pkt_rate": last.get("pkt_rate", 0),
            "byte_rate": last.get("byte_rate", 0),
            "flows": last.get("flows", 0),
            "prediction": last.get("prediction", "BENIGN"),
        },
        "blocked_sources": blocked,
        "uptime_s": round(uptime_s(), 1),
        "severity_bands": risk_engine.RISK_FORMULA_DOC["severity_bands"],
    }
