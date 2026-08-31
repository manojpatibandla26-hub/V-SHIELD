"""Input sanitization before model inference.

The RandomForest itself needs little preprocessing (tree models are
scale-free), but every input row passes through this single function so
that NaN/Inf/absurd values can never reach the model — from ANY producer
(training, simulation, PCAP, manual /api/analyze).
"""
from __future__ import annotations

import math
from typing import List

from app.core.feature_schema import FEATURES

# Hard sanity clips (well beyond any real traffic value)
CLIPS = {
    "duration_s": 86400.0,
    "flow_count": 5_000_000.0,
    "total_packets": 50_000_000.0,
    "total_bytes": 10_000_000_000_000.0,
    "syn_ack_ratio": 10_000.0,
    "distinct_dst_ports": 65_536.0,
    "distinct_dst_ips": 100_000.0,
    "distinct_src_ips": 100_000.0,
}


def sanitize_vector(row: List[float]) -> List[float]:
    out: List[float] = []
    for i, name in enumerate(FEATURES):
        v = float(row[i]) if i < len(row) else 0.0
        if math.isnan(v) or math.isinf(v):
            v = 0.0
        v = max(v, 0.0)
        cap = CLIPS.get(name)
        if cap is not None:
            v = min(v, cap)
        out.append(v)
    return out
