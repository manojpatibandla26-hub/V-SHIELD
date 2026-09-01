"""Canonical feature schema — the SINGLE source of truth for AI Sentinel.

The analysis unit is a *traffic window*: an aggregate of bidirectional
packet/flow counters between endpoints over a time window.

The SAME schema (raw counters -> derived features) is used by:
  1. ML training data generation   (ml/generate_dataset.py)
  2. Safe attack simulation        (app/simulation/generators.py)
  3. PCAP analysis                 (app/pcap/parser.py)

This guarantees the model always sees identically-defined features.
"""
from __future__ import annotations

import math
from typing import Dict, List

# ---------------------------------------------------------------
# Classes (used by training, simulation and the application UI)
# ---------------------------------------------------------------
CLASSES: List[str] = [
    "BENIGN",
    "DOS_DDOS",
    "PORT_SCAN",
    "SYN_FLOOD",
    "BRUTE_FORCE",
    "ANOMALY",
]

CLASS_DISPLAY: Dict[str, str] = {
    "BENIGN": "Normal Traffic",
    "DOS_DDOS": "DoS / DDoS Flood",
    "PORT_SCAN": "Port Scan (Reconnaissance)",
    "SYN_FLOOD": "SYN Flood",
    "BRUTE_FORCE": "Brute Force (Login Attacks)",
    "ANOMALY": "Network Anomaly",
}

# Common authentication-related TCP ports (SSH, FTP, Telnet, RDP, SMB,
# MSSQL, MySQL, VNC). Used for the auth_port_pct feature.
AUTH_PORTS = {21, 22, 23, 445, 1433, 3306, 3389, 5900}

# ---------------------------------------------------------------
# RAW counters produced by every generator / parser.
# All counts are BIDIRECTIONAL (both sides of the conversation).
# ---------------------------------------------------------------
RAW_COUNTERS: List[str] = [
    "duration_s",          # active duration of the window (seconds)
    "flow_count",          # number of distinct 5-tuple flows
    "total_packets",       # packets in both directions
    "total_bytes",         # bytes in both directions
    "syn_count",           # packets with SYN flag (incl. SYN-ACK)
    "ack_count",           # packets with ACK flag (incl. SYN-ACK, data, pure ACK)
    "fin_count",           # packets with FIN flag
    "rst_count",           # packets with RST flag
    "distinct_dst_ports",  # distinct destination ports contacted by initiator
    "distinct_dst_ips",    # distinct destination IPs
    "distinct_src_ips",    # distinct source IPs seen in the window
    "avg_flow_duration_s", # mean per-flow duration (seconds)
    "avg_flow_packets",    # mean packets per flow
    "auth_flows",          # flows targeting AUTH_PORTS
    "tcp_packets",         # TCP packets
    "udp_packets",         # UDP packets
    "icmp_packets",        # ICMP packets
]

# ---------------------------------------------------------------
# DERIVED features consumed by the ML model (canonical order!)
# ---------------------------------------------------------------
FEATURES: List[str] = [
    "duration_s",
    "flow_count",
    "total_packets",
    "total_bytes",
    "avg_pkt_size",
    "pkt_rate",
    "byte_rate",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "syn_pct",
    "rst_pct",
    "syn_ack_ratio",
    "distinct_dst_ports",
    "distinct_dst_ips",
    "distinct_src_ips",
    "avg_flow_duration_s",
    "avg_flow_packets",
    "auth_port_pct",
    "tcp_pct",
    "icmp_pct",
]

FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "duration_s": "Active duration of the traffic window (s)",
    "flow_count": "Distinct network conversations (5-tuple flows)",
    "total_packets": "Packets observed (both directions)",
    "total_bytes": "Bytes observed (both directions)",
    "avg_pkt_size": "Average packet size (bytes)",
    "pkt_rate": "Packets per second",
    "byte_rate": "Bytes per second",
    "syn_count": "Packets with TCP SYN flag",
    "ack_count": "Packets with TCP ACK flag",
    "fin_count": "Packets with TCP FIN flag",
    "rst_count": "Packets with TCP RST flag",
    "syn_pct": "Share of packets carrying SYN",
    "rst_pct": "Share of packets carrying RST",
    "syn_ack_ratio": "SYN packets per ACK packet (connection starts vs. completions)",
    "distinct_dst_ports": "Distinct destination ports contacted",
    "distinct_dst_ips": "Distinct destination IPs contacted",
    "distinct_src_ips": "Distinct source IPs in the window",
    "avg_flow_duration_s": "Mean flow duration (s)",
    "avg_flow_packets": "Mean packets per flow",
    "auth_port_pct": "Share of flows targeting login-related ports (SSH/FTP/…)",
    "tcp_pct": "Share of TCP packets",
    "icmp_pct": "Share of ICMP packets",
}

_RAW_DEFAULTS = {k: 0.0 for k in RAW_COUNTERS}


def _safe_div(a: float, b: float) -> float:
    try:
        if b is None or math.isnan(b) or b == 0:
            return 0.0
        v = a / b
        if math.isnan(v) or math.isinf(v):
            return 0.0
        return float(v)
    except (TypeError, ZeroDivisionError):
        return 0.0


def derive(raw: Dict[str, float]) -> Dict[str, float]:
    """Derive the full canonical feature vector from raw counters.

    Accepts partial/missing raw keys (defaults to 0) so that slightly
    different producers remain compatible. All ratio features are
    computed HERE — never duplicated in generators/parsers.
    """
    r = dict(_RAW_DEFAULTS)
    r.update({k: float(v) for k, v in (raw or {}).items() if k in _RAW_DEFAULTS})

    packets = max(r["total_packets"], 0.0)
    duration = max(r["duration_s"], 0.0)
    flows = max(r["flow_count"], 0.0)

    feats: Dict[str, float] = {
        "duration_s": r["duration_s"],
        "flow_count": r["flow_count"],
        "total_packets": r["total_packets"],
        "total_bytes": r["total_bytes"],
        "avg_pkt_size": _safe_div(r["total_bytes"], max(packets, 1.0)),
        "pkt_rate": _safe_div(packets, max(duration, 0.001)),
        "byte_rate": _safe_div(r["total_bytes"], max(duration, 0.001)),
        "syn_count": r["syn_count"],
        "ack_count": r["ack_count"],
        "fin_count": r["fin_count"],
        "rst_count": r["rst_count"],
        "syn_pct": _safe_div(r["syn_count"], max(packets, 1.0)),
        "rst_pct": _safe_div(r["rst_count"], max(packets, 1.0)),
        # max(ack,1) avoids divide-by-zero; high ratio == many half-open starts
        "syn_ack_ratio": _safe_div(r["syn_count"], max(r["ack_count"], 1.0)),
        "distinct_dst_ports": r["distinct_dst_ports"],
        "distinct_dst_ips": r["distinct_dst_ips"],
        "distinct_src_ips": r["distinct_src_ips"],
        "avg_flow_duration_s": r["avg_flow_duration_s"],
        "avg_flow_packets": r["avg_flow_packets"],
        "auth_port_pct": _safe_div(r["auth_flows"], max(flows, 1.0)),
        "tcp_pct": _safe_div(r["tcp_packets"], max(packets, 1.0)),
        "icmp_pct": _safe_div(r["icmp_packets"], max(packets, 1.0)),
    }
    return feats


def feature_row(feats: Dict[str, float]) -> List[float]:
    """Ordered feature list matching FEATURES (model input order)."""
    return [float(feats.get(f, 0.0)) for f in FEATURES]


def missing_features(feats: Dict[str, float]) -> List[str]:
    """Return canonical features absent from the given dict."""
    return [f for f in FEATURES if f not in feats]
