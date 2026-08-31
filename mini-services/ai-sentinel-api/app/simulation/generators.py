"""Safe attack simulation generators — SYNTHETIC data only.

NO real tools (nmap/hping3/hydra), NO real packets, NO real targets.

Each scenario produces a synthetic *traffic window*: a benign background
component (like normal network usage) plus an attack component whose
magnitude scales with the scenario intensity. This mirrors reality — an
attack does not replace all traffic, it ADDS to it — and produces a
natural detection story: early windows look almost normal, then the
anomaly detector stirs, then the classifier identifies the attack, and
risk escalates as the attack dominates the window.

The generated raw counters flow through the SAME pipeline as training
data and PCAP analysis:

    generator ──> feature_schema.derive() ──> RandomForest ──> risk ──> WS
"""
from __future__ import annotations

import random
from typing import Dict

from app.config import SIM_WINDOW_SECONDS

SCENARIOS: Dict[str, Dict] = {
    "syn_flood": {
        "name": "SYN Flood",
        "tagline": "Simulates a large number of incomplete TCP connection attempts.",
        "description": (
            "A flood of TCP SYN packets is sent without ever completing the "
            "three-way handshake. The target's connection table fills with "
            "half-open connections until legitimate users cannot connect. "
            "Generated as synthetic traffic statistics only — nothing is sent "
            "over any network."
        ),
        "expected": "SYN_FLOOD classification with rising risk as the flood intensifies",
        "source": "10.0.9.15",
        "target": "10.0.0.1:443",
    },
    "dos_ddos": {
        "name": "DoS / DDoS Flood",
        "tagline": "Simulates an overwhelming volume of traffic from many sources.",
        "description": (
            "A simulated botnet hammers one service with extreme packet and "
            "byte volume. This is the classic availability attack: it does not "
            "steal data, it makes the service unreachable. All numbers are "
            "synthetic."
        ),
        "expected": "DOS_DDOS classification; bandwidth and source-count evidence",
        "source": "botnet 10.0.9.0/24 (aggregate)",
        "target": "10.0.0.1:80",
    },
    "port_scan": {
        "name": "Port Scan",
        "tagline": "Simulates reconnaissance: one host quietly probing many ports.",
        "description": (
            "A single source probes hundreds of destination ports in sequence "
            "with tiny, payload-less connections, listening for open services — "
            "the usual first step before a targeted attack."
        ),
        "expected": "PORT_SCAN classification with distinct-port evidence",
        "source": "10.0.9.21",
        "target": "10.0.0.1:1-1024",
    },
    "brute_force": {
        "name": "Brute Force",
        "tagline": "Simulates repeated password-guessing against a login service.",
        "description": (
            "One host repeatedly opens short connections to an SSH service, "
            "each ending in failure (reset). Passwords are never actually "
            "guessed — only the connection pattern is simulated."
        ),
        "expected": "BRUTE_FORCE classification with login-service evidence",
        "source": "10.0.9.33",
        "target": "10.0.0.2:22",
    },
    "anomaly": {
        "name": "Network Anomaly",
        "tagline": "Simulates unusual-but-not-attack behaviour (unknown pattern).",
        "description": (
            "Traffic that is not a known attack: e.g. a sudden ICMP flood, a "
            "FIN sweep, or giant jumbo packets. The RandomForest alone may not "
            "recognise it — the IsolationForest anomaly detector flags it as "
            "unknown unusual behaviour."
        ),
        "expected": "ANOMALY classification driven by the anomaly detector",
        "source": "10.0.9.7",
        "target": "10.0.0.2",
    },
}


def _jit(rng: random.Random, v: float, spread: float = 0.08) -> float:
    return v * (1.0 + rng.uniform(-spread, spread))


# ------------------------------------------------------------- benign part
def benign_component(rng: random.Random) -> Dict[str, float]:
    """Normal background traffic in the window (same shape as the live engine)."""
    pkt_rate = rng.uniform(80, 900)
    packets = int(pkt_rate * SIM_WINDOW_SECONDS)
    flows = rng.randint(2, 10)
    return {
        "duration_s": SIM_WINDOW_SECONDS,
        "flow_count": flows,
        "total_packets": packets,
        "total_bytes": int(packets * rng.uniform(200, 900)),
        "syn_count": int(flows * rng.uniform(1.8, 2.6)),
        "ack_count": int(packets * rng.uniform(0.55, 0.9)),
        "fin_count": int(flows * rng.uniform(1.0, 2.2)),
        "rst_count": rng.choice([0, 0, 0, 1]),
        "distinct_dst_ports": rng.randint(1, 6),
        "distinct_dst_ips": rng.randint(1, 3),
        "distinct_src_ips": rng.choice([1, 1, 2]),
        "avg_flow_duration_s": rng.uniform(0.2, 4.0),
        "avg_flow_packets": packets / flows,
        "auth_flows": rng.choice([0, 0, 1]),
        "tcp_packets": int(packets * rng.uniform(0.8, 1.0)),
        "udp_packets": int(packets * 0.08),
        "icmp_packets": rng.choice([0, 0, 0, 2]),
    }


# ------------------------------------------------------------- blending
_SUM_KEYS = ["total_packets", "total_bytes", "syn_count", "ack_count",
             "fin_count", "rst_count", "auth_flows", "tcp_packets",
             "udp_packets", "icmp_packets", "flow_count"]
_MAX_KEYS = ["distinct_dst_ports", "distinct_dst_ips", "distinct_src_ips"]


def _blend(base: Dict[str, float], delta: Dict[str, float],
           t: float) -> Dict[str, float]:
    """background*(1-1.5t) + attack_delta — realistic 'attack adds to traffic'.

    The background share shrinks quickly as the attack ramps so the
    attack signature emerges within a few windows (mirrors how an
    escalating attack quickly dominates the traffic mix)."""
    keep = max(0.0, 1.0 - 2.5 * t)
    out: Dict[str, float] = {"duration_s": SIM_WINDOW_SECONDS}
    for k in _SUM_KEYS:
        out[k] = int(base.get(k, 0) * keep + delta.get(k, 0))
    for k in _MAX_KEYS:
        out[k] = max(base.get(k, 1), delta.get(k, 1))
    out["total_packets"] = max(out["total_packets"], 1)
    # flow-weighted averages
    fb, fd = max(base.get("flow_count", 1), 1), max(delta.get("flow_count", 0), 0)
    wf = fb * keep + fd
    if wf > 0:
        out["avg_flow_duration_s"] = (
            base.get("avg_flow_duration_s", 1.0) * fb * keep
            + delta.get("avg_flow_duration_s", 0.0) * fd) / wf
        out["avg_flow_packets"] = (
            base.get("avg_flow_packets", 1.0) * fb * keep
            + delta.get("avg_flow_packets", 0.0) * fd) / wf
    else:
        out["avg_flow_duration_s"] = base.get("avg_flow_duration_s", 1.0)
        out["avg_flow_packets"] = base.get("avg_flow_packets", 1.0)
    return out


# ------------------------------------------------------------- attack deltas
def _syn_flood_delta(t: float, rng: random.Random) -> Dict[str, float]:
    pkt_rate = _jit(rng, 200 + (t ** 1.8) * 30000)
    packets = int(pkt_rate * SIM_WINDOW_SECONDS)
    syn_share = 0.75 + 0.20 * t          # flood shape is pure from the start
    ack_share = 0.04                      # almost no completion, always
    flows = int(packets / 1.12)
    return {
        "flow_count": flows, "total_packets": packets,
        "total_bytes": int(packets * rng.uniform(46, 78)),
        "syn_count": int(packets * syn_share),
        "ack_count": int(packets * ack_share),
        "fin_count": 0, "rst_count": int(packets * 0.02 * t),
        "distinct_dst_ports": 1, "distinct_dst_ips": 1,
        "distinct_src_ips": 1,
        "avg_flow_duration_s": rng.uniform(0.004, 0.015),
        "avg_flow_packets": 1.12,
        "auth_flows": 0, "tcp_packets": packets,
    }


def _dos_ddos_delta(t: float, rng: random.Random) -> Dict[str, float]:
    pkt_rate = _jit(rng, 350 + t * 36500)
    packets = int(pkt_rate * SIM_WINDOW_SECONDS)
    avg_pkt = 950 - 790 * t
    avg_flow_pkts = rng.uniform(50, 110) * (1 - t) + rng.uniform(3, 6) * t
    flows = int(packets / max(avg_flow_pkts, 1))
    return {
        "flow_count": flows, "total_packets": packets,
        "total_bytes": int(packets * avg_pkt),
        "syn_count": int(packets * (0.12 + 0.30 * t)),
        "ack_count": int(packets * (0.28 - 0.18 * t)),
        "fin_count": int(packets * 0.01 * (1 - t)),
        "rst_count": int(packets * (0.02 + 0.12 * t)),
        "distinct_dst_ports": rng.choice([1, 2]),
        "distinct_dst_ips": 1,
        "distinct_src_ips": 1 + int(t * 42),          # botnet grows
        "avg_flow_duration_s": rng.uniform(0.2, 3.0) * (1 - 0.7 * t),
        "avg_flow_packets": avg_flow_pkts,
        "auth_flows": 0, "tcp_packets": int(packets * 0.98),
    }


def _port_scan_delta(t: float, rng: random.Random) -> Dict[str, float]:
    ports = max(int(6 + (t ** 1.1) * 900), 3)
    flows = int(ports * 1.15)
    avg_flow_pkts = 1.1 + rng.uniform(0, 1.1)
    packets = int(flows * avg_flow_pkts)
    return {
        "flow_count": flows, "total_packets": packets,
        "total_bytes": int(packets * rng.uniform(46, 92)),
        "syn_count": int(packets * (0.5 + 0.3 * t)),
        "ack_count": int(packets * 0.12),
        "fin_count": 0,
        "rst_count": int(packets * (0.22 + 0.25 * t)),
        "distinct_dst_ports": ports, "distinct_dst_ips": 1,
        "distinct_src_ips": 1,
        "avg_flow_duration_s": rng.uniform(0.005, 0.035),
        "avg_flow_packets": avg_flow_pkts,
        "auth_flows": int(flows * 0.06),
        "tcp_packets": int(packets * 0.97),
    }


def _brute_force_delta(t: float, rng: random.Random) -> Dict[str, float]:
    attempts = int(5 + (t ** 1.1) * 330)
    avg_flow_pkts = rng.uniform(5, 13)
    packets = int(attempts * avg_flow_pkts)
    return {
        "flow_count": attempts, "total_packets": packets,
        "total_bytes": int(packets * rng.uniform(80, 240)),
        "syn_count": int(packets * 0.22),
        "ack_count": int(packets * 0.42),
        "fin_count": int(packets * 0.04),
        "rst_count": int(packets * (0.05 + 0.30 * t)),
        "distinct_dst_ports": 1, "distinct_dst_ips": 1,
        "distinct_src_ips": 1,
        "avg_flow_duration_s": rng.uniform(0.1, 1.5),
        "avg_flow_packets": avg_flow_pkts,
        "auth_flows": attempts,                    # every flow hits SSH
        "tcp_packets": packets,
    }


def _anomaly_delta(t: float, rng: random.Random,
                   mode: str | None = None) -> Dict[str, float]:
    mode = mode or rng.choice(["icmp_flood", "fin_sweep", "jumbo"])
    if mode == "icmp_flood":
        packets = int(450 + (t ** 1.2) * 6000)
        icmp = int(packets * (0.4 + 0.45 * t))
        return {
            "flow_count": rng.randint(4, 30), "total_packets": packets,
            "total_bytes": int(packets * rng.uniform(64, 150)),
            "syn_count": int(packets * 0.02), "ack_count": 0, "fin_count": 0,
            "rst_count": 0, "distinct_dst_ports": 2, "distinct_dst_ips": 1,
            "distinct_src_ips": 1, "avg_flow_duration_s": 0.2,
            "avg_flow_packets": packets / 8, "auth_flows": 0,
            "tcp_packets": packets - icmp, "icmp_packets": icmp,
        }
    if mode == "fin_sweep":
        ports = int(70 + (t ** 1.2) * 580)
        packets = int(ports * 1.15)
        return {
            "flow_count": ports, "total_packets": packets,
            "total_bytes": int(packets * rng.uniform(44, 92)),
            "syn_count": int(packets * 0.03), "ack_count": int(packets * 0.2),
            "fin_count": int(packets * (0.45 + 0.35 * t)), "rst_count": 0,
            "distinct_dst_ports": ports, "distinct_dst_ips": 1,
            "distinct_src_ips": 1, "avg_flow_duration_s": 0.008,
            "avg_flow_packets": 1.15, "auth_flows": 0,
            "tcp_packets": packets,
        }
    # jumbo odd packets toward a login service
    packets = int(300 + (t ** 1.2) * 800)
    flows = int(15 + t * 280)
    return {
        "flow_count": flows, "total_packets": packets,
        "total_bytes": int(packets * (4300 + t * 4600)),
        "syn_count": int(packets * (0.3 + 0.2 * t)),
        "ack_count": int(packets * 0.35), "fin_count": 0, "rst_count": 0,
        "distinct_dst_ports": 1, "distinct_dst_ips": 1,
        "distinct_src_ips": 1, "avg_flow_duration_s": rng.uniform(0.05, 0.4),
        "avg_flow_packets": packets / max(flows, 1),
        "auth_flows": flows, "tcp_packets": packets,
    }


_DELTAS = {
    "syn_flood": _syn_flood_delta,
    "dos_ddos": _dos_ddos_delta,
    "port_scan": _port_scan_delta,
    "brute_force": _brute_force_delta,
}


def generate(attack_type: str, intensity: float,
             rng: random.Random) -> Dict[str, float]:
    """One synthetic window: benign background + scaled attack component."""
    t = max(0.0, min(1.0, intensity))
    base = benign_component(rng)
    if attack_type == "anomaly":
        delta = _anomaly_delta(t, rng)
    else:
        delta = _DELTAS[attack_type](t, rng)
    return _blend(base, delta, t)
