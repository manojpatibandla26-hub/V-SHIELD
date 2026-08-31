"""Offline PCAP analysis — READ-ONLY, safe, local file parsing.

Flow of data:
    file -> validate magic -> scapy PcapReader (streaming)
         -> packets -> bidirectional 5-tuple flows -> per (src->dst) pair
         -> raw counters (canonical schema) -> SAME ML pipeline as training
         -> predictions, risk, explanation, events

No packets are ever sent anywhere. We only read the file the user
uploaded. Heuristics that cannot be derived reliably from packet headers
are flagged in `limitations` instead of being silently invented.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from app.config import (PCAP_MAGIC_BYTES, PCAP_MAX_BYTES, PCAP_SAMPLES_DIR)
from app.core import pipeline
from app.core.feature_schema import AUTH_PORTS
from app.services import alerting

log = logging.getLogger("sentinel.pcap")

try:
    from scapy.all import IP, TCP, UDP, ICMP, PcapReader
    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    SCAPY_AVAILABLE = False


class PcapError(Exception):
    """User-friendly PCAP error."""


# ------------------------------------------------------------------ validation
def validate_file(path: Path, filename: str) -> None:
    if not filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise PcapError(
            "Unsupported file type. Please upload a .pcap or .pcapng capture.")
    size = path.stat().st_size
    if size == 0:
        raise PcapError("The uploaded file is empty.")
    if size > PCAP_MAX_BYTES:
        raise PcapError(
            f"File is too large ({size / 1e6:.1f} MB). Limit is "
            f"{PCAP_MAX_BYTES // (1024 * 1024)} MB for the demo.")
    with open(path, "rb") as fh:
        magic = fh.read(4)
    if magic not in PCAP_MAGIC_BYTES:
        raise PcapError(
            "This file does not look like a valid pcap/pcapng capture "
            "(magic bytes mismatch).")


# ------------------------------------------------------------------ flows
def _flow_key(src: str, sport: int, dst: str, dport: int, proto: str) -> Tuple:
    # canonical bidirectional key
    a, b = (src, sport), (dst, dport)
    return (tuple(sorted([a, b])), proto)


def _new_flow(src: str, sport: int, dst: str, dport: int, proto: str,
              ts: float) -> Dict:
    return {
        "initiator": src, "initiator_port": sport,
        "responder": dst, "initiator_dport": dport,
        "proto": proto, "first_ts": ts, "last_ts": ts,
        "packets": 0, "bytes": 0,
        "syn": 0, "ack": 0, "fin": 0, "rst": 0,
    }


def parse_to_flows(path: Path, max_packets: int = 200_000) -> Tuple[List[Dict], int]:
    """Parse a pcap into bidirectional flows. Returns (flows, packet_count)."""
    if not SCAPY_AVAILABLE:
        raise PcapError(
            "PCAP analysis requires the 'scapy' package "
            "(pip install scapy). It is in requirements.txt.")

    flows: Dict[Tuple, Dict] = {}
    count = 0
    try:
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                count += 1
                if count > max_packets:
                    break
                if IP not in pkt:
                    continue
                ip = pkt[IP]
                src, dst = ip.src, ip.dst
                ts = float(pkt.time)

                if TCP in pkt:
                    l4 = pkt[TCP]
                    proto, sport, dport = "tcp", int(l4.sport), int(l4.dport)
                    flags = int(l4.flags)
                    f_syn = bool(flags & 0x02)
                    f_ack = bool(flags & 0x10)
                    f_fin = bool(flags & 0x01)
                    f_rst = bool(flags & 0x04)
                elif UDP in pkt:
                    l4 = pkt[UDP]
                    proto, sport, dport = "udp", int(l4.sport), int(l4.dport)
                    f_syn = f_ack = f_fin = f_rst = False
                elif ICMP in pkt:
                    proto, sport, dport = "icmp", 0, 0
                    f_syn = f_ack = f_fin = f_rst = False
                else:
                    continue

                key = _flow_key(src, sport, dst, dport, proto)
                fl = flows.get(key)
                if fl is None:
                    fl = _new_flow(src, sport, dst, dport, proto, ts)
                    flows[key] = fl
                fl["last_ts"] = ts
                fl["packets"] += 1
                fl["bytes"] += int(len(pkt))
                fl["syn"] += f_syn
                fl["ack"] += f_ack
                fl["fin"] += f_fin
                fl["rst"] += f_rst
    except Exception as exc:  # scapy raises many shapes of parse errors
        raise PcapError(
            "Could not parse this capture file. It may be truncated, "
            "corrupted or use an unsupported link type. "
            f"(technical: {type(exc).__name__})") from exc

    return list(flows.values()), count


# ------------------------------------------------------------------ features
def flows_to_pair_windows(flows: List[Dict]) -> List[Dict]:
    """Aggregate flows into per (initiator -> responder) traffic windows."""
    pairs: Dict[Tuple[str, str], List[Dict]] = {}
    for fl in flows:
        pairs.setdefault((fl["initiator"], fl["responder"]), []).append(fl)

    windows = []
    for (src, dst), pair_flows in pairs.items():
        first = min(f["first_ts"] for f in pair_flows)
        last = max(f["last_ts"] for f in pair_flows)
        duration = max(last - first, 1.0)
        packets = sum(f["packets"] for f in pair_flows)
        bytes_ = sum(f["bytes"] for f in pair_flows)
        dports = {f["initiator_dport"] for f in pair_flows}
        auth = sum(1 for f in pair_flows if f["initiator_dport"] in AUTH_PORTS)
        tcp_pkts = sum(f["packets"] for f in pair_flows if f["proto"] == "tcp")
        udp_pkts = sum(f["packets"] for f in pair_flows if f["proto"] == "udp")
        icmp_pkts = sum(f["packets"] for f in pair_flows if f["proto"] == "icmp")
        flow_durs = [f["last_ts"] - f["first_ts"] for f in pair_flows]

        raw = {
            "duration_s": duration,
            "flow_count": len(pair_flows),
            "total_packets": packets,
            "total_bytes": bytes_,
            "syn_count": sum(f["syn"] for f in pair_flows),
            "ack_count": sum(f["ack"] for f in pair_flows),
            "fin_count": sum(f["fin"] for f in pair_flows),
            "rst_count": sum(f["rst"] for f in pair_flows),
            "distinct_dst_ports": len(dports),
            "distinct_dst_ips": 1,
            "distinct_src_ips": 1,
            "avg_flow_duration_s": sum(flow_durs) / max(len(flow_durs), 1),
            "avg_flow_packets": packets / max(len(pair_flows), 1),
            "auth_flows": auth,
            "tcp_packets": tcp_pkts,
            "udp_packets": udp_pkts,
            "icmp_packets": icmp_pkts,
        }
        windows.append({"source": src, "target": dst, "raw": raw,
                        "first_ts": first, "flow_durs": flow_durs})
    return windows


def global_window(flows: List[Dict]) -> Optional[Dict]:
    """One whole-capture aggregate (catches many->one DDoS shapes)."""
    if not flows:
        return None
    first = min(f["first_ts"] for f in flows)
    last = max(f["last_ts"] for f in flows)
    duration = max(last - first, 1.0)
    packets = sum(f["packets"] for f in flows)
    inits = {f["initiator"] for f in flows}
    resp = {f["responder"] for f in flows}
    dports = {f["initiator_dport"] for f in flows}
    raw = {
        "duration_s": duration,
        "flow_count": len(flows),
        "total_packets": packets,
        "total_bytes": sum(f["bytes"] for f in flows),
        "syn_count": sum(f["syn"] for f in flows),
        "ack_count": sum(f["ack"] for f in flows),
        "fin_count": sum(f["fin"] for f in flows),
        "rst_count": sum(f["rst"] for f in flows),
        "distinct_dst_ports": len(dports),
        "distinct_dst_ips": len(resp),
        "distinct_src_ips": len(inits),
        "avg_flow_duration_s": sum(f["last_ts"] - f["first_ts"]
                                   for f in flows) / max(len(flows), 1),
        "avg_flow_packets": packets / max(len(flows), 1),
        "auth_flows": sum(1 for f in flows if f["initiator_dport"] in AUTH_PORTS),
        "tcp_packets": sum(f["packets"] for f in flows if f["proto"] == "tcp"),
        "udp_packets": sum(f["packets"] for f in flows if f["proto"] == "udp"),
        "icmp_packets": sum(f["packets"] for f in flows if f["proto"] == "icmp"),
    }
    return {"source": "whole capture (aggregate)", "target": "all hosts",
            "raw": raw, "first_ts": first}


# ------------------------------------------------------------------ analysis
async def analyze_file(path: Path, filename: str,
                       create_events: bool = True) -> Dict:
    t0 = time.perf_counter()
    validate_file(path, filename)
    flows, packet_count = parse_to_flows(path)

    if packet_count == 0:
        raise PcapError("No packets could be read from this capture.")
    if not flows:
        raise PcapError(
            "No IP packets found. Link-layer encapsulation (e.g. pure ARP, "
            "or unusual link types) is not supported by this demo.")

    windows = flows_to_pair_windows(flows)
    results = []
    limitations: List[str] = [
        "PCAP analysis reads packet HEADERS only — payload content is never "
        "inspected, so login failures are inferred from connection shapes "
        "(short repeated flows ending in resets), not from actual "
        "authentication results.",
        "Per-second timeline approximates volume by flow start times.",
    ]
    if packet_count < 60:
        limitations.append(
            "Very short capture — statistical confidence is limited.")
    if len(flows) < 8:
        limitations.append(
            "Few flows in capture — per-pair aggregates may be noisy.")

    for w in windows:
        result = pipeline.analyze_window(w["raw"], source=w["source"],
                                         target=w["target"])
        result["ts"] = w["first_ts"]
        results.append(result)
        if create_events and result["label"] != "BENIGN":
            await alerting.publish_threat(result, origin="pcap")

    g = global_window(flows)
    global_result = None
    if g and len(windows) > 1:
        global_result = pipeline.analyze_window(g["raw"], source=g["source"],
                                                target=g["target"])

    # timeline: packets per 1-second bucket
    t_first = min(f["first_ts"] for f in flows)
    t_last = max(f["last_ts"] for f in flows)
    span = max(int(t_last - t_first) + 1, 1)
    buckets = [0] * min(span, 3600)
    # approximation: a flow's packets are attributed to its start second
    for f in flows:
        idx = min(int(f["first_ts"] - t_first), len(buckets) - 1)
        buckets[idx] += f["packets"]
    timeline = [{"t": i, "packets": b} for i, b in enumerate(buckets)]

    suspicious = [r for r in results if r["label"] != "BENIGN"]
    attack_types: Dict[str, int] = {}
    sev_dist: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    risk_dist: Dict[str, int] = {"0-24": 0, "25-49": 0, "50-74": 0,
                                 "75-100": 0}
    for r in suspicious:
        attack_types[r["label"]] = attack_types.get(r["label"], 0) + 1
        sev_dist[r["severity"]] += 1
        bucket = ("0-24" if r["risk"] <= 24 else "25-49" if r["risk"] <= 49
                  else "50-74" if r["risk"] <= 74 else "75-100")
        risk_dist[bucket] += 1

    return {
        "filename": filename,
        "total_packets": packet_count,
        "total_flows": len(flows),
        "analyzed_windows": len(results) + (1 if global_result else 0),
        "benign_flows": len(results) - len(suspicious),
        "suspicious_flows": len(suspicious),
        "attack_types": attack_types,
        "severity_distribution": sev_dist,
        "risk_distribution": risk_dist,
        "results": [summarize(r) for r in results],
        "global_assessment": summarize(global_result) if global_result else None,
        "timeline": timeline,
        "limitations": limitations,
        "analysis_ms": round((time.perf_counter() - t0) * 1000, 1),
    }


def summarize(r: Dict) -> Dict:
    """Compact per-window summary for the frontend table."""
    return {
        "event_id": r["event_id"],
        "source": r["source"],
        "target": r["target"],
        "label": r["label"],
        "classification": r["classification"],
        "confidence": r["confidence"],
        "risk": r["risk"],
        "severity": r["severity"],
        "anomaly_score": r["anomaly_score"],
        "observed": r["observed"],
        "explanation": r["explanation"],
        "features": r["features"],
        "ts": r.get("ts"),
    }
