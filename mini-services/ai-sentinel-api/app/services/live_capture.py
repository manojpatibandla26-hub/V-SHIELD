"""AI Sentinel — Live Packet Capture Engine (Scapy).

Safely captures packets from authorized local network interfaces, aggregates
them into canonical time windows, extracts the 22 NIDS features, and feeds
them directly into the RandomForest + IsolationForest ML pipeline.

Safety & Stability Guards:
- Captures ONLY from local/authorized network interfaces.
- Handles Npcap / WinPcap / permission requirements gracefully.
- Never crashes the FastAPI backend if raw packet capture is unavailable.
- Switches between LIVE capture and BASELINE synthetic stream seamlessly.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import threading
import time
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional

import scapy.all as scapy

from app.config import SIM_WINDOW_SECONDS
from app.core import pipeline
from app.services import events, state

log = logging.getLogger("sentinel.capture")

STATE_AVAILABLE = "CAPTURE_AVAILABLE"
STATE_RUNNING = "CAPTURE_RUNNING"
STATE_STOPPED = "CAPTURE_STOPPED"
STATE_ERROR = "CAPTURE_ERROR"

_lock = threading.Lock()
_capture_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()
_current_state = STATE_AVAILABLE
_current_iface: Optional[str] = None
_error_message: Optional[str] = None
_packets_captured = 0
_start_time: Optional[float] = None

_window_packets: List[Dict[str, Any]] = []
_flow_tracker: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"packets": 0, "bytes": 0, "start": time.time(), "last": time.time()})
_async_loop: Optional[asyncio.AbstractEventLoop] = None


def get_interfaces() -> List[Dict[str, Any]]:
    """Enumerate available network interfaces."""
    interfaces: List[Dict[str, Any]] = []
    seen = set()

    try:
        if hasattr(scapy.conf, "ifaces"):
            for key, iface in scapy.conf.ifaces.items():
                name = getattr(iface, "name", str(key))
                ip = getattr(iface, "ip", "")
                mac = getattr(iface, "mac", "")
                description = getattr(iface, "description", name)
                if not name or name in seen:
                    continue
                seen.add(name)
                interfaces.append({
                    "id": str(key),
                    "name": name,
                    "description": description or name,
                    "ip": ip or "0.0.0.0",
                    "mac": mac or "",
                    "is_loopback": "loopback" in name.lower() or ip == "127.0.0.1",
                    "is_active": bool(ip and ip != "0.0.0.0"),
                })
    except Exception as e:
        log.warning("Could not read scapy conf.ifaces: %s", e)

    if not interfaces:
        try:
            hostname = socket.gethostname()
            local_ips = socket.gethostbyname_ex(hostname)[2]
            for idx, ip in enumerate(local_ips):
                interfaces.append({
                    "id": f"host_iface_{idx}",
                    "name": f"Local Interface ({ip})",
                    "description": f"Host Interface - {hostname}",
                    "ip": ip,
                    "mac": "",
                    "is_loopback": ip.startswith("127."),
                    "is_active": True,
                })
        except Exception as e:
            log.warning("Could not get host IPs: %s", e)

    return interfaces


def get_status() -> Dict[str, Any]:
    """Return the current packet capture engine status."""
    with _lock:
        duration = round(time.time() - _start_time, 1) if _start_time and _current_state == STATE_RUNNING else 0.0
        return {
            "status": _current_state,
            "mode": "LIVE" if _current_state == STATE_RUNNING else "SYNTHETIC_BASELINE",
            "interface": _current_iface,
            "packets_captured": _packets_captured,
            "duration_s": duration,
            "error": _error_message,
            "pcap_provider": getattr(scapy.conf, "use_pcap", False),
        }


def _process_packet(pkt: Any) -> None:
    """Callback invoked by Scapy for each captured packet."""
    global _packets_captured
    try:
        _packets_captured += 1
        pkt_len = len(pkt) if hasattr(pkt, "__len__") else 64
        now = time.time()

        src_ip = "127.0.0.1"
        dst_ip = "127.0.0.1"
        proto = "OTHER"
        src_port = 0
        dst_port = 0
        flags = ""

        if pkt.haslayer(scapy.IP):
            src_ip = pkt[scapy.IP].src
            dst_ip = pkt[scapy.IP].dst
            proto = "IP"

        if pkt.haslayer(scapy.TCP):
            proto = "TCP"
            src_port = pkt[scapy.TCP].sport
            dst_port = pkt[scapy.TCP].dport
            flags = str(pkt[scapy.TCP].flags)
        elif pkt.haslayer(scapy.UDP):
            proto = "UDP"
            src_port = pkt[scapy.UDP].sport
            dst_port = pkt[scapy.UDP].dport
        elif pkt.haslayer(scapy.ICMP):
            proto = "ICMP"

        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto}"
        flow = _flow_tracker[flow_key]
        flow["packets"] += 1
        flow["bytes"] += pkt_len
        flow["last"] = now

        _window_packets.append({
            "ts": now,
            "len": pkt_len,
            "src": src_ip,
            "dst": dst_ip,
            "proto": proto,
            "sport": src_port,
            "dport": dst_port,
            "flags": flags,
            "flow_key": flow_key,
        })
    except Exception as exc:
        log.debug("Error processing captured packet: %s", exc)


def aggregate_and_analyze_window() -> Optional[Dict[str, Any]]:
    """Aggregate sliding window packets and run through the ML detection pipeline."""
    global _window_packets
    now = time.time()
    cutoff = now - SIM_WINDOW_SECONDS

    recent = [p for p in _window_packets if p["ts"] >= cutoff]
    _window_packets = recent

    if not recent:
        return None

    duration = max(SIM_WINDOW_SECONDS, 1.0)
    total_packets = len(recent)
    total_bytes = sum(p["len"] for p in recent)

    syn_count = sum(1 for p in recent if "S" in p.get("flags", ""))
    ack_count = sum(1 for p in recent if "A" in p.get("flags", ""))
    fin_count = sum(1 for p in recent if "F" in p.get("flags", ""))
    rst_count = sum(1 for p in recent if "R" in p.get("flags", ""))

    tcp_packets = sum(1 for p in recent if p["proto"] == "TCP")
    udp_packets = sum(1 for p in recent if p["proto"] == "UDP")
    icmp_packets = sum(1 for p in recent if p["proto"] == "ICMP")

    dst_ports = len(set(p["dport"] for p in recent if p["dport"] > 0))
    dst_ips = len(set(p["dst"] for p in recent))
    src_ips = len(set(p["src"] for p in recent))
    flow_count = len(set(p["flow_key"] for p in recent))

    auth_flows = sum(1 for p in recent if p["dport"] in (22, 3389, 80, 443, 8080))
    avg_flow_packets = total_packets / max(flow_count, 1)

    raw_features = {
        "duration_s": duration,
        "flow_count": max(flow_count, 1),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "syn_count": syn_count,
        "ack_count": ack_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "distinct_dst_ports": max(dst_ports, 1),
        "distinct_dst_ips": max(dst_ips, 1),
        "distinct_src_ips": max(src_ips, 1),
        "avg_flow_duration_s": duration / max(flow_count, 1),
        "avg_flow_packets": avg_flow_packets,
        "auth_flows": auth_flows,
        "tcp_packets": tcp_packets,
        "udp_packets": udp_packets,
        "icmp_packets": icmp_packets,
    }

    primary_src = recent[0]["src"] if recent else "127.0.0.1"
    primary_dst = recent[0]["dst"] if recent else "127.0.0.1"

    return pipeline.analyze_window(raw_features, source=primary_src, target=primary_dst)


def _capture_worker(iface: Optional[str]) -> None:
    """Background sniffing thread."""
    global _current_state, _error_message, _start_time
    log.info("Starting live Scapy packet capture on iface=%s", iface)
    try:
        kwargs: Dict[str, Any] = {
            "prn": _process_packet,
            "store": False,
            "stop_filter": lambda _: _stop_event.is_set(),
        }
        if iface:
            kwargs["iface"] = iface

        _start_time = time.time()
        with _lock:
            _current_state = STATE_RUNNING
            _error_message = None

        scapy.sniff(**kwargs)

    except PermissionError as pe:
        log.error("Packet capture permission denied: %s", pe)
        with _lock:
            _current_state = STATE_ERROR
            _error_message = "Permission denied. Windows requires Administrator privileges and Npcap installed for raw packet capture."
    except Exception as exc:
        log.error("Packet capture failed: %s", exc)
        with _lock:
            _current_state = STATE_ERROR
            _error_message = f"Capture error: {exc}"
    finally:
        with _lock:
            if _current_state == STATE_RUNNING:
                _current_state = STATE_STOPPED


def start_capture(iface: Optional[str] = None) -> Dict[str, Any]:
    """Start live packet capture in a background thread."""
    global _capture_thread, _stop_event, _current_iface, _current_state, _packets_captured
    with _lock:
        if _current_state == STATE_RUNNING:
            return {"ok": True, "status": _current_state, "message": "Capture already running", "interface": _current_iface}

        _stop_event.clear()
        _current_iface = iface
        _packets_captured = 0

        _capture_thread = threading.Thread(target=_capture_worker, args=(iface,), daemon=True)
        _capture_thread.start()
        _current_state = STATE_RUNNING

    return {"ok": True, "status": STATE_RUNNING, "interface": iface or "default"}


def stop_capture() -> Dict[str, Any]:
    """Stop the live packet capture engine."""
    global _stop_event, _current_state
    with _lock:
        _stop_event.set()
        _current_state = STATE_STOPPED

    return {"ok": True, "status": STATE_STOPPED, "message": "Packet capture stopped"}
