"""Bundled sample PCAPs (generated locally by tools/generate_samples.py).

These are SYNTHETIC captures created with scapy on this machine —
no real network traffic was captured or harmed. They exist so the
PCAP-analysis demo works out of the box.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from app.config import PCAP_SAMPLES_DIR

SAMPLES: List[Dict] = [
    {
        "name": "benign_web",
        "filename": "benign_web.pcap",
        "description": "Normal web browsing: 4 clients, full TCP handshakes, "
                       "real payload sizes, few ports.",
        "expected": "All windows classify as BENIGN.",
    },
    {
        "name": "portscan",
        "filename": "portscan.pcap",
        "description": "One host probes 500 ports with tiny SYN-only "
                       "connections (half-open scan).",
        "expected": "PORT_SCAN detected on the attacker pair.",
    },
    {
        "name": "synflood",
        "filename": "synflood.pcap",
        "description": "18,000 SYNs against one service; the target answers "
                       "only a fraction — half-open connections everywhere.",
        "expected": "SYN_FLOOD detected with high risk.",
    },
    {
        "name": "bruteforce",
        "filename": "bruteforce.pcap",
        "description": "150 short SSH connection attempts, each ending in a "
                       "reset (failed logins).",
        "expected": "BRUTE_FORCE detected on the attacker pair.",
    },
    {
        "name": "mixed_traffic",
        "filename": "mixed_traffic.pcap",
        "description": "Benign browsing + port scan + SYN flood + brute force "
                       "in one capture — the full showcase.",
        "expected": "Multiple attack types detected simultaneously.",
    },
]


def list_samples() -> List[Dict]:
    out = []
    for s in SAMPLES:
        p = PCAP_SAMPLES_DIR / s["filename"]
        out.append({
            "name": s["name"], "filename": s["filename"],
            "description": s["description"], "expected": s["expected"],
            "size_bytes": p.stat().st_size if p.exists() else 0,
            "available": p.exists(),
        })
    return out


def sample_path(name: str) -> Optional[Path]:
    for s in SAMPLES:
        if s["name"] == name:
            p = PCAP_SAMPLES_DIR / s["filename"]
            return p if p.exists() else None
    return None
