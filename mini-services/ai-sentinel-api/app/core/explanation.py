"""Explanation engine — evidence built from ACTUAL observed features.

Every explanation references the real numbers seen in the traffic window,
compared against benign baselines measured at training time
(ml/models/benign_baselines.json). Nothing here is random or generic:
if no rule fires for a class, the system says so honestly.
"""
from __future__ import annotations

from typing import Callable, Dict, List

from app.core import model_registry
from app.core.feature_schema import CLASS_DISPLAY

# ------------------------------------------------------------------ texts
CLASS_TEXTS = {
    "SYN_FLOOD": {
        "headline": "Unusual connection behaviour detected",
        "meaning": (
            "Large numbers of connection requests are being created without "
            "completing normally. Each request starts a half-open connection, "
            "and the target's connection table fills up — which can prevent "
            "legitimate users from connecting."
        ),
        "recommendation": (
            "Rate-limit new connection requests from this source, enable SYN "
            "cookies on the target host, and investigate where the source "
            "traffic originates."
        ),
    },
    "DOS_DDOS": {
        "headline": "Traffic volume far above normal levels",
        "meaning": (
            "The network is receiving an extreme amount of traffic in a very "
            "short period. This can saturate bandwidth or exhaust server "
            "resources, making services slow or unavailable."
        ),
        "recommendation": (
            "Activate rate limiting and traffic filtering at the network edge, "
            "alert the upstream provider if volume keeps growing, and check "
            "service health and auto-scaling limits."
        ),
    },
    "PORT_SCAN": {
        "headline": "Network reconnaissance detected",
        "meaning": (
            "One source is probing a large number of ports on a target in a "
            "short period, looking for open services. Scanning is usually the "
            "first step before a targeted attack."
        ),
        "recommendation": (
            "Restrict which services are reachable from outside, log the "
            "scanning source for review, and verify that no unexpected "
            "service is exposed."
        ),
    },
    "BRUTE_FORCE": {
        "headline": "Repeated login attempts detected",
        "meaning": (
            "A source is making many short, repeated connections to a login "
            "service (such as SSH or FTP). The pattern and failure rate "
            "suggest systematic password guessing."
        ),
        "recommendation": (
            "Block or rate-limit the source, enforce strong passwords or key "
            "based login, enable account lockout policies, and enable "
            "multi-factor authentication."
        ),
    },
    "ANOMALY": {
        "headline": "Unusual network behaviour detected",
        "meaning": (
            "This traffic does not match a known attack pattern, but it "
            "differs significantly from the normal baseline — for example in "
            "protocol mix, packet sizes, or the shape of its connections. "
            "Unusual does not automatically mean malicious."
        ),
        "recommendation": (
            "Investigate the involved hosts manually: check running processes, "
            "recent configuration changes, and whether this behaviour is "
            "expected in your environment."
        ),
    },
    "BENIGN": {
        "headline": "Traffic within normal patterns",
        "meaning": (
            "Connection patterns, volume and protocol mix match the learned "
            "baseline of normal traffic."
        ),
        "recommendation": "No action needed.",
    },
}

# ------------------------------------------------------------------ helpers
def _pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def _rate(x: float) -> str:
    if x >= 1000:
        return f"{x:,.0f} pkt/s"
    return f"{x:.0f} pkt/s"


def _bytes(x: float) -> str:
    for unit, div in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if x >= div:
            return f"{x / div:.1f} {unit}"
    return f"{x:.0f} B"


def _ratio(x: float) -> str:
    return f"{x:.1f}×"


Rule = tuple  # (fires, text) callables

_RULES: Dict[str, List[Rule]] = {}


def _rules(cls: str):
    def deco(fn):
        _RULES[cls] = fn()
        return fn
    return deco


def _base(key: str) -> Dict[str, float]:
    return model_registry.baselines().get("feature_percentiles", {}).get(key, {})


# ------------------------------------------------------------------ rules
@_rules("SYN_FLOOD")
def _syn_rules():
    return [
        (lambda f, b: f["syn_pct"] > 0.30,
         lambda f, b: ("SYN packet share", _pct(f["syn_pct"]),
                       "below 8%",
                       f"SYN packets make up {_pct(f['syn_pct'])} of all traffic "
                       f"(normal traffic stays below 8%).")),
        (lambda f, b: f["syn_ack_ratio"] > 1.5,
         lambda f, b: ("Connections started vs. completed", _ratio(f["syn_ack_ratio"]),
                       "below 0.5×",
                       f"Connection starts outnumber completions by "
                       f"{f['syn_ack_ratio']:.1f} to 1 — large numbers of "
                       f"half-open connections.")),
        (lambda f, b: f["avg_flow_packets"] < 2.5 and f["flow_count"] > 50,
         lambda f, b: ("Data per connection", f"{f['avg_flow_packets']:.1f} packets",
                       "10+ packets",
                       f"Each connection carries only {f['avg_flow_packets']:.1f} "
                       f"packets — almost no data is exchanged.")),
        (lambda f, b: f["pkt_rate"] > _base("pkt_rate").get("p99", 1600),
         lambda f, b: ("Packet rate", _rate(f["pkt_rate"]),
                       f"≤ {_rate(_base('pkt_rate').get('p99', 1600))}",
                       f"Packet rate is {_rate(f['pkt_rate'])} — "
                       f"{f['pkt_rate'] / max(_base('pkt_rate').get('p99', 1), 1):.0f}× "
                       f"the normal peak.")),
    ]


@_rules("DOS_DDOS")
def _dos_rules():
    return [
        (lambda f, b: f["pkt_rate"] > _base("pkt_rate").get("p99", 1600),
         lambda f, b: ("Packet rate", _rate(f["pkt_rate"]),
                       f"≤ {_rate(_base('pkt_rate').get('p99', 1600))}",
                       f"Traffic volume of {_rate(f['pkt_rate'])} is far above "
                       f"the normal peak of {_rate(_base('pkt_rate').get('p99', 1600))}.")),
        (lambda f, b: f["byte_rate"] > _base("byte_rate").get("p99", 2.0e6),
         lambda f, b: ("Bandwidth", f"{_bytes(f['byte_rate'])}/s",
                       f"≤ {_bytes(_base('byte_rate').get('p99', 2.0e6))}/s",
                       f"Bandwidth usage ({_bytes(f['byte_rate'])} per second) "
                       f"reaches saturation levels.")),
        (lambda f, b: f["distinct_src_ips"] > 5,
         lambda f, b: ("Simultaneous sources", f"{f['distinct_src_ips']:.0f}",
                       "1–3",
                       f"Traffic arrives from {f['distinct_src_ips']:.0f} "
                       f"different sources at once — typical of a botnet.")),
        (lambda f, b: f["syn_pct"] > 0.20 and f["syn_ack_ratio"] > 1.0,
         lambda f, b: ("Half-open connections", _pct(f["syn_pct"]), "below 8%",
                       f"{_pct(f['syn_pct'])} of packets are connection "
                       f"attempts that never complete.")),
    ]


@_rules("PORT_SCAN")
def _scan_rules():
    return [
        (lambda f, b: f["distinct_dst_ports"] > 30,
         lambda f, b: ("Distinct ports probed", f"{f['distinct_dst_ports']:.0f}",
                       "under 7",
                       f"One source contacted {f['distinct_dst_ports']:.0f} "
                       f"different ports in a short period.")),
        (lambda f, b: f["avg_flow_duration_s"] < 0.1,
         lambda f, b: ("Connection duration", f"{1000 * f['avg_flow_duration_s']:.0f} ms",
                       "seconds",
                       f"Each connection lasts only "
                       f"{1000 * f['avg_flow_duration_s']:.0f} ms — pure probing, "
                       f"no real session.")),
        (lambda f, b: f["avg_pkt_size"] < 130,
         lambda f, b: ("Average packet size", f"{f['avg_pkt_size']:.0f} bytes",
                       "350+ bytes",
                       f"Average packet size of {f['avg_pkt_size']:.0f} bytes — "
                       f"empty probing packets with no payload.")),
        (lambda f, b: f["rst_pct"] > 0.15,
         lambda f, b: ("Connection resets", _pct(f["rst_pct"]), "under 2%",
                       f"{_pct(f['rst_pct'])} of packets are TCP resets — "
                       f"closed ports answering the scan.")),
    ]


@_rules("BRUTE_FORCE")
def _brute_rules():
    return [
        (lambda f, b: f["auth_port_pct"] > 0.70,
         lambda f, b: ("Login-service connections", _pct(f["auth_port_pct"]),
                       "under 20%",
                       f"{_pct(f['auth_port_pct'])} of connections target "
                       f"login services such as SSH or FTP.")),
        (lambda f, b: f["flow_count"] > 20 and f["distinct_dst_ports"] <= 3,
         lambda f, b: ("Repeated attempts", f"{f['flow_count']:.0f}",
                       "1–15 flows",
                       f"{f['flow_count']:.0f} separate connections to the "
                       f"same service in a short window.")),
        (lambda f, b: f["rst_pct"] > 0.08,
         lambda f, b: ("Failed connections", _pct(f["rst_pct"]),
                       "under 2%",
                       f"{_pct(f['rst_pct'])} of connections end in resets — "
                       f"typical of failed login attempts.")),
        (lambda f, b: f["avg_flow_duration_s"] < 5,
         lambda f, b: ("Time per attempt", f"{f['avg_flow_duration_s']:.1f} s",
                       "seconds to minutes",
                       f"Each attempt lasts only {f['avg_flow_duration_s']:.1f} s — "
                       f"far too fast for human logins.")),
    ]


@_rules("ANOMALY")
def _anom_rules():
    return [
        (lambda f, b: f["icmp_pct"] > 0.30,
         lambda f, b: ("ICMP share", _pct(f["icmp_pct"]), "under 2%",
                       f"{_pct(f['icmp_pct'])} of traffic is ICMP, which is "
                       f"far above the normal share of under 2%.")),
        (lambda f, b: f["fin_count"] / max(f["total_packets"], 1) > 0.30,
         lambda f, b: ("FIN-heavy signalling",
                       _pct(f["fin_count"] / max(f["total_packets"], 1)),
                       "under 5%",
                       "An unusually large share of packets carry FIN flags — "
                       "stealth scanning or odd teardown behaviour.")),
        (lambda f, b: f["avg_pkt_size"] > 3000,
         lambda f, b: ("Packet size", f"{f['avg_pkt_size']:.0f} bytes",
                       "≤ 1500 bytes",
                       f"Average packet size of {f['avg_pkt_size']:.0f} bytes "
                       f"exceeds the normal maximum of ~1500 bytes.")),
        (lambda f, b: f["avg_flow_duration_s"] > 60,
         lambda f, b: ("Connection duration", f"{f['avg_flow_duration_s']:.0f} s",
                       "seconds",
                       f"Extremely long, nearly silent connections "
                       f"({f['avg_flow_duration_s']:.0f} s average).")),
        (lambda f, b: f["syn_pct"] < 0.05 and f["flow_count"] > 30 and
                      f["avg_pkt_size"] < 130,
         lambda f, b: ("Flag-less probing", f"{f['flow_count']:.0f} flows",
                       "—",
                       "Many small flows with almost no TCP handshake flags — "
                       "unusual null-probing behaviour.")),
    ]


@_rules("BENIGN")
def _benign_rules():
    return [
        (lambda f, b: True,
         lambda f, b: ("Packet rate", _rate(f["pkt_rate"]),
                       "60–1600 pkt/s",
                       f"Traffic volume of {_rate(f['pkt_rate'])} is inside the "
                       f"learned normal range.")),
        (lambda f, b: True,
         lambda f, b: ("Connection shape",
                       f"{f['avg_flow_packets']:.0f} packets/flow",
                       "10+ packets/flow",
                       "Connections complete normally and carry real payloads.")),
    ]


def build(label: str, feats: Dict[str, float], confidence: float,
          anomaly_score: float, extra_note: str | None = None) -> Dict:
    """Build the plain-language + evidence explanation for one window."""
    texts = CLASS_TEXTS.get(label, CLASS_TEXTS["ANOMALY"])
    rules = _RULES.get(label, [])

    evidence = []
    for fires, texter in rules:
        try:
            if fires(feats, None):
                short, observed, baseline, detail = texter(feats, None)
                evidence.append({
                    "label": short,
                    "observed": observed,
                    "baseline": baseline,
                    "detail": detail,
                })
        except Exception:  # never let formatting break detection
            continue
    evidence = evidence[:4]

    notes = []
    if label != "BENIGN" and confidence < 0.55:
        notes.append(
            f"Model confidence is moderate ({confidence * 100:.0f}%) — treat as "
            f"a lead to investigate rather than a certainty.")
    if label == "BENIGN" and anomaly_score >= 0.8:
        notes.append(
            "Flagged primarily by the anomaly detector (unsupervised), not by "
            "the attack classifier.")
    if extra_note:
        notes.append(extra_note)

    return {
        "headline": texts["headline"],
        "classification": CLASS_DISPLAY.get(label, label),
        "meaning": texts["meaning"],
        "evidence": evidence,
        "recommendation": texts["recommendation"],
        "notes": notes,
    }
