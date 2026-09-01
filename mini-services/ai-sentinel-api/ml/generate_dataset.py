"""Generate the AI Sentinel training dataset (SYNTHETIC — documented & honest).

WHY SYNTHETIC?
==============
The full CIC-IDS2017 dataset is ~50 GB and cannot be bundled with a
hackathon prototype. Instead we generate a deterministic dataset of
traffic-window features whose per-class statistical distributions are
modeled on the publicly documented behaviour of those attacks:

  BENIGN       — completed handshakes, payload-carrying packets, few ports
  DOS/DDOS     — very high packet/byte rate, degraded completion, many sources
  PORT_SCAN    — hundreds of distinct ports, tiny flows, RST-heavy
  SYN_FLOOD    — SYN-dominated, almost no ACKs, single port, huge flow churn
  BRUTE_FORCE  — repeated short connections to login ports (SSH/FTP), RSTs
  ANOMALY      — unusual-but-valid combinations (FIN sweeps, ICMP floods,
                 jumbo packets, long silent connections)

Every metric reported by the application is MEASURED on held-out samples of
THIS synthetic distribution, and the UI states this openly. To train on the
real CIC-IDS2017 dataset instead, see ml/train_real.py and the README.

Usage:
    python ml/generate_dataset.py [--samples-per-class 600]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.feature_schema import FEATURES, CLASSES, derive  # noqa: E402

PER_CLASS_DEFAULT = 600
SEED_TRAIN = 42
SEED_EVAL = 1337


# ---------------------------------------------------------------- helpers
def _lognormal(rng: np.random.Generator, median: float, sigma: float,
               lo: float, hi: float) -> float:
    return float(np.clip(rng.lognormal(np.log(median), sigma), lo, hi))


def _finish(duration: float, pkt_rate: float, avg_pkt: float, flows: int,
            syn: int, ack: int, fin: int, rst: int, dports: int, dips: int,
            sips: int, avg_flow_dur: float, auth_pct: float,
            tcp_pct: float, icmp_pct: float) -> Dict[str, float]:
    """Assemble raw counters from semantic aggregates (single place)."""
    packets = max(int(pkt_rate * duration), max(flows, 1), syn + ack + 1)
    bytes_ = int(packets * avg_pkt)
    udp_pct = max(0.0, 1.0 - tcp_pct - icmp_pct)
    return {
        "duration_s": round(float(duration), 3),
        "flow_count": int(flows),
        "total_packets": packets,
        "total_bytes": bytes_,
        "syn_count": int(min(syn, packets)),
        "ack_count": int(min(ack, packets)),
        "fin_count": int(min(fin, packets)),
        "rst_count": int(min(rst, packets)),
        "distinct_dst_ports": int(dports),
        "distinct_dst_ips": int(dips),
        "distinct_src_ips": int(sips),
        "avg_flow_duration_s": round(float(avg_flow_dur), 4),
        "avg_flow_packets": round(packets / max(flows, 1), 2),
        "auth_flows": int(flows * auth_pct),
        "tcp_packets": int(packets * tcp_pct),
        "udp_packets": int(packets * udp_pct),
        "icmp_packets": int(packets * icmp_pct),
    }


# ---------------------------------------------------------------- samplers
def sample_benign(rng: np.random.Generator) -> Dict[str, float]:
    """Realistic benign traffic per host pair — three user profiles.

    Covers the real variety of benign windows so the anomaly detector
    does not flag ordinary short captures:
      0: short browsing burst  (3-12 s, 60-500 pkt/s, bursty 0.05-1.5 s flows)
      1: steady transfer       (15-60 s, 400-1500 pkt/s, payload-heavy)
      2: background chatter    (8-40 s, 80-600 pkt/s, mixed)
    """
    profile = int(rng.integers(0, 3))
    if profile == 0:
        duration = rng.uniform(3, 12)
        pkt_rate = rng.uniform(60, 500)
        flows = int(rng.integers(3, 15))
        avg_pkt = rng.uniform(150, 800)
        avg_flow_dur = rng.uniform(0.05, 1.5)
    elif profile == 1:
        duration = rng.uniform(15, 60)
        pkt_rate = rng.uniform(400, 1500)
        flows = int(rng.integers(2, 8))
        avg_pkt = rng.uniform(400, 900)
        avg_flow_dur = rng.uniform(1, 6)
    else:
        duration = rng.uniform(8, 40)
        pkt_rate = rng.uniform(80, 600)
        flows = int(rng.integers(2, 12))
        avg_pkt = rng.uniform(150, 700)
        avg_flow_dur = rng.uniform(0.3, 5)

    packets = pkt_rate * duration
    syn = flows * rng.uniform(1.8, 2.6)          # SYN + SYN-ACK per flow
    ack = packets * rng.uniform(0.55, 0.95)      # data/keepalive/pure ACKs
    fin = flows * rng.uniform(1.0, 2.5)
    rst = int(rng.choice([0, 0, 0, 1])) * int(rng.integers(1, 4))
    auth_pct = float(rng.choice([0.0, 0.0, 0.0, 0.0,
                                 rng.uniform(0.05, 0.20)]))
    return _finish(
        duration=duration, pkt_rate=pkt_rate,
        avg_pkt=avg_pkt, flows=flows,
        syn=syn, ack=ack, fin=fin, rst=rst,
        dports=int(rng.integers(1, 7)), dips=int(rng.integers(1, 4)),
        sips=int(rng.choice([1, 1, 2])),
        avg_flow_dur=avg_flow_dur, auth_pct=auth_pct,
        tcp_pct=rng.uniform(0.80, 1.0), icmp_pct=rng.uniform(0, 0.02),
    )


def sample_dos_ddos(rng: np.random.Generator) -> Dict[str, float]:
    duration = rng.uniform(10, 60)
    pkt_rate = _lognormal(rng, 7000, 0.65, 1200, 60000)
    volumetric = rng.random() < 0.55                # payload flood vs. small pkt flood
    avg_pkt = rng.uniform(450, 1400) if volumetric else rng.uniform(60, 260)
    avg_flow_pkts = rng.uniform(15, 120) if volumetric else rng.uniform(1.2, 6)
    syn_pct = rng.uniform(0.08, 0.50)
    packets = pkt_rate * duration
    syn = packets * syn_pct
    ack = packets * rng.uniform(0.05, 0.30)
    rst = packets * rng.uniform(0.05, 0.40) if rng.random() < 0.30 else 0
    flows = int(packets / avg_flow_pkts)
    multi_source = rng.random() < 0.50              # DDoS (botnet) vs. single DoS
    return _finish(
        duration=duration, pkt_rate=pkt_rate, avg_pkt=avg_pkt, flows=flows,
        syn=syn, ack=ack, fin=packets * rng.uniform(0, 0.04), rst=rst,
        dports=int(rng.integers(1, 6)), dips=1,
        sips=int(rng.integers(5, 60)) if multi_source else 1,
        avg_flow_dur=rng.uniform(0.05, 4), auth_pct=0.0,
        tcp_pct=rng.uniform(0.9, 1.0), icmp_pct=0.0,
    )


def sample_port_scan(rng: np.random.Generator) -> Dict[str, float]:
    duration = rng.uniform(4, 40)
    ports = int(rng.integers(60, 1200))
    retries = rng.uniform(1.0, 1.3)
    flows = int(ports * retries)
    avg_flow_pkts = rng.uniform(1.05, 2.6)          # SYN [SYN-ACK/RST] [RST]
    packets = flows * avg_flow_pkts
    pkt_rate = packets / duration
    syn = packets * rng.uniform(0.45, 0.90)
    ack = packets * rng.uniform(0.05, 0.25)         # SYN-ACKs from open ports
    rst = packets * rng.uniform(0.10, 0.55)         # closed-port RSTs
    return _finish(
        duration=duration, pkt_rate=pkt_rate, avg_pkt=rng.uniform(44, 90),
        flows=flows, syn=syn, ack=ack, fin=0, rst=rst,
        dports=ports, dips=1, sips=1,
        avg_flow_dur=rng.uniform(0.002, 0.05),
        auth_pct=rng.uniform(0.02, 0.12),
        tcp_pct=rng.uniform(0.95, 1.0), icmp_pct=0.0,
    )


def sample_syn_flood(rng: np.random.Generator) -> Dict[str, float]:
    duration = rng.uniform(5, 30)
    pkt_rate = _lognormal(rng, 14000, 0.55, 2500, 80000)
    packets = pkt_rate * duration
    syn = packets * rng.uniform(0.50, 0.90)         # attacker SYNs + victim SYN-ACKs
    # victim replies with SYN-ACK (has ACK bit) to only a fraction of SYNs;
    # as the backlog overflows, completion collapses -> syn_ack_ratio explodes
    response_share = rng.uniform(0.02, 0.30)
    ack = packets * response_share
    avg_flow_pkts = rng.uniform(1.05, 1.5)          # half-open: 1-2 packets per flow
    flows = int(packets / avg_flow_pkts)
    spoofed = rng.random() < 0.35
    return _finish(
        duration=duration, pkt_rate=pkt_rate, avg_pkt=rng.uniform(42, 80),
        flows=flows, syn=syn, ack=ack, fin=0,
        rst=packets * rng.uniform(0, 0.08),
        dports=int(rng.integers(1, 4)), dips=1,
        sips=int(rng.integers(3, 200)) if spoofed else 1,
        avg_flow_dur=rng.uniform(0.001, 0.01), auth_pct=0.0,
        tcp_pct=1.0, icmp_pct=0.0,
    )


def sample_brute_force(rng: np.random.Generator) -> Dict[str, float]:
    duration = rng.uniform(10, 90)
    attempts = int(rng.integers(25, 500))
    avg_flow_pkts = rng.uniform(4, 18)              # handshake + banner + fail
    packets = attempts * avg_flow_pkts
    pkt_rate = packets / duration
    syn = packets * rng.uniform(0.12, 0.35)
    ack = packets * rng.uniform(0.30, 0.60)
    rst = packets * rng.uniform(0.08, 0.40)         # server resets after failures
    return _finish(
        duration=duration, pkt_rate=pkt_rate, avg_pkt=rng.uniform(70, 260),
        flows=attempts, syn=syn, ack=ack,
        fin=packets * rng.uniform(0.02, 0.15), rst=rst,
        dports=int(rng.integers(1, 4)), dips=1, sips=1,
        avg_flow_dur=rng.uniform(0.08, 2.5),
        auth_pct=rng.uniform(0.85, 1.0),
        tcp_pct=1.0, icmp_pct=0.0,
    )


def sample_anomaly(rng: np.random.Generator) -> Dict[str, float]:
    mode = int(rng.integers(0, 4))
    if mode == 0:  # FIN sweep (stealth scan, no SYN)
        duration = rng.uniform(5, 40)
        ports = int(rng.integers(50, 800))
        flows = ports
        avg_flow_pkts = rng.uniform(1.0, 1.5)
        packets = flows * avg_flow_pkts
        return _finish(
            duration=duration, pkt_rate=packets / duration,
            avg_pkt=rng.uniform(40, 90), flows=flows,
            syn=packets * rng.uniform(0, 0.05),
            ack=packets * rng.uniform(0.1, 0.4),
            fin=packets * rng.uniform(0.50, 0.85), rst=0,
            dports=ports, dips=1, sips=1,
            avg_flow_dur=rng.uniform(0.001, 0.03), auth_pct=0.0,
            tcp_pct=1.0, icmp_pct=0.0,
        )
    if mode == 1:  # ICMP-heavy flood
        duration = rng.uniform(5, 30)
        pkt_rate = rng.uniform(200, 8000)
        icmp_pct = rng.uniform(0.45, 0.90)
        packets = pkt_rate * duration
        return _finish(
            duration=duration, pkt_rate=pkt_rate, avg_pkt=rng.uniform(64, 140),
            flows=int(rng.integers(5, 60)),
            syn=packets * rng.uniform(0, 0.05), ack=0, fin=0,
            rst=packets * rng.uniform(0, 0.05),
            dports=int(rng.integers(1, 5)), dips=int(rng.integers(1, 4)), sips=1,
            avg_flow_dur=rng.uniform(0.01, 0.5), auth_pct=0.0,
            tcp_pct=1.0 - icmp_pct, icmp_pct=icmp_pct,
        )
    if mode == 2:  # long silent connections
        duration = rng.uniform(60, 300)
        flows = int(rng.integers(1, 5))
        packets = int(rng.integers(2, 20))
        return _finish(
            duration=duration, pkt_rate=packets / duration,
            avg_pkt=rng.uniform(40, 80), flows=flows,
            syn=flows, ack=packets * 0.5, fin=flows, rst=0,
            dports=flows, dips=1, sips=1,
            avg_flow_dur=duration * 0.8, auth_pct=0.0,
            tcp_pct=1.0, icmp_pct=0.0,
        )
    # mode 3: jumbo-packet oddity toward login service
    duration = rng.uniform(10, 60)
    pkt_rate = rng.uniform(50, 400)
    packets = pkt_rate * duration
    flows = int(rng.integers(20, 200))
    return _finish(
        duration=duration, pkt_rate=pkt_rate, avg_pkt=rng.uniform(4000, 9500),
        flows=flows,
        syn=packets * rng.uniform(0.30, 0.50), ack=packets * rng.uniform(0.2, 0.5),
        fin=0, rst=0,
        dports=1, dips=1, sips=1,
        avg_flow_dur=rng.uniform(0.05, 0.5), auth_pct=1.0,
        tcp_pct=1.0, icmp_pct=0.0,
    )


SAMPLERS = {
    "BENIGN": sample_benign,
    "DOS_DDOS": sample_dos_ddos,
    "PORT_SCAN": sample_port_scan,
    "SYN_FLOOD": sample_syn_flood,
    "BRUTE_FORCE": sample_brute_force,
    "ANOMALY": sample_anomaly,
}


def generate(samples_per_class: int, seed: int) -> list:
    rng = np.random.default_rng(seed)
    rows = []
    for label in CLASSES:
        for _ in range(samples_per_class):
            raw = SAMPLERS[label](rng)
            feats = derive(raw)
            feats["label"] = label
            rows.append(feats)
    rng.shuffle(rows)
    return rows


def write_csv(rows: list, path: Path) -> None:
    import csv
    cols = FEATURES + ["label"]
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples-per-class", type=int, default=PER_CLASS_DEFAULT)
    args = ap.parse_args()

    data_dir = Path(__file__).resolve().parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    n = args.samples_per_class
    train_rows = generate(n, SEED_TRAIN)
    eval_rows = generate(n, SEED_EVAL)   # fresh samples, different seed

    write_csv(train_rows, data_dir / "train.csv")
    write_csv(eval_rows, data_dir / "eval.csv")

    print(f"[dataset] wrote {len(train_rows)} train rows -> {data_dir/'train.csv'}")
    print(f"[dataset] wrote {len(eval_rows)} eval rows  -> {data_dir/'eval.csv'}")
    print(f"[dataset] classes: {CLASSES}")
    print("[dataset] NOTE: synthetic distribution modelled on CIC-IDS2017 "
          "attack characteristics (documented in README).")


if __name__ == "__main__":
    main()
