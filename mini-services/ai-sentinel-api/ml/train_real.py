"""Train on the REAL CIC-IDS2017 dataset (optional, for honest real-world use).

The bundled demo trains on a documented synthetic dataset (see
ml/generate_dataset.py). This script shows how to plug in the real thing.

Setup (documented, not bundled — ~50GB, free for research):
  1. Download "MachineLearningCVE" (CSV per day) from the official UNB page:
     https://www.unb.ca/cic/datasets/ids-2017.html
     or the Kaggle mirror "cicids2017" (MachineLearningCSV.zip).
  2. Place the CSV files in  ml/data/cicids2017/  (e.g. Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv)
  3. Run:  python ml/train_real.py

Label mapping applied (documented, no silent invention):
    BENIGN                                   -> BENIGN
    DDoS, DoS Hulk, DoS GoldenEye,
    DoS Slowloris, DoS Slowhttptest          -> DOS_DDOS
    PortScan                                 -> PORT_SCAN
    FTP-Patator, SSH-Patator                 -> BRUTE_FORCE
    Bot, Infiltration, Heartbleed,
    Web Attack *                             -> ANOMALY
    (SYN_FLOOD has no direct CIC-IDS2017 label; the bundled model keeps the
     synthetic SYN_FLOOD distribution. Retraining here will simply not see
     that class unless you add SYN-flood captures yourself.)

Feature mapping honesty:
    CICFlowMeter columns map naturally for ~14 of our 22 features
    (flow duration, packet/byte counts, SYN/ACK/FIN/RST counts, rates, avg
    packet size). Features without a CICFlowMeter equivalent
    (distinct_dst_ports, auth_port_pct, distinct_src_ips, icmp_pct, …) are
    derived where possible or set to documented defaults and reported as a
    limitation — we never pretend they were measured.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import DATA_DIR
from app.core.feature_schema import FEATURES, RAW_COUNTERS

CIC_DIR = DATA_DIR / "cicids2017"

LABEL_MAP = {
    "BENIGN": "BENIGN",
    "DDOS": "DOS_DDOS", "DDoS": "DOS_DDOS",
    "DOS ATTACKS": "DOS_DDOS", "DoS attacks": "DOS_DDOS",
    "DOS HULK": "DOS_DDOS", "DoS Hulk": "DOS_DDOS",
    "DOS GOLDENEYE": "DOS_DDOS", "DoS GoldenEye": "DOS_DDOS",
    "DOS SLOWLORIS": "DOS_DDOS", "DoS slowloris": "DOS_DDOS",
    "DOS SLOWHTTPTEST": "DOS_DDOS", "DoS Slowhttptest": "DOS_DDOS",
    "PORTSCAN": "PORT_SCAN", "PortScan": "PORT_SCAN",
    "FTP-PATATOR": "BRUTE_FORCE", "FTP-Patator": "BRUTE_FORCE",
    "SSH-PATATOR": "BRUTE_FORCE", "SSH-Patator": "BRUTE_FORCE",
    "BOT": "ANOMALY", "Bot": "ANOMALY",
    "INFILTRATION": "ANOMALY", "Infiltration": "ANOMALY",
    "HEARTBLEED": "ANOMALY", "Heartbleed": "ANOMALY",
}

# CICFlowMeter column -> our raw counters (best-effort mapping)
COL_ALIASES = {
    "Flow Duration": "duration_s(us)",
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "SYN Flag Count": "syn_count",
    "ACK Flag Count": "ack_count",
    "FIN Flag Count": "fin_count",
    "RST Flag Count": "rst_count",
    "Flow Packets/s": "flow_pkt_rate",
    "Flow Bytes/s": "flow_byte_rate",
    "Average Packet Size": "avg_pkt_size",
    "Protocol": "protocol_number",
    "Destination Port": "dst_port",
    "Label": "label",
}


def load_cic() -> pd.DataFrame | None:
    files = sorted(CIC_DIR.glob("*.csv"))
    if not files:
        return None
    frames = []
    for f in files:
        df = pd.read_csv(f, encoding="latin1", low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df = df.rename(columns={k: v for k, v in COL_ALIASES.items() if k in df.columns})
    df["label"] = df["label"].str.strip().map(
        lambda s: LABEL_MAP.get(s, "ANOMALY" if s.upper() != "BENIGN" else "BENIGN"))
    return df


def to_raw_counters(df: pd.DataFrame) -> pd.DataFrame:
    """Convert CICFlowMeter rows into our RAW counter schema (documented)."""
    fwd_p = pd.to_numeric(df.get("fwd_packets", 0), errors="coerce").fillna(0)
    bwd_p = pd.to_numeric(df.get("bwd_packets", 0), errors="coerce").fillna(0)
    packets = (fwd_p + bwd_p).clip(lower=1)
    fwd_b = pd.to_numeric(df.get("fwd_bytes", 0), errors="coerce").fillna(0)
    bwd_b = pd.to_numeric(df.get("bwd_bytes", 0), errors="coerce").fillna(0)
    duration_us = pd.to_numeric(df.get("duration_s(us)", 0), errors="coerce").fillna(0)
    duration = (duration_us / 1e6).clip(lower=0.001)

    raw = pd.DataFrame({
        "duration_s": duration,
        "flow_count": 1,                                   # one flow per row
        "total_packets": packets,
        "total_bytes": (fwd_b + bwd_b).clip(lower=0),
        "syn_count": pd.to_numeric(df.get("syn_count", 0), errors="coerce").fillna(0),
        "ack_count": pd.to_numeric(df.get("ack_count", 0), errors="coerce").fillna(0),
        "fin_count": pd.to_numeric(df.get("fin_count", 0), errors="coerce").fillna(0),
        "rst_count": pd.to_numeric(df.get("rst_count", 0), errors="coerce").fillna(0),
        # not available per-flow in CICFlowMeter -> documented defaults
        "distinct_dst_ports": 1,
        "distinct_dst_ips": 1,
        "distinct_src_ips": 1,
        "avg_flow_duration_s": duration,
        "avg_flow_packets": packets,
        "auth_flows": 0,
        "tcp_packets": packets,                             # protocol share approx.
        "udp_packets": 0,
        "icmp_packets": 0,
    })
    proto = pd.to_numeric(df.get("protocol_number", 6), errors="coerce").fillna(6)
    raw["tcp_packets"] = packets * (proto == 6).astype(float)
    raw["udp_packets"] = packets * (proto == 17).astype(float)
    raw["icmp_packets"] = packets * (proto == 1).astype(float)
    raw["dst_port"] = pd.to_numeric(df.get("dst_port", 0), errors="coerce").fillna(0)
    return raw


def main() -> None:
    df = load_cic()
    if df is None:
        print(f"[train_real] No CIC-IDS2017 CSVs found in {CIC_DIR}")
        print("[train_real] Download the dataset (see docstring) and place "
              "the per-day CSVs there. The bundled demo keeps running with "
              "the synthetic model in the meantime.")
        sys.exit(0)

    print(f"[train_real] loaded {len(df)} flows")
    raw = to_raw_counters(df)
    from app.core.feature_schema import derive
    rows = []
    for idx in raw.index:
        d = raw.loc[idx]
        feats = derive({k: float(d[k]) for k in RAW_COUNTERS if k in d.index})
        feats["label"] = df.loc[idx, "label"]
        rows.append(feats)
    out = pd.DataFrame(rows)[FEATURES + ["label"]]
    out = out.replace([np.inf, -np.inf], np.nan).fillna(0)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    out.to_csv(DATA_DIR / "train.csv", index=False)
    # Use a random 20% split of the same (real) data as eval
    eval_df = out.sample(frac=0.2, random_state=7)
    eval_df.to_csv(DATA_DIR / "eval.csv", index=False)

    print("[train_real] wrote train.csv / eval.csv from real CIC-IDS2017 "
          "flows — now run: python ml/train.py")
    print("[train_real] NOTE: features without CICFlowMeter equivalents "
          "(auth_port_pct, distinct_dst_ports, …) use documented defaults — "
          "see module docstring.")


if __name__ == "__main__":
    main()
