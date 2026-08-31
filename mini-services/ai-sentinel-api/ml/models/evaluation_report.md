# AI Sentinel — Model Evaluation Report

* Model: RandomForestClassifier (v1.0)
* Evaluated on 3600 held-out windows (generator seed 1337, disjoint from training seed 42)
* Dataset: **synthetic, documented distributions** — metrics reflect synthetic separability, not real-world generalization

| Metric | Value |
|---|---|
| Accuracy | 1.0000 |
| Precision (macro) | 1.0000 |
| Recall (macro) | 1.0000 |
| F1 (macro) | 1.0000 |
| Mean confidence | 0.9979 |

## Per-class metrics

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| ANOMALY | 1.000 | 1.000 | 1.000 | 600 |
| BENIGN | 1.000 | 1.000 | 1.000 | 600 |
| BRUTE_FORCE | 1.000 | 1.000 | 1.000 | 600 |
| DOS_DDOS | 1.000 | 1.000 | 1.000 | 600 |
| PORT_SCAN | 1.000 | 1.000 | 1.000 | 600 |
| SYN_FLOOD | 1.000 | 1.000 | 1.000 | 600 |

## Confusion matrix (rows = true, cols = predicted)

| true\pred | ANOMALY | BENIGN | BRUTE_FORCE | DOS_DDOS | PORT_SCAN | SYN_FLOOD |
|---|---|---|---|---|---|---|
| ANOMALY | 600 | 0 | 0 | 0 | 0 | 0 |
| BENIGN | 0 | 600 | 0 | 0 | 0 | 0 |
| BRUTE_FORCE | 0 | 0 | 600 | 0 | 0 | 0 |
| DOS_DDOS | 0 | 0 | 0 | 600 | 0 | 0 |
| PORT_SCAN | 0 | 0 | 0 | 0 | 600 | 0 |
| SYN_FLOOD | 0 | 0 | 0 | 0 | 0 | 600 |

## IsolationForest anomaly score by true class

| Class | mean raw score (higher = more anomalous) |
|---|---|
| ANOMALY | 0.1613 |
| BENIGN | -0.0368 |
| BRUTE_FORCE | 0.2209 |
| DOS_DDOS | 0.1835 |
| PORT_SCAN | 0.2145 |
| SYN_FLOOD | 0.2019 |

## Top-10 feature importances (RandomForest)

| Feature | Importance |
|---|---|
| syn_pct | 0.1082 |
| syn_ack_ratio | 0.0895 |
| syn_count | 0.0878 |
| rst_pct | 0.0831 |
| avg_flow_duration_s | 0.0723 |
| flow_count | 0.0690 |
| tcp_pct | 0.0673 |
| fin_count | 0.0637 |
| ack_count | 0.0541 |
| auth_port_pct | 0.0538 |

## Honest interpretation

- These numbers are REAL measurements on the bundled synthetic evaluation set (fresh samples, seed 1337, never used in training).
- They are high because the synthetic class distributions are separable by design. This is a property of the demo dataset, and we state it openly.
- For real-world performance, retrain with real captures using `ml/train_real.py` (CIC-IDS2017) — expect lower, more sober numbers.
