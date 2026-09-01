# AI Sentinel — AI-Powered Network Intrusion Detection System

**Educational hackathon prototype.** ML-based network threat detection with a
live SOC dashboard, safe attack simulations, and offline PCAP analysis.

> ⚠️ **Safety statement:** All traffic in this demo is **synthetic** or read
> from **offline PCAP files you supply**. No real networks are attacked, no
> attack tools are executed, and "Block Source" is a UI simulation only.

---

## 1. Project overview

AI Sentinel watches a stream of network-traffic windows and answers four
questions in real time:

1. **Is this traffic an attack?** → RandomForest classifier (6 classes)
2. **Is it unusual even if not a known attack?** → IsolationForest anomaly detector
3. **How bad is it?** → deterministic, documented 0–100 risk score + severity band
4. **Why?** → explanations citing the *actual observed feature values* vs. baseline

Every decision is made **server-side in Python**. The frontend renders
results — it never decides attack types.

### Detection classes
`BENIGN` · `DOS_DDOS` · `PORT_SCAN` · `SYN_FLOOD` · `BRUTE_FORCE` · `ANOMALY`

---

## 2. Architecture

```
INPUT                → Traffic window (synthetic / simulation / PCAP)
Feature extraction   → canonical 22-feature schema (app/core/feature_schema.py)
Preprocessing        → NaN/Inf sanitization, sanity clipping
RandomForest         → 6-class prediction + per-class probabilities
IsolationForest      → 0–1 anomaly score (benign-calibrated)
Risk engine          → 0–100 score → LOW / MEDIUM / HIGH / CRITICAL
Explanation engine   → evidence from real observed values vs baseline
FastAPI + WebSocket  → traffic_update / threat_detected / alert / mitigation
SOC dashboard        → live charts, escalating alerts, threat detail, actions
```

The **same canonical feature schema** is used for training data, simulations
and PCAP analysis — this is the core consistency guarantee of the project.

## 3. Features

- SOC dashboard: status, live traffic chart, threat timeline, threat detail
- Security Test Lab: 5 safe synthetic scenarios with escalating intensity
- Real-time WebSocket events with REST polling fallback
- PCAP/PCAPNG upload & bundled synthetic samples (offline, read-only)
- Model card with **real measured metrics** and honest dataset notes
- Alert history persisted in SQLite; resolve / simulate-block actions
- Dual-language UX: plain English first, technical details on demand

## 4. Technologies

| Layer | Tech |
|---|---|
| Frontend | React 19 / Next.js 16 (App Router), TypeScript, Tailwind 4, shadcn/ui, recharts, zustand, framer-motion |
| Backend | Python 3.12, FastAPI, uvicorn, Pydantic, native WebSockets |
| ML | scikit-learn (RandomForestClassifier + IsolationForest), pandas, numpy, joblib |
| PCAP | scapy (offline parsing; sample generator) |
| State | SQLite (events), in-memory (live traffic, blocks) |

## 5. Folder structure

```
my-project/
├── src/                                  # FRONTEND (Next.js — single "/" route)
│   ├── app/page.tsx                      # entry → SentinelApp
│   ├── components/sentinel/              # dashboard, test lab, pcap, model, alerts…
│   ├── hooks/use-sentinel-websocket.ts   # WS + reconnect + polling fallback
│   └── lib/sentinel/                     # types (API/WS contracts), api client, store
├── mini-services/ai-sentinel-api/        # BACKEND + ML (independent service, port 8000)
│   ├── index.js                          # service entry (spawns uvicorn --reload)
│   ├── package.json                      # `bun run dev` / `npm run dev`
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py                       # FastAPI + WebSocket (/ and /ws)
│   │   ├── config.py
│   │   ├── api/routes.py                 # all REST endpoints
│   │   ├── core/                         # feature_schema, pipeline, risk_engine,
│   │   │                                 # explanation, anomaly, model_registry, preprocess
│   │   ├── simulation/                   # generators (5 scenarios) + service
│   │   ├── pcap/                         # scapy parser + samples
│   │   └── services/                     # events bus, store (SQLite), state, traffic, alerting
│   ├── ml/
│   │   ├── generate_dataset.py           # documented synthetic dataset
│   │   ├── train.py                      # RF + IsolationForest + model card
│   │   ├── evaluate.py                   # metrics report (ml/models/evaluation_report.md)
│   │   ├── train_real.py                 # train on real CIC-IDS2017 (optional)
│   │   ├── data/                         # generated CSVs
│   │   └── models/                       # joblib artifacts + metadata.json
│   ├── pcaps/samples/                    # 5 synthetic sample captures
│   ├── tools/generate_samples.py         # scapy sample generator
│   └── tests/test_pipeline.py            # pytest suite (13 tests)
├── scripts/                              # laptop run helpers (sh + bat)
├── Caddyfile                             # sandbox gateway (XTransformPort routing)
└── README.md
```

> **Why this shape?** The demo sandbox exposes one public port and routes to
> sidecar services via the gateway (`?XTransformPort=8000`). On your laptop
> the same code runs with the frontend on `:3000` talking directly to
uvicorn on `:8000` — see §7.

## 6. Installation (laptop)

**Prerequisites:** Python 3.10+, Node 18+ (or Bun), git.

```bash
# 1. backend + ML
cd mini-services/ai-sentinel-api
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt        # Windows: .venv\Scripts\pip
.venv/bin/python ml/train.py                     # trains + writes ml/models/
.venv/bin/python tools/generate_samples.py       # writes pcaps/samples/

# 2. frontend
cd ../..
npm install                                      # or: bun install
```

Or use the helpers: `scripts/setup_backend.sh|bat`, `scripts/run_backend.sh|bat`,
`scripts/run_frontend.sh|bat` (auto-detect bun/npm, venv/system python).

## 7. Running

**Backend** (port 8000) — ONE instance only (the wrapper refuses to start a
second one if the port is taken):
```bash
bash scripts/run_backend.sh                  # dev mode (auto-reload on .py changes)
bash scripts/run_backend.sh --no-reload      # PRESENTATION mode (stable, no reload)
# Windows: scripts\run_backend.bat  /  scripts\run_backend.bat no-reload
# or directly:
cd mini-services/ai-sentinel-api
.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
First boot auto-trains the model if artifacts are missing (~10 s).

**Frontend** (port 3000):
```bash
npm run dev                                       # or: bun run dev
# or: bash scripts/run_frontend.sh               (Windows: scripts\run_frontend.bat)
```

**Connecting the two — choose ONE:**

- *Sandbox/gateway mode (default):* frontend calls same-origin URLs with
  `?XTransformPort=8000` (Caddy routes them). Works out of the box here.
- *Laptop mode:* create `.env.local` in the repo root:
  ```
  NEXT_PUBLIC_API_BASE=http://localhost:8000
  ```
  Every REST call and the WebSocket then go straight to uvicorn.

API docs (backend): `http://localhost:8000/docs` (FastAPI Swagger UI).

## 8. ML model training

```bash
cd mini-services/ai-sentinel-api
.venv/bin/python ml/generate_dataset.py   # 3,600 train + 3,600 eval windows
.venv/bin/python ml/train.py              # RF + IsolationForest + model card
.venv/bin/python ml/evaluate.py           # writes ml/models/evaluation_report.md
.venv/bin/python -m pytest tests/ -q      # 13 tests incl. end-to-end WS flow
```

**Dataset honesty (read this before quoting numbers):** the bundled dataset is
*synthetic*, generated from documented per-class distributions modelled on
CIC-IDS2017 attack characteristics (see `ml/generate_dataset.py`). Metrics on
the held-out set are high **because the synthetic classes are separable by
design** — the UI says so openly. This is a demo property, not a real-world
claim. `ml/train_real.py` documents the exact label mapping
(DDoS/DoS\*→DOS_DDOS, PortScan→PORT_SCAN, \*-Patator→BRUTE_FORCE,
Bot/Infiltration/Heartbleed/Web\*→ANOMALY) and trains on real CSVs you place
in `ml/data/cicids2017/` — expect sober, realistic numbers there. SYN_FLOOD
has no direct CIC-IDS2017 label and stays synthetic-distribution-trained.

## 9. Safe simulation

Dashboard → **Security Test Lab** → pick a scenario → **Run Safe Test**.
What happens: the backend generates 10 escalating synthetic traffic windows
(benign background + attack component), each window flows through the full
pipeline, and results stream over WebSocket — traffic spikes on the chart,
alerts escalate (typically MEDIUM → HIGH → CRITICAL), the threat detail
panel opens automatically. ~13 s per scenario. No packet ever leaves the
process. Attack types: `syn_flood`, `dos_ddos`, `port_scan`, `brute_force`,
`anomaly`.

## 10. PCAP analysis

Dashboard → **PCAP Analysis**: upload `.pcap`/`.pcapng` (≤25 MB) or click a
bundled sample. The backend validates magic bytes, parses packets offline
(scapy), groups them into bidirectional flows, aggregates per host-pair into
the canonical schema, and classifies. Results: totals, attack types,
severity distribution, timeline, per-pair table, and **limitations stated
honestly** (headers-only parsing, heuristic login-failure inference, etc.).
Bundled samples are synthetic captures generated by `tools/generate_samples.py`.

## 11. API documentation

Base: `http://localhost:8000` (sandbox: same origin + `?XTransformPort=8000`).

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | backend + model status |
| GET | `/api/model-info` | model card: classes, features, metrics, risk formula, label mapping |
| GET | `/api/simulation/types` | scenario metadata (frontend renders this copy) |
| POST | `/api/simulation/{type}` | start safe simulation → 202 + sim_id |
| POST | `/api/analyze` | classify one full feature vector |
| POST | `/api/pcap/upload` | multipart pcap analysis |
| GET | `/api/pcap/samples` | bundled sample list |
| POST | `/api/pcap/samples/{name}/analyze` | analyze a bundled sample |
| GET | `/api/events?limit=100` | event history |
| GET | `/api/statistics` | dashboard aggregates + network status |
| POST | `/api/events/{id}/resolve` | mark RESOLVED |
| POST | `/api/events/{id}/simulate-mitigation` | simulated block + recovery |
| POST | `/api/reset` | reset demo state (events, alerts, blocks, sims) → WS `demo_reset` |

**WebSocket:** connect to `/` or `/ws` (sandbox: `ws://host/ws?XTransformPort=8000`).
Server pushes JSON messages:

```json
{"type": "traffic_update", "ts": 0, "prediction": "BENIGN", "risk": 12,
 "severity": "LOW", "pkt_rate": 421.0, "byte_rate": 180000.2, "flows": 6, ...}
{"type": "threat_detected", "ts": 0, "event_id": "…", "attack": "SYN_FLOOD",
 "confidence": 0.94, "risk": 91, "severity": "CRITICAL", "anomaly_score": 1.0,
 "source": "10.0.9.15", "target": "10.0.0.1:443",
 "explanation": {"headline": "…", "meaning": "…",
   "evidence": [{"label": "SYN packet share", "observed": "95%",
                 "baseline": "below 8%", "detail": "…"}],
   "recommendation": "…"}, "observed": {"pkt_rate": 29400.0, ...}}
{"type": "alert", "event_id": "…", "severity": "CRITICAL", "risk": 91,
 "message": "SYN Flood detected — risk 91/100"}
{"type": "mitigation", "event_id": "…", "action": "block_source",
 "before_pkt_rate": 734, "after_pkt_rate": 120, "status": "MITIGATED",
 "note": "Simulated block only — no real firewall or host was modified."}
{"type": "sim_started|sim_progress|sim_complete", "sim_id": "…", ...}
{"type": "demo_reset", "ts": 0, "message": "Demo state reset — events cleared, …"}
```

Example REST call:
```bash
curl -X POST "http://localhost:8000/api/simulation/syn_flood"
# → {"sim_id": "…", "attack_type": "syn_flood", "status": "started", ...}
```

## 12. Risk score & severity

Threat windows: `risk = 0.40·impact_eff + 0.25·anomaly·100 + 0.20·confidence·100
+ 0.15·deviation·100` where `impact_eff = class_impact × (0.30 + 0.70·strength)`
(strength = percentile of pkt_rate within that attack class's own training
distribution; deviation = percentile vs. the benign baseline).
Benign windows: `risk = 0.30·anomaly·100 + 0.10·deviation·100` (capped at 24).
Bands: 0–24 LOW, 25–49 MEDIUM, 50–74 HIGH, 75–100 CRITICAL. Class impacts:
SYN_FLOOD 90, DOS_DDOS 85, BRUTE_FORCE 72, ANOMALY 50, PORT_SCAN 45, BENIGN 2.
The full breakdown is visible per event in the UI.

## 13. Anomaly detection

IsolationForest trained on **benign windows only**. Raw scores are calibrated
against benign percentiles (p50/p95/p99 measured on a held-out benign set):
≤p50 → 0–0.2, p95 → 0.8, ≥p99 → 1.0. The score feeds the risk engine as the
anomaly term.

**Who assigns the ANOMALY class?** The RandomForest — `ANOMALY` is one of its
six trained classes, and that is the usual path (e.g. the "Network Anomaly"
scenario). Separately, a documented override in `app/core/pipeline.py` surfaces
a window as **ANOMALY (unknown behaviour)** when the RandomForest votes BENIGN
but the anomaly score is ≥ 0.90, with a note explaining the override. This is
how the system distinguishes *known attacks* from *unusual traffic it cannot
name*.

## 14. Testing

```bash
cd mini-services/ai-sentinel-api && .venv/bin/python -m pytest tests/ -q
# 13 tests: schema, preprocessing, severity bands, risk determinism,
# model classes, generator distinctness, end-to-end pipeline, pcap
# validation, API health/model-info/analyze, websocket + simulation flow
```

## 15. Deployment

- **Frontend:** any Node host (Vercel/Netlify/静态导出). Set
  `NEXT_PUBLIC_API_BASE=https://api.your-domain.example`.
- **Backend:** any Docker/VM host: `pip install -r requirements.txt`,
  `uvicorn app.main:app --host 0.0.0.0 --port 8000`, put TLS in front (Caddy/
  nginx). WebSocket works through standard reverse proxies.
- Keep model artifacts (`ml/models/`) with the backend image, or run
  `ml/train.py` at container start (auto-trains if missing).
- No secrets are required; everything is local. Do not expose the demo
  publicly without authentication.

## 16. Limitations (honest list)

- Trained on a synthetic distribution — real-world generalization is unproven.
- No live packet capture (would need a capture agent / NetFlow exporter).
- PCAP analysis is header-only; login failures are inferred from connection
  shapes; per-second timeline is approximated by flow start times.
- One feature window per host-pair (no sliding windows per conversation).
- Explanation rules are per-class templates filled with real observed values
  (SHAP-style per-prediction attribution is future work).
- No auth/RBAC; SQLite is fine for a demo, not multi-tenant production.

## 17. Future improvements

Live traffic ingestion (SPAN/NetFlow/Zeek), retraining on real captures with
drift monitoring, SHAP explanations, per-asset risk weighting, analyst
feedback loop into risk calibration, ticketing integration, LLM summarization.

## 18. Hackathon demo (2 minutes)

0. (before the demo / between runs) Click **Reset Demo** in the header →
   confirms → clears events, alerts and blocked sources, dashboard returns
   to the clean **Protected** baseline. Also available via
   `POST /api/reset` (curl) or the `bun run demo` backend mode for a
   reload-free presentation server.
1. Open the dashboard → green **Protected** banner, traffic flowing.
2. Open **Security Test Lab** → read the safety banner.
3. Click **Run Safe Test** on *SYN Flood*.
4. (auto) App switches to the dashboard as alerts escalate MEDIUM → HIGH →
   CRITICAL; the traffic chart spikes; the threat panel opens.
5. Read the plain-language explanation + evidence (95% SYN share, 23.8×
   half-open ratio…), point at risk 91/100 CRITICAL.
6. Click **Simulate Block** → traffic collapses to baseline, event turns
   MITIGATED, status returns to Protected.
7. Open **PCAP Analysis** → click `mixed_traffic.pcap` → Port Scan + SYN
   Flood + Brute Force all detected in one capture (~4 s).
8. (optional) **ML Model** tab → live model card, or run the other four
   scenarios (~13 s each).

## 19. implemented now vs. future integration

See the **Architecture** tab in the app — every pipeline stage explicitly
separates “Implemented now” from “Production integration (future)”. Nothing
on the dashboard claims capability the code does not have.
