"""AI Sentinel — compact pytest suite (run: python -m pytest tests/ -q).

Covers: model loading, preprocessing, risk & severity math, simulation
generation, API health/analysis, PCAP validation, and the full pipeline.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("AI_SENTINEL_LOG_LEVEL", "WARNING")

import pytest


# ------------------------------------------------------------------ fixtures
@pytest.fixture(scope="session")
def ready():
    from app.core import model_registry
    assert model_registry.ensure_model()
    return True


# ------------------------------------------------------------------ schema
def test_feature_schema_consistency():
    from app.core.feature_schema import FEATURES, RAW_COUNTERS, derive
    assert len(FEATURES) == 22
    raw = {k: 0.0 for k in RAW_COUNTERS}
    raw.update({"total_packets": 600, "duration_s": 6.0,
                "syn_count": 300, "ack_count": 120,
                "total_bytes": 60000, "flow_count": 60})
    f = derive(raw)
    assert f["pkt_rate"] == pytest.approx(100.0)
    assert f["syn_pct"] == pytest.approx(0.5)
    assert f["syn_ack_ratio"] == pytest.approx(2.5)
    assert f["avg_pkt_size"] == pytest.approx(100.0)
    assert f["auth_port_pct"] == pytest.approx(0.0)


def test_preprocess_sanitizes():
    from app.core.preprocess import sanitize_vector
    from app.core.feature_schema import feature_row
    feats = {"syn_ack_ratio": float("inf"), "duration_s": float("nan"),
             "total_packets": -5, "flow_count": 1e12}
    out = sanitize_vector(feature_row(feats))
    assert out[13] == 0.0            # inf -> 0
    assert out[0] == 0.0             # nan -> 0
    assert out[2] == 0.0             # negative clipped
    assert out[1] <= 5_000_000       # clipped


# ------------------------------------------------------------------ risk
def test_severity_bands():
    from app.core.risk_engine import severity_of
    assert severity_of(0) == "LOW"
    assert severity_of(24) == "LOW"
    assert severity_of(25) == "MEDIUM"
    assert severity_of(49) == "MEDIUM"
    assert severity_of(50) == "HIGH"
    assert severity_of(74) == "HIGH"
    assert severity_of(75) == "CRITICAL"
    assert severity_of(100) == "CRITICAL"


def test_risk_deterministic_and_bounded(ready):
    from app.core.risk_engine import compute
    from app.simulation.generators import benign_component
    import random
    rng = random.Random(1)
    feats = benign_component(rng)
    r1, _ = compute("BENIGN", 0.97, 0.05, feats)
    r2, _ = compute("BENIGN", 0.97, 0.05, feats)
    assert r1 == r2                   # deterministic, never random
    assert 0 <= r1 <= 24              # benign stays LOW band
    r3, _ = compute("SYN_FLOOD", 0.99, 0.95, feats)
    assert 0 <= r3 <= 100
    assert r3 > r1


# ------------------------------------------------------------------ model
def test_model_predicts_all_classes(ready):
    from app.core import model_registry
    from app.core.feature_schema import CLASSES
    meta = model_registry.metadata()
    assert set(meta["classes"]) == set(CLASSES)
    assert meta["metrics"]["accuracy"] > 0.95
    # spot-check a strong syn-flood feature vector
    feats = {
        "duration_s": 6.0, "flow_count": 3000, "total_packets": 60000,
        "total_bytes": 60000 * 60, "avg_pkt_size": 60,
        "pkt_rate": 10000, "byte_rate": 600000, "syn_count": 54000,
        "ack_count": 2400, "fin_count": 0, "rst_count": 0,
        "syn_pct": 0.9, "rst_pct": 0.0, "syn_ack_ratio": 22.5,
        "distinct_dst_ports": 1, "distinct_dst_ips": 1, "distinct_src_ips": 1,
        "avg_flow_duration_s": 0.005, "avg_flow_packets": 1.2,
        "auth_port_pct": 0.0, "tcp_pct": 1.0, "icmp_pct": 0.0,
    }
    label, probs, conf = model_registry.predict(feats)
    assert label == "SYN_FLOOD"
    assert conf > 0.8
    assert set(probs.keys()) == set(CLASSES)


def test_simulation_generators_differ(ready):
    """The five scenarios must produce genuinely different features."""
    from app.core.feature_schema import derive
    from app.simulation import generators
    import random
    rng = random.Random(5)
    vecs = {}
    for atk in ["syn_flood", "dos_ddos", "port_scan", "brute_force", "anomaly"]:
        vecs[atk] = derive(generators.generate(atk, 1.0, rng))
    assert vecs["port_scan"]["distinct_dst_ports"] > \
        10 * vecs["syn_flood"]["distinct_dst_ports"]
    assert vecs["syn_flood"]["syn_pct"] > \
        2 * vecs["brute_force"]["syn_pct"]
    assert vecs["brute_force"]["auth_port_pct"] > 0.8
    assert vecs["dos_ddos"]["distinct_src_ips"] > \
        vecs["syn_flood"]["distinct_src_ips"]


# ------------------------------------------------------------------ pipeline
def test_pipeline_end_to_end(ready):
    from app.core import pipeline
    from app.simulation import generators
    import random
    rng = random.Random(9)
    raw = generators.generate("syn_flood", 0.9, rng)
    r = pipeline.analyze_window(raw, source="t", target="t")
    for key in ("label", "confidence", "risk", "severity", "explanation",
                "features", "observed", "probabilities"):
        assert key in r
    assert r["risk"] >= 75
    assert r["severity"] == "CRITICAL"
    assert r["explanation"]["evidence"], "explanation must cite real features"


# ------------------------------------------------------------------ pcap
def test_pcap_validation():
    from app.pcap.parser import PcapError, validate_file
    import tempfile
    p = Path(tempfile.mkstemp(suffix=".txt")[1])
    p.write_bytes(b"not a pcap at all")
    with pytest.raises(PcapError):
        validate_file(p, "x.txt")
    os.unlink(p)


def test_pcap_sample_analysis(ready):
    import asyncio
    from app.pcap import parser, samples
    from app.config import PCAP_SAMPLES_DIR
    path = samples.sample_path("portscan")
    assert path is not None and path.exists()
    res = asyncio.run(parser.analyze_file(path, path.name,
                                          create_events=False))
    assert res["total_packets"] > 500
    attacks = {r["label"] for r in res["results"]}
    assert "PORT_SCAN" in attacks
    assert res["limitations"], "limitations must be surfaced honestly"


# ------------------------------------------------------------------ API
@pytest.fixture(scope="module")
def client(ready):
    from fastapi.testclient import TestClient
    from app.main import app
    # don't start the background loop for tests
    import app.services.traffic as traffic
    traffic._task = asyncio_dud = None  # noqa: F841
    with TestClient(app) as c:
        yield c


def test_api_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["backend"] == "online"
    assert body["model"] == "online"


def test_api_model_info(client):
    r = client.get("/api/model-info")
    assert r.status_code == 200
    body = r.json()
    assert body["algorithm"] == "RandomForestClassifier"
    assert len(body["features"]) == 22
    assert body["metrics"]["accuracy"] > 0.95
    assert body["risk_model"]["severity_bands"]["CRITICAL"] == "75-100"


def test_api_analyze(client):
    from app.core.feature_schema import FEATURES
    feats = {f: 0.0 for f in FEATURES}
    feats.update({"duration_s": 6.0, "flow_count": 2, "total_packets": 600,
                  "total_bytes": 300000, "avg_pkt_size": 500,
                  "pkt_rate": 100, "byte_rate": 50000, "syn_count": 5,
                  "ack_count": 400, "fin_count": 4, "rst_count": 0,
                  "syn_pct": 0.008, "rst_pct": 0, "syn_ack_ratio": 0.0125,
                  "distinct_dst_ports": 3, "distinct_dst_ips": 1,
                  "distinct_src_ips": 1, "avg_flow_duration_s": 1.0,
                  "avg_flow_packets": 300, "auth_port_pct": 0,
                  "tcp_pct": 1.0, "icmp_pct": 0})
    r = client.post("/api/analyze", json={"features": feats})
    assert r.status_code == 200
    assert r.json()["label"] == "BENIGN"
    # missing features -> 400 with list
    r2 = client.post("/api/analyze", json={"features": {"pkt_rate": 1}})
    assert r2.status_code == 400
    assert "missing" in r2.json()["detail"]


def test_websocket_and_simulation(client):
    import time
    with client.websocket_connect("/") as ws:
        # POST a simulation and watch the full event stream until completion
        r = client.post("/api/simulation/port_scan")
        assert r.status_code == 202
        sim_id = r.json()["sim_id"]
        seen = {"traffic": 0, "threat": 0, "alert": 0, "complete": False}
        deadline = time.time() + 25
        while time.time() < deadline and not seen["complete"]:
            msg = ws.receive_json()
            t = msg.get("type")
            if t == "traffic_update":
                seen["traffic"] += 1
            elif t == "threat_detected":
                seen["threat"] += 1
            elif t == "alert":
                seen["alert"] += 1
            elif t == "sim_complete":
                seen["complete"] = True
        assert seen["traffic"] > 0, "no traffic updates streamed"
        assert seen["complete"], "simulation did not complete in time"
        # the ramp starts weak: a threat should appear as it intensifies
        assert seen["threat"] >= 1, "no threat was detected during the ramp"
        # store must contain the event
        r = client.get("/api/events?limit=10")
        evs = r.json()["events"]
        assert any(e.get("sim_id") == sim_id for e in evs)
