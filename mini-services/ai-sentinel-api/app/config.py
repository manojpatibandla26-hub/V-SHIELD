"""AI Sentinel backend configuration."""
import os
from pathlib import Path

# --- Service ---
SERVICE_NAME = "ai-sentinel-api"
SERVICE_VERSION = "1.0.0"
HOST = os.getenv("AI_SENTINEL_HOST", "0.0.0.0")
PORT = int(os.getenv("AI_SENTINEL_PORT", "8000"))

# --- Paths ---
BASE_DIR = Path(__file__).resolve().parent.parent
ML_DIR = BASE_DIR / "ml"
DATA_DIR = BASE_DIR / "ml" / "data"
MODELS_DIR = BASE_DIR / "ml" / "models"
PCAP_SAMPLES_DIR = BASE_DIR / "pcaps" / "samples"
RUNTIME_DATA_DIR = BASE_DIR / "data"
DB_PATH = RUNTIME_DATA_DIR / "sentinel.db"

for _d in (ML_DIR, DATA_DIR, MODELS_DIR, PCAP_SAMPLES_DIR, RUNTIME_DATA_DIR):
    _d.mkdir(parents=True, exist_ok=True)

MODEL_PATH = MODELS_DIR / "random_forest.joblib"
ANOMALY_MODEL_PATH = MODELS_DIR / "isolation_forest.joblib"
METADATA_PATH = MODELS_DIR / "metadata.json"
BASELINES_PATH = MODELS_DIR / "benign_baselines.json"

# --- Model ---
MODEL_VERSION = "v1.0"

# --- Simulation ---
SIM_WINDOW_SECONDS = 6.0          # each synthetic window covers ~6s of traffic
SIM_WINDOW_INTERVAL = 1.15        # seconds between emitted windows (demo pacing)
SIM_INTENSITIES = [0.03, 0.06, 0.10, 0.16, 0.25, 0.38, 0.55, 0.75, 0.92, 1.00]
BLOCK_DURATION_S = 600            # simulated blocks expire after 10 minutes

# --- Background traffic ---
TRAFFIC_INTERVAL_S = 2.4          # benign window cadence

# --- PCAP ---
PCAP_MAX_BYTES = 25 * 1024 * 1024
PCAP_MAGIC_BYTES = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",      # pcap LE / BE (usec)
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",      # pcap LE / BE (ns)
    b"\x0a\x0d\x0d\x0a",                            # pcapng
}

# --- Logging ---
LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
LOG_LEVEL = os.getenv("AI_SENTINEL_LOG_LEVEL", "INFO")
