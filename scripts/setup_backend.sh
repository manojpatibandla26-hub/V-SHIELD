#!/usr/bin/env bash
# AI Sentinel — backend setup (laptop use)
set -e
cd "$(dirname "$0")/../mini-services/ai-sentinel-api"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -q -r requirements.txt pytest httpx
.venv/bin/python ml/generate_dataset.py
.venv/bin/python ml/train.py
.venv/bin/python tools/generate_samples.py
echo "Backend ready. Start it with: scripts/run_backend.sh"
