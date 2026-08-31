#!/usr/bin/env bash
# AI Sentinel — start backend (port 8000, auto-reload on .py changes)
cd "$(dirname "$0")/../mini-services/ai-sentinel-api"
PY=python3; [ -x .venv/bin/python ] && PY=.venv/bin/python
exec $PY -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --reload-include '*.py'
