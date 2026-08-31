#!/usr/bin/env bash
# AI Sentinel — start backend (port 8000)
#
#   bash scripts/run_backend.sh               # dev mode (auto-reload on .py changes)
#   bash scripts/run_backend.sh --no-reload   # presentation mode (stable, no reload)
#
# Only ONE backend instance should run at a time — the wrapper refuses to
# start a second one if port 8000 is already in use.
cd "$(dirname "$0")/../mini-services/ai-sentinel-api"
PY=python3; [ -x .venv/bin/python ] && PY=.venv/bin/python
RELOAD_ARGS="--reload --reload-include *.py"
for arg in "$@"; do
  [ "$arg" = "--no-reload" ] || [ "$arg" = "no-reload" ] && RELOAD_ARGS=""
done
exec $PY -m uvicorn app.main:app --host 0.0.0.0 --port 8000 $RELOAD_ARGS
