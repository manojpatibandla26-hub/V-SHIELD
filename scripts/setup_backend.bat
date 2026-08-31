@echo off
REM AI Sentinel - backend setup (Windows)
cd /d "%~dp0\..\mini-services\ai-sentinel-api"
if not exist .venv ( python -m venv .venv )
.venv\Scripts\pip install --upgrade pip -q
.venv\Scripts\pip install -q -r requirements.txt pytest httpx
.venv\Scripts\python ml\generate_dataset.py
.venv\Scripts\python ml\train.py
.venv\Scripts\python tools\generate_samples.py
echo Backend ready. Start it with: scripts\run_backend.bat
