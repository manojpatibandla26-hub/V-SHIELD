@echo off
REM AI Sentinel - start backend (port 8000)
cd /d "%~dp0\..\mini-services\ai-sentinel-api"
set PY=python
if exist .venv\Scripts\python.exe set PY=.venv\Scripts\python.exe
%PY% -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --reload-include *.py
