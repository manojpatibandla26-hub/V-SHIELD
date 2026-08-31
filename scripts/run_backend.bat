@echo off
REM AI Sentinel - start backend (port 8000)
REM   scripts\run_backend.bat               - dev mode (auto-reload)
REM   scripts\run_backend.bat no-reload     - presentation mode (stable, no reload)
cd /d "%~dp0\..\mini-services\ai-sentinel-api"
set PY=python
if exist .venv\Scripts\python.exe set PY=.venv\Scripts\python.exe
set RELOAD=--reload --reload-include *.py
if "%1"=="no-reload" set RELOAD=
if "%1"=="--no-reload" set RELOAD=
%PY% -m uvicorn app.main:app --host 0.0.0.0 --port 8000 %RELOAD%
