@echo off
REM AI Sentinel - start frontend (port 3000)
REM For laptop use, create .env.local with NEXT_PUBLIC_API_BASE=http://localhost:8000
cd /d "%~dp0\.."
npm run dev
