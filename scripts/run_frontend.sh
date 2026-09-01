#!/usr/bin/env bash
# AI Sentinel — start frontend (port 3000)
# For laptop use, create .env.local with:
#   NEXT_PUBLIC_API_BASE=http://localhost:8000
cd "$(dirname "$0")/.."
if command -v bun >/dev/null 2>&1; then exec bun run dev; else exec npm run dev; fi
