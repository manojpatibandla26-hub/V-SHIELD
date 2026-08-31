"""AI Sentinel — FastAPI backend entrypoint.

Native WebSocket endpoint is mounted at BOTH "/" and "/ws" so that the
gateway (Caddy, which forwards path as-is with ?XTransformPort=8000) can
reach it either way. In local (non-sandbox) deployments, clients connect
directly to ws://localhost:8000/ws.
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app import config
from app.api import routes
from app.core import model_registry
from app.services import events, store, traffic

logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
logging.getLogger("scapy").setLevel(logging.WARNING)
log = logging.getLogger("sentinel.main")

app = FastAPI(
    title="AI Sentinel — AI-Powered Network Intrusion Detection System",
    version=config.SERVICE_VERSION,
    description=(
        "Educational hackathon prototype. Detection pipeline: "
        "synthetic flows / PCAP -> canonical features -> RandomForest "
        "classification -> IsolationForest anomaly -> risk engine -> "
        "severity -> explanation -> WebSocket -> SOC dashboard. "
        "ALL attack demonstrations are synthetic/simulated; PCAP "
        "processing is offline and read-only."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes.router)


@app.get("/")
async def root():
    return {
        "service": config.SERVICE_NAME,
        "version": config.SERVICE_VERSION,
        "docs": "/docs",
        "websocket": "connect to / (or /ws)",
        "safety": "Educational prototype — synthetic traffic only.",
    }


@app.on_event("startup")
async def startup():
    log.info("AI Sentinel backend starting on port %s", config.PORT)
    store.init()
    ok = model_registry.ensure_model()
    log.info("model ready: %s", ok)
    traffic.start()
    log.info("startup complete — SOC stream live")


@app.on_event("shutdown")
async def shutdown():
    traffic.stop()
    log.info("AI Sentinel backend stopped")


async def _ws_session(ws: WebSocket):
    await events.register(ws)
    try:
        while True:
            msg = await ws.receive_text()
            if msg.strip() in ("ping", '{"type":"ping"}'):
                await ws.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        pass
    finally:
        await events.unregister(ws)


@app.websocket("/")
async def ws_root(ws: WebSocket):
    await _ws_session(ws)


@app.websocket("/ws")
async def ws_alt(ws: WebSocket):
    await _ws_session(ws)
