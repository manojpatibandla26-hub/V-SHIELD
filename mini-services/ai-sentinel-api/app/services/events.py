"""WebSocket connection manager + event broadcast bus (native FastAPI WS)."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Dict, List, Set

from fastapi import WebSocket

log = logging.getLogger("sentinel.ws")

_clients: Set[WebSocket] = set()
_lock = asyncio.Lock()


async def register(ws: WebSocket) -> None:
    await ws.accept()
    async with _lock:
        _clients.add(ws)
    log.info("WebSocket client connected (%d online)", len(_clients))


async def unregister(ws: WebSocket) -> None:
    async with _lock:
        _clients.discard(ws)
    log.info("WebSocket client disconnected (%d online)", len(_clients))


def client_count() -> int:
    return len(_clients)


async def broadcast(message: Dict) -> None:
    """Send one JSON message to every connected client (best-effort)."""
    if not _clients:
        return
    payload = json.dumps(message, default=str)
    dead: List[WebSocket] = []
    for ws in list(_clients):
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        async with _lock:
            _clients.discard(ws)
