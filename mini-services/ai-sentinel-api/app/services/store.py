"""SQLite persistence for threat events (simple, no ORM needed).

Table: events — one row per detected threat (updated as a simulation
escalates). The runtime state (blocked sources, live traffic) stays in
memory; events are the durable audit trail.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Dict, List, Optional

from app.config import DB_PATH

_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           TEXT PRIMARY KEY,
    ts           REAL NOT NULL,
    updated_ts   REAL NOT NULL,
    attack       TEXT NOT NULL,
    confidence   REAL NOT NULL,
    risk         INTEGER NOT NULL,
    severity     TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'ACTIVE',
    source       TEXT DEFAULT 'unknown',
    target       TEXT DEFAULT 'unknown',
    sim_id       TEXT,
    origin       TEXT DEFAULT 'simulation',
    anomaly_score REAL DEFAULT 0,
    model_version TEXT DEFAULT '',
    explanation  TEXT DEFAULT '{}',
    observed     TEXT DEFAULT '{}',
    probabilities TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_sim ON events(sim_id);
"""


def init() -> None:
    global _conn
    with _lock:
        if _conn is not None:
            return
        _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(_SCHEMA)
        _conn.commit()


def _get() -> sqlite3.Connection:
    if _conn is None:
        init()
    assert _conn is not None
    return _conn


def _row_to_dict(row: sqlite3.Row) -> Dict:
    d = dict(row)
    for key in ("explanation", "observed", "probabilities"):
        try:
            d[key] = json.loads(d.get(key) or "{}")
        except (TypeError, ValueError):
            d[key] = {}
    return d


def upsert_event(event_id: str, ts: float, attack: str, confidence: float,
                 risk: int, severity: str, source: str, target: str,
                 explanation: Dict, observed: Dict, probabilities: Dict,
                 anomaly_score: float, model_version: str,
                 sim_id: Optional[str] = None, origin: str = "simulation",
                 status: str = "ACTIVE") -> Dict:
    """Insert or update (escalate) one event. Returns the stored row."""
    now = ts
    with _lock:
        c = _get()
        c.execute(
            """
            INSERT INTO events (id, ts, updated_ts, attack, confidence, risk,
                                severity, status, source, target, sim_id, origin,
                                anomaly_score, model_version, explanation,
                                observed, probabilities)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                updated_ts=excluded.updated_ts,
                attack=excluded.attack, confidence=excluded.confidence,
                risk=excluded.risk, severity=excluded.severity,
                anomaly_score=excluded.anomaly_score,
                explanation=excluded.explanation,
                observed=excluded.observed,
                probabilities=excluded.probabilities
            """,
            (event_id, ts, now, attack, float(confidence), int(risk), severity,
             status, source, target, sim_id, origin, float(anomaly_score),
             model_version, json.dumps(explanation), json.dumps(observed),
             json.dumps(probabilities)),
        )
        c.commit()
    return get_event(event_id) or {}


def update_status(event_id: str, status: str) -> Optional[Dict]:
    with _lock:
        c = _get()
        c.execute("UPDATE events SET status=? WHERE id=?", (status, event_id))
        c.commit()
    return get_event(event_id)


def clear_events() -> int:
    """Delete all events (demo reset). Returns number of rows removed."""
    with _lock:
        c = _get()
        cur = c.execute("SELECT COUNT(*) FROM events")
        n = int(cur.fetchone()[0])
        c.execute("DELETE FROM events")
        c.commit()
    return n


def get_event(event_id: str) -> Optional[Dict]:
    row = _get().execute("SELECT * FROM events WHERE id=?",
                         (event_id,)).fetchone()
    return _row_to_dict(row) if row else None


def find_by_sim(sim_id: str) -> Optional[Dict]:
    row = _get().execute("SELECT * FROM events WHERE sim_id=? ORDER BY ts "
                         "DESC LIMIT 1", (sim_id,)).fetchone()
    return _row_to_dict(row) if row else None


def list_events(limit: int = 50, status: Optional[str] = None) -> List[Dict]:
    q = "SELECT * FROM events"
    args: List = []
    if status:
        q += " WHERE status=?"
        args.append(status)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(int(limit))
    return [_row_to_dict(r) for r in _get().execute(q, args).fetchall()]


def statistics() -> Dict:
    c = _get()
    one = lambda sql: c.execute(sql).fetchone()[0]  # noqa: E731
    return {
        "events_total": int(one("SELECT COUNT(*) FROM events")),
        "threats_total": int(one(
            "SELECT COUNT(*) FROM events WHERE attack != 'BENIGN'")),
        "critical_total": int(one(
            "SELECT COUNT(*) FROM events WHERE severity='CRITICAL'")),
        "active_threats": int(one(
            "SELECT COUNT(*) FROM events WHERE attack != 'BENIGN' "
            "AND status='ACTIVE'")),
        "mitigated": int(one(
            "SELECT COUNT(*) FROM events WHERE status='MITIGATED'")),
        "resolved": int(one(
            "SELECT COUNT(*) FROM events WHERE status='RESOLVED'")),
    }
