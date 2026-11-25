"""Audit log: every tool call and the decision made about it (SQLite for now)."""
import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get("AUDIT_DB", "data/audit.db")


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute(
        """CREATE TABLE IF NOT EXISTS tool_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            tool TEXT NOT NULL,
            args TEXT NOT NULL,
            context_chars INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            risk_score REAL,
            reason TEXT
        )"""
    )
    con.commit()
    con.close()


def log_call(req, decision) -> int:
    con = sqlite3.connect(DB_PATH)
    try:
        cur = con.execute(
            "INSERT INTO tool_calls (ts, agent_id, tool, args, context_chars, verdict, risk_score, reason)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), req.agent_id, req.tool,
             json.dumps(req.args), sum(len(c) for c in req.context),
             decision.verdict.value, decision.risk_score, decision.reason),
        )
        con.commit()
        return cur.lastrowid
    finally:
        con.close()


def recent(limit: int = 20) -> list[dict]:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("SELECT * FROM tool_calls ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()