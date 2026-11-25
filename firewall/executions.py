"""
Execution records for proxy mode. A call is executed at most once, and always with the arguments that were
stored when it was checked: the agent cannot change them after approval.
"""
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

import executor
from audit import DB_PATH


def _con() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_table() -> None:
    con = _con()
    con.execute(
        """CREATE TABLE IF NOT EXISTS executions (
            call_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL,
            result TEXT,
            error TEXT,
            executed_at TEXT
        )"""
    )
    con.commit()
    con.close()


def load_call(call_id: int) -> Optional[dict]:
    """The call exactly as it was checked and logged."""
    con = _con()
    try:
        row = con.execute("SELECT agent_id, tool, args FROM tool_calls WHERE id=?", (call_id,)).fetchone()
        return {"agent_id": row["agent_id"], "tool": row["tool"], "args": json.loads(row["args"])} if row else None
    finally:
        con.close()


def mark_awaiting(call_id: int) -> None:
    """A proxy-mode call is waiting for a human. Only such calls are ever run by the firewall on approval
    (in check mode the agent runs approved calls itself)."""
    con = _con()
    try:
        con.execute("INSERT OR IGNORE INTO executions (call_id, status) VALUES (?, 'awaiting')", (call_id,))
        con.commit()
    finally:
        con.close()


def run_call(call_id: int, tool: str, args: dict, from_approval: bool = False) -> tuple[Any, Optional[str]]:
    """Claim the call (only one caller can), run it, record the outcome. Returns (result, error)."""
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    try:
        if from_approval:
            cur = con.execute("UPDATE executions SET status='running', executed_at=? "
                              "WHERE call_id=? AND status='awaiting'", (now, call_id))
            con.commit()
            if cur.rowcount == 0:
                return None, "not a call waiting for execution"
        else:
            try:
                con.execute("INSERT INTO executions (call_id, status, executed_at) VALUES (?,?,?)",
                            (call_id, "running", now))
                con.commit()
            except sqlite3.IntegrityError:
                return None, "already executed"
        result, error = executor.run(tool, args)
        con.execute("UPDATE executions SET status='done', result=?, error=? WHERE call_id=?",
                    (json.dumps(result, default=str), error, call_id))
        con.commit()
        return result, error
    finally:
        con.close()


def get(call_id: int) -> Optional[dict]:
    con = _con()
    try:
        row = con.execute("SELECT * FROM executions WHERE call_id=?", (call_id,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()