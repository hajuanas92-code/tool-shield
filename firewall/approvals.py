"""Human-approval queue (SQLite). States: pending -> approved | denied | expired."""
import sqlite3
from datetime import datetime, timedelta, timezone

from audit import DB_PATH


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _con() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_table() -> None:
    con = _con()
    con.execute(
        """CREATE TABLE IF NOT EXISTS approvals (
            call_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            decided_at TEXT,
            reviewer TEXT
        )"""
    )
    con.commit()
    con.close()


def create(call_id: int, ttl_seconds: int) -> None:
    now = _now()
    con = _con()
    con.execute(
        "INSERT INTO approvals (call_id, status, created_at, expires_at) VALUES (?,?,?,?)",
        (call_id, "pending", now.isoformat(), (now + timedelta(seconds=ttl_seconds)).isoformat()),
    )
    con.commit()
    con.close()


def _expire_old(con: sqlite3.Connection) -> None:
    con.execute("UPDATE approvals SET status='expired' WHERE status='pending' AND expires_at < ?",
                (_now().isoformat(),))
    con.commit()


def get_status(call_id: int):
    con = _con()
    try:
        _expire_old(con)
        row = con.execute("SELECT status FROM approvals WHERE call_id=?", (call_id,)).fetchone()
        return row["status"] if row else None
    finally:
        con.close()


def decide(call_id: int, approve: bool, reviewer: str) -> str:
    """Approve or deny a pending request. Raises ValueError if it is not pending."""
    new_status = "approved" if approve else "denied"
    con = _con()
    try:
        _expire_old(con)
        cur = con.execute(
            "UPDATE approvals SET status=?, decided_at=?, reviewer=? WHERE call_id=? AND status='pending'",
            (new_status, _now().isoformat(), reviewer, call_id))
        con.commit()
        if cur.rowcount == 0:
            row = con.execute("SELECT status FROM approvals WHERE call_id=?", (call_id,)).fetchone()
            raise ValueError(f"call {call_id} is {row['status']}" if row else f"call {call_id} not found")
        return new_status
    finally:
        con.close()


def list_pending() -> list[dict]:
    con = _con()
    try:
        _expire_old(con)
        rows = con.execute(
            """SELECT a.call_id, a.created_at, a.expires_at, t.agent_id, t.tool, t.args, t.reason
               FROM approvals a JOIN tool_calls t ON t.id = a.call_id
               WHERE a.status='pending' ORDER BY a.call_id""").fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()