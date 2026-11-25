"""
The real tools. In proxy mode ONLY the firewall holds these: the agent has no database, no mail
credentials and no shell, so it cannot act without going through a decision.
"""
import json
import os
import shlex
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, Optional

DATA = Path(os.environ.get("DATA_DIR", "data"))
SANDBOX = Path(os.environ.get("SANDBOX_DIR", "sandbox"))
DB = DATA / "shop.db"
EMAILS = DATA / "emails.json"
OUTBOX = DATA / "outbox.json"  # mock "sent mail" log


def list_emails() -> list:
    emails = json.loads(EMAILS.read_text())
    return [{"id": e["id"], "from": e["from"], "subject": e["subject"]} for e in emails]


def read_email(email_id: int) -> dict:
    # is_poisoned / attack_type are labels for evaluation: the agent never sees them
    for e in json.loads(EMAILS.read_text()):
        if e["id"] == email_id:
            return {"id": e["id"], "from": e["from"], "subject": e["subject"], "body": e["body"]}
    raise ValueError(f"no email with id {email_id}")


def run_sql(query: str) -> dict:
    con = sqlite3.connect(DB)
    try:
        cur = con.execute(query)  # one statement per call
        if cur.description:
            cols = [d[0] for d in cur.description]
            rows = cur.fetchmany(50)
            return {"columns": cols, "rows": rows, "truncated": len(rows) == 50}
        con.commit()
        return {"rows_affected": cur.rowcount}
    finally:
        con.close()


def send_email(to: str, subject: str, body: str) -> dict:
    outbox = json.loads(OUTBOX.read_text()) if OUTBOX.exists() else []
    outbox.append({"to": to, "subject": subject, "body": body})
    OUTBOX.write_text(json.dumps(outbox, indent=2))
    return {"status": "sent (mock)", "to": to}


def issue_refund(order_id: int, amount: float, reason: str) -> dict:
    con = sqlite3.connect(DB)
    try:
        con.execute("INSERT INTO refunds (order_id, amount, reason) VALUES (?,?,?)",
                    (order_id, amount, reason))
        con.commit()
        return {"status": "refund issued (mock)", "order_id": order_id, "amount": amount}
    finally:
        con.close()


def run_shell(command: str) -> dict:
    # the rules already allowed only allowlisted commands; still no shell=True, fixed cwd, timeout
    SANDBOX.mkdir(parents=True, exist_ok=True)
    p = subprocess.run(shlex.split(command), cwd=SANDBOX, capture_output=True, text=True, timeout=10)
    return {"returncode": p.returncode, "stdout": p.stdout[:4000], "stderr": p.stderr[:1000]}


REGISTRY = {
    "list_emails": list_emails, "read_email": read_email, "run_sql": run_sql,
    "send_email": send_email, "issue_refund": issue_refund, "run_shell": run_shell,
}


def run(tool: str, args: dict) -> tuple[Any, Optional[str]]:
    """Returns (result, error). Never raises."""
    fn = REGISTRY.get(tool)
    if fn is None:
        return None, f"no executor for '{tool}'"
    try:
        return fn(**args), None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"