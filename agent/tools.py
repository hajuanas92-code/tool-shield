"""The real tools the agent can use. They work on the fake data from step 1."""
import json
import os
import sqlite3
from pathlib import Path

DATA = Path(os.environ.get("DATA_DIR", "data"))
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
        con.execute(
            "INSERT INTO refunds (order_id, amount, reason) VALUES (?,?,?)",
            (order_id, amount, reason),
        )
        con.commit()
        return {"status": "refund issued (mock)", "order_id": order_id, "amount": amount}
    finally:
        con.close()


REGISTRY = {
    "list_emails": list_emails,
    "read_email": read_email,
    "run_sql": run_sql,
    "send_email": send_email,
    "issue_refund": issue_refund,
}