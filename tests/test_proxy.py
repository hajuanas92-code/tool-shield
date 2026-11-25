"""Proxy-mode tests: run from the project root with `pytest -q`. Uses a throw-away database, not data/."""
import json
import os
import sqlite3
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp())
os.environ["DATA_DIR"] = str(_tmp)
os.environ["AUDIT_DB"] = str(_tmp / "audit.db")
os.environ["SANDBOX_DIR"] = str(_tmp / "sandbox")
os.environ["ADMIN_KEY"] = "test-key"

_con = sqlite3.connect(_tmp / "shop.db")
_con.executescript("""
    CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT);
    CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER, product TEXT, amount REAL, status TEXT);
    CREATE TABLE refunds (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER, amount REAL, reason TEXT,
                          created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    INSERT INTO customers VALUES (1, 'Ana', 'ana@example.org');
    INSERT INTO orders VALUES (1, 1, 'Mouse', 25.0, 'paid');
""")
_con.commit()
_con.close()
(_tmp / "emails.json").write_text(json.dumps(
    [{"id": 1, "from": "ana@example.org", "subject": "hi", "body": "hello", "is_poisoned": False, "attack_type": None}]))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402

ADMIN = {"X-Admin-Key": "test-key"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def q(sql):
    con = sqlite3.connect(_tmp / "shop.db")
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def execute(client, tool, **args):
    return client.post("/v1/execute", json={"agent_id": "t", "tool": tool, "args": args}).json()


def test_allowed_read_runs_and_returns_result(client):
    r = execute(client, "list_emails")
    assert r["verdict"] == "ALLOW" and len(r["result"]) == 1


def test_allowed_write_runs(client):
    before = q("SELECT COUNT(*) FROM refunds")[0][0]
    r = execute(client, "issue_refund", order_id=1, amount=40, reason="damaged")
    assert r["verdict"] == "ALLOW" and r["error"] is None
    assert q("SELECT COUNT(*) FROM refunds")[0][0] == before + 1


def test_blocked_call_is_never_executed(client):
    r = execute(client, "run_sql", query="DROP TABLE orders")
    assert r["verdict"] == "BLOCK" and r["result"] is None
    assert q("SELECT COUNT(*) FROM orders")[0][0] == 1  # table still exists


def test_approval_runs_the_stored_call_exactly_once(client):
    before = q("SELECT COUNT(*) FROM refunds")[0][0]
    r = execute(client, "issue_refund", order_id=1, amount=500, reason="goodwill")
    cid = r["call_id"]
    assert r["verdict"] == "NEEDS_APPROVAL" and r["result"] is None
    assert q("SELECT COUNT(*) FROM refunds")[0][0] == before            # nothing ran yet
    st = client.get(f"/v1/executions/{cid}", params={"agent_id": "t"}).json()
    assert st["status"] == "pending"

    assert client.post(f"/v1/approvals/{cid}/approve").status_code == 401   # the agent has no admin key
    assert q("SELECT COUNT(*) FROM refunds")[0][0] == before

    assert client.post(f"/v1/approvals/{cid}/approve", headers=ADMIN).status_code == 200
    assert q("SELECT COUNT(*) FROM refunds")[0][0] == before + 1
    assert q("SELECT amount FROM refunds ORDER BY id DESC LIMIT 1")[0][0] == 500   # the stored arguments
    st = client.get(f"/v1/executions/{cid}", params={"agent_id": "t"}).json()
    assert st["status"] == "done" and st["error"] is None

    assert client.post(f"/v1/approvals/{cid}/approve", headers=ADMIN).status_code == 409  # no second run
    assert q("SELECT COUNT(*) FROM refunds")[0][0] == before + 1


def test_denied_call_is_never_executed(client):
    before = q("SELECT COUNT(*) FROM refunds")[0][0]
    cid = execute(client, "issue_refund", order_id=1, amount=600, reason="x")["call_id"]
    assert client.post(f"/v1/approvals/{cid}/deny", headers=ADMIN).status_code == 200
    assert client.get(f"/v1/executions/{cid}", params={"agent_id": "t"}).json()["status"] == "denied"
    assert q("SELECT COUNT(*) FROM refunds")[0][0] == before


def test_other_agents_cannot_read_a_result(client):
    cid = execute(client, "list_emails")["call_id"]
    assert client.get(f"/v1/executions/{cid}", params={"agent_id": "someone-else"}).status_code == 404


def test_check_mode_approval_does_not_execute_in_the_firewall(client):
    before = q("SELECT COUNT(*) FROM refunds")[0][0]
    r = client.post("/v1/tool-call", json={"agent_id": "t", "tool": "issue_refund",
                                           "args": {"order_id": 1, "amount": 700, "reason": "x"}}).json()
    assert r["verdict"] == "NEEDS_APPROVAL"
    assert client.post(f"/v1/approvals/{r['call_id']}/approve", headers=ADMIN).status_code == 200
    assert q("SELECT COUNT(*) FROM refunds")[0][0] == before   # in check mode the agent runs it, not the firewall