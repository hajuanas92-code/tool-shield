"""
Proxy-mode demo: the firewall EXECUTES the tools. This script plays the agent and, to keep the demo in one
command, also plays the human reviewer using ADMIN_KEY.

    export ADMIN_KEY=<same secret as the firewall>
    python demo_proxy.py          (firewall running on :8000 and able to see data/shop.db)

It writes one row to the refunds table. Reset with: python make_fake_data.py
"""
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "agent"))

import httpx  # noqa: E402

import ui  # noqa: E402

URL = os.environ.get("FIREWALL_URL", "http://localhost:8000").rstrip("/")
ADMIN = os.environ.get("ADMIN_KEY", "")
AGENT = "demo"


def execute(tool: str, args: dict) -> dict:
    try:
        return httpx.post(f"{URL}/v1/execute", timeout=15,
                          json={"agent_id": AGENT, "tool": tool, "args": args, "context": []}).json()
    except Exception as e:
        ui.error(f"cannot reach the firewall at {URL}: {e}")
        sys.exit(1)


def step(title: str) -> None:
    print("\n" + ui.c(title, "bold", "cyan"))


def refund_count() -> int:
    r = execute("run_sql", {"query": "SELECT COUNT(*) FROM refunds"})
    return r["result"]["rows"][0][0]


step("1. a normal query: the firewall runs it and returns the rows")
before = refund_count()
print(f"   refunds in the database: {before}")

step("2. a destructive query: blocked, never executed")
r = execute("run_sql", {"query": "DROP TABLE orders"})
print(f"   {ui.verdict(r['verdict'])} {ui.c(r['reason'], 'dim')}")

step("3. a $500 refund: held for a human, NOT executed yet")
r = execute("issue_refund", {"order_id": 2, "amount": 500, "reason": "goodwill"})
print(f"   {ui.verdict(r['verdict'])} {ui.c(r['reason'], 'dim')}")
call_id = r["call_id"]
print(f"   refunds in the database: {refund_count()}  (unchanged)")

if not ADMIN:
    ui.warn(f"ADMIN_KEY not set. Approve it yourself:  python cli.py approve {call_id}")
    sys.exit(0)

step("4. the human approves: the firewall runs the call it stored, exactly once")
a = httpx.post(f"{URL}/v1/approvals/{call_id}/approve", headers={"X-Admin-Key": ADMIN}, params={"reviewer": "demo"})
if a.status_code != 200:
    ui.error(f"approve failed: {a.status_code} {a.text}")
    sys.exit(1)
for _ in range(10):
    s = httpx.get(f"{URL}/v1/executions/{call_id}", params={"agent_id": AGENT}).json()
    if s["status"] == "done":
        break
    time.sleep(0.5)
print(f"   execution status: {ui.c(s['status'], 'green', 'bold')}  result: {s.get('result')}")
print(f"   refunds in the database: {refund_count()}  (was {before})")