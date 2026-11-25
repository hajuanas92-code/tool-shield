"""
Approve or deny pending actions from the terminal.

    export ADMIN_KEY=<same secret the firewall was started with>
    python cli.py list
    python cli.py approve 12
    python cli.py deny 12
    python cli.py watch          # waits for requests and asks you y/n for each one
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "agent"))

import httpx  # noqa: E402

import ui  # noqa: E402

URL = os.environ.get("FIREWALL_URL", "http://localhost:8000").rstrip("/")
KEY = os.environ.get("ADMIN_KEY", "")


def call(method: str, path: str, **params):
    try:
        r = httpx.request(method, URL + path, headers={"X-Admin-Key": KEY}, params=params, timeout=10)
    except httpx.HTTPError as e:
        ui.error(f"cannot reach the firewall at {URL}: {e}")
        sys.exit(1)
    if r.status_code >= 400:
        ui.error(f"{r.status_code}: {r.text}")
        sys.exit(1)
    return r.json()


def show(r: dict) -> None:
    print(f"{ui.c('#' + str(r['call_id']), 'yellow', 'bold')}  {ui.c(r['tool'], 'cyan', 'bold')}  "
          f"{json.loads(r['args'])}\n      {ui.c('why:', 'dim')} {r['reason']}")


def decide(call_id: int, verb: str) -> None:
    call("POST", f"/v1/approvals/{call_id}/{verb}", reviewer=os.environ.get("USER") or os.environ.get("USERNAME") or "cli")
    (ui.ok if verb == "approve" else ui.error)(f"call {call_id} {verb}d")


def watch() -> None:
    ui.info("watching for approval requests (Ctrl+C to stop)")
    seen = set()
    try:
        while True:
            for r in call("GET", "/v1/approvals"):
                if r["call_id"] in seen:
                    continue
                seen.add(r["call_id"])
                print()
                show(r)
                answer = input(f"{ui.c('approve?', 'bold')} [y = approve / n = deny / Enter = skip] ").strip().lower()
                if answer in ("y", "yes"):
                    decide(r["call_id"], "approve")
                elif answer in ("n", "no"):
                    decide(r["call_id"], "deny")
            time.sleep(2)
    except KeyboardInterrupt:
        print()


def main():
    p = argparse.ArgumentParser(prog="cli.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("watch")
    for name in ("approve", "deny"):
        sub.add_parser(name).add_argument("call_id", type=int)
    a = p.parse_args()

    if a.cmd == "list":
        rows = call("GET", "/v1/approvals")
        if not rows:
            ui.info("nothing pending")
        for r in rows:
            show(r)
    elif a.cmd == "watch":
        watch()
    else:
        decide(a.call_id, a.cmd)


if __name__ == "__main__":
    main()