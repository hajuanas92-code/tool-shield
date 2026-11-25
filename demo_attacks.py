"""
The ONE place where the agent's tool calls leave the agent.

gateway.call(tool, args, context) always returns:
    {"verdict": "ALLOW" | "BLOCK" | "NEEDS_APPROVAL",
     "reason": str, "result": <tool output> | None, "error": str | None}
and prints one coloured line per call, so agent.py does not need to print anything itself.

DirectGateway   : runs the tool immediately (no protection).
FirewallGateway : CHECK mode. Asks the firewall, then runs the tool ITSELF if allowed.
ProxyGateway    : PROXY mode. The firewall runs the tool; the agent never touches the data.
make_gateway()  : FIREWALL_URL unset -> Direct. Set -> Proxy (default) or Check (FIREWALL_MODE=check).
"""
import os
import time

import httpx

import ui
from tools import REGISTRY


def _run_tool(tool: str, args: dict, reason: str) -> dict:
    try:
        result = REGISTRY[tool](**args)
        return {"verdict": "ALLOW", "reason": reason, "result": result, "error": None}
    except Exception as e:
        return {"verdict": "ALLOW", "reason": reason, "result": None, "error": str(e)}


def _blocked(reason: str) -> dict:
    return {"verdict": "BLOCK", "reason": reason, "result": None, "error": None}


class DirectGateway:
    def call(self, tool: str, args: dict, context: list[str]) -> dict:
        out = _run_tool(tool, args, "no firewall")
        ui.print_tool_call(tool, args, out)
        return out


class _FirewallBase:
    def __init__(self, url: str | None = None, agent_id: str = "support-agent"):
        self.url = (url or os.environ["FIREWALL_URL"]).rstrip("/")
        self.agent_id = agent_id
        self.client = httpx.Client(timeout=15)

    def call(self, tool: str, args: dict, context: list[str]) -> dict:
        out = self._call(tool, args, context)
        ui.print_tool_call(tool, args, out)
        return out

    def _announce_wait(self, call_id: int, reason: str) -> float:
        ui.warn(f"call {call_id} needs human approval: {reason}")
        print(f"     approve with: {ui.c(f'python cli.py approve {call_id}', 'bold')}"
              f"   or   {ui.c('python cli.py watch', 'bold')}", flush=True)
        return float(os.environ.get("APPROVAL_TIMEOUT", "300"))


class FirewallGateway(_FirewallBase):
    """Check mode: simple, but the agent executes the tool, so a compromised agent could skip the check."""

    def _call(self, tool: str, args: dict, context: list[str]) -> dict:
        try:
            r = self.client.post(f"{self.url}/v1/tool-call", json={
                "agent_id": self.agent_id, "tool": tool, "args": args, "context": context})
            r.raise_for_status()
            d = r.json()
        except Exception as e:  # fail closed: firewall down means no tool runs
            return _blocked(f"firewall unreachable, failing closed ({e})")

        if d["verdict"] == "ALLOW":
            return _run_tool(tool, args, d["reason"])
        if d["verdict"] == "NEEDS_APPROVAL":
            timeout = self._announce_wait(d["call_id"], d["reason"])
            deadline, status = time.time() + timeout, "timeout"
            while time.time() < deadline:
                try:
                    status = self.client.get(f"{self.url}/v1/approvals/{d['call_id']}").json()["status"]
                except Exception:
                    status = "pending"
                if status in ("approved", "denied", "expired"):
                    break
                time.sleep(2)
            if status == "approved":
                ui.ok(f"call {d['call_id']} approved by a human")
                return _run_tool(tool, args, "approved by human")
            return _blocked(f"human approval {status}: {d['reason']}")
        return _blocked(d["reason"])


class ProxyGateway(_FirewallBase):
    """Proxy mode: the firewall decides AND executes. After approval it runs the arguments it stored when
    it checked the call, so the agent cannot swap them. The agent holds no database or mail access."""

    def _call(self, tool: str, args: dict, context: list[str]) -> dict:
        try:
            r = self.client.post(f"{self.url}/v1/execute", json={
                "agent_id": self.agent_id, "tool": tool, "args": args, "context": context})
            r.raise_for_status()
            d = r.json()
        except Exception as e:  # fail closed
            return _blocked(f"firewall unreachable, failing closed ({e})")

        if d["verdict"] == "ALLOW":
            return {"verdict": "ALLOW", "reason": d["reason"], "result": d["result"], "error": d["error"]}
        if d["verdict"] != "NEEDS_APPROVAL":
            return _blocked(d["reason"])

        call_id = d["call_id"]
        deadline = time.time() + self._announce_wait(call_id, d["reason"])
        while time.time() < deadline:
            try:
                s = self.client.get(f"{self.url}/v1/executions/{call_id}",
                                    params={"agent_id": self.agent_id}).json()
            except Exception:
                s = {"status": "pending"}
            if s["status"] == "done":
                ui.ok(f"call {call_id} approved by a human and executed by the firewall")
                return {"verdict": "ALLOW", "reason": "approved by human",
                        "result": s.get("result"), "error": s.get("error")}
            if s["status"] in ("denied", "expired"):
                return _blocked(f"human approval {s['status']}: {d['reason']}")
            time.sleep(2)
        return _blocked(f"human approval timeout: {d['reason']}")


def make_gateway():
    if not os.environ.get("FIREWALL_URL"):
        ui.info("no FIREWALL_URL set: tools run directly, with no protection")
        return DirectGateway()
    mode = os.environ.get("FIREWALL_MODE", "proxy").lower()
    if mode == "check":
        ui.info("check mode: the firewall approves, the agent runs the tools")
        return FirewallGateway()
    ui.info("proxy mode: the firewall runs every tool call; the agent has no direct access")
    return ProxyGateway()