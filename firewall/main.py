"""
AgentGuard firewall: rules + ML classifier + human approval + audit + tracing, in two modes:

  check mode  POST /v1/tool-call   the agent asks, then runs the tool itself
  proxy mode  POST /v1/execute     the firewall runs the tool itself (the agent has no direct access)

Run from the project root:
    export ADMIN_KEY=choose-a-secret
    uvicorn --app-dir firewall main:app --port 8000
Swagger UI: http://localhost:8000/docs
"""
import hmac
import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException

import approvals
import audit
import executions
import telemetry
import ui
from decision import Decision, Verdict
from engine import evaluate
from models import ExecuteResponse, ToolCallRequest, ToolCallResponse
from policy import get_policy

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("agentguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    telemetry.setup()
    audit.init_db()
    approvals.init_table()
    executions.init_table()
    if not os.environ.get("ADMIN_KEY"):
        log.warning(ui.c("ADMIN_KEY is not set: approving/denying and listing approvals are disabled", "yellow"))
    if get_policy("default").get("classifier", {}).get("enabled"):
        import classifier
        classifier.score_text("warm up")  # raises if the model is missing: fail loudly at startup
        log.info("injection classifier loaded")
    yield
    telemetry.shutdown()


app = FastAPI(title="AgentGuard", lifespan=lifespan)


def require_admin(x_admin_key: str | None = Header(default=None)):
    """Only humans hold ADMIN_KEY. The agent must never be able to approve its own actions."""
    expected = os.environ.get("ADMIN_KEY")
    if not expected:
        raise HTTPException(503, "ADMIN_KEY is not set on the firewall")
    if not x_admin_key or not hmac.compare_digest(x_admin_key, expected):
        raise HTTPException(401, "invalid admin key")


def _check(req: ToolCallRequest) -> tuple[Decision, int]:
    """Evaluate, log and (if needed) open an approval request. Shared by both modes."""
    with telemetry.span("tool_call", **{"agent.id": req.agent_id, "tool.name": req.tool}) as s:
        try:
            decision = evaluate(req)
        except Exception as e:  # fail closed: if anything breaks, deny
            decision = Decision(Verdict.BLOCK, f"firewall error, failing closed: {e}")
        call_id = audit.log_call(req, decision)
        if decision.verdict == Verdict.NEEDS_APPROVAL:
            ttl = int(get_policy(req.agent_id).get("approval_ttl_seconds", 300))
            approvals.create(call_id, ttl)
        s.set_attribute("call_id", call_id)
        s.set_attribute("verdict", decision.verdict.value)
        s.set_attribute("reason", decision.reason)
        if decision.risk_score is not None:
            s.set_attribute("risk_score", decision.risk_score)
    risk = f" risk={decision.risk_score:.2f}" if decision.risk_score is not None else ""
    log.info("call=%s agent=%s tool=%s %s%s %s", call_id, req.agent_id, req.tool,
             ui.verdict(decision.verdict.value), risk, ui.c(decision.reason, "dim"))
    return decision, call_id


@app.post("/v1/tool-call", response_model=ToolCallResponse)
def tool_call(req: ToolCallRequest):
    decision, call_id = _check(req)
    return ToolCallResponse(call_id=call_id, verdict=decision.verdict,
                            reason=decision.reason, risk_score=decision.risk_score)


@app.post("/v1/execute", response_model=ExecuteResponse)
def execute(req: ToolCallRequest):
    decision, call_id = _check(req)
    result = error = None
    if decision.verdict == Verdict.NEEDS_APPROVAL:
        executions.mark_awaiting(call_id)  # on approval the firewall will run the stored call
    if decision.verdict == Verdict.ALLOW:
        with telemetry.span("execute", **{"tool.name": req.tool, "call_id": call_id}) as s:
            result, error = executions.run_call(call_id, req.tool, req.args)
            if error:
                s.set_attribute("error", error)
        if error:
            log.info("call=%s %s", call_id, ui.c(f"tool error: {error}", "red"))
    return ExecuteResponse(call_id=call_id, verdict=decision.verdict, reason=decision.reason,
                           risk_score=decision.risk_score, result=result, error=error)


@app.get("/v1/executions/{call_id}")
def execution_status(call_id: int, agent_id: str):
    """The agent polls this while a call waits for a human. Returns the result once it has run."""
    call = executions.load_call(call_id)
    if call is None or call["agent_id"] != agent_id:
        raise HTTPException(404, "unknown call")
    ex = executions.get(call_id)
    if ex and ex["status"] == "done":
        return {"call_id": call_id, "status": "done",
                "result": json.loads(ex["result"]) if ex["result"] else None, "error": ex["error"]}
    status = approvals.get_status(call_id)
    if status in ("denied", "expired"):
        return {"call_id": call_id, "status": status}
    return {"call_id": call_id, "status": "pending"}


@app.get("/v1/approvals", dependencies=[Depends(require_admin)])
def list_approvals():
    return approvals.list_pending()


@app.get("/v1/approvals/{call_id}")
def approval_status(call_id: int):
    status = approvals.get_status(call_id)
    if status is None:
        raise HTTPException(404, "no approval request for this call")
    return {"call_id": call_id, "status": status}


def _decide(call_id: int, approve: bool, reviewer: str):
    with telemetry.span("approval.decide", call_id=call_id, approved=approve, reviewer=reviewer):
        try:
            status = approvals.decide(call_id, approve, reviewer)
        except ValueError as e:
            raise HTTPException(409, str(e))
    log.info("call=%s %s by %s", call_id,
             ui.c("APPROVED", "green", "bold") if approve else ui.c("DENIED", "red", "bold"), reviewer)
    if approve:
        call = executions.load_call(call_id)
        if call is not None:  # runs only proxy-mode calls, with the arguments stored when they were checked.
            executions.run_call(call_id, call["tool"], call["args"], from_approval=True)
            # (in check mode the agent polls /v1/approvals and runs the tool itself)
    return {"call_id": call_id, "status": status}


@app.post("/v1/approvals/{call_id}/approve", dependencies=[Depends(require_admin)])
def approve(call_id: int, reviewer: str = "human"):
    return _decide(call_id, True, reviewer)


@app.post("/v1/approvals/{call_id}/deny", dependencies=[Depends(require_admin)])
def deny(call_id: int, reviewer: str = "human"):
    return _decide(call_id, False, reviewer)


@app.get("/v1/audit")
def audit_log(limit: int = 20):
    return audit.recent(limit)


@app.get("/health")
def health():
    return {"status": "ok"}