"""
The decision engine: deterministic rules + optional ML injection classifier, strictest verdict wins.
Same evaluate() signature since step 3. Spans (no-ops unless tracing is on) show where time goes.
"""
from decision import Decision, Verdict
from models import ToolCallRequest
from policy import get_policy
from risk import combine, ml_decision
from rules.api_rules import check_email, check_refund
from rules.shell_rules import check_shell
from rules.sql_rules import check_sql
from telemetry import span

READ_ONLY = {"list_emails", "read_email"}
CHECKERS = {
    "run_sql": check_sql,
    "run_shell": check_shell,
    "issue_refund": check_refund,
    "send_email": check_email,
}


def evaluate(req: ToolCallRequest) -> Decision:
    policy = get_policy(req.agent_id)
    if req.tool not in policy.get("allowed_tools", []):
        return Decision(Verdict.BLOCK, f"tool '{req.tool}' is not allowed for this agent")
    if req.tool in READ_ONLY:
        return Decision(Verdict.ALLOW, "read-only tool")
    checker = CHECKERS.get(req.tool)
    if checker is None:
        return Decision(Verdict.BLOCK, f"no rules defined for '{req.tool}'; denying by default")

    with span("rules", **{"tool.name": req.tool}) as s:
        decision = checker(req.args, policy)
        s.set_attribute("rules.verdict", decision.verdict.value)

    cfg = policy.get("classifier", {})
    if cfg.get("enabled") and req.context:
        from classifier import score_context  # imported lazily: only needed when enabled
        with span("classifier", **{"context.chunks": len(req.context)}) as s:
            risk = score_context(req.context)
            s.set_attribute("classifier.risk", risk)
        decision = combine(decision, ml_decision(risk, cfg))
    return decision