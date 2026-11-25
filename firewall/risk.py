"""Turns an injection-risk score into a Decision and combines it with the rules' Decision (strictest wins)."""
from decision import Decision, Verdict

_RANK = {Verdict.ALLOW: 0, Verdict.NEEDS_APPROVAL: 1, Verdict.BLOCK: 2}


def ml_decision(risk: float, cfg: dict) -> Decision:
    block = float(cfg.get("block_threshold", 0.9))
    approve = float(cfg.get("approval_threshold", 0.5))
    if risk >= block:
        return Decision(Verdict.BLOCK,
                        f"likely prompt injection in content the agent read (risk {risk:.2f})", risk)
    if risk >= approve:
        return Decision(Verdict.NEEDS_APPROVAL,
                        f"possible prompt injection in content the agent read (risk {risk:.2f})", risk)
    return Decision(Verdict.ALLOW, f"low injection risk ({risk:.2f})", risk)


def combine(rules: Decision, ml: Decision) -> Decision:
    top = ml if _RANK[ml.verdict] > _RANK[rules.verdict] else rules
    reason = top.reason
    if _RANK[rules.verdict] == _RANK[ml.verdict] and rules.verdict != Verdict.ALLOW:
        reason = f"{rules.reason}; {ml.reason}"
    return Decision(top.verdict, reason, ml.risk_score)