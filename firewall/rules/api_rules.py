"""Business-rule checks for the refund and email tools."""
import math

from decision import Decision, Verdict


def _block(reason: str) -> Decision:
    return Decision(Verdict.BLOCK, reason)


def check_refund(args: dict, policy: dict) -> Decision:
    cfg = policy.get("refund", {})
    auto_max = float(cfg.get("auto_approve_max", 100))
    hard_limit = float(cfg.get("hard_limit", 1000))
    try:
        amount = float(args.get("amount"))
    except (TypeError, ValueError):
        return _block("refund amount is missing or not a number")
    if not math.isfinite(amount) or amount <= 0:
        return _block("refund amount must be a positive number")
    if amount > hard_limit:
        return _block(f"refund of {amount:.2f} exceeds the hard limit of {hard_limit:.2f}")
    if amount > auto_max:
        return Decision(Verdict.NEEDS_APPROVAL,
                        f"refund of {amount:.2f} is above the auto-approve limit of {auto_max:.2f}")
    return Decision(Verdict.ALLOW, f"refund of {amount:.2f} is within the auto-approve limit")


def check_email(args: dict, policy: dict) -> Decision:
    cfg = policy.get("email", {})
    domains = {d.lower() for d in cfg.get("allowed_domains", [])}
    max_body = int(cfg.get("max_body_chars", 2000))

    to = args.get("to")
    if not isinstance(to, str) or to.count("@") != 1 or any(c in to for c in " ,;<>"):
        return _block("recipient must be a single valid email address")
    domain = to.rsplit("@", 1)[1].strip().lower()
    if domain not in domains:
        return _block(f"recipient domain '{domain}' is not on the allowlist")
    body = args.get("body") or ""
    if len(str(body)) > max_body:
        return Decision(Verdict.NEEDS_APPROVAL,
                        f"email body is {len(str(body))} chars (limit {max_body}); possible data dump")
    return Decision(Verdict.ALLOW, "recipient domain is allowlisted")