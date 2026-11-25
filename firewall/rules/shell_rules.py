"""Deterministic shell-command checks: allowlist of commands, no chaining, no paths outside the sandbox."""
import shlex

from decision import Decision, Verdict

# pipes, command chaining, redirection, substitution, variable expansion, newlines
_FORBIDDEN = ["|", ";", "&", "`", "$", ">", "<", "\n"]


def _block(reason: str) -> Decision:
    return Decision(Verdict.BLOCK, reason)


def check_shell(args: dict, policy: dict) -> Decision:
    allowed = set(policy.get("shell", {}).get("allowed_commands", []))
    cmd = args.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        return _block("empty or missing shell command")
    if any(c in cmd for c in _FORBIDDEN):
        return _block("pipes, chaining, redirection and substitution are not allowed")
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return _block("shell command could not be parsed")
    if not tokens or tokens[0] not in allowed:
        return _block(f"command '{tokens[0] if tokens else ''}' is not on the allowlist")
    for t in tokens[1:]:
        if t.startswith(("/", "~")) or "=/" in t or ".." in t.split("/"):
            return _block("path outside the sandbox is not allowed")
    return Decision(Verdict.ALLOW, "allowlisted command inside the sandbox")