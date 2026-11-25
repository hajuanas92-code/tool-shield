"""Terminal colours (ASCII only, so it works on every terminal). Colours switch off automatically when the
output is piped to a file, or when NO_COLOR is set. Set FORCE_COLOR=1 to keep them (e.g. in Docker logs)."""
import json
import os
import sys

if os.name == "nt":
    os.system("")  # makes Windows terminals understand ANSI colour codes

_RESET = "\033[0m"
_CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33",
          "blue": "34", "magenta": "35", "cyan": "36"}
_VERDICT = {"ALLOW": ("green",), "BLOCK": ("red", "bold"), "NEEDS_APPROVAL": ("yellow", "bold")}


def _enabled() -> bool:
    if "NO_COLOR" in os.environ:
        return False
    return bool(os.environ.get("FORCE_COLOR")) or sys.stdout.isatty()


def c(text, *styles) -> str:
    if not styles or not _enabled():
        return str(text)
    return f"\033[{';'.join(_CODES[s] for s in styles)}m{text}{_RESET}"


def verdict(v: str) -> str:
    return c(f"[{v}]", *_VERDICT.get(v, ("bold",)))


def tool_line(tool: str, args: dict, out: dict) -> str:
    shown = json.dumps(args, default=str)
    if len(shown) > 110:
        shown = shown[:107] + "..."
    line = f"{c('TOOL', 'cyan', 'bold')} {c(tool, 'bold')} {c(shown, 'dim')} -> {verdict(out['verdict'])}"
    if out["verdict"] != "ALLOW" and out.get("reason"):
        line += f" {c(out['reason'], 'dim')}"
    if out.get("error"):
        line += f" {c('error: ' + str(out['error']), 'red')}"
    return line


def print_tool_call(tool: str, args: dict, out: dict) -> None:
    print(tool_line(tool, args, out), flush=True)


def info(msg: str) -> None:
    print(f"{c('INFO', 'blue', 'bold')} {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"{c('OK', 'green', 'bold')} {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"{c('WAIT', 'yellow', 'bold')} {msg}", flush=True)


def error(msg: str) -> None:
    print(f"{c('ERROR', 'red', 'bold')} {msg}", flush=True)