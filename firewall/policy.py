"""Loads the YAML policy. If it cannot be loaded, evaluate() raises and main.py fails closed."""
import os
from functools import lru_cache

import yaml

POLICY_PATH = os.environ.get("POLICY_PATH", "policies/default.yaml")


@lru_cache(maxsize=1)
def _load() -> dict:
    with open(POLICY_PATH) as f:
        return yaml.safe_load(f)


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def get_policy(agent_id: str) -> dict:
    raw = _load()
    override = (raw.get("agents") or {}).get(agent_id)
    return _merge(raw["default"], override) if override else raw["default"]