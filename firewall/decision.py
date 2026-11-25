"""Verdict and Decision types (kept free of heavy imports so rules stay easy to test)."""
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"


@dataclass
class Decision:
    verdict: Verdict
    reason: str
    risk_score: Optional[float] = None