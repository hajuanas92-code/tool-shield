from firewall.decision import Decision, Verdict
from firewall.risk import combine, ml_decision

CFG = {"approval_threshold": 0.5, "block_threshold": 0.9}
ALLOW = Decision(Verdict.ALLOW, "rules ok")
ASK = Decision(Verdict.NEEDS_APPROVAL, "rules ask")
BLOCK = Decision(Verdict.BLOCK, "rules block")


def test_thresholds():
    assert ml_decision(0.10, CFG).verdict == Verdict.ALLOW
    assert ml_decision(0.50, CFG).verdict == Verdict.NEEDS_APPROVAL
    assert ml_decision(0.89, CFG).verdict == Verdict.NEEDS_APPROVAL
    assert ml_decision(0.90, CFG).verdict == Verdict.BLOCK


def test_strictest_wins():
    assert combine(ALLOW, ml_decision(0.95, CFG)).verdict == Verdict.BLOCK
    assert combine(ALLOW, ml_decision(0.60, CFG)).verdict == Verdict.NEEDS_APPROVAL
    assert combine(BLOCK, ml_decision(0.01, CFG)).verdict == Verdict.BLOCK    # low risk never overrides rules
    assert combine(ASK, ml_decision(0.01, CFG)).verdict == Verdict.NEEDS_APPROVAL
    assert combine(ALLOW, ml_decision(0.01, CFG)).verdict == Verdict.ALLOW


def test_risk_score_kept_and_reasons_merged():
    d = combine(ASK, ml_decision(0.60, CFG))
    assert d.risk_score == 0.60
    assert "rules ask" in d.reason and "injection" in d.reason