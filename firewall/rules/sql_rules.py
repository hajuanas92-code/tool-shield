"""Deterministic SQL checks using a real SQL parser (sqlglot), not string matching."""
import re

import sqlglot
from sqlglot import exp

from decision import Decision, Verdict

# the one non-SELECT command the agent legitimately needs: schema lookup
_PRAGMA = re.compile(r"^\s*PRAGMA\s+table_info\(\s*['\"]?(\w+)['\"]?\s*\)\s*;?\s*$", re.IGNORECASE)


def _block(reason: str) -> Decision:
    return Decision(Verdict.BLOCK, reason)


def _trivial_where(where) -> bool:
    """True for WHERE 1=1, WHERE 'a'='a', WHERE TRUE, ... OR 1=1 (matches every row)."""
    if isinstance(where.this, exp.Boolean):
        return True
    for node in where.find_all(exp.EQ):
        if (isinstance(node.left, exp.Literal) and isinstance(node.right, exp.Literal)
                and node.left.this == node.right.this):
            return True
    return False


def check_sql(args: dict, policy: dict) -> Decision:
    cfg = policy.get("sql", {})
    allowed = {t.lower() for t in cfg.get("allowed_tables", [])}
    bulk = {t.lower() for t in cfg.get("bulk_read_tables", [])}

    query = args.get("query")
    if not isinstance(query, str) or not query.strip():
        return _block("empty or missing SQL query")

    m = _PRAGMA.match(query)
    if m:
        table = m.group(1).lower()
        if table in allowed:
            return Decision(Verdict.ALLOW, f"schema lookup on allowed table '{table}'")
        return _block(f"schema lookup on table '{table}' is not allowed")

    try:
        stmts = [s for s in sqlglot.parse(query, read="sqlite") if s is not None]
    except Exception as e:
        return _block(f"SQL could not be parsed ({type(e).__name__}); denying")
    if len(stmts) != 1:
        return _block("exactly one SQL statement allowed (stacked queries are blocked)")

    stmt = stmts[0]
    kind = type(stmt)
    name = kind.__name__.upper()
    if kind not in (exp.Select, exp.Insert, exp.Update, exp.Delete):
        return _block(f"{name} statements are not allowed")

    tables = {t.name.lower() for t in stmt.find_all(exp.Table)}
    bad = sorted(tables - allowed)
    if bad:
        return _block(f"access to table(s) not on the allowlist: {', '.join(bad)}")

    where = stmt.args.get("where")
    unfiltered = where is None or _trivial_where(where)

    if kind is exp.Select:
        if tables & bulk and unfiltered and stmt.args.get("limit") is None:
            return Decision(Verdict.NEEDS_APPROVAL,
                            "unbounded read of a sensitive table (no WHERE/LIMIT)")
        return Decision(Verdict.ALLOW, "read-only query on allowed tables")

    if kind in (exp.Update, exp.Delete) and unfiltered:
        return _block(f"{name} without a real WHERE clause would affect every row")

    if kind is exp.Delete:
        return Decision(Verdict.NEEDS_APPROVAL, "DELETE requires human approval")

    return Decision(Verdict.ALLOW, f"{name} on allowed tables")