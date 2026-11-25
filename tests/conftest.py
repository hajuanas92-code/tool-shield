import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("POLICY_PATH", str(ROOT / "policies" / "default.yaml"))
os.environ.setdefault("AUDIT_DB", str(ROOT / "data" / "audit_test.db"))
sys.path.insert(0, str(ROOT / "firewall"))