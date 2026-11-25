"""
Score the demo inbox (data/emails.json) with the trained classifier.
    python ml/eval_emails.py
Note: those emails come from the same project, so treat this as a sanity check, not a benchmark.
"""
import json
import sys
from collections import defaultdict

sys.path.insert(0, "firewall")
from classifier import score_text  # noqa: E402

emails = json.load(open("data/emails.json"))
scored = [(score_text(f"{e['from']}\n{e['subject']}\n{e['body']}"), e) for e in emails]

for thr in (0.5, 0.9):
    tp = sum(1 for s, e in scored if e["is_poisoned"] and s >= thr)
    fn = sum(1 for s, e in scored if e["is_poisoned"] and s < thr)
    fp = sum(1 for s, e in scored if not e["is_poisoned"] and s >= thr)
    tn = sum(1 for s, e in scored if not e["is_poisoned"] and s < thr)
    print(f"threshold {thr}: caught {tp}/{tp + fn} poisoned, flagged {fp}/{fp + tn} benign")

by = defaultdict(list)
for s, e in scored:
    if e["is_poisoned"]:
        by[e["attack_type"]].append(s)
print("\nmean score per attack type:")
for k, v in sorted(by.items()):
    print(f"  {k:22s} {sum(v) / len(v):.2f}  (min {min(v):.2f})")

print("\nmissed (poisoned, score < 0.5):")
for s, e in scored:
    if e["is_poisoned"] and s < 0.5:
        print(f"  #{e['id']} {s:.2f} {e['attack_type']}: {e['subject']}")
print("\nfalse alarms (benign, score >= 0.5):")
for s, e in scored:
    if not e["is_poisoned"] and s >= 0.5:
        print(f"  #{e['id']} {s:.2f}: {e['subject']}")