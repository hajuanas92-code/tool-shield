"""
Step 5b (lightweight): TF-IDF + logistic regression injection detector. No torch, no transformers.

    pip install scikit-learn joblib
    python ml/train_light.py        # reads data/train|val|test.jsonl, saves models/injection-clf/light.joblib

Trains in seconds on a laptop CPU; scoring takes about a millisecond.
"""
import json
import time
from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import FeatureUnion, Pipeline

OUT = Path("models/injection-clf")


def load(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def metrics(rows, probs, thr=0.5):
    y = np.array([r["label"] for r in rows]); pred = (probs >= thr).astype(int)
    pr, rc, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return f"precision {pr:.3f}  recall {rc:.3f}  F1 {f1:.3f}  false-positive-rate {fpr:.3f}  (n={len(y)})"


train, val, test = load("data/train.jsonl"), load("data/val.jsonl"), load("data/test.jsonl")

model = Pipeline([
    ("features", FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                 sublinear_tf=True, max_features=100_000)),
    ])),
    ("clf", LogisticRegression(C=10, max_iter=2000, class_weight="balanced")),
])

t0 = time.time()
model.fit([r["text"] for r in train], [r["label"] for r in train])
print(f"trained on {len(train)} rows in {time.time() - t0:.1f}s")

vp = model.predict_proba([r["text"] for r in val])[:, 1]
print("validation:", metrics(val, vp))

OUT.mkdir(parents=True, exist_ok=True)
joblib.dump(model, OUT / "light.joblib")
print(f"saved -> {OUT / 'light.joblib'}  ({(OUT / 'light.joblib').stat().st_size / 1e6:.1f} MB)")

probs = model.predict_proba([r["text"] for r in test])[:, 1]
print("\n=== TEST (held-out wordings, styles, attacker addresses) ===")
print("overall:", metrics(test, probs))
by = defaultdict(list)
for i, r in enumerate(test):
    by[r["source"].split(":")[0]].append(i)
for src, idx in sorted(by.items()):
    print(f"  {src:18s}", metrics([test[i] for i in idx], probs[idx]))

t0 = time.time()
model.predict_proba([r["text"] for r in test[:200]])
print(f"\nlatency: {(time.time() - t0) / 200 * 1000:.2f} ms per text")