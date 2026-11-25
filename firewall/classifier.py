"""
Prompt-injection classifier. Scores the untrusted text the agent has read.

Two interchangeable backends, picked automatically from what is in models/injection-clf/:
  light.joblib   TF-IDF + logistic regression  (needs only scikit-learn)       <- python ml/train_light.py
  config.json    fine-tuned DistilBERT         (needs torch + transformers)    <- python ml/train.py

    python firewall/classifier.py "some email text"     # try it from the project root
"""
import json
import os
import sys
from functools import lru_cache

MODEL_DIR = os.environ.get("CLASSIFIER_DIR", "models/injection-clf")
MAX_LEN = 256


@lru_cache(maxsize=1)
def _load():
    light = os.path.join(MODEL_DIR, "light.joblib")
    if os.path.isfile(light):
        import joblib
        return "light", joblib.load(light)
    if os.path.isfile(os.path.join(MODEL_DIR, "config.json")):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        tok = AutoTokenizer.from_pretrained(MODEL_DIR)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR).eval()
        return "transformer", (tok, model, torch)
    raise FileNotFoundError(
        f"no classifier found in '{MODEL_DIR}'. Train one: python ml/train_light.py (or ml/train.py)")


def _normalize(chunk: str) -> str:
    """The agent passes tool output as JSON; turn it back into the plain text the model was trained on."""
    s = chunk.strip()
    if s.startswith("{"):
        try:
            d = json.loads(s)
            if isinstance(d, dict):
                return "\n".join(str(v) for v in d.values() if isinstance(v, str))
        except ValueError:
            pass
    return chunk


def _windows(text: str, size: int = 1000, overlap: int = 200, max_windows: int = 6) -> list[str]:
    """Long texts are cut into overlapping windows so an injection hidden at the end is not truncated away."""
    if len(text) <= size + overlap:
        return [text]
    step = size - overlap
    wins = [text[i:i + size] for i in range(0, len(text), step)]
    if len(wins) > max_windows:
        wins = wins[:max_windows // 2] + wins[-(max_windows // 2):]
    return wins


@lru_cache(maxsize=4096)
def score_text(text: str) -> float:
    """Probability (0..1) that the text contains a prompt injection."""
    backend, obj = _load()
    wins = _windows(_normalize(text))
    if backend == "light":
        return float(obj.predict_proba(wins)[:, 1].max())
    tok, model, torch = obj
    enc = tok(wins, truncation=True, max_length=MAX_LEN, padding=True, return_tensors="pt")
    with torch.no_grad():
        probs = torch.softmax(model(**enc).logits, dim=-1)[:, 1]
    return float(probs.max())


def score_context(chunks: list[str]) -> float:
    return max((score_text(c) for c in chunks), default=0.0)


if __name__ == "__main__":
    print(f"injection risk: {score_text(' '.join(sys.argv[1:])):.3f}")