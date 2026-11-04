"""Pure-Python inference for the TF-IDF + logistic-regression model exported by train.py.

Replicates sklearn's TfidfVectorizer(lowercase=True, ngram_range=(1, 2), sublinear_tf=True, norm="l2")
so the runtime needs no sklearn and never unpickles anything.
"""
import json
import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent.parent / "model" / "classifier.json"
_TOKEN = re.compile(r"(?u)\b\w\w+\b")  # sklearn's default token_pattern


class Classifier:
    def __init__(self, vocab: dict, idf: list, coef: list, intercept: float):
        self.vocab, self.idf, self.coef, self.intercept = vocab, idf, coef, intercept

    @classmethod
    def load(cls, path=MODEL_PATH) -> "Classifier":
        m = json.loads(Path(path).read_text())
        return cls(m["vocab"], m["idf"], m["coef"], m["intercept"])

    def predict_proba(self, text: str) -> float:
        """P(text is an injection / jailbreak)."""
        toks = _TOKEN.findall(text.lower())
        grams = toks + [f"{a} {b}" for a, b in zip(toks, toks[1:])]
        counts = Counter(i for i in map(self.vocab.get, grams) if i is not None)
        w = {i: (1 + math.log(c)) * self.idf[i] for i, c in counts.items()}
        norm = math.sqrt(sum(v * v for v in w.values())) or 1.0
        z = self.intercept + sum(v * self.coef[i] for i, v in w.items()) / norm
        return 1.0 / (1.0 + math.exp(-z)) if z > -700 else 0.0


@lru_cache(maxsize=1)
def default() -> Classifier:
    return Classifier.load()
