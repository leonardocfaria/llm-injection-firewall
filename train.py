"""Train the injection classifier and write model/classifier.json + reports/classifier_eval.*.

Data: verazuo/jailbreak_llms (MIT licence), downloaded to data/raw/ and checked by sha256.
Usage: pip install -r requirements.txt && python train.py   (about 30 s on a laptop CPU)
"""
import csv
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

from firewall import rules
from firewall.classifier import MODEL_PATH, Classifier

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "data" / "raw"
BASE = "https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/"
FILES = {  # file -> (sha256, label)
    "jailbreak_prompts_2023_05_07.csv": ("6f0ccbea6c0118d4d563e885ae4c459980943c44b57fd66d6fbe7c869ab61e6b", 1),
    "regular_prompts_2023_05_07.csv": ("2286158d3078ac9624bf5f10e679c8db9d7549c882608638e4923a62fd7b6031", 0),
}
SEED = 42


def load_data() -> tuple[list[str], list[int]]:
    RAW.mkdir(parents=True, exist_ok=True)
    csv.field_size_limit(sys.maxsize)
    seen, texts, labels = set(), [], []
    for name, (sha, label) in FILES.items():
        path = RAW / name
        if not path.exists():
            urllib.request.urlretrieve(BASE + name, path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != sha:
            sys.exit(f"sha256 mismatch for {path}; delete it and retry")
        with path.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                t = row["prompt"].strip()
                if t and t not in seen:  # jailbreak file is read first, so duplicates keep label 1
                    seen.add(t)
                    texts.append(t)
                    labels.append(label)
    return texts, labels


def metrics(y_true, y_pred) -> dict:
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4),
            "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()}


def main():
    texts, labels = load_data()
    xtr, xte, ytr, yte = train_test_split(texts, labels, test_size=0.2, stratify=labels, random_state=SEED)
    vec = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), max_features=5000, min_df=2, sublinear_tf=True)
    lr = LogisticRegression(class_weight="balanced", max_iter=2000, random_state=SEED)
    lr.fit(vec.fit_transform(xtr), ytr)

    model = {"vocab": {k: int(v) for k, v in vec.vocabulary_.items()}, "idf": [round(x, 8) for x in vec.idf_],
             "coef": [round(x, 8) for x in lr.coef_[0]], "intercept": float(lr.intercept_[0]),
             "meta": {"dataset": "verazuo/jailbreak_llms 2023_05_07 (MIT)", "seed": SEED, "n_train": len(xtr)}}
    MODEL_PATH.parent.mkdir(exist_ok=True)
    MODEL_PATH.write_text(json.dumps(model, separators=(",", ":"), sort_keys=True))

    # The pure-Python scorer must agree with sklearn, otherwise the eval below would not describe the runtime.
    clf = Classifier.load(MODEL_PATH)
    sk = lr.predict_proba(vec.transform(xte))[:, 1]
    py = [clf.predict_proba(t) for t in xte]
    drift = max(abs(a - b) for a, b in zip(sk, py))
    assert drift < 1e-4, f"pure-Python scorer drifts from sklearn by {drift}"

    combined = [max(rules.score(t)[0], p) for t, p in zip(xte, py)]
    report = {
        "dataset": model["meta"]["dataset"], "seed": SEED, "n_train": len(xtr), "n_test": len(xte),
        "test_positives": sum(yte), "threshold": 0.5, "max_abs_drift_vs_sklearn": drift,
        "classifier": metrics(yte, [int(p >= 0.5) for p in py]),
        "rules_only": metrics(yte, [int(rules.score(t)[0] >= 0.5) for t in xte]),
        "rules_plus_classifier": metrics(yte, [int(s >= 0.5) for s in combined]),
    }
    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    (out / "classifier_eval.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = [f"# Classifier eval\n", f"Dataset: {report['dataset']}. Stratified 80/20 split, seed {SEED}.",
             f"Train {len(xtr)}, held-out test {len(xte)} ({sum(yte)} positives). Threshold 0.5.\n",
             "| scorer | precision | recall | F1 | confusion matrix [[TN, FP], [FN, TP]] |", "|---|---|---|---|---|"]
    for k in ("classifier", "rules_only", "rules_plus_classifier"):
        m = report[k]
        lines.append(f"| {k} | {m['precision']} | {m['recall']} | {m['f1']} | {m['confusion_matrix']} |")
    lines.append(f"\nPure-Python scorer vs sklearn max |diff| on test set: {drift:.2e}.")
    lines.append("\nCaveat: this dataset labels *jailbreaks*. Its 'regular' class contains hundreds of prompt templates that"
                 " start with 'Ignore all previous instructions...' (AIPRM style). The rules flag those on purpose, so the"
                 " rules' 'false positives' here are mostly instruction overrides the dataset does not count as jailbreaks."
                 " See reports/redteam.md for the injection-specific suite.")
    (out / "classifier_eval.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
