"""Score untrusted messages and decide allow / redact / block."""
import copy
import hashlib
import re

from firewall import classifier, rules

REDACTED = "[REDACTED: possible prompt injection]"
INSPECTED_ROLES = {"user", "tool"}  # system/assistant are the app's own text
_SENTENCE = re.compile(r"[^.!?\n]+[.!?]*\s*|\n+")


CLASSIFIER_MIN_WORDS = 15  # the training prompts are long (median ~1.5k chars); on a few words the model is guessing


def inspect_text(text: str) -> dict:
    s, reasons = rules.score(text)
    p = classifier.default().predict_proba(text) if len(text.split()) >= CLASSIFIER_MIN_WORDS else 0.0
    if p >= 0.5:
        reasons = reasons + [f"classifier:{p:.2f}"]
    return {"score": round(max(s, p), 4), "reasons": reasons}


def _redact(text: str, redact_at: float) -> str:
    out, hit = [], False
    for m in _SENTENCE.finditer(text):
        chunk = m.group(0)
        if chunk.strip() and inspect_text(chunk)["score"] >= redact_at:
            out.append(REDACTED + chunk[len(chunk.rstrip()):])
            hit = True
        else:
            out.append(chunk)
    # The whole text scored high but no single sentence did: drop it all.
    return "".join(out) if hit else REDACTED


def _texts(msg: dict):
    """Yield (container, key) pairs holding the message's text, for plain and list-of-parts content."""
    c = msg.get("content")
    if isinstance(c, str):
        yield msg, "content"
    elif isinstance(c, list):
        for part in c:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                yield part, "text"


def apply(messages: list, redact_at: float = 0.5, block_at: float = 0.8) -> dict:
    """Return {"action", "messages" (possibly redacted copy), "findings"}. Input is not mutated."""
    messages = copy.deepcopy(messages)
    action, findings = "allow", []
    for i, msg in enumerate(messages):
        if not isinstance(msg, dict) or msg.get("role") not in INSPECTED_ROLES:
            continue
        for holder, key in _texts(msg):
            text = holder[key]
            r = inspect_text(text)
            if r["score"] < redact_at:
                continue
            # Tool documents are attacker-reachable but are not the user: redact them, never block on them.
            if msg["role"] == "user" and r["score"] >= block_at:
                verdict = "block"
            else:
                verdict = "redact"
                holder[key] = _redact(text, redact_at)
            findings.append({"index": i, "role": msg["role"], "action": verdict, **r, "snippet": text[:80],
                             "sha256": hashlib.sha256(text.encode()).hexdigest()})
            if verdict == "block":
                action = "block"
            elif action == "allow":
                action = "redact"
    return {"action": action, "messages": messages, "findings": findings}
