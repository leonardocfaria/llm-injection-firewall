"""Score untrusted messages and decide allow / redact / block."""
import copy
import hashlib
import re

from firewall import classifier, rules

REDACTED = "[REDACTED: possible prompt injection]"
TRUSTED_ROLES = {"system", "developer", "assistant"}  # the app's own text; every other role is inspected
_SENTENCE = re.compile(r"[^.!?\n]+[.!?]*\s*|\n+")


CLASSIFIER_MIN_WORDS = 15  # the training prompts are long (median ~1.5k chars); on a few words the model is guessing


def inspect_text(text: str) -> dict:
    s, reasons = rules.score(text)
    p = classifier.default().predict_proba(text) if len(text.split()) >= CLASSIFIER_MIN_WORDS else 0.0
    if p >= 0.5:
        reasons = reasons + [f"classifier:{p:.2f}"]
    return {"score": round(max(s, p), 4), "reasons": reasons}


def _redact(text: str, redact_at: float) -> tuple[str, bool]:
    """Replace offending sentences. Returns (text, whether any sentence was replaced)."""
    out, hit = [], False
    for m in _SENTENCE.finditer(text):
        chunk = m.group(0)
        if chunk.strip() and inspect_text(chunk)["score"] >= redact_at:
            out.append(REDACTED + chunk[len(chunk.rstrip()):])
            hit = True
        else:
            out.append(chunk)
    return "".join(out), hit


def _texts(msg: dict) -> list:
    """(container, key) pairs holding the message's text, for plain and list-of-parts content."""
    c = msg.get("content")
    if isinstance(c, str):
        return [(msg, "content")]
    if isinstance(c, list):
        return [(p, "text") for p in c if isinstance(p, dict) and isinstance(p.get("text"), str)]
    return []


def apply(messages: list, redact_at: float = 0.5, block_at: float = 0.8) -> dict:
    """Return {"action", "messages" (possibly redacted copy), "findings"}. Input is not mutated."""
    messages = copy.deepcopy(messages)
    action, findings = "allow", []
    for i, msg in enumerate(messages):
        role = msg.get("role") if isinstance(msg, dict) else None
        if not isinstance(role, str) or role in TRUSTED_ROLES:
            continue
        parts = _texts(msg)
        # Score the parts joined, as the model will read them: an attack split across parts is still one attack.
        text = "\n".join(h[k] for h, k in parts)
        r = inspect_text(text)
        if r["score"] < redact_at:
            continue
        # Only the user can get a request blocked. Tool/function/other content is attacker-reachable but is
        # not the user, so it is redacted: a hostile web page must not be able to deny service to the user.
        if role == "user" and r["score"] >= block_at:
            verdict = "block"
        else:
            verdict = "redact"
            redacted = [_redact(h[k], redact_at) for h, k in parts]
            hit = any(changed for _, changed in redacted)
            for (h, k), (new, _) in zip(parts, redacted):
                h[k] = new if hit else REDACTED  # no single sentence crossed the bar: drop the whole message
        findings.append({"index": i, "role": role, "action": verdict, **r, "snippet": text[:80],
                         "sha256": hashlib.sha256(text.encode()).hexdigest()})
        if verdict == "block":
            action = "block"
        elif action == "allow":
            action = "redact"
    return {"action": action, "messages": messages, "findings": findings}
