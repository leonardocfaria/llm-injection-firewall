"""Fast heuristic prompt-injection rules: weighted regexes over normalised text."""
import re
import unicodedata

# Unicode "tag" characters (U+E0020-E007E) mirror ASCII invisibly ("ASCII smuggling"): map them back.
_TAGS = {0xE0000 + c: c for c in range(0x20, 0x7F)}

# (name, weight in [0,1], pattern). Patterns run on normalize()d text.
_RULES = [
    ("ignore_instructions", 0.95,
     r"\b(ignore|disregard|forget|override|bypass|skip)\b.{0,40}\b(previous|prior|above|earlier|preceding|all|your|the|any|initial|original)\b.{0,30}"
     r"\b(instructions?|directions|prompts?|rules|directives|guidelines|context|messages?|commands?)\b"),
    ("new_instructions", 0.7,
     r"\b(new|updated|real|actual|true)\s+(system\s+)?(instructions?|rules|directives)\s*(:|are|follow)"),
    ("role_reset", 0.6,
     r"\b(you\s+are\s+now|from\s+now\s+on,?\s+you|act\s+as\s+(an?\s+)?(unrestricted|unfiltered|evil|jailbroken))"),
    ("jailbreak_persona", 0.9,
     r"\b(as\s+dan|dan\s+mode|dan(?=.{0,80}\b(anything|jailbr\w+|restrictions)\b)|do\s+anything\s+now|developer\s+mode|jailbreak(en)?|god\s*mode|no\s+(restrictions|limitations|filters|rules)|unfiltered\s+and\s+uncensored)\b"),
    ("prompt_exfiltration", 0.9,
     r"\b(reveal|print|show|repeat|output|display|leak|read|tell\s+me|what\s+(is|are|was|were))\b.{0,40}\b(system\s+prompt|initial\s+prompt|hidden\s+(prompt|instructions)|"
     r"(instructions|rules|prompt)\s+(that\s+)?you\s+(were|have\s+been)\s+given|"
     r"(your|the)\s+(instructions|rules|prompt)\s+(above|verbatim|word\s+for\s+word)|everything\s+above)"),
    ("fake_delimiter", 0.8,
     r"(<\s*/?\s*(system|im_start|im_end|instructions?)\s*>|\[/?(inst|system)\]|^#{2,}\s*(system|instruction)|<\|(im_start|im_end|system|endoftext)\|>)"),
    # Bounded on purpose: unbounded [^)]* runs here backtracked cubically on attacker text (ReDoS).
    ("exfil_markdown_image", 0.85, r"!\[[^\[\]\n]{0,200}\]\(\s*https?://[^()\s]{0,500}?[?&][^()\s=]{0,100}="),
    ("exfil_send_data", 0.8,
     r"\b(send|post|forward|upload|exfiltrate|email)\b.{0,60}\b(conversation|chat\s+history|password|api\s+key|credentials|secrets?|tokens?|user\s+data)\b.{0,40}\b(to|at)\b"),
    ("tool_hijack", 0.75,
     r"\b(call|invoke|execute|run|use)\s+(the\s+)?([\w-]+\s+)?(tool|function)\b.{0,40}\b(without|instead|immediately|silently|do\s+not\s+tell)"),
    ("hidden_from_user", 0.7, r"\b(do\s+not|don'?t|never)\s+(tell|inform|mention\s+(this\s+)?to|reveal\s+(this\s+)?to|let)\s+the\s+user\b"),
    ("ai_addressing_doc", 0.6,
     r"\b(attention|note|important|instructions?)\s+(to|for)\s+(the\s+)?(ai|assistant|llm|language\s+model|chatbot|agent)\b"),
    ("base64_blob", 0.5, r"\b(decode|base64)\b.{0,40}[a-z0-9+/]{40,}={0,2}"),
]
_COMPILED = [(n, w, re.compile(p, re.I | re.M | re.S)) for n, w, p in _RULES]


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text.translate(_TAGS))
    # drop invisible format characters (zero-width, bidi controls, soft hyphen, ...)
    text = "".join(c for c in text if unicodedata.category(c) != "Cf").lower()
    # "i g n o r e  a l l" -> "ignore all": join runs of 3+ single characters, before collapsing spaces
    text = re.sub(r"\b(?:\w ){2,}\w\b", lambda m: m.group(0).replace(" ", ""), text)
    return re.sub(r"[ \t]+", " ", text)


def score(text: str) -> tuple[float, list[str]]:
    """Return (max weight of matching rules, names of matching rules)."""
    t = normalize(text)
    hits = [(n, w) for n, w, rx in _COMPILED if rx.search(t)]
    return (max((w for _, w in hits), default=0.0), [n for n, _ in hits])
