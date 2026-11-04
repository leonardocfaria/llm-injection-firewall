"""Prompt-injection firewall: an HTTP proxy for OpenAI-compatible /v1/chat/completions.

python -m firewall.proxy --upstream http://127.0.0.1:8081 --port 8080 --audit-log audit.jsonl
"""
import argparse
import html
import json
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from firewall import audit as audit_mod
from firewall import output_check, policy

MAX_BODY = 1_000_000
CHAT_PATH = "/v1/chat/completions"
BLOCKED_OUTPUT = "[blocked by llm-injection-firewall: the response leaked protected content]"


def check_response(resp, system: str | None, canary: str | None) -> list[str]:
    """Check every choice's text, refusal and tool-call arguments for leaks; blank out leaking choices in place."""
    reasons = []
    choices = resp.get("choices") if isinstance(resp, dict) else None
    for choice in choices if isinstance(choices, list) else []:
        msg = choice.get("message") if isinstance(choice, dict) else None
        if not isinstance(msg, dict):
            continue
        c = msg.get("content")
        texts = [c] if isinstance(c, str) else [p["text"] for p in c if isinstance(p, dict) and isinstance(p.get("text"), str)] if isinstance(c, list) else []
        texts += [msg["refusal"]] if isinstance(msg.get("refusal"), str) else []
        calls = msg.get("tool_calls") if isinstance(msg.get("tool_calls"), list) else []
        calls += [msg["function_call"]] if isinstance(msg.get("function_call"), dict) else []
        for call in calls:
            fn = call.get("function", call) if isinstance(call, dict) else None
            if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                texts.append(fn["arguments"])
        found = sorted({r for t in texts for r in output_check.check(t, system, canary)})
        if found:
            reasons += found
            msg["content"] = BLOCKED_OUTPUT
            for k in ("tool_calls", "function_call", "refusal"):
                msg.pop(k, None)
    return reasons


def _dashboard(events: list) -> bytes:
    e = html.escape
    rows = "".join(
        f"<tr class='{e(str(ev.get('action')))}'><td>{e(str(ev.get('ts', '')))}</td><td>{e(str(ev.get('request_id', '')))[:8]}</td>"
        f"<td>{e(str(ev.get('stage', '')))}</td><td>{e(str(ev.get('action', '')))}</td><td>{e(str(ev.get('score', '')))}</td>"
        f"<td>{e(', '.join(map(str, ev.get('reasons', []))))}</td><td>{e(str(ev.get('snippet', '')))}</td></tr>"
        for ev in reversed(events))
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="5">
<title>Injection firewall</title><style>
body{{font:14px system-ui,sans-serif;margin:16px;background:#fff;color:#111}} table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top}}
.block td:nth-child(4){{color:#b00020;font-weight:600}} .redact td:nth-child(4){{color:#a15c00;font-weight:600}}
.allow td:nth-child(4){{color:#1b6e20}}</style></head><body>
<h1>Recent decisions</h1><p>{len(events)} shown, newest first. Auto-refresh 5 s.</p>
<table><tr><th>time (UTC)</th><th>request</th><th>stage</th><th>action</th><th>score</th><th>reasons</th><th>snippet</th></tr>
{rows}</table></body></html>""".encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "llm-injection-firewall"
    timeout = 30  # a client that stalls mid-body must not hold a thread forever

    def log_message(self, *args):
        pass  # the audit log is the log

    def _send(self, code: int, body, ctype="application/json", headers=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _error(self, code: int, msg: str, etype="invalid_request_error", **extra):
        self._send(code, {"error": {"message": msg, "type": etype, **extra}})

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, {"ok": True})
        elif self.path == "/api/decisions":
            self._send(200, self.server.audit.recent())
        elif self.path in ("/", "/dashboard"):
            self._send(200, _dashboard(self.server.audit.recent()), "text/html; charset=utf-8")
        else:
            self._error(404, "not found")

    def do_POST(self):
        if self.path != CHAT_PATH:
            return self._error(404, "not found")
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length < 0:  # a negative length would make read() wait for EOF
                raise ValueError
        except ValueError:
            return self._error(400, "bad Content-Length")
        if length > MAX_BODY:
            self.close_connection = True  # don't read the oversized body
            return self._error(413, f"body larger than {MAX_BODY} bytes")
        try:
            body = json.loads(self.rfile.read(length))
        except (ValueError, RecursionError):  # RecursionError: absurdly deep nesting
            return self._error(400, "body is not valid JSON")
        if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
            return self._error(400, "'messages' must be a list")
        if body.get("stream"):
            # shortcut: no streaming, output checks need the full response; add chunk buffering if apps need it.
            return self._error(400, "stream=true is not supported by the firewall")

        rid, audit = uuid.uuid4().hex, self.server.audit
        try:
            decision = policy.apply(body["messages"], self.server.redact_at, self.server.block_at)
        except Exception as e:  # last resort: a request we cannot inspect is refused, never forwarded
            audit.log(request_id=rid, stage="input", action="error", reasons=[type(e).__name__])
            return self._error(400, "request could not be inspected", request_id=rid)
        top = max(decision["findings"], key=lambda f: f["score"], default={})
        audit.log(request_id=rid, stage="input", action=decision["action"], score=top.get("score", 0.0),
                  reasons=sorted({r for f in decision["findings"] for r in f["reasons"]}),
                  snippet=top.get("snippet", ""), findings=decision["findings"])
        if decision["action"] == "block":
            return self._error(403, "request blocked: possible prompt injection", "prompt_injection_blocked",
                               request_id=rid, reasons=sorted({r for f in decision["findings"] for r in f["reasons"]}))

        system = output_check.system_text(body["messages"])
        messages, canary = output_check.add_canary(decision["messages"])
        req = urllib.request.Request(self.server.upstream + CHAT_PATH, json.dumps({**body, "messages": messages}).encode(),
                                     {"Content-Type": "application/json",
                                      **({"Authorization": self.headers["Authorization"]} if self.headers.get("Authorization") else {})})
        try:
            with urllib.request.urlopen(req, timeout=self.server.timeout_s) as r:
                resp = json.loads(r.read())
        except urllib.error.HTTPError as e:
            # Pass upstream errors (429, 400, ...) through so clients can back off; there is no model output in them.
            audit.log(request_id=rid, stage="upstream", action="error", reasons=[f"upstream_http_{e.code}"])
            err = e.read()
            try:
                json.loads(err)
            except ValueError:
                return self._error(502, f"upstream returned HTTP {e.code}", "upstream_error", request_id=rid)
            return self._send(e.code, err)
        except (OSError, ValueError, RecursionError) as e:
            audit.log(request_id=rid, stage="upstream", action="error", reasons=[type(e).__name__])
            return self._error(502, "upstream unreachable or returned invalid JSON", "upstream_error", request_id=rid)

        out_reasons = check_response(resp, system, canary)
        if out_reasons:
            audit.log(request_id=rid, stage="output", action="block", score=1.0, reasons=sorted(set(out_reasons)))
        action = "block" if out_reasons else decision["action"]
        self._send(200, resp, headers={"X-Firewall-Action": action, "X-Firewall-Request-Id": rid})


def make_server(host: str, port: int, upstream: str, audit=None, redact_at=0.5, block_at=0.8, timeout_s=30):
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.upstream, srv.audit = upstream.rstrip("/"), audit or audit_mod.Audit(None)
    srv.redact_at, srv.block_at, srv.timeout_s = redact_at, block_at, timeout_s
    return srv


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--upstream", default="http://127.0.0.1:8081")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--audit-log", default="audit.jsonl")
    ap.add_argument("--redact-at", type=float, default=0.5)
    ap.add_argument("--block-at", type=float, default=0.8)
    a = ap.parse_args()
    print(f"firewall on http://{a.host}:{a.port} -> {a.upstream}  (dashboard: /dashboard)")
    make_server(a.host, a.port, a.upstream, audit_mod.Audit(a.audit_log), a.redact_at, a.block_at).serve_forever()
