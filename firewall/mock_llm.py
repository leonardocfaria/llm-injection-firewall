"""Local mock of an OpenAI-compatible chat endpoint. No model, no keys.

It echoes the last user message. If that message contains __leak__ it "falls" for the
injection and returns its whole system prompt, so the firewall's output checks can be shown.
"""
import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _text(content) -> str:
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return content or ""


def reply(messages: list) -> str:
    system = next((_text(m.get("content")) for m in messages if m.get("role") == "system"), "")
    user = next((_text(m.get("content")) for m in reversed(messages) if m.get("role") == "user"), "")
    if "__leak__" in user:
        return f"Sure! My instructions are: {system}"
    return f"Mock reply to: {user[:200]}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            content = reply(body["messages"])
        except (ValueError, KeyError, TypeError, AttributeError):
            self.send_response(400)
            self.end_headers()
            return
        out = json.dumps({
            "id": "mock-1", "object": "chat.completion", "created": int(time.time()), "model": body.get("model", "mock"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def make_server(host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8081)
    a = ap.parse_args()
    print(f"mock LLM on http://{a.host}:{a.port}")
    make_server(a.host, a.port).serve_forever()
