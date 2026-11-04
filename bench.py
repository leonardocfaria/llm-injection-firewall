"""Latency benchmark: policy alone, and proxy round trip vs calling the mock directly. Writes reports/latency.md.

python bench.py [n]   (default n=500, about 10 s on a laptop CPU)
"""
import json
import platform
import statistics
import sys
import threading
import time
import urllib.request
from pathlib import Path

from firewall import audit, mock_llm, policy, proxy

SHORT = [{"role": "system", "content": "You are a helpful assistant."},
         {"role": "user", "content": "What are three good things to do in Lisbon on a rainy day?"}]
LONG_DOC = " ".join(["The museum opens at nine and closes at six, with late opening on Thursdays."] * 40)
RAG = SHORT + [{"role": "tool", "content": LONG_DOC}]


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] * 1000


def timed(fn, n):
    fn()  # warm-up (loads the model)
    out = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t)
    return out


def post(url, msgs):
    req = urllib.request.Request(url + proxy.CHAT_PATH, json.dumps({"model": "mock", "messages": msgs}).encode(),
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        r.read()


def main(n=500):
    mock = mock_llm.make_server("127.0.0.1", 0)
    threading.Thread(target=mock.serve_forever, daemon=True).start()
    mock_url = f"http://127.0.0.1:{mock.server_address[1]}"
    fw = proxy.make_server("127.0.0.1", 0, mock_url, audit.Audit(None))
    threading.Thread(target=fw.serve_forever, daemon=True).start()
    fw_url = f"http://127.0.0.1:{fw.server_address[1]}"

    rows = {
        "policy.apply, short chat": timed(lambda: policy.apply(SHORT), n),
        f"policy.apply, chat + {len(LONG_DOC)}-char tool doc": timed(lambda: policy.apply(RAG), n),
        "HTTP direct to mock, short chat": timed(lambda: post(mock_url, SHORT), n),
        "HTTP through firewall, short chat": timed(lambda: post(fw_url, SHORT), n),
        "HTTP through firewall, chat + tool doc": timed(lambda: post(fw_url, RAG), n),
    }
    lines = ["# Latency benchmark\n", f"`python bench.py {n}` on {platform.processor() or platform.machine()}, "
             f"Python {platform.python_version()}, single client, localhost, mock upstream.\n",
             "| case | p50 ms | p95 ms | p99 ms | mean ms |", "|---|---|---|---|---|"]
    for k, xs in rows.items():
        lines.append(f"| {k} | {pct(xs, .5):.2f} | {pct(xs, .95):.2f} | {pct(xs, .99):.2f} | {statistics.mean(xs) * 1000:.2f} |")
    overhead = statistics.median(rows["HTTP through firewall, short chat"]) - statistics.median(rows["HTTP direct to mock, short chat"])
    lines.append(f"\nFirewall overhead on a short chat (p50 difference): {overhead * 1000:.2f} ms.")
    Path(__file__).with_name("reports").joinpath("latency.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    fw.shutdown()
    mock.shutdown()


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 500)
