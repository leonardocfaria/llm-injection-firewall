# Latency benchmark

`python bench.py 500` on x86_64, Python 3.13.18, single client, localhost, mock upstream.

| case | p50 ms | p95 ms | p99 ms | mean ms |
|---|---|---|---|---|
| policy.apply, short chat | 0.03 | 0.04 | 0.06 | 0.03 |
| policy.apply, chat + 3039-char tool doc | 1.14 | 1.88 | 2.08 | 1.26 |
| HTTP direct to mock, short chat | 1.03 | 1.56 | 2.01 | 1.07 |
| HTTP through firewall, short chat | 2.41 | 3.23 | 5.26 | 2.51 |
| HTTP through firewall, chat + tool doc | 3.59 | 4.59 | 5.52 | 3.77 |

Firewall overhead on a short chat (p50 difference): 1.38 ms.
