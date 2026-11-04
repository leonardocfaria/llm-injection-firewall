# Latency benchmark

`python bench.py 300` on x86_64, Python 3.13.18, single client, localhost, mock upstream.

| case | p50 ms | p95 ms | p99 ms | mean ms |
|---|---|---|---|---|
| policy.apply, short chat | 0.03 | 0.05 | 0.07 | 0.04 |
| policy.apply, chat + 3039-char tool doc | 1.34 | 2.51 | 4.18 | 1.56 |
| HTTP direct to mock, short chat | 1.07 | 1.32 | 1.53 | 1.07 |
| HTTP through firewall, short chat | 2.47 | 3.34 | 6.30 | 2.57 |
| HTTP through firewall, chat + tool doc | 4.04 | 5.16 | 6.86 | 4.33 |

Firewall overhead on a short chat (p50 difference): 1.40 ms.
