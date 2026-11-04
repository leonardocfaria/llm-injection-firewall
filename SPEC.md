# llm-injection-firewall

## Goal
Build "llm-injection-firewall": a prompt-injection firewall for LLM apps. A small HTTP proxy (Python, FastAPI or stdlib) placed in front of an OpenAI-compatible chat endpoint. It scores each incoming prompt and each retrieved/tool document with (1) fast heuristic rules, (2) a small trained classifier (for example TF-IDF + logistic regression, trained in-repo on public prompt-injection datasets with a documented licence, with a held-out eval reporting precision/recall/F1 and a confusion matrix), and (3) an output check for system-prompt leakage and canary tokens. Policies: allow / redact / block, with JSON audit logs and a tiny web dashboard of recent decisions. Use a local mock LLM for all tests and the demo (no real API keys). Include a docker-compose demo, a red-team test suite of attack strings, and a latency benchmark.

## Definition of done
- [ ] Proxy runs locally and applies allow/redact/block policies
- [ ] Classifier trained in-repo; eval report (P/R/F1, confusion matrix) committed under reports/
- [ ] Canary-token and system-prompt-leak output checks work
- [ ] Red-team test suite and unit tests pass with one command
- [ ] Dashboard shows recent decisions
- [ ] CI workflow runs the tests
- [ ] README with setup, usage, architecture, threat model and limitations
- [ ] Self code review done
- [ ] Draft PR open

