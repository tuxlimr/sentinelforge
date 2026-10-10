# SentinelForge

**Security regression testing for LLM apps, RAG pipelines and AI agents.**

SentinelForge runs deterministic security tests against an AI application, turns confirmed findings into
reproducible regression tests, and shows the evidence in a local dashboard. It is a testing aid, not a guarantee of
security: a clean run only means the configured tests found no failure under the tested conditions.

- **Find → verify → regress.** Failed cases are re-run to confirm them, then saved as pytest regression tests.
- **Deterministic by default.** No LLM judge. Every verdict is a reproducible assertion.
- **Safe by default.** Synthetic canaries, mock tools, explicit scope, bounded budgets, redacted evidence.
- **Local first.** Runs offline against bundled demo apps. Nothing leaves your machine.

## What is in the box

| Area | What it does |
|---|---|
| Security Scans | Run 11 tests across 3 packs (prompt injection, canary leakage, tool permissions) and see a CI gate verdict |
| Findings & Verification | Evidence, expected vs. observed, remediation, and a Find → Verify → Regress lifecycle |
| Regression Tests | Saved findings, replay against a target, export as a pytest file |
| Evaluation Matrix | Precision, recall and stability of the checks, measured on labeled vulnerable and safe fixtures |
| Exploit Lab | Mutate a payload (base64, leetspeak, roleplay, …) and see which variants get through |
| Settings | Allowed tools, canaries, limits and the CI failure threshold |

Reports can be exported as JSON or SARIF 2.1.0.

## Quick start

Requires Python 3.14 and Node 20+.

```bash
# Backend
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e "backend[dev]"
sentinelforge serve                                    # API on http://127.0.0.1:8000

# Frontend (second terminal)
cd frontend && npm install && npm run dev              # UI on http://localhost:5173
```

Open http://localhost:5173, choose **Vulnerable demo**, and run the scan.

### CLI and CI

```bash
sentinelforge test --target safe_demo --fail-on high   # exit 1 on a confirmed finding at or above "high"
```

Run the tests: `cd backend && python -m pytest`

## Project layout

```text
backend/    Python 3.14 + FastAPI: engine, test packs, adapters, storage, CLI
frontend/   React + Vite + TypeScript dashboard
docs/       Architecture, getting started, writing tests
project.md  Full product specification and roadmap
```

## Documentation

- [Getting started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Writing test cases and packs](docs/test-authoring.md)
- [Safety and scope](docs/safety-and-scope.md)
- [Product specification](project.md)

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Please follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
