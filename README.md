# SentinelForge

**Security regression testing for LLM apps, RAG pipelines and AI agents.**

SentinelForge runs deterministic security tests against an AI application, turns confirmed findings into
reproducible regression tests, and shows the evidence in a local dashboard. It is a testing aid, not a guarantee of
security: a clean run only means the configured tests found no failure under the tested conditions.

- **Find → verify → regress.** Failed cases are re-run to confirm them, then saved as pytest regression tests.
- **Deterministic by default.** No LLM judge. Every verdict is a reproducible assertion.
- **Safe by default.** Synthetic canaries, mock tools, explicit scope, bounded budgets, redacted evidence.
- **Local first.** Runs offline against bundled demo apps. Nothing leaves your machine.

> [!IMPORTANT]
> SentinelForge is a free, open-source community project. It exists to help people test **their own** AI
> applications, content and infrastructure. Use it fairly and lawfully, and only on systems you own or are
> explicitly authorized to test. Any illegal use is strictly prohibited. See [Responsible use](#responsible-use).

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

## Screenshots

The dashboard running against the bundled demo apps.

### Security Scans
Pick a target and packs, run the tests, and see the CI gate verdict and pass-rate trend.

![Security Scans: run launcher, CI policy gate and pass-rate trend](docs/screenshots/scans.png)

### Findings & Verification
A failing run on the vulnerable demo: every finding shows the payload, the redacted response, expected vs. observed, and the fix.

![Findings: 11 confirmed findings with evidence and remediation, CI gate blocked](docs/screenshots/findings.png)

### Regression Tests
Saved findings replayed against a target, with the exported pytest file alongside.

![Regression Tests: replay results and exported pytest file](docs/screenshots/regressions.png)

### Evaluation Matrix
Precision, recall and stability of the checks, measured on labeled vulnerable and safe fixtures.

![Evaluation Matrix: precision, recall, confusion matrix](docs/screenshots/evaluation.png)

### Exploit Lab
Mutate a payload and see which variants get past the target.

![Exploit Lab: payload library and fuzzing mutation matrix](docs/screenshots/exploit-lab.png)

### Settings
Allowed tools, canaries, limits and the CI failure threshold.

![Settings: allowed tools, canaries, limits and CI threshold](docs/screenshots/settings.png)

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

### Network exposure check (nmap)

Flags open TCP ports on your app's host that you did not expect, such as an exposed Redis, vector DB, Ollama or Jupyter. Needs [nmap](https://nmap.org/download) installed (`winget install Insecure.Nmap`).

```bash
sentinelforge exposure localhost --expect 8000                              # loopback needs no confirmation
sentinelforge exposure app.example.com --expect 443 --authorized            # non-local hosts need --authorized
```

Scope rules: one host per scan (no ranges or CIDR), fixed nmap arguments (TCP connect scan, no scripts, no service or OS detection), at most 100 ports. An open port proves reachability only, not that the service is unauthenticated. Results are saved as a run (`POST /api/exposure` for the API) and show up in History, Findings and SARIF. They cannot yet be saved as regression tests.

Data (runs, regressions, settings) is stored in SQLite at `.sentinelforge/sentinelforge.db` in the directory you start the CLI or API from; set `SENTINELFORGE_HOME` to move it. JSON data from earlier versions is imported automatically on first start.

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

## Responsible use

SentinelForge is an open-source project built to help the community test the security of their own AI
applications and personal content. Fair, lawful use is the intention.

**You may** use it to test applications, content, hosts and networks that you own, or that you have explicit
written permission to test.

**You must not** use it to:

- scan, probe or attack systems you do not own or are not authorized to test
- access, extract or disclose data that is not yours
- disrupt, degrade or damage any service
- break any law, regulation, contract or terms of service that applies to you

**Any illegal activity is strictly prohibited.** You are solely responsible for how you use this software and
for having the authorization to do so. The built-in safeguards (explicit authorization, host allow-lists,
fixed non-intrusive nmap arguments, bounded budgets) reduce the risk of misuse, but they do not make an
unauthorized test lawful.

The software is provided "as is", without warranty of any kind, as set out in the [license](LICENSE). The
authors and contributors accept no liability for misuse or for any damage caused by it.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Please follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
