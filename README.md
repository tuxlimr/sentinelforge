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

Install the CLI from PyPI (the package is `sentinelforge-ai`; the command is `sentinelforge`). Python 3.11+.

```bash
pip install sentinelforge-ai
sentinelforge guide            # 2-minute offline tour, no API keys
```

### Run the dashboard from source

Requires Python 3.11+ and Node 20+.

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
sentinelforge guide                                   # 2-minute offline tour of the whole loop
sentinelforge test --target safe_demo --fail-on high  # exit 1 on a confirmed finding at or above "high"
```

### Testing your own app

Point SentinelForge at your app's HTTP endpoint with a `sentinelforge.yaml` file. Only test apps you own or are
authorized to test (see [Responsible use](#responsible-use)).

```bash
sentinelforge init --url https://your-app.example.com/api/ask   # writes sentinelforge.yaml + a CI workflow
# edit sentinelforge.yaml: set scope.authorization_confirmed: true once you have confirmed you may test it
export APP_TOKEN=...                                            # only if your endpoint needs auth
sentinelforge test --config sentinelforge.yaml                  # run the packs against your app
sentinelforge regressions add --run latest                      # lock in confirmed findings
sentinelforge regressions replay --config sentinelforge.yaml    # after your fix: exit 0 when all pass
sentinelforge regressions export --config sentinelforge.yaml -o tests/test_ai_security.py
```

Your endpoint receives `POST {"prompt": "...", "context": {...}}` and should return
`{"text": "...", "tool_calls": [{"name": "...", "args": {}}]}`. Plain text also works.

```yaml
version: 1
target:
  kind: http
  url: https://your-app.example.com/api/ask
  headers:
    Authorization: "Bearer ${APP_TOKEN}"   # secrets come from environment variables only
scope:
  authorization_confirmed: true            # never inferred from the URL
  allowed_hosts: [your-app.example.com]    # requests to any other host, or redirects, are blocked
  allowed_tools: [search_docs]             # any other tool your agent calls is a finding
limits: {max_cases: 30, timeout_seconds: 10, verify_repeats: 2}
tests:
  packs: [prompt_injection, canary_leakage, tool_permissions]
ci:
  fail_on: high
```

The config is validated strictly: unknown keys are errors (so a typo in a safety setting is never ignored),
sensitive headers must reference environment variables, and the exported pytest file reads those variables at
run time, so no secret is ever written to disk.

### Website security check

Checks a website you own (or are authorized to test) for common security misconfigurations and for front-end
libraries in a known-vulnerable range. Misconfigurations: missing security headers (CSP, HSTS, clickjacking,
nosniff, Referrer-Policy), weak cookie flags, software version disclosure, CORS that trusts any origin, exposed
`.git`, `.env` and `phpinfo()` files, directory listing, plain HTTP and invalid TLS certificates. Libraries:
jQuery, jQuery UI, Bootstrap, Lodash, Moment.js and AngularJS, read from script and stylesheet URLs on the page
(or a version banner in a same-host file) and compared to the published fix version. A match means that release
has a fix; it is not proof the site can be exploited.

```bash
sentinelforge webscan http://localhost:3000/                          # loopback needs no confirmation
sentinelforge webscan https://your-site.example.com/ --authorized     # only for sites you may test
```

It is passive: about a dozen ordinary GET requests, no attack payloads, no logins or form submissions, and
redirects to other hosts are never followed. Secret values found in exposed files are never stored, only their
names. A missing header is a weakness, not proof of an exploitable vulnerability, and it does not test for SQL
injection, XSS or broken access control; use an active scanner such as OWASP ZAP for those. Results are saved as a
run (`POST /api/webscan`) and appear in the dashboard.

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
