# AI Security Testing Platform — Project Specification

**Working name:** SentinelForge  
**Repository name:** `sentinelforge`  
**Document type:** Product vision, architecture, roadmap, and implementation guide  
**Status:** Initial product specification  
**Audience:** Founder, contributors, AI coding agents, and early adopters

> **Product promise:** Continuously test AI applications for security failures, turn confirmed findings into reproducible regression tests, and help teams understand and fix risk before deployment.

---

## 1. Executive Summary

SentinelForge is an extensible, developer-first security testing platform for applications built with large language models (LLMs), retrieval-augmented generation (RAG), and tool-using AI agents.

The product begins as an open-source Python framework and command-line interface (CLI). It should later support CI/CD integrations, a local web dashboard, and an optional hosted SaaS product. The architecture must allow new test packs, model providers, agent frameworks, evaluators, and reporting integrations to be added without rewriting the core.

The platform is intended to help developers and security teams answer:

1. Can an attacker manipulate the system through untrusted input or retrieved content?
2. Can the application disclose protected data or cross tenant boundaries?
3. Can an agent use tools or perform actions beyond its authorization?
4. Do changes to prompts, models, policies, or retrieval pipelines introduce security regressions?
5. Can each finding be reproduced, explained, prioritized, and converted into a regression test?

SentinelForge is a **testing and assurance aid**, not a guarantee of security. Results must clearly distinguish observed evidence, heuristic signals, evaluator judgments, and untested areas.

## 2. Product Principles

- **Security by design:** Treat test inputs, model outputs, retrieved documents, tool results, plugins, and reports as untrusted data.
- **Evidence over claims:** A finding should include the test, expected behavior, observed behavior, evidence, confidence, and limitations.
- **Safe by default:** Use synthetic data, mock tools, non-destructive tests, explicit scope, and bounded resource use.
- **Developer-first:** Make the first successful scan easy to run locally and in CI.
- **Composable:** Keep the core independent from any one LLM provider or agent framework.
- **Reproducible:** Support stable test IDs, versioned test packs, saved run metadata, and regression replay.
- **Transparent evaluation:** Do not treat an LLM judge as ground truth. Use deterministic assertions where possible and label model-based evaluations.
- **Privacy-aware:** Avoid retaining prompts, outputs, secrets, or customer data by default. Redact sensitive content in logs.
- **Portable:** Core tests should run locally; a hosted service must be optional.
- **Honest reporting:** A clean scan means only that configured tests did not detect a failure under the tested conditions.
- **Open-core discipline:** Keep the community edition genuinely useful; charge for operational convenience and team-scale workflows rather than artificial limitations on basic safety.

## 3. Target Users

### Primary users
- Python developers shipping LLM features.
- Teams building RAG applications and AI agents.
- Platform engineers adding AI quality and security checks to CI/CD.
- Product security engineers assessing AI-specific risks.

### Secondary users
- AI platform teams managing many internal applications.
- Consultants and auditors who need repeatable, evidence-backed test reports.
- Researchers developing and comparing security test suites.

### Initial ideal customer profile
A small or medium software team with a Python-based LLM application, an existing CI pipeline, and no repeatable way to test AI security regressions.

## 4. Scope and Non-Goals

### In scope
- Authorized testing of AI applications and their exposed interfaces.
- Prompt-injection and instruction-boundary tests.
- Sensitive-data exposure checks using synthetic canaries or explicitly supplied test fixtures.
- Tool authorization and policy-enforcement tests in a sandbox or controlled test environment.
- RAG access-control and retrieval-boundary tests.
- Output-policy and unsafe-action checks.
- Reproducible findings, regression tests, reports, and CI exit codes.
- Extensible plugin interfaces and provider adapters.

### Out of scope for the initial releases
- Unrestricted autonomous attacks against public targets.
- Exploitation of third-party systems without authorization.
- Automatic destructive remediation in production.
- A claim that passing tests proves an AI system is secure.
- Building a foundation model or hosting customer models.
- Collecting customer prompts and outputs for training by default.
- A large multi-tenant cloud platform before the CLI and test engine prove useful.

## 5. Product Differentiation

A basic prompt list or one-off jailbreak scanner is not enough. SentinelForge should focus on **security regression testing and evidence management**.

Core differentiators:

1. **Find → verify → regress:** Convert a finding into a repeatable test that runs after relevant changes.
2. **Policy-aware testing:** Test against the application's explicit rules, data boundaries, and tool permissions.
3. **Agent-aware test orchestration:** Understand application components and run relevant tests with controlled budgets.
4. **Evidence-backed results:** Preserve sanitized evidence, reproducibility metadata, and evaluator limitations.
5. **CI-native operation:** Fail or warn builds according to a configurable policy.
6. **Provider and framework neutrality:** Support direct HTTP APIs and optional adapters without forcing a framework migration.
7. **Local-first operation:** Make useful testing possible without sending application data to a SentinelForge-hosted service.

## 6. MVP Definition

The first public release should be narrow, dependable, and easy to try.

### MVP features
- Python package and `sentinelforge` CLI.
- Configuration file with explicit target, scope, limits, and enabled test packs.
- A simple target interface for a local callable or an authorized HTTP endpoint.
- Test case schema with stable IDs, tags, risk category, expected behavior, and severity guidance.
- Initial deterministic checks:
  - expected refusal / policy behavior,
  - synthetic canary leakage,
  - basic prompt-injection resistance checks,
  - mock-tool authorization boundary checks.
- Optional model-based evaluator, disabled unless explicitly configured.
- JSON report and readable terminal summary.
- Exit codes suitable for CI.
- Saved regression cases for verified findings.
- Unit tests, type checks, linting, sample target, and a short quick-start guide.

### MVP success criteria
- A new developer can install the package and run a sample scan in under 10 minutes.
- A run is reproducible given the same target, test pack, configuration, and fixed fixtures, within documented provider variability.
- Each reported finding includes enough information to understand what was tested and why it failed.
- The CLI never executes arbitrary commands or destructive actions from model-generated output.
- Tests pass offline using mocks, with no API key required for the core sample.
- A small number of external developers can use the project without founder-led setup.

## 7. Feature Roadmap

### Phase 0 — Discovery and design
- Interview 10–15 developers or AI security practitioners.
- Review adjacent tools and public threat taxonomies.
- Pick one first integration and one first use case.
- Write the threat model and acceptance criteria.
- Validate the proposed CLI workflow before building a dashboard.

### Phase 1 — Open-source MVP
- Core test runner and case schema.
- Python SDK and CLI.
- Local callable and HTTP target adapters.
- Deterministic assertions and synthetic canary tests.
- JSON/Markdown reports.
- Basic CI examples for GitHub Actions.
- Versioned sample test packs.
- Documentation, contribution guide, license, and security policy.

### Phase 2 — Useful developer workflow
- RAG-specific checks with synthetic documents and user identities.
- Tool permission tests using mocks and explicit action allowlists.
- Regression test export and replay.
- Baseline comparison between two runs.
- SARIF output where findings map appropriately to supported fields.
- More detailed severity and confidence model.
- Test selection by changed prompt, model, tool, or retrieval configuration.
- Optional adapters for selected agent frameworks, added only after user demand.

### Phase 3 — Team readiness
- HTML report and local dashboard.
- Team-shared test suites and policy profiles.
- Run history, comparisons, and regression trends.
- Signed or checksummed test-pack releases.
- Role-based access control for hosted features.
- Audit events and configurable retention.
- Organization-wide policy templates.

### Phase 4 — Hosted product
- Multi-tenant hosted dashboard.
- Secure project and environment management.
- Scheduled testing and notifications.
- Private test suites and team collaboration.
- CI integrations and service accounts.
- Usage limits, metering, billing, and subscription management.
- Data retention controls and deletion workflows.
- Enterprise deployment options only after security review.

### Phase 5 — Advanced agentic capabilities
- Risk-based planning of test runs from an explicit threat model.
- Bounded agent that proposes test cases and test sequences.
- Human approval before active, intrusive, or state-changing tests.
- Controlled verification loops for suspected findings.
- Deduplication and clustering of similar findings.
- Suggested mitigations linked to evidence and regression tests.
- Human-reviewed test-pack contributions and quality scoring.

## 8. Agentic Maneuver: Controlled Security Orchestration

“Agentic maneuver” means the system can reason about which tests to run, adapt a bounded test plan based on observations, and verify candidate findings. It does **not** mean an unrestricted autonomous attacker.

### Agent workflow

1. **Scope:** Load the user's target declaration, authorization, allowed interfaces, time budget, request budget, and prohibited actions.
2. **Model:** Build a limited inventory of application capabilities from user-provided configuration and safe discovery.
3. **Plan:** Select test cases based on enabled test packs, threat model, and budget.
4. **Execute:** Run only registered tests through approved adapters.
5. **Observe:** Capture sanitized requests, responses, assertions, and tool events.
6. **Hypothesize:** Suggest potential security failures with explicit evidence requirements.
7. **Verify:** Re-run a candidate with bounded variations or deterministic checks where possible.
8. **Classify:** Assign severity, confidence, evidence quality, and known limitations.
9. **Regress:** Offer a replayable test case for human review.
10. **Report:** Produce results and recommended next steps.

### Required guardrails
- Require explicit authorization and target scope for non-local targets.
- Default to local mocks or a sample app.
- Enforce hard limits on requests, time, concurrency, and token spend.
- Use allowlisted URLs and block redirects outside scope.
- Never execute model-generated shell commands, SQL mutations, code, or tool actions directly.
- Treat retrieved content and target responses as untrusted data, never as system instructions.
- Keep tool permissions separate from the model's reasoning.
- Require human approval for state-changing, destructive, or potentially disruptive tests.
- Use synthetic canary secrets by default; do not scan for or collect unrelated real secrets.
- Redact credentials and sensitive output before persistence.
- Provide a global stop mechanism and fail closed on scope or policy errors.
- Record why a test was selected, skipped, stopped, or marked inconclusive.
- Do not automatically attack discovered third-party URLs or expand scope.

### Agent roles (logical components, not necessarily separate LLM agents)
- **Planner:** Selects tests from the registered catalog.
- **Runner:** Executes registered test cases through approved adapters.
- **Verifier:** Checks candidate findings against deterministic criteria or bounded repeats.
- **Triage component:** Groups findings and recommends priority.
- **Reporter:** Produces a factual report from structured results.

Begin with deterministic orchestration and a single optional LLM-assisted planner. Do not introduce multiple autonomous agents until simpler orchestration demonstrates a measurable benefit.

## 9. Initial Security Test Categories

Use established public taxonomies, including the OWASP Top 10 for LLM Applications and MITRE ATLAS, as reference material. Treat them as evolving references, not as a substitute for a product-specific threat model.

### A. Input and instruction handling
- Direct prompt injection test cases.
- Untrusted-content boundary tests.
- Indirect prompt injection in controlled synthetic documents.
- Refusal and policy-boundary regression cases.

### B. Data confidentiality
- Synthetic canary leakage.
- Cross-user and cross-tenant retrieval boundary checks.
- System prompt or configuration disclosure checks where disclosure is explicitly prohibited.
- Redaction and logging checks for sensitive test fixtures.

### C. Agent and tool security
- Tool allowlist enforcement.
- Authorization checks before sensitive actions.
- Confirmation requirements for high-impact actions.
- Attempts to make an agent call a tool outside the declared scope, using mocks or a controlled sandbox.

### D. RAG and retrieval
- Document-level access control.
- Tenant isolation.
- Retrieval poisoning scenarios using synthetic content.
- Citation and source-grounding checks as supporting quality signals, not security proof.

### E. Output and downstream use
- Output schema and validation checks.
- Unsafe HTML/Markdown rendering checks where applicable.
- Tests that ensure downstream code treats model output as untrusted input.
- Checks for improper reliance on generated SQL or code without validation.

### F. Operational controls
- Rate limits and bounded retries.
- Fail-closed behavior when policy services are unavailable.
- Logging redaction.
- Dependency and configuration checks where implemented.

For each category, document the threat, prerequisites, test procedure, expected safe behavior, failure condition, severity rationale, false-positive risks, and remediation guidance.

## 10. Technical Architecture

### Recommended starting stack
- **Language:** Python 3.11+ (support matrix finalized in packaging configuration).
- **CLI:** Typer or an equivalent lightweight CLI framework.
- **Validation:** Pydantic models or typed dataclasses.
- **Tests:** pytest.
- **HTTP:** httpx.
- **Lint/type checks:** Ruff and mypy or an equivalent consistent toolchain.
- **Reports:** JSON first; Markdown and HTML later.
- **Packaging:** `pyproject.toml`, standard wheel/sdist build.
- **CI:** GitHub Actions.
- **Persistence:** JSONL or SQLite locally; managed relational database only when hosted multi-user needs justify it.
- **Hosted API later:** FastAPI or a comparable framework.
- **Dashboard later:** Choose a frontend stack only after users need persistent shared results.

Avoid introducing Kubernetes, a message broker, a vector database, or a microservice architecture in the MVP without a demonstrated requirement.

### Logical components

```text
CLI / Python SDK
      |
Configuration and Scope Validator
      |
Test Planner (deterministic first; optional AI assistance)
      |
Policy and Budget Guard
      |
Test Runner ---- Registered Test Packs
      |
Target Adapters ---- Local Callable / Authorized HTTP / Future Framework Adapters
      |
Evidence Sanitizer and Result Normalizer
      |
Finding Verifier and Regression Case Generator
      |
JSON / Markdown Reports ---- CI Exit Status
      |
Future: Local Dashboard / Hosted API / Team Platform
```

### Design requirements
- Core domain types must not depend on a specific provider SDK.
- Target adapters must have explicit timeouts, retry policies, and scope checks.
- Test packs must declare required capabilities and potential side effects.
- Evaluators must return structured outcomes with rationale and confidence.
- Every run must include tool version, test-pack version, configuration hash, timestamp, and target identifier, without recording secrets.
- Make random seeds configurable where meaningful; document nondeterministic model behavior.
- Keep persistence behind an interface so local files can later be replaced or supplemented by a database.
- Keep cloud-only capabilities out of core imports.

## 11. Proposed Repository Structure

```text
sentinelforge/
├── README.md
├── PROJECT.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── pyproject.toml
├── .gitignore
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── docs/
│   ├── getting-started.md
│   ├── concepts.md
│   ├── threat-model.md
│   ├── configuration.md
│   ├── test-authoring.md
│   ├── reporting.md
│   ├── safety-and-scope.md
│   └── roadmap.md
├── examples/
│   ├── vulnerable_demo_app.py
│   ├── safe_demo_app.py
│   ├── sentinelforge.yaml
│   └── github-actions.yml
├── src/
│   └── sentinelforge/
│       ├── __init__.py
│       ├── cli.py
│       ├── config.py
│       ├── errors.py
│       ├── logging.py
│       ├── models/
│       │   ├── case.py
│       │   ├── finding.py
│       │   ├── run.py
│       │   └── target.py
│       ├── engine/
│       │   ├── planner.py
│       │   ├── runner.py
│       │   ├── budgets.py
│       │   ├── scope.py
│       │   └── policy.py
│       ├── adapters/
│       │   ├── base.py
│       │   ├── callable_target.py
│       │   └── http_target.py
│       ├── packs/
│       │   ├── base.py
│       │   ├── prompt_injection.py
│       │   ├── canary_leakage.py
│       │   └── tool_permissions.py
│       ├── evaluators/
│       │   ├── base.py
│       │   └── deterministic.py
│       ├── findings/
│       │   ├── verify.py
│       │   └── regression.py
│       └── reporters/
│           ├── json_report.py
│           └── terminal.py
└── tests/
    ├── unit/
    ├── integration/
    ├── safety/
    └── fixtures/
```

This is a target structure, not a requirement to create every module on day one. Start with the smallest coherent subset and grow as working features demand.

## 12. Core Data Contracts

### Test case
Each case should include:
- Stable unique ID and version.
- Name, description, category, and tags.
- Risk being tested.
- Preconditions and required target capabilities.
- Input fixture or safe input generator.
- Expected behavior and assertion method.
- Suggested severity if it fails.
- Side-effect classification.
- References and limitations.

### Finding
Each finding should include:
- Stable finding ID and linked test-case ID.
- Run ID and target alias.
- Status: `confirmed`, `potential`, `inconclusive`, `not_reproduced`, or `accepted_risk`.
- Severity: `critical`, `high`, `medium`, `low`, or `informational`.
- Confidence and evidence quality as separate fields.
- Sanitized evidence and reproduction instructions.
- Affected component, if known.
- Recommended mitigation.
- Regression-test availability.
- Timestamp and tool/test-pack versions.

Do not call a finding “confirmed” merely because an LLM evaluator says so. Define category-specific verification requirements.

### Run result
Include:
- Run ID, timestamps, duration, and exit status.
- Target alias and approved scope.
- Configuration and pack versions.
- Counts by outcome and severity.
- Budget consumption.
- Skipped tests and reasons.
- Sanitization status.
- Warnings about nondeterminism and coverage.

## 13. CLI and Configuration Design

Proposed commands:

```bash
sentinelforge init
sentinelforge test --target demo
sentinelforge test --config sentinelforge.yaml
sentinelforge report --run latest --format json
sentinelforge regressions list
sentinelforge regressions export --format pytest
sentinelforge packs list
```

Use consistent terminology; decide between `scan` and `test` before public release rather than supporting duplicate command names indefinitely.

Example configuration (illustrative):

```yaml
version: 1

target:
  kind: callable
  name: demo
  entrypoint: examples.safe_demo_app:ask

scope:
  authorization_confirmed: true
  allowed_hosts: []
  allow_state_changes: false

limits:
  max_cases: 30
  timeout_seconds: 10
  max_concurrency: 2
  max_estimated_cost_usd: 1.00

tests:
  packs:
    - prompt_injection
    - canary_leakage
    - tool_permissions

report:
  formats:
    - terminal
    - json
  redact_sensitive_values: true
```

Configuration is untrusted input. Validate it strictly, reject unknown safety-critical settings where appropriate, and never infer authorization from a URL alone.

## 14. Security, Privacy, and Trust

- Threat-model the scanner itself, not only the applications it tests.
- Never store API keys in test fixtures, reports, or source control.
- Support environment variables or a secrets manager for credentials.
- Redact known secrets and synthetic canaries from logs by default.
- Minimize retention and provide clear deletion behavior.
- Avoid sending customer prompts, outputs, or code to third-party model providers unless explicitly configured.
- Explain which provider receives which data when an external evaluator is enabled.
- Keep audit logs free of raw secrets.
- Sign releases and use dependency scanning as the project matures.
- Provide a responsible-disclosure process in `SECURITY.md`.
- Run the framework against controlled demo targets in CI.
- Treat generated remediation as a suggestion; do not auto-apply it to production.
- Document that security tests can be incomplete, probabilistic, and sensitive to model/provider changes.

## 15. Evaluation and Quality Metrics

### Product metrics
- Time from installation to first useful report.
- Number of repeat users and repeat runs.
- Number of independent contributors.
- Successful integrations and active repositories.
- Conversion from active free users to paid trials, once a hosted tier exists.
- Retention and reasons for churn.

### Test quality metrics
- Precision of reported findings on labeled fixtures.
- Recall on a controlled, versioned benchmark set.
- False-positive and false-negative rates by test category.
- Reproducibility rate of findings.
- Test runtime and estimated model/API cost.
- Percentage of findings with actionable evidence.
- Percentage of test cases with documented limitations.

Never optimize only for the number of vulnerabilities reported. More findings can mean more noise, not better security.

## 16. Monetization Strategy

### Free, open-source core
- Local CLI and Python SDK.
- Core test packs.
- JSON reports.
- Local regression export.
- Sample applications and CI examples.

### Paid developer/team features to validate
- Shared run history and team dashboards.
- Scheduled tests and notifications.
- Private test packs and policy templates.
- Centralized project management.
- Collaboration, audit history, and access control.
- Retention controls and compliance-oriented reporting.
- Hosted runners or private deployment options.

### Commercial validation
Before implementing billing:
1. Interview target users about their existing workflow and costs.
2. Publish a demo and an installable alpha.
3. Ask users to run it against their own authorized test application.
4. Observe repeat usage rather than relying on GitHub stars.
5. Test willingness to pay for one specific workflow.
6. Implement only the paid feature with the clearest repeated demand.

Avoid promising compliance certification, guaranteed protection, or complete vulnerability coverage.

## 17. Distribution and Community

- Public GitHub repository with a concise README and five-minute quick start.
- Short demo showing a deliberately vulnerable local app and the resulting regression test.
- A small, reproducible public benchmark.
- Issues labelled `good first issue`, `test-pack`, `adapter`, and `documentation`.
- Versioned releases and changelog.
- Community test packs reviewed for safety and quality.
- Clear contribution and responsible-disclosure policies.
- Technical articles that teach the problem and report measured results honestly.

Do not create a leaderboard until benchmark methodology, test leakage risks, and reproducibility are well understood.

## 18. Definition of Done

A feature is complete when:
- Its expected behavior and failure cases are documented.
- Unit and relevant integration tests pass.
- Safety and scope restrictions are tested.
- Errors are clear and do not leak secrets.
- Reports accurately represent evidence and uncertainty.
- Documentation includes an example.
- CI passes on supported platforms.
- Backward compatibility and configuration changes are considered.
- No feature claims more security coverage than it provides.

## 19. First Ten Implementation Tasks

1. Create package metadata, license, CI, and a minimal README.
2. Define `TestCase`, `TestResult`, `Finding`, and `RunSummary` models.
3. Implement a local callable target interface.
4. Implement a deterministic test runner with timeout and case-count limits.
5. Add a sample intentionally vulnerable local demo and a safe demo.
6. Implement synthetic canary leakage tests.
7. Implement a basic instruction-boundary test with explicit expected behavior.
8. Generate terminal and JSON reports.
9. Add regression export and CI exit codes.
10. Publish an alpha release and invite feedback from developers building AI applications.

## 20. Immediate Next Step

Do not start by implementing every module in the proposed tree. Begin with a vertical slice:

**One sample AI application → three security tests → structured findings → JSON report → CI failure on a confirmed regression.**

Once that workflow is reliable, expand test coverage and introduce agentic planning under strict budgets and scope controls.

### Decisions to make before coding
- Confirm project name and package name.
- Choose the initial license after considering the intended open-source and commercial model.
- Choose the first target interface: local Python callable or authorized HTTP endpoint.
- Define the first three tests and their evidence requirements.
- Decide whether external LLM evaluators are excluded from the MVP (recommended) or opt-in.
- Validate the target user's pain before building hosted infrastructure.

---

**North-star outcome:** A developer can continuously test an AI application's security, reproduce failures, and verify that fixes remain effective as the application changes—without handing control of the application to an unrestricted autonomous agent.
