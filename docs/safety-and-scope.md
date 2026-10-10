# Safety and scope

SentinelForge is for **authorized** testing. These guardrails are enforced in code, and each has a test.

## Scope

- Demo targets run locally and need no authorization.
- An HTTP target requires `authorization_confirmed: true` **and** its host in `allowed_hosts`. Both are checked before
  any request is sent. Nothing is inferred from a URL alone.
- Redirects are never followed. A redirect response stops the run with a scope error.
- Scope errors fail closed: the run stops and nothing is reported as passed.

## Budgets

- `max_cases` caps how many cases run. Skipped cases are listed with the reason.
- `timeout_seconds` bounds each request.
- `verify_repeats` bounds re-runs used to confirm a finding.

## Data handling

- Test inputs are synthetic. Canaries are fake secrets used only to detect leaks.
- Canary values are redacted from stored evidence (`engine/redaction.py`).
- Request headers (which may hold credentials) are excluded from the stored config hash.
- Nothing is sent to a third-party service. There is no telemetry.

## Execution safety

- Target output and tool calls are treated as untrusted data. They are compared to rules and never executed.
- Tools in tests are mocks. The allowlist is configurable in Settings.
- The API listens on `127.0.0.1` only and accepts browser calls only from the local dev origin.
- Run ids are reduced to a basename before touching the filesystem, which blocks path traversal.

## What a result means

A **clean run** means the configured tests did not detect a failure under the tested conditions. It does not mean the
application is secure. Every case lists its limitations. Treat results as evidence to investigate, and do not rely on
them as a certification.
