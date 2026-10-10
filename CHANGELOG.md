# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-10

### Added
- `sentinelforge webscan` and `POST /api/webscan`: passive website security check for sites you own or are
  authorized to test. Security headers (CSP, HSTS, clickjacking, nosniff, Referrer-Policy), cookie flags, version
  disclosure, CORS origin reflection, exposed `.git` / `.env` / `phpinfo()`, directory listing, plain HTTP and
  invalid TLS. GET requests only (at most 15), no offsite redirects, secret values never stored.

### Fixed
- Dashboard: reads retry transient connection failures instead of showing "Is the API running?"; writes are never
  retried. The dev server binds 127.0.0.1 explicitly.

## [0.1.0] - 2026-10-10

First release on PyPI as `sentinelforge-ai` (Python 3.11+).

### Added
- Test engine with 11 deterministic cases in three packs: prompt injection, canary leakage, tool permissions.
- Verification re-runs: a finding is `confirmed` only if it fails every run, otherwise `potential`.
- Local callable and authorized HTTP target adapters, with fail-closed scope checks and blocked redirects.
- Bundled vulnerable and safe demo apps that run fully offline.
- Regression tests: save, replay against a target, export as pytest.
- Exploit Lab with nine deterministic payload mutations.
- Evaluation matrix: precision, recall and stability measured on labeled fixtures.
- JSON and SARIF 2.1.0 report export; CI exit codes via the `sentinelforge test` CLI.
- FastAPI backend and React dashboard (Security Scans, Findings, Regressions, Evaluation, Exploit Lab, Settings).
- Canary redaction in stored evidence; local SQLite storage (earlier JSON data is imported automatically).
- `sentinelforge guide`: offline walkthrough of scan, findings, regressions, fix and replay.
- `sentinelforge.yaml` with `--config` to test your own HTTP endpoint, strictly validated; secrets only via
  environment variables.
- CLI commands `report`, `regressions list|add|replay|export` and `init` (config plus GitHub Actions workflow).
- `sentinelforge exposure`: nmap TCP connect scan flagging unexpected open ports on an authorized host.
