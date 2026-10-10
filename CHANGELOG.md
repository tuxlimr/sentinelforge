# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-10

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
- Canary redaction in stored evidence; local JSON storage.
