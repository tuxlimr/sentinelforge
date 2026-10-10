# Security Policy

## Reporting a vulnerability

Please report vulnerabilities **privately**. Do not open a public issue or pull request.

Use GitHub's private reporting: open the repository's **Security** tab and choose **Report a vulnerability**.
Include the affected version, steps to reproduce, the impact you expect, and any suggested fix.

You can expect an acknowledgement within a few days. We will keep you updated, agree on a disclosure date with you,
and credit you in the release notes if you wish.

## Supported versions

This is an early alpha (0.x). Only the latest release receives fixes.

## Scope

In scope: the SentinelForge engine, API, CLI and dashboard, including scope enforcement, redaction, the HTTP target
adapter and the handling of untrusted input (configuration, target responses, stored runs).

Out of scope: vulnerabilities in applications you test with SentinelForge, and findings that only affect the
deliberately vulnerable demo app (`backend/sentinelforge/demo/vulnerable_app.py`).

## Using SentinelForge responsibly

Only test systems you own or are explicitly authorized to test. The HTTP target requires you to confirm
authorization and list the allowed host, and it blocks redirects, but the responsibility for authorization is yours.
See [docs/safety-and-scope.md](docs/safety-and-scope.md).

## Design notes for reviewers

- The API binds to `127.0.0.1` and allows browser calls only from the local dev origin.
- Config, target replies and stored files are treated as untrusted. Run ids are reduced to a basename before file access.
- Model or target output is never executed. Tool calls are evaluated as data against an allowlist.
- Synthetic canaries are redacted before evidence is stored.
