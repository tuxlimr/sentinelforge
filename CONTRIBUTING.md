# Contributing to SentinelForge

Thanks for helping. This project aims to stay small, readable and honest about what it can and cannot prove.

## Ground rules

- **Deterministic first.** New checks should be reproducible assertions, not model judgments.
- **Safe by default.** Test inputs are synthetic. Tools are mocks. Nothing may execute model output.
- **No overclaiming.** A test or doc must not imply more coverage than it provides. State limitations.
- **Readable code.** Small modules, clear names, docstrings that explain *why*. Follow the surrounding style.

## Development setup

```bash
pip install -e "backend[dev]"
cd backend && python -m pytest          # backend tests
cd ../frontend && npm install
npm run build                           # type-checks (tsc) and builds
```

Python 3.14 and Node 20+ are expected. If your path contains `&` and npm scripts fail, run the tools directly, for
example `node node_modules/typescript/bin/tsc --noEmit`.

## Making a change

1. Open an issue for anything larger than a small fix.
2. Create a branch and keep the change focused.
3. Add or update tests. Safety and scope behavior needs a test.
4. Update docs and the changelog when behavior changes.
5. Open a pull request and describe what changed and why.

A change is done when its behavior and failure cases are documented, tests pass, errors do not leak secrets, and
reports represent evidence and uncertainty accurately.

## Adding a test pack

See [docs/test-authoring.md](docs/test-authoring.md). Every case needs a stable ID, an expected behavior, a
deterministic check, a severity, limitations and a mitigation.

## Licensing of contributions

SentinelForge is licensed under the Apache License 2.0. By submitting a contribution you confirm that:

1. you wrote it or have the right to submit it, and
2. you license it to the project under Apache-2.0, **and** you grant the project's copyright holder a perpetual,
   worldwide, non-exclusive, royalty-free right to relicense your contribution, including under commercial or
   proprietary terms, as part of future versions of the project.

This lets the maintainer offer commercial editions later without having to track down every contributor. Versions
already released under Apache-2.0 stay available under Apache-2.0. If you do not agree, please do not submit a
contribution.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
