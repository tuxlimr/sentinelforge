# Getting started

This walks you from a fresh clone to your first confirmed finding and regression test in a few minutes. Everything runs
offline against the bundled demo apps. No API key is needed.

## 1. Install

You need Python 3.14 and Node 20 or newer.

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e "backend[dev]"

cd frontend && npm install
```

## 2. Start the API and the dashboard

```bash
sentinelforge serve                  # terminal 1: http://127.0.0.1:8000
cd frontend && npm run dev           # terminal 2: http://localhost:5173
```

## 3. Run a scan

1. Open **Security Scans**.
2. Pick **Vulnerable demo** and click **Run security tests**.
3. You land on **Findings & Verification** with 11 confirmed findings and a **BLOCKED** CI gate.

Run again with **Safe demo**. All 11 cases pass and the gate is **PASSED**.

## 4. Verify and regress

1. In **Findings & Verification**, open a finding and read the prompt, the response and why the assertion failed.
2. Click **Export to regression suite**.
3. Open **Regression Tests**, choose a target and click **Replay suite**. Against the safe demo it passes. Against the
   vulnerable demo it is blocked.
4. Click **Export pytest** to download a test file you can commit.

## 5. Try the Exploit Lab

Open **Exploit Lab**, pick a payload, and click **Launch fuzzing**. The matrix shows which mutations (base64, leetspeak,
roleplay, …) still get through. **Convert to regression test** saves a winning variant.

## 6. Use it in CI

```bash
sentinelforge test --target safe_demo --fail-on high
```

The command exits `1` if any confirmed finding is at or above the threshold, and `2` on a scope or configuration error.
Results are stored under `.sentinelforge/` (override with the `SENTINELFORGE_HOME` environment variable).

## Testing your own app

Choose **HTTP endpoint** in the scan form. Your endpoint receives `POST {"prompt": "...", "context": {...}}` and replies
`{"text": "...", "tool_calls": [{"name": "...", "args": {...}}]}`. You must confirm authorization, and only that host
is contacted. See [safety-and-scope.md](safety-and-scope.md).
