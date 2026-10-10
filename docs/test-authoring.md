# Writing test cases and packs

A **test case** is one safe, repeatable probe with an explicit pass condition. A **pack** is a module that builds a
list of cases.

## Anatomy of a case

Defined in `backend/sentinelforge/models/case.py`:

| Field | Meaning |
|---|---|
| `id`, `version` | Stable ID such as `SF-PI-001`. Never reuse an ID for a different test |
| `pack`, `category`, `tags` | Where the case belongs |
| `risk` | The harm if the case fails |
| `prompt`, `context` | What is sent to the target. Use synthetic data only |
| `expected` | Safe behavior, in plain words |
| `check` | The deterministic assertion (see below) |
| `severity` | Suggested severity if the case fails |
| `side_effects` | `none` or `mock_tools` |
| `limitations`, `mitigation`, `references` | Required: what the test cannot detect, how to fix, where to read more |

## Available checks

| `check.type` | Passes when |
|---|---|
| `not_contains` | None of `values` (plus the scope canaries if `include_scope_canaries` is true) appear in the response |
| `forbidden_tool_calls` | Every requested tool is in the allowlist |
| `no_tool_calls` | None of the listed `tools` are requested |

Add a new check by writing a function in `engine/evaluators.py` and registering it in `CHECKS`.

## Add a pack

1. Create `backend/sentinelforge/packs/my_pack.py` with a `build_cases()` function returning `TestCase` objects.
2. Register it in `packs/__init__.py` inside `PACKS` (title, description, OWASP reference, module).
3. Add tests proving the vulnerable demo fails the new cases and the safe demo passes them. If a demo app needs a new
   behavior, change it in `backend/sentinelforge/demo/`.
4. Update the case count in the docs and `CHANGELOG.md`.

## Rules for good cases

- **A pass must mean something.** Prefer a marker that cannot appear unless the app obeyed the attack. The prompt
  injection pack splits its marker (`'ZE'` + `'BRA-7731'`) so quoting the prompt never triggers a false alarm.
- **Synthetic only.** Never include real secrets, real customer data or live URLs.
- **Mock tools only.** Cases may inspect requested tool calls, but nothing is executed.
- **Document limits.** Say what the case cannot catch. Do not imply broader coverage than it provides.
- **No model judges** in the core pack. A model-based evaluator must be opt-in and clearly labeled.
