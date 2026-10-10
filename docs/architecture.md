# Architecture

SentinelForge is two separate modules that talk over HTTP.

```text
frontend/ (React)  ──/api──▶  backend/ (FastAPI)  ──▶  Target (demo app or authorized HTTP endpoint)
                                  │
                                  └──▶ .sentinelforge/  (runs, regressions, settings as local files)
```

## Backend (`backend/sentinelforge/`)

| Package | Responsibility |
|---|---|
| `models/` | Pydantic types: test cases, config (scope, limits), runs and findings |
| `packs/` | Registered test packs. Each module builds `TestCase` objects |
| `adapters/` | The only way the engine reaches an app: callable and HTTP targets, scope checks |
| `demo/` | Deliberately vulnerable and hardened sample apps (offline) |
| `engine/` | Runner, deterministic evaluators, redaction, mutations, Exploit Lab, replay, benchmark |
| `storage/` | Local JSON persistence for runs, regressions and settings |
| `api/` | FastAPI app and routers (`runs`, `regressions`, `lab`, `meta`) |
| `reporters.py` | SARIF export |
| `cli.py` | `sentinelforge test` and `sentinelforge serve` |

### Request flow for a scan

1. The API validates a `RunRequest` and applies saved settings.
2. `build_target` creates an adapter. HTTP targets fail closed unless authorization and the host are declared.
3. The runner executes each selected case within the case budget.
4. An evaluator returns a pass/fail verdict with a readable assertion. Evaluators are deterministic.
5. A failed case is re-run `verify_repeats` times. It is `confirmed` only if every run fails, otherwise `potential`.
6. Evidence is redacted, the run is summarized (verdict, counts, budget, config hash) and stored.

## Frontend (`frontend/src/`)

| Folder | Contents |
|---|---|
| `api/` | Typed client and response types mirroring the backend models |
| `components/` | Layout (top bar, sidebar), metric cards, badges, modal, finding detail |
| `pages/` | Scans, Findings, Regressions, Evaluation, Exploit Lab, Settings |
| `styles/` | Design tokens (from the Stitch design) and component styles |
| `hooks/` | `useAsync` data loading |

During development, Vite proxies `/api` to the backend on port 8000.

## Design decisions

- **Deterministic verdicts.** No model judge, so results are reproducible and cheap.
- **Adapters isolate targets.** Core types do not depend on any LLM provider or framework.
- **Local files first.** Persistence sits behind small functions so a database can replace it later.
- **Honest benchmarks.** The evaluation matrix measures the bundled checks on two labeled demo apps, not your app.
