"""Runs the selected test cases against a target and builds the run summary."""

from __future__ import annotations

import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
import uuid
from datetime import datetime, timezone

from .. import PACK_VERSION, __version__
from ..adapters import ScopeError, Target, TargetReply, build_target
from ..models import SEVERITY_RANK, CaseResult, Evidence, Finding, Run, RunRequest, TestCase
from ..packs import PACKS, all_cases
from .evaluators import Verdict, evaluate
from .redaction import redact


def _ask_and_evaluate(target: Target, case: TestCase, request: RunRequest) -> tuple[Verdict, TargetReply]:
    reply = target.ask(case.prompt, case.context, request.limits.timeout_seconds)
    return evaluate(case, reply, request.scope), reply


def _verify(target: Target, case: TestCase, request: RunRequest) -> int:
    """Re-run a failed case; return how many extra runs also failed."""
    still_failing = 0
    for _ in range(request.limits.verify_repeats):
        try:
            verdict, _ = _ask_and_evaluate(target, case, request)
            still_failing += not verdict.passed
        except ScopeError:
            raise
        except Exception:
            pass  # a flaky verification run neither confirms nor clears the finding
    return still_failing


def _build_finding(case: TestCase, verdict: Verdict, reply: TargetReply, failed_runs: int, total_runs: int,
                   request: RunRequest) -> Finding:
    confirmed = failed_runs == total_runs
    return Finding(
        id=f"F-{case.id}",
        case_id=case.id,
        status="confirmed" if confirmed else "potential",
        severity=case.severity,
        confidence="high" if confirmed else "medium",
        evidence_quality="deterministic",
        title=case.name,
        pack=case.pack,
        category=case.category,
        risk=case.risk,
        expected=case.expected,
        evidence=Evidence(
            prompt=redact(case.prompt, request.scope),
            response=redact(reply.text, request.scope),
            tool_calls=reply.tool_calls,
            assertion=verdict.assertion,
        ),
        reproductions=f"Failed {failed_runs} of {total_runs} runs.",
        mitigation=case.mitigation,
        limitations=case.limitations,
    )


def _run_case(target: Target, case: TestCase, request: RunRequest) -> tuple[CaseResult, Finding | None, int]:
    """Execute one case. Returns its result, an optional finding, and requests made."""
    started = time.perf_counter()

    def result(outcome: str, note: str = "") -> CaseResult:
        return CaseResult(
            case_id=case.id, name=case.name, pack=case.pack, category=case.category, severity=case.severity,
            outcome=outcome, duration_ms=int((time.perf_counter() - started) * 1000), note=note,
        )

    try:
        verdict, reply = _ask_and_evaluate(target, case, request)
    except ScopeError:
        raise
    except Exception as error:  # target failure is inconclusive, never a pass
        return result("error", type(error).__name__), None, 1

    if verdict.passed:
        return result("passed"), None, 1

    failed_runs = 1 + _verify(target, case, request)
    total_runs = 1 + request.limits.verify_repeats
    finding = _build_finding(case, verdict, reply, failed_runs, total_runs, request)
    return result("failed", finding.status), finding, total_runs


def resolve_concurrency(requested: int | None, case_count: int) -> int:
    """Worker count: the explicit limit, or auto-sized to this machine. Never more than the cases to run.

    Targets are I/O bound (HTTP calls), so threads scale past the core count; the auto cap
    matches Python's own ThreadPoolExecutor default.
    """
    auto = min(32, (os.cpu_count() or 1) + 4)
    return max(1, min(requested or auto, case_count))


def _run_cases(target: Target, cases: list[TestCase], request: RunRequest, workers: int):
    """Run cases on a thread pool, keeping results in case order. A ScopeError aborts the whole run."""
    if workers <= 1:
        return [_run_case(target, case, request) for case in cases]
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sf-case")
    try:
        futures = [pool.submit(_run_case, target, case, request) for case in cases]
        return [future.result() for future in futures]
    except BaseException:
        pool.shutdown(wait=False, cancel_futures=True)  # fail closed: stop issuing requests
        raise
    finally:
        pool.shutdown(wait=True)


def _decide_verdict(findings: list[Finding], errors: int) -> str:
    serious = any(f.status == "confirmed" and SEVERITY_RANK[f.severity] >= SEVERITY_RANK["high"] for f in findings)
    if serious:
        return "fail"
    return "warn" if findings or errors else "pass"


def _config_hash(request: RunRequest) -> str:
    """Stable fingerprint of the configuration, excluding headers (may hold secrets)."""
    config = request.model_dump(mode="json")
    config["target"].pop("headers", None)
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:12]


def execute(request: RunRequest) -> Run:
    started = time.perf_counter()
    unknown = [pack for pack in request.packs if pack not in PACKS]
    if unknown:
        raise ScopeError(f"Unknown packs: {unknown}")

    target = build_target(request.target, request.scope)
    selected = [case for case in all_cases() if case.pack in request.packs]
    within_budget = selected[: request.limits.max_cases]
    skipped = [{"case_id": c.id, "reason": "max_cases budget reached"} for c in selected[request.limits.max_cases:]]

    workers = resolve_concurrency(request.limits.max_concurrency, len(within_budget))
    outcomes = _run_cases(target, within_budget, request, workers)
    results = [result for result, _, _ in outcomes]
    findings = [finding for _, finding, _ in outcomes if finding]
    requests_made = sum(used for _, _, used in outcomes)
    findings.sort(key=lambda f: -SEVERITY_RANK[f.severity])

    errors = sum(r.outcome == "error" for r in results)
    verdict = _decide_verdict(findings, errors)
    warnings = ["A clean run only means the configured tests did not detect a failure under the tested conditions."]
    if errors:
        warnings.insert(0, "Some cases errored and are reported as inconclusive, not as passed.")

    now = datetime.now(timezone.utc)
    return Run(
        id=now.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4],
        label=request.label,
        started_at=now.isoformat(timespec="seconds"),
        duration_ms=int((time.perf_counter() - started) * 1000),
        tool_version=__version__,
        pack_version=PACK_VERSION,
        config_hash=_config_hash(request),
        target=target.name,
        target_kind=request.target.kind,
        packs=request.packs,
        exit_status=1 if verdict == "fail" else 0,
        verdict=verdict,
        counts={
            "passed": sum(r.outcome == "passed" for r in results),
            "failed": sum(r.outcome == "failed" for r in results),
            "error": errors,
            "skipped": len(skipped),
        },
        severity_counts={sev: sum(f.severity == sev for f in findings) for sev in SEVERITY_RANK},
        budget={"requests": requests_made, "cases_run": len(within_budget), "max_cases": request.limits.max_cases, "concurrency": workers},
        results=results,
        findings=findings,
        skipped=skipped,
        warnings=warnings,
        sanitization="Synthetic canaries are redacted from stored evidence; headers are excluded from the config hash.",
    )
