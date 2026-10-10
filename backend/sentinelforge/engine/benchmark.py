"""Evaluation benchmark: how accurate are the deterministic checks?

Ground truth comes from two labeled fixtures. The vulnerable demo is known to be
exploitable by every case (expected: FAIL). The safe demo is known to resist every
case (expected: PASS). Comparing observed outcomes to those labels gives precision,
recall, and run-to-run stability. No LLM judge is involved.
"""

from __future__ import annotations

import time

from pydantic import BaseModel

from ..adapters import build_target
from ..models import Scope, TargetSpec
from ..packs import PACKS, all_cases
from .evaluators import evaluate

FIXTURES = [("vulnerable_demo", True), ("safe_demo", False)]  # (target kind, is vulnerable)


class BenchmarkRequest(BaseModel):
    repeats: int = 5


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator * 100, 1) if denominator else None


def _observe(kind: str, case, scope: Scope) -> tuple[bool, float]:
    """Return (detected_failure, latency_ms) for one case against one fixture."""
    target = build_target(TargetSpec(kind=kind), scope)
    started = time.perf_counter()
    reply = target.ask(case.prompt, case.context, 10)
    verdict = evaluate(case, reply, scope)
    return (not verdict.passed), (time.perf_counter() - started) * 1000


def run_benchmark(request: BenchmarkRequest) -> dict:
    scope, cases = Scope(), all_cases()
    repeats = max(1, min(request.repeats, 20))

    suites = {pack_id: {"tp": 0, "fn": 0, "fp": 0, "tn": 0} for pack_id in PACKS}
    discrepancies, latencies, unstable, pairs = [], [], 0, 0

    for case in cases:
        for kind, is_vulnerable in FIXTURES:
            observations = []
            for _ in range(repeats):
                detected, latency = _observe(kind, case, scope)
                observations.append(detected)
                latencies.append(latency)
            pairs += 1
            unstable += len(set(observations)) > 1

            detected = observations[0]
            bucket = {(True, True): "tp", (True, False): "fp", (False, True): "fn", (False, False): "tn"}[(detected, is_vulnerable)]
            suites[case.pack][bucket] += 1
            if bucket in ("fp", "fn"):
                discrepancies.append({
                    "case_id": case.id, "name": case.name, "fixture": kind,
                    "expected": "FAIL" if is_vulnerable else "PASS", "observed": "FAIL" if detected else "PASS",
                })

    totals = {key: sum(s[key] for s in suites.values()) for key in ("tp", "fn", "fp", "tn")}
    return {
        "fixtures": pairs,
        "repeats": repeats,
        "engine": "deterministic",
        "llm_judge": "not configured",
        "precision": _ratio(totals["tp"], totals["tp"] + totals["fp"]),
        "recall": _ratio(totals["tp"], totals["tp"] + totals["fn"]),
        "accuracy": _ratio(totals["tp"] + totals["tn"], pairs),
        "instability": _ratio(unstable, pairs) or 0.0,
        "avg_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0,
        "totals": totals,
        "suites": [
            {
                "pack": pack_id, "title": PACKS[pack_id]["title"], "cases": sum(c.pack == pack_id for c in cases),
                **counts,
                "precision": _ratio(counts["tp"], counts["tp"] + counts["fp"]),
                "recall": _ratio(counts["tp"], counts["tp"] + counts["fn"]),
            }
            for pack_id, counts in suites.items()
        ],
        "discrepancies": discrepancies,
        "cases": [{"id": c.id, "name": c.name, "pack": c.pack, "severity": c.severity} for c in cases],
    }
