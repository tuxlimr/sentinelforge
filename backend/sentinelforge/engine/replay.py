"""Replay saved regression cases against a target, like a CI job would."""

from __future__ import annotations

import time

from pydantic import BaseModel

from ..adapters import build_target
from ..models import Scope, TargetSpec
from ..packs import all_cases
from ..storage import regressions
from .evaluators import evaluate


class ReplayRequest(BaseModel):
    target: TargetSpec = TargetSpec(kind="safe_demo")
    scope: Scope = Scope()


class ReplayResult(BaseModel):
    id: str
    status: str  # "passing" | "blocked" | "error"
    duration_ms: int
    message: str


def replay(request: ReplayRequest) -> list[ReplayResult]:
    target = build_target(request.target, request.scope)
    cases = {case.id: case for case in all_cases()}
    results = []
    for record in regressions.list_regressions():
        started = time.perf_counter()
        case = cases.get(record["case_id"])
        if case is None:
            results.append(ReplayResult(id=record["id"], status="error", duration_ms=0, message="Case no longer exists"))
            continue
        try:
            reply = target.ask(record["prompt"], record["context"], 10)
            verdict = evaluate(case.model_copy(update={"prompt": record["prompt"]}), reply, request.scope)
            status, message = ("passing" if verdict.passed else "blocked"), verdict.assertion
        except Exception as error:
            status, message = "error", type(error).__name__
        results.append(ReplayResult(id=record["id"], status=status, message=message,
                                    duration_ms=int((time.perf_counter() - started) * 1000)))
    return results
