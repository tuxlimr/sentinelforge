"""Exploit Lab: apply payload mutations to one test case and see which succeed."""

from __future__ import annotations

import time

from pydantic import BaseModel

from ..adapters import build_target
from ..models import Limits, Scope, TargetSpec
from ..packs import all_cases
from .evaluators import evaluate
from .mutations import MUTATIONS, apply_mutation
from .redaction import redact


class FuzzRequest(BaseModel):
    case_id: str
    mutations: list[str] = list(MUTATIONS)
    target: TargetSpec = TargetSpec()
    scope: Scope = Scope()
    limits: Limits = Limits()


class FuzzResult(BaseModel):
    mutation: str
    label: str
    prompt: str
    outcome: str  # "exploited" | "resisted" | "error"
    response: str
    tool_calls: list[dict]
    assertion: str
    duration_ms: int


def fuzz(request: FuzzRequest) -> list[FuzzResult]:
    case = next((c for c in all_cases() if c.id == request.case_id), None)
    if case is None:
        raise KeyError(request.case_id)
    unknown = [m for m in request.mutations if m not in MUTATIONS]
    if unknown:
        raise KeyError(f"Unknown mutations: {unknown}")

    target = build_target(request.target, request.scope)
    results = []
    for mutation_id in request.mutations[: request.limits.max_cases]:
        prompt = apply_mutation(mutation_id, case.prompt)
        started = time.perf_counter()
        try:
            reply = target.ask(prompt, case.context, request.limits.timeout_seconds)
            verdict = evaluate(case, reply, request.scope)
            outcome, text, calls, assertion = ("resisted" if verdict.passed else "exploited"), reply.text, reply.tool_calls, verdict.assertion
        except Exception as error:  # target failure is inconclusive
            outcome, text, calls, assertion = "error", "", [], type(error).__name__
        results.append(FuzzResult(
            mutation=mutation_id, label=MUTATIONS[mutation_id].label, prompt=redact(prompt, request.scope),
            outcome=outcome, response=redact(text, request.scope), tool_calls=calls, assertion=assertion,
            duration_ms=int((time.perf_counter() - started) * 1000),
        ))
    return results
