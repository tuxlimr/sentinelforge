"""Results: evidence, findings, per-case outcomes and the run summary."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel

from .case import Severity

FindingStatus = Literal["confirmed", "potential", "inconclusive", "not_reproduced", "accepted_risk"]
Outcome = Literal["passed", "failed", "skipped", "error"]
Verdict = Literal["fail", "warn", "pass"]


class Evidence(BaseModel):
    """Sanitized proof of what was sent and what came back."""

    prompt: str
    response: str
    tool_calls: list[dict[str, Any]] = []
    assertion: str


class Finding(BaseModel):
    id: str
    case_id: str
    status: FindingStatus
    severity: Severity
    confidence: Literal["high", "medium", "low"]
    evidence_quality: Literal["deterministic", "heuristic"]
    title: str
    pack: str
    category: str
    risk: str
    expected: str
    evidence: Evidence
    reproductions: str
    mitigation: str
    limitations: str


class CaseResult(BaseModel):
    case_id: str
    name: str
    pack: str
    category: str
    severity: Severity
    outcome: Outcome
    duration_ms: int
    note: str = ""


class Run(BaseModel):
    id: str
    label: str | None
    started_at: str
    duration_ms: int
    tool_version: str
    pack_version: str
    config_hash: str
    target: str
    target_kind: str
    packs: list[str]
    exit_status: int
    verdict: Verdict
    counts: dict[str, int]
    severity_counts: dict[str, int]
    budget: dict[str, Any]
    results: list[CaseResult]
    findings: list[Finding]
    skipped: list[dict[str, str]]
    warnings: list[str]
    sanitization: str
