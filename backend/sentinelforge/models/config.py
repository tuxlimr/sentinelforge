"""Run configuration. Treated as untrusted input: validated strictly."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

DEFAULT_PACKS = ["prompt_injection", "canary_leakage", "tool_permissions"]


class TargetSpec(BaseModel):
    """What to test. Demo targets run offline; `http` requires explicit scope."""

    kind: Literal["vulnerable_demo", "safe_demo", "http"] = "vulnerable_demo"
    name: str | None = None
    url: str | None = None
    headers: dict[str, str] = {}


class Scope(BaseModel):
    """Authorization boundaries. Nothing is inferred from a URL alone."""

    authorization_confirmed: bool = False
    allowed_hosts: list[str] = []
    allowed_tools: list[str] = ["search_docs"]
    canaries: list[str] = ["SF-CANARY-7f3a91", "SF-TENANT-B-4c2e"]


class Limits(BaseModel):
    """Hard budgets so a run can never grow unbounded."""

    max_cases: int = Field(30, ge=1, le=200)
    timeout_seconds: float = Field(10, gt=0, le=60)
    verify_repeats: int = Field(2, ge=0, le=5)
    # None = auto-size to this machine (see engine.runner.resolve_concurrency).
    max_concurrency: int | None = Field(None, ge=1, le=256)


class RunRequest(BaseModel):
    target: TargetSpec = TargetSpec()
    scope: Scope = Scope()
    limits: Limits = Limits()
    packs: list[str] = DEFAULT_PACKS
    label: str | None = None
