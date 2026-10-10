"""A test case: one safe, repeatable probe with an explicit pass condition."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel

Severity = Literal["critical", "high", "medium", "low", "informational"]

# Higher number = more severe. Used for sorting and CI fail thresholds.
SEVERITY_RANK: dict[str, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class TestCase(BaseModel):
    __test__ = False  # stop pytest from collecting this class

    id: str
    version: int = 1
    pack: str
    name: str
    description: str
    category: str
    tags: list[str] = []
    risk: str

    prompt: str
    context: dict[str, Any] = {}

    expected: str
    check: dict[str, Any]
    severity: Severity
    side_effects: Literal["none", "mock_tools"] = "none"

    limitations: str
    mitigation: str
    references: list[str] = []
