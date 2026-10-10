"""Target adapter interface: the only way the engine talks to an application."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class ScopeError(Exception):
    """The target is outside the authorized scope. The run must fail closed."""


class TargetError(Exception):
    """The target could not be used as an AI endpoint (bad HTTP status, unreachable, or a non-AI response).

    Its message is written for a person and is stored as the case note, so a run shows *why* it was
    inconclusive instead of a bare exception type.
    """


@dataclass
class TargetReply:
    text: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


class Target(ABC):
    name: str

    @abstractmethod
    def ask(self, prompt: str, context: dict[str, Any], timeout: float) -> TargetReply:
        """Send one prompt and return the app's text plus any requested tool calls."""
