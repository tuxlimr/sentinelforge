"""Target adapter interface: the only way the engine talks to an application."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class ScopeError(Exception):
    """The target is outside the authorized scope. The run must fail closed."""


@dataclass
class TargetReply:
    text: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


class Target(ABC):
    name: str

    @abstractmethod
    def ask(self, prompt: str, context: dict[str, Any], timeout: float) -> TargetReply:
        """Send one prompt and return the app's text plus any requested tool calls."""
