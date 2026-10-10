"""Adapter for a local Python function `ask(prompt, context) -> dict`."""

from __future__ import annotations

from typing import Any, Callable

from .base import Target, TargetReply


class CallableTarget(Target):
    def __init__(self, name: str, function: Callable[[str, dict], dict]):
        self.name = name
        self._function = function

    def ask(self, prompt: str, context: dict[str, Any], timeout: float) -> TargetReply:
        reply = self._function(prompt, context)
        return TargetReply(text=reply.get("text", ""), tool_calls=list(reply.get("tool_calls", [])))
