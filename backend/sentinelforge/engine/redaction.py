"""Sanitize evidence before it is stored or displayed."""

from __future__ import annotations

from ..models import Scope


def redact(text: str, scope: Scope) -> str:
    """Keep a short prefix of each canary so evidence stays useful but not copyable."""
    for canary in scope.canaries:
        text = text.replace(canary, canary[:6] + "…[REDACTED]")
    return text
