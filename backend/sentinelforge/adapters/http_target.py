"""Adapter for an authorized HTTP endpoint.

Protocol: POST {"prompt": str, "context": {...}} and expect
{"text": str, "tool_calls": [{"name": str, "args": {...}}]} (plain text also works).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from ..models import Scope, TargetSpec
from .base import ScopeError, Target, TargetReply


class HttpTarget(Target):
    def __init__(self, spec: TargetSpec, scope: Scope):
        self._check_scope(spec, scope)
        self.url = spec.url
        self.headers = spec.headers
        self.name = spec.name or urlparse(spec.url).hostname

    @staticmethod
    def _check_scope(spec: TargetSpec, scope: Scope) -> None:
        """Fail closed: authorization and host allowlisting are both mandatory."""
        if not scope.authorization_confirmed:
            raise ScopeError("Authorization must be explicitly confirmed for HTTP targets.")
        parsed = urlparse(spec.url or "")
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ScopeError("Target URL must be a valid http(s) URL.")
        if parsed.hostname not in scope.allowed_hosts:
            raise ScopeError(f"Host '{parsed.hostname}' is not listed in allowed hosts.")

    def ask(self, prompt: str, context: dict[str, Any], timeout: float) -> TargetReply:
        response = httpx.post(
            self.url,
            json={"prompt": prompt, "context": context},
            headers=self.headers,
            timeout=timeout,
            follow_redirects=False,  # never leave the approved scope
        )
        if response.is_redirect:
            raise ScopeError("Target attempted a redirect; redirects are blocked.")
        response.raise_for_status()
        return self._parse(response)

    @staticmethod
    def _parse(response: httpx.Response) -> TargetReply:
        try:
            body = response.json()
        except ValueError:
            return TargetReply(text=response.text)
        if isinstance(body, dict):
            return TargetReply(text=str(body.get("text", "")), tool_calls=list(body.get("tool_calls", [])))
        return TargetReply(text=str(body))
