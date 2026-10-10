"""Adapter for an authorized HTTP endpoint.

Protocol: POST {"prompt": str, "context": {...}} and expect
{"text": str, "tool_calls": [{"name": str, "args": {...}}]} (plain text also works).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from ..models import Scope, TargetSpec
from .base import ScopeError, Target, TargetError, TargetReply


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
        try:
            response = httpx.post(
                self.url,
                json={"prompt": prompt, "context": context},
                headers=self.headers,
                timeout=timeout,
                follow_redirects=False,  # never leave the approved scope
            )
        except httpx.HTTPError as error:
            raise TargetError(f"Could not reach the target ({type(error).__name__}). Is the URL correct and the app running?") from error
        if response.is_redirect:
            raise ScopeError("Target attempted a redirect; redirects are blocked.")
        if response.status_code >= 400:
            raise TargetError(self._status_message(response.status_code))
        return self._parse(response)

    @staticmethod
    def _status_message(status: int) -> str:
        hint = {
            401: " Authentication failed; check the credentials in your config headers.",
            403: " Access was forbidden; check your credentials, or whether a WAF is blocking the request.",
            404: " Is this the right path to an LLM endpoint that accepts POST {\"prompt\", \"context\"}?",
            405: " The endpoint does not accept POST; is this an LLM endpoint?",
        }.get(status, " Is this an LLM endpoint that accepts POST {\"prompt\", \"context\"}?")
        return f"Target returned HTTP {status}, not an AI response.{hint}"

    @staticmethod
    def _parse(response: httpx.Response) -> TargetReply:
        try:
            body = response.json()
        except ValueError:
            # A 200 that is not JSON (e.g. an HTML page) is almost never an AI endpoint.
            if "html" in response.headers.get("content-type", "").lower() or "<html" in response.text[:200].lower():
                raise TargetError("Target returned an HTML page, not an AI response. Is this an LLM endpoint "
                                  "that accepts POST {\"prompt\", \"context\"} and returns {\"text\", ...}?") from None
            return TargetReply(text=response.text)
        if isinstance(body, dict):
            return TargetReply(text=str(body.get("text", "")), tool_calls=list(body.get("tool_calls", [])))
        return TargetReply(text=str(body))
