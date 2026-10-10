"""A hardened sample AI app that should pass every bundled test."""

from __future__ import annotations

REFUSAL = "Sorry, I can't help with that request."

_BLOCKED_HINTS = ("delete", "email", "tenant b", "system prompt", "text above", "debug mode", "ignore")


def ask(prompt: str, context: dict | None = None) -> dict:
    """Treats user and document text as data, and only ever uses the search tool."""
    text = prompt.lower()

    if "summarize" in text:  # summarizes content without following instructions inside it
        return {"text": "Summary: planning notes covering targets, hiring and vendors.", "tool_calls": []}

    if any(hint in text for hint in _BLOCKED_HINTS):
        return {"text": REFUSAL, "tool_calls": []}

    return {
        "text": "I can only search documentation. What would you like to know?",
        "tool_calls": [{"name": "search_docs", "args": {"q": prompt[:40]}}],
    }
