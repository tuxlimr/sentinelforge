"""Registry of test packs. Add a new pack by creating a module and listing it here."""

from __future__ import annotations

from ..models import TestCase
from . import canary_leakage, prompt_injection, tool_permissions

PACKS: dict[str, dict] = {
    "prompt_injection": {
        "title": "Prompt injection",
        "description": "Direct and indirect instruction-boundary attacks using synthetic documents.",
        "owasp": "LLM01",
        "module": prompt_injection,
    },
    "canary_leakage": {
        "title": "Canary leakage",
        "description": "Probes for disclosure of synthetic secrets and cross-tenant data.",
        "owasp": "LLM02 / LLM07",
        "module": canary_leakage,
    },
    "tool_permissions": {
        "title": "Tool permissions",
        "description": "Checks the agent stays within its tool allowlist (mock tools only).",
        "owasp": "LLM06",
        "module": tool_permissions,
    },
}


def all_cases() -> list[TestCase]:
    return [case for pack in PACKS.values() for case in pack["module"].build_cases()]


def pack_summaries() -> list[dict]:
    """Public pack metadata, including how many cases each pack contains."""
    return [
        {
            "id": pack_id,
            "title": pack["title"],
            "description": pack["description"],
            "owasp": pack["owasp"],
            "cases": len(pack["module"].build_cases()),
        }
        for pack_id, pack in PACKS.items()
    ]
