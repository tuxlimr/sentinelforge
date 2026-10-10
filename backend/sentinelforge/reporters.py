"""Report formats. SARIF 2.1.0 lets findings show up in code-scanning tools."""

from __future__ import annotations

from . import __version__
from .models import Run

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "informational": "note"}


def to_sarif(run: Run) -> dict:
    rules = {
        f.case_id: {
            "id": f.case_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "help": {"text": f.mitigation},
            "properties": {"category": f.category, "pack": f.pack},
        }
        for f in run.findings
    }
    results = [
        {
            "ruleId": f.case_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.risk}. {f.evidence.assertion}. Status: {f.status}."},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"target/{run.target}"}}}],
            "properties": {"severity": f.severity, "confidence": f.confidence, "runId": run.id},
        }
        for f in run.findings
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SentinelForge", "version": __version__, "rules": list(rules.values())}},
            "results": results,
        }],
    }
