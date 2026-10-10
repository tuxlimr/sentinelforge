"""Terminal rendering shared by `test`, `report` and `guide`. ASCII-only so piped output never breaks."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from .models import SEVERITY_RANK, Run

VERDICT_STYLE = {"pass": "green", "warn": "yellow", "fail": "red"}
SEVERITY_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "informational": "dim"}
STATUS_NOTE = {"passing": "[green]PASSING[/]", "blocked": "[red]STILL VULNERABLE[/]", "error": "[yellow]ERROR[/]"}
VERDICT_TEXT = {
    "pass": "No failures detected by the configured tests.",
    "warn": "Some issues or inconclusive cases need review.",
    "fail": "Confirmed high-severity findings. This build should not ship.",
}


def severity_failures(run: Run, fail_on: str) -> list:
    """Confirmed findings at or above the CI threshold."""
    threshold = SEVERITY_RANK[fail_on]
    return [f for f in run.findings if f.status == "confirmed" and SEVERITY_RANK[f.severity] >= threshold]


def print_results(console: Console, run: Run) -> None:
    table = Table(title=f"Run {run.id} on {run.target}", title_justify="left")
    for column in ("Case", "Pack", "Severity", "Outcome"):
        table.add_column(column)
    for result in run.results:
        outcome = {"passed": "[green]PASS[/]", "failed": "[red]FAIL[/]"}.get(result.outcome, f"[yellow]{result.outcome.upper()}[/]")
        severity = f"[{SEVERITY_STYLE[result.severity]}]{result.severity}[/]"
        name = escape(result.name)
        if result.outcome in ("error", "skipped") and result.note:
            name += f"\n[dim]{escape(result.note)}[/]"
        table.add_row(f"{result.case_id} {name}", result.pack, severity, outcome)
    console.print(table)


def print_findings(console: Console, run: Run, limit: int | None = None) -> None:
    """Each finding: what failed, the evidence, and how to fix it."""
    for finding in run.findings[:limit]:
        style = SEVERITY_STYLE[finding.severity]
        body = (
            f"[bold]Risk:[/] {escape(finding.risk)}\n"
            f"[bold]Expected:[/] {escape(finding.expected)}\n"
            f"[bold]Observed:[/] {escape(finding.evidence.assertion)}\n"
            f"[bold]Sent:[/] {escape(_clip(finding.evidence.prompt))}\n"
            f"[bold]Reply:[/] {escape(_clip(finding.evidence.response))}\n"
            f"[bold green]Fix:[/] {escape(finding.mitigation)}\n"
            f"[dim]{finding.reproductions} Limits: {escape(finding.limitations)}[/]"
        )
        console.print(Panel(body, title=f"[{style}]{finding.severity.upper()}[/] {finding.case_id} {escape(finding.title)} ({finding.status})",
                            title_align="left", border_style=style))
    hidden = len(run.findings) - len(run.findings[:limit])
    if hidden > 0:
        console.print(f"[dim]... and {hidden} more. See `sentinelforge report {run.id}`.[/]")


def print_summary(console: Console, run: Run) -> None:
    counts = run.counts
    line = f"{counts.get('passed', 0)} passed, {counts.get('failed', 0)} failed, {counts.get('error', 0)} errored, {counts.get('skipped', 0)} skipped"
    style = VERDICT_STYLE[run.verdict]
    console.print(f"\n[bold {style}]Verdict: {run.verdict.upper()}[/]  {VERDICT_TEXT[run.verdict]}")
    console.print(f"{line} in {run.duration_ms} ms ({run.budget.get('requests', 0)} requests).")
    for warning in run.warnings:
        console.print(f"[dim]Note: {warning}[/]")


def print_next_steps(console: Console, run: Run, fail_on: str = "high", rerun: str | None = None) -> None:
    rerun = escape(rerun or f"--target {run.target_kind}")
    steps = []
    if run.findings:
        steps.append(f"Fix the issues above, then re-run: sentinelforge test {rerun}")
        steps.append(f"Lock them in as tests:        sentinelforge regressions add --run {run.id}")
        steps.append(f"Replay after your fix:        sentinelforge regressions replay {rerun}")
    else:
        steps.append("Add this to CI:               sentinelforge init")
        steps.append("Export findings to GitHub:    sentinelforge report latest --format sarif -o sentinelforge.sarif")
    steps.append(f"Full report:                  sentinelforge report {run.id} --format markdown")
    console.print(Panel("\n".join(steps), title="Next steps", title_align="left", border_style="blue"))


def to_markdown(run: Run) -> str:
    lines = [
        f"# SentinelForge report: {run.id}",
        "",
        f"- Target: `{run.target}` ({run.target_kind})",
        f"- Verdict: **{run.verdict.upper()}** ({VERDICT_TEXT[run.verdict]})",
        f"- Started: {run.started_at}, duration {run.duration_ms} ms",
        f"- Tool {run.tool_version}, packs {run.pack_version}, config `{run.config_hash}`",
        "",
        "## Results",
        "",
        "| Case | Pack | Severity | Outcome |",
        "|---|---|---|---|",
        *[f"| {r.case_id} {r.name} | {r.pack} | {r.severity} | {r.outcome} |" for r in run.results],
        "",
        f"## Findings ({len(run.findings)})",
        "",
    ]
    for f in run.findings:
        lines += [
            f"### {f.case_id}: {f.title} ({f.severity}, {f.status})",
            "",
            f"- **Risk:** {f.risk}",
            f"- **Expected:** {f.expected}",
            f"- **Observed:** {f.evidence.assertion}",
            f"- **Confidence:** {f.confidence}; evidence: {f.evidence_quality}",
            f"- **Fix:** {f.mitigation}",
            f"- **Limitations:** {f.limitations}",
            "",
        ]
    if not run.findings:
        lines += ["No findings.", ""]
    lines += ["## Caveats", "", *[f"- {w}" for w in run.warnings], f"- {run.sanitization}", ""]
    return "\n".join(lines)


def _clip(text: str, width: int = 140) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 3] + "..."


