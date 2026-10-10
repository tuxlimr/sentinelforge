"""`sentinelforge guide`: a first-run walkthrough of the whole find -> verify -> regress loop.

Everything runs offline against the bundled demo apps, so it needs no API keys and touches nothing remote.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.rule import Rule

from .engine import execute
from .engine.replay import ReplayRequest, replay
from .models import RunRequest, TargetSpec
from .storage import regressions, runs
from .terminal import STATUS_NOTE, print_findings, print_results, print_summary

EXPORT_FILE = "sentinelforge_regressions.py"


def _step(console: Console, number: int, title: str) -> None:
    console.print()
    console.print(Rule(f"[bold]Step {number}: {title}[/]", align="left"))


def _proceed(assume_yes: bool, question: str, default: bool = True) -> bool:
    return True if assume_yes else typer.confirm(question, default=default)


def _scan(console: Console, kind: str):
    request = RunRequest(target=TargetSpec(kind=kind), label="guide")  # type: ignore[arg-type]
    with console.status(f"Running test packs against {kind}..."):
        run = execute(request)
    runs.save_run(run)
    return run


def _replay(console: Console, kind: str) -> list:
    with console.status(f"Replaying saved regressions against {kind}..."):
        results = replay(ReplayRequest(target=TargetSpec(kind=kind)))  # type: ignore[arg-type]
    for result in results:
        console.print(f"  {STATUS_NOTE[result.status]}  {result.id}")
    return results


def run_guide(console: Console, assume_yes: bool = False) -> int:
    """Walk through scan, triage, regression, fix and replay. Returns a process exit code."""
    console.print("[bold]SentinelForge guided tour[/]  (about 2 minutes, fully offline)")
    console.print("You will scan a deliberately vulnerable demo app, lock its failures in as regression tests,\n"
                  "then confirm a fixed app passes them. This is the loop you would run in CI.")

    _step(console, 1, "Scan an app with known weaknesses")
    run = _scan(console, "vulnerable_demo")
    print_results(console, run)
    print_summary(console, run)
    if not run.findings:
        console.print("[yellow]The demo reported no findings, so there is nothing to walk through. Check your install.[/]")
        return 1

    _step(console, 2, "Understand the findings")
    console.print(f"{len(run.findings)} findings. Each shows what was expected, what happened, and how to fix it. Top 3:")
    print_findings(console, run, limit=3)
    if not _proceed(assume_yes, "Continue to lock these in as regression tests?"):
        console.print(f"Stopped. Resume anytime with `sentinelforge regressions add --run {run.id}`.")
        return 0

    _step(console, 3, "Save confirmed findings as regression tests")
    saved = [regressions.add_regression(f.case_id, run.id) for f in run.findings if f.status == "confirmed"]
    console.print(f"Saved {len(saved)} regression cases to {runs.data_dir() / 'regressions.jsonl'}")

    _step(console, 4, "Replay them against the still-vulnerable app")
    console.print("Before any fix, every regression should fail. That proves the tests really detect the problem.")
    before = _replay(console, "vulnerable_demo")
    broken = sum(r.status == "blocked" for r in before)
    console.print(f"{broken} of {len(before)} regressions caught the vulnerability.")

    _step(console, 5, "Apply a fix and replay")
    console.print("In your own project you would apply each finding's Fix. Here we switch to the hardened demo app.")
    if not _proceed(assume_yes, "Replay against the fixed app?"):
        return 0
    after = _replay(console, "safe_demo")
    fixed = sum(r.status == "passing" for r in after)
    colour = "green" if fixed == len(after) else "yellow"
    console.print(f"[{colour}]{fixed} of {len(after)} regressions pass on the fixed app.[/]")

    _step(console, 6, "Export the regressions as pytest tests for CI")
    target = Path.cwd() / EXPORT_FILE
    if target.exists() and not _proceed(assume_yes, f"{EXPORT_FILE} exists. Overwrite?", default=False):
        console.print(f"Kept existing {EXPORT_FILE}.")
    else:
        target.write_text(regressions.export_pytest(), encoding="utf-8")
        console.print(f"Wrote {target}. Point its TARGET at your app and run `pytest {EXPORT_FILE}`.")

    console.print()
    console.print("[bold green]Tour complete.[/] Next:")
    console.print("  sentinelforge init          add the CI workflow to your repo")
    console.print("  sentinelforge serve         open the dashboard API for the web UI")
    console.print("  sentinelforge report latest --format markdown")
    console.print("[dim]A passing run means the configured tests found no failure. It is not proof of security.[/]")
    return 0 if fixed == len(after) else 1

