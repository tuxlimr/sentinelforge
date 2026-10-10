"""Command-line interface: guided tour, CI test runs, reports, regressions, and the API for the web UI."""

from __future__ import annotations

import json
from contextlib import nullcontext
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .adapters import ScopeError
from .engine import execute
from .engine.replay import ReplayRequest, replay
from .models import Limits, Run, RunRequest, TargetSpec
from .reporters import to_sarif
from .storage import regressions, runs
from .terminal import (
    STATUS_NOTE, print_findings, print_next_steps, print_results, print_summary, severity_failures, to_markdown,
)

app = typer.Typer(help="SentinelForge: security regression testing for AI apps. New here? Run `sentinelforge guide`.",
                  no_args_is_help=True)
regressions_app = typer.Typer(help="Manage and replay saved regression tests.", no_args_is_help=True)
app.add_typer(regressions_app, name="regressions")
console = Console()


class Target(str, Enum):
    vulnerable_demo = "vulnerable_demo"
    safe_demo = "safe_demo"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class Format(str, Enum):
    terminal = "terminal"
    json = "json"
    sarif = "sarif"
    markdown = "markdown"


def _fail(message: str, code: int = 2) -> typer.Exit:
    console.print(f"[red]Error:[/red] {message}")
    return typer.Exit(code)


def _load_run(run_id: str) -> Run:
    """Resolve a run id, or `latest`, with a helpful message when there is none."""
    if run_id == "latest":
        history = runs.list_runs()
        if not history:
            raise _fail("No runs yet. Start with `sentinelforge guide` or `sentinelforge test`.")
        return history[0]
    run = runs.get_run(run_id)
    if run is None:
        raise _fail(f"Run '{run_id}' not found. List runs with `sentinelforge report latest` or check .sentinelforge/runs.")
    return run


def _render(run: Run, fmt: Format) -> str:
    if fmt is Format.json:
        return run.model_dump_json(indent=2)
    if fmt is Format.sarif:
        return json.dumps(to_sarif(run), indent=2)
    return to_markdown(run)


def _emit(run: Run, fmt: Format, output: Path | None) -> None:
    """Write a machine-readable report to a file, or to stdout when no path is given."""
    text = _render(run, fmt)
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"Wrote {fmt.value} report to {output}")
    else:
        typer.echo(text)


@app.command()
def guide(
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Accept every prompt (non-interactive)")] = False,
) -> None:
    """Interactive first-run tour: scan, understand findings, save regressions, fix, replay, export."""
    from .guide import run_guide

    raise typer.Exit(run_guide(console, assume_yes=yes))


@app.command()
def test(
    target: Annotated[Target, typer.Option(help="Which bundled demo app to test")] = Target.safe_demo,
    fail_on: Annotated[Severity, typer.Option(help="Lowest severity that fails the build")] = Severity.high,
    concurrency: Annotated[int | None, typer.Option(min=1, max=256, help="Parallel workers (default: auto-sized to this machine)")] = None,
    format: Annotated[Format, typer.Option(help="terminal for people; json/sarif/markdown for machines")] = Format.terminal,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write the report here instead of stdout")] = None,
    details: Annotated[bool, typer.Option(help="Show full evidence and fixes for each finding")] = True,
) -> None:
    """Run all packs and exit 1 when a confirmed finding meets --fail-on (exit 2 = scope/config error)."""
    try:
        request = RunRequest(target=TargetSpec(kind=target.value), limits=Limits(max_concurrency=concurrency))
        with console.status(f"Testing {target.value}...") if format is Format.terminal else nullcontext():
            run = execute(request)
    except ScopeError as error:
        raise _fail(f"Scope error: {error}") from error
    runs.save_run(run)

    if format is Format.terminal:
        print_results(console, run)
        if details:
            print_findings(console, run)
        print_summary(console, run)
        print_next_steps(console, run, fail_on.value)
    else:
        _emit(run, format, output)

    raise typer.Exit(1 if severity_failures(run, fail_on.value) else 0)


@app.command()
def report(
    run_id: Annotated[str, typer.Argument(help="A run id, or 'latest'")] = "latest",
    format: Annotated[Format, typer.Option(help="Output format")] = Format.terminal,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write to a file")] = None,
) -> None:
    """Show or export a saved run."""
    run = _load_run(run_id)
    if format is Format.terminal:
        print_results(console, run)
        print_findings(console, run)
        print_summary(console, run)
    else:
        _emit(run, format, output)


@regressions_app.command("list")
def regressions_list() -> None:
    """List saved regression tests."""
    records = regressions.list_regressions()
    if not records:
        console.print("No regressions saved yet. After a scan: `sentinelforge regressions add --run latest`.")
        return
    table = Table(title=f"{len(records)} regression tests")
    for column in ("ID", "Name", "Severity", "Source"):
        table.add_column(column)
    for record in records:
        table.add_row(record["id"], record["name"], record["severity"], record["source"])
    console.print(table)


@regressions_app.command("add")
def regressions_add(
    run: Annotated[str, typer.Option(help="Run id, or 'latest'")] = "latest",
    case: Annotated[str | None, typer.Option(help="Only this case id (default: all confirmed findings)")] = None,
) -> None:
    """Save a run's confirmed findings as replayable regression tests."""
    source = _load_run(run)
    chosen = [f for f in source.findings if f.status == "confirmed" and (case is None or f.case_id == case)]
    if not chosen:
        raise _fail("No confirmed findings to save" + (f" for case {case}." if case else " in that run."), code=1)
    for finding in chosen:
        regressions.add_regression(finding.case_id, source.id)
    console.print(f"Saved {len(chosen)} regression(s) from run {source.id}. Replay: `sentinelforge regressions replay`.")


@regressions_app.command("replay")
def regressions_replay(
    target: Annotated[Target, typer.Option(help="Which demo app to replay against")] = Target.safe_demo,
) -> None:
    """Replay every saved regression. Exit 1 if any still reproduce (use as a CI gate)."""
    if not regressions.list_regressions():
        raise _fail("No regressions saved yet. Run `sentinelforge regressions add` first.", code=1)
    try:
        results = replay(ReplayRequest(target=TargetSpec(kind=target.value)))
    except ScopeError as error:
        raise _fail(f"Scope error: {error}") from error
    for result in results:
        console.print(f"  {STATUS_NOTE[result.status]}  {result.id}  [dim]{result.message}[/]")
    bad = [r for r in results if r.status != "passing"]
    console.print(f"\n{len(results) - len(bad)} of {len(results)} regressions pass on {target.value}.")
    raise typer.Exit(1 if bad else 0)


@regressions_app.command("export")
def regressions_export(
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write a pytest file here")] = None,
) -> None:
    """Export regressions as a pytest file."""
    text = regressions.export_pytest()
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"Wrote {output}")
    else:
        typer.echo(text)


WORKFLOW = """\
name: SentinelForge
on: [push, pull_request]

jobs:
  ai-security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.14"
      - run: pip install sentinelforge
      # Replace safe_demo with your own target once you have one configured.
      - name: Run security tests
        run: sentinelforge test --target safe_demo --fail-on high --format sarif -o sentinelforge.sarif
      - name: Replay saved regressions
        run: sentinelforge regressions replay --target safe_demo
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sentinelforge.sarif
"""


@app.command()
def init(
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing workflow")] = False,
) -> None:
    """Add a GitHub Actions workflow that gates builds on SentinelForge."""
    path = Path.cwd() / ".github" / "workflows" / "sentinelforge.yml"
    if path.exists() and not force:
        raise _fail(f"{path} already exists. Use --force to overwrite.", code=1)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(WORKFLOW, encoding="utf-8")
    console.print(f"Wrote {path}")
    console.print("Commit it, and builds will fail on confirmed findings. Edit the target line to test your own app.")


@app.command()
def serve(port: int = 8000) -> None:
    """Start the API (bound to localhost only) for the React dashboard."""
    import uvicorn

    uvicorn.run("sentinelforge.api:app", host="127.0.0.1", port=port)


