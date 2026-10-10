"""Command-line interface: guided tour, CI test runs, reports, regressions, and the API for the web UI."""

from __future__ import annotations

import json
from contextlib import nullcontext
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .adapters import ScopeError
from .config_file import ConfigError, ProjectConfig, load_config, starter_config
from .engine import execute
from .engine.replay import ReplayRequest, replay
from .models import Limits, Run, RunRequest, Scope, TargetSpec
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
        raise _fail(f"Run '{run_id}' not found. List runs with `sentinelforge report latest` or look in .sentinelforge/sentinelforge.db.")
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


ConfigOption = Annotated[Path | None, typer.Option("--config", "-c", help="Project config (sentinelforge.yaml) for testing your own app")]


def _load_config(path: Path) -> ProjectConfig:
    try:
        return load_config(path)
    except ConfigError as error:
        raise _fail(str(error)) from error


def _resolve(config: Path | None, target: Target | None) -> tuple[ProjectConfig | None, TargetSpec, Scope, str]:
    """Config file or demo target (not both). Returns the config, target, scope and how to re-run it."""
    if config and target:
        raise _fail("Use either --config or --target, not both.")
    if config:
        project = _load_config(config)
        try:
            spec = project.target_spec()
        except ConfigError as error:
            raise _fail(str(error)) from error
        return project, spec, project.scope_model(), f"--config {config}"
    kind = (target or Target.safe_demo).value
    return None, TargetSpec(kind=kind), Scope(), f"--target {kind}"


@app.command()
def test(
    config: ConfigOption = None,
    target: Annotated[Target | None, typer.Option(help="A bundled demo app (default: safe_demo). Use --config for your own app.")] = None,
    fail_on: Annotated[Severity | None, typer.Option(help="Lowest severity that fails the build (default: config ci.fail_on, else high)")] = None,
    concurrency: Annotated[int | None, typer.Option(min=1, max=256, help="Parallel workers (default: auto-sized to this machine)")] = None,
    format: Annotated[Format, typer.Option(help="terminal for people; json/sarif/markdown for machines")] = Format.terminal,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write the report here instead of stdout")] = None,
    details: Annotated[bool, typer.Option(help="Show full evidence and fixes for each finding")] = True,
) -> None:
    """Run the test packs and exit 1 when a confirmed finding meets --fail-on (exit 2 = scope/config error)."""
    project, spec, scope, rerun = _resolve(config, target)
    threshold = fail_on.value if fail_on else (project.ci.fail_on if project else "high")
    if project:
        request = project.run_request()
        if concurrency:
            request.limits.max_concurrency = concurrency
    else:
        request = RunRequest(target=spec, scope=scope, limits=Limits(max_concurrency=concurrency))
    name = spec.name or spec.url or spec.kind
    try:
        with console.status(f"Testing {escape(name)}...", spinner="line") if format is Format.terminal else nullcontext():
            run = execute(request)
    except ScopeError as error:
        raise _fail(f"Scope error: {error}") from error
    runs.save_run(run)

    if format is Format.terminal:
        print_results(console, run)
        if details:
            print_findings(console, run)
        print_summary(console, run)
        print_next_steps(console, run, threshold, rerun)
    else:
        _emit(run, format, output)

    raise typer.Exit(1 if severity_failures(run, threshold) else 0)


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
    config: ConfigOption = None,
    target: Annotated[Target | None, typer.Option(help="A bundled demo app (default: safe_demo). Use --config for your own app.")] = None,
) -> None:
    """Replay every saved regression. Exit 1 if any still reproduce (use as a CI gate)."""
    if not regressions.list_regressions():
        raise _fail("No regressions saved yet. Run `sentinelforge regressions add` first.", code=1)
    _, spec, scope, _ = _resolve(config, target)
    try:
        with console.status("Replaying regressions...", spinner="line"):
            results = replay(ReplayRequest(target=spec, scope=scope))
    except ScopeError as error:
        raise _fail(f"Scope error: {error}") from error
    for result in results:
        console.print(f"  {STATUS_NOTE[result.status]}  {escape(result.id)}  [dim]{escape(result.message)}[/]")
    bad = [r for r in results if r.status != "passing"]
    console.print(f"\n{len(results) - len(bad)} of {len(results)} regressions pass on {escape(spec.name or spec.url or spec.kind)}.")
    raise typer.Exit(1 if bad else 0)


@regressions_app.command("export")
def regressions_export(
    config: ConfigOption = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write a pytest file here")] = None,
) -> None:
    """Export regressions as a pytest file. With --config, the tests call your HTTP endpoint."""
    project = _load_config(config) if config else None
    if project and project.target.kind == "http":
        text = regressions.export_pytest(url=project.target.url, headers=project.target.headers,  # raw ${VAR} values
                                         allowed_tools=project.scope.allowed_tools, canaries=project.scope.canaries)
    else:
        text = regressions.export_pytest()
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"Wrote {output}")
    else:
        typer.echo(text)


@app.command()
def exposure(
    host: Annotated[str, typer.Argument(help="One hostname or IP address (localhost is always allowed)")],
    expect: Annotated[list[int] | None, typer.Option("--expect", "-e", help="A port that should be open (repeatable)")] = None,
    ports: Annotated[str | None, typer.Option(help="Comma-separated ports to probe (default: common app and AI-stack ports)")] = None,
    authorized: Annotated[bool, typer.Option("--authorized", help="Confirm you are authorized to scan a non-local host")] = False,
    fail_on: Annotated[Severity, typer.Option(help="Lowest severity that fails the build")] = Severity.high,
) -> None:
    """Check which TCP ports on a host are open that should not be (needs nmap)."""
    from .engine.exposure import DEFAULT_PORTS, ExposureError, ExposureRequest, scan

    try:
        probe = [int(p) for p in ports.split(",")] if ports else list(DEFAULT_PORTS)
        request = ExposureRequest(host=host, expected_ports=expect or [], ports=probe,
                                  scope=Scope(authorization_confirmed=authorized, allowed_hosts=[host] if authorized else []))
        with console.status(f"Scanning {host} with nmap...", spinner="line"):
            run = scan(request)
    except ValueError as error:
        raise _fail(f"Ports must be comma-separated integers: {error}") from error
    except ScopeError as error:
        raise _fail(f"Scope error: {error}") from error
    except ExposureError as error:
        raise _fail(str(error), code=3) from error
    runs.save_run(run)
    print_results(console, run)
    print_findings(console, run)
    print_summary(console, run)
    raise typer.Exit(1 if severity_failures(run, fail_on.value) else 0)


@app.command()
def webscan(
    url: Annotated[str, typer.Argument(help="The site to check, e.g. https://your-site.example.com/ (localhost is always allowed)")],
    authorized: Annotated[bool, typer.Option("--authorized", help="Confirm you own this site or are authorized to test it")] = False,
    fail_on: Annotated[Severity, typer.Option(help="Lowest severity that fails the build")] = Severity.high,
) -> None:
    """Check a website for misconfigurations and outdated front-end libraries (passive: GET requests only)."""
    from urllib.parse import urlparse

    from .engine.webscan import WebScanRequest, scan as web_scan

    host = urlparse(url).hostname or ""
    request = WebScanRequest(url=url, scope=Scope(authorization_confirmed=authorized, allowed_hosts=[host] if authorized else []))
    try:
        with console.status(f"Checking {escape(url)}...", spinner="line"):
            run = web_scan(request)
    except ScopeError as error:
        raise _fail(f"Scope error: {error}") from error
    runs.save_run(run)
    print_results(console, run)
    print_findings(console, run)
    print_summary(console, run)
    raise typer.Exit(1 if severity_failures(run, fail_on.value) else 0)


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
      - run: pip install sentinelforge-ai   # the PyPI name; "sentinelforge" on PyPI is a different project
      - name: Run security tests
        run: sentinelforge test --config sentinelforge.yaml --format sarif -o sentinelforge.sarif
        # env:
        #   APP_TOKEN: ${{ secrets.APP_TOKEN }}   # for headers that reference ${APP_TOKEN}
      - name: Replay saved regressions
        if: hashFiles('.sentinelforge/sentinelforge.db') != ''
        run: sentinelforge regressions replay --config sentinelforge.yaml
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sentinelforge.sarif
"""


@app.command()
def init(
    url: Annotated[str | None, typer.Option(help="Your app's endpoint, e.g. https://app.example.com/api/ask")] = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing files")] = False,
) -> None:
    """Create sentinelforge.yaml and a GitHub Actions workflow that gates builds on it."""
    try:
        config_text = starter_config(url)
    except ConfigError as error:
        raise _fail(str(error)) from error
    files = {Path.cwd() / "sentinelforge.yaml": config_text,
             Path.cwd() / ".github" / "workflows" / "sentinelforge.yml": WORKFLOW}
    existing = [str(path) for path in files if path.exists()]
    if existing and not force:
        raise _fail(f"Already exists: {', '.join(existing)}. Use --force to overwrite.", code=1)
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        console.print(f"Wrote {path}")
    if url:
        console.print("Next: confirm you are authorized to test this app, set scope.authorization_confirmed: true, "
                      "then run `sentinelforge test --config sentinelforge.yaml`.")
    else:
        console.print("Next: edit the target in sentinelforge.yaml to point at your app, "
                      "or run `sentinelforge init --url <your endpoint> --force`.")


@app.command()
def serve(port: int = 8000) -> None:
    """Start the API (bound to localhost only) for the React dashboard."""
    import uvicorn

    uvicorn.run("sentinelforge.api:app", host="127.0.0.1", port=port)


