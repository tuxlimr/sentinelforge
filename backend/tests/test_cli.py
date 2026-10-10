import json

import pytest
from typer.testing import CliRunner

from sentinelforge.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Each test gets its own data dir and working directory."""
    monkeypatch.setenv("SENTINELFORGE_HOME", str(tmp_path / "data"))
    monkeypatch.chdir(tmp_path)


def test_guide_runs_the_whole_loop_and_exports_pytest(tmp_path):
    result = runner.invoke(app, ["guide", "--yes"])
    assert result.exit_code == 0, result.output
    assert "11 of 11 regressions caught the vulnerability" in result.output
    assert "11 of 11 regressions pass on the fixed app" in result.output
    exported = (tmp_path / "sentinelforge_regressions.py").read_text(encoding="utf-8")
    compile(exported, "exported", "exec")


def test_test_command_exit_codes_gate_the_build():
    assert runner.invoke(app, ["test", "--target", "safe_demo"]).exit_code == 0
    assert runner.invoke(app, ["test", "--target", "vulnerable_demo"]).exit_code == 1
    assert runner.invoke(app, ["test", "--target", "nonsense"]).exit_code == 2  # rejected by the CLI, not a traceback


def test_machine_formats_are_pure_json():
    result = runner.invoke(app, ["test", "--target", "vulnerable_demo", "--format", "json"])
    assert json.loads(result.stdout)["verdict"] == "fail" and result.exit_code == 1
    sarif = runner.invoke(app, ["test", "--target", "vulnerable_demo", "--format", "sarif"])
    assert json.loads(sarif.stdout)["version"] == "2.1.0"


def test_report_latest_and_missing_run():
    assert runner.invoke(app, ["report", "latest"]).exit_code == 2  # nothing saved yet: clear error
    runner.invoke(app, ["test", "--target", "vulnerable_demo"])
    markdown = runner.invoke(app, ["report", "latest", "--format", "markdown"])
    assert markdown.exit_code == 0 and "## Findings (11)" in markdown.stdout
    assert runner.invoke(app, ["report", "does-not-exist"]).exit_code == 2


def test_regressions_gate_fails_until_the_app_is_fixed():
    assert runner.invoke(app, ["regressions", "replay"]).exit_code == 1  # none saved
    runner.invoke(app, ["test", "--target", "vulnerable_demo"])
    assert runner.invoke(app, ["regressions", "add", "--run", "latest"]).exit_code == 0
    assert runner.invoke(app, ["regressions", "replay", "--target", "vulnerable_demo"]).exit_code == 1
    assert runner.invoke(app, ["regressions", "replay", "--target", "safe_demo"]).exit_code == 0


def test_untrusted_text_with_brackets_does_not_break_rendering(monkeypatch):
    from sentinelforge.terminal import print_findings
    from rich.console import Console
    from sentinelforge.engine import execute
    from sentinelforge.models import RunRequest, TargetSpec

    run = execute(RunRequest(target=TargetSpec(kind="vulnerable_demo")))
    run.findings[0].evidence.response = "[/bold] [red]oops[/ closing tag"
    print_findings(Console(record=True, width=100), run, limit=1)  # must not raise MarkupError


def test_init_writes_workflow_once():
    first = runner.invoke(app, ["init"])
    assert first.exit_code == 0
    assert runner.invoke(app, ["init"]).exit_code == 1  # refuses to overwrite
    assert runner.invoke(app, ["init", "--force"]).exit_code == 0
