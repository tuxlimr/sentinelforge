"""`sentinelforge.yaml`: strict loading, and the full loop against a real HTTP endpoint."""

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from typer.testing import CliRunner

from sentinelforge.cli import app
from sentinelforge.config_file import ConfigError, load_config, starter_config
from sentinelforge.demo import safe_app, vulnerable_app

runner = CliRunner()
TOKEN = "s3cret-token-value"


class _App(BaseHTTPRequestHandler):
    """A stand-in for a user's AI app: /vulnerable and /safe, behind a bearer token."""

    def do_POST(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send_response(401)
            self.end_headers()
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        handler = vulnerable_app.ask if self.path == "/vulnerable" else safe_app.ask
        payload = json.dumps(handler(body["prompt"], body.get("context"))).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture(autouse=True)
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("APP_TOKEN", TOKEN)
    return tmp_path


def write_config(tmp_path, url, *, authorized=True, hosts=("127.0.0.1",), extra="", headers=None):
    headers = headers if headers is not None else {"Authorization": "Bearer ${APP_TOKEN}"}
    header_yaml = "".join(f"\n    {k}: {json.dumps(v)}" for k, v in headers.items())
    text = f"""version: 1
target:
  kind: http
  url: {json.dumps(url)}
  headers:{header_yaml or " {}"}
scope:
  authorization_confirmed: {str(authorized).lower()}
  allowed_hosts: {json.dumps(list(hosts))}
limits:
  verify_repeats: 1
{extra}"""
    path = tmp_path / "sentinelforge.yaml"
    path.write_text(text, encoding="utf-8")
    return path


# --- strict loading ------------------------------------------------------------------------------

def test_unknown_keys_are_rejected_at_every_level(tmp_path):
    for extra in ("telemetry: on", "scope_typo: true"):
        path = write_config(tmp_path, "http://127.0.0.1/x", extra=extra)
        with pytest.raises(ConfigError, match="Extra inputs"):
            load_config(path)
    path = write_config(tmp_path, "http://127.0.0.1/x")
    path.write_text(path.read_text().replace("authorization_confirmed", "authorisation_confirmed"))
    with pytest.raises(ConfigError, match="authorisation_confirmed"):
        load_config(path)


def test_literal_secrets_in_sensitive_headers_are_refused(tmp_path):
    path = write_config(tmp_path, "http://127.0.0.1/x", headers={"X-Api-Key": "abc123literal"})
    with pytest.raises(ConfigError, match="environment variable") as error:
        load_config(path)
    assert "abc123literal" not in str(error.value)  # never echo the secret back


def test_missing_env_var_is_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.delenv("APP_TOKEN")
    with pytest.raises(ConfigError, match=r"\$\{APP_TOKEN\}"):
        load_config(write_config(tmp_path, "http://127.0.0.1/x")).run_request()


def test_malformed_files_fail_cleanly(tmp_path):
    path = tmp_path / "sentinelforge.yaml"
    for text in ("[1, 2", "just a string", "version: 2\ntarget: {kind: safe_demo}", "!!python/object/apply:os.system ['echo hi']"):
        path.write_text(text)
        with pytest.raises(ConfigError):
            load_config(path)
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.yaml")


def test_http_needs_a_url_and_demo_targets_take_no_url(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("version: 1\ntarget: {kind: http}")
    with pytest.raises(ConfigError, match="url is required"):
        load_config(path)
    path.write_text("version: 1\ntarget: {kind: safe_demo, url: 'http://x'}")
    with pytest.raises(ConfigError, match="only apply to http"):
        load_config(path)


def test_starter_configs_load_and_quote_the_url(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text(starter_config(None))
    assert load_config(path).target.kind == "safe_demo"
    path.write_text(starter_config("https://app.example.com/api/ask?x=1#frag: [evil]"))
    config = load_config(path)
    assert config.target.url == "https://app.example.com/api/ask?x=1#frag: [evil]"
    assert config.scope.allowed_hosts == ["app.example.com"] and config.scope.authorization_confirmed is False
    with pytest.raises(ConfigError):
        starter_config("not a url")


# --- the full loop against a real endpoint -------------------------------------------------------

def test_scope_is_enforced_for_http_targets(tmp_path, server):
    assert runner.invoke(app, ["test", "--config", str(write_config(tmp_path, server + "/vulnerable", authorized=False))]).exit_code == 2
    assert runner.invoke(app, ["test", "--config", str(write_config(tmp_path, server + "/vulnerable", hosts=["other.test"]))]).exit_code == 2
    assert runner.invoke(app, ["test", "--target", "safe_demo", "--config", "x.yaml"]).exit_code == 2


def test_find_regress_fix_replay_export_against_a_real_endpoint(tmp_path, server):
    vulnerable = write_config(tmp_path, server + "/vulnerable", extra="ci:\n  fail_on: critical")
    result = runner.invoke(app, ["test", "--config", str(vulnerable), "--format", "json"])
    run = json.loads(result.stdout)
    assert result.exit_code == 1 and run["target_kind"] == "http" and len(run["findings"]) == 11
    assert TOKEN not in result.stdout  # the secret header never reaches the report

    assert runner.invoke(app, ["regressions", "add", "--run", "latest"]).exit_code == 0
    assert runner.invoke(app, ["regressions", "replay", "--config", str(vulnerable)]).exit_code == 1

    fixed = write_config(tmp_path, server + "/safe")
    replayed = runner.invoke(app, ["regressions", "replay", "--config", str(fixed)])
    assert replayed.exit_code == 0 and "11 of 11 regressions pass" in replayed.output
    assert runner.invoke(app, ["test", "--config", str(fixed)]).exit_code == 0

    exported = runner.invoke(app, ["regressions", "export", "--config", str(fixed), "-o", "test_exported.py"])
    assert exported.exit_code == 0
    source = (tmp_path / "test_exported.py").read_text(encoding="utf-8")
    assert TOKEN not in source and "${APP_TOKEN}" in source
    done = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "test_exported.py"],
                          cwd=tmp_path, capture_output=True, text=True)
    assert "11 passed" in done.stdout, done.stdout[-1500:]


def test_init_writes_config_and_workflow(tmp_path):
    assert runner.invoke(app, ["init", "--url", "https://app.example.com/api/ask"]).exit_code == 0
    config = load_config(tmp_path / "sentinelforge.yaml")
    assert config.target.url == "https://app.example.com/api/ask" and not config.scope.authorization_confirmed
    workflow = (tmp_path / ".github" / "workflows" / "sentinelforge.yml").read_text()
    assert "--config sentinelforge.yaml" in workflow
    assert runner.invoke(app, ["init"]).exit_code == 1  # refuses to overwrite either file
