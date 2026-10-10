"""An HTTP target that is not an AI endpoint should give a clear, inconclusive error, never a pass."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sentinelforge.engine import execute
from sentinelforge.engine.replay import ReplayRequest, replay
from sentinelforge.models import Limits, RunRequest, Scope, TargetSpec
from sentinelforge.storage import regressions


def make_server(handler_fn, path_check=lambda p: True):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            handler_fn(self)

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/ask"


def _send(handler, status, body, content_type="text/plain"):
    data = body.encode()
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def run_http(url, concurrency=None):
    spec = TargetSpec(kind="http", url=url)
    scope = Scope(authorization_confirmed=True, allowed_hosts=["127.0.0.1"])
    return execute(RunRequest(target=spec, scope=scope, limits=Limits(max_concurrency=concurrency)))


@pytest.fixture
def server(request):
    httpd, url = make_server(request.param)
    yield url
    httpd.shutdown()


def notes(run):
    return [r.note for r in run.results]


def every_note_is_a_human_message(run):
    # A TargetError note is a sentence; a bare exception type (the old behaviour) is one CamelCase word.
    return all(" " in note and not note.isidentifier() for note in notes(run))


@pytest.mark.parametrize("server", [lambda h: _send(h, 404, "Not Found")], indirect=True)
def test_404_is_inconclusive_with_a_helpful_note(server):
    run = run_http(server, concurrency=1)  # sequential: the toy server handles loopback reliably
    assert run.counts["error"] == 11 and run.counts["passed"] == 0 and run.counts["failed"] == 0
    assert run.verdict != "pass" and not run.findings
    assert every_note_is_a_human_message(run)  # not a bare "HTTPStatusError"
    assert any("HTTP 404" in note and "LLM endpoint" in note for note in notes(run))


@pytest.mark.parametrize("server", [lambda h: _send(h, 403, "Forbidden")], indirect=True)
def test_403_mentions_credentials_or_waf(server):
    run = run_http(server, concurrency=1)
    assert any("HTTP 403" in n and ("credentials" in n or "WAF" in n) for n in notes(run))


@pytest.mark.parametrize("server", [lambda h: _send(h, 200, "<html><body>Hello</body></html>", "text/html")], indirect=True)
def test_html_200_is_not_treated_as_an_ai_response(server):
    run = run_http(server, concurrency=1)
    assert run.counts["error"] == 11 and run.counts["passed"] == 0
    assert any("HTML page" in note for note in notes(run))


@pytest.mark.parametrize("server", [lambda h: _send(h, 200, '{"text": "I cannot help with that."}', "application/json")], indirect=True)
def test_a_real_ai_json_response_is_evaluated_normally(server):
    run = run_http(server, concurrency=1)  # sequential: avoid loopback concurrency flakiness
    assert run.counts["passed"] >= 1  # a proper AI reply is scored, not errored
    # No case was rejected as a non-AI endpoint (a transient connection blip would be acceptable, a protocol reject is not).
    assert not any(any(s in r.note for s in ("not an AI", "HTTP 4", "HTTP 5")) for r in run.results)


def test_unreachable_target_is_a_clear_error():
    run = run_http("http://127.0.0.1:9/ask")  # nothing listening
    assert run.counts["error"] == 11 and "Could not reach" in run.results[0].note


@pytest.mark.parametrize("server", [lambda h: _send(h, 404, "nope")], indirect=True)
def test_replay_against_a_non_ai_target_reports_the_reason(server, tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_HOME", str(tmp_path))
    regressions.add_regression("SF-PI-001", "test")
    spec = TargetSpec(kind="http", url=server)
    scope = Scope(authorization_confirmed=True, allowed_hosts=["127.0.0.1"])
    results = replay(ReplayRequest(target=spec, scope=scope))
    assert results[0].status == "error" and "HTTP 404" in results[0].message
