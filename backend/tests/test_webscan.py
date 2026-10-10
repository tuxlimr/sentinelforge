"""Website security check, exercised against real local HTTP servers."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from sentinelforge.adapters import ScopeError
from sentinelforge.api import app
from sentinelforge.cli import app as cli
from sentinelforge.engine.webscan import MAX_REQUESTS, PROBE_ORIGIN, WebScanRequest, _cookie_checks, _header_checks, _Page, scan
from sentinelforge.models import Scope

SECRETS = ["hunter2", "sk-live-0123456789", "abc123secure"]


def _respond(handler, status=200, body="", headers=()):
    data = body.encode()
    handler.send_response(status)
    for name, value in headers:
        handler.send_header(name, value)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


class Vulnerable(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.1"
    files = {"/.env": "DB_PASSWORD=hunter2\nAPI_KEY=sk-live-0123456789\n", "/.git/HEAD": "ref: refs/heads/main\n",
             "/phpinfo.php": "<html><title>phpinfo()</title></html>"}

    def do_GET(self):
        if self.path in self.files:
            return _respond(self, body=self.files[self.path])
        headers = [("X-Powered-By", "PHP/7.2.1"), ("Set-Cookie", "session=abc123secure; Path=/")]
        if origin := self.headers.get("Origin"):
            headers += [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]
        _respond(self, body="<html><title>Index of /</title></html>", headers=headers)

    def log_message(self, *args):
        pass


class Hardened(Vulnerable):
    server_version = "nginx"
    sys_version = ""

    def do_GET(self):
        if self.path != "/":
            return _respond(self, 404, "not found")
        _respond(self, body="<html><title>Home</title></html>", headers=[
            ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
            ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Set-Cookie", "session=x; Path=/; HttpOnly; SameSite=Lax")])


class SoftNotFound(Hardened):
    """Answers 200 with an HTML 'not found' page for every path: must not look like exposed files."""

    def do_GET(self):
        _respond(self, body="<html><title>Page not found</title>ref: nothing here; KEY = value</html>",
                 headers=[("Content-Security-Policy", "frame-ancestors 'none'"), ("X-Content-Type-Options", "nosniff"),
                          ("Referrer-Policy", "no-referrer")])


class OffsiteRedirect(Hardened):
    def do_GET(self):
        _respond(self, 302, headers=[("Location", "http://elsewhere.invalid/")])


_HARD_HEADERS = [
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
    ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Set-Cookie", "session=x; Path=/; HttpOnly; SameSite=Lax"),
]


class OldLibraries(Hardened):
    """Old library URLs, plus one same-host script whose version is only in the file banner."""

    requested: list[str] = []

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        OldLibraries.requested.append(path)
        if path == "/js/jquery.min.js":
            return _respond(self, body="/*! jQuery v1.11.0 | (c) jQuery Foundation */\n")
        if path != "/":
            return _respond(self, 404, "not found")
        _respond(self, headers=_HARD_HEADERS, body="""<html><head>
          <script src="/vendor/jquery-1.12.4.min.js"></script>
          <script src="/js/jquery.min.js"></script>
          <script src="https://cdn.invalid/npm/lodash@4.17.20/lodash.min.js"></script>
          <link rel="stylesheet" href="https://cdn.invalid/bootstrap-3.4.0.min.css"></link>
          <script src="https://cdn.invalid/moment.js/2.24.0/moment.min.js"></script>
          <script src="https://cdn.invalid/angularjs/1.6.4/angular.min.js"></script>
          <script src="https://cdn.invalid/jquery-ui-1.12.1/jquery-ui.min.js"></script>
          <link rel="stylesheet" href="/bootstrap-icons.min.css"></link>
          <!-- <script src="/jquery-1.8.0.min.js"></script> -->
        </head><body><p>jquery-1.8.0.min.js is only mentioned in the text.</p></body></html>""")


class CurrentLibraries(Hardened):
    def do_GET(self):
        if self.path != "/":
            return _respond(self, 404, "not found")
        _respond(self, headers=_HARD_HEADERS, body=(
            "<html><script src='https://cdn.invalid/jquery-3.7.1.min.js'></script>"
            "<script src='https://cdn.invalid/lodash@4.18.0/lodash.min.js'></script></html>"))


def serve(handler):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/"


@pytest.fixture
def site(request):
    httpd, url = serve(request.param)
    yield url
    httpd.shutdown()


def ids(run):
    return {f.case_id for f in run.findings}


@pytest.mark.parametrize("site", [Vulnerable], indirect=True)
def test_misconfigured_site_is_caught(site):
    run = scan(WebScanRequest(url=site))
    assert ids(run) >= {"WEB-001", "WEB-002", "WEB-003", "WEB-004", "WEB-006", "WEB-007", "WEB-008", "WEB-010",
                        "WEB-020", "WEB-021", "WEB-022"}
    assert run.verdict == "fail" and run.findings[0].severity == "critical"
    cors = next(f for f in run.findings if f.case_id == "WEB-010")
    assert cors.severity == "high" and PROBE_ORIGIN in cors.evidence.response
    assert run.budget["requests"] <= MAX_REQUESTS


@pytest.mark.parametrize("site", [Vulnerable], indirect=True)
def test_secret_values_are_never_stored(site):
    run = scan(WebScanRequest(url=site))
    stored = run.model_dump_json()
    assert not [s for s in SECRETS if s in stored]
    env = next(f for f in run.findings if f.case_id == "WEB-021")
    assert "DB_PASSWORD" in env.evidence.response and "API_KEY" in env.evidence.response  # names only


@pytest.mark.parametrize("site", [Hardened], indirect=True)
def test_hardened_site_passes(site):
    run = scan(WebScanRequest(url=site))
    assert not run.findings and run.verdict == "pass", [f.case_id for f in run.findings]


@pytest.mark.parametrize("site", [SoftNotFound], indirect=True)
def test_sites_that_answer_200_for_everything_are_not_false_positives(site):
    run = scan(WebScanRequest(url=site))
    assert not ids(run) & {"WEB-020", "WEB-021", "WEB-022"}


@pytest.mark.parametrize("site", [OffsiteRedirect], indirect=True)
def test_redirects_to_other_hosts_are_not_followed(site):
    run = scan(WebScanRequest(url=site))
    assert any("elsewhere.invalid" in w and "not followed" in w for w in run.warnings)


@pytest.mark.parametrize("url", ["ftp://example.test/", "example.test", "http://user:pw@127.0.0.1/", "javascript:alert(1)"])
def test_bad_urls_are_rejected(url):
    with pytest.raises(ScopeError):
        scan(WebScanRequest(url=url))


def test_remote_sites_need_authorization_and_allowlist():
    with pytest.raises(ScopeError, match="Authorization"):
        scan(WebScanRequest(url="https://example.test/"))
    with pytest.raises(ScopeError, match="not listed"):
        scan(WebScanRequest(url="https://example.test/", scope=Scope(authorization_confirmed=True, allowed_hosts=["other.test"])))


def test_unreachable_site_is_a_clear_error():
    with pytest.raises(ScopeError, match="Could not"):
        scan(WebScanRequest(url="http://127.0.0.1:9/", timeout_seconds=2))


def page(headers):
    return _Page(200, httpx.Headers(headers), "<html></html>")


def test_https_only_checks():
    checks = {c.id: c for c in _header_checks(page([]), https=True)}
    assert checks["WEB-005"].passed is False  # no HSTS
    assert {c.id: c for c in _header_checks(page([("Strict-Transport-Security", "max-age=31536000")]), https=True)}["WEB-005"].passed
    assert "WEB-005" not in {c.id for c in _header_checks(page([]), https=False)}


def test_cookie_value_containing_flag_names_cannot_fake_the_flags():
    weak = _cookie_checks(page([("Set-Cookie", "token=secure-httponly-samesite; Path=/")]), https=True)[0]
    assert weak.passed is False and "Secure" in weak.observed and "HttpOnly" in weak.observed and "token" in weak.observed
    strong = _cookie_checks(page([("Set-Cookie", "token=x; Secure; HttpOnly; SameSite=Strict")]), https=True)[0]
    assert strong.passed


@pytest.mark.parametrize("site", [OldLibraries], indirect=True)
def test_outdated_libraries_are_reported_without_leaving_the_host(site):
    OldLibraries.requested.clear()
    run = scan(WebScanRequest(url=site, timeout_seconds=2))
    assert ids(run) >= {"WEB-031", "WEB-032", "WEB-033", "WEB-034", "WEB-035", "WEB-036"}
    jquery = next(f for f in run.findings if f.case_id == "WEB-031")
    assert jquery.confidence == "medium" and "1.12.4" in jquery.evidence.response and "1.11.0" in jquery.evidence.response
    assert "Upgrade jQuery" in jquery.mitigation and "not proof" in jquery.limitations
    assert "/js/jquery.min.js" in OldLibraries.requested
    assert "/vendor/jquery-1.12.4.min.js" not in OldLibraries.requested
    assert run.budget["requests"] == 6  # page, one same-host banner, CORS, three sensitive paths


@pytest.mark.parametrize("site", [CurrentLibraries], indirect=True)
def test_current_library_versions_are_not_findings(site):
    run = scan(WebScanRequest(url=site, timeout_seconds=2))
    assert not ids(run) & {"WEB-031", "WEB-032", "WEB-033", "WEB-034", "WEB-035", "WEB-036"}
    jquery = next(r for r in run.results if r.case_id == "WEB-031")
    assert jquery.outcome == "passed" and "3.7.1" in jquery.name


@pytest.mark.parametrize("site", [Vulnerable], indirect=True)
def test_cli_and_api(site, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert CliRunner().invoke(cli, ["webscan", site]).exit_code == 1  # critical findings fail the build
    assert CliRunner().invoke(cli, ["webscan", "https://example.test/"]).exit_code == 2  # not authorized
    client = TestClient(app)
    run = client.post("/api/webscan", json={"url": site}).json()
    assert run["target_kind"] == "web" and client.get(f"/api/runs/{run['id']}").status_code == 200
    assert client.post("/api/webscan", json={"url": "https://example.test/"}).status_code == 400
