import httpx
import pytest

from sentinelforge.adapters import ScopeError, build_target
from sentinelforge.adapters.callable_target import CallableTarget
from sentinelforge.adapters.http_target import HttpTarget
from sentinelforge.models import Scope, TargetSpec

URL = "http://app.test/ask"
SCOPE = Scope(authorization_confirmed=True, allowed_hosts=["app.test"])


def http_spec(url=URL, **kw):
    return TargetSpec(kind="http", url=url, **kw)


def test_callable_target_normalizes_reply():
    target = CallableTarget("t", lambda prompt, ctx: {"text": prompt.upper()})
    reply = target.ask("hi", {}, 1)
    assert reply.text == "HI" and reply.tool_calls == []


def test_callable_target_handles_missing_keys():
    reply = CallableTarget("t", lambda p, c: {}).ask("hi", {}, 1)
    assert reply.text == "" and reply.tool_calls == []


def test_build_target_demo_kinds_need_no_scope():
    assert build_target(TargetSpec(kind="safe_demo"), Scope()).name == "safe-demo"
    assert build_target(TargetSpec(kind="vulnerable_demo"), Scope()).name == "vulnerable-demo"


@pytest.mark.parametrize("url", [None, "", "ftp://app.test/x", "not a url", "file:///etc/passwd"])
def test_http_rejects_invalid_urls(url):
    with pytest.raises(ScopeError):
        HttpTarget(http_spec(url), SCOPE)


def test_http_requires_authorization_even_for_allowed_host():
    with pytest.raises(ScopeError):
        HttpTarget(http_spec(), Scope(authorization_confirmed=False, allowed_hosts=["app.test"]))


def test_http_rejects_host_not_in_allowlist():
    with pytest.raises(ScopeError):
        HttpTarget(http_spec("http://evil.test/ask"), SCOPE)


def test_http_host_match_is_exact_not_substring():
    with pytest.raises(ScopeError):
        HttpTarget(http_spec("http://app.test.evil.com/ask"), SCOPE)


def test_http_name_defaults_to_hostname():
    assert HttpTarget(http_spec(), SCOPE).name == "app.test"
    assert HttpTarget(http_spec(name="prod"), SCOPE).name == "prod"


def fake_post(monkeypatch, response: httpx.Response, captured: dict | None = None):
    response.request = response._request or httpx.Request("POST", URL)

    def post(url, **kwargs):
        if captured is not None:
            captured.update(kwargs, url=url)
        return response
    monkeypatch.setattr(httpx, "post", post)


def test_http_ask_parses_json_and_disables_redirects(monkeypatch):
    captured = {}
    fake_post(monkeypatch, httpx.Response(200, json={"text": "ok", "tool_calls": [{"name": "search_docs"}]}), captured)
    reply = HttpTarget(http_spec(headers={"Authorization": "x"}), SCOPE).ask("p", {"a": 1}, 3)
    assert reply.text == "ok" and reply.tool_calls == [{"name": "search_docs"}]
    assert captured["follow_redirects"] is False and captured["timeout"] == 3
    assert captured["json"] == {"prompt": "p", "context": {"a": 1}}


def test_http_ask_accepts_plain_text(monkeypatch):
    fake_post(monkeypatch, httpx.Response(200, text="just text"))
    assert HttpTarget(http_spec(), SCOPE).ask("p", {}, 1).text == "just text"


def test_http_ask_blocks_redirects(monkeypatch):
    fake_post(monkeypatch, httpx.Response(302, headers={"location": "http://evil.test"}, request=httpx.Request("POST", URL)))
    with pytest.raises(ScopeError):
        HttpTarget(http_spec(), SCOPE).ask("p", {}, 1)


def test_http_ask_raises_on_server_error(monkeypatch):
    fake_post(monkeypatch, httpx.Response(500, request=httpx.Request("POST", URL)))
    with pytest.raises(httpx.HTTPStatusError):
        HttpTarget(http_spec(), SCOPE).ask("p", {}, 1)
