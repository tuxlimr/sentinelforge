import shutil
import socket
import subprocess

import pytest
from fastapi.testclient import TestClient

from sentinelforge.adapters import ScopeError
from sentinelforge.api import app
from sentinelforge.engine import exposure
from sentinelforge.engine.exposure import ExposureError, ExposureRequest, build_command, check_scope, parse_open_ports, scan
from sentinelforge.models import Scope

XML = """<?xml version="1.0"?><nmaprun><host><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/></port>
<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
<port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
</ports></host></nmaprun>"""


@pytest.fixture
def fake_nmap(monkeypatch):
    """Pretend nmap is installed and returns XML, recording the command it was given."""
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=XML, stderr="")

    monkeypatch.setattr(exposure, "find_nmap", lambda: "nmap")
    monkeypatch.setattr(exposure.subprocess, "run", run)
    return calls


def authorized(host: str, **extra) -> ExposureRequest:
    return ExposureRequest(host=host, scope=Scope(authorization_confirmed=True, allowed_hosts=[host]), **extra)


# --- scope: fail closed ------------------------------------------------------------------------

@pytest.mark.parametrize("host", ["-sS", "--script=vuln", "10.0.0.0/24", "10.0.0.1-50", "1-3.0.0.1", "10.0.0.-5", "a.com b.com", "a.com;rm -rf", "", "$(id)", "a.com\n-oN x"])
def test_anything_nmap_could_read_as_more_than_one_host_is_rejected(host):
    with pytest.raises(ScopeError):
        check_scope(authorized(host))


def test_remote_hosts_need_authorization_and_an_allowlist_entry():
    with pytest.raises(ScopeError, match="Authorization"):
        check_scope(ExposureRequest(host="example.test"))
    with pytest.raises(ScopeError, match="not listed"):
        check_scope(ExposureRequest(host="example.test", scope=Scope(authorization_confirmed=True, allowed_hosts=["other.test"])))
    check_scope(authorized("example.test"))
    check_scope(ExposureRequest(host="localhost"))  # loopback needs no confirmation
    check_scope(ExposureRequest(host="127.0.0.1"))


@pytest.mark.parametrize("ports", [[], [0], [70000], list(range(1, 102))])
def test_port_list_is_bounded(ports):
    with pytest.raises(ScopeError):
        check_scope(ExposureRequest(host="localhost", ports=ports))


def test_command_is_fixed_and_has_no_scripts_or_service_detection():
    command = build_command("nmap", ExposureRequest(host="localhost", ports=[6379, 22, 22]))
    assert command == ["nmap", "-sT", "-Pn", "-n", "--open", "-T3", "--max-retries", "1", "-p", "22,6379", "-oX", "-", "localhost"]
    assert not any(arg.startswith(("--script", "-sV", "-O", "-A")) for arg in command)


# --- parsing ---------------------------------------------------------------------------------

def test_parse_keeps_only_open_tcp_ports():
    assert [(p["port"], p["service"]) for p in parse_open_ports(XML)] == [(443, "https"), (6379, "redis"), (8080, "http-proxy")]


@pytest.mark.parametrize("bad", ["not xml", '<!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>'])
def test_hostile_or_broken_output_is_refused(bad):
    with pytest.raises(ExposureError):
        parse_open_ports(bad)


def test_oversized_output_is_refused():
    with pytest.raises(ExposureError, match="large"):
        parse_open_ports("<a>" + "x" * 2_100_000 + "</a>")


# --- scan --------------------------------------------------------------------------------------

def test_scan_flags_only_unexpected_open_ports(fake_nmap):
    run = scan(authorized("example.test", expected_ports=[443, 22]))
    assert [f.case_id for f in run.findings] == ["SF-NX-6379", "SF-NX-8080"]  # sensitive port first
    assert [f.severity for f in run.findings] == ["high", "medium"]
    assert run.verdict == "fail" and run.exit_status == 1 and run.target_kind == "network"
    assert run.counts["passed"] == 1 and run.counts["failed"] == 2
    assert any("22" in w for w in run.warnings)  # expected port not seen open
    command, kwargs = fake_nmap[0]
    assert kwargs["shell"] is False and kwargs["timeout"] == 60 and command[-1] == "example.test"


def test_clean_scan_passes(fake_nmap):
    run = scan(authorized("example.test", expected_ports=[443, 6379, 8080]))
    assert run.verdict == "pass" and not run.findings


def test_missing_nmap_gives_an_install_hint(monkeypatch):
    monkeypatch.setattr(exposure.shutil, "which", lambda _: None)
    monkeypatch.setattr(exposure.os, "name", "posix")
    with pytest.raises(ExposureError, match="nmap.org"):
        scan(ExposureRequest(host="localhost"))


def test_nmap_timeout_and_failure_are_reported(monkeypatch):
    monkeypatch.setattr(exposure, "find_nmap", lambda: "nmap")

    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 1)

    monkeypatch.setattr(exposure.subprocess, "run", timeout)
    with pytest.raises(ExposureError, match="did not finish"):
        scan(ExposureRequest(host="localhost"))
    monkeypatch.setattr(exposure.subprocess, "run", lambda c, **k: subprocess.CompletedProcess(c, 1, "", "boom"))
    with pytest.raises(ExposureError, match="boom"):
        scan(ExposureRequest(host="localhost"))


def test_api_saves_the_run_and_maps_errors(fake_nmap):
    client = TestClient(app)
    body = {"host": "example.test", "expected_ports": [443], "scope": {"authorization_confirmed": True, "allowed_hosts": ["example.test"]}}
    run = client.post("/api/exposure", json=body).json()
    assert run["verdict"] == "fail" and client.get(f"/api/runs/{run['id']}").status_code == 200
    assert client.post("/api/exposure", json={"host": "example.test"}).status_code == 400
    assert client.post("/api/exposure", json={"host": "-sS"}).status_code == 400


# --- real nmap (skipped until installed) -----------------------------------------------------

@pytest.mark.skipif(not (shutil.which("nmap") or exposure.os.name == "nt"), reason="nmap is not installed")
def test_real_nmap_finds_a_local_listener():
    try:
        exposure.find_nmap()
    except ExposureError:
        pytest.skip("nmap is not installed")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        found = scan(ExposureRequest(host="127.0.0.1", ports=[port]))
        assert [f.case_id for f in found.findings] == [f"SF-NX-{port}"]
        assert scan(ExposureRequest(host="127.0.0.1", ports=[port], expected_ports=[port])).verdict == "pass"
