import pytest
from fastapi.testclient import TestClient

from sentinelforge.adapters import ScopeError
from sentinelforge.api import app
from sentinelforge.engine import execute
from sentinelforge.models import RunRequest, Scope, TargetSpec


def run_against(kind: str):
    return execute(RunRequest(target=TargetSpec(kind=kind)))


def test_vulnerable_demo_fails_the_build():
    run = run_against("vulnerable_demo")
    assert run.verdict == "fail" and run.exit_status == 1
    assert all(f.status == "confirmed" for f in run.findings)
    assert len(run.findings) == 11


def test_safe_demo_passes_everything():
    run = run_against("safe_demo")
    assert run.verdict == "pass" and not run.findings
    assert run.counts["passed"] == 11


def test_canaries_are_redacted_from_evidence():
    run = run_against("vulnerable_demo")
    stored = run.model_dump_json()
    assert "SF-CANARY-7f3a91" not in stored and "SF-TENANT-B-4c2e" not in stored


def test_max_cases_budget_is_enforced():
    run = execute(RunRequest(limits={"max_cases": 3}))
    assert run.budget["cases_run"] == 3 and len(run.skipped) == 8


def test_http_target_requires_authorization_and_allowed_host():
    spec = TargetSpec(kind="http", url="http://example.test/ask")
    with pytest.raises(ScopeError):
        execute(RunRequest(target=spec))
    with pytest.raises(ScopeError):
        execute(RunRequest(target=spec, scope=Scope(authorization_confirmed=True, allowed_hosts=["other.test"])))


def test_api_run_regression_and_export_flow():
    client = TestClient(app)
    run = client.post("/api/runs", json={"target": {"kind": "vulnerable_demo"}}).json()
    assert client.get(f"/api/runs/{run['id']}").status_code == 200

    case_id = run["findings"][0]["case_id"]
    assert client.post("/api/regressions", json={"case_id": case_id, "source": run["id"]}).status_code == 200
    exported = client.get("/api/regressions/export").text
    assert f"def test_{case_id.lower().replace('-', '_')}" in exported
    compile(exported, "exported", "exec")  # must be valid Python


def test_api_rejects_out_of_scope_target():
    body = {"target": {"kind": "http", "url": "http://example.test"}}
    assert TestClient(app).post("/api/runs", json=body).status_code == 400


def test_exploit_lab_mutations_change_outcomes():
    client = TestClient(app)
    body = {"case_id": "SF-PI-001", "target": {"kind": "vulnerable_demo"}}
    results = {r["mutation"]: r["outcome"] for r in client.post("/api/lab/fuzz", json=body).json()}
    assert results["baseline"] == "exploited" and results["base64"] == "exploited"
    assert results["leetspeak"] == "resisted"  # the app's pattern no longer matches


def test_lab_payload_can_be_saved_and_replayed():
    client = TestClient(app)
    saved = client.post("/api/regressions", json={
        "case_id": "SF-PI-001", "source": "exploit-lab", "prompt": "mutated", "mutation": "uppercase"}).json()
    assert saved["id"] == "SF-PI-001+uppercase"
    client.post("/api/regressions", json={"case_id": "SF-CL-003", "source": "exploit-lab"})
    safe = client.post("/api/regressions/replay", json={"target": {"kind": "safe_demo"}}).json()
    assert {r["status"] for r in safe} == {"passing"}
    vulnerable = client.post("/api/regressions/replay", json={"target": {"kind": "vulnerable_demo"}}).json()
    assert any(r["status"] == "blocked" for r in vulnerable)
    assert client.delete("/api/regressions/SF-PI-001+uppercase").status_code == 204


def test_benchmark_measures_the_labeled_fixtures():
    result = TestClient(app).post("/api/benchmark", json={"repeats": 2}).json()
    assert result["precision"] == 100.0 and result["recall"] == 100.0
    assert result["instability"] == 0.0 and not result["discrepancies"]


def test_sarif_export_lists_findings():
    client = TestClient(app)
    run = client.post("/api/runs", json={"target": {"kind": "vulnerable_demo"}}).json()
    sarif = client.get(f"/api/runs/{run['id']}/sarif").json()
    assert sarif["version"] == "2.1.0" and len(sarif["runs"][0]["results"]) == 11


def test_settings_are_applied_to_runs():
    client = TestClient(app)
    saved = client.get("/api/settings").json()
    client.put("/api/settings", json={**saved, "allowed_tools": ["search_docs", "send_email"]})
    assert client.get("/api/settings").json()["allowed_tools"] == ["search_docs", "send_email"]
