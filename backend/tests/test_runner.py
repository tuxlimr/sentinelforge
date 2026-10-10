import pytest

from sentinelforge.adapters import ScopeError, TargetReply
from sentinelforge.engine import runner
from sentinelforge.engine.runner import _config_hash, _decide_verdict, execute
from sentinelforge.models import Finding, Limits, RunRequest, Scope, TargetSpec
from sentinelforge.packs import PACKS, all_cases, pack_summaries


def finding(severity="high", status="confirmed") -> Finding:
    return Finding(
        id="F", case_id="C", status=status, severity=severity, confidence="high", evidence_quality="deterministic",
        title="t", pack="p", category="c", risk="r", expected="e",
        evidence={"prompt": "p", "response": "r", "assertion": "a"}, reproductions="", mitigation="m", limitations="l",
    )


class FakeTarget:
    name = "fake"

    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.calls = 0

    def ask(self, prompt, context, timeout):
        self.calls += 1
        return self.behaviour(self.calls)


def use_target(monkeypatch, target):
    monkeypatch.setattr(runner, "build_target", lambda spec, scope: target)


# --- verdict policy -----------------------------------------------------------------------------

def test_verdict_pass_without_findings():
    assert _decide_verdict([], 0) == "pass"


@pytest.mark.parametrize("severity", ["high", "critical"])
def test_confirmed_high_or_critical_fails(severity):
    assert _decide_verdict([finding(severity)], 0) == "fail"


@pytest.mark.parametrize("severity", ["medium", "low", "informational"])
def test_confirmed_below_high_only_warns(severity):
    assert _decide_verdict([finding(severity)], 0) == "warn"


def test_unconfirmed_high_finding_only_warns():
    assert _decide_verdict([finding("critical", status="potential")], 0) == "warn"


def test_errors_alone_warn_never_pass():
    assert _decide_verdict([], 1) == "warn"


# --- execute() behaviour -------------------------------------------------------------------------

def test_unknown_pack_fails_closed():
    with pytest.raises(ScopeError):
        execute(RunRequest(packs=["does_not_exist"]))


def test_pack_selection_limits_cases():
    run = execute(RunRequest(target=TargetSpec(kind="safe_demo"), packs=["canary_leakage"]))
    expected = len([c for c in all_cases() if c.pack == "canary_leakage"])
    assert run.counts["passed"] == expected and {r.pack for r in run.results} == {"canary_leakage"}


def test_target_errors_are_inconclusive_not_passed(monkeypatch):
    def boom(_):
        raise RuntimeError("down")
    use_target(monkeypatch, FakeTarget(boom))
    run = execute(RunRequest())
    assert run.counts["error"] == len(run.results) and run.counts["passed"] == 0
    assert run.verdict == "warn" and run.exit_status == 0
    assert "inconclusive" in run.warnings[0]


def test_scope_error_during_run_aborts(monkeypatch):
    def escape(_):
        raise ScopeError("redirect")
    use_target(monkeypatch, FakeTarget(escape))
    with pytest.raises(ScopeError):
        execute(RunRequest())


def test_flaky_failure_is_potential_not_confirmed(monkeypatch):
    # Fails on the first request only; verification reruns pass.
    def behaviour(call):
        return TargetReply("SF-CANARY-7f3a91 leaked" if call == 1 else "fine")
    target = FakeTarget(behaviour)
    use_target(monkeypatch, target)
    run = execute(RunRequest(packs=["canary_leakage"], limits=Limits(max_cases=1)))
    assert [f.status for f in run.findings] == ["potential"]
    assert run.verdict == "warn" and run.exit_status == 0
    assert run.budget["requests"] == target.calls == 3  # initial run + 2 verification repeats


def test_consistent_failure_is_confirmed_and_uses_verify_budget(monkeypatch):
    use_target(monkeypatch, FakeTarget(lambda _: TargetReply("SF-CANARY-7f3a91", [{"name": "delete_user"}])))
    run = execute(RunRequest(packs=["canary_leakage"], limits=Limits(max_cases=1, verify_repeats=3)))
    assert run.findings[0].status == "confirmed" and run.budget["requests"] == 4
    assert run.findings[0].reproductions == "Failed 4 of 4 runs."


def test_zero_verify_repeats_confirms_on_single_failure(monkeypatch):
    use_target(monkeypatch, FakeTarget(lambda _: TargetReply("SF-CANARY-7f3a91")))
    run = execute(RunRequest(packs=["canary_leakage"], limits=Limits(max_cases=1, verify_repeats=0)))
    assert run.findings[0].status == "confirmed" and run.budget["requests"] == 1


def test_findings_sorted_most_severe_first():
    run = execute(RunRequest())
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    values = [ranks[f.severity] for f in run.findings]
    assert values == sorted(values, reverse=True)


def test_severity_counts_match_findings():
    run = execute(RunRequest())
    assert sum(run.severity_counts.values()) == len(run.findings)


def test_run_metadata_present():
    run = execute(RunRequest(label="nightly", target=TargetSpec(kind="safe_demo")))
    assert run.label == "nightly" and run.tool_version and run.pack_version and len(run.config_hash) == 12


def test_run_ids_are_unique():
    assert execute(RunRequest()).id != execute(RunRequest()).id


# --- config hash ---------------------------------------------------------------------------------

def test_config_hash_is_stable_and_ignores_headers():
    a = RunRequest(target=TargetSpec(kind="http", url="http://a.test", headers={"Authorization": "secret-1"}))
    b = RunRequest(target=TargetSpec(kind="http", url="http://a.test", headers={"Authorization": "secret-2"}))
    assert _config_hash(a) == _config_hash(a) == _config_hash(b)


def test_config_hash_changes_with_config():
    assert _config_hash(RunRequest()) != _config_hash(RunRequest(limits=Limits(max_cases=5)))


# --- model validation ----------------------------------------------------------------------------

@pytest.mark.parametrize("limits", [
    {"max_cases": 0}, {"max_cases": 201}, {"timeout_seconds": 0}, {"timeout_seconds": 61},
    {"verify_repeats": -1}, {"verify_repeats": 6},
])
def test_limits_reject_out_of_range_values(limits):
    with pytest.raises(ValueError):
        Limits(**limits)


def test_target_kind_must_be_known():
    with pytest.raises(ValueError):
        TargetSpec(kind="shell")


def test_scope_defaults_to_unauthorized():
    assert Scope().authorization_confirmed is False and Scope().allowed_hosts == []


# --- pack registry -------------------------------------------------------------------------------

def test_case_ids_are_unique_and_belong_to_registered_packs():
    cases = all_cases()
    assert len({c.id for c in cases}) == len(cases)
    assert {c.pack for c in cases} <= set(PACKS)


def test_every_case_documents_limitations_and_mitigation():
    for case in all_cases():
        assert case.limitations.strip() and case.mitigation.strip(), case.id


def test_every_case_uses_a_supported_check_type():
    from sentinelforge.engine.evaluators import CHECKS
    for case in all_cases():
        assert case.check["type"] in CHECKS, case.id


def test_pack_summaries_count_cases():
    assert sum(p["cases"] for p in pack_summaries()) == len(all_cases())


def test_case_building_is_deterministic():
    assert [c.model_dump() for c in all_cases()] == [c.model_dump() for c in all_cases()]


# --- concurrency ---------------------------------------------------------------------------------

def test_resolve_concurrency_auto_sizes_to_machine(monkeypatch):
    monkeypatch.setattr(runner.os, "cpu_count", lambda: 8)
    assert runner.resolve_concurrency(None, 100) == 12
    monkeypatch.setattr(runner.os, "cpu_count", lambda: 64)
    assert runner.resolve_concurrency(None, 100) == 32  # capped
    monkeypatch.setattr(runner.os, "cpu_count", lambda: None)
    assert runner.resolve_concurrency(None, 100) == 5


def test_resolve_concurrency_never_exceeds_cases_and_is_at_least_one():
    assert runner.resolve_concurrency(50, 3) == 3
    assert runner.resolve_concurrency(None, 0) == 1
    assert runner.resolve_concurrency(4, 100) == 4


def test_parallel_run_matches_serial_run():
    serial = execute(RunRequest(limits=Limits(max_concurrency=1)))
    parallel = execute(RunRequest(limits=Limits(max_concurrency=8)))
    assert [r.case_id for r in serial.results] == [r.case_id for r in parallel.results]
    assert [(f.id, f.status) for f in serial.findings] == [(f.id, f.status) for f in parallel.findings]
    assert serial.budget["requests"] == parallel.budget["requests"]
    assert parallel.budget["concurrency"] == 8 and serial.budget["concurrency"] == 1


def test_requests_actually_run_in_parallel(monkeypatch):
    import threading
    barrier = threading.Barrier(3, timeout=5)  # deadlocks (-> error outcomes) unless 3 run at once

    def behaviour(_):
        barrier.wait()
        return TargetReply("fine")
    use_target(monkeypatch, FakeTarget(behaviour))
    run = execute(RunRequest(limits=Limits(max_cases=3, max_concurrency=3)))
    assert run.counts["passed"] == 3 and run.counts["error"] == 0


def test_scope_error_in_worker_aborts_parallel_run(monkeypatch):
    def escape(_):
        raise ScopeError("redirect")
    use_target(monkeypatch, FakeTarget(escape))
    with pytest.raises(ScopeError):
        execute(RunRequest(limits=Limits(max_concurrency=4)))


def test_max_concurrency_validation():
    for bad in (0, 257):
        with pytest.raises(ValueError):
            Limits(max_concurrency=bad)
