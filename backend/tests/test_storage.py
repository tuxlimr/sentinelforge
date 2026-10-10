import json

import pytest

from sentinelforge.engine import execute
from sentinelforge.models import RunRequest, TargetSpec
from sentinelforge.storage import regressions, runs, settings


def make_run(kind="safe_demo"):
    return execute(RunRequest(target=TargetSpec(kind=kind)))


# --- runs ----------------------------------------------------------------------------------------

def test_run_round_trips_through_disk():
    run = make_run("vulnerable_demo")
    runs.save_run(run)
    assert runs.get_run(run.id) == run


def test_get_missing_run_returns_none():
    assert runs.get_run("nope") is None


def test_list_runs_newest_first():
    older, newer = make_run(), make_run()
    older.started_at, newer.started_at = "2026-01-01T00:00:00+00:00", "2026-02-01T00:00:00+00:00"
    runs.save_run(older)
    runs.save_run(newer)
    assert [r.id for r in runs.list_runs()] == [newer.id, older.id]


def test_delete_run():
    run = make_run()
    runs.save_run(run)
    assert runs.delete_run(run.id) is True
    assert runs.delete_run(run.id) is False and runs.get_run(run.id) is None


def test_run_id_cannot_traverse_out_of_runs_dir(tmp_path):
    outside = tmp_path / "secret.json"
    outside.write_text("{}")
    assert runs.get_run("../secret") is None
    assert runs.delete_run("../secret") is False and outside.exists()


def test_data_dir_follows_env_override(tmp_path):
    assert runs.data_dir() == tmp_path


# --- settings ------------------------------------------------------------------------------------

def test_settings_default_when_missing():
    assert settings.load_settings() == settings.Settings()


def test_settings_round_trip():
    saved = settings.save_settings(settings.Settings(allowed_tools=["a"], max_cases=5, fail_on="low"))
    assert settings.load_settings() == saved


@pytest.mark.parametrize("bad", [{"max_cases": 0}, {"timeout_seconds": 100}, {"verify_repeats": 9}, {"fail_on": "nope"}])
def test_settings_validation(bad):
    with pytest.raises(ValueError):
        settings.Settings(**bad)


# --- regressions ---------------------------------------------------------------------------------

def test_regression_id_composition():
    assert regressions.regression_id("SF-PI-001", None) == "SF-PI-001"
    assert regressions.regression_id("SF-PI-001", "baseline") == "SF-PI-001"
    assert regressions.regression_id("SF-PI-001", "base64") == "SF-PI-001+base64"


def test_list_empty_when_no_file():
    assert regressions.list_regressions() == []


def test_add_regression_is_idempotent():
    first = regressions.add_regression("SF-PI-001", "scan")
    second = regressions.add_regression("SF-PI-001", "other-source")
    assert first == second and len(regressions.list_regressions()) == 1


def test_mutated_variant_is_stored_separately_with_custom_prompt():
    regressions.add_regression("SF-PI-001", "scan")
    record = regressions.add_regression("SF-PI-001", "lab", prompt="X", mutation="uppercase")
    assert record["id"] == "SF-PI-001+uppercase" and record["prompt"] == "X"
    assert len(regressions.list_regressions()) == 2


def test_add_unknown_case_raises_and_writes_nothing():
    with pytest.raises(KeyError):
        regressions.add_regression("SF-NOPE-999", "scan")
    assert regressions.list_regressions() == []


def test_remove_regression_only_removes_target():
    regressions.add_regression("SF-PI-001", "scan")
    regressions.add_regression("SF-CL-003", "scan")
    regressions.remove_regression("SF-PI-001")
    assert [r["id"] for r in regressions.list_regressions()] == ["SF-CL-003"]


def test_legacy_records_without_id_get_case_id():
    (runs.data_dir() / "regressions.jsonl").write_text(json.dumps({"case_id": "SF-PI-001"}) + "\n\n")
    assert regressions.list_regressions()[0]["id"] == "SF-PI-001"


def test_test_function_name_is_a_valid_identifier():
    name = regressions.test_function_name("SF-PI-001+zero_width")
    assert name == "test_sf_pi_001_zero_width" and name.isidentifier()


def test_export_pytest_is_valid_python_and_runs_against_safe_app():
    for case_id in ("SF-PI-001", "SF-CL-003"):
        regressions.add_regression(case_id, "scan")
    regressions.add_regression("SF-PI-001", "lab", prompt="it's a \"quoted\" prompt\n", mutation="uppercase")
    source = regressions.export_pytest()
    namespace: dict = {}
    exec(compile(source, "exported", "exec"), namespace)  # exported tests must pass on the safe demo
    tests = [fn for name, fn in namespace.items() if name.startswith("test_")]
    assert len(tests) == 3
    for fn in tests:
        fn()


def test_exported_tests_fail_against_vulnerable_app():
    regressions.add_regression("SF-PI-001", "scan")
    source = regressions.export_pytest().replace("safe_app", "vulnerable_app")
    namespace: dict = {}
    exec(compile(source, "exported", "exec"), namespace)
    with pytest.raises(AssertionError):
        namespace["test_sf_pi_001"]()


# --- sqlite --------------------------------------------------------------------------------------

def test_legacy_json_files_are_imported_once_and_left_in_place():
    run = make_run("vulnerable_demo")
    folder = runs.data_dir() / "runs"
    folder.mkdir()
    (folder / f"{run.id}.json").write_text(run.model_dump_json(indent=2), encoding="utf-8")
    (folder / "broken.json").write_text("{not json", encoding="utf-8")  # must not block startup
    (runs.data_dir() / "settings.json").write_text(settings.Settings(max_cases=7).model_dump_json(), encoding="utf-8")
    (runs.data_dir() / "regressions.jsonl").write_text(
        json.dumps({"id": "SF-PI-001", "case_id": "SF-PI-001", "name": "n", "pack": "p", "severity": "high", "mutation": None,
                    "source": run.id, "prompt": "x", "context": {}, "check": {"type": "not_contains", "values": []}}) + "\n")

    assert runs.get_run(run.id) == run
    assert settings.load_settings().max_cases == 7
    assert [r["id"] for r in regressions.list_regressions()] == ["SF-PI-001"]

    runs.delete_run(run.id)  # a deletion must not be undone by re-importing the old file next time
    assert runs.get_run(run.id) is None and (folder / f"{run.id}.json").exists()


def test_data_lives_in_one_sqlite_file():
    runs.save_run(make_run())
    regressions.add_regression("SF-PI-001", "scan")
    settings.save_settings(settings.Settings(timeout_seconds=5))
    assert (runs.data_dir() / "sentinelforge.db").is_file()
    assert not list(runs.data_dir().glob("*.jsonl")) and not (runs.data_dir() / "runs").exists()


def test_concurrent_writers_do_not_lose_runs():
    from concurrent.futures import ThreadPoolExecutor

    created = [make_run() for _ in range(20)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(runs.save_run, created))
    assert {r.id for r in runs.list_runs()} == {r.id for r in created}
