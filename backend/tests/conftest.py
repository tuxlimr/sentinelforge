import pytest


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    """Every test gets its own data dir so nothing touches the real .sentinelforge folder."""
    monkeypatch.setenv("SENTINELFORGE_HOME", str(tmp_path))
