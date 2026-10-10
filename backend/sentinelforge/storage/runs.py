"""Local JSON persistence for runs. Swappable for a database later."""

from __future__ import annotations

import os
from pathlib import Path

from ..models import Run


def data_dir() -> Path:
    root = Path(os.environ.get("SENTINELFORGE_HOME", Path.cwd() / ".sentinelforge"))
    root.mkdir(parents=True, exist_ok=True)
    return root


def _runs_dir() -> Path:
    path = data_dir() / "runs"
    path.mkdir(exist_ok=True)
    return path


def _run_path(run_id: str) -> Path:
    return _runs_dir() / f"{Path(run_id).name}.json"  # basename only: blocks path traversal


def save_run(run: Run) -> None:
    _run_path(run.id).write_text(run.model_dump_json(indent=2), encoding="utf-8")


def list_runs() -> list[Run]:
    runs = [Run.model_validate_json(p.read_text(encoding="utf-8")) for p in _runs_dir().glob("*.json")]
    return sorted(runs, key=lambda run: run.started_at, reverse=True)


def get_run(run_id: str) -> Run | None:
    path = _run_path(run_id)
    return Run.model_validate_json(path.read_text(encoding="utf-8")) if path.exists() else None


def delete_run(run_id: str) -> bool:
    path = _run_path(run_id)
    if not path.exists():
        return False
    path.unlink()
    return True
