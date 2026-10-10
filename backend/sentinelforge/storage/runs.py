"""Run persistence in SQLite (see `db.py`)."""

from __future__ import annotations

from ..models import Run
from .db import connect, data_dir

__all__ = ["data_dir", "save_run", "list_runs", "get_run", "delete_run"]


def save_run(run: Run) -> None:
    with connect() as db:
        db.execute(
            "INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?,?)",
            (run.id, run.started_at, run.label, run.target, run.target_kind, run.verdict,
             len(run.findings), run.duration_ms, run.model_dump_json()),
        )


def list_runs() -> list[Run]:
    """Newest first."""
    with connect() as db:
        rows = db.execute("SELECT payload FROM runs ORDER BY started_at DESC, id DESC").fetchall()
    return [Run.model_validate_json(row["payload"]) for row in rows]


def get_run(run_id: str) -> Run | None:
    with connect() as db:
        row = db.execute("SELECT payload FROM runs WHERE id = ?", (run_id,)).fetchone()
    return Run.model_validate_json(row["payload"]) if row else None


def delete_run(run_id: str) -> bool:
    with connect() as db:
        return db.execute("DELETE FROM runs WHERE id = ?", (run_id,)).rowcount > 0
