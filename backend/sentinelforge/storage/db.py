"""SQLite connection and schema. One file, `sentinelforge.db`, inside the data directory.

A connection is opened per operation: SQLite handles the locking, and it keeps the API's thread pool safe
and lets tests point SENTINELFORGE_HOME at a temp directory. Existing JSON files from earlier versions are
imported once, on first open, and left in place.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE runs (
    id          TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL,
    label       TEXT,
    target      TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    findings    INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    payload     TEXT NOT NULL            -- the full Run as JSON, so the API returns it unchanged
);
CREATE INDEX runs_started_at ON runs (started_at DESC);

CREATE TABLE regressions (
    id         TEXT PRIMARY KEY,         -- case id, plus +<mutation> for mutated payloads
    case_id    TEXT NOT NULL,
    name       TEXT NOT NULL,
    pack       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    mutation   TEXT,
    source     TEXT NOT NULL,            -- a run id, or "exploit-lab"
    prompt     TEXT NOT NULL,
    context    TEXT NOT NULL,            -- JSON
    "check"    TEXT NOT NULL,            -- JSON
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE settings (
    id      INTEGER PRIMARY KEY CHECK (id = 1),   -- a single row
    payload TEXT NOT NULL
);
"""


def data_dir() -> Path:
    root = Path(os.environ.get("SENTINELFORGE_HOME", Path.cwd() / ".sentinelforge"))
    root.mkdir(parents=True, exist_ok=True)
    return root


def db_path() -> Path:
    return data_dir() / "sentinelforge.db"


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    """Open the database, creating or migrating it first. Commits on success, rolls back on error."""
    connection = sqlite3.connect(db_path(), timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        _enable_wal(connection)
        connection.execute("PRAGMA foreign_keys = ON")
        if connection.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
            _initialise(connection)
        with connection:
            yield connection
    finally:
        connection.close()


def _enable_wal(connection: sqlite3.Connection) -> None:
    """Switching journal mode ignores the busy timeout, so racing first-time openers retry. WAL then persists in the file."""
    for attempt in range(50):
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            return
        except sqlite3.OperationalError:
            if attempt == 49:
                raise
            time.sleep(0.05)


def _initialise(connection: sqlite3.Connection) -> None:
    with connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("PRAGMA user_version").fetchone()[0] >= SCHEMA_VERSION:
            return  # another process finished first
        _create_tables(connection)
        _import_legacy_files(connection)
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def _create_tables(connection: sqlite3.Connection) -> None:
    for statement in SCHEMA.split(";"):
        if statement.strip():
            connection.execute(statement)


def _complete(record: dict) -> dict:
    """Very old records held only a case id; fill the rest in from the case catalog."""
    from ..packs import all_cases

    case = next((c for c in all_cases() if c.id == record["case_id"]), None)
    if case is None:
        return record
    defaults = {"name": case.name, "pack": case.pack, "severity": case.severity, "source": "imported",
                "prompt": case.prompt, "context": case.context, "check": case.check}
    return {**defaults, **record}


def _import_legacy_files(connection: sqlite3.Connection) -> None:
    """One-time import of runs/*.json, regressions.jsonl and settings.json from earlier versions."""
    root = data_dir()
    for path in sorted((root / "runs").glob("*.json")) if (root / "runs").is_dir() else []:
        try:
            run = json.loads(path.read_text(encoding="utf-8"))
            connection.execute(
                "INSERT OR IGNORE INTO runs VALUES (?,?,?,?,?,?,?,?,?)",
                (run["id"], run["started_at"], run.get("label"), run["target"], run["target_kind"], run["verdict"],
                 len(run["findings"]), run["duration_ms"], json.dumps(run)),
            )
        except (OSError, ValueError, KeyError):
            continue  # skip a damaged legacy file rather than block startup

    legacy = root / "regressions.jsonl"
    if legacy.exists():
        for line in legacy.read_text(encoding="utf-8").splitlines():
            try:
                r = _complete(json.loads(line))
                connection.execute(
                    'INSERT OR IGNORE INTO regressions (id, case_id, name, pack, severity, mutation, source, prompt, context, "check")'
                    " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (r.get("id", r["case_id"]), r["case_id"], r["name"], r["pack"], r["severity"], r.get("mutation"),
                     r["source"], r["prompt"], json.dumps(r.get("context", {})), json.dumps(r["check"])),
                )
            except (ValueError, KeyError):
                continue

    legacy = root / "settings.json"
    if legacy.exists():
        try:
            connection.execute("INSERT OR IGNORE INTO settings VALUES (1, ?)", (json.dumps(json.loads(legacy.read_text(encoding="utf-8"))),))
        except (OSError, ValueError):
            pass
