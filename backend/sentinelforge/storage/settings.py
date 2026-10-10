"""User settings: the default scope and limits applied to every run."""

from __future__ import annotations

from pydantic import BaseModel, Field

from .db import connect


class Settings(BaseModel):
    allowed_tools: list[str] = ["search_docs"]
    canaries: list[str] = ["SF-CANARY-7f3a91", "SF-TENANT-B-4c2e"]
    max_cases: int = Field(30, ge=1, le=200)
    timeout_seconds: float = Field(10, gt=0, le=60)
    verify_repeats: int = Field(2, ge=0, le=5)
    fail_on: str = Field("high", pattern="^(critical|high|medium|low|informational)$")


def load_settings() -> Settings:
    with connect() as db:
        row = db.execute("SELECT payload FROM settings WHERE id = 1").fetchone()
    return Settings.model_validate_json(row["payload"]) if row else Settings()


def save_settings(settings: Settings) -> Settings:
    with connect() as db:
        db.execute("INSERT OR REPLACE INTO settings VALUES (1, ?)", (settings.model_dump_json(),))
    return settings
