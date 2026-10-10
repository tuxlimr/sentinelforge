"""User settings: the default scope and limits applied to every run."""

from __future__ import annotations

from pydantic import BaseModel, Field

from .runs import data_dir


class Settings(BaseModel):
    allowed_tools: list[str] = ["search_docs"]
    canaries: list[str] = ["SF-CANARY-7f3a91", "SF-TENANT-B-4c2e"]
    max_cases: int = Field(30, ge=1, le=200)
    timeout_seconds: float = Field(10, gt=0, le=60)
    verify_repeats: int = Field(2, ge=0, le=5)
    fail_on: str = Field("high", pattern="^(critical|high|medium|low|informational)$")


def _file():
    return data_dir() / "settings.json"


def load_settings() -> Settings:
    path = _file()
    return Settings.model_validate_json(path.read_text(encoding="utf-8")) if path.exists() else Settings()


def save_settings(settings: Settings) -> Settings:
    _file().write_text(settings.model_dump_json(indent=2), encoding="utf-8")
    return settings
