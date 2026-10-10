"""Regression tests: save, list, replay and export as pytest."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from ...adapters import ScopeError
from ...engine.replay import ReplayRequest, ReplayResult, replay
from ...storage import regressions, runs

router = APIRouter(prefix="/regressions", tags=["regressions"])


class SaveRegression(BaseModel):
    case_id: str
    source: str  # a run id, or "exploit-lab"
    prompt: str | None = None  # a mutated payload, if saving from the lab
    mutation: str | None = None


@router.get("")
def list_regressions() -> list[dict]:
    return regressions.list_regressions()


@router.post("")
def add_regression(body: SaveRegression) -> dict:
    if body.source != "exploit-lab" and runs.get_run(body.source) is None:
        raise HTTPException(404, "Source run not found")
    try:
        return regressions.add_regression(body.case_id, body.source, body.prompt, body.mutation)
    except KeyError as error:
        raise HTTPException(404, "Unknown case") from error


@router.get("/export", response_class=PlainTextResponse)
def export_pytest() -> str:
    return regressions.export_pytest()


@router.post("/replay", response_model=list[ReplayResult])
async def replay_all(request: ReplayRequest) -> list[ReplayResult]:
    try:
        return await run_in_threadpool(replay, request)
    except ScopeError as error:
        raise HTTPException(400, str(error)) from error


@router.delete("/{regression_id:path}", status_code=204)
def remove_regression(regression_id: str) -> None:
    regressions.remove_regression(regression_id)
