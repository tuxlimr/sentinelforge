"""Scan runs: create, list, inspect, delete and export."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool

from ...adapters import ScopeError
from ...engine import execute
from ...models import Run, RunRequest
from ...reporters import to_sarif
from ...storage import runs, settings

router = APIRouter(prefix="/runs", tags=["runs"])


def apply_saved_settings(request: RunRequest) -> RunRequest:
    """Fill in scope and limits the caller did not set explicitly from saved settings."""
    saved = settings.load_settings()
    scope_fields = request.scope.model_fields_set
    if "allowed_tools" not in scope_fields:
        request.scope.allowed_tools = saved.allowed_tools
    if "canaries" not in scope_fields:
        request.scope.canaries = saved.canaries
    if "limits" not in request.model_fields_set:
        request.limits = request.limits.model_copy(update={
            "max_cases": saved.max_cases, "timeout_seconds": saved.timeout_seconds, "verify_repeats": saved.verify_repeats,
        })
    return request


def get_run_or_404(run_id: str) -> Run:
    run = runs.get_run(run_id)
    if run is None:
        raise HTTPException(404, "Run not found")
    return run


@router.post("", response_model=Run)
async def create_run(request: RunRequest) -> Run:
    try:
        run = await run_in_threadpool(execute, apply_saved_settings(request))
    except ScopeError as error:
        raise HTTPException(400, str(error)) from error
    runs.save_run(run)
    return run


@router.get("", response_model=list[Run])
def list_runs() -> list[Run]:
    return runs.list_runs()


@router.get("/{run_id}", response_model=Run)
def get_run(run_id: str) -> Run:
    return get_run_or_404(run_id)


@router.get("/{run_id}/sarif")
def get_sarif(run_id: str) -> dict:
    return to_sarif(get_run_or_404(run_id))


@router.delete("/{run_id}", status_code=204)
def delete_run(run_id: str) -> None:
    if not runs.delete_run(run_id):
        raise HTTPException(404, "Run not found")
