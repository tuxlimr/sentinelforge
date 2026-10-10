"""Network exposure scan (nmap). Results are saved as an ordinary run."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool

from ...adapters import ScopeError
from ...engine.exposure import ExposureError, ExposureRequest, scan
from ...models import Run
from ...storage import runs

router = APIRouter(prefix="/exposure", tags=["exposure"])


@router.post("", response_model=Run)
async def run_exposure_scan(request: ExposureRequest) -> Run:
    try:
        run = await run_in_threadpool(scan, request)
    except ScopeError as error:
        raise HTTPException(400, str(error)) from error
    except ExposureError as error:
        raise HTTPException(503, str(error)) from error
    runs.save_run(run)
    return run
