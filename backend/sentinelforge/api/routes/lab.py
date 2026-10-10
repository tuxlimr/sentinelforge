"""Exploit Lab: payload library and mutation fuzzing."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool

from ...adapters import ScopeError
from ...engine.lab import FuzzRequest, FuzzResult, fuzz
from ...engine.mutations import mutation_catalog
from ...packs import all_cases

router = APIRouter(prefix="/lab", tags=["lab"])


@router.get("/payloads")
def payload_library() -> list[dict]:
    return [case.model_dump() for case in all_cases()]


@router.get("/mutations")
def mutations() -> list[dict]:
    return mutation_catalog()


@router.post("/fuzz", response_model=list[FuzzResult])
async def run_fuzz(request: FuzzRequest) -> list[FuzzResult]:
    try:
        return await run_in_threadpool(fuzz, request)
    except KeyError as error:
        raise HTTPException(404, str(error.args[0])) from error
    except ScopeError as error:
        raise HTTPException(400, str(error)) from error
