"""Health, test-pack catalog, evaluation benchmark and settings."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.concurrency import run_in_threadpool

from ... import PACK_VERSION, __version__
from ...engine.benchmark import BenchmarkRequest, run_benchmark
from ...packs import all_cases, pack_summaries
from ...storage import settings

router = APIRouter()


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "pack_version": PACK_VERSION}


@router.get("/packs")
def get_packs() -> list[dict]:
    return pack_summaries()


@router.get("/cases")
def get_cases() -> list[dict]:
    return [case.model_dump() for case in all_cases()]


@router.post("/benchmark")
async def benchmark(request: BenchmarkRequest = BenchmarkRequest()) -> dict:
    return await run_in_threadpool(run_benchmark, request)


@router.get("/settings", response_model=settings.Settings)
def get_settings() -> settings.Settings:
    return settings.load_settings()


@router.put("/settings", response_model=settings.Settings)
def put_settings(body: settings.Settings) -> settings.Settings:
    return settings.save_settings(body)
