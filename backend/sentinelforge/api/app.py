"""FastAPI application. The React frontend talks to these endpoints under /api."""

from __future__ import annotations

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .. import __version__
from .routes import lab, meta, regressions, runs

# Only the local dev frontend may call this API from a browser.
ALLOWED_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]

app = FastAPI(title="SentinelForge API", version=__version__)
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["*"], allow_headers=["*"])

api = APIRouter(prefix="/api")
for module in (meta, runs, regressions, lab):
    api.include_router(module.router)
app.include_router(api)
