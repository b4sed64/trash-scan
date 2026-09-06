"""Trash Scan API application factory."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api import (
    admin,
    approvals,
    audit,
    auth,
    emergency,
    findings,
    notifications,
    scans,
    schedules,
    targets,
)
from .bootstrap import create_all, seed_builtin_deny_rules
from .config import get_settings
from .services import ScopeError
from .services.authorization_service import PermissionDenied


@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.getenv("TRASHSCAN_AUTO_CREATE", "1") == "1":
        create_all()
    seed_builtin_deny_rules()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="Trash Scan API", version="1.0.0", lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.frontend_origin],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(PermissionDenied)
    async def _permission_denied(_: Request, exc: PermissionDenied):
        return JSONResponse(status_code=403, content={"detail": exc.message})

    @app.exception_handler(ScopeError)
    async def _scope_error(_: Request, exc: ScopeError):
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    app.include_router(auth.router)
    app.include_router(targets.router)
    app.include_router(scans.router)
    app.include_router(schedules.router)
    app.include_router(findings.router)
    app.include_router(approvals.router)
    app.include_router(emergency.router)
    app.include_router(admin.router)
    app.include_router(audit.router)
    app.include_router(notifications.router)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
