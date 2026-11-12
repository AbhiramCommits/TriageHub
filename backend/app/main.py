"""TriageHub FastAPI application."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.auth import oauth, oidc
from app.config import settings
from app.integrations.github.router import router as github_router
from app.integrations.slack.router import router as slack_router
from app.routers import findings, health, users


def create_app() -> FastAPI:
    app = FastAPI(title="TriageHub", version="1.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.console_url],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router)
    app.include_router(findings.router)
    app.include_router(users.router)
    app.include_router(oauth.router)
    app.include_router(oidc.router)
    app.include_router(slack_router)
    app.include_router(github_router)

    dist = Path(__file__).resolve().parent.parent / "frontend_dist"
    if dist.is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str) -> FileResponse:
            candidate = dist / full_path
            if full_path and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(dist / "index.html")

    return app


app = create_app()
