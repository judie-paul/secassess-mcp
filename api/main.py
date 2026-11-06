"""FastAPI application entry point.

Run with:  uvicorn api.main:app --reload
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

import config
from api.routes.organizations import router as organizations_router
from api.dependencies import Services
from api.errors import AppError


def _error(status_code: int, code: str, message: str, details=None) -> JSONResponse:
    body = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = jsonable_encoder(details)
    return JSONResponse(status_code=status_code, content=body)


def create_app(data_dir: Optional[Path] = None, reports_dir: Optional[Path] = None) -> FastAPI:
    app = FastAPI(
        title=config.API_TITLE,
        version=config.API_VERSION,
        description=(
            "Deterministic security assessment backend. Numeric scores, rankings and evidence are "
            "authoritative; AI clients add interpretation only."
        ),
    )
    app.state.services = Services(data_dir, reports_dir)

    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError):
        return _error(exc.status_code, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError):
        errors = exc.errors()
        first = errors[0] if errors else {"loc": (), "msg": "Invalid request"}
        location = ".".join(str(p) for p in first.get("loc", ()))
        return _error(422, "validation_error", f"{location}: {first.get('msg')}", errors)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException):
        return _error(exc.status_code, "http_error", str(exc.detail))

    @app.get("/health", tags=["meta"])
    def health():
        return {"status": "ok", "reference_time": config.REFERENCE_TIME}

    app.include_router(organizations_router)
    return app


app = create_app()
