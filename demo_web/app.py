from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from demo_web.session import SessionManager
from demo_web.story import timeline_for_mode

ROOT = Path(__file__).resolve().parents[1]


class StartDemoRequest(BaseModel):
    mode: str = Field(pattern="^(lockbit_public|safe_file_activity)$")
    limit: int | None = Field(default=None, ge=1, le=100)
    delay: float | None = Field(default=None, ge=0.0, le=10.0)


def create_app(*, root: Path | None = None, session_manager: SessionManager | None = None) -> FastAPI:
    app_root = root or ROOT
    manager = session_manager or SessionManager(app_root)
    templates = Jinja2Templates(directory=str(app_root / "demo_web" / "templates"))

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            await manager.reset()

    app = FastAPI(title="ATMT Wazuh Live Demo", lifespan=lifespan)
    app.state.session_manager = manager
    app.mount("/static", StaticFiles(directory=str(app_root / "demo_web" / "static")), name="static")
    app.mount("/results", StaticFiles(directory=str(app_root / "results")), name="results")

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        snapshot = manager.snapshot()
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "initial_state": snapshot,
                "lockbit_timeline": timeline_for_mode("lockbit_public"),
                "safe_timeline": timeline_for_mode("safe_file_activity"),
            },
        )

    @app.get("/api/status")
    async def status() -> JSONResponse:
        return JSONResponse(manager.snapshot())

    @app.post("/api/setup")
    async def setup() -> JSONResponse:
        try:
            await manager.setup()
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return JSONResponse({"accepted": True, "state": manager.snapshot()})

    @app.post("/api/reset")
    async def reset() -> JSONResponse:
        await manager.reset()
        return JSONResponse({"accepted": True, "state": manager.snapshot()})

    @app.post("/api/demo/start")
    async def start_demo(payload: StartDemoRequest) -> JSONResponse:
        try:
            await manager.start_demo(mode=payload.mode, limit=payload.limit, delay=payload.delay)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return JSONResponse({"accepted": True, "state": manager.snapshot()})

    @app.get("/api/stream")
    async def stream() -> StreamingResponse:
        queue = await manager.subscribe()

        async def event_stream() -> Any:
            try:
                while True:
                    try:
                        message = await asyncio.wait_for(queue.get(), timeout=15.0)
                        yield message
                    except asyncio.TimeoutError:
                        yield "event: ping\ndata: {}\n\n"
            finally:
                manager.unsubscribe(queue)

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    return app


app = create_app()
