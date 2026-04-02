from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from .service import AnalyticsService


class PostLogsRequest(BaseModel):
    side: str = Field(description="仅支持 b")
    logs: list[str | dict[str, Any]] = Field(default_factory=list)


@asynccontextmanager
async def lifespan(app: FastAPI):
    service: AnalyticsService = app.state.analytics_service
    service.initialize(auto_sync=True)
    try:
        yield
    finally:
        service.stop_auto_sync()


def create_app(service: AnalyticsService | None = None) -> FastAPI:
    analytics_service = service or AnalyticsService()
    app = FastAPI(
        title="Moseeker Traffic Analytics API",
        version="1.0.0",
        summary="B-side 全量库 + 增量库 + Bot 细分类 + 用户增量统计接口",
        lifespan=lifespan,
    )
    app.state.analytics_service = analytics_service

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/summary")
    def summary() -> dict[str, Any]:
        return analytics_service.get_summary()

    @app.get("/bots/catalog")
    def bot_catalog() -> list[dict[str, Any]]:
        return analytics_service.get_bot_catalog()

    @app.get("/increment/snapshot")
    def increment_snapshot(limit: int | None = Query(default=None, ge=1, le=5000)) -> dict[str, Any]:
        return analytics_service.get_increment_snapshot(limit=limit)

    @app.get("/users/{user_id}")
    def user_detail(user_id: str) -> dict[str, Any]:
        result = analytics_service.get_user_detail(user_id)
        if result is None:
            raise HTTPException(status_code=404, detail="user_id not found")
        return result

    @app.post("/logs")
    def post_logs(payload: PostLogsRequest) -> dict[str, Any]:
        if not payload.logs:
            raise HTTPException(status_code=400, detail="logs cannot be empty")
        try:
            return analytics_service.ingest_api_logs(payload.side, payload.logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/sync")
    def sync_now() -> dict[str, Any]:
        return analytics_service.sync_from_local_logs()

    return app
