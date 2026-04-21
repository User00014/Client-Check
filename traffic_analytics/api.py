from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .service import AnalyticsService
from .support import DashboardQueryError


class PostLogsRequest(BaseModel):
    side: str = Field(description="仅支持 b")
    logs: list[str | dict[str, Any]] = Field(default_factory=list)


class GenerateReportRequest(BaseModel):
    customer_name: str | None = None
    host: str | None = None
    date_from: str
    date_to: str


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

    @app.get("/frontend/filters")
    def frontend_filters(
        customer_name: str | None = Query(default=None),
        date_from: str | None = Query(default=None),
        date_to: str | None = Query(default=None),
    ) -> dict[str, Any]:
        try:
            return analytics_service.get_dashboard_filters(
                customer_name=customer_name,
                date_from=date_from,
                date_to=date_to,
            )
        except DashboardQueryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.to_dict()) from exc

    @app.get("/frontend/dashboard")
    def frontend_dashboard(
        customer_name: str | None = Query(default=None),
        host: str | None = Query(default=None),
        date_from: str | None = Query(default=None),
        date_to: str | None = Query(default=None),
        top_bots: int = Query(default=10, ge=1),
        top_pages: int = Query(default=10, ge=1),
    ) -> dict[str, Any]:
        try:
            return analytics_service.get_filtered_dashboard(
                customer_name=customer_name,
                host=host,
                date_from=date_from,
                date_to=date_to,
                top_bots=top_bots,
                top_pages=top_pages,
                exclude_sensitive_pages=False,
            )
        except DashboardQueryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.to_dict()) from exc

    @app.post("/frontend/report")
    def frontend_report(payload: GenerateReportRequest) -> dict[str, str]:
        try:
            result = analytics_service.generate_word_report(
                customer_name=payload.customer_name,
                host=payload.host,
                date_from=payload.date_from,
                date_to=payload.date_to,
            )
        except DashboardQueryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.to_dict()) from exc
        return {
            "filename": result["filename"],
            "download_url": f"/frontend/report/download?name={result['filename']}",
        }

    @app.get("/frontend/report/download")
    def frontend_report_download(name: str = Query(...)) -> FileResponse:
        try:
            path = analytics_service.resolve_report_download_path(name)
        except DashboardQueryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.to_dict()) from exc
        return FileResponse(
            path,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=path.name,
        )

    return app
