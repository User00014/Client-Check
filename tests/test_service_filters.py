from __future__ import annotations

import uuid
from pathlib import Path

from traffic_analytics.service import AnalyticsService


def test_build_filter_sql_uses_index_list_and_host() -> None:
    tmp_path = Path.cwd() / "output" / "current"
    token = uuid.uuid4().hex
    service = AnalyticsService(
        full_db_path=tmp_path / f"test-full-{token}.sqlite",
        increment_db_path=tmp_path / f"test-increment-{token}.sqlite",
        snapshot_path=tmp_path / f"test-snapshot-{token}.json",
        frontend_snapshot_path=tmp_path / f"test-frontend-{token}.json",
        log_dir=tmp_path,
        auto_sync_interval_seconds=3600,
    )
    where_sql, params = service._build_filter_sql(
        index_names=["nginx-logs-moseeker-2026.03.01"],
        host="www.moseeker.com",
        date_from="2026-03-01",
        date_to="2026-03-31",
        exclude_sensitive_pages=False,
    )
    assert "source_ref IN (?)" in where_sql
    assert "host = ?" in where_sql
    assert "nginx-logs-moseeker-2026.03.01" in params
    assert "www.moseeker.com" in params


def test_shopify_guard_sql_requires_app_proxy() -> None:
    service = AnalyticsService()
    where_sql, _ = service._build_filter_sql(
        index_names=["nginx-logs-shopify.deeplumen.io-2026.04.07"],
        host="shopify.deeplumen.io",
        date_from=None,
        date_to=None,
        exclude_sensitive_pages=False,
    )
    assert "LIKE '/app-proxy%'" in where_sql
