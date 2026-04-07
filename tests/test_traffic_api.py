from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from traffic_analytics.api import create_app
from traffic_analytics.classification import repo_classify_access
from traffic_analytics.remote_source import KibanaRemoteLogSource
from traffic_analytics.service import AnalyticsService


def test_api_end_to_end(tmp_path: Path) -> None:
    log_dir = tmp_path / "日志"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "moseeker_b_side_access_20260301.log").write_text(
        '172.25.0.191 - - [01/Mar/2026:10:00:00 +0800] "GET /ai/about HTTP/1.1" 200 123 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"\n',
        encoding="utf-8",
    )
    (log_dir / "moseeker_b_side_access_20260302.log").write_text(
        '172.25.0.191 - - [02/Mar/2026:10:00:00 +0800] "GET /ai/contact HTTP/1.1" 200 123 "-" "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.3; +https://openai.com/gptbot)"\n',
        encoding="utf-8",
    )
    (log_dir / "moseeker_b_side_access_20260303.log").write_text(
        '172.25.0.191 - - [03/Mar/2026:10:00:00 +0800] "GET /ai/solution HTTP/1.1" 200 123 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"\n',
        encoding="utf-8",
    )
    (log_dir / "moseeker_b_side_access_20260304.log").write_text(
        '172.25.0.191 - - [04/Mar/2026:10:00:00 +0800] "GET /ai/case HTTP/1.1" 200 123 "-" "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"\n',
        encoding="utf-8",
    )

    service = AnalyticsService(
        full_db_path=tmp_path / "full.sqlite",
        increment_db_path=tmp_path / "increment.sqlite",
        snapshot_path=tmp_path / "snapshot.json",
        log_dir=log_dir,
        auto_sync_interval_seconds=3600,
    )
    app = create_app(service)

    with TestClient(app) as client:
        summary = client.get("/summary")
        assert summary.status_code == 200
        payload = summary.json()
        assert payload["total_requests"] == 4
        assert payload["total_bot_families"] >= 2

        bots = client.get("/bots/catalog")
        assert bots.status_code == 200
        families = {item["bot_family"] for item in bots.json()}
        assert "GPTBot" in families
        assert "ChatGPT-User" in families

        post_result = client.post(
            "/logs",
            json={
                "side": "b",
                "logs": [
                    '172.25.0.191 - - [05/Mar/2026:10:00:00 +0800] "GET /ai/new-page HTTP/1.1" 200 123 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"'
                ],
            },
        )
        assert post_result.status_code == 200

        increment = client.get("/increment/snapshot?limit=20")
        assert increment.status_code == 200
        overview = increment.json()["daily_overview"]
        assert overview


def test_repo_static_takes_priority_over_ai_bot() -> None:
    result = repo_classify_access(
        host="www.tec-do.com",
        uri="/static/home/js/jquery.min.js",
        args="",
        status=200,
        referer="-",
        user_agent="YisouSpider",
    )
    assert result["category"] == "static"


def test_customer_alias_filter_uses_base_domain(tmp_path: Path) -> None:
    service = AnalyticsService(
        full_db_path=tmp_path / "full.sqlite",
        increment_db_path=tmp_path / "increment.sqlite",
        snapshot_path=tmp_path / "snapshot.json",
        log_dir=tmp_path / "日志",
        auto_sync_interval_seconds=3600,
    )
    where_sql, params = service._build_filter_sql(
        customer="moseeker",
        date_from="2026-03-01",
        date_to="2026-03-31",
        exclude_sensitive_pages=False,
    )
    assert "customer_domain" in where_sql
    assert "moseeker.com" in params


def test_remote_index_scope_expands_index_names_and_skips_www_tecdo() -> None:
    source = KibanaRemoteLogSource()
    scope = source._scope_query(["www.moseeker.com", "tec-do.com", "www.tec-do.com", "geo.tec-do.com"])
    values = [item["wildcard"]["_index"]["value"] for item in scope["bool"]["should"]]

    assert "*www.moseeker.com*" in values
    assert "*www-moseeker-com*" in values
    assert "*tec-do.com*" in values
    assert "*tec-do-com*" in values
    assert "*www.tec-do.com*" not in values
    assert "*www-tec-do-com*" not in values
    assert "*geo.tec-do.com*" not in values
    assert "*geo-tec-do-com*" not in values
