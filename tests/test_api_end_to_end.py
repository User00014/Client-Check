from __future__ import annotations

import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from traffic_analytics.api import create_app
from traffic_analytics.classification import repo_classify_access
from traffic_analytics.service import AnalyticsService


def test_api_end_to_end() -> None:
    tmp_path = Path.cwd() / "output" / "current"
    token = uuid.uuid4().hex
    log_dir = tmp_path
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
        full_db_path=tmp_path / f"test-full-{token}.sqlite",
        increment_db_path=tmp_path / f"test-increment-{token}.sqlite",
        snapshot_path=tmp_path / f"test-snapshot-{token}.json",
        frontend_snapshot_path=tmp_path / f"test-frontend-{token}.json",
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
        assert increment.json()["daily_overview"]


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


def test_shopify_app_proxy_scope_bypasses_unknown_and_seo_bot() -> None:
    result = repo_classify_access(
        host="shopify2.deeplumen.cn",
        uri="/app-proxy/products/demo-item",
        args="",
        status=200,
        referer="-",
        user_agent="Mozilla/5.0 (compatible; PetalBot; +https://example.com/bot)",
    )
    assert result["category"] == "seo_bot"
    assert result["channel"] == "PetalBot"


def test_repo_ai_mapping_uses_official_sheet() -> None:
    result = repo_classify_access(
        host="www.tec-do.com",
        uri="/docs/ai",
        args="",
        status=200,
        referer="-",
        user_agent="Mozilla/5.0 (compatible; OAI-SearchBot/1.3; +https://openai.com/searchbot)",
    )
    assert result["category"] == "ai_index"
    assert result["channel"] == "OAI-SearchBot"


def test_repo_sheet_can_move_previous_ai_bot_to_seo() -> None:
    result = repo_classify_access(
        host="www.tec-do.com",
        uri="/docs/seo",
        args="",
        status=200,
        referer="-",
        user_agent="Mozilla/5.0 (compatible; 360Spider; +https://example.com/bot)",
    )
    assert result["category"] == "seo_bot"
    assert result["channel"] == "360Spider"


def test_unlisted_bot_goes_to_ai_unclassified() -> None:
    result = repo_classify_access(
        host="www.tec-do.com",
        uri="/news",
        args="",
        status=200,
        referer="-",
        user_agent="Mozilla/5.0 (compatible; NewCrawlerBot/2.0; +https://example.com/bot)",
    )
    assert result["category"] == "seo_bot"
    assert result["channel"] == "Others"
