from __future__ import annotations

from traffic_analytics.index_filtering import parse_index_name
from traffic_analytics.remote_source import KibanaRemoteLogSource


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
    assert "*geo.tec-do.com*" in values
    assert "*geo-tec-do-com*" in values
    assert "*tec-do*" in values
    assert "*moseeker*" in values


def test_list_index_options_uses_real_indices_and_skips_www_tecdo() -> None:
    source = KibanaRemoteLogSource()

    def fake_post_json(path: str, payload: dict) -> dict:
        return {
            "rawResponse": {
                "aggregations": {
                    "indices": {
                        "buckets": [
                            {"key": "nginx-prelogs-www.moseeker.com-pre-2026.04.07", "doc_count": 50},
                            {"key": "nginx-prelogs-www.tec-do.com-pre-2026.04.07", "doc_count": 40},
                            {"key": "nginx-prelogs-tec-do-pre-2026.04.07", "doc_count": 30},
                            {"key": "nginx-prelogs-geo-tec-do-pre-2026.04.07", "doc_count": 20},
                        ]
                    }
                }
            }
        }

    source._post_json = fake_post_json  # type: ignore[method-assign]
    rows = source.list_index_options()

    assert [row["value"] for row in rows] == [
        "nginx-prelogs-www.moseeker.com-pre-2026.04.07",
        "nginx-prelogs-tec-do-pre-2026.04.07",
        "nginx-prelogs-geo-tec-do-pre-2026.04.07",
    ]
    assert rows[1]["index_name"] == "nginx-prelogs-tec-do-pre-2026.04.07"
    assert rows[1]["index_prefix"] == "nginx-prelogs"
    assert rows[0]["customer_name"] == "www.moseeker.com"
    assert rows[1]["index_tag"] == "pre"
    assert rows[0]["index_date"] == "2026-04-07"
    assert rows[1]["label"] == "nginx-prelogs-tec-do-pre-2026.04.07"


def test_parse_index_name_splits_customer_and_date() -> None:
    assert parse_index_name("nginx-logs-moseeker-2026.04.01") == {
        "index_prefix": "nginx-logs",
        "customer_name": "moseeker",
        "index_tag": "",
        "index_date": "2026-04-01",
        "label": "nginx-logs-moseeker-2026.04.01",
    }
    assert parse_index_name("moseeker-nginx-logs-2026.03.02") == {
        "index_prefix": "nginx-logs",
        "customer_name": "moseeker",
        "index_tag": "",
        "index_date": "2026-03-02",
        "label": "moseeker-nginx-logs-2026.03.02",
    }
