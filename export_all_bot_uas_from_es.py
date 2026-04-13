from __future__ import annotations

import argparse
import base64
import csv
import json
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import request

from traffic_analytics.classification import classify_agent, repo_classify_ai_bot


KIBANA_SEARCH_PATH = "/internal/search/es"
KIBANA_HEADERS = {
    "Content-Type": "application/json",
    "kbn-xsrf": "1",
    "kbn-version": "9.3.0",
    "x-elastic-internal-origin": "kibana",
}

# 这组启发式 token 用来补捞“代码现有规则没命中，但从 UA 看起来很像 bot/脚本”的访问。
# 只要命中这里，就会被导出到 CSV；如果又没有命中已有分类规则，则标成“未分类”。
HEURISTIC_BOT_TOKENS = (
    "bot",
    "spider",
    "crawler",
    "crawl",
    "slurp",
    "scraper",
    "scan",
    "fetch",
    "headless",
    "selenium",
    "playwright",
    "phantomjs",
    "python-requests",
    "python-urllib",
    "curl/",
    "libcurl",
    "wget",
    "go-http-client",
    "apache-httpclient",
    "okhttp",
    "axios",
    "node-fetch",
    "java/",
    "restsharp",
    "httpclient",
)


@dataclass
class UaRecord:
    ua: str
    requests: int
    sample_index: str
    source_index_count: int
    first_seen: str
    last_seen: str
    sample_host: str
    sample_uri: str
    sample_status: str
    sample_referer: str
    actor_type: str
    actor_bucket: str
    bot_category: str
    bot_family: str
    vendor: str
    product: str
    purpose: str
    confidence: str
    match_token: str
    heuristic_token: str
    ai_report_category: str
    ai_report_channel: str
    bot_group: str
    final_label: str
    selected_by: str


class KibanaEsClient:
    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url = base_url.rstrip("/")
        pair = f"{username}:{password}".encode("utf-8")
        self.auth = "Basic " + base64.b64encode(pair).decode("ascii")
        self.ssl_context = ssl.create_default_context()

    def post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        headers = dict(KIBANA_HEADERS)
        headers["Authorization"] = self.auth
        req = request.Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with request.urlopen(req, timeout=120, context=self.ssl_context) as resp:
            return json.loads(resp.read().decode("utf-8"))


def heuristic_bot_token(user_agent: str) -> str:
    ua = user_agent.lower()
    for token in HEURISTIC_BOT_TOKENS:
        if token in ua:
            return token
    return ""


def final_label(ai_category: str, bot_category: str, actor_type: str) -> str:
    # 先保留已经明确识别出的非 AI 类别，避免像普通 Baiduspider 这类 SEO
    # 爬虫被 AI 正则误吞进去。
    if bot_category == "SEO Bot":
        return "SEO Bot"
    if bot_category == "Social Preview Bot":
        return "Social Preview Bot"
    if bot_category == "Verification Bot":
        return "Verification Bot"
    if actor_type == "automation":
        return "Automation / Script"
    if ai_category == "ai_search":
        return "AI Search"
    if ai_category == "ai_training":
        return "AI Training"
    if ai_category == "ai_index":
        return "AI Index"
    if ai_category == "ai_unclassified":
        return "AI 未纳入三类"
    if bot_category == "Other External Bot":
        return "Other External Bot"
    return "未分类"


def bot_group(final_label_text: str, actor_type: str) -> str:
    if final_label_text in {"AI Search", "AI Training", "AI Index", "AI 未纳入三类"}:
        return "AI Bot"
    if final_label_text in {"SEO Bot", "Other External Bot", "Social Preview Bot", "Verification Bot"}:
        return "普通 Bot"
    if actor_type == "automation" or final_label_text == "Automation / Script":
        return "Automation / Script"
    return "未分类"


def selected_by(actor_type: str, heuristic_token_text: str) -> str:
    if actor_type in {"bot", "automation"}:
        return "code_rule"
    if heuristic_token_text:
        return "heuristic"
    return ""


def should_export(actor_type: str, heuristic_token_text: str) -> bool:
    return actor_type in {"bot", "automation"} or bool(heuristic_token_text)


def iter_all_unique_uas(client: KibanaEsClient, index: str, page_size: int = 1000) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    after_key: dict[str, Any] | None = None
    while True:
        composite: dict[str, Any] = {
            "size": page_size,
            "sources": [
                {
                    "ua": {
                        "terms": {
                            "field": "ua.keyword",
                        }
                    }
                }
            ],
        }
        if after_key:
            composite["after"] = after_key
        payload = {
            "params": {
                "index": index,
                "body": {
                    "size": 0,
                    "track_total_hits": False,
                    "query": {
                        "bool": {
                            "filter": [
                                {"exists": {"field": "ua.keyword"}},
                            ]
                        }
                    },
                    "aggs": {
                        "uas": {
                            "composite": composite,
                            "aggs": {
                                "first_seen": {"min": {"field": "@timestamp"}},
                                "last_seen": {"max": {"field": "@timestamp"}},
                                "source_index_count": {"cardinality": {"field": "_index"}},
                                "sample": {
                                    "top_hits": {
                                        "size": 1,
                                        "sort": [{"@timestamp": "desc"}],
                                        "_source": ["ua", "host", "uri", "status", "referer"],
                                    }
                                },
                            },
                        }
                    },
                },
            }
        }
        response = client.post_json(KIBANA_SEARCH_PATH, payload)
        buckets = response.get("rawResponse", {}).get("aggregations", {}).get("uas", {}).get("buckets", [])
        rows.extend(buckets)
        after_key = response.get("rawResponse", {}).get("aggregations", {}).get("uas", {}).get("after_key")
        if not after_key or not buckets:
            break
    return rows


def bucket_to_record(bucket: dict[str, Any]) -> UaRecord | None:
    ua = str(bucket.get("key", {}).get("ua") or "").strip()
    if not ua:
        return None
    agent = classify_agent(ua)
    ai = repo_classify_ai_bot(ua)
    heuristic = heuristic_bot_token(ua)
    if not should_export(agent.get("actor_type", ""), heuristic):
        return None

    sample_hits = bucket.get("sample", {}).get("hits", {}).get("hits", [])
    sample_hit = sample_hits[0] if sample_hits else {}
    sample_source = sample_hit.get("_source", {}) if sample_hit else {}
    ai_report_category = ai[0] if ai else ""
    ai_report_channel = ai[1] if ai else ""
    label = final_label(ai_report_category, str(agent.get("category") or ""), str(agent.get("actor_type") or ""))

    return UaRecord(
        ua=ua,
        requests=int(bucket.get("doc_count") or 0),
        sample_index=str(sample_hit.get("_index") or ""),
        source_index_count=int(bucket.get("source_index_count", {}).get("value") or 0),
        first_seen=str(bucket.get("first_seen", {}).get("value_as_string") or ""),
        last_seen=str(bucket.get("last_seen", {}).get("value_as_string") or ""),
        sample_host=str(sample_source.get("host") or ""),
        sample_uri=str(sample_source.get("uri") or ""),
        sample_status=str(sample_source.get("status") or ""),
        sample_referer=str(sample_source.get("referer") or ""),
        actor_type=str(agent.get("actor_type") or ""),
        actor_bucket=str(agent.get("bucket") or ""),
        bot_category=str(agent.get("category") or ""),
        bot_family=str(agent.get("family") or ""),
        vendor=str(agent.get("vendor") or ""),
        product=str(agent.get("product") or ""),
        purpose=str(agent.get("purpose") or ""),
        confidence=str(agent.get("confidence") or ""),
        match_token=str(agent.get("match_token") or ""),
        heuristic_token=heuristic,
        ai_report_category=ai_report_category,
        ai_report_channel=ai_report_channel,
        bot_group=bot_group(label, str(agent.get("actor_type") or "")),
        final_label=label,
        selected_by=selected_by(str(agent.get("actor_type") or ""), heuristic),
    )


def write_csv(output_path: Path, records: list[UaRecord]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "ua",
                "requests",
                "sample_index",
                "source_index_count",
                "first_seen",
                "last_seen",
                "sample_host",
                "sample_uri",
                "sample_status",
                "sample_referer",
                "actor_type",
                "actor_bucket",
                "bot_category",
                "bot_family",
                "vendor",
                "product",
                "purpose",
                "confidence",
                "match_token",
                "heuristic_token",
                "ai_report_category",
                "ai_report_channel",
                "bot_group",
                "final_label",
                "selected_by",
            ],
        )
        writer.writeheader()
        for item in records:
            writer.writerow(item.__dict__)


def main() -> None:
    parser = argparse.ArgumentParser(description="从 Kibana/ES 全量导出 bot UA 并分类")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--index", default="nginx-logs-moseeker-*")
    parser.add_argument("--output", default="output/current/all_bot_ua_catalog.csv")
    args = parser.parse_args()

    client = KibanaEsClient(args.base_url, args.username, args.password)
    buckets = iter_all_unique_uas(client, args.index)
    records = [item for bucket in buckets if (item := bucket_to_record(bucket)) is not None]
    records.sort(key=lambda row: (-row.requests, row.final_label, row.bot_family, row.ua))
    write_csv(Path(args.output), records)

    summary: dict[str, int] = {}
    for row in records:
        summary[row.final_label] = summary.get(row.final_label, 0) + 1

    print(f"unique_ua_buckets={len(buckets)}")
    print(f"exported_bot_like_uas={len(records)}")
    for label, count in sorted(summary.items(), key=lambda item: (-item[1], item[0])):
        print(f"{label}={count}")
    print(f"output={Path(args.output).resolve()}")


if __name__ == "__main__":
    main()
