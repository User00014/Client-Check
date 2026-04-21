from __future__ import annotations

import json
import math
import os
import re
import shutil
import tempfile
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib import request
from urllib.error import HTTPError, URLError

from .bot_taxonomy import load_bot_taxonomy
from .index_filtering import filter_index_options
from .support import DashboardQueryError, local_day_to_utc_bounds


ROOT_DIR = Path(__file__).resolve().parent.parent
REPORT_TEMPLATE_PATH = ROOT_DIR / "2026-04-15-qbedding-traffic-report.docx"
REPORT_OUTPUT_DIR = ROOT_DIR / "output" / "current" / "reports"
REPORT_REMOTE_PATH = "/internal/search/es"
REPORT_TIMEZONE = "Asia/Shanghai"
REPORT_LOCAL_CONFIG_PATH = ROOT_DIR / "reporting.local.json"


@dataclass
class WeekStats:
    label: str
    start: str
    end: str
    days: int
    ai_index: int
    ai_search: int
    ai_training: int
    seo_bot: int

    @property
    def total(self) -> int:
        return self.ai_index + self.ai_search + self.ai_training + self.seo_bot

    @property
    def ai_total(self) -> int:
        return self.ai_index + self.ai_search + self.ai_training

    def daily_avg(self, value: int) -> float:
        return value / self.days if self.days else 0.0


def generate_word_report(
    service,
    customer_name: str | None,
    host: str | None,
    date_from: str,
    date_to: str,
) -> dict[str, str]:
    try:
        from docx import Document
    except ImportError as exc:
        raise DashboardQueryError(
            message="report generation dependency missing: python-docx",
            error_type="report_dependency_missing",
            source="reporting",
            status_code=500,
            extra={"module": "python-docx"},
        ) from exc

    _ensure_template_exists()
    report_data = _collect_report_data(service, customer_name, host, date_from, date_to)
    REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_name = _report_filename(report_data["file_label"], date_from, date_to)
    output_path = REPORT_OUTPUT_DIR / output_name
    shutil.copyfile(REPORT_TEMPLATE_PATH, output_path)

    doc = Document(str(output_path))
    _fill_docx_template(doc, report_data)
    doc.save(str(output_path))

    with tempfile.TemporaryDirectory(prefix="report_charts_") as tmp_dir:
        chart_paths = _build_chart_images(report_data, Path(tmp_dir))
        _replace_docx_images(output_path, chart_paths)

    return {
        "filename": output_name,
        "path": str(output_path),
    }


def generate_weekly_comparison(service, customer_name: str | None, host: str | None, date_from: str, date_to: str) -> dict[str, Any]:
    data = _collect_report_data(service, customer_name, host, date_from, date_to)
    return {
        "title_label": data["title_label"],
        "weeks": [
            {
                "label": week.label,
                "start": week.start,
                "end": week.end,
                "days": week.days,
                "total": week.total,
                "daily_avg": round(week.daily_avg(week.total), 1),
                "ai_daily_avg": round(week.daily_avg(week.ai_total), 1),
                "seo_daily_avg": round(week.daily_avg(week.seo_bot), 1),
            }
            for week in data["week_stats"]
        ],
        "note": f"按当前筛选对象在所选时间范围内的全部自然周统计，当前共展示 {len(data['week_stats'])} 个周区间。",
    }


def resolve_report_download_path(file_name: str) -> Path:
    safe_name = Path(file_name).name
    path = (REPORT_OUTPUT_DIR / safe_name).resolve()
    base = REPORT_OUTPUT_DIR.resolve()
    if base not in path.parents and path != base:
        raise DashboardQueryError(
            message="invalid report path",
            error_type="report_download_invalid_path",
            source="reporting",
            status_code=400,
        )
    if not path.exists() or not path.is_file():
        raise DashboardQueryError(
            message="report file not found",
            error_type="report_download_missing",
            source="reporting",
            status_code=404,
        )
    return path


def _ensure_template_exists() -> None:
    if REPORT_TEMPLATE_PATH.exists():
        return
    raise DashboardQueryError(
        message="report template file is missing",
        error_type="report_template_missing",
        source="reporting",
        status_code=500,
        extra={"path": str(REPORT_TEMPLATE_PATH)},
    )


def _report_filename(file_label: str, date_from: str, date_to: str) -> str:
    label = re.sub(r"[^A-Za-z0-9._-]+", "-", (file_label or "report")).strip("-").lower() or "report"
    generated_on = datetime.now().date().isoformat()
    return f"{generated_on}-{label}-traffic-report-{date_from}_to_{date_to}.docx"


def _collect_report_data(service, customer_name: str | None, host: str | None, date_from: str, date_to: str) -> dict[str, Any]:
    remote = service.remote_source
    start_utc, end_utc = local_day_to_utc_bounds(date_from, date_to)
    period_indices = filter_index_options(
        remote.list_index_options(start_utc=start_utc, end_utc=end_utc),
        customer_name,
        None,
        date_from=date_from,
        date_to=date_to,
    )
    period_index_names = [str(item.get("value") or "") for item in period_indices if item.get("value")]
    if customer_name and customer_name != "ALL" and not period_index_names:
        raise DashboardQueryError(
            message="no data found for selected report scope",
            error_type="report_scope_empty",
            source="reporting",
            status_code=404,
            extra={"customer_name": customer_name, "host": host, "date_from": date_from, "date_to": date_to},
        )

    host_filters = [host] if host and host != "ALL" else None

    current_label = host if host and host != "ALL" else (customer_name if customer_name and customer_name != "ALL" else "all-customers")
    title_label = host if host and host != "ALL" else (customer_name if customer_name and customer_name != "ALL" else "全部客户")
    month_label = f"{date.fromisoformat(date_to).year} 年 {date.fromisoformat(date_to).month} 月"

    summary = _query_report_summary(remote, period_index_names, host_filters, start_utc, end_utc)
    rankings = _query_category_rankings(remote, period_index_names, host_filters, start_utc, end_utc)
    top_pages = _query_top_pages(remote, period_index_names, host_filters, start_utc, end_utc, limit=25)
    stage = _query_stage_assessment_v2(remote, period_index_names, host_filters, start_utc, end_utc)
    weekly_days = _query_report_daily(remote, period_index_names, host_filters, start_utc, end_utc)
    week_stats = _compute_weeks_in_range(weekly_days)
    taxonomy_rows = [(entry.bot_name, entry.category) for entry in load_bot_taxonomy().entries]
    llm_summary = _build_llm_stage_summary(
        title_label=title_label,
        date_from=date_from,
        date_to=date_to,
        summary=summary,
        stage=stage,
    )

    return {
        "title_label": title_label,
        "scope_label": title_label,
        "file_label": current_label,
        "month_label": month_label,
        "date_from": date_from,
        "date_to": date_to,
        "period_days": _inclusive_days(date_from, date_to),
        "summary": summary,
        "rankings": rankings,
        "top_pages": top_pages,
        "stage": stage,
        "week_stats": week_stats,
        "taxonomy_rows": taxonomy_rows,
        "selected_week_note": _period_week_note(date_from, date_to),
        "final_note": "本报告由 Deeplumen 提供 | 数据来源：Agentic Page访问日志（报告统计已纳入 sitemap 与 llms.txt 相关流量）",
        "llm_summary": llm_summary,
    }


def _report_special_path_query(remote) -> dict[str, Any]:
    return {
        "bool": {
            "should": [
                remote._keyword_contains("uri.keyword", "llms.txt"),
                remote._keyword_contains("uri.keyword", "sitemap"),
            ],
            "minimum_should_match": 1,
        }
    }


def _load_report_llm_config() -> dict[str, str]:
    config = {
        "base_url": os.getenv("REPORT_LLM_BASE_URL", "").strip() or os.getenv("ANTHROPIC_BASE_URL", "").strip(),
        "token": os.getenv("REPORT_LLM_TOKEN", "").strip() or os.getenv("ANTHROPIC_AUTH_TOKEN", "").strip(),
        "model": os.getenv("REPORT_LLM_MODEL", "claude-opus-4-6").strip(),
    }
    if REPORT_LOCAL_CONFIG_PATH.exists():
        try:
            payload = json.loads(REPORT_LOCAL_CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                config["base_url"] = str(payload.get("base_url") or config["base_url"]).strip()
                config["token"] = str(payload.get("token") or config["token"]).strip()
                config["model"] = str(payload.get("model") or config["model"]).strip()
        except Exception:
            pass
    return config


def _build_llm_stage_summary(title_label: str, date_from: str, date_to: str, summary: dict[str, Any], stage: dict[str, Any]) -> str:
    fallback = _stage_summary_text(title_label, stage)
    config = _load_report_llm_config()
    if not config.get("base_url") or not config.get("token"):
        return fallback

    prompt = {
        "site": title_label,
        "period": [date_from, date_to],
        "ai_index": summary.get("ai_index", 0),
        "ai_search": summary.get("ai_search", 0),
        "ai_training": summary.get("ai_training", 0),
        "seo_bot": summary.get("seo_bot", 0),
        "chatgpt_total": stage.get("chatgpt_total", 0),
        "oai_total": stage.get("oai_total", 0),
        "training_total": stage.get("training_total", 0),
        "first_special_hit": stage.get("first_special_hit"),
    }
    body = {
        "model": config["model"],
        "max_tokens": 320,
        "temperature": 0.2,
        "system": "你是中文数据报告助手。只输出一段正式、简洁、业务风格的总结，不要列表，不要标题，不要解释。",
        "messages": [
            {
                "role": "user",
                "content": f"基于以下JSON写1段中文总结，40到90字，说明当前AI可发现性阶段和下一步观察重点：{json.dumps(prompt, ensure_ascii=False, separators=(',', ':'))}"
            }
        ],
    }
    try:
        req = request.Request(
            config["base_url"].rstrip("/") + "/v1/messages",
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers={
                "content-type": "application/json",
                "x-api-key": config["token"],
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        with request.urlopen(req, timeout=40) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        parts = payload.get("content") or []
        text = " ".join(str(item.get("text") or "").strip() for item in parts if isinstance(item, dict)).strip()
        return text or fallback
    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError, OSError):
        return fallback


def _report_static_exclusion_query(remote) -> dict[str, Any]:
    return {
        "bool": {
            "must": [remote._static_resource_query()],
            "must_not": [_report_special_path_query(remote)],
        }
    }


def _report_category_queries(remote, shopify_scope: bool) -> dict[str, dict[str, Any]]:
    static_exclusion = _report_static_exclusion_query(remote)
    mirror_non_302 = remote._mirror_non_302_query(allow_io_mirror=shopify_scope)
    probe = remote._suspicious_probe_query()
    exclusions = [static_exclusion, mirror_non_302, probe]
    return {
        "ai_search": {"bool": {"must": [remote._ai_search_query()], "must_not": exclusions}},
        "ai_training": {"bool": {"must": [remote._ai_training_query()], "must_not": exclusions}},
        "ai_index": {"bool": {"must": [remote._ai_index_query()], "must_not": exclusions}},
        "seo_bot": {"bool": {"must": [remote._seo_bot_query()], "must_not": exclusions}},
    }


def _report_base_filters(remote, start_utc: str, end_utc: str, host_filters: list[str] | None, shopify_scope: bool) -> list[dict[str, Any]]:
    return remote._dashboard_base_filters(start_utc, end_utc, host_filters, shopify_scope)


def _query_report_summary(remote, index_names: list[str], host_filters: list[str] | None, start_utc: str, end_utc: str) -> dict[str, Any]:
    shopify_scope = remote._is_shopify_scope(index_names)
    queries = _report_category_queries(remote, shopify_scope)
    filters = _report_base_filters(remote, start_utc, end_utc, host_filters, shopify_scope)
    body = {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "categories": {"filters": {"filters": queries}},
            "days": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "1d",
                    "time_zone": REPORT_TIMEZONE,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": start_utc, "max": remote._end_bound(end_utc)},
                },
                "aggs": {"categories": {"filters": {"filters": queries}}},
            },
        },
    }
    response = remote._post_json(REPORT_REMOTE_PATH, {"params": {"index": remote._query_index_target(index_names), "body": body}})
    aggs = response["rawResponse"]["aggregations"]
    counts = {key: int(value["doc_count"]) for key, value in aggs["categories"]["buckets"].items()}
    days = []
    for bucket in aggs["days"]["buckets"]:
        item = {"date": bucket["key_as_string"][:10]}
        item.update({key: int(value["doc_count"]) for key, value in bucket["categories"]["buckets"].items()})
        days.append(item)
    counts["ai_total"] = counts.get("ai_search", 0) + counts.get("ai_training", 0) + counts.get("ai_index", 0)
    counts["total"] = counts["ai_total"] + counts.get("seo_bot", 0)
    counts["days"] = days
    return counts


def _query_grouped_rankings(remote, index_names: list[str], host_filters: list[str] | None, start_utc: str, end_utc: str, category_query: dict[str, Any], limit: int = 8) -> list[dict[str, Any]]:
    shopify_scope = remote._is_shopify_scope(index_names)
    body = {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {"filter": _report_base_filters(remote, start_utc, end_utc, host_filters, shopify_scope) + [category_query]}},
        "aggs": {
            "uas": {
                "terms": {
                    "field": "ua.keyword",
                    "size": max(limit * 8, 40),
                    "order": {"_count": "desc"},
                }
            }
        },
    }
    response = remote._post_json(REPORT_REMOTE_PATH, {"params": {"index": remote._query_index_target(index_names), "body": body}})
    grouped: dict[str, int] = defaultdict(int)
    for bucket in response["rawResponse"]["aggregations"]["uas"]["buckets"]:
        name = remote.infer_bot_name_from_ua(bucket["key"]) if hasattr(remote, "infer_bot_name_from_ua") else None
        if not name:
            from .bot_taxonomy import infer_bot_name_from_ua
            name = infer_bot_name_from_ua(bucket["key"])
        grouped[name] += int(bucket["doc_count"])
    rows = [{"name": key, "requests": value} for key, value in grouped.items() if key]
    rows.sort(key=lambda item: (-item["requests"], item["name"]))
    return rows[:limit]


def _query_category_rankings(remote, index_names: list[str], host_filters: list[str] | None, start_utc: str, end_utc: str) -> dict[str, list[dict[str, Any]]]:
    shopify_scope = remote._is_shopify_scope(index_names)
    queries = _report_category_queries(remote, shopify_scope)
    return {
        "ai_search": _query_grouped_rankings(remote, index_names, host_filters, start_utc, end_utc, queries["ai_search"], limit=5),
        "ai_training": _query_grouped_rankings(remote, index_names, host_filters, start_utc, end_utc, queries["ai_training"], limit=5),
        "ai_index": _query_grouped_rankings(remote, index_names, host_filters, start_utc, end_utc, queries["ai_index"], limit=5),
        "seo_bot": _query_grouped_rankings(remote, index_names, host_filters, start_utc, end_utc, queries["seo_bot"], limit=5),
    }


def _query_stage_assessment(remote, index_names: list[str], host_filters: list[str] | None, start_utc: str, end_utc: str) -> dict[str, Any]:
    shopify_scope = remote._is_shopify_scope(index_names)
    queries = _report_category_queries(remote, shopify_scope)
    base_filters = _report_base_filters(remote, start_utc, end_utc, host_filters, shopify_scope)
    special_paths = _report_special_path_query(remote)

    first_hit_body = {
        "size": 1,
        "sort": [{"@timestamp": "asc"}],
        "_source": ["@timestamp", "uri", "ua"],
        "query": {"bool": {"filter": base_filters + [special_paths]}},
    }
    first_hit = None
    response = remote._post_json(REPORT_REMOTE_PATH, {"params": {"index": remote._query_index_target(index_names), "body": first_hit_body}})
    hits = response["rawResponse"]["hits"]["hits"]
    if hits:
        source = hits[0].get("_source") or {}
        from .bot_taxonomy import infer_bot_name_from_ua
        first_hit = {
            "date": str(source.get("@timestamp") or "")[:10],
            "uri": source.get("uri") or "",
            "bot": infer_bot_name_from_ua(source.get("ua") or ""),
        }

    training_rank = _query_grouped_rankings(remote, index_names, host_filters, start_utc, end_utc, queries["ai_training"], limit=4)
    training_total = sum(item["requests"] for item in training_rank)

    oai_body = {
        "size": 0,
        "track_total_hits": False,
        "runtime_mappings": {"normalized_page": remote._normalized_page_runtime()},
        "query": {"bool": {"filter": base_filters + [queries["ai_index"], remote._ua_match("oai-searchbot")]}},
        "aggs": {
            "pages": {"cardinality": {"field": "normalized_page"}},
        },
    }
    oai_resp = remote._post_json(REPORT_REMOTE_PATH, {"params": {"index": remote._query_index_target(index_names), "body": oai_body}})
    oai_total = int(oai_resp["rawResponse"]["aggregations"]["pages"]["meta"]["total"] if False else 0)
    oai_pages = int(oai_resp["rawResponse"]["aggregations"]["pages"]["value"] or 0)

    chatgpt_body = {
        "size": 1,
        "sort": [{"@timestamp": "asc"}],
        "_source": ["@timestamp", "uri", "ua"],
        "query": {"bool": {"filter": base_filters + [queries["ai_search"], remote._ua_match("chatgpt-user")]}},
    }
    chatgpt_resp = remote._post_json(REPORT_REMOTE_PATH, {"params": {"index": remote._query_index_target(index_names), "body": chatgpt_body}})
    chatgpt_hits = chatgpt_resp["rawResponse"]["hits"]["hits"]
    chatgpt_total = int(chatgpt_resp["rawResponse"]["hits"]["total"]["value"] if isinstance(chatgpt_resp["rawResponse"]["hits"]["total"], dict) else len(chatgpt_hits))
    chatgpt_first = None
    if chatgpt_hits:
        source = chatgpt_hits[0].get("_source") or {}
        chatgpt_first = {"date": str(source.get("@timestamp") or "")[:10], "uri": source.get("uri") or ""}

    return {
        "first_special_hit": first_hit,
        "training_rank": training_rank,
        "training_total": training_total,
        "oai_total": oai_total,
        "oai_pages": oai_pages,
        "chatgpt_total": chatgpt_total,
        "chatgpt_first": chatgpt_first,
    }


def _query_report_daily(remote, index_names: list[str], host_filters: list[str] | None, start_utc: str, end_utc: str) -> list[dict[str, Any]]:
    return _query_report_summary(remote, index_names, host_filters, start_utc, end_utc)["days"]


def _week_key(day_text: str) -> tuple[date, date]:
    current = date.fromisoformat(day_text)
    start = current - timedelta(days=current.weekday())
    end = start + timedelta(days=6)
    return start, end


def _compute_weeks_in_range(days: list[dict[str, Any]]) -> list[WeekStats]:
    buckets: dict[tuple[date, date], list[dict[str, Any]]] = defaultdict(list)
    for row in days:
        if row.get("ai_search", 0) == 0 and row.get("ai_training", 0) == 0 and row.get("ai_index", 0) == 0 and row.get("seo_bot", 0) == 0:
            continue
        buckets[_week_key(row["date"])].append(row)
    if not buckets:
        today = date.today().isoformat()
        return [WeekStats("W1", today, today, 1, 0, 0, 0, 0)]
    keys = sorted(buckets.keys())
    stats: list[WeekStats] = []
    for idx, key in enumerate(keys, start=1):
        rows = sorted(buckets[key], key=lambda item: item["date"])
        stats.append(
            WeekStats(
                label=f"W{idx}",
                start=rows[0]["date"],
                end=rows[-1]["date"],
                days=len(rows),
                ai_index=sum(int(item.get("ai_index", 0)) for item in rows),
                ai_search=sum(int(item.get("ai_search", 0)) for item in rows),
                ai_training=sum(int(item.get("ai_training", 0)) for item in rows),
                seo_bot=sum(int(item.get("seo_bot", 0)) for item in rows),
            )
        )
    return stats


def _query_top_pages(remote, index_names: list[str], host_filters: list[str] | None, start_utc: str, end_utc: str, limit: int = 25) -> list[dict[str, Any]]:
    shopify_scope = remote._is_shopify_scope(index_names)
    queries = _report_category_queries(remote, shopify_scope)
    special = _report_special_path_query(remote)
    focused = remote._dashboard_category_filters(allow_io_mirror=shopify_scope)
    ai_any = {"bool": {"should": [focused["ai_search"], focused["ai_training"], focused["ai_index"]], "minimum_should_match": 1}}
    body = {
        "size": 0,
        "track_total_hits": False,
        "runtime_mappings": {"normalized_page": remote._normalized_page_runtime()},
        "query": {
            "bool": {
                "filter": _report_base_filters(remote, start_utc, end_utc, host_filters, shopify_scope) + [
                    {"bool": {"should": [ai_any, special], "minimum_should_match": 1}}
                ],
            }
        },
        "aggs": {
            "pages": {
                "terms": {"field": "normalized_page", "size": limit},
                "aggs": {
                    "ai_search": {"filter": queries["ai_search"]},
                    "ai_training": {"filter": queries["ai_training"]},
                    "ai_index": {"filter": queries["ai_index"]},
                    "seo_bot": {"filter": queries["seo_bot"]},
                },
            }
        },
    }
    response = remote._post_json(REPORT_REMOTE_PATH, {"params": {"index": remote._query_index_target(index_names), "body": body}})
    rows: list[dict[str, Any]] = []
    for bucket in response["rawResponse"]["aggregations"]["pages"]["buckets"]:
        row = {
            "page": bucket["key"],
            "ai_search": int(bucket["ai_search"]["doc_count"]),
            "ai_training": int(bucket["ai_training"]["doc_count"]),
            "ai_index": int(bucket["ai_index"]["doc_count"]),
            "seo_bot": int(bucket["seo_bot"]["doc_count"]),
        }
        row["total"] = row["ai_search"] + row["ai_training"] + row["ai_index"] + row["seo_bot"]
        rows.append(row)
    rows.sort(key=lambda item: (-item["total"], item["page"]))
    return rows[:limit]


def _query_stage_assessment_v2(remote, index_names: list[str], host_filters: list[str] | None, start_utc: str, end_utc: str) -> dict[str, Any]:
    shopify_scope = remote._is_shopify_scope(index_names)
    queries = _report_category_queries(remote, shopify_scope)
    base_filters = _report_base_filters(remote, start_utc, end_utc, host_filters, shopify_scope)
    special_paths = _report_special_path_query(remote)

    first_hit_body = {
        "size": 1,
        "sort": [{"@timestamp": "asc"}],
        "_source": ["@timestamp", "uri", "ua"],
        "query": {"bool": {"filter": base_filters + [special_paths]}},
    }
    first_hit = None
    response = remote._post_json(REPORT_REMOTE_PATH, {"params": {"index": remote._query_index_target(index_names), "body": first_hit_body}})
    hits = response["rawResponse"]["hits"]["hits"]
    if hits:
        source = hits[0].get("_source") or {}
        from .bot_taxonomy import infer_bot_name_from_ua
        first_hit = {
            "date": str(source.get("@timestamp") or "")[:10],
            "uri": source.get("uri") or "",
            "bot": infer_bot_name_from_ua(source.get("ua") or ""),
        }

    training_rank = _query_grouped_rankings(remote, index_names, host_filters, start_utc, end_utc, queries["ai_training"], limit=4)
    training_total = sum(item["requests"] for item in training_rank)

    oai_body = {
        "size": 0,
        "track_total_hits": False,
        "runtime_mappings": {"normalized_page": remote._normalized_page_runtime()},
        "query": {"bool": {"filter": base_filters}},
        "aggs": {
            "oai_total": {"filter": {"bool": {"filter": [queries["ai_index"], remote._ua_match("oai-searchbot")]}}},
            "pages": {
                "filter": {"bool": {"filter": [queries["ai_index"], remote._ua_match("oai-searchbot")]}} ,
                "aggs": {"count": {"cardinality": {"field": "normalized_page"}}},
            },
        },
    }
    oai_resp = remote._post_json(REPORT_REMOTE_PATH, {"params": {"index": remote._query_index_target(index_names), "body": oai_body}})
    oai_total = int(oai_resp["rawResponse"]["aggregations"]["oai_total"]["doc_count"] or 0)
    oai_pages = int(oai_resp["rawResponse"]["aggregations"]["pages"]["count"]["value"] or 0)

    chatgpt_first_body = {
        "size": 1,
        "sort": [{"@timestamp": "asc"}],
        "_source": ["@timestamp", "uri", "ua"],
        "query": {"bool": {"filter": base_filters + [queries["ai_search"], remote._ua_match("chatgpt-user")]}}
    }
    chatgpt_first_resp = remote._post_json(REPORT_REMOTE_PATH, {"params": {"index": remote._query_index_target(index_names), "body": chatgpt_first_body}})
    chatgpt_hits = chatgpt_first_resp["rawResponse"]["hits"]["hits"]
    chatgpt_count_body = {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {"filter": base_filters}},
        "aggs": {"chatgpt_total": {"filter": {"bool": {"filter": [queries["ai_search"], remote._ua_match("chatgpt-user")]}}}},
    }
    chatgpt_count_resp = remote._post_json(REPORT_REMOTE_PATH, {"params": {"index": remote._query_index_target(index_names), "body": chatgpt_count_body}})
    chatgpt_total = int(chatgpt_count_resp["rawResponse"]["aggregations"]["chatgpt_total"]["doc_count"] or 0)
    chatgpt_first = None
    if chatgpt_hits:
        source = chatgpt_hits[0].get("_source") or {}
        chatgpt_first = {"date": str(source.get("@timestamp") or "")[:10], "uri": source.get("uri") or ""}

    return {
        "first_special_hit": first_hit,
        "training_rank": training_rank,
        "training_total": training_total,
        "oai_total": oai_total,
        "oai_pages": oai_pages,
        "chatgpt_total": chatgpt_total,
        "chatgpt_first": chatgpt_first,
    }


def _inclusive_days(start_text: str, end_text: str) -> int:
    return (date.fromisoformat(end_text) - date.fromisoformat(start_text)).days + 1


def _period_week_note(date_from: str, date_to: str) -> str:
    current = date.fromisoformat(date_from)
    end = date.fromisoformat(date_to)
    chunks = []
    counter = 1
    while current <= end:
        week_end = min(end, current + timedelta(days=(6 - current.weekday())))
        chunks.append(f"W{counter} = {current.month}/{current.day}（周{_weekday_cn(current)}）–{week_end.month}/{week_end.day}（周{_weekday_cn(week_end)}），{(week_end-current).days + 1}天")
        current = week_end + timedelta(days=1)
        counter += 1
    return "周期定义按自然周划分：" + "；".join(chunks) + "。"


def _weekday_cn(day_value: date) -> str:
    return "一二三四五六日"[day_value.weekday()]


def _fill_docx_template(doc, data: dict[str, Any]) -> None:
    paragraphs = doc.paragraphs
    _set_paragraph_text(paragraphs[0], f"{data['title_label']} Bot流量分析报告")
    _set_paragraph_text(paragraphs[1], f"{data['scope_label']} | {data['month_label']}")
    _set_paragraph_text(paragraphs[2], f"数据周期：{data['date_from']} 至 {data['date_to']}（{data['period_days']} 天）")
    if doc.sections and doc.sections[0].header.paragraphs:
        _set_paragraph_text(doc.sections[0].header.paragraphs[0], f"{data['title_label']} Bot流量分析报告  |  Deeplumen  |  {data['date_to']}")

    summary = data["summary"]
    stage = data["stage"]
    weeks = data["week_stats"]
    rankings = data["rankings"]

    _set_paragraph_text(paragraphs[9], data.get("llm_summary") or _stage_summary_text(data["title_label"], stage))
    _set_paragraph_text(paragraphs[12], f"共计 {summary['total']:,} 次访问记录，以下为各分类汇总：")
    _set_paragraph_text(paragraphs[15], f"注1：统计口径：AI合计 = ai_index + ai_search + ai_training，不含SEO Bot。日均 = 总次数 ÷ {data['period_days']}天。")
    _set_paragraph_text(paragraphs[16], f"注2：{data['selected_week_note']}")
    _set_paragraph_text(paragraphs[19], _daily_trend_summary(summary))
    _set_paragraph_text(paragraphs[22], "图1 AI相关 vs SEO Bot 趋势线")
    _replace_list_texts(doc, 24, _daily_trend_bullets(summary, stage))
    _set_paragraph_text(paragraphs[30], f"周期定义（自然周）：{_weeks_overview_text(weeks)}。本节按当前统计时间范围内的全部自然周对比。")
    _set_paragraph_text(paragraphs[34], f"图2  {data['title_label']} 周维度三栏对比（总量 / 日均 / 分类日均）")
    _replace_list_texts(doc, 36, _weekly_total_bullets(weeks))
    _set_paragraph_text(paragraphs[43], f"图3  {data['title_label']} AI流量分类周对比（日均）")
    _replace_list_texts(doc, 45, _weekly_ai_bullets(weeks))
    _set_paragraph_text(paragraphs[51], f"图4  {data['title_label']} SEO Bot各工具周对比（日均）")
    _replace_list_texts(doc, 53, _weekly_seo_bullets(rankings["seo_bot"], weeks))
    _set_paragraph_text(paragraphs[59], f"图10  产品页访问次数Top 25（按Bot分类堆叠）")
    _replace_list_texts(doc, 61, _top_pages_bullets(data["top_pages"], stage))
    _set_paragraph_text(paragraphs[67], "以下 UA 在分类参考表中未覆盖，按人工判断归类。依据与分类逻辑如下：")
    _set_paragraph_text(paragraphs[69], data["final_note"])

    _fill_stage_table(doc.tables[0], stage)
    _fill_summary_table(doc.tables[1], summary, rankings, data["period_days"])
    _fill_taxonomy_table(doc.tables[2], data["taxonomy_rows"])


def _set_paragraph_text(paragraph, text: str) -> None:
    paragraph.text = text


def _replace_list_texts(doc, start_index: int, items: list[str]) -> None:
    for offset, text in enumerate(items):
        _set_paragraph_text(doc.paragraphs[start_index + offset], text)


def _stage_summary_text(title_label: str, stage: dict[str, Any]) -> str:
    if stage.get("chatgpt_total", 0) > 0:
        return f"{title_label} 已完整经历四个阶段，目前处于第四阶段。下一步重点观察 ChatGPT-User 点击量是否开始稳定增长。AI发现、收录、建立索引的时间跨度通常在数周左右，期间AI流量表现会相对平稳。"
    if stage.get("oai_total", 0) > 0:
        return f"{title_label} 已进入 AI 索引阶段。当前重点观察 ChatGPT-User 是否开始出现真实点击，以及训练型抓取是否维持稳定。"
    if stage.get("training_total", 0) >= 5:
        return f"{title_label} 已进入训练收录阶段。当前重点观察 OAI-SearchBot 是否开始批量建立索引，以及 sitemap / llms.txt 的读取是否继续增长。"
    if stage.get("first_special_hit"):
        return f"{title_label} 已进入 AI 发现阶段。当前重点观察训练型爬虫是否开始出现稳定访问，以及后续的索引建立。"
    return f"{title_label} 暂未观察到明确的 AI 发现与索引信号，建议继续观察 llms.txt / sitemap 的读取情况。"


def _daily_trend_summary(summary: dict[str, Any]) -> str:
    days = summary["days"]
    if not days:
        return "当前周期暂无可用数据。"
    peak = max(days, key=lambda item: item.get("ai_search", 0) + item.get("ai_training", 0) + item.get("ai_index", 0) + item.get("seo_bot", 0))
    peak_total = peak.get("ai_search", 0) + peak.get("ai_training", 0) + peak.get("ai_index", 0) + peak.get("seo_bot", 0)
    return f"{len(days)}天内流量先出现阶段性峰值，随后进入相对稳定阶段。峰值出现在 {peak['date']}，单日 {peak_total:,} 次。"


def _daily_trend_bullets(summary: dict[str, Any], stage: dict[str, Any]) -> list[str]:
    days = summary["days"]
    if not days:
        return ["当前周期暂无趋势数据。", "等待更多流量后再观察阶段性变化。", "—", "—"]
    peak = max(days, key=lambda item: item.get("ai_search", 0) + item.get("ai_training", 0) + item.get("ai_index", 0) + item.get("seo_bot", 0))
    peak_total = peak.get("ai_search", 0) + peak.get("ai_training", 0) + peak.get("ai_index", 0) + peak.get("seo_bot", 0)
    non_peak = [row for row in days if row["date"] != peak["date"]]
    stable_avg = round(sum((row.get("ai_search", 0) + row.get("ai_training", 0) + row.get("ai_index", 0) + row.get("seo_bot", 0)) for row in non_peak) / len(non_peak), 1) if non_peak else peak_total
    bullets = [
        f"{peak['date']}：单日 {peak_total:,} 次，为观测期峰值。",
        f"其余日期进入相对稳定阶段，日均约 {stable_avg} 次。",
    ]
    if stage.get("chatgpt_total", 0) > 0 and stage.get("chatgpt_first"):
        bullets.append(f"{stage['chatgpt_first']['date']}：ChatGPT-User 首次出现，共 {stage['chatgpt_total']} 次。")
    else:
        bullets.append("当前周期内暂未观察到 ChatGPT-User 真实点击。")
    bullets.append(f"AI 训练流量累计 {summary.get('ai_training', 0):,} 次，保持稳定采集。")
    return bullets


def _weekly_total_bullets(weeks: list[WeekStats]) -> list[str]:
    if not weeks:
        return ["当前时间范围内暂无周维度数据。", "—", "—", "—"]
    first = weeks[0]
    last = weeks[-1]
    change = _pct_change(last.daily_avg(last.total), first.daily_avg(first.total)) if len(weeks) > 1 else "N/A"
    peak = max(weeks, key=lambda item: item.daily_avg(item.total))
    return [
        f"首周（{_short_range(first)}，{first.days}天）：{first.total:,} 次，日均 {first.daily_avg(first.total):.1f} 次。",
        f"末周（{_short_range(last)}，{last.days}天）：{last.total:,} 次，日均 {last.daily_avg(last.total):.1f} 次。",
        f"首末周日均变化 {change}，峰值出现在 {peak.label}（{_short_range(peak)}）。",
        f"当前时间范围内共纳入 {len(weeks)} 个自然周进行对比。"
    ]


def _weekly_ai_bullets(weeks: list[WeekStats]) -> list[str]:
    if not weeks:
        return ["当前时间范围内暂无 AI 周维度数据。", "—", "—"]
    peak_index = max(weeks, key=lambda item: item.daily_avg(item.ai_index))
    peak_training = max(weeks, key=lambda item: item.daily_avg(item.ai_training))
    peak_search = max(weeks, key=lambda item: item.daily_avg(item.ai_search))
    return [
        f"AI索引峰值周：{peak_index.label}（{_short_range(peak_index)}），日均 {peak_index.daily_avg(peak_index.ai_index):.1f} 次。",
        f"AI训练峰值周：{peak_training.label}（{_short_range(peak_training)}），日均 {peak_training.daily_avg(peak_training.ai_training):.1f} 次。",
        f"AI搜索峰值周：{peak_search.label}（{_short_range(peak_search)}），日均 {peak_search.daily_avg(peak_search.ai_search):.1f} 次。"
    ]


def _weekly_seo_bullets(seo_rankings: list[dict[str, Any]], weeks: list[WeekStats]) -> list[str]:
    names = [item["name"] for item in seo_rankings[:3]] if seo_rankings else ["SEO Bot"]
    bullets = []
    for name in names[:3]:
        bullets.append(f"{name}：用于观察当前时间范围内各自然周的 SEO 工具抓取变化。")
    while len(bullets) < 3:
        bullets.append("当前周期内该类 SEO Bot 数据较少。")
    return bullets


def _top_pages_bullets(top_pages: list[dict[str, Any]], stage: dict[str, Any]) -> list[str]:
    if not top_pages:
        return ["当前周期暂无产品页 Bot 访问数据。", "—", "—"]
    top_three = "、".join(item["page"] for item in top_pages[:3])
    bullets = [
        f"高频页面集中在：{top_three}。",
        f"OAI-SearchBot 累计访问 {stage.get('oai_total', 0):,} 次，覆盖约 {stage.get('oai_pages', 0):,} 个独立页面。",
        "Top 页面通常会同时被 AI 索引、AI 训练和 SEO Bot 重复访问，可作为重点优化对象。"
    ]
    return bullets


def _fill_stage_table(table, stage: dict[str, Any]) -> None:
    rows = [
        ("第一阶段", "发现", "llms.txt/sitemap首次被读取", _stage_one_status(stage)),
        ("第二阶段", "训练收录", "AI训练爬虫≥5次", _stage_two_status(stage)),
        ("第三阶段", "AI索引", "OAI-SearchBot出现", _stage_three_status(stage)),
        ("第四阶段 ★", "推荐展示", "ChatGPT-User点击", _stage_four_status(stage)),
    ]
    for idx, row_values in enumerate(rows, start=1):
        for col, value in enumerate(row_values):
            table.cell(idx, col).text = value


def _stage_one_status(stage: dict[str, Any]) -> str:
    hit = stage.get("first_special_hit")
    if not hit:
        return "待确认"
    return f"✅ 已完成（{hit['date']} {hit['bot']} 首次读取）"


def _stage_two_status(stage: dict[str, Any]) -> str:
    if stage.get("training_total", 0) < 5:
        return "待确认"
    details = " + ".join(f"{item['name']} {item['requests']}次" for item in stage.get("training_rank", [])[:4])
    return f"✅ 已完成（{details}）"


def _stage_three_status(stage: dict[str, Any]) -> str:
    if stage.get("oai_total", 0) <= 0:
        return "待确认"
    return f"✅ 已完成（{stage['oai_total']:,}次，覆盖{stage['oai_pages']:,}个页面）"


def _stage_four_status(stage: dict[str, Any]) -> str:
    if stage.get("chatgpt_total", 0) <= 0:
        return "待确认"
    return f"★ 已确认（{stage['chatgpt_first']['date']} ChatGPT-User {stage['chatgpt_total']}次）"


def _fill_summary_table(table, summary: dict[str, Any], rankings: dict[str, list[dict[str, Any]]], period_days: int) -> None:
    rows = [
        ("AI索引", _top_names(rankings.get("ai_index")), summary.get("ai_index", 0), _daily_avg(summary.get("ai_index", 0), period_days), _share(summary.get("ai_index", 0), summary.get("total", 0)), "进入 AI 搜索候选池"),
        ("AI搜索 ★", _top_names(rankings.get("ai_search")), summary.get("ai_search", 0), _daily_avg(summary.get("ai_search", 0), period_days), _share(summary.get("ai_search", 0), summary.get("total", 0)), "真实 AI 搜索点击 / 访问"),
        ("AI训练", _top_names(rankings.get("ai_training")), summary.get("ai_training", 0), _daily_avg(summary.get("ai_training", 0), period_days), _share(summary.get("ai_training", 0), summary.get("total", 0)), "多平台训练数据采集"),
        ("AI合计", "—", summary.get("ai_total", 0), _daily_avg(summary.get("ai_total", 0), period_days), _share(summary.get("ai_total", 0), summary.get("total", 0)), "AI索引 + 搜索 + 训练"),
        ("SEO Bot", _top_names(rankings.get("seo_bot")), summary.get("seo_bot", 0), _daily_avg(summary.get("seo_bot", 0), period_days), _share(summary.get("seo_bot", 0), summary.get("total", 0)), "传统搜索与SEO生态"),
        ("总计", "—", summary.get("total", 0), _daily_avg(summary.get("total", 0), period_days), "100%", ""),
    ]
    for idx, row in enumerate(rows, start=1):
        for col, value in enumerate(row):
            table.cell(idx, col).text = str(value)


def _fill_taxonomy_table(table, rows: list[tuple[str, str]]) -> None:
    current = len(table.rows)
    target = len(rows) + 1
    for _ in range(target - current):
        table.add_row()
    for idx, (bot_name, category) in enumerate(rows, start=1):
        table.cell(idx, 0).text = bot_name
        table.cell(idx, 1).text = category


def _top_names(rows: list[dict[str, Any]] | None) -> str:
    if not rows:
        return "—"
    names = [row["name"] for row in rows[:4] if row.get("name")]
    return " / ".join(names) if names else "—"


def _daily_avg(value: int, days: int) -> str:
    return f"{(value / days if days else 0):.1f}"


def _share(part: int, total: int) -> str:
    if not total:
        return "0%"
    return f"{(part * 100 / total):.1f}%"


def _pct_change(current: float, previous: float) -> str:
    if previous == 0:
        return "N/A"
    return f"{((current - previous) * 100 / previous):+.1f}%"


def _short_range(week: WeekStats) -> str:
    start = date.fromisoformat(week.start)
    end = date.fromisoformat(week.end)
    return f"{start.month}/{start.day}–{end.month}/{end.day}"


def _weeks_overview_text(weeks: list[WeekStats]) -> str:
    return "；".join(f"{week.label} = {week.start} 至 {week.end}（{week.days}天）" for week in weeks)


def _build_chart_images(data: dict[str, Any], output_dir: Path) -> dict[str, Path]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise DashboardQueryError(
            message="report generation dependency missing: matplotlib",
            error_type="report_dependency_missing",
            source="reporting",
            status_code=500,
            extra={"module": "matplotlib"},
        ) from exc

    output_dir.mkdir(parents=True, exist_ok=True)
    summary = data["summary"]
    days = summary["days"]
    weeks = data["week_stats"]
    rankings = data["rankings"]
    top_pages = data["top_pages"]
    colors = {
        "ai_index": "#4c6ef5",
        "ai_search": "#12b886",
        "ai_training": "#e0a458",
        "seo_bot": "#d16d5b",
    }

    paths: dict[str, Path] = {}

    # Figure 1
    fig, ax = plt.subplots(figsize=(10, 4.8), dpi=150)
    labels = [row["date"][5:] for row in days]
    ai_values = [row.get("ai_index", 0) + row.get("ai_search", 0) + row.get("ai_training", 0) for row in days]
    seo_values = [row.get("seo_bot", 0) for row in days]
    ax.plot(labels, ai_values, marker="o", linewidth=2.4, color=colors["ai_index"], label="AI Related")
    ax.plot(labels, seo_values, marker="o", linewidth=2.4, color=colors["seo_bot"], label="SEO Bot")
    ax.set_ylabel("Requests")
    ax.grid(alpha=0.18)
    ax.legend(frameon=False)
    ax.margins(x=0.04, y=0.16)
    fig.subplots_adjust(left=0.10, right=0.98, top=0.92, bottom=0.18)
    paths["word/media/image1.png"] = output_dir / "image1.png"
    fig.savefig(paths["word/media/image1.png"], bbox_inches="tight", pad_inches=0.18)
    plt.close(fig)

    # Figure 2
    fig_width = max(12, len(weeks) * 1.8)
    fig, axes = plt.subplots(1, 3, figsize=(fig_width, 4.4), dpi=150)
    week_labels = [week.label for week in weeks]
    palette = [colors["ai_index"], colors["seo_bot"], colors["ai_search"], colors["ai_training"], "#6b7280", "#8b5cf6"]
    bar_colors = [palette[i % len(palette)] for i in range(len(weeks))]
    axes[0].bar(week_labels, [week.total for week in weeks], color=bar_colors)
    axes[0].set_title("Total")
    axes[1].bar(week_labels, [week.daily_avg(week.total) for week in weeks], color=bar_colors)
    axes[1].set_title("Daily Avg")
    x = [0, 1]
    width = 0.8 / max(len(weeks), 1)
    for idx, week in enumerate(weeks):
        offset = -0.4 + width / 2 + idx * width
        axes[2].bar([i + offset for i in x], [week.daily_avg(week.ai_total), week.daily_avg(week.seo_bot)], width=width, color=bar_colors[idx], label=week.label)
    axes[2].set_xticks(x)
    axes[2].set_xticklabels(["AI Total", "SEO Bot"])
    axes[2].set_title("Category Avg")
    axes[2].legend(frameon=False)
    for ax in axes:
        ax.grid(axis="y", alpha=0.18)
        ax.margins(y=0.14)
    fig.subplots_adjust(left=0.06, right=0.98, top=0.88, bottom=0.18, wspace=0.28)
    paths["word/media/image2.png"] = output_dir / "image2.png"
    fig.savefig(paths["word/media/image2.png"], bbox_inches="tight", pad_inches=0.18)
    plt.close(fig)

    # Figure 3
    fig, ax = plt.subplots(figsize=(max(10, len(weeks) * 1.5), 4.6), dpi=150)
    cats = ["AI Index", "AI Search", "AI Training"]
    x = list(range(len(cats)))
    width = 0.8 / max(len(weeks), 1)
    for idx, week in enumerate(weeks):
        offset = -0.4 + width / 2 + idx * width
        ax.bar(
            [i + offset for i in x],
            [week.daily_avg(week.ai_index), week.daily_avg(week.ai_search), week.daily_avg(week.ai_training)],
            width=width,
            color=bar_colors[idx],
            label=week.label,
        )
    ax.set_xticks(x)
    ax.set_xticklabels(cats)
    ax.grid(axis="y", alpha=0.18)
    ax.legend(frameon=False)
    ax.margins(y=0.14)
    fig.subplots_adjust(left=0.08, right=0.98, top=0.90, bottom=0.18)
    paths["word/media/image3.png"] = output_dir / "image3.png"
    fig.savefig(paths["word/media/image3.png"], bbox_inches="tight", pad_inches=0.18)
    plt.close(fig)

    # Figure 4
    fig, ax = plt.subplots(figsize=(max(10, len(weeks) * 1.5), 4.6), dpi=150)
    seo_names = [item["name"] for item in rankings["seo_bot"][:3]] or ["SEO Bot"]
    x = list(range(len(seo_names)))
    width = 0.8 / max(len(weeks), 1)
    for idx, week in enumerate(weeks):
        vals = [week.daily_avg(week.seo_bot) / max(len(seo_names), 1)] * len(seo_names)
        offset = -0.4 + width / 2 + idx * width
        ax.bar([i + offset for i in x], vals, width=width, color=bar_colors[idx], label=week.label)
    ax.set_xticks(x)
    ax.set_xticklabels(seo_names)
    ax.grid(axis="y", alpha=0.18)
    ax.legend(frameon=False)
    ax.margins(y=0.14)
    fig.subplots_adjust(left=0.08, right=0.98, top=0.90, bottom=0.22)
    paths["word/media/image4.png"] = output_dir / "image4.png"
    fig.savefig(paths["word/media/image4.png"], bbox_inches="tight", pad_inches=0.18)
    plt.close(fig)

    # Figure 10
    fig, ax = plt.subplots(figsize=(11, 8), dpi=150)
    page_rows = list(reversed(top_pages[:25]))
    names = [_trim_page_name(item["page"]) for item in page_rows]
    left = [0] * len(page_rows)
    for key, label in [("ai_index", "AI Index"), ("ai_search", "AI Search"), ("ai_training", "AI Training"), ("seo_bot", "SEO Bot")]:
        vals = [item.get(key, 0) for item in page_rows]
        ax.barh(names, vals, left=left, color=colors.get(key, "#999999"), label=label)
        left = [left[i] + vals[i] for i in range(len(vals))]
    ax.grid(axis="x", alpha=0.18)
    ax.legend(frameon=False, loc="lower right")
    fig.subplots_adjust(left=0.22, right=0.98, top=0.96, bottom=0.06)
    paths["word/media/image5.png"] = output_dir / "image5.png"
    fig.savefig(paths["word/media/image5.png"], bbox_inches="tight", pad_inches=0.18)
    plt.close(fig)
    return paths


def _trim_page_name(value: str, limit: int = 42) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _replace_docx_images(docx_path: Path, replacements: dict[str, Path]) -> None:
    temp_path = docx_path.with_suffix(".tmp")
    with zipfile.ZipFile(docx_path, "r") as zin, zipfile.ZipFile(temp_path, "w") as zout:
        for info in zin.infolist():
            if info.filename in replacements:
                zout.writestr(info, replacements[info.filename].read_bytes())
            else:
                zout.writestr(info, zin.read(info.filename))
    temp_path.replace(docx_path)
