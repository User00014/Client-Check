from __future__ import annotations

import base64
import json
import os
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterator
from urllib import request
from urllib.parse import urlparse

from .classification import normalize_page, repo_classify_access


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_csv(name: str, default: list[str]) -> list[str]:
    value = os.getenv(name)
    if value is None:
        return list(default)
    items = [item.strip() for item in value.split(",")]
    return [item for item in items if item] or list(default)


REMOTE_BASE_URL = _env_str("TRAFFIC_REMOTE_BASE_URL", "")
REMOTE_USERNAME = _env_str("TRAFFIC_REMOTE_USERNAME", "")
REMOTE_PASSWORD = _env_str("TRAFFIC_REMOTE_PASSWORD", "")
REMOTE_INDEX = _env_str("TRAFFIC_REMOTE_INDEX", "*nginx-logs-*")
REMOTE_HOST_FILTER = _env_str("TRAFFIC_REMOTE_HOST_FILTER", "www.moseeker.com")
REMOTE_CUSTOMER_DOMAINS = _env_csv("TRAFFIC_REMOTE_CUSTOMER_DOMAINS", ["www.moseeker.com", "www.tec-do.com"])
REMOTE_BATCH_SIZE = _env_int("TRAFFIC_REMOTE_BATCH_SIZE", 5000)
REMOTE_PATH = "/internal/search/es"
REMOTE_TIMEZONE = "Asia/Shanghai"
REMOTE_CUSTOMER_MAP = {
    "moseeker": ["www.moseeker.com", "geo.moseeker.com"],
    "tecdo": ["www.tec-do.com", "tec-do.com"],
}
REMOTE_AI_SEARCH_PLATFORMS = [
    ("ChatGPT-User", ["chatgpt-user"]),
    ("OAI-SearchBot", ["oai-searchbot"]),
    ("ClaudeBot", ["claudebot"]),
    ("claude-web", ["claude-web"]),
    ("GoogleAgent-Mariner", ["googleagent-mariner"]),
    ("Applebot-Extended", ["applebot-extended"]),
    ("PerplexityBot", ["perplexitybot"]),
    ("Perplexity-User", ["perplexity-user"]),
    ("MistralAI-User", ["mistralai-user"]),
    ("meta-externalagent", ["meta-externalagent"]),
    ("cohere-ai", ["cohere-ai"]),
    ("YouBot", ["youbot"]),
    ("DuckAssistBot", ["duckassistbot"]),
    ("Moonshot", ["moonshot"]),
]
REMOTE_AI_TRAINING_PLATFORMS = [
    ("GPTBot", ["gptbot"]),
    ("anthropic-ai", ["anthropic-ai"]),
    ("Google-Extended", ["google-extended"]),
    ("Amazonbot", ["amazonbot"]),
    ("CCBot", ["ccbot"]),
    ("Diffbot", ["diffbot"]),
    ("AI2Bot", ["ai2bot"]),
]
REMOTE_AI_INDEX_PLATFORMS = [
    ("GoogleOther", ["googleother"]),
    ("Bytespider", ["bytespider"]),
    ("ToutiaoSpider", ["toutiaospider"]),
    ("Baiduspider-render", ["baiduspider-render"]),
    ("Qwen", ["qwen"]),
    ("Alibaba", ["alibaba"]),
    ("YisouSpider", ["yisouspider"]),
    ("360Spider", ["360spider"]),
    ("Baiduspider-AI", ["baiduspider", "ai"]),
]


@dataclass
class RemoteSearchConfig:
    base_url: str = REMOTE_BASE_URL
    username: str = REMOTE_USERNAME
    password: str = REMOTE_PASSWORD
    index: str = REMOTE_INDEX
    host_filter: str = REMOTE_HOST_FILTER
    customer_domains: list[str] | None = None
    batch_size: int = REMOTE_BATCH_SIZE


class KibanaRemoteLogSource:
    def __init__(self, config: RemoteSearchConfig | None = None) -> None:
        self.config = config or RemoteSearchConfig()
        if self.config.customer_domains is None:
            self.config.customer_domains = list(REMOTE_CUSTOMER_DOMAINS)

    def is_configured(self) -> bool:
        return bool(self.config.base_url and self.config.username and self.config.password)

    def source_ref_label(self) -> str:
        if not self.config.base_url:
            return "remote_kibana"
        parsed = urlparse(self.config.base_url)
        return parsed.netloc or parsed.path or "remote_kibana"

    def iter_logs(self, since: str | None = None) -> Iterator[dict[str, Any]]:
        self._ensure_configured()
        search_after: list[Any] | None = None
        while True:
            payload = {
                "params": {
                    "index": self.config.index,
                    "body": self._search_body(since=since, search_after=search_after),
                }
            }
            response = self._post_json(REMOTE_PATH, payload)
            hits = response.get("rawResponse", {}).get("hits", {}).get("hits", [])
            if not hits:
                break
            for hit in hits:
                source = hit.get("_source") or {}
                source["_index"] = hit.get("_index", "")
                source["_id"] = hit.get("_id", "")
                source["_sort"] = hit.get("sort", [])
                yield source
            search_after = hits[-1].get("sort")
            if not search_after:
                break

    def estimate_since(self, latest_request_time: str | None) -> str | None:
        if not latest_request_time:
            return None
        dt = datetime.fromisoformat(latest_request_time)
        return (dt - timedelta(days=2)).isoformat()

    def _search_body(self, since: str | None, search_after: list[Any] | None) -> dict[str, Any]:
        filters: list[dict[str, Any]] = [self._scope_query(self.config.customer_domains or [self.config.host_filter])]
        if since:
            filters.append({"range": {"@timestamp": {"gte": since}}})
        body: dict[str, Any] = {
            "size": self.config.batch_size,
            "sort": [{"@timestamp": "asc"}, {"_seq_no": "asc"}],
            "_source": [
                "@timestamp",
                "ts",
                "remote_addr",
                "host",
                "method",
                "uri",
                "status",
                "bytes",
                "referer",
                "ua",
                "args",
                "service_name",
                "log_type",
                "client_name",
                "log_source",
            ],
            "query": {"bool": {"filter": filters}},
        }
        if search_after:
            body["search_after"] = search_after
        return body

    def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._ensure_configured()
        auth_text = f"{self.config.username}:{self.config.password}".encode("utf-8")
        headers = {
            "Authorization": "Basic " + base64.b64encode(auth_text).decode("ascii"),
            "Content-Type": "application/json",
            "kbn-xsrf": "1",
            "kbn-version": "9.3.0",
            "x-elastic-internal-origin": "kibana",
        }
        req = request.Request(
            self.config.base_url.rstrip("/") + path,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        context = ssl.create_default_context()
        with request.urlopen(req, timeout=60, context=context) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _ensure_configured(self) -> None:
        if self.is_configured():
            return
        raise RuntimeError(
            "remote source is not configured; set TRAFFIC_REMOTE_BASE_URL, "
            "TRAFFIC_REMOTE_USERNAME and TRAFFIC_REMOTE_PASSWORD"
        )

    def get_repo_focused_counts(self, host: str, start_utc: str, end_utc: str) -> dict[str, int]:
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {"bool": {"filter": self._base_filters(host, start_utc, end_utc)}},
            "aggs": {"focused": {"filters": {"filters": self._focused_category_filters()}}},
        }
        response = self._post_json(REMOTE_PATH, {"params": {"index": self.config.index, "body": body}})
        buckets = response["rawResponse"]["aggregations"]["focused"]["buckets"]
        return {key: int(value["doc_count"]) for key, value in buckets.items()}

    def get_repo_daily_focused_counts(self, host: str, start_utc: str, end_utc: str, timezone: str = REMOTE_TIMEZONE) -> list[dict[str, Any]]:
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {"bool": {"filter": self._base_filters(host, start_utc, end_utc)}},
            "aggs": {
                "days": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "1d",
                        "time_zone": timezone,
                        "min_doc_count": 0,
                        "extended_bounds": {"min": start_utc, "max": self._end_bound(end_utc)},
                    },
                    "aggs": {"focused": {"filters": {"filters": self._focused_category_filters()}}},
                }
            },
        }
        response = self._post_json(REMOTE_PATH, {"params": {"index": self.config.index, "body": body}})
        rows: list[dict[str, Any]] = []
        for bucket in response["rawResponse"]["aggregations"]["days"]["buckets"]:
            item = {"date": bucket["key_as_string"][:10]}
            item.update({key: int(value["doc_count"]) for key, value in bucket["focused"]["buckets"].items()})
            rows.append(item)
        return rows

    def list_customer_domains(self) -> list[dict[str, Any]]:
        results = []
        for customer, hosts in REMOTE_CUSTOMER_MAP.items():
            body = {
                "size": 0,
                "track_total_hits": False,
                "query": {"bool": {"filter": [self._scope_query(hosts)]}},
            }
            response = self._post_json(REMOTE_PATH, {"params": {"index": self.config.index, "body": body}})
            total = int(response["rawResponse"]["hits"]["total"])
            results.append({"customer": customer, "hosts": hosts, "requests": total})
        return sorted(results, key=lambda x: (-x["requests"], x["customer"]))

    def get_time_bounds(self) -> dict[str, str]:
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {"bool": {"filter": [self._scope_query(self.all_customer_hosts())]}},
            "aggs": {
                "min_ts": {"min": {"field": "@timestamp", "format": "strict_date_optional_time"}},
                "max_ts": {"max": {"field": "@timestamp", "format": "strict_date_optional_time"}},
            },
        }
        response = self._post_json(REMOTE_PATH, {"params": {"index": self.config.index, "body": body}})
        aggs = response["rawResponse"]["aggregations"]
        return {
            "date_from": self._utc_to_local_day(aggs["min_ts"].get("value_as_string", "")),
            "date_to": self._utc_to_local_day(aggs["max_ts"].get("value_as_string", "")),
        }

    def get_live_dashboard_window(
        self,
        hosts: list[str],
        start_utc: str,
        end_utc: str,
        top_bots: int = 10,
        top_pages: int = 10,
        include_rankings: bool = True,
    ) -> dict[str, Any]:
        focused = self._dashboard_category_filters()
        human_referred = self._human_referred_filters()
        ai_any = {"bool": {"should": [focused["ai_search"], focused["ai_training"], focused["ai_index"]], "minimum_should_match": 1}}
        user_any = {"bool": {"should": [focused["user_traditional"], focused["user_ai"], focused["user_platform"], focused["user_direct"]], "minimum_should_match": 1}}
        base_filters = [
            {"range": {"@timestamp": {"gte": start_utc, "lt": end_utc}}},
            self._scope_query(hosts),
        ]
        aggs: dict[str, Any] = {
            "focused": {"filters": {"filters": focused}},
            "human_referred": {"filters": {"filters": human_referred}},
            "days": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "1d",
                    "time_zone": REMOTE_TIMEZONE,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": start_utc, "max": self._end_bound(end_utc)},
                },
                "aggs": {
                    "focused": {"filters": {"filters": focused}},
                    "human_referred": {"filters": {"filters": human_referred}},
                },
            },
        }
        if include_rankings:
            aggs["ai_search_rankings"] = {"filters": {"filters": self._platform_filters(REMOTE_AI_SEARCH_PLATFORMS, focused["ai_search"])}}
            aggs["ai_training_rankings"] = {"filters": {"filters": self._platform_filters(REMOTE_AI_TRAINING_PLATFORMS, focused["ai_training"])}}
            aggs["ai_index_rankings"] = {"filters": {"filters": self._platform_filters(REMOTE_AI_INDEX_PLATFORMS, focused["ai_index"])}}
        body = {
            "size": 0,
            "track_total_hits": False,
            "runtime_mappings": {"normalized_page": self._normalized_page_runtime()},
            "query": {"bool": {"filter": base_filters}},
            "aggs": aggs,
        }
        response = self._post_json(REMOTE_PATH, {"params": {"index": self.config.index, "body": body}})
        raw_aggs = response["rawResponse"]["aggregations"]
        result = {
            "focused": {key: int(item["doc_count"]) for key, item in raw_aggs["focused"]["buckets"].items()},
            "human_referred": {key: int(item["doc_count"]) for key, item in raw_aggs["human_referred"]["buckets"].items()},
            "days": [],
            "ai_category_rankings": {"ai_search": [], "ai_training": [], "ai_index": []},
            "page_ranking": [],
        }
        for bucket in raw_aggs["days"]["buckets"]:
            day = {"date": bucket["key_as_string"][:10]}
            day.update({key: int(item["doc_count"]) for key, item in bucket["focused"]["buckets"].items()})
            day.update({f"referred_{key}": int(item["doc_count"]) for key, item in bucket["human_referred"]["buckets"].items()})
            result["days"].append(day)
        if include_rankings:
            for agg_name, target_key in (
                ("ai_search_rankings", "ai_search"),
                ("ai_training_rankings", "ai_training"),
                ("ai_index_rankings", "ai_index"),
            ):
                buckets = raw_aggs[agg_name]["buckets"]
                rows = [{"platform": key, "requests": int(item["doc_count"])} for key, item in buckets.items() if int(item["doc_count"]) > 0]
                rows.sort(key=lambda item: (-item["requests"], item["platform"]))
                result["ai_category_rankings"][target_key] = rows[: max(top_bots, 1)]
            page_keys = self._top_ai_pages(hosts, start_utc, end_utc, max(top_pages, 1))
            if page_keys:
                result["page_ranking"] = self._page_breakdown(hosts, start_utc, end_utc, page_keys, focused, ai_any, user_any)
        return result

    def get_recent_dashboard_records(self, hosts: list[str], start_utc: str, end_utc: str, limit: int = 8) -> list[dict[str, Any]]:
        focused = self._dashboard_category_filters()
        any_focus = {"bool": {"should": list(focused.values()), "minimum_should_match": 1}}
        body = {
            "size": max(limit, 1),
            "sort": [{"@timestamp": "desc"}],
            "_source": ["@timestamp", "host", "uri", "args", "status", "referer", "ua"],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": start_utc, "lt": end_utc}}},
                        self._scope_query(hosts),
                        any_focus,
                    ]
                }
            },
        }
        response = self._post_json(REMOTE_PATH, {"params": {"index": self.config.index, "body": body}})
        rows = []
        for hit in response["rawResponse"]["hits"]["hits"]:
            source = hit.get("_source") or {}
            classification = repo_classify_access(
                source.get("host"),
                source.get("uri"),
                source.get("args"),
                source.get("status"),
                source.get("referer"),
                source.get("ua"),
            )
            category = classification["category"]
            if category not in {"user_traditional", "user_ai", "user_platform", "user_direct", "ai_search", "ai_training", "ai_index"}:
                continue
            rows.append(
                {
                    "access_time": self._format_access_time(source.get("@timestamp")),
                    "traffic_type": "ai" if category in {"ai_search", "ai_training", "ai_index"} else "user",
                    "traffic_channel": classification["channel"],
                    "webpage": normalize_page(source.get("uri") or "") or "",
                    "access_status": "Success" if int(source.get("status") or 0) < 400 else "Failure",
                }
            )
        return rows[: max(limit, 1)]

    def all_customer_hosts(self) -> list[str]:
        hosts: list[str] = []
        seen = set()
        for items in REMOTE_CUSTOMER_MAP.values():
            for item in items:
                for host in self._merge_subdomains(item):
                    if host and host not in seen:
                        seen.add(host)
                        hosts.append(host)
        return hosts

    def resolve_customer(self, customer: str | None) -> dict[str, Any] | None:
        raw = (customer or "").strip().lower()
        if not raw or raw == "all":
            return None
        for key, hosts in REMOTE_CUSTOMER_MAP.items():
            merged_hosts: list[str] = []
            base_domains: list[str] = []
            for host in hosts:
                merged_hosts.extend(self._merge_subdomains(host))
                base = self._extract_base_domain(self._normalize_domain(host))
                if base:
                    base_domains.append(base)
            merged_hosts = sorted({item for item in merged_hosts if item})
            base_domains = sorted({item for item in base_domains if item})
            aliases = {key, *merged_hosts, *base_domains}
            if raw in aliases:
                return {
                    "customer": key,
                    "hosts": merged_hosts,
                    "base_domains": base_domains,
                }
        normalized = self._normalize_domain(raw)
        base = self._extract_base_domain(normalized)
        return {
            "customer": raw,
            "hosts": self._merge_subdomains(normalized),
            "base_domains": [base] if base else [],
        }

    def _end_bound(self, end_utc: str) -> str:
        dt = datetime.fromisoformat(end_utc.replace("Z", "+00:00"))
        return (dt - timedelta(microseconds=1)).isoformat().replace("+00:00", "Z")

    def _base_filters(self, host: str, start_utc: str, end_utc: str) -> list[dict[str, Any]]:
        return [
            {"range": {"@timestamp": {"gte": start_utc, "lt": end_utc}}},
            self._scope_query([host]),
        ]

    def _scope_query(self, domains: list[str]) -> dict[str, Any]:
        hosts: list[str] = []
        seen = set()
        for domain in domains:
            for item in self._merge_subdomains(domain):
                if item and item not in seen:
                    seen.add(item)
                    hosts.append(item)
        return {"bool": {"should": [{"terms": {"host": hosts}}], "minimum_should_match": 1}}

    def _merge_subdomains(self, domain: str) -> list[str]:
        host = self._normalize_domain(domain)
        base = self._extract_base_domain(host)
        candidates = [host, base, f"www.{base}", f"mmm.{base}", f"geo.{base}"]
        seen = set()
        result = []
        for item in candidates:
            if item and item not in seen:
                seen.add(item)
                result.append(item)
        return result

    def _normalize_domain(self, domain: str) -> str:
        raw = (domain or "").strip().lower()
        if not raw:
            return ""
        value = raw if "://" in raw else "http://" + raw
        try:
            parsed = urlparse(value)
            host = parsed.hostname or ""
        except Exception:
            host = raw
        if "/" in host:
            host = host.split("/", 1)[0]
        return host.split(":", 1)[0]

    def _extract_base_domain(self, domain: str) -> str:
        for prefix in ("www.", "mmm.", "geo."):
            if domain.startswith(prefix):
                return domain[len(prefix):]
        return domain

    def _focused_category_filters(self) -> dict[str, Any]:
        return self._dashboard_category_filters()

    def _dashboard_category_filters(self) -> dict[str, Any]:
        ai_bot = self._ai_bot_query()
        seo_bot = self._seo_bot_query()
        static_q = self._static_resource_query()
        mirror_non_302 = self._mirror_non_302_query()
        probe_q = self._suspicious_probe_query()
        user_base_must_not = [ai_bot, seo_bot, static_q, mirror_non_302, probe_q]
        ai_base_must_not = [static_q, mirror_non_302, probe_q]
        user_ai_query = {"bool": {"should": self._user_ai_should(), "minimum_should_match": 1}}
        user_traditional_query = {"bool": {"should": self._user_traditional_should(), "minimum_should_match": 1}}
        user_platform_query = {"bool": {"should": self._user_platform_should(), "minimum_should_match": 1}}
        return {
            "user_traditional": {
                "bool": {
                    "must_not": user_base_must_not + [user_ai_query],
                    "should": self._user_traditional_should(),
                    "minimum_should_match": 1,
                }
            },
            "user_ai": {
                "bool": {
                    "must_not": user_base_must_not,
                    "should": self._user_ai_should(),
                    "minimum_should_match": 1,
                }
            },
            "user_platform": {
                "bool": {
                    "must_not": user_base_must_not + [user_ai_query, user_traditional_query],
                    "should": self._user_platform_should(),
                    "minimum_should_match": 1,
                }
            },
            "user_direct": {
                "bool": {
                    "must_not": user_base_must_not + [user_ai_query, user_traditional_query, user_platform_query],
                }
            },
            "ai_search": {"bool": {"must": [self._ai_search_query()], "must_not": ai_base_must_not}},
            "ai_training": {"bool": {"must": [self._ai_training_query()], "must_not": ai_base_must_not}},
            "ai_index": {"bool": {"must": [self._ai_index_query()], "must_not": ai_base_must_not}},
        }

    def _human_referred_filters(self) -> dict[str, Any]:
        return {
            "total": {"bool": {"should": self._user_ai_should(), "minimum_should_match": 1, "must_not": [self._ai_bot_query(), self._seo_bot_query(), self._static_resource_query(), self._mirror_non_302_query(), self._suspicious_probe_query()]}},
            "chatgpt": {"bool": {"must_not": [self._ai_bot_query(), self._seo_bot_query(), self._static_resource_query(), self._mirror_non_302_query(), self._suspicious_probe_query()], "should": [self._chatgpt_utm_query()], "minimum_should_match": 1}},
            "perplexity": {"bool": {"must_not": [self._ai_bot_query(), self._seo_bot_query(), self._static_resource_query(), self._mirror_non_302_query(), self._suspicious_probe_query()], "should": [self._referer_host_query('perplexity.ai')], "minimum_should_match": 1}},
        }

    def _platform_filters(self, rules: list[tuple[str, list[str]]], category_query: dict[str, Any]) -> dict[str, Any]:
        filters: dict[str, Any] = {}
        for label, tokens in rules:
            if label == "Baiduspider-AI":
                query = {"bool": {"must": [category_query, self._ua_match("baiduspider"), self._ua_match("ai")]}}
            else:
                query = {"bool": {"must": [category_query, self._any_ua_match(tokens)]}}
            filters[label] = query
        return filters

    def _normalized_page_runtime(self) -> dict[str, Any]:
        return {
            "type": "keyword",
            "script": {
                "source": """
                    if (!doc.containsKey('uri.keyword') || doc['uri.keyword'].empty) return;
                    String path = doc['uri.keyword'].value;
                    int q = path.indexOf('?');
                    if (q >= 0) path = path.substring(0, q);
                    if (path.length() == 0) return;
                    if (path.length() > 1 && path.endsWith('/')) path = path.substring(0, path.length() - 1);
                    emit(path);
                """
            },
        }

    def _utc_to_local_day(self, value: str) -> str:
        if not value:
            return ""
        dt = datetime.fromisoformat(value.replace("Z", "+00:00")) + timedelta(hours=8)
        return dt.date().isoformat()

    def _format_access_time(self, value: str | None) -> str:
        if not value:
            return ""
        return (datetime.fromisoformat(str(value).replace("Z", "+00:00")) + timedelta(hours=8)).replace(tzinfo=None).isoformat(sep=" ")

    def _top_ai_pages(self, hosts: list[str], start_utc: str, end_utc: str, limit: int) -> list[str]:
        focused = self._dashboard_category_filters()
        ai_any = {"bool": {"should": [focused["ai_search"], focused["ai_training"], focused["ai_index"]], "minimum_should_match": 1}}
        body = {
            "size": 0,
            "track_total_hits": False,
            "runtime_mappings": {"normalized_page": self._normalized_page_runtime()},
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": start_utc, "lt": end_utc}}},
                        self._scope_query(hosts),
                        ai_any,
                    ]
                }
            },
            "aggs": {"pages": {"terms": {"field": "normalized_page", "size": max(limit, 1)}}},
        }
        response = self._post_json(REMOTE_PATH, {"params": {"index": self.config.index, "body": body}})
        return [bucket["key"] for bucket in response["rawResponse"]["aggregations"]["pages"]["buckets"] if bucket.get("key")]

    def _page_breakdown(
        self,
        hosts: list[str],
        start_utc: str,
        end_utc: str,
        page_keys: list[str],
        focused: dict[str, Any],
        ai_any: dict[str, Any],
        user_any: dict[str, Any],
    ) -> list[dict[str, Any]]:
        body = {
            "size": 0,
            "track_total_hits": False,
            "runtime_mappings": {"normalized_page": self._normalized_page_runtime()},
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": start_utc, "lt": end_utc}}},
                        self._scope_query(hosts),
                        {"terms": {"normalized_page": page_keys}},
                    ]
                }
            },
            "aggs": {
                "pages": {
                    "terms": {"field": "normalized_page", "size": len(page_keys)},
                    "aggs": {
                        "ai_requests": {"filter": ai_any},
                        "user_requests": {"filter": user_any},
                        "user_traditional": {"filter": focused["user_traditional"]},
                        "user_ai": {"filter": focused["user_ai"]},
                        "ai_search": {"filter": focused["ai_search"]},
                        "ai_training": {"filter": focused["ai_training"]},
                        "ai_index": {"filter": focused["ai_index"]},
                    },
                }
            },
        }
        response = self._post_json(REMOTE_PATH, {"params": {"index": self.config.index, "body": body}})
        rows = []
        for bucket in response["rawResponse"]["aggregations"]["pages"]["buckets"]:
            rows.append(
                {
                    "page": bucket["key"],
                    "ai_requests": int(bucket["ai_requests"]["doc_count"]),
                    "user_requests": int(bucket["user_requests"]["doc_count"]),
                    "user_traditional": int(bucket["user_traditional"]["doc_count"]),
                    "user_ai": int(bucket["user_ai"]["doc_count"]),
                    "ai_search": int(bucket["ai_search"]["doc_count"]),
                    "ai_training": int(bucket["ai_training"]["doc_count"]),
                    "ai_index": int(bucket["ai_index"]["doc_count"]),
                }
            )
        rows.sort(key=lambda item: (-item["ai_requests"], item["page"]))
        return rows

    def _user_ai_should(self) -> list[dict[str, Any]]:
        return [self._chatgpt_utm_query(), self._referer_host_query("perplexity.ai"), self._referer_host_query("gemini.google.com")]

    def _user_traditional_should(self) -> list[dict[str, Any]]:
        return [self._referer_host_query("google.com"), self._referer_host_query("bing.com"), self._referer_host_query("baidu.com"), self._referer_host_query("duckduckgo.com")]

    def _user_platform_should(self) -> list[dict[str, Any]]:
        return [self._referer_host_query("admin.shopify.com")]

    def _chatgpt_utm_query(self) -> dict[str, Any]:
        return {
            "bool": {
                "should": [
                    self._keyword_contains("args", "utm_source=chatgpt.com"),
                    self._keyword_contains("uri.keyword", "utm_source=chatgpt.com"),
                ],
                "minimum_should_match": 1,
            }
        }

    def _referer_host_query(self, domain: str) -> dict[str, Any]:
        escaped = domain.replace(".", "\\.")
        pattern = f"([a-zA-Z][a-zA-Z0-9+.\\-]*://)?([^/?#@]*\\.)?{escaped}(:[0-9]+)?([/?#].*)?"
        return {"regexp": {"referer": {"value": pattern, "case_insensitive": True}}}

    def _ai_search_query(self) -> dict[str, Any]:
        return self._any_ua_match(["chatgpt-user", "oai-searchbot", "claudebot", "claude-web", "googleagent-mariner", "applebot-extended", "perplexitybot", "perplexity-user", "mistralai-user", "meta-externalagent", "cohere-ai", "youbot", "duckassistbot", "moonshot"])

    def _ai_training_query(self) -> dict[str, Any]:
        return self._any_ua_match(["gptbot", "anthropic-ai", "google-extended", "amazonbot", "ccbot", "diffbot", "ai2bot"])

    def _ai_index_query(self) -> dict[str, Any]:
        return {
            "bool": {
                "should": [
                    self._any_ua_match(["googleother", "bytespider", "toutiaospider", "baiduspider-render", "qwen", "alibaba", "yisouspider", "360spider"]),
                    {"bool": {"must": [self._ua_match("baiduspider"), self._ua_match("ai")]}}
                ],
                "minimum_should_match": 1,
            }
        }

    def _ai_bot_query(self) -> dict[str, Any]:
        return {
            "bool": {
                "should": [
                    self._ai_search_query(),
                    self._ai_training_query(),
                    self._ai_index_query(),
                    self._any_ua_match(["facebookbot", "imagesiftbot", "omgilibot", "timpibot"]),
                ],
                "minimum_should_match": 1,
            }
        }

    def _seo_bot_query(self) -> dict[str, Any]:
        return {
            "bool": {
                "should": [
                    self._ua_match("googlebot-image"),
                    self._ua_match("googlebot"),
                    self._ua_match("bingbot"),
                    self._ua_match("duckduckbot"),
                    self._ua_match("yandexbot"),
                    self._ua_match("slurp"),
                    self._ua_match("petalbot"),
                    self._ua_match("sogou"),
                    self._ua_match("sosospider"),
                    {
                        "bool": {
                            "must": [self._ua_match("baiduspider")],
                            "must_not": [
                                self._ua_match("baiduspider-render"),
                                {"bool": {"must": [self._ua_match("baiduspider"), self._ua_match("ai")]}}
                            ],
                        }
                    },
                    self._any_keyword_contains("ua.keyword", ["bot", "spider", "crawler", "crawl", "slurp", "scraper", "scan", "fetch"]),
                ],
                "minimum_should_match": 1,
            }
        }

    def _suspicious_probe_query(self) -> dict[str, Any]:
        patterns = ["/.git", "/.aws", "/.env", "/.s3cfg", "/phpinfo.php", "/info.php", "/_debugbar", "/debug", "/debugbar", "/aws-credentials", "/wp-config.php", "/test.php"]
        return {"bool": {"should": [self._keyword_wildcard("uri.keyword", p + "*") for p in patterns], "minimum_should_match": 1}}

    def _mirror_non_302_query(self) -> dict[str, Any]:
        return {
            "bool": {
                "must": [
                    {"bool": {"should": [self._keyword_wildcard("host", "mmm.*"), {"regexp": {"host": {"value": ".*\\.deeplumen\\.io", "case_insensitive": True}}}], "minimum_should_match": 1}}
                ],
                "must_not": [{"term": {"status": 302}}],
            }
        }

    def _static_resource_query(self) -> dict[str, Any]:
        exts = [".css", ".js", ".map", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".webp", ".avif", ".bmp", ".tif", ".tiff", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".mov", ".flv", ".m4a", ".zip", ".tar", ".gz", ".7z", ".rar", ".exe", ".dll", ".iso", ".bin", ".txt", ".xml", ".json", ".webmanifest", ".yaml", ".yml", ".ini", ".conf", ".log", ".toml", ".sql", ".bak", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv"]
        pattern = ".*(" + "|".join(["\\." + ext[1:] for ext in exts]) + ")(\\?.*)?"
        return {"regexp": {"uri.keyword": {"value": pattern, "case_insensitive": True}}}

    def _any_keyword_contains(self, field: str, tokens: list[str]) -> dict[str, Any]:
        return {"bool": {"should": [self._keyword_contains(field, token) for token in tokens], "minimum_should_match": 1}}

    def _keyword_contains(self, field: str, token: str) -> dict[str, Any]:
        return self._keyword_wildcard(field, "*" + token + "*")

    def _keyword_wildcard(self, field: str, pattern: str) -> dict[str, Any]:
        return {"wildcard": {field: {"value": pattern, "case_insensitive": True}}}

    def _ua_match(self, token: str) -> dict[str, Any]:
        return {"match_phrase": {"ua": token}}

    def _any_ua_match(self, tokens: list[str]) -> dict[str, Any]:
        return {"bool": {"should": [self._ua_match(token) for token in tokens], "minimum_should_match": 1}}
