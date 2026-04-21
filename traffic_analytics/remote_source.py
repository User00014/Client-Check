from __future__ import annotations

import base64
import ipaddress
import json
import os
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator
from urllib.error import HTTPError, URLError
from urllib import request
from urllib.parse import urlparse

from .bot_taxonomy import UNCLASSIFIED_BOT_HINT_TOKENS, infer_bot_name_from_ua, infer_bot_signal_from_ua, load_bot_taxonomy
from .index_filtering import normalize_index_option, parse_index_name
from .support import DashboardQueryError

from .classification import normalize_page, repo_classify_access


ROOT_DIR = Path(__file__).resolve().parent.parent
LOCAL_REMOTE_CONFIG_PATH = ROOT_DIR / "remote_source.local.json"


def _load_local_remote_config() -> dict[str, Any]:
    try:
        if LOCAL_REMOTE_CONFIG_PATH.exists():
            return json.loads(LOCAL_REMOTE_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


LOCAL_REMOTE_CONFIG = _load_local_remote_config()


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None:
        local_value = LOCAL_REMOTE_CONFIG.get(name)
        if isinstance(local_value, str):
            local_value = local_value.strip()
            return local_value if local_value else default
        return default
    value = value.strip()
    return value if value else default


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        value = LOCAL_REMOTE_CONFIG.get(name)
        if value is None:
            return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_csv(name: str, default: list[str]) -> list[str]:
    value = os.getenv(name)
    if value is None:
        value = LOCAL_REMOTE_CONFIG.get(name)
        if value is None:
            return list(default)
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()] or list(default)
    items = [item.strip() for item in value.split(",")]
    return [item for item in items if item] or list(default)


REMOTE_BASE_URL = _env_str("TRAFFIC_REMOTE_BASE_URL", "")
REMOTE_USERNAME = _env_str("TRAFFIC_REMOTE_USERNAME", "")
REMOTE_PASSWORD = _env_str("TRAFFIC_REMOTE_PASSWORD", "")
REMOTE_INDEX = _env_str("TRAFFIC_REMOTE_INDEX", "*nginx*")
REMOTE_HOST_FILTER = _env_str("TRAFFIC_REMOTE_HOST_FILTER", "www.moseeker.com")
REMOTE_CUSTOMER_DOMAINS = _env_csv("TRAFFIC_REMOTE_CUSTOMER_DOMAINS", [])
REMOTE_BATCH_SIZE = _env_int("TRAFFIC_REMOTE_BATCH_SIZE", 5000)
REMOTE_PATH = "/internal/search/es"
REMOTE_TIMEZONE = "Asia/Shanghai"
REMOTE_NGINX_INDEX_GLOB = "*nginx*"


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
        filters: list[dict[str, Any]] = []
        if self.config.customer_domains:
            filters.append(self._scope_query(self.config.customer_domains))
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
            "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
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
        try:
            with request.urlopen(req, timeout=60, context=context) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            index_name = str((payload.get("params") or {}).get("index") or "")
            raise DashboardQueryError(
                message=f"remote ES query failed: HTTP {exc.code}",
                error_type="remote_es_http_error",
                source="remote_es",
                status_code=502,
                extra={
                    "path": path,
                    "index": index_name,
                    "response": body[:4000],
                },
            ) from exc
        except URLError as exc:
            index_name = str((payload.get("params") or {}).get("index") or "")
            raise DashboardQueryError(
                message=f"remote ES query failed: {exc.reason}",
                error_type="remote_es_network_error",
                source="remote_es",
                status_code=502,
                extra={
                    "path": path,
                    "index": index_name,
                },
            ) from exc

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

    def list_index_options(self, start_utc: str | None = None, end_utc: str | None = None) -> list[dict[str, Any]]:
        filters: list[dict[str, Any]] = []
        if start_utc and end_utc:
            filters.append({"range": {"@timestamp": {"gte": start_utc, "lt": end_utc}}})
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
            "aggs": {
                "indices": {
                    "terms": {
                        "field": "_index",
                        "size": max(self.config.batch_size, 2000),
                        "order": {"_count": "desc"},
                    }
                }
            },
        }
        response = self._post_json(REMOTE_PATH, {"params": {"index": self._metadata_index_target(), "body": body}})
        buckets = response.get("rawResponse", {}).get("aggregations", {}).get("indices", {}).get("buckets", [])
        rows: list[dict[str, Any]] = []
        for bucket in buckets:
            index_name = str(bucket.get("key") or "").strip()
            if not self._is_supported_index_name(index_name):
                continue
            if self._should_skip_index_name(index_name):
                continue
            row = normalize_index_option(index_name, int(bucket.get("doc_count") or 0))
            if str(row.get("customer_name") or "").strip().lower() in {"test"}:
                continue
            rows.append(row)
        rows.sort(
            key=lambda item: (
                str(item.get("index_date") or ""),
                int(item.get("requests") or 0),
                str(item.get("value") or ""),
            ),
            reverse=True,
        )
        return rows

    def list_customer_domains(self, start_utc: str | None = None, end_utc: str | None = None) -> list[dict[str, Any]]:
        grouped: dict[str, int] = {}
        for row in self.list_index_options(start_utc=start_utc, end_utc=end_utc):
            customer_name = str(row.get("customer_name") or "").strip()
            if not customer_name:
                continue
            grouped[customer_name] = grouped.get(customer_name, 0) + int(row.get("requests") or 0)
        return [
            {"customer": customer_name, "requests": requests}
            for customer_name, requests in sorted(grouped.items(), key=lambda item: (-item[1], item[0]))
        ]

    def list_host_options(
        self,
        index_names: list[str] | None = None,
        start_utc: str | None = None,
        end_utc: str | None = None,
    ) -> list[dict[str, Any]]:
        exact_index_names = self._clean_index_names(index_names)
        filters: list[dict[str, Any]] = []
        if start_utc and end_utc:
            filters.append({"range": {"@timestamp": {"gte": start_utc, "lt": end_utc}}})
        if self._is_shopify_scope(exact_index_names):
            filters.append(self._shopify_path_query())
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
            "aggs": {
                "hosts": {
                    "terms": {
                        "field": "host",
                        "size": max(self.config.batch_size, 1000),
                        "order": {"_count": "desc"},
                    }
                }
            },
        }
        response = self._post_json(
            REMOTE_PATH,
            {"params": {"index": self._query_index_target(exact_index_names), "body": body}},
        )
        buckets = response.get("rawResponse", {}).get("aggregations", {}).get("hosts", {}).get("buckets", [])
        rows: list[dict[str, Any]] = []
        for bucket in buckets:
            host_value = self._clean_host_value(bucket.get("key"))
            if not self._is_displayable_host(host_value):
                continue
            rows.append(
                {
                    "value": host_value,
                    "label": host_value,
                    "requests": int(bucket.get("doc_count") or 0),
                }
            )
        return rows

    def get_time_bounds(self) -> dict[str, str]:
        body = {
            "size": 0,
            "track_total_hits": False,
            "aggs": {
                "min_ts": {"min": {"field": "@timestamp", "format": "strict_date_optional_time"}},
                "max_ts": {"max": {"field": "@timestamp", "format": "strict_date_optional_time"}},
            },
        }
        response = self._post_json(REMOTE_PATH, {"params": {"index": self._metadata_index_target(), "body": body}})
        aggs = response["rawResponse"]["aggregations"]
        return {
            "date_from": self._utc_to_local_day(aggs["min_ts"].get("value_as_string", "")),
            "date_to": self._utc_to_local_day(aggs["max_ts"].get("value_as_string", "")),
        }

    def get_live_dashboard_window(
        self,
        index_names: list[str] | None = None,
        host_filters: list[str] | None = None,
        start_utc: str = "",
        end_utc: str = "",
        top_bots: int = 10,
        top_pages: int = 10,
        include_rankings: bool = True,
    ) -> dict[str, Any]:
        exact_index_names = self._clean_index_names(index_names)
        shopify_scope = self._is_shopify_scope(exact_index_names)
        focused = self._dashboard_category_filters(allow_io_mirror=shopify_scope)
        human_referred = self._human_referred_filters(allow_io_mirror=shopify_scope)
        ai_any = {"bool": {"should": [focused["ai_search"], focused["ai_training"], focused["ai_index"]], "minimum_should_match": 1}}
        user_any = {"bool": {"should": [focused["user_traditional"], focused["user_ai"], focused["user_platform"], focused["user_direct"]], "minimum_should_match": 1}}
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
            aggs["ai_search_rankings"] = {"filters": {"filters": self._platform_filters(self._official_ai_platforms("ai_search"), focused["ai_search"])}}
            aggs["ai_training_rankings"] = {"filters": {"filters": self._platform_filters(self._official_ai_platforms("ai_training"), focused["ai_training"])}}
            aggs["ai_index_rankings"] = {"filters": {"filters": self._platform_filters(self._official_ai_platforms("ai_index"), focused["ai_index"])}}
        body = {
            "size": 0,
            "track_total_hits": False,
            "runtime_mappings": {"normalized_page": self._normalized_page_runtime()},
            "query": {"bool": {"filter": self._dashboard_base_filters(start_utc, end_utc, host_filters, shopify_scope)}},
            "aggs": aggs,
        }
        response = self._post_json(
            REMOTE_PATH,
            {"params": {"index": self._query_index_target(exact_index_names), "body": body}},
        )
        raw_aggs = response["rawResponse"]["aggregations"]
        result = {
            "focused": {key: int(item["doc_count"]) for key, item in raw_aggs["focused"]["buckets"].items()},
            "human_referred": {key: int(item["doc_count"]) for key, item in raw_aggs["human_referred"]["buckets"].items()},
            "days": [],
            "ai_category_rankings": {"ai_search": [], "ai_training": [], "ai_index": []},
            "unknown_bot_rankings": [],
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
            page_keys = self._top_ai_pages(exact_index_names, host_filters, start_utc, end_utc, max(top_pages, 1), shopify_scope)
            if page_keys:
                result["page_ranking"] = self._page_breakdown(
                    exact_index_names,
                    host_filters,
                    start_utc,
                    end_utc,
                    page_keys,
                    focused,
                    ai_any,
                    user_any,
                    shopify_scope,
                )
            result["unknown_bot_rankings"] = self._unknown_bot_rankings(
                exact_index_names,
                host_filters,
                start_utc,
                end_utc,
                max(top_bots, 1),
                shopify_scope,
            )
        return result

    def get_recent_dashboard_records(
        self,
        index_names: list[str] | None = None,
        host_filters: list[str] | None = None,
        start_utc: str = "",
        end_utc: str = "",
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        exact_index_names = self._clean_index_names(index_names)
        shopify_scope = self._is_shopify_scope(exact_index_names)
        focused = self._dashboard_category_filters(allow_io_mirror=shopify_scope)
        any_focus = {"bool": {"should": list(focused.values()), "minimum_should_match": 1}}
        body = {
            "size": max(limit, 1),
            "sort": [{"@timestamp": "desc"}],
            "_source": ["@timestamp", "host", "uri", "args", "status", "referer", "ua"],
            "query": {
                "bool": {
                    "filter": self._dashboard_base_filters(start_utc, end_utc, host_filters, shopify_scope) + [any_focus]
                }
            },
        }
        response = self._post_json(
            REMOTE_PATH,
            {"params": {"index": self._query_index_target(exact_index_names), "body": body}},
        )
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
                source_ref=hit.get("_index"),
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
        return [row["value"] for row in self.list_host_options()]

    def resolve_customer(self, customer: str | None) -> dict[str, Any] | None:
        raw = (customer or "").strip().lower()
        if not raw or raw == "all":
            return None
        rows = [row for row in self.list_index_options() if str(row.get("customer_name") or "").lower() == raw]
        if not rows:
            return {
                "customer": raw,
                "index_names": [],
                "hosts": [],
                "base_domains": [raw],
            }
        return {
            "customer": rows[0]["customer_name"],
            "index_names": [str(row.get("value") or "") for row in rows if row.get("value")],
            "hosts": [],
            "base_domains": [rows[0]["customer_name"]],
        }

    def _metadata_index_target(self) -> str:
        configured = (self.config.index or "").strip()
        if configured and configured != "*" and "nginx" in configured.lower():
            return configured
        return REMOTE_NGINX_INDEX_GLOB

    def _query_index_target(self, index_names: list[str] | None = None) -> str:
        exact_index_names = self._clean_index_names(index_names)
        if exact_index_names:
            return ",".join(exact_index_names)
        return self._metadata_index_target()

    def _clean_index_names(self, index_names: list[str] | None) -> list[str]:
        seen: set[str] = set()
        rows: list[str] = []
        for index_name in index_names or []:
            value = str(index_name or "").strip()
            if not value or value in seen:
                continue
            if not self._is_supported_index_name(value):
                continue
            if self._should_skip_index_name(value):
                continue
            seen.add(value)
            rows.append(value)
        return rows

    def _is_supported_index_name(self, index_name: str) -> bool:
        lower = index_name.lower()
        return "nginx" in lower and "heartbeat" not in lower

    def _is_shopify_index_name(self, index_name: str) -> bool:
        return "shopify" in index_name.lower()

    def _is_shopify_scope(self, index_names: list[str] | None) -> bool:
        cleaned = [index_name for index_name in (index_names or []) if index_name]
        return bool(cleaned) and all(self._is_shopify_index_name(index_name) for index_name in cleaned)

    def _dashboard_base_filters(
        self,
        start_utc: str,
        end_utc: str,
        host_filters: list[str] | None,
        shopify_scope: bool,
    ) -> list[dict[str, Any]]:
        filters: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": start_utc, "lt": end_utc}}}]
        cleaned_hosts = [self._clean_host_value(item) for item in (host_filters or []) if self._clean_host_value(item)]
        if cleaned_hosts:
            filters.append({"terms": {"host": cleaned_hosts}})
        if shopify_scope:
            filters.append(self._shopify_path_query())
        return filters

    def _clean_host_value(self, value: Any) -> str:
        host = str(value or "").strip().lower()
        if not host:
            return ""
        if "/" in host:
            host = host.split("/", 1)[0]
        return host.split(":", 1)[0]

    def _is_displayable_host(self, host: str) -> bool:
        if not host or host in {"_", "localhost", "0.0.0.0", "127.0.0.1"}:
            return False
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            pass
        return "." in host and any(ch.isalpha() for ch in host)

    def _official_ai_platforms(self, repo_category: str) -> list[tuple[str, list[str]]]:
        taxonomy = load_bot_taxonomy()
        rows = [
            (entry.bot_name, [entry.token])
            for entry in taxonomy.ai_by_repo.get(repo_category, ())
            if entry.token
        ]
        rows.sort(key=lambda item: item[0].lower())
        return rows

    def _official_ai_tokens(self, repo_category: str) -> list[str]:
        return [tokens[0] for _, tokens in self._official_ai_platforms(repo_category)]

    def _official_seo_tokens(self) -> list[str]:
        taxonomy = load_bot_taxonomy()
        tokens = [entry.token for entry in taxonomy.non_ai_entries if entry.category == "SEO Bot" and entry.token]
        return sorted(set(tokens))

    def _unknown_bot_query(self, allow_io_mirror: bool = False) -> dict[str, Any]:
        official_tokens = sorted(load_bot_taxonomy().all_tokens)
        must_not: list[dict[str, Any]] = [
            self._static_resource_query(),
            self._mirror_non_302_query(allow_io_mirror=allow_io_mirror),
            self._suspicious_probe_query(),
        ]
        if official_tokens:
            must_not.append(self._any_ua_match(official_tokens))
        return {
            "bool": {
                "must_not": must_not,
                "should": [self._any_keyword_contains("ua.keyword", list(UNCLASSIFIED_BOT_HINT_TOKENS))],
                "minimum_should_match": 1,
            }
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
        patterns = self._expand_index_patterns(domains)
        if not patterns:
            return {"match_all": {}}
        return {
            "bool": {
                "should": [{"wildcard": {"_index": {"value": pattern}}} for pattern in patterns],
                "minimum_should_match": 1,
            }
        }

    def _expand_index_patterns(self, domains: list[str]) -> list[str]:
        seen = set()
        patterns: list[str] = []
        for domain in domains:
            normalized = self._normalize_domain(domain)
            if not normalized:
                continue
            if self._should_skip_index_domain(normalized):
                continue
            base = self._extract_base_domain(normalized)
            base_label = self._base_index_label(base)
            for item in (
                f"*{normalized}*",
                f"*{normalized.replace('.', '-')}*",
                f"*{base}*" if base else "",
                f"*{base.replace('.', '-')}*" if base else "",
                f"*{base_label}*" if base_label else "",
            ):
                if item not in seen:
                    seen.add(item)
                    patterns.append(item)
        return patterns

    def _should_skip_index_domain(self, domain: str) -> bool:
        return domain in {"www.tec-do.com"}

    def _should_skip_index_name(self, index_name: str) -> bool:
        lower = index_name.lower()
        return "www.tec-do.com" in lower or "www-tec-do-com" in lower

    def _base_index_label(self, domain: str) -> str:
        if not domain:
            return ""
        parts = [part for part in domain.split(".") if part]
        if len(parts) >= 2:
            return parts[-2]
        return parts[0] if parts else ""

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

    def _dashboard_category_filters(self, allow_io_mirror: bool = False) -> dict[str, Any]:
        ai_bot = self._ai_bot_query()
        seo_bot = self._seo_bot_query()
        unknown_bot = self._unknown_bot_query(allow_io_mirror=allow_io_mirror)
        static_q = self._static_resource_query()
        mirror_non_302 = self._mirror_non_302_query(allow_io_mirror=allow_io_mirror)
        probe_q = self._suspicious_probe_query()
        user_base_must_not = [ai_bot, seo_bot, unknown_bot, static_q, mirror_non_302, probe_q]
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

    def _human_referred_filters(self, allow_io_mirror: bool = False) -> dict[str, Any]:
        must_not = [
            self._ai_bot_query(),
            self._seo_bot_query(),
            self._unknown_bot_query(allow_io_mirror=allow_io_mirror),
            self._static_resource_query(),
            self._mirror_non_302_query(allow_io_mirror=allow_io_mirror),
            self._suspicious_probe_query(),
        ]
        return {
            "total": {"bool": {"should": self._user_ai_should(), "minimum_should_match": 1, "must_not": must_not}},
            "chatgpt": {"bool": {"must_not": must_not, "should": [self._chatgpt_utm_query()], "minimum_should_match": 1}},
            "perplexity": {"bool": {"must_not": must_not, "should": [self._referer_host_query('perplexity.ai')], "minimum_should_match": 1}},
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

    def _top_ai_pages(
        self,
        index_names: list[str],
        host_filters: list[str] | None,
        start_utc: str,
        end_utc: str,
        limit: int,
        shopify_scope: bool,
    ) -> list[str]:
        focused = self._dashboard_category_filters(allow_io_mirror=shopify_scope)
        ai_any = {"bool": {"should": [focused["ai_search"], focused["ai_training"], focused["ai_index"]], "minimum_should_match": 1}}
        body = {
            "size": 0,
            "track_total_hits": False,
            "runtime_mappings": {"normalized_page": self._normalized_page_runtime()},
            "query": {
                "bool": {
                    "filter": self._dashboard_base_filters(start_utc, end_utc, host_filters, shopify_scope) + [ai_any]
                }
            },
            "aggs": {"pages": {"terms": {"field": "normalized_page", "size": max(limit, 1)}}},
        }
        response = self._post_json(REMOTE_PATH, {"params": {"index": self._query_index_target(index_names), "body": body}})
        return [bucket["key"] for bucket in response["rawResponse"]["aggregations"]["pages"]["buckets"] if bucket.get("key")]

    def _page_breakdown(
        self,
        index_names: list[str],
        host_filters: list[str] | None,
        start_utc: str,
        end_utc: str,
        page_keys: list[str],
        focused: dict[str, Any],
        ai_any: dict[str, Any],
        user_any: dict[str, Any],
        shopify_scope: bool,
    ) -> list[dict[str, Any]]:
        body = {
            "size": 0,
            "track_total_hits": False,
            "runtime_mappings": {"normalized_page": self._normalized_page_runtime()},
            "query": {
                "bool": {
                    "filter": self._dashboard_base_filters(start_utc, end_utc, host_filters, shopify_scope) + [{"terms": {"normalized_page": page_keys}}]
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
        response = self._post_json(REMOTE_PATH, {"params": {"index": self._query_index_target(index_names), "body": body}})
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

    def _unknown_bot_rankings(
        self,
        index_names: list[str],
        host_filters: list[str] | None,
        start_utc: str,
        end_utc: str,
        limit: int,
        shopify_scope: bool,
    ) -> list[dict[str, Any]]:
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {
                "bool": {
                    "filter": self._dashboard_base_filters(start_utc, end_utc, host_filters, shopify_scope) + [self._unknown_bot_query(allow_io_mirror=shopify_scope)]
                }
            },
            "aggs": {
                "uas": {
                    "terms": {
                        "field": "ua.keyword",
                        "size": max(limit * 8, 50),
                        "order": {"_count": "desc"},
                    }
                }
            },
        }
        response = self._post_json(REMOTE_PATH, {"params": {"index": self._query_index_target(index_names), "body": body}})
        grouped: dict[str, dict[str, Any]] = {}
        for bucket in response["rawResponse"]["aggregations"]["uas"]["buckets"]:
            ua_value = str(bucket.get("key") or "")
            bot_name = infer_bot_name_from_ua(ua_value)
            signal = infer_bot_signal_from_ua(ua_value)
            item = grouped.setdefault(
                bot_name,
                {
                    "platform": bot_name,
                    "requests": 0,
                    "signal": signal,
                    "sample_ua": ua_value,
                    "sample_ua_count": 0,
                },
            )
            count = int(bucket.get("doc_count") or 0)
            item["requests"] += count
            if not item.get("signal") and signal:
                item["signal"] = signal
            if count > int(item.get("sample_ua_count") or 0):
                item["sample_ua"] = ua_value
                item["sample_ua_count"] = count
        rows = [
            {
                "platform": item["platform"],
                "requests": item["requests"],
                "signal": item.get("signal") or "",
                "sample_ua": item.get("sample_ua") or "",
            }
            for item in grouped.values()
            if item.get("platform")
        ]
        rows.sort(key=lambda item: (-item["requests"], item["platform"]))
        return rows[: max(limit, 1)]

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
        return self._any_ua_match(self._official_ai_tokens("ai_search"))

    def _ai_training_query(self) -> dict[str, Any]:
        return self._any_ua_match(self._official_ai_tokens("ai_training"))

    def _ai_index_query(self) -> dict[str, Any]:
        return self._any_ua_match(self._official_ai_tokens("ai_index"))

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
        taxonomy_tokens = self._official_seo_tokens()
        should_filters = [
            self._any_ua_match(taxonomy_tokens) if taxonomy_tokens else {"match_none": {}},
            self._ua_match("duckduckbot"),
            self._ua_match("yandexbot"),
            self._ua_match("sosospider"),
        ]
        return {
            "bool": {
                "should": should_filters,
                "minimum_should_match": 1,
            }
        }

    def _suspicious_probe_query(self) -> dict[str, Any]:
        patterns = ["/.git", "/.aws", "/.env", "/.s3cfg", "/phpinfo.php", "/info.php", "/_debugbar", "/debug", "/debugbar", "/aws-credentials", "/wp-config.php", "/test.php"]
        return {"bool": {"should": [self._keyword_wildcard("uri.keyword", p + "*") for p in patterns], "minimum_should_match": 1}}

    def _shopify_path_query(self) -> dict[str, Any]:
        return self._keyword_wildcard("uri.keyword", "/app-proxy*")

    def _mirror_non_302_query(self, allow_io_mirror: bool = False) -> dict[str, Any]:
        mirror_hosts = [self._keyword_wildcard("host", "mmm.*")]
        if not allow_io_mirror:
            mirror_hosts.append({"regexp": {"host": {"value": ".*\\.deeplumen\\.io", "case_insensitive": True}}})
        return {
            "bool": {
                "must": [
                    {"bool": {"should": mirror_hosts, "minimum_should_match": 1}}
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
