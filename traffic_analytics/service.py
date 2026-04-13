from __future__ import annotations

import json
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, date
from pathlib import Path
from typing import Any

from .classification import (
    browser_family,
    classify_agent,
    derive_session_actor_key,
    derive_user_key,
    device_type,
    normalize_ip,
    normalize_page,
    os_family,
    page_exclusion_reason,
    repo_classify_access,
    repo_extract_base_domain,
    sha1_short,
)
from .index_filtering import build_select_options, filter_index_options
from .settings import (
    AUTO_SYNC_CHECK_INTERVAL_SECONDS,
    BOT_SESSION_GAP_SECONDS,
    DATABASE_DIR,
    FULL_DB_PATH,
    FRONTEND_SNAPSHOT_PATH,
    HUMAN_SESSION_GAP_SECONDS,
    INCREMENT_DB_PATH,
    LOG_DIR,
    SKIP_FIRST_DAYS,
    SNAPSHOT_PATH,
    TARGET_METHOD,
)
from .remote_source import KibanaRemoteLogSource


B_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<dt>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

DOC_AI_SEARCH_TOKENS = (
    "chatgpt-user",
    "oai-searchbot",
    "claudebot",
    "claude-web",
    "googleagent-mariner",
    "applebot-extended",
    "perplexitybot",
    "perplexity-user",
    "mistralai-user",
    "meta-externalagent",
    "cohere-ai",
    "youbot",
    "duckassistbot",
    "moonshot",
)
DOC_AI_TRAINING_TOKENS = (
    "gptbot",
    "anthropic-ai",
    "google-extended",
    "amazonbot",
    "ccbot",
    "diffbot",
    "ai2bot",
)
DOC_AI_INDEX_TOKENS = (
    "googleother",
    "bytespider",
    "toutiaospider",
    "baiduspider-render",
    "qwen",
    "alibaba",
    "yisouspider",
    "360spider",
)
DOC_AI_UNCLASSIFIED_TOKENS = (
    "facebookbot",
    "imagesiftbot",
    "omgilibot",
    "timpibot",
)
DOC_SEO_SPECIFIC_TOKENS = (
    "googlebot",
    "googlebot-image",
    "bingbot",
    "duckduckbot",
    "yandexbot",
    "slurp",
    "petalbot",
    "sogou",
    "sosospider",
)
DOC_SEO_GENERIC_TOKENS = ("bot", "spider", "crawler", "crawl", "slurp", "scraper", "scan", "fetch")
DOC_SUSPICIOUS_PREFIXES = (
    "/.git",
    "/.aws",
    "/.env",
    "/.s3cfg",
    "/phpinfo.php",
    "/info.php",
    "/_debugbar",
    "/debug",
    "/debugbar",
    "/aws-credentials",
    "/wp-config.php",
    "/test.php",
)
DOC_STATIC_EXTS = (
    ".css", ".js", ".map",
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".webp", ".avif", ".bmp", ".tif", ".tiff",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".mov", ".flv", ".m4a",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".exe", ".dll", ".iso", ".bin",
    ".txt", ".xml", ".json", ".webmanifest", ".yaml", ".yml", ".ini", ".conf", ".log", ".toml", ".sql", ".bak",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv",
)


def _sql_escape(value: str) -> str:
    return value.replace("'", "''")


def _sql_like_any(column: str, tokens: tuple[str, ...]) -> str:
    return "(" + " OR ".join(
        f"LOWER(COALESCE({column}, '')) LIKE '%{_sql_escape(token)}%'" for token in tokens
    ) + ")"


def _sql_prefix_any(column: str, prefixes: tuple[str, ...]) -> str:
    return "(" + " OR ".join(
        f"LOWER(COALESCE({column}, '')) LIKE '{_sql_escape(prefix)}%'" for prefix in prefixes
    ) + ")"


def _sql_suffix_any(column: str, suffixes: tuple[str, ...]) -> str:
    return "(" + " OR ".join(
        f"LOWER(COALESCE({column}, '')) LIKE '%{_sql_escape(suffix)}'" for suffix in suffixes
    ) + ")"


@dataclass
class IngestResult:
    inserted: int
    duplicates: int
    affected_days: set[str]


@dataclass
class DateWindow:
    start: str
    end: str


def local_day_to_utc_bounds(day_start: str, day_end: str, tz_offset_hours: int = 8) -> tuple[str, str]:
    start_dt = datetime.fromisoformat(day_start + "T00:00:00") - timedelta(hours=tz_offset_hours)
    end_dt = datetime.fromisoformat(day_end + "T00:00:00") + timedelta(days=1) - timedelta(hours=tz_offset_hours)
    return start_dt.isoformat(timespec="milliseconds") + "Z", end_dt.isoformat(timespec="milliseconds") + "Z"


class AnalyticsService:
    def __init__(
        self,
        full_db_path: Path = FULL_DB_PATH,
        increment_db_path: Path = INCREMENT_DB_PATH,
        snapshot_path: Path = SNAPSHOT_PATH,
        frontend_snapshot_path: Path = FRONTEND_SNAPSHOT_PATH,
        log_dir: Path = LOG_DIR,
        auto_sync_interval_seconds: int = AUTO_SYNC_CHECK_INTERVAL_SECONDS,
    ) -> None:
        self.full_db_path = Path(full_db_path)
        self.increment_db_path = Path(increment_db_path)
        self.snapshot_path = Path(snapshot_path)
        self.frontend_snapshot_path = Path(frontend_snapshot_path)
        self.log_dir = Path(log_dir)
        self.auto_sync_interval_seconds = auto_sync_interval_seconds
        self.remote_source = KibanaRemoteLogSource()
        self.allow_on_demand_sync = True
        self._sync_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._auto_sync_thread: threading.Thread | None = None

    @staticmethod
    def _extra_dashboard_filter_sql(exclude_sensitive_pages: bool) -> tuple[str, list[Any]]:
        if not exclude_sensitive_pages:
            return "1=1", []
        return (
            """
            NOT (
                LOWER(COALESCE(uri, '')) LIKE '%.php%'
                OR LOWER(COALESCE(uri, '')) LIKE '%wp-login%'
                OR LOWER(COALESCE(uri, '')) LIKE '%wp-admin%'
                OR LOWER(COALESCE(uri, '')) LIKE '%/login%'
                OR LOWER(COALESCE(uri, '')) LIKE '%signin%'
                OR LOWER(COALESCE(uri, '')) LIKE '%sign-in%'
                OR LOWER(COALESCE(uri, '')) LIKE '%auth%'
            )
            """,
            [],
        )

    @staticmethod
    def _doc_static_sql() -> str:
        return _sql_suffix_any("uri", DOC_STATIC_EXTS)

    @staticmethod
    def _doc_suspicious_sql() -> str:
        return _sql_prefix_any("uri", DOC_SUSPICIOUS_PREFIXES)

    @staticmethod
    def _doc_mirror_unknown_sql() -> str:
        return """
        (
            (LOWER(COALESCE(host, '')) LIKE 'mmm.%' OR LOWER(COALESCE(host, '')) LIKE '%.deeplumen.io')
            AND COALESCE(status, 0) <> 302
        )
        """

    @staticmethod
    def _doc_ai_search_sql() -> str:
        return _sql_like_any("user_agent", DOC_AI_SEARCH_TOKENS)

    @staticmethod
    def _doc_ai_training_sql() -> str:
        return _sql_like_any("user_agent", DOC_AI_TRAINING_TOKENS)

    @staticmethod
    def _doc_ai_index_sql() -> str:
        return f"({_sql_like_any('user_agent', DOC_AI_INDEX_TOKENS)} OR LOWER(COALESCE(user_agent, '')) LIKE '%baiduspider%ai%')"

    @staticmethod
    def _doc_ai_unclassified_sql() -> str:
        return _sql_like_any("user_agent", DOC_AI_UNCLASSIFIED_TOKENS)

    @staticmethod
    def _doc_seo_bot_sql() -> str:
        specific = _sql_like_any("user_agent", DOC_SEO_SPECIFIC_TOKENS)
        generic = _sql_like_any("user_agent", DOC_SEO_GENERIC_TOKENS)
        baidu_non_ai = "LOWER(COALESCE(user_agent, '')) LIKE '%baiduspider%' AND LOWER(COALESCE(user_agent, '')) NOT LIKE '%baiduspider-render%' AND LOWER(COALESCE(user_agent, '')) NOT LIKE '%baiduspider%ai%'"
        return f"({specific} OR {generic} OR ({baidu_non_ai}))"

    @staticmethod
    def _doc_any_ai_bot_sql() -> str:
        return f"({AnalyticsService._doc_ai_search_sql()} OR {AnalyticsService._doc_ai_training_sql()} OR {AnalyticsService._doc_ai_index_sql()} OR {AnalyticsService._doc_ai_unclassified_sql()})"

    @staticmethod
    def _doc_focus_exclusion_sql() -> str:
        return f"({AnalyticsService._doc_static_sql()} OR {AnalyticsService._doc_suspicious_sql()} OR {AnalyticsService._doc_mirror_unknown_sql()} OR {AnalyticsService._doc_seo_bot_sql()})"

    @staticmethod
    def _calc_previous_window(date_from: str | None, date_to: str | None) -> DateWindow | None:
        if not date_from or not date_to:
            return None
        start = date.fromisoformat(date_from)
        end = date.fromisoformat(date_to)
        if end < start:
            start, end = end, start
        span = (end - start).days + 1
        prev_end = start - timedelta(days=1)
        prev_start = prev_end - timedelta(days=span - 1)
        return DateWindow(start=prev_start.isoformat(), end=prev_end.isoformat())

    @staticmethod
    def _calc_change_pct(current: int, previous: int) -> float | None:
        if previous == 0:
            if current == 0:
                return None
            return 100.0
        return round((current - previous) * 100.0 / previous, 2)

    @staticmethod
    def _calc_share_pct(part: int, total: int) -> float:
        if total == 0:
            return 0.0
        return round(part * 100.0 / total, 2)

    def _build_filter_sql(
        self,
        customer: str | None = None,
        host: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        exclude_sensitive_pages: bool = False,
        index_names: list[str] | None = None,
    ) -> tuple[str, list[Any]]:
        filters: list[str] = []
        params: list[Any] = []
        selected_index_names = [str(item).strip() for item in (index_names or []) if str(item).strip()]
        if selected_index_names:
            placeholders = ", ".join("?" for _ in selected_index_names)
            filters.append(f"source_ref IN ({placeholders})")
            params.extend(selected_index_names)
            if any("shopify" in item.lower() for item in selected_index_names):
                filters.append("LOWER(COALESCE(uri, '')) LIKE '/app-proxy%'")
        elif customer and customer != "ALL":
            resolved = self.remote_source.resolve_customer(customer)
            domains = (resolved or {}).get("base_domains") or [repo_extract_base_domain(customer)]
            hosts = (resolved or {}).get("hosts") or []
            domains = [domain for domain in domains if domain]
            host_fallbacks = [host for host in hosts if host]
            parts: list[str] = []
            if len(domains) == 1:
                parts.append("customer_domain = ?")
                params.append(domains[0])
            elif domains:
                placeholders = ", ".join("?" for _ in domains)
                parts.append(f"customer_domain IN ({placeholders})")
                params.extend(domains)
            if host_fallbacks:
                placeholders = ", ".join("?" for _ in host_fallbacks)
                parts.append(f"(COALESCE(customer_domain, '') = '' AND host IN ({placeholders}))")
                params.extend(host_fallbacks)
            if parts:
                filters.append("(" + " OR ".join(parts) + ")")
        if host and host != "ALL":
            filters.append("host = ?")
            params.append(host)
        if date_from:
            filters.append("request_day >= ?")
            params.append(date_from)
        if date_to:
            filters.append("request_day <= ?")
            params.append(date_to)
        extra_filter_sql, extra_params = self._extra_dashboard_filter_sql(exclude_sensitive_pages)
        filters.append(extra_filter_sql)
        params.extend(extra_params)
        return (" AND ".join(filters) if filters else "1=1"), params

    @staticmethod
    def _focused_ai_sql() -> str:
        exclusions = (
            f"{AnalyticsService._doc_static_sql()} "
            f"OR {AnalyticsService._doc_suspicious_sql()} "
            f"OR {AnalyticsService._doc_mirror_unknown_sql()}"
        )
        return f"(repo_category IN ('ai_search', 'ai_training', 'ai_index') AND NOT ({exclusions}))"

    @staticmethod
    def _focused_user_sql() -> str:
        return "repo_category IN ('user_traditional', 'user_ai', 'user_platform', 'user_direct')"

    @staticmethod
    def _user_ai_sql() -> str:
        return "repo_category = 'user_ai'"

    @staticmethod
    def _user_traditional_sql() -> str:
        return "repo_category = 'user_traditional'"

    @staticmethod
    def _user_platform_sql() -> str:
        return "repo_category = 'user_platform'"

    @staticmethod
    def _user_direct_sql() -> str:
        return "repo_category = 'user_direct'"

    @staticmethod
    def _repo_focused_all_sql() -> str:
        return "repo_category IN ('user_traditional', 'user_ai', 'user_platform', 'user_direct', 'ai_search', 'ai_training', 'ai_index')"

    @staticmethod
    def _repo_focus_excluded_sql() -> str:
        return "repo_category IN ('seo_bot', 'static', 'suspicious_probe', 'unknown', 'ai_unclassified')"

    @staticmethod
    def _ai_search_sql() -> str:
        return "repo_category = 'ai_search'"

    @staticmethod
    def _ai_training_sql() -> str:
        return "repo_category = 'ai_training'"

    @staticmethod
    def _ai_index_sql() -> str:
        return "repo_category = 'ai_index'"

    def initialize(self, auto_sync: bool = False, rebuild: bool = False, initial_sync: bool = True) -> None:
        DATABASE_DIR.mkdir(parents=True, exist_ok=True)
        self._ensure_full_schema()
        self._ensure_increment_schema()
        if rebuild:
            self._reset_full_db()
            self._reset_increment_db()
        if initial_sync:
            self.sync_from_local_logs()
        if auto_sync:
            self.start_auto_sync()

    def start_auto_sync(self) -> None:
        if self._auto_sync_thread and self._auto_sync_thread.is_alive():
            return

        def _loop() -> None:
            while not self._stop_event.wait(self.auto_sync_interval_seconds):
                try:
                    self.sync_from_local_logs()
                except Exception:
                    continue

        self._auto_sync_thread = threading.Thread(target=_loop, name="traffic-auto-sync", daemon=True)
        self._auto_sync_thread.start()

    def stop_auto_sync(self) -> None:
        self._stop_event.set()
        if self._auto_sync_thread and self._auto_sync_thread.is_alive():
            self._auto_sync_thread.join(timeout=2)

    def sync_from_local_logs(self) -> dict[str, Any]:
        with self._sync_lock:
            self._ensure_full_schema()
            self._ensure_increment_schema()
            summary = {"files_scanned": 0, "inserted": 0, "duplicates": 0}
            if self.remote_source.is_configured():
                result = self._ingest_remote_logs()
                summary["files_scanned"] = 1
                summary["inserted"] = result.inserted
                summary["duplicates"] = result.duplicates
            else:
                files_scanned = 0
                inserted = 0
                duplicates = 0
                for path in self._list_local_log_files():
                    state = self._get_file_state(path)
                    if not self._should_scan_file(path, state):
                        continue
                    result = self._ingest_log_file(path)
                    self._upsert_file_state(path)
                    files_scanned += 1
                    inserted += result.inserted
                    duplicates += result.duplicates
                summary["files_scanned"] = files_scanned
                summary["inserted"] = inserted
                summary["duplicates"] = duplicates
            self._rebuild_derived_tables()
            snapshot = self._write_snapshot_file()
            summary["snapshot"] = snapshot
            return summary

    def ingest_api_logs(self, side: str, logs: list[str | dict[str, Any]]) -> dict[str, Any]:
        with self._sync_lock:
            normalized_side = side.lower()
            if normalized_side != "b":
                raise ValueError("this service only accepts side='b'")

            inserted = 0
            duplicates = 0
            affected_days: set[str] = set()
            with self._full_conn() as conn:
                for item in logs:
                    row = self._build_request_row(normalized_side, item, source_kind="api", source_ref="api")
                    if row is None:
                        continue
                    if self._insert_request_row(conn, row):
                        inserted += 1
                        if row["request_day"]:
                            affected_days.add(row["request_day"])
                    else:
                        duplicates += 1
                conn.commit()

            self._rebuild_derived_tables()
            snapshot = self._write_snapshot_file()
            return {
                "inserted": inserted,
                "duplicates": duplicates,
                "affected_days": sorted(affected_days),
                "snapshot": snapshot,
            }

    def get_summary(self) -> dict[str, Any]:
        self._ensure_fresh_daily_sync()
        with self._increment_conn() as conn:
            overview = [dict(row) for row in conn.execute("SELECT * FROM daily_overview ORDER BY date")]
            metadata = self._metadata_dict(conn)
        if self.snapshot_path.exists():
            snapshot = json.loads(self.snapshot_path.read_text(encoding="utf-8"))
            total_requests = snapshot.get("metrics", {}).get("total_requests", 0)
            total_users = snapshot.get("metrics", {}).get("total_users", 0)
            bot_feature_rows = snapshot.get("bot_feature_breakdown", [])
            total_bot_families = len({row.get("bot_family", "") for row in bot_feature_rows if row.get("bot_family")})
            if snapshot.get("daily_overview"):
                overview = snapshot["daily_overview"]
        else:
            with self._full_conn() as conn:
                total_requests = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
                total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                total_bot_families = conn.execute(
                    "SELECT COUNT(DISTINCT bot_family) FROM requests WHERE bot_family NOT IN ('', 'Unknown Agent') AND actor_type IN ('bot', 'automation')"
                ).fetchone()[0]
        return {
            "metadata": metadata,
            "total_requests": total_requests,
            "total_users": total_users,
            "total_bot_families": total_bot_families,
            "daily_overview": overview,
        }

    def get_increment_snapshot(self, limit: int | None = None) -> dict[str, Any]:
        self._ensure_fresh_daily_sync()
        clause = "" if not limit else f" LIMIT {int(limit)}"
        with self._increment_conn() as conn:
            overview = [dict(row) for row in conn.execute(f"SELECT * FROM daily_overview ORDER BY date DESC{clause}")]
            users = [dict(row) for row in conn.execute(f"SELECT * FROM daily_user_increment ORDER BY date DESC, requests DESC{clause}")]
            bots = [dict(row) for row in conn.execute(f"SELECT * FROM daily_bot_increment ORDER BY date DESC, requests DESC{clause}")]
            pages = [dict(row) for row in conn.execute(f"SELECT * FROM daily_page_increment ORDER BY date DESC, human_requests DESC{clause}")]
            metadata = self._metadata_dict(conn)
        return {
            "metadata": metadata,
            "daily_overview": overview,
            "daily_user_increment": users,
            "daily_bot_increment": bots,
            "daily_page_increment": pages,
        }

    def get_frontend_dashboard(
        self,
        days: int = 14,
        top_bots: int = 10,
        top_pages: int = 10,
        top_users: int = 10,
    ) -> dict[str, Any]:
        if self.frontend_snapshot_path.exists():
            return json.loads(self.frontend_snapshot_path.read_text(encoding="utf-8"))
        self._ensure_fresh_daily_sync()
        snapshot = {}
        if self.snapshot_path.exists():
            snapshot = json.loads(self.snapshot_path.read_text(encoding="utf-8"))

        with self._increment_conn() as conn:
            overview_rows = [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM daily_overview ORDER BY date DESC LIMIT ?",
                    (max(days, 1),),
                )
            ]
            user_rows = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT date, user_id, requests, sessions, is_new_user, first_page, last_page
                    FROM daily_user_increment
                    ORDER BY date DESC, requests DESC
                    LIMIT ?
                    """,
                    (max(top_users, 1),),
                )
            ]
            page_rows = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT date, page, human_requests, human_sessions, bot_requests, bot_sessions
                    FROM daily_page_increment
                    ORDER BY date DESC, human_requests DESC
                    LIMIT ?
                    """,
                    (max(top_pages, 1),),
                )
            ]
            metadata = self._metadata_dict(conn)
        overview_rows = list(reversed(overview_rows))
        return self._build_frontend_dashboard_payload(
            snapshot=snapshot,
            overview_rows=overview_rows,
            user_rows=user_rows,
            page_rows=page_rows,
            metadata=metadata,
            top_bots=top_bots,
            top_pages=top_pages,
        )

    def get_dashboard_filters(
        self,
        customer_name: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> dict[str, Any]:
        try:
            start_utc = end_utc = None
            if date_from and date_to:
                start_utc, end_utc = local_day_to_utc_bounds(date_from, date_to)
            all_indices = self.remote_source.list_index_options(start_utc=start_utc, end_utc=end_utc)
            filtered_indices = filter_index_options(
                all_indices,
                customer_name,
                None,
                date_from=date_from,
                date_to=date_to,
            )
            customers = build_select_options(all_indices, "customer_name", "全部客户")
            hosts = [{"value": "ALL", "label": "全部 Host", "requests": 0}]
            if customer_name and customer_name != "ALL":
                hosts.extend(
                    self.remote_source.list_host_options(
                        index_names=[str(item.get("value") or "") for item in filtered_indices if item.get("value")],
                        start_utc=start_utc,
                        end_utc=end_utc,
                    )
                )
            bounds = self.remote_source.get_time_bounds()
            return {
                "customers": customers,
                "hosts": hosts,
                "defaults": {
                    "customer_name": customer_name or "ALL",
                    "host": "ALL",
                    "date_from": bounds.get("date_from", ""),
                    "date_to": bounds.get("date_to", ""),
                    "top_bots": 10,
                    "top_pages": 10,
                    "exclude_sensitive_pages": False,
                },
            }
        except Exception:
            self._ensure_fresh_daily_sync()
            all_indices = self._list_local_index_options()
            filtered_indices = filter_index_options(
                all_indices,
                customer_name,
                None,
                date_from=date_from,
                date_to=date_to,
            )
            customers = build_select_options(all_indices, "customer_name", "全部客户")
            hosts = [{"value": "ALL", "label": "全部 Host", "requests": 0}]
            if customer_name and customer_name != "ALL":
                latest_index_names = [str(item.get("value") or "") for item in filtered_indices if item.get("value")]
                if latest_index_names:
                    hosts.extend(self._list_local_host_options(latest_index_names))
            with self._full_conn() as conn:
                bounds = conn.execute(
                    """
                    SELECT
                        MIN(request_day) AS min_day,
                        MAX(request_day) AS max_day
                    FROM requests
                    """
                ).fetchone()
            return {
                "customers": customers,
                "hosts": hosts,
                "defaults": {
                    "customer_name": customer_name or "ALL",
                    "host": "ALL",
                    "date_from": bounds["min_day"] if bounds and bounds["min_day"] else "",
                    "date_to": bounds["max_day"] if bounds and bounds["max_day"] else "",
                    "top_bots": 10,
                    "top_pages": 10,
                    "exclude_sensitive_pages": False,
                },
            }

    def get_filtered_dashboard(
        self,
        customer: str | None = None,
        customer_name: str | None = None,
        host: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        top_bots: int = 10,
        top_pages: int = 10,
        exclude_sensitive_pages: bool = False,
    ) -> dict[str, Any]:
        selected_customer = customer if customer is not None else customer_name
        if date_from and date_to:
            try:
                return self._get_filtered_dashboard_live(
                    customer=selected_customer,
                    host=host,
                    date_from=date_from,
                    date_to=date_to,
                    top_bots=top_bots,
                    top_pages=top_pages,
                    exclude_sensitive_pages=exclude_sensitive_pages,
                )
            except Exception:
                pass
        self._ensure_fresh_daily_sync()
        where_sql, params = self._build_filter_sql(selected_customer, host, date_from, date_to, exclude_sensitive_pages)
        previous_window = self._calc_previous_window(date_from, date_to)
        prev_where_sql, prev_params = self._build_filter_sql(
            selected_customer,
            host,
            previous_window.start if previous_window else None,
            previous_window.end if previous_window else None,
            exclude_sensitive_pages,
        )
        focused_user_sql = self._focused_user_sql()
        focused_ai_sql = self._focused_ai_sql()
        user_ai_sql = self._user_ai_sql()
        user_traditional_sql = self._user_traditional_sql()
        user_platform_sql = self._user_platform_sql()
        user_direct_sql = self._user_direct_sql()
        ai_search_sql = self._ai_search_sql()
        ai_training_sql = self._ai_training_sql()
        ai_index_sql = self._ai_index_sql()
        ai_search_focused_sql = f"({ai_search_sql} AND {focused_ai_sql})"
        ai_training_focused_sql = f"({ai_training_sql} AND {focused_ai_sql})"
        ai_index_focused_sql = f"({ai_index_sql} AND {focused_ai_sql})"
        user_ai_chatgpt_sql = "(repo_category = 'user_ai' AND LOWER(COALESCE(repo_channel, '')) = 'chatgpt')"
        user_ai_perplexity_sql = "(repo_category = 'user_ai' AND LOWER(COALESCE(repo_channel, '')) = 'perplexity')"

        with self._full_conn() as conn:
            card_row = conn.execute(
                f"""
                SELECT
                    SUM(CASE WHEN {focused_user_sql} THEN 1 ELSE 0 END)
                      + SUM(CASE WHEN {focused_ai_sql} THEN 1 ELSE 0 END) AS total_requests,
                    SUM(CASE WHEN {focused_user_sql} THEN 1 ELSE 0 END) AS user_requests,
                    SUM(CASE WHEN {focused_ai_sql} THEN 1 ELSE 0 END) AS ai_requests,
                    COUNT(DISTINCT CASE WHEN is_counted_user = 1 THEN user_id END) AS active_users,
                    COUNT(DISTINCT CASE WHEN {focused_ai_sql} THEN session_actor_key END) AS active_ai_actors,
                    MIN(request_day) AS date_from,
                    MAX(request_day) AS date_to
                FROM requests
                WHERE {where_sql}
                """,
                params,
            ).fetchone()

            human_row = conn.execute(
                f"""
                SELECT
                    SUM(CASE WHEN {focused_user_sql} THEN 1 ELSE 0 END) AS total_human_traffic,
                    SUM(CASE WHEN {user_ai_sql} THEN 1 ELSE 0 END) AS human_ai_channel,
                    SUM(CASE WHEN {user_traditional_sql} THEN 1 ELSE 0 END) AS human_traditional_channel,
                    SUM(CASE WHEN {user_platform_sql} THEN 1 ELSE 0 END) AS human_platform_channel,
                    SUM(CASE WHEN {user_direct_sql} THEN 1 ELSE 0 END) AS human_direct_channel
                FROM requests
                WHERE {where_sql}
                """,
                params,
            ).fetchone()

            prev_human_row = conn.execute(
                f"""
                SELECT
                    SUM(CASE WHEN {focused_user_sql} THEN 1 ELSE 0 END) AS total_human_traffic,
                    SUM(CASE WHEN {user_ai_sql} THEN 1 ELSE 0 END) AS human_ai_channel,
                    SUM(CASE WHEN {user_traditional_sql} THEN 1 ELSE 0 END) AS human_traditional_channel,
                    SUM(CASE WHEN {user_platform_sql} THEN 1 ELSE 0 END) AS human_platform_channel,
                    SUM(CASE WHEN {user_direct_sql} THEN 1 ELSE 0 END) AS human_direct_channel
                FROM requests
                WHERE {prev_where_sql}
                """,
                prev_params,
            ).fetchone()

            ai_row = conn.execute(
                f"""
                SELECT
                    SUM(CASE WHEN {focused_ai_sql} THEN 1 ELSE 0 END) AS total_ai_traffic,
                    SUM(CASE WHEN {ai_search_focused_sql} THEN 1 ELSE 0 END) AS ai_search,
                    SUM(CASE WHEN {ai_training_focused_sql} THEN 1 ELSE 0 END) AS ai_training,
                    SUM(CASE WHEN {ai_index_focused_sql} THEN 1 ELSE 0 END) AS ai_index
                FROM requests
                WHERE {where_sql}
                """,
                params,
            ).fetchone()

            prev_ai_row = conn.execute(
                f"""
                SELECT
                    SUM(CASE WHEN {focused_ai_sql} THEN 1 ELSE 0 END) AS total_ai_traffic,
                    SUM(CASE WHEN {ai_search_focused_sql} THEN 1 ELSE 0 END) AS ai_search,
                    SUM(CASE WHEN {ai_training_focused_sql} THEN 1 ELSE 0 END) AS ai_training,
                    SUM(CASE WHEN {ai_index_focused_sql} THEN 1 ELSE 0 END) AS ai_index
                FROM requests
                WHERE {prev_where_sql}
                """,
                prev_params,
            ).fetchone()

            trend_rows = [
                dict(row)
                for row in conn.execute(
                    f"""
                    SELECT
                        request_day AS date,
                        SUM(CASE WHEN {focused_user_sql} THEN 1 ELSE 0 END)
                          + SUM(CASE WHEN {focused_ai_sql} THEN 1 ELSE 0 END) AS total_requests,
                        SUM(CASE WHEN {focused_user_sql} THEN 1 ELSE 0 END) AS user_requests,
                        SUM(CASE WHEN {focused_ai_sql} THEN 1 ELSE 0 END) AS ai_requests,
                        COUNT(DISTINCT CASE WHEN is_counted_user = 1 THEN user_id END) AS active_users
                    FROM requests
                    WHERE {where_sql}
                    GROUP BY request_day
                    ORDER BY request_day
                    """,
                    params,
                )
            ]

            human_trend_rows = [
                dict(row)
                for row in conn.execute(
                    f"""
                    SELECT
                        request_day AS date,
                        SUM(CASE WHEN {focused_user_sql} THEN 1 ELSE 0 END) AS total_human_traffic,
                        SUM(CASE WHEN {user_ai_sql} THEN 1 ELSE 0 END) AS human_ai_channel,
                        SUM(CASE WHEN {user_traditional_sql} THEN 1 ELSE 0 END) AS human_traditional_channel,
                        SUM(CASE WHEN {user_platform_sql} THEN 1 ELSE 0 END) AS human_platform_channel,
                        SUM(CASE WHEN {user_direct_sql} THEN 1 ELSE 0 END) AS human_direct_channel
                    FROM requests
                    WHERE {where_sql}
                    GROUP BY request_day
                    ORDER BY request_day
                    """,
                    params,
                )
            ]

            ai_trend_rows = [
                dict(row)
                for row in conn.execute(
                    f"""
                    SELECT
                        request_day AS date,
                        SUM(CASE WHEN {focused_ai_sql} THEN 1 ELSE 0 END) AS total_ai_traffic,
                        SUM(CASE WHEN {ai_search_focused_sql} THEN 1 ELSE 0 END) AS ai_search,
                        SUM(CASE WHEN {ai_training_focused_sql} THEN 1 ELSE 0 END) AS ai_training,
                        SUM(CASE WHEN {ai_index_focused_sql} THEN 1 ELSE 0 END) AS ai_index
                    FROM requests
                    WHERE {where_sql}
                    GROUP BY request_day
                    ORDER BY request_day
                    """,
                    params,
                )
            ]

            human_referred_row = conn.execute(
                f"""
                SELECT
                    SUM(CASE WHEN {user_ai_sql} THEN 1 ELSE 0 END) AS total_ai_referred_human_traffic,
                    SUM(CASE WHEN {user_ai_chatgpt_sql} THEN 1 ELSE 0 END) AS chatgpt,
                    SUM(CASE WHEN {user_ai_perplexity_sql} THEN 1 ELSE 0 END) AS perplexity
                FROM requests
                WHERE {where_sql}
                """,
                params,
            ).fetchone()

            prev_human_referred_row = conn.execute(
                f"""
                SELECT
                    SUM(CASE WHEN {user_ai_sql} THEN 1 ELSE 0 END) AS total_ai_referred_human_traffic,
                    SUM(CASE WHEN {user_ai_chatgpt_sql} THEN 1 ELSE 0 END) AS chatgpt,
                    SUM(CASE WHEN {user_ai_perplexity_sql} THEN 1 ELSE 0 END) AS perplexity
                FROM requests
                WHERE {prev_where_sql}
                """,
                prev_params,
            ).fetchone()

            human_referred_trend_rows = [
                dict(row)
                for row in conn.execute(
                    f"""
                    SELECT
                        request_day AS date,
                        SUM(CASE WHEN {user_ai_sql} THEN 1 ELSE 0 END) AS total_ai_referred_human_traffic,
                        SUM(CASE WHEN {user_ai_chatgpt_sql} THEN 1 ELSE 0 END) AS chatgpt,
                        SUM(CASE WHEN {user_ai_perplexity_sql} THEN 1 ELSE 0 END) AS perplexity
                    FROM requests
                    WHERE {where_sql}
                    GROUP BY request_day
                    ORDER BY request_day
                    """,
                    params,
                )
            ]

            bot_rows = [
                dict(row)
                for row in conn.execute(
                    f"""
                    SELECT
                        repo_category,
                        COALESCE(NULLIF(repo_channel, ''), NULLIF(bot_family, ''), 'Unknown') AS platform,
                        COUNT(*) AS requests
                    FROM requests
                    WHERE {where_sql}
                      AND {focused_ai_sql}
                    GROUP BY repo_category, platform
                    ORDER BY repo_category, requests DESC, platform
                    """,
                    params,
                )
            ]

            page_rows = [
                dict(row)
                for row in conn.execute(
                    f"""
                    SELECT
                        normalized_page AS page,
                        SUM(CASE WHEN {focused_ai_sql} THEN 1 ELSE 0 END) AS ai_requests,
                        SUM(CASE WHEN {focused_user_sql} THEN 1 ELSE 0 END) AS user_requests,
                        SUM(CASE WHEN {user_traditional_sql} THEN 1 ELSE 0 END) AS user_traditional,
                        SUM(CASE WHEN {user_ai_sql} THEN 1 ELSE 0 END) AS user_ai,
                        SUM(CASE WHEN {ai_search_focused_sql} THEN 1 ELSE 0 END) AS ai_search,
                        SUM(CASE WHEN {ai_training_focused_sql} THEN 1 ELSE 0 END) AS ai_training,
                        SUM(CASE WHEN {ai_index_focused_sql} THEN 1 ELSE 0 END) AS ai_index
                    FROM requests
                    WHERE {where_sql}
                      AND normalized_page IS NOT NULL
                      AND normalized_page <> ''
                      AND is_clean_path = 1
                    GROUP BY normalized_page
                    HAVING SUM(CASE WHEN {focused_ai_sql} THEN 1 ELSE 0 END) > 0
                    ORDER BY ai_requests DESC, normalized_page
                    LIMIT ?
                    """,
                    [*params, max(top_pages, 1)],
                )
            ]

            access_rows = [
                dict(row)
                for row in conn.execute(
                    f"""
                    SELECT
                        request_time,
                        normalized_page AS page,
                        status,
                        referer,
                        repo_category,
                        repo_channel,
                        bot_family,
                        bot_category,
                        actor_bucket,
                        actor_type
                    FROM requests
                    WHERE {where_sql}
                      AND (
                        {focused_user_sql}
                        OR {focused_ai_sql}
                      )
                    ORDER BY request_time DESC
                    LIMIT 8
                    """,
                    params,
                )
            ]

        latest = trend_rows[-1] if trend_rows else {}

        human_total = int(human_row["total_human_traffic"] or 0)
        ai_total = int(ai_row["total_ai_traffic"] or 0)
        ai_rankings = {
            "ai_search": [],
            "ai_training": [],
            "ai_index": [],
        }
        for row in bot_rows:
            category = row["repo_category"]
            if category in ai_rankings and len(ai_rankings[category]) < max(top_bots, 1):
                ai_rankings[category].append(
                    {
                        "platform": row["platform"],
                        "requests": row["requests"],
                    }
                )
        referred_total = int(human_referred_row["total_ai_referred_human_traffic"] or 0)
        referred_chatgpt = int(human_referred_row["chatgpt"] or 0)
        referred_perplexity = int(human_referred_row["perplexity"] or 0)
        prev_referred_total = int(prev_human_referred_row["total_ai_referred_human_traffic"] or 0)
        prev_referred_chatgpt = int(prev_human_referred_row["chatgpt"] or 0)
        prev_referred_perplexity = int(prev_human_referred_row["perplexity"] or 0)
        referred_other = max(referred_total - referred_chatgpt - referred_perplexity, 0)
        prev_referred_other = max(prev_referred_total - prev_referred_chatgpt - prev_referred_perplexity, 0)
        return {
            "meta": {
                "customer_name": selected_customer or "ALL",
                "host": host or "ALL",
                "date_from": date_from or (card_row["date_from"] if card_row else ""),
                "date_to": date_to or (card_row["date_to"] if card_row else ""),
                "top_bots": max(top_bots, 1),
                "top_pages": max(top_pages, 1),
                "exclude_sensitive_pages": exclude_sensitive_pages,
                "previous_date_from": previous_window.start if previous_window else "",
                "previous_date_to": previous_window.end if previous_window else "",
            },
            "cards": {
                "total_requests": card_row["total_requests"] or 0,
                "user_requests": card_row["user_requests"] or 0,
                "ai_requests": card_row["ai_requests"] or 0,
                "human_requests": card_row["user_requests"] or 0,
                "bot_requests": card_row["ai_requests"] or 0,
                "active_users": card_row["active_users"] or 0,
                "active_ai_actors": card_row["active_ai_actors"] or 0,
                "active_bot_actors": card_row["active_ai_actors"] or 0,
                "latest_date": latest.get("date", ""),
                "latest_total_requests": latest.get("total_requests", 0),
            },
            "trend": trend_rows,
            "human_summary": {
                "total_human_traffic": human_total,
                "change_pct": self._calc_change_pct(human_total, int(prev_human_row["total_human_traffic"] or 0)),
                "human_ai_channel": human_row["human_ai_channel"] or 0,
                "human_ai_channel_change_pct": self._calc_change_pct(int(human_row["human_ai_channel"] or 0), int(prev_human_row["human_ai_channel"] or 0)),
                "human_ai_channel_share_ratio_pct": self._calc_share_pct(int(human_row["human_ai_channel"] or 0), human_total),
                "human_traditional_channel": human_row["human_traditional_channel"] or 0,
                "human_traditional_channel_change_pct": self._calc_change_pct(int(human_row["human_traditional_channel"] or 0), int(prev_human_row["human_traditional_channel"] or 0)),
                "human_traditional_channel_share_ratio_pct": self._calc_share_pct(int(human_row["human_traditional_channel"] or 0), human_total),
                "human_platform_channel": human_row["human_platform_channel"] or 0,
                "human_platform_channel_change_pct": self._calc_change_pct(int(human_row["human_platform_channel"] or 0), int(prev_human_row["human_platform_channel"] or 0)),
                "human_platform_channel_share_ratio_pct": self._calc_share_pct(int(human_row["human_platform_channel"] or 0), human_total),
                "human_direct_channel": human_row["human_direct_channel"] or 0,
                "human_direct_channel_change_pct": self._calc_change_pct(int(human_row["human_direct_channel"] or 0), int(prev_human_row["human_direct_channel"] or 0)),
                "human_direct_channel_share_ratio_pct": self._calc_share_pct(int(human_row["human_direct_channel"] or 0), human_total),
                "human_platform_combined_channel": int(human_row["human_platform_channel"] or 0) + int(human_row["human_direct_channel"] or 0),
                "human_platform_combined_channel_change_pct": self._calc_change_pct(
                    int(human_row["human_platform_channel"] or 0) + int(human_row["human_direct_channel"] or 0),
                    int(prev_human_row["human_platform_channel"] or 0) + int(prev_human_row["human_direct_channel"] or 0),
                ),
                "human_platform_combined_channel_share_ratio_pct": self._calc_share_pct(
                    int(human_row["human_platform_channel"] or 0) + int(human_row["human_direct_channel"] or 0),
                    human_total,
                ),
            },
            "ai_summary": {
                "total_ai_traffic": ai_total,
                "change_pct": self._calc_change_pct(ai_total, int(prev_ai_row["total_ai_traffic"] or 0)),
                "ai_search": ai_row["ai_search"] or 0,
                "ai_search_change_pct": self._calc_change_pct(int(ai_row["ai_search"] or 0), int(prev_ai_row["ai_search"] or 0)),
                "ai_search_share_ratio_pct": self._calc_share_pct(int(ai_row["ai_search"] or 0), ai_total),
                "ai_training": ai_row["ai_training"] or 0,
                "ai_training_change_pct": self._calc_change_pct(int(ai_row["ai_training"] or 0), int(prev_ai_row["ai_training"] or 0)),
                "ai_training_share_ratio_pct": self._calc_share_pct(int(ai_row["ai_training"] or 0), ai_total),
                "ai_index": ai_row["ai_index"] or 0,
                "ai_index_change_pct": self._calc_change_pct(int(ai_row["ai_index"] or 0), int(prev_ai_row["ai_index"] or 0)),
                "ai_index_share_ratio_pct": self._calc_share_pct(int(ai_row["ai_index"] or 0), ai_total),
            },
            "human_trend": human_trend_rows,
            "ai_trend": ai_trend_rows,
            "human_referred_summary": {
                "total_ai_referred_human_traffic": referred_total,
                "change_pct": self._calc_change_pct(referred_total, prev_referred_total),
                "chatgpt": referred_chatgpt,
                "chatgpt_change_pct": self._calc_change_pct(referred_chatgpt, prev_referred_chatgpt),
                "chatgpt_share_ratio_pct": self._calc_share_pct(referred_chatgpt, referred_total),
                "perplexity": referred_perplexity,
                "perplexity_change_pct": self._calc_change_pct(referred_perplexity, prev_referred_perplexity),
                "perplexity_share_ratio_pct": self._calc_share_pct(referred_perplexity, referred_total),
                "other_ai_referred": referred_other,
                "other_ai_referred_change_pct": self._calc_change_pct(referred_other, prev_referred_other),
                "other_ai_referred_share_ratio_pct": self._calc_share_pct(referred_other, referred_total),
            },
            "human_referred_trend": [
                {
                    "date": row["date"],
                    "total_ai_referred_human_traffic": int(row["total_ai_referred_human_traffic"] or 0),
                    "chatgpt": int(row["chatgpt"] or 0),
                    "perplexity": int(row["perplexity"] or 0),
                    "other_ai_referred": max(
                        int(row["total_ai_referred_human_traffic"] or 0) - int(row["chatgpt"] or 0) - int(row["perplexity"] or 0),
                        0,
                    ),
                }
                for row in human_referred_trend_rows
            ],
            "ai_category_rankings": ai_rankings,
            "top_bots": bot_rows,
            "top_pages": page_rows,
            "page_ranking": page_rows,
            "access_records": [
                {
                    "access_time": row["request_time"],
                    "traffic_type": "ai" if row["actor_type"] in ("bot", "automation") else "user",
                    "traffic_channel": (
                        (row["repo_channel"] or row["bot_family"] or "Unknown")
                        if row["actor_type"] in ("bot", "automation")
                        else (
                            row["repo_channel"] or (
                                "Traditional Channel" if row["repo_category"] == "user_traditional"
                                else "Platform Channel" if row["repo_category"] == "user_platform"
                                else "Direct"
                            )
                        )
                    ),
                    "webpage": row["page"] or "",
                    "access_status": "Success" if row["status"] and int(row["status"]) < 400 else "Failure",
                }
                for row in access_rows
            ],
        }

    def _get_filtered_dashboard_live(
        self,
        customer: str | None,
        host: str | None,
        date_from: str,
        date_to: str,
        top_bots: int,
        top_pages: int,
        exclude_sensitive_pages: bool,
    ) -> dict[str, Any]:
        previous_window = self._calc_previous_window(date_from, date_to)
        start_utc, end_utc = local_day_to_utc_bounds(date_from, date_to)
        current_indices = filter_index_options(
            self.remote_source.list_index_options(start_utc=start_utc, end_utc=end_utc),
            customer,
            None,
            date_from=date_from,
            date_to=date_to,
        )
        current_index_names = [str(item.get("value") or "") for item in current_indices if item.get("value")]
        if customer and customer != "ALL" and not current_index_names:
            return self._empty_live_dashboard_payload(customer, host, date_from, date_to, top_bots, top_pages, exclude_sensitive_pages, previous_window)
        host_filters = [host] if host and host != "ALL" else None
        current = self.remote_source.get_live_dashboard_window(
            index_names=current_index_names,
            host_filters=host_filters,
            start_utc=start_utc,
            end_utc=end_utc,
            top_bots=top_bots,
            top_pages=top_pages,
            include_rankings=True,
        )
        previous = {"focused": {}, "human_referred": {}}
        access_rows = self.remote_source.get_recent_dashboard_records(
            index_names=current_index_names,
            host_filters=host_filters,
            start_utc=start_utc,
            end_utc=end_utc,
            limit=8,
        )

        focused = current["focused"]
        prev_focused = previous.get("focused", {})
        referred = current["human_referred"]
        prev_referred = previous.get("human_referred", {})
        human_total = int(focused.get("user_traditional", 0) + focused.get("user_ai", 0) + focused.get("user_platform", 0) + focused.get("user_direct", 0))
        prev_human_total = int(prev_focused.get("user_traditional", 0) + prev_focused.get("user_ai", 0) + prev_focused.get("user_platform", 0) + prev_focused.get("user_direct", 0))
        ai_total = int(focused.get("ai_search", 0) + focused.get("ai_training", 0) + focused.get("ai_index", 0))
        prev_ai_total = int(prev_focused.get("ai_search", 0) + prev_focused.get("ai_training", 0) + prev_focused.get("ai_index", 0))
        referred_total = int(referred.get("total", 0))
        prev_referred_total = int(prev_referred.get("total", 0))
        referred_chatgpt = int(referred.get("chatgpt", 0))
        prev_referred_chatgpt = int(prev_referred.get("chatgpt", 0))
        referred_perplexity = int(referred.get("perplexity", 0))
        prev_referred_perplexity = int(prev_referred.get("perplexity", 0))
        referred_other = max(referred_total - referred_chatgpt - referred_perplexity, 0)
        prev_referred_other = max(prev_referred_total - prev_referred_chatgpt - prev_referred_perplexity, 0)

        trend_rows = []
        human_trend_rows = []
        ai_trend_rows = []
        human_referred_trend_rows = []
        for row in current["days"]:
            day_human_total = int(row.get("user_traditional", 0) + row.get("user_ai", 0) + row.get("user_platform", 0) + row.get("user_direct", 0))
            day_ai_total = int(row.get("ai_search", 0) + row.get("ai_training", 0) + row.get("ai_index", 0))
            day_referred_total = int(row.get("referred_total", 0))
            day_referred_chatgpt = int(row.get("referred_chatgpt", 0))
            day_referred_perplexity = int(row.get("referred_perplexity", 0))
            trend_rows.append(
                {
                    "date": row["date"],
                    "total_requests": day_human_total + day_ai_total,
                    "user_requests": day_human_total,
                    "ai_requests": day_ai_total,
                    "active_users": 0,
                }
            )
            human_trend_rows.append(
                {
                    "date": row["date"],
                    "total_human_traffic": day_human_total,
                    "human_ai_channel": int(row.get("user_ai", 0)),
                    "human_traditional_channel": int(row.get("user_traditional", 0)),
                    "human_platform_channel": int(row.get("user_platform", 0)),
                    "human_direct_channel": int(row.get("user_direct", 0)),
                    "human_platform_combined_channel": int(row.get("user_platform", 0)) + int(row.get("user_direct", 0)),
                }
            )
            ai_trend_rows.append(
                {
                    "date": row["date"],
                    "total_ai_traffic": day_ai_total,
                    "ai_search": int(row.get("ai_search", 0)),
                    "ai_training": int(row.get("ai_training", 0)),
                    "ai_index": int(row.get("ai_index", 0)),
                }
            )
            human_referred_trend_rows.append(
                {
                    "date": row["date"],
                    "total_ai_referred_human_traffic": day_referred_total,
                    "chatgpt": day_referred_chatgpt,
                    "perplexity": day_referred_perplexity,
                    "other_ai_referred": max(day_referred_total - day_referred_chatgpt - day_referred_perplexity, 0),
                }
            )

        latest = trend_rows[-1] if trend_rows else {}
        ai_category_rankings = current.get("ai_category_rankings", {"ai_search": [], "ai_training": [], "ai_index": []})
        top_bots_rows = []
        for key in ("ai_search", "ai_training", "ai_index"):
            for item in ai_category_rankings.get(key, []):
                top_bots_rows.append({"repo_category": key, "platform": item["platform"], "requests": item["requests"]})

        return {
            "meta": {
                "customer_name": customer or "ALL",
                "host": host or "ALL",
                "date_from": date_from,
                "date_to": date_to,
                "top_bots": max(top_bots, 1),
                "top_pages": max(top_pages, 1),
                "exclude_sensitive_pages": exclude_sensitive_pages,
                "previous_date_from": previous_window.start if previous_window else "",
                "previous_date_to": previous_window.end if previous_window else "",
            },
            "cards": {
                "total_requests": human_total + ai_total,
                "user_requests": human_total,
                "ai_requests": ai_total,
                "human_requests": human_total,
                "bot_requests": ai_total,
                "active_users": 0,
                "active_ai_actors": 0,
                "active_bot_actors": 0,
                "latest_date": latest.get("date", ""),
                "latest_total_requests": latest.get("total_requests", 0),
            },
            "trend": trend_rows,
            "human_summary": {
                "total_human_traffic": human_total,
                "change_pct": self._calc_change_pct(human_total, prev_human_total),
                "human_ai_channel": int(focused.get("user_ai", 0)),
                "human_ai_channel_change_pct": self._calc_change_pct(int(focused.get("user_ai", 0)), int(prev_focused.get("user_ai", 0))),
                "human_ai_channel_share_ratio_pct": self._calc_share_pct(int(focused.get("user_ai", 0)), human_total),
                "human_traditional_channel": int(focused.get("user_traditional", 0)),
                "human_traditional_channel_change_pct": self._calc_change_pct(int(focused.get("user_traditional", 0)), int(prev_focused.get("user_traditional", 0))),
                "human_traditional_channel_share_ratio_pct": self._calc_share_pct(int(focused.get("user_traditional", 0)), human_total),
                "human_platform_channel": int(focused.get("user_platform", 0)),
                "human_platform_channel_change_pct": self._calc_change_pct(int(focused.get("user_platform", 0)), int(prev_focused.get("user_platform", 0))),
                "human_platform_channel_share_ratio_pct": self._calc_share_pct(int(focused.get("user_platform", 0)), human_total),
                "human_direct_channel": int(focused.get("user_direct", 0)),
                "human_direct_channel_change_pct": self._calc_change_pct(int(focused.get("user_direct", 0)), int(prev_focused.get("user_direct", 0))),
                "human_direct_channel_share_ratio_pct": self._calc_share_pct(int(focused.get("user_direct", 0)), human_total),
                "human_platform_combined_channel": int(focused.get("user_platform", 0)) + int(focused.get("user_direct", 0)),
                "human_platform_combined_channel_change_pct": self._calc_change_pct(
                    int(focused.get("user_platform", 0)) + int(focused.get("user_direct", 0)),
                    int(prev_focused.get("user_platform", 0)) + int(prev_focused.get("user_direct", 0)),
                ),
                "human_platform_combined_channel_share_ratio_pct": self._calc_share_pct(
                    int(focused.get("user_platform", 0)) + int(focused.get("user_direct", 0)),
                    human_total,
                ),
            },
            "ai_summary": {
                "total_ai_traffic": ai_total,
                "change_pct": self._calc_change_pct(ai_total, prev_ai_total),
                "ai_search": int(focused.get("ai_search", 0)),
                "ai_search_change_pct": self._calc_change_pct(int(focused.get("ai_search", 0)), int(prev_focused.get("ai_search", 0))),
                "ai_search_share_ratio_pct": self._calc_share_pct(int(focused.get("ai_search", 0)), ai_total),
                "ai_training": int(focused.get("ai_training", 0)),
                "ai_training_change_pct": self._calc_change_pct(int(focused.get("ai_training", 0)), int(prev_focused.get("ai_training", 0))),
                "ai_training_share_ratio_pct": self._calc_share_pct(int(focused.get("ai_training", 0)), ai_total),
                "ai_index": int(focused.get("ai_index", 0)),
                "ai_index_change_pct": self._calc_change_pct(int(focused.get("ai_index", 0)), int(prev_focused.get("ai_index", 0))),
                "ai_index_share_ratio_pct": self._calc_share_pct(int(focused.get("ai_index", 0)), ai_total),
            },
            "human_trend": human_trend_rows,
            "ai_trend": ai_trend_rows,
            "human_referred_summary": {
                "total_ai_referred_human_traffic": referred_total,
                "change_pct": self._calc_change_pct(referred_total, prev_referred_total),
                "chatgpt": referred_chatgpt,
                "chatgpt_change_pct": self._calc_change_pct(referred_chatgpt, prev_referred_chatgpt),
                "chatgpt_share_ratio_pct": self._calc_share_pct(referred_chatgpt, referred_total),
                "perplexity": referred_perplexity,
                "perplexity_change_pct": self._calc_change_pct(referred_perplexity, prev_referred_perplexity),
                "perplexity_share_ratio_pct": self._calc_share_pct(referred_perplexity, referred_total),
                "other_ai_referred": referred_other,
                "other_ai_referred_change_pct": self._calc_change_pct(referred_other, prev_referred_other),
                "other_ai_referred_share_ratio_pct": self._calc_share_pct(referred_other, referred_total),
            },
            "human_referred_trend": human_referred_trend_rows,
            "ai_category_rankings": ai_category_rankings,
            "top_bots": top_bots_rows,
            "top_pages": current.get("page_ranking", []),
            "page_ranking": current.get("page_ranking", []),
            "access_records": access_rows,
        }

    def _empty_live_dashboard_payload(
        self,
        customer: str | None,
        host: str | None,
        date_from: str,
        date_to: str,
        top_bots: int,
        top_pages: int,
        exclude_sensitive_pages: bool,
        previous_window: DateWindow | None,
    ) -> dict[str, Any]:
        return {
            "meta": {
                "customer_name": customer or "ALL",
                "host": host or "ALL",
                "date_from": date_from,
                "date_to": date_to,
                "top_bots": max(top_bots, 1),
                "top_pages": max(top_pages, 1),
                "exclude_sensitive_pages": exclude_sensitive_pages,
                "previous_date_from": previous_window.start if previous_window else "",
                "previous_date_to": previous_window.end if previous_window else "",
            },
            "cards": {
                "total_requests": 0,
                "user_requests": 0,
                "ai_requests": 0,
                "human_requests": 0,
                "bot_requests": 0,
                "active_users": 0,
                "active_ai_actors": 0,
                "active_bot_actors": 0,
                "latest_date": "",
                "latest_total_requests": 0,
            },
            "trend": [],
            "human_summary": {
                "total_human_traffic": 0,
                "change_pct": None,
                "human_ai_channel": 0,
                "human_ai_channel_change_pct": None,
                "human_ai_channel_share_ratio_pct": 0.0,
                "human_traditional_channel": 0,
                "human_traditional_channel_change_pct": None,
                "human_traditional_channel_share_ratio_pct": 0.0,
                "human_platform_channel": 0,
                "human_platform_channel_change_pct": None,
                "human_platform_channel_share_ratio_pct": 0.0,
                "human_direct_channel": 0,
                "human_direct_channel_change_pct": None,
                "human_direct_channel_share_ratio_pct": 0.0,
                "human_platform_combined_channel": 0,
                "human_platform_combined_channel_change_pct": None,
                "human_platform_combined_channel_share_ratio_pct": 0.0,
            },
            "ai_summary": {
                "total_ai_traffic": 0,
                "change_pct": None,
                "ai_search": 0,
                "ai_search_change_pct": None,
                "ai_search_share_ratio_pct": 0.0,
                "ai_training": 0,
                "ai_training_change_pct": None,
                "ai_training_share_ratio_pct": 0.0,
                "ai_index": 0,
                "ai_index_change_pct": None,
                "ai_index_share_ratio_pct": 0.0,
            },
            "human_trend": [],
            "ai_trend": [],
            "human_referred_summary": {
                "total_ai_referred_human_traffic": 0,
                "change_pct": None,
                "chatgpt": 0,
                "chatgpt_change_pct": None,
                "chatgpt_share_ratio_pct": 0.0,
                "perplexity": 0,
                "perplexity_change_pct": None,
                "perplexity_share_ratio_pct": 0.0,
                "other_ai_referred": 0,
                "other_ai_referred_change_pct": None,
                "other_ai_referred_share_ratio_pct": 0.0,
            },
            "human_referred_trend": [],
            "ai_category_rankings": {"ai_search": [], "ai_training": [], "ai_index": []},
            "top_bots": [],
            "top_pages": [],
            "page_ranking": [],
            "access_records": [],
        }

    def _build_frontend_dashboard_payload(
        self,
        snapshot: dict[str, Any],
        overview_rows: list[dict[str, Any]],
        user_rows: list[dict[str, Any]],
        page_rows: list[dict[str, Any]],
        metadata: dict[str, str],
        top_bots: int = 10,
        top_pages: int = 10,
    ) -> dict[str, Any]:
        latest_day = overview_rows[-1] if overview_rows else {}
        bot_rows = snapshot.get("top_bot_families", [])[: max(top_bots, 1)]
        top_pages_rows = snapshot.get("top_pages", [])[: max(top_pages, 1)]
        metrics = snapshot.get("metrics", {})
        cards = {
            "total_requests": metrics.get("total_requests", 0),
            "total_users": metrics.get("total_users", 0),
            "total_bot_families": len(
                {
                    row.get("bot_family", "")
                    for row in snapshot.get("bot_feature_breakdown", [])
                    if row.get("bot_family")
                }
            ),
            "total_human_sessions": metrics.get("total_human_sessions", 0),
            "total_bot_sessions": metrics.get("total_bot_sessions", 0),
            "latest_date": latest_day.get("date", ""),
            "latest_total_requests": latest_day.get("total_requests", 0),
            "latest_human_requests": latest_day.get("human_requests", 0),
            "latest_bot_requests": latest_day.get("bot_requests", 0),
            "latest_active_users": latest_day.get("active_users", 0),
            "latest_new_users": latest_day.get("new_users", 0),
        }
        chart_series = [
            {
                "date": row["date"],
                "total_requests": row["total_requests"],
                "human_requests": row["human_requests"],
                "bot_requests": row["bot_requests"],
                "active_users": row["active_users"],
                "new_users": row["new_users"],
                "human_sessions": row["human_sessions"],
                "bot_sessions": row["bot_sessions"],
            }
            for row in overview_rows
        ]
        bot_cards = [
            {
                "bot_family": row.get("bot_family", ""),
                "bot_category": row.get("bot_category", ""),
                "actor_bucket": row.get("actor_bucket", ""),
                "requests": row.get("requests", 0),
            }
            for row in bot_rows
        ]
        page_cards = [
            {
                "page": row.get("page", ""),
                "requests": row.get("requests", 0),
            }
            for row in top_pages_rows
        ]
        recent_users = [
            {
                "date": row["date"],
                "user_id": row["user_id"],
                "requests": row["requests"],
                "sessions": row["sessions"],
                "is_new_user": row["is_new_user"],
                "first_page": row["first_page"],
                "last_page": row["last_page"],
            }
            for row in user_rows
        ]
        active_pages = [
            {
                "date": row["date"],
                "page": row["page"],
                "human_requests": row["human_requests"],
                "human_sessions": row["human_sessions"],
                "bot_requests": row["bot_requests"],
                "bot_sessions": row["bot_sessions"],
            }
            for row in page_rows
        ]
        return {
            "meta": {
                "source": "frontend-dashboard",
                "generated_at": snapshot.get("generated_at", ""),
                "last_refresh_at": metadata.get("last_refresh_at", ""),
            },
            "cards": cards,
            "trend": chart_series,
            "top_bots": bot_cards,
            "top_pages": page_cards,
            "recent_users": recent_users,
            "active_pages": active_pages,
        }

    def get_bot_catalog(self) -> list[dict[str, Any]]:
        self._ensure_fresh_daily_sync()
        query = """
        SELECT
            bot_family,
            bot_category,
            actor_bucket,
            bot_vendor,
            bot_product,
            bot_purpose,
            bot_description,
            actor_type,
            COUNT(*) AS requests,
            COUNT(DISTINCT session_actor_key) AS unique_actors,
            MIN(request_time) AS first_seen,
            MAX(request_time) AS last_seen,
            MIN(user_agent) AS sample_user_agent
        FROM requests
        WHERE actor_type IN ('bot', 'automation')
        GROUP BY bot_family, bot_category, actor_bucket, bot_vendor, bot_product, bot_purpose, bot_description, actor_type
        ORDER BY requests DESC, bot_family
        """
        with self._full_conn() as conn:
            return [dict(row) for row in conn.execute(query)]

    def get_user_detail(self, user_id: str) -> dict[str, Any] | None:
        self._ensure_fresh_daily_sync()
        with self._full_conn() as conn:
            user_row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
            if not user_row:
                return None
            sessions = [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM human_sessions WHERE user_id = ? ORDER BY start_time DESC LIMIT 100",
                    (user_id,),
                )
            ]
            activity = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT request_day AS date, COUNT(*) AS requests
                    FROM requests
                    WHERE user_id = ? AND is_counted_user = 1
                    GROUP BY request_day
                    ORDER BY request_day DESC
                    LIMIT 100
                    """,
                    (user_id,),
                )
            ]
        return {
            "user": dict(user_row),
            "recent_sessions": sessions,
            "daily_activity": activity,
        }

    def _ensure_fresh_daily_sync(self) -> None:
        if not self.allow_on_demand_sync:
            return
        current_day = datetime.now().strftime("%Y-%m-%d")
        with self._increment_conn() as conn:
            last_refresh = conn.execute("SELECT value FROM metadata WHERE key = 'last_refresh_day'").fetchone()
        if not last_refresh or last_refresh[0] != current_day:
            self.sync_from_local_logs()

    def _full_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.full_db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    def _increment_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.increment_db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    def _ensure_full_schema(self) -> None:
        self.full_db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._full_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY,
                    source_kind TEXT NOT NULL,
                    source_side TEXT NOT NULL,
                    source_ref TEXT,
                    request_time TEXT NOT NULL,
                    request_day TEXT NOT NULL,
                    method TEXT,
                    uri TEXT,
                    args TEXT,
                    normalized_page TEXT,
                    page_exclusion_reason TEXT,
                    is_page_request INTEGER NOT NULL,
                    status INTEGER,
                    bytes_sent INTEGER,
                    host TEXT,
                    customer_domain TEXT,
                    referer TEXT,
                    proxy_ip TEXT,
                    client_ip TEXT,
                    user_agent TEXT,
                    fingerprint TEXT,
                    browser TEXT,
                    os TEXT,
                    device_type TEXT,
                    actor_type TEXT,
                    actor_bucket TEXT,
                    bot_category TEXT,
                    bot_family TEXT,
                    bot_vendor TEXT,
                    bot_product TEXT,
                    bot_purpose TEXT,
                    bot_description TEXT,
                    match_token TEXT,
                    repo_category TEXT,
                    repo_channel TEXT,
                    identity_confidence TEXT,
                    user_key TEXT,
                    user_id TEXT,
                    session_actor_key TEXT,
                    is_target_method INTEGER NOT NULL,
                    is_in_report_window INTEGER NOT NULL DEFAULT 0,
                    is_clean_path INTEGER NOT NULL,
                    is_counted_user INTEGER NOT NULL DEFAULT 0,
                    is_counted_bot INTEGER NOT NULL DEFAULT 0,
                    inserted_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS source_files (
                    file_path TEXT PRIMARY KEY,
                    size_bytes INTEGER NOT NULL,
                    modified_at TEXT NOT NULL,
                    ingested_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    user_key TEXT UNIQUE NOT NULL,
                    first_seen TEXT NOT NULL,
                    first_day TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_day TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    identity_confidence TEXT NOT NULL,
                    sample_client_ip TEXT,
                    sample_user_agent TEXT,
                    browser TEXT,
                    os TEXT,
                    device_type TEXT,
                    first_page TEXT,
                    last_page TEXT,
                    request_count INTEGER NOT NULL,
                    active_days INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS human_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    request_day TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    source_side TEXT NOT NULL,
                    entry_page TEXT,
                    referer TEXT,
                    pageviews INTEGER NOT NULL,
                    duration_seconds INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS bot_sessions (
                    session_id TEXT PRIMARY KEY,
                    session_actor_key TEXT NOT NULL,
                    request_day TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    source_side TEXT NOT NULL,
                    bot_category TEXT,
                    bot_family TEXT,
                    actor_bucket TEXT,
                    entry_page TEXT,
                    referer TEXT,
                    pageviews INTEGER NOT NULL,
                    duration_seconds INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_requests_day ON requests(request_day);
                CREATE INDEX IF NOT EXISTS idx_requests_user ON requests(user_id, request_time);
                CREATE INDEX IF NOT EXISTS idx_requests_counted_user ON requests(is_counted_user, request_day);
                CREATE INDEX IF NOT EXISTS idx_requests_counted_bot ON requests(is_counted_bot, request_day);
                CREATE INDEX IF NOT EXISTS idx_requests_session_actor ON requests(session_actor_key, request_time);
                CREATE INDEX IF NOT EXISTS idx_requests_actor_type ON requests(actor_type, request_day);
                CREATE INDEX IF NOT EXISTS idx_requests_host_day ON requests(host, request_day);
                CREATE INDEX IF NOT EXISTS idx_requests_host_page ON requests(host, normalized_page);
                CREATE INDEX IF NOT EXISTS idx_human_sessions_day ON human_sessions(request_day);
                CREATE INDEX IF NOT EXISTS idx_bot_sessions_day ON bot_sessions(request_day);
                """
            )
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(requests)")}
            if "args" not in columns:
                conn.execute("ALTER TABLE requests ADD COLUMN args TEXT")
            if "repo_category" not in columns:
                conn.execute("ALTER TABLE requests ADD COLUMN repo_category TEXT")
            if "repo_channel" not in columns:
                conn.execute("ALTER TABLE requests ADD COLUMN repo_channel TEXT")
            if "customer_domain" not in columns:
                conn.execute("ALTER TABLE requests ADD COLUMN customer_domain TEXT")
            conn.commit()

    def _ensure_increment_schema(self) -> None:
        self.increment_db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._increment_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS daily_overview (
                    date TEXT PRIMARY KEY,
                    total_requests INTEGER NOT NULL,
                    human_requests INTEGER NOT NULL,
                    app_webview_requests INTEGER NOT NULL,
                    bot_requests INTEGER NOT NULL,
                    countable_bot_requests INTEGER NOT NULL,
                    automation_requests INTEGER NOT NULL,
                    human_sessions INTEGER NOT NULL,
                    bot_sessions INTEGER NOT NULL,
                    active_users INTEGER NOT NULL,
                    new_users INTEGER NOT NULL,
                    returning_users INTEGER NOT NULL,
                    cumulative_users INTEGER NOT NULL,
                    ai_retrieval_requests INTEGER NOT NULL,
                    ai_training_requests INTEGER NOT NULL,
                    ai_indexer_requests INTEGER NOT NULL,
                    seo_bot_requests INTEGER NOT NULL,
                    social_bot_requests INTEGER NOT NULL,
                    verification_bot_requests INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS daily_user_increment (
                    date TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    requests INTEGER NOT NULL,
                    sessions INTEGER NOT NULL,
                    is_new_user INTEGER NOT NULL,
                    first_request_time TEXT NOT NULL,
                    last_request_time TEXT NOT NULL,
                    first_page TEXT,
                    last_page TEXT,
                    PRIMARY KEY (date, user_id)
                );

                CREATE TABLE IF NOT EXISTS daily_bot_increment (
                    date TEXT NOT NULL,
                    bot_family TEXT NOT NULL,
                    bot_category TEXT NOT NULL,
                    actor_bucket TEXT NOT NULL,
                    requests INTEGER NOT NULL,
                    sessions INTEGER NOT NULL,
                    PRIMARY KEY (date, bot_family, bot_category)
                );

                CREATE TABLE IF NOT EXISTS daily_page_increment (
                    date TEXT NOT NULL,
                    page TEXT NOT NULL,
                    human_requests INTEGER NOT NULL,
                    human_sessions INTEGER NOT NULL,
                    bot_requests INTEGER NOT NULL,
                    bot_sessions INTEGER NOT NULL,
                    PRIMARY KEY (date, page)
                );

                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            conn.commit()

    def _reset_full_db(self) -> None:
        with self._full_conn() as conn:
            conn.executescript(
                """
                DELETE FROM requests;
                DELETE FROM source_files;
                DELETE FROM users;
                DELETE FROM human_sessions;
                DELETE FROM bot_sessions;
                DELETE FROM metadata;
                """
            )
            conn.commit()

    def _reset_increment_db(self) -> None:
        with self._increment_conn() as conn:
            conn.executescript(
                """
                DELETE FROM daily_overview;
                DELETE FROM daily_user_increment;
                DELETE FROM daily_bot_increment;
                DELETE FROM daily_page_increment;
                DELETE FROM metadata;
                """
            )
            conn.commit()

    def _get_file_state(self, path: Path) -> sqlite3.Row | None:
        with self._full_conn() as conn:
            return conn.execute("SELECT * FROM source_files WHERE file_path = ?", (str(path),)).fetchone()

    def _should_scan_file(self, path: Path, state: sqlite3.Row | None) -> bool:
        stat = path.stat()
        modified_at = datetime.fromtimestamp(stat.st_mtime).isoformat()
        if not state:
            return True
        return state["size_bytes"] != stat.st_size or state["modified_at"] != modified_at

    def _upsert_file_state(self, path: Path) -> None:
        stat = path.stat()
        modified_at = datetime.fromtimestamp(stat.st_mtime).isoformat()
        with self._full_conn() as conn:
            conn.execute(
                """
                INSERT INTO source_files(file_path, size_bytes, modified_at, ingested_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(file_path) DO UPDATE SET
                    size_bytes = excluded.size_bytes,
                    modified_at = excluded.modified_at,
                    ingested_at = excluded.ingested_at
                """,
                (str(path), stat.st_size, modified_at, datetime.now().isoformat()),
            )
            conn.commit()

    def _list_local_log_files(self) -> list[Path]:
        if not self.log_dir.exists():
            return []
        return sorted(self.log_dir.glob("moseeker_b_side_access_*.log"))

    def _ingest_log_file(self, path: Path) -> IngestResult:
        inserted = 0
        duplicates = 0
        affected_days: set[str] = set()
        side = "b"
        batch: list[dict[str, Any]] = []

        with self._full_conn() as conn:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for raw_line in handle:
                    row = self._build_request_row(side, raw_line.rstrip("\n"), source_kind="file", source_ref=str(path))
                    if row is None:
                        continue
                    batch.append(row)
                    if len(batch) >= 1000:
                        inserted_delta, duplicates_delta = self._insert_request_rows(conn, batch)
                        inserted += inserted_delta
                        duplicates += duplicates_delta
                        affected_days.update(row["request_day"] for row in batch if row["request_day"])
                        batch.clear()
                if batch:
                    inserted_delta, duplicates_delta = self._insert_request_rows(conn, batch)
                    inserted += inserted_delta
                    duplicates += duplicates_delta
                    affected_days.update(row["request_day"] for row in batch if row["request_day"])
            conn.commit()
        return IngestResult(inserted=inserted, duplicates=duplicates, affected_days=affected_days)

    def _ingest_remote_logs(self) -> IngestResult:
        inserted = 0
        duplicates = 0
        affected_days: set[str] = set()
        with self._full_conn() as conn:
            latest = conn.execute("SELECT MAX(request_time) FROM requests").fetchone()[0]
            since = self.remote_source.estimate_since(latest)
            batch: list[dict[str, Any]] = []
            for item in self.remote_source.iter_logs(since=since):
                row = self._build_request_row(
                    "b",
                    item,
                    source_kind="remote_kibana",
                    source_ref=self.remote_source.source_ref_label(),
                )
                if row is None:
                    continue
                batch.append(row)
                if len(batch) >= 1000:
                    inserted_delta, duplicates_delta = self._insert_request_rows(conn, batch)
                    inserted += inserted_delta
                    duplicates += duplicates_delta
                    affected_days.update(row["request_day"] for row in batch if row["request_day"])
                    batch.clear()
            if batch:
                inserted_delta, duplicates_delta = self._insert_request_rows(conn, batch)
                inserted += inserted_delta
                duplicates += duplicates_delta
                affected_days.update(row["request_day"] for row in batch if row["request_day"])
            conn.commit()
        return IngestResult(inserted=inserted, duplicates=duplicates, affected_days=affected_days)

    def _build_request_row(
        self,
        side: str,
        payload: str | dict[str, Any],
        source_kind: str,
        source_ref: str,
    ) -> dict[str, Any] | None:
        try:
            if source_kind == "remote_kibana":
                item = self._parse_remote_payload(payload)
            elif side == "b":
                item = self._parse_b_payload(payload)
            else:
                item = self._parse_c_payload(payload)
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

        if not item:
            return None

        resolved_source_ref = item.get("source_ref") or source_ref
        request_time = item["request_time"]
        request_day = request_time.strftime("%Y-%m-%d")
        user_agent = item.get("user_agent", "")
        classification = classify_agent(user_agent)
        repo_classification = repo_classify_access(
            item.get("host"),
            item.get("uri"),
            item.get("args"),
            item.get("status"),
            item.get("referer"),
            user_agent,
            resolved_source_ref,
        )
        normalized_page = normalize_page(item.get("uri") or "")
        exclusion_reason = page_exclusion_reason(normalized_page)
        is_page_request = 1 if normalized_page else 0
        is_clean_path = 1 if normalized_page and not exclusion_reason else 0
        fingerprint = sha1_short(user_agent or "", 24)
        user_key, identity_confidence = derive_user_key(side, classification["actor_type"], item["client_ip"], user_agent)
        session_actor_key = derive_session_actor_key(
            classification["actor_type"],
            item["client_ip"],
            user_agent,
            user_key,
        )

        dedupe_payload = {
            "side": side,
            "source_kind": source_kind,
            "source_doc_id": item.get("source_doc_id", ""),
            "request_time": request_time.isoformat(),
            "method": item.get("method"),
            "uri": item.get("uri"),
            "args": item.get("args"),
            "status": item.get("status"),
            "host": item.get("host"),
            "client_ip": item.get("client_ip"),
            "proxy_ip": item.get("proxy_ip"),
            "referer": item.get("referer"),
            "user_agent": user_agent,
        }
        request_id = sha1_short(json.dumps(dedupe_payload, ensure_ascii=False, sort_keys=True), 32)

        return {
            "request_id": request_id,
            "source_kind": source_kind,
            "source_side": side,
            "source_ref": source_ref,
            "request_time": request_time.isoformat(sep=" "),
            "request_day": request_day,
            "method": item.get("method"),
            "uri": item.get("uri"),
            "args": item.get("args") or "",
            "normalized_page": normalized_page,
            "page_exclusion_reason": exclusion_reason or "",
            "is_page_request": is_page_request,
            "status": item.get("status"),
            "bytes_sent": item.get("bytes_sent"),
            "host": item.get("host") or "",
            "customer_domain": repo_extract_base_domain(item.get("host") or ""),
            "referer": item.get("referer") or "(direct / none)",
            "proxy_ip": item.get("proxy_ip") or "",
            "client_ip": item.get("client_ip") or "",
            "user_agent": user_agent,
            "fingerprint": fingerprint,
            "browser": browser_family(user_agent),
            "os": os_family(user_agent),
            "device_type": device_type(user_agent),
            "actor_type": classification["actor_type"],
            "actor_bucket": classification["bucket"],
            "bot_category": classification["category"],
            "bot_family": classification["family"],
            "bot_vendor": classification["vendor"],
            "bot_product": classification["product"],
            "bot_purpose": classification["purpose"],
            "bot_description": classification["description"],
            "match_token": classification["match_token"],
            "repo_category": repo_classification["category"],
            "repo_channel": repo_classification["channel"],
            "identity_confidence": identity_confidence if user_key else classification["confidence"],
            "user_key": user_key or "",
            "user_id": "",
            "session_actor_key": session_actor_key or "",
            "is_target_method": 1 if (item.get("method") or "").upper() == TARGET_METHOD else 0,
            "is_in_report_window": 0,
            "is_clean_path": is_clean_path,
            "is_counted_user": 0,
            "is_counted_bot": 0,
            "inserted_at": datetime.now().isoformat(),
        }

    def _insert_request_row(self, conn: sqlite3.Connection, row: dict[str, Any]) -> bool:
        inserted, _ = self._insert_request_rows(conn, [row])
        return inserted > 0

    def _insert_request_rows(self, conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> tuple[int, int]:
        before = conn.total_changes
        conn.executemany(
            """
            INSERT OR IGNORE INTO requests (
                request_id, source_kind, source_side, source_ref, request_time, request_day,
                method, uri, normalized_page, page_exclusion_reason, is_page_request,
                args,
                status, bytes_sent, host, customer_domain, referer, proxy_ip, client_ip, user_agent, fingerprint,
                browser, os, device_type, actor_type, actor_bucket, bot_category, bot_family,
                bot_vendor, bot_product, bot_purpose, bot_description, match_token, repo_category, repo_channel,
                identity_confidence, user_key, user_id, session_actor_key, is_target_method,
                is_in_report_window, is_clean_path, is_counted_user, is_counted_bot, inserted_at
            ) VALUES (
                :request_id, :source_kind, :source_side, :source_ref, :request_time, :request_day,
                :method, :uri, :normalized_page, :page_exclusion_reason, :is_page_request,
                :args,
                :status, :bytes_sent, :host, :customer_domain, :referer, :proxy_ip, :client_ip, :user_agent, :fingerprint,
                :browser, :os, :device_type, :actor_type, :actor_bucket, :bot_category, :bot_family,
                :bot_vendor, :bot_product, :bot_purpose, :bot_description, :match_token, :repo_category, :repo_channel,
                :identity_confidence, :user_key, :user_id, :session_actor_key, :is_target_method,
                :is_in_report_window, :is_clean_path, :is_counted_user, :is_counted_bot, :inserted_at
            )
            """,
            rows,
        )
        inserted = conn.total_changes - before
        return inserted, max(len(rows) - inserted, 0)

    def _parse_b_payload(self, payload: str | dict[str, Any]) -> dict[str, Any] | None:
        if isinstance(payload, dict):
            raw_line = payload.get("raw_line", "")
        else:
            raw_line = payload
        match = B_LINE_RE.match(raw_line)
        if not match:
            return None
        item = match.groupdict()
        request_time = datetime.strptime(item["dt"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        bytes_sent = self._to_int(item.get("bytes"))
        referer = item["referer"] if item["referer"] and item["referer"] != "-" else "(direct / none)"
        return {
            "request_time": request_time,
            "method": item.get("method") or "",
            "uri": item.get("uri") or "",
            "args": "",
            "status": self._to_int(item.get("status")),
            "bytes_sent": bytes_sent,
            "host": "",
            "referer": referer,
            "proxy_ip": normalize_ip(item.get("ip")),
            "client_ip": normalize_ip(item.get("ip")),
            "user_agent": item.get("ua") or "",
        }

    def _parse_c_payload(self, payload: str | dict[str, Any]) -> dict[str, Any] | None:
        item = json.loads(payload) if isinstance(payload, str) else payload
        ts = item.get("ts") or item.get("@timestamp")
        if not ts:
            return None
        request_time = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).replace(tzinfo=None)
        referer = item.get("referer") or "(direct / none)"
        client_ip = normalize_ip(item.get("x_forwarded_for") or item.get("remote_addr"))
        return {
            "request_time": request_time,
            "method": item.get("method") or "",
            "uri": item.get("uri") or "",
            "args": item.get("args") or "",
            "status": self._to_int(item.get("status")),
            "bytes_sent": self._to_int(item.get("bytes")),
            "host": item.get("host") or "",
            "referer": referer,
            "proxy_ip": normalize_ip(item.get("remote_addr")),
            "client_ip": client_ip,
            "user_agent": item.get("ua") or "",
        }

    def _parse_remote_payload(self, payload: str | dict[str, Any]) -> dict[str, Any] | None:
        item = json.loads(payload) if isinstance(payload, str) else payload
        ts = item.get("ts") or item.get("@timestamp")
        if not ts:
            return None
        request_time = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).replace(tzinfo=None)
        referer = item.get("referer") or "(direct / none)"
        return {
            "request_time": request_time,
            "method": item.get("method") or "",
            "uri": item.get("uri") or "",
            "args": item.get("args") or "",
            "status": self._to_int(item.get("status")),
            "bytes_sent": self._to_int(item.get("bytes")),
            "host": item.get("host") or "",
            "referer": referer,
            "proxy_ip": normalize_ip(item.get("remote_addr")),
            "client_ip": normalize_ip(item.get("remote_addr")),
            "user_agent": item.get("ua") or "",
            "source_doc_id": item.get("_id") or "",
        }

    def _rebuild_derived_tables(self) -> None:
        with self._full_conn() as conn:
            skip_before_day = self._compute_skip_before_day(conn)
            conn.execute(
                """
                UPDATE requests
                SET is_in_report_window = CASE WHEN request_day >= ? THEN 1 ELSE 0 END,
                    is_counted_user = CASE
                        WHEN request_day >= ?
                         AND repo_category IN ('user_traditional', 'user_ai', 'user_platform', 'user_direct')
                         AND user_key <> ''
                        THEN 1 ELSE 0 END,
                    is_counted_bot = CASE
                        WHEN request_day >= ?
                         AND repo_category IN ('ai_search', 'ai_training', 'ai_index')
                        THEN 1 ELSE 0 END,
                    user_id = ''
                """,
                (skip_before_day, skip_before_day, skip_before_day),
            )
            conn.execute("DELETE FROM users")
            conn.execute("DELETE FROM human_sessions")
            conn.execute("DELETE FROM bot_sessions")
            self._rebuild_users(conn)
            self._rebuild_human_sessions(conn)
            self._rebuild_bot_sessions(conn)
            conn.execute(
                """
                INSERT INTO metadata(key, value) VALUES('skip_before_day', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (skip_before_day,),
            )
            conn.execute(
                """
                INSERT INTO metadata(key, value) VALUES('last_refresh_at', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (datetime.now().isoformat(),),
            )
            conn.commit()
        self._rebuild_increment_db()

    def _compute_skip_before_day(self, conn: sqlite3.Connection) -> str:
        days = [
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT request_day FROM requests WHERE source_side = 'b' ORDER BY request_day"
            )
        ]
        if not days:
            return "0000-00-00"
        index = min(SKIP_FIRST_DAYS, len(days) - 1)
        return days[index]

    def _rebuild_users(self, conn: sqlite3.Connection) -> None:
        query = """
        WITH ranked AS (
            SELECT
                user_key,
                request_time,
                normalized_page,
                ROW_NUMBER() OVER (PARTITION BY user_key ORDER BY request_time ASC) AS rn_first,
                ROW_NUMBER() OVER (PARTITION BY user_key ORDER BY request_time DESC) AS rn_last
            FROM requests
            WHERE is_counted_user = 1
        ),
        pages AS (
            SELECT
                user_key,
                MAX(CASE WHEN rn_first = 1 THEN normalized_page END) AS first_page,
                MAX(CASE WHEN rn_last = 1 THEN normalized_page END) AS last_page
            FROM ranked
            GROUP BY user_key
        )
        SELECT
            r.user_key,
            MIN(r.request_time) AS first_seen,
            MAX(r.request_time) AS last_seen,
            MIN(r.request_day) AS first_day,
            MAX(r.request_day) AS last_day,
            MIN(r.actor_type) AS actor_type,
            MIN(r.identity_confidence) AS identity_confidence,
            MIN(r.client_ip) AS sample_client_ip,
            MIN(r.user_agent) AS sample_user_agent,
            MIN(r.browser) AS browser,
            MIN(r.os) AS os,
            MIN(r.device_type) AS device_type,
            COUNT(*) AS request_count,
            COUNT(DISTINCT r.request_day) AS active_days,
            p.first_page,
            p.last_page
        FROM requests r
        LEFT JOIN pages p ON p.user_key = r.user_key
        WHERE r.is_counted_user = 1
        GROUP BY r.user_key, p.first_page, p.last_page
        """
        rows = list(conn.execute(query))
        mappings: list[tuple[str, str]] = []
        for row in rows:
            user_key = row["user_key"]
            user_id = "U-" + sha1_short(user_key, 16)
            conn.execute(
                """
                INSERT INTO users(
                    user_id, user_key, first_seen, first_day, last_seen, last_day, actor_type,
                    identity_confidence, sample_client_ip, sample_user_agent, browser, os,
                    device_type, first_page, last_page, request_count, active_days
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    user_key,
                    row["first_seen"],
                    row["first_day"],
                    row["last_seen"],
                    row["last_day"],
                    row["actor_type"],
                    row["identity_confidence"],
                    row["sample_client_ip"],
                    row["sample_user_agent"],
                    row["browser"],
                    row["os"],
                    row["device_type"],
                    row["first_page"] or "",
                    row["last_page"] or "",
                    row["request_count"],
                    row["active_days"],
                ),
            )
            mappings.append((user_key, user_id))

        conn.execute("DROP TABLE IF EXISTS temp_user_map")
        conn.execute("CREATE TEMP TABLE temp_user_map(user_key TEXT PRIMARY KEY, user_id TEXT NOT NULL)")
        conn.executemany("INSERT INTO temp_user_map(user_key, user_id) VALUES(?, ?)", mappings)
        conn.execute(
            """
            UPDATE requests
            SET user_id = COALESCE(
                (SELECT m.user_id FROM temp_user_map m WHERE m.user_key = requests.user_key),
                ''
            )
            """
        )
        conn.execute("DROP TABLE temp_user_map")

    def _rebuild_human_sessions(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            """
            SELECT user_id, request_time, request_day, source_side, normalized_page, referer
            FROM requests
            WHERE is_counted_user = 1 AND user_id <> ''
            ORDER BY user_id, request_time
            """
        )
        gap = timedelta(seconds=HUMAN_SESSION_GAP_SECONDS)
        current: dict[str, Any] | None = None
        counter = 0
        for row in rows:
            event_time = datetime.fromisoformat(row["request_time"])
            if (
                current is None
                or row["user_id"] != current["user_id"]
                or event_time - current["last_seen"] > gap
            ):
                if current:
                    self._insert_human_session(conn, current)
                counter += 1
                current = {
                    "session_id": f"HS-{counter:09d}",
                    "user_id": row["user_id"],
                    "request_day": row["request_day"],
                    "start_time": row["request_time"],
                    "end_time": row["request_time"],
                    "source_side": row["source_side"],
                    "entry_page": row["normalized_page"] or "",
                    "referer": row["referer"] or "(direct / none)",
                    "pageviews": 1,
                    "last_seen": event_time,
                }
            else:
                current["end_time"] = row["request_time"]
                current["pageviews"] += 1
                current["last_seen"] = event_time
        if current:
            self._insert_human_session(conn, current)

    def _insert_human_session(self, conn: sqlite3.Connection, session: dict[str, Any]) -> None:
        duration_seconds = max(
            0,
            int(
                (
                    datetime.fromisoformat(session["end_time"])
                    - datetime.fromisoformat(session["start_time"])
                ).total_seconds()
            ),
        )
        conn.execute(
            """
            INSERT INTO human_sessions(
                session_id, user_id, request_day, start_time, end_time, source_side,
                entry_page, referer, pageviews, duration_seconds
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session["session_id"],
                session["user_id"],
                session["request_day"],
                session["start_time"],
                session["end_time"],
                session["source_side"],
                session["entry_page"],
                session["referer"],
                session["pageviews"],
                duration_seconds,
            ),
        )

    def _rebuild_bot_sessions(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            """
            SELECT session_actor_key, request_time, request_day, source_side,
                   normalized_page, referer, bot_category, bot_family, actor_bucket
            FROM requests
            WHERE is_counted_bot = 1 AND session_actor_key <> ''
            ORDER BY session_actor_key, request_time
            """
        )
        gap = timedelta(seconds=BOT_SESSION_GAP_SECONDS)
        current: dict[str, Any] | None = None
        counter = 0
        for row in rows:
            event_time = datetime.fromisoformat(row["request_time"])
            if (
                current is None
                or row["session_actor_key"] != current["session_actor_key"]
                or event_time - current["last_seen"] > gap
            ):
                if current:
                    self._insert_bot_session(conn, current)
                counter += 1
                current = {
                    "session_id": f"BS-{counter:09d}",
                    "session_actor_key": row["session_actor_key"],
                    "request_day": row["request_day"],
                    "start_time": row["request_time"],
                    "end_time": row["request_time"],
                    "source_side": row["source_side"],
                    "bot_category": row["bot_category"],
                    "bot_family": row["bot_family"],
                    "actor_bucket": row["actor_bucket"],
                    "entry_page": row["normalized_page"] or "",
                    "referer": row["referer"] or "(direct / none)",
                    "pageviews": 1,
                    "last_seen": event_time,
                }
            else:
                current["end_time"] = row["request_time"]
                current["pageviews"] += 1
                current["last_seen"] = event_time
        if current:
            self._insert_bot_session(conn, current)

    def _insert_bot_session(self, conn: sqlite3.Connection, session: dict[str, Any]) -> None:
        duration_seconds = max(
            0,
            int(
                (
                    datetime.fromisoformat(session["end_time"])
                    - datetime.fromisoformat(session["start_time"])
                ).total_seconds()
            ),
        )
        conn.execute(
            """
            INSERT INTO bot_sessions(
                session_id, session_actor_key, request_day, start_time, end_time,
                source_side, bot_category, bot_family, actor_bucket, entry_page,
                referer, pageviews, duration_seconds
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session["session_id"],
                session["session_actor_key"],
                session["request_day"],
                session["start_time"],
                session["end_time"],
                session["source_side"],
                session["bot_category"],
                session["bot_family"],
                session["actor_bucket"],
                session["entry_page"],
                session["referer"],
                session["pageviews"],
                duration_seconds,
            ),
        )

    def _rebuild_increment_db(self) -> None:
        with self._increment_conn() as inc, self._full_conn() as full:
            inc.execute("DELETE FROM daily_overview")
            inc.execute("DELETE FROM daily_user_increment")
            inc.execute("DELETE FROM daily_bot_increment")
            inc.execute("DELETE FROM daily_page_increment")
            try:
                inc.execute("DETACH DATABASE full_db")
            except sqlite3.OperationalError:
                pass
            escaped_full_db = str(self.full_db_path).replace("'", "''")
            inc.execute(f"ATTACH DATABASE '{escaped_full_db}' AS full_db")

            request_days = [row[0] for row in full.execute("SELECT DISTINCT request_day FROM requests WHERE is_in_report_window = 1 ORDER BY request_day")]
            cumulative_users = 0
            for day in request_days:
                total_requests = full.execute("SELECT COUNT(*) FROM requests WHERE request_day = ? AND is_in_report_window = 1", (day,)).fetchone()[0]
                human_requests = full.execute("SELECT COUNT(*) FROM requests WHERE request_day = ? AND is_counted_user = 1", (day,)).fetchone()[0]
                app_webview_requests = full.execute("SELECT COUNT(*) FROM requests WHERE request_day = ? AND is_counted_user = 1 AND actor_type = 'human_app'", (day,)).fetchone()[0]
                bot_requests = full.execute("SELECT COUNT(*) FROM requests WHERE request_day = ? AND is_in_report_window = 1 AND actor_type IN ('bot', 'automation')", (day,)).fetchone()[0]
                countable_bot_requests = full.execute("SELECT COUNT(*) FROM requests WHERE request_day = ? AND is_counted_bot = 1", (day,)).fetchone()[0]
                automation_requests = full.execute("SELECT COUNT(*) FROM requests WHERE request_day = ? AND is_in_report_window = 1 AND actor_type = 'automation'", (day,)).fetchone()[0]
                human_sessions = full.execute("SELECT COUNT(*) FROM human_sessions WHERE request_day = ?", (day,)).fetchone()[0]
                bot_sessions = full.execute("SELECT COUNT(*) FROM bot_sessions WHERE request_day = ?", (day,)).fetchone()[0]
                active_users = full.execute("SELECT COUNT(DISTINCT user_id) FROM requests WHERE request_day = ? AND is_counted_user = 1", (day,)).fetchone()[0]
                new_users = full.execute("SELECT COUNT(*) FROM users WHERE first_day = ?", (day,)).fetchone()[0]
                returning_users = max(active_users - new_users, 0)
                cumulative_users += new_users

                category_aliases = {
                    "AI Retrieval": ("AI Retrieval", "AI Search"),
                    "AI Training": ("AI Training",),
                    "AI Indexer": ("AI Indexer", "AI Index"),
                    "SEO Bot": ("SEO Bot",),
                    "Social Preview Bot": ("Social Preview Bot",),
                    "Verification Bot": ("Verification Bot",),
                }
                category_counts = {}
                for category, aliases in category_aliases.items():
                    placeholders = ", ".join("?" for _ in aliases)
                    category_counts[category] = full.execute(
                        f"SELECT COUNT(*) FROM requests WHERE request_day = ? AND is_counted_bot = 1 AND bot_category IN ({placeholders})",
                        (day, *aliases),
                    ).fetchone()[0]

                inc.execute(
                    """
                    INSERT INTO daily_overview(
                        date, total_requests, human_requests, app_webview_requests, bot_requests,
                        countable_bot_requests, automation_requests, human_sessions, bot_sessions,
                        active_users, new_users, returning_users, cumulative_users,
                        ai_retrieval_requests, ai_training_requests, ai_indexer_requests,
                        seo_bot_requests, social_bot_requests, verification_bot_requests
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        day,
                        total_requests,
                        human_requests,
                        app_webview_requests,
                        bot_requests,
                        countable_bot_requests,
                        automation_requests,
                        human_sessions,
                        bot_sessions,
                        active_users,
                        new_users,
                        returning_users,
                        cumulative_users,
                        category_counts["AI Retrieval"],
                        category_counts["AI Training"],
                        category_counts["AI Indexer"],
                        category_counts["SEO Bot"],
                        category_counts["Social Preview Bot"],
                        category_counts["Verification Bot"],
                    ),
                )

            inc.execute(
                """
                WITH request_counts AS (
                    SELECT
                        request_day AS date,
                        user_id,
                        COUNT(*) AS requests,
                        MIN(request_time) AS first_request_time,
                        MAX(request_time) AS last_request_time
                    FROM full_db.requests
                    WHERE is_counted_user = 1 AND user_id <> ''
                    GROUP BY request_day, user_id
                ),
                ranked_pages AS (
                    SELECT
                        request_day AS date,
                        user_id,
                        normalized_page,
                        ROW_NUMBER() OVER (PARTITION BY request_day, user_id ORDER BY request_time ASC) AS rn_first,
                        ROW_NUMBER() OVER (PARTITION BY request_day, user_id ORDER BY request_time DESC) AS rn_last
                    FROM full_db.requests
                    WHERE is_counted_user = 1 AND user_id <> ''
                ),
                pages AS (
                    SELECT
                        date,
                        user_id,
                        MAX(CASE WHEN rn_first = 1 THEN normalized_page END) AS first_page,
                        MAX(CASE WHEN rn_last = 1 THEN normalized_page END) AS last_page
                    FROM ranked_pages
                    GROUP BY date, user_id
                ),
                session_counts AS (
                    SELECT request_day AS date, user_id, COUNT(*) AS sessions
                    FROM full_db.human_sessions
                    GROUP BY request_day, user_id
                )
                INSERT INTO daily_user_increment(
                    date, user_id, requests, sessions, is_new_user,
                    first_request_time, last_request_time, first_page, last_page
                )
                SELECT
                    rc.date,
                    rc.user_id,
                    rc.requests,
                    COALESCE(sc.sessions, 0) AS sessions,
                    CASE WHEN u.first_day = rc.date THEN 1 ELSE 0 END AS is_new_user,
                    rc.first_request_time,
                    rc.last_request_time,
                    COALESCE(p.first_page, ''),
                    COALESCE(p.last_page, '')
                FROM request_counts rc
                LEFT JOIN session_counts sc ON sc.date = rc.date AND sc.user_id = rc.user_id
                LEFT JOIN pages p ON p.date = rc.date AND p.user_id = rc.user_id
                LEFT JOIN full_db.users u ON u.user_id = rc.user_id
                """
            )

            inc.execute(
                """
                WITH request_counts AS (
                    SELECT request_day AS date, bot_family, bot_category, actor_bucket, COUNT(*) AS requests
                    FROM full_db.requests
                    WHERE is_counted_bot = 1
                    GROUP BY request_day, bot_family, bot_category, actor_bucket
                ),
                session_counts AS (
                    SELECT request_day AS date, bot_family, bot_category, COUNT(*) AS sessions
                    FROM full_db.bot_sessions
                    GROUP BY request_day, bot_family, bot_category
                )
                INSERT INTO daily_bot_increment(date, bot_family, bot_category, actor_bucket, requests, sessions)
                SELECT
                    rc.date,
                    rc.bot_family,
                    rc.bot_category,
                    rc.actor_bucket,
                    rc.requests,
                    COALESCE(sc.sessions, 0) AS sessions
                FROM request_counts rc
                LEFT JOIN session_counts sc
                    ON sc.date = rc.date
                   AND sc.bot_family = rc.bot_family
                   AND sc.bot_category = rc.bot_category
                """
            )

            inc.execute(
                """
                WITH request_counts AS (
                    SELECT
                        request_day AS date,
                        normalized_page AS page,
                        SUM(CASE WHEN is_counted_user = 1 THEN 1 ELSE 0 END) AS human_requests,
                        SUM(CASE WHEN is_counted_bot = 1 THEN 1 ELSE 0 END) AS bot_requests
                    FROM full_db.requests
                    WHERE is_in_report_window = 1 AND normalized_page IS NOT NULL AND normalized_page <> ''
                    GROUP BY request_day, normalized_page
                ),
                human_session_counts AS (
                    SELECT request_day AS date, entry_page AS page, COUNT(*) AS human_sessions
                    FROM full_db.human_sessions
                    WHERE entry_page IS NOT NULL AND entry_page <> ''
                    GROUP BY request_day, entry_page
                ),
                bot_session_counts AS (
                    SELECT request_day AS date, entry_page AS page, COUNT(*) AS bot_sessions
                    FROM full_db.bot_sessions
                    WHERE entry_page IS NOT NULL AND entry_page <> ''
                    GROUP BY request_day, entry_page
                )
                INSERT INTO daily_page_increment(date, page, human_requests, human_sessions, bot_requests, bot_sessions)
                SELECT
                    rc.date,
                    rc.page,
                    rc.human_requests,
                    COALESCE(hs.human_sessions, 0) AS human_sessions,
                    rc.bot_requests,
                    COALESCE(bs.bot_sessions, 0) AS bot_sessions
                FROM request_counts rc
                LEFT JOIN human_session_counts hs ON hs.date = rc.date AND hs.page = rc.page
                LEFT JOIN bot_session_counts bs ON bs.date = rc.date AND bs.page = rc.page
                """
            )

            refresh_at = datetime.now().isoformat()
            refresh_day = datetime.now().strftime("%Y-%m-%d")
            inc.execute("INSERT INTO metadata(key, value) VALUES('last_refresh_at', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (refresh_at,))
            inc.execute("INSERT INTO metadata(key, value) VALUES('last_refresh_day', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (refresh_day,))
            inc.commit()
            inc.execute("DETACH DATABASE full_db")

    def _write_snapshot_file(self) -> dict[str, Any]:
        with self._full_conn() as full, self._increment_conn() as inc:
            overview_rows = [dict(row) for row in inc.execute("SELECT * FROM daily_overview ORDER BY date")]
            user_rows = [
                dict(row)
                for row in inc.execute(
                    """
                    SELECT date, user_id, requests, sessions, is_new_user, first_page, last_page
                    FROM daily_user_increment
                    ORDER BY date DESC, requests DESC
                    LIMIT 10
                    """
                )
            ]
            page_rows = [
                dict(row)
                for row in inc.execute(
                    """
                    SELECT date, page, human_requests, human_sessions, bot_requests, bot_sessions
                    FROM daily_page_increment
                    ORDER BY date DESC, human_requests DESC
                    LIMIT 10
                    """
                )
            ]
            metadata = self._metadata_dict(inc)
            total_requests = full.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            total_human_requests = full.execute("SELECT COUNT(*) FROM requests WHERE is_counted_user = 1").fetchone()[0]
            total_bot_requests = full.execute("SELECT COUNT(*) FROM requests WHERE is_counted_bot = 1").fetchone()[0]
            total_users = full.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            total_human_sessions = full.execute("SELECT COUNT(*) FROM human_sessions").fetchone()[0]
            total_bot_sessions = full.execute("SELECT COUNT(*) FROM bot_sessions").fetchone()[0]
            top_bots = [dict(row) for row in full.execute(
                """
                SELECT bot_family, bot_category, actor_bucket, COUNT(*) AS requests
                FROM requests
                WHERE actor_type IN ('bot', 'automation')
                GROUP BY bot_family, bot_category, actor_bucket
                ORDER BY requests DESC
                LIMIT 20
                """
            )]
            top_pages = [dict(row) for row in full.execute(
                """
                SELECT normalized_page AS page, COUNT(*) AS requests
                FROM requests
                WHERE is_in_report_window = 1 AND normalized_page IS NOT NULL AND normalized_page <> ''
                GROUP BY normalized_page
                ORDER BY requests DESC
                LIMIT 20
                """
            )]
            bot_feature_breakdown = [dict(row) for row in full.execute(
                """
                SELECT bot_family, bot_vendor, bot_product, bot_purpose, bot_description, actor_type, COUNT(*) AS requests
                FROM requests
                WHERE actor_type IN ('bot', 'automation')
                GROUP BY bot_family, bot_vendor, bot_product, bot_purpose, bot_description, actor_type
                ORDER BY requests DESC
                """
            )]
            snapshot = {
                "generated_at": datetime.now().isoformat(),
                "full_db_path": str(self.full_db_path),
                "increment_db_path": str(self.increment_db_path),
                "metrics": {
                    "total_requests": total_requests,
                    "total_human_requests": total_human_requests,
                    "total_bot_requests": total_bot_requests,
                    "total_users": total_users,
                    "total_human_sessions": total_human_sessions,
                    "total_bot_sessions": total_bot_sessions,
                },
                "daily_overview": overview_rows,
                "top_bot_families": top_bots,
                "bot_feature_breakdown": bot_feature_breakdown,
                "top_pages": top_pages,
            }
            self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
            self.snapshot_path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
            frontend_payload = self._build_frontend_dashboard_payload(
                snapshot=snapshot,
                overview_rows=overview_rows[-14:],
                user_rows=user_rows,
                page_rows=page_rows,
                metadata=metadata,
                top_bots=10,
                top_pages=10,
            )
            self.frontend_snapshot_path.write_text(
                json.dumps(frontend_payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            return snapshot

    def _metadata_dict(self, conn: sqlite3.Connection) -> dict[str, str]:
        return {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM metadata")}

    @staticmethod
    def _to_int(value: Any) -> int | None:
        if value in (None, "", "-"):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
