
from __future__ import annotations
"""报表读取与组装层。

这里不做原始日志解析，只负责把已经入库/聚合好的数据组织成前端需要的
卡片、趋势图、排行表和访问记录结构。
"""

import json
from datetime import date
from typing import Any

from .index_filtering import build_select_options, filter_index_options, normalize_index_option
from .support import local_day_to_utc_bounds


class DashboardMixin:
    """面向 dashboard 的查询与结果拼装逻辑。"""
    def get_summary(self) -> dict[str, Any]:
        """返回首页摘要。

        优先读快照和增量库，避免每次都扫描全量明细表。
        """
        # Summary prefers aggregated artifacts first so the landing page stays
        # cheap even when the raw requests table is large.
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
        """返回增量库中的原始按天汇总结果，便于调试和导出。"""
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
        """构建旧版快照式前端面板数据。"""
        # This is the older snapshot-style payload builder. It is kept separate
        # from the fully interactive filtered dashboard path on purpose.
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
        """返回前端筛选项。

        主路径优先直接查询 ES，因为索引和 host 选项本来就是 ES 维度信息；
        只有 ES 不可用时，才降级到本地 SQLite 镜像。
        """
        # 按你的要求，筛选项主路径优先走 ES：先从 ES 拉索引，再按索引拉 host。
        # 本地库只作为兜底，不再作为主筛选来源。
        cache_key = f"filters:{customer_name or 'ALL'}:{date_from or ''}:{date_to or ''}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        start_utc = end_utc = None
        if date_from and date_to:
            start_utc, end_utc = local_day_to_utc_bounds(date_from, date_to)
        try:
            all_indices = self.remote_source.list_index_options(start_utc=start_utc, end_utc=end_utc)
            filtered_indices = filter_index_options(all_indices, customer_name, None)
            customers = build_select_options(all_indices, "customer_name", "全部客户")
            hosts = [{"value": "ALL", "label": "全部 Host", "requests": 0}]
            if customer_name and customer_name != "ALL":
                latest_index_name = self._latest_index_name(filtered_indices)
                if latest_index_name:
                    hosts.extend(self.remote_source.list_host_options([latest_index_name]))
            bounds = self.remote_source.get_time_bounds()
            return self._cache_set(cache_key, {
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
            }, 60)
        except Exception:
            # ES 不可用时才退回本地镜像。
            self._ensure_fresh_daily_sync()
            all_indices = self._list_local_index_options()
            filtered_indices = filter_index_options(all_indices, customer_name, None)
            customers = build_select_options(all_indices, "customer_name", "全部客户")
            hosts = [{"value": "ALL", "label": "全部 Host", "requests": 0}]
            if customer_name and customer_name != "ALL":
                latest_index_name = self._latest_index_name(filtered_indices)
                if latest_index_name:
                    hosts.extend(self._list_local_host_options([latest_index_name]))
            with self._full_conn() as conn:
                bounds = conn.execute(
                    """
                    SELECT
                        MIN(request_day) AS min_day,
                        MAX(request_day) AS max_day
                    FROM requests
                    """
                ).fetchone()
            return self._cache_set(cache_key, {
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
            }, 60)
    def get_filtered_dashboard(
        self,
        customer_name: str | None = None,
        host: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        top_bots: int = 10,
        top_pages: int = 10,
        exclude_sensitive_pages: bool = False,
    ) -> dict[str, Any]:
        """返回交互式 dashboard 主数据。

        这里有两条路径：
        - 优先走 ES 实时聚合，拿到最新且与线上一致的统计；
        - 如果 ES 查询失败，则回退到本地 SQLite，用近似同口径 SQL 继续服务。
        """
        # Interactive filtering prefers live ES. SQLite is only the degraded
        # path so the panel can still answer if ES metadata/querying fails.
        cache_key = f"dashboard:{customer_name or 'ALL'}:{host or 'ALL'}:{date_from or ''}:{date_to or ''}:{top_bots}:{top_pages}:{int(exclude_sensitive_pages)}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        use_live_dashboard = bool(date_from and date_to and getattr(self, "enable_live_dashboard", False))
        if use_live_dashboard:
            try:
                return self._cache_set(cache_key, self._get_filtered_dashboard_live(
                    customer_name=customer_name,
                    host=host,
                    date_from=date_from,
                    date_to=date_to,
                    top_bots=top_bots,
                    top_pages=top_pages,
                    exclude_sensitive_pages=exclude_sensitive_pages,
                ), 30)
            except Exception:
                pass
        span_days_local = 1
        self._ensure_fresh_daily_sync()
        candidate_indices = filter_index_options(
            self._list_local_index_options(),
            customer_name,
            None,
            date_from=date_from,
            date_to=date_to,
        )
        index_names = [item["value"] for item in candidate_indices] if candidate_indices else None
        where_sql, params = self._build_filter_sql(index_names, host, date_from, date_to, exclude_sensitive_pages)
        previous_window = self._calc_previous_window(date_from, date_to)
        prev_where_sql, prev_params = self._build_filter_sql(
            index_names,
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
        ai_unclassified_sql = self._ai_unclassified_sql()
        ai_search_focused_sql = f"({ai_search_sql} AND {focused_ai_sql})"
        ai_training_focused_sql = f"({ai_training_sql} AND {focused_ai_sql})"
        ai_index_focused_sql = f"({ai_index_sql} AND {focused_ai_sql})"
        ai_unclassified_focused_sql = f"({ai_unclassified_sql} AND {focused_ai_sql})"
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
                    SUM(CASE WHEN {ai_index_focused_sql} THEN 1 ELSE 0 END) AS ai_index,
                    SUM(CASE WHEN {ai_unclassified_focused_sql} THEN 1 ELSE 0 END) AS ai_unclassified
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
                    SUM(CASE WHEN {ai_index_focused_sql} THEN 1 ELSE 0 END) AS ai_index,
                    SUM(CASE WHEN {ai_unclassified_focused_sql} THEN 1 ELSE 0 END) AS ai_unclassified
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
                        SUM(CASE WHEN {ai_index_focused_sql} THEN 1 ELSE 0 END) AS ai_index,
                        SUM(CASE WHEN {ai_unclassified_focused_sql} THEN 1 ELSE 0 END) AS ai_unclassified
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

            if span_days_local <= 1:
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
                            SUM(CASE WHEN {ai_index_focused_sql} THEN 1 ELSE 0 END) AS ai_index,
                            SUM(CASE WHEN {ai_unclassified_focused_sql} THEN 1 ELSE 0 END) AS ai_unclassified
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
            else:
                page_rows = []
                access_rows = []

            unclassified_bot_rows = [
                dict(row)
                for row in conn.execute(
                    f"""
                    SELECT
                        COALESCE(NULLIF(repo_channel, ''), NULLIF(bot_family, ''), 'UnknownBot') AS bot_name,
                        COALESCE(NULLIF(user_agent, ''), '-') AS user_agent,
                        COUNT(*) AS requests
                    FROM requests
                    WHERE {where_sql}
                      AND {ai_unclassified_focused_sql}
                    GROUP BY bot_name, user_agent
                    ORDER BY requests DESC, bot_name, user_agent
                    LIMIT ?
                    """,
                    [*params, max(top_bots, 1)],
                )
            ]

        latest = trend_rows[-1] if trend_rows else {}

        human_total = int(human_row["total_human_traffic"] or 0)
        ai_total = int(ai_row["total_ai_traffic"] or 0)
        ai_rankings = {
            "ai_search": [],
            "ai_training": [],
            "ai_index": [],
            "ai_unclassified": [],
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
        return self._cache_set(cache_key, {
            "meta": {
                "customer_name": customer_name or "ALL",
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
                "ai_unclassified": ai_row["ai_unclassified"] or 0,
                "ai_unclassified_change_pct": self._calc_change_pct(int(ai_row["ai_unclassified"] or 0), int(prev_ai_row["ai_unclassified"] or 0)),
                "ai_unclassified_share_ratio_pct": self._calc_share_pct(int(ai_row["ai_unclassified"] or 0), ai_total),
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
            "unclassified_bots": unclassified_bot_rows,
            "top_bots": bot_rows,
            "top_pages": page_rows,
            "page_ranking": page_rows,
            "access_records": [
                {
                    "access_time": row["request_time"],
                    "traffic_type": "ai" if row["repo_category"] in ("ai_search", "ai_training", "ai_index", "ai_unclassified") else "user",
                    "traffic_channel": (
                        (row["repo_channel"] or row["bot_family"] or "Unknown")
                        if row["repo_category"] in ("ai_search", "ai_training", "ai_index", "ai_unclassified")
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
        }, 30)
    def _list_local_index_options(self) -> list[dict[str, Any]]:
        # SQLite stores the raw source_ref, so we normalize it the same way as
        # the live ES path to keep frontend payloads consistent.
        with self._full_conn() as conn:
            rows = conn.execute(
                """
                SELECT source_ref, COUNT(*) AS requests
                FROM requests
                WHERE COALESCE(source_ref, '') <> ''
                GROUP BY source_ref
                ORDER BY requests DESC, source_ref
                """
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            results.append(normalize_index_option(item["source_ref"], item["requests"]))
        return results
    def _list_local_host_options(self, index_names: list[str] | None = None) -> list[dict[str, Any]]:
        # Host options are narrowed by the selected index slice so the second
        # dropdown stays small and meaningful.
        where = ["COALESCE(host, '') <> ''"]
        params: list[Any] = []
        selected_indices = [item for item in (index_names or []) if item and item != "ALL"]
        if selected_indices:
            where.append(f"source_ref IN ({', '.join('?' for _ in selected_indices)})")
            params.extend(selected_indices)
        with self._full_conn() as conn:
            rows = conn.execute(
                f"""
                SELECT host AS value, host AS label, COUNT(*) AS requests
                FROM requests
                WHERE {' AND '.join(where)}
                GROUP BY host
                ORDER BY requests DESC, host
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]
    def _get_filtered_dashboard_live(
        self,
        customer_name: str | None,
        host: str | None,
        date_from: str,
        date_to: str,
        top_bots: int,
        top_pages: int,
        exclude_sensitive_pages: bool,
    ) -> dict[str, Any]:
        """通过 ES 实时聚合构建 dashboard。

        这是前端主路径使用的实时看板实现，AI 三分类排行也是在这里直接
        按 UA 规则聚合出来的。
        """
        # The live dashboard always works from the selected index slice first,
        # then optionally narrows further by host.
        previous_window = self._calc_previous_window(date_from, date_to)
        start_utc, end_utc = local_day_to_utc_bounds(date_from, date_to)
        index_names: list[str] | None = None
        if customer_name and customer_name != "ALL":
            candidate_indices = filter_index_options(
                self.remote_source.list_index_options(start_utc=start_utc, end_utc=end_utc),
                customer_name,
                None,
                date_from=date_from,
                date_to=date_to,
            )
            index_names = [item["value"] for item in candidate_indices] if candidate_indices else None
        host_filters = [host] if host and host != "ALL" else None
        current = self.remote_source.get_live_dashboard_window(
            index_names=index_names,
            host_filters=host_filters,
            start_utc=start_utc,
            end_utc=end_utc,
            top_bots=top_bots,
            top_pages=top_pages,
            include_rankings=True,
            include_page_ranking=False,
        )
        # 为保证首屏速度，实时路径不再执行“上一周期”第二次聚合查询。
        previous = {"focused": {}, "human_referred": {}, "ai_unclassified_total": 0}
        access_rows: list[dict[str, Any]] = []

        focused = current["focused"]
        prev_focused = previous.get("focused", {})
        unclassified_total = int(current.get("ai_unclassified_total", 0))
        prev_unclassified_total = int(previous.get("ai_unclassified_total", 0))
        referred = current["human_referred"]
        prev_referred = previous.get("human_referred", {})
        human_total = int(focused.get("user_traditional", 0) + focused.get("user_ai", 0) + focused.get("user_platform", 0) + focused.get("user_direct", 0))
        prev_human_total = int(prev_focused.get("user_traditional", 0) + prev_focused.get("user_ai", 0) + prev_focused.get("user_platform", 0) + prev_focused.get("user_direct", 0))
        ai_total = int(focused.get("ai_search", 0) + focused.get("ai_training", 0) + focused.get("ai_index", 0) + unclassified_total)
        prev_ai_total = int(prev_focused.get("ai_search", 0) + prev_focused.get("ai_training", 0) + prev_focused.get("ai_index", 0) + prev_unclassified_total)
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
            day_ai_total = int(row.get("ai_search", 0) + row.get("ai_training", 0) + row.get("ai_index", 0) + row.get("ai_unclassified", 0))
            # 未分类 AI 不参与日维主聚合，避免 ES 重过滤拖慢面板。
            day_ai_unclassified = 0
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
                    "ai_unclassified": day_ai_unclassified,
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
        ai_category_rankings = current.get("ai_category_rankings", {"ai_search": [], "ai_training": [], "ai_index": [], "ai_unclassified": []})
        unclassified_bots = current.get("unclassified_bots", [])
        top_bots_rows = []
        for key in ("ai_search", "ai_training", "ai_index", "ai_unclassified"):
            for item in ai_category_rankings.get(key, []):
                top_bots_rows.append({"repo_category": key, "platform": item["platform"], "requests": item["requests"]})

        return {
            "meta": {
                "customer_name": customer_name or "ALL",
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
                "ai_unclassified": unclassified_total,
                "ai_unclassified_change_pct": self._calc_change_pct(unclassified_total, prev_unclassified_total),
                "ai_unclassified_share_ratio_pct": self._calc_share_pct(unclassified_total, ai_total),
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
            "unclassified_bots": unclassified_bots,
            "top_bots": top_bots_rows,
            "top_pages": current.get("page_ranking", []),
            "page_ranking": current.get("page_ranking", []),
            "access_records": access_rows,
        }
    def _latest_index_name(self, options: list[dict[str, Any]]) -> str:
        if not options:
            return ""
        latest = max(
            options,
            key=lambda item: (
                item.get("index_date") or "",
                int(item.get("requests") or 0),
                item.get("value") or "",
            ),
        )
        return str(latest.get("value") or "")
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
