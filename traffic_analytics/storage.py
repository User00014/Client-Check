from __future__ import annotations
"""SQLite 存储层。

负责两件事：
1. 确保全量库 / 增量库的表结构存在；
2. 提供统一的数据库连接、元数据读写和文件状态记录能力。
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any


class StorageMixin:
    """把与 SQLite 打交道的基础能力抽成 mixin，供主 service 复用。"""
    def _ensure_fresh_daily_sync(self) -> None:
        """按“天”做懒同步，避免每个读接口都触发一次全量刷新。"""
        # On-demand reads refresh at day granularity so the fallback path stays
        # reasonably fresh without doing a sync for every HTTP request.
        if not self.allow_on_demand_sync:
            return
        current_day = datetime.now().strftime("%Y-%m-%d")
        with self._increment_conn() as conn:
            last_refresh = conn.execute("SELECT value FROM metadata WHERE key = 'last_refresh_day'").fetchone()
        if not last_refresh or last_refresh[0] != current_day:
            self.sync_from_local_logs()
    def _full_conn(self) -> sqlite3.Connection:
        """打开全量明细库连接。"""
        conn = sqlite3.connect(self.full_db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn
    def _increment_conn(self) -> sqlite3.Connection:
        """打开增量聚合库连接。"""
        conn = sqlite3.connect(self.increment_db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn
    def _ensure_full_schema(self) -> None:
        """确保全量库存在，并包含原始请求与派生实体表。"""
        # Full DB stores raw requests and the derived entities used by fallback
        # querying and snapshot generation.
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
        """确保增量库存在，并包含按天汇总后的轻量级统计表。"""
        # Increment DB stores daily aggregates for cheaper summary-style reads.
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
        """清空全量库中的业务数据，但保留表结构。"""
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
        """清空增量库中的聚合数据，但保留表结构。"""
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
        """读取某个日志文件上次入库时记录的大小和修改时间。"""
        with self._full_conn() as conn:
            return conn.execute("SELECT * FROM source_files WHERE file_path = ?", (str(path),)).fetchone()
    def _should_scan_file(self, path: Path, state: sqlite3.Row | None) -> bool:
        """根据文件大小和修改时间判断日志是否需要重新扫描。"""
        stat = path.stat()
        modified_at = datetime.fromtimestamp(stat.st_mtime).isoformat()
        if not state:
            return True
        return state["size_bytes"] != stat.st_size or state["modified_at"] != modified_at
    def _upsert_file_state(self, path: Path) -> None:
        """更新日志文件的扫描状态，避免重复全量导入。"""
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
    def _metadata_dict(self, conn: sqlite3.Connection) -> dict[str, str]:
        """把 metadata 表拍平成普通字典，方便上层直接使用。"""
        return {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM metadata")}
    def _to_int(value: Any) -> int | None:
        """把日志里的字符串数值安全转换为整数。"""
        if value in (None, "", "-"):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
