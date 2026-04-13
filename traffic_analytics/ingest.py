from __future__ import annotations
"""日志入库与派生数据重建层。

这个模块负责把不同来源的日志统一清洗成 `requests` 明细表，再基于明细表
重建 users、sessions、daily_overview 等派生统计结果。
"""

import json
import sqlite3
from datetime import datetime
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
from .support import B_LINE_RE, IngestResult


class IngestMixin:
    """封装“原始日志 -> SQLite 明细 -> 聚合统计”的整条入库流水线。"""
    def sync_from_local_logs(self) -> dict[str, Any]:
        """执行一次同步。

        优先走远端 Kibana 拉取；若未配置远端，则回退扫描本地日志文件。
        无论入口来源是什么，最终都会汇总到同一套后续重建逻辑。
        """
        # Historical method name aside, this is the shared ingestion entry for
        # both remote ES sync and local-log fallback.
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
            self._cache_clear()
            summary["snapshot"] = snapshot
            return summary
    def ingest_api_logs(self, side: str, logs: list[str | dict[str, Any]]) -> dict[str, Any]:
        """接收 API 传入的日志，并复用与文件/ES 相同的入库链路。"""
        # API writes reuse the same raw-request pipeline as ES/local ingestion,
        # which keeps downstream rebuild logic unified.
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
            self._cache_clear()
            return {
                "inserted": inserted,
                "duplicates": duplicates,
                "affected_days": sorted(affected_days),
                "snapshot": snapshot,
            }
    def _list_local_log_files(self) -> list[Path]:
        """列出项目日志目录下符合命名约定的 B 端日志文件。"""
        if not self.log_dir.exists():
            return []
        return sorted(self.log_dir.glob("moseeker_b_side_access_*.log"))
    def _ingest_log_file(self, path: Path) -> IngestResult:
        """按批次读取单个日志文件并写入 requests 表。"""
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
        """从远端 Kibana 增量拉取日志并入库。"""
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
        """把任意来源的一条日志统一转成 requests 表行结构。

        这是整个项目最关键的“标准化入口”：
        - 先把不同来源的原始字段清洗成统一请求对象；
        - 再调用分类模块写入 actor / bot / repo_category 等标签；
        - 最后补足 request_id、user_key、session_actor_key 等派生字段。
        """
        # Normalize every source format into one canonical request-row schema
        # before inserting into SQLite.
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
            item.get("source_ref") or source_ref,
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
            "source_ref": resolved_source_ref,
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
        """解析 B 端 Nginx access log。"""
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
        """解析结构化 JSON 格式的 C 端日志。"""
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
        """解析从远端 ES/Kibana 拉回来的结构化日志。"""
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
            "source_ref": item.get("_index") or "",
        }
    def _rebuild_derived_tables(self) -> None:
        """基于 requests 明细表重建所有派生表。

        重建顺序是固定的：先重算统计窗口和计数标记，再重建用户、session，
        最后重建增量库和快照文件。这样能保证所有报表字段始终来自同一批明细。
        """
        # Users, sessions, increment tables, and snapshots are all derived from
        # the raw requests table rebuilt here in a fixed order.
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
                         AND repo_category IN ('ai_search', 'ai_training', 'ai_index', 'ai_unclassified')
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
        """根据最早若干天的数据决定报表统计从哪一天开始算。"""
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
        """把多条请求聚合成用户维度画像，并生成稳定的 user_id。"""
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
        """按时间间隔把用户请求切分成人类 session。"""
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
        """落一条人类 session 到 `human_sessions` 表。"""
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
        """按更短的时间窗口切分 Bot session。"""
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
        """落一条 Bot session 到 `bot_sessions` 表。"""
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
        """把全量明细库压缩成按天聚合的增量库。"""
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
        """把常用统计导出成 JSON 快照，供首页和前端快速读取。"""
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
