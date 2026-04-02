from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib import patches

from generate_access_dashboard import B_LINE_RE, LOG_DIR, is_crawler_ua, normalize_page
from generate_person_session_dashboard import (
    OUTPUT_DIR,
    SKIP_FIRST_DAYS,
    TARGET_METHOD,
    b_skip_before_date,
    fmt_count,
    page_exclusion_reason,
    session_gap_label,
    setup_fonts,
    short_label,
    style_panel,
)


BOT_SESSION_GAP_SECONDS = 60
BOT_CATEGORY_COLORS = {
    "AI Retrieval": "#2F80ED",
    "AI Training": "#7C4DFF",
    "AI Indexer": "#12B4A0",
    "SEO Bot": "#F2994A",
    "Social / Platform Bot": "#49A3FF",
    "Other External Bot": "#98A2B3",
}
BOT_RULES: list[tuple[str, str, list[str]]] = [
    ("AI Retrieval", "OAI-SearchBot", ["oai-searchbot"]),
    ("AI Retrieval", "ChatGPT-User", ["chatgpt-user"]),
    ("AI Retrieval", "meta-externalagent", ["meta-externalagent"]),
    ("AI Retrieval", "PerplexityBot", ["perplexitybot"]),
    ("AI Retrieval", "Claude-SearchBot", ["claude-searchbot"]),
    ("AI Training", "GPTBot", ["gptbot"]),
    ("AI Training", "Amazonbot", ["amazonbot"]),
    ("AI Training", "ClaudeBot", ["claudebot"]),
    ("AI Training", "CCBot", ["ccbot"]),
    ("AI Indexer", "360Spider", ["360spider"]),
    ("AI Indexer", "Bytespider", ["bytespider"]),
    ("AI Indexer", "Baiduspider-AI", ["baiduspider-ai"]),
    ("AI Indexer", "Baiduspider-render", ["baiduspider-render"]),
    ("AI Indexer", "YisouSpider", ["yisouspider", "yisou"]),
    ("AI Indexer", "GoogleOther", ["googleother"]),
    ("SEO Bot", "Googlebot-Image", ["googlebot-image"]),
    ("SEO Bot", "Googlebot", ["googlebot"]),
    ("SEO Bot", "bingbot", ["bingbot"]),
    ("SEO Bot", "Sogou", ["sogou"]),
    ("SEO Bot", "PetalBot", ["petalbot"]),
    ("SEO Bot", "Baiduspider", ["baiduspider"]),
    ("SEO Bot", "DotBot", ["dotbot"]),
    ("SEO Bot", "MJ12bot", ["mj12bot"]),
    ("SEO Bot", "Slurp", ["slurp"]),
    ("Social / Platform Bot", "facebookexternalhit", ["facebookexternalhit"]),
    ("Social / Platform Bot", "Facebot", ["facebot"]),
    ("Social / Platform Bot", "Twitterbot", ["twitterbot"]),
    ("Social / Platform Bot", "TikTokSpider", ["tiktokspider"]),
]
EXCLUDED_BOT_RULES: list[tuple[str, list[str]]] = [
    ("script_client_bot", ["curl", "okhttp", "axios", "go-http-client", "httpclient", "python", "wget", "java/"]),
    ("scanner_monitor_bot", ["scanner", "monitor", "headless", "scrapy"]),
]


@dataclass
class BotRequestRecord:
    request_time: datetime
    day: str
    proxy_ip: str
    fingerprint: str
    bot_category: str
    bot_family: str
    page: str
    referer: str
    user_agent: str


@dataclass
class BotSessionRecord:
    session_id: int
    day: str
    start: datetime
    end: datetime
    proxy_ip: str
    fingerprint: str
    bot_category: str
    bot_family: str
    entry_page: str
    referer: str
    pageviews: int


def classify_bot(user_agent: str) -> tuple[str, str] | tuple[None, str]:
    ua = user_agent.lower()
    for reason, tokens in EXCLUDED_BOT_RULES:
        if any(token in ua for token in tokens):
            return None, reason
    for category, family, tokens in BOT_RULES:
        if any(token in ua for token in tokens):
            return category, family
    if is_crawler_ua(user_agent):
        return "Other External Bot", "Other Bot"
    return None, "non_bot_ua"


def bot_group(category: str) -> str:
    if category in {"AI Retrieval", "AI Training", "AI Indexer"}:
        return "AI Bot"
    if category == "SEO Bot":
        return "SEO Bot"
    return "Other External Bot"


def load_bside_bot_records() -> tuple[list[BotRequestRecord], Counter]:
    skip_before = b_skip_before_date()
    dropped = Counter()
    records: list[BotRequestRecord] = []

    for path in sorted(LOG_DIR.glob("moseeker_b_side_access_*.log")):
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                match = B_LINE_RE.match(line)
                if not match:
                    continue
                item = match.groupdict()
                dt = datetime.strptime(item["dt"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
                day = dt.strftime("%Y-%m-%d")
                if day < skip_before:
                    dropped["skip_first_3_days"] += 1
                    continue
                if item["method"] != TARGET_METHOD:
                    dropped["non_get_method"] += 1
                    continue
                if not is_crawler_ua(item["ua"]):
                    dropped["non_bot_ua"] += 1
                    continue

                page = normalize_page(item["uri"])
                if not page:
                    dropped["static_or_non_page"] += 1
                    continue
                exclusion_reason = page_exclusion_reason(page)
                if exclusion_reason:
                    dropped[exclusion_reason] += 1
                    continue

                bot_category, bot_family_or_reason = classify_bot(item["ua"])
                if bot_category is None:
                    dropped[bot_family_or_reason] += 1
                    continue

                referer = item["referer"] if item["referer"] and item["referer"] != "-" else "(direct / none)"
                fingerprint = hashlib.sha1(item["ua"].encode("utf-8", "ignore")).hexdigest()[:12]
                records.append(
                    BotRequestRecord(
                        request_time=dt,
                        day=day,
                        proxy_ip=item["ip"],
                        fingerprint=fingerprint,
                        bot_category=bot_category,
                        bot_family=bot_family_or_reason,
                        page=page,
                        referer=referer,
                        user_agent=item["ua"],
                    )
                )

    records.sort(key=lambda row: row.request_time)
    return records, dropped


def build_bot_sessions(records: list[BotRequestRecord], session_gap: timedelta) -> list[BotSessionRecord]:
    sessions: list[BotSessionRecord] = []
    last_seen: dict[str, datetime] = {}
    active_session: dict[str, int] = {}

    for record in records:
        prev = last_seen.get(record.fingerprint)
        session_index = active_session.get(record.fingerprint)
        if prev is None or record.request_time - prev > session_gap or session_index is None:
            session_index = len(sessions)
            sessions.append(
                BotSessionRecord(
                    session_id=session_index + 1,
                    day=record.day,
                    start=record.request_time,
                    end=record.request_time,
                    proxy_ip=record.proxy_ip,
                    fingerprint=record.fingerprint,
                    bot_category=record.bot_category,
                    bot_family=record.bot_family,
                    entry_page=record.page,
                    referer=record.referer,
                    pageviews=1,
                )
            )
            active_session[record.fingerprint] = session_index
        else:
            sessions[session_index].end = record.request_time
            sessions[session_index].pageviews += 1
        last_seen[record.fingerprint] = record.request_time

    return sessions


def write_bot_requests_csv(records: list[BotRequestRecord], target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "request_time",
                "date",
                "proxy_ip",
                "fingerprint",
                "bot_category",
                "bot_group",
                "bot_family",
                "page",
                "referer",
                "user_agent",
            ]
        )
        for record in records:
            writer.writerow(
                [
                    record.request_time.isoformat(sep=" "),
                    record.day,
                    record.proxy_ip,
                    record.fingerprint,
                    record.bot_category,
                    bot_group(record.bot_category),
                    record.bot_family,
                    record.page,
                    record.referer,
                    record.user_agent,
                ]
            )


def write_bot_sessions_csv(sessions: list[BotSessionRecord], target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "session_id",
                "day",
                "start",
                "end",
                "proxy_ip",
                "fingerprint",
                "bot_category",
                "bot_group",
                "bot_family",
                "entry_page",
                "referer",
                "pageviews",
                "duration_seconds",
            ]
        )
        for session in sessions:
            duration_seconds = max(0, int((session.end - session.start).total_seconds()))
            writer.writerow(
                [
                    session.session_id,
                    session.day,
                    session.start.isoformat(sep=" "),
                    session.end.isoformat(sep=" "),
                    session.proxy_ip,
                    session.fingerprint,
                    session.bot_category,
                    bot_group(session.bot_category),
                    session.bot_family,
                    session.entry_page,
                    session.referer,
                    session.pageviews,
                    duration_seconds,
                ]
            )


def write_daily_csv(daily_requests: Counter, daily_sessions: Counter, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    dates = sorted(set(daily_requests) | set(daily_sessions))
    with target.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["date", "bot_requests", "bot_sessions"])
        for day in dates:
            writer.writerow([day, daily_requests.get(day, 0), daily_sessions.get(day, 0)])


def write_summary_json(summary: dict, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


def add_card(ax, title: str, value: str, subtitle: str, accent: str) -> None:
    ax.set_axis_off()
    panel = patches.FancyBboxPatch(
        (0, 0),
        1,
        1,
        boxstyle="round,pad=0.02,rounding_size=0.05",
        transform=ax.transAxes,
        fc="white",
        ec="#E7EBF3",
        lw=1.0,
    )
    ax.add_patch(panel)
    ax.add_patch(
        patches.FancyBboxPatch(
            (0.03, 0.12),
            0.02,
            0.76,
            boxstyle="round,pad=0,rounding_size=0.02",
            transform=ax.transAxes,
            fc=accent,
            ec=accent,
            lw=0,
        )
    )
    ax.text(0.08, 0.72, title, fontsize=11, color="#667085", transform=ax.transAxes)
    ax.text(0.08, 0.40, value, fontsize=22, fontweight="bold", color="#101828", transform=ax.transAxes)
    ax.text(0.08, 0.16, subtitle, fontsize=9, color="#98A2B3", transform=ax.transAxes)


def render_category_panel(ax, category_requests: Counter, category_sessions: Counter) -> None:
    style_panel(ax, "Bot 分类汇总", "全图统一按 bot session 展示；括号内不再混入请求量")
    rows = sorted(category_sessions.items(), key=lambda item: item[1], reverse=True)
    names = [name for name, _ in rows][::-1]
    values = [value for _, value in rows][::-1]
    ypos = np.arange(len(names))
    colors = [BOT_CATEGORY_COLORS.get(name, "#98A2B3") for name in names]
    ax.barh(ypos, values, color=colors, height=0.56)
    ax.set_yticks(ypos)
    ax.set_yticklabels(names)
    ax.set_xlabel("Bot sessions", fontsize=9, color="#738196")
    ax.grid(axis="x", color="#EEF2F7", lw=0.9)
    max_value = max(values) if values else 1
    for y, name, value in zip(ypos, names, values):
        ax.text(value + max_value * 0.02, y, fmt_count(value), va="center", fontsize=8.8, color="#334155")


def render_scope_panel(ax, session_gap_seconds: int, dropped: Counter) -> None:
    ax.set_axis_off()
    panel = patches.FancyBboxPatch(
        (0, 0),
        1,
        1,
        boxstyle="round,pad=0.02,rounding_size=0.04",
        transform=ax.transAxes,
        fc="white",
        ec="#E7EBF3",
        lw=1.0,
    )
    ax.add_patch(panel)
    ax.text(0.05, 0.93, "统计口径与排除项", fontsize=12, fontweight="bold", color="#182230", transform=ax.transAxes)
    ax.text(0.95, 0.93, "B-side bot 清洗版", fontsize=9, color="#7B879A", ha="right", transform=ax.transAxes)
    scope_lines = [
        "仅统计 B-side；只保留 GET 页面请求。",
        f"bot session 规则：同一 bot 指纹 {session_gap_label(session_gap_seconds)} 无活动后切新会话。",
        "分类主干：AI Retrieval / AI Training / AI Indexer / SEO Bot。",
        "补充分类：Social / Platform Bot、Other External Bot。",
        "排除：静态资源、admin/wp-/php/ashx/tel/feed/backup、残缺路径、隐藏探测路径。",
        "额外排除：Script / Client Bot、Scanner / Monitor Bot，不纳入客户 bot 报表。",
        f"当前被排除的脚本/扫描类 bot 请求约 {fmt_count(dropped.get('script_client_bot', 0) + dropped.get('scanner_monitor_bot', 0))}。",
    ]
    y = 0.83
    for line in scope_lines:
        ax.text(0.06, y, "- " + line, fontsize=9.0, color="#334155", transform=ax.transAxes, va="top")
        y -= 0.11


def render_dashboard(
    records: list[BotRequestRecord],
    sessions: list[BotSessionRecord],
    dropped: Counter,
    target: Path,
    session_gap_seconds: int,
) -> dict:
    target.parent.mkdir(parents=True, exist_ok=True)
    daily_requests = Counter(record.day for record in records)
    daily_sessions = Counter(session.day for session in sessions)
    category_requests = Counter(record.bot_category for record in records)
    category_sessions = Counter(session.bot_category for session in sessions)
    family_requests = Counter(record.bot_family for record in records)
    family_sessions = Counter(session.bot_family for session in sessions)
    entry_sessions = Counter(session.entry_page for session in sessions)
    duration_seconds = [max(0, int((session.end - session.start).total_seconds())) for session in sessions]
    duration_buckets = {
        "0s": sum(1 for value in duration_seconds if value == 0),
        "1-60s": sum(1 for value in duration_seconds if 1 <= value <= 60),
        "61-300s": sum(1 for value in duration_seconds if 61 <= value <= 300),
        "300s+": sum(1 for value in duration_seconds if value > 300),
    }
    ai_sessions = sum(category_sessions.get(name, 0) for name in ("AI Retrieval", "AI Training", "AI Indexer"))
    seo_sessions = category_sessions.get("SEO Bot", 0)
    unique_fingerprints = len({session.fingerprint for session in sessions})
    top_family, top_family_sessions = family_sessions.most_common(1)[0] if family_sessions else ("-", 0)
    peak_day, peak_sessions = max(daily_sessions.items(), key=lambda item: item[1]) if daily_sessions else ("-", 0)

    days = sorted(daily_requests)
    labels = [datetime.strptime(day, "%Y-%m-%d").strftime("%m-%d") for day in days]
    session_values = np.array([daily_sessions.get(day, 0) for day in days], dtype=float)
    ma7 = np.array([session_values[max(0, idx - 6) : idx + 1].mean() for idx in range(len(session_values))], dtype=float)

    fig = plt.figure(figsize=(18, 10.5), dpi=200, facecolor="#F5F7FB")
    gs = fig.add_gridspec(12, 24, left=0.03, right=0.97, top=0.92, bottom=0.05, hspace=0.92, wspace=0.85)
    fig.text(0.03, 0.965, "Moseeker B-side Bot Traffic Dashboard", fontsize=22, fontweight="bold", color="#0F172A")
    fig.text(
        0.03,
        0.938,
        f"仅统计 B-side | 当前看板统一按 bot session 展示 | bot session 阈值 {session_gap_label(session_gap_seconds)} | Script / 扫描类 bot 已排除",
        fontsize=10,
        color="#6B7280",
    )

    card_axes = [
        fig.add_subplot(gs[0:2, 0:4]),
        fig.add_subplot(gs[0:2, 4:8]),
        fig.add_subplot(gs[0:2, 8:12]),
        fig.add_subplot(gs[0:2, 12:16]),
        fig.add_subplot(gs[0:2, 16:20]),
        fig.add_subplot(gs[0:2, 20:24]),
    ]
    add_card(card_axes[0], "Bot Sessions", fmt_count(len(sessions)), f"会话阈值 {session_gap_label(session_gap_seconds)}", "#2F80ED")
    add_card(card_axes[1], "唯一 Bot 指纹", fmt_count(unique_fingerprints), "用于 bot session 聚合", "#4C9AFF")
    add_card(card_axes[2], "AI Bot Sessions", fmt_count(ai_sessions), "AI Retrieval / Training / Indexer", "#12B4A0")
    add_card(card_axes[3], "SEO Bot Sessions", fmt_count(seo_sessions), "Googlebot / Bingbot / Sogou 等", "#F2994A")
    add_card(card_axes[4], "峰值日期", peak_day, f"{fmt_count(peak_sessions)} 会话", "#7C4DFF")
    add_card(card_axes[5], "Top Bot 家族", top_family, f"{fmt_count(top_family_sessions)} 会话", "#00A58E")

    ax_trend = fig.add_subplot(gs[2:7, 0:12])
    style_panel(ax_trend, "每日 Bot Session 趋势", "全图统一按 bot session 展示；请求量明细保留在 CSV / Excel 中")
    x = np.arange(len(days))
    ax_trend.bar(x, session_values, color="#D8E8FF", width=0.68, edgecolor="none")
    ax_trend.plot(x, ma7, color="#2F80ED", lw=2.3, marker="o", markersize=3.2)
    ax_trend.set_ylabel("Bot sessions", fontsize=9, color="#667085")
    ax_trend.set_xlim(-0.6, len(x) - 0.4)
    tick_step = max(1, len(days) // 14)
    ax_trend.set_xticks(x[::tick_step] if len(x) else x)
    ax_trend.set_xticklabels(labels[::tick_step] if labels else labels)
    ax_trend.set_ylim(0, session_values.max() * 1.25 if len(session_values) else 1)
    if days:
        peak_idx = days.index(peak_day)
        ax_trend.annotate(
            f"峰值 {fmt_count(peak_sessions)}",
            xy=(peak_idx, peak_sessions),
            xytext=(max(0, peak_idx - 3), peak_sessions + session_values.max() * 0.12),
            arrowprops={"arrowstyle": "-", "color": "#2F80ED"},
            fontsize=9,
            color="#2F80ED",
            bbox={"boxstyle": "round,pad=0.2", "fc": "white", "ec": "#D7E6FF"},
        )

    ax_category = fig.add_subplot(gs[2:7, 12:18])
    render_category_panel(ax_category, category_requests, category_sessions)

    ax_family = fig.add_subplot(gs[2:7, 18:24])
    style_panel(ax_family, "Top Bot 家族", "全图统一按 bot session 展示")
    family_rows = family_sessions.most_common(8)
    family_names = [name for name, _ in family_rows][::-1]
    family_values = [value for _, value in family_rows][::-1]
    ypos = np.arange(len(family_names))
    ax_family.barh(ypos, family_values, color="#5BA2FF", alpha=0.92, height=0.56)
    ax_family.set_yticks(ypos)
    ax_family.set_yticklabels(family_names)
    ax_family.set_xlabel("Bot sessions", fontsize=9, color="#738196")
    ax_family.grid(axis="x", color="#EEF2F7", lw=0.9)
    max_family_value = max(family_values) if family_values else 1
    for y, value in zip(ypos, family_values):
        ax_family.text(value + max_family_value * 0.02, y, fmt_count(value), va="center", fontsize=8.8, color="#334155")

    ax_entry = fig.add_subplot(gs[7:12, 0:8])
    ax_entry.set_axis_off()
    panel = patches.FancyBboxPatch(
        (0, 0),
        1,
        1,
        boxstyle="round,pad=0.02,rounding_size=0.04",
        transform=ax_entry.transAxes,
        fc="white",
        ec="#E7EBF3",
        lw=1.0,
    )
    ax_entry.add_patch(panel)
    ax_entry.text(0.05, 0.93, "Bot 入口页面 Top 9", fontsize=12, fontweight="bold", color="#182230", transform=ax_entry.transAxes)
    ax_entry.text(0.95, 0.93, "按 bot session", fontsize=9, color="#7B879A", ha="right", transform=ax_entry.transAxes)
    ax_entry.text(0.05, 0.89, "统计每个 bot session 的首个页面。", fontsize=8.6, color="#7B879A", transform=ax_entry.transAxes)
    ax_entry.text(0.07, 0.84, "入口路径", fontsize=9, color="#7B879A", transform=ax_entry.transAxes)
    ax_entry.text(0.93, 0.84, "会话", fontsize=9, color="#7B879A", ha="right", transform=ax_entry.transAxes)
    top = 0.78
    row_h = 0.07
    for idx, (name, value) in enumerate(entry_sessions.most_common(9), start=1):
        y = top - (idx - 1) * row_h
        if idx % 2 == 1:
            ax_entry.add_patch(patches.Rectangle((0.04, y - 0.04), 0.92, 0.055, transform=ax_entry.transAxes, fc="#F8FAFD", ec="none"))
        ax_entry.text(0.06, y, f"{idx}. {short_label(name, 30)}", fontsize=9.5, color="#223044", transform=ax_entry.transAxes)
        ax_entry.text(0.93, y, fmt_count(value), fontsize=9.5, color="#223044", ha="right", transform=ax_entry.transAxes)

    ax_duration = fig.add_subplot(gs[7:12, 8:16])
    style_panel(ax_duration, "Bot Session 停留分布", "1 分钟会话阈值下，展示 bot session 的日志时长分层")
    bucket_names = list(duration_buckets.keys())
    bucket_values = [duration_buckets[name] for name in bucket_names]
    xpos = np.arange(len(bucket_names))
    ax_duration.bar(xpos, bucket_values, color="#F2994A", width=0.58)
    ax_duration.set_xticks(xpos)
    ax_duration.set_xticklabels(bucket_names)
    ax_duration.set_ylabel("Bot sessions", fontsize=9, color="#667085")
    ax_duration.set_ylim(0, max(bucket_values) * 1.22 if bucket_values and max(bucket_values) else 1)
    max_bucket = max(bucket_values) if bucket_values else 1
    for x_pos, value in zip(xpos, bucket_values):
        ax_duration.text(x_pos, value + max_bucket * 0.03, fmt_count(value), ha="center", fontsize=8.8, color="#475467")

    ax_scope = fig.add_subplot(gs[7:12, 16:24])
    render_scope_panel(ax_scope, session_gap_seconds, dropped)

    fig.text(
        0.03,
        0.022,
        "说明：这版主看板统一按 bot session 展示，只保留客户相关外部 bot，不含 curl/okhttp/scanner 等脚本或扫描型访问；请求量仍保留在 CSV / Excel 中。",
        fontsize=9,
        color="#6B7280",
    )
    fig.savefig(target, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)

    return {
        "date_start": days[0] if days else None,
        "date_end": days[-1] if days else None,
        "cleaned_bot_requests": len(records),
        "bot_sessions": len(sessions),
        "ai_bot_requests": sum(category_requests.get(name, 0) for name in ("AI Retrieval", "AI Training", "AI Indexer")),
        "seo_bot_requests": category_requests.get("SEO Bot", 0),
        "ai_bot_sessions": ai_sessions,
        "seo_bot_sessions": seo_sessions,
        "peak_day": peak_day,
        "peak_requests": max(daily_requests.values()) if daily_requests else 0,
        "peak_sessions": peak_sessions,
        "top_bot_family": top_family,
        "top_bot_family_requests": family_requests.get(top_family, 0),
        "top_bot_family_sessions": top_family_sessions,
        "daily_requests": sorted(daily_requests.items()),
        "daily_sessions": sorted(daily_sessions.items()),
        "category_requests": category_requests.most_common(),
        "category_sessions": category_sessions.most_common(),
        "family_requests": family_requests.most_common(),
        "family_sessions": family_sessions.most_common(),
        "top_entry_pages": entry_sessions.most_common(10),
        "duration_buckets": duration_buckets,
        "dropped_records": dropped,
        "filters": {
            "source_side": "B-side only",
            "allowed_methods": [TARGET_METHOD],
            "skip_first_days": SKIP_FIRST_DAYS,
            "include_only_bot_ua": True,
            "exclude_script_client_bot": True,
            "exclude_scanner_monitor_bot": True,
            "page_only": True,
            "exclude_path_contains": ["admin", "wp-", ".php", "tel:", "/feed", ".ashx", ".backup"],
            "exclude_path_suffixes": ["-"],
            "exclude_hidden_probe_paths": True,
            "session_gap_seconds": session_gap_seconds,
            "session_key": "full_user_agent_hash only",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate B-side bot dashboard.")
    parser.add_argument("--session-gap-seconds", type=int, default=BOT_SESSION_GAP_SECONDS, help="Bot session gap in seconds")
    args = parser.parse_args()

    setup_fonts()
    records, dropped = load_bside_bot_records()
    sessions = build_bot_sessions(records, timedelta(seconds=args.session_gap_seconds))
    stem = f"bside_bot_dashboard_{args.session_gap_seconds}s"
    write_bot_requests_csv(records, OUTPUT_DIR / f"{stem}_requests.csv")
    write_bot_sessions_csv(sessions, OUTPUT_DIR / f"{stem}_sessions.csv")
    write_daily_csv(Counter(record.day for record in records), Counter(session.day for session in sessions), OUTPUT_DIR / f"{stem}_daily.csv")
    summary = render_dashboard(records, sessions, dropped, OUTPUT_DIR / f"{stem}.png", args.session_gap_seconds)
    write_summary_json(summary, OUTPUT_DIR / f"{stem}_summary.json")


if __name__ == "__main__":
    main()
