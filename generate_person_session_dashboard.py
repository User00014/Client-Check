from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from statistics import mean

import matplotlib.pyplot as plt
import numpy as np
from matplotlib import font_manager, patches, rcParams

from generate_access_dashboard import B_LINE_RE, LOG_DIR, is_crawler_ua, normalize_page


OUTPUT_DIR = Path(__file__).resolve().parent / "output" / "current"
SKIP_FIRST_DAYS = 3
TARGET_METHOD = "GET"
CLARITY_SESSION_GAP_SECONDS = 30 * 60
PATH_CONTAINS_RULES = [
    ("tel:", "telephone_link_path"),
    ("/feed", "feed_path"),
    ("admin", "cms_admin_or_scan_path"),
    ("wp-", "cms_admin_or_scan_path"),
    (".php", "cms_admin_or_scan_path"),
    (".ashx", "cms_admin_or_scan_path"),
    (".backup", "backup_or_config_path"),
]
PATH_SUFFIX_RULES = [
    ("-", "truncated_path"),
]


@dataclass
class SessionRecord:
    session_id: int
    start: datetime
    end: datetime
    day: str
    proxy_ip: str
    fingerprint: str
    browser: str
    os: str
    device_type: str
    entry_page: str
    referer: str
    pageviews: int


def setup_fonts() -> None:
    candidates = [
        Path(r"C:\Windows\Fonts\msyh.ttc"),
        Path(r"C:\Windows\Fonts\simhei.ttf"),
        Path(r"C:\Windows\Fonts\segoeui.ttf"),
    ]
    font_name = None
    for path in candidates:
        if path.exists():
            font_manager.fontManager.addfont(str(path))
            font_name = font_manager.FontProperties(fname=str(path)).get_name()
            break
    if font_name:
        rcParams["font.family"] = font_name
    rcParams["axes.unicode_minus"] = False


def fmt_count(value: int) -> str:
    if value >= 10_000:
        return f"{value / 10_000:.1f}万"
    if value >= 1_000:
        return f"{value / 1_000:.1f}k"
    return str(value)


def short_label(text: str, limit: int = 28) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def browser_family(user_agent: str) -> str:
    ua = user_agent.lower()
    if "micromessenger" in ua:
        return "WeChat"
    if "edg/" in ua or "edge/" in ua:
        return "Edge"
    if "firefox/" in ua:
        return "Firefox"
    if "chrome/" in ua and "edg/" not in ua and "opr/" not in ua:
        return "Chrome"
    if "safari/" in ua and "chrome/" not in ua:
        return "Safari"
    return "Other"


def os_family(user_agent: str) -> str:
    ua = user_agent.lower()
    if "windows" in ua:
        return "Windows"
    if "android" in ua:
        return "Android"
    if "iphone" in ua or "ipad" in ua or "ios" in ua:
        return "iOS"
    if "mac os x" in ua or "macintosh" in ua:
        return "macOS"
    if "linux" in ua:
        return "Linux"
    return "Other"


def device_type(user_agent: str) -> str:
    ua = user_agent.lower()
    if "ipad" in ua or "tablet" in ua:
        return "Tablet"
    if "mobile" in ua or "android" in ua or "iphone" in ua:
        return "Mobile"
    return "Desktop"


def b_skip_before_date() -> str:
    dates = set()
    for path in sorted(LOG_DIR.glob("moseeker_b_side_access_*.log")):
        match = path.stem.split("_")[-1]
        try:
            dates.add(datetime.strptime(match, "%Y%m%d").strftime("%Y-%m-%d"))
        except ValueError:
            continue
    ordered = sorted(dates)
    if not ordered:
        raise RuntimeError("No usable B-side log dates found.")
    return ordered[min(SKIP_FIRST_DAYS, len(ordered) - 1)]


def session_gap_label(session_gap_seconds: int) -> str:
    if session_gap_seconds % 3600 == 0:
        hours = session_gap_seconds // 3600
        return f"{hours} 小时"
    if session_gap_seconds % 60 == 0:
        minutes = session_gap_seconds // 60
        return f"{minutes} 分钟"
    return f"{session_gap_seconds} 秒"


def page_exclusion_reason(path: str) -> str | None:
    lower = path.lower()
    if lower.startswith("/."):
        return "hidden_probe_path"
    for token, reason in PATH_CONTAINS_RULES:
        if token in lower:
            return reason
    for suffix, reason in PATH_SUFFIX_RULES:
        if lower.endswith(suffix):
            return reason
    return None


def load_bside_records() -> tuple[list[tuple[datetime, str, str, str, str, str]], Counter]:
    skip_before = b_skip_before_date()
    dropped = Counter()
    records: list[tuple[datetime, str, str, str, str, str]] = []

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
                if is_crawler_ua(item["ua"]):
                    dropped["crawler_ua"] += 1
                    continue

                page = normalize_page(item["uri"])
                if not page:
                    dropped["static_or_non_page"] += 1
                    continue
                exclusion_reason = page_exclusion_reason(page)
                if exclusion_reason:
                    dropped[exclusion_reason] += 1
                    continue

                referer = item["referer"] if item["referer"] and item["referer"] != "-" else "(direct / none)"
                records.append((dt, day, item["ip"], item["ua"], page, referer))

    records.sort(key=lambda row: row[0])
    return records, dropped


def build_sessions(records: list[tuple[datetime, str, str, str, str, str]], session_gap: timedelta) -> list[SessionRecord]:
    sessions: list[SessionRecord] = []
    last_seen: dict[str, datetime] = {}
    active_session: dict[str, int] = {}

    for dt, day, proxy_ip, user_agent, page, referer in records:
        fingerprint = hashlib.sha1(user_agent.encode("utf-8", "ignore")).hexdigest()[:12]
        prev = last_seen.get(fingerprint)
        session_index = active_session.get(fingerprint)

        if prev is None or dt - prev > session_gap or session_index is None:
            session_index = len(sessions)
            sessions.append(
                SessionRecord(
                    session_id=session_index + 1,
                    start=dt,
                    end=dt,
                    day=day,
                    proxy_ip=proxy_ip,
                    fingerprint=fingerprint,
                    browser=browser_family(user_agent),
                    os=os_family(user_agent),
                    device_type=device_type(user_agent),
                    entry_page=page,
                    referer=referer,
                    pageviews=1,
                )
            )
            active_session[fingerprint] = session_index
        else:
            sessions[session_index].end = dt
            sessions[session_index].pageviews += 1

        last_seen[fingerprint] = dt

    return sessions


def write_session_csv(sessions: list[SessionRecord], target: Path) -> None:
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
                "browser",
                "os",
                "device_type",
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
                    session.browser,
                    session.os,
                    session.device_type,
                    session.entry_page,
                    session.referer,
                    session.pageviews,
                    duration_seconds,
                ]
            )


def write_daily_csv(daily_sessions: Counter, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["date", "estimated_sessions"])
        for day in sorted(daily_sessions):
            writer.writerow([day, daily_sessions[day]])


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


def style_panel(ax, title: str, subtitle: str) -> None:
    ax.set_facecolor("white")
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.grid(axis="y", color="#EEF2F7", lw=0.9)
    ax.tick_params(colors="#738196", labelsize=9, length=0)
    ax.set_title(title, loc="left", pad=10, fontsize=12, fontweight="bold", color="#182230")
    ax.text(0, 1.01, subtitle, transform=ax.transAxes, fontsize=9, color="#7B879A", va="bottom")


def render_device_panel(ax, device_counter: Counter) -> None:
    ax.set_facecolor("white")
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_xticks([])
    ax.set_yticks([])
    ax.set_title("设备分布（按人次）", loc="left", pad=10, fontsize=12, fontweight="bold", color="#182230")
    ax.text(0.0, 1.01, "电脑 / 手机 / 平板按人次分层。", transform=ax.transAxes, fontsize=9, color="#7B879A", va="bottom")

    labels = ["Desktop", "Mobile", "Tablet"]
    values = [device_counter.get(label, 0) for label in labels]
    colors = ["#2F80ED", "#49A3FF", "#B7D4FF"]
    total = sum(values) or 1
    ax.pie(
        values,
        colors=colors,
        startangle=90,
        counterclock=False,
        wedgeprops={"width": 0.32, "edgecolor": "white"},
    )
    ax.text(0, 0.06, "Desktop", ha="center", va="center", fontsize=13, fontweight="bold", color="#0F172A")
    ax.text(0, -0.12, f"{values[0] / total:.1%}", ha="center", va="center", fontsize=11, color="#6B7280")

    legend_y = -1.02
    display_names = {"Desktop": "电脑", "Mobile": "手机", "Tablet": "平板"}
    for idx, (label, value) in enumerate(zip(labels, values)):
        ax.add_patch(
            patches.Rectangle((-1.1, legend_y - idx * 0.23), 0.08, 0.08, color=colors[idx], transform=ax.transData)
        )
        ax.text(-0.95, legend_y + 0.04 - idx * 0.23, display_names[label], fontsize=9.5, color="#334155", va="center")
        ax.text(0.98, legend_y + 0.04 - idx * 0.23, fmt_count(value), fontsize=9.5, color="#334155", va="center", ha="right")


def render_dashboard(
    sessions: list[SessionRecord],
    records_count: int,
    dropped: Counter,
    target: Path,
    session_gap_seconds: int,
) -> dict:
    target.parent.mkdir(parents=True, exist_ok=True)

    daily_sessions = Counter(session.day for session in sessions)
    entry_counter = Counter(session.entry_page for session in sessions)
    browser_counter = Counter(session.browser for session in sessions)
    os_counter = Counter(session.os for session in sessions)
    device_counter = Counter(session.device_type for session in sessions)
    proxy_counter = Counter(session.proxy_ip for session in sessions)
    unique_fingerprints = len({session.fingerprint for session in sessions})
    pageviews = [session.pageviews for session in sessions]
    duration_seconds = [max(0, int((session.end - session.start).total_seconds())) for session in sessions]
    session_gap_text = session_gap_label(session_gap_seconds)

    days = sorted(daily_sessions)
    labels = [datetime.strptime(day, "%Y-%m-%d").strftime("%m-%d") for day in days]
    values = np.array([daily_sessions[day] for day in days], dtype=float)
    ma7 = np.array([values[max(0, idx - 6) : idx + 1].mean() for idx in range(len(values))], dtype=float)

    peak_day, peak_value = max(daily_sessions.items(), key=lambda item: item[1]) if daily_sessions else ("-", 0)
    avg_pages = mean(pageviews) if pageviews else 0.0
    avg_duration_seconds = mean(duration_seconds) if duration_seconds else 0.0
    home_share = 0 if not sessions else entry_counter.get("/", 0) / len(sessions)
    duration_buckets = {
        "0s": sum(1 for value in duration_seconds if value == 0),
        "1-30s": sum(1 for value in duration_seconds if 1 <= value <= 30),
        "31-300s": sum(1 for value in duration_seconds if 31 <= value <= 300),
        "300s+": sum(1 for value in duration_seconds if value > 300),
    }

    fig = plt.figure(figsize=(18, 10.5), dpi=200, facecolor="#F5F7FB")
    gs = fig.add_gridspec(12, 24, left=0.03, right=0.97, top=0.92, bottom=0.05, hspace=0.92, wspace=0.8)

    fig.text(0.03, 0.965, "Moseeker B-side Person-Session Dashboard", fontsize=22, fontweight="bold", color="#0F172A")
    fig.text(
        0.03,
        0.938,
        f"仅统计 B-side | 会话键使用浏览器指纹（完整 UA 哈希） | 与 Clarity 对齐：同一指纹 {session_gap_text} 无活动后切新会话 | 代理内网 IP 不参与会话键",
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
    add_card(card_axes[0], "估算人次", fmt_count(len(sessions)), f"会话阈值 {session_gap_text}", "#2F80ED")
    add_card(card_axes[1], "唯一浏览器指纹", fmt_count(unique_fingerprints), "B-side 仅用指纹聚合", "#4C9AFF")
    add_card(card_axes[2], "平均页数/人次", f"{avg_pages:.1f}", "中位数 {}".format(int(np.median(pageviews)) if pageviews else 0), "#00A58E")
    add_card(card_axes[3], "平均时长", f"{avg_duration_seconds:.1f} 秒", "大量会话为单页即走", "#F2994A")
    add_card(card_axes[4], "峰值日期", peak_day, f"{fmt_count(peak_value)} 人次", "#7C4DFF")
    add_card(card_axes[5], "首页入口占比", f"{home_share:.1%}", f"可用页面请求 {fmt_count(records_count)}", "#12B4A0")

    ax_trend = fig.add_subplot(gs[2:7, 0:12])
    style_panel(ax_trend, "每日人次趋势", "柱形为单日估算人次，折线为 7 日均线；已去掉最早 3 天、仅保留 GET、已去爬虫、静态资源与异常路径")
    x = np.arange(len(days))
    ax_trend.bar(x, values, color="#CFE2FF", width=0.68, edgecolor="none")
    ax_trend.plot(x, ma7, color="#2F80ED", lw=2.5, marker="o", markersize=3.2)
    ax_trend.set_xlim(-0.6, len(x) - 0.4)
    tick_step = max(1, len(days) // 14)
    tick_positions = x[::tick_step] if len(x) else x
    tick_labels = labels[::tick_step] if labels else labels
    ax_trend.set_xticks(tick_positions)
    ax_trend.set_xticklabels(tick_labels)
    ax_trend.set_ylabel("Estimated sessions", fontsize=9, color="#667085")
    ax_trend.set_ylim(0, values.max() * 1.25 if len(values) else 1)
    peak_idx = days.index(peak_day) if days else 0
    ax_trend.annotate(
        f"峰值 {fmt_count(peak_value)}",
        xy=(peak_idx, peak_value),
        xytext=(max(0, peak_idx - 3), peak_value + values.max() * 0.12 if len(values) else 1),
        arrowprops={"arrowstyle": "-", "color": "#2F80ED"},
        fontsize=9,
        color="#2F80ED",
        bbox={"boxstyle": "round,pad=0.2", "fc": "white", "ec": "#D7E6FF"},
    )

    ax_browser = fig.add_subplot(gs[2:7, 12:18])
    style_panel(ax_browser, "浏览器分布（按人次）", "同一会话只记一次浏览器类别，更贴近人次结构")
    browser_rows = browser_counter.most_common(6)
    browser_names = [name for name, _ in browser_rows][::-1]
    browser_values = [value for _, value in browser_rows][::-1]
    ypos = np.arange(len(browser_names))
    ax_browser.barh(ypos, browser_values, color="#2F80ED", alpha=0.92, height=0.56)
    ax_browser.set_yticks(ypos)
    ax_browser.set_yticklabels(browser_names)
    ax_browser.set_xlabel("Estimated sessions", fontsize=9, color="#738196")
    ax_browser.grid(axis="x", color="#EEF2F7", lw=0.9)
    for y, value in zip(ypos, browser_values):
        ax_browser.text(value + max(browser_values) * 0.02, y, fmt_count(value), va="center", fontsize=9, color="#334155")

    ax_device = fig.add_subplot(gs[2:7, 18:24])
    render_device_panel(ax_device, device_counter)

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
    ax_entry.text(0.05, 0.93, "入口页面 Top 9", fontsize=12, fontweight="bold", color="#182230", transform=ax_entry.transAxes)
    ax_entry.text(0.95, 0.93, "按人次", fontsize=9, color="#7B879A", ha="right", transform=ax_entry.transAxes)
    ax_entry.text(0.05, 0.89, "统计每次人次的首个页面，而不是总 PV。", fontsize=8.6, color="#7B879A", transform=ax_entry.transAxes)
    ax_entry.text(0.07, 0.84, "入口路径", fontsize=9, color="#7B879A", transform=ax_entry.transAxes)
    ax_entry.text(0.93, 0.84, "人次", fontsize=9, color="#7B879A", ha="right", transform=ax_entry.transAxes)
    top = 0.78
    row_h = 0.07
    for idx, (name, value) in enumerate(entry_counter.most_common(9), start=1):
        y = top - (idx - 1) * row_h
        if idx % 2 == 1:
            ax_entry.add_patch(
                patches.Rectangle((0.04, y - 0.04), 0.92, 0.055, transform=ax_entry.transAxes, fc="#F8FAFD", ec="none")
            )
        ax_entry.text(0.06, y, f"{idx}. {short_label(name, 30)}", fontsize=9.5, color="#223044", transform=ax_entry.transAxes)
        ax_entry.text(0.93, y, fmt_count(value), fontsize=9.5, color="#223044", ha="right", transform=ax_entry.transAxes)

    ax_duration = fig.add_subplot(gs[7:12, 8:16])
    style_panel(ax_duration, "会话停留分布", "会话边界与 Clarity 对齐为 30 分钟无活动；这里展示日志中的持续时间分层")
    bucket_names = list(duration_buckets.keys())
    bucket_values = [duration_buckets[name] for name in bucket_names]
    xpos = np.arange(len(bucket_names))
    ax_duration.bar(xpos, bucket_values, color="#F2994A", width=0.58)
    ax_duration.set_xticks(xpos)
    ax_duration.set_xticklabels(bucket_names)
    ax_duration.set_ylabel("Estimated sessions", fontsize=9, color="#667085")
    ax_duration.set_ylim(0, max(bucket_values) * 1.22 if bucket_values else 1)
    for x_pos, value in zip(xpos, bucket_values):
        ax_duration.text(x_pos, value + max(bucket_values) * 0.03, fmt_count(value), ha="center", fontsize=8.8, color="#475467")

    ax_scope = fig.add_subplot(gs[7:12, 16:24])
    ax_scope.set_axis_off()
    panel = patches.FancyBboxPatch(
        (0, 0),
        1,
        1,
        boxstyle="round,pad=0.02,rounding_size=0.04",
        transform=ax_scope.transAxes,
        fc="white",
        ec="#E7EBF3",
        lw=1.0,
    )
    ax_scope.add_patch(panel)
    ax_scope.text(0.05, 0.93, "统计口径与排除项", fontsize=12, fontweight="bold", color="#182230", transform=ax_scope.transAxes)
    ax_scope.text(0.95, 0.93, "请按此理解图中数字", fontsize=9, color="#7B879A", ha="right", transform=ax_scope.transAxes)
    scope_lines = [
        "仅统计 B-side；本批 B-side 只能拿到内网代理 IP，因此不使用 IP 做会话键。",
        "浏览器指纹近似：使用完整 UA 哈希，并同时展示浏览器 / OS / 设备分类。",
        f"人次定义：参照 Clarity，按同一浏览器指纹 {session_gap_text} 无活动后切新会话。",
        "过滤项：去掉最早 3 天、仅保留 GET、剔除 UA 识别爬虫、全局过滤静态资源。",
        "路径剔除：删除含 admin / wp- / .php / tel: / /feed / .ashx / .backup 的路径。",
        "路径剔除：删除以 - 结尾的残缺路径，以及 `/.env`、`/.git/config` 这类隐藏探测路径。",
        "残余风险：多个真实用户若共用同一 UA 且访问时间接近，会被合并；缺少 tab 与前端事件数据，因此是 Clarity 风格近似估算。",
    ]
    y = 0.82
    for line in scope_lines:
        ax_scope.text(0.06, y, "- " + line, fontsize=9.1, color="#334155", transform=ax_scope.transAxes, va="top")
        y -= 0.12

    fig.text(
        0.03,
        0.022,
        "说明：这版强调“B-side 人次估算”，不是 UV。由于不使用公网 IP，只能按浏览器指纹近似还原 Clarity 风格会话，因此更适合看趋势与结构，而不是绝对人数。",
        fontsize=9,
        color="#6B7280",
    )
    fig.savefig(target, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)

    return {
        "date_start": days[0] if days else None,
        "date_end": days[-1] if days else None,
        "estimated_sessions": len(sessions),
        "qualifying_page_requests": records_count,
        "unique_fingerprints": unique_fingerprints,
        "avg_pages_per_session": round(avg_pages, 2) if sessions else 0,
        "avg_duration_seconds": round(avg_duration_seconds, 2) if sessions else 0,
        "home_entry_share": round(home_share, 4) if sessions else 0,
        "peak_day": peak_day,
        "peak_sessions": peak_value,
        "top_entry_pages": entry_counter.most_common(10),
        "browser_share": browser_counter.most_common(),
        "device_share": device_counter.most_common(),
        "os_share": os_counter.most_common(),
        "proxy_ip_share": proxy_counter.most_common(),
        "duration_buckets": duration_buckets,
        "dropped_records": dropped,
        "filters": {
            "source_side": "B-side only",
            "skip_first_days": SKIP_FIRST_DAYS,
            "allowed_methods": [TARGET_METHOD],
            "exclude_crawler_ua": True,
            "page_only": True,
            "exclude_path_contains": [token for token, _ in PATH_CONTAINS_RULES],
            "exclude_path_suffixes": [suffix for suffix, _ in PATH_SUFFIX_RULES],
            "exclude_hidden_probe_paths": True,
            "session_gap_seconds": session_gap_seconds,
            "session_alignment": "approximate Microsoft Clarity inactivity timeout",
            "session_key": "full_user_agent_hash only",
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate B-side person-session dashboard.")
    parser.add_argument(
        "--session-gap-seconds",
        type=int,
        default=CLARITY_SESSION_GAP_SECONDS,
        help="Session gap in seconds; default aligns to Clarity inactivity timeout",
    )
    return parser.parse_args()


def main() -> None:
    setup_fonts()
    args = parse_args()
    records, dropped = load_bside_records()
    sessions = build_sessions(records, timedelta(seconds=args.session_gap_seconds))
    daily_sessions = Counter(session.day for session in sessions)
    stem = f"bside_person_session_dashboard_clarity_{args.session_gap_seconds}s"
    write_session_csv(sessions, OUTPUT_DIR / f"{stem}_sessions.csv")
    write_daily_csv(daily_sessions, OUTPUT_DIR / f"{stem}_daily.csv")
    summary = render_dashboard(sessions, len(records), dropped, OUTPUT_DIR / f"{stem}.png", args.session_gap_seconds)
    write_summary_json(summary, OUTPUT_DIR / f"{stem}_summary.json")


if __name__ == "__main__":
    main()
