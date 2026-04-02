from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

import matplotlib.pyplot as plt
import numpy as np
from matplotlib import font_manager, patches, rcParams


ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "日志"
OUTPUT_DIR = ROOT / "output"


B_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<dt>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

ASSET_EXTS = {
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
    ".xml",
    ".txt",
    ".webp",
    ".avif",
    ".mp4",
    ".mp3",
    ".json",
    ".pdf",
}
IGNORE_PREFIXES = ("/wp-content/", "/wp-includes/")
STATUS_ORDER = ["2xx", "3xx", "4xx", "5xx", "other"]
STATUS_COLORS = {
    "2xx": "#2F80ED",
    "3xx": "#86B6FF",
    "4xx": "#F2994A",
    "5xx": "#EB5757",
    "other": "#C3CAD7",
}
METHOD_COLORS = ["#2F80ED", "#67A5FF", "#9CC3FF", "#D7E6FF"]
BOT_TOKENS = [
    "bot",
    "spider",
    "crawler",
    "curl",
    "python",
    "java/",
    "go-http-client",
    "scanner",
    "monitor",
    "bytespider",
    "headless",
    "scrapy",
    "wget",
    "httpclient",
    "axios",
    "okhttp",
    "feedfetcher",
    "googleother",
    "facebookexternalhit",
    "slurp",
]
IP_GEO_OVERRIDES = {
    "39.171.200.156": {"location": "中国 · 上海", "org": "China Mobile"},
    "178.156.169.144": {"location": "美国 · 弗吉尼亚 Ashburn", "org": "Hetzner Online"},
    "118.26.36.227": {"location": "中国香港 · 近似归属", "org": "UCloud (HK)"},
    "66.249.79.135": {"location": "美国 · 俄勒冈 The Dalles", "org": "Googlebot"},
    "185.177.72.60": {"location": "法国 · 巴黎", "org": "FBW NETWORKS"},
    "66.249.79.136": {"location": "美国 · 加州 Mountain View", "org": "Googlebot"},
    "66.249.79.137": {"location": "美国 · 俄勒冈 The Dalles", "org": "Googlebot"},
    "101.42.246.195": {"location": "中国 · 北京", "org": "Tencent Cloud"},
    "82.157.16.188": {"location": "中国 · 近似归属", "org": "Tencent / Shenzhen"},
    "101.43.224.14": {"location": "中国 · 近似归属", "org": "Tencent / Shenzhen"},
    "202.8.9.242": {"location": "日本 · 东京品川", "org": "Teraswitch"},
}


@dataclass
class DashboardData:
    date_range: list[datetime]
    daily_b: Counter
    daily_c: Counter
    daily_b_crawler: Counter
    daily_c_crawler: Counter
    b_status_by_day: dict[str, Counter]
    c_status_by_day: dict[str, Counter]
    b_status_total: Counter
    c_status_total: Counter
    method_total: Counter
    page_total: Counter
    c_host_total: Counter
    c_ip_total: Counter
    public_ip_total: Counter
    crawler_family_total: Counter
    b_total: int
    c_total: int
    raw_b_total: int
    raw_c_total: int
    crawler_b_total: int
    crawler_c_total: int


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


def status_bucket(status: str | int | None) -> str:
    try:
        value = int(status)
    except (TypeError, ValueError):
        return "other"
    if 200 <= value < 300:
        return "2xx"
    if 300 <= value < 400:
        return "3xx"
    if 400 <= value < 500:
        return "4xx"
    if 500 <= value < 600:
        return "5xx"
    return "other"


def normalize_page(uri: str) -> str | None:
    path = urlsplit(uri).path or "/"
    if path.startswith(IGNORE_PREFIXES):
        return None
    lower = path.lower()
    if any(lower.endswith(ext) for ext in ASSET_EXTS):
        return None
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


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


def date_sequence(start: datetime, end: datetime) -> list[datetime]:
    current = start
    result = []
    while current <= end:
        result.append(current)
        current += timedelta(days=1)
    return result


def normalize_ip(raw_ip: str | None) -> str:
    if not raw_ip:
        return ""
    return raw_ip.split(",")[0].strip()


def is_crawler_ua(user_agent: str | None) -> bool:
    ua = (user_agent or "").lower()
    return any(token in ua for token in BOT_TOKENS)


def crawler_family(user_agent: str | None) -> str:
    ua = (user_agent or "").lower()
    family_rules = [
        ("Googlebot", ["googlebot", "googleother", "feedfetcher"]),
        ("360Spider", ["360spider"]),
        ("Bytespider", ["bytespider"]),
        ("YisouSpider", ["yisouspider", "yisou"]),
        ("SogouSpider", ["sogou"]),
        ("Curl/Script", ["curl", "python", "wget", "go-http-client", "axios", "httpclient", "okhttp"]),
        ("Scanner/Monitor", ["scanner", "monitor", "headless", "scrapy"]),
    ]
    for family, tokens in family_rules:
        if any(token in ua for token in tokens):
            return family
    return "Other Bot"


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_unspecified
    )


def iter_b_logs() -> Iterable[Path]:
    yield from sorted(LOG_DIR.glob("moseeker_b_side_access_*.log"))


def iter_c_logs() -> Iterable[Path]:
    yield from sorted(LOG_DIR.glob("moseeker_c_side_access_*.log"))


def skip_days(skip_first_days: int) -> set[str]:
    if skip_first_days <= 0:
        return set()
    dates = set()
    for path in list(iter_b_logs()) + list(iter_c_logs()):
        match = re.search(r"_(\d{8})\.log$", path.name)
        if not match:
            continue
        dates.add(datetime.strptime(match.group(1), "%Y%m%d").strftime("%Y-%m-%d"))
    return set(sorted(dates)[:skip_first_days])


def parse_logs(
    exclude_crawlers: bool = False,
    skip_first_days: int = 0,
    allowed_methods: set[str] | None = None,
    page_only: bool = False,
) -> DashboardData:
    skipped_days = skip_days(skip_first_days)
    daily_b: Counter = Counter()
    daily_c: Counter = Counter()
    daily_b_crawler: Counter = Counter()
    daily_c_crawler: Counter = Counter()
    b_status_by_day: dict[str, Counter] = defaultdict(Counter)
    c_status_by_day: dict[str, Counter] = defaultdict(Counter)
    b_status_total: Counter = Counter()
    c_status_total: Counter = Counter()
    method_total: Counter = Counter()
    page_total: Counter = Counter()
    c_host_total: Counter = Counter()
    c_ip_total: Counter = Counter()
    public_ip_total: Counter = Counter()
    crawler_family_total: Counter = Counter()
    all_days: list[datetime] = []
    b_total = 0
    c_total = 0
    raw_b_total = 0
    raw_c_total = 0
    crawler_b_total = 0
    crawler_c_total = 0

    for path in iter_b_logs():
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                match = B_LINE_RE.match(line)
                if not match:
                    continue
                item = match.groupdict()
                dt = datetime.strptime(item["dt"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
                day = dt.strftime("%Y-%m-%d")
                if day in skipped_days:
                    continue
                if allowed_methods and item["method"] not in allowed_methods:
                    continue
                page = normalize_page(item["uri"])
                if page_only and not page:
                    continue

                all_days.append(dt)
                raw_b_total += 1
                is_crawler = is_crawler_ua(item["ua"])
                if is_crawler:
                    daily_b_crawler[day] += 1
                    crawler_b_total += 1
                    crawler_family_total[crawler_family(item["ua"])] += 1
                    if exclude_crawlers:
                        continue

                daily_b[day] += 1
                b_total += 1

                bucket = status_bucket(item["status"])
                b_status_by_day[day][bucket] += 1
                b_status_total[bucket] += 1
                method_total[item["method"]] += 1

                if page:
                    page_total[page] += 1

    for path in iter_c_logs():
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    item = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                ts = item.get("ts") or item.get("@timestamp")
                if not ts:
                    continue
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
                except ValueError:
                    continue

                day = dt.strftime("%Y-%m-%d")
                if day in skipped_days:
                    continue
                method = item.get("method") or "UNKNOWN"
                if allowed_methods and method not in allowed_methods:
                    continue
                page = normalize_page(item.get("uri") or "")
                if page_only and not page:
                    continue

                all_days.append(dt)
                raw_c_total += 1
                user_agent = item.get("ua") or ""
                is_crawler = is_crawler_ua(user_agent)
                if is_crawler:
                    daily_c_crawler[day] += 1
                    crawler_c_total += 1
                    crawler_family_total[crawler_family(user_agent)] += 1
                    if exclude_crawlers:
                        continue

                daily_c[day] += 1
                c_total += 1

                bucket = status_bucket(item.get("status"))
                c_status_by_day[day][bucket] += 1
                c_status_total[bucket] += 1

                method_total[method] += 1

                host = item.get("host") or "-"
                c_host_total[host] += 1

                ip = normalize_ip(item.get("x_forwarded_for") or item.get("remote_addr") or "-")
                c_ip_total[ip] += 1
                if is_public_ip(ip):
                    public_ip_total[ip] += 1

                if page:
                    page_total[page] += 1

    if not all_days:
        raise RuntimeError("No readable log records were found.")

    start = min(all_days).replace(hour=0, minute=0, second=0, microsecond=0)
    end = max(all_days).replace(hour=0, minute=0, second=0, microsecond=0)
    return DashboardData(
        date_range=date_sequence(start, end),
        daily_b=daily_b,
        daily_c=daily_c,
        daily_b_crawler=daily_b_crawler,
        daily_c_crawler=daily_c_crawler,
        b_status_by_day=dict(b_status_by_day),
        c_status_by_day=dict(c_status_by_day),
        b_status_total=b_status_total,
        c_status_total=c_status_total,
        method_total=method_total,
        page_total=page_total,
        c_host_total=c_host_total,
        c_ip_total=c_ip_total,
        public_ip_total=public_ip_total,
        crawler_family_total=crawler_family_total,
        b_total=b_total,
        c_total=c_total,
        raw_b_total=raw_b_total,
        raw_c_total=raw_c_total,
        crawler_b_total=crawler_b_total,
        crawler_c_total=crawler_c_total,
    )


def write_daily_csv(data: DashboardData, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "date",
                "b_requests",
                "c_requests",
                "b_crawler_detected",
                "c_crawler_detected",
                "b_2xx",
                "b_3xx",
                "b_4xx",
                "b_5xx",
                "b_other",
                "c_2xx",
                "c_3xx",
                "c_4xx",
                "c_5xx",
                "c_other",
            ]
        )
        for dt in data.date_range:
            key = dt.strftime("%Y-%m-%d")
            b_bucket = data.b_status_by_day.get(key, Counter())
            c_bucket = data.c_status_by_day.get(key, Counter())
            writer.writerow(
                [
                    key,
                    data.daily_b.get(key, 0),
                    data.daily_c.get(key, 0),
                    data.daily_b_crawler.get(key, 0),
                    data.daily_c_crawler.get(key, 0),
                    b_bucket.get("2xx", 0),
                    b_bucket.get("3xx", 0),
                    b_bucket.get("4xx", 0),
                    b_bucket.get("5xx", 0),
                    b_bucket.get("other", 0),
                    c_bucket.get("2xx", 0),
                    c_bucket.get("3xx", 0),
                    c_bucket.get("4xx", 0),
                    c_bucket.get("5xx", 0),
                    c_bucket.get("other", 0),
                ]
            )


def write_summary_json(
    data: DashboardData,
    target: Path,
    exclude_crawlers: bool = False,
    skip_first_days: int = 0,
    allowed_methods: set[str] | None = None,
    page_only: bool = False,
) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    crawler_total = data.crawler_b_total + data.crawler_c_total
    raw_total = data.raw_b_total + data.raw_c_total
    page_total_sum = sum(data.page_total.values())
    payload = {
        "date_start": data.date_range[0].strftime("%Y-%m-%d"),
        "date_end": data.date_range[-1].strftime("%Y-%m-%d"),
        "b_total": data.b_total,
        "c_total": data.c_total,
        "raw_b_total": data.raw_b_total,
        "raw_c_total": data.raw_c_total,
        "crawler_b_total": data.crawler_b_total,
        "crawler_c_total": data.crawler_c_total,
        "crawler_total": crawler_total,
        "crawler_share_of_raw": 0 if raw_total == 0 else round(crawler_total / raw_total, 4),
        "top_crawler_families": data.crawler_family_total.most_common(10),
        "page_request_total": page_total_sum,
        "c_unique_ip": len(data.c_ip_total),
        "top_pages": data.page_total.most_common(10),
        "top_c_hosts": data.c_host_total.most_common(8),
        "top_public_ips": data.public_ip_total.most_common(12),
        "method_share": data.method_total.most_common(),
        "notes": {
            "b_total_scope": (
                "B-side page-like requests after selected filters; static assets are excluded globally."
                if page_only
                else "B-side total requests after selected filters; includes page and asset requests."
            ),
            "page_request_total_scope": "B-side and C-side page-like requests after selected filters; excludes wp-content/wp-includes and common static asset extensions.",
        },
        "filters": {
            "exclude_crawlers": exclude_crawlers,
            "skip_first_days": skip_first_days,
            "allowed_methods": sorted(allowed_methods) if allowed_methods else "ALL",
            "page_only": page_only,
            "page_filters": [
                "exclude /wp-content/*",
                "exclude /wp-includes/*",
                "exclude common static asset extensions",
            ],
        },
    }
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_public_ip_csv(data: DashboardData, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ip", "requests", "location", "organization"])
        for ip, value in data.public_ip_total.most_common(20):
            geo = IP_GEO_OVERRIDES.get(ip, {})
            writer.writerow([ip, value, geo.get("location", "待补充"), geo.get("org", "待补充")])


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
    ax.text(0.08, 0.72, title, fontsize=11, color="#5D6B82", transform=ax.transAxes)
    ax.text(0.08, 0.40, value, fontsize=24, fontweight="bold", color="#111827", transform=ax.transAxes)
    ax.text(0.08, 0.16, subtitle, fontsize=9, color="#7B879A", transform=ax.transAxes)


def style_panel(ax, title: str, subtitle: str | None = None) -> None:
    ax.set_facecolor("white")
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.grid(axis="y", color="#EEF2F7", lw=0.9)
    ax.tick_params(colors="#738196", labelsize=9, length=0)
    ax.set_title(title, loc="left", pad=8, fontsize=12, fontweight="bold", color="#182230")
    if subtitle:
        ax.text(
            0,
            1.005,
            subtitle,
            transform=ax.transAxes,
            fontsize=9,
            color="#7B879A",
            va="bottom",
        )


def draw_page_table(ax, rows: list[tuple[str, int]]) -> None:
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
    ax.text(0.05, 0.93, "热门页面 Top 9", fontsize=12, fontweight="bold", color="#182230", transform=ax.transAxes)
    ax.text(0.95, 0.93, "仅页面型请求", fontsize=9, color="#7B879A", ha="right", transform=ax.transAxes)
    ax.text(0.05, 0.89, "B-side / C-side 已过滤静态资源，仅展示前 9 个路径。", fontsize=8.6, color="#7B879A", transform=ax.transAxes)
    ax.text(0.07, 0.84, "页面路径", fontsize=9, color="#7B879A", transform=ax.transAxes)
    ax.text(0.93, 0.84, "请求量", fontsize=9, color="#7B879A", ha="right", transform=ax.transAxes)

    top = 0.78
    row_h = 0.07
    for idx, (name, value) in enumerate(rows[:9], start=1):
        y = top - (idx - 1) * row_h
        if y < 0.08:
            break
        if idx % 2 == 1:
            ax.add_patch(
                patches.Rectangle((0.04, y - 0.04), 0.92, 0.055, transform=ax.transAxes, fc="#F8FAFD", ec="none")
            )
        ax.text(0.06, y, f"{idx:>2}. {short_label(name, 30)}", fontsize=9.5, color="#223044", transform=ax.transAxes)
        ax.text(0.93, y, fmt_count(value), fontsize=9.5, color="#223044", ha="right", transform=ax.transAxes)


def draw_public_ip_table(ax, rows: list[tuple[str, int]]) -> None:
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
    ax.text(0.05, 0.93, "Top Public IP 与归属地", fontsize=12, fontweight="bold", color="#182230", transform=ax.transAxes)
    ax.text(0.95, 0.93, "近似定位", fontsize=9, color="#7B879A", ha="right", transform=ax.transAxes)
    ax.text(0.06, 0.84, "IP", fontsize=9, color="#7B879A", transform=ax.transAxes)
    ax.text(0.39, 0.84, "归属地 / 组织", fontsize=9, color="#7B879A", transform=ax.transAxes)
    ax.text(0.93, 0.84, "请求量", fontsize=9, color="#7B879A", ha="right", transform=ax.transAxes)

    top = 0.78
    row_h = 0.105
    for idx, (ip, value) in enumerate(rows[:6], start=1):
        geo = IP_GEO_OVERRIDES.get(ip, {})
        location = geo.get("location", "待补充")
        org = geo.get("org", "待补充")
        y = top - (idx - 1) * row_h
        if idx % 2 == 1:
            ax.add_patch(
                patches.Rectangle((0.04, y - 0.055), 0.92, 0.083, transform=ax.transAxes, fc="#F8FAFD", ec="none")
            )
        ax.text(0.06, y, ip, fontsize=9.3, color="#223044", transform=ax.transAxes)
        ax.text(0.39, y + 0.012, short_label(location, 22), fontsize=9.1, color="#223044", transform=ax.transAxes)
        ax.text(0.39, y - 0.022, short_label(org, 22), fontsize=8.5, color="#7B879A", transform=ax.transAxes)
        ax.text(0.93, y, fmt_count(value), fontsize=9.3, color="#223044", ha="right", transform=ax.transAxes)


def draw_scope_panel(ax, exclude_crawlers: bool, skip_first_days: int, allowed_methods: set[str] | None, data: DashboardData) -> None:
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
    ax.text(0.95, 0.93, "请按此理解图中数字", fontsize=9, color="#7B879A", ha="right", transform=ax.transAxes)

    methods_text = "/".join(sorted(allowed_methods)) if allowed_methods else "全部方法"
    crawler_total = data.crawler_b_total + data.crawler_c_total
    raw_total = data.raw_b_total + data.raw_c_total
    crawler_share = 0 if raw_total == 0 else crawler_total / raw_total
    lines = [
        f"时间范围：已去掉最早 {skip_first_days} 天不完整数据。" if skip_first_days else "时间范围：未额外去掉前置日期。",
        f"请求方法：仅保留 {methods_text}。",
        (
            f"爬虫处理：已剔除 UA 识别爬虫 {fmt_count(crawler_total)}，约占原始请求 {crawler_share:.1%}。"
            if exclude_crawlers
            else "爬虫处理：本图未剔除爬虫。"
        ),
        "全图只统计页面型请求，已过滤 /wp-content、/wp-includes 与常见静态资源扩展。",
        "总量卡片、趋势图、热门页面三者现在使用同一统计口径。",
        "热门页面表仅展示 Top 9，所以表内合计不会等于总量卡片。",
    ]
    y = 0.82
    for line in lines:
        ax.text(0.06, y, "- " + line, fontsize=9.2, color="#334155", transform=ax.transAxes, va="top")
        y -= 0.12


def draw_crawler_module(ax, data: DashboardData, exclude_crawlers: bool) -> None:
    style_panel(
        ax,
        "爬虫检测模块",
        "按 UA 规则识别；当前看板{}".format("已剔除这些请求" if exclude_crawlers else "仍包含这些请求"),
    )
    families = data.crawler_family_total.most_common(6)
    if not families:
        ax.text(0.5, 0.5, "未检测到明显爬虫 UA", ha="center", va="center", fontsize=11, color="#667085", transform=ax.transAxes)
        ax.set_xticks([])
        ax.set_yticks([])
        return

    raw_total = data.raw_b_total + data.raw_c_total
    crawler_total = data.crawler_b_total + data.crawler_c_total
    share = 0 if raw_total == 0 else crawler_total / raw_total
    ax.text(
        0.0,
        1.07,
        f"检测到 {fmt_count(crawler_total)} | 占原始请求 {share:.1%} | B-side {fmt_count(data.crawler_b_total)} | C-side {fmt_count(data.crawler_c_total)}",
        transform=ax.transAxes,
        fontsize=9,
        color="#7B879A",
        va="bottom",
    )

    labels = [short_label(name, 16) for name, _ in families][::-1]
    values = [value for _, value in families][::-1]
    ypos = np.arange(len(labels))
    ax.barh(ypos, values, color="#F2994A", alpha=0.92, height=0.56)
    ax.set_yticks(ypos)
    ax.set_yticklabels(labels)
    ax.set_xlabel("Detected crawler requests", fontsize=9, color="#738196")
    ax.grid(axis="x", color="#EEF2F7", lw=0.9)
    for y, value in zip(ypos, values):
        ax.text(value + max(values) * 0.02, y, fmt_count(value), va="center", fontsize=9, color="#334155")


def render_dashboard(
    data: DashboardData,
    target: Path,
    exclude_crawlers: bool = False,
    skip_first_days: int = 0,
    allowed_methods: set[str] | None = None,
    page_only: bool = False,
) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)

    date_keys = [dt.strftime("%Y-%m-%d") for dt in data.date_range]
    labels = [dt.strftime("%m-%d") for dt in data.date_range]
    b_series = np.array([data.daily_b.get(key, 0) for key in date_keys])
    c_series = np.array([data.daily_c.get(key, 0) for key in date_keys])
    b_plot = np.array([data.daily_b[key] if key in data.daily_b else np.nan for key in date_keys], dtype=float)
    c_plot = np.array([data.daily_c[key] if key in data.daily_c else np.nan for key in date_keys], dtype=float)

    c_status = {
        bucket: np.array([data.c_status_by_day.get(key, Counter()).get(bucket, 0) for key in date_keys])
        for bucket in STATUS_ORDER
    }

    method_counter = Counter(data.method_total)
    other_methods = method_counter.pop("UNKNOWN", 0) + method_counter.pop("OPTIONS", 0) + method_counter.pop("PROPFIND", 0)
    method_rows = method_counter.most_common(3)
    if other_methods:
        method_rows.append(("其他", other_methods))
    method_labels = [name for name, _ in method_rows]
    method_sizes = [value for _, value in method_rows]

    top_pages = data.page_total.most_common(9)
    page_total_sum = sum(data.page_total.values())

    b_peak_day, b_peak_value = max(data.daily_b.items(), key=lambda item: item[1])
    c_peak_day, c_peak_value = max(data.daily_c.items(), key=lambda item: item[1])
    total_days = len(data.date_range)
    c_unique_ip = len(data.c_ip_total)
    crawler_total = data.crawler_b_total + data.crawler_c_total
    raw_total = data.raw_b_total + data.raw_c_total
    crawler_share = 0 if raw_total == 0 else crawler_total / raw_total

    fig = plt.figure(figsize=(18, 10), dpi=200, facecolor="#F5F7FB")
    gs = fig.add_gridspec(12, 24, left=0.03, right=0.97, top=0.92, bottom=0.05, hspace=0.82, wspace=0.8)

    fig.text(0.03, 0.965, "Moseeker Access Log Dashboard", fontsize=22, fontweight="bold", color="#0F172A")
    header_bits = []
    if skip_first_days:
        header_bits.append(f"已去掉最早 {skip_first_days} 天")
    if exclude_crawlers:
        header_bits.append("已剔除 UA 识别爬虫")
    if allowed_methods:
        header_bits.append("仅保留 " + "/".join(sorted(allowed_methods)))
    if page_only:
        header_bits.append("全图已过滤静态资源")
    header_suffix = "  |  " + " · ".join(header_bits) if header_bits else ""
    fig.text(
        0.03,
        0.938,
        f"日志区间 {date_keys[0]} 至 {date_keys[-1]}  |  基于本地 B-side 与 C-side 访问日志自动生成{header_suffix}",
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
    add_card(card_axes[0], "B-side 页面请求" + ("（净）" if exclude_crawlers else ""), fmt_count(data.b_total), f"与趋势图同口径 | 峰值 {b_peak_day}", "#2F80ED")
    add_card(card_axes[1], "首页 `/` 请求", fmt_count(data.page_total.get('/', 0)), "页面型 GET 请求", "#4C9AFF")
    add_card(card_axes[2], "C-side 页面请求" + ("（净）" if exclude_crawlers else ""), fmt_count(data.c_total), f"与状态结构同口径 | 峰值 {c_peak_day}", "#49A3FF")
    add_card(card_axes[3], "检测到爬虫", fmt_count(crawler_total), f"占同口径原始请求 {crawler_share:.1%}", "#F2994A")
    add_card(card_axes[4], "覆盖日期", f"{total_days} 天", "按自然日补齐空档后统计", "#7C4DFF")
    add_card(card_axes[5], "C-side 唯一 IP", f"{c_unique_ip}", "当前净流量口径下统计", "#00A58E")

    ax_trend = fig.add_subplot(gs[2:7, 0:13])
    style_panel(
        ax_trend,
        "每日请求趋势",
        "左轴为 B-side，右轴为 C-side；全图仅统计页面型请求，缺失日志日期以断点显示{}".format("；已剔除爬虫" if exclude_crawlers else ""),
    )
    x = np.arange(len(date_keys))
    ax_trend.plot(x, b_plot, color="#2F80ED", lw=2.5)
    ax_trend.fill_between(x, b_plot, color="#DDEBFF", alpha=0.65)
    ax_trend.scatter(x, b_plot, color="#2F80ED", s=10, zorder=3)
    ax_trend.set_xlim(-0.5, len(x) - 0.5)
    ax_trend.set_xticks(x[::4])
    ax_trend.set_xticklabels([labels[i] for i in range(0, len(labels), 4)])
    ax_trend.set_ylabel("B-side requests", color="#5B6B7F", fontsize=9)
    ax_trend.set_ylim(0, np.nanmax(b_plot) * 1.18)

    ax_trend_r = ax_trend.twinx()
    for spine in ax_trend_r.spines.values():
        spine.set_visible(False)
    ax_trend_r.plot(x, c_plot, color="#F2994A", lw=2.0, marker="o", markersize=3.5)
    ax_trend_r.set_yticks([])
    ax_trend_r.set_ylim(0, np.nanmax(c_plot) * 1.22)

    b_peak_idx = date_keys.index(b_peak_day)
    c_peak_idx = date_keys.index(c_peak_day)
    ax_trend.annotate(
        f"B峰值 {fmt_count(b_peak_value)}",
        xy=(b_peak_idx, b_peak_value),
        xytext=(max(1, b_peak_idx - 5), b_peak_value + np.nanmax(b_plot) * 0.10),
        arrowprops={"arrowstyle": "-", "color": "#2F80ED"},
        fontsize=9,
        color="#2F80ED",
        bbox={"boxstyle": "round,pad=0.2", "fc": "white", "ec": "#D9E6F7"},
    )
    ax_trend_r.annotate(
        f"C峰值 {fmt_count(c_peak_value)}",
        xy=(c_peak_idx, c_peak_value),
        xytext=(max(1, c_peak_idx - 4), c_peak_value + np.nanmax(c_plot) * 0.08),
        arrowprops={"arrowstyle": "-", "color": "#F2994A"},
        fontsize=9,
        color="#B96B14",
        bbox={"boxstyle": "round,pad=0.2", "fc": "white", "ec": "#F6D8B6"},
    )

    legend_handles = [
        plt.Line2D([0], [0], color="#2F80ED", lw=2.5, label="B-side" + ("（净流量）" if exclude_crawlers else "")),
        plt.Line2D([0], [0], color="#F2994A", lw=2.0, marker="o", markersize=4, label="C-side" + ("（净流量）" if exclude_crawlers else "")),
    ]
    ax_trend.legend(handles=legend_handles, loc="upper left", frameon=False, fontsize=9)

    ax_status = fig.add_subplot(gs[2:7, 13:24])
    style_panel(ax_status, "C-side 状态结构", "堆叠柱突出 302 / 404 / 其他异常状态，便于对外部探测流量做快速分层{}".format("；已剔除爬虫" if exclude_crawlers else ""))
    bottom = np.zeros(len(date_keys))
    for bucket in STATUS_ORDER:
        values = c_status[bucket]
        ax_status.bar(x, values, bottom=bottom, color=STATUS_COLORS[bucket], width=0.68, label=bucket)
        bottom += values
    ax_status.set_xlim(-0.6, len(x) - 0.4)
    ax_status.set_xticks(x[::4])
    ax_status.set_xticklabels([labels[i] for i in range(0, len(labels), 4)])
    ax_status.set_ylim(0, np.nanmax(bottom) * 1.18 if np.nanmax(bottom) else 1)
    ax_status.legend(ncol=5, loc="upper left", bbox_to_anchor=(0, 1.01), frameon=False, fontsize=8.5, handlelength=1.1)
    for idx in [c_peak_idx]:
        ax_status.text(
            idx,
            bottom[idx] + max(bottom) * 0.03,
            fmt_count(int(bottom[idx])),
            ha="center",
            fontsize=8.5,
            color="#475467",
        )

    ax_table = fig.add_subplot(gs[7:12, 0:8])
    draw_page_table(ax_table, top_pages)
    ax_table.text(0.95, 0.86, "净流量" if exclude_crawlers else "原始流量", fontsize=9, color="#7B879A", ha="right", transform=ax_table.transAxes)

    ax_bot = fig.add_subplot(gs[7:12, 8:16])
    draw_crawler_module(ax_bot, data, exclude_crawlers)

    if allowed_methods and len(allowed_methods) == 1:
        ax_scope = fig.add_subplot(gs[7:12, 16:24])
        draw_scope_panel(ax_scope, exclude_crawlers, skip_first_days, allowed_methods, data)
    else:
        ax_donut = fig.add_subplot(gs[7:12, 16:24])
        ax_donut.set_facecolor("white")
        for spine in ax_donut.spines.values():
            spine.set_visible(False)
        ax_donut.set_xticks([])
        ax_donut.set_yticks([])
        ax_donut.set_title("请求方法占比", loc="left", pad=16, fontsize=12, fontweight="bold", color="#182230")
        ax_donut.text(
            0.0,
            1.03,
            "整体仍以 GET 为主，POST 主要集中在登录与表单相关路径{}".format("；当前为去爬虫后的净流量" if exclude_crawlers else ""),
            transform=ax_donut.transAxes,
            fontsize=9,
            color="#7B879A",
            va="bottom",
        )
        ax_donut.pie(
            method_sizes,
            colors=METHOD_COLORS[: len(method_sizes)],
            startangle=90,
            counterclock=False,
            wedgeprops={"width": 0.32, "edgecolor": "white"},
        )
        top_method_pct = method_sizes[0] / sum(method_sizes)
        ax_donut.text(0, 0.06, method_labels[0], ha="center", va="center", fontsize=13, fontweight="bold", color="#0F172A")
        ax_donut.text(0, -0.12, f"{top_method_pct:.1%}", ha="center", va="center", fontsize=11, color="#6B7280")

        legend_y = -1.02
        for idx, (label, value) in enumerate(zip(method_labels, method_sizes)):
            ax_donut.add_patch(
                patches.Rectangle((-1.1, legend_y - idx * 0.23), 0.08, 0.08, color=METHOD_COLORS[idx], transform=ax_donut.transData)
            )
            ax_donut.text(-0.95, legend_y + 0.04 - idx * 0.23, label, fontsize=9.5, color="#334155", va="center")
            ax_donut.text(0.98, legend_y + 0.04 - idx * 0.23, fmt_count(value), fontsize=9.5, color="#334155", va="center", ha="right")

    fig.text(
        0.03,
        0.022,
        "说明：爬虫识别基于 UA 规则，适合做运营看板净流量清洗，但不等同于严格反爬或精准访客识别；本图已去掉最早 {} 天。".format(skip_first_days if skip_first_days else 0),
        fontsize=9,
        color="#6B7280",
    )
    fig.savefig(target, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)


def output_stem(
    exclude_crawlers: bool,
    skip_first_days: int,
    allowed_methods: set[str] | None = None,
    page_only: bool = False,
) -> str:
    stem = "access_log_dashboard"
    if exclude_crawlers:
        stem += "_no_crawlers"
    if allowed_methods:
        stem += "_" + "_".join(m.lower() for m in sorted(allowed_methods))
    if page_only:
        stem += "_pages_only"
    if skip_first_days:
        stem += f"_skip{skip_first_days}"
    return stem


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate access log dashboard.")
    parser.add_argument("--exclude-crawlers", action="store_true", help="Remove crawler UA traffic before charting")
    parser.add_argument("--skip-first-days", type=int, default=0, help="Skip earliest N log days")
    parser.add_argument(
        "--methods",
        nargs="+",
        default=None,
        help="Only keep these HTTP methods, e.g. GET or GET HEAD",
    )
    parser.add_argument("--page-only", action="store_true", help="Keep only page-like requests and filter static assets globally")
    return parser.parse_args()


def main() -> None:
    setup_fonts()
    args = parse_args()
    allowed_methods = {m.upper() for m in args.methods} if args.methods else None
    data = parse_logs(
        exclude_crawlers=args.exclude_crawlers,
        skip_first_days=args.skip_first_days,
        allowed_methods=allowed_methods,
        page_only=args.page_only,
    )
    stem = output_stem(args.exclude_crawlers, args.skip_first_days, allowed_methods, args.page_only)
    write_daily_csv(data, OUTPUT_DIR / f"{stem}_daily.csv")
    write_public_ip_csv(data, OUTPUT_DIR / f"{stem}_public_ip_geo.csv")
    write_summary_json(
        data,
        OUTPUT_DIR / f"{stem}_summary.json",
        exclude_crawlers=args.exclude_crawlers,
        skip_first_days=args.skip_first_days,
        allowed_methods=allowed_methods,
        page_only=args.page_only,
    )
    render_dashboard(
        data,
        OUTPUT_DIR / f"{stem}.png",
        exclude_crawlers=args.exclude_crawlers,
        skip_first_days=args.skip_first_days,
        allowed_methods=allowed_methods,
        page_only=args.page_only,
    )


if __name__ == "__main__":
    main()
