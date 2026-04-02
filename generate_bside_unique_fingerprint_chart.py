from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean

import matplotlib.pyplot as plt
import numpy as np
from matplotlib import patches

from generate_person_session_dashboard import (
    OUTPUT_DIR,
    browser_family,
    device_type,
    fmt_count,
    load_bside_records,
    os_family,
    setup_fonts,
    short_label,
    style_panel,
)


def write_daily_csv(daily_unique: dict[str, int], target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["date", "daily_unique_fingerprints"])
        for day in sorted(daily_unique):
            writer.writerow([day, daily_unique[day]])


def write_fingerprint_csv(rows: list[dict[str, object]], target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "fingerprint",
                "first_seen",
                "first_day",
                "browser",
                "os",
                "device_type",
                "first_entry_page",
                "proxy_ip",
                "request_count",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


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


def render_device_panel(ax, device_counter: Counter, total: int) -> None:
    ax.set_facecolor("white")
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_xticks([])
    ax.set_yticks([])
    ax.set_title("设备分布（按唯一指纹）", loc="left", pad=10, fontsize=12, fontweight="bold", color="#182230")
    ax.text(0.0, 1.01, "同一指纹全周期只记一次。", transform=ax.transAxes, fontsize=9, color="#7B879A", va="bottom")

    labels = ["Desktop", "Mobile", "Tablet"]
    values = [device_counter.get(label, 0) for label in labels]
    colors = ["#2F80ED", "#49A3FF", "#B7D4FF"]
    ax.pie(
        values,
        colors=colors,
        startangle=90,
        counterclock=False,
        wedgeprops={"width": 0.32, "edgecolor": "white"},
    )
    center_label = "Desktop" if values and values[0] >= max(values) else labels[int(np.argmax(values))]
    center_value = values[labels.index(center_label)] if labels else 0
    share = center_value / total if total else 0
    ax.text(0, 0.06, center_label, ha="center", va="center", fontsize=13, fontweight="bold", color="#0F172A")
    ax.text(0, -0.12, f"{share:.1%}", ha="center", va="center", fontsize=11, color="#6B7280")

    legend_y = -1.02
    display_names = {"Desktop": "电脑", "Mobile": "手机", "Tablet": "平板"}
    for idx, (label, value) in enumerate(zip(labels, values)):
        ax.add_patch(
            patches.Rectangle((-1.1, legend_y - idx * 0.23), 0.08, 0.08, color=colors[idx], transform=ax.transData)
        )
        ax.text(-0.95, legend_y + 0.04 - idx * 0.23, display_names[label], fontsize=9.5, color="#334155", va="center")
        ax.text(0.98, legend_y + 0.04 - idx * 0.23, fmt_count(value), fontsize=9.5, color="#334155", va="center", ha="right")


def render_scope_panel(ax) -> None:
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
    ax.text(0.95, 0.93, "这版统计“唯一指纹”", fontsize=9, color="#7B879A", ha="right", transform=ax.transAxes)
    lines = [
        "仅统计 B-side；不使用代理内网 IP 做去重。",
        "浏览器指纹近似：使用完整 UA 哈希，不是真正的强指纹。",
        "全周期唯一指纹：同一 UA 哈希无论访问多少次都只记 1 个。",
        "日唯一指纹：同一指纹在同一天内重复访问仍只记 1 个。",
        "过滤项：去掉最早 3 天、仅保留 GET、剔除 UA 识别爬虫、全局过滤静态资源。",
        "额外排除：以 `/.` 开头的隐藏配置探测路径。",
        "风险：不同用户若 UA 完全一致会被合并，同一用户换浏览器或升级版本会被拆分。",
    ]
    y = 0.83
    for line in lines:
        ax.text(0.06, y, "- " + line, fontsize=9.0, color="#334155", transform=ax.transAxes, va="top")
        y -= 0.11


def render_dashboard(
    daily_unique: dict[str, int],
    browser_counter: Counter,
    device_counter: Counter,
    page_counter: Counter,
    total_unique: int,
    fingerprint_rows: list[dict[str, object]],
    output_path: Path,
) -> dict:
    days = sorted(daily_unique)
    labels = [datetime.strptime(day, "%Y-%m-%d").strftime("%m-%d") for day in days]
    values = np.array([daily_unique[day] for day in days], dtype=float)
    ma7 = np.array([values[max(0, idx - 6) : idx + 1].mean() for idx in range(len(values))], dtype=float)
    avg_daily = mean(values) if len(values) else 0
    peak_day, peak_value = max(daily_unique.items(), key=lambda item: item[1]) if daily_unique else ("-", 0)
    home_unique = page_counter.get("/", 0)
    home_share = home_unique / total_unique if total_unique else 0
    desktop_share = device_counter.get("Desktop", 0) / total_unique if total_unique else 0

    fig = plt.figure(figsize=(18, 10.5), dpi=200, facecolor="#F5F7FB")
    gs = fig.add_gridspec(12, 24, left=0.03, right=0.97, top=0.92, bottom=0.05, hspace=0.92, wspace=0.8)

    fig.text(0.03, 0.965, "Moseeker B-side Unique Fingerprint Dashboard", fontsize=22, fontweight="bold", color="#0F172A")
    fig.text(
        0.03,
        0.938,
        "仅统计 B-side | 强行按浏览器指纹（完整 UA 哈希）去重 | 这版反映近似设备规模，不等于真实人数",
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
    add_card(card_axes[0], "全周期唯一指纹", fmt_count(total_unique), "整段时间强制去重后规模", "#2F80ED")
    add_card(card_axes[1], "日均唯一指纹", fmt_count(int(round(avg_daily))), "同一指纹按天去重", "#4C9AFF")
    add_card(card_axes[2], "峰值日期", peak_day, f"{fmt_count(peak_value)} 唯一指纹", "#7C4DFF")
    add_card(card_axes[3], "首页首访占比", f"{home_share:.1%}", f"首页首访 {fmt_count(home_unique)}", "#12B4A0")
    add_card(card_axes[4], "电脑设备占比", f"{desktop_share:.1%}", f"电脑指纹 {fmt_count(device_counter.get('Desktop', 0))}", "#00A58E")
    add_card(card_axes[5], "Top 浏览器", browser_counter.most_common(1)[0][0] if browser_counter else "-", f"{fmt_count(browser_counter.most_common(1)[0][1]) if browser_counter else '0'} 唯一指纹", "#F2994A")

    ax_trend = fig.add_subplot(gs[2:7, 0:12])
    style_panel(ax_trend, "每日唯一浏览器指纹趋势", "柱形为单日去重后的唯一指纹数，折线为 7 日均线；已去掉最早 3 天、仅保留 GET、已去爬虫与静态资源")
    x = np.arange(len(days))
    ax_trend.bar(x, values, color="#CFE2FF", width=0.68, edgecolor="none")
    ax_trend.plot(x, ma7, color="#2F80ED", lw=2.5, marker="o", markersize=3.2)
    ax_trend.set_xlim(-0.6, len(x) - 0.4)
    tick_step = max(1, len(days) // 14)
    tick_positions = x[::tick_step] if len(x) else x
    tick_labels = labels[::tick_step] if labels else labels
    ax_trend.set_xticks(tick_positions)
    ax_trend.set_xticklabels(tick_labels)
    ax_trend.set_ylabel("Unique fingerprints", fontsize=9, color="#667085")
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
    style_panel(ax_browser, "浏览器分布（按唯一指纹）", "同一指纹全周期只记一次，更接近去重设备结构")
    browser_rows = browser_counter.most_common(6)
    browser_names = [name for name, _ in browser_rows][::-1]
    browser_values = [value for _, value in browser_rows][::-1]
    ypos = np.arange(len(browser_names))
    ax_browser.barh(ypos, browser_values, color="#2F80ED", alpha=0.92, height=0.56)
    ax_browser.set_yticks(ypos)
    ax_browser.set_yticklabels(browser_names)
    ax_browser.set_xlabel("Unique fingerprints", fontsize=9, color="#738196")
    ax_browser.grid(axis="x", color="#EEF2F7", lw=0.9)
    for y, value in zip(ypos, browser_values):
        ax_browser.text(value + max(browser_values) * 0.02, y, fmt_count(value), va="center", fontsize=9, color="#334155")

    ax_device = fig.add_subplot(gs[2:7, 18:24])
    render_device_panel(ax_device, device_counter, total_unique)

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
    ax_entry.text(0.05, 0.93, "首访页面 Top 9", fontsize=12, fontweight="bold", color="#182230", transform=ax_entry.transAxes)
    ax_entry.text(0.95, 0.93, "按唯一指纹", fontsize=9, color="#7B879A", ha="right", transform=ax_entry.transAxes)
    ax_entry.text(0.05, 0.89, "每个指纹只按首次出现页面记 1 次。", fontsize=8.6, color="#7B879A", transform=ax_entry.transAxes)
    ax_entry.text(0.07, 0.84, "首访路径", fontsize=9, color="#7B879A", transform=ax_entry.transAxes)
    ax_entry.text(0.93, 0.84, "唯一指纹", fontsize=9, color="#7B879A", ha="right", transform=ax_entry.transAxes)
    top = 0.78
    row_h = 0.07
    for idx, (name, value) in enumerate(page_counter.most_common(9), start=1):
        y = top - (idx - 1) * row_h
        if idx % 2 == 1:
            ax_entry.add_patch(
                patches.Rectangle((0.04, y - 0.04), 0.92, 0.055, transform=ax_entry.transAxes, fc="#F8FAFD", ec="none")
            )
        ax_entry.text(0.06, y, f"{idx}. {short_label(name, 30)}", fontsize=9.5, color="#223044", transform=ax_entry.transAxes)
        ax_entry.text(0.93, y, fmt_count(value), fontsize=9.5, color="#223044", ha="right", transform=ax_entry.transAxes)

    ax_device_bar = fig.add_subplot(gs[7:12, 8:16])
    style_panel(ax_device_bar, "设备类型对比", "按全周期唯一指纹统计，不随访问次数放大")
    device_names = ["Desktop", "Mobile", "Tablet"]
    device_values = [device_counter.get(name, 0) for name in device_names]
    x2 = np.arange(len(device_names))
    ax_device_bar.bar(x2, device_values, color=["#2F80ED", "#49A3FF", "#B7D4FF"], width=0.58)
    ax_device_bar.set_xticks(x2)
    ax_device_bar.set_xticklabels(["电脑", "手机", "平板"])
    ax_device_bar.set_ylabel("Unique fingerprints", fontsize=9, color="#667085")
    ax_device_bar.set_ylim(0, max(device_values) * 1.22 if device_values and max(device_values) else 1)
    for x_pos, value in zip(x2, device_values):
        ax_device_bar.text(x_pos, value + max(device_values) * 0.03 if max(device_values) else 0.1, fmt_count(value), ha="center", fontsize=8.8, color="#475467")

    ax_scope = fig.add_subplot(gs[7:12, 16:24])
    render_scope_panel(ax_scope)

    fig.text(
        0.03,
        0.022,
        "说明：这版不是“人次”，而是按完整 UA 哈希强制去重后的唯一指纹规模，更适合看近似设备量级与结构分布。",
        fontsize=9,
        color="#6B7280",
    )
    fig.savefig(output_path, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)

    return {
        "date_start": days[0] if days else None,
        "date_end": days[-1] if days else None,
        "unique_fingerprints_total": total_unique,
        "avg_daily_unique_fingerprints": round(avg_daily, 2) if days else 0,
        "peak_day": peak_day,
        "peak_daily_unique_fingerprints": peak_value,
        "home_first_seen_share": round(home_share, 4) if total_unique else 0,
        "desktop_share": round(desktop_share, 4) if total_unique else 0,
        "browser_share": browser_counter.most_common(),
        "device_share": device_counter.most_common(),
        "top_first_seen_pages": page_counter.most_common(10),
        "filters": {
            "source_side": "B-side only",
            "dedupe_key": "full_user_agent_hash",
            "dedupe_mode": "force global unique fingerprint",
            "daily_unique_mode": "dedupe within each day",
            "skip_first_days": 3,
            "allowed_methods": ["GET"],
            "exclude_crawler_ua": True,
            "page_only": True,
            "exclude_hidden_probe_paths": True,
        },
    }


def main() -> None:
    setup_fonts()
    records, dropped = load_bside_records()

    seen_by_day: dict[str, set[str]] = defaultdict(set)
    fingerprint_rows_map: dict[str, dict[str, object]] = {}
    page_counter = Counter()
    browser_counter = Counter()
    device_counter = Counter()

    for dt, day, proxy_ip, user_agent, page, _referer in records:
        fingerprint = hashlib.sha1(user_agent.encode("utf-8", "ignore")).hexdigest()[:12]
        seen_by_day[day].add(fingerprint)

        if fingerprint not in fingerprint_rows_map:
            row = {
                "fingerprint": fingerprint,
                "first_seen": dt.isoformat(sep=" "),
                "first_day": day,
                "browser": browser_family(user_agent),
                "os": os_family(user_agent),
                "device_type": device_type(user_agent),
                "first_entry_page": page,
                "proxy_ip": proxy_ip,
                "request_count": 1,
            }
            fingerprint_rows_map[fingerprint] = row
            page_counter[page] += 1
            browser_counter[row["browser"]] += 1
            device_counter[row["device_type"]] += 1
        else:
            fingerprint_rows_map[fingerprint]["request_count"] += 1

    fingerprint_rows = sorted(fingerprint_rows_map.values(), key=lambda row: row["first_seen"])
    daily_unique = {day: len(fingerprints) for day, fingerprints in sorted(seen_by_day.items())}

    stem = "bside_unique_fingerprint_dashboard"
    daily_path = OUTPUT_DIR / f"{stem}_daily.csv"
    detail_path = OUTPUT_DIR / f"{stem}_detail.csv"
    image_path = OUTPUT_DIR / f"{stem}.png"
    summary_path = OUTPUT_DIR / f"{stem}_summary.json"

    write_daily_csv(daily_unique, daily_path)
    write_fingerprint_csv(fingerprint_rows, detail_path)
    summary = render_dashboard(daily_unique, browser_counter, device_counter, page_counter, len(fingerprint_rows), fingerprint_rows, image_path)
    summary["qualifying_page_requests"] = len(records)
    summary["dropped_records"] = dropped
    write_summary_json(summary, summary_path)


if __name__ == "__main__":
    main()
