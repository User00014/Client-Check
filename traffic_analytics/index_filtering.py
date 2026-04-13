from __future__ import annotations
"""索引名解析与筛选工具。

前端下拉框拿到的是 ES 索引名，但业务筛选想按“客户 / 日期 / 标签”
这样的语义字段来做，所以这个模块负责把原始索引名拆成结构化信息。
"""

import re
from typing import Any


INDEX_DATE_RE = re.compile(r"(?P<date>\d{4}\.\d{2}\.\d{2})$")
INDEX_MARKERS = ("nginx-prelogs", "nginx-logs")
KNOWN_INDEX_TAGS = {"formatted", "pre", "test"}


def parse_index_name(index_name: str) -> dict[str, str]:
    """把原始索引名拆成前缀、客户名、标签、日期四部分。"""
    # We treat the raw ES index name as a structured identifier:
    # prefix + customer body + optional tag + optional date suffix.
    raw = (index_name or "").strip()
    match = INDEX_DATE_RE.search(raw)
    index_date = match.group("date").replace(".", "-") if match else ""
    stem = raw[: match.start()].rstrip("-_.") if match else raw
    index_prefix, subject = _split_index_stem(stem)
    customer_name, index_tag = _split_subject_and_tag(subject)
    return {
        "index_prefix": index_prefix,
        "customer_name": customer_name or raw,
        "index_tag": index_tag,
        "index_date": index_date,
        "label": raw,
    }


def filter_index_options(
    options: list[dict[str, Any]],
    customer_name: str | None,
    index_date: str | None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, Any]]:
    """按客户名与日期窗口过滤索引选项。"""
    # The UI only keeps customer/date as first-class index filters now.
    results = []
    for item in options:
        if customer_name and customer_name != "ALL" and item.get("customer_name") != customer_name:
            continue
        if index_date and index_date != "ALL" and item.get("index_date") != index_date:
            continue
        item_date = str(item.get("index_date") or "")
        if date_from and item_date and item_date < date_from:
            continue
        if date_to and item_date and item_date > date_to:
            continue
        results.append(item)
    return results


def build_select_options(
    options: list[dict[str, Any]],
    field: str,
    all_label: str,
    allow_empty: bool = False,
) -> list[dict[str, Any]]:
    """把明细索引列表压缩成前端下拉框可直接使用的选项。"""
    # Collapse repeated index metadata into dropdown options and carry the
    # aggregated request count so the UI can sort by real traffic weight.
    grouped: dict[str, int] = {}
    for item in options:
        value = str(item.get(field) or "")
        if not value and not allow_empty:
            continue
        grouped[value] = grouped.get(value, 0) + int(item.get("requests") or 0)
    rows = [{"value": "ALL", "label": all_label, "requests": 0}]
    rows.extend(
        {
            "value": key,
            "label": key or "(无标签)",
            "requests": grouped[key],
        }
        for key in sorted(grouped.keys(), key=lambda k: (-grouped[k], k))
    )
    return rows


def normalize_index_option(index_name: str, requests: int) -> dict[str, Any]:
    """把单个索引名标准化成统一字典结构。"""
    # Keep both the raw index name and its parsed fields. The raw name is still
    # needed for exact ES filtering, while parsed fields drive the UI.
    parsed = parse_index_name(index_name)
    return {
        "value": index_name,
        "index_name": index_name,
        "index_prefix": parsed.get("index_prefix", ""),
        "customer_name": parsed.get("customer_name", index_name),
        "index_tag": parsed.get("index_tag", ""),
        "index_date": parsed.get("index_date", ""),
        "label": index_name,
        "requests": requests,
    }


def _split_index_stem(stem: str) -> tuple[str, str]:
    """从索引主体里识别固定前缀，剩余部分留给客户名/标签继续拆分。"""
    # Real index names are not fully uniform, so we detect the known marker
    # from the left, right, or middle and then keep the remaining part as the
    # customer/tag payload for a second parsing pass.
    value = (stem or "").strip("-_.")
    lower = value.lower()
    for marker in INDEX_MARKERS:
        prefix = marker + "-"
        suffix = "-" + marker
        if lower.startswith(prefix):
            return marker, value[len(prefix):] or value
        if lower.endswith(suffix):
            return marker, value[: -len(suffix)] or value
        middle = "-" + marker + "-"
        if middle in lower:
            left, right = value.split(middle, 1)
            if left and not right:
                return marker, left
            if right and not left:
                return marker, right
            if left and right:
                return marker, right if len(right) >= len(left) else left
    return "", value


def _split_subject_and_tag(subject: str) -> tuple[str, str]:
    """只从尾部识别 tag，避免把客户名中的连字符误判成标签。"""
    # Tags are only recognized from the tail so names like "tec-do" do not
    # get broken apart accidentally.
    value = (subject or "").strip("-_.")
    if not value:
        return "", ""
    parts = value.split("-")
    tags: list[str] = []
    while parts and parts[-1].lower() in KNOWN_INDEX_TAGS:
        tags.insert(0, parts.pop())
    customer_name = "-".join(parts) if parts else value
    index_tag = "-".join(tags)
    return customer_name, index_tag
