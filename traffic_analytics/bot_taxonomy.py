from __future__ import annotations
"""正式 Bot 分类表加载与复用工具。

分类来源优先使用项目根目录的 `Bot种类划分.xlsx`，并将其作为
AI/非 AI Bot 识别的单一来源。若 xlsx 读取失败，则回退 `bot_summary.csv`。
"""

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import csv
import re
import xml.etree.ElementTree as ET
import zipfile
from typing import Any


ROOT_DIR = Path(__file__).resolve().parent.parent
OFFICIAL_BOT_XLSX_PATH = ROOT_DIR / "Bot种类划分.xlsx"
OFFICIAL_BOT_CSV_PATH = ROOT_DIR / "bot_summary.csv"
OFFICIAL_BOT_FALLBACK_ROWS: tuple[tuple[str, str, str], ...] = (
    ("Sogou", "SEO Bot", "sogou"),
    ("AhrefsBot", "SEO Bot", "ahrefsbot"),
    ("okhttp", "Automation / Script", "okhttp"),
    ("HeadlessChrome", "Automation / Script", "headlesschrome"),
    ("node-fetch", "Automation / Script", "fetch"),
    ("PhantomJsCloud", "SEO Bot", "phantomjs"),
    ("Googlebot", "SEO Bot", "googlebot"),
    ("curl", "Automation / Script", "curl/"),
    ("python-requests", "Automation / Script", "python-requests"),
    ("axios", "Automation / Script", "axios"),
    ("Baiduspider", "SEO Bot", "baiduspider"),
    ("wget", "Automation / Script", "wget"),
    ("GoogleOther", "AI Training", "googleother"),
    ("bingbot", "SEO Bot", "bingbot"),
    ("facebookexternalhit", "Social Preview Bot", "facebookexternalhit"),
    ("360Spider", "SEO Bot", "360spider"),
    ("GPTBot", "AI Training", "gptbot"),
    ("Bytespider", "AI Search", "bytespider"),
    ("ClaudeBot", "AI Training", "claudebot"),
    ("Slurp", "SEO Bot", "slurp"),
    ("Baiduspider-render", "SEO Bot", "baiduspider-render"),
    ("YisouSpider", "SEO Bot", "yisouspider"),
    ("OAI-SearchBot", "AI Index", "oai-searchbot"),
    ("Bun", "Automation / Script", "bun/"),
    ("visionheight.com/scan", "SEO Bot", "visionheight.com/scan"),
    ("PerplexityBot", "AI Search", "perplexitybot"),
    ("MJ12bot", "SEO Bot", "mj12bot"),
    ("PetalBot", "SEO Bot", "petalbot"),
    ("ChatGPT-User", "AI Search", "chatgpt-user"),
    ("YouBot", "AI Search", "youbot"),
    ("Amazonbot", "AI Training", "amazonbot"),
    ("Timpibot", "AI Training", "timpibot"),
    ("Go-http-client", "Automation / Script", "go-http-client"),
    ("Scrapy", "Automation / Script", "scrapy"),
    ("DotBot", "SEO Bot", "dotbot"),
    ("Twitterbot", "Social Preview Bot", "twitterbot"),
    ("AliyunSecBo", "Automation / Script", "aliyunsecbo"),
    ("meta-externalagent", "AI Training", "meta-externalagent"),
    ("CCBot", "AI Training", "ccbot"),
    ("SEODiffBot", "SEO Bot", "seodiffbot"),
    ("Googlebot-Image", "SEO Bot", "googlebot-image"),
    ("TikTokSpider", "Social Preview Bot", "tiktokspider"),
    ("Google-Site-Verification", "Verification Bot", "google-site-verification"),
)

AI_CATEGORY_TO_REPO_CATEGORY = {
    "AI Search": "ai_search",
    "AI Training": "ai_training",
    "AI Index": "ai_index",
}
NON_AI_BOT_CATEGORIES = {
    "SEO Bot",
    "Automation / Script",
    "Social Preview Bot",
    "Verification Bot",
}
BOT_TAXONOMY_CATEGORIES = (
    "AI Search",
    "AI Training",
    "AI Index",
    "SEO Bot",
    "Automation / Script",
    "Social Preview Bot",
    "Verification Bot",
    "Other External Bot",
)
OFFICIAL_AI_REPO_CATEGORIES = ("ai_search", "ai_training", "ai_index")
OFFICIAL_AI_REPO_CATEGORIES_WITH_UNCLASSIFIED = ("ai_search", "ai_training", "ai_index", "ai_unclassified")

# 未命中正式表时，用这些关键词兜底判断“这像是一个 Bot/脚本流量”。
UNCLASSIFIED_BOT_HINT_TOKENS = (
    "bot",
    "spider",
    "crawler",
    "scrapy",
    "headless",
    "scan",
    "scanner",
    "python-requests",
    "curl/",
    "wget",
    "go-http-client",
    "okhttp",
    "axios",
    "phantomjs",
    "selenium",
    "playwright",
    "fetch",
)
BOT_NAME_HINTS = (
    "bot",
    "spider",
    "crawler",
    "scrapy",
    "scan",
    "scanner",
    "requests",
    "curl",
    "wget",
    "http-client",
    "okhttp",
    "axios",
    "phantomjs",
    "headless",
    "fetch",
    "agent",
)
BOT_NAME_IGNORE = {
    "mozilla",
    "compatible",
    "linux",
    "windows",
    "applewebkit",
    "chrome",
    "safari",
    "firefox",
    "mobile",
    "android",
    "iphone",
    "macintosh",
    "version",
}
BOT_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9._\-]{1,63}")
CELL_REF_RE = re.compile(r"([A-Z]+)")
XML_NS = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
SPREADSHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
ET.register_namespace("", SPREADSHEET_NS)


@dataclass(frozen=True)
class BotTaxonomyEntry:
    bot_name: str
    category: str
    token: str
    repo_category: str | None


@dataclass(frozen=True)
class BotTaxonomy:
    entries: tuple[BotTaxonomyEntry, ...]
    ai_entries: tuple[BotTaxonomyEntry, ...]
    non_ai_entries: tuple[BotTaxonomyEntry, ...]
    ai_by_repo: dict[str, tuple[BotTaxonomyEntry, ...]]
    all_tokens: frozenset[str]


def _normalize_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_token(value: object) -> str:
    return _normalize_text(value).lower()


def _validate_taxonomy_payload(bot_name: str, category: str, token: str) -> tuple[str, str, str]:
    clean_name = _normalize_text(bot_name)
    clean_category = _normalize_text(category)
    clean_token = _normalize_token(token)
    if not clean_name:
        raise ValueError("bot_name cannot be empty")
    if clean_category not in BOT_TAXONOMY_CATEGORIES:
        raise ValueError(f"unsupported bot category: {clean_category}")
    if len(clean_token) < 3:
        raise ValueError("sample_ua_token must contain at least 3 characters")
    if clean_token in {"bot", "spider", "crawler", "crawl", "fetch", "scan", "scanner", "agent"}:
        raise ValueError("sample_ua_token is too broad; use a more specific bot token")
    return clean_name, clean_category, clean_token


def _load_shared_strings(zf: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in zf.namelist():
        return []
    root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
    values: list[str] = []
    for si in root.findall("a:si", XML_NS):
        # 一个单元格字符串可能是多个 <t> 片段拼接。
        parts = [node.text or "" for node in si.findall(".//a:t", XML_NS)]
        values.append("".join(parts))
    return values


def _cell_value(cell: ET.Element, shared_strings: list[str]) -> str:
    cell_type = cell.attrib.get("t", "")
    if cell_type == "inlineStr":
        return "".join((node.text or "") for node in cell.findall(".//a:t", XML_NS))
    value_node = cell.find("a:v", XML_NS)
    if value_node is None or value_node.text is None:
        return ""
    raw = value_node.text
    if cell_type == "s":
        try:
            return shared_strings[int(raw)]
        except (ValueError, IndexError):
            return ""
    return raw


def _append_shared_string(root: ET.Element, value: str) -> int:
    si = ET.SubElement(root, f"{{{SPREADSHEET_NS}}}si")
    text_node = ET.SubElement(si, f"{{{SPREADSHEET_NS}}}t")
    text_node.text = value
    count = len(root.findall(f"{{{SPREADSHEET_NS}}}si"))
    root.set("count", str(count))
    root.set("uniqueCount", str(count))
    return count - 1


def _set_cell_string(cell: ET.Element, shared_root: ET.Element, value: str) -> None:
    cell.set("t", "s")
    for child in list(cell):
        cell.remove(child)
    value_node = ET.SubElement(cell, f"{{{SPREADSHEET_NS}}}v")
    value_node.text = str(_append_shared_string(shared_root, value))


def _upsert_xlsx_row(
    path: Path,
    *,
    bot_name: str,
    category: str,
    sample_ua_token: str,
    sample_ua: str = "",
    note: str = "",
) -> dict[str, Any]:
    with zipfile.ZipFile(path, "r") as zf:
        files = {name: zf.read(name) for name in zf.namelist()}
    shared_root = ET.fromstring(files.get("xl/sharedStrings.xml", b'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>'))
    shared_strings = [
        "".join((node.text or "") for node in si.findall(".//a:t", XML_NS))
        for si in shared_root.findall("a:si", XML_NS)
    ]
    sheet_root = ET.fromstring(files["xl/worksheets/sheet1.xml"])
    sheet_data = sheet_root.find("a:sheetData", XML_NS)
    if sheet_data is None:
        raise ValueError("sheet1.xml has no sheetData")

    rows = sheet_data.findall("a:row", XML_NS)
    if not rows:
        raise ValueError("taxonomy sheet has no header row")
    header_row = rows[0]
    headers_by_name: dict[str, str] = {}
    for cell in header_row.findall("a:c", XML_NS):
        ref = cell.attrib.get("r", "")
        match = CELL_REF_RE.match(ref)
        if not match:
            continue
        text = _normalize_text(_cell_value(cell, shared_strings))
        if text:
            headers_by_name[text] = match.group(1)

    required_headers = ("bot_name", "category", "sample_ua_token")
    missing = [name for name in required_headers if name not in headers_by_name]
    if missing:
        raise ValueError("taxonomy sheet missing headers: " + ", ".join(missing))

    max_row = 1
    target_row: ET.Element | None = None
    token_col = headers_by_name["sample_ua_token"]
    name_col = headers_by_name["bot_name"]
    for row in rows[1:]:
        row_index = int(row.attrib.get("r", "0") or 0)
        max_row = max(max_row, row_index)
        values_by_col: dict[str, str] = {}
        for cell in row.findall("a:c", XML_NS):
            ref = cell.attrib.get("r", "")
            match = CELL_REF_RE.match(ref)
            if match:
                values_by_col[match.group(1)] = _normalize_text(_cell_value(cell, shared_strings))
        existing_token = _normalize_token(values_by_col.get(token_col))
        existing_name = _normalize_text(values_by_col.get(name_col)).lower()
        if existing_token == sample_ua_token or existing_name == bot_name.lower():
            target_row = row
            break

    created = target_row is None
    if target_row is None:
        next_row = max_row + 1
        target_row = ET.SubElement(sheet_data, f"{{{SPREADSHEET_NS}}}row", {"r": str(next_row)})
    else:
        next_row = int(target_row.attrib.get("r", "0") or 0)

    cells_by_col: dict[str, ET.Element] = {}
    for cell in target_row.findall("a:c", XML_NS):
        ref = cell.attrib.get("r", "")
        match = CELL_REF_RE.match(ref)
        if match:
            cells_by_col[match.group(1)] = cell

    def ensure_cell(header: str) -> ET.Element:
        col = headers_by_name[header]
        if col in cells_by_col:
            return cells_by_col[col]
        cell = ET.Element(f"{{{SPREADSHEET_NS}}}c", {"r": f"{col}{next_row}"})
        target_row.append(cell)
        cells_by_col[col] = cell
        return cell

    values = {
        "bot_name": bot_name,
        "category": category,
        "sample_ua_token": sample_ua_token,
        "ua_variants": "1",
        "说明": note or "前端维护",
        "是否存在争议": "0",
        "sample_ua": sample_ua,
        "bot流量": "0",
    }
    for header, value in values.items():
        if header in headers_by_name and (created or header in required_headers or value):
            _set_cell_string(ensure_cell(header), shared_root, value)

    target_row[:] = sorted(
        list(target_row),
        key=lambda cell: CELL_REF_RE.match(cell.attrib.get("r", "")).group(1) if CELL_REF_RE.match(cell.attrib.get("r", "")) else "",
    )

    files["xl/sharedStrings.xml"] = ET.tostring(shared_root, encoding="utf-8", xml_declaration=True)
    files["xl/worksheets/sheet1.xml"] = ET.tostring(sheet_root, encoding="utf-8", xml_declaration=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    tmp_path.replace(path)
    return {"created": created, "bot_name": bot_name, "category": category, "sample_ua_token": sample_ua_token}


def _sheet_rows_from_xlsx(path: Path) -> list[dict[str, str]]:
    with zipfile.ZipFile(path, "r") as zf:
        shared_strings = _load_shared_strings(zf)
        sheet_xml = zf.read("xl/worksheets/sheet1.xml")
    root = ET.fromstring(sheet_xml)
    rows: list[dict[str, str]] = []
    headers_by_col: dict[str, str] = {}
    for row in root.findall(".//a:sheetData/a:row", XML_NS):
        values_by_col: dict[str, str] = {}
        for cell in row.findall("a:c", XML_NS):
            ref = cell.attrib.get("r", "")
            match = CELL_REF_RE.match(ref)
            if not match:
                continue
            col = match.group(1)
            values_by_col[col] = _normalize_text(_cell_value(cell, shared_strings))
        row_index = int(row.attrib.get("r", "0") or 0)
        if row_index == 1:
            headers_by_col = {col: text for col, text in values_by_col.items() if text}
            continue
        if not values_by_col:
            continue
        normalized: dict[str, str] = {}
        for col, header in headers_by_col.items():
            normalized[header] = values_by_col.get(col, "")
        if normalized:
            rows.append(normalized)
    return rows


def _entries_from_rows(rows: list[dict[str, str]]) -> list[BotTaxonomyEntry]:
    entries: list[BotTaxonomyEntry] = []
    seen_tokens: set[str] = set()
    for row in rows:
        bot_name = _normalize_text(row.get("bot_name"))
        category = _normalize_text(row.get("category"))
        token = _normalize_text(row.get("sample_ua_token")).lower()
        if not bot_name or not category or not token:
            continue
        if token in seen_tokens:
            continue
        seen_tokens.add(token)
        entries.append(
            BotTaxonomyEntry(
                bot_name=bot_name,
                category=category,
                token=token,
                repo_category=AI_CATEGORY_TO_REPO_CATEGORY.get(category),
            )
        )
    return entries


def _load_entries_from_xlsx(path: Path) -> list[BotTaxonomyEntry]:
    rows = _sheet_rows_from_xlsx(path)
    return _entries_from_rows(rows)


def _load_entries_from_csv(path: Path) -> list[BotTaxonomyEntry]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = [{key: _normalize_text(value) for key, value in row.items()} for row in reader]
    return _entries_from_rows(rows)


def _load_entries_from_fallback() -> list[BotTaxonomyEntry]:
    return [
        BotTaxonomyEntry(
            bot_name=bot_name,
            category=category,
            token=token,
            repo_category=AI_CATEGORY_TO_REPO_CATEGORY.get(category),
        )
        for bot_name, category, token in OFFICIAL_BOT_FALLBACK_ROWS
    ]


def list_bot_taxonomy_rows() -> list[dict[str, str]]:
    taxonomy = load_bot_taxonomy()
    return [
        {
            "bot_name": entry.bot_name,
            "category": entry.category,
            "sample_ua_token": entry.token,
            "repo_category": entry.repo_category or "",
        }
        for entry in taxonomy.entries
    ]


def upsert_bot_taxonomy_entry(
    *,
    bot_name: str,
    category: str,
    sample_ua_token: str,
    sample_ua: str = "",
    note: str = "",
) -> dict[str, Any]:
    clean_name, clean_category, clean_token = _validate_taxonomy_payload(bot_name, category, sample_ua_token)
    if OFFICIAL_BOT_XLSX_PATH.exists():
        result = _upsert_xlsx_row(
            OFFICIAL_BOT_XLSX_PATH,
            bot_name=clean_name,
            category=clean_category,
            sample_ua_token=clean_token,
            sample_ua=_normalize_text(sample_ua),
            note=_normalize_text(note),
        )
    else:
        existing_rows: list[dict[str, str]] = []
        if OFFICIAL_BOT_CSV_PATH.exists():
            with OFFICIAL_BOT_CSV_PATH.open("r", encoding="utf-8-sig", newline="") as handle:
                existing_rows = [dict(row) for row in csv.DictReader(handle)]
        fieldnames = ["bot_name", "category", "ua_variants", "sample_ua_token", "说明", "是否存在争议", "sample_ua", "bot流量"]
        created = True
        for row in existing_rows:
            if _normalize_token(row.get("sample_ua_token")) == clean_token or _normalize_text(row.get("bot_name")).lower() == clean_name.lower():
                row.update({"bot_name": clean_name, "category": clean_category, "sample_ua_token": clean_token})
                if sample_ua:
                    row["sample_ua"] = _normalize_text(sample_ua)
                if note:
                    row["说明"] = _normalize_text(note)
                created = False
                break
        if created:
            existing_rows.append(
                {
                    "bot_name": clean_name,
                    "category": clean_category,
                    "ua_variants": "1",
                    "sample_ua_token": clean_token,
                    "说明": _normalize_text(note) or "前端维护",
                    "是否存在争议": "0",
                    "sample_ua": _normalize_text(sample_ua),
                    "bot流量": "0",
                }
            )
        with OFFICIAL_BOT_CSV_PATH.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows([{key: row.get(key, "") for key in fieldnames} for row in existing_rows])
        result = {"created": created, "bot_name": clean_name, "category": clean_category, "sample_ua_token": clean_token}
    load_bot_taxonomy.cache_clear()
    return result


@lru_cache(maxsize=1)
def load_bot_taxonomy() -> BotTaxonomy:
    entries: list[BotTaxonomyEntry] = []
    if OFFICIAL_BOT_XLSX_PATH.exists():
        try:
            entries = _load_entries_from_xlsx(OFFICIAL_BOT_XLSX_PATH)
        except Exception:
            entries = []
    if not entries and OFFICIAL_BOT_CSV_PATH.exists():
        try:
            entries = _load_entries_from_csv(OFFICIAL_BOT_CSV_PATH)
        except Exception:
            entries = []
    if not entries:
        entries = _load_entries_from_fallback()
    ai_entries = [item for item in entries if item.repo_category in OFFICIAL_AI_REPO_CATEGORIES]
    non_ai_entries = [item for item in entries if item.category in NON_AI_BOT_CATEGORIES]
    ai_by_repo = {
        category: tuple(item for item in ai_entries if item.repo_category == category)
        for category in OFFICIAL_AI_REPO_CATEGORIES
    }
    all_tokens = frozenset(item.token for item in entries if item.token)
    return BotTaxonomy(
        entries=tuple(entries),
        ai_entries=tuple(ai_entries),
        non_ai_entries=tuple(non_ai_entries),
        ai_by_repo=ai_by_repo,
        all_tokens=all_tokens,
    )


def infer_bot_name_from_ua(user_agent: str | None) -> str:
    ua = _normalize_text(user_agent)
    if not ua or ua == "-":
        return "UnknownBot"
    ua_lower = ua.lower()
    taxonomy = load_bot_taxonomy()
    for entry in taxonomy.entries:
        if entry.token and entry.token in ua_lower:
            return entry.bot_name
    for token in BOT_NAME_RE.findall(ua):
        lowered = token.lower()
        if lowered in BOT_NAME_IGNORE:
            continue
        if any(hint in lowered for hint in BOT_NAME_HINTS):
            return token
    return "UnknownBot"


def infer_bot_signal_from_ua(user_agent: str | None) -> str:
    ua = _normalize_text(user_agent)
    if not ua or ua == "-":
        return ""
    ua_lower = ua.lower()
    taxonomy = load_bot_taxonomy()
    for entry in taxonomy.entries:
        if entry.token and entry.token in ua_lower:
            return entry.token
    for token in UNCLASSIFIED_BOT_HINT_TOKENS:
        if token in ua_lower:
            return token
    for token in BOT_NAME_RE.findall(ua):
        lowered = token.lower()
        if lowered in BOT_NAME_IGNORE:
            continue
        if any(hint in lowered for hint in BOT_NAME_HINTS):
            return token
    return ""


def is_official_bot_ua(user_agent: str | None) -> bool:
    ua = _normalize_text(user_agent).lower()
    if not ua or ua == "-":
        return False
    taxonomy = load_bot_taxonomy()
    return any(token in ua for token in taxonomy.all_tokens)


def is_potential_unclassified_bot_ua(user_agent: str | None) -> bool:
    ua = _normalize_text(user_agent).lower()
    if not ua or ua == "-":
        return False
    if is_official_bot_ua(ua):
        return False
    return any(token in ua for token in UNCLASSIFIED_BOT_HINT_TOKENS)
