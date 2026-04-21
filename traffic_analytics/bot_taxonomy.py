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
