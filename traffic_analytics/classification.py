from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import parse_qs, urlparse, urlsplit

from .bot_taxonomy import infer_bot_name_from_ua, is_potential_unclassified_bot_ua, load_bot_taxonomy


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

REPO_BAIDU_AI_RE = re.compile(r"baiduspider.*ai")
REPO_AI_RETRIEVAL_RULES = [
    ("chatgpt-user", "ChatGPT-User"),
    ("oai-searchbot", "OAI-SearchBot"),
    ("claudebot", "ClaudeBot"),
    ("claude-web", "claude-web"),
    ("googleagent-mariner", "GoogleAgent-Mariner"),
    ("applebot-extended", "Applebot-Extended"),
    ("perplexitybot", "PerplexityBot"),
    ("perplexity-user", "Perplexity-User"),
    ("mistralai-user", "MistralAI-User"),
    ("meta-externalagent", "meta-externalagent"),
    ("cohere-ai", "cohere-ai"),
    ("youbot", "YouBot"),
    ("duckassistbot", "DuckAssistBot"),
    ("moonshot", "Moonshot"),
]
REPO_AI_TRAINING_RULES = [
    ("gptbot", "GPTBot"),
    ("anthropic-ai", "anthropic-ai"),
    ("google-extended", "Google-Extended"),
    ("amazonbot", "Amazonbot"),
    ("ccbot", "CCBot"),
    ("diffbot", "Diffbot"),
    ("ai2bot", "AI2Bot"),
]
REPO_AI_INDEX_RULES = [
    ("googleother", "GoogleOther"),
    ("bytespider", "Bytespider"),
    ("toutiaospider", "ToutiaoSpider"),
    ("baiduspider-render", "Baiduspider-render"),
    ("qwen", "Qwen"),
    ("alibaba", "Alibaba"),
    ("yisouspider", "YisouSpider"),
    ("360spider", "360Spider"),
]
REPO_AI_UNCLASSIFIED_RULES = [
    ("facebookbot", "FacebookBot"),
    ("imagesiftbot", "ImagesiftBot"),
    ("omgilibot", "Omgilibot"),
    ("timpibot", "Timpibot"),
]
REPO_SEO_OTHER_KEYWORDS = ["bot", "spider", "crawler", "crawl", "slurp", "scraper", "scan", "fetch"]
REPO_SUSPICIOUS_PATTERNS = [
    "/.git", "/.aws", "/.env", "/.s3cfg",
    "/phpinfo.php", "/info.php",
    "/_debugbar", "/debug", "/debugbar",
    "/aws-credentials", "/wp-config.php", "/test.php",
]
REPO_STATIC_EXTENSIONS = [
    ".css", ".js", ".map",
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".webp", ".avif", ".bmp", ".tif", ".tiff",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".mov", ".flv", ".m4a",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".exe", ".dll", ".iso", ".bin",
    ".txt", ".xml", ".json", ".webmanifest", ".yaml", ".yml", ".ini", ".conf", ".log", ".toml", ".sql", ".bak",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv",
]


@dataclass(frozen=True)
class AgentRule:
    family: str
    category: str
    bucket: str
    vendor: str
    product: str
    purpose: str
    actor_type: str
    confidence: str
    description: str
    tokens: tuple[str, ...]


BOT_RULES: tuple[AgentRule, ...] = (
    AgentRule("OAI-SearchBot", "AI Retrieval", "AI Bot", "OpenAI", "ChatGPT Search", "search retrieval crawl", "bot", "high", "OpenAI search retrieval crawler for search-style results.", ("oai-searchbot",)),
    AgentRule("ChatGPT-User", "AI Retrieval", "AI Bot", "OpenAI", "ChatGPT", "user-triggered fetch", "bot", "high", "User-triggered retrieval agent fetching pages on behalf of ChatGPT users.", ("chatgpt-user",)),
    AgentRule("GPTBot", "AI Training", "AI Bot", "OpenAI", "GPTBot", "foundation model crawl", "bot", "high", "OpenAI crawler commonly used for model improvement and corpus acquisition.", ("gptbot",)),
    AgentRule("Claude-SearchBot", "AI Retrieval", "AI Bot", "Anthropic", "Claude Search", "search retrieval crawl", "bot", "high", "Anthropic search crawler used for retrieval-style results.", ("claude-searchbot",)),
    AgentRule("ClaudeBot", "AI Training", "AI Bot", "Anthropic", "ClaudeBot", "foundation model crawl", "bot", "high", "Anthropic crawler for training/index acquisition scenarios.", ("claudebot",)),
    AgentRule("PerplexityBot", "AI Retrieval", "AI Bot", "Perplexity", "Perplexity", "answer retrieval crawl", "bot", "high", "Perplexity retrieval crawler used for answer generation and page fetching.", ("perplexitybot",)),
    AgentRule("meta-externalagent", "AI Retrieval", "AI Bot", "Meta", "Meta External Agent", "external AI fetch", "bot", "high", "Meta external agent used to fetch shared content for AI or platform experiences.", ("meta-externalagent",)),
    AgentRule("Amazonbot", "AI Training", "AI Bot", "Amazon", "Amazonbot", "crawl and indexing", "bot", "high", "Amazon crawler used for indexing and AI-related fetch workloads.", ("amazonbot",)),
    AgentRule("CCBot", "AI Training", "AI Bot", "Common Crawl", "CCBot", "web archive crawl", "bot", "high", "Common Crawl crawler frequently reused by downstream AI training pipelines.", ("ccbot",)),
    AgentRule("Bytespider", "AI Indexer", "AI Bot", "ByteDance", "Bytespider", "indexing and content understanding", "bot", "high", "ByteDance spider used by search and content products.", ("bytespider",)),
    AgentRule("YisouSpider", "AI Indexer", "AI Bot", "Yisou", "YisouSpider", "indexing and discovery", "bot", "high", "Yisou content crawler for search and content discovery.", ("yisouspider", "yisou")),
    AgentRule("360Spider", "AI Indexer", "AI Bot", "360 Search", "360Spider", "indexing and SEO discovery", "bot", "high", "360 search crawler that often masquerades as common desktop browsers.", ("360spider",)),
    AgentRule("Baiduspider-AI", "AI Indexer", "AI Bot", "Baidu", "Baiduspider AI", "AI-oriented crawl", "bot", "high", "Baidu AI-oriented crawl identity.", ("baiduspider-ai",)),
    AgentRule("Baiduspider-render", "AI Indexer", "AI Bot", "Baidu", "Baiduspider Render", "render crawl", "bot", "high", "Baidu rendering crawler.", ("baiduspider-render",)),
    AgentRule("GoogleOther", "AI Indexer", "AI Bot", "Google", "GoogleOther", "specialized fetch", "bot", "high", "Google specialized fetch crawler distinct from standard Googlebot.", ("googleother",)),
    AgentRule("Googlebot-Image", "SEO Bot", "SEO Bot", "Google", "Googlebot Image", "image indexing", "bot", "high", "Google image indexing crawler.", ("googlebot-image",)),
    AgentRule("Googlebot", "SEO Bot", "SEO Bot", "Google", "Googlebot", "search indexing", "bot", "high", "Google search indexing crawler.", ("googlebot",)),
    AgentRule("bingbot", "SEO Bot", "SEO Bot", "Microsoft", "Bingbot", "search indexing", "bot", "high", "Bing search crawler.", ("bingbot",)),
    AgentRule("Baiduspider", "SEO Bot", "SEO Bot", "Baidu", "Baiduspider", "search indexing", "bot", "high", "Baidu search crawler.", ("baiduspider",)),
    AgentRule("Sogou", "SEO Bot", "SEO Bot", "Sogou", "SogouSpider", "search indexing", "bot", "high", "Sogou search crawler.", ("sogou",)),
    AgentRule("PetalBot", "SEO Bot", "SEO Bot", "Huawei", "PetalBot", "search indexing", "bot", "high", "Huawei Petal search crawler.", ("petalbot",)),
    AgentRule("DotBot", "SEO Bot", "SEO Bot", "Moz", "DotBot", "SEO link crawl", "bot", "high", "Moz crawler used in SEO/link graph products.", ("dotbot",)),
    AgentRule("MJ12bot", "SEO Bot", "SEO Bot", "Majestic", "MJ12bot", "SEO link crawl", "bot", "high", "Majestic SEO crawler.", ("mj12bot",)),
    AgentRule("Slurp", "SEO Bot", "SEO Bot", "Yahoo", "Slurp", "search indexing", "bot", "high", "Yahoo crawler.", ("slurp",)),
    AgentRule("facebookexternalhit", "Social Preview Bot", "Social / Platform Bot", "Meta", "facebookexternalhit", "link preview fetch", "bot", "high", "Facebook link preview crawler.", ("facebookexternalhit",)),
    AgentRule("Facebot", "Social Preview Bot", "Social / Platform Bot", "Meta", "Facebot", "link preview fetch", "bot", "high", "Meta link preview crawler.", ("facebot",)),
    AgentRule("Twitterbot", "Social Preview Bot", "Social / Platform Bot", "X", "Twitterbot", "link preview fetch", "bot", "high", "Twitter/X link preview crawler.", ("twitterbot",)),
    AgentRule("TikTokSpider", "Social Preview Bot", "Social / Platform Bot", "TikTok", "TikTokSpider", "preview and indexing fetch", "bot", "high", "TikTok preview/content fetch crawler.", ("tiktokspider",)),
    AgentRule("Google-Site-Verification", "Verification Bot", "Verification Bot", "Google", "Site Verification", "ownership verification", "bot", "high", "Google ownership verification agent.", ("google-site-verification",)),
    AgentRule("HeadlessChrome", "Browser Automation", "Automation / Script", "Unknown", "Headless Browser", "browser automation", "automation", "medium", "Headless browser automation or scripted crawl.", ("headlesschrome", "headless")),
    AgentRule("Scrapy", "Security / Scanner", "Automation / Script", "Unknown", "Scrapy", "scripted crawling", "automation", "high", "Scrapy-based scripted crawler.", ("scrapy",)),
    AgentRule("python-requests", "Automation / Script", "Automation / Script", "Unknown", "python-requests", "scripted HTTP client", "automation", "high", "Python requests client, often used for scripts, probes, or internal automation.", ("python-requests",)),
    AgentRule("curl", "Automation / Script", "Automation / Script", "Unknown", "curl", "scripted HTTP client", "automation", "high", "curl or libcurl client.", ("libcurl", "curl/")),
    AgentRule("Go-http-client", "Automation / Script", "Automation / Script", "Unknown", "Go-http-client", "scripted HTTP client", "automation", "high", "Go HTTP client automation.", ("go-http-client",)),
    AgentRule("okhttp", "Automation / Script", "Automation / Script", "Unknown", "okhttp", "scripted HTTP client", "automation", "medium", "OkHttp client often used by mobile apps, SDK probes, or scripts.", ("okhttp",)),
    AgentRule("axios", "Automation / Script", "Automation / Script", "Unknown", "axios", "scripted HTTP client", "automation", "medium", "Axios-based scripted client.", ("axios",)),
    AgentRule("wget", "Automation / Script", "Automation / Script", "Unknown", "wget", "scripted fetch", "automation", "high", "wget scripted fetch client.", ("wget",)),
    AgentRule("Bun", "Automation / Script", "Automation / Script", "Unknown", "Bun", "scripted runtime client", "automation", "medium", "Bun runtime client, often used by scripts or asset checks.", ("bun/",)),
)

APP_RULES: tuple[AgentRule, ...] = (
    AgentRule("Doubao / newsai", "AI App WebView", "App WebView", "ByteDance", "newsai", "in-app page open", "human_app", "medium", "Likely human-triggered AI app webview traffic.", ("newsai/",)),
    AgentRule("Douyin / aweme", "App WebView", "App WebView", "ByteDance", "aweme", "in-app page open", "human_app", "medium", "Likely human-triggered Douyin/TikTok in-app browser traffic.", ("appname/aweme", " aweme_")),
    AgentRule("Larus Nova", "AI App WebView", "App WebView", "ByteDance", "nova", "in-app page open", "human_app", "medium", "Likely human-triggered Nova app traffic rather than a crawler.", ("com.larus.nova/",)),
    AgentRule("WeChat", "App WebView", "App WebView", "Tencent", "WeChat", "in-app page open", "human_app", "high", "WeChat in-app browser traffic.", ("micromessenger",)),
)

GENERIC_BOT_TOKENS = ("bot", "spider", "crawler")
GENERIC_AUTOMATION_TOKENS = ("scanner", "monitor", "selenium", "playwright", "phantomjs", "java/")
OFFICIAL_BOT_BUCKETS = {
    "AI Search": ("AI Bot", "bot", "AI search crawl"),
    "AI Training": ("AI Bot", "bot", "AI training crawl"),
    "AI Index": ("AI Bot", "bot", "AI index crawl"),
    "SEO Bot": ("SEO Bot", "bot", "SEO crawl"),
    "Social Preview Bot": ("Social / Platform Bot", "bot", "social preview fetch"),
    "Verification Bot": ("Verification Bot", "bot", "verification fetch"),
    "Automation / Script": ("Automation / Script", "automation", "automation or scripted HTTP client"),
}
OFFICIAL_VENDOR_HINTS = (
    ("openai", "OpenAI"),
    ("chatgpt", "OpenAI"),
    ("anthropic", "Anthropic"),
    ("claude", "Anthropic"),
    ("perplexity", "Perplexity"),
    ("amazon", "Amazon"),
    ("google", "Google"),
    ("baidu", "Baidu"),
    ("bing", "Microsoft"),
    ("sogou", "Sogou"),
    ("petal", "Huawei"),
    ("meta", "Meta"),
    ("facebook", "Meta"),
    ("twitter", "X"),
    ("tiktok", "TikTok"),
    ("byte", "ByteDance"),
    ("360", "360 Search"),
    ("yisou", "Yisou"),
    ("ahrefs", "Ahrefs"),
    ("mj12", "Majestic"),
    ("dotbot", "Moz"),
    ("common crawl", "Common Crawl"),
    ("ccbot", "Common Crawl"),
)


def sha1_short(text: str, size: int = 16) -> str:
    return hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest()[:size]


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


def page_exclusion_reason(path: str | None) -> str | None:
    if not path:
        return "static_or_non_page"
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


def normalize_ip(raw_ip: str | None) -> str:
    if not raw_ip:
        return ""
    return raw_ip.split(",")[0].strip()


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


def _match_rule(user_agent: str, rules: Iterable[AgentRule]) -> tuple[AgentRule | None, str | None]:
    ua = user_agent.lower()
    for rule in rules:
        for token in rule.tokens:
            if token in ua:
                return rule, token
    return None, None


def _official_taxonomy_entries():
    taxonomy = load_bot_taxonomy()
    return sorted(taxonomy.entries, key=lambda item: (-len(item.token), item.bot_name.lower()))


def _official_taxonomy_match(user_agent: str | None):
    ua = (user_agent or "").strip().lower()
    if not ua or ua == "-":
        return None, None
    for entry in _official_taxonomy_entries():
        if entry.token and entry.token in ua:
            return entry, entry.token
    return None, None


def _guess_vendor(bot_name: str) -> str:
    lowered = bot_name.lower()
    for token, vendor in OFFICIAL_VENDOR_HINTS:
        if token in lowered:
            return vendor
    return "Unknown"


def _official_entry_payload(entry, token: str) -> dict[str, str]:
    bucket, actor_type, purpose = OFFICIAL_BOT_BUCKETS.get(entry.category, ("Other External Bot", "bot", "generic crawler activity"))
    return {
        "actor_type": actor_type,
        "bucket": bucket,
        "category": entry.category,
        "family": entry.bot_name,
        "vendor": _guess_vendor(entry.bot_name),
        "product": entry.bot_name,
        "purpose": purpose,
        "confidence": "high",
        "description": f"Matched official bot taxonomy category: {entry.category}.",
        "match_token": token,
    }


def classify_agent(user_agent: str | None) -> dict[str, str]:
    ua = (user_agent or "").strip()
    ua_lower = ua.lower()
    if not ua or ua == "-":
        return {
            "actor_type": "unknown",
            "bucket": "Unknown",
            "category": "Unknown",
            "family": "Unknown Agent",
            "vendor": "Unknown",
            "product": "Unknown",
            "purpose": "unidentified traffic",
            "confidence": "low",
            "description": "Missing or empty user agent.",
            "match_token": "",
        }

    official_entry, official_token = _official_taxonomy_match(ua)
    if official_entry:
        return _official_entry_payload(official_entry, official_token or "")

    rule, token = _match_rule(ua, BOT_RULES)
    if rule:
        return {
            "actor_type": rule.actor_type,
            "bucket": rule.bucket,
            "category": rule.category,
            "family": rule.family,
            "vendor": rule.vendor,
            "product": rule.product,
            "purpose": rule.purpose,
            "confidence": rule.confidence,
            "description": rule.description,
            "match_token": token or "",
        }

    rule, token = _match_rule(ua, APP_RULES)
    if rule:
        return {
            "actor_type": rule.actor_type,
            "bucket": rule.bucket,
            "category": rule.category,
            "family": rule.family,
            "vendor": rule.vendor,
            "product": rule.product,
            "purpose": rule.purpose,
            "confidence": rule.confidence,
            "description": rule.description,
            "match_token": token or "",
        }

    for token in GENERIC_AUTOMATION_TOKENS:
        if token in ua_lower:
            return {
                "actor_type": "automation",
                "bucket": "Automation / Script",
                "category": "Security / Scanner",
                "family": "Generic Automation",
                "vendor": "Unknown",
                "product": "Generic Automation",
                "purpose": "script or scanner activity",
                "confidence": "medium",
                "description": "Matched a generic automation/scanner token.",
                "match_token": token,
            }

    for token in GENERIC_BOT_TOKENS:
        if token in ua_lower:
            return {
                "actor_type": "bot",
                "bucket": "Other External Bot",
                "category": "Other External Bot",
                "family": "Other Bot",
                "vendor": "Unknown",
                "product": "Other Bot",
                "purpose": "generic crawler activity",
                "confidence": "medium",
                "description": "Matched a generic crawler token.",
                "match_token": token,
            }

    family = browser_family(ua)
    return {
        "actor_type": "human",
        "bucket": "Standard Browser",
        "category": "Human Browser",
        "family": family,
        "vendor": family,
        "product": family,
        "purpose": "interactive browsing",
        "confidence": "medium",
        "description": "Looks like an interactive browser or app browser.",
        "match_token": "",
    }


def derive_user_key(source_side: str, actor_type: str, client_ip: str, user_agent: str) -> tuple[str | None, str]:
    if actor_type not in {"human", "human_app"}:
        return None, "none"
    public_ip = client_ip if is_public_ip(client_ip) else ""
    fingerprint = sha1_short(user_agent or "")
    if source_side == "c" and public_ip:
        return sha1_short(f"c|{public_ip}|{fingerprint}", 24), "high"
    if source_side == "c" and client_ip:
        return sha1_short(f"c|{client_ip}|{fingerprint}", 24), "medium"
    if source_side == "b":
        return sha1_short(f"b|{fingerprint}", 24), "low"
    if client_ip:
        return sha1_short(f"x|{client_ip}|{fingerprint}", 24), "medium"
    return sha1_short(f"u|{fingerprint}", 24), "low"


def derive_session_actor_key(actor_type: str, client_ip: str, user_agent: str, user_key: str | None) -> str | None:
    fingerprint = sha1_short(user_agent or "")
    if actor_type in {"human", "human_app"}:
        return user_key
    if actor_type in {"bot", "automation"}:
        if client_ip:
            return sha1_short(f"bot|{client_ip}|{fingerprint}", 24)
        return sha1_short(f"bot|{fingerprint}", 24)
    return None


def repo_sanitize_host(host: str | None) -> str:
    h = (host or "").strip().lower()
    if ":" in h:
        return h.split(":", 1)[0]
    return h


def repo_extract_base_domain(domain: str | None) -> str:
    host = repo_sanitize_host(domain)
    for prefix in ("www.", "mmm.", "geo."):
        if host.startswith(prefix):
            return host[len(prefix):]
    return host


def repo_host_matches(host: str, domain: str) -> bool:
    if not host:
        return False
    return host == domain or host.endswith("." + domain)


def repo_referer_host(referer: str | None) -> str:
    ref = (referer or "").strip()
    if not ref or ref == "-":
        return ""
    raw = ref if "://" in ref else "http://" + ref
    try:
        parsed = urlparse(raw)
    except ValueError:
        return ""
    return repo_sanitize_host(parsed.hostname or "")


def repo_has_chatgpt_utm(uri: str | None, args: str | None) -> bool:
    uri_text = (uri or "").lower()
    if "utm_source=chatgpt.com" in uri_text:
        return True
    query = (args or "").strip()
    if not query:
        if "?" in (uri or ""):
            query = (uri or "").split("?", 1)[1]
    if not query:
        return False
    try:
        values = parse_qs(query)
    except Exception:
        return "utm_source=chatgpt.com" in query.lower()
    return any((v or "").strip().lower() == "chatgpt.com" for v in values.get("utm_source", []))


def repo_is_static_resource(uri: str | None) -> bool:
    path = (uri or "").lower()
    if "?" in path:
        path = path.split("?", 1)[0]
    return any(path.endswith(ext) for ext in REPO_STATIC_EXTENSIONS)


def repo_is_suspicious_probe(uri: str | None) -> bool:
    path = (uri or "").lower()
    return any(path.startswith(prefix) for prefix in REPO_SUSPICIOUS_PATTERNS)


def repo_is_c_mirror_host(host: str | None) -> bool:
    h = repo_sanitize_host(host)
    return h.startswith("mmm.") or h.endswith(".deeplumen.io")


def repo_is_shopify_app_proxy(uri: str | None) -> bool:
    path = (uri or "").strip().lower()
    if "?" in path:
        path = path.split("?", 1)[0]
    return path.startswith("/app-proxy")


def repo_is_shopify_source(source_ref: str | None) -> bool:
    return "shopify" in (source_ref or "").strip().lower()


def repo_classify_ai_bot(user_agent: str | None) -> tuple[str, str] | None:
    entry, _ = _official_taxonomy_match(user_agent)
    if entry and entry.repo_category:
        return entry.repo_category, entry.bot_name
    return None


def repo_classify_seo_bot(user_agent: str | None) -> str | None:
    entry, _ = _official_taxonomy_match(user_agent)
    if entry and entry.category == "SEO Bot":
        return entry.bot_name
    ua = (user_agent or "").lower()
    if "duckduckbot" in ua:
        return "DuckDuckBot"
    if "yandexbot" in ua:
        return "YandexBot"
    if "sosospider" in ua:
        return "Sosospider"
    for keyword in REPO_SEO_OTHER_KEYWORDS:
        if keyword in ua:
            return "Others"
    return None


def repo_classify_access(
    host: str | None,
    uri: str | None,
    args: str | None,
    status: int | None,
    referer: str | None,
    user_agent: str | None,
    source_ref: str | None = None,
) -> dict[str, str]:
    shopify_scope = repo_is_shopify_source(source_ref) or repo_is_shopify_app_proxy(uri)
    if shopify_scope and not repo_is_shopify_app_proxy(uri):
        return {"category": "unknown", "channel": ""}
    if repo_is_static_resource(uri):
        return {"category": "static", "channel": "StaticResource"}
    if repo_is_c_mirror_host(host) and int(status or 0) != 302 and not shopify_scope:
        return {"category": "unknown", "channel": ""}
    if repo_is_suspicious_probe(uri):
        return {"category": "suspicious_probe", "channel": "SuspiciousProbe"}
    ai = repo_classify_ai_bot(user_agent)
    if ai:
        return {"category": ai[0], "channel": ai[1]}
    seo = repo_classify_seo_bot(user_agent)
    if seo:
        return {"category": "seo_bot", "channel": seo}
    official_entry, _ = _official_taxonomy_match(user_agent)
    if official_entry:
        return {"category": "unknown", "channel": official_entry.bot_name}
    if is_potential_unclassified_bot_ua(user_agent):
        return {"category": "unknown", "channel": infer_bot_name_from_ua(user_agent)}
    if repo_has_chatgpt_utm(uri, args):
        return {"category": "user_ai", "channel": "ChatGPT"}

    ref_host = repo_referer_host(referer)
    if repo_host_matches(ref_host, "perplexity.ai"):
        return {"category": "user_ai", "channel": "Perplexity"}
    if repo_host_matches(ref_host, "gemini.google.com"):
        return {"category": "user_ai", "channel": "Gemini"}
    if repo_host_matches(ref_host, "google.com"):
        return {"category": "user_traditional", "channel": "Google"}
    if repo_host_matches(ref_host, "bing.com"):
        return {"category": "user_traditional", "channel": "Bing"}
    if repo_host_matches(ref_host, "baidu.com"):
        return {"category": "user_traditional", "channel": "Baidu"}
    if repo_host_matches(ref_host, "duckduckgo.com"):
        return {"category": "user_traditional", "channel": "DuckDuckGo"}
    if repo_host_matches(ref_host, "admin.shopify.com"):
        return {"category": "user_platform", "channel": "Shopify"}
    return {"category": "user_direct", "channel": "Direct/Unknown"}
