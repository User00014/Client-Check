from __future__ import annotations

import argparse
import json
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib import request
from urllib.error import HTTPError, URLError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run local helper for report LLM summary generation.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18181)
    return parser.parse_args()


def fallback_summary(llm_context: dict) -> str:
    site = str(llm_context.get("site") or "当前站点")
    chatgpt_total = int(llm_context.get("chatgpt_total") or 0)
    oai_total = int(llm_context.get("oai_total") or 0)
    training_total = int(llm_context.get("training_total") or 0)
    if chatgpt_total > 0:
        return f"{site} 已完整经历四个阶段，目前处于第四阶段。下一步重点观察 ChatGPT-User 点击量是否开始稳定增长。AI发现、收录、建立索引的时间跨度通常在数周左右，期间AI流量表现会相对平稳。"
    if oai_total > 0:
        return f"{site} 已进入 AI 索引阶段。当前重点观察 ChatGPT-User 是否开始出现真实点击，以及训练型抓取是否维持稳定。"
    if training_total >= 5:
        return f"{site} 已进入训练收录阶段。当前重点观察 OAI-SearchBot 是否开始批量建立索引，以及 sitemap / llms.txt 的读取是否继续增长。"
    return f"{site} 暂未观察到明确的 AI 发现与索引信号，建议继续观察 llms.txt / sitemap 的读取情况。"


def generate_llm_summary(llm_context: dict, llm_config: dict) -> str:
    fallback = fallback_summary(llm_context)
    base_url = str(llm_config.get("base_url") or "").strip()
    token = str(llm_config.get("token") or "").strip()
    model = str(llm_config.get("model") or "claude-opus-4-6").strip()
    if not base_url or not token:
        return fallback

    body = {
        "model": model,
        "max_tokens": 320,
        "temperature": 0.2,
        "system": "你是中文数据报告助手。只输出一段正式、简洁、业务风格的总结，不要列表，不要标题，不要解释。",
        "messages": [
            {
                "role": "user",
                "content": "基于以下JSON写1段中文总结，40到90字，说明当前AI可发现性阶段和下一步观察重点："
                + json.dumps(llm_context, ensure_ascii=False, separators=(",", ":")),
            }
        ],
    }
    headers = {
        "Content-Type": "application/json",
        "x-api-key": token,
        "anthropic-version": "2023-06-01",
    }
    req = request.Request(
        base_url.rstrip("/") + "/v1/messages",
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=120) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        parts = payload.get("content") or []
        text = " ".join(str(item.get("text") or "").strip() for item in parts if isinstance(item, dict)).strip()
        return text or fallback
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
        return fallback


def _extract_json_payload(text: str) -> dict:
    text = (text or "").strip()
    if not text:
        return {}
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.S).strip()
    try:
        payload = json.loads(text)
        return payload if isinstance(payload, dict) else {}
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.S)
        if not match:
            return {}
        try:
            payload = json.loads(match.group(0))
            return payload if isinstance(payload, dict) else {}
        except json.JSONDecodeError:
            return {}


def generate_llm_sections(llm_context: dict, llm_config: dict) -> dict:
    summary_text = generate_llm_summary(llm_context, llm_config)
    base_url = str(llm_config.get("base_url") or "").strip()
    token = str(llm_config.get("token") or "").strip()
    model = str(llm_config.get("model") or "claude-opus-4-6").strip()
    fallback = {"summary_text": summary_text}
    if not base_url or not token:
        return fallback

    prompt = {
        "task": "为中文流量报告生成结构化章节结论",
                        "rules": {
                            "style": "简洁、清楚、偏业务表达，适合非技术人员阅读，有数据支撑，不空泛，不长篇大论",
                            "anomaly_rule": "如果没有显著异常，就把 anomaly_intro 写成未发现显著异常，anomaly_1_title 和 anomaly_2_title 留空字符串",
                            "finding_rule": "finding1_body 到 finding3_body 每段 50-110 字",
                            "section_rule": "daily_summary/pages_summary/compare_summary/weekly_summary 每段 45-120 字",
                            "specificity_rule": "优先写出具体 AI BOT平台名、具体重点页面名、具体周均值变化，不要只写笼统概括。",
                            "terminology_rule": "全文统一使用“AI BOT流量”“AI 搜索 BOT”“AI 训练 BOT”“AI 索引 BOT”“AI BOT平台”这些表述，不要写 AI 流量、AI 访问、Agentic Page 等说法。",
                            "non_shopify_rule": "如果 is_shopify=false，不要提可观测性、SEO Bot、Agentic Page、人类流量、产品页，也不要解释什么不统计；只围绕 AI BOT总量、AI BOT平台构成、周维度日均变化、重点页面与成功访问展开。",
                            "platform_rule": "所有平台比较必须使用同一层级的具体平台小类，例如 Bytespider、ChatGPT-User、GPTBot、ClaudeBot、OAI-SearchBot。禁止拿大类（如 AI 搜索 BOT、OpenAI）和小类直接比较。发现 2 只需要直接讲清楚哪个具体 AI BOT平台访问占比最高。",
                            "format": "只输出 JSON 对象，不要 markdown，不要解释",
                        },
        "context": llm_context,
        "output_schema": {
            "summary_text": "string",
            "finding1_body": "string",
            "finding2_body": "string",
            "finding3_body": "string",
            "anomaly_intro": "string",
            "anomaly_1_title": "string",
            "anomaly_1_body": "string",
            "anomaly_2_title": "string",
            "anomaly_2_body": "string",
            "daily_summary": "string",
            "weekly_summary": "string",
            "pages_summary": "string",
            "compare_summary": "string",
        },
    }
    body = {
        "model": model,
        "max_tokens": 1800,
        "temperature": 0.15,
        "system": "你是中文数据报告分析助手。读者是产品经理和直接对接客户的业务人员。请严格输出一个 JSON 对象，结论必须简洁、清楚、非技术化、有数据支撑，不允许空泛套话，不要输出 JSON 以外的任何内容。",
        "messages": [
            {
                "role": "user",
                "content": json.dumps(prompt, ensure_ascii=False, separators=(",", ":")),
            }
        ],
    }
    headers = {
        "Content-Type": "application/json",
        "x-api-key": token,
        "anthropic-version": "2023-06-01",
    }
    req = request.Request(
        base_url.rstrip("/") + "/v1/messages",
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=180) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        parts = payload.get("content") or []
        text = " ".join(str(item.get("text") or "").strip() for item in parts if isinstance(item, dict)).strip()
        parsed = _extract_json_payload(text)
        if not parsed:
            return fallback
        parsed["summary_text"] = str(parsed.get("summary_text") or summary_text).strip() or summary_text
        return parsed
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
        return fallback


def build_handler():
    class Handler(BaseHTTPRequestHandler):
        def _cors_origin(self) -> str:
            origin = str(self.headers.get("Origin") or "").strip()
            return origin or "*"

        def _write_json(self, status: int, payload):
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", self._cors_origin())
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Access-Control-Request-Private-Network")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.send_header("Access-Control-Max-Age", "600")
            self.end_headers()
            self.wfile.write(data)

        def _read_json(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            return json.loads(raw.decode("utf-8"))

        def do_OPTIONS(self):
            self._write_json(HTTPStatus.NO_CONTENT, {})

        def do_GET(self):
            parsed_path = urlparse(self.path).path
            if parsed_path == "/health":
                return self._write_json(HTTPStatus.OK, {"status": "ok"})
            return self._write_json(HTTPStatus.NOT_FOUND, {"detail": "not found"})

        def do_POST(self):
            parsed_path = urlparse(self.path).path
            if parsed_path == "/ping":
                return self._write_json(HTTPStatus.OK, {"ok": True, "detail": "helper ready"})
            if parsed_path == "/check-llm":
                payload = self._read_json()
                llm_config = payload.get("llm_config") or {}
                sections = generate_llm_sections({"site": "health-check", "period": [], "ai_index": 0, "ai_search": 0, "ai_training": 0, "seo_bot": 0}, llm_config)
                return self._write_json(HTTPStatus.OK, {"ok": bool(sections.get("summary_text")), "detail": "LLM connection ok" if sections.get("summary_text") else "LLM unavailable"})
            if parsed_path != "/report-summary":
                return self._write_json(HTTPStatus.NOT_FOUND, {"detail": "not found"})
            payload = self._read_json()
            sections = generate_llm_sections(
                payload.get("llm_context") or {},
                payload.get("llm_config") or {},
            )
            return self._write_json(HTTPStatus.OK, sections)

        def log_message(self, format, *args):
            return

    return Handler


def main() -> None:
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), build_handler())
    print(f"local report llm helper listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
