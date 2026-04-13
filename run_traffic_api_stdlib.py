from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from traffic_analytics.service import AnalyticsService


WEB_DIR = Path(__file__).resolve().parent / "web"
DASHBOARD_HTML = WEB_DIR / "dashboard.html"


def parse_filters_query(path: str) -> dict[str, str | None]:
    qs = parse_qs(urlparse(path).query)
    return {
        "customer_name": qs["customer_name"][0] if "customer_name" in qs else None,
        "date_from": qs["date_from"][0] if "date_from" in qs else None,
        "date_to": qs["date_to"][0] if "date_to" in qs else None,
    }


def parse_dashboard_query(path: str) -> dict[str, str | int | None]:
    qs = parse_qs(urlparse(path).query)
    return {
        "top_bots": int(qs["top_bots"][0]) if "top_bots" in qs else 10,
        "top_pages": int(qs["top_pages"][0]) if "top_pages" in qs else 10,
        "customer_name": qs["customer_name"][0] if "customer_name" in qs else None,
        "host": qs["host"][0] if "host" in qs else None,
        "date_from": qs["date_from"][0] if "date_from" in qs else None,
        "date_to": qs["date_to"][0] if "date_to" in qs else None,
    }


def build_handler(service: AnalyticsService):
    class Handler(BaseHTTPRequestHandler):
        def _summary_from_snapshot(self):
            if not service.snapshot_path.exists():
                return None
            payload = json.loads(service.snapshot_path.read_text(encoding="utf-8"))
            bot_rows = payload.get("bot_feature_breakdown", [])
            return {
                "metadata": {"source": "snapshot", "generated_at": payload.get("generated_at", "")},
                "total_requests": payload.get("metrics", {}).get("total_requests", 0),
                "total_users": payload.get("metrics", {}).get("total_users", 0),
                "total_bot_families": len({row.get("bot_family", "") for row in bot_rows if row.get("bot_family")}),
                "daily_overview": payload.get("daily_overview", []),
            }

        def _write_html(self, status: int, text: str):
            data = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(data)

        def _write_json(self, status: int, payload):
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(data)

        def _read_json(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            return json.loads(raw.decode("utf-8"))

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path in {"/", "/panel", "/dashboard"}:
                if not DASHBOARD_HTML.exists():
                    return self._write_json(HTTPStatus.NOT_FOUND, {"detail": "dashboard html not found"})
                return self._write_html(HTTPStatus.OK, DASHBOARD_HTML.read_text(encoding="utf-8"))
            if parsed.path == "/health":
                return self._write_json(HTTPStatus.OK, {"status": "ok"})
            if parsed.path == "/summary":
                payload = self._summary_from_snapshot()
                if payload is None:
                    payload = service.get_summary()
                return self._write_json(HTTPStatus.OK, payload)
            if parsed.path == "/frontend/filters":
                query = parse_filters_query(self.path)
                return self._write_json(
                    HTTPStatus.OK,
                    service.get_dashboard_filters(
                        customer_name=query["customer_name"],
                        date_from=query["date_from"],
                        date_to=query["date_to"],
                    ),
                )
            if parsed.path == "/frontend/dashboard":
                query = parse_dashboard_query(self.path)
                return self._write_json(
                    HTTPStatus.OK,
                    service.get_filtered_dashboard(
                        customer_name=query["customer_name"],
                        host=query["host"],
                        date_from=query["date_from"],
                        date_to=query["date_to"],
                        top_bots=max(int(query["top_bots"]), 1),
                        top_pages=max(int(query["top_pages"]), 1),
                        exclude_sensitive_pages=False,
                    ),
                )
            if parsed.path == "/bots/catalog":
                return self._write_json(HTTPStatus.OK, service.get_bot_catalog())
            if parsed.path == "/increment/snapshot":
                qs = parse_qs(parsed.query)
                limit = int(qs["limit"][0]) if "limit" in qs else None
                return self._write_json(HTTPStatus.OK, service.get_increment_snapshot(limit=limit))
            if parsed.path.startswith("/users/"):
                user_id = parsed.path.split("/users/", 1)[1]
                payload = service.get_user_detail(user_id)
                if payload is None:
                    return self._write_json(HTTPStatus.NOT_FOUND, {"detail": "user_id not found"})
                return self._write_json(HTTPStatus.OK, payload)
            return self._write_json(HTTPStatus.NOT_FOUND, {"detail": "not found"})

        def do_POST(self):
            if self.path == "/logs":
                try:
                    payload = self._read_json()
                    result = service.ingest_api_logs(payload.get("side", ""), payload.get("logs", []))
                    return self._write_json(HTTPStatus.OK, result)
                except ValueError as exc:
                    return self._write_json(HTTPStatus.BAD_REQUEST, {"detail": str(exc)})
            if self.path == "/sync":
                return self._write_json(HTTPStatus.OK, service.sync_from_local_logs())
            return self._write_json(HTTPStatus.NOT_FOUND, {"detail": "not found"})

        def log_message(self, format, *args):
            return

    return Handler


def main():
    parser = argparse.ArgumentParser(description="Run stdlib B-side traffic analytics API")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8010)
    parser.add_argument("--rebuild", action="store_true")
    parser.add_argument("--skip-initial-sync", action="store_true")
    parser.add_argument("--use-existing-db", action="store_true")
    args = parser.parse_args()

    print("starting stdlib api", flush=True)
    service = AnalyticsService()
    if args.use_existing_db:
        print("using existing uploaded databases", flush=True)
        service.allow_on_demand_sync = False
    else:
        print("initializing service", flush=True)
        service.initialize(auto_sync=True, rebuild=args.rebuild, initial_sync=not args.skip_initial_sync)
        print("service initialized", flush=True)
    server = ThreadingHTTPServer((args.host, args.port), build_handler(service))
    print(f"listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    finally:
        service.stop_auto_sync()


if __name__ == "__main__":
    main()
