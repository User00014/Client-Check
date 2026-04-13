from __future__ import annotations

import argparse
import os
from http.server import ThreadingHTTPServer

from run_traffic_api_stdlib import build_handler
from traffic_analytics.remote_source import KibanaRemoteLogSource, RemoteSearchConfig
from traffic_analytics.service import AnalyticsService


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run local dashboard against remote ES nginx indices.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8010)
    parser.add_argument("--es-base-url", default=os.getenv("TRAFFIC_REMOTE_BASE_URL", ""))
    parser.add_argument("--es-username", default=os.getenv("TRAFFIC_REMOTE_USERNAME", ""))
    parser.add_argument("--es-password", default=os.getenv("TRAFFIC_REMOTE_PASSWORD", ""))
    parser.add_argument("--es-index", default=os.getenv("TRAFFIC_REMOTE_INDEX", "*nginx*"))
    parser.add_argument("--batch-size", type=int, default=2000)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.es_base_url or not args.es_username or not args.es_password:
        raise SystemExit(
            "missing ES credentials; provide --es-base-url/--es-username/--es-password "
            "or set TRAFFIC_REMOTE_BASE_URL / TRAFFIC_REMOTE_USERNAME / TRAFFIC_REMOTE_PASSWORD"
        )
    service = AnalyticsService()
    service.remote_source = KibanaRemoteLogSource(
        RemoteSearchConfig(
            base_url=args.es_base_url,
            username=args.es_username,
            password=args.es_password,
            index=args.es_index,
            batch_size=args.batch_size,
        )
    )
    service.allow_on_demand_sync = False

    server = ThreadingHTTPServer((args.host, args.port), build_handler(service))
    print(f"local dashboard listening on http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    finally:
        service.stop_auto_sync()


if __name__ == "__main__":
    main()
