from __future__ import annotations

import argparse

import uvicorn

from traffic_analytics import create_app
from traffic_analytics.service import AnalyticsService


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Moseeker traffic analytics API")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8010)
    args = parser.parse_args()

    service = AnalyticsService()
    app = create_app(service)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
