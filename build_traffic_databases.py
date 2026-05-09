from __future__ import annotations

import argparse
from pprint import pprint

from traffic_analytics.service import AnalyticsService


def main() -> None:
    parser = argparse.ArgumentParser(description="Build B-side traffic analytics databases")
    parser.add_argument("--rebuild", action="store_true", help="reset existing databases before rebuilding")
    parser.add_argument(
        "--rebuild-derived-only",
        action="store_true",
        help="rebuild only derived users/sessions/increment data from the existing full database",
    )
    parser.add_argument(
        "--materialize-remote",
        action="store_true",
        help="explicitly copy remote ES logs into the local SQLite database",
    )
    args = parser.parse_args()

    service = AnalyticsService()
    if service.remote_source.is_configured() and not args.materialize_remote:
        pprint(
            {
                "skipped": True,
                "reason": "remote ES source is configured; local SQLite materialization is disabled",
            }
        )
        return

    if args.materialize_remote:
        service.allow_on_demand_sync = True

    if args.rebuild_derived_only:
        service._ensure_full_schema()
        service._ensure_increment_schema()
        service._rebuild_derived_tables()
    else:
        service.initialize(auto_sync=False, rebuild=args.rebuild)
    pprint(service.get_summary())


if __name__ == "__main__":
    main()
