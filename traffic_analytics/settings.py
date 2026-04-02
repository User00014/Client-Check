from __future__ import annotations

from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT_DIR / "日志"
OUTPUT_DIR = ROOT_DIR / "output" / "current"
DATABASE_DIR = OUTPUT_DIR / "database"
FULL_DB_PATH = DATABASE_DIR / "moseeker_full_analytics.sqlite"
INCREMENT_DB_PATH = DATABASE_DIR / "moseeker_increment_analytics.sqlite"
SNAPSHOT_PATH = DATABASE_DIR / "full_statistics_snapshot.json"
FRONTEND_SNAPSHOT_PATH = DATABASE_DIR / "frontend_dashboard_snapshot.json"

SKIP_FIRST_DAYS = 3
TARGET_METHOD = "GET"
HUMAN_SESSION_GAP_SECONDS = 30 * 60
BOT_SESSION_GAP_SECONDS = 60
AUTO_SYNC_CHECK_INTERVAL_SECONDS = 30 * 60
