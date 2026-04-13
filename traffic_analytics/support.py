from __future__ import annotations
"""多个模块都会用到的小型数据结构与通用工具。"""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, date

# B 端 Nginx access log 的正则解析模板。
B_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<dt>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)


@dataclass
class IngestResult:
    """一次入库/同步操作的结果摘要。"""
    inserted: int
    duplicates: int
    affected_days: set[str]


@dataclass
class DateWindow:
    """一个闭区间日期窗口，常用于和上一周期做对比。"""
    start: str
    end: str


def local_day_to_utc_bounds(day_start: str, day_end: str, tz_offset_hours: int = 8) -> tuple[str, str]:
    """把本地自然日边界转换成 UTC 查询区间。

    ES 存的是 UTC 时间，而前端筛选使用的是本地日期，所以每次查询前
    都要先把“本地 00:00 ~ 次日 00:00”换算成 UTC。
    """
    start_dt = datetime.fromisoformat(day_start + "T00:00:00") - timedelta(hours=tz_offset_hours)
    end_dt = datetime.fromisoformat(day_end + "T00:00:00") + timedelta(days=1) - timedelta(hours=tz_offset_hours)
    return start_dt.isoformat(timespec="milliseconds") + "Z", end_dt.isoformat(timespec="milliseconds") + "Z"
