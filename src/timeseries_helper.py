"""
Timeseries helpers: normalize Zabbix history into series of points per item.

No API or MCP calls; used by get_timeseries in zabbix_mcp_server. Unit-testable.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List


def history_row_to_point(row: Dict[str, Any], include_iso_timestamp: bool) -> Dict[str, Any]:
    """Convert one Zabbix history row to a normalized point: timestamp, value, optional datetime_utc."""
    clock = row.get("clock")
    value = row.get("value")
    point: Dict[str, Any] = {
        "timestamp": int(clock) if clock is not None else 0,
        "value": str(value) if value is not None else "",
    }
    if include_iso_timestamp and clock is not None:
        try:
            dt = datetime.fromtimestamp(int(clock), tz=timezone.utc)
            point["datetime_utc"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OSError):
            pass
    return point


def group_history_into_series(
    raw_history: List[Dict[str, Any]], include_iso_timestamp: bool
) -> List[Dict[str, Any]]:
    """Group raw history rows by itemid and convert each group to a series with points."""
    series_by_itemid: Dict[str, List[Dict[str, Any]]] = {}
    for row in raw_history:
        itemid = str(row.get("itemid", ""))
        if itemid not in series_by_itemid:
            series_by_itemid[itemid] = []
        series_by_itemid[itemid].append(history_row_to_point(row, include_iso_timestamp))

    return [
        {"itemid": itemid, "points": points, "count": len(points)}
        for itemid, points in series_by_itemid.items()
    ]
