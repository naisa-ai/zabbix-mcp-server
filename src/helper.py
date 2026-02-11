"""
WLC helpers: parsing, unwrap, constants for Zabbix host/item output.

No API or MCP calls; used by wlc_tools. Unit-testable.
"""

import json as _json
import os
import re
from typing import Any, Dict, List, Optional

# Set WLC_ACTIVE_HOSTS_DEBUG=1 (or true/yes) to log _fetch_active_wlc_hosts steps to stderr
_WLC_ACTIVE_HOSTS_DEBUG = os.environ.get("WLC_ACTIVE_HOSTS_DEBUG", "").strip().lower() in ("1", "true", "yes")


def oid_suffix_to_mac(index_suffix: str) -> str:
    """
    Convert SNMP index suffix (6 decimal octets) to canonical MAC xx:xx:xx:xx:xx:xx.

    The OID suffix is the full 6 octets of the MAC encoded as decimal, dot-separated.
    Example: "1.2.3.4.5.6" -> "01:02:03:04:05:06"
    """
    if not index_suffix or not index_suffix.strip():
        return ""
    parts = [p.strip() for p in index_suffix.strip().split(".")]
    try:
        octets = [int(p) for p in parts[-6:] if p]
    except ValueError:
        return ""
    if len(octets) < 6:
        octets = [0] * (6 - len(octets)) + octets
    else:
        octets = octets[-6:]
    return ":".join(f"{b:02x}" for b in octets)


def normalize_snmp_hex_mac(raw: str) -> str:
    """Normalize SNMP hex MAC to canonical form xx:xx:xx:xx:xx:xx (lowercase, 6 octets)."""
    if not raw or not isinstance(raw, str):
        return ""
    s = raw.strip()
    s = re.sub(r"[\s:.\-]", "", s)
    if not re.match(r"^[0-9a-fA-F]+$", s):
        return ""
    if len(s) != 12:
        return ""
    return ":".join(s[i : i + 2].lower() for i in range(0, 12, 2))


# --- Constants ---
ACTIVE_AP_STATUS = 1
ZABBIX_SERVER_HOST_NAME = "Zabbix server"
KEY_BSN_AP_OPERATION_STATUS = "bsnAPOperationStatus"
KEY_BSN_AP_NAME = "bsnAPName"
KEY_BSN_AP_IP = "bsnAPIP"
KEY_BSN_AP_IP_ADDRESS = "bsnApIpAddress"
KEY_BSN_AP_DOT3_MAC = "bsnAPDot3MacAddress"
KEY_CLIENT_COUNT = "bsnApIfNoOfUsers"
KEY_BSN_AP_IF_NO_OF_USERS_PREFIX = "bsnApIfNoOfUsers"
MAX_ITEMS_FETCH = 2000
MAX_ITEMS_WITH_ERRORS_RETURNED = 100
KEY_ARUBA_AP_STATUS = "ap.status"
KEY_ARUBA_RADIO_CONNECTED_CLIENTS = "radio.connectedClients"
KEY_ARUBA_AP_CLIENTS_SUM = "ap.clients.sum"
KEY_ARUBA_AP_NAME = "ap.name"
KEY_ARUBA_AP_IP = "ap.ip"

_CISCO_BSN_AP_OID_LINE = re.compile(r"\.6\.([\d.]+)\s*=\s*INTEGER:\s*(\d+)")


def _ensure_list(obj: Any) -> List[Any]:
    if obj is None:
        return []
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        return [obj]
    return []


def normalize_hostid(hostid: Any) -> Optional[str]:
    """Normalize a single host id to string. Accepts str or int. Returns None if empty/null."""
    if hostid is None:
        return None
    if isinstance(hostid, (int, float)):
        return str(int(hostid))
    s = str(hostid).strip()
    if not s or s.lower() == "null":
        return None
    return s


def normalize_hostids(hostids: Any) -> List[str]:
    """Normalize hostids to list of strings. Accepts list, comma-separated str, or single str/int."""
    if hostids is None:
        return []
    if isinstance(hostids, list):
        return [str(x).strip() for x in hostids if str(x).strip() and str(x).strip().lower() != "null"]
    if isinstance(hostids, (int, float)):
        return [str(int(hostids))]
    s = str(hostids).strip()
    if not s or s.lower() == "null":
        return []
    return [h.strip() for h in s.split(",") if h.strip() and h.strip().lower() != "null"]


def _index_from_key(key: str) -> str:
    if not key or "[" not in key or "]" not in key:
        return ""
    return key[key.index("[") + 1 : key.rindex("]")].strip('"')


def _looks_like_aruba_ap_name(index: str) -> bool:
    if not index or not index.strip():
        return False
    return bool(re.search(r"[A-Za-z]", index))


def _parse_aruba_ap_name_from_item_name(item_name: str) -> str:
    if not item_name or not isinstance(item_name, str):
        return ""
    m = re.search(r'AP\s*"\s*([^"]+)\s*"', item_name, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def parse_cisco_bsnAPOperationStatus_bulk(items_json: Any) -> List[Dict[str, Any]]:
    items = _ensure_list(items_json)
    out: List[Dict[str, Any]] = []
    for it in items:
        key = (it.get("key_") or it.get("key", "")) or ""
        if key.strip() != KEY_BSN_AP_OPERATION_STATUS:
            continue
        raw = it.get("lastvalue") or ""
        if not raw or not isinstance(raw, str):
            continue
        hostid = it.get("hostid")
        for line in raw.strip().split("\n"):
            line = line.strip()
            m = _CISCO_BSN_AP_OID_LINE.search(line)
            if m:
                index_suffix, lastvalue = m.group(1), m.group(2)
                out.append({"index_suffix": index_suffix, "lastvalue": lastvalue, "hostid": hostid})
    return out


def parse_wlc_bsnAPOperationStatus_lastvalue(items_json: Any) -> List[Dict[str, Any]]:
    items = _ensure_list(items_json)
    out = []
    for it in items:
        key = (it.get("key_") or it.get("key", "")) or ""
        if KEY_BSN_AP_OPERATION_STATUS not in key:
            continue
        if key.strip() == KEY_BSN_AP_OPERATION_STATUS:
            continue
        lastval = it.get("lastvalue")
        if lastval is None or lastval == "":
            continue
        index_suffix = _index_from_key(key)
        out.append({
            "index_suffix": index_suffix,
            "lastvalue": lastval,
            "hostid": it.get("hostid"),
            "key_": key,
            "name": it.get("name"),
            "itemid": it.get("itemid"),
        })
    return out


def build_ap_inventory_mac_to_host(
    hosts_json: Any,
    items_name_json: Any,
    items_ip_json: Any,
    mac_from_key_index: bool = True,
) -> Dict[str, Dict[str, str]]:
    hosts = _ensure_list(hosts_json)
    name_items = _ensure_list(items_name_json)
    ip_items = _ensure_list(items_ip_json)
    hostid_to_host = {h.get("hostid"): h.get("host") or h.get("name") or "" for h in hosts}
    by_key: Dict[tuple, Dict[str, str]] = {}
    for it in name_items:
        key = (it.get("key_") or it.get("key", "")) or ""
        if KEY_BSN_AP_NAME not in key and "bsnAPName" not in key:
            continue
        hostid = it.get("hostid")
        idx = _index_from_key(key)
        k = (hostid, idx)
        mac = oid_suffix_to_mac(idx) if mac_from_key_index else normalize_snmp_hex_mac((it.get("lastvalue") or "").strip())
        if not mac:
            continue
        by_key[k] = {
            "ap_host": hostid_to_host.get(hostid, ""),
            "ap_name": (it.get("lastvalue") or it.get("name") or "").strip(),
            "ap_ip": "",
            "_mac": mac,
        }
    for it in ip_items:
        key = (it.get("key_") or it.get("key", "")) or ""
        if KEY_BSN_AP_IP not in key and "bsnAPIP" not in key and "ap" not in key.lower():
            continue
        hostid = it.get("hostid")
        idx = _index_from_key(key)
        k = (hostid, idx)
        if k in by_key:
            by_key[k]["ap_ip"] = (it.get("lastvalue") or "").strip()
        else:
            mac = oid_suffix_to_mac(idx) if mac_from_key_index else normalize_snmp_hex_mac((it.get("lastvalue") or "").strip())
            if mac:
                by_key[k] = {
                    "ap_host": hostid_to_host.get(hostid, ""),
                    "ap_name": "",
                    "ap_ip": (it.get("lastvalue") or "").strip(),
                    "_mac": mac,
                }
    result: Dict[str, Dict[str, str]] = {}
    for v in by_key.values():
        mac = v.pop("_mac", None)
        if mac:
            result[mac] = {k: v for k, v in v.items() if k != "_mac"}
    return result


def build_cisco_ap_name_inventory(
    items_mac_json: Any,
    items_ip_json: Any,
    hostid_to_host: Optional[Dict[str, str]] = None,
) -> Dict[str, Dict[str, str]]:
    hostid_to_host = hostid_to_host or {}
    mac_items = _ensure_list(items_mac_json)
    ip_items = _ensure_list(items_ip_json)
    by_ap_name: Dict[tuple, Dict[str, str]] = {}
    for it in mac_items:
        key = (it.get("key_") or it.get("key", "")) or ""
        if KEY_BSN_AP_DOT3_MAC not in key and "bsnAPDot3MacAddress" not in key and "bsnAPEthernetMacAddress" not in key:
            continue
        ap_name = _index_from_key(key)
        if not ap_name:
            continue
        raw_mac = (it.get("lastvalue") or "").strip()
        mac = normalize_snmp_hex_mac(raw_mac)
        if not mac:
            continue
        hostid = it.get("hostid", "")
        by_ap_name[(hostid, ap_name)] = {
            "mac": mac,
            "ap_name": ap_name,
            "ap_ip": "",
            "ap_host": hostid_to_host.get(hostid, ""),
        }
    for it in ip_items:
        key = (it.get("key_") or it.get("key", "")) or ""
        if KEY_BSN_AP_IP_ADDRESS not in key and "bsnApIpAddress" not in key:
            continue
        ap_name = _index_from_key(key)
        if not ap_name:
            continue
        hostid = it.get("hostid", "")
        k = (hostid, ap_name)
        if k in by_ap_name:
            by_ap_name[k]["ap_ip"] = (it.get("lastvalue") or "").strip()
    result = {}
    for v in by_ap_name.values():
        mac = v.get("mac")
        if mac:
            result[mac] = {"ap_name": v.get("ap_name", ""), "ap_ip": v.get("ap_ip", ""), "ap_host": v.get("ap_host", "")}
    return result


def parse_cisco_client_count_by_ap_name(items_json: Any) -> Dict[tuple, int]:
    items = _ensure_list(items_json)
    by_ap: Dict[tuple, int] = {}
    for it in items:
        key = (it.get("key_") or it.get("key", "")) or ""
        if KEY_BSN_AP_IF_NO_OF_USERS_PREFIX not in key:
            continue
        ap_name = _index_from_key(key)
        if not ap_name:
            continue
        try:
            val = int(float(it.get("lastvalue") or 0))
        except (TypeError, ValueError):
            continue
        hostid = it.get("hostid", "")
        k = (hostid, ap_name)
        by_ap[k] = by_ap.get(k, 0) + val
    return by_ap


def parse_client_counts_for_hosts(items_json: Any) -> Dict[str, int]:
    items = _ensure_list(items_json)
    by_host: Dict[str, int] = {}
    patterns = ["bsnApIfNoOfUsers", "NoOfUsers", "client", "Client", "connectedClients"]
    for it in items:
        key = (it.get("key_") or it.get("key", "")) or ""
        if not any(p in key for p in patterns):
            continue
        try:
            val = int(float(it.get("lastvalue") or 0))
        except (TypeError, ValueError):
            continue
        hostid = it.get("hostid")
        if hostid:
            by_host[hostid] = by_host.get(hostid, 0) + val
    return by_host


def parse_aruba_ap_status(items_json: Any) -> List[Dict[str, Any]]:
    items = _ensure_list(items_json)
    out = []
    for it in items:
        key = (it.get("key_") or it.get("key", "")) or ""
        if KEY_ARUBA_AP_STATUS not in key:
            continue
        ap_index = _index_from_key(key)
        if not ap_index:
            continue
        out.append({"ap_index": ap_index, "lastvalue": (it.get("lastvalue") or "").strip(), "hostid": it.get("hostid")})
    return out


def parse_aruba_radio_connected_clients(items_json: Any) -> Dict[tuple, int]:
    items = _ensure_list(items_json)
    by_ap: Dict[tuple, int] = {}
    for it in items:
        key = (it.get("key_") or it.get("key", "")) or ""
        if KEY_ARUBA_RADIO_CONNECTED_CLIENTS not in key:
            continue
        full_index = _index_from_key(key)
        if not full_index:
            continue
        parts = full_index.rsplit(".", 1)
        ap_index = parts[0] if len(parts) == 2 and parts[1] in ("1", "2") else full_index
        try:
            val = int(float(it.get("lastvalue") or 0))
        except (TypeError, ValueError):
            continue
        hostid = it.get("hostid", "")
        k = (hostid, ap_index)
        by_ap[k] = by_ap.get(k, 0) + val
    return by_ap


def map_aruba_active_aps_to_client_counts(
    status_items: List[Dict[str, Any]],
    ap_index_to_client_count: Dict[tuple, int],
    active_status_values: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    active_status_values = active_status_values or ["1", "up"]
    out = []
    for it in status_items:
        status = (it.get("lastvalue") or "").strip().lower()
        if status not in [v.lower() for v in active_status_values]:
            continue
        ap_index = it.get("ap_index", "")
        hostid = it.get("hostid", "")
        count = ap_index_to_client_count.get((hostid, ap_index), 0)
        out.append({"ap_index": ap_index, "hostid": hostid, "ap_host": "", "ap_name": "", "ap_ip": "", "client_count": count})
    return out


def map_active_aps_to_client_counts(
    status_items: List[Dict[str, Any]],
    mac_to_ap: Dict[str, Dict[str, str]],
    host_client_counts: Dict[str, int],
    active_status_value: str = "1",
) -> List[Dict[str, Any]]:
    out = []
    for it in status_items:
        if str(it.get("lastvalue")) != active_status_value:
            continue
        idx = it.get("index_suffix", "")
        mac = oid_suffix_to_mac(idx)
        if not mac:
            continue
        ap_info = mac_to_ap.get(mac)
        if not ap_info:
            ap_info = {"ap_host": "", "ap_name": it.get("name", ""), "ap_ip": ""}
        hostid = it.get("hostid")
        client_count = host_client_counts.get(hostid, 0) if hostid else 0
        out.append({
            "mac": mac,
            "ap_host": ap_info.get("ap_host", ""),
            "ap_name": ap_info.get("ap_name", ""),
            "ap_ip": ap_info.get("ap_ip", ""),
            "client_count": client_count,
        })
    return out


def _unwrap_host_get_result(parsed: Any) -> List[Dict[str, Any]]:
    if isinstance(parsed, dict) and "result" in parsed:
        raw = parsed.get("result")
        if isinstance(raw, str):
            try:
                return _json.loads(raw)
            except _json.JSONDecodeError:
                pass
    return _ensure_list(parsed)


def _unwrap_host_get_to_list(parse_result: Any) -> List[Dict[str, Any]]:
    data = parse_result
    if data is not None and hasattr(data, "text"):
        raw = getattr(data, "text", None)
        if isinstance(raw, str):
            try:
                data = _json.loads(raw)
            except _json.JSONDecodeError:
                data = []
        elif isinstance(raw, (list, dict)):
            data = raw
    return _unwrap_host_get_result(data) if data is not None else _ensure_list(data)


def _unwrap_items_json(items_json: Any) -> List[Any]:
    items: List[Any] = []
    if isinstance(items_json, dict) and "result" in items_json:
        raw = items_json.get("result")
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, str):
            try:
                items = _json.loads(raw)
            except _json.JSONDecodeError:
                pass
    else:
        items = _ensure_list(items_json)
        if len(items) == 1 and isinstance(items[0], dict) and "result" in items[0]:
            raw = items[0].get("result")
            if isinstance(raw, list):
                items = raw
            elif isinstance(raw, str):
                try:
                    items = _json.loads(raw)
                except _json.JSONDecodeError:
                    pass
    return items


def get_hostids_with_item_errors(items_json: Any) -> set:
    items = _unwrap_items_json(items_json)
    out: set = set()
    for it in items:
        if not isinstance(it, dict):
            continue
        if (it.get("error") or "").strip():
            hid = it.get("hostid")
            if hid:
                out.add(str(hid))
    return out


def get_hostids_with_current_data(
    items_json: Any,
    max_age_seconds: Optional[int] = None,
    now_ts: Optional[float] = None,
) -> set:
    import time
    items = _unwrap_items_json(items_json)
    cutoff = None
    if max_age_seconds is not None:
        now_ts = now_ts if now_ts is not None else time.time()
        cutoff = now_ts - max_age_seconds
    out: set = set()
    for it in items:
        if not isinstance(it, dict):
            continue
        lastval = it.get("lastvalue")
        if lastval is None or str(lastval).strip() == "":
            continue
        if cutoff is not None:
            try:
                lastclock = int(float(it.get("lastclock") or 0))
            except (TypeError, ValueError):
                lastclock = 0
            if lastclock < cutoff:
                continue
        hid = it.get("hostid")
        if hid:
            out.add(str(hid))
    return out


def filter_items_with_errors(items_json: Any) -> List[Dict[str, Any]]:
    items = _unwrap_items_json(items_json)
    return [it for it in items if isinstance(it, dict) and (it.get("error") or "").strip()]


def filter_active_available_wlc_hosts(
    hosts_json: Any,
    exclude_name: Optional[str] = None,
    groupids: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    exclude_name = exclude_name or ZABBIX_SERVER_HOST_NAME
    hosts = _ensure_list(hosts_json)
    out: List[Dict[str, Any]] = []
    for h in hosts:
        name = (h.get("name") or h.get("host") or "").strip()
        if name == exclude_name:
            continue
        if groupids is not None and groupids:
            groups = h.get("hostgroups") or []
            group_ids = [g.get("groupid") for g in groups if g.get("groupid")]
            if not any(gid in groupids for gid in group_ids):
                continue
        out.append(h)
    return out


def _host_vendor(host: Dict[str, Any]) -> str:
    groups = host.get("hostgroups") or []
    names = [(g.get("name") or "").lower() for g in groups]
    if any("cisco" in n for n in names):
        return "cisco"
    if any("aruba" in n for n in names):
        return "aruba"
    return ""


def _unwrap_item_get_to_list(parse_result: Any) -> List[Any]:
    data = parse_result
    if data is not None and hasattr(data, "text"):
        raw = getattr(data, "text", None)
        if isinstance(raw, str):
            try:
                data = _json.loads(raw)
            except _json.JSONDecodeError:
                data = []
        elif isinstance(raw, (list, dict)):
            data = raw
    return _unwrap_items_json(data) if isinstance(data, (list, dict)) else _ensure_list(data)


def get_wlc_active_hosts_debug() -> bool:
    """Return whether WLC active hosts debug logging is enabled."""
    return _WLC_ACTIVE_HOSTS_DEBUG
