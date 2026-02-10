"""
WLC tools: async functions that call Zabbix API via get_zabbix_client().

Same pattern as zabbix_mcp_server.py (get_zabbix_client, client.host.get / client.item.get).
Registered as MCP tools in zabbix_mcp_server; also importable from here (e.g. WLC_AGENT_TOOLS).
"""

import os
import sys
from typing import Any, Dict, List, Optional

from . import helper


def _get_zabbix_client():
    """Lazy import to avoid circular import (zabbix_mcp_server imports this module)."""
    from .zabbix_mcp_server import get_zabbix_client
    return get_zabbix_client()


def _api_result_to_list(raw: Any) -> List[Any]:
    """Normalize Zabbix API response to list of dicts (same pattern as server)."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    if isinstance(raw, dict) and "result" in raw:
        r = raw["result"]
        if isinstance(r, list):
            return [x for x in r if isinstance(x, dict)]
        if isinstance(r, dict):
            return [r]
    return []


def _debug(msg: str) -> None:
    if helper.get_wlc_active_hosts_debug():
        print(f"[_fetch_active_wlc_hosts] {msg}", file=sys.stderr)


def _norm_opt_str(v: Any) -> Optional[str]:
    if v is None or v == "":
        return None
    s = str(v).strip()
    return None if s.lower() == "null" else (s or None)


def _norm_opt_int(v: Any, default: int) -> int:
    if v is None:
        return default
    if isinstance(v, int):
        return v
    s = str(v).strip().lower()
    if s == "null" or s == "":
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _items_to_dict_list(raw: Any) -> List[Dict[str, Any]]:
    lst = _api_result_to_list(raw)
    return [x for x in (lst or []) if isinstance(x, dict)]


async def _fetch_active_wlc_hosts(
    wlc_hostid: Optional[str] = None,
    groupids: Optional[List[str]] = None,
    data_age_seconds: int = 3600,
) -> tuple:
    try:
        client = _get_zabbix_client()
    except Exception as e:
        _debug(f"get_zabbix_client failed: {e}")
        return ([], {})
    params_host = {"output": "extend", "filter": {"status": 0}}
    if wlc_hostid:
        params_host["hostids"] = [wlc_hostid]
    if groupids:
        params_host["groupids"] = groupids
    _debug(f"params_host: {params_host}")
    hosts_raw = client.host.get(**params_host)
    hosts = _api_result_to_list(hosts_raw)
    hosts = helper.filter_active_available_wlc_hosts(hosts)
    _debug(f"after filter_active_available_wlc_hosts: len={len(hosts)}")
    if not hosts:
        _debug("early return: no hosts after filter")
        return ([], {})
    hostids = [h.get("hostid") for h in hosts if h.get("hostid")]
    params_items = {"hostids": hostids, "output": "extend", "limit": helper.MAX_ITEMS_FETCH}
    items_raw = client.item.get(**params_items)
    items_data = items_raw
    hostids_with_data = helper.get_hostids_with_current_data(items_data, max_age_seconds=data_age_seconds)
    _debug(f"hostids_with_data: len={len(hostids_with_data)}")
    hosts = [h for h in hosts if str(h.get("hostid", "")) in hostids_with_data]
    _debug(f"after filter by hostids_with_data: len(hosts)={len(hosts)}")
    hostid_to_host = {h.get("hostid"): h.get("host") or h.get("name") or "" for h in hosts}
    return (hosts, hostid_to_host)


async def get_active_wlc_hosts(
    wlc_hostid: Optional[str] = None,
    groupids: Optional[str] = None,
    data_age_seconds: Optional[int] = None,
) -> dict:
    try:
        _get_zabbix_client()
    except Exception as e:
        return {"error": str(e), "hosts": [], "count": 0}
    try:
        hid = _norm_opt_str(wlc_hostid)
        gids_raw = _norm_opt_str(groupids)
        gids = [g.strip() for g in gids_raw.split(",") if g.strip()] if gids_raw else None
        age = _norm_opt_int(data_age_seconds, int(os.environ.get("ZABBIX_ACTIVE_HOSTS_DATA_AGE_SECONDS", "3600")))
        hosts, _ = await _fetch_active_wlc_hosts(wlc_hostid=hid, groupids=gids, data_age_seconds=age)
        out = [{"hostid": h.get("hostid"), "host": h.get("host"), "name": h.get("name")} for h in hosts]
        return {"hosts": out, "count": len(out)}
    except Exception as e:
        return {"error": str(e), "hosts": [], "count": 0}


async def get_host_item_errors(
    wlc_hostid: Optional[str] = None,
    host_name: Optional[str] = None,
) -> dict:
    try:
        client = _get_zabbix_client()
    except Exception as e:
        return {"error": str(e), "items_with_errors": [], "count": 0, "total_items": 0}
    try:
        hid_norm = _norm_opt_str(wlc_hostid)
        name_norm = _norm_opt_str(host_name)
        hostid = hid_norm
        host_display = (hid_norm or name_norm) or ""
        if not hostid and name_norm:
            hosts_raw = client.host.get(output="extend", filter={"host": name_norm})
            hosts = _api_result_to_list(hosts_raw)
            if not hosts:
                hosts_raw = client.host.get(output="extend", filter={"name": name_norm})
                hosts = _api_result_to_list(hosts_raw)
            if not hosts:
                return {"error": f"No host found for name {name_norm!r}", "items_with_errors": [], "count": 0, "total_items": 0}
            hostid = hosts[0].get("hostid")
            host_display = hosts[0].get("host") or hosts[0].get("name") or hostid
        if not hostid:
            return {"error": "Pass wlc_hostid or host_name", "items_with_errors": [], "count": 0, "total_items": 0}
        params_item = {"hostids": [hostid], "output": "extend", "limit": helper.MAX_ITEMS_FETCH}
        items_raw = client.item.get(**params_item)
        items_data = items_raw
        items_all = _api_result_to_list(items_data)
        with_errors = helper.filter_items_with_errors(items_data)
        out = [
            {"key_": it.get("key_") or it.get("key", ""), "name": (it.get("name") or "")[:80], "state": it.get("state", ""), "error": (it.get("error") or "").strip()}
            for it in with_errors[: helper.MAX_ITEMS_WITH_ERRORS_RETURNED]
        ]
        total_with_errors = len(with_errors)
        return {
            "hostid": hostid,
            "host": host_display,
            "name": host_display,
            "items_with_errors": out,
            "count": total_with_errors,
            "total_items": len(items_all),
            "truncated": total_with_errors > helper.MAX_ITEMS_WITH_ERRORS_RETURNED,
            "truncated_note": f"(showing first {helper.MAX_ITEMS_WITH_ERRORS_RETURNED} of {total_with_errors} items with errors)" if total_with_errors > helper.MAX_ITEMS_WITH_ERRORS_RETURNED else None,
        }
    except Exception as e:
        return {"error": str(e), "items_with_errors": [], "count": 0, "total_items": 0}


async def get_wlc_bsnAPOperationStatus_lastvalue(
    wlc_hostid: Optional[str] = None,
    groupids: Optional[str] = None,
) -> dict:
    try:
        _get_zabbix_client()
    except Exception as e:
        return {"error": str(e), "items": []}
    try:
        hid = _norm_opt_str(wlc_hostid)
        gids_raw = _norm_opt_str(groupids)
        gids = [g.strip() for g in gids_raw.split(",") if g.strip()] if gids_raw else None
        hosts, _ = await _fetch_active_wlc_hosts(wlc_hostid=hid, groupids=gids)
        if not hosts:
            return {"items": [], "count": 0}
        hostids = [h.get("hostid") for h in hosts if h.get("hostid")]
        client = _get_zabbix_client()
        params = {"output": ["itemid", "hostid", "name", "key_", "lastvalue", "lastclock"], "search": {"key_": helper.KEY_BSN_AP_OPERATION_STATUS}, "hostids": hostids}
        data = client.item.get(**params)
        items = helper.parse_wlc_bsnAPOperationStatus_lastvalue(data)
        return {"items": items, "count": len(items)}
    except Exception as e:
        return {"error": str(e), "items": []}


async def get_ap_mac_inventory(
    wlc_hostid: Optional[str] = None,
    groupids: Optional[str] = None,
) -> dict:
    try:
        _get_zabbix_client()
    except Exception as e:
        return {"error": "Zabbix API not available", "inventory": {}}
    try:
        hid = _norm_opt_str(wlc_hostid)
        gids_raw = _norm_opt_str(groupids)
        gids = [g.strip() for g in gids_raw.split(",") if g.strip()] if gids_raw else None
        hosts, _ = await _fetch_active_wlc_hosts(wlc_hostid=hid, groupids=gids)
        if not hosts:
            return {"inventory": {}, "count": 0}
        hostids = [h.get("hostid") for h in hosts if h.get("hostid")]
        client = _get_zabbix_client()
        name_result = client.item.get(output=["itemid", "hostid", "name", "key_", "lastvalue"], search={"key_": "bsnAPName"}, hostids=hostids)
        ip_result = client.item.get(output=["itemid", "hostid", "name", "key_", "lastvalue"], search={"key_": "bsnAPIP"}, hostids=hostids)
        name_items = name_result
        ip_items = ip_result
        inventory = helper.build_ap_inventory_mac_to_host(hosts, name_items, ip_items, mac_from_key_index=True)
        return {"inventory": inventory, "count": len(inventory)}
    except Exception as e:
        return {"error": str(e), "inventory": {}}


async def get_client_counts_for_ap_hosts(hostids: str) -> dict:
    try:
        client = _get_zabbix_client()
    except Exception as e:
        return {"error": "Zabbix API not available", "counts": {}}
    hostids_norm = _norm_opt_str(hostids)
    if not hostids_norm:
        return {"error": "hostids required (comma-separated)", "counts": {}}
    ids = [h.strip() for h in hostids_norm.split(",") if h.strip()]
    ids = [i for i in ids if i.lower() != "null"]
    if not ids:
        return {"error": "hostids required (comma-separated)", "counts": {}}
    params = {"hostids": ids, "output": ["itemid", "hostid", "key_", "lastvalue"], "search": {"key_": "bsnApIfNoOfUsers"}}
    try:
        data = client.item.get(**params)
        counts = helper.parse_client_counts_for_hosts(data)
        return {"counts": counts}
    except Exception as e:
        return {"error": str(e), "counts": {}}


async def _get_clients_per_ap_impl(ids: List[str]) -> dict:
    by_host: Dict[str, List[Dict[str, Any]]] = {hid: [] for hid in ids}
    try:
        client = _get_zabbix_client()
    except Exception as e:
        return {"error": "Zabbix API not available", "by_host": by_host, "hostids": ids}
    try:
        params_cisco = {"hostids": ids, "output": "extend", "search": {"key_": helper.KEY_BSN_AP_IF_NO_OF_USERS_PREFIX}}
        cisco_result = client.item.get(**params_cisco)
        cisco_data = _items_to_dict_list(cisco_result)
        cisco_by_ap = helper.parse_cisco_client_count_by_ap_name(cisco_data)
        params_aruba = {"hostids": ids, "output": "extend", "search": {"key_": helper.KEY_ARUBA_RADIO_CONNECTED_CLIENTS}}
        aruba_result = client.item.get(**params_aruba)
        aruba_data = _items_to_dict_list(aruba_result)
        aruba_by_ap = helper.parse_aruba_radio_connected_clients(aruba_data)
        for (hostid, ap_key), count in cisco_by_ap.items():
            if hostid in by_host:
                by_host[hostid].append({"ap": ap_key, "client_count": count})
        for (hostid, ap_key), count in aruba_by_ap.items():
            if hostid in by_host:
                by_host[hostid].append({"ap": ap_key, "client_count": count})
        return {"by_host": by_host, "hostids": ids}
    except Exception as e:
        return {"error": str(e), "by_host": by_host, "hostids": ids}


async def get_clients_per_ap(hostids: str) -> dict:
    if isinstance(hostids, list):
        ids = [str(x).strip() for x in hostids if str(x).strip()]
    else:
        hostids_norm = _norm_opt_str(hostids)
        if not hostids_norm:
            return {"error": "hostids required (comma-separated)", "by_host": {}, "hostids": []}
        ids = [h.strip() for h in hostids_norm.split(",") if h.strip()]
    ids = [i for i in ids if (i or "").lower() != "null"]
    if not ids:
        return {"error": "hostids required (comma-separated)", "by_host": {}, "hostids": []}
    return await _get_clients_per_ap_impl(ids)


async def _get_active_aps_for_host_impl(hid: str) -> dict:
    try:
        client = _get_zabbix_client()
    except Exception as e:
        return {"error": "Zabbix API not available", "hostid": hid, "active_aps": [], "count": 0}
    try:
        params_host = {"output": "extend", "hostids": [hid], "filter": {"status": 0}}
        hosts_raw = client.host.get(**params_host)
        hosts = _api_result_to_list(hosts_raw)
        hosts = [h for h in helper._ensure_list(hosts) if isinstance(h, dict)]
        host = hosts[0] if hosts else {}
        vendor = helper._host_vendor(host)
        params_cisco = {"hostids": [hid], "output": "extend", "search": {"key_": helper.KEY_BSN_AP_OPERATION_STATUS}}
        status_result = client.item.get(**params_cisco)
        status_data = _items_to_dict_list(status_result)
        bulk_status = helper.parse_cisco_bsnAPOperationStatus_bulk(status_data)
        status_items = helper.parse_wlc_bsnAPOperationStatus_lastvalue(status_data) if not bulk_status else []
        active_aps: List[Dict[str, Any]] = []
        if bulk_status or status_items:
            vendor = vendor or "cisco"
            hostid_to_host = {hid: host.get("host") or host.get("name") or ""}
            if bulk_status:
                for it in bulk_status:
                    if str(it.get("lastvalue")) != "1":
                        continue
                    idx = it.get("index_suffix", "")
                    mac = helper.oid_suffix_to_mac(idx)
                    active_aps.append({"index_suffix": idx, "mac": mac or "", "ap_name": "", "ap_ip": ""})
            else:
                for it in status_items:
                    if str(it.get("lastvalue")) != "1":
                        continue
                    idx = it.get("index_suffix", "")
                    mac = helper.oid_suffix_to_mac(idx)
                    active_aps.append({"index_suffix": idx, "mac": mac or "", "ap_name": "", "ap_ip": ""})
            if active_aps:
                mac_result = client.item.get(hostids=[hid], output="extend", search={"key_": "bsnAPDot3MacAddress"})
                ip_result = client.item.get(hostids=[hid], output="extend", search={"key_": "bsnApIpAddress"})
                mac_items = _items_to_dict_list(mac_result)
                ip_items = _items_to_dict_list(ip_result)
                mac_to_ap = helper.build_cisco_ap_name_inventory(mac_items, ip_items, hostid_to_host)
                for entry in active_aps:
                    info = mac_to_ap.get(entry.get("mac") or "")
                    if info:
                        entry["ap_name"] = info.get("ap_name", "")
                        entry["ap_ip"] = info.get("ap_ip", "")
        if not active_aps or vendor == "aruba":
            params_aruba = {"hostids": [hid], "output": "extend", "search": {"key_": helper.KEY_ARUBA_AP_STATUS}}
            aruba_result = client.item.get(**params_aruba)
            ap_status_data = _items_to_dict_list(aruba_result)
            ap_status_items = helper.parse_aruba_ap_status(ap_status_data)
            aruba_active = []
            for it in ap_status_items:
                if (it.get("lastvalue") or "").strip().lower() not in ("1", "up"):
                    continue
                ap_index = it.get("ap_index", "")
                ap_name = ap_index if helper._looks_like_aruba_ap_name(ap_index) else ""
                aruba_active.append({"ap_index": ap_index, "ap_name": ap_name, "ap_ip": ""})
            if aruba_active:
                vendor = "aruba"
                active_aps = aruba_active
                if any(not e.get("ap_name") for e in active_aps):
                    ap_index_to_name = {}
                    radio_result = client.item.get(hostids=[hid], output="extend", search={"key_": helper.KEY_ARUBA_RADIO_CONNECTED_CLIENTS})
                    radio_items = _items_to_dict_list(radio_result)
                    for it in radio_items:
                        key = (it.get("key_") or it.get("key", "")) or ""
                        if helper.KEY_ARUBA_RADIO_CONNECTED_CLIENTS not in key:
                            continue
                        full_index = helper._index_from_key(key)
                        if not full_index:
                            continue
                        parts = full_index.rsplit(".", 1)
                        ap_index = parts[0] if len(parts) == 2 and parts[1] in ("1", "2") else full_index
                        ap_name = helper._parse_aruba_ap_name_from_item_name(it.get("name") or "")
                        if ap_name and ap_index not in ap_index_to_name:
                            ap_index_to_name[ap_index] = ap_name
                    if not ap_index_to_name:
                        for key_pattern in (helper.KEY_ARUBA_AP_NAME, "ap.hostname"):
                            name_result = client.item.get(hostids=[hid], output="extend", search={"key_": key_pattern})
                            name_items = _items_to_dict_list(name_result)
                            for it in name_items:
                                key = (it.get("key_") or it.get("key", "")) or ""
                                if key_pattern not in key:
                                    continue
                                ap_index = helper._index_from_key(key)
                                if not ap_index:
                                    continue
                                ap_name = (it.get("lastvalue") or "").strip()
                                if ap_name and ap_index not in ap_index_to_name:
                                    ap_index_to_name[ap_index] = ap_name
                            if ap_index_to_name:
                                break
                    for entry in active_aps:
                        if not entry.get("ap_name"):
                            entry["ap_name"] = ap_index_to_name.get(entry.get("ap_index", ""), "")
        return {"hostid": hid, "vendor": vendor or "", "active_aps": active_aps, "count": len(active_aps)}
    except Exception as e:
        return {"error": str(e), "hostid": hid, "active_aps": [], "count": 0}


async def get_active_aps_for_host(hostid: str) -> dict:
    hid = _norm_opt_str(hostid) or ""
    if not hid:
        return {"error": "hostid required", "hostid": "", "active_aps": [], "count": 0}
    return await _get_active_aps_for_host_impl(hid)


async def get_active_ap_client_counts(
    wlc_hostid: Optional[str] = None,
    groupids: Optional[str] = None,
) -> dict:
    try:
        _get_zabbix_client()
    except Exception as e:
        return {"error": "Zabbix API not available", "active_aps": [], "count": 0}
    try:
        hid = _norm_opt_str(wlc_hostid)
        gids_raw = _norm_opt_str(groupids)
        gids = [g.strip() for g in gids_raw.split(",") if g.strip()] if gids_raw else None
        hosts, hostid_to_host = await _fetch_active_wlc_hosts(wlc_hostid=hid, groupids=gids)
        if not hosts:
            return {"active_aps": [], "count": 0}
        hostids = [h.get("hostid") for h in hosts if h.get("hostid")]
        if not hostids:
            return {"active_aps": [], "count": 0}
        clients_result = await _get_clients_per_ap_impl(hostids)
        if clients_result.get("error"):
            return {"error": clients_result["error"], "active_aps": [], "count": 0}
        by_host_clients = clients_result.get("by_host", {})
        active_aps = []
        for hid in hostids:
            aps_result = await _get_active_aps_for_host_impl(hid)
            if aps_result.get("error"):
                continue
            vendor = aps_result.get("vendor", "")
            aps_list = aps_result.get("active_aps", [])
            host_entries = by_host_clients.get(hid, [])
            for ap in aps_list:
                key = ap.get("ap_name", "") if vendor == "cisco" else ap.get("ap_index", "")
                client_count = next((e["client_count"] for e in host_entries if e.get("ap") == key), 0)
                active_aps.append({
                    "mac": ap.get("mac", "") if vendor == "cisco" else "",
                    "ap_host": hostid_to_host.get(hid, ""),
                    "ap_name": ap.get("ap_name", ""),
                    "ap_ip": ap.get("ap_ip", ""),
                    "client_count": client_count,
                })
        return {"active_aps": active_aps, "count": len(active_aps)}
    except Exception as e:
        return {"error": str(e), "active_aps": [], "count": 0}


WLC_AGENT_TOOLS = [
    get_active_wlc_hosts,
    get_host_item_errors,
    get_wlc_bsnAPOperationStatus_lastvalue,
    get_ap_mac_inventory,
    get_client_counts_for_ap_hosts,
    get_clients_per_ap,
    get_active_aps_for_host,
    get_active_ap_client_counts,
]
