#!/usr/bin/env python3
"""
Zabbix MCP Server - Complete integration with Zabbix API using python-zabbix-utils

This server provides comprehensive access to Zabbix API functionality through
the Model Context Protocol (MCP), enabling AI assistants and other tools to
interact with Zabbix monitoring systems.

Author: Zabbix MCP Server Contributors
License: MIT
"""

# -----------------------------------------------------------------------------
# FILE STRUCTURE
# -----------------------------------------------------------------------------
# 1. Package setup (when run as script)
# 2. Imports and configuration (logging, FastMCP, env)
# 3. Shared helpers (get_zabbix_client, format_response, validate_read_only)
# 4. Hosts, host interfaces & groups -> host_*, hostinterface_get, hostgroup_*
# 5. Items             -> item_*, discover_itemids_for_hosts
# 6. Triggers & templates -> trigger_*, template_*
# 7. Problems & events   -> problem_*, event_*
# 8. History, trends & timeseries -> history_get, trend_get, get_timeseries
# 9. Users, proxies, maintenance -> user_*, proxy_*, maintenance_*
# 10. Other (graphs, discovery rules, item prototypes, config, macros, system)
# 11. Entry point (main)
# 12. WLC tools (Wireless LAN Controller / active APs) -> get_active_wlc_hosts, get_host_item_errors, etc.
# -----------------------------------------------------------------------------

# When run as script (e.g. python src/zabbix_mcp_server.py), set up package for relative imports.
# TODO: align with a consistent pythonpath/package convention across repos.
if __package__ is None or __package__ == "":
    import sys
    from pathlib import Path
    _root = Path(__file__).resolve().parent.parent
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))
    __package__ = "src"

import os
import json
import logging
from typing import Any, Dict, List, Optional, Union
from fastmcp import FastMCP
from zabbix_utils import ZabbixAPI
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO if os.getenv("DEBUG") else logging.WARNING,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize FastMCP
mcp = FastMCP("Zabbix MCP Server")

# Global Zabbix API client
zabbix_api: Optional[ZabbixAPI] = None


def get_zabbix_client() -> ZabbixAPI:
    """Get or create Zabbix API client with proper authentication.
    
    Returns:
        ZabbixAPI: Authenticated Zabbix API client
        
    Raises:
        ValueError: If required environment variables are missing
        Exception: If authentication fails
    """
    global zabbix_api
    
    if zabbix_api is None:
        url = os.getenv("ZABBIX_URL")
        if not url:
            raise ValueError("ZABBIX_URL environment variable is required")
        
        logger.info(f"Initializing Zabbix API client for {url}")
        
        # Configure SSL verification
        verify_ssl = os.getenv("VERIFY_SSL", "true").lower() in ("true", "1", "yes")
        logger.info(f"SSL certificate verification: {'enabled' if verify_ssl else 'disabled'}")
        
        # Initialize client
        zabbix_api = ZabbixAPI(url=url, validate_certs=verify_ssl)

        # Authenticate using token or username/password
        token = os.getenv("ZABBIX_TOKEN")
        if token:
            logger.info("Authenticating with API token")
            zabbix_api.login(token=token)
        else:
            user = os.getenv("ZABBIX_USER")
            password = os.getenv("ZABBIX_PASSWORD")
            if not user or not password:
                raise ValueError("Either ZABBIX_TOKEN or ZABBIX_USER/ZABBIX_PASSWORD must be set")
            logger.info(f"Authenticating with username: {user}")
            zabbix_api.login(user=user, password=password)
        
        logger.info("Successfully authenticated with Zabbix API")
    
    return zabbix_api


def is_read_only() -> bool:
    """Check if server is in read-only mode.
    
    Returns:
        bool: True if read-only mode is enabled
    """
    return os.getenv("READ_ONLY", "true").lower() in ("true", "1", "yes")


def _to_json_serializable(obj: Any) -> Any:
    """Recursively convert data to JSON-serializable types.
    Avoids embedding Python repr (single quotes) from default=str for nested objects.
    """
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return str(obj)
    if isinstance(obj, dict):
        return {str(k): _to_json_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_json_serializable(v) for v in obj]
    if hasattr(obj, "isoformat"):  # datetime, date, time
        return obj.isoformat()
    return str(obj)


def format_response(data: Any) -> str:
    """Format response data as JSON string.
    
    Args:
        data: Data to format
        
    Returns:
        str: JSON formatted string
    """
    normalized = _to_json_serializable(data)
    return json.dumps(normalized, indent=2)


def validate_read_only() -> None:
    """Validate that write operations are allowed.
    
    Raises:
        ValueError: If server is in read-only mode
    """
    if is_read_only():
        raise ValueError("Server is in read-only mode - write operations are not allowed")


# HOST MANAGEMENT
@mcp.tool()
def host_get(hostids: Optional[List[str]] = None, 
             groupids: Optional[List[str]] = None,
             templateids: Optional[List[str]] = None,
             output: Union[str, List[str]] = "extend",
             search: Optional[Dict[str, str]] = None,
             filter: Optional[Dict[str, Any]] = None,
             limit: Optional[int] = None) -> str:
    """Get hosts from Zabbix with optional filtering.
    
    Args:
        hostids: List of host IDs to retrieve
        groupids: List of host group IDs to filter by
        templateids: List of template IDs to filter by
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of hosts
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if hostids:
        params["hostids"] = hostids
    if groupids:
        params["groupids"] = groupids
    if templateids:
        params["templateids"] = templateids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    if limit:
        params["limit"] = limit
    
    result = client.host.get(**params)
    return format_response(result)


@mcp.tool()
def host_create(host: str, groups: List[Dict[str, str]], 
                interfaces: List[Dict[str, Any]],
                templates: Optional[List[Dict[str, str]]] = None,
                inventory_mode: int = -1,
                status: int = 0) -> str:
    """Create a new host in Zabbix.
    
    Args:
        host: Host name
        groups: List of host groups (format: [{"groupid": "1"}])
        interfaces: List of host interfaces
        templates: List of templates to link (format: [{"templateid": "1"}])
        inventory_mode: Inventory mode (-1=disabled, 0=manual, 1=automatic)
        status: Host status (0=enabled, 1=disabled)
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "host": host,
        "groups": groups,
        "interfaces": interfaces,
        "inventory_mode": inventory_mode,
        "status": status
    }
    
    if templates:
        params["templates"] = templates
    
    result = client.host.create(**params)
    return format_response(result)


@mcp.tool()
def host_update(hostid: str, host: Optional[str] = None, 
                name: Optional[str] = None, status: Optional[int] = None) -> str:
    """Update an existing host in Zabbix.
    
    Args:
        hostid: Host ID to update
        host: New host name
        name: New visible name
        status: New status (0=enabled, 1=disabled)
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"hostid": hostid}
    
    if host:
        params["host"] = host
    if name:
        params["name"] = name
    if status is not None:
        params["status"] = status
    
    result = client.host.update(**params)
    return format_response(result)


@mcp.tool()
def host_delete(hostids: List[str]) -> str:
    """Delete hosts from Zabbix.
    
    Args:
        hostids: List of host IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.host.delete(*hostids)
    return format_response(result)


@mcp.tool()
def hostinterface_get(
    hostids: Optional[List[str]] = None,
    interfaceids: Optional[List[str]] = None,
    output: Union[str, List[str]] = "extend",
    search: Optional[Dict[str, str]] = None,
    filter: Optional[Dict[str, Any]] = None,
) -> str:
    """Get host interfaces from Zabbix (Zabbix API hostinterface.get).
    
    Args:
        hostids: List of host IDs to get interfaces for
        interfaceids: List of interface IDs to retrieve
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        
    Returns:
        str: JSON formatted list of host interfaces
    """
    client = get_zabbix_client()
    params: Dict[str, Any] = {"output": output}
    
    if hostids:
        params["hostids"] = hostids
    if interfaceids:
        params["interfaceids"] = interfaceids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    result = client.hostinterface.get(**params)
    return format_response(result)


# -----------------------------------------------------------------------------
# HOST GROUP MANAGEMENT
@mcp.tool()
def hostgroup_get(groupids: Optional[List[str]] = None,
                  output: Union[str, List[str]] = "extend",
                  search: Optional[Dict[str, str]] = None,
                  filter: Optional[Dict[str, Any]] = None) -> str:
    """Get host groups from Zabbix.
    
    Args:
        groupids: List of group IDs to retrieve
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        
    Returns:
        str: JSON formatted list of host groups
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if groupids:
        params["groupids"] = groupids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    result = client.hostgroup.get(**params)
    return format_response(result)


@mcp.tool()
def hostgroup_create(name: str) -> str:
    """Create a new host group in Zabbix.
    
    Args:
        name: Host group name
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.hostgroup.create(name=name)
    return format_response(result)


@mcp.tool()
def hostgroup_update(groupid: str, name: str) -> str:
    """Update an existing host group in Zabbix.
    
    Args:
        groupid: Group ID to update
        name: New group name
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.hostgroup.update(groupid=groupid, name=name)
    return format_response(result)


@mcp.tool()
def hostgroup_delete(groupids: List[str]) -> str:
    """Delete host groups from Zabbix.
    
    Args:
        groupids: List of group IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.hostgroup.delete(*groupids)
    return format_response(result)


# ITEM MANAGEMENT
@mcp.tool()
def item_get(itemids: Optional[List[str]] = None,
             hostids: Optional[List[str]] = None,
             groupids: Optional[List[str]] = None,
             templateids: Optional[List[str]] = None,
             output: Union[str, List[str]] = "extend",
             search: Optional[Dict[str, str]] = None,
             filter: Optional[Dict[str, Any]] = None,
             limit: Optional[int] = None) -> str:
    """Get items from Zabbix with optional filtering.
    
    Args:
        itemids: List of item IDs to retrieve
        hostids: List of host IDs to filter by
        groupids: List of host group IDs to filter by
        templateids: List of template IDs to filter by
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of items
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if itemids:
        params["itemids"] = itemids
    if hostids:
        params["hostids"] = hostids
    if groupids:
        params["groupids"] = groupids
    if templateids:
        params["templateids"] = templateids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    if limit:
        params["limit"] = limit
    
    result = client.item.get(**params)
    return format_response(result)


@mcp.tool()
def item_create(name: str, key_: str, hostid: str, type: int,
                value_type: int, delay: str = "1m",
                units: Optional[str] = None,
                description: Optional[str] = None) -> str:
    """Create a new item in Zabbix.
    
    Args:
        name: Item name
        key_: Item key
        hostid: Host ID
        type: Item type (0=Zabbix agent, 2=Zabbix trapper, etc.)
        value_type: Value type (0=float, 1=character, 3=unsigned int, 4=text)
        delay: Update interval
        units: Value units
        description: Item description
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "name": name,
        "key_": key_,
        "hostid": hostid,
        "type": type,
        "value_type": value_type,
        "delay": delay
    }
    
    if units:
        params["units"] = units
    if description:
        params["description"] = description
    
    result = client.item.create(**params)
    return format_response(result)


@mcp.tool()
def item_update(itemid: str, name: Optional[str] = None,
                key_: Optional[str] = None, delay: Optional[str] = None,
                status: Optional[int] = None) -> str:
    """Update an existing item in Zabbix.
    
    Args:
        itemid: Item ID to update
        name: New item name
        key_: New item key
        delay: New update interval
        status: New status (0=enabled, 1=disabled)
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"itemid": itemid}
    
    if name:
        params["name"] = name
    if key_:
        params["key_"] = key_
    if delay:
        params["delay"] = delay
    if status is not None:
        params["status"] = status
    
    result = client.item.update(**params)
    return format_response(result)


@mcp.tool()
def item_delete(itemids: List[str]) -> str:
    """Delete items from Zabbix.
    
    Args:
        itemids: List of item IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.item.delete(*itemids)
    return format_response(result)


# TRIGGER MANAGEMENT
@mcp.tool()
def trigger_get(triggerids: Optional[List[str]] = None,
                hostids: Optional[List[str]] = None,
                groupids: Optional[List[str]] = None,
                templateids: Optional[List[str]] = None,
                output: Union[str, List[str]] = "extend",
                search: Optional[Dict[str, str]] = None,
                filter: Optional[Dict[str, Any]] = None,
                limit: Optional[int] = None) -> str:
    """Get triggers from Zabbix with optional filtering.
    
    Args:
        triggerids: List of trigger IDs to retrieve
        hostids: List of host IDs to filter by
        groupids: List of host group IDs to filter by
        templateids: List of template IDs to filter by
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of triggers
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if triggerids:
        params["triggerids"] = triggerids
    if hostids:
        params["hostids"] = hostids
    if groupids:
        params["groupids"] = groupids
    if templateids:
        params["templateids"] = templateids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    if limit:
        params["limit"] = limit
    
    result = client.trigger.get(**params)
    return format_response(result)


@mcp.tool()
def trigger_create(description: str, expression: str,
                   priority: int = 0, status: int = 0,
                   comments: Optional[str] = None) -> str:
    """Create a new trigger in Zabbix.
    
    Args:
        description: Trigger description
        expression: Trigger expression
        priority: Severity (0=not classified, 1=info, 2=warning, 3=average, 4=high, 5=disaster)
        status: Status (0=enabled, 1=disabled)
        comments: Additional comments
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "description": description,
        "expression": expression,
        "priority": priority,
        "status": status
    }
    
    if comments:
        params["comments"] = comments
    
    result = client.trigger.create(**params)
    return format_response(result)


@mcp.tool()
def trigger_update(triggerid: str, description: Optional[str] = None,
                   expression: Optional[str] = None, priority: Optional[int] = None,
                   status: Optional[int] = None) -> str:
    """Update an existing trigger in Zabbix.
    
    Args:
        triggerid: Trigger ID to update
        description: New trigger description
        expression: New trigger expression
        priority: New severity level
        status: New status (0=enabled, 1=disabled)
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"triggerid": triggerid}
    
    if description:
        params["description"] = description
    if expression:
        params["expression"] = expression
    if priority is not None:
        params["priority"] = priority
    if status is not None:
        params["status"] = status
    
    result = client.trigger.update(**params)
    return format_response(result)


@mcp.tool()
def trigger_delete(triggerids: List[str]) -> str:
    """Delete triggers from Zabbix.
    
    Args:
        triggerids: List of trigger IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.trigger.delete(*triggerids)
    return format_response(result)


# TEMPLATE MANAGEMENT
@mcp.tool()
def template_get(templateids: Optional[List[str]] = None,
                 groupids: Optional[List[str]] = None,
                 hostids: Optional[List[str]] = None,
                 output: Union[str, List[str]] = "extend",
                 search: Optional[Dict[str, str]] = None,
                 filter: Optional[Dict[str, Any]] = None) -> str:
    """Get templates from Zabbix with optional filtering.
    
    Args:
        templateids: List of template IDs to retrieve
        groupids: List of host group IDs to filter by
        hostids: List of host IDs to filter by
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        
    Returns:
        str: JSON formatted list of templates
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if templateids:
        params["templateids"] = templateids
    if groupids:
        params["groupids"] = groupids
    if hostids:
        params["hostids"] = hostids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    result = client.template.get(**params)
    return format_response(result)


@mcp.tool()
def template_create(host: str, groups: List[Dict[str, str]],
                    name: Optional[str] = None, description: Optional[str] = None) -> str:
    """Create a new template in Zabbix.
    
    Args:
        host: Template technical name
        groups: List of host groups (format: [{"groupid": "1"}])
        name: Template visible name
        description: Template description
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "host": host,
        "groups": groups
    }
    
    if name:
        params["name"] = name
    if description:
        params["description"] = description
    
    result = client.template.create(**params)
    return format_response(result)


@mcp.tool()
def template_update(templateid: str, host: Optional[str] = None,
                    name: Optional[str] = None, description: Optional[str] = None) -> str:
    """Update an existing template in Zabbix.
    
    Args:
        templateid: Template ID to update
        host: New template technical name
        name: New template visible name
        description: New template description
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"templateid": templateid}
    
    if host:
        params["host"] = host
    if name:
        params["name"] = name
    if description:
        params["description"] = description
    
    result = client.template.update(**params)
    return format_response(result)


@mcp.tool()
def template_delete(templateids: List[str]) -> str:
    """Delete templates from Zabbix.
    
    Args:
        templateids: List of template IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.template.delete(*templateids)
    return format_response(result)


# PROBLEM MANAGEMENT
@mcp.tool()
def problem_get(eventids: Optional[List[str]] = None,
                groupids: Optional[List[str]] = None,
                hostids: Optional[List[str]] = None,
                objectids: Optional[List[str]] = None,
                output: Union[str, List[str]] = "extend",
                time_from: Optional[int] = None,
                time_till: Optional[int] = None,
                recent: bool = False,
                severities: Optional[List[int]] = None,
                limit: Optional[int] = None) -> str:
    """Get problems from Zabbix with optional filtering.
    
    Args:
        eventids: List of event IDs to retrieve
        groupids: List of host group IDs to filter by
        hostids: List of host IDs to filter by
        objectids: List of object IDs to filter by
        output: Output format (extend or list of specific fields)
        time_from: Start time (Unix timestamp)
        time_till: End time (Unix timestamp)
        recent: Only recent problems
        severities: List of severity levels to filter by
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of problems
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if eventids:
        params["eventids"] = eventids
    if groupids:
        params["groupids"] = groupids
    if hostids:
        params["hostids"] = hostids
    if objectids:
        params["objectids"] = objectids
    if time_from:
        params["time_from"] = time_from
    if time_till:
        params["time_till"] = time_till
    if recent:
        params["recent"] = recent
    if severities:
        params["severities"] = severities
    if limit:
        params["limit"] = limit
    
    result = client.problem.get(**params)
    return format_response(result)


# EVENT MANAGEMENT
@mcp.tool()
def event_get(eventids: Optional[List[str]] = None,
              groupids: Optional[List[str]] = None,
              hostids: Optional[List[str]] = None,
              objectids: Optional[List[str]] = None,
              output: Union[str, List[str]] = "extend",
              time_from: Optional[int] = None,
              time_till: Optional[int] = None,
              limit: Optional[int] = None) -> str:
    """Get events from Zabbix with optional filtering.
    
    Args:
        eventids: List of event IDs to retrieve
        groupids: List of host group IDs to filter by
        hostids: List of host IDs to filter by
        objectids: List of object IDs to filter by
        output: Output format (extend or list of specific fields)
        time_from: Start time (Unix timestamp)
        time_till: End time (Unix timestamp)
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of events
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if eventids:
        params["eventids"] = eventids
    if groupids:
        params["groupids"] = groupids
    if hostids:
        params["hostids"] = hostids
    if objectids:
        params["objectids"] = objectids
    if time_from:
        params["time_from"] = time_from
    if time_till:
        params["time_till"] = time_till
    if limit:
        params["limit"] = limit
    
    result = client.event.get(**params)
    return format_response(result)


@mcp.tool()
def event_acknowledge(eventids: List[str], action: int = 1,
                      message: Optional[str] = None) -> str:
    """Acknowledge events in Zabbix.
    
    Args:
        eventids: List of event IDs to acknowledge
        action: Acknowledge action (1=acknowledge, 2=close, etc.)
        message: Acknowledge message
        
    Returns:
        str: JSON formatted acknowledgment result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "eventids": eventids,
        "action": action
    }
    
    if message:
        params["message"] = message
    
    result = client.event.acknowledge(**params)
    return format_response(result)


# HISTORY MANAGEMENT
@mcp.tool()
def history_get(itemids: List[str], history: int = 0,
                time_from: Optional[int] = None,
                time_till: Optional[int] = None,
                limit: Optional[int] = None,
                sortfield: str = "clock",
                sortorder: str = "DESC") -> str:
    """Get history data from Zabbix.
    
    Args:
        itemids: List of item IDs to get history for
        history: History type (0=float, 1=character, 2=log, 3=unsigned, 4=text)
        time_from: Start time (Unix timestamp)
        time_till: End time (Unix timestamp)
        limit: Maximum number of results
        sortfield: Field to sort by
        sortorder: Sort order (ASC or DESC)
        
    Returns:
        str: JSON formatted history data
    """
    client = get_zabbix_client()
    params = {
        "itemids": itemids,
        "history": history,
        "sortfield": sortfield,
        "sortorder": sortorder
    }
    
    if time_from:
        params["time_from"] = time_from
    if time_till:
        params["time_till"] = time_till
    if limit:
        params["limit"] = limit
    
    result = client.history.get(**params)
    return format_response(result)


# TREND MANAGEMENT
@mcp.tool()
def trend_get(itemids: List[str], time_from: Optional[int] = None,
              time_till: Optional[int] = None,
              limit: Optional[int] = None) -> str:
    """Get trend data from Zabbix.
    
    Args:
        itemids: List of item IDs to get trends for
        time_from: Start time (Unix timestamp)
        time_till: End time (Unix timestamp)
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted trend data
    """
    client = get_zabbix_client()
    params = {"itemids": itemids}
    
    if time_from:
        params["time_from"] = time_from
    if time_till:
        params["time_till"] = time_till
    if limit:
        params["limit"] = limit
    
    result = client.trend.get(**params)
    return format_response(result)


# USER MANAGEMENT
@mcp.tool()
def user_get(userids: Optional[List[str]] = None,
             output: Union[str, List[str]] = "extend",
             search: Optional[Dict[str, str]] = None,
             filter: Optional[Dict[str, Any]] = None) -> str:
    """Get users from Zabbix with optional filtering.
    
    Args:
        userids: List of user IDs to retrieve
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        
    Returns:
        str: JSON formatted list of users
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if userids:
        params["userids"] = userids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    result = client.user.get(**params)
    return format_response(result)


@mcp.tool()
def user_create(username: str, passwd: str, usrgrps: List[Dict[str, str]],
                name: Optional[str] = None, surname: Optional[str] = None,
                email: Optional[str] = None) -> str:
    """Create a new user in Zabbix.
    
    Args:
        username: Username
        passwd: Password
        usrgrps: List of user groups (format: [{"usrgrpid": "1"}])
        name: First name
        surname: Last name
        email: Email address
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "username": username,
        "passwd": passwd,
        "usrgrps": usrgrps
    }
    
    if name:
        params["name"] = name
    if surname:
        params["surname"] = surname
    if email:
        params["email"] = email
    
    result = client.user.create(**params)
    return format_response(result)


@mcp.tool()
def user_update(userid: str, username: Optional[str] = None,
                name: Optional[str] = None, surname: Optional[str] = None,
                email: Optional[str] = None) -> str:
    """Update an existing user in Zabbix.
    
    Args:
        userid: User ID to update
        username: New username
        name: New first name
        surname: New last name
        email: New email address
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"userid": userid}
    
    if username:
        params["username"] = username
    if name:
        params["name"] = name
    if surname:
        params["surname"] = surname
    if email:
        params["email"] = email
    
    result = client.user.update(**params)
    return format_response(result)


@mcp.tool()
def user_delete(userids: List[str]) -> str:
    """Delete users from Zabbix.
    
    Args:
        userids: List of user IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.user.delete(*userids)
    return format_response(result)


# PROXY MANAGEMENT
@mcp.tool()
def proxy_get(proxyids: Optional[List[str]] = None,
              output: str = "extend",
              search: Optional[Dict[str, str]] = None,
              filter: Optional[Dict[str, Any]] = None,
              limit: Optional[int] = None) -> str:
    """Get proxies from Zabbix with optional filtering.
    
    Args:
        proxyids: List of proxy IDs to retrieve
        output: Output format (extend, shorten, or specific fields)
        search: Search criteria
        filter: Filter criteria
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of proxies
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if proxyids:
        params["proxyids"] = proxyids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    if limit:
        params["limit"] = limit
    
    result = client.proxy.get(**params)
    return format_response(result)


@mcp.tool()
def proxy_create(host: str, status: int = 5,
                 description: Optional[str] = None,
                 tls_connect: int = 1,
                 tls_accept: int = 1) -> str:
    """Create a new proxy in Zabbix.
    
    Args:
        host: Proxy name
        status: Proxy status (5=active proxy, 6=passive proxy)
        description: Proxy description
        tls_connect: TLS connection settings (1=no encryption, 2=PSK, 4=certificate)
        tls_accept: TLS accept settings (1=no encryption, 2=PSK, 4=certificate)
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "host": host,
        "status": status,
        "tls_connect": tls_connect,
        "tls_accept": tls_accept
    }
    
    if description:
        params["description"] = description
    
    result = client.proxy.create(**params)
    return format_response(result)


@mcp.tool()
def proxy_update(proxyid: str, host: Optional[str] = None,
                 status: Optional[int] = None,
                 description: Optional[str] = None,
                 tls_connect: Optional[int] = None,
                 tls_accept: Optional[int] = None) -> str:
    """Update an existing proxy in Zabbix.
    
    Args:
        proxyid: Proxy ID to update
        host: New proxy name
        status: New proxy status (5=active proxy, 6=passive proxy)
        description: New proxy description
        tls_connect: New TLS connection settings
        tls_accept: New TLS accept settings
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"proxyid": proxyid}
    
    if host:
        params["host"] = host
    if status is not None:
        params["status"] = status
    if description:
        params["description"] = description
    if tls_connect is not None:
        params["tls_connect"] = tls_connect
    if tls_accept is not None:
        params["tls_accept"] = tls_accept
    
    result = client.proxy.update(**params)
    return format_response(result)


@mcp.tool()
def proxy_delete(proxyids: List[str]) -> str:
    """Delete proxies from Zabbix.
    
    Args:
        proxyids: List of proxy IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.proxy.delete(*proxyids)
    return format_response(result)


# MAINTENANCE MANAGEMENT
@mcp.tool()
def maintenance_get(maintenanceids: Optional[List[str]] = None,
                    groupids: Optional[List[str]] = None,
                    hostids: Optional[List[str]] = None,
                    output: Union[str, List[str]] = "extend") -> str:
    """Get maintenance periods from Zabbix.
    
    Args:
        maintenanceids: List of maintenance IDs to retrieve
        groupids: List of host group IDs to filter by
        hostids: List of host IDs to filter by
        output: Output format (extend or list of specific fields)
        
    Returns:
        str: JSON formatted list of maintenance periods
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if maintenanceids:
        params["maintenanceids"] = maintenanceids
    if groupids:
        params["groupids"] = groupids
    if hostids:
        params["hostids"] = hostids
    
    result = client.maintenance.get(**params)
    return format_response(result)


@mcp.tool()
def maintenance_create(name: str, active_since: int, active_till: int,
                       groupids: Optional[List[str]] = None,
                       hostids: Optional[List[str]] = None,
                       timeperiods: Optional[List[Dict[str, Any]]] = None,
                       description: Optional[str] = None) -> str:
    """Create a new maintenance period in Zabbix.
    
    Args:
        name: Maintenance name
        active_since: Start time (Unix timestamp)
        active_till: End time (Unix timestamp)
        groupids: List of host group IDs
        hostids: List of host IDs
        timeperiods: List of time periods
        description: Maintenance description
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "name": name,
        "active_since": active_since,
        "active_till": active_till
    }
    
    if groupids:
        params["groupids"] = groupids
    if hostids:
        params["hostids"] = hostids
    if timeperiods:
        params["timeperiods"] = timeperiods
    if description:
        params["description"] = description
    
    result = client.maintenance.create(**params)
    return format_response(result)


@mcp.tool()
def maintenance_update(maintenanceid: str, name: Optional[str] = None,
                       active_since: Optional[int] = None, active_till: Optional[int] = None,
                       description: Optional[str] = None) -> str:
    """Update an existing maintenance period in Zabbix.
    
    Args:
        maintenanceid: Maintenance ID to update
        name: New maintenance name
        active_since: New start time (Unix timestamp)
        active_till: New end time (Unix timestamp)
        description: New maintenance description
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"maintenanceid": maintenanceid}
    
    if name:
        params["name"] = name
    if active_since:
        params["active_since"] = active_since
    if active_till:
        params["active_till"] = active_till
    if description:
        params["description"] = description
    
    result = client.maintenance.update(**params)
    return format_response(result)


@mcp.tool()
def maintenance_delete(maintenanceids: List[str]) -> str:
    """Delete maintenance periods from Zabbix.
    
    Args:
        maintenanceids: List of maintenance IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.maintenance.delete(*maintenanceids)
    return format_response(result)


# GRAPH MANAGEMENT
@mcp.tool()
def graph_get(graphids: Optional[List[str]] = None,
              hostids: Optional[List[str]] = None,
              templateids: Optional[List[str]] = None,
              output: Union[str, List[str]] = "extend",
              search: Optional[Dict[str, str]] = None,
              filter: Optional[Dict[str, Any]] = None) -> str:
    """Get graphs from Zabbix with optional filtering.
    
    Args:
        graphids: List of graph IDs to retrieve
        hostids: List of host IDs to filter by
        templateids: List of template IDs to filter by
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        
    Returns:
        str: JSON formatted list of graphs
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if graphids:
        params["graphids"] = graphids
    if hostids:
        params["hostids"] = hostids
    if templateids:
        params["templateids"] = templateids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    result = client.graph.get(**params)
    return format_response(result)


# DISCOVERY RULE MANAGEMENT
@mcp.tool()
def discoveryrule_get(itemids: Optional[List[str]] = None,
                      hostids: Optional[List[str]] = None,
                      templateids: Optional[List[str]] = None,
                      output: Union[str, List[str]] = "extend",
                      search: Optional[Dict[str, str]] = None,
                      filter: Optional[Dict[str, Any]] = None) -> str:
    """Get discovery rules from Zabbix with optional filtering.
    
    Args:
        itemids: List of discovery rule IDs to retrieve
        hostids: List of host IDs to filter by
        templateids: List of template IDs to filter by
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        
    Returns:
        str: JSON formatted list of discovery rules
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if itemids:
        params["itemids"] = itemids
    if hostids:
        params["hostids"] = hostids
    if templateids:
        params["templateids"] = templateids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    result = client.discoveryrule.get(**params)
    return format_response(result)


# ITEM PROTOTYPE MANAGEMENT
@mcp.tool()
def itemprototype_get(itemids: Optional[List[str]] = None,
                      discoveryids: Optional[List[str]] = None,
                      hostids: Optional[List[str]] = None,
                      output: Union[str, List[str]] = "extend",
                      search: Optional[Dict[str, str]] = None,
                      filter: Optional[Dict[str, Any]] = None) -> str:
    """Get item prototypes from Zabbix with optional filtering.
    
    Args:
        itemids: List of item prototype IDs to retrieve
        discoveryids: List of discovery rule IDs to filter by
        hostids: List of host IDs to filter by
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        
    Returns:
        str: JSON formatted list of item prototypes
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if itemids:
        params["itemids"] = itemids
    if discoveryids:
        params["discoveryids"] = discoveryids
    if hostids:
        params["hostids"] = hostids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    result = client.itemprototype.get(**params)
    return format_response(result)


# CONFIGURATION EXPORT/IMPORT
@mcp.tool()
def configuration_export(format: str = "json",
                         options: Optional[Dict[str, Any]] = None) -> str:
    """Export configuration from Zabbix.
    
    Args:
        format: Export format (json, xml)
        options: Export options
        
    Returns:
        str: JSON formatted export result
    """
    client = get_zabbix_client()
    params = {"format": format}
    
    if options:
        params["options"] = options
    
    result = client.configuration.export(**params)
    return format_response(result)


@mcp.tool()
def configuration_import(format: str, source: str,
                         rules: Dict[str, Any]) -> str:
    """Import configuration to Zabbix.
    
    Args:
        format: Import format (json, xml)
        source: Configuration data to import
        rules: Import rules
        
    Returns:
        str: JSON formatted import result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "format": format,
        "source": source,
        "rules": rules
    }
    
    result = client.configuration.import_(**params)
    return format_response(result)


# MACRO MANAGEMENT
@mcp.tool()
def usermacro_get(globalmacroids: Optional[List[str]] = None,
                  hostids: Optional[List[str]] = None,
                  output: Union[str, List[str]] = "extend",
                  search: Optional[Dict[str, str]] = None,
                  filter: Optional[Dict[str, Any]] = None) -> str:
    """Get global macros from Zabbix with optional filtering.
    
    Args:
        globalmacroids: List of global macro IDs to retrieve
        hostids: List of host IDs to filter by (for host macros)
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        
    Returns:
        str: JSON formatted list of global macros
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if globalmacroids:
        params["globalmacroids"] = globalmacroids
    if hostids:
        params["hostids"] = hostids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    result = client.usermacro.get(**params)
    return format_response(result)


# SYSTEM INFO
@mcp.tool()
def apiinfo_version() -> str:
    """Get Zabbix API version information.
    
    Returns:
        str: JSON formatted API version info
    """
    client = get_zabbix_client()
    result = client.apiinfo.version()
    return format_response(result)


def get_transport_config() -> Dict[str, Any]:
    """Get transport configuration from environment variables.
    
    Returns:
        Dict[str, Any]: Transport configuration
        
    Raises:
        ValueError: If invalid transport configuration
    """
    transport = os.getenv("ZABBIX_MCP_TRANSPORT", "stdio").lower()
    
    if transport not in ["stdio", "streamable-http"]:
        raise ValueError(f"Invalid ZABBIX_MCP_TRANSPORT: {transport}. Must be 'stdio' or 'streamable-http'")
    
    config = {"transport": transport}
    
    if transport == "streamable-http":
        # Check AUTH_TYPE requirement
        auth_type = os.getenv("AUTH_TYPE", "").lower()
        if auth_type != "no-auth":
            raise ValueError("AUTH_TYPE must be set to 'no-auth' when using streamable-http transport")
        
        # Get HTTP configuration with defaults
        config.update({
            "host": os.getenv("ZABBIX_MCP_HOST", "127.0.0.1"),
            "port": int(os.getenv("ZABBIX_MCP_PORT", "8000")),
            "stateless_http": os.getenv("ZABBIX_MCP_STATELESS_HTTP", "false").lower() in ("true", "1", "yes")
        })
        
        logger.info(f"HTTP transport configured: {config['host']}:{config['port']}, stateless_http={config['stateless_http']}")
    
    return config


def main():
    """Main entry point for uv execution."""
    logger.info("Starting Zabbix MCP Server")
    
    # Get transport configuration
    try:
        transport_config = get_transport_config()
        logger.info(f"Transport: {transport_config['transport']}")
    except ValueError as e:
        logger.error(f"Transport configuration error: {e}")
        return 1
    
    # Log configuration
    logger.info(f"Read-only mode: {is_read_only()}")
    logger.info(f"Zabbix URL: {os.getenv('ZABBIX_URL', 'Not configured')}")
    
    try:
        if transport_config["transport"] == "stdio":
            mcp.run()
        else:  # streamable-http
            mcp.run(
                transport="streamable-http",
                host=transport_config["host"],
                port=transport_config["port"],
                stateless_http=transport_config["stateless_http"]
            )
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise


# WLC tools (Wireless LAN Controller / active APs)
from . import helper  # noqa: E402
from .wlc_tools import (  # noqa: E402
    get_active_wlc_hosts as _get_active_wlc_hosts,
    get_active_ap_client_counts as _get_active_ap_client_counts,
    get_active_aps_for_host as _get_active_aps_for_host,
    get_client_counts_for_ap_hosts as _get_client_counts_for_ap_hosts,
    get_clients_per_ap as _get_clients_per_ap,
    get_host_item_errors as _get_host_item_errors,
)


@mcp.tool()
async def get_active_wlc_hosts(
    wlc_hostid: Optional[Union[str, int]] = None,
    groupids: Optional[str] = None,
    data_age_seconds: Optional[int] = None,
) -> str:
    """Get active WLC hosts (Wireless LAN Controllers) with recent item data.
    
    Args:
        wlc_hostid: Optional WLC host ID (str or int) to filter by a single host
        groupids: Optional comma-separated host group IDs to filter by
        data_age_seconds: Maximum age in seconds for item data (default from env ZABBIX_ACTIVE_HOSTS_DATA_AGE_SECONDS or 3600)
        
    Returns:
        str: JSON with hosts list and count (hostid, host, name per host)
    """
    result = await _get_active_wlc_hosts(
        wlc_hostid=helper.normalize_hostid(wlc_hostid), groupids=groupids, data_age_seconds=data_age_seconds
    )
    return format_response(result)


@mcp.tool()
async def get_host_item_errors(
    wlc_hostid: Optional[Union[str, int]] = None,
    host_name: Optional[str] = None,
) -> str:
    """Get Zabbix items that have errors for a WLC host.
    
    Args:
        wlc_hostid: WLC host ID (str or int). Use either wlc_hostid or host_name
        host_name: WLC host name (resolved to hostid). Use either wlc_hostid or host_name
        
    Returns:
        str: JSON with hostid, host, items_with_errors list (key_, name, state, error), count, total_items
    """
    result = await _get_host_item_errors(wlc_hostid=helper.normalize_hostid(wlc_hostid), host_name=host_name)
    return format_response(result)


@mcp.tool()
async def get_client_counts_for_ap_hosts(hostids: Optional[Union[List[str], str, int]] = None) -> str:
    """Get total client count per WLC host for given host IDs.
    
    Args:
        hostids: List of host IDs (e.g. ["10782", "10783"]), comma-separated string, or single id (str/int)
        
    Returns:
        str: JSON with counts dict (hostid -> total client count)
    """
    try:
        ids = helper.normalize_hostids(hostids)
        if not ids:
            return format_response({"error": "hostids required (list of host IDs)", "counts": {}})
        result = await _get_client_counts_for_ap_hosts(hostids=ids)
        return format_response(result)
    except Exception as e:
        return format_response({"error": str(e), "counts": {}})


@mcp.tool()
async def get_clients_per_ap(hostids: Optional[Union[List[str], str, int]] = None) -> str:
    """Get client count per AP for given WLC host IDs (Cisco and Aruba).
    
    Args:
        hostids: List of host IDs (e.g. ["10782", "10783"]), comma-separated string, or single id (str/int)
        
    Returns:
        str: JSON with by_host dict (hostid -> list of {ap, client_count}) and hostids list
    """
    try:
        ids = helper.normalize_hostids(hostids)
        if not ids:
            return format_response({"error": "hostids required (list of host IDs)", "by_host": {}, "hostids": []})
        result = await _get_clients_per_ap(hostids=ids)
        return format_response(result)
    except Exception as e:
        return format_response({"error": str(e), "by_host": {}, "hostids": []})


@mcp.tool()
async def get_active_aps_for_host(hostid: Optional[Union[str, int]] = None) -> str:
    """Get active APs for a single WLC host (Cisco and Aruba).
    
    Args:
        hostid: WLC host ID (str or int)
        
    Returns:
        str: JSON with hostid, vendor, active_aps list (mac, ap_name, ap_ip, etc.) and count
    """
    try:
        hid = helper.normalize_hostid(hostid)
        if not hid:
            return format_response({"error": "hostid required", "hostid": "", "active_aps": [], "count": 0})
        result = await _get_active_aps_for_host(hostid=hid)
        return format_response(result)
    except Exception as e:
        return format_response({"error": str(e), "hostid": "", "active_aps": [], "count": 0})


@mcp.tool()
async def get_active_ap_client_counts(
    wlc_hostid: Optional[Union[str, int]] = None,
    groupids: Optional[str] = None,
) -> str:
    """Get active APs with client counts for WLC hosts (all hosts or filtered).
    
    Args:
        wlc_hostid: Optional WLC host ID (str or int) to filter by a single host
        groupids: Optional comma-separated host group IDs to filter by
        
    Returns:
        str: JSON with active_aps list (mac, ap_host, ap_name, ap_ip, client_count) and count
    """
    result = await _get_active_ap_client_counts(
        wlc_hostid=helper.normalize_hostid(wlc_hostid), groupids=groupids
    )
    return format_response(result)


__all__ = ["main", "mcp"]


if __name__ == "__main__":
    main()
