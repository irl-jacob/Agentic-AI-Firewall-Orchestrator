"""
AFO FastMCP Server
Exposes all AFO operations as MCP tools for the Bun TUI
"""

import asyncio
import json
import os
from typing import Any

from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from backend.models import Action, Direction, PolicyRule, Protocol
from backend.nftables import NftablesBackend
from backend.safety import SafetyEnforcer
from db.database import get_session, init_db
from services.bulk_operations import get_bulk_operations
from services.config_manager import get_config_manager
from services.domain_blocker import get_domain_blocker
from services.firewall import FirewallService
from services.geoip import get_geoip_service
from services.multi_firewall import MultiFirewallManager

load_dotenv()

# Global state
app_state = {
    "backend": None,
    "session": None,
    "firewall_service": None,
    "config_manager": None,
    "geoip_service": None,
    "domain_blocker": None,
    "bulk_operations": None,
    "safety_enforcer": None,
    "multi_manager": None,
}


async def initialize_backend():
    """Initialize the AFO backend and services."""
    # Initialize database
    await init_db()

    # Get database session
    session_gen = get_session()
    session = await anext(session_gen)
    app_state["session"] = session

    # Initialize multi-firewall manager
    multi_manager = MultiFirewallManager(session)
    app_state["multi_manager"] = multi_manager

    # Configure backend
    backend_type = os.environ.get("AFO_BACKEND", "nftables").lower()
    force_dry_run = os.environ.get("AFO_DRY_RUN", "0") == "1"

    if backend_type == "opnsense":
        from backend.opnsense import OPNsenseMCPBackend

        backend = OPNsenseMCPBackend(dry_run=force_dry_run)
        try:
            await backend.connect()
            multi_manager.add_backend(
                "opnsense-primary",
                backend,
                description="Primary OPNsense Firewall",
                enabled=True,
            )
        except Exception as e:
            print(f"Warning: Could not connect to OPNsense: {e}")
            backend = NftablesBackend(dry_run=True)
            multi_manager.add_backend(
                "nftables-fallback",
                backend,
                description="Local NFTables (Fallback)",
                enabled=True,
            )
    else:
        backend = NftablesBackend(dry_run=force_dry_run)
        multi_manager.add_backend(
            "nftables-local",
            backend,
            description="Local nftables Firewall",
            enabled=True,
        )

    app_state["backend"] = backend

    # Initialize services
    safety_enforcer = SafetyEnforcer()
    app_state["safety_enforcer"] = safety_enforcer

    firewall_service = FirewallService(backend, session)
    app_state["firewall_service"] = firewall_service

    config_manager = get_config_manager(backend, session, safety_enforcer)
    app_state["config_manager"] = config_manager

    geoip_service = get_geoip_service(backend, session)
    app_state["geoip_service"] = geoip_service

    domain_blocker = get_domain_blocker(backend)
    app_state["domain_blocker"] = domain_blocker

    bulk_operations = get_bulk_operations(backend)
    app_state["bulk_operations"] = bulk_operations

    return backend


# Create MCP server
server = Server("afo-mcp-server")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List all available AFO tools."""
    return [
        # Rule Management
        Tool(
            name="list_rules",
            description="List all active firewall rules",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="deploy_rule",
            description="Deploy a new firewall rule",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Rule name"},
                    "action": {
                        "type": "string",
                        "enum": ["ACCEPT", "DROP", "REJECT"],
                        "description": "Action to take",
                    },
                    "direction": {
                        "type": "string",
                        "enum": ["INBOUND", "OUTBOUND", "FORWARD"],
                        "description": "Traffic direction",
                    },
                    "protocol": {
                        "type": "string",
                        "enum": ["TCP", "UDP", "ICMP", "ANY"],
                        "description": "Protocol",
                    },
                    "port": {"type": "integer", "description": "Port number (optional)"},
                    "source": {"type": "string", "description": "Source IP/CIDR (optional)"},
                    "destination": {"type": "string", "description": "Destination IP/CIDR (optional)"},
                    "description": {"type": "string", "description": "Rule description"},
                },
                "required": ["name", "action", "direction", "protocol", "description"],
            },
        ),
        Tool(
            name="delete_rule",
            description="Delete a firewall rule by ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "Rule ID to delete"},
                },
                "required": ["rule_id"],
            },
        ),
        # Preset Configuration
        Tool(
            name="list_presets",
            description="List all available configuration presets",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="preview_preset",
            description="Preview changes that would be made by applying a preset",
            inputSchema={
                "type": "object",
                "properties": {
                    "preset_name": {"type": "string", "description": "Name of the preset"},
                },
                "required": ["preset_name"],
            },
        ),
        Tool(
            name="apply_preset",
            description="Apply a configuration preset",
            inputSchema={
                "type": "object",
                "properties": {
                    "preset_name": {"type": "string", "description": "Name of the preset"},
                    "user": {"type": "string", "description": "User applying the preset", "default": "admin"},
                },
                "required": ["preset_name"],
            },
        ),
        Tool(
            name="remove_preset",
            description="Remove the active configuration preset",
            inputSchema={
                "type": "object",
                "properties": {
                    "user": {"type": "string", "description": "User removing the preset", "default": "admin"},
                },
            },
        ),
        Tool(
            name="get_active_preset",
            description="Get the currently active preset configuration",
            inputSchema={"type": "object", "properties": {}},
        ),
        # GeoIP Filtering
        Tool(
            name="block_country",
            description="Block traffic from a country",
            inputSchema={
                "type": "object",
                "properties": {
                    "country_code": {"type": "string", "description": "ISO country code (e.g., CN, RU)"},
                },
                "required": ["country_code"],
            },
        ),
        Tool(
            name="unblock_country",
            description="Unblock traffic from a country",
            inputSchema={
                "type": "object",
                "properties": {
                    "country_code": {"type": "string", "description": "ISO country code"},
                },
                "required": ["country_code"],
            },
        ),
        # Domain Blocking
        Tool(
            name="block_domain",
            description="Block a domain",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to block (e.g., facebook.com)"},
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="unblock_domain",
            description="Unblock a domain",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to unblock"},
                },
                "required": ["domain"],
            },
        ),
        # Bulk Operations
        Tool(
            name="bulk_delete_port",
            description="Delete all rules for a specific port",
            inputSchema={
                "type": "object",
                "properties": {
                    "port": {"type": "integer", "description": "Port number"},
                },
                "required": ["port"],
            },
        ),
        Tool(
            name="bulk_delete_ip",
            description="Delete all rules affecting a specific IP",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address"},
                },
                "required": ["ip"],
            },
        ),
        Tool(
            name="bulk_delete_temporary",
            description="Delete all temporary rules",
            inputSchema={"type": "object", "properties": {}},
        ),
        # System
        Tool(
            name="get_backend_status",
            description="Get the status of the firewall backend",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="toggle_dry_run",
            description="Toggle between DRY RUN and LIVE mode",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    try:
        # Rule Management
        if name == "list_rules":
            rules = await app_state["backend"].list_rules()
            rules_data = [
                {
                    "id": r.id,
                    "name": r.name,
                    "action": r.action.value,
                    "direction": r.direction.value,
                    "protocol": r.protocol.value,
                    "port": r.port,
                    "source": r.source,
                    "destination": r.destination,
                    "enabled": r.enabled,
                }
                for r in rules
            ]
            return [TextContent(type="text", text=json.dumps(rules_data, indent=2))]

        elif name == "deploy_rule":
            rule = PolicyRule(
                name=arguments["name"],
                action=Action[arguments["action"]],
                direction=Direction[arguments["direction"]],
                protocol=Protocol[arguments["protocol"]],
                port=arguments.get("port"),
                source=arguments.get("source"),
                destination=arguments.get("destination"),
                description=arguments["description"],
            )
            success, message = await app_state["firewall_service"].deploy_rule(rule, user="admin")
            return [TextContent(type="text", text=json.dumps({"success": success, "message": message}))]

        elif name == "delete_rule":
            success = await app_state["backend"].delete_rule(arguments["rule_id"])
            return [TextContent(type="text", text=json.dumps({"success": success}))]

        # Preset Configuration
        elif name == "list_presets":
            presets = await app_state["config_manager"].list_presets()
            presets_data = [
                {
                    "name": p.name,
                    "version": p.version,
                    "description": p.description,
                    "rules_count": len(p.rules),
                    "geoip_blocks": len(p.geoip_blocks),
                }
                for p in presets
            ]
            return [TextContent(type="text", text=json.dumps(presets_data, indent=2))]

        elif name == "preview_preset":
            preview = await app_state["config_manager"].preview_preset(arguments["preset_name"])
            return [TextContent(type="text", text=json.dumps(preview, indent=2))]

        elif name == "apply_preset":
            success, message = await app_state["config_manager"].apply_preset(
                arguments["preset_name"], user=arguments.get("user", "admin")
            )
            return [TextContent(type="text", text=json.dumps({"success": success, "message": message}))]

        elif name == "remove_preset":
            success, message = await app_state["config_manager"].remove_preset(user=arguments.get("user", "admin"))
            return [TextContent(type="text", text=json.dumps({"success": success, "message": message}))]

        elif name == "get_active_preset":
            active = await app_state["config_manager"].get_active_preset()
            if active:
                data = {
                    "preset_name": active.preset_name,
                    "preset_version": active.preset_version,
                    "applied_at": active.applied_at.isoformat(),
                    "applied_by": active.applied_by,
                }
            else:
                data = None
            return [TextContent(type="text", text=json.dumps(data))]

        # GeoIP Filtering
        elif name == "block_country":
            success, message = await app_state["geoip_service"].create_country_rule(
                arguments["country_code"], Action.DROP
            )
            return [TextContent(type="text", text=json.dumps({"success": success, "message": message}))]

        elif name == "unblock_country":
            success, message = await app_state["geoip_service"].delete_country_rule(arguments["country_code"])
            return [TextContent(type="text", text=json.dumps({"success": success, "message": message}))]

        # Domain Blocking
        elif name == "block_domain":
            success, message = await app_state["domain_blocker"].block_domain(arguments["domain"])
            return [TextContent(type="text", text=json.dumps({"success": success, "message": message}))]

        elif name == "unblock_domain":
            success, message = await app_state["domain_blocker"].unblock_domain(arguments["domain"])
            return [TextContent(type="text", text=json.dumps({"success": success, "message": message}))]

        # Bulk Operations
        elif name == "bulk_delete_port":
            result = await app_state["bulk_operations"].delete_by_port(arguments["port"])
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {"success": result.success, "deleted": result.deleted, "errors": result.errors}
                    ),
                )
            ]

        elif name == "bulk_delete_ip":
            result = await app_state["bulk_operations"].delete_by_ip(arguments["ip"])
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {"success": result.success, "deleted": result.deleted, "errors": result.errors}
                    ),
                )
            ]

        elif name == "bulk_delete_temporary":
            result = await app_state["bulk_operations"].delete_temporary_rules()
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {"success": result.success, "deleted": result.deleted, "errors": result.errors}
                    ),
                )
            ]

        # System
        elif name == "get_backend_status":
            status = await app_state["backend"].get_status()
            dry_run = getattr(app_state["backend"], "dry_run", False)
            return [TextContent(type="text", text=json.dumps({"status": status, "dry_run": dry_run}))]

        elif name == "toggle_dry_run":
            if hasattr(app_state["backend"], "toggle_dry_run"):
                new_mode = app_state["backend"].toggle_dry_run()
                return [TextContent(type="text", text=json.dumps({"dry_run": new_mode}))]
            else:
                return [TextContent(type="text", text=json.dumps({"error": "Backend doesn't support mode toggle"}))]

        else:
            return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

    except Exception as e:
        return [TextContent(type="text", text=json.dumps({"error": str(e)}))]


async def main():
    """Run the MCP server."""
    # Initialize backend
    await initialize_backend()

    # Run server with error handling for Python 3.14 compatibility
    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())
    except RuntimeError as e:
        if "cancel scope" in str(e):
            # Known issue with Python 3.14 and anyio - ignore cleanup error
            pass
        else:
            raise


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
