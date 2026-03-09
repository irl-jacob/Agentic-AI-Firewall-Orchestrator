"""Operations command router for AFO.

Routes structured commands (show interfaces, list nat, etc.) directly
to backend methods without needing the LLM. Works with both nftables
and OPNsense backends.
"""

import re

from backend.base import FirewallBackend


# ── Command patterns → handler mappings ──────────────────────────

COMMAND_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Interfaces
    (re.compile(r"^(?:show|list|get)\s+(?:network\s+)?interfaces?$", re.I), "interfaces"),
    (re.compile(r"^(?:show|list)\s+(?:network\s+)?(?:int|iface|nic)s?$", re.I), "interfaces"),
    # Routes
    (re.compile(r"^(?:show|list|get)\s+(?:routing\s+table|routes?)$", re.I), "routes"),
    (re.compile(r"^(?:show|list)\s+(?:routing|route\s+table)$", re.I), "routes"),
    # NAT
    (re.compile(r"^(?:show|list|get)\s+nat(?:\s+rules?)?$", re.I), "nat_list"),
    (re.compile(r"^(?:add|create|enable)\s+(?:nat\s+)?masquerade\s+(?:on\s+)?(\S+)$", re.I), "nat_masquerade"),
    (re.compile(
        r"^(?:add|create)\s+(?:nat\s+)?(?:port[- ]?forward|dnat)\s+"
        r"(tcp|udp)\s+(\d+)\s+(?:to\s+)?(\d+\.\d+\.\d+\.\d+)[:/](\d+)$", re.I
    ), "nat_dnat"),
    # Connections
    (re.compile(r"^(?:show|list)\s+(?:active\s+)?connections?$", re.I), "connections"),
    (re.compile(r"^(?:show|list)\s+(?:open\s+)?(?:sockets?|ports?)$", re.I), "connections"),
    # Diagnostics
    (re.compile(r"^(?:run\s+)?diagnostics?(?:\s+(\S+))?$", re.I), "diagnostics"),
    (re.compile(r"^(?:network\s+)?(?:health|check|diag)(?:\s+(\S+))?$", re.I), "diagnostics"),
    # VLANs
    (re.compile(r"^(?:show|list|get)\s+vlans?$", re.I), "vlans"),
    # Backup
    (re.compile(r"^(?:create|make|save)\s+backup$", re.I), "backup"),
    # Status
    (re.compile(r"^(?:show|get)\s+(?:firewall\s+)?status$", re.I), "status"),
    (re.compile(r"^status$", re.I), "status"),
    # Block domain (DNS)
    (re.compile(r"^block\s+domain\s+(\S+)$", re.I), "block_domain"),
    (re.compile(r"^(?:dns\s+)?block\s+(\S+\.\S+)$", re.I), "block_domain"),
    # Rules (shortcut)
    (re.compile(r"^(?:show|list|get)\s+(?:firewall\s+)?rules?$", re.I), "list_rules"),
    # Help
    (re.compile(r"^(?:show\s+)?(?:ops|operations|commands?)(?:\s+help)?$", re.I), "help"),
    (re.compile(r"^help\s+(?:ops|operations|commands?)$", re.I), "help"),
]


def _format_table(rows: list[dict], columns: list[str] | None = None) -> str:
    """Format a list of dicts as an aligned text table."""
    if not rows:
        return "  (none)"

    if columns is None:
        columns = list(rows[0].keys())

    # Calculate column widths
    widths = {col: len(col) for col in columns}
    for row in rows:
        for col in columns:
            val = str(row.get(col, ""))
            widths[col] = max(widths[col], min(len(val), 40))

    # Header
    header = "  ".join(col.upper().ljust(widths[col]) for col in columns)
    sep = "  ".join("-" * widths[col] for col in columns)
    lines = [header, sep]

    # Rows
    for row in rows:
        line = "  ".join(str(row.get(col, ""))[:40].ljust(widths[col]) for col in columns)
        lines.append(line)

    return "\n".join(lines)


async def handle_operation(user_input: str, backend: FirewallBackend) -> dict | None:
    """Check if input matches an operations command and execute it.

    Returns:
        A chat result dict if handled, or None to fall through to LLM.
    """
    text = user_input.strip()

    for pattern, cmd_type in COMMAND_PATTERNS:
        match = pattern.match(text)
        if not match:
            continue

        try:
            if cmd_type == "interfaces":
                ifaces = await backend.list_interfaces()
                if not ifaces:
                    return _chat("No interface data available. Backend may not support this.")
                display = _format_table(ifaces, ["name", "state", "ipv4", "mac", "mtu"])
                return _chat(f"Network Interfaces:\n\n{display}")

            elif cmd_type == "routes":
                routes = await backend.show_routes()
                if not routes:
                    return _chat("No routing data available.")
                display = _format_table(routes, ["destination", "gateway", "device", "metric"])
                return _chat(f"Routing Table:\n\n{display}")

            elif cmd_type == "nat_list":
                rules = await backend.list_nat_rules()
                if not rules:
                    return _chat("No NAT rules configured.")
                display = _format_table(rules, ["type", "chain", "rule"])
                return _chat(f"NAT Rules:\n\n{display}")

            elif cmd_type == "nat_masquerade":
                iface = match.group(1)
                ok, msg = await backend.add_nat_masquerade(iface)
                return _chat(msg)

            elif cmd_type == "nat_dnat":
                proto, ext_port, dest_ip, dest_port = match.groups()
                ok, msg = await backend.add_nat_dnat(
                    proto.lower(), int(ext_port), dest_ip, int(dest_port)
                )
                return _chat(msg)

            elif cmd_type == "connections":
                conns = await backend.show_connections()
                if not conns:
                    return _chat("No active connections found.")
                display = _format_table(conns[:30], ["proto", "state", "local", "remote"])
                count = len(conns)
                return _chat(f"Active Connections ({count}):\n\n{display}")

            elif cmd_type == "diagnostics":
                target = match.group(1) if match.lastindex else None
                result = await backend.run_diagnostics(target)

                parts = [f"Status: {result.get('status', 'unknown')}"]
                parts.append(f"Active connections: {result.get('active_connections', '?')}")

                ifaces = result.get("interfaces", [])
                if ifaces:
                    up = [i["name"] for i in ifaces if i.get("state") == "UP"]
                    parts.append(f"Interfaces UP: {', '.join(up) if up else 'none'}")

                routes = result.get("routes", [])
                if routes:
                    parts.append(f"Routes: {len(routes)}")

                nat = result.get("nat_rules", [])
                if nat:
                    parts.append(f"NAT rules: {len(nat)}")

                ping = result.get("ping")
                if ping:
                    status = "reachable" if ping["reachable"] else "unreachable"
                    parts.append(f"Ping {ping['target']}: {status}")

                return _chat("Network Diagnostics:\n\n" + "\n".join(f"  {p}" for p in parts))

            elif cmd_type == "vlans":
                vlans = await backend.list_vlans()
                if not vlans:
                    return _chat("No VLANs configured.")
                display = _format_table(vlans, ["name", "vlan_id", "parent", "state"])
                return _chat(f"VLANs:\n\n{display}")

            elif cmd_type == "backup":
                ok, msg = await backend.create_backup()
                return _chat(msg)

            elif cmd_type == "status":
                status = await backend.get_status()
                return _chat(f"Firewall Status: {status}")

            elif cmd_type == "block_domain":
                domain = match.group(1)
                ok, msg = await backend.block_domain(domain)
                return _chat(msg)

            elif cmd_type == "list_rules":
                rules = await backend.list_rules()
                if not rules:
                    return _chat("No firewall rules found.")
                rows = [
                    {
                        "name": r.name[:20],
                        "action": r.action.value,
                        "proto": r.protocol.value,
                        "dir": r.direction.value[:3],
                        "port": r.port or "",
                        "source": (r.source or "any")[:18],
                        "dest": (r.destination or "any")[:18],
                    }
                    for r in rules
                ]
                display = _format_table(rows, ["name", "action", "proto", "dir", "port", "source", "dest"])
                return _chat(f"Firewall Rules ({len(rules)}):\n\n{display}")

            elif cmd_type == "help":
                return _chat(OPS_HELP)

        except Exception as e:
            return _chat(f"Operation failed: {e}")

    return None  # Not an operations command — fall through to LLM


def _chat(response: str) -> dict:
    """Wrap a response string in the standard chat result format."""
    return {"type": "chat", "response": response}


OPS_HELP = """\
Available operations (no LLM needed):

  Interfaces & Network:
    show interfaces       - List network interfaces
    show routes           - Show routing table
    show connections      - Show active connections
    show vlans            - List VLAN interfaces
    show status           - Firewall backend status
    diagnostics [target]  - Run network diagnostics

  NAT:
    show nat              - List NAT rules
    add masquerade <iface>              - Enable NAT masquerade
    add port-forward tcp 8080 to 10.0.0.5:80  - Add DNAT rule

  Firewall:
    show rules            - List firewall rules
    create backup         - Backup current config

  DNS:
    block domain <name>   - Block a domain

  Tip: These commands work instantly without the LLM.\
"""
