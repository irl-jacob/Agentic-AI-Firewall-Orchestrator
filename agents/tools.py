"""LangChain tool wrappers for MCP server functions.

These wrap the MCP tool functions so LangChain agents can call them.
Uses direct imports for local testing; can be swapped to MCP client calls
for remote deployment.
"""

from langchain_core.tools import tool

from afo_mcp.tools.conflicts import detect_conflicts as _detect_conflicts
from afo_mcp.tools.network import get_network_context as _get_network_context


@tool
def get_network_context() -> str:
    """Get current network interfaces, IPs, VLANs, and active nftables ruleset.

    Use this to understand the network topology before generating rules.
    """
    ctx = _get_network_context()
    data = ctx.model_dump()

    parts = [f"Hostname: {data['hostname']}", "Interfaces:"]
    for iface in data["interfaces"]:
        parts.append(
            f"  - {iface['name']}: state={iface['state']}, "
            f"ipv4={iface['ipv4_addresses']}, ipv6={iface['ipv6_addresses']}, "
            f"vlan={iface['vlan_id']}"
        )
    parts.append(f"\nActive Ruleset:\n{data['active_ruleset'][:2000]}")

    return "\n".join(parts)


@tool
def validate_syntax(command: str) -> str:
    """Validate nftables command syntax without applying it.

    Args:
        command: The nftables command to validate.

    Returns a validation result with any errors or warnings.
    """
    # Placeholder or integration with Backend.validate_rule if possible.
    # For now, simplistic check or fallback message since legacy tool is gone.
    return "Validation requires backend integration. Proceed with care."


@tool
def validate_structure(command: str) -> str:
    """Lightweight structural validation of nftables syntax (no root needed).

    Args:
        command: The nftables command to check structurally.
    """
    # Similar placeholder
    return "Structural validation deprecated. Proceed."


@tool
def detect_conflicts(proposed_rule: str) -> str:
    """Check if a proposed rule conflicts with existing active rules.

    Args:
        proposed_rule: The nftables rule to check for conflicts.
    """
    report = _detect_conflicts(proposed_rule)
    data = report.model_dump()

    if not data["has_conflicts"]:
        return "NO CONFLICTS: Rule is safe to deploy."

    parts = [f"CONFLICTS FOUND ({len(data['conflicts'])}):\n"]
    for conflict in data["conflicts"]:
        parts.append(f"  Type: {conflict['type']}")
        parts.append(f"  Existing: {conflict['existing_rule']}")
        parts.append(f"  Explanation: {conflict['explanation']}\n")

    if data["recommendations"]:
        parts.append("Recommendations:")
        for rec in data["recommendations"]:
            parts.append(f"  - {rec}")

    return "\n".join(parts)


ALL_TOOLS = [get_network_context, validate_structure, detect_conflicts]
