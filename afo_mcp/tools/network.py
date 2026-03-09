"""Network context tool - gathers current network state for firewall rules."""

import re
import subprocess
from pathlib import Path

from afo_mcp.models import NetworkContext, NetworkInterface


def _parse_proc_net_dev() -> dict[str, dict[str, int]]:
    """Parse /proc/net/dev for interface statistics."""
    stats = {}
    proc_path = Path("/proc/net/dev")

    if not proc_path.exists():
        return stats

    content = proc_path.read_text()
    lines = content.strip().split("\n")[2:]  # Skip header lines

    for line in lines:
        parts = line.split()
        if len(parts) >= 10:
            iface = parts[0].rstrip(":")
            stats[iface] = {
                "rx_bytes": int(parts[1]),
                "tx_bytes": int(parts[9]),
            }

    return stats


def _parse_ip_addr() -> list[NetworkInterface]:
    """Parse 'ip addr' output to get interface details."""
    interfaces = []

    try:
        result = subprocess.run(
            ["ip", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return interfaces

        # Also get link info for MAC and state
        link_result = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return interfaces

    # Parse link info first
    link_info: dict[str, dict] = {}
    for line in link_result.stdout.strip().split("\n"):
        if not line:
            continue
        # Format: 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...
        match = re.match(r"\d+:\s+(\S+):\s+<([^>]*)>.*mtu\s+(\d+)", line)
        if match:
            iface_name = match.group(1).rstrip("@")  # Handle veth@if123 format
            flags = match.group(2).split(",")
            mtu = int(match.group(3))

            # Extract MAC address
            mac_match = re.search(r"link/\S+\s+([\da-f:]+)", line)
            mac = mac_match.group(1) if mac_match else None

            # Check for VLAN
            vlan_match = re.search(r"@.*\.(\d+)", iface_name)
            vlan_id = int(vlan_match.group(1)) if vlan_match else None

            state = "UP" if "UP" in flags else "DOWN"

            link_info[iface_name.split("@")[0]] = {
                "state": state,
                "mtu": mtu,
                "mac_address": mac,
                "vlan_id": vlan_id,
            }

    # Parse address info
    iface_addrs: dict[str, dict] = {}
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        # Format: 1: lo    inet 127.0.0.1/8 scope host lo
        parts = line.split()
        if len(parts) < 4:
            continue

        iface_name = parts[1].rstrip("@")
        iface_name = iface_name.split("@")[0]  # Handle veth@if123

        if iface_name not in iface_addrs:
            iface_addrs[iface_name] = {"ipv4": [], "ipv6": []}

        addr_type = parts[2]
        addr = parts[3].split("/")[0]  # Remove CIDR prefix

        if addr_type == "inet":
            iface_addrs[iface_name]["ipv4"].append(addr)
        elif addr_type == "inet6":
            iface_addrs[iface_name]["ipv6"].append(addr)

    # Get traffic stats
    stats = _parse_proc_net_dev()

    # Build interface objects
    for iface_name in set(list(link_info.keys()) + list(iface_addrs.keys())):
        info = link_info.get(iface_name, {})
        addrs = iface_addrs.get(iface_name, {"ipv4": [], "ipv6": []})
        iface_stats = stats.get(iface_name, {"rx_bytes": 0, "tx_bytes": 0})

        interfaces.append(
            NetworkInterface(
                name=iface_name,
                mac_address=info.get("mac_address"),
                ipv4_addresses=addrs["ipv4"],
                ipv6_addresses=addrs["ipv6"],
                state=info.get("state", "UNKNOWN"),
                mtu=info.get("mtu", 1500),
                vlan_id=info.get("vlan_id"),
                rx_bytes=iface_stats["rx_bytes"],
                tx_bytes=iface_stats["tx_bytes"],
            )
        )

    return interfaces


def _get_active_ruleset() -> str:
    """Get current nftables ruleset."""
    try:
        result = subprocess.run(
            ["nft", "list", "ruleset"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout
        return f"# Error listing ruleset: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "# Timeout listing ruleset"
    except FileNotFoundError:
        return "# nft command not found"
    except PermissionError:
        return "# Permission denied - need root for nft"


def _get_hostname() -> str:
    """Get system hostname."""
    try:
        result = subprocess.run(
            ["hostname"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "unknown"


def get_network_context() -> NetworkContext:
    """Gather complete network context for firewall rule generation.

    Returns:
        NetworkContext with interfaces, active ruleset, and system info.

    This tool provides the LLM with the current network state needed to
    generate appropriate firewall rules. It includes:
    - All network interfaces with IPs, MACs, and VLAN tags
    - The current nftables ruleset
    - System hostname for rule comments
    """
    return NetworkContext(
        interfaces=_parse_ip_addr(),
        active_ruleset=_get_active_ruleset(),
        hostname=_get_hostname(),
    )
