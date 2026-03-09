import asyncio
import os
import tempfile
from datetime import datetime
from pathlib import Path

from backend.base import FirewallBackend
from backend.models import Action, Direction, PolicyRule, Protocol


class NftablesBackend(FirewallBackend):
    """
    Nftables implementation of the FirewallBackend.
    """

    def __init__(self, backup_dir: str = "/var/lib/afo/backups", dry_run: bool = False):
        super().__init__()
        self.backup_dir = Path(backup_dir)
        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Fallback for dev environments without root
            self.backup_dir = Path("/tmp/afo_backups")
            self.backup_dir.mkdir(parents=True, exist_ok=True)

        self.dry_run = dry_run

    async def list_rules(self) -> list[PolicyRule]:
        """List all currently active rules (parsing nft list ruleset)."""
        if self.dry_run:
            # Return dummy rules for visualization in dry run mode
            return [
                PolicyRule(
                    id="dry_run_1",
                    name="dry_run_rule_1",
                    action=Action.ACCEPT,
                    direction=Direction.INBOUND,
                    protocol=Protocol.TCP,
                    port=22,
                    description="Mock SSH Rule",
                    source=None,
                    destination=None,
                    priority=100,
                    enabled=True
                )
            ]

        # This is a simplified parser for demonstration.
        # A robust implementation would need a full nftables JSON parser.
        proc = await asyncio.create_subprocess_exec(
            "nft",
            "list",
            "ruleset",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to list ruleset: {stderr.decode()}")

        # Return empty list for now as parsing is complex and not strictly required for initial deployment logic
        return []

    def _to_nft_command(self, rule: PolicyRule) -> str:
        """Convert PolicyRule to nftables command syntax."""
        # Mapping for Protocol enum to nftables protocol
        proto_map = {
            Protocol.TCP: "tcp",
            Protocol.UDP: "udp",
            Protocol.ICMP: "icmp",
            Protocol.ICMPV6: "icmpv6",
            Protocol.ANY: "",  # ANY doesn't add a protocol match
        }

        # Mapping for Action enum to nftables action
        action_map = {
            Action.ACCEPT: "accept",
            Action.DROP: "drop",
            Action.REJECT: "reject",
        }

        # Mapping Direction to standard nftables chains
        chain_map = {
            Direction.INBOUND: "input",
            Direction.OUTBOUND: "output",
        }
        chain_name = chain_map.get(rule.direction, "input")

        parts = [f"add rule inet filter {chain_name}"]

        # Source
        if rule.source:
             # Check if it's IPv6
             prefix = "ip6" if ":" in rule.source else "ip"
             parts.append(f"{prefix} saddr {rule.source}")

        # Destination
        if rule.destination:
             prefix = "ip6" if ":" in rule.destination else "ip"
             parts.append(f"{prefix} daddr {rule.destination}")

        # Protocol
        if rule.protocol != Protocol.ANY:
            parts.append(f"{proto_map[rule.protocol]}")

        # Port (requires protocol)
        if rule.port and rule.protocol in (Protocol.TCP, Protocol.UDP):
            parts.append(f"dport {rule.port}")

        # Action
        parts.append(action_map[rule.action])

        # Comment - always include rule ID for deletion tracking
        comment_parts = []
        if rule.id:
            comment_parts.append(f"[AFO:{rule.id}]")
        if rule.description:
            comment_parts.append(rule.description)

        if comment_parts:
            comment_text = " ".join(comment_parts)
            parts.append(f'comment "{comment_text}"')
        elif rule.name:
            # Fallback to rule name if no description
            parts.append(f'comment "[AFO:{rule.id}] {rule.name}"' if rule.id else f'comment "{rule.name}"')

        return " ".join(parts)

    async def validate_rule(self, rule: PolicyRule) -> bool:
        """Validate a rule's syntax using nft --check."""
        if self.dry_run:
            return True

        # First, do basic structural validation
        if not rule.action:
            return False

        # Generate the command
        command = self._to_nft_command(rule)

        # Basic syntax check - ensure command looks reasonable
        if not command or not command.startswith("add rule"):
            return False

        # Try to validate with nft --check if possible
        # This requires root privileges, so it may fail for permission reasons
        # which we distinguish from actual syntax errors
        chain_map = {
            Direction.INBOUND: "input",
            Direction.OUTBOUND: "output",
        }
        chain_name = chain_map.get(rule.direction, "input")
        hook_name = chain_name

        # Create minimal config for validation
        config = f"""
        table inet filter {{
            chain {chain_name} {{
                type filter hook {hook_name} priority 0; policy accept;
            }}
        }}
        {command}
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".nft", delete=False) as tmp:
            tmp.write(config)
            tmp_path = tmp.name

        try:
            proc = await asyncio.create_subprocess_exec(
                "nft",
                "--check",
                "-f",
                tmp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                return True

            # Check if it's a permission error or syntax error
            stderr_text = stderr.decode().lower()
            if "permission" in stderr_text or "access" in stderr_text or "not permitted" in stderr_text:
                # Permission denied - log warning but allow (will fail on actual deploy if no perms)
                import structlog
                logger = structlog.get_logger()
                logger.warning("nft_validation_permission_denied", error=stderr.decode())
                return True  # Allow to proceed, actual deploy will handle permission error

            # Actual syntax error
            import structlog
            logger = structlog.get_logger()
            logger.error("nft_validation_failed", error=stderr.decode())
            return False

        except Exception as e:
            # If validation command fails to run (e.g., nft not installed),
            # still allow if basic syntax looks OK
            import structlog
            logger = structlog.get_logger()
            logger.warning("nft_validation_exception", error=str(e))
            return True
        finally:
            try:
                os.remove(tmp_path)
            except:
                pass

    async def _ensure_table_and_chains(self) -> None:
        """Ensure the inet filter table and standard chains exist."""
        # Create table if it doesn't exist
        success, stderr = await self._run_nft("add table inet filter")
        if not success:
            stderr_lower = stderr.lower()
            if "permission" in stderr_lower or "not permitted" in stderr_lower:
                raise RuntimeError("Permission denied - run AFO with sudo/root privileges to create tables")
            elif "exists" not in stderr_lower:
                # Table might already exist, which is fine
                raise RuntimeError(f"Failed to create table: {stderr}")

        # Create chains if they don't exist (idempotent with 'add')
        await self._run_nft(
            "add chain inet filter input { type filter hook input priority 0 ; policy accept ; }"
        )
        await self._run_nft(
            "add chain inet filter output { type filter hook output priority 0 ; policy accept ; }"
        )

    async def _run_nft(self, command: str) -> tuple[bool, str]:
        """Run an nft command and return (success, stderr)."""
        proc = await asyncio.create_subprocess_exec(
            "nft", *command.split(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode == 0, stderr.decode().strip()

    async def deploy_rule(self, rule: PolicyRule) -> bool:
        """Apply a new rule atomically."""
        if self.dry_run:
            return True

        # 1. Create backup
        await self._create_backup(rule.id or "unknown")

        # 2. Ensure table and chains exist
        await self._ensure_table_and_chains()

        # 3. Validate first
        if not await self.validate_rule(rule):
            raise RuntimeError("Rule validation failed - syntax error")

        # 4. Apply rule
        command = self._to_nft_command(rule)
        success, stderr = await self._run_nft(command)

        if not success:
            # Check for common errors and provide helpful messages
            stderr_lower = stderr.lower()
            if "permission" in stderr_lower or "not permitted" in stderr_lower:
                raise RuntimeError("Permission denied - run AFO with sudo/root privileges")
            elif "table does not exist" in stderr_lower:
                raise RuntimeError("nftables table not found - ensure nftables is installed and running")
            else:
                raise RuntimeError(f"nft command failed: {stderr}")

        return True

    async def delete_rule(self, rule_id: str) -> bool:
        """Remove a rule by its ID (handle).

        Parses nftables ruleset to find the rule by comment or attributes,
        extracts its handle, and deletes it.
        """
        if self.dry_run:
            return True

        try:
            # Get ruleset with handles (-a flag shows handles)
            proc = await asyncio.create_subprocess_exec(
                "nft", "list", "ruleset", "-a",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                import structlog
                logger = structlog.get_logger()
                logger.error("nft_list_failed", error=stderr.decode())
                return False

            # Parse the output to find our rule
            handle_info = self._parse_rule_handle(stdout.decode(), rule_id)

            if not handle_info:
                import structlog
                logger = structlog.get_logger()
                logger.warning("rule_handle_not_found", rule_id=rule_id)
                return False

            table, chain, handle = handle_info

            # Delete the rule by handle
            delete_cmd = f"delete rule {table} {chain} handle {handle}"
            success, stderr = await self._run_nft(delete_cmd)

            if not success:
                import structlog
                logger = structlog.get_logger()
                logger.error("nft_delete_failed", error=stderr, handle=handle)
                return False

            import structlog
            logger = structlog.get_logger()
            logger.info("rule_deleted", rule_id=rule_id, handle=handle, chain=chain)
            return True

        except Exception as e:
            import structlog
            logger = structlog.get_logger()
            logger.error("delete_rule_exception", error=str(e))
            return False

    def _parse_rule_handle(self, ruleset_output: str, rule_id: str) -> tuple[str, str, int] | None:
        """Parse nftables ruleset output to find a rule's handle.

        Returns (table, chain, handle) tuple or None if not found.

        Looks for rules with comments containing [AFO:{rule_id}] format.

        Example nftables output:
            table inet filter {
                chain input {
                    type filter hook input priority 0; policy accept;
                    ip saddr 10.0.0.5 tcp dport 22 drop comment "[AFO:rule-123] Block SSH" # handle 42
                }
            }
        """
        import re

        lines = ruleset_output.split('\n')
        current_table = None
        current_chain = None

        for line in lines:
            # Track current table context
            table_match = re.match(r'\s*table\s+(\S+\s+\S+)\s+{', line)
            if table_match:
                current_table = table_match.group(1)
                continue

            # Track current chain context
            chain_match = re.match(r'\s*chain\s+(\S+)\s+{', line)
            if chain_match:
                current_chain = chain_match.group(1)
                continue

            # Reset context on closing braces
            if '}' in line and current_chain:
                # Check if we're closing a chain or table
                if line.strip() == '}' or re.match(r'\s*}\s*$', line):
                    # Could be closing chain or table - be conservative
                    if current_chain and not re.search(r'chain\s+\w+', line):
                        current_chain = None

            # Look for rules with handles
            # Format: <rule content> # handle <number>
            handle_match = re.search(r'#\s*handle\s+(\d+)', line)
            if handle_match and current_table and current_chain:
                handle = int(handle_match.group(1))

                # Primary method: Look for AFO-specific ID format in comment
                afo_id_match = re.search(r'\[AFO:([^\]]+)\]', line)
                if afo_id_match:
                    found_id = afo_id_match.group(1)
                    if found_id == rule_id:
                        return (current_table, current_chain, handle)

                # Fallback: Try to match by comment containing rule_id
                comment_match = re.search(r'comment\s+"([^"]*)"', line)
                if comment_match:
                    comment = comment_match.group(1)
                    # Check if rule_id appears in comment
                    if rule_id in comment:
                        return (current_table, current_chain, handle)

        return None

    async def rollback(self, steps: int = 1) -> bool:
        """Revert to the last backup."""
        backups = sorted(self.backup_dir.glob("*.nft"), key=os.path.getmtime, reverse=True)
        if not backups:
            return False

        target_backup = backups[0] # For steps=1

        proc = await asyncio.create_subprocess_exec(
            "nft",
            "-f",
            str(target_backup),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode == 0

    async def get_status(self) -> str:
        """Get the current status."""
        if self.dry_run:
            return "Active (Dry Run)"

        proc = await asyncio.create_subprocess_exec(
            "nft",
            "list",
            "ruleset",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            return "Active"
        return f"Error: {stderr.decode()}"

    async def _create_backup(self, rule_id: str) -> Path | None:
        """Create a backup of current ruleset."""
        proc = await asyncio.create_subprocess_exec(
            "nft",
            "list",
            "ruleset",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"backup_{rule_id}_{timestamp}.nft"
        backup_path.write_bytes(stdout)
        return backup_path

    # ── Extended operations ──────────────────────────────────────

    async def _run_cmd(self, *args: str) -> tuple[bool, str]:
        """Run a system command and return (success, stdout)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                return True, stdout.decode().strip()
            return False, stderr.decode().strip()
        except FileNotFoundError:
            return False, f"Command not found: {args[0]}"

    async def list_interfaces(self) -> list[dict]:
        """List network interfaces using `ip` command."""
        ok, output = await self._run_cmd("ip", "-j", "addr", "show")
        if not ok:
            return []
        try:
            import json
            raw = json.loads(output)
            interfaces = []
            for iface in raw:
                ipv4 = [
                    a["local"]
                    for a in iface.get("addr_info", [])
                    if a.get("family") == "inet"
                ]
                ipv6 = [
                    a["local"]
                    for a in iface.get("addr_info", [])
                    if a.get("family") == "inet6"
                ]
                interfaces.append({
                    "name": iface["ifname"],
                    "state": iface.get("operstate", "UNKNOWN"),
                    "mac": iface.get("address", ""),
                    "mtu": iface.get("mtu", 0),
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "flags": iface.get("flags", []),
                })
            return interfaces
        except Exception:
            return []

    async def show_routes(self) -> list[dict]:
        """Show routing table using `ip route`."""
        ok, output = await self._run_cmd("ip", "-j", "route", "show")
        if not ok:
            return []
        try:
            import json
            raw = json.loads(output)
            routes = []
            for r in raw:
                routes.append({
                    "destination": r.get("dst", "default"),
                    "gateway": r.get("gateway", ""),
                    "device": r.get("dev", ""),
                    "protocol": r.get("protocol", ""),
                    "scope": r.get("scope", ""),
                    "metric": r.get("metric", 0),
                })
            return routes
        except Exception:
            return []

    async def list_nat_rules(self) -> list[dict]:
        """List NAT rules from nftables."""
        ok, output = await self._run_cmd("nft", "list", "table", "inet", "nat")
        if not ok:
            # Try ip nat table (older convention)
            ok, output = await self._run_cmd("nft", "list", "table", "ip", "nat")
            if not ok:
                return []

        rules = []
        current_chain = ""
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("chain "):
                current_chain = line.split()[1]
            elif any(kw in line for kw in ["masquerade", "dnat", "snat", "redirect"]):
                rules.append({
                    "chain": current_chain,
                    "rule": line,
                    "type": next(
                        (kw for kw in ["masquerade", "dnat", "snat", "redirect"] if kw in line),
                        "unknown",
                    ),
                })
        return rules

    async def add_nat_masquerade(self, interface: str) -> tuple[bool, str]:
        """Add masquerade NAT for an outbound interface."""
        if self.dry_run:
            return True, f"[DRY RUN] Would add masquerade on {interface}"

        # Ensure nat table exists
        await self._run_nft("add table inet nat")
        await self._run_nft(
            "add chain inet nat postrouting { type nat hook postrouting priority 100 ; }"
        )
        ok, err = await self._run_nft(
            f'add rule inet nat postrouting oifname "{interface}" masquerade'
        )
        if ok:
            return True, f"Masquerade NAT added on {interface}"
        return False, f"Failed: {err}"

    async def add_nat_dnat(
        self, protocol: str, external_port: int, dest_ip: str, dest_port: int
    ) -> tuple[bool, str]:
        """Add DNAT (port forward) rule."""
        if self.dry_run:
            return True, f"[DRY RUN] Would forward {protocol}/{external_port} -> {dest_ip}:{dest_port}"

        await self._run_nft("add table inet nat")
        await self._run_nft(
            "add chain inet nat prerouting { type nat hook prerouting priority -100 ; }"
        )
        ok, err = await self._run_nft(
            f"add rule inet nat prerouting {protocol} dport {external_port} dnat to {dest_ip}:{dest_port}"
        )
        if ok:
            return True, f"Port forward {protocol}/{external_port} -> {dest_ip}:{dest_port}"
        return False, f"Failed: {err}"

    async def show_connections(self) -> list[dict]:
        """Show active connections using `ss`."""
        ok, output = await self._run_cmd("ss", "-tunap")
        if not ok:
            return []

        connections = []
        for line in output.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 5:
                connections.append({
                    "proto": parts[0],
                    "state": parts[1],
                    "local": parts[4] if len(parts) > 4 else "",
                    "remote": parts[5] if len(parts) > 5 else "",
                    "process": parts[-1] if "users:" in line else "",
                })
        return connections[:50]  # Limit to 50

    async def run_diagnostics(self, target: str | None = None) -> dict:
        """Run network diagnostics."""
        result = {}

        # Interfaces
        result["interfaces"] = await self.list_interfaces()

        # Routes
        result["routes"] = await self.show_routes()

        # NAT
        result["nat_rules"] = await self.list_nat_rules()

        # DNS resolution test
        if target:
            ok, output = await self._run_cmd("ping", "-c", "1", "-W", "2", target)
            result["ping"] = {"target": target, "reachable": ok, "output": output[:200]}

        # Firewall status
        result["status"] = await self.get_status()

        # Active connections count
        conns = await self.show_connections()
        result["active_connections"] = len(conns)

        return result

    async def list_vlans(self) -> list[dict]:
        """List VLAN interfaces."""
        ok, output = await self._run_cmd("ip", "-j", "link", "show", "type", "vlan")
        if not ok:
            return []
        try:
            import json
            raw = json.loads(output)
            return [
                {
                    "name": v["ifname"],
                    "vlan_id": v.get("linkinfo", {}).get("info_data", {}).get("id"),
                    "parent": v.get("link"),
                    "state": v.get("operstate", "UNKNOWN"),
                }
                for v in raw
            ]
        except Exception:
            return []

    async def create_backup(self) -> tuple[bool, str]:
        """Create a full nftables backup."""
        path = await self._create_backup("manual")
        if path:
            return True, f"Backup saved to {path}"
        return False, "Failed to create backup"
