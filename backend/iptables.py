import asyncio
import os
from pathlib import Path

from backend.base import FirewallBackend
from backend.models import Action, Direction, PolicyRule, Protocol


class IptablesBackend(FirewallBackend):
    """
    Iptables implementation of the FirewallBackend.
    """

    def __init__(self, backup_dir: str = "/var/lib/afo/backups", dry_run: bool = False):
        super().__init__()
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.dry_run = dry_run

    async def list_rules(self) -> list[PolicyRule]:
        """List all currently active rules (parsing iptables-save)."""
        proc = await asyncio.create_subprocess_exec(
            "iptables-save",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to list rules: {stderr.decode()}")

        # Simplified parsing: return empty list for now, similar to NftablesBackend
        # Real implementation would parse stdout lines
        return []

    def _to_iptables_command(self, rule: PolicyRule) -> list[str]:
        """Convert PolicyRule to iptables command arguments."""
        # Map Action
        action_map = {
            Action.ACCEPT: "ACCEPT",
            Action.DROP: "DROP",
            Action.REJECT: "REJECT",
        }

        # Map Direction to Chain
        # Note: Iptables chains are INPUT/OUTPUT/FORWARD.
        # Direction.INBOUND -> INPUT
        # Direction.OUTBOUND -> OUTPUT
        chain_map = {
            Direction.INBOUND: "INPUT",
            Direction.OUTBOUND: "OUTPUT",
        }

        cmd = ["-A", chain_map[rule.direction.value]]

        # Protocol
        if rule.protocol != Protocol.ANY:
            cmd.extend(["-p", rule.protocol.value.lower()])

        # Source
        if rule.source:
            cmd.extend(["-s", rule.source])

        # Destination
        if rule.destination:
            cmd.extend(["-d", rule.destination])

        # Port (requires protocol)
        if rule.port and rule.protocol in (Protocol.TCP, Protocol.UDP):
            cmd.extend(["--dport", str(rule.port)])

        # Action
        cmd.extend(["-j", action_map[rule.action]])

        # Comment
        if rule.description:
            cmd.extend(["-m", "comment", "--comment", rule.description])

        return cmd

    async def validate_rule(self, rule: PolicyRule) -> bool:
        """
        Validate a rule's syntax.
        iptables --check (-C) exists, but it checks if a rule EXISTS, not if syntax is valid.
        To validate syntax without applying, we can try applying it to a user-defined chain or check return code?
        Actually, iptables doesn't have a dry-run syntax check like nft --check.
        Best effort: Construct command and ensure no obvious errors.
        Or try to add to a temporary chain?
        For now, we'll assume valid if translation works.
        """
        try:
            self._to_iptables_command(rule)
            return True
        except Exception:
            return False

    async def deploy_rule(self, rule: PolicyRule) -> bool:
        """Apply a new rule."""
        # 1. Create backup
        await self._create_backup(rule.id or "unknown")

        # 2. Apply
        cmd_args = self._to_iptables_command(rule)
        proc = await asyncio.create_subprocess_exec(
            "iptables",
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        return proc.returncode == 0

    async def delete_rule(self, rule_id: str) -> bool:
        """Remove a rule."""
        # Iptables deletion requires the exact rule spec (replace -A with -D)
        # Without state tracking mapping IDs to exact specs, this is hard.
        # Placeholder.
        return False

    async def rollback(self, steps: int = 1) -> bool:
        """Revert to the last backup."""
        backups = sorted(self.backup_dir.glob("*.iptables"), key=os.path.getmtime, reverse=True)
        if not backups:
            return False

        target_backup = backups[0]

        proc = await asyncio.create_subprocess_exec(
            "iptables-restore",
            str(target_backup),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode == 0

    async def get_status(self) -> str:
        """Get status."""
        proc = await asyncio.create_subprocess_exec(
            "iptables",
            "-L",
            "-n",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            return "Active"
        return f"Error: {stderr.decode()}"

    async def _create_backup(self, rule_id: str) -> Path | None:
        """Create a backup (iptables-save)."""
        proc = await asyncio.create_subprocess_exec(
            "iptables-save",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            return None

        # iptables-save output
        timestamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"backup_{rule_id}_{timestamp}.iptables"
        backup_path.write_bytes(stdout)
        return backup_path
