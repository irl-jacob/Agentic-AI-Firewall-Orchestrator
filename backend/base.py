from abc import ABC, abstractmethod

from backend.models import PolicyRule


class FirewallBackend(ABC):
    """
    Abstract base class for firewall implementations (e.g., nftables, iptables, OPNsense).
    """

    def __init__(self):
        self._dry_run = False

    @property
    def dry_run(self) -> bool:
        """Get current dry run mode."""
        return self._dry_run

    @dry_run.setter
    def dry_run(self, value: bool) -> None:
        """Set dry run mode."""
        self._dry_run = value

    def toggle_dry_run(self) -> bool:
        """Toggle dry run mode. Returns new state."""
        self._dry_run = not self._dry_run
        return self._dry_run

    @abstractmethod
    async def list_rules(self) -> list[PolicyRule]:
        """List all currently active rules."""
        pass

    @abstractmethod
    async def validate_rule(self, rule: PolicyRule) -> bool:
        """Validate a rule's syntax and semantics."""
        pass

    @abstractmethod
    async def deploy_rule(self, rule: PolicyRule) -> bool:
        """Apply a new rule."""
        pass

    @abstractmethod
    async def delete_rule(self, rule_id: str) -> bool:
        """Remove a rule by its ID."""
        pass

    @abstractmethod
    async def rollback(self, steps: int = 1) -> bool:
        """Revert the last N changes."""
        pass

    @abstractmethod
    async def get_status(self) -> str:
        """Get the current status of the firewall backend."""
        pass

    # ── Extended operations (optional, override in subclasses) ──

    async def list_interfaces(self) -> list[dict]:
        """List network interfaces with IPs, state, and stats."""
        return []

    async def show_routes(self) -> list[dict]:
        """Show the routing table."""
        return []

    async def list_nat_rules(self) -> list[dict]:
        """List NAT rules (masquerade, SNAT, DNAT)."""
        return []

    async def add_nat_masquerade(self, interface: str) -> tuple[bool, str]:
        """Add masquerade NAT on an interface."""
        return False, "NAT not supported by this backend"

    async def add_nat_dnat(
        self, protocol: str, external_port: int, dest_ip: str, dest_port: int
    ) -> tuple[bool, str]:
        """Add a DNAT/port-forward rule."""
        return False, "NAT not supported by this backend"

    async def remove_nat_rule(self, rule_id: str) -> tuple[bool, str]:
        """Remove a NAT rule."""
        return False, "NAT not supported by this backend"

    async def show_connections(self) -> list[dict]:
        """Show active/tracked connections."""
        return []

    async def run_diagnostics(self, target: str | None = None) -> dict:
        """Run network diagnostics."""
        return {"error": "Diagnostics not supported by this backend"}

    async def list_vlans(self) -> list[dict]:
        """List VLANs."""
        return []

    async def block_domain(self, domain: str) -> tuple[bool, str]:
        """Block a domain (DNS-level)."""
        return False, "DNS blocking not supported by this backend"

    async def create_backup(self) -> tuple[bool, str]:
        """Create a configuration backup."""
        return False, "Backup not supported by this backend"
