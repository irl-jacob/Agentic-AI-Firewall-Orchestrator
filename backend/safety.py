import ipaddress
from pathlib import Path

import structlog
import yaml

from backend.models import Action, PolicyRule

logger = structlog.get_logger(__name__)


class SafetyEnforcer:
    """
    Enforces safety policies to prevent accidental self-lockout or disruption of critical services.
    """

    def __init__(self, config_path: str = "config/safety.yaml"):
        self.config_path = Path(config_path)
        self.allowlist: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        self._load_config()

    def _load_config(self) -> None:
        """Load allowlist from YAML config."""
        if not self.config_path.exists():
            return

        try:
            with open(self.config_path) as f:
                data = yaml.safe_load(f) or {}

            for entry in data.get("allowlist", []):
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                    self.allowlist.add(network)
                except ValueError:
                    logger.warning("safety_allowlist_invalid_entry", entry=entry)
        except Exception as exc:
            logger.error("safety_config_load_failed", path=str(self.config_path), error=str(exc))

    def is_safe(self, rule: PolicyRule) -> bool:
        """
        Check if a rule is safe to deploy.
        Returns False if the rule blocks an allowlisted IP.
        """
        # Reset debug attributes
        self._blocked_by = None
        self._blocked_target = None

        # We only care about blocking rules
        if rule.action not in (Action.DROP, Action.REJECT):
            return True

        # Check source and destination against allowlist
        targets = []
        if rule.source:
            targets.append(rule.source)
        if rule.destination:
            targets.append(rule.destination)

        for target in targets:
            try:
                # Try to parse as IP network
                target_net = ipaddress.ip_network(target, strict=False)
                for allowed in self.allowlist:
                    # If target overlaps with allowed, it's unsafe
                    if target_net.overlaps(allowed):
                        # Store which allowlist entry caused the block for debugging
                        self._blocked_by = str(allowed)
                        self._blocked_target = target
                        return False
            except ValueError:
                # Not a valid IP/network - might be an alias name
                # Aliases are safe to use (they're managed in OPNsense)
                pass

        # Special check: DROP ALL (source=None, dest=None) with NO port is unsafe
        if not rule.source and not rule.destination and not rule.port:
             self._blocked_by = "drop-all-check"
             self._blocked_target = "no source/dest/port specified"
             return False

        return True
