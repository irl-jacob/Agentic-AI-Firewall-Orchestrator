"""Multi-backend firewall manager for managing multiple firewalls."""

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from backend.base import FirewallBackend
from backend.models import PolicyRule


class FirewallBackendConfig:
    """Configuration for a single firewall backend."""

    def __init__(
        self,
        name: str,
        backend: FirewallBackend,
        description: str = "",
        enabled: bool = True,
    ):
        self.name = name
        self.backend = backend
        self.description = description
        self.enabled = enabled


class MultiFirewallManager:
    """
    Manages multiple firewall backends and allows selecting which one(s) to deploy to.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.backends: dict[str, FirewallBackendConfig] = {}
        self.logger = structlog.get_logger()

    def add_backend(
        self,
        name: str,
        backend: FirewallBackend,
        description: str = "",
        enabled: bool = True,
    ) -> None:
        """Add a firewall backend to the manager."""
        self.backends[name] = FirewallBackendConfig(
            name=name,
            backend=backend,
            description=description,
            enabled=enabled,
        )
        self.logger.info("backend_added", name=name, description=description)

    def remove_backend(self, name: str) -> None:
        """Remove a firewall backend from the manager."""
        if name in self.backends:
            del self.backends[name]
            self.logger.info("backend_removed", name=name)

    def get_backend(self, name: str) -> FirewallBackend | None:
        """Get a specific backend by name."""
        config = self.backends.get(name)
        return config.backend if config else None

    def list_backends(self) -> list[FirewallBackendConfig]:
        """List all available backends."""
        return [config for config in self.backends.values() if config.enabled]

    def get_backend_names(self) -> list[str]:
        """Get list of enabled backend names."""
        return [name for name, config in self.backends.items() if config.enabled]

    async def deploy_rule_to_backend(
        self,
        backend_name: str,
        rule: PolicyRule,
        user: str = "system",
    ) -> tuple[bool, str]:
        """
        Deploy a rule to a specific backend.

        Returns:
            Tuple of (success: bool, message: str).
        """
        backend_config = self.backends.get(backend_name)
        if not backend_config:
            return False, f"Backend '{backend_name}' not found"

        if not backend_config.enabled:
            return False, f"Backend '{backend_name}' is disabled"

        try:
            # Import here to avoid circular dependency
            from services.firewall import FirewallService

            service = FirewallService(backend_config.backend, self.session)
            success, message = await service.deploy_rule(rule, user=user)

            if success:
                self.logger.info(
                    "rule_deployed_to_backend",
                    backend=backend_name,
                    rule_name=rule.name,
                )
            else:
                self.logger.error(
                    "rule_deployment_failed",
                    backend=backend_name,
                    rule_name=rule.name,
                    error=message,
                )

            return success, message

        except Exception as e:
            error_msg = f"Failed to deploy to {backend_name}: {str(e)}"
            self.logger.error("deployment_exception", backend=backend_name, error=str(e))
            return False, error_msg

    async def deploy_rule_to_multiple(
        self,
        backend_names: list[str],
        rule: PolicyRule,
        user: str = "system",
    ) -> dict[str, tuple[bool, str]]:
        """
        Deploy a rule to multiple backends.

        Returns:
            Dict mapping backend name to (success, message) tuple.
        """
        results = {}
        for backend_name in backend_names:
            success, message = await self.deploy_rule_to_backend(
                backend_name, rule, user
            )
            results[backend_name] = (success, message)

        return results

    async def delete_rule_from_backend(
        self,
        backend_name: str,
        rule: PolicyRule,
        user: str = "system",
    ) -> tuple[bool, str]:
        """
        Delete a rule from a specific backend.

        Returns:
            Tuple of (success: bool, message: str).
        """
        backend_config = self.backends.get(backend_name)
        if not backend_config:
            return False, f"Backend '{backend_name}' not found"

        if not backend_config.enabled:
            return False, f"Backend '{backend_name}' is disabled"

        try:
            from services.firewall import FirewallService

            service = FirewallService(backend_config.backend, self.session)
            success, message = await service.delete_rule(rule, user=user)

            if success:
                self.logger.info(
                    "rule_deleted_from_backend",
                    backend=backend_name,
                    rule_name=rule.name,
                )
            else:
                self.logger.error(
                    "rule_deletion_failed",
                    backend=backend_name,
                    rule_name=rule.name,
                    error=message,
                )

            return success, message

        except Exception as e:
            error_msg = f"Failed to delete from {backend_name}: {str(e)}"
            self.logger.error("deletion_exception", backend=backend_name, error=str(e))
            return False, error_msg
