"""Bulk operations service for AFO.

Enables batch operations on multiple firewall rules:
- "delete all rules for port 22"
- "disable all rules blocking 10.0.0.5"
- "enable all SSH rules"
- "remove all temporary rules"
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from backend.base import FirewallBackend
from backend.models import Action, PolicyRule, Protocol

logger = logging.getLogger(__name__)


@dataclass
class BulkOperationResult:
    """Result of a bulk operation."""

    operation: str
    total_matched: int
    succeeded: int
    failed: int
    affected_rules: list[str]
    errors: list[str]
    success: bool


class BulkOperations:
    """Service for bulk rule operations."""

    def __init__(self, backend: FirewallBackend):
        """
        Initialize bulk operations service.

        Args:
            backend: Firewall backend
        """
        self.backend = backend
        self._lock = asyncio.Lock()

    async def delete_rules_by_port(self, port: int) -> BulkOperationResult:
        """
        Delete all rules affecting a specific port.

        Args:
            port: Port number

        Returns:
            BulkOperationResult with operation details
        """
        async with self._lock:
            try:
                # Get all rules
                all_rules = await self.backend.list_rules()

                # Filter rules by port
                matching_rules = [
                    rule for rule in all_rules
                    if rule.port == port or (isinstance(rule.port, list) and port in rule.port)
                ]

                if not matching_rules:
                    logger.info(f"No rules found for port {port}")
                    return BulkOperationResult(
                        operation=f"delete_by_port_{port}",
                        total_matched=0,
                        succeeded=0,
                        failed=0,
                        affected_rules=[],
                        errors=[],
                        success=True,
                    )

                # Delete each rule
                succeeded = []
                failed = []
                errors = []

                for rule in matching_rules:
                    try:
                        success = await self.backend.delete_rule(rule.id)
                        if success:
                            succeeded.append(rule.id)
                            logger.info(f"Deleted rule {rule.id} (port {port})")
                        else:
                            failed.append(rule.id)
                            errors.append(f"Failed to delete {rule.id}")
                    except Exception as e:
                        failed.append(rule.id)
                        errors.append(f"Error deleting {rule.id}: {e}")
                        logger.error(f"Error deleting rule {rule.id}: {e}")

                logger.info(
                    f"Bulk delete by port {port}: {len(succeeded)} succeeded, {len(failed)} failed"
                )

                return BulkOperationResult(
                    operation=f"delete_by_port_{port}",
                    total_matched=len(matching_rules),
                    succeeded=len(succeeded),
                    failed=len(failed),
                    affected_rules=succeeded,
                    errors=errors,
                    success=len(failed) == 0,
                )

            except Exception as e:
                logger.error(f"Error in bulk delete by port: {e}")
                return BulkOperationResult(
                    operation=f"delete_by_port_{port}",
                    total_matched=0,
                    succeeded=0,
                    failed=0,
                    affected_rules=[],
                    errors=[str(e)],
                    success=False,
                )

    async def delete_rules_by_ip(self, ip: str) -> BulkOperationResult:
        """
        Delete all rules affecting a specific IP address.

        Args:
            ip: IP address or CIDR

        Returns:
            BulkOperationResult with operation details
        """
        async with self._lock:
            try:
                all_rules = await self.backend.list_rules()

                # Filter rules by IP (source or destination)
                matching_rules = [
                    rule for rule in all_rules
                    if rule.source == ip or rule.destination == ip
                ]

                if not matching_rules:
                    logger.info(f"No rules found for IP {ip}")
                    return BulkOperationResult(
                        operation=f"delete_by_ip_{ip}",
                        total_matched=0,
                        succeeded=0,
                        failed=0,
                        affected_rules=[],
                        errors=[],
                        success=True,
                    )

                succeeded = []
                failed = []
                errors = []

                for rule in matching_rules:
                    try:
                        success = await self.backend.delete_rule(rule.id)
                        if success:
                            succeeded.append(rule.id)
                            logger.info(f"Deleted rule {rule.id} (IP {ip})")
                        else:
                            failed.append(rule.id)
                            errors.append(f"Failed to delete {rule.id}")
                    except Exception as e:
                        failed.append(rule.id)
                        errors.append(f"Error deleting {rule.id}: {e}")

                logger.info(
                    f"Bulk delete by IP {ip}: {len(succeeded)} succeeded, {len(failed)} failed"
                )

                return BulkOperationResult(
                    operation=f"delete_by_ip_{ip}",
                    total_matched=len(matching_rules),
                    succeeded=len(succeeded),
                    failed=len(failed),
                    affected_rules=succeeded,
                    errors=errors,
                    success=len(failed) == 0,
                )

            except Exception as e:
                logger.error(f"Error in bulk delete by IP: {e}")
                return BulkOperationResult(
                    operation=f"delete_by_ip_{ip}",
                    total_matched=0,
                    succeeded=0,
                    failed=0,
                    affected_rules=[],
                    errors=[str(e)],
                    success=False,
                )

    async def delete_rules_by_protocol(self, protocol: Protocol) -> BulkOperationResult:
        """
        Delete all rules for a specific protocol.

        Args:
            protocol: Protocol (TCP, UDP, etc.)

        Returns:
            BulkOperationResult with operation details
        """
        async with self._lock:
            try:
                all_rules = await self.backend.list_rules()
                matching_rules = [rule for rule in all_rules if rule.protocol == protocol]

                if not matching_rules:
                    return BulkOperationResult(
                        operation=f"delete_by_protocol_{protocol.value}",
                        total_matched=0,
                        succeeded=0,
                        failed=0,
                        affected_rules=[],
                        errors=[],
                        success=True,
                    )

                succeeded = []
                failed = []
                errors = []

                for rule in matching_rules:
                    try:
                        success = await self.backend.delete_rule(rule.id)
                        if success:
                            succeeded.append(rule.id)
                        else:
                            failed.append(rule.id)
                            errors.append(f"Failed to delete {rule.id}")
                    except Exception as e:
                        failed.append(rule.id)
                        errors.append(f"Error deleting {rule.id}: {e}")

                return BulkOperationResult(
                    operation=f"delete_by_protocol_{protocol.value}",
                    total_matched=len(matching_rules),
                    succeeded=len(succeeded),
                    failed=len(failed),
                    affected_rules=succeeded,
                    errors=errors,
                    success=len(failed) == 0,
                )

            except Exception as e:
                return BulkOperationResult(
                    operation=f"delete_by_protocol_{protocol.value}",
                    total_matched=0,
                    succeeded=0,
                    failed=0,
                    affected_rules=[],
                    errors=[str(e)],
                    success=False,
                )

    async def delete_temporary_rules(self) -> BulkOperationResult:
        """
        Delete all temporary rules (rules with TTL or is_temporary flag).

        Returns:
            BulkOperationResult with operation details
        """
        async with self._lock:
            try:
                all_rules = await self.backend.list_rules()
                matching_rules = [
                    rule for rule in all_rules
                    if getattr(rule, 'is_temporary', False) or getattr(rule, 'ttl_seconds', None)
                ]

                if not matching_rules:
                    return BulkOperationResult(
                        operation="delete_temporary",
                        total_matched=0,
                        succeeded=0,
                        failed=0,
                        affected_rules=[],
                        errors=[],
                        success=True,
                    )

                succeeded = []
                failed = []
                errors = []

                for rule in matching_rules:
                    try:
                        success = await self.backend.delete_rule(rule.id)
                        if success:
                            succeeded.append(rule.id)
                        else:
                            failed.append(rule.id)
                            errors.append(f"Failed to delete {rule.id}")
                    except Exception as e:
                        failed.append(rule.id)
                        errors.append(f"Error deleting {rule.id}: {e}")

                return BulkOperationResult(
                    operation="delete_temporary",
                    total_matched=len(matching_rules),
                    succeeded=len(succeeded),
                    failed=len(failed),
                    affected_rules=succeeded,
                    errors=errors,
                    success=len(failed) == 0,
                )

            except Exception as e:
                return BulkOperationResult(
                    operation="delete_temporary",
                    total_matched=0,
                    succeeded=0,
                    failed=0,
                    affected_rules=[],
                    errors=[str(e)],
                    success=False,
                )

    async def enable_rules_by_filter(
        self,
        port: Optional[int] = None,
        ip: Optional[str] = None,
        protocol: Optional[Protocol] = None,
    ) -> BulkOperationResult:
        """
        Enable rules matching filter criteria.

        Args:
            port: Optional port filter
            ip: Optional IP filter
            protocol: Optional protocol filter

        Returns:
            BulkOperationResult with operation details
        """
        async with self._lock:
            try:
                all_rules = await self.backend.list_rules()

                # Apply filters
                matching_rules = all_rules
                if port is not None:
                    matching_rules = [
                        r for r in matching_rules
                        if r.port == port or (isinstance(r.port, list) and port in r.port)
                    ]
                if ip is not None:
                    matching_rules = [
                        r for r in matching_rules
                        if r.source == ip or r.destination == ip
                    ]
                if protocol is not None:
                    matching_rules = [r for r in matching_rules if r.protocol == protocol]

                # Filter only disabled rules
                matching_rules = [r for r in matching_rules if not r.enabled]

                if not matching_rules:
                    return BulkOperationResult(
                        operation="enable_rules",
                        total_matched=0,
                        succeeded=0,
                        failed=0,
                        affected_rules=[],
                        errors=[],
                        success=True,
                    )

                succeeded = []
                failed = []
                errors = []

                for rule in matching_rules:
                    try:
                        # Enable the rule
                        rule.enabled = True
                        success = await self.backend.deploy_rule(rule)
                        if success:
                            succeeded.append(rule.id)
                        else:
                            failed.append(rule.id)
                            errors.append(f"Failed to enable {rule.id}")
                    except Exception as e:
                        failed.append(rule.id)
                        errors.append(f"Error enabling {rule.id}: {e}")

                return BulkOperationResult(
                    operation="enable_rules",
                    total_matched=len(matching_rules),
                    succeeded=len(succeeded),
                    failed=len(failed),
                    affected_rules=succeeded,
                    errors=errors,
                    success=len(failed) == 0,
                )

            except Exception as e:
                return BulkOperationResult(
                    operation="enable_rules",
                    total_matched=0,
                    succeeded=0,
                    failed=0,
                    affected_rules=[],
                    errors=[str(e)],
                    success=False,
                )

    async def disable_rules_by_filter(
        self,
        port: Optional[int] = None,
        ip: Optional[str] = None,
        protocol: Optional[Protocol] = None,
    ) -> BulkOperationResult:
        """
        Disable rules matching filter criteria.

        Args:
            port: Optional port filter
            ip: Optional IP filter
            protocol: Optional protocol filter

        Returns:
            BulkOperationResult with operation details
        """
        async with self._lock:
            try:
                all_rules = await self.backend.list_rules()

                # Apply filters
                matching_rules = all_rules
                if port is not None:
                    matching_rules = [
                        r for r in matching_rules
                        if r.port == port or (isinstance(r.port, list) and port in r.port)
                    ]
                if ip is not None:
                    matching_rules = [
                        r for r in matching_rules
                        if r.source == ip or r.destination == ip
                    ]
                if protocol is not None:
                    matching_rules = [r for r in matching_rules if r.protocol == protocol]

                # Filter only enabled rules
                matching_rules = [r for r in matching_rules if r.enabled]

                if not matching_rules:
                    return BulkOperationResult(
                        operation="disable_rules",
                        total_matched=0,
                        succeeded=0,
                        failed=0,
                        affected_rules=[],
                        errors=[],
                        success=True,
                    )

                succeeded = []
                failed = []
                errors = []

                for rule in matching_rules:
                    try:
                        # Disable the rule
                        rule.enabled = False
                        success = await self.backend.deploy_rule(rule)
                        if success:
                            succeeded.append(rule.id)
                        else:
                            failed.append(rule.id)
                            errors.append(f"Failed to disable {rule.id}")
                    except Exception as e:
                        failed.append(rule.id)
                        errors.append(f"Error disabling {rule.id}: {e}")

                return BulkOperationResult(
                    operation="disable_rules",
                    total_matched=len(matching_rules),
                    succeeded=len(succeeded),
                    failed=len(failed),
                    affected_rules=succeeded,
                    errors=errors,
                    success=len(failed) == 0,
                )

            except Exception as e:
                return BulkOperationResult(
                    operation="disable_rules",
                    total_matched=0,
                    succeeded=0,
                    failed=0,
                    affected_rules=[],
                    errors=[str(e)],
                    success=False,
                )

    async def delete_all_rules(self, confirm: bool = False) -> BulkOperationResult:
        """
        Delete ALL rules (dangerous operation).

        Args:
            confirm: Must be True to proceed

        Returns:
            BulkOperationResult with operation details
        """
        if not confirm:
            return BulkOperationResult(
                operation="delete_all",
                total_matched=0,
                succeeded=0,
                failed=0,
                affected_rules=[],
                errors=["Confirmation required - set confirm=True"],
                success=False,
            )

        async with self._lock:
            try:
                all_rules = await self.backend.list_rules()

                if not all_rules:
                    return BulkOperationResult(
                        operation="delete_all",
                        total_matched=0,
                        succeeded=0,
                        failed=0,
                        affected_rules=[],
                        errors=[],
                        success=True,
                    )

                succeeded = []
                failed = []
                errors = []

                for rule in all_rules:
                    try:
                        success = await self.backend.delete_rule(rule.id)
                        if success:
                            succeeded.append(rule.id)
                        else:
                            failed.append(rule.id)
                            errors.append(f"Failed to delete {rule.id}")
                    except Exception as e:
                        failed.append(rule.id)
                        errors.append(f"Error deleting {rule.id}: {e}")

                logger.warning(
                    f"Deleted ALL rules: {len(succeeded)} succeeded, {len(failed)} failed"
                )

                return BulkOperationResult(
                    operation="delete_all",
                    total_matched=len(all_rules),
                    succeeded=len(succeeded),
                    failed=len(failed),
                    affected_rules=succeeded,
                    errors=errors,
                    success=len(failed) == 0,
                )

            except Exception as e:
                return BulkOperationResult(
                    operation="delete_all",
                    total_matched=0,
                    succeeded=0,
                    failed=0,
                    affected_rules=[],
                    errors=[str(e)],
                    success=False,
                )


# Global instance
_bulk_operations: Optional[BulkOperations] = None


def get_bulk_operations(backend: FirewallBackend) -> BulkOperations:
    """Get or create the global bulk operations service."""
    global _bulk_operations
    if _bulk_operations is None:
        _bulk_operations = BulkOperations(backend)
    return _bulk_operations
