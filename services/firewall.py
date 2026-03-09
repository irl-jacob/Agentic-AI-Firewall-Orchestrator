import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from backend.base import FirewallBackend
from backend.models import PolicyRule
from backend.safety import SafetyEnforcer
from db.models import AuditEntry, DeploymentLog
from services.rule_scheduler import format_duration, get_scheduler


class FirewallService:
    """
    High-level service for managing firewall operations.
    Handles orchestration between the database (audit/logging) and the firewall backend.
    """

    def __init__(self, backend: FirewallBackend, session: AsyncSession):
        self.backend = backend
        self.session = session
        self.logger = structlog.get_logger()
        self.safety_enforcer = SafetyEnforcer()
        self.scheduler = get_scheduler()

    async def list_rules(self) -> list[PolicyRule]:
        """List active rules from the backend."""
        return await self.backend.list_rules()

    async def deploy_rule(self, rule: PolicyRule, user: str = "system") -> tuple[bool, str]:
        """
        Deploy a rule with audit logging and database tracking.

        Returns:
            Tuple of (success: bool, message: str).
        """
        # Create snapshot BEFORE deployment
        try:
            from services.snapshot import get_snapshot_manager

            snapshot_manager = get_snapshot_manager(self.backend, self.session)
            snapshot_id = await snapshot_manager.create_snapshot(
                user=user,
                description=f"Before deploying rule: {rule.name}",
                original_command=getattr(rule, 'original_command', ''),
                parsed_intent=getattr(rule, 'parsed_intent', None)
            )
        except Exception as e:
            self.logger.warning(f"Failed to create snapshot: {e}")
            snapshot_id = None

        if not self.safety_enforcer.is_safe(rule):
            # Get debug info about why it was blocked
            blocked_by = getattr(self.safety_enforcer, '_blocked_by', 'unknown')
            blocked_target = getattr(self.safety_enforcer, '_blocked_target', 'unknown')

            # Show all allowlist entries for debugging
            allowlist_str = ", ".join([str(n) for n in self.safety_enforcer.allowlist])

            # Show the actual rule values for debugging
            rule_debug = (f"source={rule.source}, dest={rule.destination}, "
                         f"port={rule.port}, action={rule.action}")

            msg = (f"Rule '{rule.name}' blocked by Safety Policy\n"
                   f"Rule values: {rule_debug}\n"
                   f"Reason: {blocked_target} overlaps with allowlist entry {blocked_by}\n"
                   f"Current allowlist: [{allowlist_str}]\n"
                   f"Config file: {self.safety_enforcer.config_path}")
            self.logger.warning("safety_block", rule_name=rule.name, blocked_by=blocked_by)
            return False, msg

        rule_id = rule.id or "unknown"
        log_entry = DeploymentLog(
            status="PENDING",
            details=f"Deploying rule: {rule.name}",
            rule_id=rule_id,
        )
        self.session.add(log_entry)
        await self.session.commit()
        await self.session.refresh(log_entry)

        try:
            # 1. Deploy (backend now handles validation internally)
            self.logger.info("deploying_rule", rule_name=rule.name)
            deployed = await self.backend.deploy_rule(rule)

            if not deployed:
                msg = f"Backend deployment failed for rule '{rule.name}' — deploy_rule() returned False"
                self.logger.error("deployment_rejected", rule_name=rule.name)
                log_entry.status = "FAILURE"
                log_entry.details = msg
                self.session.add(log_entry)
                await self.session.commit()
                return False, msg

            # Update rule_id now that the backend may have assigned a UUID
            actual_rule_id = rule.id or rule_id
            log_entry.rule_id = actual_rule_id

            # 2. Handle TTL scheduling if this is a temporary rule
            ttl_message = ""
            if rule.is_temporary and rule.ttl_seconds:
                await self.scheduler.schedule_rule(
                    rule_id=actual_rule_id,
                    rule_name=rule.name,
                    ttl_seconds=rule.ttl_seconds,
                    delete_callback=self._delete_rule_by_id,
                    user=user
                )
                ttl_message = f" (auto-expires in {format_duration(rule.ttl_seconds)})"
                self.logger.info("rule_scheduled_for_deletion", rule_name=rule.name, ttl_seconds=rule.ttl_seconds)

            # 3. Success
            log_entry.status = "SUCCESS"
            log_entry.details = f"Successfully deployed rule: {rule.name}{ttl_message}"
            log_entry.expires_at = rule.expires_at  # Track expiration in deployment log
            self.session.add(log_entry)

            audit_details = f"Deployed rule {rule.name} ({actual_rule_id})"
            if rule.is_temporary:
                audit_details += f" [TEMPORARY - expires in {format_duration(rule.ttl_seconds or 0)}]"

            audit = AuditEntry(
                action="DEPLOY_RULE",
                user=user,
                details=audit_details,
                resource_id=actual_rule_id,
                snapshot_id=snapshot_id,
                risk_level=getattr(rule, 'risk_level', 'low')
            )
            self.session.add(audit)
            await self.session.commit()

            self.logger.info("rule_deployed", rule_name=rule.name, is_temporary=rule.is_temporary, rule_id=actual_rule_id)
            success_message = f"Rule deployed successfully{ttl_message}."
            return True, success_message

        except Exception as e:
            # Provide clear error message distinguishing between different failure types
            error_str = str(e)
            if "not connected" in error_str.lower() or "connection" in error_str.lower():
                msg = f"Backend connection error: {error_str}"
            elif "api error" in error_str.lower():
                msg = f"Backend API error: {error_str}"
            else:
                msg = f"Deployment failed: {error_str}"

            self.logger.error("deployment_failed", error=error_str, rule_name=rule.name)
            log_entry.status = "FAILURE"
            log_entry.details = msg
            self.session.add(log_entry)
            await self.session.commit()
            return False, msg

    async def delete_rule(self, rule: PolicyRule, user: str = "system") -> tuple[bool, str]:
        """
        Delete a rule from the firewall.

        Returns:
            Tuple of (success: bool, message: str).
        """
        rule_id = rule.id or "unknown"
        log_entry = DeploymentLog(
            status="PENDING",
            details=f"Deleting rule: {rule.name}",
            rule_id=rule_id,
        )
        self.session.add(log_entry)
        await self.session.commit()
        await self.session.refresh(log_entry)

        try:
            # 1. Find and delete the rule
            self.logger.info("deleting_rule", rule_name=rule.name)

            # First list all rules to find a match
            existing_rules = await self.backend.list_rules()
            rule_to_delete = None

            for existing in existing_rules:
                # Match by key attributes (flexible matching - None values are wildcards)
                matches = True

                # Action must always match
                if existing.action != rule.action:
                    matches = False

                # Direction - match if specified
                if rule.direction and existing.direction != rule.direction:
                    matches = False

                # Protocol - match if specified
                if rule.protocol and rule.protocol.value != "ANY" and existing.protocol != rule.protocol:
                    matches = False

                # Source - match if specified
                if rule.source and existing.source != rule.source:
                    matches = False

                # Destination - match if specified
                if rule.destination and existing.destination != rule.destination:
                    matches = False

                # Port - match if specified
                if rule.port and existing.port != rule.port:
                    matches = False

                if matches:
                    rule_to_delete = existing
                    break

            if not rule_to_delete:
                msg = f"Rule not found: {rule.name}"
                log_entry.status = "FAILURE"
                log_entry.details = msg
                self.session.add(log_entry)
                await self.session.commit()
                return False, msg

            # Delete the rule
            success = await self.backend.delete_rule(rule_to_delete.id)

            if success:
                # 2. Success
                log_entry.status = "SUCCESS"
                log_entry.details = f"Successfully deleted rule: {rule.name}"
                self.session.add(log_entry)

                audit = AuditEntry(
                    action="DELETE_RULE",
                    user=user,
                    details=f"Deleted rule {rule.name} ({rule.id})",
                    resource_id=rule_id,
                )
                self.session.add(audit)
                await self.session.commit()

                self.logger.info("rule_deleted", rule_name=rule.name)
                return True, "Rule deleted successfully."
            else:
                msg = f"Failed to delete rule: {rule.name}"
                log_entry.status = "FAILURE"
                log_entry.details = msg
                self.session.add(log_entry)
                await self.session.commit()
                return False, msg

        except Exception as e:
            self.logger.error("deletion_failed", error=str(e))
            log_entry.status = "FAILURE"
            log_entry.details = str(e)
            self.session.add(log_entry)
            await self.session.commit()
            return False, str(e)

    async def rollback(self, steps: int = 1, user: str = "system") -> bool:
        """Rollback the last N changes."""
        try:
            success = await self.backend.rollback(steps)

            audit = AuditEntry(
                action="ROLLBACK",
                user=user,
                details=f"Rolled back {steps} steps. Success: {success}",
            )
            self.session.add(audit)
            await self.session.commit()

            return success
        except Exception as e:
            self.logger.error("rollback_failed", error=str(e))
            return False

    async def _delete_rule_by_id(self, rule_id: str, user: str = "system") -> bool:
        """
        Delete a rule by ID (used by scheduler for automatic deletion).
        
        Args:
            rule_id: ID of the rule to delete
            user: User initiating the deletion (typically "system" for auto-delete)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.logger.info("auto_deleting_rule", rule_id=rule_id, user=user)

            # Get the rule from backend
            existing_rules = await self.backend.list_rules()
            rule_to_delete = None

            for existing in existing_rules:
                if existing.id == rule_id:
                    rule_to_delete = existing
                    break

            if not rule_to_delete:
                self.logger.warning("rule_not_found_for_deletion", rule_id=rule_id)
                return False

            # Delete the rule
            success = await self.backend.delete_rule(rule_id)

            if success:
                # Log the automatic deletion
                log_entry = DeploymentLog(
                    status="SUCCESS",
                    details=f"Auto-deleted expired rule: {rule_to_delete.name}",
                    rule_id=rule_id,
                )
                self.session.add(log_entry)

                audit = AuditEntry(
                    action="AUTO_DELETE_RULE",
                    user=user,
                    details=f"Automatically deleted expired rule {rule_to_delete.name} (TTL expired)",
                    resource_id=rule_id,
                )
                self.session.add(audit)
                await self.session.commit()

                self.logger.info("rule_auto_deleted", rule_name=rule_to_delete.name, rule_id=rule_id)
                return True
            else:
                self.logger.error("auto_deletion_failed", rule_id=rule_id)
                return False

        except Exception as e:
            self.logger.error("auto_deletion_error", rule_id=rule_id, error=str(e))
            return False
