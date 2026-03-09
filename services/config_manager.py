"""Configuration preset management for AFO.

Provides preset loading, validation, and application with rollback support.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.base import FirewallBackend
from backend.models import Action, Direction, PolicyRule, Protocol
from backend.safety import SafetyEnforcer
from db.models import ActiveConfig, AuditEntry

logger = logging.getLogger(__name__)


class PresetRule(BaseModel):
    """Single rule in a preset configuration."""

    name: str
    description: str
    action: Action
    direction: Direction
    protocol: Protocol
    port: Optional[int] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    priority: int = 100
    enabled: bool = True


class PresetConfig(BaseModel):
    """Complete preset configuration."""

    name: str
    version: str = "1.0"
    description: str
    metadata: dict = Field(default_factory=dict)
    rules: list[PresetRule]
    geoip_blocks: list[str] = Field(default_factory=list)
    domain_blocks: list[str] = Field(default_factory=list)

    @field_validator("rules")
    @classmethod
    def validate_rules(cls, rules):
        if not rules:
            raise ValueError("Preset must contain at least one rule")
        return rules


class ConfigManager:
    """Manages preset configurations."""

    def __init__(
        self,
        backend: FirewallBackend,
        session: AsyncSession,
        safety_enforcer: SafetyEnforcer,
    ):
        self.backend = backend
        self.session = session
        self.safety_enforcer = safety_enforcer
        self._lock = asyncio.Lock()
        self.preset_dir = Path("config/presets")

    def _load_preset_file(self, preset_path: Path) -> PresetConfig:
        """Load and validate a preset from JSON file."""
        try:
            with open(preset_path, "r") as f:
                data = json.load(f)
            return PresetConfig(**data)
        except Exception as e:
            logger.error(f"Failed to load preset {preset_path}: {e}")
            raise ValueError(f"Invalid preset file: {e}")

    async def list_presets(self) -> list[PresetConfig]:
        """List all available preset configurations."""
        presets = []
        if not self.preset_dir.exists():
            logger.warning(f"Preset directory not found: {self.preset_dir}")
            return presets

        for json_file in self.preset_dir.glob("*.json"):
            try:
                preset = self._load_preset_file(json_file)
                presets.append(preset)
            except Exception as e:
                logger.error(f"Failed to load preset {json_file}: {e}")
                continue

        return presets

    async def get_preset(self, name: str) -> PresetConfig:
        """Get a specific preset by name."""
        preset_path = self.preset_dir / f"{name}.json"
        if not preset_path.exists():
            raise ValueError(f"Preset not found: {name}")
        return self._load_preset_file(preset_path)

    def _validate_preset_safety(self, preset: PresetConfig) -> list[str]:
        """Validate preset against safety policy."""
        violations = []
        for rule_data in preset.rules:
            rule = PolicyRule(
                name=rule_data.name,
                description=rule_data.description,
                action=rule_data.action,
                direction=rule_data.direction,
                protocol=rule_data.protocol,
                port=rule_data.port,
                source=rule_data.source,
                destination=rule_data.destination,
                priority=rule_data.priority,
                enabled=rule_data.enabled,
            )
            if not self.safety_enforcer.is_safe(rule):
                violations.append(f"Rule '{rule.name}' violates safety policy")
        return violations

    async def preview_preset(self, name: str) -> dict:
        """Preview what would happen if preset is applied (dry-run)."""
        preset = await self.get_preset(name)
        current_rules = await self.backend.list_rules()

        # Validate safety
        safety_violations = self._validate_preset_safety(preset)

        return {
            "preset_name": preset.name,
            "preset_version": preset.version,
            "rules_to_add": len(preset.rules),
            "rules_to_delete": len(current_rules),
            "geoip_blocks": len(preset.geoip_blocks),
            "domain_blocks": len(preset.domain_blocks),
            "safety_violations": safety_violations,
            "has_violations": len(safety_violations) > 0,
        }

    async def apply_preset(self, name: str, user: str = "system") -> tuple[bool, str]:
        """Apply a preset configuration with validation and rollback.

        Steps:
        1. Load and validate preset
        2. Validate ALL rules against safety policy FIRST
        3. Create snapshot of current rules (for rollback)
        4. Deploy new rules (staged)
        5. Only after ALL succeed, delete old rules
        6. Store active config in database
        7. Create audit entry
        """
        async with self._lock:
            try:
                # 1. Load preset
                preset = await self.get_preset(name)
                logger.info(f"Applying preset: {preset.name} v{preset.version}")

                # 2. Validate safety BEFORE any changes
                violations = self._validate_preset_safety(preset)
                if violations:
                    error_msg = f"Safety violations: {', '.join(violations)}"
                    logger.error(error_msg)
                    return False, error_msg

                # 3. Create snapshot BEFORE any changes
                from services.snapshot import get_snapshot_manager

                snapshot_manager = get_snapshot_manager(self.backend, self.session)
                snapshot_id = await snapshot_manager.create_snapshot(
                    user=user, description=f"Before applying preset: {preset.name}"
                )
                logger.info(f"Created snapshot {snapshot_id}")

                # 4. Get current rules
                current_rules = await self.backend.list_rules()
                logger.info(f"Current rules: {len(current_rules)}")

                # 5. Deploy new rules (but don't delete old ones yet)
                from services.firewall import FirewallService

                firewall_service = FirewallService(self.backend, self.session)
                deployed_ids = []

                for rule_data in preset.rules:
                    rule = PolicyRule(
                        name=rule_data.name,
                        description=rule_data.description,
                        action=rule_data.action,
                        direction=rule_data.direction,
                        protocol=rule_data.protocol,
                        port=rule_data.port,
                        source=rule_data.source,
                        destination=rule_data.destination,
                        priority=rule_data.priority,
                        enabled=rule_data.enabled,
                    )

                    success, msg = await firewall_service.deploy_rule(rule, user=user)
                    if not success:
                        # Rollback: delete newly deployed rules
                        logger.error(f"Deployment failed: {msg}")
                        await self._cleanup_deployed_rules(deployed_ids)
                        return False, f"Deployment failed: {msg}"

                    if rule.id:
                        deployed_ids.append(rule.id)

                logger.info(f"Deployed {len(deployed_ids)} new rules")

                # 6. Apply GeoIP blocks
                if preset.geoip_blocks:
                    try:
                        from services.geoip import get_geoip_service

                        geoip = get_geoip_service(self.backend, self.session)
                        for country_code in preset.geoip_blocks:
                            await geoip.create_country_rule(country_code, Action.DROP)
                        logger.info(f"Applied {len(preset.geoip_blocks)} GeoIP blocks")
                    except Exception as e:
                        logger.warning(f"Failed to apply GeoIP blocks: {e}")

                # 7. Apply domain blocks
                if preset.domain_blocks:
                    try:
                        from services.domain_blocker import get_domain_blocker

                        blocker = get_domain_blocker(self.backend, self.session)
                        for domain in preset.domain_blocks:
                            await blocker.block_domain(domain)
                        logger.info(f"Applied {len(preset.domain_blocks)} domain blocks")
                    except Exception as e:
                        logger.warning(f"Failed to apply domain blocks: {e}")

                # 8. Only after ALL new rules succeed, delete old rules
                for old_rule in current_rules:
                    try:
                        await self.backend.delete_rule(old_rule.id)
                    except Exception as e:
                        logger.warning(f"Failed to delete old rule {old_rule.id}: {e}")

                logger.info(f"Deleted {len(current_rules)} old rules")

                # 9. Store active config in database
                active_config = ActiveConfig(
                    preset_name=preset.name,
                    preset_version=preset.version,
                    applied_by=user,
                    snapshot_id=snapshot_id,
                    rule_ids=json.dumps(deployed_ids),
                )
                self.session.add(active_config)
                await self.session.commit()

                # 10. Create audit entry
                audit = AuditEntry(
                    action="APPLY_CONFIG",
                    user=user,
                    details=f"Applied preset: {preset.name} v{preset.version}",
                    snapshot_id=snapshot_id,
                    risk_level="medium",
                )
                self.session.add(audit)
                await self.session.commit()

                logger.info(f"Successfully applied preset: {preset.name}")
                return True, f"Successfully applied preset: {preset.name}"

            except Exception as e:
                logger.error(f"Error applying preset: {e}", exc_info=True)
                return False, f"Error: {e}"

    async def _cleanup_deployed_rules(self, rule_ids: list[str]) -> None:
        """Clean up rules that were deployed during a failed preset application."""
        logger.info(f"Cleaning up {len(rule_ids)} deployed rules")
        for rule_id in rule_ids:
            try:
                await self.backend.delete_rule(rule_id)
            except Exception as e:
                logger.warning(f"Failed to cleanup rule {rule_id}: {e}")

    async def remove_preset(self, user: str = "system") -> tuple[bool, str]:
        """Remove active preset configuration."""
        async with self._lock:
            try:
                # Get active config
                result = await self.session.execute(
                    select(ActiveConfig).order_by(ActiveConfig.applied_at.desc())
                )
                active = result.scalars().first()

                if not active:
                    return False, "No active preset configuration"

                logger.info(f"Removing preset: {active.preset_name}")

                # Create snapshot
                from services.snapshot import get_snapshot_manager

                snapshot_manager = get_snapshot_manager(self.backend, self.session)
                snapshot_id = await snapshot_manager.create_snapshot(
                    user=user,
                    description=f"Before removing preset: {active.preset_name}",
                )

                # Delete all rules using bulk operations
                from services.bulk_operations import get_bulk_operations

                bulk_ops = get_bulk_operations(self.backend)
                result = await bulk_ops.delete_all_rules(confirm=True)

                if not result.success:
                    error_msg = f"Failed to remove rules: {', '.join(result.errors)}"
                    logger.error(error_msg)
                    return False, error_msg

                # Clear active config
                await self.session.delete(active)
                await self.session.commit()

                # Create audit entry
                audit = AuditEntry(
                    action="REMOVE_CONFIG",
                    user=user,
                    details=f"Removed preset: {active.preset_name}",
                    snapshot_id=snapshot_id,
                    risk_level="high",
                )
                self.session.add(audit)
                await self.session.commit()

                logger.info(f"Successfully removed preset: {active.preset_name}")
                return True, f"Removed preset: {active.preset_name}"

            except Exception as e:
                logger.error(f"Error removing preset: {e}", exc_info=True)
                return False, f"Error: {e}"

    async def get_active_preset(self) -> Optional[ActiveConfig]:
        """Get currently active preset."""
        result = await self.session.execute(
            select(ActiveConfig).order_by(ActiveConfig.applied_at.desc())
        )
        return result.scalars().first()


def get_config_manager(
    backend: FirewallBackend, session: AsyncSession, safety_enforcer: SafetyEnforcer
) -> ConfigManager:
    """Factory function to create ConfigManager instance."""
    return ConfigManager(backend, session, safety_enforcer)
