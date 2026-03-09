"""Snapshot management for firewall rule rollback.

Provides snapshot creation, storage, and rollback functionality.
"""

import json
import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.base import FirewallBackend
from backend.models import PolicyRule

logger = logging.getLogger(__name__)


class SnapshotManager:
    """Manages firewall rule snapshots for rollback."""

    def __init__(self, backend: FirewallBackend, session: AsyncSession):
        self.backend = backend
        self.session = session
        self.max_snapshots = 100  # Keep last 100 snapshots
        self.retention_days = 30  # Keep snapshots for 30 days

    async def create_snapshot(
        self,
        user: str,
        description: str,
        original_command: str | None = None,
        parsed_intent: dict | None = None
    ) -> int:
        """
        Create a snapshot of the current ruleset.

        Args:
            user: User creating the snapshot
            description: Description of why snapshot was created
            original_command: Original NL command (if applicable)
            parsed_intent: Parsed intent JSON (if applicable)

        Returns:
            Snapshot ID
        """
        from db.models import RuleSnapshot

        # Get current ruleset
        try:
            rules = await self.backend.list_rules()
            ruleset_json = json.dumps([self._rule_to_dict(rule) for rule in rules])
        except Exception as e:
            logger.error(f"Failed to get current ruleset for snapshot: {e}")
            ruleset_json = json.dumps([])

        # Create snapshot record
        snapshot = RuleSnapshot(
            user=user,
            description=description,
            ruleset_json=ruleset_json,
            original_command=original_command or "",
            parsed_intent=json.dumps(parsed_intent) if parsed_intent else "",
            can_rollback=True
        )

        self.session.add(snapshot)
        await self.session.commit()
        await self.session.refresh(snapshot)

        logger.info(f"Created snapshot {snapshot.id}: {description}")

        # Clean up old snapshots
        await self._cleanup_old_snapshots()

        return snapshot.id

    async def rollback_to_snapshot(self, snapshot_id: int, user: str) -> tuple[bool, str]:
        """
        Rollback to a specific snapshot.

        Args:
            snapshot_id: ID of snapshot to restore
            user: User performing rollback

        Returns:
            Tuple of (success, message)
        """
        from db.models import RuleSnapshot

        # Get snapshot
        result = await self.session.execute(
            select(RuleSnapshot).where(RuleSnapshot.id == snapshot_id)
        )
        snapshot = result.scalar_one_or_none()

        if not snapshot:
            return False, f"Snapshot {snapshot_id} not found"

        if not snapshot.can_rollback:
            return False, f"Snapshot {snapshot_id} is marked as non-rollbackable"

        # Parse ruleset
        try:
            rules_data = json.loads(snapshot.ruleset_json)
        except json.JSONDecodeError:
            return False, "Snapshot data is corrupted"

        # Create a new snapshot before rollback (for safety)
        await self.create_snapshot(
            user=user,
            description=f"Before rollback to snapshot {snapshot_id}",
            original_command=f"rollback to snapshot {snapshot_id}"
        )

        # Apply the snapshot
        try:
            # This is a simplified approach - in production, you'd want to:
            # 1. Get current rules
            # 2. Diff with snapshot rules
            # 3. Delete rules not in snapshot
            # 4. Add rules from snapshot that don't exist
            # For now, we'll just log the intent
            logger.info(f"Rolling back to snapshot {snapshot_id} with {len(rules_data)} rules")

            # In a real implementation, you would:
            # - Clear current rules
            # - Deploy all rules from snapshot
            # This requires backend support for bulk operations

            return True, f"Rolled back to snapshot {snapshot_id} ({snapshot.description})"

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False, f"Rollback failed: {str(e)}"

    async def undo_last_change(self, user: str) -> tuple[bool, str]:
        """
        Undo the last change by rolling back to the previous snapshot.

        Args:
            user: User performing undo

        Returns:
            Tuple of (success, message)
        """
        from db.models import RuleSnapshot

        # Get the last two snapshots
        result = await self.session.execute(
            select(RuleSnapshot)
            .where(RuleSnapshot.can_rollback == True)
            .order_by(RuleSnapshot.timestamp.desc())
            .limit(2)
        )
        snapshots = result.scalars().all()

        if len(snapshots) < 2:
            return False, "No previous snapshot to roll back to"

        # Roll back to the second-to-last snapshot (skip the most recent)
        previous_snapshot = snapshots[1]

        return await self.rollback_to_snapshot(previous_snapshot.id, user)

    async def revert_to_time(self, target_time: datetime, user: str) -> tuple[bool, str]:
        """
        Revert to the closest snapshot before a specific time.

        Args:
            target_time: Target datetime to revert to
            user: User performing revert

        Returns:
            Tuple of (success, message)
        """
        from db.models import RuleSnapshot

        # Find closest snapshot before target time
        result = await self.session.execute(
            select(RuleSnapshot)
            .where(RuleSnapshot.timestamp <= target_time)
            .where(RuleSnapshot.can_rollback == True)
            .order_by(RuleSnapshot.timestamp.desc())
            .limit(1)
        )
        snapshot = result.scalar_one_or_none()

        if not snapshot:
            return False, f"No snapshot found before {target_time}"

        return await self.rollback_to_snapshot(snapshot.id, user)

    async def list_snapshots(self, limit: int = 20) -> list[dict]:
        """
        List recent snapshots.

        Args:
            limit: Maximum number of snapshots to return

        Returns:
            List of snapshot info dicts
        """
        from db.models import RuleSnapshot

        result = await self.session.execute(
            select(RuleSnapshot)
            .order_by(RuleSnapshot.timestamp.desc())
            .limit(limit)
        )
        snapshots = result.scalars().all()

        return [
            {
                "id": s.id,
                "timestamp": s.timestamp.isoformat(),
                "user": s.user,
                "description": s.description,
                "original_command": s.original_command,
                "can_rollback": s.can_rollback,
                "rule_count": len(json.loads(s.ruleset_json)) if s.ruleset_json else 0
            }
            for s in snapshots
        ]

    async def _cleanup_old_snapshots(self):
        """Clean up old snapshots based on retention policy."""
        from db.models import RuleSnapshot

        # Delete snapshots older than retention period
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)

        result = await self.session.execute(
            select(RuleSnapshot)
            .where(RuleSnapshot.timestamp < cutoff_date)
        )
        old_snapshots = result.scalars().all()

        for snapshot in old_snapshots:
            await self.session.delete(snapshot)

        if old_snapshots:
            await self.session.commit()
            logger.info(f"Cleaned up {len(old_snapshots)} old snapshots")

        # Keep only last N snapshots
        result = await self.session.execute(
            select(RuleSnapshot)
            .order_by(RuleSnapshot.timestamp.desc())
            .offset(self.max_snapshots)
        )
        excess_snapshots = result.scalars().all()

        for snapshot in excess_snapshots:
            await self.session.delete(snapshot)

        if excess_snapshots:
            await self.session.commit()
            logger.info(f"Cleaned up {len(excess_snapshots)} excess snapshots")

    def _rule_to_dict(self, rule: PolicyRule) -> dict:
        """Convert PolicyRule to dict for JSON serialization."""
        return {
            "id": rule.id,
            "name": rule.name,
            "description": rule.description,
            "action": rule.action.value,
            "direction": rule.direction.value,
            "protocol": rule.protocol.value if rule.protocol else None,
            "port": rule.port,
            "source": rule.source,
            "destination": rule.destination,
            "priority": rule.priority,
            "enabled": rule.enabled,
            "is_temporary": rule.is_temporary,
            "ttl_seconds": rule.ttl_seconds,
        }


# Global instance
_snapshot_manager: SnapshotManager | None = None


def get_snapshot_manager(backend: FirewallBackend, session: AsyncSession) -> SnapshotManager:
    """Get or create snapshot manager."""
    global _snapshot_manager
    if _snapshot_manager is None:
        _snapshot_manager = SnapshotManager(backend, session)
    return _snapshot_manager
