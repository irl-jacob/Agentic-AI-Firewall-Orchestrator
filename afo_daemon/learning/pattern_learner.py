"""Pattern Learner - Analyzes logs to extract patterns."""

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from afo_daemon.learning.memory_store import MemoryStore
from db.models import AuditEntry, DeploymentLog

logger = structlog.get_logger()


class PatternLearner:
    """Analyzes historical data to discover patterns."""

    def __init__(self, session: AsyncSession, memory_store: MemoryStore):
        self.session = session
        self.memory = memory_store
        self.min_observations = 3  # Minimum occurrences to consider a pattern
        self.time_window = timedelta(hours=1)  # Time window for clustering

    async def analyze_deployment_history(
        self,
        days: int = 7,
    ) -> list[dict[str, Any]]:
        """Find patterns in auto-block deployments."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # Get deployment logs
        result = await self.session.execute(
            select(DeploymentLog)
            .where(DeploymentLog.timestamp >= cutoff)
            .order_by(DeploymentLog.timestamp.desc())
        )
        deployments = result.scalars().all()

        logger.info(
            "analyzing_deployments",
            total_deployments=len(deployments),
            days=days,
        )

        # Group by IP address (extract from details)
        ip_groups = defaultdict(list)
        for deployment in deployments:
            # Try to extract IP from details
            ip = self._extract_ip_from_details(deployment.details)
            if ip:
                ip_groups[ip].append(deployment)

        # Identify repeat offenders (IPs blocked multiple times)
        patterns = []
        for ip, deploys in ip_groups.items():
            if len(deploys) >= self.min_observations:
                # This is a pattern - repeat offender
                confidence = min(0.95, 0.6 + (len(deploys) * 0.05))

                # Extract ports and protocols
                ports = set()
                protocols = set()
                for deploy in deploys:
                    port = self._extract_port_from_details(deploy.details)
                    proto = self._extract_protocol_from_details(deploy.details)
                    if port:
                        ports.add(port)
                    if proto:
                        protocols.add(proto)

                pattern = {
                    "type": "attack",
                    "signature": f"repeat_offender_{ip}",
                    "confidence": confidence,
                    "source_ips": [ip],
                    "ports": list(ports),
                    "protocols": list(protocols),
                    "evidence_count": len(deploys),
                    "context": {
                        "first_seen": deploys[-1].timestamp.isoformat(),
                        "last_seen": deploys[0].timestamp.isoformat(),
                        "deployment_ids": [d.rule_id for d in deploys],
                    },
                }
                patterns.append(pattern)

                # Store in memory
                await self.memory.store_pattern(
                    pattern_type="attack",
                    signature=pattern["signature"],
                    confidence=confidence,
                    source_ips=[ip],
                    ports=list(ports),
                    protocols=list(protocols),
                    context=pattern["context"],
                )

                logger.info(
                    "repeat_offender_detected",
                    ip=ip,
                    occurrences=len(deploys),
                    confidence=confidence,
                )

        return patterns

    async def analyze_audit_trail(
        self,
        days: int = 7,
    ) -> list[dict[str, Any]]:
        """Identify frequently modified rules and user patterns."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        result = await self.session.execute(
            select(AuditEntry)
            .where(AuditEntry.timestamp >= cutoff)
            .order_by(AuditEntry.timestamp.desc())
        )
        entries = result.scalars().all()

        logger.info(
            "analyzing_audit_trail",
            total_entries=len(entries),
            days=days,
        )

        # Group by resource_id to find frequently modified rules
        resource_groups = defaultdict(list)
        for entry in entries:
            if entry.resource_id:
                resource_groups[entry.resource_id].append(entry)

        patterns = []
        for resource_id, audit_entries in resource_groups.items():
            if len(audit_entries) >= self.min_observations:
                # Frequently modified resource
                actions = [e.action for e in audit_entries]

                pattern = {
                    "type": "anomaly",
                    "signature": f"frequent_modification_{resource_id}",
                    "confidence": 0.7,
                    "context": {
                        "resource_id": resource_id,
                        "modification_count": len(audit_entries),
                        "actions": actions,
                        "users": list(set(e.user for e in audit_entries)),
                    },
                }
                patterns.append(pattern)

                logger.info(
                    "frequent_modification_detected",
                    resource_id=resource_id,
                    modifications=len(audit_entries),
                )

        return patterns

    async def detect_false_positives(
        self,
        days: int = 7,
    ) -> list[dict[str, Any]]:
        """Find rules deployed then quickly deleted (<1 hour)."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # Get all deployments
        deploy_result = await self.session.execute(
            select(DeploymentLog)
            .where(DeploymentLog.timestamp >= cutoff)
            .order_by(DeploymentLog.timestamp.asc())
        )
        deployments = list(deploy_result.scalars().all())

        # Get all audit entries (looking for deletions/rollbacks)
        audit_result = await self.session.execute(
            select(AuditEntry)
            .where(AuditEntry.timestamp >= cutoff)
            .where(AuditEntry.action.in_(["rollback", "delete_rule", "rule_deleted"]))
            .order_by(AuditEntry.timestamp.asc())
        )
        deletions = list(audit_result.scalars().all())

        logger.info(
            "detecting_false_positives",
            deployments=len(deployments),
            deletions=len(deletions),
        )

        patterns = []
        for deployment in deployments:
            # Find if this rule was deleted within 1 hour
            for deletion in deletions:
                if deletion.resource_id == deployment.rule_id:
                    time_diff = deletion.timestamp - deployment.timestamp
                    if timedelta(0) < time_diff < timedelta(hours=1):
                        # False positive detected
                        ip = self._extract_ip_from_details(deployment.details)

                        pattern = {
                            "type": "false_positive",
                            "signature": f"false_positive_{ip or deployment.rule_id}",
                            "confidence": 0.8,
                            "source_ips": [ip] if ip else [],
                            "context": {
                                "rule_id": deployment.rule_id,
                                "deployed_at": deployment.timestamp.isoformat(),
                                "deleted_at": deletion.timestamp.isoformat(),
                                "time_to_deletion": str(time_diff),
                                "deletion_reason": deletion.details,
                            },
                        }
                        patterns.append(pattern)

                        # Store in memory
                        await self.memory.store_pattern(
                            pattern_type="false_positive",
                            signature=pattern["signature"],
                            confidence=0.8,
                            source_ips=[ip] if ip else [],
                            context=pattern["context"],
                        )

                        logger.info(
                            "false_positive_detected",
                            rule_id=deployment.rule_id,
                            time_to_deletion=str(time_diff),
                        )

        return patterns

    async def detect_legitimate_traffic(
        self,
        days: int = 7,
    ) -> list[dict[str, Any]]:
        """Identify user-approved patterns from audit trail."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # Look for user confirmations and approvals
        result = await self.session.execute(
            select(AuditEntry)
            .where(AuditEntry.timestamp >= cutoff)
            .where(AuditEntry.user_confirmed == True)  # noqa: E712
            .order_by(AuditEntry.timestamp.desc())
        )
        approvals = result.scalars().all()

        logger.info(
            "detecting_legitimate_traffic",
            approvals=len(approvals),
        )

        patterns = []
        for approval in approvals:
            # Extract details from approved action
            ip = self._extract_ip_from_details(approval.details)
            if ip:
                pattern = {
                    "type": "legitimate",
                    "signature": f"legitimate_{ip}",
                    "confidence": 0.9,
                    "source_ips": [ip],
                    "context": {
                        "approved_by": approval.user,
                        "approved_at": approval.timestamp.isoformat(),
                        "action": approval.action,
                        "details": approval.details,
                    },
                }
                patterns.append(pattern)

                # Store in memory
                await self.memory.store_pattern(
                    pattern_type="legitimate",
                    signature=pattern["signature"],
                    confidence=0.9,
                    source_ips=[ip],
                    context=pattern["context"],
                )

                logger.info(
                    "legitimate_traffic_detected",
                    ip=ip,
                    approved_by=approval.user,
                )

        return patterns

    def _extract_ip_from_details(self, details: str) -> str | None:
        """Extract IP address from deployment/audit details."""
        import re

        # Try to find IP address pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, details)
        if match:
            return match.group(0)

        # Try JSON parsing
        try:
            data = json.loads(details)
            if isinstance(data, dict):
                # Common keys for IP addresses
                for key in ["ip", "source_ip", "src_ip", "address", "host"]:
                    if key in data:
                        return str(data[key])
        except (json.JSONDecodeError, ValueError):
            pass

        return None

    def _extract_port_from_details(self, details: str) -> int | None:
        """Extract port number from details."""
        try:
            data = json.loads(details)
            if isinstance(data, dict):
                for key in ["port", "dport", "destination_port", "dst_port"]:
                    if key in data:
                        return int(data[key])
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

        return None

    def _extract_protocol_from_details(self, details: str) -> str | None:
        """Extract protocol from details."""
        try:
            data = json.loads(details)
            if isinstance(data, dict):
                for key in ["protocol", "proto"]:
                    if key in data:
                        return str(data[key])
        except (json.JSONDecodeError, ValueError):
            pass

        # Check for common protocols in text
        details_lower = details.lower()
        for proto in ["tcp", "udp", "icmp", "ssh", "http", "https"]:
            if proto in details_lower:
                return proto

        return None

    async def run_full_analysis(self, days: int = 7) -> dict[str, Any]:
        """Run all pattern detection analyses."""
        logger.info("starting_full_pattern_analysis", days=days)

        attack_patterns = await self.analyze_deployment_history(days)
        audit_patterns = await self.analyze_audit_trail(days)
        false_positives = await self.detect_false_positives(days)
        legitimate = await self.detect_legitimate_traffic(days)

        total_patterns = (
            len(attack_patterns)
            + len(audit_patterns)
            + len(false_positives)
            + len(legitimate)
        )

        # Record metric
        await self.memory.record_metric(
            metric_type="pattern_detected",
            value=float(total_patterns),
            context={
                "attack_patterns": len(attack_patterns),
                "audit_patterns": len(audit_patterns),
                "false_positives": len(false_positives),
                "legitimate": len(legitimate),
            },
        )

        logger.info(
            "pattern_analysis_complete",
            total_patterns=total_patterns,
            attack=len(attack_patterns),
            audit=len(audit_patterns),
            false_positives=len(false_positives),
            legitimate=len(legitimate),
        )

        return {
            "total_patterns": total_patterns,
            "attack_patterns": attack_patterns,
            "audit_patterns": audit_patterns,
            "false_positives": false_positives,
            "legitimate": legitimate,
        }
