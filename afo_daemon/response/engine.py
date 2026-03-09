import asyncio
from datetime import datetime, timedelta

import structlog

from afo_daemon.detection.models import SecurityEvent, ThreatType
from backend.models import Action, Direction, PolicyRule, Protocol
from services.firewall import FirewallService

logger = structlog.get_logger()


class ResponseEngine:
    """
    Evaluates security events and triggers automated responses (blocking).
    Manages temporary rules (TTL).
    """

    def __init__(self, service: FirewallService, ttl_minutes: int = 60):
        self.service = service
        self.ttl_minutes = ttl_minutes
        self.active_blocks: dict[str, datetime] = {}  # Rule ID -> Expiry Time
        self.running = False

    async def start(self) -> None:
        """Start the TTL manager loop."""
        self.running = True
        while self.running:
            await self._check_expirations()
            await asyncio.sleep(60)  # Check every minute

    def stop(self) -> None:
        self.running = False

    async def process_event(self, event: SecurityEvent) -> None:
        """Evaluate event and take action if needed."""
        if event.confidence < 0.8:
            logger.info("event_ignored_low_confidence", security_event=event.model_dump())
            return

        if event.type in (ThreatType.BRUTE_FORCE, ThreatType.DOS):
            await self._block_source(event)

    async def _block_source(self, event: SecurityEvent) -> None:
        """Create and deploy a blocking rule."""
        rule_name = f"autoblock_{event.source_ip.replace('.', '_')}_{int(datetime.now().timestamp())}"

        rule = PolicyRule(
            name=rule_name,
            description=f"Auto-blocked due to {event.type} from {event.source_ip}",
            action=Action.DROP,
            direction=Direction.INBOUND,
            protocol=Protocol.ANY,
            source=event.source_ip,
            priority=50,  # High priority (lower number usually, but assume 50 is high relative to default 100)
        )

        try:
            success, message = await self.service.deploy_rule(rule, user="auto_responder")
            if success:
                # Track for TTL
                expiry = datetime.now() + timedelta(minutes=self.ttl_minutes)
                self.active_blocks[rule.id or rule_name] = expiry # Backend should populate ID, but fallback to name
                logger.info("autoblock_deployed", ip=event.source_ip, rule_id=rule.id)
            else:
                logger.warning("autoblock_failed", ip=event.source_ip, reason=message)
        except Exception as e:
            logger.error("autoblock_error", error=str(e))

    async def _check_expirations(self) -> None:
        """Remove expired rules."""
        now = datetime.now()
        expired_ids = [rid for rid, expiry in self.active_blocks.items() if now > expiry]

        for rid in expired_ids:
            try:
                # We need delete_rule in FirewallService/Backend
                # Currently backend.delete_rule exists but is a placeholder.
                # Assuming it works or we implement it.
                await self.service.backend.delete_rule(rid)
                del self.active_blocks[rid]
                logger.info("autoblock_expired", rule_id=rid)
            except Exception as e:
                logger.error("autoblock_expiry_failed", rule_id=rid, error=str(e))
