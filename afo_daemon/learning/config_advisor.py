"""Config Advisor - Auto-applies learned configurations with safety checks."""

import json
import os
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from afo_daemon.learning.memory_store import MemoryStore
from backend.models import Action, Direction, PolicyRule, Protocol
from backend.safety import SafetyEnforcer
from db.models import ConfigInsight

logger = structlog.get_logger()


class ConfigAdvisor:
    """Processes insights and applies configuration changes safely."""

    def __init__(
        self,
        session: AsyncSession,
        memory_store: MemoryStore,
        firewall_service: Any,  # FirewallService
    ):
        self.session = session
        self.memory = memory_store
        self.firewall_service = firewall_service
        self.safety_enforcer = SafetyEnforcer()

        # Get configuration from environment
        self.mode = os.getenv("LEARNING_MODE", "monitor")
        self.auto_apply_threshold = float(
            os.getenv("LEARNING_AUTO_APPLY_THRESHOLD", "0.9")
        )
        self.confidence_threshold = float(
            os.getenv("LEARNING_CONFIDENCE_THRESHOLD", "0.7")
        )

        logger.info(
            "config_advisor_initialized",
            mode=self.mode,
            auto_apply_threshold=self.auto_apply_threshold,
            confidence_threshold=self.confidence_threshold,
        )

    async def process_insights(self) -> dict[str, Any]:
        """Main processing loop - applies insights based on mode."""
        # Get pending insights above confidence threshold
        insights = await self.memory.get_pending_insights(
            min_confidence=self.confidence_threshold
        )

        if not insights:
            logger.info("no_pending_insights")
            return {
                "processed": 0,
                "applied": 0,
                "skipped": 0,
                "failed": 0,
            }

        logger.info("processing_insights", total=len(insights), mode=self.mode)

        applied = 0
        skipped = 0
        failed = 0

        for insight in insights:
            # Validate safety first
            if not await self._validate_insight_safety(insight):
                logger.warning(
                    "insight_failed_safety",
                    insight_id=insight.id,
                    insight_type=insight.insight_type,
                )
                skipped += 1
                continue

            # Check mode and confidence
            should_apply = False

            if self.mode == "monitor":
                # Only log, don't apply
                logger.info(
                    "insight_monitor_mode",
                    insight_id=insight.id,
                    description=insight.description,
                    confidence=insight.confidence,
                )
                skipped += 1
                continue

            elif self.mode == "cautious":
                # Apply only very high confidence (>0.9)
                if insight.confidence >= self.auto_apply_threshold:
                    should_apply = True
                else:
                    logger.info(
                        "insight_below_threshold",
                        insight_id=insight.id,
                        confidence=insight.confidence,
                        threshold=self.auto_apply_threshold,
                    )
                    skipped += 1

            elif self.mode == "aggressive":
                # Apply high confidence (>0.7) with safety checks
                if insight.confidence >= self.confidence_threshold:
                    should_apply = True
                else:
                    skipped += 1

            elif self.mode == "manual":
                # Require user approval
                if insight.user_approved:
                    should_apply = True
                else:
                    logger.info(
                        "insight_requires_approval",
                        insight_id=insight.id,
                        description=insight.description,
                    )
                    skipped += 1

            if should_apply:
                success = await self._apply_insight(insight)
                if success:
                    applied += 1
                    await self.memory.record_metric(
                        metric_type="config_applied",
                        value=1.0,
                        insight_id=insight.id,
                        context={"insight_type": insight.insight_type},
                    )
                else:
                    failed += 1

        logger.info(
            "insights_processed",
            total=len(insights),
            applied=applied,
            skipped=skipped,
            failed=failed,
        )

        return {
            "processed": len(insights),
            "applied": applied,
            "skipped": skipped,
            "failed": failed,
        }

    async def _validate_insight_safety(self, insight: ConfigInsight) -> bool:
        """Validate insight against safety policies."""
        try:
            recommendation = json.loads(insight.recommendation)

            # For rule suggestions, validate the rule
            if insight.insight_type == "rule_suggestion":
                # Build a PolicyRule from recommendation
                rule = self._build_rule_from_recommendation(recommendation)
                if not rule:
                    logger.warning(
                        "invalid_rule_recommendation",
                        insight_id=insight.id,
                    )
                    return False

                # Check against safety enforcer
                if not self.safety_enforcer.is_safe(rule):
                    logger.warning(
                        "rule_blocked_by_safety",
                        insight_id=insight.id,
                        rule_name=rule.name,
                    )
                    return False

                # Additional check: no DROP ALL rules
                if (
                    rule.action in (Action.DROP, Action.REJECT)
                    and not rule.source
                    and not rule.destination
                    and not rule.port
                ):
                    logger.warning(
                        "drop_all_rule_rejected",
                        insight_id=insight.id,
                    )
                    return False

            # Mark as safety validated
            insight.safety_validated = True
            self.session.add(insight)
            await self.session.commit()

            return True

        except Exception as e:
            logger.error(
                "safety_validation_failed",
                insight_id=insight.id,
                error=str(e),
            )
            return False

    async def _apply_insight(self, insight: ConfigInsight) -> bool:
        """Apply an insight based on its type."""
        try:
            recommendation = json.loads(insight.recommendation)

            if insight.insight_type == "rule_suggestion":
                return await self._apply_rule_suggestion(insight, recommendation)

            elif insight.insight_type == "signature_update":
                return await self._apply_signature_update(insight, recommendation)

            elif insight.insight_type == "preset_adjustment":
                logger.info(
                    "preset_adjustment_not_implemented",
                    insight_id=insight.id,
                )
                # TODO: Implement preset adjustments in future
                return False

            else:
                logger.warning(
                    "unknown_insight_type",
                    insight_id=insight.id,
                    insight_type=insight.insight_type,
                )
                return False

        except Exception as e:
            logger.error(
                "insight_application_failed",
                insight_id=insight.id,
                error=str(e),
            )
            return False

    async def _apply_rule_suggestion(
        self,
        insight: ConfigInsight,
        recommendation: dict[str, Any],
    ) -> bool:
        """Apply a rule suggestion through FirewallService."""
        try:
            # Build PolicyRule from recommendation
            rule = self._build_rule_from_recommendation(recommendation)
            if not rule:
                logger.error(
                    "failed_to_build_rule",
                    insight_id=insight.id,
                )
                return False

            # Deploy through FirewallService
            success, message = await self.firewall_service.deploy_rule(
                rule=rule,
                user="learning_system",
            )

            if success:
                # Mark insight as applied
                await self.memory.mark_insight_applied(insight.id, success=True)

                logger.info(
                    "rule_suggestion_applied",
                    insight_id=insight.id,
                    rule_name=rule.name,
                    message=message,
                )
                return True
            else:
                logger.warning(
                    "rule_deployment_failed",
                    insight_id=insight.id,
                    message=message,
                )
                return False

        except Exception as e:
            logger.error(
                "rule_suggestion_application_failed",
                insight_id=insight.id,
                error=str(e),
            )
            return False

    async def _apply_signature_update(
        self,
        insight: ConfigInsight,
        recommendation: dict[str, Any],
    ) -> bool:
        """Apply a signature update to SignatureMatcher."""
        try:
            pattern = recommendation.get("pattern")
            signature_type = recommendation.get("signature_type", "regex")

            if not pattern:
                logger.error(
                    "missing_signature_pattern",
                    insight_id=insight.id,
                )
                return False

            # TODO: Integrate with SignatureMatcher to add new patterns
            # For now, just log the signature update
            logger.info(
                "signature_update_logged",
                insight_id=insight.id,
                pattern=pattern,
                signature_type=signature_type,
            )

            # Mark as applied
            await self.memory.mark_insight_applied(insight.id, success=True)

            # Note: Full implementation would update SignatureMatcher's pattern database
            # This requires extending SignatureMatcher to support dynamic pattern loading

            return True

        except Exception as e:
            logger.error(
                "signature_update_failed",
                insight_id=insight.id,
                error=str(e),
            )
            return False

    def _build_rule_from_recommendation(
        self,
        recommendation: dict[str, Any],
    ) -> PolicyRule | None:
        """Build a PolicyRule from a recommendation dict."""
        try:
            # Parse action
            action_str = recommendation.get("action", "block").upper()
            if action_str == "BLOCK":
                action = Action.DROP
            elif action_str == "ALLOW":
                action = Action.ACCEPT
            elif action_str == "REJECT":
                action = Action.REJECT
            else:
                action = Action.DROP

            # Parse protocol
            protocol_str = recommendation.get("protocol", "").upper()
            if protocol_str == "TCP":
                protocol = Protocol.TCP
            elif protocol_str == "UDP":
                protocol = Protocol.UDP
            elif protocol_str == "ICMP":
                protocol = Protocol.ICMP
            else:
                protocol = Protocol.ANY

            # Build rule
            source = recommendation.get("source")
            port = recommendation.get("port")
            reason = recommendation.get("reason", "Learned from patterns")

            rule = PolicyRule(
                name=f"learned_{source or 'rule'}",
                action=action,
                direction=Direction.INPUT,
                protocol=protocol,
                source=source,
                destination=None,
                port=port,
                description=reason,
            )

            return rule

        except Exception as e:
            logger.error(
                "rule_building_failed",
                error=str(e),
                recommendation=recommendation,
            )
            return None

    async def approve_insight(self, insight_id: int, user: str) -> bool:
        """Manually approve an insight for application."""
        from sqlalchemy import select

        result = await self.session.execute(
            select(ConfigInsight).where(ConfigInsight.id == insight_id)
        )
        insight = result.scalar_one_or_none()

        if not insight:
            logger.warning("insight_not_found", insight_id=insight_id)
            return False

        insight.user_approved = True
        self.session.add(insight)
        await self.session.commit()

        logger.info(
            "insight_approved",
            insight_id=insight_id,
            user=user,
        )

        # If in manual mode, apply immediately
        if self.mode == "manual":
            return await self._apply_insight(insight)

        return True

    async def reject_insight(self, insight_id: int, user: str, reason: str) -> bool:
        """Reject an insight and provide feedback."""
        # Store feedback
        await self.memory.store_feedback(
            feedback_type="incorrect",
            user=user,
            insight_id=insight_id,
            comment=reason,
        )

        # Mark as applied (but with failure) to remove from pending
        await self.memory.mark_insight_applied(insight_id, success=False)

        logger.info(
            "insight_rejected",
            insight_id=insight_id,
            user=user,
            reason=reason,
        )

        return True
