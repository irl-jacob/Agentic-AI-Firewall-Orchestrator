"""Learning MCP Tools - Expose learning system to LLMs."""

import json
from typing import Any

import structlog

from db.database import get_session
from services.learning_service import get_learning_service

logger = structlog.get_logger()


async def list_learned_patterns(
    pattern_type: str | None = None,
    min_confidence: float = 0.0,
    limit: int = 50,
) -> dict[str, Any]:
    """
    List discovered patterns from the learning system.

    Args:
        pattern_type: Filter by type (attack/false_positive/legitimate/anomaly)
        min_confidence: Minimum confidence threshold (0.0-1.0)
        limit: Maximum number of patterns to return

    Returns:
        Dictionary with patterns list and metadata
    """
    try:
        async for session in get_session():
            from afo_daemon.learning.memory_store import MemoryStore

            memory = MemoryStore(session)
            patterns = await memory.get_patterns(
                pattern_type=pattern_type,
                min_confidence=min_confidence,
                active_only=True,
                limit=limit,
            )

            result = []
            for pattern in patterns:
                result.append({
                    "id": pattern.id,
                    "type": pattern.pattern_type,
                    "signature": pattern.signature,
                    "confidence": pattern.confidence,
                    "evidence_count": pattern.evidence_count,
                    "first_seen": pattern.first_seen.isoformat(),
                    "last_seen": pattern.last_seen.isoformat(),
                    "source_ips": json.loads(pattern.source_ips),
                    "ports": json.loads(pattern.ports),
                    "protocols": json.loads(pattern.protocols),
                    "validated": pattern.validated,
                    "active": pattern.active,
                })

            return {
                "success": True,
                "patterns": result,
                "total": len(result),
                "filters": {
                    "pattern_type": pattern_type,
                    "min_confidence": min_confidence,
                },
            }

    except Exception as e:
        logger.error("list_patterns_failed", error=str(e))
        return {
            "success": False,
            "error": str(e),
            "patterns": [],
        }


async def get_pattern_details(pattern_id: int) -> dict[str, Any]:
    """
    Get detailed information about a specific pattern.

    Args:
        pattern_id: ID of the pattern to retrieve

    Returns:
        Dictionary with pattern details and performance metrics
    """
    try:
        async for session in get_session():
            from afo_daemon.learning.memory_store import MemoryStore

            memory = MemoryStore(session)
            pattern = await memory.get_pattern_by_id(pattern_id)

            if not pattern:
                return {
                    "success": False,
                    "error": f"Pattern {pattern_id} not found",
                }

            # Get performance metrics
            performance = await memory.get_pattern_performance(pattern_id)

            return {
                "success": True,
                "pattern": {
                    "id": pattern.id,
                    "type": pattern.pattern_type,
                    "signature": pattern.signature,
                    "confidence": pattern.confidence,
                    "evidence_count": pattern.evidence_count,
                    "first_seen": pattern.first_seen.isoformat(),
                    "last_seen": pattern.last_seen.isoformat(),
                    "source_ips": json.loads(pattern.source_ips),
                    "ports": json.loads(pattern.ports),
                    "protocols": json.loads(pattern.protocols),
                    "context": json.loads(pattern.context),
                    "llm_analysis": pattern.llm_analysis,
                    "validated": pattern.validated,
                    "active": pattern.active,
                },
                "performance": performance,
            }

    except Exception as e:
        logger.error("get_pattern_details_failed", error=str(e))
        return {
            "success": False,
            "error": str(e),
        }


async def validate_pattern(
    pattern_id: int,
    is_correct: bool,
    user: str = "system",
    comment: str | None = None,
) -> dict[str, Any]:
    """
    Provide feedback on a pattern's accuracy.

    Args:
        pattern_id: ID of the pattern to validate
        is_correct: Whether the pattern is correct
        user: User providing feedback
        comment: Optional comment

    Returns:
        Success status
    """
    try:
        async for session in get_session():
            from afo_daemon.learning.memory_store import MemoryStore
            from sqlalchemy import select
            from db.models import LearnedPattern

            memory = MemoryStore(session)

            # Get pattern
            result = await session.execute(
                select(LearnedPattern).where(LearnedPattern.id == pattern_id)
            )
            pattern = result.scalar_one_or_none()

            if not pattern:
                return {
                    "success": False,
                    "error": f"Pattern {pattern_id} not found",
                }

            # Store feedback
            feedback_type = "correct" if is_correct else "incorrect"
            await memory.store_feedback(
                feedback_type=feedback_type,
                user=user,
                pattern_id=pattern_id,
                comment=comment,
            )

            # Update pattern validation status
            pattern.validated = is_correct
            if not is_correct:
                # Deactivate incorrect patterns
                pattern.active = False
                pattern.confidence = max(0.0, pattern.confidence - 0.3)

            session.add(pattern)
            await session.commit()

            logger.info(
                "pattern_validated",
                pattern_id=pattern_id,
                is_correct=is_correct,
                user=user,
            )

            return {
                "success": True,
                "pattern_id": pattern_id,
                "validated": is_correct,
                "message": f"Pattern marked as {'correct' if is_correct else 'incorrect'}",
            }

    except Exception as e:
        logger.error("validate_pattern_failed", error=str(e))
        return {
            "success": False,
            "error": str(e),
        }


async def list_insights(
    insight_type: str | None = None,
    min_confidence: float = 0.0,
    pending_only: bool = True,
    limit: int = 50,
) -> dict[str, Any]:
    """
    List configuration insights from the learning system.

    Args:
        insight_type: Filter by type (rule_suggestion/preset_adjustment/signature_update)
        min_confidence: Minimum confidence threshold
        pending_only: Only show unapplied insights
        limit: Maximum number to return

    Returns:
        Dictionary with insights list
    """
    try:
        async for session in get_session():
            from afo_daemon.learning.memory_store import MemoryStore

            memory = MemoryStore(session)

            if pending_only:
                insights = await memory.get_pending_insights(
                    min_confidence=min_confidence,
                    insight_type=insight_type,
                    limit=limit,
                )
            else:
                from sqlalchemy import select
                from db.models import ConfigInsight

                query = select(ConfigInsight)
                if insight_type:
                    query = query.where(ConfigInsight.insight_type == insight_type)
                if min_confidence > 0.0:
                    query = query.where(ConfigInsight.confidence >= min_confidence)
                query = query.order_by(ConfigInsight.confidence.desc()).limit(limit)

                result = await session.execute(query)
                insights = result.scalars().all()

            result_list = []
            for insight in insights:
                result_list.append({
                    "id": insight.id,
                    "type": insight.insight_type,
                    "description": insight.description,
                    "recommendation": json.loads(insight.recommendation),
                    "reasoning": insight.reasoning,
                    "confidence": insight.confidence,
                    "based_on_patterns": json.loads(insight.based_on_patterns),
                    "created_at": insight.created_at.isoformat(),
                    "applied": insight.applied,
                    "applied_at": insight.applied_at.isoformat() if insight.applied_at else None,
                    "user_approved": insight.user_approved,
                    "safety_validated": insight.safety_validated,
                })

            return {
                "success": True,
                "insights": result_list,
                "total": len(result_list),
                "filters": {
                    "insight_type": insight_type,
                    "min_confidence": min_confidence,
                    "pending_only": pending_only,
                },
            }

    except Exception as e:
        logger.error("list_insights_failed", error=str(e))
        return {
            "success": False,
            "error": str(e),
            "insights": [],
        }


async def approve_insight(
    insight_id: int,
    user: str = "system",
) -> dict[str, Any]:
    """
    Approve an insight for application.

    Args:
        insight_id: ID of the insight to approve
        user: User approving the insight

    Returns:
        Success status and application result
    """
    try:
        async for session in get_session():
            from services.firewall import FirewallService
            from backend.nftables import NftablesBackend

            # Get firewall service
            backend = NftablesBackend()
            firewall_service = FirewallService(backend, session)

            # Get learning service
            learning_service = get_learning_service(session, firewall_service)

            # Approve and potentially apply
            success = await learning_service.config_advisor.approve_insight(
                insight_id=insight_id,
                user=user,
            )

            return {
                "success": success,
                "insight_id": insight_id,
                "message": "Insight approved" if success else "Approval failed",
            }

    except Exception as e:
        logger.error("approve_insight_failed", error=str(e))
        return {
            "success": False,
            "error": str(e),
        }


async def reject_insight(
    insight_id: int,
    user: str = "system",
    reason: str = "User rejected",
) -> dict[str, Any]:
    """
    Reject an insight and provide feedback.

    Args:
        insight_id: ID of the insight to reject
        user: User rejecting the insight
        reason: Reason for rejection

    Returns:
        Success status
    """
    try:
        async for session in get_session():
            from services.firewall import FirewallService
            from backend.nftables import NftablesBackend

            # Get firewall service
            backend = NftablesBackend()
            firewall_service = FirewallService(backend, session)

            # Get learning service
            learning_service = get_learning_service(session, firewall_service)

            # Reject
            success = await learning_service.config_advisor.reject_insight(
                insight_id=insight_id,
                user=user,
                reason=reason,
            )

            return {
                "success": success,
                "insight_id": insight_id,
                "message": "Insight rejected",
            }

    except Exception as e:
        logger.error("reject_insight_failed", error=str(e))
        return {
            "success": False,
            "error": str(e),
        }


async def get_learning_metrics(days: int = 7) -> dict[str, Any]:
    """
    Get learning system performance metrics.

    Args:
        days: Number of days to look back

    Returns:
        Dictionary with metrics and statistics
    """
    try:
        from datetime import datetime, timedelta, timezone

        async for session in get_session():
            from sqlalchemy import select, func
            from db.models import LearningMetric, LearnedPattern, ConfigInsight

            cutoff = datetime.now(timezone.utc) - timedelta(days=days)

            # Get metric counts
            metric_result = await session.execute(
                select(
                    LearningMetric.metric_type,
                    func.count(LearningMetric.id).label("count"),
                )
                .where(LearningMetric.timestamp >= cutoff)
                .group_by(LearningMetric.metric_type)
            )
            metrics = {row[0]: row[1] for row in metric_result}

            # Get pattern counts
            pattern_result = await session.execute(
                select(
                    LearnedPattern.pattern_type,
                    func.count(LearnedPattern.id).label("count"),
                )
                .where(LearnedPattern.first_seen >= cutoff)
                .group_by(LearnedPattern.pattern_type)
            )
            patterns = {row[0]: row[1] for row in pattern_result}

            # Get insight counts
            insight_result = await session.execute(
                select(
                    ConfigInsight.insight_type,
                    func.count(ConfigInsight.id).label("count"),
                )
                .where(ConfigInsight.created_at >= cutoff)
                .group_by(ConfigInsight.insight_type)
            )
            insights = {row[0]: row[1] for row in insight_result}

            # Get applied insights count
            applied_result = await session.execute(
                select(func.count(ConfigInsight.id))
                .where(ConfigInsight.created_at >= cutoff)
                .where(ConfigInsight.applied == True)  # noqa: E712
            )
            applied_count = applied_result.scalar() or 0

            return {
                "success": True,
                "period_days": days,
                "metrics": metrics,
                "patterns_detected": patterns,
                "insights_generated": insights,
                "insights_applied": applied_count,
            }

    except Exception as e:
        logger.error("get_learning_metrics_failed", error=str(e))
        return {
            "success": False,
            "error": str(e),
        }
