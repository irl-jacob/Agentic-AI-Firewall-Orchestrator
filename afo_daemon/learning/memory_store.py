"""Memory Store - Persistent storage for patterns and insights."""

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import ConfigInsight, LearnedPattern, LearningMetric, PatternFeedback

logger = structlog.get_logger()


class MemoryStore:
    """Manages persistent storage and retrieval of learned patterns and insights."""

    def __init__(self, session: AsyncSession):
        self.session = session
        # In-memory cache with 5-minute TTL
        self._pattern_cache: dict[int, tuple[LearnedPattern, datetime]] = {}
        self._cache_ttl = timedelta(minutes=5)

    async def store_pattern(
        self,
        pattern_type: str,
        signature: str,
        confidence: float,
        source_ips: list[str] | None = None,
        ports: list[int] | None = None,
        protocols: list[str] | None = None,
        context: dict[str, Any] | None = None,
        llm_analysis: str | None = None,
    ) -> LearnedPattern:
        """Store a newly discovered pattern."""
        pattern = LearnedPattern(
            pattern_type=pattern_type,
            signature=signature,
            confidence=confidence,
            evidence_count=1,
            source_ips=json.dumps(source_ips or []),
            ports=json.dumps(ports or []),
            protocols=json.dumps(protocols or []),
            context=json.dumps(context or {}),
            llm_analysis=llm_analysis,
            validated=False,
            active=True,
        )

        self.session.add(pattern)
        await self.session.commit()
        await self.session.refresh(pattern)

        logger.info(
            "pattern_stored",
            pattern_id=pattern.id,
            pattern_type=pattern_type,
            confidence=confidence,
        )

        return pattern

    async def get_patterns(
        self,
        pattern_type: str | None = None,
        min_confidence: float = 0.0,
        active_only: bool = True,
        limit: int = 100,
    ) -> list[LearnedPattern]:
        """Retrieve patterns matching criteria."""
        query = select(LearnedPattern)

        if pattern_type:
            query = query.where(LearnedPattern.pattern_type == pattern_type)
        if active_only:
            query = query.where(LearnedPattern.active == True)  # noqa: E712
        if min_confidence > 0.0:
            query = query.where(LearnedPattern.confidence >= min_confidence)

        query = query.order_by(LearnedPattern.confidence.desc()).limit(limit)

        result = await self.session.execute(query)
        patterns = result.scalars().all()

        return list(patterns)

    async def update_pattern_evidence(
        self,
        pattern_id: int,
        additional_ips: list[str] | None = None,
        additional_ports: list[int] | None = None,
        increment_count: int = 1,
    ) -> LearnedPattern | None:
        """Update pattern with new evidence."""
        result = await self.session.execute(
            select(LearnedPattern).where(LearnedPattern.id == pattern_id)
        )
        pattern = result.scalar_one_or_none()

        if not pattern:
            logger.warning("pattern_not_found", pattern_id=pattern_id)
            return None

        # Update evidence count
        pattern.evidence_count += increment_count
        pattern.last_seen = datetime.now(timezone.utc)

        # Merge IPs
        if additional_ips:
            existing_ips = json.loads(pattern.source_ips)
            merged_ips = list(set(existing_ips + additional_ips))
            pattern.source_ips = json.dumps(merged_ips)

        # Merge ports
        if additional_ports:
            existing_ports = json.loads(pattern.ports)
            merged_ports = list(set(existing_ports + additional_ports))
            pattern.ports = json.dumps(merged_ports)

        # Increase confidence with more evidence (logarithmic growth)
        if pattern.evidence_count > 1:
            confidence_boost = min(0.1, 0.02 * (pattern.evidence_count - 1))
            pattern.confidence = min(1.0, pattern.confidence + confidence_boost)

        await self.session.commit()
        await self.session.refresh(pattern)

        logger.info(
            "pattern_updated",
            pattern_id=pattern_id,
            evidence_count=pattern.evidence_count,
            confidence=pattern.confidence,
        )

        return pattern

    async def store_insight(
        self,
        insight_type: str,
        description: str,
        recommendation: dict[str, Any],
        reasoning: str,
        confidence: float,
        based_on_patterns: list[int],
        impact_assessment: dict[str, Any] | None = None,
    ) -> ConfigInsight:
        """Store a configuration insight."""
        insight = ConfigInsight(
            insight_type=insight_type,
            description=description,
            recommendation=json.dumps(recommendation),
            reasoning=reasoning,
            confidence=confidence,
            based_on_patterns=json.dumps(based_on_patterns),
            applied=False,
            user_approved=False,
            safety_validated=False,
            impact_assessment=json.dumps(impact_assessment or {}),
        )

        self.session.add(insight)
        await self.session.commit()
        await self.session.refresh(insight)

        logger.info(
            "insight_stored",
            insight_id=insight.id,
            insight_type=insight_type,
            confidence=confidence,
        )

        return insight

    async def get_pending_insights(
        self,
        min_confidence: float = 0.0,
        insight_type: str | None = None,
        limit: int = 50,
    ) -> list[ConfigInsight]:
        """Retrieve insights that haven't been applied yet."""
        query = select(ConfigInsight).where(ConfigInsight.applied == False)  # noqa: E712

        if insight_type:
            query = query.where(ConfigInsight.insight_type == insight_type)
        if min_confidence > 0.0:
            query = query.where(ConfigInsight.confidence >= min_confidence)

        query = query.order_by(ConfigInsight.confidence.desc()).limit(limit)

        result = await self.session.execute(query)
        insights = result.scalars().all()

        return list(insights)

    async def mark_insight_applied(
        self,
        insight_id: int,
        success: bool = True,
    ) -> ConfigInsight | None:
        """Mark an insight as applied."""
        result = await self.session.execute(
            select(ConfigInsight).where(ConfigInsight.id == insight_id)
        )
        insight = result.scalar_one_or_none()

        if not insight:
            logger.warning("insight_not_found", insight_id=insight_id)
            return None

        insight.applied = success
        if success:
            insight.applied_at = datetime.now(timezone.utc)

        await self.session.commit()
        await self.session.refresh(insight)

        logger.info(
            "insight_marked_applied",
            insight_id=insight_id,
            success=success,
        )

        return insight

    async def record_metric(
        self,
        metric_type: str,
        value: float,
        context: dict[str, Any] | None = None,
        pattern_id: int | None = None,
        insight_id: int | None = None,
    ) -> LearningMetric:
        """Record a learning system metric."""
        metric = LearningMetric(
            metric_type=metric_type,
            value=value,
            context=json.dumps(context or {}),
            pattern_id=pattern_id,
            insight_id=insight_id,
        )

        self.session.add(metric)
        await self.session.commit()
        await self.session.refresh(metric)

        return metric

    async def get_pattern_performance(
        self,
        pattern_id: int,
    ) -> dict[str, Any]:
        """Get performance metrics for a pattern."""
        # Get feedback
        feedback_result = await self.session.execute(
            select(PatternFeedback).where(PatternFeedback.pattern_id == pattern_id)
        )
        feedbacks = feedback_result.scalars().all()

        # Calculate statistics
        total_feedback = len(feedbacks)
        if total_feedback == 0:
            return {
                "pattern_id": pattern_id,
                "total_feedback": 0,
                "accuracy": None,
                "feedback_breakdown": {},
            }

        feedback_counts = {}
        for fb in feedbacks:
            feedback_counts[fb.feedback_type] = feedback_counts.get(fb.feedback_type, 0) + 1

        correct = feedback_counts.get("correct", 0)
        accuracy = correct / total_feedback if total_feedback > 0 else 0.0

        return {
            "pattern_id": pattern_id,
            "total_feedback": total_feedback,
            "accuracy": accuracy,
            "feedback_breakdown": feedback_counts,
        }

    async def store_feedback(
        self,
        feedback_type: str,
        user: str,
        pattern_id: int | None = None,
        insight_id: int | None = None,
        comment: str | None = None,
    ) -> PatternFeedback:
        """Store user feedback on a pattern or insight."""
        feedback = PatternFeedback(
            pattern_id=pattern_id,
            insight_id=insight_id,
            feedback_type=feedback_type,
            user=user,
            comment=comment,
        )

        self.session.add(feedback)
        await self.session.commit()
        await self.session.refresh(feedback)

        logger.info(
            "feedback_stored",
            feedback_type=feedback_type,
            pattern_id=pattern_id,
            insight_id=insight_id,
        )

        return feedback

    def _is_cache_valid(self, cached_time: datetime) -> bool:
        """Check if cached entry is still valid."""
        return datetime.now(timezone.utc) - cached_time < self._cache_ttl

    async def get_pattern_by_id(self, pattern_id: int) -> LearnedPattern | None:
        """Get a pattern by ID with caching."""
        # Check cache first
        if pattern_id in self._pattern_cache:
            pattern, cached_time = self._pattern_cache[pattern_id]
            if self._is_cache_valid(cached_time):
                return pattern

        # Fetch from database
        result = await self.session.execute(
            select(LearnedPattern).where(LearnedPattern.id == pattern_id)
        )
        pattern = result.scalar_one_or_none()

        if pattern:
            self._pattern_cache[pattern_id] = (pattern, datetime.now(timezone.utc))

        return pattern
