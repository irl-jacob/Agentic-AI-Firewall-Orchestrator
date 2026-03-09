"""Learning Service - Orchestrates the learning system."""

import asyncio
import os
from datetime import timedelta
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from afo_daemon.learning.config_advisor import ConfigAdvisor
from afo_daemon.learning.insight_engine import InsightEngine
from afo_daemon.learning.memory_store import MemoryStore
from afo_daemon.learning.pattern_learner import PatternLearner

logger = structlog.get_logger()


class LearningService:
    """High-level orchestration of the learning system."""

    def __init__(
        self,
        session: AsyncSession,
        firewall_service: Any,  # FirewallService
    ):
        self.session = session
        self.firewall_service = firewall_service

        # Initialize components
        self.memory = MemoryStore(session)
        self.pattern_learner = PatternLearner(session, self.memory)
        self.insight_engine = InsightEngine(self.memory)
        self.config_advisor = ConfigAdvisor(session, self.memory, firewall_service)

        # Configuration
        self.cycle_interval = int(os.getenv("LEARNING_CYCLE_INTERVAL", "3600"))
        self.history_days = int(os.getenv("LEARNING_HISTORY_DAYS", "7"))
        self.min_observations = int(os.getenv("LEARNING_MIN_OBSERVATIONS", "3"))

        self.running = False
        self._task: asyncio.Task | None = None

        logger.info(
            "learning_service_initialized",
            cycle_interval=self.cycle_interval,
            history_days=self.history_days,
            min_observations=self.min_observations,
        )

    async def start(self) -> None:
        """Start the learning service background loop."""
        if self.running:
            logger.warning("learning_service_already_running")
            return

        self.running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("learning_service_started")

    async def stop(self) -> None:
        """Stop the learning service."""
        if not self.running:
            return

        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        logger.info("learning_service_stopped")

    async def _run_loop(self) -> None:
        """Main learning loop."""
        while self.running:
            try:
                logger.info("learning_cycle_starting")
                await self.run_learning_cycle()
                logger.info(
                    "learning_cycle_complete",
                    next_cycle_in=self.cycle_interval,
                )

                # Wait for next cycle
                await asyncio.sleep(self.cycle_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    "learning_cycle_error",
                    error=str(e),
                    error_type=type(e).__name__,
                )
                # Backoff on error
                await asyncio.sleep(60)

    async def run_learning_cycle(self) -> dict[str, Any]:
        """
        Execute one complete learning cycle.

        Steps:
        1. Analyze deployment history
        2. Analyze audit trail
        3. Detect false positives
        4. Detect legitimate traffic
        5. Generate insights from patterns
        6. Process insights based on mode
        """
        cycle_start = asyncio.get_event_loop().time()

        try:
            # Step 1-4: Pattern detection
            logger.info("learning_step_1_pattern_detection")
            pattern_results = await self.pattern_learner.run_full_analysis(
                days=self.history_days
            )

            total_patterns = pattern_results["total_patterns"]
            logger.info(
                "pattern_detection_complete",
                total_patterns=total_patterns,
                attack=len(pattern_results["attack_patterns"]),
                false_positives=len(pattern_results["false_positives"]),
                legitimate=len(pattern_results["legitimate"]),
            )

            # Step 5: Generate insights
            if total_patterns > 0:
                logger.info("learning_step_2_insight_generation")
                insights = await self.insight_engine.generate_insights_from_patterns()
                logger.info("insights_generated", count=len(insights))
            else:
                logger.info("no_patterns_for_insights")
                insights = []

            # Step 6: Process insights
            if insights:
                logger.info("learning_step_3_config_application")
                application_results = await self.config_advisor.process_insights()
                logger.info(
                    "insights_processed",
                    applied=application_results["applied"],
                    skipped=application_results["skipped"],
                    failed=application_results["failed"],
                )
            else:
                application_results = {
                    "processed": 0,
                    "applied": 0,
                    "skipped": 0,
                    "failed": 0,
                }

            cycle_duration = asyncio.get_event_loop().time() - cycle_start

            # Record cycle metrics
            await self.memory.record_metric(
                metric_type="learning_cycle_complete",
                value=cycle_duration,
                context={
                    "patterns_detected": total_patterns,
                    "insights_generated": len(insights),
                    "insights_applied": application_results["applied"],
                    "duration_seconds": cycle_duration,
                },
            )

            return {
                "success": True,
                "duration": cycle_duration,
                "patterns": pattern_results,
                "insights_generated": len(insights),
                "insights_applied": application_results["applied"],
                "insights_skipped": application_results["skipped"],
                "insights_failed": application_results["failed"],
            }

        except Exception as e:
            logger.error(
                "learning_cycle_failed",
                error=str(e),
                error_type=type(e).__name__,
            )
            return {
                "success": False,
                "error": str(e),
            }

    async def get_status(self) -> dict[str, Any]:
        """Get current learning service status."""
        # Get pattern counts
        all_patterns = await self.memory.get_patterns(active_only=True, limit=1000)
        pattern_counts = {}
        for pattern in all_patterns:
            pattern_counts[pattern.pattern_type] = (
                pattern_counts.get(pattern.pattern_type, 0) + 1
            )

        # Get pending insights
        pending_insights = await self.memory.get_pending_insights()

        return {
            "running": self.running,
            "cycle_interval": self.cycle_interval,
            "history_days": self.history_days,
            "mode": self.config_advisor.mode,
            "patterns": {
                "total": len(all_patterns),
                "by_type": pattern_counts,
            },
            "pending_insights": len(pending_insights),
        }

    async def trigger_manual_cycle(self) -> dict[str, Any]:
        """Manually trigger a learning cycle (for testing/debugging)."""
        logger.info("manual_learning_cycle_triggered")
        return await self.run_learning_cycle()


# Singleton instance management
_learning_service: LearningService | None = None


def get_learning_service(
    session: AsyncSession,
    firewall_service: Any,
) -> LearningService:
    """Get or create the learning service singleton."""
    global _learning_service
    if _learning_service is None:
        _learning_service = LearningService(session, firewall_service)
    return _learning_service
