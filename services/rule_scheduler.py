"""
Rule Scheduler Service for AFO

Handles automatic expiration and cleanup of temporary firewall rules.
"""

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

MAX_DELETE_RETRIES = 3


@dataclass
class ScheduledRule:
    """Represents a rule with an expiration time."""
    rule_id: str
    rule_name: str
    expires_at: datetime
    delete_callback: Callable
    user: str = "system"
    created_at: datetime = field(default_factory=datetime.now)
    consecutive_failures: int = 0  # evict after MAX_DELETE_RETRIES

    @property
    def remaining_seconds(self) -> float:
        """Get remaining time in seconds."""
        remaining = (self.expires_at - datetime.now()).total_seconds()
        return max(0, remaining)

    @property
    def is_expired(self) -> bool:
        """Check if the rule has expired."""
        return datetime.now() >= self.expires_at

    @property
    def remaining_formatted(self) -> str:
        """Get remaining time as a formatted string."""
        remaining = self.remaining_seconds
        if remaining <= 0:
            return "Expired"

        hours = int(remaining // 3600)
        minutes = int((remaining % 3600) // 60)
        seconds = int(remaining % 60)

        if hours > 0:
            return f"{hours}h {minutes}m"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"


class RuleScheduler:
    """
    Scheduler for managing temporary firewall rules with TTL.
    
    Automatically deletes rules when they expire.
    """

    def __init__(self, check_interval: int = 30):
        """
        Initialize the scheduler.
        
        Args:
            check_interval: How often to check for expired rules (seconds)
        """
        self.scheduled_rules: dict[str, ScheduledRule] = {}
        self.check_interval = check_interval
        self._running = False
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    async def start(self):
        """Start the scheduler background task."""
        if self._running:
            logger.warning("Scheduler already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._scheduler_loop())
        logger.info(f"Rule scheduler started (check interval: {self.check_interval}s)")

    async def stop(self):
        """Stop the scheduler."""
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Rule scheduler stopped")

    async def _scheduler_loop(self):
        """Main scheduler loop that checks for expired rules."""
        while self._running:
            try:
                await self._check_expired_rules()
                await asyncio.sleep(self.check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                await asyncio.sleep(self.check_interval)

    async def _check_expired_rules(self):
        """Check and delete expired rules."""
        async with self._lock:
            expired_rules = [
                rule for rule in self.scheduled_rules.values()
                if rule.is_expired
            ]

            for rule in expired_rules:
                logger.info(f"Rule '{rule.rule_name}' (ID: {rule.rule_id}) has expired. Deleting...")
                try:
                    # Call the delete callback
                    await rule.delete_callback(rule.rule_id, rule.user)

                    # Remove from scheduled rules on success
                    del self.scheduled_rules[rule.rule_id]
                    logger.info(f"Successfully deleted expired rule '{rule.rule_name}'")

                except Exception as e:
                    rule.consecutive_failures += 1
                    logger.error(
                        f"Failed to delete expired rule '{rule.rule_name}' "
                        f"(attempt {rule.consecutive_failures}/{MAX_DELETE_RETRIES}): {e}"
                    )
                    if rule.consecutive_failures >= MAX_DELETE_RETRIES:
                        # Evict to prevent infinite retry storm; rule may still be
                        # active on OPNsense — operator must clean up manually.
                        del self.scheduled_rules[rule.rule_id]
                        logger.error(
                            f"EVICTED '{rule.rule_name}' after {MAX_DELETE_RETRIES} failed attempts. "
                            f"Rule may still be active on OPNsense — manual cleanup required."
                        )

    async def schedule_rule(
        self,
        rule_id: str,
        rule_name: str,
        ttl_seconds: int,
        delete_callback: Callable,
        user: str = "system"
    ) -> ScheduledRule:
        """
        Schedule a rule for automatic deletion.
        
        Args:
            rule_id: Unique identifier for the rule
            rule_name: Human-readable name of the rule
            ttl_seconds: Time-to-live in seconds
            delete_callback: Async function to call for deletion (rule_id, user) -> bool
            user: User who created the rule
            
        Returns:
            ScheduledRule object
        """
        expires_at = datetime.now() + timedelta(seconds=ttl_seconds)

        scheduled_rule = ScheduledRule(
            rule_id=rule_id,
            rule_name=rule_name,
            expires_at=expires_at,
            delete_callback=delete_callback,
            user=user
        )

        async with self._lock:
            self.scheduled_rules[rule_id] = scheduled_rule

        logger.info(
            f"Scheduled rule '{rule_name}' (ID: {rule_id}) "
            f"for deletion in {ttl_seconds}s at {expires_at}"
        )

        return scheduled_rule

    async def cancel_scheduled_deletion(self, rule_id: str) -> bool:
        """
        Cancel a scheduled deletion (make rule permanent).
        
        Args:
            rule_id: ID of the rule to cancel
            
        Returns:
            True if cancelled, False if not found
        """
        async with self._lock:
            if rule_id in self.scheduled_rules:
                rule = self.scheduled_rules.pop(rule_id)
                logger.info(f"Cancelled scheduled deletion for rule '{rule.rule_name}'")
                return True
            return False

    def get_scheduled_rule(self, rule_id: str) -> ScheduledRule | None:
        """Get a scheduled rule by ID."""
        return self.scheduled_rules.get(rule_id)

    def get_all_scheduled(self) -> list[ScheduledRule]:
        """Get all scheduled rules."""
        return list(self.scheduled_rules.values())

    def get_expiring_soon(self, within_seconds: int = 300) -> list[ScheduledRule]:
        """
        Get rules expiring within the specified time window.
        
        Args:
            within_seconds: Time window in seconds (default: 5 minutes)
            
        Returns:
            List of ScheduledRule objects expiring soon
        """
        cutoff = datetime.now() + timedelta(seconds=within_seconds)
        return [
            rule for rule in self.scheduled_rules.values()
            if rule.expires_at <= cutoff and not rule.is_expired
        ]


# Global scheduler instance
_scheduler: RuleScheduler | None = None


def get_scheduler() -> RuleScheduler:
    """Get or create the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = RuleScheduler()
    return _scheduler


def parse_duration(text: str) -> int | None:
    """
    Parse a duration string into seconds.
    
    Supports formats like:
    - "10 minutes"
    - "1 hour"
    - "30s"
    - "2h 30m"
    - "24 hours"
    
    Args:
        text: Duration string
        
    Returns:
        Duration in seconds, or None if parsing fails
    """
    import re

    text = text.lower().strip()
    total_seconds = 0

    # Use non-overlapping patterns - more specific first
    # Hours: match "hours", "hour", "hrs", "hr", but not "h" if it's a single letter
    hour_patterns = [
        r'(\d+)\s*hours?',
        r'(\d+)\s*hrs?',
    ]
    hours_found = 0
    for pattern in hour_patterns:
        matches = re.findall(pattern, text)
        if matches:
            hours_found = max(hours_found, max(int(m) for m in matches))

    # Check for single letter 'h' if no hours found yet
    if hours_found == 0:
        h_matches = re.findall(r'(\d+)\s*h\b', text)
        if h_matches:
            hours_found = max(int(m) for m in h_matches)

    total_seconds += hours_found * 3600

    # Minutes: match "minutes", "minute", "min", "mins", but not "m" alone
    minute_patterns = [
        r'(\d+)\s*minutes?',
        r'(\d+)\s*mins?',
    ]
    minutes_found = 0
    for pattern in minute_patterns:
        matches = re.findall(pattern, text)
        if matches:
            minutes_found = max(minutes_found, max(int(m) for m in matches))

    # Check for single letter 'm' if no minutes found yet
    if minutes_found == 0:
        m_matches = re.findall(r'(\d+)\s*m\b', text)
        if m_matches:
            minutes_found = max(int(m) for m in m_matches)

    total_seconds += minutes_found * 60

    # Seconds: match "seconds", "sec", "secs", or "s"
    second_patterns = [
        r'(\d+)\s*seconds?',
        r'(\d+)\s*secs?',
    ]
    seconds_found = 0
    for pattern in second_patterns:
        matches = re.findall(pattern, text)
        if matches:
            seconds_found = max(seconds_found, max(int(m) for m in matches))

    # Check for single letter 's' if no seconds found yet
    if seconds_found == 0:
        s_matches = re.findall(r'(\d+)\s*s\b', text)
        if s_matches:
            seconds_found = max(int(m) for m in s_matches)

    total_seconds += seconds_found

    return total_seconds if total_seconds > 0 else None


def format_duration(seconds: int) -> str:
    """Format seconds into a human-readable duration string."""
    if seconds < 60:
        return f"{seconds} second{'s' if seconds != 1 else ''}"
    elif seconds < 3600:
        minutes = seconds // 60
        remaining = seconds % 60
        if remaining == 0:
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        return f"{minutes}m {remaining}s"
    elif seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        if minutes == 0:
            return f"{hours} hour{'s' if hours != 1 else ''}"
        return f"{hours}h {minutes}m"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        if hours == 0:
            return f"{days} day{'s' if days != 1 else ''}"
        return f"{days}d {hours}h"
