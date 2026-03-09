"""Rate limiting and auto-blocking service for AFO.

Monitors connection attempts and automatically blocks IPs that exceed
configured thresholds.
"""

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from backend.base import FirewallBackend
from backend.models import Action, Direction, PolicyRule, Protocol

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    max_requests_per_minute: int = 100
    max_requests_per_hour: int = 1000
    block_duration_seconds: int = 3600  # 1 hour
    whitelist: set[str] = field(default_factory=set)
    enabled: bool = True


@dataclass
class IPStats:
    """Statistics for an IP address."""
    ip: str
    request_count_minute: int = 0
    request_count_hour: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    blocked: bool = False
    blocked_at: datetime | None = None
    block_reason: str = ""


class RateLimiter:
    """Monitors and enforces rate limits on network traffic."""

    def __init__(self, backend: FirewallBackend, config: RateLimitConfig | None = None):
        self.backend = backend
        self.config = config or RateLimitConfig()
        self.ip_stats: dict[str, IPStats] = {}
        self.blocked_ips: set[str] = set()
        self._running = False
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    async def start(self):
        """Start the rate limiter monitoring loop."""
        if self._running:
            logger.warning("Rate limiter already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info("Rate limiter started")

    async def stop(self):
        """Stop the rate limiter."""
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Rate limiter stopped")

    async def record_request(self, ip: str, port: int | None = None, protocol: str = "TCP"):
        """
        Record a request from an IP address.

        Args:
            ip: Source IP address
            port: Destination port (optional)
            protocol: Protocol (TCP/UDP/etc)
        """
        if not self.config.enabled:
            return

        # Skip whitelisted IPs
        if ip in self.config.whitelist:
            return

        async with self._lock:
            # Get or create stats
            if ip not in self.ip_stats:
                self.ip_stats[ip] = IPStats(ip=ip)

            stats = self.ip_stats[ip]
            stats.request_count_minute += 1
            stats.request_count_hour += 1
            stats.last_seen = datetime.now()

            # Check thresholds
            if stats.request_count_minute > self.config.max_requests_per_minute:
                await self._auto_block(ip, f"Exceeded {self.config.max_requests_per_minute} req/min")
            elif stats.request_count_hour > self.config.max_requests_per_hour:
                await self._auto_block(ip, f"Exceeded {self.config.max_requests_per_hour} req/hour")

    async def _auto_block(self, ip: str, reason: str):
        """Automatically block an IP address."""
        if ip in self.blocked_ips:
            return  # Already blocked

        stats = self.ip_stats[ip]
        stats.blocked = True
        stats.blocked_at = datetime.now()
        stats.block_reason = reason

        # Create firewall rule
        rule = PolicyRule(
            id=f"autoblock_{ip.replace('.', '_')}",
            name=f"autoblock_{ip}",
            description=f"Auto-blocked: {reason}",
            action=Action.DROP,
            direction=Direction.INBOUND,
            protocol=Protocol.ANY,
            port=None,
            source=ip,
            destination=None,
            priority=1000,  # High priority
            enabled=True,
            ttl_seconds=self.config.block_duration_seconds,
            is_temporary=True
        )

        try:
            success = await self.backend.deploy_rule(rule)
            if success:
                self.blocked_ips.add(ip)
                logger.warning(f"Auto-blocked {ip}: {reason}")
                # TODO: Send alert to user
            else:
                logger.error(f"Failed to auto-block {ip}")
        except Exception as e:
            logger.error(f"Error auto-blocking {ip}: {e}")

    async def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                await asyncio.sleep(60)  # Check every minute

                async with self._lock:
                    now = datetime.now()

                    # Reset per-minute counters
                    for stats in self.ip_stats.values():
                        stats.request_count_minute = 0

                    # Reset per-hour counters (every hour)
                    if now.minute == 0:
                        for stats in self.ip_stats.values():
                            stats.request_count_hour = 0

                    # Unblock expired blocks
                    expired_blocks = []
                    for ip in self.blocked_ips:
                        stats = self.ip_stats.get(ip)
                        if stats and stats.blocked_at:
                            elapsed = (now - stats.blocked_at).total_seconds()
                            if elapsed >= self.config.block_duration_seconds:
                                expired_blocks.append(ip)

                    for ip in expired_blocks:
                        await self._unblock(ip)

                    # Clean up old stats (older than 24 hours)
                    cutoff = now - timedelta(hours=24)
                    old_ips = [
                        ip for ip, stats in self.ip_stats.items()
                        if stats.last_seen < cutoff and not stats.blocked
                    ]
                    for ip in old_ips:
                        del self.ip_stats[ip]

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in rate limiter monitor loop: {e}")

    async def _unblock(self, ip: str):
        """Unblock an IP address."""
        try:
            # Find and delete the auto-block rule
            rule_id = f"autoblock_{ip.replace('.', '_')}"
            success = await self.backend.delete_rule(rule_id)

            if success:
                self.blocked_ips.discard(ip)
                if ip in self.ip_stats:
                    self.ip_stats[ip].blocked = False
                logger.info(f"Auto-unblocked {ip} (block expired)")
            else:
                logger.warning(f"Failed to unblock {ip}")
        except Exception as e:
            logger.error(f"Error unblocking {ip}: {e}")

    def add_to_whitelist(self, ip: str):
        """Add an IP to the whitelist (never auto-block)."""
        self.config.whitelist.add(ip)
        logger.info(f"Added {ip} to whitelist")

    def remove_from_whitelist(self, ip: str):
        """Remove an IP from the whitelist."""
        self.config.whitelist.discard(ip)
        logger.info(f"Removed {ip} from whitelist")

    def get_stats(self) -> dict:
        """Get current rate limiter statistics."""
        return {
            "enabled": self.config.enabled,
            "total_ips_tracked": len(self.ip_stats),
            "blocked_ips": len(self.blocked_ips),
            "whitelist_size": len(self.config.whitelist),
            "config": {
                "max_req_per_min": self.config.max_requests_per_minute,
                "max_req_per_hour": self.config.max_requests_per_hour,
                "block_duration": self.config.block_duration_seconds
            }
        }

    def get_top_requesters(self, limit: int = 10) -> list[IPStats]:
        """Get top requesters by request count."""
        sorted_stats = sorted(
            self.ip_stats.values(),
            key=lambda s: s.request_count_hour,
            reverse=True
        )
        return sorted_stats[:limit]


# Global instance
_rate_limiter: RateLimiter | None = None


def get_rate_limiter(backend: FirewallBackend, config: RateLimitConfig | None = None) -> RateLimiter:
    """Get or create the global rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter(backend, config)
    return _rate_limiter
