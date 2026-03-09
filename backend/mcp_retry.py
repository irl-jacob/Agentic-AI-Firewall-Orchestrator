"""MCP retry logic and error translation for OPNsense backend."""

import asyncio
import json
import logging
from functools import wraps
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Maximum retry attempts for transient failures
MAX_RETRIES = 3
INITIAL_BACKOFF = 1.0  # seconds
MAX_BACKOFF = 10.0  # seconds


# User-friendly error translations
MCP_ERROR_TRANSLATIONS = {
    "ECONNREFUSED": "Cannot connect to OPNsense. Check that the firewall is reachable at the configured address.",
    "ETIMEDOUT": "Connection to OPNsense timed out. Check network connectivity and firewall status.",
    "EHOSTUNREACH": "OPNsense host is unreachable. Verify the IP address and network routing.",
    "ENOTFOUND": "Cannot resolve OPNsense hostname. Check DNS configuration.",
    "401": "Authentication failed. Verify your API key and secret are correct.",
    "403": "Permission denied. Your API key may not have firewall management permissions.",
    "404": "Resource not found. The requested rule, interface, or endpoint may not exist.",
    "500": "OPNsense internal server error. Check the firewall logs for details.",
    "502": "Bad gateway. OPNsense may be restarting or experiencing issues.",
    "503": "Service unavailable. OPNsense may be overloaded or under maintenance.",
    "timeout": "Request timed out. OPNsense may be slow to respond or unreachable.",
    "ECONNRESET": "Connection reset by OPNsense. The firewall may have restarted.",
}


def translate_mcp_error(error: Exception) -> str:
    """
    Translate technical MCP error to user-friendly message.

    Args:
        error: Exception from MCP call

    Returns:
        User-friendly error message
    """
    error_str = str(error).lower()

    # Check for known error codes/messages
    for code, message in MCP_ERROR_TRANSLATIONS.items():
        if code.lower() in error_str:
            return message

    # Check for common patterns
    if "connection" in error_str and "refused" in error_str:
        return MCP_ERROR_TRANSLATIONS["ECONNREFUSED"]
    elif "timeout" in error_str or "timed out" in error_str:
        return MCP_ERROR_TRANSLATIONS["timeout"]
    elif "authentication" in error_str or "auth" in error_str:
        return MCP_ERROR_TRANSLATIONS["401"]
    elif "permission" in error_str or "forbidden" in error_str:
        return MCP_ERROR_TRANSLATIONS["403"]
    elif "not found" in error_str:
        return MCP_ERROR_TRANSLATIONS["404"]

    # Fallback to generic message
    return f"OPNsense communication error: {str(error)[:100]}"


def is_retryable_error(error: Exception) -> bool:
    """
    Determine if an error is transient and should be retried.

    Args:
        error: Exception from MCP call

    Returns:
        True if error is retryable, False otherwise
    """
    error_str = str(error).lower()

    # Retryable errors (transient network issues)
    retryable_patterns = [
        "timeout",
        "timed out",
        "connection reset",
        "econnreset",
        "502",
        "503",
        "temporarily unavailable",
    ]

    for pattern in retryable_patterns:
        if pattern in error_str:
            return True

    # Non-retryable errors (permanent failures)
    non_retryable_patterns = [
        "401",
        "403",
        "404",
        "authentication",
        "permission",
        "not found",
        "econnrefused",  # Wrong address, won't fix with retry
    ]

    for pattern in non_retryable_patterns:
        if pattern in error_str:
            return False

    # Default: retry unknown errors (conservative approach)
    return True


def retry_with_backoff(max_retries: int = MAX_RETRIES):
    """
    Decorator to retry async functions with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts

    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            last_error = None
            backoff = INITIAL_BACKOFF

            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_error = e

                    # Don't retry on last attempt
                    if attempt == max_retries:
                        break

                    # Check if error is retryable
                    if not is_retryable_error(e):
                        logger.warning(f"{func.__name__} failed with non-retryable error: {e}")
                        break

                    # Log retry attempt
                    logger.warning(
                        f"{func.__name__} failed (attempt {attempt + 1}/{max_retries + 1}): {e}. "
                        f"Retrying in {backoff:.1f}s..."
                    )

                    # Wait with exponential backoff
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, MAX_BACKOFF)

            # All retries exhausted
            logger.error(f"{func.__name__} failed after {max_retries + 1} attempts: {last_error}")
            raise last_error

        return wrapper
    return decorator


async def verify_rule_deployed(
    backend: Any,
    rule_id: str,
    max_wait: int = 10
) -> bool:
    """
    Verify that a rule was actually deployed to the firewall.

    Args:
        backend: Firewall backend instance
        rule_id: ID of the rule to verify
        max_wait: Maximum seconds to wait for rule to appear

    Returns:
        True if rule is found, False otherwise
    """
    for attempt in range(max_wait):
        try:
            rules = await backend.list_rules()
            for rule in rules:
                if rule.id == rule_id:
                    logger.info(f"Verified rule {rule_id} is deployed")
                    return True

            # Wait a bit before checking again
            if attempt < max_wait - 1:
                await asyncio.sleep(1)
        except Exception as e:
            logger.warning(f"Verification attempt {attempt + 1} failed: {e}")
            if attempt < max_wait - 1:
                await asyncio.sleep(1)

    logger.error(f"Rule {rule_id} not found after {max_wait} seconds")
    return False


class MCPHealthMonitor:
    """Monitor MCP connection health and reconnect if needed."""

    def __init__(self, backend: Any):
        self.backend = backend
        self.last_success = None
        self.consecutive_failures = 0
        self.max_failures = 3

    def record_success(self):
        """Record a successful MCP call."""
        from datetime import datetime
        self.last_success = datetime.now()
        self.consecutive_failures = 0

    def record_failure(self):
        """Record a failed MCP call."""
        self.consecutive_failures += 1

    async def check_health(self) -> bool:
        """
        Check if MCP connection is healthy.

        Returns:
            True if healthy, False if reconnection needed
        """
        if self.consecutive_failures >= self.max_failures:
            logger.warning(
                f"MCP connection unhealthy ({self.consecutive_failures} consecutive failures). "
                "Attempting reconnection..."
            )
            try:
                await self.backend.disconnect()
                await self.backend.connect()
                self.consecutive_failures = 0
                logger.info("MCP reconnection successful")
                return True
            except Exception as e:
                logger.error(f"MCP reconnection failed: {e}")
                return False

        return True
