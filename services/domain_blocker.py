"""Domain blocking service for AFO.

Blocks domains using OPNsense host aliases and firewall rules.
Enables commands like "block facebook.com" or "block all social media".
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from backend.base import FirewallBackend
from backend.models import Action, Direction, PolicyRule, Protocol

logger = logging.getLogger(__name__)


def validate_domain(domain: str) -> bool:
    """
    Validate domain name format.

    Args:
        domain: Domain name to validate

    Returns:
        True if valid, False otherwise
    """
    # Basic domain validation regex
    # Allows: example.com, sub.example.com, example.co.uk, *.example.com
    pattern = r'^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def sanitize_domain_name(domain: str) -> str:
    """
    Sanitize domain name for use in alias/rule names.

    Args:
        domain: Domain name (e.g., "google.com" or "*.google.com")

    Returns:
        Sanitized name (e.g., "google_com" or "wildcard_google_com")
    """
    # Handle wildcard
    if domain.startswith("*."):
        domain = "wildcard_" + domain[2:]
    # Replace dots and special chars with underscores
    return domain.replace(".", "_").replace("-", "_")


@dataclass
class DomainCategory:
    """Predefined domain category."""

    name: str
    description: str
    domains: list[str] = field(default_factory=list)


# Predefined domain categories
DOMAIN_CATEGORIES = {
    "social_media": DomainCategory(
        name="social_media",
        description="Social media platforms",
        domains=[
            "facebook.com",
            "*.facebook.com",
            "instagram.com",
            "*.instagram.com",
            "twitter.com",
            "*.twitter.com",
            "x.com",
            "*.x.com",
            "tiktok.com",
            "*.tiktok.com",
            "snapchat.com",
            "*.snapchat.com",
            "linkedin.com",
            "*.linkedin.com",
            "reddit.com",
            "*.reddit.com",
            "pinterest.com",
            "*.pinterest.com",
            "tumblr.com",
            "*.tumblr.com",
        ],
    ),
    "streaming": DomainCategory(
        name="streaming",
        description="Video streaming services",
        domains=[
            "youtube.com",
            "*.youtube.com",
            "netflix.com",
            "*.netflix.com",
            "hulu.com",
            "*.hulu.com",
            "twitch.tv",
            "*.twitch.tv",
            "vimeo.com",
            "*.vimeo.com",
            "dailymotion.com",
            "*.dailymotion.com",
        ],
    ),
    "gaming": DomainCategory(
        name="gaming",
        description="Gaming platforms and services",
        domains=[
            "steam.com",
            "*.steam.com",
            "steampowered.com",
            "*.steampowered.com",
            "epicgames.com",
            "*.epicgames.com",
            "roblox.com",
            "*.roblox.com",
            "minecraft.net",
            "*.minecraft.net",
            "ea.com",
            "*.ea.com",
            "blizzard.com",
            "*.blizzard.com",
            "battle.net",
            "*.battle.net",
        ],
    ),
    "gambling": DomainCategory(
        name="gambling",
        description="Gambling and betting sites",
        domains=[
            "bet365.com",
            "*.bet365.com",
            "pokerstars.com",
            "*.pokerstars.com",
            "draftkings.com",
            "*.draftkings.com",
            "fanduel.com",
            "*.fanduel.com",
        ],
    ),
    "adult": DomainCategory(
        name="adult",
        description="Adult content sites",
        domains=[
            # Common adult content domains (keeping it minimal)
            "pornhub.com",
            "*.pornhub.com",
            "xvideos.com",
            "*.xvideos.com",
            "xnxx.com",
            "*.xnxx.com",
        ],
    ),
    "ads": DomainCategory(
        name="ads",
        description="Advertising and tracking domains",
        domains=[
            "doubleclick.net",
            "*.doubleclick.net",
            "googlesyndication.com",
            "*.googlesyndication.com",
            "googleadservices.com",
            "*.googleadservices.com",
            "adnxs.com",
            "*.adnxs.com",
            "advertising.com",
            "*.advertising.com",
        ],
    ),
    "malware": DomainCategory(
        name="malware",
        description="Known malware and phishing domains",
        domains=[
            # This would typically be populated from threat feeds
            # Placeholder for now
        ],
    ),
}


class DomainBlocker:
    """Service for domain blocking using OPNsense host aliases."""

    def __init__(self, backend: FirewallBackend):
        """
        Initialize domain blocker.

        Args:
            backend: Firewall backend (OPNsense required)
        """
        self.backend = backend
        self._lock = asyncio.Lock()

    async def block_domain(self, domain: str, reason: Optional[str] = None) -> tuple[bool, str]:
        """
        Block a domain by resolving it to IPs and creating firewall rules.

        Args:
            domain: Domain to block (e.g., "facebook.com")
            reason: Optional reason for blocking

        Returns:
            Tuple of (success, message)
        """
        async with self._lock:
            # Validate domain
            if not validate_domain(domain):
                return False, f"Invalid domain name: {domain}"

            # Normalize domain
            domain = domain.lower().strip()

            try:
                # Resolve domain to IP addresses
                import socket
                logger.info(f"Resolving domain: {domain}")

                try:
                    # Get all IPs for the domain (IPv4)
                    addr_info = socket.getaddrinfo(domain, None, socket.AF_INET)
                    ips = list(set([addr[4][0] for addr in addr_info]))

                    if not ips:
                        return False, f"Could not resolve {domain} to any IP addresses"

                    logger.info(f"Resolved {domain} to {len(ips)} IP(s): {ips}")

                except socket.gaierror as e:
                    return False, f"Failed to resolve {domain}: {e}"

                # Create firewall rules for each IP
                rule_ids = []
                sanitized = sanitize_domain_name(domain)

                for idx, ip in enumerate(ips):
                    rule_id = f"domain_block_{sanitized}_{idx}"
                    rule_name = f"block_{sanitized}_{idx}"

                    rule = PolicyRule(
                        id=rule_id,
                        name=rule_name,
                        description=reason or f"Block {domain} ({ip})",
                        action=Action.DROP,
                        direction=Direction.OUTBOUND,
                        protocol=Protocol.ANY,
                        port=None,
                        source=None,
                        destination=ip,
                        priority=400,
                        enabled=True,
                    )

                    try:
                        deployed = await self.backend.deploy_rule(rule)
                        if deployed:
                            rule_ids.append(rule_id)
                            logger.info(f"Created rule blocking {ip} ({domain})")
                        else:
                            logger.error(f"Failed to deploy rule for {ip}")
                    except Exception as e:
                        logger.error(f"Error deploying rule for {ip}: {e}")

                if rule_ids:
                    return True, f"Successfully blocked {domain} ({len(rule_ids)} IP(s))"
                else:
                    return False, f"Failed to create blocking rules for {domain}"

            except Exception as e:
                logger.error(f"Error blocking domain {domain}: {e}")
                return False, f"Error: {e}"

    async def unblock_domain(self, domain: str) -> tuple[bool, str]:
        """
        Unblock a domain by removing all its firewall rules.

        Args:
            domain: Domain to unblock

        Returns:
            Tuple of (success, message)
        """
        async with self._lock:
            # Normalize domain
            domain = domain.lower().strip()

            # Sanitize domain
            sanitized = sanitize_domain_name(domain)

            try:
                # Get all rules
                all_rules = await self.backend.list_rules()
                logger.info(f"Found {len(all_rules)} total rules")

                # Find rules matching this domain
                rules_to_delete = []
                for rule in all_rules:
                    # Match by rule name, ID, or description
                    rule_name = (rule.name or "").lower()
                    rule_id = (rule.id or "").lower()
                    rule_desc = (rule.description or "").lower()

                    # Match patterns:
                    # - Rule name: block_<domain>_* or contains domain
                    # - Rule ID: domain_block_<domain>_*
                    # - Description: "Block <domain>" or "block <domain>"
                    if (f"block_{sanitized}" in rule_name or
                        f"domain_block_{sanitized}" in rule_id or
                        f"block {domain}" in rule_desc or
                        f"block_{sanitized}" in rule_desc):
                        rules_to_delete.append(rule)
                        logger.info(f"Found matching rule: {rule.name} (ID: {rule.id})")

                if not rules_to_delete:
                    logger.warning(f"No blocking rules found for {domain} (sanitized: {sanitized})")
                    return False, f"No blocking rules found for {domain}"

                # Delete all matching rules
                deleted_count = 0
                for rule in rules_to_delete:
                    try:
                        success = await self.backend.delete_rule(rule.id)
                        if success:
                            deleted_count += 1
                            logger.info(f"Deleted rule: {rule.name}")
                    except Exception as e:
                        logger.error(f"Error deleting rule {rule.name}: {e}")

                if deleted_count > 0:
                    return True, f"Unblocked {domain} ({deleted_count} rule(s) deleted)"
                else:
                    return False, f"Failed to delete rules for {domain}"

            except Exception as e:
                logger.error(f"Error unblocking domain {domain}: {e}")
                return False, f"Error: {e}"

    async def list_blocked_domains(self) -> list[str]:
        """
        List all currently blocked domains.

        Returns:
            List of blocked domain names
        """
        try:
            # Get all aliases
            if not hasattr(self.backend, 'list_aliases'):
                return []

            aliases = await self.backend.list_aliases()

            # Filter for domain_block_* aliases
            blocked_domains = []
            for alias in aliases:
                if alias.get("name", "").startswith("domain_block_"):
                    # Extract domain from alias name
                    # domain_block_google_com → google.com
                    sanitized = alias["name"].replace("domain_block_", "")
                    # Handle wildcard
                    if sanitized.startswith("wildcard_"):
                        domain = "*." + sanitized.replace("wildcard_", "").replace("_", ".")
                    else:
                        domain = sanitized.replace("_", ".")
                    blocked_domains.append(domain)

            return blocked_domains

        except Exception as e:
            logger.error(f"Error listing blocked domains: {e}")
            return []


def get_domain_blocker(backend: FirewallBackend) -> DomainBlocker:
    """Get a DomainBlocker instance."""
    return DomainBlocker(backend)
