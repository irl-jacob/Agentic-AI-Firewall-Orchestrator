"""GeoIP service for country-based filtering.

Integrates MaxMind GeoLite2 database for IP-to-country lookups.
Enables commands like "block all traffic from Russia" or "allow only from US and India".
"""

import logging
import os
from pathlib import Path
from typing import Optional

try:
    import geoip2.database
    import geoip2.errors
    from geoip2.models import Country
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    geoip2 = None

from backend.base import FirewallBackend
from backend.models import Action, Direction, PolicyRule, Protocol

logger = logging.getLogger(__name__)


# Country name to ISO code mapping
COUNTRY_NAME_TO_CODE = {
    "russia": "RU",
    "china": "CN",
    "united states": "US",
    "america": "US",
    "usa": "US",
    "north korea": "KP",
    "south korea": "KR",
    "iran": "IR",
    "iraq": "IQ",
    "syria": "SY",
    "belarus": "BY",
    "venezuela": "VE",
    "cuba": "CU",
    "india": "IN",
    "pakistan": "PK",
    "afghanistan": "AF",
    "ukraine": "UA",
    "germany": "DE",
    "france": "FR",
    "united kingdom": "GB",
    "uk": "GB",
    "britain": "GB",
    "japan": "JP",
    "canada": "CA",
    "mexico": "MX",
    "brazil": "BR",
    "australia": "AU",
    "spain": "ES",
    "italy": "IT",
    "netherlands": "NL",
    "poland": "PL",
    "turkey": "TR",
    "saudi arabia": "SA",
    "egypt": "EG",
    "israel": "IL",
    "vietnam": "VN",
    "thailand": "TH",
    "indonesia": "ID",
    "philippines": "PH",
    "malaysia": "MY",
    "singapore": "SG",
}


def normalize_country_code(country: str) -> str:
    """
    Normalize country name or code to ISO code.

    Args:
        country: Country name or ISO code

    Returns:
        ISO country code (uppercase)
    """
    country_lower = country.lower().strip()

    # Check if it's already a valid 2-letter code
    if len(country) == 2:
        return country.upper()

    # Look up in mapping
    if country_lower in COUNTRY_NAME_TO_CODE:
        return COUNTRY_NAME_TO_CODE[country_lower]

    # Return as-is (uppercase) and let it fail later if invalid
    return country.upper()


class GeoIPService:
    """Service for GeoIP lookups and country-based filtering."""

    def __init__(self, backend: FirewallBackend, db_path: Optional[str] = None):
        """
        Initialize GeoIP service.

        Args:
            backend: Firewall backend for rule deployment
            db_path: Path to GeoLite2-Country.mmdb (optional)
        """
        self.backend = backend
        self.db_path = db_path or self._find_geoip_db()
        self.reader: Optional[geoip2.database.Reader] = None
        self._initialize_reader()

    def _find_geoip_db(self) -> str:
        """Find GeoLite2 database in common locations."""
        common_paths = [
            "/usr/share/GeoIP/GeoLite2-Country.mmdb",
            "/var/lib/GeoIP/GeoLite2-Country.mmdb",
            "/opt/GeoIP/GeoLite2-Country.mmdb",
            str(Path.home() / ".local/share/GeoIP/GeoLite2-Country.mmdb"),
            "./GeoLite2-Country.mmdb",
        ]

        for path in common_paths:
            if os.path.exists(path):
                logger.info(f"Found GeoIP database at {path}")
                return path

        logger.warning("GeoIP database not found in common locations")
        return ""

    def _initialize_reader(self):
        """Initialize GeoIP database reader."""
        if not GEOIP2_AVAILABLE:
            logger.warning("geoip2 library not installed - country filtering disabled")
            return

        if not self.db_path or not os.path.exists(self.db_path):
            logger.warning("GeoIP database not available - country filtering disabled")
            return

        try:
            self.reader = geoip2.database.Reader(self.db_path)
            logger.info("GeoIP database loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load GeoIP database: {e}")
            self.reader = None

    def lookup_country(self, ip: str) -> Optional[str]:
        """
        Look up country code for an IP address.

        Args:
            ip: IP address to look up

        Returns:
            ISO 3166-1 alpha-2 country code (e.g., "US", "RU") or None
        """
        if not self.reader:
            logger.warning("GeoIP lookup attempted but database not available")
            return None

        try:
            response = self.reader.country(ip)
            return response.country.iso_code
        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"IP {ip} not found in GeoIP database")
            return None
        except Exception as e:
            logger.error(f"GeoIP lookup error for {ip}: {e}")
            return None

    def lookup_country_name(self, ip: str) -> Optional[str]:
        """
        Look up country name for an IP address.

        Args:
            ip: IP address to look up

        Returns:
            Country name (e.g., "United States", "Russia") or None
        """
        if not self.reader:
            return None

        try:
            response = self.reader.country(ip)
            return response.country.name
        except Exception as e:
            logger.error(f"GeoIP lookup error for {ip}: {e}")
            return None

    async def create_country_rule(
        self,
        country_codes: list[str],
        action: Action,
        direction: Direction = Direction.INBOUND,
        description: Optional[str] = None,
    ) -> list[str]:
        """
        Create firewall rules for country-based filtering using real IP ranges.

        This method:
        1. Fetches IP ranges from database (downloads if needed)
        2. Creates firewall rules with actual IP ranges
        3. Uses efficient strategies for large IP lists

        Args:
            country_codes: List of ISO country codes (e.g., ["US", "RU"])
            action: Action to take (ALLOW or DROP)
            direction: Traffic direction
            description: Optional rule description

        Returns:
            List of created rule IDs
        """
        if not country_codes:
            logger.warning("No country codes provided")
            return []

        # Normalize country codes (convert names to ISO codes)
        normalized_codes = []
        for code in country_codes:
            normalized = normalize_country_code(code)
            normalized_codes.append(normalized)
            if normalized != code.upper():
                logger.info(f"Normalized '{code}' to '{normalized}'")

        country_codes = normalized_codes

        # Try to use database-backed IP ranges
        try:
            from services.geoip_db import GeoIPDatabase
            from db.database import get_session

            # Get session properly (it's an async generator)
            session_gen = get_session()
            session = await anext(session_gen)

            try:
                geoip_db = GeoIPDatabase(session)

                # Collect all IP ranges for all countries
                all_ranges = []
                for country_code in country_codes:
                    ranges = await geoip_db.get_country_ranges(country_code, ip_version=4)

                    # If no ranges found, try to download them
                    if not ranges:
                        logger.info(f"No IP ranges found for {country_code}, downloading...")
                        success = await geoip_db.update_country(country_code, ip_version=4)
                        if success:
                            ranges = await geoip_db.get_country_ranges(country_code, ip_version=4)

                    if ranges:
                        all_ranges.extend(ranges)
                        logger.info(f"Found {len(ranges)} IP ranges for {country_code}")
                    else:
                        logger.warning(f"Could not get IP ranges for {country_code}")

                if not all_ranges:
                    logger.error("No IP ranges found for any country")
                    await session.close()
                    return []

                # Create rules based on number of ranges
                result = await self._create_ip_based_rules(
                    country_codes, all_ranges, action, direction, description
                )
                await session.close()
                return result

            except Exception as e:
                await session.close()
                raise

        except Exception as e:
            logger.error(f"Error using GeoIP database: {e}")
            import traceback
            logger.error(traceback.format_exc())
            logger.info("Falling back to placeholder rules")
            return await self._create_placeholder_rules(country_codes, action, direction, description)
        rule_id = f"geoip_{action.value.lower()}_{'_'.join([c.lower() for c in country_codes])}"
        rule_name = f"geoip_{action_str}_{'_'.join(country_codes)}"

        if not description:
            action_text = "Allow" if action == Action.ACCEPT else "Block"
            description = f"{action_text} traffic from {', '.join(country_codes)}"

        rule = PolicyRule(
            id=rule_id,
            name=rule_name,
            description=description,
            action=action,
            direction=direction,
            protocol=Protocol.ANY,
            port=None,
            source=alias_name,  # Reference the GeoIP alias
            destination=None,
            priority=500,
            enabled=True,
        )

        try:
            deployed = await self.backend.deploy_rule(rule)
            if deployed:
                logger.info(f"Created GeoIP rule: {rule_name} using alias {alias_name}")
                return [rule_id]
            else:
                logger.error(f"Failed to deploy GeoIP rule: {rule_name}")
                return []
        except Exception as e:
            logger.error(f"Error deploying GeoIP rule: {e}")
            return []

    async def _create_placeholder_rules(
        self,
        country_codes: list[str],
        action: Action,
        direction: Direction,
        description: Optional[str]
    ) -> list[str]:
        """
        Create placeholder rules for backends that don't support GeoIP aliases.

        These rules are created as DISABLED to avoid safety check issues.
        User must manually create GeoIP alias and enable the rule.
        """
        rule_ids = []
        for country_code in country_codes:
            rule_id = f"geoip_{action.value.lower()}_{country_code.lower()}"
            rule_name = f"geoip_{country_code}"

            if not description:
                action_str = "Allow" if action == Action.ACCEPT else "Block"
                description = f"{action_str} traffic from {country_code} - REQUIRES MANUAL GEOIP ALIAS SETUP"

            rule = PolicyRule(
                id=rule_id,
                name=rule_name,
                description=description,
                action=action,
                direction=direction,
                protocol=Protocol.ANY,
                port=None,
                source="any",  # Will be changed to alias manually
                destination=None,
                priority=500,
                enabled=False,  # Disabled until alias is configured
            )

            try:
                success = await self.backend.deploy_rule(rule)
                if success:
                    rule_ids.append(rule_id)
                    logger.info(f"Created DISABLED placeholder GeoIP rule for {country_code}: {action.value}")
                else:
                    logger.error(f"Failed to create GeoIP rule for {country_code}")
            except Exception as e:
                logger.error(f"Error creating GeoIP rule for {country_code}: {e}")

        return rule_ids

    async def _create_ip_based_rules(
        self,
        country_codes: list[str],
        ip_ranges: list[str],
        action: Action,
        direction: Direction,
        description: Optional[str]
    ) -> list[str]:
        """
        Create firewall rules from actual IP ranges.

        Strategy:
        - Few ranges (<50): Create individual rules
        - Many ranges (>=50): Try alias, fallback to first 100 individual rules

        Args:
            country_codes: List of country codes
            ip_ranges: List of CIDR ranges
            action: Action to take
            direction: Traffic direction
            description: Optional description

        Returns:
            List of created rule IDs
        """
        action_str = "block" if action == Action.DROP else "allow"
        countries_str = "_".join([c.lower() for c in country_codes])

        logger.info(f"Creating rules for {len(ip_ranges)} IP ranges from {', '.join(country_codes)}")

        # Strategy 1: Few ranges - create individual rules
        if len(ip_ranges) < 50:
            return await self._create_individual_ip_rules(
                country_codes, ip_ranges, action, direction, description
            )

        # Strategy 2: Many ranges - try alias first, fallback to individual rules
        logger.info(f"Large IP list ({len(ip_ranges)} ranges), attempting alias-based approach...")

        # Try alias-based approach for OPNsense
        if hasattr(self.backend, 'host'):
            try:
                result = await self._create_alias_based_rule(
                    country_codes, ip_ranges, action, direction, description
                )
                if result:
                    logger.info("Successfully created alias-based rule")
                    return result
                else:
                    logger.warning("Alias creation failed, falling back to individual rules")
            except Exception as e:
                logger.warning(f"Alias creation error: {e}, falling back to individual rules")

        # Fallback: Create individual rules for first 100 ranges
        logger.info(f"Creating individual rules for first 100 of {len(ip_ranges)} ranges")
        return await self._create_individual_ip_rules(
            country_codes, ip_ranges[:100], action, direction, description
        )

    async def _create_individual_ip_rules(
        self,
        country_codes: list[str],
        ip_ranges: list[str],
        action: Action,
        direction: Direction,
        description: Optional[str]
    ) -> list[str]:
        """Create individual firewall rules for each IP range."""
        rule_ids = []
        countries_str = "_".join([c.lower() for c in country_codes])
        action_str = "block" if action == Action.DROP else "allow"

        for idx, ip_range in enumerate(ip_ranges):
            rule_id = f"geoip_{action.value.lower()}_{countries_str}_{idx}"
            rule_name = f"geoip_{countries_str}_{idx}"

            if not description:
                desc = f"{action_str.capitalize()} {ip_range} ({', '.join(country_codes)})"
            else:
                desc = f"{description} - {ip_range}"

            rule = PolicyRule(
                id=rule_id,
                name=rule_name,
                description=desc,
                action=action,
                direction=direction,
                protocol=Protocol.ANY,
                port=None,
                source=ip_range,
                destination=None,
                priority=500,
                enabled=True,
            )

            try:
                success = await self.backend.deploy_rule(rule)
                if success:
                    rule_ids.append(rule_id)
                else:
                    logger.error(f"Failed to deploy rule for {ip_range}")
            except Exception as e:
                logger.error(f"Error deploying rule for {ip_range}: {e}")

        logger.info(f"Created {len(rule_ids)} individual IP rules")
        return rule_ids

    async def _create_alias_based_rule(
        self,
        country_codes: list[str],
        ip_ranges: list[str],
        action: Action,
        direction: Direction,
        description: Optional[str]
    ) -> list[str]:
        """Create OPNsense alias with all IPs and single rule referencing it."""
        action_str = "block" if action == Action.DROP else "allow"
        countries_str = "_".join([c.lower() for c in country_codes])
        alias_name = f"geoip_{action_str}_{countries_str}"

        # Create alias via direct API (not GeoIP type, but network type with IPs)
        try:
            import httpx

            if not hasattr(self.backend, 'host') or not self.backend.host:
                logger.error("OPNsense host not configured")
                return []

            url = f"https://{self.backend.host}/api/firewall/alias/addItem"

            alias_data = {
                "alias": {
                    "enabled": "1",
                    "name": alias_name,
                    "type": "network",  # Network type for IP ranges
                    "content": "\n".join(ip_ranges),  # Newline-separated
                    "description": description or f"{action_str.capitalize()} traffic from {', '.join(country_codes)}"
                }
            }

            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    url,
                    json=alias_data,
                    auth=(self.backend.api_key, self.backend.api_secret),
                    timeout=30.0
                )

                if response.status_code == 200:
                    # Apply changes
                    apply_url = f"https://{self.backend.host}/api/firewall/alias/reconfigure"
                    await client.post(apply_url, auth=(self.backend.api_key, self.backend.api_secret), timeout=30.0)

                    logger.info(f"Created OPNsense alias '{alias_name}' with {len(ip_ranges)} IP ranges")

                    # Create single rule referencing the alias
                    rule_id = f"geoip_{action.value.lower()}_{countries_str}"
                    rule = PolicyRule(
                        id=rule_id,
                        name=f"geoip_{countries_str}",
                        description=description or f"{action_str.capitalize()} {', '.join(country_codes)}",
                        action=action,
                        direction=direction,
                        protocol=Protocol.ANY,
                        port=None,
                        source=alias_name,  # Reference the alias
                        destination=None,
                        priority=500,
                        enabled=True,
                    )

                    success = await self.backend.deploy_rule(rule)
                    if success:
                        logger.info(f"Created rule referencing alias '{alias_name}'")
                        return [rule_id]
                    else:
                        logger.error("Failed to deploy rule")
                        return []
                else:
                    logger.error(f"Failed to create alias: {response.status_code}")
                    return []

        except Exception as e:
            logger.error(f"Error creating alias-based rule: {e}")
            return []

    async def block_countries(
        self, country_codes: list[str], description: Optional[str] = None
    ) -> list[str]:
        """
        Block traffic from specified countries.

        Args:
            country_codes: List of ISO country codes to block
            description: Optional rule description

        Returns:
            List of created rule IDs
        """
        return await self.create_country_rule(
            country_codes, Action.DROP, Direction.INBOUND, description
        )

    async def allow_countries_only(
        self, country_codes: list[str], description: Optional[str] = None
    ) -> list[str]:
        """
        Allow traffic only from specified countries (block all others).

        This creates ACCEPT rules for specified countries and a default DROP rule.

        Args:
            country_codes: List of ISO country codes to allow
            description: Optional rule description

        Returns:
            List of created rule IDs
        """
        rule_ids = []

        # Create ACCEPT rules for specified countries
        allow_ids = await self.create_country_rule(
            country_codes, Action.ACCEPT, Direction.INBOUND, description
        )
        rule_ids.extend(allow_ids)

        # Create default DROP rule for all other countries
        default_rule = PolicyRule(
            id="geoip_default_drop",
            name="geoip_default_drop",
            description="Block traffic from countries not explicitly allowed",
            action=Action.DROP,
            direction=Direction.INBOUND,
            protocol=Protocol.ANY,
            port=None,
            source=None,
            destination=None,
            priority=1000,  # Lower priority (evaluated last)
            enabled=True,
            metadata={"geoip_default": True},
        )

        try:
            success = await self.backend.deploy_rule(default_rule)
            if success:
                rule_ids.append("geoip_default_drop")
                logger.info("Created default GeoIP DROP rule")
        except Exception as e:
            logger.error(f"Error creating default GeoIP rule: {e}")

        return rule_ids

    async def unblock_countries(self, country_codes: list[str]) -> tuple[bool, str]:
        """
        Remove all GeoIP blocking rules for specified countries.

        This finds and deletes all rules that were created for blocking
        the specified countries.

        Args:
            country_codes: List of ISO country codes (e.g., ["RU", "CN"])

        Returns:
            Tuple of (success, message)
        """
        if not country_codes:
            return False, "No countries specified"

        # Normalize country codes
        normalized_codes = []
        for code in country_codes:
            normalized = normalize_country_code(code)
            normalized_codes.append(normalized)

        country_codes = normalized_codes

        try:
            # Get all existing rules
            all_rules = await self.backend.list_rules()

            logger.info(f"Found {len(all_rules)} total rules in firewall")

            # Find rules matching the country codes
            rules_to_delete = []

            for rule in all_rules:
                # Match rules by name pattern
                for country_code in country_codes:
                    country_upper = country_code.upper()
                    country_lower = country_code.lower()
                    rule_name_lower = rule.name.lower()

                    # Match patterns:
                    # 1. "Block 2.56.24.0/22 (RU)" - description-based names
                    # 2. "geoip_ru_0" - explicit geoip names
                    # 3. Any rule with country code in parentheses
                    if (f"({country_upper})" in rule.name or
                        f"geoip_{country_lower}" in rule_name_lower or
                        f"_{country_lower}_" in rule_name_lower):
                        rules_to_delete.append(rule)
                        logger.info(f"Matched rule for deletion: {rule.name}")
                        break

            logger.info(f"Found {len(rules_to_delete)} rules to delete for {country_codes}")

            if not rules_to_delete:
                # Log all rule names for debugging
                logger.warning(f"No matching rules found. All rule names: {[r.name for r in all_rules[:20]]}")
                # Return helpful message with sample rule names
                sample_names = [r.name for r in all_rules[:10]]
                return False, f"No GeoIP rules found for {', '.join(country_codes)}. Found {len(all_rules)} total rules. Sample names: {', '.join(sample_names[:5])}"

            # Delete all matching rules
            deleted_count = 0
            failed_count = 0

            for rule in rules_to_delete:
                try:
                    success = await self.backend.delete_rule(rule.id)
                    if success:
                        deleted_count += 1
                        logger.info(f"Deleted GeoIP rule: {rule.name}")
                    else:
                        failed_count += 1
                        logger.error(f"Failed to delete rule: {rule.name}")
                except Exception as e:
                    failed_count += 1
                    logger.error(f"Error deleting rule {rule.name}: {e}")

            if deleted_count > 0:
                msg = f"Deleted {deleted_count} GeoIP rule(s) for {', '.join(country_codes)}"
                if failed_count > 0:
                    msg += f" ({failed_count} failed)"
                return True, msg
            else:
                return False, f"Failed to delete rules for {', '.join(country_codes)}"

        except Exception as e:
            logger.error(f"Error unblocking countries: {e}")
            return False, f"Error: {e}"

    def is_available(self) -> bool:
        """Check if GeoIP service is available."""
        return self.reader is not None

    def get_stats(self) -> dict:
        """Get GeoIP service statistics."""
        return {
            "available": self.is_available(),
            "db_path": self.db_path,
            "db_exists": os.path.exists(self.db_path) if self.db_path else False,
        }

    def close(self):
        """Close GeoIP database reader."""
        if self.reader:
            self.reader.close()
            self.reader = None
            logger.info("GeoIP database closed")


# Global instance
_geoip_service: Optional[GeoIPService] = None


def get_geoip_service(
    backend: FirewallBackend, db_path: Optional[str] = None
) -> GeoIPService:
    """Get or create the global GeoIP service."""
    global _geoip_service
    if _geoip_service is None:
        _geoip_service = GeoIPService(backend, db_path)
    return _geoip_service


# Country code mappings for common names
COUNTRY_NAME_TO_CODE = {
    "united states": "US",
    "usa": "US",
    "america": "US",
    "russia": "RU",
    "russian federation": "RU",
    "china": "CN",
    "india": "IN",
    "united kingdom": "GB",
    "uk": "GB",
    "britain": "GB",
    "canada": "CA",
    "australia": "AU",
    "germany": "DE",
    "france": "FR",
    "japan": "JP",
    "south korea": "KR",
    "korea": "KR",
    "north korea": "KP",
    "brazil": "BR",
    "mexico": "MX",
    "spain": "ES",
    "italy": "IT",
    "netherlands": "NL",
    "sweden": "SE",
    "norway": "NO",
    "denmark": "DK",
    "finland": "FI",
    "poland": "PL",
    "ukraine": "UA",
    "turkey": "TR",
    "iran": "IR",
    "iraq": "IQ",
    "israel": "IL",
    "saudi arabia": "SA",
    "egypt": "EG",
    "south africa": "ZA",
    "nigeria": "NG",
    "kenya": "KE",
    "argentina": "AR",
    "chile": "CL",
    "colombia": "CO",
    "venezuela": "VE",
    "pakistan": "PK",
    "bangladesh": "BD",
    "vietnam": "VN",
    "thailand": "TH",
    "malaysia": "MY",
    "singapore": "SG",
    "indonesia": "ID",
    "philippines": "PH",
    "new zealand": "NZ",
}


def normalize_country_name(name: str) -> Optional[str]:
    """
    Normalize country name to ISO code.

    Args:
        name: Country name (e.g., "United States", "Russia")

    Returns:
        ISO 3166-1 alpha-2 country code or None
    """
    name_lower = name.lower().strip()
    return COUNTRY_NAME_TO_CODE.get(name_lower)
