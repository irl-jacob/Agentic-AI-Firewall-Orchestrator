"""GeoIP database service for storing and retrieving country IP ranges."""

import logging
from datetime import datetime
from typing import Optional

import httpx
from sqlalchemy import Column, DateTime, Integer, String, func, select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import declarative_base

from db.database import get_session

logger = logging.getLogger(__name__)

Base = declarative_base()


class GeoIPRange(Base):
    """GeoIP IP range model."""

    __tablename__ = "geoip_ranges"

    id = Column(Integer, primary_key=True, autoincrement=True)
    country_code = Column(String, nullable=False, index=True)
    country_name = Column(String)
    ip_range = Column(String, nullable=False)
    ip_version = Column(Integer, nullable=False, default=4, index=True)
    last_updated = Column(DateTime, default=datetime.utcnow)


class GeoIPDatabase:
    """Manages GeoIP IP ranges in the database."""

    # GitHub repo with country IP blocks
    GITHUB_BASE_URL = "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master"

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_country_ranges(self, country_code: str, ip_version: int = 4) -> list[str]:
        """
        Get IP ranges for a country from the database.

        Args:
            country_code: ISO country code (e.g., "RU", "CN")
            ip_version: 4 or 6 for IPv4/IPv6

        Returns:
            List of CIDR ranges (e.g., ["5.62.60.0/22", "5.62.62.0/23"])
        """
        country_code = country_code.upper()

        # Query database
        result = await self.session.execute(
            select(GeoIPRange.ip_range)
            .where(GeoIPRange.country_code == country_code)
            .where(GeoIPRange.ip_version == ip_version)
        )
        ranges = [row[0] for row in result.fetchall()]

        if not ranges:
            logger.warning(f"No IP ranges found for {country_code} (IPv{ip_version})")
            logger.info(f"Try running: python -m services.geoip_db --update {country_code}")

        return ranges

    async def download_country_ranges(self, country_code: str, ip_version: int = 4) -> list[str]:
        """
        Download IP ranges for a country from GitHub.

        Args:
            country_code: ISO country code
            ip_version: 4 or 6

        Returns:
            List of CIDR ranges
        """
        country_code = country_code.lower()
        ipv = "ipv4" if ip_version == 4 else "ipv6"

        url = f"{self.GITHUB_BASE_URL}/{ipv}/{country_code}.cidr"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                response.raise_for_status()

                # Parse CIDR ranges (one per line)
                ranges = [
                    line.strip()
                    for line in response.text.split("\n")
                    if line.strip() and not line.startswith("#")
                ]

                logger.info(f"Downloaded {len(ranges)} ranges for {country_code.upper()} (IPv{ip_version})")
                return ranges

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.error(f"Country code {country_code.upper()} not found in GeoIP database")
            else:
                logger.error(f"HTTP error downloading {country_code}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error downloading GeoIP data for {country_code}: {e}")
            return []

    async def import_country_ranges(
        self, country_code: str, ranges: list[str], ip_version: int = 4, country_name: Optional[str] = None
    ) -> int:
        """
        Import IP ranges for a country into the database.

        Args:
            country_code: ISO country code
            ranges: List of CIDR ranges
            ip_version: 4 or 6
            country_name: Optional country name

        Returns:
            Number of ranges imported
        """
        country_code = country_code.upper()

        # Delete existing ranges for this country
        await self.session.execute(
            delete(GeoIPRange)
            .where(GeoIPRange.country_code == country_code)
            .where(GeoIPRange.ip_version == ip_version)
        )

        # Insert new ranges
        imported = 0
        for ip_range in ranges:
            try:
                geoip_range = GeoIPRange(
                    country_code=country_code,
                    country_name=country_name,
                    ip_range=ip_range,
                    ip_version=ip_version,
                    last_updated=datetime.utcnow(),
                )
                self.session.add(geoip_range)
                imported += 1
            except Exception as e:
                logger.warning(f"Failed to import range {ip_range}: {e}")

        await self.session.commit()
        logger.info(f"Imported {imported} ranges for {country_code} (IPv{ip_version})")
        return imported

    async def update_country(self, country_code: str, ip_version: int = 4) -> bool:
        """
        Download and import IP ranges for a country.

        Args:
            country_code: ISO country code
            ip_version: 4 or 6

        Returns:
            True if successful
        """
        ranges = await self.download_country_ranges(country_code, ip_version)
        if not ranges:
            return False

        imported = await self.import_country_ranges(country_code, ranges, ip_version)
        return imported > 0

    async def get_country_count(self, country_code: str, ip_version: int = 4) -> int:
        """Get the number of IP ranges for a country."""
        result = await self.session.execute(
            select(func.count(GeoIPRange.id))
            .where(GeoIPRange.country_code == country_code.upper())
            .where(GeoIPRange.ip_version == ip_version)
        )
        return result.scalar() or 0


# CLI for testing and updates
if __name__ == "__main__":
    import asyncio
    import sys

    async def main():
        if len(sys.argv) < 3 or sys.argv[1] != "--update":
            print("Usage: python -m services.geoip_db --update <country_code>")
            print("Example: python -m services.geoip_db --update RU")
            sys.exit(1)

        country_code = sys.argv[2].upper()

        # Get session properly
        session_gen = get_session()
        session = await anext(session_gen)

        try:
            db = GeoIPDatabase(session)

            print(f"Downloading IP ranges for {country_code}...")
            success = await db.update_country(country_code, ip_version=4)

            if success:
                count = await db.get_country_count(country_code)
                print(f"✓ Successfully imported {count} IPv4 ranges for {country_code}")
            else:
                print(f"✗ Failed to download ranges for {country_code}")
                sys.exit(1)
        finally:
            await session.close()

    asyncio.run(main())
