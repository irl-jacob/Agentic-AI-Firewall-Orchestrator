from abc import ABC, abstractmethod
from datetime import datetime

from pydantic import BaseModel, Field


class IntelRecord(BaseModel):
    """Information about a malicious entity."""

    ip: str
    source: str
    tags: list[str] = Field(default_factory=list)
    confidence: float = 1.0
    last_seen: datetime = Field(default_factory=datetime.now)


class ThreatFeed(ABC):
    """Abstract base class for threat intelligence feeds."""

    def __init__(self, name: str, url: str):
        self.name = name
        self.url = url

    @abstractmethod
    async def fetch(self) -> list[IntelRecord]:
        """Fetch and parse threat data."""
        pass


class TextListFeed(ThreatFeed):
    """Generic feed parsing plain text IP lists (one per line)."""

    async def fetch(self) -> list[IntelRecord]:
        # In a real implementation, we'd use aiohttp to fetch self.url
        # For this phase, we'll simulate or read local file if url is a path
        records = []
        try:
            # Simple simulation for now
            # If URL starts with http, would fetch.
            # Assuming it returns a list of IPs.
            # For simplicity in this demo, let's mock the data source
            # or rely on subclasses to override or inject a fetcher.
            pass
        except Exception:
            pass
        return records


class MockFeed(ThreatFeed):
    """Mock feed for testing."""

    def __init__(self, name: str, ips: list[str]):
        super().__init__(name, "mock://")
        self.ips = ips

    async def fetch(self) -> list[IntelRecord]:
        return [
            IntelRecord(ip=ip, source=self.name, tags=["mock_threat"], confidence=0.8)
            for ip in self.ips
        ]
