import asyncio

from afo_daemon.intelligence.feeds import IntelRecord, ThreatFeed


class IntelResult(IntelRecord):
    """Aggregated result for an IP."""
    pass


class IntelManager:
    """Aggregates threat intelligence from multiple feeds."""

    def __init__(self, feeds: list[ThreatFeed]):
        self.feeds = feeds
        self.cache: dict[str, IntelRecord] = {}
        self.last_update = None

    async def update_feeds(self) -> None:
        """Fetch data from all feeds."""
        tasks = [feed.fetch() for feed in self.feeds]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        count = 0
        for result in results:
            if isinstance(result, list):
                for record in result:
                    self.cache[record.ip] = record
                    count += 1

        self.last_update = __import__("datetime").datetime.now()

    def check_ip(self, ip: str) -> IntelResult | None:
        """Check if an IP is known to be malicious."""
        record = self.cache.get(ip)
        if record:
            return IntelResult(**record.model_dump())
        return None
