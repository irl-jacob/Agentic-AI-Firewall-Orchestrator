import asyncio
import os
from collections.abc import Callable

from afo_daemon.detection.models import SecurityEvent
from afo_daemon.detection.signatures import SignatureMatcher


class LogMonitor:
    """
    Monitors log files for new entries and matches them against signatures.
    Simple polling implementation for portability (Watchdog can be added later).
    """

    def __init__(
        self,
        files: list[str],
        callback: Callable[[SecurityEvent], None],
        matcher: SignatureMatcher | None = None,
    ):
        self.files = files
        self.callback = callback
        self.matcher = matcher or SignatureMatcher()
        self.running = False
        self._file_pointers = {}

    async def start(self) -> None:
        """Start monitoring."""
        self.running = True
        # Seek to end of files initially to avoid processing old logs
        for file_path in self.files:
            if os.path.exists(file_path):
                with open(file_path) as f:
                    f.seek(0, 2)
                    self._file_pointers[file_path] = f.tell()

        while self.running:
            for file_path in self.files:
                if not os.path.exists(file_path):
                    continue

                await self._process_file(file_path)

            await asyncio.sleep(1)  # Poll interval

    async def _process_file(self, file_path: str) -> None:
        """Read new lines from file."""
        try:
            current_size = os.path.getsize(file_path)
            last_pos = self._file_pointers.get(file_path, 0)

            if current_size < last_pos:
                # File rotated (truncated)
                last_pos = 0

            if current_size > last_pos:
                with open(file_path) as f:
                    f.seek(last_pos)
                    lines = f.readlines()
                    self._file_pointers[file_path] = f.tell()

                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue

                        event = self.matcher.match(line, file_path)
                        if event:
                            # Invoke callback (potentially async, but callback def is sync here)
                            # If callback is async, we should await it.
                            # For now, assume sync or fire-and-forget.
                            if asyncio.iscoroutinefunction(self.callback):
                                await self.callback(event)
                            else:
                                self.callback(event)
        except Exception:
            pass  # Log error in production

    def stop(self) -> None:
        """Stop monitoring."""
        self.running = False
