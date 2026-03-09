import re

from afo_daemon.detection.models import SecurityEvent, ThreatSignature, ThreatType


class SignatureMatcher:
    """Evaluates log lines against known threat signatures."""

    def __init__(self, signatures: list[ThreatSignature] | None = None):
        self.signatures = signatures or self._default_signatures()
        # Compile regexes for performance
        self._compiled = [
            (sig, re.compile(sig.regex_pattern)) for sig in self.signatures
        ]

    def _default_signatures(self) -> list[ThreatSignature]:
        """Return built-in signatures."""
        return [
            ThreatSignature(
                name="SSH Failed Login",
                type=ThreatType.BRUTE_FORCE,
                # Pattern to capture IP from: "Failed password for [invalid user] root from 192.168.1.1 port ..."
                regex_pattern=r"Failed password for .*? from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                log_file="/var/log/auth.log",
                risk_level=5,
                description="Detects failed SSH login attempts",
            ),
            ThreatSignature(
                name="SSH Invalid User",
                type=ThreatType.BRUTE_FORCE,
                regex_pattern=r"Invalid user .*? from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                log_file="/var/log/auth.log",
                risk_level=5,
            ),
        ]

    def match(self, log_line: str, log_file: str) -> SecurityEvent | None:
        """Check if a log line matches any signature."""
        for sig, pattern in self._compiled:
            # Simple check: does the signature apply to this log file?
            # In a real system, we might route logs to specific matchers.
            # For now, allow matching if filename ends with the configured one (e.g. auth.log)
            if not log_file.endswith(sig.log_file.split("/")[-1]):
                continue

            match = pattern.search(log_line)
            if match:
                source_ip = match.group(1)
                return SecurityEvent(
                    source_ip=source_ip,
                    type=sig.type,
                    raw_log=log_line,
                    confidence=0.9,  # High confidence for regex match
                    context={"signature": sig.name, "log_file": log_file},
                )
        return None
