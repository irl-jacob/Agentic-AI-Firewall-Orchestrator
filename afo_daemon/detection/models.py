from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ThreatType(StrEnum):
    BRUTE_FORCE = "BRUTE_FORCE"
    PORT_SCAN = "PORT_SCAN"
    DOS = "DOS"
    MALICIOUS_IP = "MALICIOUS_IP"
    UNKNOWN = "UNKNOWN"


class SecurityEvent(BaseModel):
    """Represents a detected security threat."""

    timestamp: datetime = Field(default_factory=datetime.now)
    source_ip: str
    type: ThreatType
    raw_log: str
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    context: dict = Field(default_factory=dict)


class ThreatSignature(BaseModel):
    """Regex-based signature for identifying threats in logs."""

    name: str
    type: ThreatType
    regex_pattern: str
    log_file: str
    risk_level: int = Field(5, ge=1, le=10)
    description: str | None = None
