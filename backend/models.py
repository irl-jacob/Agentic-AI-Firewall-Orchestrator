from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Action(StrEnum):
    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"


class Protocol(StrEnum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ICMPV6 = "ICMPV6"
    ANY = "ANY"


class Direction(StrEnum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"


class PolicyRule(BaseModel):
    """
    Vendor-neutral representation of a firewall rule.
    """

    id: str | None = Field(None, description="Unique identifier for the rule")
    name: str = Field(..., description="Human-readable name of the rule")
    description: str | None = Field(None, description="Description of the rule purpose")

    direction: Direction
    action: Action
    protocol: Protocol

    source: str | None = Field(None, description="Source IP/CIDR (e.g., 10.0.0.1/32 or ANY)")
    destination: str | None = Field(None, description="Destination IP/CIDR")

    port: int | None = Field(None, description="Port number (if applicable)")

    priority: int = Field(100, description="Priority of the rule (lower is higher priority)")
    enabled: bool = Field(True, description="Whether the rule is active")

    # TTL fields for temporary rules
    ttl_seconds: int | None = Field(None, description="Time-to-live in seconds for temporary rules")
    expires_at: datetime | None = Field(None, description="When the rule expires (auto-calculated from ttl_seconds)")
    is_temporary: bool = Field(False, description="Whether this is a temporary rule that will auto-expire")
