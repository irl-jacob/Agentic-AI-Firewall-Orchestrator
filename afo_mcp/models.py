"""Pydantic models for AFO MCP server.

These schemas define the data structures used across all MCP tools,
ensuring type safety and validation for LLM-provided input.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class NetworkInterface(BaseModel):
    """A network interface with its configuration."""

    name: str = Field(..., description="Interface name (e.g., eth0, enp3s0)")
    mac_address: str | None = Field(None, description="MAC address if available")
    ipv4_addresses: list[str] = Field(
        default_factory=list, description="IPv4 addresses assigned"
    )
    ipv6_addresses: list[str] = Field(
        default_factory=list, description="IPv6 addresses assigned"
    )
    state: str = Field(..., description="Interface state (UP, DOWN, UNKNOWN)")
    mtu: int = Field(1500, description="Maximum transmission unit")
    vlan_id: int | None = Field(None, description="VLAN tag if applicable")
    rx_bytes: int = Field(0, description="Bytes received")
    tx_bytes: int = Field(0, description="Bytes transmitted")


class NetworkContext(BaseModel):
    """Complete network context for firewall rule generation."""

    interfaces: list[NetworkInterface] = Field(
        default_factory=list, description="All network interfaces"
    )
    active_ruleset: str = Field("", description="Current nftables ruleset (raw)")
    hostname: str = Field("", description="System hostname")
    timestamp: datetime = Field(
        default_factory=datetime.now, description="When context was captured"
    )


class RuleAction(StrEnum):
    """Firewall rule actions."""

    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"
    JUMP = "jump"
    RETURN = "return"
    LOG = "log"
    COUNTER = "counter"


class RuleDirection(StrEnum):
    """Traffic direction for rules."""

    INPUT = "input"
    OUTPUT = "output"
    FORWARD = "forward"


class Protocol(StrEnum):
    """Common network protocols."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    ANY = "any"


class FirewallRule(BaseModel):
    """A structured firewall rule."""

    id: str | None = Field(None, description="Unique rule identifier")
    table: str = Field("filter", description="nftables table name")
    chain: str = Field(..., description="Chain name (e.g., input, output, forward)")
    family: str = Field("inet", description="Address family (inet, ip, ip6)")

    # Match conditions
    protocol: Protocol | None = Field(None, description="Protocol to match")
    source_address: str | None = Field(
        None, description="Source IP/network (e.g., 10.0.0.0/8, 192.168.1.1)"
    )
    destination_address: str | None = Field(
        None, description="Destination IP/network (e.g., 10.0.0.0/8, 192.168.1.1)"
    )
    source_port: int | str | None = Field(
        None, description="Source port or range (e.g., 1024-65535)"
    )
    destination_port: int | str | None = Field(
        None, description="Destination port or range"
    )
    interface_in: str | None = Field(None, description="Input interface")
    interface_out: str | None = Field(None, description="Output interface")

    # Action
    action: RuleAction = Field(..., description="What to do with matching packets")
    jump_target: str | None = Field(None, description="Target chain for jump action")

    # Metadata
    comment: str | None = Field(None, description="Human-readable description")
    priority: int = Field(0, description="Rule priority (lower = earlier)")
    enabled: bool = Field(True, description="Whether rule is active")

    # TTL fields for temporary rules
    ttl_seconds: int | None = Field(None, description="Time-to-live in seconds for temporary rules")
    expires_at: datetime | None = Field(None, description="When the rule expires")
    is_temporary: bool = Field(False, description="Whether this rule auto-expires")

    def to_nft_command(self) -> str:
        """Convert rule to nftables command syntax."""
        parts = [f"add rule {self.family} {self.table} {self.chain}"]

        if self.interface_in:
            parts.append(f'iifname "{self.interface_in}"')
        if self.interface_out:
            parts.append(f'oifname "{self.interface_out}"')

        # Protocol handling: use "tcp dport"/"udp dport" for port matches
        # (which implies the protocol), or "meta l4proto X" when no ports.
        has_ports = (
            (self.source_port and self.protocol in (Protocol.TCP, Protocol.UDP))
            or (self.destination_port and self.protocol in (Protocol.TCP, Protocol.UDP))
        )
        if self.protocol and self.protocol != Protocol.ANY and not has_ports:
            parts.append(f"meta l4proto {self.protocol.value}")

        # Address matching requires ip/ip6 prefix
        if self.source_address:
            prefix = "ip6" if ":" in self.source_address else "ip"
            parts.append(f"{prefix} saddr {self.source_address}")
        if self.destination_address:
            prefix = "ip6" if ":" in self.destination_address else "ip"
            parts.append(f"{prefix} daddr {self.destination_address}")

        # Port matching with protocol prefix (e.g. "tcp dport 22")
        if self.source_port and self.protocol in (Protocol.TCP, Protocol.UDP):
            parts.append(f"{self.protocol.value} sport {self.source_port}")
        if self.destination_port and self.protocol in (Protocol.TCP, Protocol.UDP):
            parts.append(f"{self.protocol.value} dport {self.destination_port}")

        if self.comment:
            parts.append(f'comment "{self.comment}"')

        if self.action == RuleAction.JUMP and self.jump_target:
            parts.append(f"jump {self.jump_target}")
        else:
            parts.append(self.action.value)

        return " ".join(parts)


class RuleSet(BaseModel):
    """A collection of firewall rules."""

    name: str = Field(..., description="Ruleset name")
    description: str = Field("", description="Ruleset purpose")
    rules: list[FirewallRule] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    version: int = Field(1, description="Ruleset version for tracking changes")


class ValidationResult(BaseModel):
    """Result of syntax validation."""

    valid: bool = Field(..., description="Whether the syntax is valid")
    command: str = Field(..., description="The command that was validated")
    errors: list[str] = Field(default_factory=list, description="Error messages if invalid")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")
    line_numbers: list[int] = Field(
        default_factory=list, description="Line numbers with errors"
    )


class ConflictType(StrEnum):
    """Types of rule conflicts."""

    SHADOW = "shadow"  # New rule will never match (shadowed by existing)
    REDUNDANT = "redundant"  # New rule duplicates existing functionality
    CONTRADICTION = "contradiction"  # New rule contradicts existing rule
    OVERLAP = "overlap"  # Partial overlap in match criteria


class ConflictReport(BaseModel):
    """Report of detected conflicts between rules."""

    has_conflicts: bool = Field(..., description="Whether any conflicts were found")
    proposed_rule: str = Field(..., description="The rule being checked")
    conflicts: list[dict] = Field(
        default_factory=list,
        description="List of conflicts with type, existing rule, and explanation",
    )
    recommendations: list[str] = Field(
        default_factory=list, description="Suggested resolutions"
    )


class DeploymentStatus(StrEnum):
    """Status of a rule deployment."""

    PENDING = "pending"
    APPROVED = "approved"
    DEPLOYED = "deployed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class DeploymentResult(BaseModel):
    """Result of a deployment operation."""

    success: bool = Field(..., description="Whether deployment succeeded")
    status: DeploymentStatus = Field(..., description="Current deployment status")
    rule_id: str = Field(..., description="ID of the deployed rule")
    backup_path: str | None = Field(None, description="Path to rollback backup")
    error: str | None = Field(None, description="Error message if failed")
    timestamp: datetime = Field(default_factory=datetime.now)
    heartbeat_active: bool = Field(
        False, description="Whether heartbeat monitor is running"
    )
