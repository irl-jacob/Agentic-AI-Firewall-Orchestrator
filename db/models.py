from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


def _utcnow() -> datetime:
    """Timezone-aware UTC now (replaces deprecated datetime.utcnow)."""
    return datetime.now(timezone.utc)


class DeploymentLog(SQLModel, table=True):
    """Log of firewall rule deployments."""

    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=_utcnow)
    status: str
    details: str
    rule_id: str
    expires_at: datetime | None = Field(default=None, description="When the rule expires (for temporary rules)")


class AuditEntry(SQLModel, table=True):
    """Audit log for security actions."""

    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=_utcnow)
    action: str
    user: str
    details: str
    resource_id: str | None = None

    # Enhanced audit fields
    original_command: str | None = Field(default=None, description="Original natural language command")
    parsed_intent: str | None = Field(default=None, description="Parsed intent JSON")
    mcp_call: str | None = Field(default=None, description="MCP tool call (name + args)")
    mcp_response: str | None = Field(default=None, description="MCP response JSON")
    user_confirmed: bool = Field(default=False, description="Whether user confirmed high-risk action")
    snapshot_id: int | None = Field(default=None, description="Link to RuleSnapshot")
    risk_level: str | None = Field(default=None, description="Risk level: low, medium, high, critical")


class RuleSnapshot(SQLModel, table=True):
    """Snapshot of firewall ruleset for rollback."""

    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=_utcnow)
    user: str
    description: str  # "Before deploying rule X"
    ruleset_json: str  # Full ruleset as JSON
    original_command: str = Field(default="", description="NL command that triggered this")
    parsed_intent: str = Field(default="", description="JSON of parsed intent")
    can_rollback: bool = Field(default=True, description="Whether this snapshot can be rolled back to")


class ActiveConfig(SQLModel, table=True):
    """Track which preset configuration is currently active."""

    id: int | None = Field(default=None, primary_key=True)
    preset_name: str = Field(description="Name of the applied preset")
    preset_version: str = Field(description="Version of the preset")
    applied_at: datetime = Field(default_factory=_utcnow)
    applied_by: str = Field(default="system", description="User who applied the preset")
    snapshot_id: int | None = Field(default=None, description="Link to RuleSnapshot")
    rule_ids: str = Field(default="[]", description="JSON array of rule IDs deployed by this preset")


class LearnedPattern(SQLModel, table=True):
    """Stores discovered patterns from log analysis."""

    id: int | None = Field(default=None, primary_key=True)
    pattern_type: str = Field(description="attack/false_positive/legitimate/anomaly")
    signature: str = Field(description="Pattern signature (e.g., regex, IP range)")
    confidence: float = Field(description="Confidence score 0.0-1.0")
    evidence_count: int = Field(default=1, description="Number of observations")
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    source_ips: str = Field(default="[]", description="JSON array of source IPs")
    ports: str = Field(default="[]", description="JSON array of ports")
    protocols: str = Field(default="[]", description="JSON array of protocols")
    context: str = Field(default="{}", description="Additional context as JSON")
    llm_analysis: str | None = Field(default=None, description="LLM-generated analysis")
    validated: bool = Field(default=False, description="User validated this pattern")
    active: bool = Field(default=True, description="Pattern is active for matching")


class ConfigInsight(SQLModel, table=True):
    """Configuration recommendations based on patterns."""

    id: int | None = Field(default=None, primary_key=True)
    insight_type: str = Field(description="rule_suggestion/preset_adjustment/signature_update")
    description: str = Field(description="Human-readable description")
    recommendation: str = Field(description="Recommendation details as JSON")
    reasoning: str = Field(description="Why this recommendation was made")
    confidence: float = Field(description="Confidence score 0.0-1.0")
    based_on_patterns: str = Field(default="[]", description="JSON array of pattern IDs")
    created_at: datetime = Field(default_factory=_utcnow)
    applied: bool = Field(default=False, description="Whether recommendation was applied")
    applied_at: datetime | None = Field(default=None)
    user_approved: bool = Field(default=False, description="User approved this insight")
    safety_validated: bool = Field(default=False, description="Passed safety checks")
    impact_assessment: str = Field(default="{}", description="Impact analysis as JSON")


class LearningMetric(SQLModel, table=True):
    """Tracks learning system performance."""

    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=_utcnow)
    metric_type: str = Field(description="pattern_detected/false_positive/true_positive/config_applied")
    value: float = Field(description="Metric value")
    context: str = Field(default="{}", description="Additional context as JSON")
    pattern_id: int | None = Field(default=None, description="Related pattern ID")
    insight_id: int | None = Field(default=None, description="Related insight ID")


class PatternFeedback(SQLModel, table=True):
    """User feedback on patterns and recommendations."""

    id: int | None = Field(default=None, primary_key=True)
    pattern_id: int | None = Field(default=None, description="Related pattern ID")
    insight_id: int | None = Field(default=None, description="Related insight ID")
    feedback_type: str = Field(description="correct/incorrect/partial/dangerous")
    user: str = Field(description="User who provided feedback")
    comment: str | None = Field(default=None, description="Optional comment")
    timestamp: datetime = Field(default_factory=_utcnow)

