"""AFO MCP Server - Exposes firewall orchestration tools to LLMs.

This server provides tools for:
- Gathering network context (interfaces, IPs, current rules)
- Validating nftables syntax
- Detecting rule conflicts
- Safe deployment with rollback capability
"""

import os
from typing import Any

from dotenv import load_dotenv
from fastmcp import FastMCP

from afo_mcp.models import (
    ConflictReport,
    DeploymentResult,
    NetworkContext,
)
from afo_mcp.tools.conflicts import detect_conflicts as _detect_conflicts
from afo_mcp.tools.deployer import (
    confirm_deployment,
    deploy_policy as _deploy_policy,
    rollback_deployment,
)
from afo_mcp.tools.learning import (
    approve_insight as _approve_insight,
    get_learning_metrics as _get_learning_metrics,
    get_pattern_details as _get_pattern_details,
    list_insights as _list_insights,
    list_learned_patterns as _list_learned_patterns,
    reject_insight as _reject_insight,
    validate_pattern as _validate_pattern,
)
from afo_mcp.tools.network import get_network_context as _get_network_context

# from afo_mcp.tools.validator import validate_syntax as _validate_syntax - Removed, using backend now

# Load environment variables
load_dotenv()

# Initialize FastMCP server
mcp = FastMCP("AFO - Autonomous Firewall Orchestrator")


@mcp.tool()
def get_network_context() -> dict[str, Any]:
    """Get current network context for firewall rule generation.

    Returns information about:
    - Network interfaces (names, IPs, MACs, VLANs, state)
    - Current nftables ruleset
    - System hostname

    Use this before generating firewall rules to understand the network topology.
    """
    ctx: NetworkContext = _get_network_context()
    return ctx.model_dump()


# @mcp.tool()
# def validate_syntax(command: str, platform: str = "nftables") -> dict[str, Any]:
    # Deprecated in favor of internal backend validation
    # keeping stub or removing? Removing for cleanup as per Phase 1 Plan 6
    # pass


@mcp.tool()
def detect_conflicts(proposed_rule: str, active_ruleset: str | None = None) -> dict[str, Any]:
    """Check for conflicts between a proposed rule and active rules.

    Args:
        proposed_rule: The nftables rule to check
        active_ruleset: Current ruleset (fetched automatically if not provided)

    Returns conflict report with:
    - has_conflicts: Whether any conflicts found
    - conflicts: List of {type, existing_rule, explanation}
    - recommendations: Suggested resolutions

    Conflict types:
    - shadow: New rule will never match (shadowed by existing)
    - redundant: New rule duplicates existing
    - contradiction: Rules have opposite actions
    - overlap: Partial overlap in criteria

    Run this before deploying new rules to catch issues early.
    """
    report: ConflictReport = _detect_conflicts(proposed_rule, active_ruleset)
    return report.model_dump()


@mcp.tool()
def deploy_policy(
    rule_id: str,
    rule_content: str,
    approved: bool = False,
    enable_heartbeat: bool = True,
    heartbeat_timeout: int = 30,
) -> dict[str, Any]:
    """Deploy a firewall rule with safety mechanisms.

    Args:
        rule_id: Unique identifier for tracking this rule
        rule_content: The nftables rule(s) to deploy
        approved: MUST be True to actually deploy (safety requirement)
        enable_heartbeat: Start auto-rollback timer (recommended)
        heartbeat_timeout: Seconds before auto-rollback (default 30)

    Returns deployment result with:
    - success: Whether deployment succeeded
    - status: pending/approved/deployed/failed/rolled_back
    - backup_path: Location of rollback backup
    - heartbeat_active: Whether auto-rollback is armed

    Safety features:
    1. Requires explicit approved=True
    2. Creates backup before any changes
    3. Heartbeat monitor auto-rolls back if not confirmed
    4. Use confirm_deployment() to finalize or rollback_deployment() to revert

    IMPORTANT: After deployment, call confirm_deployment(rule_id) to stop
    the auto-rollback timer, or let it expire to automatically revert.
    """
    result: DeploymentResult = _deploy_policy(
        rule_id=rule_id,
        rule_content=rule_content,
        approved=approved,
        enable_heartbeat=enable_heartbeat,
        heartbeat_timeout=heartbeat_timeout,
    )
    return result.model_dump()


@mcp.tool()
def confirm_rule_deployment(rule_id: str) -> dict[str, Any]:
    """Confirm a deployment and disable auto-rollback.

    Args:
        rule_id: The rule ID from deploy_policy()

    Call this after verifying the deployed rules work correctly.
    This stops the heartbeat timer that would otherwise rollback.

    Returns:
        success: Whether confirmation succeeded
    """
    success = confirm_deployment(rule_id)
    return {"success": success, "rule_id": rule_id}


@mcp.tool()
def rollback_rule(rule_id: str) -> dict[str, Any]:
    """Manually rollback a deployed rule.

    Args:
        rule_id: The rule ID to rollback

    Restores the system to the state before this rule was deployed.
    """
    result: DeploymentResult = rollback_deployment(rule_id)
    return result.model_dump()


@mcp.tool()
async def list_learned_patterns(
    pattern_type: str | None = None,
    min_confidence: float = 0.0,
    limit: int = 50,
) -> dict[str, Any]:
    """List patterns discovered by the learning system.

    Args:
        pattern_type: Filter by type (attack/false_positive/legitimate/anomaly)
        min_confidence: Minimum confidence threshold (0.0-1.0)
        limit: Maximum number of patterns to return

    Returns patterns with:
    - id, type, signature, confidence
    - evidence_count, first_seen, last_seen
    - source_ips, ports, protocols
    - validated status

    Use this to review what the system has learned from logs and deployments.
    """
    return await _list_learned_patterns(pattern_type, min_confidence, limit)


@mcp.tool()
async def get_pattern_details(pattern_id: int) -> dict[str, Any]:
    """Get detailed information about a specific learned pattern.

    Args:
        pattern_id: ID of the pattern to retrieve

    Returns:
    - Full pattern details including context and LLM analysis
    - Performance metrics (accuracy, feedback breakdown)

    Use this to investigate a pattern before validating or acting on it.
    """
    return await _get_pattern_details(pattern_id)


@mcp.tool()
async def validate_pattern(
    pattern_id: int,
    is_correct: bool,
    user: str = "system",
    comment: str | None = None,
) -> dict[str, Any]:
    """Provide feedback on a pattern's accuracy.

    Args:
        pattern_id: ID of the pattern to validate
        is_correct: Whether the pattern is correct
        user: User providing feedback
        comment: Optional comment explaining the validation

    Validates or invalidates a learned pattern. Incorrect patterns are
    deactivated and their confidence is reduced.

    Use this to improve the learning system's accuracy over time.
    """
    return await _validate_pattern(pattern_id, is_correct, user, comment)


@mcp.tool()
async def list_insights(
    insight_type: str | None = None,
    min_confidence: float = 0.0,
    pending_only: bool = True,
    limit: int = 50,
) -> dict[str, Any]:
    """List configuration insights generated by the learning system.

    Args:
        insight_type: Filter by type (rule_suggestion/preset_adjustment/signature_update)
        min_confidence: Minimum confidence threshold
        pending_only: Only show unapplied insights
        limit: Maximum number to return

    Returns insights with:
    - id, type, description, recommendation
    - reasoning, confidence, based_on_patterns
    - applied status, user_approved, safety_validated

    Insights are configuration recommendations based on learned patterns.
    Review and approve insights to apply them to your firewall.
    """
    return await _list_insights(insight_type, min_confidence, pending_only, limit)


@mcp.tool()
async def approve_insight(
    insight_id: int,
    user: str = "system",
) -> dict[str, Any]:
    """Approve an insight for application.

    Args:
        insight_id: ID of the insight to approve
        user: User approving the insight

    Approves a configuration insight. In manual mode, this will apply
    the insight immediately. In other modes, it marks the insight as
    approved for the next learning cycle.

    Use this after reviewing an insight and deciding it should be applied.
    """
    return await _approve_insight(insight_id, user)


@mcp.tool()
async def reject_insight(
    insight_id: int,
    user: str = "system",
    reason: str = "User rejected",
) -> dict[str, Any]:
    """Reject an insight and provide feedback.

    Args:
        insight_id: ID of the insight to reject
        user: User rejecting the insight
        reason: Reason for rejection

    Rejects a configuration insight and stores feedback. The insight
    will not be applied and the feedback helps improve future recommendations.

    Use this when an insight is incorrect or undesirable.
    """
    return await _reject_insight(insight_id, user, reason)


@mcp.tool()
async def get_learning_metrics(days: int = 7) -> dict[str, Any]:
    """Get learning system performance metrics.

    Args:
        days: Number of days to look back

    Returns:
    - Patterns detected by type
    - Insights generated by type
    - Insights applied count
    - Learning cycle metrics

    Use this to monitor the learning system's activity and effectiveness.
    """
    return await _get_learning_metrics(days)


def main() -> None:
    """Run the MCP server."""
    host = os.environ.get("MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("MCP_PORT", "8765"))

    print(f"Starting AFO MCP Server on {host}:{port}")
    print("Tools available:")
    print("  - get_network_context: Gather network state")
    print("  - detect_conflicts: Find rule conflicts")
    print("  - deploy_policy: Apply rules with rollback")
    print("  - confirm_rule_deployment: Finalize deployment")
    print("  - rollback_rule: Revert deployment")
    print("\nLearning System Tools:")
    print("  - list_learned_patterns: View discovered patterns")
    print("  - get_pattern_details: Detailed pattern info")
    print("  - validate_pattern: Provide pattern feedback")
    print("  - list_insights: View configuration recommendations")
    print("  - approve_insight: Approve recommendation")
    print("  - reject_insight: Reject recommendation")
    print("  - get_learning_metrics: View learning performance")

    mcp.run()


if __name__ == "__main__":
    main()
