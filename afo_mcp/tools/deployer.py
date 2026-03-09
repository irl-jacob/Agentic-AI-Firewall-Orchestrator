"""Deployment tool - safely applies firewall rules via FirewallService."""

import asyncio
from collections.abc import Callable

from afo_mcp.models import (
    DeploymentResult,
    DeploymentStatus,
    FirewallRule,
    Protocol,
    RuleAction,
)
from backend.models import Action, Direction, PolicyRule, Protocol as BackendProtocol
from backend.nftables import NftablesBackend
from db.database import get_session
from services.firewall import FirewallService


# Convert MCP models to Backend models
def _convert_rule(mcp_rule: FirewallRule) -> PolicyRule:
    # Map Action
    action_map = {
        RuleAction.ACCEPT: Action.ACCEPT,
        RuleAction.DROP: Action.DROP,
        RuleAction.REJECT: Action.REJECT,
    }
    # Default to DROP if unknown or complex (JUMP/LOG not fully supported in backend yet)
    action = action_map.get(mcp_rule.action, Action.DROP)

    # Map Protocol
    protocol_map = {
        Protocol.TCP: BackendProtocol.TCP,
        Protocol.UDP: BackendProtocol.UDP,
        Protocol.ICMP: BackendProtocol.ICMP,
        Protocol.ICMPV6: BackendProtocol.ICMP, # Mapping ICMPv6 to ICMP for now or need to expand backend
        Protocol.ANY: BackendProtocol.ANY,
    }
    protocol = protocol_map.get(mcp_rule.protocol, BackendProtocol.ANY)

    # Map Direction
    # MCP rules have "chain" (input, output, forward). Backend uses Direction enum.
    direction_map = {
        "input": Direction.INBOUND,
        "output": Direction.OUTBOUND,
        "forward": Direction.INBOUND, # Approximate mapping
    }
    direction = direction_map.get(mcp_rule.chain, Direction.INBOUND)

    return PolicyRule(
        name=f"rule_{mcp_rule.id}" if mcp_rule.id else "generated_rule",
        description=mcp_rule.comment,
        direction=direction,
        action=action,
        protocol=protocol,
        source=mcp_rule.source_address,
        destination=mcp_rule.destination_address,
        port=int(mcp_rule.destination_port) if mcp_rule.destination_port else None,
        enabled=mcp_rule.enabled,
        id=mcp_rule.id
    )

def deploy_policy(
    rule_id: str,
    rule_content: str, # Legacy: was raw nft content.
    approved: bool = False,
    enable_heartbeat: bool = True,
    heartbeat_timeout: int | None = None,
    heartbeat_fn: Callable[[], bool] | None = None,
    structured_rule: FirewallRule | None = None, # New: passing structured rule
) -> DeploymentResult:
    """
    Deploy a firewall rule using the FirewallService.

    Note: 'rule_content' (raw string) is deprecated in favor of 'structured_rule'.
    If 'structured_rule' is provided, it is used. Otherwise, we fail as parsing raw nft is not fully implemented.
    """
    if not approved:
         return DeploymentResult(
            success=False,
            status=DeploymentStatus.PENDING,
            rule_id=rule_id,
            error="Deployment requires explicit approval (approved=True)",
        )

    if structured_rule is None:
         return DeploymentResult(
            success=False,
            status=DeploymentStatus.FAILED,
            rule_id=rule_id,
            error="Deployment requires structured_rule (raw content deployment deprecated)",
        )

    # We need to run async code in this sync function
    # In a real app, this would be refactored to be fully async
    try:
        policy_rule = _convert_rule(structured_rule)

        async def _run_deploy():
            # Setup dependencies
            # In a real app, these would be injected or singletons
            backend = NftablesBackend()
            async for session in get_session():
                service = FirewallService(backend, session)
                success, message = await service.deploy_rule(policy_rule, user="mcp_agent")
                return success, message

        success, message = asyncio.run(_run_deploy())

        if success:
             return DeploymentResult(
                success=True,
                status=DeploymentStatus.DEPLOYED,
                rule_id=rule_id,
                heartbeat_active=False # Heartbeat handled by service/backend if implemented
            )
        else:
             return DeploymentResult(
                success=False,
                status=DeploymentStatus.FAILED,
                rule_id=rule_id,
                error=message
            )

    except Exception as e:
        return DeploymentResult(
            success=False,
            status=DeploymentStatus.FAILED,
            rule_id=rule_id,
            error=f"Adapter error: {str(e)}"
        )

def rollback_deployment(rule_id: str) -> DeploymentResult:
    """Rollback using FirewallService."""
    try:
        async def _run_rollback():
            backend = NftablesBackend()
            async for session in get_session():
                service = FirewallService(backend, session)
                return await service.rollback(steps=1, user="mcp_agent")

        success = asyncio.run(_run_rollback())

        status = DeploymentStatus.ROLLED_BACK if success else DeploymentStatus.FAILED
        return DeploymentResult(
            success=success,
            status=status,
            rule_id=rule_id,
            error=None if success else "Rollback failed"
        )
    except Exception as e:
        return DeploymentResult(
            success=False,
            status=DeploymentStatus.FAILED,
            rule_id=rule_id,
            error=f"Adapter error: {str(e)}"
        )

# Stub for confirm_deployment as it's less relevant with the new architecture
def confirm_deployment(rule_id: str) -> bool:
    return True
