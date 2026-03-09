"""Conflict detection tool - identifies rule conflicts before deployment."""

import re
from dataclasses import dataclass
from ipaddress import IPv4Network, ip_network

from afo_mcp.models import ConflictReport, ConflictType


@dataclass
class ParsedRule:
    """A parsed nftables rule for comparison."""

    table: str = ""
    chain: str = ""
    family: str = "inet"
    protocol: str | None = None
    saddr: str | None = None
    daddr: str | None = None
    sport: str | None = None
    dport: str | None = None
    iif: str | None = None
    oif: str | None = None
    action: str = ""
    raw: str = ""


def _parse_rule(rule_text: str) -> ParsedRule | None:
    """Parse an nftables rule into structured form."""
    rule_text = rule_text.strip()
    if not rule_text or rule_text.startswith("#"):
        return None

    parsed = ParsedRule(raw=rule_text)

    # Extract table/chain from context or rule
    # Format: add rule inet filter input ...
    add_match = re.match(
        r"add rule\s+(\w+)\s+(\w+)\s+(\w+)\s+(.+)", rule_text, re.IGNORECASE
    )
    if add_match:
        parsed.family = add_match.group(1)
        parsed.table = add_match.group(2)
        parsed.chain = add_match.group(3)
        rule_body = add_match.group(4)
    else:
        rule_body = rule_text

    # Parse match conditions
    # Protocol
    proto_match = re.search(r"\b(tcp|udp|icmp|icmpv6)\b", rule_body, re.IGNORECASE)
    if proto_match:
        parsed.protocol = proto_match.group(1).lower()

    # Source address
    saddr_match = re.search(r"(?:ip\s+)?saddr\s+(\S+)", rule_body)
    if saddr_match:
        parsed.saddr = saddr_match.group(1)

    # Destination address
    daddr_match = re.search(r"(?:ip\s+)?daddr\s+(\S+)", rule_body)
    if daddr_match:
        parsed.daddr = daddr_match.group(1)

    # Source port
    sport_match = re.search(r"sport\s+(\S+)", rule_body)
    if sport_match:
        parsed.sport = sport_match.group(1)

    # Destination port
    dport_match = re.search(r"dport\s+(\S+)", rule_body)
    if dport_match:
        parsed.dport = dport_match.group(1)

    # Input interface
    iif_match = re.search(r"iifname\s+[\"']?(\S+?)[\"']?(?:\s|$)", rule_body)
    if iif_match:
        parsed.iif = iif_match.group(1)

    # Output interface
    oif_match = re.search(r"oifname\s+[\"']?(\S+?)[\"']?(?:\s|$)", rule_body)
    if oif_match:
        parsed.oif = oif_match.group(1)

    # Action (last word that's an action keyword)
    action_match = re.search(
        r"\b(accept|drop|reject|return|jump|goto|log|counter)\b",
        rule_body,
        re.IGNORECASE,
    )
    if action_match:
        parsed.action = action_match.group(1).lower()

    return parsed


def _networks_overlap(net1_str: str, net2_str: str) -> bool:
    """Check if two network specifications overlap."""
    try:
        # Handle bare IPs by adding /32 or /128
        if "/" not in net1_str:
            net1_str = f"{net1_str}/32" if ":" not in net1_str else f"{net1_str}/128"
        if "/" not in net2_str:
            net2_str = f"{net2_str}/32" if ":" not in net2_str else f"{net2_str}/128"

        net1 = ip_network(net1_str, strict=False)
        net2 = ip_network(net2_str, strict=False)

        # Check if same IP version (both IPv4 or both IPv6)
        net1_is_v4 = isinstance(net1, IPv4Network)
        net2_is_v4 = isinstance(net2, IPv4Network)
        if net1_is_v4 != net2_is_v4:
            return False

        return net1.overlaps(net2)
    except ValueError:
        # If we can't parse, assume potential overlap for safety
        return True


def _ports_overlap(port1: str | None, port2: str | None) -> bool:
    """Check if two port specifications overlap."""
    if port1 is None or port2 is None:
        # None means "any port", which overlaps with everything
        return True

    def parse_port_range(p: str) -> set[int]:
        """Parse port or port range into set of ports."""
        p = p.strip()
        if "-" in p:
            start, end = p.split("-")
            return set(range(int(start), int(end) + 1))
        elif "," in p:
            return {int(x.strip()) for x in p.split(",")}
        else:
            return {int(p)}

    try:
        ports1 = parse_port_range(port1)
        ports2 = parse_port_range(port2)
        return bool(ports1 & ports2)
    except ValueError:
        return True


def _rules_overlap(rule1: ParsedRule, rule2: ParsedRule) -> bool:
    """Check if two rules have overlapping match criteria."""
    # Must be same table/chain
    if rule1.table and rule2.table and rule1.table != rule2.table:
        return False
    if rule1.chain and rule2.chain and rule1.chain != rule2.chain:
        return False

    # Check protocol
    if rule1.protocol and rule2.protocol and rule1.protocol != rule2.protocol:
        return False

    # Check addresses
    if rule1.saddr and rule2.saddr:
        if not _networks_overlap(rule1.saddr, rule2.saddr):
            return False
    if rule1.daddr and rule2.daddr:
        if not _networks_overlap(rule1.daddr, rule2.daddr):
            return False

    # Check ports
    if not _ports_overlap(rule1.sport, rule2.sport):
        return False
    if not _ports_overlap(rule1.dport, rule2.dport):
        return False

    # Check interfaces
    if rule1.iif and rule2.iif and rule1.iif != rule2.iif:
        return False
    if rule1.oif and rule2.oif and rule1.oif != rule2.oif:
        return False

    return True


def _detect_conflict_type(
    proposed: ParsedRule, existing: ParsedRule
) -> tuple[ConflictType, str] | None:
    """Determine the type of conflict between two rules."""
    if not _rules_overlap(proposed, existing):
        return None

    # Check for contradiction (same match, opposite action)
    if proposed.action and existing.action:
        accept_actions = {"accept"}
        deny_actions = {"drop", "reject"}

        proposed_accepts = proposed.action in accept_actions
        proposed_denies = proposed.action in deny_actions
        existing_accepts = existing.action in accept_actions
        existing_denies = existing.action in deny_actions

        if (proposed_accepts and existing_denies) or (proposed_denies and existing_accepts):
            return (
                ConflictType.CONTRADICTION,
                f"Opposite actions: proposed={proposed.action}, existing={existing.action}",
            )

    # Check for redundancy (same match and action)
    if proposed.action == existing.action:
        return (
            ConflictType.REDUNDANT,
            "Proposed rule duplicates existing rule functionality",
        )

    # Check for shadowing (existing rule matches broader, will catch traffic first)
    # This is a simplified check - existing is broader if it has fewer specific criteria
    existing_specificity = sum([
        existing.protocol is not None,
        existing.saddr is not None,
        existing.daddr is not None,
        existing.sport is not None,
        existing.dport is not None,
        existing.iif is not None,
        existing.oif is not None,
    ])
    proposed_specificity = sum([
        proposed.protocol is not None,
        proposed.saddr is not None,
        proposed.daddr is not None,
        proposed.sport is not None,
        proposed.dport is not None,
        proposed.iif is not None,
        proposed.oif is not None,
    ])

    if existing_specificity < proposed_specificity:
        return (
            ConflictType.SHADOW,
            "Proposed rule may be shadowed by less specific existing rule",
        )

    return (ConflictType.OVERLAP, "Rules have overlapping match criteria")


def detect_conflicts(
    proposed_rule: str, active_ruleset: str | None = None
) -> ConflictReport:
    """Detect conflicts between a proposed rule and the active ruleset.

    Args:
        proposed_rule: The nftables rule to check
        active_ruleset: Current ruleset (if None, fetches from system)

    Returns:
        ConflictReport with any detected conflicts and recommendations.

    This tool performs basic conflict detection. In Phase 2, this will be
    enhanced with Z3 solver for formal verification.
    """
    conflicts: list[dict] = []
    recommendations: list[str] = []

    # Get active ruleset if not provided
    if active_ruleset is None:
        from afo_mcp.tools.network import get_network_context

        ctx = get_network_context()
        active_ruleset = ctx.active_ruleset

    # Parse proposed rule
    proposed = _parse_rule(proposed_rule)
    if proposed is None:
        return ConflictReport(
            has_conflicts=False,
            proposed_rule=proposed_rule,
            conflicts=[],
            recommendations=["Could not parse proposed rule"],
        )

    # Extract rules from active ruleset
    # Look for lines within chain blocks
    in_chain = False
    current_chain = ""
    current_table = ""
    current_family = ""

    for line in active_ruleset.split("\n"):
        line = line.strip()

        # Track table context
        table_match = re.match(r"table\s+(\w+)\s+(\w+)\s*\{?", line)
        if table_match:
            current_family = table_match.group(1)
            current_table = table_match.group(2)
            continue

        # Track chain context
        chain_match = re.match(r"chain\s+(\w+)\s*\{?", line)
        if chain_match:
            current_chain = chain_match.group(1)
            in_chain = True
            continue

        if line == "}":
            if in_chain:
                in_chain = False
            continue

        # Parse rule within chain
        if in_chain and line and not line.startswith("type ") and not line.startswith("policy "):
            # Construct full rule context
            existing = _parse_rule(line)
            if existing:
                existing.family = current_family
                existing.table = current_table
                existing.chain = current_chain

                conflict = _detect_conflict_type(proposed, existing)
                if conflict:
                    conflict_type, explanation = conflict
                    conflicts.append({
                        "type": conflict_type.value,
                        "existing_rule": line,
                        "explanation": explanation,
                    })

    # Generate recommendations
    if conflicts:
        conflict_types = {c["type"] for c in conflicts}

        if ConflictType.CONTRADICTION.value in conflict_types:
            recommendations.append(
                "Review rule logic - contradicting rules may cause unexpected behavior"
            )
        if ConflictType.SHADOW.value in conflict_types:
            recommendations.append(
                "Consider rule ordering or make the proposed rule more specific"
            )
        if ConflictType.REDUNDANT.value in conflict_types:
            recommendations.append(
                "This rule may be unnecessary - consider removing if truly redundant"
            )
        if ConflictType.OVERLAP.value in conflict_types:
            recommendations.append(
                "Verify intended behavior for overlapping traffic"
            )

    return ConflictReport(
        has_conflicts=len(conflicts) > 0,
        proposed_rule=proposed_rule,
        conflicts=conflicts,
        recommendations=recommendations,
    )
