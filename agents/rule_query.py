"""Rule query system for AFO.

Answers questions about active firewall rules.
"""

from backend.base import FirewallBackend
from backend.models import PolicyRule


class RuleQueryEngine:
    """Queries and filters firewall rules."""

    def __init__(self, backend: FirewallBackend):
        self.backend = backend

    async def query(self, question: str) -> str:
        """
        Answer a question about firewall rules.

        Args:
            question: Natural language question

        Returns:
            Answer as formatted string
        """
        question_lower = question.lower()

        # Get all rules
        try:
            rules = await self.backend.list_rules()
        except Exception as e:
            return f"Error retrieving rules: {e}"

        if not rules:
            return "No firewall rules are currently active."

        # Route to appropriate handler
        if "blocking port" in question_lower or "block port" in question_lower:
            return await self._rules_blocking_port(rules, question)
        elif "blocked ip" in question_lower or "blocked address" in question_lower:
            return await self._list_blocked_ips(rules)
        elif "why" in question_lower and "blocked" in question_lower:
            return await self._explain_why_blocked(rules, question)
        elif "conflict" in question_lower:
            return await self._check_conflicts(rules)
        elif "affecting" in question_lower or "affect" in question_lower:
            return await self._rules_affecting_target(rules, question)
        elif "show" in question_lower or "list" in question_lower:
            return await self._list_all_rules(rules, question)
        else:
            return "I can answer questions like:\n" \
                   "- 'What rules are blocking port 22?'\n" \
                   "- 'List all blocked IPs'\n" \
                   "- 'Why is 203.0.113.5 blocked?'\n" \
                   "- 'Are there any conflicting rules?'\n" \
                   "- 'What rules affect 10.0.0.5?'"

    async def _rules_blocking_port(self, rules: list[PolicyRule], question: str) -> str:
        """Find rules blocking a specific port."""
        import re

        # Extract port number
        port_match = re.search(r'\b(\d+)\b', question)
        if not port_match:
            return "Please specify a port number (e.g., 'port 22')."

        port = port_match.group(1)

        # Filter rules
        matching_rules = [
            r for r in rules
            if r.action.value in ["DROP", "REJECT"] and r.port == port
        ]

        if not matching_rules:
            return f"No rules are currently blocking port {port}."

        # Format response
        lines = [f"Rules blocking port {port}:"]
        for rule in matching_rules:
            source = rule.source or "any"
            dest = rule.destination or "any"
            lines.append(f"  • {rule.name}: {rule.action.value} from {source} to {dest}")

        return "\n".join(lines)

    async def _list_blocked_ips(self, rules: list[PolicyRule]) -> str:
        """List all blocked IP addresses."""
        blocked_ips = set()

        for rule in rules:
            if rule.action.value in ["DROP", "REJECT"]:
                if rule.source:
                    blocked_ips.add(rule.source)
                if rule.destination:
                    blocked_ips.add(rule.destination)

        if not blocked_ips:
            return "No IP addresses are currently blocked."

        lines = ["Blocked IP addresses:"]
        for ip in sorted(blocked_ips):
            lines.append(f"  • {ip}")

        return "\n".join(lines)

    async def _explain_why_blocked(self, rules: list[PolicyRule], question: str) -> str:
        """Explain why a specific IP is blocked."""
        import re

        # Extract IP address
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b'
        ip_match = re.search(ip_pattern, question)
        if not ip_match:
            return "Please specify an IP address (e.g., '203.0.113.5')."

        ip = ip_match.group(0)

        # Find matching rules
        matching_rules = []
        for rule in rules:
            if rule.action.value in ["DROP", "REJECT"]:
                if rule.source == ip or rule.destination == ip:
                    matching_rules.append(rule)
                # Check if IP is in subnet
                elif rule.source and "/" in rule.source:
                    # Simple subnet check (could be improved)
                    if ip.startswith(rule.source.split("/")[0][:7]):
                        matching_rules.append(rule)

        if not matching_rules:
            return f"{ip} is not currently blocked by any rules."

        # Format response
        lines = [f"{ip} is blocked by the following rules:"]
        for rule in matching_rules:
            reason = rule.description or "No description provided"
            lines.append(f"  • {rule.name}: {reason}")

        return "\n".join(lines)

    async def _check_conflicts(self, rules: list[PolicyRule]) -> str:
        """Check for conflicting rules."""
        conflicts = []

        # Simple conflict detection: same source/dest but different actions
        for i, rule1 in enumerate(rules):
            for rule2 in rules[i+1:]:
                if (rule1.source == rule2.source and
                    rule1.destination == rule2.destination and
                    rule1.port == rule2.port and
                    rule1.protocol == rule2.protocol):

                    if rule1.action != rule2.action:
                        conflicts.append((rule1, rule2))

        if not conflicts:
            return "No obvious conflicts detected in current rules."

        lines = ["Conflicting rules detected:"]
        for rule1, rule2 in conflicts:
            lines.append(f"  • {rule1.name} ({rule1.action.value}) vs {rule2.name} ({rule2.action.value})")
            lines.append(f"    Both affect: {rule1.source or 'any'} → {rule1.destination or 'any'}")

        return "\n".join(lines)

    async def _rules_affecting_target(self, rules: list[PolicyRule], question: str) -> str:
        """Find rules affecting a specific IP or port."""
        import re

        # Extract IP or port
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b'
        ip_match = re.search(ip_pattern, question)

        if ip_match:
            target = ip_match.group(0)
            matching_rules = [
                r for r in rules
                if r.source == target or r.destination == target
            ]

            if not matching_rules:
                return f"No rules currently affect {target}."

            lines = [f"Rules affecting {target}:"]
            for rule in matching_rules:
                lines.append(f"  • {rule.name}: {rule.action.value} {rule.protocol.value} port {rule.port or 'any'}")

            return "\n".join(lines)

        return "Please specify an IP address or port."

    async def _list_all_rules(self, rules: list[PolicyRule], question: str) -> str:
        """List all rules with optional filtering."""
        if not rules:
            return "No firewall rules are currently active."

        # Check for filters
        question_lower = question.lower()
        filtered_rules = rules

        if "block" in question_lower or "drop" in question_lower:
            filtered_rules = [r for r in rules if r.action.value in ["DROP", "REJECT"]]
        elif "allow" in question_lower or "accept" in question_lower:
            filtered_rules = [r for r in rules if r.action.value == "ACCEPT"]

        if not filtered_rules:
            return "No rules match your filter criteria."

        # Format response
        lines = [f"Active firewall rules ({len(filtered_rules)}):"]
        for rule in filtered_rules[:20]:  # Limit to 20 rules
            source = rule.source or "any"
            dest = rule.destination or "any"
            port = f":{rule.port}" if rule.port else ""
            lines.append(
                f"  • {rule.name}: {rule.action.value} {rule.protocol.value}{port} "
                f"from {source} to {dest}"
            )

        if len(filtered_rules) > 20:
            lines.append(f"  ... and {len(filtered_rules) - 20} more")

        return "\n".join(lines)


# Global instance
_rule_query_engine: RuleQueryEngine | None = None


def get_rule_query_engine(backend: FirewallBackend) -> RuleQueryEngine:
    """Get or create rule query engine."""
    global _rule_query_engine
    if _rule_query_engine is None or _rule_query_engine.backend != backend:
        _rule_query_engine = RuleQueryEngine(backend)
    return _rule_query_engine


async def query_rules(backend: FirewallBackend, question: str) -> str:
    """
    Query firewall rules.

    Args:
        backend: Firewall backend
        question: Natural language question

    Returns:
        Answer as formatted string
    """
    engine = get_rule_query_engine(backend)
    return await engine.query(question)
