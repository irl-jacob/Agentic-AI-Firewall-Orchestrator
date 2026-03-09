"""Risk analysis for firewall rules.

Identifies high-risk operations that require explicit user confirmation.
"""

from dataclasses import dataclass
from enum import Enum

from backend.models import PolicyRule


class RiskLevel(Enum):
    """Risk levels for firewall operations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskAssessment:
    """Risk assessment result."""
    level: RiskLevel
    reasons: list[str]
    requires_confirmation: bool
    warning_message: str | None = None
    bypass_on_urgency: bool = False  # Can skip confirmation if urgent


class RiskAnalyzer:
    """Analyzes firewall rules for risk."""

    def __init__(self):
        # Critical ports that should rarely be blocked from all sources
        self.critical_ports = {
            22: "SSH",
            443: "HTTPS",
            80: "HTTP",
            3389: "RDP",
        }

        # Private/internal subnets
        self.private_subnets = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]

    def assess_rule(self, rule: PolicyRule, user_input: str = "") -> RiskAssessment:
        """
        Assess the risk level of a firewall rule.

        Args:
            rule: PolicyRule to assess
            user_input: Original user input (for context)

        Returns:
            RiskAssessment object
        """
        reasons = []
        risk_level = RiskLevel.LOW
        requires_confirmation = False
        warning_message = None
        bypass_on_urgency = False

        # Check for blocking all traffic
        if (rule.action.value in ["DROP", "REJECT"] and
            not rule.source and not rule.destination and
            not rule.port and not rule.protocol):
            reasons.append("Blocks ALL traffic (will disconnect you)")
            risk_level = RiskLevel.CRITICAL
            requires_confirmation = True
            warning_message = "⚠️  CRITICAL: This will block ALL traffic and disconnect you from the server!"

        # Check for blocking large subnets
        elif rule.source or rule.destination:
            target = rule.source or rule.destination
            if "/" in target:
                prefix = int(target.split("/")[1])
                if prefix <= 16:
                    reasons.append(f"Affects large subnet ({target})")
                    risk_level = RiskLevel.HIGH
                    requires_confirmation = True
                    warning_message = f"⚠️  This rule affects a large subnet ({target}) with potentially millions of IPs."
                elif prefix <= 24:
                    reasons.append(f"Affects subnet ({target})")
                    risk_level = RiskLevel.MEDIUM

        # Check for blocking critical ports from all sources
        if rule.port and rule.action.value in ["DROP", "REJECT"]:
            try:
                port_num = int(rule.port)
                if port_num in self.critical_ports and not rule.source:
                    service_name = self.critical_ports[port_num]
                    reasons.append(f"Blocks {service_name} (port {port_num}) from ALL sources")
                    risk_level = RiskLevel.HIGH
                    requires_confirmation = True
                    warning_message = f"⚠️  This will block {service_name} from ALL sources. You may lose access!"
                    bypass_on_urgency = True  # Allow bypass if under attack
            except ValueError:
                pass

        # Check for blocking internal/private subnets
        if rule.action.value in ["DROP", "REJECT"]:
            target = rule.source or rule.destination
            if target:
                for private_subnet in self.private_subnets:
                    if target.startswith(private_subnet.split("/")[0][:7]):  # Match first 3 octets
                        reasons.append(f"Blocks internal/private network ({target})")
                        if risk_level == RiskLevel.LOW:
                            risk_level = RiskLevel.MEDIUM

        # Check for temporary rules with very short TTL
        if rule.is_temporary and rule.ttl_seconds:
            if rule.ttl_seconds < 60:
                reasons.append(f"Very short TTL ({rule.ttl_seconds}s)")
            elif rule.ttl_seconds > 86400:  # > 24 hours
                reasons.append(f"Very long TTL ({rule.ttl_seconds // 3600}h)")

        # Check for urgency indicators in user input
        urgency_keywords = ["now", "immediately", "asap", "urgent", "emergency", "attack", "ddos", "brute force"]
        if any(keyword in user_input.lower() for keyword in urgency_keywords):
            bypass_on_urgency = True

        # If no specific risks found, it's low risk
        if not reasons:
            reasons.append("Standard firewall rule")

        return RiskAssessment(
            level=risk_level,
            reasons=reasons,
            requires_confirmation=requires_confirmation,
            warning_message=warning_message,
            bypass_on_urgency=bypass_on_urgency
        )

    def assess_bulk_operation(self, operation: str, count: int) -> RiskAssessment:
        """
        Assess risk of bulk operations (delete multiple rules, etc.).

        Args:
            operation: Type of operation (delete, disable, etc.)
            count: Number of rules affected

        Returns:
            RiskAssessment object
        """
        reasons = []
        risk_level = RiskLevel.LOW
        requires_confirmation = False
        warning_message = None

        if count > 10:
            reasons.append(f"Affects {count} rules")
            risk_level = RiskLevel.HIGH
            requires_confirmation = True
            warning_message = f"⚠️  This will {operation} {count} rules. This may significantly change your firewall configuration."
        elif count > 5:
            reasons.append(f"Affects {count} rules")
            risk_level = RiskLevel.MEDIUM
            requires_confirmation = True
            warning_message = f"This will {operation} {count} rules. Please confirm."
        elif count > 1:
            reasons.append(f"Affects {count} rules")
            risk_level = RiskLevel.LOW

        return RiskAssessment(
            level=risk_level,
            reasons=reasons,
            requires_confirmation=requires_confirmation,
            warning_message=warning_message,
            bypass_on_urgency=False
        )

    def assess_rollback(self, steps: int) -> RiskAssessment:
        """
        Assess risk of rollback operation.

        Args:
            steps: Number of changes to roll back

        Returns:
            RiskAssessment object
        """
        reasons = []
        risk_level = RiskLevel.LOW
        requires_confirmation = False
        warning_message = None

        if steps > 5:
            reasons.append(f"Rolling back {steps} changes")
            risk_level = RiskLevel.HIGH
            requires_confirmation = True
            warning_message = f"⚠️  This will undo the last {steps} changes. Your firewall configuration will be significantly altered."
        elif steps > 1:
            reasons.append(f"Rolling back {steps} changes")
            risk_level = RiskLevel.MEDIUM
            requires_confirmation = True
            warning_message = f"This will undo the last {steps} changes."
        else:
            reasons.append("Rolling back last change")
            risk_level = RiskLevel.LOW

        return RiskAssessment(
            level=risk_level,
            reasons=reasons,
            requires_confirmation=requires_confirmation,
            warning_message=warning_message,
            bypass_on_urgency=False
        )


# Global instance
_risk_analyzer: RiskAnalyzer | None = None


def get_risk_analyzer() -> RiskAnalyzer:
    """Get or create the global risk analyzer."""
    global _risk_analyzer
    if _risk_analyzer is None:
        _risk_analyzer = RiskAnalyzer()
    return _risk_analyzer
