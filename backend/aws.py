import logging

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None

from backend.base import FirewallBackend
from backend.models import Action, Direction, PolicyRule, Protocol

logger = logging.getLogger(__name__)


class AWSBackend(FirewallBackend):
    """
    AWS Security Group implementation of the FirewallBackend.
    """

    def __init__(self, region: str, security_group_id: str, dry_run: bool = False):
        super().__init__()
        if not boto3:
            raise ImportError("boto3 is required for AWSBackend")

        self.ec2 = boto3.client("ec2", region_name=region)
        self.sg_id = security_group_id
        self.dry_run = dry_run

    async def list_rules(self) -> list[PolicyRule]:
        """Fetch rules from Security Group."""
        try:
            # Note: boto3 is synchronous. In a real async app, run in executor.
            response = self.ec2.describe_security_groups(GroupIds=[self.sg_id])
            sg = response["SecurityGroups"][0]

            rules = []

            # Process Inbound (Ingress)
            for perm in sg.get("IpPermissions", []):
                rules.extend(self._parse_permission(perm, Direction.INBOUND))

            # Process Outbound (Egress)
            for perm in sg.get("IpPermissionsEgress", []):
                rules.extend(self._parse_permission(perm, Direction.OUTBOUND))

            return rules
        except Exception as e:
            logger.error(f"Failed to list SG rules: {e}")
            return []

    def _parse_permission(self, perm: dict, direction: Direction) -> list[PolicyRule]:
        """Convert AWS Permission dict to PolicyRules."""
        rules = []
        protocol = perm.get("IpProtocol")
        from_port = perm.get("FromPort")

        # Map Protocol
        if protocol == "-1":
            proto = Protocol.ANY
        elif protocol == "tcp":
            proto = Protocol.TCP
        elif protocol == "udp":
            proto = Protocol.UDP
        elif protocol == "icmp":
            proto = Protocol.ICMP
        else:
            proto = Protocol.ANY # Default/Unknown

        # Extract sources/destinations
        targets = []
        for ip_range in perm.get("IpRanges", []):
            targets.append(ip_range.get("CidrIp"))
        for ipv6_range in perm.get("Ipv6Ranges", []):
            targets.append(ipv6_range.get("CidrIpv6"))

        if not targets:
            targets = ["0.0.0.0/0"] # If no ranges, implies something else or empty?
            # Actually empty IpRanges means no rules usually, but let's handle gracefully

        for target in targets:
            rule = PolicyRule(
                name=f"aws_{direction.value}_{proto.value}_{from_port or 'all'}",
                action=Action.ACCEPT, # SGs are allow-only (mostly)
                direction=direction,
                protocol=proto,
                port=from_port if from_port and from_port != -1 else None,
                source=target if direction == Direction.INBOUND else None,
                destination=target if direction == Direction.OUTBOUND else None,
            )
            rules.append(rule)

        return rules

    async def validate_rule(self, rule: PolicyRule) -> bool:
        """Validate rule compatibility with Security Groups."""
        # SGs only support ACCEPT. DROP/REJECT is implicit (default deny).
        # We can't explicit deny specific IPs easily (requires NACLs).
        if rule.action != Action.ACCEPT:
            logger.warning("AWS Security Groups only support ACCEPT rules (Allow).")
            return False
        return True

    async def deploy_rule(self, rule: PolicyRule) -> bool:
        """Add a rule to the Security Group."""
        if not await self.validate_rule(rule):
            return False

        # Construct permission dict
        permission = {
            'IpProtocol': rule.protocol.value.lower() if rule.protocol != Protocol.ANY else '-1',
            'IpRanges': [{'CidrIp': rule.source}] if rule.source and rule.direction == Direction.INBOUND else [],
            # Note: Handling destination for egress requires IpRanges inside IpPermissionsEgress
        }

        if rule.direction == Direction.OUTBOUND and rule.destination:
             permission['IpRanges'] = [{'CidrIp': rule.destination}]

        if rule.port and rule.protocol in (Protocol.TCP, Protocol.UDP):
            permission['FromPort'] = rule.port
            permission['ToPort'] = rule.port

        try:
            if rule.direction == Direction.INBOUND:
                self.ec2.authorize_security_group_ingress(
                    GroupId=self.sg_id,
                    IpPermissions=[permission]
                )
            else:
                self.ec2.authorize_security_group_egress(
                    GroupId=self.sg_id,
                    IpPermissions=[permission]
                )
            return True
        except ClientError as e:
            logger.error(f"AWS Error: {e}")
            return False

    async def delete_rule(self, rule_id: str) -> bool:
        # Complex without storing the exact permission object.
        # Placeholder.
        return False

    async def rollback(self, steps: int = 1) -> bool:
        return False

    async def get_status(self) -> str:
        try:
            self.ec2.describe_security_groups(GroupIds=[self.sg_id])
            return "Connected"
        except Exception:
            return "Disconnected"
