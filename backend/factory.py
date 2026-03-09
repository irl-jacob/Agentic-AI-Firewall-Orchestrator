import shutil

from backend.base import FirewallBackend
from backend.iptables import IptablesBackend
from backend.nftables import NftablesBackend


def get_backend(config: dict = None) -> FirewallBackend:
    """
    Auto-detect and return the appropriate FirewallBackend.
    Priority: Config > nftables > iptables
    """
    config = config or {}
    backend_type = config.get("type")

    if backend_type == "aws":
        from backend.aws import AWSBackend
        return AWSBackend(
            region=config.get("region", "us-east-1"),
            security_group_id=config.get("security_group_id")
        )

    if backend_type == "opnsense":
        from backend.opnsense import OPNsenseMCPBackend
        return OPNsenseMCPBackend(
            host=config.get("url") or config.get("host"),
            api_key=config.get("api_key"),
            api_secret=config.get("api_secret"),
            verify_ssl=config.get("verify_ssl", False),
            interface=config.get("interface", "lan"),
            ssh_host=config.get("ssh_host"),
            ssh_username=config.get("ssh_username"),
            ssh_password=config.get("ssh_password"),
            ssh_key_path=config.get("ssh_key_path"),
        )

    if shutil.which("nft"):
        return NftablesBackend()
    elif shutil.which("iptables"):
        return IptablesBackend()
    else:
        raise RuntimeError("No compatible firewall backend found (nft or iptables required)")
