"""Slash command parser for AFO.

Provides deterministic command handling without LLM inference.
Commands start with / and have clear syntax.
"""

import re
from typing import Optional


class SlashCommand:
    """Parsed slash command."""

    def __init__(self, command: str, subcommand: str, args: list[str]):
        self.command = command
        self.subcommand = subcommand
        self.args = args

    def __repr__(self):
        return f"SlashCommand({self.command} {self.subcommand} {self.args})"


def parse_slash_command(text: str) -> Optional[SlashCommand]:
    """
    Parse slash command from user input.

    Supported commands:
    - /config apply [preset_name]
    - /config remove
    - /config list
    - /config preview <preset_name>
    - /geoip block <countries...>
    - /geoip allow <countries...>
    - /domain block <domain>
    - /domain block category <category>
    - /bulk delete port <port>
    - /bulk delete ip <ip>
    - /bulk delete temp
    - /bulk enable port <port>
    - /bulk disable port <port>
    - /rate stats
    - /rate whitelist add <ip>
    - /rate whitelist remove <ip>

    Args:
        text: User input text

    Returns:
        SlashCommand if valid command found, None otherwise
    """
    text = text.strip()

    # Must start with /
    if not text.startswith("/"):
        return None

    # Split into parts
    parts = text.split()
    if len(parts) < 2:
        return None

    command = parts[0][1:].lower()  # Remove leading /
    subcommand = parts[1].lower()
    args = parts[2:] if len(parts) > 2 else []

    # Validate command structure
    valid_commands = {
        "geoip": ["block", "allow", "unblock"],
        "domain": ["block", "unblock"],
        "bulk": ["delete", "enable", "disable"],
        "rate": ["stats", "whitelist"],
        "config": ["apply", "remove", "list", "preview"],
    }

    if command not in valid_commands:
        return None

    if subcommand not in valid_commands[command]:
        return None

    return SlashCommand(command, subcommand, args)


def format_slash_command_help() -> str:
    """Get help text for slash commands."""
    return """
Available Slash Commands:

Configuration Presets:
  /config list                     List available presets
  /config apply [name]             Apply a preset configuration
  /config preview <name>           Preview preset without applying
  /config remove                   Remove active configuration
  Examples:
    /config list
    /config apply home_basic
    /config preview development
    /config remove

GeoIP Filtering:
  /geoip block <countries...>      Block traffic from countries
  /geoip allow <countries...>      Allow only from countries
  /geoip unblock <countries...>    Remove country blocks
  Examples:
    /geoip block Russia China
    /geoip allow US India UK
    /geoip unblock Russia

Domain Blocking:
  /domain block <domain>           Block single domain
  /domain block category <name>    Block domain category
  /domain unblock <domain>         Unblock domain
  Examples:
    /domain block facebook.com
    /domain block category social_media
    /domain unblock twitter.com

Bulk Operations:
  /bulk delete port <port>         Delete all rules for port
  /bulk delete ip <ip>             Delete all rules for IP
  /bulk delete temp                Delete temporary rules
  /bulk enable port <port>         Enable all rules for port
  /bulk disable port <port>        Disable all rules for port
  Examples:
    /bulk delete port 22
    /bulk delete ip 10.0.0.5
    /bulk delete temp

Rate Limiting:
  /rate stats                      Show rate limiter statistics
  /rate whitelist add <ip>         Add IP to whitelist
  /rate whitelist remove <ip>      Remove IP from whitelist
  Examples:
    /rate stats
    /rate whitelist add 192.168.1.100

Help:
  /help or /                       Show this help message
"""


def is_slash_command(text: str) -> bool:
    """Check if text is a slash command."""
    return text.strip().startswith("/")
