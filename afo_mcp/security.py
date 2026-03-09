"""Security utilities for AFO.

Shared security checks to prevent injection attacks and other vulnerabilities.
"""

import re

# Characters that could enable shell injection
DANGEROUS_CHARS = frozenset(";|&$`\\")

# Pattern for shell metacharacters
SHELL_METACHAR_PATTERN = re.compile(r"[;|&$`\\]")


def contains_dangerous_chars(text: str) -> bool:
    """Check if text contains characters that could enable shell injection.

    Args:
        text: The text to check

    Returns:
        True if dangerous characters are found, False otherwise.
    """
    return bool(DANGEROUS_CHARS & set(text))


def sanitize_for_shell(text: str) -> str | None:
    """Return sanitized text or None if it cannot be made safe.

    For firewall rules, we reject rather than sanitize to avoid
    accidentally changing the rule semantics.

    Args:
        text: The text to check

    Returns:
        The original text if safe, None if dangerous characters found.
    """
    if contains_dangerous_chars(text):
        return None
    return text


def is_valid_interface_name(name: str) -> bool:
    """Validate a network interface name.

    Args:
        name: Interface name to validate

    Returns:
        True if the name is a valid Linux interface name.
    """
    # Linux interface names: alphanumeric, dash, underscore, dot
    # Max 15 chars (IFNAMSIZ - 1)
    if not name or len(name) > 15:
        return False
    return bool(re.match(r"^[a-zA-Z0-9_.-]+$", name))


def is_valid_table_name(name: str) -> bool:
    """Validate an nftables table name.

    Args:
        name: Table name to validate

    Returns:
        True if the name is a valid nftables table name.
    """
    if not name or len(name) > 64:
        return False
    return bool(re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", name))


def is_valid_chain_name(name: str) -> bool:
    """Validate an nftables chain name.

    Args:
        name: Chain name to validate

    Returns:
        True if the name is a valid nftables chain name.
    """
    # Same rules as table names
    return is_valid_table_name(name)
