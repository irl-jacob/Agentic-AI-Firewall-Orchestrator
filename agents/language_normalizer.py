"""Natural language normalizer for firewall rule requests.

This module preprocesses user input to normalize directional language
and resolve ambiguities before sending to the LLM.
"""

import re


def normalize_directional_language(text: str) -> str:
    """Normalize directional language in user input.
    
    This helps the LLM understand user intent by standardizing
    common directional patterns before processing.
    
    Args:
        text: Raw user input
        
    Returns:
        Normalized text with clear directional markers
    """
    original = text.lower().strip()
    normalized = original

    # Patterns that indicate SOURCE (incoming traffic)
    source_patterns = [
        (r'\bfrom\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', r'FROM_IP \1'),
        (r'\bcoming\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', r'FROM_IP \1'),
        (r'\boriginating\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', r'FROM_IP \1'),
        (r'\barriving\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', r'FROM_IP \1'),
        (r'\bingress\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', r'FROM_IP \1'),
        (r'\binbound\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', r'FROM_IP \1'),
    ]

    # Patterns that indicate DESTINATION (outgoing traffic)
    dest_patterns = [
        (r'\bto\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', r'TO_IP \1'),
        (r'\bdestined\s+(?:for|to)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', r'TO_IP \1'),
        (r'\bgoing\s+(?:to|toward)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', r'TO_IP \1'),
        (r'\boutgoing\s+(?:to|toward)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', r'TO_IP \1'),
        (r'\begress\s+(?:to|toward)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', r'TO_IP \1'),
        (r'\boutbound\s+(?:to|toward)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', r'TO_IP \1'),
    ]

    # Apply source patterns
    for pattern, replacement in source_patterns:
        normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)

    # Apply destination patterns
    for pattern, replacement in dest_patterns:
        normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)

    # Handle "access from/to" patterns
    normalized = re.sub(
        r'\baccess\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)',
        r'ACCESS_FROM_IP \1',
        normalized,
        flags=re.IGNORECASE
    )
    normalized = re.sub(
        r'\baccess\s+to\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)',
        r'ACCESS_TO_IP \1',
        normalized,
        flags=re.IGNORECASE
    )

    # Handle "stop X from connecting" = block incoming from X
    normalized = re.sub(
        r'\bstop\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\s+from\s+connecting',
        r'BLOCK_FROM_IP \1',
        normalized,
        flags=re.IGNORECASE
    )

    # Handle "stop connecting to X" = block outgoing to X
    normalized = re.sub(
        r'\bstop\s+(?:connecting\s+)?to\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)',
        r'BLOCK_TO_IP \1',
        normalized,
        flags=re.IGNORECASE
    )

    # Handle "prevent X from Y" = block incoming from X
    normalized = re.sub(
        r'\bprevent\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\s+from',
        r'PREVENT_FROM_IP \1',
        normalized,
        flags=re.IGNORECASE
    )

    # Handle "prevent access to X" = block outgoing to X
    normalized = re.sub(
        r'\bprevent\s+(?:access\s+)?to\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)',
        r'PREVENT_TO_IP \1',
        normalized,
        flags=re.IGNORECASE
    )

    # Handle ambiguous patterns with just an IP and no direction
    # Pattern: "block 10.0.0.5" or "deny 192.168.1.1" (no from/to)
    if re.search(r'\b(?:block|deny|drop|reject)\s+(?:all\s+)?(?:traffic\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', normalized):
        if 'FROM_IP' not in normalized and 'TO_IP' not in normalized:
            # Default to FROM for safety
            normalized = re.sub(
                r'\b(block|deny|drop|reject)\s+(?:all\s+)?(?:traffic\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                r'\1 FROM_IP \2',
                normalized,
                flags=re.IGNORECASE
            )

    # Handle "incoming" and "outgoing" keywords
    normalized = re.sub(r'\bincoming\b', 'INCOMING_TRAFFIC', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\binbound\b', 'INCOMING_TRAFFIC', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\bingress\b', 'INCOMING_TRAFFIC', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\boutgoing\b', 'OUTGOING_TRAFFIC', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\boutbound\b', 'OUTGOING_TRAFFIC', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\begress\b', 'OUTGOING_TRAFFIC', normalized, flags=re.IGNORECASE)

    # Handle port direction hints
    # "block port 22 from X" = destination_port: 22, source: X
    # "block port 22 to X" = destination_port: 22, destination: X
    normalized = re.sub(
        r'\bport\s+(\d+)\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'PORT \1 FROM_IP \2',
        normalized,
        flags=re.IGNORECASE
    )
    normalized = re.sub(
        r'\bport\s+(\d+)\s+to\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'PORT \1 TO_IP \2',
        normalized,
        flags=re.IGNORECASE
    )

    # Only normalize if we made changes
    if normalized != original:
        # Convert markers back to clearer language for the LLM
        normalized = normalized.replace('FROM_IP ', 'from ')
        normalized = normalized.replace('TO_IP ', 'to ')
        normalized = normalized.replace('ACCESS_FROM_IP ', 'access from ')
        normalized = normalized.replace('ACCESS_TO_IP ', 'access to ')
        normalized = normalized.replace('BLOCK_FROM_IP ', 'block from ')
        normalized = normalized.replace('BLOCK_TO_IP ', 'block to ')
        normalized = normalized.replace('PREVENT_FROM_IP ', 'prevent from ')
        normalized = normalized.replace('PREVENT_TO_IP ', 'prevent to ')
        normalized = normalized.replace('INCOMING_TRAFFIC', 'incoming')
        normalized = normalized.replace('OUTGOING_TRAFFIC', 'outgoing')
        normalized = normalized.replace('PORT ', 'port ')

        return normalized

    return text


def detect_directional_ambiguity(text: str) -> str | None:
    """Detect if the input has ambiguous directional language.
    
    Args:
        text: User input to check
        
    Returns:
        Clarification question if ambiguous, None otherwise
    """
    lower = text.lower()

    # Check if there's an IP address
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b'
    has_ip = bool(re.search(ip_pattern, lower))

    # Check for directional keywords
    has_from = bool(re.search(r'\bfrom\b', lower))
    has_to = bool(re.search(r'\bto\b', lower))
    has_incoming = bool(re.search(r'\b(incoming|inbound|ingress)\b', lower))
    has_outgoing = bool(re.search(r'\b(outgoing|outbound|egress)\b', lower))

    # If has IP but no clear direction, it's ambiguous
    if has_ip and not (has_from or has_to or has_incoming or has_outgoing):
        # Extract the IP for the clarification message
        ip_match = re.search(ip_pattern, text)
        if ip_match:
            ip = ip_match.group(0)
            return (
                f"Do you want to block traffic FROM {ip} (incoming to this server) "
                f"or TO {ip} (outgoing from this server)?"
            )

    return None


def preprocess_input(text: str) -> tuple[str, str | None]:
    """Preprocess user input to normalize language and check ambiguity.
    
    Args:
        text: Raw user input
        
    Returns:
        Tuple of (normalized_text, clarification_question)
        If clarification_question is not None, ask user before proceeding
    """
    # Normalize directional language
    normalized = normalize_directional_language(text)

    # Check for ambiguity
    clarification = detect_directional_ambiguity(text)

    return normalized, clarification


# Common test cases for validation
TEST_CASES = [
    # (input, expected_direction)
    ("block ssh from 10.0.0.5", "incoming"),
    ("block ssh to 10.0.0.5", "outgoing"),
    ("deny traffic from 192.168.1.0/24", "incoming"),
    ("deny traffic to 8.8.8.8", "outgoing"),
    ("allow http from 10.0.0.0/8", "incoming"),
    ("allow http to 10.0.0.100", "outgoing"),
    ("drop packets coming from 172.16.0.1", "incoming"),
    ("drop packets destined for 172.16.0.1", "outgoing"),
    ("prevent access from 10.0.0.5", "incoming"),
    ("prevent access to 10.0.0.5", "outgoing"),
    ("stop 192.168.1.50 from connecting", "incoming"),
    ("stop connecting to 192.168.1.50", "outgoing"),
    ("block port 80 from 10.0.0.5", "incoming"),
    ("block port 443 to 8.8.8.8", "outgoing"),
    ("reject incoming ssh from 10.0.0.1", "incoming"),
    ("reject outgoing ssh to 10.0.0.1", "outgoing"),
]


if __name__ == "__main__":
    # Test the normalizer
    print("Testing directional language normalizer:")
    print("=" * 60)

    for test_input, expected in TEST_CASES:
        normalized, clarification = preprocess_input(test_input)
        print(f"\nInput: '{test_input}'")
        print(f"Expected: {expected}")
        print(f"Normalized: '{normalized}'")
        if clarification:
            print(f"Clarification needed: {clarification}")

    # Test ambiguous cases
    print("\n" + "=" * 60)
    print("Testing ambiguous cases:")
    ambiguous_cases = [
        "block 10.0.0.5",
        "deny 192.168.1.100",
        "drop traffic 172.16.0.1",
    ]

    for test_input in ambiguous_cases:
        normalized, clarification = preprocess_input(test_input)
        print(f"\nInput: '{test_input}'")
        print(f"Clarification: {clarification or 'None'}")
