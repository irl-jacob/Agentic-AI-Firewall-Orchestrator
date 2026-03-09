"""Multi-turn clarification dialog manager for AFO.

Handles ambiguous commands by asking follow-up questions and tracking
conversation context across multiple turns.
"""

from dataclasses import dataclass
from enum import Enum


class ClarificationType(Enum):
    """Types of clarification needed."""
    DIRECTION = "direction"  # FROM vs TO
    SCOPE = "scope"  # Which traffic/port/protocol
    ACTION = "action"  # Block vs allow
    TARGET = "target"  # Which IP/subnet
    CONFIRMATION = "confirmation"  # High-risk confirmation
    AMBIGUOUS = "ambiguous"  # General ambiguity


@dataclass
class ClarificationRequest:
    """A clarification question to ask the user."""
    type: ClarificationType
    question: str
    options: list[str] | None = None  # Suggested options
    context: dict | None = None  # Additional context
    original_input: str = ""


@dataclass
class ClarificationResponse:
    """User's response to a clarification question."""
    original_request: ClarificationRequest
    user_response: str
    selected_option: str | None = None


class ClarificationManager:
    """Manages multi-turn clarification dialogs."""

    def __init__(self):
        self.pending_clarifications: dict[str, ClarificationRequest] = {}
        self.clarification_history: list[tuple[ClarificationRequest, ClarificationResponse]] = []

    def needs_clarification(self, user_input: str, parsed_data: dict | None = None) -> ClarificationRequest | None:
        """
        Determine if user input needs clarification.

        Args:
            user_input: Raw user input
            parsed_data: Parsed data from LLM (if available)

        Returns:
            ClarificationRequest if clarification needed, None otherwise
        """
        import re

        user_lower = user_input.lower().strip()

        # Check for directional ambiguity
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b'
        has_ip = bool(re.search(ip_pattern, user_input))
        has_from = 'from' in user_lower
        has_to = 'to' in user_lower
        has_direction = has_from or has_to or any(word in user_lower for word in ['incoming', 'outgoing', 'inbound', 'outbound'])

        if has_ip and not has_direction:
            ip_match = re.search(ip_pattern, user_input)
            ip = ip_match.group(0) if ip_match else "the IP"

            return ClarificationRequest(
                type=ClarificationType.DIRECTION,
                question=f"Do you want to block traffic FROM {ip} (incoming) or TO {ip} (outgoing)?",
                options=["FROM (incoming)", "TO (outgoing)"],
                context={"ip": ip, "original_input": user_input},
                original_input=user_input
            )

        # Check for vague commands
        vague_patterns = [
            (r'\b(bad|suspicious|weird|strange)\s+traffic\b', "scope"),
            (r'\bmake\s+.*\s+secure\b', "scope"),
            (r'\bfix\s+', "scope"),
            (r'\bstop\s+(?:the\s+)?attack\b', "target"),
            (r'\bblock\s+everything\b', "confirmation"),
        ]

        for pattern, clarif_type in vague_patterns:
            if re.search(pattern, user_lower):
                if clarif_type == "scope":
                    return ClarificationRequest(
                        type=ClarificationType.SCOPE,
                        question="Can you be more specific? What traffic do you want to block?",
                        options=[
                            "A specific IP address",
                            "A specific port",
                            "A specific protocol (TCP/UDP/ICMP)",
                            "Traffic from a country",
                            "All traffic (dangerous!)"
                        ],
                        context={"original_input": user_input},
                        original_input=user_input
                    )
                elif clarif_type == "target":
                    return ClarificationRequest(
                        type=ClarificationType.TARGET,
                        question="Which attack? Please provide the source IP or subnet.",
                        options=None,
                        context={"original_input": user_input},
                        original_input=user_input
                    )
                elif clarif_type == "confirmation":
                    return ClarificationRequest(
                        type=ClarificationType.CONFIRMATION,
                        question="⚠️  WARNING: Blocking all traffic will disconnect you from the server. Are you sure?",
                        options=["Yes, block everything", "No, cancel"],
                        context={"original_input": user_input, "high_risk": True},
                        original_input=user_input
                    )

        # Check for missing critical information
        if parsed_data:
            # If LLM returned a rule but it's missing key fields
            if parsed_data.get("intent") == "rule":
                missing = []
                if not parsed_data.get("action"):
                    missing.append("action (block/allow)")
                if not parsed_data.get("source_address") and not parsed_data.get("destination_address"):
                    missing.append("IP address")

                if missing:
                    return ClarificationRequest(
                        type=ClarificationType.AMBIGUOUS,
                        question=f"I need more information: {', '.join(missing)}. Can you provide these details?",
                        options=None,
                        context={"missing_fields": missing, "original_input": user_input},
                        original_input=user_input
                    )

        return None

    def create_clarification_prompt(self, request: ClarificationRequest) -> str:
        """
        Create a user-friendly clarification prompt.

        Args:
            request: ClarificationRequest object

        Returns:
            Formatted prompt string
        """
        prompt = f"❓ {request.question}\n"

        if request.options:
            prompt += "\nOptions:\n"
            for i, option in enumerate(request.options, 1):
                prompt += f"  {i}. {option}\n"
            prompt += "\nReply with the number or describe your choice."

        return prompt.strip()

    def parse_clarification_response(
        self,
        request: ClarificationRequest,
        user_response: str
    ) -> ClarificationResponse:
        """
        Parse user's response to a clarification question.

        Args:
            request: Original clarification request
            user_response: User's response

        Returns:
            ClarificationResponse object
        """
        selected_option = None

        # Try to match numbered response
        if request.options:
            user_response_stripped = user_response.strip()
            if user_response_stripped.isdigit():
                idx = int(user_response_stripped) - 1
                if 0 <= idx < len(request.options):
                    selected_option = request.options[idx]
            else:
                # Try to match option text
                user_lower = user_response.lower()
                for option in request.options:
                    if option.lower() in user_lower or user_lower in option.lower():
                        selected_option = option
                        break

        return ClarificationResponse(
            original_request=request,
            user_response=user_response,
            selected_option=selected_option
        )

    def resolve_clarification(
        self,
        request: ClarificationRequest,
        response: ClarificationResponse
    ) -> dict:
        """
        Resolve a clarification and return updated context.

        Args:
            request: Original clarification request
            response: User's response

        Returns:
            Dict with resolved information to merge into original command
        """
        resolved = {}

        if request.type == ClarificationType.DIRECTION:
            if response.selected_option:
                if "FROM" in response.selected_option or "incoming" in response.user_response.lower():
                    resolved["chain"] = "input"
                    resolved["source_address"] = request.context.get("ip")
                elif "TO" in response.selected_option or "outgoing" in response.user_response.lower():
                    resolved["chain"] = "output"
                    resolved["destination_address"] = request.context.get("ip")

        elif request.type == ClarificationType.SCOPE:
            user_lower = response.user_response.lower()
            if "ip" in user_lower or response.selected_option == "A specific IP address":
                resolved["needs_ip"] = True
            elif "port" in user_lower or response.selected_option == "A specific port":
                resolved["needs_port"] = True
            elif "protocol" in user_lower or "tcp" in user_lower or "udp" in user_lower:
                resolved["needs_protocol"] = True
            elif "country" in user_lower or "geo" in user_lower:
                resolved["needs_country"] = True
            elif "all" in user_lower or "everything" in user_lower:
                resolved["block_all"] = True
                resolved["high_risk"] = True

        elif request.type == ClarificationType.TARGET:
            # Extract IP from response
            import re
            ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b'
            ip_match = re.search(ip_pattern, response.user_response)
            if ip_match:
                resolved["source_address"] = ip_match.group(0)
                resolved["chain"] = "input"

        elif request.type == ClarificationType.CONFIRMATION:
            if response.selected_option:
                if "Yes" in response.selected_option or "yes" in response.user_response.lower():
                    resolved["confirmed"] = True
                else:
                    resolved["confirmed"] = False
                    resolved["cancelled"] = True

        # Store in history
        self.clarification_history.append((request, response))

        return resolved

    def get_conversation_context(self) -> str:
        """
        Get a summary of the clarification conversation for context.

        Returns:
            String summary of clarification history
        """
        if not self.clarification_history:
            return ""

        context_parts = []
        for req, resp in self.clarification_history[-3:]:  # Last 3 clarifications
            context_parts.append(f"Q: {req.question}")
            context_parts.append(f"A: {resp.user_response}")

        return "\n".join(context_parts)


# Global instance
_clarification_manager: ClarificationManager | None = None


def get_clarification_manager() -> ClarificationManager:
    """Get or create the global clarification manager."""
    global _clarification_manager
    if _clarification_manager is None:
        _clarification_manager = ClarificationManager()
    return _clarification_manager
