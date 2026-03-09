"""Enhanced Firewall Agent with Web Search Validation

Integrates web search validation into the rule generation process.
"""

import asyncio
import os
from typing import Any

from agents.firewall_agent import process_request as _original_process_request
from agents.web_search_validator import validate_with_web_search
from backend.models import PolicyRule


async def process_request_with_validation(
    user_input: str,
    enable_web_search: bool = None,
    min_confidence: float = 0.7,
) -> dict[str, Any]:
    """
    Process a firewall request with optional web search validation.

    Args:
        user_input: User's firewall request
        enable_web_search: Enable web search validation (default from env)
        min_confidence: Minimum confidence to proceed (default 0.7)

    Returns:
        Enhanced response with validation results
    """
    # Check if web search is enabled
    if enable_web_search is None:
        enable_web_search = os.getenv("ENABLE_WEB_SEARCH_VALIDATION", "false").lower() == "true"

    # Process request normally first
    response = await _original_process_request(user_input)

    # If web search is disabled or no rule generated, return original response
    if not enable_web_search or response.get("type") != "rule":
        return response

    # Extract proposed rule
    rule = response.get("rule")
    if not rule or not isinstance(rule, PolicyRule):
        return response

    # Build proposed rule dict for validation
    proposed_rule = {
        "action": rule.action.value if hasattr(rule.action, "value") else str(rule.action),
        "source": rule.source,
        "destination": rule.destination,
        "port": rule.port,
        "protocol": rule.protocol.value if hasattr(rule.protocol, "value") else str(rule.protocol),
    }

    # Validate with web search
    validation = await validate_with_web_search(
        user_request=user_input,
        proposed_rule=proposed_rule,
        ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        model=os.getenv("OLLAMA_MODEL", "qwen2.5-coder:3b"),
    )

    # Add validation to response
    response["validation"] = validation

    # Check if validation passed
    if not validation["is_valid"] or not validation["is_safe"]:
        response["type"] = "validation_failed"
        response["response"] = f"""⚠️ Web Search Validation Failed

Reasoning: {validation['reasoning']}

Recommendation: {validation['recommendation']}

Confidence: {validation['confidence']:.2f}

The proposed rule was rejected based on web research and LLM analysis.
"""
        return response

    # Check confidence threshold
    if validation["confidence"] < min_confidence:
        response["type"] = "low_confidence"
        response["response"] = f"""⚠️ Low Confidence Validation

Confidence: {validation['confidence']:.2f} (minimum: {min_confidence})

Reasoning: {validation['reasoning']}

The rule may be valid but requires manual review.
"""
        return response

    # Validation passed - enhance response
    response["response"] += f"""

✅ Web Search Validation: PASSED
Confidence: {validation['confidence']:.2f}
Reasoning: {validation['reasoning']}
"""

    return response


# Convenience function for sync contexts
def process_request_with_validation_sync(
    user_input: str,
    enable_web_search: bool = None,
    min_confidence: float = 0.7,
) -> dict[str, Any]:
    """Synchronous wrapper for process_request_with_validation."""
    return asyncio.run(
        process_request_with_validation(user_input, enable_web_search, min_confidence)
    )
