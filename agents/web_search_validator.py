"""Web Search Integration for Firewall Agent

Adds web search capability to research user requests before implementation.
The LLM validates if the request is legitimate and safe before applying.
"""

import json
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class WebSearchValidator:
    """Validates firewall requests using web search and LLM analysis."""

    def __init__(self, ollama_host: str = "http://localhost:11434", model: str = "qwen2.5-coder:3b"):
        self.ollama_host = ollama_host
        self.model = model
        self.search_api = "https://api.duckduckgo.com/"  # Free search API

    async def search_web(self, query: str, max_results: int = 5) -> list[dict[str, Any]]:
        """Search the web for information about the query."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # DuckDuckGo Instant Answer API
                response = await client.get(
                    "https://api.duckduckgo.com/",
                    params={
                        "q": query,
                        "format": "json",
                        "no_html": 1,
                        "skip_disambig": 1,
                    }
                )
                response.raise_for_status()
                data = response.json()

                results = []

                # Extract abstract
                if data.get("Abstract"):
                    results.append({
                        "title": data.get("Heading", ""),
                        "snippet": data.get("Abstract", ""),
                        "url": data.get("AbstractURL", ""),
                    })

                # Extract related topics
                for topic in data.get("RelatedTopics", [])[:max_results]:
                    if isinstance(topic, dict) and "Text" in topic:
                        results.append({
                            "title": topic.get("Text", "")[:100],
                            "snippet": topic.get("Text", ""),
                            "url": topic.get("FirstURL", ""),
                        })

                logger.info("web_search_complete", query=query, results=len(results))
                return results

        except Exception as e:
            logger.error("web_search_failed", error=str(e), query=query)
            return []

    async def validate_request(
        self,
        user_request: str,
        proposed_rule: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Validate a firewall request using web search and LLM analysis.

        Returns:
            {
                "is_valid": bool,
                "is_safe": bool,
                "confidence": float,
                "reasoning": str,
                "search_results": list,
                "recommendation": str
            }
        """
        # Step 1: Search for information about the request
        search_query = self._build_search_query(user_request, proposed_rule)
        search_results = await self.search_web(search_query)

        # Step 2: Build context for LLM
        context = self._build_context(user_request, proposed_rule, search_results)

        # Step 3: Ask LLM to validate
        validation = await self._llm_validate(context)

        # Step 4: Return validation result
        return {
            "is_valid": validation.get("is_valid", False),
            "is_safe": validation.get("is_safe", False),
            "confidence": validation.get("confidence", 0.0),
            "reasoning": validation.get("reasoning", ""),
            "search_results": search_results,
            "recommendation": validation.get("recommendation", ""),
        }

    def _build_search_query(self, user_request: str, proposed_rule: dict[str, Any]) -> str:
        """Build a search query from the user request."""
        # Extract key terms
        action = proposed_rule.get("action", "")
        source = proposed_rule.get("source", "")
        port = proposed_rule.get("port", "")
        protocol = proposed_rule.get("protocol", "")

        # Build query
        query_parts = []

        if source:
            query_parts.append(f"IP address {source}")
        if port:
            query_parts.append(f"port {port}")
        if protocol:
            query_parts.append(f"{protocol} protocol")

        query_parts.append("security threat")

        return " ".join(query_parts)

    def _build_context(
        self,
        user_request: str,
        proposed_rule: dict[str, Any],
        search_results: list[dict[str, Any]],
    ) -> str:
        """Build context for LLM validation."""
        context = f"""You are a firewall security expert. Validate this firewall request.

USER REQUEST:
{user_request}

PROPOSED RULE:
Action: {proposed_rule.get('action', 'N/A')}
Source: {proposed_rule.get('source', 'N/A')}
Destination: {proposed_rule.get('destination', 'N/A')}
Port: {proposed_rule.get('port', 'N/A')}
Protocol: {proposed_rule.get('protocol', 'N/A')}

WEB SEARCH RESULTS:
"""

        for i, result in enumerate(search_results[:3], 1):
            context += f"\n{i}. {result.get('title', 'N/A')}\n"
            context += f"   {result.get('snippet', 'N/A')[:200]}\n"

        context += """

VALIDATION TASK:
Analyze the request and search results. Determine:
1. Is this a legitimate security request?
2. Is it safe to implement?
3. Are there any red flags or concerns?
4. What is your confidence level (0.0-1.0)?

Respond in JSON format:
{
    "is_valid": true/false,
    "is_safe": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "Detailed explanation",
    "recommendation": "approve/reject/modify"
}

Consider:
- Is the IP/port/protocol commonly associated with threats?
- Does the action make sense for the target?
- Are there any security best practices being violated?
- Could this accidentally block legitimate traffic?
"""
        return context

    async def _llm_validate(self, context: str) -> dict[str, Any]:
        """Use LLM to validate the request."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.ollama_host}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": context,
                        "stream": False,
                    },
                )
                response.raise_for_status()
                llm_response = response.json().get("response", "")

                # Try to extract JSON
                validation = self._extract_json(llm_response)

                if validation:
                    logger.info(
                        "llm_validation_complete",
                        is_valid=validation.get("is_valid"),
                        confidence=validation.get("confidence"),
                    )
                    return validation
                else:
                    # Fallback if JSON extraction fails
                    return {
                        "is_valid": False,
                        "is_safe": False,
                        "confidence": 0.0,
                        "reasoning": "Failed to parse LLM response",
                        "recommendation": "reject",
                    }

        except Exception as e:
            logger.error("llm_validation_failed", error=str(e))
            return {
                "is_valid": False,
                "is_safe": False,
                "confidence": 0.0,
                "reasoning": f"Validation error: {str(e)}",
                "recommendation": "reject",
            }

    def _extract_json(self, text: str) -> dict[str, Any] | None:
        """Extract JSON from LLM response."""
        import re

        # Try direct JSON parsing
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to find JSON in code blocks
        json_pattern = r'```(?:json)?\s*(\{.*?\})\s*```'
        match = re.search(json_pattern, text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Try to find JSON object in text
        json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        match = re.search(json_pattern, text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

        return None


# Integration with existing firewall agent
async def validate_with_web_search(
    user_request: str,
    proposed_rule: dict[str, Any],
    ollama_host: str = "http://localhost:11434",
    model: str = "qwen2.5-coder:3b",
) -> dict[str, Any]:
    """
    Validate a firewall request using web search.

    This function can be called before deploying a rule to add an extra
    layer of validation using web research.

    Args:
        user_request: Original user request
        proposed_rule: The rule that would be deployed
        ollama_host: Ollama API host
        model: LLM model to use

    Returns:
        Validation result with is_valid, is_safe, confidence, reasoning
    """
    validator = WebSearchValidator(ollama_host, model)
    return await validator.validate_request(user_request, proposed_rule)
