import json

import structlog

from afo_daemon.detection.models import SecurityEvent
from agents.firewall_agent import chat

logger = structlog.get_logger()


class LLMAnalyzer:
    """
    Uses an LLM to analyze ambiguous security events and generate reports.
    """

    def __init__(self):
        pass

    async def analyze_event(self, event: SecurityEvent) -> dict | None:
        """
        Analyze a security event using the LLM.
        Returns a dict with analysis results (e.g. { "risk": "high", "explanation": "..." }).
        """
        prompt = f"""
        Analyze the following security event log and determine if it represents a malicious attack.
        Log: {event.raw_log}
        Source IP: {event.source_ip}
        Detected Type: {event.type.value}

        Provide a JSON response with the following keys:
        - is_malicious: boolean
        - confidence: float (0.0 to 1.0)
        - reasoning: string explanation
        - recommended_action: "BLOCK", "MONITOR", or "IGNORE"
        """

        try:
            # chat() is synchronous in agents/firewall_agent.py, but we are in async context.
            # In a real app, offload to thread or make chat async.
            # For this prototype, blocking call is acceptable if rare.
            response = chat(prompt)

            if response["type"] == "chat":
                text = response["response"]
                # Try to extract JSON if the LLM output it in markdown block
                # Reusing helper from firewall_agent if accessible, or simple extraction here
                return self._extract_json(text)

            return None

        except Exception as e:
            logger.error("llm_analysis_failed", error=str(e))
            return None

    def _extract_json(self, text: str) -> dict | None:
        """Simple JSON extractor."""
        try:
            import re
            # Look for JSON block
            match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
            if match:
                return json.loads(match.group(1))
            # Look for raw braces
            match = re.search(r"(\{.*\})", text, re.DOTALL)
            if match:
                return json.loads(match.group(1))
        except Exception:
            pass
        return None
