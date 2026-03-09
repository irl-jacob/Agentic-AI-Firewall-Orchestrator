"""Insight Engine - LLM-based insight generation from patterns."""

import json
import os
import re
from typing import Any

import httpx
import structlog

from afo_daemon.learning.memory_store import MemoryStore
from db.models import LearnedPattern

logger = structlog.get_logger()


class InsightEngine:
    """Generates configuration insights using LLM analysis of patterns."""

    def __init__(self, memory_store: MemoryStore):
        self.memory = memory_store
        self.ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:3b")

    async def analyze_pattern_cluster(
        self,
        patterns: list[LearnedPattern],
    ) -> dict[str, Any] | None:
        """Analyze a cluster of related patterns and generate insights."""
        if not patterns:
            return None

        # Build context for LLM
        pattern_descriptions = []
        for p in patterns:
            source_ips = json.loads(p.source_ips)
            ports = json.loads(p.ports)
            protocols = json.loads(p.protocols)
            context = json.loads(p.context)

            desc = f"""
Pattern ID: {p.id}
Type: {p.pattern_type}
Signature: {p.signature}
Confidence: {p.confidence:.2f}
Evidence Count: {p.evidence_count}
Source IPs: {', '.join(source_ips) if source_ips else 'N/A'}
Ports: {', '.join(map(str, ports)) if ports else 'N/A'}
Protocols: {', '.join(protocols) if protocols else 'N/A'}
First Seen: {p.first_seen}
Last Seen: {p.last_seen}
Context: {json.dumps(context, indent=2)}
"""
            pattern_descriptions.append(desc.strip())

        prompt = f"""You are a firewall security analyst. Analyze these detected patterns and provide insights.

PATTERNS:
{chr(10).join(pattern_descriptions)}

Provide your analysis in the following JSON format:
{{
    "summary": "Brief summary of what these patterns indicate",
    "threat_level": "low/medium/high/critical",
    "recommendations": [
        "Specific actionable recommendation 1",
        "Specific actionable recommendation 2"
    ],
    "suggested_rules": [
        {{
            "action": "block/allow",
            "source": "IP or CIDR",
            "port": port_number_or_null,
            "protocol": "tcp/udp/icmp or null",
            "reason": "Why this rule is needed"
        }}
    ]
}}

Focus on practical, safe recommendations. Only suggest blocking rules for confirmed threats with high confidence."""

        try:
            analysis = await self._call_llm(prompt)
            if analysis:
                # Try to extract JSON from response
                json_data = self._extract_json(analysis)
                if json_data:
                    return json_data

                # Fallback: return raw analysis
                return {
                    "summary": analysis[:500],
                    "threat_level": "medium",
                    "recommendations": ["Review patterns manually"],
                    "suggested_rules": [],
                }
        except Exception as e:
            logger.error("pattern_analysis_failed", error=str(e))
            return None

        return None

    async def recommend_signature_updates(
        self,
        attack_patterns: list[LearnedPattern],
    ) -> list[dict[str, Any]]:
        """Generate new signature patterns from attack patterns."""
        if not attack_patterns:
            return []

        # Group patterns by similarity
        pattern_groups = self._group_similar_patterns(attack_patterns)

        recommendations = []
        for group in pattern_groups:
            if len(group) < 2:
                continue  # Need multiple patterns to generate signature

            # Extract common characteristics
            all_ips = set()
            all_ports = set()
            all_protocols = set()

            for pattern in group:
                all_ips.update(json.loads(pattern.source_ips))
                all_ports.update(json.loads(pattern.ports))
                all_protocols.update(json.loads(pattern.protocols))

            prompt = f"""Generate a regex pattern to detect similar attacks based on these characteristics:

Source IPs: {', '.join(list(all_ips)[:10])}
Ports: {', '.join(map(str, list(all_ports)))}
Protocols: {', '.join(list(all_protocols))}
Pattern Count: {len(group)}

Provide a regex pattern that would match log entries for these attacks.
Return ONLY the regex pattern, nothing else."""

            try:
                regex_pattern = await self._call_llm(prompt)
                if regex_pattern:
                    # Clean up the response
                    regex_pattern = regex_pattern.strip().strip('`').strip('"').strip("'")

                    recommendations.append({
                        "signature_type": "regex",
                        "pattern": regex_pattern,
                        "confidence": 0.7,
                        "based_on_patterns": [p.id for p in group],
                        "description": f"Detects attacks similar to {len(group)} observed patterns",
                    })
            except Exception as e:
                logger.error("signature_generation_failed", error=str(e))

        return recommendations

    async def recommend_preset_adjustments(
        self,
        patterns: list[LearnedPattern],
        current_preset: str = "home_basic",
    ) -> dict[str, Any] | None:
        """Suggest preset configuration adjustments based on patterns."""
        if not patterns:
            return None

        # Analyze pattern types
        pattern_types = {}
        for p in patterns:
            pattern_types[p.pattern_type] = pattern_types.get(p.pattern_type, 0) + 1

        prompt = f"""Analyze these security patterns and suggest firewall preset adjustments:

Current Preset: {current_preset}

Pattern Summary:
- Attack patterns: {pattern_types.get('attack', 0)}
- False positives: {pattern_types.get('false_positive', 0)}
- Legitimate traffic: {pattern_types.get('legitimate', 0)}
- Anomalies: {pattern_types.get('anomaly', 0)}

Based on this data, should the firewall preset be adjusted? Consider:
1. If many false positives, suggest relaxing rules
2. If many attacks, suggest stricter rules
3. If legitimate traffic is blocked, suggest allowlist additions

Respond in JSON format:
{{
    "adjustment_needed": true/false,
    "suggested_preset": "preset_name or null",
    "reasoning": "Why this adjustment is recommended",
    "confidence": 0.0-1.0
}}"""

        try:
            response = await self._call_llm(prompt)
            if response:
                json_data = self._extract_json(response)
                return json_data
        except Exception as e:
            logger.error("preset_recommendation_failed", error=str(e))

        return None

    async def _call_llm(self, prompt: str) -> str | None:
        """Call Ollama LLM with the given prompt."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.ollama_host}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                    },
                )
                response.raise_for_status()
                data = response.json()
                return data.get("response", "").strip()
        except Exception as e:
            logger.error("llm_call_failed", error=str(e), host=self.ollama_host)
            return None

    def _extract_json(self, text: str) -> dict[str, Any] | None:
        """Extract JSON from LLM response."""
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

        logger.warning("json_extraction_failed", text_preview=text[:200])
        return None

    def _group_similar_patterns(
        self,
        patterns: list[LearnedPattern],
    ) -> list[list[LearnedPattern]]:
        """Group patterns by similarity (same ports/protocols)."""
        groups: dict[str, list[LearnedPattern]] = {}

        for pattern in patterns:
            ports = json.loads(pattern.ports)
            protocols = json.loads(pattern.protocols)

            # Create a key based on ports and protocols
            key = f"{','.join(map(str, sorted(ports)))}_{','.join(sorted(protocols))}"

            if key not in groups:
                groups[key] = []
            groups[key].append(pattern)

        return list(groups.values())

    async def generate_insights_from_patterns(
        self,
        min_confidence: float = 0.7,
    ) -> list[dict[str, Any]]:
        """Generate insights from all high-confidence patterns."""
        # Get attack patterns
        attack_patterns = await self.memory.get_patterns(
            pattern_type="attack",
            min_confidence=min_confidence,
            active_only=True,
        )

        insights = []

        # Analyze attack patterns in clusters
        if attack_patterns:
            # Group into clusters of 5 for analysis
            for i in range(0, len(attack_patterns), 5):
                cluster = attack_patterns[i : i + 5]
                analysis = await self.analyze_pattern_cluster(cluster)

                if analysis and analysis.get("suggested_rules"):
                    # Create insights for each suggested rule
                    for rule in analysis["suggested_rules"]:
                        insight = {
                            "insight_type": "rule_suggestion",
                            "description": f"Block {rule.get('source', 'unknown')} - {rule.get('reason', 'threat detected')}",
                            "recommendation": rule,
                            "reasoning": analysis.get("summary", ""),
                            "confidence": 0.8 if analysis.get("threat_level") == "high" else 0.7,
                            "based_on_patterns": [p.id for p in cluster],
                        }
                        insights.append(insight)

                        # Store in memory
                        await self.memory.store_insight(
                            insight_type="rule_suggestion",
                            description=insight["description"],
                            recommendation=rule,
                            reasoning=insight["reasoning"],
                            confidence=insight["confidence"],
                            based_on_patterns=[p.id for p in cluster],
                        )

            # Generate signature updates
            signature_recs = await self.recommend_signature_updates(attack_patterns)
            for sig_rec in signature_recs:
                insight = {
                    "insight_type": "signature_update",
                    "description": sig_rec["description"],
                    "recommendation": {
                        "pattern": sig_rec["pattern"],
                        "signature_type": sig_rec["signature_type"],
                    },
                    "reasoning": "Generated from observed attack patterns",
                    "confidence": sig_rec["confidence"],
                    "based_on_patterns": sig_rec["based_on_patterns"],
                }
                insights.append(insight)

                await self.memory.store_insight(
                    insight_type="signature_update",
                    description=insight["description"],
                    recommendation=insight["recommendation"],
                    reasoning=insight["reasoning"],
                    confidence=insight["confidence"],
                    based_on_patterns=sig_rec["based_on_patterns"],
                )

        logger.info("insights_generated", total_insights=len(insights))
        return insights
