# Web Search Validation - Usage Guide

## Overview

AFO now includes web search validation that researches firewall requests before implementation. The system uses web search to gather information about IPs, ports, and protocols, then uses LLM analysis to validate if the request is legitimate and safe.

## How It Works

```
User Request → Web Search → LLM Analysis → Validation → Implementation
```

### Example Flow

```
1. User: "block traffic from 1.2.3.4"

2. Web Search:
   Query: "IP address 1.2.3.4 security threat"
   Results:
   - "IP 1.2.3.4 associated with malware C2 servers"
   - "Known for SSH brute force attacks"
   - "Listed in multiple threat databases"

3. LLM Analysis:
   Context: User request + Proposed rule + Search results
   Output: {
     "is_valid": true,
     "is_safe": true,
     "confidence": 0.95,
     "reasoning": "IP confirmed malicious in multiple sources",
     "recommendation": "approve"
   }

4. Validation Result: ✅ APPROVED
   Rule deployed with high confidence
```

## Configuration

### Enable Web Search

Edit `.env`:

```bash
# Enable web search validation
ENABLE_WEB_SEARCH_VALIDATION=true

# Minimum confidence threshold (0.0-1.0)
WEB_SEARCH_MIN_CONFIDENCE=0.7

# Search API endpoint
WEB_SEARCH_API=https://api.duckduckgo.com/
```

### Confidence Thresholds

- **0.9-1.0**: Very high confidence - Auto-approve
- **0.7-0.9**: High confidence - Approve with logging
- **0.5-0.7**: Medium confidence - Manual review recommended
- **0.0-0.5**: Low confidence - Reject or require approval

## Usage Examples

### Example 1: Blocking Malicious IP

```python
from agents.enhanced_agent import process_request_with_validation

# User request
result = await process_request_with_validation(
    "block all traffic from 203.0.113.50"
)

# With web search enabled:
# 1. Searches: "IP address 203.0.113.50 security threat"
# 2. Finds: Multiple threat intelligence sources
# 3. LLM validates: High confidence (0.92)
# 4. Result: ✅ APPROVED

print(result["response"])
# Output:
# Rule created: Block traffic from 203.0.113.50
#
# ✅ Web Search Validation: PASSED
# Confidence: 0.92
# Reasoning: IP confirmed in threat databases, blocking is appropriate
```

### Example 2: Protecting Legitimate Services

```python
result = await process_request_with_validation(
    "block all traffic from 8.8.8.8"
)

# With web search enabled:
# 1. Searches: "IP address 8.8.8.8 security threat"
# 2. Finds: "Google Public DNS service"
# 3. LLM validates: Unsafe to block (confidence: 0.95)
# 4. Result: ❌ REJECTED

print(result["response"])
# Output:
# ⚠️ Web Search Validation Failed
#
# Reasoning: This is Google's public DNS server. Blocking would
# break DNS resolution for all services.
#
# Recommendation: reject
```

### Example 3: Low Confidence - Manual Review

```python
result = await process_request_with_validation(
    "block port 8080 from 192.168.1.50"
)

# With web search enabled:
# 1. Searches: "IP address 192.168.1.50 port 8080 security threat"
# 2. Finds: Limited information (private IP)
# 3. LLM validates: Low confidence (0.45)
# 4. Result: ⚠️ MANUAL REVIEW

print(result["response"])
# Output:
# ⚠️ Low Confidence Validation
#
# Confidence: 0.45 (minimum: 0.70)
#
# Reasoning: Private IP address with insufficient threat intelligence.
# Port 8080 commonly used for web services.
#
# The rule may be valid but requires manual review.
```

## Integration with TUI

The web search validation works automatically in the TUI:

```bash
# Launch AFO
./afo

# In the TUI, type:
block traffic from 1.2.3.4

# System will:
# 1. Parse your request
# 2. Search the web for information
# 3. Validate with LLM
# 4. Show validation results
# 5. Deploy if approved
```

## Integration with API

```python
from agents.enhanced_agent import process_request_with_validation

async def handle_firewall_request(user_input: str):
    result = await process_request_with_validation(
        user_input=user_input,
        enable_web_search=True,  # Override env setting
        min_confidence=0.8       # Custom threshold
    )

    if result["type"] == "validation_failed":
        # Validation rejected the rule
        return {
            "status": "rejected",
            "reason": result["validation"]["reasoning"]
        }

    elif result["type"] == "low_confidence":
        # Needs manual review
        return {
            "status": "pending_review",
            "confidence": result["validation"]["confidence"]
        }

    else:
        # Validation passed
        return {
            "status": "approved",
            "rule": result["rule"]
        }
```

## What Gets Searched

The system builds intelligent search queries based on the request:

### For IP Addresses
```
Query: "IP address {ip} security threat"
Looks for: Threat intelligence, reputation, known attacks
```

### For Ports
```
Query: "port {port} {protocol} security threat"
Looks for: Common exploits, vulnerabilities, attack patterns
```

### For Protocols
```
Query: "{protocol} protocol security threat"
Looks for: Protocol vulnerabilities, attack vectors
```

## Search Results Processing

The system extracts information from:

1. **DuckDuckGo Instant Answers** - Quick facts and summaries
2. **Related Topics** - Additional context and sources
3. **Abstracts** - Detailed information

Results are limited to top 5 most relevant entries to avoid information overload.

## LLM Validation Process

The LLM receives:

```
USER REQUEST: block traffic from 1.2.3.4

PROPOSED RULE:
Action: block
Source: 1.2.3.4
Port: N/A
Protocol: N/A

WEB SEARCH RESULTS:
1. Malicious IP Database
   IP 1.2.3.4 is known for SSH brute force attacks

2. Threat Intelligence Feed
   This IP has been reported 47 times in the last 30 days

3. Security Blog
   Analysis of botnet using this IP for DDoS attacks

VALIDATION TASK:
Analyze and determine:
1. Is this a legitimate security request?
2. Is it safe to implement?
3. Are there any red flags?
4. What is your confidence level?
```

The LLM responds with structured validation:

```json
{
    "is_valid": true,
    "is_safe": true,
    "confidence": 0.95,
    "reasoning": "IP confirmed malicious in multiple threat databases. Blocking is appropriate and safe.",
    "recommendation": "approve"
}
```

## Safety Features

### Multiple Validation Layers

1. **Web Search** - Gathers external information
2. **LLM Analysis** - Contextual understanding
3. **Confidence Scoring** - Quantifies certainty
4. **Safety Enforcer** - Checks against allowlist (existing)
5. **User Approval** - Final human oversight (if enabled)

### Prevents Common Mistakes

- ❌ Blocking legitimate services (DNS, CDNs)
- ❌ Blocking entire subnets accidentally
- ❌ Blocking critical infrastructure
- ❌ Creating overly broad rules
- ❌ Implementing rules based on outdated information

## Performance Considerations

### Latency

- Web search: ~1-2 seconds
- LLM analysis: ~2-5 seconds
- Total overhead: ~3-7 seconds per request

### Caching

The system caches search results for:
- Same IP: 1 hour
- Same port: 24 hours
- Same protocol: 7 days

### Rate Limiting

DuckDuckGo API has no official rate limits, but best practices:
- Max 1 request per second
- Implement exponential backoff on errors
- Cache aggressively

## Troubleshooting

### Web Search Not Working

```bash
# Check if enabled
grep ENABLE_WEB_SEARCH_VALIDATION .env

# Test search manually
python -c "
from agents.web_search_validator import WebSearchValidator
import asyncio

async def test():
    validator = WebSearchValidator()
    results = await validator.search_web('test query')
    print(results)

asyncio.run(test())
"
```

### Low Confidence Results

If you're getting too many low confidence results:

1. **Lower threshold**: `WEB_SEARCH_MIN_CONFIDENCE=0.5`
2. **Disable for internal IPs**: Add logic to skip private ranges
3. **Use manual mode**: Review all validations

### LLM Not Responding

```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Test LLM directly
curl http://localhost:11434/api/generate -d '{
  "model": "qwen2.5-coder:3b",
  "prompt": "test",
  "stream": false
}'
```

## Advanced Usage

### Custom Search API

Replace DuckDuckGo with your own search:

```python
class CustomSearchValidator(WebSearchValidator):
    async def search_web(self, query: str, max_results: int = 5):
        # Use your own search API
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://your-search-api.com/search",
                params={"q": query, "limit": max_results},
                headers={"Authorization": f"Bearer {YOUR_API_KEY}"}
            )
            return response.json()["results"]
```

### Threat Intelligence Integration

Enhance with threat feeds:

```python
class ThreatIntelValidator(WebSearchValidator):
    async def validate_request(self, user_request, proposed_rule):
        # Standard web search
        validation = await super().validate_request(user_request, proposed_rule)

        # Add threat intelligence
        ip = proposed_rule.get("source")
        if ip:
            threat_score = await self.check_virustotal(ip)
            validation["threat_score"] = threat_score

            if threat_score > 50:
                validation["confidence"] = min(1.0, validation["confidence"] + 0.1)

        return validation
```

### Custom Validation Logic

Add your own validation rules:

```python
async def custom_validate(user_request, proposed_rule):
    # Standard validation
    result = await validate_with_web_search(user_request, proposed_rule)

    # Custom logic
    if proposed_rule["source"] in WHITELIST:
        result["is_valid"] = False
        result["reasoning"] = "IP is whitelisted"

    if proposed_rule["port"] in CRITICAL_PORTS:
        result["confidence"] = max(0.9, result["confidence"])

    return result
```

## Testing

Run the test suite:

```bash
# Test web search validator
pytest tests/test_web_search_validator.py -v

# Test with real search (requires internet)
pytest tests/test_web_search_validator.py -v --run-integration
```

## Monitoring

Track validation metrics:

```python
from prometheus_client import Counter, Histogram

validation_total = Counter(
    'afo_web_search_validations_total',
    'Total web search validations',
    ['result']
)

validation_duration = Histogram(
    'afo_web_search_duration_seconds',
    'Web search validation duration'
)

# In your code
with validation_duration.time():
    result = await validate_with_web_search(request, rule)
    validation_total.labels(result=result["recommendation"]).inc()
```

## Best Practices

1. **Start Disabled** - Test without web search first
2. **Monitor Confidence** - Track validation confidence over time
3. **Review Rejections** - Check false negatives
4. **Tune Thresholds** - Adjust based on your environment
5. **Cache Results** - Reduce API calls and latency
6. **Fallback Mode** - Continue without web search if API fails
7. **Rate Limit** - Respect API limits
8. **Log Everything** - Track all validations for audit

## Security Considerations

- Web search results are **untrusted external data**
- LLM validation adds **AI reasoning** but isn't perfect
- Always maintain **human oversight** for critical rules
- Use **multiple validation layers** (web search + safety enforcer)
- **Log all validations** for audit trail
- **Don't rely solely** on web search - it's an enhancement

## Future Enhancements

Planned improvements:

1. **Multiple search engines** - Google, Bing, specialized security search
2. **Threat intelligence APIs** - VirusTotal, AbuseIPDB, Shodan
3. **Machine learning** - Train on validation history
4. **Caching layer** - Redis for faster lookups
5. **Batch validation** - Validate multiple rules at once
6. **Real-time updates** - Subscribe to threat feeds
7. **Custom validators** - Plugin system for custom logic

## Summary

Web search validation adds an intelligent research layer to AFO:

✅ **Researches** requests before implementation
✅ **Validates** using LLM analysis
✅ **Prevents** blocking legitimate services
✅ **Increases** confidence in automated decisions
✅ **Provides** reasoning for all validations

Enable it with: `ENABLE_WEB_SEARCH_VALIDATION=true`
